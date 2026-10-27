//! Polling of a single SNMP agent.

use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

use chrono::{DateTime, Utc};
use snafu::Snafu;
use snmp2::{AsyncSession, Oid};
use tokio::time::timeout;

use super::{
    config::{Conversion, MetricTypeOverride, SnmpVersion},
    convert::{Datum, format_oid},
};
use crate::event::metric::{Metric, MetricKind, MetricTags, MetricValue};

/// Maximum number of OIDs requested in a single GET.
///
/// Many agents reject or truncate large requests, so scalar fields are fetched in chunks.
const MAX_OIDS_PER_GET: usize = 32;

/// SNMP `noSuchName` error status, returned by v1 agents at the end of a GETNEXT walk.
const ERROR_STATUS_NO_SUCH_NAME: u32 = 2;

/// Connection and protocol settings shared by all agents of a source.
#[derive(Clone, Debug)]
pub(super) struct SessionSettings {
    pub version: SnmpVersion,
    pub community: Vec<u8>,
    pub security: Option<snmp2::v3::Security>,
    pub timeout: Duration,
    pub retries: u32,
    pub max_repetitions: u32,
}

/// The validated set of values to collect from each agent.
#[derive(Clone, Debug)]
pub(super) struct PollPlan {
    pub namespace: Option<String>,
    pub endpoint_tag: Option<String>,
    pub static_tags: BTreeMap<String, String>,
    pub fields: Vec<PlannedField>,
    pub tables: Vec<PlannedTable>,
}

#[derive(Clone, Debug)]
pub(super) struct PlannedField {
    pub name: String,
    pub oid: Vec<u64>,
    pub is_tag: bool,
    pub conversion: Option<Conversion>,
    pub scale: Option<f64>,
    pub metric_type: Option<MetricTypeOverride>,
}

#[derive(Clone, Debug)]
pub(super) struct PlannedTable {
    pub name: String,
    pub index_tag: Option<String>,
    pub inherit_tags: Vec<String>,
    pub columns: Vec<PlannedField>,
}

#[derive(Debug, Snafu)]
pub(super) enum PollError {
    #[snafu(display("Request timed out after {timeout:?}."))]
    Timeout { timeout: Duration },

    #[snafu(display("Failed to open session: {source}"))]
    Connect { source: std::io::Error },

    #[snafu(display("SNMP error: {source}"))]
    Protocol { source: snmp2::Error },

    #[snafu(display("Agent returned error status {status} for variable binding {index}."))]
    ErrorStatus { status: u32, index: u32 },

    #[snafu(display("Agent returned OIDs out of order while walking {root}."))]
    WalkNotIncreasing { root: String },

    #[snafu(display("OID {oid} cannot be encoded."))]
    InvalidOid { oid: String },
}

impl PollError {
    /// Whether retrying the request on a fresh session may succeed.
    const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::Connect { .. } | Self::Protocol { .. }
        )
    }
}

/// A non-fatal problem with a single value.
#[derive(Debug)]
pub(super) struct ValueError {
    pub field: String,
    pub reason: String,
}

/// The result of polling one agent.
#[derive(Debug, Default)]
pub(super) struct PollOutcome {
    pub metrics: Vec<Metric>,
    /// Approximate number of payload bytes received.
    pub bytes: usize,
    /// Whether at least one request got a response.
    pub reachable: bool,
    pub request_errors: Vec<PollError>,
    pub value_errors: Vec<ValueError>,
}

enum Request<'a> {
    Get(&'a [Vec<u64>]),
    GetNext(&'a [u64]),
    GetBulk(&'a [u64]),
}

struct Response {
    error_status: u32,
    error_index: u32,
    varbinds: Vec<(Vec<u64>, Datum)>,
    bytes: usize,
}

/// A polled SNMP agent and its session.
pub(super) struct Agent {
    pub endpoint: String,
    host: String,
    port: u16,
    settings: SessionSettings,
    session: Option<AsyncSession>,
    next_request_id: i32,
}

impl Agent {
    pub(super) const fn new(
        endpoint: String,
        host: String,
        port: u16,
        settings: SessionSettings,
    ) -> Self {
        Self {
            endpoint,
            host,
            port,
            settings,
            session: None,
            next_request_id: 1,
        }
    }

    /// Polls every field and table in the plan.
    ///
    /// Failures of individual requests are collected in the outcome instead of aborting the poll.
    /// A failed table is skipped entirely, so that rows never miss their tag columns.
    pub(super) async fn poll(&mut self, plan: &PollPlan) -> PollOutcome {
        let mut outcome = PollOutcome::default();
        let endpoint = self.endpoint.clone();
        let builder = MetricBuilder {
            plan,
            timestamp: Utc::now(),
            endpoint: &endpoint,
        };

        let scalar_values = self.fetch_scalars(plan, &mut outcome).await;
        let mut scalar_tags = MetricTags::default();
        let mut inheritable = BTreeMap::new();
        let mut scalar_metrics = Vec::new();
        for field in &plan.fields {
            // Several fields may share an OID, such as a raw and a scaled copy of one value.
            let Some(datum) = scalar_values.get(&field.oid).cloned() else {
                continue;
            };
            match resolve(field, datum) {
                Ok(Resolved::Tag(value)) => {
                    scalar_tags.replace(field.name.clone(), value.clone());
                    inheritable.insert(field.name.as_str(), value);
                }
                Ok(Resolved::Value(value)) => scalar_metrics.push((field.name.clone(), value)),
                Ok(Resolved::Absent) => {}
                Err(reason) => outcome.value_errors.push(ValueError {
                    field: field.name.clone(),
                    reason,
                }),
            }
        }
        let tags = builder.base_tags(&scalar_tags);
        outcome.metrics.extend(
            scalar_metrics
                .into_iter()
                .map(|(name, value)| builder.metric(name, value, tags.clone())),
        );

        for table in &plan.tables {
            self.poll_table(table, &builder, &inheritable, &mut outcome)
                .await;
        }

        outcome
    }

    /// Fetches all scalar fields with GET requests, keyed by OID.
    async fn fetch_scalars(
        &mut self,
        plan: &PollPlan,
        outcome: &mut PollOutcome,
    ) -> HashMap<Vec<u64>, Datum> {
        let mut values = HashMap::new();
        let field_oids: Vec<Vec<u64>> = plan.fields.iter().map(|f| f.oid.clone()).collect();
        for chunk in field_oids.chunks(MAX_OIDS_PER_GET) {
            let mut chunk = chunk.to_vec();
            while !chunk.is_empty() {
                let response = self.request(Request::Get(&chunk)).await;
                if let Ok(response) = &response {
                    outcome.reachable = true;
                    outcome.bytes += response.bytes;
                }
                match response {
                    // SNMPv1 agents fail the whole request when one OID does not exist, and point
                    // at it with the error index. Drop that OID and ask again for the others.
                    Ok(response)
                        if response.error_status == ERROR_STATUS_NO_SUCH_NAME
                            && (1..=chunk.len()).contains(&(response.error_index as usize)) =>
                    {
                        chunk.remove(response.error_index as usize - 1);
                    }
                    Ok(response) if response.error_status != 0 => {
                        outcome.request_errors.push(PollError::ErrorStatus {
                            status: response.error_status,
                            index: response.error_index,
                        });
                        break;
                    }
                    Ok(response) => {
                        values.extend(
                            response
                                .varbinds
                                .into_iter()
                                .filter(|(oid, _)| chunk.contains(oid)),
                        );
                        break;
                    }
                    Err(error) => {
                        outcome.request_errors.push(error);
                        break;
                    }
                }
            }
        }
        values
    }

    /// Walks every column of a table and emits one metric per row and value column.
    ///
    /// The table is skipped if any column fails, so that rows never miss their tag columns.
    async fn poll_table(
        &mut self,
        table: &PlannedTable,
        builder: &MetricBuilder<'_>,
        inheritable: &BTreeMap<&str, String>,
        outcome: &mut PollOutcome,
    ) {
        let mut rows: BTreeMap<Vec<u64>, Vec<(&PlannedField, Datum)>> = BTreeMap::new();
        for column in &table.columns {
            match self.walk(&column.oid, outcome).await {
                Ok(varbinds) => {
                    for (oid, datum) in varbinds {
                        let index = oid[column.oid.len()..].to_vec();
                        rows.entry(index).or_default().push((column, datum));
                    }
                }
                Err(error) => {
                    outcome.request_errors.push(error);
                    return;
                }
            }
        }

        let mut inherited = MetricTags::default();
        for name in &table.inherit_tags {
            if let Some(value) = inheritable.get(name.as_str()) {
                inherited.replace(name.clone(), value.clone());
            }
        }
        let base = builder.base_tags(&inherited);

        for (index, cells) in rows {
            let mut tags = base.clone();
            if let Some(index_tag) = &table.index_tag {
                tags.replace(index_tag.clone(), format_oid(&index));
            }
            let mut values = Vec::new();
            for (column, datum) in cells {
                match resolve(column, datum) {
                    Ok(Resolved::Tag(value)) => {
                        tags.replace(column.name.clone(), value);
                    }
                    Ok(Resolved::Value(value)) => values.push((column, value)),
                    Ok(Resolved::Absent) => {}
                    Err(reason) => outcome.value_errors.push(ValueError {
                        field: format!("{}.{}", table.name, column.name),
                        reason,
                    }),
                }
            }
            outcome
                .metrics
                .extend(values.into_iter().map(|(column, value)| {
                    builder.metric(
                        format!("{}_{}", table.name, column.name),
                        value,
                        tags.clone(),
                    )
                }));
        }
    }

    /// Walks the subtree under `root`, returning every varbind inside it.
    ///
    /// Every response is recorded in `outcome` as it arrives, so a walk that fails part-way still
    /// shows that the agent answered.
    async fn walk(
        &mut self,
        root: &[u64],
        outcome: &mut PollOutcome,
    ) -> Result<Vec<(Vec<u64>, Datum)>, PollError> {
        let mut out = Vec::new();
        let mut cursor = root.to_vec();
        let use_bulk = self.settings.version != SnmpVersion::V1;

        loop {
            let request = if use_bulk {
                Request::GetBulk(&cursor)
            } else {
                Request::GetNext(&cursor)
            };
            let response = self.request(request).await?;
            outcome.reachable = true;
            outcome.bytes += response.bytes;
            if response.error_status == ERROR_STATUS_NO_SUCH_NAME && !use_bulk {
                // SNMPv1 end of MIB.
                break;
            }
            if response.error_status != 0 {
                return Err(PollError::ErrorStatus {
                    status: response.error_status,
                    index: response.error_index,
                });
            }
            if response.varbinds.is_empty() {
                break;
            }

            let mut done = false;
            for (oid, datum) in response.varbinds {
                if datum == Datum::EndOfMibView || !oid.starts_with(root) || oid.len() == root.len()
                {
                    done = true;
                    break;
                }
                if oid <= cursor {
                    return Err(PollError::WalkNotIncreasing {
                        root: format_oid(root),
                    });
                }
                cursor.clone_from(&oid);
                out.push((oid, datum));
            }
            if done {
                break;
            }
        }

        Ok(out)
    }

    /// Sends a request, retrying transient failures on a fresh session.
    async fn request(&mut self, request: Request<'_>) -> Result<Response, PollError> {
        let attempts = self.settings.retries.saturating_add(1);
        let mut last_error = None;
        for _ in 0..attempts {
            match self.attempt(&request).await {
                Ok(response) => return Ok(response),
                // The agent's engine boots or time changed and the security context was updated.
                // The session stays valid and the request can be sent again right away.
                Err(PollError::Protocol {
                    source: snmp2::Error::AuthUpdated,
                }) => {
                    last_error = Some(PollError::Protocol {
                        source: snmp2::Error::AuthUpdated,
                    });
                }
                Err(error) if error.is_transient() => {
                    // Drop the session so a late response to this request cannot be mistaken for
                    // the response to the next one.
                    self.session = None;
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.expect("at least one attempt is made"))
    }

    async fn attempt(&mut self, request: &Request<'_>) -> Result<Response, PollError> {
        let limit = self.settings.timeout;
        timeout(limit, async {
            let max_repetitions = self.settings.max_repetitions;
            let session = self.session().await?;
            let pdu = match request {
                Request::Get(oids) => {
                    let oids = oids
                        .iter()
                        .map(|oid| to_asn_oid(oid))
                        .collect::<Result<Vec<_>, _>>()?;
                    let refs: Vec<&Oid<'_>> = oids.iter().collect();
                    session.get_many(&refs).await
                }
                Request::GetNext(oid) => session.getnext(&to_asn_oid(oid)?).await,
                Request::GetBulk(oid) => {
                    session
                        .getbulk(&[&to_asn_oid(oid)?], 0, max_repetitions)
                        .await
                }
            }
            .map_err(|source| PollError::Protocol { source })?;

            let mut bytes = 0;
            let mut varbinds = Vec::new();
            for (oid, value) in pdu.varbinds {
                let datum = Datum::from_value(&value);
                bytes += oid.as_bytes().len() + datum.wire_len();
                // OIDs with arcs that do not fit in a u64 cannot match a configured OID.
                if let Some(arcs) = oid.iter() {
                    varbinds.push((arcs.collect(), datum));
                }
            }
            Ok(Response {
                error_status: pdu.error_status,
                error_index: pdu.error_index,
                varbinds,
                bytes,
            })
        })
        .await
        .map_err(|_| PollError::Timeout { timeout: limit })?
    }

    async fn session(&mut self) -> Result<&mut AsyncSession, PollError> {
        if self.session.is_none() {
            let destination = (self.host.as_str(), self.port);
            let request_id = self.next_request_id;
            // Start each new session at a different request ID, so a stale datagram addressed to a
            // previous session can never validate.
            self.next_request_id = self.next_request_id.wrapping_add(1 << 20);
            let session = match self.settings.version {
                SnmpVersion::V1 => {
                    AsyncSession::new_v1(destination, &self.settings.community, request_id).await
                }
                SnmpVersion::V2c => {
                    AsyncSession::new_v2c(destination, &self.settings.community, request_id).await
                }
                SnmpVersion::V3 => {
                    let security = self
                        .settings
                        .security
                        .clone()
                        .expect("security is validated at build time for v3");
                    AsyncSession::new_v3(destination, request_id, security).await
                }
            };
            let mut session = session.map_err(|source| PollError::Connect { source })?;
            session
                .init()
                .await
                .map_err(|source| PollError::Protocol { source })?;
            self.session = Some(session);
        }
        Ok(self.session.as_mut().expect("session was just created"))
    }
}

fn to_asn_oid(arcs: &[u64]) -> Result<Oid<'static>, PollError> {
    Oid::from(arcs).map_err(|_| PollError::InvalidOid {
        oid: format_oid(arcs),
    })
}

enum Resolved {
    Tag(String),
    Value(MetricValue),
    Absent,
}

/// Applies a field's conversion, scale and type to a fetched value.
fn resolve(field: &PlannedField, datum: Datum) -> Result<Resolved, String> {
    if matches!(datum, Datum::Missing | Datum::EndOfMibView) {
        return Ok(Resolved::Absent);
    }
    let datum = match field.conversion {
        Some(conversion) => datum.convert(conversion)?,
        None => datum,
    };

    if field.is_tag {
        return Ok(datum
            .into_tag_value()
            .map_or(Resolved::Absent, Resolved::Tag));
    }

    match datum {
        Datum::Number { value, counter } => {
            let value = field.scale.map_or(value, |scale| value * scale);
            let counter = match field.metric_type {
                Some(MetricTypeOverride::Counter) => true,
                Some(MetricTypeOverride::Gauge) => false,
                None => counter,
            };
            Ok(Resolved::Value(if counter {
                MetricValue::Counter { value }
            } else {
                MetricValue::Gauge { value }
            }))
        }
        other => Err(format!(
            "expected a number but got {}; set `is_tag` or use the `int` or `float` conversion",
            other.describe()
        )),
    }
}

struct MetricBuilder<'a> {
    plan: &'a PollPlan,
    timestamp: DateTime<Utc>,
    endpoint: &'a str,
}

impl MetricBuilder<'_> {
    /// Combines static tags, the endpoint tag and `extra`, in increasing order of precedence.
    fn base_tags(&self, extra: &MetricTags) -> MetricTags {
        let mut tags = MetricTags::default();
        for (key, value) in &self.plan.static_tags {
            tags.replace(key.clone(), value.clone());
        }
        if let Some(endpoint_tag) = &self.plan.endpoint_tag {
            tags.replace(endpoint_tag.clone(), self.endpoint.to_string());
        }
        for (key, value) in extra.iter_single() {
            tags.replace(key.to_string(), value.to_string());
        }
        tags
    }

    fn metric(&self, name: String, value: MetricValue, tags: MetricTags) -> Metric {
        Metric::new(name, MetricKind::Absolute, value)
            .with_namespace(self.plan.namespace.clone())
            .with_tags(Some(tags))
            .with_timestamp(Some(self.timestamp))
    }

    /// The `up` gauge, reporting whether the agent responded during this poll.
    pub(super) fn up(&self, reachable: bool) -> Metric {
        self.metric(
            "up".to_string(),
            MetricValue::Gauge {
                value: if reachable { 1.0 } else { 0.0 },
            },
            self.base_tags(&MetricTags::default()),
        )
    }
}

/// Builds the `up` metric for an agent.
pub(super) fn up_metric(plan: &PollPlan, endpoint: &str, reachable: bool) -> Metric {
    MetricBuilder {
        plan,
        timestamp: Utc::now(),
        endpoint,
    }
    .up(reachable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str) -> PlannedField {
        PlannedField {
            name: name.to_string(),
            oid: vec![1, 3, 6, 1],
            is_tag: false,
            conversion: None,
            scale: None,
            metric_type: None,
        }
    }

    fn value(resolved: Result<Resolved, String>) -> MetricValue {
        match resolved {
            Ok(Resolved::Value(value)) => value,
            _ => panic!("expected a metric value"),
        }
    }

    #[test]
    fn resolves_counter_and_gauge() {
        let datum = Datum::Number {
            value: 10.0,
            counter: true,
        };
        assert_eq!(
            value(resolve(&field("a"), datum.clone())),
            MetricValue::Counter { value: 10.0 }
        );

        let mut overridden = field("a");
        overridden.metric_type = Some(MetricTypeOverride::Gauge);
        assert_eq!(
            value(resolve(&overridden, datum)),
            MetricValue::Gauge { value: 10.0 }
        );
    }

    #[test]
    fn applies_scale() {
        let mut scaled = field("temperature");
        scaled.scale = Some(0.1);
        let datum = Datum::Number {
            value: 235.0,
            counter: false,
        };
        match value(resolve(&scaled, datum)) {
            MetricValue::Gauge { value } => assert!((value - 23.5).abs() < 1e-9),
            other => panic!("unexpected value {other:?}"),
        }
    }

    #[test]
    fn rejects_text_values() {
        let result = resolve(&field("descr"), Datum::Bytes(b"eth0".to_vec()));
        assert!(result.is_err());
    }

    #[test]
    fn resolves_tags_and_missing_values() {
        let mut tag = field("descr");
        tag.is_tag = true;
        assert!(matches!(
            resolve(&tag, Datum::Bytes(b"eth0".to_vec())),
            Ok(Resolved::Tag(value)) if value == "eth0"
        ));
        assert!(matches!(
            resolve(&field("a"), Datum::Missing),
            Ok(Resolved::Absent)
        ));
    }

    #[test]
    fn builds_tags_in_precedence_order() {
        let plan = PollPlan {
            namespace: Some("snmp".to_string()),
            endpoint_tag: Some("endpoint".to_string()),
            static_tags: BTreeMap::from([
                ("site".to_string(), "dc1".to_string()),
                ("endpoint".to_string(), "overridden".to_string()),
            ]),
            fields: vec![],
            tables: vec![],
        };
        let metric = up_metric(&plan, "10.0.0.1", true);
        assert_eq!(metric.name(), "up");
        assert_eq!(metric.namespace(), Some("snmp"));
        assert_eq!(metric.tag_value("endpoint").as_deref(), Some("10.0.0.1"));
        assert_eq!(metric.tag_value("site").as_deref(), Some("dc1"));
        assert_eq!(metric.value(), &MetricValue::Gauge { value: 1.0 });
    }
}
