//! Configuration for the `snmp` source.

use std::{collections::BTreeMap, time::Duration};

use serde_with::serde_as;
use snafu::Snafu;
use vector_lib::{
    config::LogNamespace, configurable::configurable_component, sensitive_string::SensitiveString,
};

use super::{
    convert::parse_oid,
    poller::{Agent, PlannedField, PlannedTable, PollPlan, SessionSettings},
};
use crate::config::{SourceConfig, SourceContext, SourceOutput};

/// Configuration for the `snmp` source.
#[serde_as]
#[configurable_component(source(
    "snmp",
    "Collect metrics from network devices and other agents using SNMP."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SnmpConfig {
    /// SNMP agents to poll.
    ///
    /// Each endpoint is a host name or IP address with an optional port, optionally prefixed with
    /// `udp://`. The port defaults to `161`. Only UDP is supported. Credentials such as
    /// `public@host` are rejected: set them in `community` or `usm`.
    #[configurable(metadata(docs::examples = "udp://192.168.1.1:161"))]
    #[configurable(metadata(docs::examples = "10.0.0.2"))]
    #[configurable(metadata(docs::examples = "[2001:db8::1]:1161"))]
    pub endpoints: Vec<String>,

    /// The interval between polls.
    #[serde(default = "default_scrape_interval")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "scrape_interval_secs")]
    #[configurable(metadata(docs::human_name = "Scrape Interval"))]
    pub scrape_interval: Duration,

    /// The timeout for each SNMP request.
    ///
    /// A request that times out is retried up to `retries` times.
    #[serde(default = "default_scrape_timeout")]
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(rename = "scrape_timeout_secs")]
    #[configurable(metadata(docs::human_name = "Scrape Timeout"))]
    pub scrape_timeout: Duration,

    /// The number of times a failed request is retried before the agent is considered unreachable.
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// The SNMP protocol version to use.
    #[serde(default)]
    pub version: SnmpVersion,

    /// The community string used to authenticate with the agents.
    ///
    /// Only used with SNMP versions `v1` and `v2c`.
    #[serde(default = "default_community")]
    #[configurable(metadata(docs::examples = "public"))]
    pub community: SensitiveString,

    /// The maximum number of variable bindings to request in each GETBULK request while walking a
    /// table.
    ///
    /// Only used with SNMP versions `v2c` and `v3`. Version `v1` walks tables with GETNEXT, which
    /// returns one variable binding per request.
    #[serde(default = "default_max_repetitions")]
    pub max_repetitions: u32,

    /// `SNMPv3` security settings.
    pub usm: Option<UsmConfig>,

    /// The namespace for the metrics emitted by the source.
    ///
    /// If set to an empty string, no namespace is added to the metrics.
    #[serde(default = "default_namespace")]
    pub namespace: String,

    /// The name of the tag that holds the endpoint of the polled agent.
    ///
    /// The tag value is the endpoint exactly as configured. If set to an empty string, the tag is
    /// not added.
    #[serde(default = "default_endpoint_tag")]
    pub endpoint_tag: String,

    /// Tags added to every metric emitted by the source.
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "A tag name and its value.",
        docs::examples = "tags_example()",
    ))]
    pub tags: BTreeMap<String, String>,

    /// Scalar values to fetch with SNMP GET.
    ///
    /// Each value is emitted as a metric named after the field, unless the field is a tag.
    /// Fields marked as tags are added to every scalar metric from the same agent, and to table
    /// metrics that list them in `inherit_tags`.
    #[serde(default)]
    pub fields: Vec<FieldConfig>,

    /// Tables to walk.
    ///
    /// Each table row produces one metric per non-tag column. Metric names are the table name and
    /// the column name joined with an underscore.
    #[serde(default)]
    pub tables: Vec<TableConfig>,
}

/// SNMP protocol version.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SnmpVersion {
    /// SNMP version 1.
    V1,

    /// SNMP version 2c.
    #[default]
    V2c,

    /// SNMP version 3, using the User-based Security Model configured in `usm`.
    V3,
}

/// User-based Security Model (USM) settings for SNMP version 3.
///
/// Required when `version` is `v3`, and rejected otherwise.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UsmConfig {
    /// The user name.
    #[configurable(metadata(docs::examples = "monitor"))]
    pub username: String,

    /// The security level.
    #[serde(default)]
    pub security_level: SecurityLevel,

    /// The authentication protocol.
    ///
    /// Required when `security_level` is `auth_no_priv` or `auth_priv`.
    pub auth_protocol: Option<AuthProtocol>,

    /// The authentication password.
    ///
    /// Required when `security_level` is `auth_no_priv` or `auth_priv`.
    #[configurable(metadata(docs::examples = "${SNMP_AUTH_PASSWORD}"))]
    pub auth_password: Option<SensitiveString>,

    /// The privacy (encryption) protocol.
    ///
    /// Required when `security_level` is `auth_priv`.
    pub privacy_protocol: Option<PrivacyProtocol>,

    /// The privacy (encryption) password.
    ///
    /// Required when `security_level` is `auth_priv`.
    #[configurable(metadata(docs::examples = "${SNMP_PRIV_PASSWORD}"))]
    pub privacy_password: Option<SensitiveString>,

    /// The context name.
    #[configurable(metadata(docs::examples = "vlan-10"))]
    pub context_name: Option<String>,

    /// The method used to extend a localized privacy key when it is shorter than the privacy
    /// protocol requires.
    ///
    /// This only applies to `aes192` and `aes256` with an authentication protocol whose digest is
    /// too short. Agents differ in which method they implement, so set this to match the agent.
    pub key_extension: Option<KeyExtension>,
}

/// `SNMPv3` security level.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "The variant names follow the security level names in RFC 3414."
)]
pub enum SecurityLevel {
    /// No authentication and no encryption.
    NoAuthNoPriv,

    /// Authentication without encryption.
    #[default]
    AuthNoPriv,

    /// Authentication and encryption.
    AuthPriv,
}

/// `SNMPv3` authentication protocol.
#[configurable_component]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthProtocol {
    /// HMAC-MD5-96.
    Md5,

    /// HMAC-SHA-96.
    Sha1,

    /// HMAC-SHA-224.
    Sha224,

    /// HMAC-SHA-256.
    Sha256,

    /// HMAC-SHA-384.
    Sha384,

    /// HMAC-SHA-512.
    Sha512,
}

/// `SNMPv3` privacy protocol.
#[configurable_component]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyProtocol {
    /// DES in CBC mode.
    Des,

    /// AES-128 in CFB mode.
    Aes128,

    /// AES-192 in CFB mode.
    Aes192,

    /// AES-256 in CFB mode.
    Aes256,
}

/// Privacy key extension method.
#[configurable_component]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyExtension {
    /// The method from draft-blumenthal-aes-usm-04, used by Net-SNMP and most agents.
    Blumenthal,

    /// The method from draft-reeder-snmpv3-usm-3desede-00, used by some Cisco devices.
    Reeder,
}

/// A value fetched from an agent.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FieldConfig {
    /// The name of the metric or tag.
    ///
    /// For table columns, the metric name is prefixed with the table name.
    #[configurable(metadata(docs::examples = "uptime"))]
    pub name: String,

    /// The object identifier in dotted numeric form.
    ///
    /// For scalar fields, this is the full OID of the instance, usually ending in `.0`.
    /// For table columns, this is the OID of the column, and each row's index is the remainder
    /// of the OIDs returned by the walk.
    #[configurable(metadata(docs::examples = "1.3.6.1.2.1.1.3.0"))]
    pub oid: String,

    /// Whether the value is used as a tag instead of being emitted as a metric.
    #[serde(default)]
    pub is_tag: bool,

    /// Converts the value before it is used.
    ///
    /// Without a conversion, octet strings that are printable UTF-8 text are used as is, and any
    /// other octet strings are hex-encoded.
    pub conversion: Option<Conversion>,

    /// A factor that the value is multiplied by after any conversion.
    ///
    /// Use it for agents that report values in scaled units, such as tenths of a degree.
    /// Not allowed for tags.
    #[configurable(metadata(docs::examples = 0.1))]
    pub scale: Option<f64>,

    /// Overrides the metric type derived from the SNMP type.
    ///
    /// By default, `Counter32` and `Counter64` values become counters and all other numeric values
    /// become gauges. Not allowed for tags.
    pub metric_type: Option<MetricTypeOverride>,
}

/// A conversion applied to a value.
#[configurable_component]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Conversion {
    /// Formats an octet string as a colon-separated hardware address, such as
    /// `00:1a:2b:3c:4d:5e`. An empty octet string produces no tag. Only allowed for tags.
    Hwaddr,

    /// Formats a 4-byte or 16-byte octet string as an IPv4 or IPv6 address.
    /// An empty octet string produces no tag. Only allowed for tags.
    Ipaddr,

    /// Parses the value as a number and truncates it to an integer.
    Int,

    /// Parses the value as a floating-point number.
    Float,
}

/// The type of the emitted metric.
#[configurable_component]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MetricTypeOverride {
    /// A monotonically increasing counter.
    Counter,

    /// A gauge.
    Gauge,
}

/// A table to walk.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TableConfig {
    /// The name of the table, used as the prefix of its metric names.
    #[configurable(metadata(docs::examples = "interface"))]
    pub name: String,

    /// The name of the tag that holds the row index.
    ///
    /// The index is the part of each returned OID after the column OID, in dotted form.
    /// If set to an empty string, the tag is not added.
    #[serde(default = "default_index_tag")]
    pub index_tag: String,

    /// Names of scalar fields marked as tags to add to every metric of this table.
    #[serde(default)]
    #[configurable(metadata(docs::examples = "inherit_tags_example()"))]
    pub inherit_tags: Vec<String>,

    /// The columns to walk.
    pub columns: Vec<FieldConfig>,
}

const fn default_scrape_interval() -> Duration {
    Duration::from_secs(15)
}

const fn default_scrape_timeout() -> Duration {
    Duration::from_secs(5)
}

const fn default_retries() -> u32 {
    3
}

fn default_community() -> SensitiveString {
    "public".to_string().into()
}

const fn default_max_repetitions() -> u32 {
    10
}

fn default_namespace() -> String {
    "snmp".to_string()
}

fn default_endpoint_tag() -> String {
    "endpoint".to_string()
}

fn default_index_tag() -> String {
    "index".to_string()
}

fn tags_example() -> BTreeMap<String, String> {
    BTreeMap::from([("site".to_string(), "dc1".to_string())])
}

fn inherit_tags_example() -> Vec<String> {
    vec!["sys_name".to_string()]
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            endpoints: vec!["udp://127.0.0.1:161".to_string()],
            scrape_interval: default_scrape_interval(),
            scrape_timeout: default_scrape_timeout(),
            retries: default_retries(),
            version: SnmpVersion::default(),
            community: default_community(),
            max_repetitions: default_max_repetitions(),
            usm: None,
            namespace: default_namespace(),
            endpoint_tag: default_endpoint_tag(),
            tags: BTreeMap::new(),
            fields: vec![FieldConfig {
                name: "uptime".to_string(),
                oid: "1.3.6.1.2.1.1.3.0".to_string(),
                is_tag: false,
                conversion: None,
                scale: None,
                metric_type: None,
            }],
            tables: Vec::new(),
        }
    }
}

impl_generate_config_from_default!(SnmpConfig);

#[derive(Debug, Snafu, PartialEq)]
pub(super) enum BuildError {
    #[snafu(display("At least one field or table must be configured."))]
    NothingToCollect,

    #[snafu(display("Invalid endpoint {endpoint:?}: {reason}"))]
    InvalidEndpoint { endpoint: String, reason: String },

    #[snafu(display("Invalid `{path}`: {reason}"))]
    InvalidField { path: String, reason: String },

    #[snafu(display("Invalid table {table:?}: {reason}"))]
    InvalidTable { table: String, reason: String },

    #[snafu(display("`usm` is required when `version` is `v3`."))]
    MissingUsm,

    #[snafu(display("`usm` is only allowed when `version` is `v3`."))]
    UnexpectedUsm,

    #[snafu(display("Invalid `usm`: {reason}"))]
    InvalidUsm { reason: String },

    #[snafu(display("`max_repetitions` must be greater than zero."))]
    ZeroMaxRepetitions,

    #[snafu(display("`scrape_interval_secs` must be greater than zero."))]
    ZeroScrapeInterval,
}

#[async_trait::async_trait]
#[typetag::serde(name = "snmp")]
impl SourceConfig for SnmpConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<crate::sources::Source> {
        let plan = self.plan()?;
        let session = self.session_settings()?;
        let agents = self
            .endpoints
            .iter()
            .map(|endpoint| {
                let (host, port) = parse_endpoint(endpoint)?;
                Ok(Agent::new(endpoint.clone(), host, port, session.clone()))
            })
            .collect::<Result<Vec<_>, BuildError>>()?;

        Ok(super::run(agents, plan, self.scrape_interval, cx))
    }

    fn outputs(&self, _global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        vec![SourceOutput::new_metrics()]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

impl SnmpConfig {
    pub(super) fn session_settings(&self) -> Result<SessionSettings, BuildError> {
        if self.scrape_interval.is_zero() {
            return Err(BuildError::ZeroScrapeInterval);
        }
        if self.max_repetitions == 0 {
            return Err(BuildError::ZeroMaxRepetitions);
        }
        let security = match (self.version, &self.usm) {
            (SnmpVersion::V3, None) => return Err(BuildError::MissingUsm),
            (SnmpVersion::V1 | SnmpVersion::V2c, Some(_)) => return Err(BuildError::UnexpectedUsm),
            (SnmpVersion::V3, Some(usm)) => Some(usm.security()?),
            (SnmpVersion::V1 | SnmpVersion::V2c, None) => None,
        };
        Ok(SessionSettings {
            version: self.version,
            community: self.community.inner().as_bytes().to_vec(),
            security,
            timeout: self.scrape_timeout,
            retries: self.retries,
            max_repetitions: self.max_repetitions,
        })
    }

    pub(super) fn plan(&self) -> Result<PollPlan, BuildError> {
        if self.fields.is_empty() && self.tables.is_empty() {
            return Err(BuildError::NothingToCollect);
        }

        let fields = self
            .fields
            .iter()
            .enumerate()
            .map(|(i, field)| plan_field(field, &format!("fields[{i}]")))
            .collect::<Result<Vec<_>, _>>()?;

        let scalar_tags: Vec<&str> = self
            .fields
            .iter()
            .filter(|field| field.is_tag)
            .map(|field| field.name.as_str())
            .collect();

        let tables = self
            .tables
            .iter()
            .enumerate()
            .map(|(i, table)| {
                if table.name.is_empty() {
                    return Err(BuildError::InvalidField {
                        path: format!("tables[{i}].name"),
                        reason: "must not be empty".to_string(),
                    });
                }
                if table.columns.is_empty() {
                    return Err(BuildError::InvalidTable {
                        table: table.name.clone(),
                        reason: "at least one column is required".to_string(),
                    });
                }
                if let Some(unknown) = table
                    .inherit_tags
                    .iter()
                    .find(|tag| !scalar_tags.contains(&tag.as_str()))
                {
                    return Err(BuildError::InvalidTable {
                        table: table.name.clone(),
                        reason: format!(
                            "`inherit_tags` refers to {unknown:?}, which is not a field with `is_tag` set"
                        ),
                    });
                }
                let columns = table
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(j, column)| plan_field(column, &format!("tables[{i}].columns[{j}]")))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PlannedTable {
                    name: table.name.clone(),
                    index_tag: Some(table.index_tag.clone()).filter(|tag| !tag.is_empty()),
                    inherit_tags: table.inherit_tags.clone(),
                    columns,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(PollPlan {
            namespace: Some(self.namespace.clone()).filter(|ns| !ns.is_empty()),
            endpoint_tag: Some(self.endpoint_tag.clone()).filter(|tag| !tag.is_empty()),
            static_tags: self.tags.clone(),
            fields,
            tables,
        })
    }
}

fn plan_field(field: &FieldConfig, path: &str) -> Result<PlannedField, BuildError> {
    let invalid = |suffix: &str, reason: &str| BuildError::InvalidField {
        path: format!("{path}.{suffix}"),
        reason: reason.to_string(),
    };

    if field.name.is_empty() {
        return Err(invalid("name", "must not be empty"));
    }
    let oid = parse_oid(&field.oid).map_err(|reason| invalid("oid", &reason))?;

    if field.is_tag {
        if field.scale.is_some() {
            return Err(invalid("scale", "not allowed when `is_tag` is set"));
        }
        if field.metric_type.is_some() {
            return Err(invalid("metric_type", "not allowed when `is_tag` is set"));
        }
    } else if matches!(
        field.conversion,
        Some(Conversion::Hwaddr | Conversion::Ipaddr)
    ) {
        return Err(invalid(
            "conversion",
            "`hwaddr` and `ipaddr` produce text, so `is_tag` must be set",
        ));
    }
    if let Some(scale) = field.scale
        && !scale.is_finite()
    {
        return Err(invalid("scale", "must be a finite number"));
    }

    Ok(PlannedField {
        name: field.name.clone(),
        oid,
        is_tag: field.is_tag,
        conversion: field.conversion,
        scale: field.scale,
        metric_type: field.metric_type,
    })
}

impl UsmConfig {
    fn security(&self) -> Result<snmp2::v3::Security, BuildError> {
        let invalid = |reason: &str| BuildError::InvalidUsm {
            reason: reason.to_string(),
        };

        if self.username.is_empty() {
            return Err(invalid("`username` must not be empty"));
        }

        let needs_auth = self.security_level != SecurityLevel::NoAuthNoPriv;
        let needs_priv = self.security_level == SecurityLevel::AuthPriv;

        if !needs_auth && (self.auth_protocol.is_some() || self.auth_password.is_some()) {
            return Err(invalid(
                "`auth_protocol` and `auth_password` are not allowed with `no_auth_no_priv`",
            ));
        }
        if !needs_priv && (self.privacy_protocol.is_some() || self.privacy_password.is_some()) {
            return Err(invalid(
                "`privacy_protocol` and `privacy_password` are only allowed with `auth_priv`",
            ));
        }

        let auth_password = if needs_auth {
            self.auth_password
                .as_ref()
                .map(|password| password.inner().as_bytes().to_vec())
                .filter(|password| !password.is_empty())
                .ok_or_else(|| invalid("`auth_password` is required for this security level"))?
        } else {
            Vec::new()
        };

        let mut security = snmp2::v3::Security::new(self.username.as_bytes(), &auth_password);

        security = if needs_auth {
            let protocol = self
                .auth_protocol
                .ok_or_else(|| invalid("`auth_protocol` is required for this security level"))?;
            security.with_auth_protocol(protocol.into())
        } else {
            security.with_auth(snmp2::v3::Auth::NoAuthNoPriv)
        };

        if needs_priv {
            let cipher = self
                .privacy_protocol
                .ok_or_else(|| invalid("`privacy_protocol` is required with `auth_priv`"))?;
            let privacy_password = self
                .privacy_password
                .as_ref()
                .map(|password| password.inner().as_bytes().to_vec())
                .filter(|password| !password.is_empty())
                .ok_or_else(|| invalid("`privacy_password` is required with `auth_priv`"))?;
            security = security.with_auth(snmp2::v3::Auth::AuthPriv {
                cipher: cipher.into(),
                privacy_password,
            });
        }

        if let Some(context_name) = &self.context_name {
            security = security.with_context_name(context_name);
        }
        if let Some(method) = self.key_extension {
            security = security.with_key_extension_method(method.into());
        }

        Ok(security)
    }
}

impl From<AuthProtocol> for snmp2::v3::AuthProtocol {
    fn from(protocol: AuthProtocol) -> Self {
        match protocol {
            AuthProtocol::Md5 => Self::Md5,
            AuthProtocol::Sha1 => Self::Sha1,
            AuthProtocol::Sha224 => Self::Sha224,
            AuthProtocol::Sha256 => Self::Sha256,
            AuthProtocol::Sha384 => Self::Sha384,
            AuthProtocol::Sha512 => Self::Sha512,
        }
    }
}

impl From<PrivacyProtocol> for snmp2::v3::Cipher {
    fn from(protocol: PrivacyProtocol) -> Self {
        match protocol {
            PrivacyProtocol::Des => Self::Des,
            PrivacyProtocol::Aes128 => Self::Aes128,
            PrivacyProtocol::Aes192 => Self::Aes192,
            PrivacyProtocol::Aes256 => Self::Aes256,
        }
    }
}

impl From<KeyExtension> for snmp2::v3::KeyExtension {
    fn from(method: KeyExtension) -> Self {
        match method {
            KeyExtension::Blumenthal => Self::Blumenthal,
            KeyExtension::Reeder => Self::Reeder,
        }
    }
}

const DEFAULT_PORT: u16 = 161;

/// Splits an endpoint into a host and a port.
///
/// Endpoints are parsed as URIs, like the addresses of other UDP components. Accepted forms are
/// `host`, `host:port`, `[v6]` and `[v6]:port`, each optionally prefixed with `udp://`.
pub(super) fn parse_endpoint(endpoint: &str) -> Result<(String, u16), BuildError> {
    let invalid = |reason: &str| BuildError::InvalidEndpoint {
        endpoint: endpoint.to_string(),
        reason: reason.to_string(),
    };

    let uri = endpoint
        .parse::<http::Uri>()
        .map_err(|error| invalid(&error.to_string()))?;
    if let Some(scheme) = uri.scheme_str()
        && scheme != "udp"
    {
        return Err(invalid(&format!(
            "unsupported scheme {scheme:?}, only \"udp\" is supported"
        )));
    }
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err(invalid("paths and query strings are not supported"));
    }
    // SNMP URLs (RFC 4088) carry the community before `@`. Reject it instead of ignoring it, so
    // nobody polls with a different community than they think.
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(invalid(
            "credentials are not allowed in endpoints, set `community` or `usm` instead",
        ));
    }
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| invalid("host is missing"))?;
    // `http::Uri` keeps the brackets around IPv6 addresses.
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    // `http::Uri` drops a port it cannot parse, such as `host:abc`, instead of failing.
    let authority = uri.authority().map_or("", |authority| authority.as_str());
    let after_host = authority
        .rsplit_once(']')
        .map_or(authority, |(_, rest)| rest);
    let port = match uri.port() {
        None if after_host.contains(':') => return Err(invalid("invalid port")),
        None => DEFAULT_PORT,
        Some(port) => match port.as_str().parse::<u16>() {
            Ok(0) | Err(_) => return Err(invalid(&format!("invalid port {:?}", port.as_str()))),
            Ok(port) => port,
        },
    };
    Ok((host.to_string(), port))
}
