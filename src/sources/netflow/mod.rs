//! The `netflow` source: flow records from NetFlow v5, NetFlow v9, IPFIX, and sFlow v5 exporters,
//! received over UDP and decoded with `rustflow`.

use std::{
    borrow::Cow,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use listenfd::ListenFd;
use rustflow_core_new::{
    convert::CommonFlow,
    protocol::{
        Family, ParseError, Protocol,
        information_element::{DataType, ElementId, InformationElement, Registry},
    },
    reader::{Collector, PendingLimits, Received, Record},
};
use serde_with::serde_as;
use vector_lib::{
    EstimatedJsonEncodedSizeOf,
    config::{LegacyKey, LogNamespace},
    configurable::configurable_component,
    internal_event::{
        ByteSize, BytesReceived, CountByteSize, EventsReceived, InternalEventHandle as _,
        Protocol as TransportProtocol,
    },
    lookup::{OwnedValuePath, lookup_v2::OptionalValuePath, owned_value_path, path},
    schema::Definition,
};
use vrl::value::{Kind, kind::Collection};

use self::event::{common_flow_object, elements_object, protocol_name};
use super::util::net::{SocketListenAddr, try_bind_udp_socket};
use crate::{
    SourceSender,
    config::{
        DataType as EventDataType, GenerateConfig, Resource, SourceConfig, SourceContext,
        SourceOutput, log_schema,
    },
    event::LogEvent,
    internal_events::{
        NetflowMetrics, NetflowParseError, NetflowUnknownVersionError, SocketBindError, SocketMode,
        SocketReceiveError, StreamClosedError,
    },
    net,
    shutdown::ShutdownSignal,
    sources::SourceError,
};

mod event;

/// The output options records are sent to.
pub const OPTIONS_OUTPUT: &str = "options";

/// The largest UDP payload.
const MAX_DATAGRAM_LENGTH: usize = 65_535;

/// Configuration for the `netflow` source.
#[serde_as]
#[configurable_component(source(
    "netflow",
    "Collect flow records from NetFlow, IPFIX, and sFlow exporters."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct NetflowConfig {
    address: SocketListenAddr,

    #[serde(default)]
    family: FlowFamily,

    #[serde(default)]
    format: RecordFormat,

    /// The time, in seconds, a NetFlow v9 or IPFIX template is kept after it was last received.
    ///
    /// Data that arrives after its template has expired cannot be decoded until the exporter
    /// sends the template again. Exporters resend their templates periodically; this should be
    /// longer than that interval.
    #[serde(default = "default_template_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[configurable(metadata(docs::human_name = "Template Timeout"))]
    template_timeout_secs: Duration,

    pending: Option<PendingConfig>,

    /// Information elements to decode besides IANA's, such as an exporter's enterprise-specific
    /// elements.
    ///
    /// An element of an enterprise number and ID that IANA's registry or an earlier entry already
    /// has replaces it. Elements not listed are decoded as octet arrays and named by their
    /// number, such as `(35632/80)`.
    #[serde(default)]
    custom_elements: Vec<CustomElement>,

    /// The size of the receive buffer used for the listening socket.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    receive_buffer_bytes: Option<usize>,

    /// Overrides the name of the log field used to add the exporter's IP address to each event.
    ///
    /// By default, the [global `log_schema.host_key` option][global_host_key] is used.
    ///
    /// Set to `""` to suppress this key.
    ///
    /// [global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
    host_key: Option<OptionalValuePath>,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    log_namespace: Option<bool>,
}

/// The flow protocols to listen for.
///
/// NetFlow and IPFIX share the version field at the start of a datagram, so one port serves all
/// three; sFlow has a port of its own.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowFamily {
    /// NetFlow v5, NetFlow v9, and IPFIX, told apart by the version of each datagram.
    #[default]
    Netflow,

    /// sFlow v5.
    Sflow,
}

impl FlowFamily {
    const fn family(self) -> Family {
        match self {
            Self::Netflow => Family::Netflow,
            Self::Sflow => Family::Sflow,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Netflow => "netflow",
            Self::Sflow => "sflow",
        }
    }
}

/// The fields of the events flow records are decoded into.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordFormat {
    /// The record's IPFIX information elements, keyed by name, such as `sourceIPv4Address` and
    /// `octetDeltaCount`, whatever protocol the flow arrived in.
    ///
    /// Every element the exporter sent is kept, along with the elements the collector adds:
    /// the exporter's address, the collection time, absolute flow start and end times, and the
    /// sampling the exporter stated.
    #[default]
    Ipfix,

    /// A fixed set of fields, such as `src_addr`, `dst_port`, `bytes`, and `sampling_rate`, mapped
    /// from the record's elements whatever protocol the flow arrived in.
    ///
    /// Elements outside that set are left out.
    Common,
}

/// Holds NetFlow v9 and IPFIX data that arrives before its template.
///
/// When set, data sets whose template has not been received yet are held, and decoded once the
/// template arrives. When not set, such data is dropped. Data held past either limit is dropped.
///
/// An exporter that reuses a template ID for another template while data for the old one is held
/// gets that data decoded with the new template; a short `max_age_secs` narrows that window.
#[serde_as]
#[configurable_component]
#[derive(Clone, Copy, Debug)]
#[serde(deny_unknown_fields)]
pub struct PendingConfig {
    /// The maximum size of the datagrams held for each protocol of an exporter.
    #[serde(default = "default_pending_max_bytes")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    max_bytes: usize,

    /// The maximum time, in seconds, a datagram is held waiting for its template.
    #[serde(default = "default_pending_max_age")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[configurable(metadata(docs::human_name = "Maximum Age"))]
    max_age_secs: Duration,
}

/// An information element to decode, such as an exporter's enterprise-specific element.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CustomElement {
    /// The private enterprise number of the vendor that defines the element.
    ///
    /// `0` stands for IANA, for an element IANA's registry does not have yet.
    #[configurable(metadata(docs::examples = 35632))]
    enterprise_number: u32,

    /// The element's ID within its enterprise.
    #[configurable(metadata(docs::examples = 80))]
    id: u16,

    /// The name the element's values are keyed by.
    #[configurable(metadata(docs::examples = "ntopL7Protocol"))]
    name: String,

    data_type: ElementDataType,
}

/// The data type of an information element's values, as IANA's IPFIX data types registry names
/// them.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ElementDataType {
    /// Bytes, written as hexadecimal.
    OctetArray,
    /// An unsigned 8-bit integer.
    Unsigned8,
    /// An unsigned 16-bit integer.
    Unsigned16,
    /// An unsigned 32-bit integer.
    Unsigned32,
    /// An unsigned 64-bit integer.
    Unsigned64,
    /// A signed 8-bit integer.
    Signed8,
    /// A signed 16-bit integer.
    Signed16,
    /// A signed 32-bit integer.
    Signed32,
    /// A signed 64-bit integer.
    Signed64,
    /// A single-precision floating-point number.
    Float32,
    /// A double-precision floating-point number.
    Float64,
    /// A boolean.
    Boolean,
    /// A MAC address.
    MacAddress,
    /// A UTF-8 string.
    String,
    /// A time, in seconds since the UNIX epoch.
    DateTimeSeconds,
    /// A time, in milliseconds since the UNIX epoch.
    DateTimeMilliseconds,
    /// A time, as an NTP timestamp of microsecond precision.
    DateTimeMicroseconds,
    /// A time, as an NTP timestamp of nanosecond precision.
    DateTimeNanoseconds,
    /// An IPv4 address.
    Ipv4Address,
    /// An IPv6 address.
    Ipv6Address,
}

impl From<ElementDataType> for DataType {
    fn from(data_type: ElementDataType) -> Self {
        match data_type {
            ElementDataType::OctetArray => Self::OctetArray,
            ElementDataType::Unsigned8 => Self::Unsigned8,
            ElementDataType::Unsigned16 => Self::Unsigned16,
            ElementDataType::Unsigned32 => Self::Unsigned32,
            ElementDataType::Unsigned64 => Self::Unsigned64,
            ElementDataType::Signed8 => Self::Signed8,
            ElementDataType::Signed16 => Self::Signed16,
            ElementDataType::Signed32 => Self::Signed32,
            ElementDataType::Signed64 => Self::Signed64,
            ElementDataType::Float32 => Self::Float32,
            ElementDataType::Float64 => Self::Float64,
            ElementDataType::Boolean => Self::Boolean,
            ElementDataType::MacAddress => Self::MacAddress,
            ElementDataType::String => Self::String,
            ElementDataType::DateTimeSeconds => Self::DateTimeSeconds,
            ElementDataType::DateTimeMilliseconds => Self::DateTimeMilliseconds,
            ElementDataType::DateTimeMicroseconds => Self::DateTimeMicroseconds,
            ElementDataType::DateTimeNanoseconds => Self::DateTimeNanoseconds,
            ElementDataType::Ipv4Address => Self::Ipv4Address,
            ElementDataType::Ipv6Address => Self::Ipv6Address,
        }
    }
}

const fn default_template_timeout() -> Duration {
    Duration::from_mins(30)
}

const fn default_pending_max_bytes() -> usize {
    1024 * 1024
}

const fn default_pending_max_age() -> Duration {
    Duration::from_mins(1)
}

impl NetflowConfig {
    /// A configuration listening on `address` with every other option at its default.
    #[must_use]
    pub const fn from_address(address: SocketListenAddr) -> Self {
        Self {
            address,
            family: FlowFamily::Netflow,
            format: RecordFormat::Ipfix,
            template_timeout_secs: default_template_timeout(),
            pending: None,
            custom_elements: Vec::new(),
            receive_buffer_bytes: None,
            host_key: None,
            log_namespace: None,
        }
    }

    fn host_key(&self) -> Option<OwnedValuePath> {
        self.host_key
            .clone()
            .map_or_else(|| log_schema().host_key().cloned(), |key| key.path)
    }

    fn registry(&self) -> Registry {
        let mut registry = Registry::iana();
        for element in &self.custom_elements {
            registry.insert(InformationElement {
                id: ElementId::from((element.enterprise_number, element.id)),
                name: Cow::Owned(element.name.clone()),
                data_type: element.data_type.into(),
                semantics: None,
            });
        }
        registry
    }

    fn collector(&self, registry: Registry) -> Collector {
        let collector = Collector::new(self.family.family(), registry, self.template_timeout_secs);
        match self.pending {
            Some(pending) => collector.with_pending(PendingLimits {
                session_bytes: pending.max_bytes,
                max_age: pending.max_age_secs,
            }),
            None => collector,
        }
    }

    fn schema_definition(&self, log_namespace: LogNamespace) -> Definition {
        let host_key = self.host_key().map(LegacyKey::InsertIfEmpty);
        Definition::new_with_default_metadata(
            Kind::object(Collection::from_unknown(Kind::any())),
            [log_namespace],
        )
        .with_standard_vector_source_metadata()
        .with_source_metadata(
            Self::NAME,
            host_key,
            &owned_value_path!("host"),
            Kind::bytes(),
            Some("host"),
        )
        .with_source_metadata(
            Self::NAME,
            Some(LegacyKey::InsertIfEmpty(owned_value_path!("flow_type"))),
            &owned_value_path!("flow_type"),
            Kind::bytes(),
            None,
        )
    }
}

impl GenerateConfig for NetflowConfig {
    fn generate_config() -> serde_json::Value {
        serde_json::to_value(Self::from_address(SocketListenAddr::SocketAddr(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 2055)),
        )))
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "netflow")]
impl SourceConfig for NetflowConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<super::Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);
        let registry = self.registry();
        let source = NetflowSource {
            address: self.address,
            receive_buffer_bytes: self.receive_buffer_bytes,
            family: self.family,
            collector: self.collector(registry.clone()),
            events: EventBuilder {
                format: self.format,
                registry,
                host_key: self.host_key(),
                log_namespace,
            },
        };
        Ok(Box::pin(source.run(cx.shutdown, cx.out)))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);
        let schema_definition = self.schema_definition(log_namespace);
        vec![
            SourceOutput::new_maybe_logs(EventDataType::Log, schema_definition.clone()),
            SourceOutput::new_maybe_logs(EventDataType::Log, schema_definition)
                .with_port(OPTIONS_OUTPUT),
        ]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![self.address.as_udp_resource()]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

struct NetflowSource {
    address: SocketListenAddr,
    receive_buffer_bytes: Option<usize>,
    family: FlowFamily,
    collector: Collector,
    events: EventBuilder,
}

/// What a flow record's event is made of besides the record.
struct EventBuilder {
    format: RecordFormat,
    registry: Registry,
    host_key: Option<OwnedValuePath>,
    log_namespace: LogNamespace,
}

impl EventBuilder {
    /// The event of `record`, received from `exporter` at `received`. Options records keep their
    /// elements whatever the format, as the common fields describe flows alone.
    fn build(&self, record: &Record, exporter: SocketAddr, received: DateTime<Utc>) -> LogEvent {
        let object = match self.format {
            RecordFormat::Common if !record.is_options() => {
                common_flow_object(&CommonFlow::from(record))
            }
            _ => elements_object(record, &self.registry, received.timestamp()),
        };
        let mut log = LogEvent::from(object);
        self.log_namespace.insert_standard_vector_source_metadata(
            &mut log,
            NetflowConfig::NAME,
            received,
        );
        self.log_namespace.insert_source_metadata(
            NetflowConfig::NAME,
            &mut log,
            self.host_key.as_ref().map(LegacyKey::InsertIfEmpty),
            path!("host"),
            exporter.ip().to_string(),
        );
        self.log_namespace.insert_source_metadata(
            NetflowConfig::NAME,
            &mut log,
            Some(LegacyKey::InsertIfEmpty(path!("flow_type"))),
            path!("flow_type"),
            protocol_name(record),
        );
        log
    }
}

impl NetflowSource {
    async fn run(
        mut self,
        mut shutdown: ShutdownSignal,
        mut out: SourceSender,
    ) -> Result<(), SourceError> {
        let socket = try_bind_udp_socket(self.address, ListenFd::from_env())
            .await
            .map_err(|error| {
                emit!(SocketBindError {
                    mode: SocketMode::Udp,
                    error: &error,
                });
                SourceError::from(error)
            })?;
        if let Some(receive_buffer_bytes) = self.receive_buffer_bytes
            && let Err(error) = net::set_receive_buffer_size(&socket, receive_buffer_bytes)
        {
            warn!(message = "Failed configuring receive buffer size on UDP socket.", %error);
        }
        info!(message = "Listening.", address = %self.address);

        let bytes_received = register!(BytesReceived::from(TransportProtocol::UDP));
        let events_received = register!(EventsReceived);
        let mut metrics = NetflowMetrics::new(self.family.name());
        let mut buf = vec![0; MAX_DATAGRAM_LENGTH];
        let mut records = Vec::new();

        loop {
            let (length, exporter) = tokio::select! {
                received = socket.recv_from(&mut buf) => match received {
                    Ok(received) => received,
                    Err(error) => {
                        emit!(SocketReceiveError {
                            mode: SocketMode::Udp,
                            error: &error,
                        });
                        return Err(SourceError::from(error));
                    }
                },
                _ = &mut shutdown => return Ok(()),
            };
            let time = SystemTime::now();
            bytes_received.emit(ByteSize(length));
            metrics.datagram_received(exporter.ip(), length, time);

            records.clear();
            self.collect(&buf[..length], exporter, time, &mut records, &mut metrics);
            if records.is_empty() {
                continue;
            }

            let received = DateTime::<Utc>::from(time);
            let (options, flows): (Vec<_>, Vec<_>) =
                records.iter().partition(|record| record.is_options());
            for (protocol, count) in count_by_protocol(&flows) {
                metrics.flows_processed(exporter.ip(), protocol, count);
            }
            let flows: Vec<_> = flows
                .into_iter()
                .map(|record| self.events.build(record, exporter, received))
                .collect();
            let options: Vec<_> = options
                .into_iter()
                .map(|record| self.events.build(record, exporter, received))
                .collect();
            events_received.emit(CountByteSize(
                flows.len() + options.len(),
                flows.estimated_json_encoded_size_of() + options.estimated_json_encoded_size_of(),
            ));

            if !send(&mut out, None, flows, &mut shutdown).await
                || !send(&mut out, Some(OPTIONS_OUTPUT), options, &mut shutdown).await
            {
                return Ok(());
            }
        }
    }

    /// Decodes a datagram, adding its records to `records` and counting what went wrong.
    fn collect(
        &mut self,
        datagram: &[u8],
        exporter: SocketAddr,
        time: SystemTime,
        records: &mut Vec<Record>,
        metrics: &mut NetflowMetrics,
    ) {
        let protocol = match Protocol::of(self.family.family(), datagram) {
            Ok(protocol) => protocol,
            Err(error) => {
                metrics.unknown_version(exporter.ip());
                emit!(NetflowUnknownVersionError {
                    exporter,
                    family: self.family.name(),
                    error: &error,
                });
                return;
            }
        };
        let received = Received {
            exporter,
            time: Some(time),
        };
        if let Err(error) = self.collector.collect(received, datagram, records) {
            let protocol = event::protocol_of(protocol);
            metrics.parse_error(exporter.ip(), protocol);
            emit!(NetflowParseError {
                exporter,
                protocol,
                error_code: error_code(&error),
                error: &error,
            });
        }
    }
}

/// How many of `flows` are of each protocol. A datagram's flows are of its protocol, but held
/// data released along with them need not be counted alike.
fn count_by_protocol(flows: &[&Record]) -> Vec<(&'static str, u64)> {
    let mut counts: Vec<(&'static str, u64)> = Vec::new();
    for flow in flows {
        let protocol = protocol_name(flow);
        match counts.iter_mut().find(|(known, _)| *known == protocol) {
            Some((_, count)) => *count += 1,
            None => counts.push((protocol, 1)),
        }
    }
    counts
}

/// Sends `events` to `output`, the default output if `None`; `false` once the source should stop.
async fn send(
    out: &mut SourceSender,
    output: Option<&str>,
    events: Vec<LogEvent>,
    shutdown: &mut ShutdownSignal,
) -> bool {
    if events.is_empty() {
        return true;
    }
    let count = events.len();
    let sent = async {
        match output {
            Some(output) => out.send_batch_named(output, events).await,
            None => out.send_batch(events).await,
        }
    };
    tokio::select! {
        result = sent => {
            if result.is_err() {
                emit!(StreamClosedError { count });
                return false;
            }
            true
        }
        _ = shutdown => false,
    }
}

/// A bounded error code for a parse error, to tag metrics with.
const fn error_code(error: &ParseError) -> &'static str {
    match error {
        ParseError::Truncated(_) => "truncated",
        ParseError::Version(_) => "unexpected_version",
        ParseError::SetLength(_) => "invalid_set_length",
        ParseError::TemplateId(_) => "reserved_template_id",
        ParseError::MessageLength(_) => "invalid_message_length",
        ParseError::ScopeFieldCount(_) => "invalid_scope_field_count",
        ParseError::AddressType(_) => "unknown_address_type",
        ParseError::AsPathSegmentType(_) => "unknown_as_path_segment_type",
        ParseError::Utf8 => "invalid_utf8",
    }
}

#[cfg(test)]
mod tests;
