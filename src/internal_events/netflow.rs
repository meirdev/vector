use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use metrics::{Counter, Gauge};
use vector_lib::{
    NamedInternalEvent, counter, gauge,
    internal_event::{CounterName, GaugeName, InternalEvent, LossyF64, error_stage, error_type},
};

/// Exporters the `netflow` source keeps metric handles for. Past this, the handles are dropped
/// and registered again as exporters send, so that a flood of spoofed source addresses cannot
/// grow the set without bound.
const MAX_EXPORTERS: usize = 65_536;

/// The per-exporter metrics of the `netflow` source.
///
/// The handles are registered on the first datagram from each exporter and kept, so that a
/// datagram does not look its metrics up by label.
pub(crate) struct NetflowMetrics {
    family: &'static str,
    exporters: HashMap<IpAddr, ExporterHandles>,
    protocols: HashMap<(IpAddr, &'static str), ProtocolHandles>,
}

struct ExporterHandles {
    received_packets: Counter,
    received_bytes: Counter,
    unknown_version_packets: Counter,
    last_seen: Gauge,
}

struct ProtocolHandles {
    flows_processed: Counter,
    parse_errors: Counter,
}

impl NetflowMetrics {
    /// The metrics of a source listening for `family`, such as `netflow` or `sflow`.
    pub(crate) fn new(family: &'static str) -> Self {
        Self {
            family,
            exporters: HashMap::new(),
            protocols: HashMap::new(),
        }
    }

    fn exporter(&mut self, source: IpAddr) -> &ExporterHandles {
        if self.exporters.len() >= MAX_EXPORTERS && !self.exporters.contains_key(&source) {
            self.exporters.clear();
            self.protocols.clear();
        }
        let family = self.family;
        self.exporters.entry(source).or_insert_with(|| {
            let source_ip = source.to_string();
            ExporterHandles {
                received_packets: counter!(
                    CounterName::NetflowReceivedPacketsTotal,
                    "family" => family,
                    "source_ip" => source_ip.clone(),
                ),
                received_bytes: counter!(
                    CounterName::NetflowReceivedBytesTotal,
                    "source_ip" => source_ip.clone(),
                ),
                unknown_version_packets: counter!(
                    CounterName::NetflowUnknownVersionPacketsTotal,
                    "source_ip" => source_ip.clone(),
                ),
                last_seen: gauge!(
                    GaugeName::NetflowExporterLastSeenTimestampSeconds,
                    "family" => family,
                    "source_ip" => source_ip,
                ),
            }
        })
    }

    fn protocol(&mut self, source: IpAddr, protocol: &'static str) -> &ProtocolHandles {
        if self.protocols.len() >= MAX_EXPORTERS
            && !self.protocols.contains_key(&(source, protocol))
        {
            self.protocols.clear();
        }
        self.protocols.entry((source, protocol)).or_insert_with(|| {
            let source_ip = source.to_string();
            ProtocolHandles {
                flows_processed: counter!(
                    CounterName::NetflowFlowsProcessedTotal,
                    "protocol" => protocol,
                    "source_ip" => source_ip.clone(),
                ),
                parse_errors: counter!(
                    CounterName::NetflowParseErrorsTotal,
                    "protocol" => protocol,
                    "source_ip" => source_ip,
                ),
            }
        })
    }

    /// A datagram of `bytes` from `source`, received at `time`, whether it parses or not.
    pub(crate) fn datagram_received(&mut self, source: IpAddr, bytes: usize, time: SystemTime) {
        let exporter = self.exporter(source);
        exporter.received_packets.increment(1);
        exporter.received_bytes.increment(bytes as u64);
        let seconds = time
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        exporter.last_seen.set(LossyF64(seconds));
    }

    /// Flow records of `protocol` from `source`, options records not counted.
    pub(crate) fn flows_processed(&mut self, source: IpAddr, protocol: &'static str, count: u64) {
        if count > 0 {
            self.protocol(source, protocol)
                .flows_processed
                .increment(count);
        }
    }

    /// A datagram of `protocol` from `source` that could not be parsed.
    pub(crate) fn parse_error(&mut self, source: IpAddr, protocol: &'static str) {
        self.protocol(source, protocol).parse_errors.increment(1);
    }

    /// A datagram from `source` whose version is not of the family listened for.
    pub(crate) fn unknown_version(&mut self, source: IpAddr) {
        self.exporter(source).unknown_version_packets.increment(1);
    }
}

#[derive(Debug, NamedInternalEvent)]
pub(crate) struct NetflowParseError<'a, E> {
    pub exporter: SocketAddr,
    pub protocol: &'static str,
    pub error_code: &'static str,
    pub error: &'a E,
}

impl<E: std::fmt::Display> InternalEvent for NetflowParseError<'_, E> {
    fn emit(self) {
        error!(
            message = "Failed to parse flow datagram.",
            exporter = %self.exporter,
            protocol = self.protocol,
            error = %self.error,
            error_code = self.error_code,
            error_type = error_type::PARSER_FAILED,
            stage = error_stage::PROCESSING,
        );
        counter!(
            CounterName::ComponentErrorsTotal,
            "error_code" => self.error_code,
            "error_type" => error_type::PARSER_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}

#[derive(Debug, NamedInternalEvent)]
pub(crate) struct NetflowUnknownVersionError<'a, E> {
    pub exporter: SocketAddr,
    pub family: &'static str,
    pub error: &'a E,
}

impl<E: std::fmt::Display> InternalEvent for NetflowUnknownVersionError<'_, E> {
    fn emit(self) {
        error!(
            message = "Received a datagram of an unknown flow protocol version.",
            exporter = %self.exporter,
            family = self.family,
            error = %self.error,
            error_code = "unknown_version",
            error_type = error_type::PARSER_FAILED,
            stage = error_stage::PROCESSING,
        );
        counter!(
            CounterName::ComponentErrorsTotal,
            "error_code" => "unknown_version",
            "error_type" => error_type::PARSER_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}
