use std::net::SocketAddr;

use futures::{Stream, StreamExt};
use rustflow_core_new::protocol::information_element::iana;
use tokio::{net::UdpSocket, time::Duration};
use vector_lib::{
    config::LogNamespace,
    event::{Event, EventStatus, into_event_stream},
    lookup::{event_path, owned_value_path, path},
    metrics::Controller,
};
use vrl::value::Value;

use super::*;
use crate::{
    config::SourceContext,
    test_util::{
        addr::next_addr,
        collect_n, collect_ready,
        components::{
            COMPONENT_ERROR_TAGS, SOCKET_PUSH_SOURCE_TAGS, assert_source_compliance,
            assert_source_error,
        },
    },
};

/// The exporter the tests send from.
const EXPORTER: &str = "127.0.0.1";

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<NetflowConfig>();
}

#[test]
fn config_defaults_and_options() {
    let config: NetflowConfig = serde_yaml::from_str(indoc::indoc! {r"
        address: 0.0.0.0:6343
        family: sflow
        format: common
        template_timeout_secs: 600
        pending:
          max_bytes: 4096
        custom_elements:
          - enterprise_number: 35632
            id: 80
            name: ntopL7Protocol
            data_type: unsigned16
    "})
    .unwrap();

    assert_eq!(config.family, FlowFamily::Sflow);
    assert_eq!(config.format, RecordFormat::Common);
    assert_eq!(config.template_timeout_secs, Duration::from_mins(10));
    let pending = config.pending.unwrap();
    assert_eq!(pending.max_bytes, 4096);
    assert_eq!(pending.max_age_secs, default_pending_max_age());
    let registry = config.registry();
    let element = registry.get(ElementId::from((35632, 80))).unwrap();
    assert_eq!(element.name, "ntopL7Protocol");
    assert_eq!(element.data_type, DataType::Unsigned16);
}

fn words(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// A NetFlow v5 datagram of one TCP flow, `192.0.2.1:443` to `198.51.100.2:51000`, of 10 packets
/// and 1500 octets.
fn netflow_v5() -> Vec<u8> {
    let header = [
        words(&[5, 1]),
        3_600_000u32.to_be_bytes().to_vec(),     // sysUptime
        1_700_000_000u32.to_be_bytes().to_vec(), // unix_secs
        0u32.to_be_bytes().to_vec(),             // unix_nsecs
        42u32.to_be_bytes().to_vec(),            // flow_sequence
        vec![0, 0],                              // engine type and id
        0u16.to_be_bytes().to_vec(),             // sampling interval
    ]
    .concat();
    let flow = [
        vec![192, 0, 2, 1],                  // srcaddr
        vec![198, 51, 100, 2],               // dstaddr
        vec![0, 0, 0, 0],                    // nexthop
        words(&[1, 2]),                      // input, output
        10u32.to_be_bytes().to_vec(),        // dPkts
        1_500u32.to_be_bytes().to_vec(),     // dOctets
        3_590_000u32.to_be_bytes().to_vec(), // first
        3_599_000u32.to_be_bytes().to_vec(), // last
        words(&[443, 51_000]),               // srcport, dstport
        vec![0, 0x12, 6, 0],                 // pad1, tcp_flags, prot, tos
        words(&[64_500, 64_501]),            // src_as, dst_as
        vec![24, 24, 0, 0],                  // src_mask, dst_mask, pad2
    ]
    .concat();
    assert_eq!(flow.len(), 48);
    [header, flow].concat()
}

fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(4 + body.len()).unwrap();
    [&words(&[id, length])[..], body].concat()
}

fn ipfix(sets: &[Vec<u8>]) -> Vec<u8> {
    let body = sets.concat();
    let length = u16::try_from(16 + body.len()).unwrap();
    [
        words(&[10, length]),
        1_700_000_000u32.to_be_bytes().to_vec(),
        7u32.to_be_bytes().to_vec(),
        1u32.to_be_bytes().to_vec(),
        body,
    ]
    .concat()
}

/// An IPFIX datagram with a template, a flow of it, an options template for interface names and
/// an options record of it. The template has an enterprise element, ntop's 35632/80 in two bytes.
fn ipfix_with_options() -> Vec<u8> {
    let template = set(
        2,
        &[
            words(&[256, 3]),
            words(&[iana::SOURCE_IPV4_ADDRESS.id, 4]),
            words(&[iana::OCTET_DELTA_COUNT.id, 8]),
            words(&[0x8000 | 0x50, 2]),
            35_632u32.to_be_bytes().to_vec(),
        ]
        .concat(),
    );
    let flow = set(
        256,
        &[
            vec![192, 0, 2, 1],
            1_500u64.to_be_bytes().to_vec(),
            7u16.to_be_bytes().to_vec(),
        ]
        .concat(),
    );
    let options_template = set(
        3,
        &words(&[
            257,
            2,
            1,
            iana::INGRESS_INTERFACE.id,
            4,
            iana::INTERFACE_NAME.id,
            8,
        ]),
    );
    let options = set(
        257,
        &[3u32.to_be_bytes().to_vec(), b"eth0\0\0\0\0".to_vec()].concat(),
    );
    ipfix(&[template, flow, options_template, options])
}

struct Running {
    address: SocketAddr,
    events: Box<dyn Stream<Item = Event> + Unpin + Send>,
    options: Box<dyn Stream<Item = Event> + Unpin + Send>,
}

async fn start(configure: impl FnOnce(&mut NetflowConfig)) -> Running {
    let (guard, address) = next_addr();
    let mut config = NetflowConfig::from_address(address.into());
    configure(&mut config);

    let (mut sender, events) = SourceSender::new_test();
    let options = sender
        .add_outputs(EventStatus::Delivered, OPTIONS_OUTPUT.to_owned())
        .flat_map(into_event_stream);
    let source = config
        .build(SourceContext::new_test(sender, None))
        .await
        .unwrap();
    tokio::spawn(source);
    // Wait for the socket to be bound.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(guard);

    Running {
        address,
        events: Box::new(events),
        options: Box::new(options),
    }
}

async fn send(to: SocketAddr, datagrams: &[Vec<u8>]) {
    let socket = UdpSocket::bind((EXPORTER, 0)).await.unwrap();
    for datagram in datagrams {
        socket.send_to(datagram, to).await.unwrap();
    }
}

#[tokio::test]
async fn netflow_v5_flow_as_ipfix_elements() {
    let event = assert_source_compliance(&SOCKET_PUSH_SOURCE_TAGS, async {
        let mut running = start(|_| {}).await;
        send(running.address, &[netflow_v5()]).await;
        collect_n(&mut running.events, 1).await.remove(0)
    })
    .await;

    let log = event.as_log();
    assert_eq!(log["sourceIPv4Address"], "192.0.2.1".into());
    assert_eq!(log["destinationIPv4Address"], "198.51.100.2".into());
    assert_eq!(log["sourceTransportPort"], 443.into());
    assert_eq!(log["protocolIdentifier"], 6.into());
    assert_eq!(log["octetDeltaCount"], 1_500.into());
    assert_eq!(log["packetDeltaCount"], 10.into());
    assert_eq!(log["bgpSourceAsNumber"], 64_500.into());
    // The uptime-relative times are made absolute: the flow ended a second before export.
    assert_eq!(
        log["flowEndMilliseconds"],
        Value::Timestamp(DateTime::from_timestamp(1_699_999_999, 0).unwrap())
    );
    assert_eq!(log["originalExporterIPv4Address"], EXPORTER.into());
    assert!(log.contains(event_path!("collectionTimeMilliseconds")));
    assert_eq!(log["host"], EXPORTER.into());
    assert_eq!(log["flow_type"], "netflow_v5".into());
    assert_eq!(log["source_type"], "netflow".into());
    assert!(log.contains(event_path!("timestamp")));
}

#[tokio::test]
async fn netflow_v5_flow_as_common_fields() {
    let mut running = start(|config| config.format = RecordFormat::Common).await;
    send(running.address, &[netflow_v5()]).await;
    let event = collect_n(&mut running.events, 1).await.remove(0);

    let log = event.as_log();
    assert_eq!(log["flow_type"], "netflow_v5".into());
    assert_eq!(log["sequence_num"], 42.into());
    assert_eq!(log["src_addr"], "192.0.2.1".into());
    assert_eq!(log["dst_addr"], "198.51.100.2".into());
    assert_eq!(log["src_port"], 443.into());
    assert_eq!(log["dst_port"], 51_000.into());
    assert_eq!(log["proto"], 6.into());
    assert_eq!(log["bytes"], 1_500.into());
    assert_eq!(log["packets"], 10.into());
    assert_eq!(log["src_as"], 64_500.into());
    assert_eq!(log["sampler_address"], EXPORTER.into());
    assert_eq!(
        log["time_flow_end"],
        Value::Timestamp(DateTime::from_timestamp(1_699_999_999, 0).unwrap())
    );
    assert!(!log.contains(event_path!("sourceIPv4Address")));
    assert_eq!(log["host"], EXPORTER.into());
}

#[tokio::test]
async fn ipfix_options_records_go_to_their_own_output() {
    let mut running = start(|config| {
        config.custom_elements.push(CustomElement {
            enterprise_number: 35_632,
            id: 80,
            name: "ntopL7Protocol".to_owned(),
            data_type: ElementDataType::Unsigned16,
        });
    })
    .await;
    send(running.address, &[ipfix_with_options()]).await;

    let flow = collect_n(&mut running.events, 1).await.remove(0);
    let flow = flow.as_log();
    assert_eq!(flow["sourceIPv4Address"], "192.0.2.1".into());
    assert_eq!(flow["octetDeltaCount"], 1_500.into());
    assert_eq!(flow["ntopL7Protocol"], 7.into());
    assert_eq!(flow["originalObservationDomainId"], 1.into());
    assert_eq!(flow["flow_type"], "ipfix".into());

    let options = collect_n(&mut running.options, 1).await.remove(0);
    let options = options.as_log();
    assert_eq!(options["ingressInterface"], 3.into());
    assert_eq!(options["interfaceName"], "eth0".into());
    assert_eq!(options["flow_type"], "ipfix".into());
    assert!(collect_ready(&mut running.events).is_empty());
}

#[tokio::test]
async fn vector_namespace_puts_the_exporter_in_metadata() {
    let mut running = start(|config| config.log_namespace = Some(true)).await;
    send(running.address, &[netflow_v5()]).await;
    let event = collect_n(&mut running.events, 1).await.remove(0);

    let log = event.as_log();
    assert_eq!(log["sourceIPv4Address"], "192.0.2.1".into());
    assert!(!log.contains(event_path!("host")));
    assert!(!log.contains(event_path!("source_type")));
    let meta = log.metadata().value();
    assert_eq!(
        meta.get(path!(NetflowConfig::NAME, "host")).unwrap(),
        &Value::from(EXPORTER)
    );
    assert_eq!(
        meta.get(path!(NetflowConfig::NAME, "flow_type")).unwrap(),
        &Value::from("netflow_v5")
    );
    assert_eq!(
        meta.get(path!("vector", "source_type")).unwrap(),
        &Value::from("netflow")
    );
    assert!(meta.get(path!("vector", "ingest_timestamp")).is_some());
}

#[tokio::test]
async fn host_key_can_be_renamed() {
    let mut running = start(|config| {
        config.host_key = Some(OptionalValuePath::from(owned_value_path!("exporter")));
    })
    .await;
    send(running.address, &[netflow_v5()]).await;
    let event = collect_n(&mut running.events, 1).await.remove(0);

    assert_eq!(event.as_log()["exporter"], EXPORTER.into());
    assert!(!event.as_log().contains(event_path!("host")));
}

#[tokio::test]
async fn unknown_versions_are_component_errors_and_the_source_goes_on() {
    assert_source_error(&COMPONENT_ERROR_TAGS, async {
        let mut running = start(|_| {}).await;
        send(running.address, &[vec![0, 4, 0, 0], netflow_v5()]).await;
        let event = collect_n(&mut running.events, 1).await.remove(0);
        assert_eq!(event.as_log()["sourceIPv4Address"], "192.0.2.1".into());
    })
    .await;
}

#[tokio::test]
async fn malformed_datagrams_are_component_errors_and_the_source_goes_on() {
    assert_source_error(&COMPONENT_ERROR_TAGS, async {
        let mut running = start(|_| {}).await;
        let mut truncated = netflow_v5();
        truncated.truncate(40);
        send(running.address, &[truncated, netflow_v5()]).await;
        let event = collect_n(&mut running.events, 1).await.remove(0);
        assert_eq!(event.as_log()["sourceIPv4Address"], "192.0.2.1".into());
    })
    .await;
}

/// Reads global metrics, so needs a process of its own, as `cargo nextest` gives each test.
#[tokio::test]
async fn exporter_metrics() {
    crate::test_util::components::init_test();
    let mut running = start(|_| {}).await;
    let mut truncated = netflow_v5();
    truncated.truncate(40);
    send(
        running.address,
        &[vec![0, 4, 0, 0], truncated, netflow_v5()],
    )
    .await;
    collect_n(&mut running.events, 1).await;

    let metrics = Controller::get().unwrap().capture_metrics();
    let counter = |name: &str, tags: &[(&str, &str)]| {
        metrics
            .iter()
            .find(|metric| {
                metric.name() == name
                    && tags
                        .iter()
                        .all(|(key, value)| metric.tag_value(key).as_deref() == Some(*value))
            })
            .map(|metric| match metric.value() {
                vector_lib::event::MetricValue::Counter { value }
                | vector_lib::event::MetricValue::Gauge { value } => *value,
                other => panic!("unexpected metric value {other:?}"),
            })
    };
    let source_ip = [("source_ip", EXPORTER)];
    assert_eq!(
        counter(
            "netflow_received_packets_total",
            &[("family", "netflow"), source_ip[0]]
        ),
        Some(3.0)
    );
    assert_eq!(
        counter("netflow_received_bytes_total", &source_ip),
        Some(f64::from(4 + 40 + 72))
    );
    assert_eq!(
        counter("netflow_unknown_version_packets_total", &source_ip),
        Some(1.0)
    );
    assert_eq!(
        counter(
            "netflow_parse_errors_total",
            &[("protocol", "netflow_v5"), source_ip[0]]
        ),
        Some(1.0)
    );
    assert_eq!(
        counter(
            "netflow_flows_processed_total",
            &[("protocol", "netflow_v5"), source_ip[0]]
        ),
        Some(1.0)
    );
    assert!(
        counter(
            "netflow_exporter_last_seen_timestamp_seconds",
            &[("family", "netflow"), source_ip[0]]
        )
        .unwrap()
            > 1_700_000_000.0
    );
    assert_eq!(
        counter(
            "component_errors_total",
            &[("error_code", "unknown_version")]
        ),
        Some(1.0)
    );
    assert_eq!(
        counter("component_errors_total", &[("error_code", "truncated")]),
        Some(1.0)
    );
}

#[test]
fn output_schema_definitions() {
    let config = NetflowConfig::from_address(SocketListenAddr::SocketAddr(
        "0.0.0.0:2055".parse().unwrap(),
    ));
    for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
        let outputs = config.outputs(namespace);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].port, None);
        assert_eq!(outputs[1].port.as_deref(), Some(OPTIONS_OUTPUT));
    }
}
