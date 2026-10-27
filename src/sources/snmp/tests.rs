#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_pass_by_value,
    clippy::cast_precision_loss,
    reason = "The fake agent encodes small, known values."
)]

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use tokio::net::UdpSocket;
use vector_lib::EstimatedJsonEncodedSizeOf;

use super::{
    SnmpConfig,
    config::{BuildError, parse_endpoint},
};
use crate::{
    SourceSender,
    config::{SourceConfig, SourceContext},
    event::{Event, MetricValue},
    shutdown::ShutdownSignal,
    test_util::components::{
        COMPONENT_ERROR_TAGS, PULL_SOURCE_TAGS, run_and_assert_source_compliance,
        run_and_assert_source_error,
    },
};

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<SnmpConfig>();
}

fn parse(yaml: &str) -> SnmpConfig {
    serde_yaml::from_str(yaml).expect("config should parse")
}

#[test]
fn parses_full_config() {
    let config = parse(
        r#"
endpoints: ["udp://10.0.0.1:161", "10.0.0.2"]
scrape_interval_secs: 30
scrape_timeout_secs: 2.5
retries: 1
version: v3
max_repetitions: 25
usm:
  username: monitor
  security_level: auth_priv
  auth_protocol: sha256
  auth_password: authpass123
  privacy_protocol: aes128
  privacy_password: privpass123
  context_name: ctx
namespace: network
endpoint_tag: device
tags:
  site: dc1
fields:
  - name: uptime
    oid: 1.3.6.1.2.1.1.3.0
  - name: sys_name
    oid: .1.3.6.1.2.1.1.5.0
    is_tag: true
  - name: temperature
    oid: 1.3.6.1.4.1.9.9.13.1.3.1.3.1
    scale: 0.1
tables:
  - name: interface
    inherit_tags: [sys_name]
    columns:
      - name: if_descr
        oid: 1.3.6.1.2.1.2.2.1.2
        is_tag: true
      - name: mac
        oid: 1.3.6.1.2.1.2.2.1.6
        is_tag: true
        conversion: hwaddr
      - name: in_octets
        oid: 1.3.6.1.2.1.31.1.1.1.6
      - name: oper_status
        oid: 1.3.6.1.2.1.2.2.1.8
        metric_type: gauge
"#,
    );
    assert_eq!(config.scrape_interval, Duration::from_secs(30));
    assert_eq!(config.scrape_timeout, Duration::from_millis(2500));

    let plan = config.plan().expect("plan should be valid");
    assert_eq!(plan.namespace.as_deref(), Some("network"));
    assert_eq!(plan.endpoint_tag.as_deref(), Some("device"));
    assert_eq!(plan.fields.len(), 3);
    assert_eq!(plan.fields[1].oid, vec![1, 3, 6, 1, 2, 1, 1, 5, 0]);
    assert_eq!(plan.tables[0].index_tag.as_deref(), Some("index"));
    assert_eq!(plan.tables[0].columns.len(), 4);

    config
        .session_settings()
        .expect("session settings should be valid");
}

#[test]
fn rejects_unknown_fields() {
    let result = serde_yaml::from_str::<SnmpConfig>(
        r#"
endpoints: ["10.0.0.1"]
fields:
  - name: uptime
    oid: 1.3.6.1.2.1.1.3.0
    kind: gauge
"#,
    );
    assert!(result.is_err());
}

fn plan_error(yaml: &str) -> BuildError {
    parse(yaml).plan().expect_err("plan should be rejected")
}

fn session_error(yaml: &str) -> BuildError {
    parse(yaml)
        .session_settings()
        .expect_err("session settings should be rejected")
}

#[test]
fn rejects_invalid_plans() {
    assert_eq!(plan_error("endpoints: [a]"), BuildError::NothingToCollect);

    let error = plan_error(
        r#"
endpoints: [a]
fields: [{ name: x, oid: "sysUpTime.0" }]
"#,
    );
    assert!(matches!(error, BuildError::InvalidField { ref path, .. } if path == "fields[0].oid"));

    let error = plan_error(
        r"
endpoints: [a]
fields: [{ name: mac, oid: 1.3.6.1, conversion: hwaddr }]
",
    );
    assert!(
        matches!(error, BuildError::InvalidField { ref path, .. } if path == "fields[0].conversion")
    );

    let error = plan_error(
        r"
endpoints: [a]
fields: [{ name: n, oid: 1.3.6.1, is_tag: true, scale: 2.0 }]
",
    );
    assert!(
        matches!(error, BuildError::InvalidField { ref path, .. } if path == "fields[0].scale")
    );

    let error = plan_error(
        r"
endpoints: [a]
fields: [{ name: uptime, oid: 1.3.6.1 }]
tables:
  - name: t
    inherit_tags: [uptime]
    columns: [{ name: c, oid: 1.3.6.2 }]
",
    );
    assert!(matches!(error, BuildError::InvalidTable { .. }));

    let error = plan_error(
        r"
endpoints: [a]
tables: [{ name: t, columns: [] }]
",
    );
    assert!(matches!(error, BuildError::InvalidTable { .. }));
}

#[test]
fn rejects_invalid_security() {
    const FIELDS: &str = "fields: [{ name: u, oid: 1.3.6.1 }]\n";

    assert_eq!(
        session_error(&format!("endpoints: [a]\nversion: v3\n{FIELDS}")),
        BuildError::MissingUsm
    );
    assert_eq!(
        session_error(&format!(
            "endpoints: [a]\nversion: v2c\nusm: {{ username: u }}\n{FIELDS}"
        )),
        BuildError::UnexpectedUsm
    );
    assert!(matches!(
        session_error(&format!(
            "endpoints: [a]\nversion: v3\nusm: {{ username: u, security_level: auth_no_priv }}\n{FIELDS}"
        )),
        BuildError::InvalidUsm { .. }
    ));
    assert!(matches!(
        session_error(&format!(
            "endpoints: [a]\nversion: v3\nusm: {{ username: u, security_level: no_auth_no_priv, auth_protocol: md5 }}\n{FIELDS}"
        )),
        BuildError::InvalidUsm { .. }
    ));
    assert!(matches!(
        session_error(&format!(
            "endpoints: [a]\nversion: v3\nusm: {{ username: u, security_level: auth_priv, auth_protocol: sha1, auth_password: p }}\n{FIELDS}"
        )),
        BuildError::InvalidUsm { .. }
    ));
    assert_eq!(
        session_error(&format!("endpoints: [a]\nmax_repetitions: 0\n{FIELDS}")),
        BuildError::ZeroMaxRepetitions
    );

    parse(&format!(
        "endpoints: [a]\nversion: v3\nusm: {{ username: u, security_level: no_auth_no_priv }}\n{FIELDS}"
    ))
    .session_settings()
    .expect("no_auth_no_priv needs no passwords");
}

#[test]
fn parses_endpoints() {
    let ok = |endpoint: &str| parse_endpoint(endpoint).expect("endpoint should parse");
    assert_eq!(ok("10.0.0.1"), ("10.0.0.1".into(), 161));
    assert_eq!(ok("10.0.0.1:1161"), ("10.0.0.1".into(), 1161));
    assert_eq!(
        ok("udp://router.example.com"),
        ("router.example.com".into(), 161)
    );
    assert_eq!(
        ok("udp://router.example.com:162/"),
        ("router.example.com".into(), 162)
    );
    assert_eq!(ok("[2001:db8::1]"), ("2001:db8::1".into(), 161));
    assert_eq!(ok("udp://[2001:db8::1]:1161"), ("2001:db8::1".into(), 1161));

    for bad in [
        "tcp://10.0.0.1",
        "udp://",
        "10.0.0.1:0",
        "10.0.0.1:x",
        "[::1",
        "udp://10.0.0.1/path",
        "2001:db8::1",
        "udp://public@10.0.0.1:161",
        "udp://public@10.0.0.1",
        "public@[::1]:161",
    ] {
        assert!(parse_endpoint(bad).is_err(), "{bad} should be rejected");
    }

    // The colon in user info must not be reported as a bad port.
    let error = parse_endpoint("udp://user:pass@10.0.0.1").expect_err("credentials are rejected");
    assert!(
        error.to_string().contains("credentials are not allowed"),
        "unexpected error: {error}"
    );
}

// A minimal SNMP agent for end-to-end tests.

#[derive(Clone)]
enum TestValue {
    Integer(i64),
    Octets(Vec<u8>),
    Counter32(u32),
    Counter64(u64),
    Timeticks(u32),
}

type Mib = BTreeMap<Vec<u64>, TestValue>;

fn oid(text: &str) -> Vec<u64> {
    text.split('.').map(|arc| arc.parse().unwrap()).collect()
}

fn test_mib() -> Mib {
    let mut mib = Mib::new();
    mib.insert(oid("1.3.6.1.2.1.1.3.0"), TestValue::Timeticks(123_456));
    mib.insert(
        oid("1.3.6.1.2.1.1.5.0"),
        TestValue::Octets(b"router1".to_vec()),
    );
    mib.insert(oid("1.3.6.1.4.1.1.1.0"), TestValue::Integer(235));
    for (index, name, mac, octets, status) in [
        (1, "lo", [0u8; 6], 1000u64, 1i64),
        (2, "eth0", [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e], 5000, 2),
    ] {
        mib.insert(
            oid(&format!("1.3.6.1.2.1.2.2.1.2.{index}")),
            TestValue::Octets(name.as_bytes().to_vec()),
        );
        mib.insert(
            oid(&format!("1.3.6.1.2.1.2.2.1.6.{index}")),
            TestValue::Octets(mac.to_vec()),
        );
        mib.insert(
            oid(&format!("1.3.6.1.2.1.2.2.1.8.{index}")),
            TestValue::Integer(status),
        );
        mib.insert(
            oid(&format!("1.3.6.1.2.1.31.1.1.1.6.{index}")),
            TestValue::Counter64(octets),
        );
    }
    mib.insert(oid("1.3.6.1.2.1.2.2.1.10.1"), TestValue::Counter32(1));
    mib
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn encode_signed(tag: u8, value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    tlv(tag, &bytes[start..])
}

fn encode_unsigned(tag: u8, value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().take_while(|b| **b == 0).count().min(7);
    let mut content = Vec::new();
    if bytes[start] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[start..]);
    tlv(tag, &content)
}

fn encode_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.push(((rest & 0x7f) as u8) | 0x80);
            rest >>= 7;
        }
        chunk.reverse();
        content.extend(chunk);
    }
    tlv(0x06, &content)
}

enum Reply<'a> {
    Value(&'a TestValue),
    EndOfMibView,
    NoSuchObject,
}

fn encode_varbind(oid: &[u64], reply: Reply<'_>) -> Vec<u8> {
    let value = match reply {
        Reply::Value(TestValue::Integer(n)) => encode_signed(0x02, *n),
        Reply::Value(TestValue::Octets(bytes)) => tlv(0x04, bytes),
        Reply::Value(TestValue::Counter32(n)) => encode_unsigned(0x41, u64::from(*n)),
        Reply::Value(TestValue::Timeticks(n)) => encode_unsigned(0x43, u64::from(*n)),
        Reply::Value(TestValue::Counter64(n)) => encode_unsigned(0x46, *n),
        Reply::EndOfMibView => tlv(0x82, &[]),
        Reply::NoSuchObject => tlv(0x80, &[]),
    };
    let mut content = encode_oid(oid);
    content.extend(value);
    tlv(0x30, &content)
}

fn encode_response(
    version: i64,
    community: &[u8],
    request_id: i32,
    error_status: i64,
    error_index: i64,
    varbinds: &[Vec<u8>],
) -> Vec<u8> {
    let mut pdu = encode_signed(0x02, i64::from(request_id));
    pdu.extend(encode_signed(0x02, error_status));
    pdu.extend(encode_signed(0x02, error_index));
    pdu.extend(tlv(0x30, &varbinds.concat()));

    let mut message = encode_signed(0x02, version);
    message.extend(tlv(0x04, community));
    message.extend(tlv(0xa2, &pdu));
    tlv(0x30, &message)
}

/// OIDs under this prefix make the fake agent answer with an error status.
const ERROR_SUBTREE: &[u64] = &[1, 3, 6, 1, 4, 1, 66666];

/// Builds the response to one request, or `None` to stay silent.
fn answer(mib: &Mib, community: &[u8], request: &[u8]) -> Option<Vec<u8>> {
    let pdu = snmp2::Pdu::from_bytes(request).ok()?;
    if pdu.community != community {
        return None;
    }
    let version = pdu.version().ok()? as i64;
    let requested: Vec<Vec<u64>> = pdu
        .varbinds
        .clone()
        .map(|(oid, _)| oid.iter().unwrap().collect())
        .collect();

    // Requests under this subtree get a `genErr` (5) response, like a failing agent subsystem.
    if requested.iter().any(|oid| oid.starts_with(ERROR_SUBTREE)) {
        return Some(encode_response(version, community, pdu.req_id, 5, 1, &[]));
    }

    let mut varbinds = Vec::new();
    let mut error_status = 0;
    match pdu.message_type {
        snmp2::MessageType::GetRequest => {
            for (i, oid) in requested.iter().enumerate() {
                varbinds.push(match mib.get(oid) {
                    Some(value) => encode_varbind(oid, Reply::Value(value)),
                    // SNMPv1 fails the whole request and points at the first unknown OID.
                    None if version == 0 => {
                        return Some(encode_response(
                            version,
                            community,
                            pdu.req_id,
                            2,
                            i as i64 + 1,
                            &[],
                        ));
                    }
                    None => encode_varbind(oid, Reply::NoSuchObject),
                });
            }
        }
        snmp2::MessageType::GetNextRequest => {
            for oid in &requested {
                match mib
                    .range::<Vec<u64>, _>((
                        std::ops::Bound::Excluded(oid.clone()),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                {
                    Some((next, value)) => varbinds.push(encode_varbind(next, Reply::Value(value))),
                    None if version == 0 => error_status = 2,
                    None => varbinds.push(encode_varbind(oid, Reply::EndOfMibView)),
                }
            }
        }
        snmp2::MessageType::GetBulkRequest => {
            // For GETBULK, the error index field carries max-repetitions.
            let max_repetitions = pdu.error_index as usize;
            let mut cursor = requested[0].clone();
            for _ in 0..max_repetitions {
                let next = mib
                    .range::<Vec<u64>, _>((
                        std::ops::Bound::Excluded(cursor.clone()),
                        std::ops::Bound::Unbounded,
                    ))
                    .next();
                if let Some((next, value)) = next {
                    varbinds.push(encode_varbind(next, Reply::Value(value)));
                    cursor.clone_from(next);
                } else {
                    varbinds.push(encode_varbind(&cursor, Reply::EndOfMibView));
                    break;
                }
            }
        }
        _ => return None,
    }
    Some(encode_response(
        version,
        community,
        pdu.req_id,
        error_status,
        0,
        &varbinds,
    ))
}

async fn spawn_agent(community: &'static [u8]) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mib = test_mib();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if let Some(response) = answer(&mib, community, &buf[..len]) {
                _ = socket.send_to(&response, peer).await;
            }
        }
    });
    address
}

fn agent_config(address: SocketAddr, version: &str) -> SnmpConfig {
    parse(&format!(
        r#"
endpoints: ["udp://{address}"]
version: {version}
community: secret
max_repetitions: 3
tags:
  site: dc1
fields:
  - name: uptime
    oid: 1.3.6.1.2.1.1.3.0
  - name: sys_name
    oid: 1.3.6.1.2.1.1.5.0
    is_tag: true
  - name: temperature
    oid: 1.3.6.1.4.1.1.1.0
    scale: 0.1
  - name: missing
    oid: 1.3.6.1.4.1.1.2.0
tables:
  - name: interface
    inherit_tags: [sys_name]
    columns:
      - name: descr
        oid: 1.3.6.1.2.1.2.2.1.2
        is_tag: true
      - name: mac
        oid: 1.3.6.1.2.1.2.2.1.6
        is_tag: true
        conversion: hwaddr
      - name: oper_status
        oid: 1.3.6.1.2.1.2.2.1.8
      - name: in_octets
        oid: 1.3.6.1.2.1.31.1.1.1.6
"#
    ))
}

fn find<'a>(events: &'a [Event], name: &str, index: Option<&str>) -> &'a crate::event::Metric {
    events
        .iter()
        .map(Event::as_metric)
        .find(|metric| {
            metric.name() == name
                && index.is_none_or(|index| metric.tag_value("index").as_deref() == Some(index))
        })
        .unwrap_or_else(|| panic!("metric {name} with index {index:?} not found"))
}

async fn assert_collects(version: &str) {
    let address = spawn_agent(b"secret").await;
    let events = run_and_assert_source_compliance(
        agent_config(address, version),
        Duration::from_secs(1),
        &PULL_SOURCE_TAGS,
    )
    .await;

    // One poll: uptime, temperature, 2 rows x 2 value columns, and `up`.
    assert_eq!(events.len(), 7, "{events:#?}");

    let up = find(&events, "up", None);
    assert_eq!(up.value(), &MetricValue::Gauge { value: 1.0 });

    let uptime = find(&events, "uptime", None);
    assert_eq!(uptime.namespace(), Some("snmp"));
    assert_eq!(uptime.value(), &MetricValue::Gauge { value: 123_456.0 });
    assert_eq!(uptime.tag_value("sys_name").as_deref(), Some("router1"));
    assert_eq!(uptime.tag_value("site").as_deref(), Some("dc1"));
    assert_eq!(
        uptime.tag_value("endpoint").as_deref(),
        Some(format!("udp://{address}").as_str())
    );

    match find(&events, "temperature", None).value() {
        MetricValue::Gauge { value } => assert!((value - 23.5).abs() < 1e-9),
        other => panic!("unexpected temperature {other:?}"),
    }

    let in_octets = find(&events, "interface_in_octets", Some("2"));
    assert_eq!(in_octets.value(), &MetricValue::Counter { value: 5000.0 });
    assert_eq!(in_octets.tag_value("descr").as_deref(), Some("eth0"));
    assert_eq!(
        in_octets.tag_value("mac").as_deref(),
        Some("00:1a:2b:3c:4d:5e")
    );
    assert_eq!(in_octets.tag_value("sys_name").as_deref(), Some("router1"));

    let status = find(&events, "interface_oper_status", Some("1"));
    assert_eq!(status.value(), &MetricValue::Gauge { value: 1.0 });
    assert_eq!(status.tag_value("descr").as_deref(), Some("lo"));
    assert_eq!(
        status.tag_value("mac").as_deref(),
        Some("00:00:00:00:00:00")
    );
}

#[tokio::test]
async fn collects_from_v2c_agent() {
    assert_collects("v2c").await;
}

#[tokio::test]
async fn collects_from_v1_agent() {
    assert_collects("v1").await;
}

#[tokio::test]
async fn reports_unreachable_agent() {
    let address = spawn_agent(b"other").await;
    let mut config = agent_config(address, "v2c");
    config.scrape_timeout = Duration::from_millis(100);
    config.retries = 1;

    let events =
        run_and_assert_source_error(config, Duration::from_secs(1), &COMPONENT_ERROR_TAGS).await;

    assert!(!events.is_empty());
    for event in &events {
        let metric = event.as_metric();
        assert_eq!(metric.name(), "up");
        assert_eq!(metric.value(), &MetricValue::Gauge { value: 0.0 });
    }

    // The `up` event is counted, so its size must be counted too.
    let endpoint = format!("udp://{address}");
    let event_bytes = crate::metrics::Controller::get()
        .expect("metrics controller should be initialized")
        .capture_metrics()
        .into_iter()
        .find(|metric| {
            metric.name() == "component_received_event_bytes_total"
                && metric.tag_value("endpoint").as_deref() == Some(endpoint.as_str())
        })
        .expect("event bytes should be reported for the endpoint");
    // Each poll emitted exactly one `up` metric, sized as a batch of one.
    let expected: usize = events
        .iter()
        .map(|event| {
            vec![event.as_metric().clone()]
                .estimated_json_encoded_size_of()
                .get()
        })
        .sum();
    assert_eq!(
        event_bytes.value(),
        &MetricValue::Counter {
            value: expected as f64
        }
    );
}

#[tokio::test]
async fn table_walk_error_keeps_agent_up() {
    let address = spawn_agent(b"secret").await;
    let config = parse(&format!(
        r#"
endpoints: ["udp://{address}"]
community: secret
tables:
  - name: broken
    columns:
      - name: value
        oid: 1.3.6.1.4.1.66666.1
"#
    ));

    let events =
        run_and_assert_source_error(config, Duration::from_secs(1), &COMPONENT_ERROR_TAGS).await;

    assert!(!events.is_empty());
    for event in &events {
        let metric = event.as_metric();
        assert_eq!(metric.name(), "up");
        assert_eq!(metric.value(), &MetricValue::Gauge { value: 1.0 });
    }
}

#[test]
fn rejects_zero_scrape_interval() {
    assert_eq!(
        session_error(
            "endpoints: [a]\nscrape_interval_secs: 0\nfields: [{ name: u, oid: 1.3.6.1 }]\n"
        ),
        BuildError::ZeroScrapeInterval
    );
}

#[tokio::test]
async fn emits_every_field_sharing_an_oid() {
    let address = spawn_agent(b"secret").await;
    let config = parse(&format!(
        r#"
endpoints: ["udp://{address}"]
community: secret
fields:
  - name: uptime
    oid: 1.3.6.1.2.1.1.3.0
  - name: uptime_seconds
    oid: 1.3.6.1.2.1.1.3.0
    scale: 0.01
"#
    ));
    let events =
        run_and_assert_source_compliance(config, Duration::from_secs(1), &PULL_SOURCE_TAGS).await;

    assert_eq!(
        find(&events, "uptime", None).value(),
        &MetricValue::Gauge { value: 123_456.0 }
    );
    match find(&events, "uptime_seconds", None).value() {
        MetricValue::Gauge { value } => assert!((value - 1_234.56).abs() < 1e-9),
        other => panic!("unexpected value {other:?}"),
    }
}

#[tokio::test]
async fn shutdown_interrupts_a_poll_in_progress() {
    // The agent never answers, so without interruption a poll would take minutes.
    let address = spawn_agent(b"other").await;
    let mut config = agent_config(address, "v2c");
    config.scrape_timeout = Duration::from_secs(30);
    config.retries = 3;

    let (tx, _rx) = SourceSender::new_test();
    let mut cx = SourceContext::new_test(tx, None);
    let (trigger, shutdown, _done) = ShutdownSignal::new_wired();
    cx.shutdown = shutdown;
    let source = tokio::spawn(config.build(cx).await.expect("source should build"));

    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(trigger);

    let result = tokio::time::timeout(Duration::from_secs(5), source)
        .await
        .expect("source should stop promptly after shutdown")
        .expect("source task should not panic");
    assert!(result.is_ok());
}

#[tokio::test]
async fn slow_agent_does_not_delay_others() {
    let fast = spawn_agent(b"secret").await;
    // This agent never answers, so its poll lasts several timeouts.
    let silent = spawn_agent(b"other").await;
    let mut config = agent_config(fast, "v2c");
    config.endpoints.push(format!("udp://{silent}"));
    config.scrape_timeout = Duration::from_secs(5);
    config.retries = 0;

    let events =
        run_and_assert_source_compliance(config, Duration::from_secs(1), &PULL_SOURCE_TAGS).await;

    // The fast agent's full poll arrives long before the silent agent's first timeout.
    let fast_endpoint = format!("udp://{fast}");
    assert_eq!(events.len(), 7, "{events:#?}");
    for event in &events {
        assert_eq!(
            event.as_metric().tag_value("endpoint").as_deref(),
            Some(fast_endpoint.as_str())
        );
    }
}

#[tokio::test]
async fn poll_timer_skips_missed_ticks() {
    assert_eq!(
        super::poll_timer(Duration::from_secs(1)).missed_tick_behavior(),
        tokio::time::MissedTickBehavior::Skip
    );
}
