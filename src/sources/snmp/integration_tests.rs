//! Integration tests against `snmpsim`, an SNMP agent simulator.
//!
//! The simulated device is defined in `tests/integration/snmp/data/public.snmprec`, and the
//! `SNMPv3` users in the `Dockerfile` next to it.

use std::time::Duration;

use super::SnmpConfig;
use crate::{
    event::{Event, Metric, MetricValue},
    test_util::components::{
        COMPONENT_ERROR_TAGS, PULL_SOURCE_TAGS, run_and_assert_source_compliance,
        run_and_assert_source_error,
    },
};

/// The SNMP password for every authenticated user of the simulator.
const AUTH_PASSWORD: &str = "authpass123";

/// The privacy (encryption) password for every encrypting user of the simulator.
const PRIVACY_PASSWORD: &str = "privpass123";

fn snmp_address() -> String {
    std::env::var("SNMP_ADDRESS").unwrap_or_else(|_| "127.0.0.1:11161".to_string())
}

/// The fields and tables polled by every test, covering each value type and conversion.
const COLLECTION: &str = r"
fields:
  - name: uptime
    oid: 1.3.6.1.2.1.1.3.0
  - name: sys_name
    oid: 1.3.6.1.2.1.1.5.0
    is_tag: true
  - name: temperature
    oid: 1.3.6.1.4.1.99999.1.0
    scale: 0.1
  - name: load
    oid: 1.3.6.1.4.1.99999.2.0
    conversion: float
  - name: mgmt_ip
    oid: 1.3.6.1.4.1.99999.3.0
    is_tag: true
  - name: loopback_ip
    oid: 1.3.6.1.4.1.99999.4.0
    is_tag: true
    conversion: ipaddr
  - name: missing
    oid: 1.3.6.1.4.1.99999.99.0
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
      - name: speed
        oid: 1.3.6.1.2.1.2.2.1.5
      - name: oper_status
        oid: 1.3.6.1.2.1.2.2.1.8
      - name: in_octets
        oid: 1.3.6.1.2.1.2.2.1.10
      - name: hc_in_octets
        oid: 1.3.6.1.2.1.31.1.1.1.6
";

/// Builds a config from the protocol settings and the shared collection.
fn config(protocol: &str) -> SnmpConfig {
    let yaml = format!(
        "endpoints: [\"udp://{}\"]\nscrape_timeout_secs: 2\nretries: 1\n{protocol}\n{COLLECTION}",
        snmp_address()
    );
    serde_yaml::from_str(&yaml).expect("config should parse")
}

/// Builds an `SNMPv3` config. The simulator selects its data file by the context name `public`.
fn v3_config(usm: &str) -> SnmpConfig {
    config(&format!(
        "version: v3\nusm:\n  context_name: public\n{}",
        usm.lines().fold(String::new(), |mut out, line| {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
            out
        })
    ))
}

async fn collect(config: SnmpConfig) -> Vec<Metric> {
    run_and_assert_source_compliance(config, Duration::from_secs(3), &PULL_SOURCE_TAGS)
        .await
        .into_iter()
        .map(Event::into_metric)
        .collect()
}

fn find<'a>(metrics: &'a [Metric], name: &str, index: Option<&str>) -> &'a Metric {
    metrics
        .iter()
        .find(|metric| {
            metric.name() == name
                && index.is_none_or(|index| metric.tag_value("index").as_deref() == Some(index))
        })
        .unwrap_or_else(|| panic!("metric {name} with index {index:?} not found in {metrics:#?}"))
}

fn assert_gauge(metric: &Metric, expected: f64) {
    match metric.value() {
        MetricValue::Gauge { value } => assert!(
            (value - expected).abs() < 1e-9,
            "{}: expected {expected}, got {value}",
            metric.name()
        ),
        other => panic!("{}: expected a gauge, got {other:?}", metric.name()),
    }
}

fn assert_counter(metric: &Metric, expected: f64) {
    assert_eq!(
        metric.value(),
        &MetricValue::Counter { value: expected },
        "{}",
        metric.name()
    );
}

/// Checks everything the simulated device exposes, except 64-bit counters.
fn assert_device(metrics: &[Metric]) {
    assert_gauge(find(metrics, "up", None), 1.0);

    let uptime = find(metrics, "uptime", None);
    assert_gauge(uptime, 123_456.0);
    assert_eq!(uptime.namespace(), Some("snmp"));
    assert_eq!(
        uptime.tag_value("endpoint").as_deref(),
        Some(format!("udp://{}", snmp_address()).as_str())
    );
    assert_eq!(uptime.tag_value("sys_name").as_deref(), Some("test-device"));
    assert_eq!(uptime.tag_value("mgmt_ip").as_deref(), Some("192.168.1.1"));
    assert_eq!(
        uptime.tag_value("loopback_ip").as_deref(),
        Some("192.168.1.2")
    );

    assert_gauge(find(metrics, "temperature", None), 23.5);
    assert_gauge(find(metrics, "load", None), 42.5);
    assert!(
        metrics.iter().all(|metric| metric.name() != "missing"),
        "a missing OID must not produce a metric"
    );

    for (index, descr, mac, speed, status, octets) in [
        ("1", "lo", None, 10_000_000.0, 1.0, 1000.0),
        (
            "2",
            "eth0",
            Some("00:1a:2b:3c:4d:5e"),
            1_000_000_000.0,
            1.0,
            2000.0,
        ),
        (
            "3",
            "eth1",
            Some("00:1a:2b:3c:4d:5f"),
            1_000_000_000.0,
            2.0,
            3000.0,
        ),
    ] {
        let speed_metric = find(metrics, "interface_speed", Some(index));
        assert_gauge(speed_metric, speed);
        assert_eq!(speed_metric.tag_value("descr").as_deref(), Some(descr));
        // The loopback interface has an empty hardware address, so it gets no `mac` tag.
        assert_eq!(speed_metric.tag_value("mac").as_deref(), mac);
        assert_eq!(
            speed_metric.tag_value("sys_name").as_deref(),
            Some("test-device")
        );
        assert_gauge(find(metrics, "interface_oper_status", Some(index)), status);
        assert_counter(find(metrics, "interface_in_octets", Some(index)), octets);
    }
}

fn assert_64_bit_counters(metrics: &[Metric]) {
    for (index, octets) in [
        ("1", 10_000_000_000.0),
        ("2", 20_000_000_000.0),
        ("3", 30_000_000_000.0),
    ] {
        assert_counter(find(metrics, "interface_hc_in_octets", Some(index)), octets);
    }
}

#[tokio::test]
async fn collects_with_v2c() {
    let metrics = collect(config("version: v2c\ncommunity: public")).await;

    assert_device(&metrics);
    assert_64_bit_counters(&metrics);
    // 3 scalar metrics, 3 rows of 4 value columns, and `up`.
    assert_eq!(metrics.len(), 16, "{metrics:#?}");
}

#[tokio::test]
async fn collects_with_v1() {
    let metrics = collect(config("version: v1\ncommunity: public")).await;

    assert_device(&metrics);
    // SNMPv1 has no 64-bit counter type, so the agent skips those values.
    assert!(
        metrics
            .iter()
            .all(|metric| metric.name() != "interface_hc_in_octets")
    );
    assert_eq!(metrics.len(), 13, "{metrics:#?}");
}

#[tokio::test]
async fn collects_with_v3_no_auth_no_priv() {
    let metrics = collect(v3_config(
        "username: noauth\nsecurity_level: no_auth_no_priv",
    ))
    .await;

    assert_device(&metrics);
    assert_64_bit_counters(&metrics);
}

#[tokio::test]
async fn collects_with_v3_auth_no_priv() {
    let metrics = collect(v3_config(&format!(
        "username: authonly\nsecurity_level: auth_no_priv\nauth_protocol: sha512\nauth_password: {AUTH_PASSWORD}"
    )))
    .await;

    assert_device(&metrics);
    assert_64_bit_counters(&metrics);
}

#[tokio::test]
async fn collects_with_v3_auth_priv() {
    let metrics = collect(v3_config(&format!(
        "username: sha256aes\nsecurity_level: auth_priv\nauth_protocol: sha256\nauth_password: {AUTH_PASSWORD}\nprivacy_protocol: aes128\nprivacy_password: {PRIVACY_PASSWORD}"
    )))
    .await;

    assert_device(&metrics);
    assert_64_bit_counters(&metrics);
}

#[tokio::test]
async fn collects_with_v3_aes256_blumenthal_key_extension() {
    let metrics = collect(v3_config(&format!(
        "username: aes256blmt\nsecurity_level: auth_priv\nauth_protocol: sha1\nauth_password: {AUTH_PASSWORD}\nprivacy_protocol: aes256\nprivacy_password: {PRIVACY_PASSWORD}\nkey_extension: blumenthal"
    )))
    .await;

    assert_device(&metrics);
}

#[tokio::test]
async fn collects_with_v3_aes256_reeder_key_extension() {
    let metrics = collect(v3_config(&format!(
        "username: aes256reeder\nsecurity_level: auth_priv\nauth_protocol: sha1\nauth_password: {AUTH_PASSWORD}\nprivacy_protocol: aes256\nprivacy_password: {PRIVACY_PASSWORD}\nkey_extension: reeder"
    )))
    .await;

    assert_device(&metrics);
}

async fn assert_unreachable(config: SnmpConfig) {
    let events =
        run_and_assert_source_error(config, Duration::from_secs(3), &COMPONENT_ERROR_TAGS).await;

    assert!(!events.is_empty());
    for event in events {
        let metric = event.into_metric();
        assert_eq!(metric.name(), "up");
        assert_gauge(&metric, 0.0);
    }
}

#[tokio::test]
async fn reports_wrong_community() {
    // The simulator drops requests with an unknown community, so every request times out.
    let mut config = config("version: v2c\ncommunity: wrong");
    config.scrape_timeout = Duration::from_millis(200);
    config.retries = 0;
    assert_unreachable(config).await;
}

#[tokio::test]
async fn reports_wrong_v3_password() {
    let mut config = v3_config(&format!(
        "username: sha256aes\nsecurity_level: auth_priv\nauth_protocol: sha256\nauth_password: wrong-password\nprivacy_protocol: aes128\nprivacy_password: {PRIVACY_PASSWORD}"
    ));
    config.retries = 0;
    assert_unreachable(config).await;
}
