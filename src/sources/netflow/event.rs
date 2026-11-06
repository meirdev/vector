//! Flow records as the objects of log events.

use std::collections::btree_map::Entry;

use chrono::DateTime;
use ordered_float::NotNan;
use rustflow_core_new::{
    convert::{CommonFlow, FlowType},
    for_each_flow_field,
    protocol::{
        Protocol,
        information_element::{ElementId, Registry},
        value::Value as FlowValue,
    },
    reader::Record,
};
use vrl::value::{KeyString, ObjectMap, Value};

/// A record as an object keyed by the names of its information elements, such as
/// `sourceIPv4Address`, scope elements first. An element the registry does not name is keyed by
/// its number, `(id)` or `(pen/id)`; one the record holds more than once is keyed by an array of
/// its values.
///
/// `reference_secs`, a UNIX second near the record's times such as when it was received, picks
/// the era of the date-times that wrap.
pub(super) fn elements_object(
    record: &Record,
    registry: &Registry,
    reference_secs: i64,
) -> ObjectMap {
    let mut object = ObjectMap::new();
    for (element, value) in record.scope_elements().chain(record.iter()) {
        let Some(value) = value_of(value, reference_secs) else {
            continue;
        };
        match object.entry(element_name(registry, element)) {
            Entry::Vacant(entry) => {
                entry.insert(value);
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(values) => values.push(value),
                first => {
                    let first = std::mem::replace(first, Value::Null);
                    entry.insert(Value::Array(vec![first, value]));
                }
            },
        }
    }
    object
}

fn element_name(registry: &Registry, element: ElementId) -> KeyString {
    match registry.get(element) {
        Some(known) => KeyString::from(known.name.as_ref()),
        None => KeyString::from(element.to_string()),
    }
}

/// A value as Vector holds it: integers and floats as numbers, date-times as timestamps, and
/// addresses and octets in their RFC 7373 textual form. Lists, which have no such form, and
/// values to ignore are `None`.
fn value_of(value: &FlowValue, reference_secs: i64) -> Option<Value> {
    Some(match value {
        FlowValue::Unsigned8(v) => Value::Integer(i64::from(*v)),
        FlowValue::Unsigned16(v) => Value::Integer(i64::from(*v)),
        FlowValue::Unsigned32(v) => Value::Integer(i64::from(*v)),
        FlowValue::Unsigned64(v) => unsigned(*v),
        FlowValue::Signed8(v) => Value::Integer(i64::from(*v)),
        FlowValue::Signed16(v) => Value::Integer(i64::from(*v)),
        FlowValue::Signed32(v) => Value::Integer(i64::from(*v)),
        FlowValue::Signed64(v) => Value::Integer(*v),
        FlowValue::Float32(v) => Value::Float(NotNan::new(f64::from(*v)).ok()?),
        FlowValue::Float64(v) => Value::Float(NotNan::new(*v).ok()?),
        FlowValue::Boolean(v) => Value::Boolean(*v),
        FlowValue::String(v) => Value::from(v.as_str()),
        FlowValue::DateTimeSeconds(_)
        | FlowValue::DateTimeMilliseconds(_)
        | FlowValue::DateTimeMicroseconds(_)
        | FlowValue::DateTimeNanoseconds(_) => value
            .unix_nanos(reference_secs)
            .and_then(|nanos| i64::try_from(nanos).ok())
            .map_or_else(
                || Value::from(value.to_string()),
                |nanos| Value::Timestamp(DateTime::from_timestamp_nanos(nanos)),
            ),
        FlowValue::Unsigned256(_)
        | FlowValue::MacAddress(_)
        | FlowValue::OctetArray(_)
        | FlowValue::Ipv4Address(_)
        | FlowValue::Ipv6Address(_) => Value::from(value.to_string()),
        FlowValue::BasicList(_)
        | FlowValue::SubTemplateList(_)
        | FlowValue::SubTemplateMultiList(_)
        | FlowValue::Null => return None,
    })
}

/// An unsigned 64-bit integer, as a string when it is past the integers Vector holds.
fn unsigned(value: u64) -> Value {
    i64::try_from(value).map_or_else(|_| Value::from(value.to_string()), Value::Integer)
}

const fn flow_type_name(flow_type: FlowType) -> &'static str {
    match flow_type {
        FlowType::NetflowV5 => "netflow_v5",
        FlowType::NetflowV9 => "netflow_v9",
        FlowType::Ipfix => "ipfix",
        FlowType::SflowV5 => "sflow_v5",
    }
}

/// Defines `common_flow_object` from the fields of a `CommonFlow`, each a kind and whether it is
/// always set, as `for_each_flow_field!` lists them.
macro_rules! common_flow_object {
    ($($name:ident: $kind:ident $presence:ident,)*) => {
        /// A flow as an object of the fixed fields of a `CommonFlow`, unset fields left out.
        pub(super) fn common_flow_object(flow: &CommonFlow) -> ObjectMap {
            let mut object = ObjectMap::new();
            $( common_flow_object!(@field object, flow.$name, $name, $kind, $presence); )*
            object
        }
    };
    (@field $object:ident, $value:expr, $name:ident, $kind:ident, required) => {
        $object.insert(
            field_key(stringify!($kind), stringify!($name)),
            common_flow_object!(@value $kind, $value),
        );
    };
    (@field $object:ident, $value:expr, $name:ident, $kind:ident, optional) => {
        if let Some(value) = $value {
            $object.insert(
                field_key(stringify!($kind), stringify!($name)),
                common_flow_object!(@value $kind, value),
            );
        }
    };
    (@value FlowType, $value:expr) => { Value::from(flow_type_name($value)) };
    (@value Timestamp, $value:expr) => { Value::Timestamp(DateTime::from_timestamp_nanos($value)) };
    (@value U8, $value:expr) => { Value::Integer(i64::from($value)) };
    (@value U16, $value:expr) => { Value::Integer(i64::from($value)) };
    (@value U32, $value:expr) => { Value::Integer(i64::from($value)) };
    (@value U64, $value:expr) => { unsigned($value) };
    (@value Ip, $value:expr) => { Value::from($value.to_string()) };
    (@value Mac, $value:expr) => { Value::from(FlowValue::MacAddress($value.into_array()).to_string()) };
}

for_each_flow_field!(common_flow_object);

/// A `CommonFlow` field's key. Times in nanoseconds become timestamps, and lose the `_ns` of
/// their names.
fn field_key(kind: &str, name: &'static str) -> KeyString {
    match kind {
        "Timestamp" => KeyString::from(name.strip_suffix("_ns").unwrap_or(name)),
        _ => KeyString::from(name),
    }
}

/// The name of a record's protocol, such as `netflow_v9`, as events and metrics give it.
pub(super) fn protocol_name(record: &Record) -> &'static str {
    protocol_of(record.protocol)
}

/// The name of `protocol`, such as `netflow_v9`.
pub(super) fn protocol_of(protocol: Protocol) -> &'static str {
    flow_type_name(protocol.into())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use chrono::{TimeZone, Utc};
    use rustflow_core_new::{protocol::information_element::iana, reader::Scope};
    use similar_asserts::assert_eq;
    use vrl::value;

    use super::*;

    fn record(scope: Vec<(Scope, FlowValue)>, fields: Vec<(ElementId, FlowValue)>) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.into_iter().unzip();
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 7,
            scope,
            elements: Arc::new(elements.into()),
            values,
        }
    }

    fn object(record: &Record) -> Value {
        Value::Object(elements_object(record, &Registry::iana(), 1_700_000_000))
    }

    #[test]
    fn elements_are_keyed_by_name_with_typed_values() {
        let flow = record(
            Vec::new(),
            vec![
                (
                    iana::FLOW_START_MILLISECONDS,
                    FlowValue::DateTimeMilliseconds(1_352_140_261_135),
                ),
                (iana::OCTET_DELTA_COUNT, FlowValue::Unsigned64(195_383)),
                (
                    iana::SOURCE_IPV4_ADDRESS,
                    FlowValue::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
                ),
                (
                    iana::DESTINATION_IPV6_ADDRESS,
                    FlowValue::Ipv6Address(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
                ),
                (iana::SOURCE_TRANSPORT_PORT, FlowValue::Unsigned16(80)),
                (
                    iana::SOURCE_MAC_ADDRESS,
                    FlowValue::MacAddress([0, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]),
                ),
                (iana::INTERFACE_NAME, FlowValue::String("eth0".into())),
                (iana::FLOW_END_REASON, FlowValue::Null),
            ],
        );

        assert_eq!(
            object(&flow),
            value!({
                "flowStartMilliseconds": (Utc.timestamp_millis_opt(1_352_140_261_135).unwrap()),
                "octetDeltaCount": 195_383,
                "sourceIPv4Address": "192.0.2.1",
                "destinationIPv6Address": "2001:db8::3",
                "sourceTransportPort": 80,
                "sourceMacAddress": "00:1b:21:aa:bb:cc",
                "interfaceName": "eth0",
            })
        );
    }

    #[test]
    fn an_element_held_twice_is_keyed_once_by_an_array() {
        let flow = record(
            Vec::new(),
            vec![
                (
                    iana::MPLS_TOP_LABEL_STACK_SECTION,
                    FlowValue::OctetArray(vec![0, 0x64, 1]),
                ),
                (iana::PACKET_DELTA_COUNT, FlowValue::Unsigned64(1)),
                (
                    iana::MPLS_TOP_LABEL_STACK_SECTION,
                    FlowValue::OctetArray(vec![0, 0xc8, 1]),
                ),
                (
                    iana::MPLS_TOP_LABEL_STACK_SECTION,
                    FlowValue::OctetArray(vec![0, 0xff, 1]),
                ),
            ],
        );

        assert_eq!(
            object(&flow),
            value!({
                "mplsTopLabelStackSection": ["006401", "00c801", "00ff01"],
                "packetDeltaCount": 1,
            })
        );
    }

    #[test]
    fn unnamed_elements_are_keyed_by_number_and_scope_comes_first() {
        let options = record(
            vec![(
                Scope::Element(iana::INGRESS_INTERFACE),
                FlowValue::Unsigned32(3),
            )],
            vec![(
                ElementId::from((35_566, 403)),
                FlowValue::String("sip:a".into()),
            )],
        );

        assert_eq!(
            object(&options),
            value!({ "ingressInterface": 3, "(35566/403)": "sip:a" })
        );
    }

    #[test]
    fn integers_past_i64_and_nan_floats() {
        let flow = record(
            Vec::new(),
            vec![
                (iana::OCTET_TOTAL_COUNT, FlowValue::Unsigned64(u64::MAX)),
                (iana::SAMPLING_PROBABILITY, FlowValue::Float64(f64::NAN)),
            ],
        );

        assert_eq!(
            object(&flow),
            value!({ "octetTotalCount": "18446744073709551615" })
        );
    }

    #[test]
    fn common_flows_have_fixed_fields() {
        let flow = record(
            Vec::new(),
            vec![
                (
                    iana::COLLECTION_TIME_MILLISECONDS,
                    FlowValue::DateTimeMilliseconds(1_700_000_000_000),
                ),
                (
                    iana::SOURCE_IPV4_ADDRESS,
                    FlowValue::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
                ),
                (iana::OCTET_DELTA_COUNT, FlowValue::Unsigned64(1_000)),
                (iana::SOURCE_TRANSPORT_PORT, FlowValue::Unsigned16(443)),
                (
                    iana::SOURCE_MAC_ADDRESS,
                    FlowValue::MacAddress([0, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]),
                ),
            ],
        );

        assert_eq!(
            Value::Object(common_flow_object(&CommonFlow::from(&flow))),
            value!({
                "flow_type": "ipfix",
                "time_received": (Utc.timestamp_millis_opt(1_700_000_000_000).unwrap()),
                "sequence_num": 7,
                "bytes": 1_000,
                "src_addr": "192.0.2.1",
                "src_mac": "00:1b:21:aa:bb:cc",
                "etype": 0x0800,
                "src_port": 443,
            })
        );
    }
}
