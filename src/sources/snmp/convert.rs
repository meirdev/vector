//! Conversion of SNMP values into the numbers and strings that make up Vector metrics.

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
};

use snmp2::Value;

use super::config::Conversion;

/// An owned, simplified SNMP value.
///
/// SNMP responses borrow from the session's receive buffer, so values are converted into this
/// type before the next request is sent.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Datum {
    /// A numeric value. `counter` is true when the SNMP type is monotonic (Counter32 or Counter64).
    Number { value: f64, counter: bool },

    /// Raw bytes from an OCTET STRING or Opaque value.
    Bytes(Vec<u8>),

    /// A value that already has a canonical text form, such as an `IpAddress` or an OID.
    Text(String),

    /// The agent has no value for this OID (`noSuchObject`, `noSuchInstance`, or `NULL`).
    Missing,

    /// The walk reached the end of the agent's MIB view.
    EndOfMibView,
}

impl Datum {
    pub(super) fn from_value(value: &Value<'_>) -> Self {
        #[allow(
            clippy::cast_precision_loss,
            reason = "SNMP integers are converted to f64 metric values, matching other Vector metric sources."
        )]
        match value {
            Value::Boolean(b) => Self::gauge(f64::from(u8::from(*b))),
            Value::Integer(n) => Self::gauge(*n as f64),
            Value::Unsigned32(n) | Value::Timeticks(n) => Self::gauge(f64::from(*n)),
            Value::Counter32(n) => Self::counter(f64::from(*n)),
            Value::Counter64(n) => Self::counter(*n as f64),
            Value::OctetString(bytes) | Value::Opaque(bytes) => Self::Bytes(bytes.to_vec()),
            Value::IpAddress(ip) => Self::Text(Ipv4Addr::from(*ip).to_string()),
            Value::ObjectIdentifier(oid) => Self::Text(oid.iter().map_or_else(
                || oid.to_id_string(),
                |arcs| format_oid(&arcs.collect::<Vec<_>>()),
            )),
            Value::EndOfMibView => Self::EndOfMibView,
            // `Null`, `noSuchObject` and `noSuchInstance` mean that the agent has no value.
            // Constructed types and PDUs never appear as varbind values in a valid response.
            _ => Self::Missing,
        }
    }

    const fn gauge(value: f64) -> Self {
        Self::Number {
            value,
            counter: false,
        }
    }

    const fn counter(value: f64) -> Self {
        Self::Number {
            value,
            counter: true,
        }
    }

    /// Approximate number of payload bytes this value occupied on the wire.
    pub(super) const fn wire_len(&self) -> usize {
        match self {
            Self::Number { .. } => 8,
            Self::Bytes(bytes) => bytes.len(),
            Self::Text(text) => text.len(),
            Self::Missing | Self::EndOfMibView => 0,
        }
    }

    /// Applies a configured conversion.
    pub(super) fn convert(self, conversion: Conversion) -> Result<Self, String> {
        match conversion {
            Conversion::Hwaddr => match self {
                // Interfaces without a hardware address, such as loopbacks and tunnels, report an
                // empty octet string. Treat it as no value rather than as an error.
                Self::Bytes(bytes) if bytes.is_empty() => Ok(Self::Missing),
                Self::Bytes(bytes) => Ok(Self::Text(format_hwaddr(&bytes))),
                other => Err(format!(
                    "expected an octet string, got {}",
                    other.describe()
                )),
            },
            Conversion::Ipaddr => match self {
                Self::Bytes(bytes) if bytes.is_empty() => Ok(Self::Missing),
                Self::Bytes(bytes) => match bytes.len() {
                    4 => {
                        let octets: [u8; 4] = bytes.try_into().expect("length checked");
                        Ok(Self::Text(Ipv4Addr::from(octets).to_string()))
                    }
                    16 => {
                        let octets: [u8; 16] = bytes.try_into().expect("length checked");
                        Ok(Self::Text(Ipv6Addr::from(octets).to_string()))
                    }
                    len => Err(format!(
                        "expected an octet string of 4 or 16 bytes, got {len} bytes"
                    )),
                },
                // An SNMP IpAddress value is already rendered as text.
                Self::Text(text) => Ok(Self::Text(text)),
                other => Err(format!(
                    "expected an IP address or octet string, got {}",
                    other.describe()
                )),
            },
            Conversion::Int => self.parse_number().map(|value| Self::gauge(value.trunc())),
            Conversion::Float => self.parse_number().map(Self::gauge),
        }
    }

    fn parse_number(self) -> Result<f64, String> {
        match self {
            Self::Number { value, .. } => Ok(value),
            Self::Bytes(bytes) => {
                let text = std::str::from_utf8(trim_nul(&bytes))
                    .map_err(|_| "octet string is not valid UTF-8".to_string())?;
                text.trim()
                    .parse::<f64>()
                    .map_err(|_| format!("cannot parse {text:?} as a number"))
            }
            Self::Text(text) => text
                .trim()
                .parse::<f64>()
                .map_err(|_| format!("cannot parse {text:?} as a number")),
            other => Err(format!("expected a number, got {}", other.describe())),
        }
    }

    /// Renders the value as a tag value.
    pub(super) fn into_tag_value(self) -> Option<String> {
        match self {
            Self::Number { value, .. } => Some(format_number(value)),
            Self::Bytes(bytes) => Some(render_bytes(&bytes)),
            Self::Text(text) => Some(text),
            Self::Missing | Self::EndOfMibView => None,
        }
    }

    pub(super) const fn describe(&self) -> &'static str {
        match self {
            Self::Number { .. } => "a number",
            Self::Bytes(_) => "an octet string",
            Self::Text(_) => "a text value",
            Self::Missing => "no value",
            Self::EndOfMibView => "the end of the MIB view",
        }
    }
}

/// Renders an OCTET STRING.
///
/// Printable UTF-8 text is returned as is, without trailing NUL bytes that some agents append.
/// Anything else is hex-encoded, which keeps the value lossless so that VRL can decode it with
/// `decode_base16`.
pub(super) fn render_bytes(bytes: &[u8]) -> String {
    let trimmed = trim_nul(bytes);
    match std::str::from_utf8(trimmed) {
        Ok(text)
            if text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r')) =>
        {
            text.to_string()
        }
        _ => hex::encode(bytes),
    }
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    &bytes[..end]
}

fn format_hwaddr(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Formats a number for use as a tag, without a trailing `.0` for integral values.
fn format_number(value: f64) -> String {
    const MAX_EXACT: f64 = 9_007_199_254_740_992.0; // 2^53
    if value.fract() == 0.0 && value.abs() < MAX_EXACT {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "The value is integral and within the exactly representable range."
        )]
        let integer = value as i64;
        integer.to_string()
    } else {
        value.to_string()
    }
}

/// Formats an OID in dotted numeric form.
pub(super) fn format_oid(arcs: &[u64]) -> String {
    let mut out = String::new();
    for (i, arc) in arcs.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        write!(out, "{arc}").expect("writing to a String cannot fail");
    }
    out
}

/// Parses an OID in dotted numeric form. A leading dot is accepted.
pub(super) fn parse_oid(text: &str) -> Result<Vec<u64>, String> {
    let trimmed = text.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        return Err("OID is empty".to_string());
    }
    let arcs = trimmed
        .split('.')
        .map(|arc| {
            arc.parse::<u64>()
                .map_err(|_| format!("invalid OID {text:?}: {arc:?} is not a number"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if arcs.len() < 2 {
        return Err(format!(
            "invalid OID {text:?}: at least two arcs are required"
        ));
    }
    if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
        return Err(format!("invalid OID {text:?}: invalid leading arcs"));
    }
    Ok(arcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_snmp_types() {
        assert_eq!(
            Datum::from_value(&Value::Counter64(42)),
            Datum::Number {
                value: 42.0,
                counter: true
            }
        );
        assert_eq!(
            Datum::from_value(&Value::Counter32(7)),
            Datum::Number {
                value: 7.0,
                counter: true
            }
        );
        assert_eq!(
            Datum::from_value(&Value::Integer(-3)),
            Datum::Number {
                value: -3.0,
                counter: false
            }
        );
        assert_eq!(
            Datum::from_value(&Value::Timeticks(100)),
            Datum::Number {
                value: 100.0,
                counter: false
            }
        );
        assert_eq!(
            Datum::from_value(&Value::IpAddress([10, 0, 0, 1])),
            Datum::Text("10.0.0.1".into())
        );
        assert_eq!(Datum::from_value(&Value::NoSuchObject), Datum::Missing);
        assert_eq!(Datum::from_value(&Value::EndOfMibView), Datum::EndOfMibView);
    }

    #[test]
    fn renders_printable_text_as_is() {
        assert_eq!(render_bytes(b"eth0"), "eth0");
        assert_eq!(render_bytes(b"router\0"), "router");
        assert_eq!(render_bytes(b""), "");
    }

    #[test]
    fn renders_binary_as_hex() {
        assert_eq!(
            render_bytes(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            "001a2b3c4d5e"
        );
        assert_eq!(render_bytes(&[0xff, 0xfe]), "fffe");
        assert_eq!(render_bytes(&[0x41, 0x01]), "4101");
    }

    #[test]
    fn converts_hwaddr() {
        let datum = Datum::Bytes(vec![0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(
            datum.convert(Conversion::Hwaddr),
            Ok(Datum::Text("00:1a:2b:3c:4d:5e".into()))
        );
        assert!(Datum::gauge(1.0).convert(Conversion::Hwaddr).is_err());
        assert_eq!(
            Datum::Bytes(vec![]).convert(Conversion::Hwaddr),
            Ok(Datum::Missing)
        );
    }

    #[test]
    fn converts_ipaddr() {
        assert_eq!(
            Datum::Bytes(vec![192, 168, 1, 1]).convert(Conversion::Ipaddr),
            Ok(Datum::Text("192.168.1.1".into()))
        );
        let mut v6 = vec![0u8; 16];
        v6[15] = 1;
        assert_eq!(
            Datum::Bytes(v6).convert(Conversion::Ipaddr),
            Ok(Datum::Text("::1".into()))
        );
        assert_eq!(
            Datum::Bytes(vec![]).convert(Conversion::Ipaddr),
            Ok(Datum::Missing)
        );
        assert_eq!(
            Datum::Text("10.0.0.1".into()).convert(Conversion::Ipaddr),
            Ok(Datum::Text("10.0.0.1".into()))
        );
        assert!(
            Datum::Bytes(vec![1, 2, 3])
                .convert(Conversion::Ipaddr)
                .is_err()
        );
    }

    #[test]
    fn converts_numbers() {
        assert_eq!(
            Datum::Bytes(b" 42.5 ".to_vec()).convert(Conversion::Float),
            Ok(Datum::gauge(42.5))
        );
        assert_eq!(
            Datum::Bytes(b"42.9\0".to_vec()).convert(Conversion::Int),
            Ok(Datum::gauge(42.0))
        );
        assert_eq!(
            Datum::counter(5.0).convert(Conversion::Float),
            Ok(Datum::gauge(5.0))
        );
        assert!(
            Datum::Bytes(b"abc".to_vec())
                .convert(Conversion::Float)
                .is_err()
        );
    }

    #[test]
    fn formats_tag_values() {
        assert_eq!(Datum::gauge(3.0).into_tag_value(), Some("3".into()));
        assert_eq!(Datum::gauge(2.5).into_tag_value(), Some("2.5".into()));
        assert_eq!(Datum::Missing.into_tag_value(), None);
    }

    #[test]
    fn parses_oids() {
        assert_eq!(
            parse_oid("1.3.6.1.2.1.1.3.0"),
            Ok(vec![1, 3, 6, 1, 2, 1, 1, 3, 0])
        );
        assert_eq!(parse_oid(".1.3.6"), Ok(vec![1, 3, 6]));
        assert!(parse_oid("").is_err());
        assert!(parse_oid("1").is_err());
        assert!(parse_oid("1.3.x").is_err());
        assert!(parse_oid("3.1").is_err());
        assert!(parse_oid("1.40").is_err());
        assert!(parse_oid("sysUpTime.0").is_err());
    }

    #[test]
    fn formats_oids() {
        assert_eq!(format_oid(&[1, 3, 6, 1]), "1.3.6.1");
        assert_eq!(format_oid(&[]), "");
    }
}
