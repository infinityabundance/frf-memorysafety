//! Strict canonical evidence, resource bounds, and domain-separated identities.
//!
//! The encoding implemented here is deliberately called
//! [`CANONICAL_SCHEMA`], not RFC 8785/JCS. It is a separately versioned,
//! restricted grammar documented in `SPEC.md`.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Serialize, Serializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// Identity of the restricted encoding emitted by this crate.
pub const CANONICAL_SCHEMA: &str = "ms-canonical-json-v1";

/// Maximum accepted encoded size.
pub const MAX_BYTES: usize = 4 * 1024 * 1024;
/// Maximum accepted nesting depth.
pub const MAX_DEPTH: usize = 64;
/// Maximum members in one object.
pub const MAX_OBJECT_MEMBERS: usize = 16_384;
/// Maximum elements in one array.
pub const MAX_ARRAY_ELEMENTS: usize = 65_536;
/// Maximum bytes in one string.
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
/// Maximum total value nodes.
pub const MAX_NODES: usize = 262_144;

/// Errors produced by the identity layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Encoded input exceeds [`MAX_BYTES`].
    TooLarge {
        /// Observed byte length.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Nesting exceeds [`MAX_DEPTH`].
    TooDeep {
        /// Observed depth.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// An object has more than [`MAX_OBJECT_MEMBERS`] members.
    TooManyObjectMembers {
        /// Observed member count.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// An array has more than [`MAX_ARRAY_ELEMENTS`] elements.
    TooManyArrayElements {
        /// Observed element count.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// A string exceeds [`MAX_STRING_BYTES`].
    StringTooLong {
        /// Observed byte length.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// The value has more than [`MAX_NODES`] nodes.
    TooManyNodes {
        /// Observed node count.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// An object repeats a key after JSON unescaping.
    DuplicateKey(
        /// Repeated key.
        String,
    ),
    /// A floating-point number was encountered.
    FloatNotAllowed(
        /// Path at which the number appeared.
        String,
    ),
    /// The bytes are valid JSON but are not in canonical form.
    NonCanonical,
    /// The input is not valid UTF-8.
    InvalidUtf8,
    /// The input is not valid JSON.
    Json(
        /// Parser diagnostic.
        String,
    ),
    /// The text is not a well-formed `ms1-` identity.
    InvalidId(
        /// Rejected text.
        String,
    ),
    /// A digest was checked against the wrong domain separator.
    DomainMismatch {
        /// Domain the caller required.
        expected: IdentityDomain,
        /// Domain that was supplied.
        actual: IdentityDomain,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, limit } => {
                write!(f, "encoded evidence is {actual} bytes; limit is {limit}")
            }
            Self::TooDeep { actual, limit } => {
                write!(f, "evidence nesting depth is {actual}; limit is {limit}")
            }
            Self::TooManyObjectMembers { actual, limit } => {
                write!(f, "object has {actual} members; limit is {limit}")
            }
            Self::TooManyArrayElements { actual, limit } => {
                write!(f, "array has {actual} elements; limit is {limit}")
            }
            Self::StringTooLong { actual, limit } => {
                write!(f, "string has {actual} bytes; limit is {limit}")
            }
            Self::TooManyNodes { actual, limit } => {
                write!(f, "evidence has {actual} nodes; limit is {limit}")
            }
            Self::DuplicateKey(key) => write!(f, "duplicate object key {key:?}"),
            Self::FloatNotAllowed(path) => {
                write!(f, "floating-point number is forbidden at {path}")
            }
            Self::NonCanonical => write!(f, "bytes are not in {CANONICAL_SCHEMA} form"),
            Self::InvalidUtf8 => write!(f, "input is not valid UTF-8"),
            Self::Json(message) => write!(f, "invalid JSON: {message}"),
            Self::InvalidId(id) => write!(f, "invalid FRF-MemorySafety identity {id:?}"),
            Self::DomainMismatch { expected, actual } => {
                write!(
                    f,
                    "identity domain mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<serde_json::Error> for IdentityError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value.to_string())
    }
}

/// Typed domain separators. They are part of every identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDomain {
    /// Subject/candidate identity.
    Subject,
    /// Unsafe boundary identity.
    Boundary,
    /// Obligation identity.
    Obligation,
    /// Court or compatibility-run identity.
    Court,
    /// Execution identity.
    Execution,
    /// Finding identity.
    Finding,
    /// Assessment identity.
    Assessment,
    /// Handoff identity.
    Handoff,
    /// Dependency-graph identity.
    Graph,
    /// Lifecycle-trace identity.
    Trace,
    /// Detector-control identity.
    Control,
    /// Policy identity.
    Policy,
}

impl IdentityDomain {
    /// Exact domain separator bytes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "MS/SUBJECT/v1",
            Self::Boundary => "MS/BOUNDARY/v1",
            Self::Obligation => "MS/OBLIGATION/v1",
            Self::Court => "MS/COURT/v1",
            Self::Execution => "MS/EXECUTION/v1",
            Self::Finding => "MS/FINDING/v1",
            Self::Assessment => "MS/ASSESSMENT/v1",
            Self::Handoff => "MS/HANDOFF/v1",
            Self::Graph => "MS/GRAPH/v1",
            Self::Trace => "MS/TRACE/v1",
            Self::Control => "MS/CONTROL/v1",
            Self::Policy => "MS/POLICY/v1",
        }
    }
}

impl fmt::Display for IdentityDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated full SHA-256 identity with a domain suffix.
///
/// The domain is part of the identity computation and is not recoverable from
/// the textual form. Callers that need a typed comparison store the domain
/// alongside the value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MsId(String);

impl MsId {
    /// Parse the textual `ms1-<64 lowercase hex>` form.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidId`] for a wrong prefix, length, or
    /// non-lowercase hexadecimal payload.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("ms1-") else {
            return Err(IdentityError::InvalidId(value));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IdentityError::InvalidId(value));
        }
        Ok(Self(value))
    }

    /// Borrow the canonical textual form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the canonical textual form.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for MsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for MsId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MsId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(de::Error::custom)
    }
}

/// Compute a domain-separated identity over canonical value bytes.
#[must_use]
pub fn digest_bytes(domain: IdentityDomain, bytes: &[u8]) -> MsId {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_str().as_bytes());
    hasher.update([0u8]);
    hasher.update(bytes);
    let digest = hasher.finalize();
    MsId(format!("ms1-{}", hex_lower(&digest)))
}

/// Parse, strictly validate, canonicalize, and hash a value.
///
/// # Errors
///
/// Returns [`IdentityError`] if the value cannot be encoded in canonical form.
pub fn digest_value(domain: IdentityDomain, value: &Value) -> Result<MsId, IdentityError> {
    Ok(digest_bytes(domain, &canonical_bytes(value)?))
}

/// Lowercase hexadecimal encoding.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode lowercase or uppercase hexadecimal bytes.
///
/// # Errors
///
/// Returns [`IdentityError::InvalidId`] for odd length or non-hex digits.
pub fn hex_decode(value: &str) -> Result<Vec<u8>, IdentityError> {
    if value.len() % 2 != 0 {
        return Err(IdentityError::InvalidId(value.to_owned()));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(|| IdentityError::InvalidId(value.to_owned()))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| IdentityError::InvalidId(value.to_owned()))?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Strict parse without canonicality comparison.
///
/// Duplicate keys and floating-point numbers are rejected during
/// deserialization. Resource limits are enforced after parsing.
///
/// # Errors
///
/// Returns [`IdentityError`] for invalid UTF-8/JSON, duplicate keys, floats,
/// trailing bytes, or a resource-limit violation.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, IdentityError> {
    if bytes.len() > MAX_BYTES {
        return Err(IdentityError::TooLarge {
            actual: bytes.len(),
            limit: MAX_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| IdentityError::InvalidUtf8)?;
    if text.trim().is_empty() {
        return Err(IdentityError::Json("empty input".to_owned()));
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    enforce_limits(&strict.0)?;
    Ok(strict.0)
}

/// Parse and require byte-exact canonical form.
///
/// # Errors
///
/// Returns [`IdentityError::NonCanonical`] when the bytes are valid but not in
/// canonical form, or another [`IdentityError`] when parsing fails.
pub fn require_canonical(bytes: &[u8]) -> Result<Value, IdentityError> {
    let value = parse_strict(bytes)?;
    let encoded = canonical_bytes(&value)?;
    if encoded != bytes {
        return Err(IdentityError::NonCanonical);
    }
    Ok(value)
}

/// Encode a value in `ms-canonical-json-v1`.
///
/// # Errors
///
/// Returns [`IdentityError`] for floats, resource-limit violations, or values
/// that cannot be represented by the restricted grammar.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, IdentityError> {
    enforce_limits(value)?;
    let mut out = Vec::new();
    encode_value(value, "$", &mut out)?;
    Ok(out)
}

fn encode_value(value: &Value, path: &str, out: &mut Vec<u8>) -> Result<(), IdentityError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                out.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_u64() {
                out.extend_from_slice(value.to_string().as_bytes());
            } else {
                return Err(IdentityError::FloatNotAllowed(path.to_owned()));
            }
        }
        Value::String(value) => encode_string(value, out),
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                encode_value(value, &format!("{path}[{index}]"), out)?;
            }
            out.push(b']');
        }
        Value::Object(object) => {
            out.push(b'{');
            let mut entries: Vec<(&String, &Value)> = object.iter().collect();
            entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                encode_string(key, out);
                out.push(b':');
                encode_value(value, &format!("{path}.{key}"), out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn encode_string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            ch if (ch as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", ch as u32).as_bytes());
            }
            ch => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Compare strings by UTF-16 code units, as required by the canonical order.
#[must_use]
pub fn utf16_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn enforce_limits(value: &Value) -> Result<(), IdentityError> {
    let mut nodes = 0usize;
    let mut stack = vec![(value, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES {
            return Err(IdentityError::TooManyNodes {
                actual: nodes,
                limit: MAX_NODES,
            });
        }
        if depth > MAX_DEPTH {
            return Err(IdentityError::TooDeep {
                actual: depth,
                limit: MAX_DEPTH,
            });
        }
        match value {
            Value::String(string) => {
                if string.len() > MAX_STRING_BYTES {
                    return Err(IdentityError::StringTooLong {
                        actual: string.len(),
                        limit: MAX_STRING_BYTES,
                    });
                }
            }
            Value::Array(values) => {
                if values.len() > MAX_ARRAY_ELEMENTS {
                    return Err(IdentityError::TooManyArrayElements {
                        actual: values.len(),
                        limit: MAX_ARRAY_ELEMENTS,
                    });
                }
                for value in values {
                    stack.push((value, depth + 1));
                }
            }
            Value::Object(object) => {
                if object.len() > MAX_OBJECT_MEMBERS {
                    return Err(IdentityError::TooManyObjectMembers {
                        actual: object.len(),
                        limit: MAX_OBJECT_MEMBERS,
                    });
                }
                let mut keys = BTreeSet::new();
                for (key, value) in object {
                    if !keys.insert(key) {
                        return Err(IdentityError::DuplicateKey(key.clone()));
                    }
                    if key.len() > MAX_STRING_BYTES {
                        return Err(IdentityError::StringTooLong {
                            actual: key.len(),
                            limit: MAX_STRING_BYTES,
                        });
                    }
                    stack.push((value, depth + 1));
                }
            }
            Value::Number(number) => {
                if number.as_i64().is_none() && number.as_u64().is_none() {
                    return Err(IdentityError::FloatNotAllowed("$".to_owned()));
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
    }
    Ok(())
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without floating-point numbers or duplicate keys")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        StrictValue::deserialize(deserializer)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Self::Value, E> {
        Err(E::custom(
            "floating-point numbers are not permitted by ms-canonical-json-v1",
        ))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1024));
        while let Some(value) = seq.next_element::<StrictValue>()? {
            values.push(value.0);
            if values.len() > MAX_ARRAY_ELEMENTS {
                return Err(de::Error::custom(format!(
                    "array exceeds {MAX_ARRAY_ELEMENTS} elements"
                )));
            }
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = Map::new();
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate object key {key:?}")));
            }
            if keys.len() > MAX_OBJECT_MEMBERS {
                return Err(de::Error::custom(format!(
                    "object exceeds {MAX_OBJECT_MEMBERS} members"
                )));
            }
            let value = map.next_value::<StrictValue>()?;
            object.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_orders_keys_by_utf16_units() {
        // U+1F600 is encoded as the surrogate pair D83D DE00 in UTF-16, so it
        // sorts before U+E000 even though its scalar value is larger.
        let value = json!({"\u{1f600}": 1, "\u{e000}": 2, "a": 3});
        let bytes = canonical_bytes(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "{\"a\":3,\"\u{1f600}\":1,\"\u{e000}\":2}"
        );
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let error = parse_strict(br#"{"a":1,"a":2}"#).unwrap_err();
        assert!(matches!(error, IdentityError::Json(_)));
    }

    #[test]
    fn float_is_rejected() {
        let error = parse_strict(br#"{"a":1.5}"#).unwrap_err();
        assert!(matches!(error, IdentityError::Json(_)));
    }

    #[test]
    fn noncanonical_is_rejected() {
        assert_eq!(
            require_canonical(br#"{ "a": 1 }"#).unwrap_err(),
            IdentityError::NonCanonical
        );
        assert!(require_canonical(br#"{"a":1}"#).is_ok());
    }

    #[test]
    fn digest_is_domain_separated() {
        let value = json!({"x": 1});
        let a = digest_value(IdentityDomain::Subject, &value).unwrap();
        let b = digest_value(IdentityDomain::Boundary, &value).unwrap();
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("ms1-"));
    }

    #[test]
    fn duplicate_key_after_unescaping_is_rejected() {
        let error = parse_strict(br#"{"a":1,"\u0061":2}"#).unwrap_err();
        assert!(matches!(error, IdentityError::Json(_)));
    }

    #[test]
    fn excess_depth_is_rejected_not_silently_accepted() {
        let mut text = String::new();
        for _ in 0..=MAX_DEPTH {
            text.push('[');
        }
        text.push('0');
        for _ in 0..=MAX_DEPTH {
            text.push(']');
        }
        let error = parse_strict(text.as_bytes()).unwrap_err();
        assert!(
            matches!(
                error,
                IdentityError::TooDeep { .. } | IdentityError::Json(_)
            ),
            "unexpected depth error: {error:?}"
        );
    }

    #[test]
    fn utf16_order_differs_from_scalar_order_for_some_pairs() {
        assert_eq!(utf16_cmp("\u{1f600}", "\u{e000}"), std::cmp::Ordering::Less);
        assert_eq!("\u{1f600}".cmp("\u{e000}"), std::cmp::Ordering::Greater);
        assert_eq!(utf16_cmp("a", "b"), std::cmp::Ordering::Less);
    }
}
