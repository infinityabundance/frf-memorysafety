//! Strict canonical-encoding and identity vectors.

use frf_memorysafety::identity::{
    canonical_bytes, digest_bytes, digest_value, parse_strict, require_canonical, IdentityDomain,
    IdentityError, MsId, MAX_ARRAY_ELEMENTS, MAX_BYTES, MAX_DEPTH, MAX_OBJECT_MEMBERS,
    MAX_STRING_BYTES,
};
use serde_json::{json, Value};

const VECTOR: &str = "{\"a\":{\"A\":null,\"b\":true},\"big\":18446744073709551615,\"ctrl\":\"\\u0001\\n\\t\\\"\\\\\",\"neg\":-1,\"z\":0,\"😀\":1,\"\u{e000}\":2}";

#[test]
fn canonical_vector_is_byte_exact_and_utf16_ordered() {
    let value = json!({
        "z": 0,
        "a": {"b": true, "A": null},
        "😀": 1,
        "\u{e000}": 2,
        "ctrl": "\u{0001}\n\t\"\\",
        "neg": -1,
        "big": 18_446_744_073_709_551_615_u64,
    });
    assert_eq!(canonical_bytes(&value).unwrap(), VECTOR.as_bytes());
    assert_eq!(require_canonical(VECTOR.as_bytes()).unwrap(), value);
    assert_eq!(
        require_canonical(format!(" {VECTOR} ").as_bytes()).unwrap_err(),
        IdentityError::NonCanonical
    );
}

#[test]
fn invalid_utf8_is_rejected_as_an_encoding_error() {
    assert!(matches!(
        parse_strict(&[0xff]),
        Err(IdentityError::InvalidUtf8)
    ));
}

#[test]
fn canonical_encoder_enforces_the_encoded_byte_limit() {
    let value = json!({
        "a": "a".repeat(MAX_STRING_BYTES),
        "b": "b".repeat(MAX_STRING_BYTES),
        "c": "c".repeat(MAX_STRING_BYTES),
        "d": "d".repeat(MAX_STRING_BYTES),
        "e": "e".repeat(MAX_STRING_BYTES),
    });
    assert!(matches!(
        canonical_bytes(&value),
        Err(IdentityError::TooLarge { .. })
    ));
}

#[test]
fn duplicate_keys_and_floats_are_rejected() {
    assert!(parse_strict(br#"{"a":1,"a":2}"#).is_err());
    assert!(parse_strict(br#"{"a":1,"\u0061":2}"#).is_err());
    assert!(parse_strict(br#"{"a":1.0}"#).is_err());
    assert!(parse_strict(br#"{"a":1e3}"#).is_err());
    assert!(parse_strict(b"[1,2.5]").is_err());
    assert!(parse_strict(br#"{"a":1}x"#).is_err());
}

#[test]
fn resource_limits_are_enforced() {
    let too_large = vec![b' '; MAX_BYTES + 1];
    assert!(matches!(
        parse_strict(&too_large),
        Err(IdentityError::TooLarge { .. })
    ));

    let long_string = format!("\"{}\"", "a".repeat(MAX_STRING_BYTES + 1));
    assert!(matches!(
        parse_strict(long_string.as_bytes()),
        Err(IdentityError::StringTooLong { .. })
    ));

    let mut nested = String::new();
    for _ in 0..=MAX_DEPTH {
        nested.push('[');
    }
    nested.push('0');
    for _ in 0..=MAX_DEPTH {
        nested.push(']');
    }
    assert!(parse_strict(nested.as_bytes()).is_err());

    let mut members = String::from("{");
    for index in 0..=MAX_OBJECT_MEMBERS {
        if index != 0 {
            members.push(',');
        }
        members.push_str(&format!("\"k{index}\":0"));
    }
    members.push('}');
    assert!(parse_strict(members.as_bytes()).is_err());

    let array = format!(
        "[{}]",
        std::iter::repeat_n("0", MAX_ARRAY_ELEMENTS + 1)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(parse_strict(array.as_bytes()).is_err());

    // 65,536 inner arrays of five numbers exceed the total-node limit while
    // remaining below the per-array member limit.
    let mut nodes = String::from("[");
    for index in 0..65_536 {
        if index != 0 {
            nodes.push(',');
        }
        nodes.push_str("[0,0,0,0,0]");
    }
    nodes.push(']');
    assert!(parse_strict(nodes.as_bytes()).is_err());
}

#[test]
fn domain_separation_changes_every_digest() {
    let value = json!({"x": 1});
    let subject = digest_value(IdentityDomain::Subject, &value).unwrap();
    let boundary = digest_value(IdentityDomain::Boundary, &value).unwrap();
    let policy = digest_value(IdentityDomain::Policy, &value).unwrap();
    assert_ne!(subject, boundary);
    assert_ne!(subject, policy);
    for id in [&subject, &boundary, &policy] {
        let text = id.as_str();
        assert_eq!(text.len(), 4 + 64);
        assert!(text.starts_with("ms1-"));
        assert!(text[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }
    assert_eq!(
        subject,
        digest_bytes(
            IdentityDomain::Subject,
            canonical_bytes(&value).unwrap().as_slice()
        )
    );
}

#[test]
fn identity_parser_is_strict() {
    let ok = MsId::parse(format!("ms1-{}", "a".repeat(64))).unwrap();
    assert_eq!(ok.as_str().len(), 68);
    assert!(MsId::parse(format!("ms1-{}", "A".repeat(64))).is_err());
    assert!(MsId::parse("ms1-abc").is_err());
    assert!(MsId::parse(format!("ms2-{}", "a".repeat(64))).is_err());
    assert!(MsId::parse("").is_err());
}

#[test]
fn canonical_encoder_rejects_floats_inside_values() {
    let value: Value = serde_json::from_str("1.5").unwrap();
    assert!(canonical_bytes(&value).is_err());
}
