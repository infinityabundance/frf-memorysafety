//! Phase 9.2 publication checks.
//!
//! The paper claim table must map every claim to at least one receipt. This test
//! scans `PAPER.md` directly; it does not trust the table's prose.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;

use serde_json::Value;

fn read_json(path: &str) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

#[test]
fn paper_claim_table_maps_every_claim_to_receipts() {
    let paper = fs::read_to_string("PAPER.md").expect("PAPER.md");
    let claims = read_json("evaluation/CLAIMS.json");
    let entries = claims["claims"]
        .as_array()
        .expect("CLAIMS.json claims array");

    let mut by_id: BTreeMap<String, &Value> = BTreeMap::new();
    for entry in entries {
        let id = entry["id"]
            .as_str()
            .expect("CLAIMS.json claim id")
            .to_owned();
        assert!(
            entry["receipts"]
                .as_array()
                .is_some_and(|receipts| !receipts.is_empty()),
            "claim {id} has no receipt mapping"
        );
        assert!(
            entry["observed"].is_object(),
            "claim {id} has no observed value"
        );
        assert!(
            matches!(entry["status"].as_str(), Some("supported" | "unsupported")),
            "claim {id} has an invalid status"
        );
        assert!(
            by_id.insert(id.clone(), entry).is_none(),
            "duplicate claim {id}"
        );
    }

    let mut table_ids = Vec::new();
    for line in paper.lines() {
        let line = line.trim();
        if !line.starts_with("| PC") {
            continue;
        }
        let first = line
            .trim_matches('|')
            .split('|')
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        assert!(
            first.starts_with("PC") && first[2..].chars().all(|c| c.is_ascii_digit()),
            "malformed paper claim id {first:?}"
        );
        table_ids.push(first);
    }
    assert!(!table_ids.is_empty(), "PAPER.md has no claim table rows");

    let table_set: BTreeSet<String> = table_ids.iter().cloned().collect();
    assert_eq!(
        table_set.len(),
        table_ids.len(),
        "PAPER.md repeats a claim id"
    );

    for id in &table_ids {
        let entry = by_id
            .get(id)
            .unwrap_or_else(|| panic!("PAPER.md claim {id} is missing from CLAIMS.json"));
        assert!(
            entry["receipts"]
                .as_array()
                .is_some_and(|receipts| !receipts.is_empty()),
            "PAPER.md claim {id} has no receipt mapping"
        );
    }

    for (id, entry) in &by_id {
        if entry["in_paper"].as_bool().unwrap_or(false) {
            assert!(
                table_set.contains(id),
                "CLAIMS.json claim {id} is missing from the PAPER.md table"
            );
        }
    }

    assert!(
        paper.contains(claims["protocol_sha256"].as_str().expect("digest")),
        "PAPER.md does not record the frozen protocol digest"
    );
}
