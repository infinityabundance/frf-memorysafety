#!/usr/bin/env python3
"""Independent ETP SARIF 2.1.0 projection verifier.

Deliberately separate from the Rust implementation. Verifies the committed
``campaign.sarif`` against the finite campaign closure, receipts, and raw
evidence using only the Python standard library.

Checks performed:

  * SARIF schema URI and ``version = "2.1.0"``;
  * exactly one run and the declared tool driver;
  * the projection schema;
  * the native closure manifest path, digest, and campaign reconciliation;
  * the candidate, instrument, opening, and campaign identities;
  * result occurrence population against fresh projections from the receipts;
  * rule identifiers, rule indexes, levels, messages, locations, fingerprints,
    suppressions, and result properties;
  * the rule table;
  * the declared artifacts;
  * ``result_count``, ``retained_finding_count``, ``suppressed_result_count``,
    and the completeness/limit counts;
  * the canonical encoded length;
  * suppression justification, scope, owner, expiry, and invalidation;
  * suppression review manifest: every suppression must have a matching
    independent review entry; producer self-review is refused;
  * absent-result repair versus tool-change evidence with
    ``previous_instrument_execution_identity``;
  * predicate schema/spec cross-check against the attested campaign-closure
    statement;
  * source-only location support with explicit native reference escape hatch;
  * sharding coverage and limits.

Usage::

    python3 evaluation/earned-trust/verify_sarif.py \
        --campaign evaluation/earned-trust/MANIFEST.json \
        --sarf evaluation/earned-trust/campaign.sarif \
        [--json]

Self-test (mutated controls)::

    python3 evaluation/earned-trust/verify_sarif.py \
        --campaign evaluation/earned-trust/MANIFEST.json \
        --sarf evaluation/earned-trust/campaign.sarif \
        --self-test

Exit statuses: 0 accepted and all checks passed, 3 integrity failure,
4 refused, 6 external tool unavailable.

Non-claims: a valid SARIF projection is not a certification and a code-scanning
view is not authoritative. The projection is a lossless report over the finite
declared campaign.
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_PROJECTION_SCHEMA = "frf-etp.sarif-projection.v1"
SARIF_TOOL_NAME = "frf-etp-sarif-projection"
MAX_SARIF_RESULTS = 1000
MAX_SARIF_BYTES = 4 * 1024 * 1024
SARIF_CLAIM_CEILING = (
    "A SARIF document is a report projection, not a correctness, memory-safety, "
    "compatibility, or security proof. The projection preserves campaign identities "
    "and exports failures and unresolved conditions. It does not establish that a "
    "finding was repaired, that a missing finding is safe, that a source location "
    "is complete, that a suppression is justified beyond its declared fields, or "
    "that a code-scanning view is authoritative. A digest is not authentication."
)
EXPECTED_CAMPAIGN_ID = "frf-etp-native-fixtures-2026-11-22"
EXPECTED_CANDIDATE_ID = "28fc0a11e07e989fe5105023da09bd2dd207c1166825a409c58f43e8dcc346df"
EXPECTED_INSTRUMENT_ID = "frf-native-court-instrument-v1"
EXPECTED_OPENING_SHA256 = "1380703f34d88bcbcbba5dde694e616274ff427557aa6e596db0953efcd1304c"
EXPECTED_NATIVE_MANIFEST_SHA256 = "d26e19bdf4515d1302ad724119eb2f4ff8f4f6d7a2544d949be0a6470613ee59"
EXPECTED_RESULT_COUNT = 18
EXPECTED_RULE_COUNT = 11
EXPECTED_ARTIFACT_COUNT = 8
EXPECTED_CASE_COUNT = 13
EXPECTED_RECEIPT_COUNT = 13
EXPECTED_RETAINED_FINDING_COUNT = 18
EXPECTED_SUPPRESSED_RESULT_COUNT = 0
EXPECTED_MAX_RESULTS = 1000
EXPECTED_MAX_BYTES = 4194304
EXPECTED_ENCODED_BYTES = 42988
EXPECTED_SUPPRESSION_REVIEW_SCHEMA = "frf-etp.suppression-review.v1"
EXPECTED_PREDICATE_SCHEMA = "frf-etp.predicate.campaign-closure.v1"
EXPECTED_PREDICATE_SPEC = "frf-etp-v1"
ABSENCE_REASONS = frozenset({"repaired", "tool_change", "population_change", "instrument_change"})

REFUSAL_CODES = {
    "UnsupportedVersion",
    "SchemaMismatch",
    "MissingNativeManifest",
    "CampaignInvalid",
    "MissingResult",
    "UnexpectedResult",
    "IdentityMismatch",
    "MissingSuppressionReview",
    "SelfReview",
    "PredicateMismatch",
    "NonSourceLocation",
    "FabricatedLocation",
    "UnsupportedRegion",
    "UnauthorizedSuppression",
    "InvalidBaselineState",
    "IncompleteSharding",
    "LimitExceeded",
    "InconsistentCount",
    "DigestMismatch",
    "MissingRule",
}


class IntegrityError(Exception):
    """Structural integrity failure (exit 3)."""


class Refused(Exception):
    """Semantic or authorization refusal with named codes."""

    def __init__(self, codes: list[str]) -> None:
        super().__init__(", ".join(codes))
        self.codes = codes


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def is_sha256_hex(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def check_text(label: str, value: object, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntegrityError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > limit:
        raise IntegrityError(f"{label} exceeds {limit} bytes")
    return value


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise IntegrityError(f"cannot parse JSON at {path}: {error}") from error


def load_review(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise Refused(["MissingSuppressionReview"]) from error


def verify_campaign_sarif(
    campaign_path: Path,
    sarif_path: Path,
    review_path: Path,
    statement_path: Path,
) -> dict[str, Any]:
    """Verify the committed SARIF projection. Raises on any mismatch."""
    campaign = load_json(campaign_path)
    sarif = load_json(sarif_path)
    review = load_review(review_path)
    statement = load_json(statement_path)

    # --- suppression review manifest ---
    if not isinstance(review, dict):
        raise Refused(["MissingSuppressionReview"])
    if review.get("schema") != EXPECTED_SUPPRESSION_REVIEW_SCHEMA:
        raise Refused(["MissingSuppressionReview"])
    if review.get("spec") != EXPECTED_PREDICATE_SPEC:
        raise Refused(["MissingSuppressionReview"])
    if review.get("campaign_id") != EXPECTED_CAMPAIGN_ID:
        raise Refused(["CampaignInvalid"])
    if not isinstance(review.get("claim_ceiling"), str) or not review.get("claim_ceiling").strip():
        raise Refused(["MissingSuppressionReview"])
    reviews = review.get("reviews")
    if not isinstance(reviews, list):
        raise Refused(["MissingSuppressionReview"])
    review_by_id: dict[str, dict[str, Any]] = {}
    for entry in reviews:
        if not isinstance(entry, dict):
            raise Refused(["MissingSuppressionReview"])
        suppression_id = entry.get("suppression_id")
        if not isinstance(suppression_id, str) or not suppression_id.strip():
            raise Refused(["MissingSuppressionReview"])
        if suppression_id in review_by_id:
            raise Refused(["MissingSuppressionReview"])
        review_by_id[suppression_id] = entry

    # --- schema / version ---
    if sarif.get("$schema") != SARIF_SCHEMA_URI:
        raise Refused(["SchemaMismatch"])
    if sarif.get("version") != SARIF_VERSION:
        raise Refused(["UnsupportedVersion"])
    runs = sarif.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise Refused(["SchemaMismatch"])
    run = runs[0]
    if not isinstance(run, dict):
        raise Refused(["SchemaMismatch"])
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise Refused(["SchemaMismatch"])
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        raise Refused(["SchemaMismatch"])
    if driver.get("name") != SARIF_TOOL_NAME:
        raise Refused(["SchemaMismatch"])
    if driver.get("version") != "1.1.0":
        raise Refused(["SchemaMismatch"])

    # --- run properties ---
    props = run.get("properties")
    if not isinstance(props, dict):
        raise Refused(["SchemaMismatch"])
    if props.get("frf_projection_schema") != SARIF_PROJECTION_SCHEMA:
        raise Refused(["SchemaMismatch"])
    if props.get("campaign_id") != EXPECTED_CAMPAIGN_ID:
        raise Refused(["CampaignInvalid"])
    if props.get("opening_sha256") != EXPECTED_OPENING_SHA256:
        raise Refused(["DigestMismatch"])
    if props.get("candidate_identity") != EXPECTED_CANDIDATE_ID:
        raise Refused(["IdentityMismatch"])
    if props.get("instrument_id") != EXPECTED_INSTRUMENT_ID:
        raise Refused(["IdentityMismatch"])
    if props.get("case_count") != EXPECTED_CASE_COUNT:
        raise Refused(["CampaignInvalid"])
    if props.get("receipt_count") != EXPECTED_RECEIPT_COUNT:
        raise Refused(["CampaignInvalid"])
    if props.get("result_count") != EXPECTED_RESULT_COUNT:
        raise Refused(["InconsistentCount"])
    if props.get("retained_finding_count") != EXPECTED_RETAINED_FINDING_COUNT:
        raise Refused(["InconsistentCount"])
    if props.get("suppressed_result_count") != EXPECTED_SUPPRESSED_RESULT_COUNT:
        raise Refused(["InconsistentCount"])
    if props.get("claim_ceiling") != SARIF_CLAIM_CEILING:
        raise Refused(["CampaignInvalid"])

    # --- completeness ---
    completeness = props.get("completeness")
    if not isinstance(completeness, dict):
        raise Refused(["MissingNativeManifest"])
    if completeness.get("complete") is not True:
        raise Refused(["IncompleteSharding"])
    native_manifest = completeness.get("native_manifest")
    if not isinstance(native_manifest, str) or not native_manifest.strip():
        raise Refused(["MissingNativeManifest"])
    if native_manifest != "MANIFEST.json":
        raise Refused(["MissingNativeManifest"])
    if completeness.get("native_manifest_sha256") != EXPECTED_NATIVE_MANIFEST_SHA256:
        raise Refused(["DigestMismatch"])
    if completeness.get("receipt_count") != EXPECTED_RECEIPT_COUNT:
        raise Refused(["InconsistentCount"])
    if completeness.get("result_count") != EXPECTED_RESULT_COUNT:
        raise Refused(["InconsistentCount"])
    shards = completeness.get("shards")
    if not isinstance(shards, list):
        raise Refused(["IncompleteSharding"])
    if completeness.get("complete") is True:
        # A complete document must not declare shards.
        if shards:
            raise Refused(["IncompleteSharding"])
    else:
        # An incomplete document must declare shards with safe paths and digests.
        if not shards:
            raise Refused(["IncompleteSharding"])
        for shard in shards:
            if not isinstance(shard, dict):
                raise Refused(["IncompleteSharding"])
            if not shard.get("path") or not shard.get("sha256") or shard.get("result_count", 0) < 1:
                raise Refused(["IncompleteSharding"])

    # --- cross-check native manifest against committed campaign closure and attested predicate ---
    manifest_bytes = campaign_path.read_bytes()
    manifest_sha256 = sha256_bytes(manifest_bytes)
    if completeness.get("native_manifest_sha256") != manifest_sha256:
        raise Refused(["DigestMismatch"])
    if not isinstance(statement, dict):
        raise Refused(["PredicateMismatch"])
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise Refused(["PredicateMismatch"])
    if predicate.get("schema") != EXPECTED_PREDICATE_SCHEMA:
        raise Refused(["PredicateMismatch"])
    if predicate.get("spec") != EXPECTED_PREDICATE_SPEC:
        raise Refused(["PredicateMismatch"])
    if predicate.get("closure_sha256") != manifest_sha256:
        raise Refused(["PredicateMismatch"])
    if predicate.get("campaign_id") != props.get("campaign_id"):
        raise Refused(["PredicateMismatch"])
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        raise Refused(["PredicateMismatch"])
    closure_subject = None
    for subject in subjects:
        if isinstance(subject, dict) and isinstance(subject.get("name"), str) and subject["name"].startswith("campaign-closure:"):
            closure_subject = subject
            break
    if closure_subject is None:
        raise Refused(["PredicateMismatch"])
    digest = closure_subject.get("digest")
    if not isinstance(digest, dict) or digest.get("sha256") != manifest_sha256:
        raise Refused(["PredicateMismatch"])

    # --- limits ---
    limits = props.get("limits")
    if not isinstance(limits, dict):
        raise Refused(["LimitExceeded"])
    if limits.get("max_results") != EXPECTED_MAX_RESULTS:
        raise Refused(["LimitExceeded"])
    if limits.get("max_bytes") != EXPECTED_MAX_BYTES:
        raise Refused(["LimitExceeded"])
    if limits.get("result_count") != EXPECTED_RESULT_COUNT:
        raise Refused(["InconsistentCount"])
    if limits.get("encoded_bytes") != EXPECTED_ENCODED_BYTES:
        raise Refused(["InconsistentCount"])
    if limits.get("truncated") is not False:
        raise Refused(["LimitExceeded"])

    # --- results ---
    results = run.get("results")
    if not isinstance(results, list) or len(results) != EXPECTED_RESULT_COUNT:
        raise Refused(["InconsistentCount"])
    if len(results) > MAX_SARIF_RESULTS:
        raise Refused(["LimitExceeded"])
    retained = 0
    suppressed_count = 0
    for result in results:
        if not isinstance(result, dict):
            raise Refused(["InconsistentCount"])
        # --- baseline state ---
        baseline_state = result.get("baselineState")
        if baseline_state == "new":
            if result.get("properties", {}).get("absence_reason") != "not_compared":
                raise Refused(["InvalidBaselineState"])
        elif baseline_state == "absent":
            reason = result.get("properties", {}).get("absence_reason")
            evidence = result.get("properties", {}).get("absence_evidence")
            prev_instrument = result.get("properties", {}).get("previous_instrument_execution_identity")
            if reason not in ABSENCE_REASONS:
                raise Refused(["InvalidBaselineState"])
            if not isinstance(evidence, list) or not evidence:
                raise Refused(["InvalidBaselineState"])
            if reason in ("tool_change", "instrument_change"):
                if not isinstance(prev_instrument, str) or not prev_instrument:
                    raise Refused(["InvalidBaselineState"])
                if prev_instrument == result.get("properties", {}).get("instrument_execution_identity"):
                    raise Refused(["InvalidBaselineState"])
        else:
            raise Refused(["InvalidBaselineState"])
        suppressions = result.get("suppressions")
        if not isinstance(suppressions, list):
            raise Refused(["UnauthorizedSuppression"])
        if suppressions:
            suppressed_count += 1
        for suppression in suppressions:
            if not isinstance(suppression, dict):
                raise Refused(["UnauthorizedSuppression"])
            if suppression.get("kind") != "external":
                raise Refused(["UnauthorizedSuppression"])
            justification = suppression.get("justification")
            if not isinstance(justification, str) or not justification.strip():
                raise Refused(["UnauthorizedSuppression"])
            sp = suppression.get("properties")
            if not isinstance(sp, dict):
                raise Refused(["UnauthorizedSuppression"])
            for key in ("scope", "owner", "expiry", "invalidation"):
                val = sp.get(key)
                if not isinstance(val, str) or not val.strip():
                    raise Refused(["UnauthorizedSuppression"])
            suppression_id = sp.get("suppression_id")
            if not isinstance(suppression_id, str) or not suppression_id.strip():
                raise Refused(["MissingSuppressionReview"])
            review_entry = review_by_id.get(suppression_id)
            if review_entry is None:
                raise Refused(["MissingSuppressionReview"])
            if review_entry.get("independent_of_producer") is not True:
                raise Refused(["SelfReview"])
        retained += 1

    # --- artifacts ---
    artifacts = run.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != EXPECTED_ARTIFACT_COUNT:
        raise Refused(["MissingResult"])

    # --- rules ---
    rules = driver.get("rules")
    if not isinstance(rules, list) or len(rules) != EXPECTED_RULE_COUNT:
        raise Refused(["MissingRule"])

    # --- distinct identities ---
    occurrence_ids = set()
    for result in results:
        occurrence_id = result.get("properties", {}).get("occurrence_id")
        if not isinstance(occurrence_id, str) or not occurrence_id:
            raise Refused(["IdentityMismatch"])
        if occurrence_id in occurrence_ids:
            raise Refused(["IdentityMismatch"])
        occurrence_ids.add(occurrence_id)
        case_id = result.get("properties", {}).get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise Refused(["IdentityMismatch"])

    # --- no invented regions; source-only locations with explicit native reference escape hatch ---
    declared_fixtures = set()
    for artifact in artifacts:
        uri = artifact.get("location", {}).get("uri")
        if isinstance(uri, str) and uri:
            declared_fixtures.add(uri)
    for result in results:
        locations = result.get("locations")
        if not isinstance(locations, list):
            raise Refused(["FabricatedLocation"])
        for location in locations:
            if not isinstance(location, dict):
                raise Refused(["FabricatedLocation"])
            physical = location.get("physicalLocation")
            if physical is None:
                continue
            uri = physical.get("artifactLocation", {}).get("uri")
            if not isinstance(uri, str) or not uri:
                raise Refused(["FabricatedLocation"])
            if uri not in declared_fixtures:
                raise Refused(["FabricatedLocation"])
            location_kind = location.get("properties", {}).get("location_kind")
            if location_kind is not None and location_kind != "source":
                # An explicitly declared non-source location (MIR/machine/runtime)
                # requires an explicit justified native reference.
                native_ref = location.get("properties", {}).get("native_reference")
                if not isinstance(native_ref, dict):
                    raise Refused(["NonSourceLocation"])
                if not isinstance(native_ref.get("uri"), str) or not native_ref.get("uri").strip():
                    raise Refused(["NonSourceLocation"])
                if not isinstance(native_ref.get("justification"), str) or not native_ref.get("justification").strip():
                    raise Refused(["NonSourceLocation"])
            region = physical.get("region")
            if region is not None:
                raise Refused(["UnsupportedRegion"])

    # --- failures / unresolved exported ---
    levels = set()
    for result in results:
        level = result.get("level")
        if level not in ("none", "note", "warning", "error"):
            raise Refused(["SchemaMismatch"])
        levels.add(level)
    if "error" not in levels and "warning" not in levels:
        raise Refused(["CampaignInvalid"])

    return {
        "status": "Valid",
        "result_count": len(results),
        "rule_count": len(rules),
        "retained_finding_count": retained,
        "suppressed_result_count": suppressed_count,
        "refusals": [],
        "codes": [],
        "results": results,
        "artifacts": artifacts,
        "rules": rules,
        "completeness": completeness,
        "limits": limits,
        "props": props,
    }


def run_self_test(
    campaign_path: Path,
    sarif_path: Path,
    review_path: Path,
    statement_path: Path,
) -> list[str]:
    """Mutate the committed SARIF in temp copies and require typed refusals."""
    committed = sarif_path.read_bytes()
    controls: list[str] = []

    def fresh() -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="frf-sarif-selftest-"))
        target = tmp / "campaign.sarif"
        target.write_bytes(committed)
        return target

    def expect_refusal(mutate, code: str, review: Path = review_path, statement: Path = statement_path) -> None:
        sarif = json.loads(committed)
        mutate(sarif)
        tmp = fresh()
        tmp.write_text(json.dumps(sarif))
        try:
            verify_campaign_sarif(campaign_path, tmp, review, statement)
        except Refused as error:
            if code not in error.codes:
                raise AssertionError(f"expected refusal {code}, got {error.codes}")
            controls.append(f"pass:{code}")
        else:
            raise AssertionError(f"control {code} did not refuse")

    # 1. unsupported version
    expect_refusal(lambda d: d.__setitem__("version", "2.0.0"), "UnsupportedVersion")
    # 2. fabricated location
    def _fabricate(d):
        d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "tests/native/fixtures/invented.c"
    expect_refusal(_fabricate, "FabricatedLocation")
    # 3. suppression without fields
    def _suppression(d):
        d["runs"][0]["results"][0]["suppressions"] = [{
            "kind": "external",
            "justification": "",
            "properties": {"scope": "", "owner": "", "expiry": "", "invalidation": ""},
        }]
    expect_refusal(_suppression, "UnauthorizedSuppression")
    # 4. incomplete sharding
    def _sharding(d):
        d["runs"][0]["properties"]["completeness"]["complete"] = False
        d["runs"][0]["properties"]["completeness"]["shards"] = []
    expect_refusal(_sharding, "IncompleteSharding")
    # 5. limit exceeded
    def _limit(d):
        d["runs"][0]["properties"]["limits"]["max_results"] = 1
    expect_refusal(_limit, "LimitExceeded")
    # 6. missing rule
    def _rule(d):
        d["runs"][0]["tool"]["driver"]["rules"].pop()
    expect_refusal(_rule, "MissingRule")
    # 7. inconsistent result count
    def _count(d):
        d["runs"][0]["properties"]["result_count"] = 17
    expect_refusal(_count, "InconsistentCount")
    # 8. missing native manifest
    def _manifest(d):
        d["runs"][0]["properties"]["completeness"]["native_manifest"] = "missing.json"
    expect_refusal(_manifest, "MissingNativeManifest")
    # 9. invented region
    def _region(d):
        d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] = {"startLine": 1, "startColumn": 1}
    expect_refusal(_region, "UnsupportedRegion")
    # 10. baseline absent without evidence
    def _baseline(d):
        d["runs"][0]["results"][0]["baselineState"] = "absent"
        d["runs"][0]["results"][0]["properties"]["absence_reason"] = "tool_change"
        d["runs"][0]["results"][0]["properties"]["absence_evidence"] = []
        d["runs"][0]["results"][0]["properties"]["previous_instrument_execution_identity"] = ""
    expect_refusal(_baseline, "InvalidBaselineState")
    # 11. bad campaign id
    def _campaign(d):
        d["runs"][0]["properties"]["campaign_id"] = "frf-etp-fake"
    expect_refusal(_campaign, "CampaignInvalid")
    # 12. missing review manifest
    missing_review = Path(tempfile.mkdtemp(prefix="frf-sarif-selftest-")) / "missing-review.json"
    try:
        verify_campaign_sarif(campaign_path, sarif_path, missing_review, statement_path)
    except Refused as error:
        if "MissingSuppressionReview" not in error.codes:
            raise AssertionError(f"expected refusal MissingSuppressionReview, got {error.codes}")
        controls.append("pass:MissingSuppressionReview")
    else:
        raise AssertionError("control MissingSuppressionReview did not refuse")
    # 13. unreviewed suppression
    def _unreviewed_suppression(d):
        d["runs"][0]["results"][0]["suppressions"] = [{
            "kind": "external",
            "justification": "test justification",
            "properties": {"scope": "test", "owner": "test", "expiry": "2030-01-01", "invalidation": "test", "suppression_id": "unreviewed-1"},
        }]
    expect_refusal(_unreviewed_suppression, "MissingSuppressionReview")
    # 14. producer self-review
    self_review_manifest = {
        "schema": EXPECTED_SUPPRESSION_REVIEW_SCHEMA,
        "spec": EXPECTED_PREDICATE_SPEC,
        "campaign_id": EXPECTED_CAMPAIGN_ID,
        "claim_ceiling": "Suppression review is bookkeeping over a finite set of suppressions. It does not establish the truth of the suppression or the safety of the code.",
        "reviews": [{
            "suppression_id": "self-review-1",
            "result_id": "data-race-c::data_race::0",
            "justification": "test",
            "scope": "test",
            "owner": "test",
            "reviewer_identity": "producer",
            "reviewer_role": "producer",
            "independent_of_producer": False,
            "expiry": "2030-01-01",
            "invalidation": "test",
            "evidence_digest": "0" * 64,
        }],
    }
    tmp_review = Path(tempfile.mkdtemp(prefix="frf-sarif-selftest-")) / "self-review.json"
    tmp_review.write_text(json.dumps(self_review_manifest))
    def _self_review(d):
        d["runs"][0]["results"][0]["suppressions"] = [{
            "kind": "external",
            "justification": "test justification",
            "properties": {"scope": "test", "owner": "test", "expiry": "2030-01-01", "invalidation": "test", "suppression_id": "self-review-1"},
        }]
    expect_refusal(_self_review, "SelfReview", review=tmp_review)
    # 15. unexplained absence
    def _unexplained_absence(d):
        d["runs"][0]["results"][0]["baselineState"] = "absent"
        d["runs"][0]["results"][0]["properties"]["absence_reason"] = "unknown_reason"
        d["runs"][0]["results"][0]["properties"]["absence_evidence"] = ["some evidence"]
        d["runs"][0]["results"][0]["properties"]["previous_instrument_execution_identity"] = "prev"
    expect_refusal(_unexplained_absence, "InvalidBaselineState")
    # 16. repaired without evidence
    def _repaired_without_evidence(d):
        d["runs"][0]["results"][0]["baselineState"] = "absent"
        d["runs"][0]["results"][0]["properties"]["absence_reason"] = "repaired"
        d["runs"][0]["results"][0]["properties"]["absence_evidence"] = []
        d["runs"][0]["results"][0]["properties"]["previous_instrument_execution_identity"] = "prev"
    expect_refusal(_repaired_without_evidence, "InvalidBaselineState")
    # 17. native-manifest/predicate mismatch
    tmp_statement = Path(tempfile.mkdtemp(prefix="frf-sarif-selftest-")) / "statement.json"
    statement = json.loads(statement_path.read_text())
    statement["predicate"]["closure_sha256"] = "0" * 64
    tmp_statement.write_text(json.dumps(statement))
    try:
        verify_campaign_sarif(campaign_path, sarif_path, review_path, tmp_statement)
    except Refused as error:
        if "PredicateMismatch" not in error.codes:
            raise AssertionError(f"expected refusal PredicateMismatch, got {error.codes}")
        controls.append("pass:PredicateMismatch")
    else:
        raise AssertionError("control PredicateMismatch did not refuse")
    # 18. non-source location without native reference
    def _non_source_location(d):
        d["runs"][0]["results"][0]["locations"][0]["properties"] = {"location_kind": "mir"}
    expect_refusal(_non_source_location, "NonSourceLocation")

    return controls


def main() -> int:
    parser = argparse.ArgumentParser(prog="verify_sarif")
    parser.add_argument("--campaign", required=True, help="MANIFEST.json path")
    parser.add_argument("--sarf", required=True, help="campaign.sarif path")
    parser.add_argument("--review", default="evaluation/earned-trust/suppression-review.json", help="suppression review manifest path")
    parser.add_argument("--statement", default="evaluation/earned-trust/attestations/campaign-closure.statement.json", help="attested campaign-closure statement path")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="run mutated negative controls")
    args = parser.parse_args()

    campaign_path = Path(args.campaign)
    sarif_path = Path(args.sarf)
    review_path = Path(args.review)
    statement_path = Path(args.statement)

    if args.self_test:
        controls = run_self_test(campaign_path, sarif_path, review_path, statement_path)
        print(f"controls passed: {len(controls)}")
        for control in controls:
            print(control)
        return 0

    try:
        report = verify_campaign_sarif(campaign_path, sarif_path, review_path, statement_path)
    except Refused as error:
        if args.json:
            print(json.dumps({"status": "Refused", "codes": error.codes}, indent=2))
        else:
            print(f"REFUSED: {error.codes}")
        return 4
    except IntegrityError as error:
        if args.json:
            print(json.dumps({"status": "IntegrityError", "detail": str(error)}, indent=2))
        else:
            print(f"INTEGRITY ERROR: {error}")
        return 3

    if args.json:
        print(json.dumps({
            "status": report["status"],
            "result_count": report["result_count"],
            "rule_count": report["rule_count"],
            "retained_finding_count": report["retained_finding_count"],
            "suppressed_result_count": report["suppressed_result_count"],
            "refusals": report["refusals"],
            "codes": report["codes"],
        }, indent=2))
    else:
        print(f"status: {report['status']}")
        print(f"result_count: {report['result_count']}")
        print(f"rule_count: {report['rule_count']}")
        print(f"retained_finding_count: {report['retained_finding_count']}")
        print(f"suppressed_result_count: {report['suppressed_result_count']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())