//! Phase 7.2 live-chain assertion.
//!
//! With `FRF_BRIDGE_LIVE_BUNDLE` set (the `ci/bridge-gate.sh` path), the test
//! verifies the real captured bundle and requires a complete three-provider
//! custody chain. Without it (the default `ci/gate.sh` path), the test
//! executes the same bridge code and asserts the typed `NOT_RUN` result: no
//! `#[ignore]`, no silent skip.

use std::fs;

use frf_memorysafety::bridge::{
    verify_bundle_bytes, BridgeNotRun, BridgeOutcome, BridgeStatus, CustodyStage,
    BRIDGE_BUNDLE_SCHEMA, BRIDGE_SPEC,
};

#[test]
fn live_chain_is_complete_or_typed_not_run() {
    if let Ok(path) = std::env::var("FRF_BRIDGE_LIVE_BUNDLE") {
        let bytes = fs::read(&path).expect("live bundle is readable");
        let report = verify_bundle_bytes(&bytes, None);
        assert_eq!(report.outcome, BridgeOutcome::Complete);
        assert_eq!(report.stage, CustodyStage::GemelCustody);
        assert_eq!(report.generated_identities, 0);
        assert_eq!(report.authentic_native_identities, 3);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.observations.len(), 3);
    } else {
        let bundle = format!(
            "{{\"schema\":{BRIDGE_BUNDLE_SCHEMA:?},\"spec\":{BRIDGE_SPEC:?},\
             \"expected_candidate_sha256\":\"{}\",\"observations\":[]}}",
            "0".repeat(64)
        );
        let report = verify_bundle_bytes(bundle.as_bytes(), None);
        assert_eq!(
            report.outcome,
            BridgeOutcome::NotRun {
                reason: BridgeNotRun::MissingFinding
            }
        );
        assert_eq!(report.exit_code(), 6);
        assert_eq!(report.generated_identities, 0);
        assert_eq!(report.authentic_native_identities, 0);
        let status = BridgeStatus::observe();
        assert!(!status.all_live_available);
        assert_eq!(status.exit_code(), 6);
    }
}
