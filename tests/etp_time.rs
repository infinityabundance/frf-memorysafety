//! Phase 10.4a RFC 3161 trusted-time tests.
//!
//! Every test executes. The tests generate a local, test-only TSA under
//! `target/` inside the hardened gate container, create a real OpenSSL `ts`
//! token, and require the declared refusal for each corrupted control. No
//! private key is written outside `target/`.

#![allow(clippy::too_many_lines)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frf_memorysafety::etp_time::{
    current_unix, stamp_token, verify_token, StampTokenRequest, TimeRefusalCode, TimeStatus,
    VerifyTokenRequest, LOCAL_TEST_TSA_TRUST_DOMAIN,
};
use frf_memorysafety::identity::hex_lower;
use sha2::{Digest, Sha256};

const POLICY_OID: &str = "1.3.6.1.4.1.99999.1";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn openssl() -> PathBuf {
    let candidate = PathBuf::from("/usr/bin/openssl");
    if candidate.is_file() {
        candidate
    } else {
        PathBuf::from("openssl")
    }
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read");
    hex_lower(&Sha256::digest(&bytes))
}

fn run(args: &[&str]) {
    let status = Command::new(openssl())
        .args(args)
        .status()
        .expect("openssl");
    assert!(status.success(), "openssl failed: {args:?}");
}

struct TestTsa {
    dir: PathBuf,
    ca: PathBuf,
    tsa_cert: PathBuf,
    other_ca: PathBuf,
    config: PathBuf,
}

impl Drop for TestTsa {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl TestTsa {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let dir = repo()
            .join("target/etp-time-tests")
            .join(format!("tsa-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("test TSA directory");
        let ca_key = dir.join("ca.key");
        let ca = dir.join("ca.crt");
        let tsa_key = dir.join("tsa.key");
        let tsa_csr = dir.join("tsa.csr");
        let tsa_cert = dir.join("tsa.crt");
        let ext = dir.join("ext.cnf");
        let config = dir.join("tsa.cnf");
        let serial_path = dir.join("tsaserial");
        let other_key = dir.join("other.key");
        let other_ca = dir.join("other.crt");
        fs::write(
            &ext,
            "basicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature,nonRepudiation\n\
             extendedKeyUsage=critical,timeStamping\n\
             subjectKeyIdentifier=hash\n\
             authorityKeyIdentifier=keyid,issuer\n",
        )
        .expect("extension config");
        fs::write(&serial_path, "01\n").expect("serial");

        run(&[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            ca_key.to_str().expect("path"),
        ]);
        run(&[
            "req",
            "-new",
            "-x509",
            "-key",
            ca_key.to_str().expect("path"),
            "-out",
            ca.to_str().expect("path"),
            "-days",
            "2",
            "-sha256",
            "-subj",
            "/CN=FRF Test TSA CA (local, test-only)",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        run(&[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            tsa_key.to_str().expect("path"),
        ]);
        run(&[
            "req",
            "-new",
            "-key",
            tsa_key.to_str().expect("path"),
            "-out",
            tsa_csr.to_str().expect("path"),
            "-sha256",
            "-subj",
            "/CN=FRF Local Test TSA",
        ]);
        run(&[
            "x509",
            "-req",
            "-in",
            tsa_csr.to_str().expect("path"),
            "-CA",
            ca.to_str().expect("path"),
            "-CAkey",
            ca_key.to_str().expect("path"),
            "-CAcreateserial",
            "-out",
            tsa_cert.to_str().expect("path"),
            "-days",
            "2",
            "-sha256",
            "-extfile",
            ext.to_str().expect("path"),
        ]);
        run(&[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            other_key.to_str().expect("path"),
        ]);
        run(&[
            "req",
            "-new",
            "-x509",
            "-key",
            other_key.to_str().expect("path"),
            "-out",
            other_ca.to_str().expect("path"),
            "-days",
            "2",
            "-sha256",
            "-subj",
            "/CN=Unrelated Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        fs::write(
            &config,
            format!(
                "[ tsa ]\ndefault_tsa = tsa_config1\n\n\
                 [ tsa_config1 ]\n\
                 dir = {dir}\n\
                 serial = {serial}\n\
                 crypto_device = builtin\n\
                 signer_cert = {cert}\n\
                 certs = {cert}\n\
                 signer_key = {key}\n\
                 signer_digest = sha256\n\
                 default_policy = {policy}\n\
                 other_policies = {policy}\n\
                 digests = sha256, sha384, sha512\n\
                 accuracy = secs:1\n\
                 ordering = yes\n\
                 tsa_name = yes\n\
                 ess_cert_id_chain = no\n\
                 ess_cert_id_alg = sha256\n",
                dir = dir.display(),
                serial = serial_path.display(),
                cert = tsa_cert.display(),
                key = tsa_key.display(),
                policy = POLICY_OID,
            ),
        )
        .expect("TSA config");
        Self {
            dir,
            ca,
            tsa_cert,
            other_ca,
            config,
        }
    }

    fn stamp(&self, imprint: &str) -> (PathBuf, PathBuf, u64) {
        let token = self.dir.join("token.tsr");
        let request = self.dir.join("request.tsq");
        let report = stamp_token(&StampTokenRequest {
            imprint_hex: imprint,
            tsa_config: &self.config,
            tsa_section: None,
            out_token: &token,
            out_request: Some(&request),
            tsa_cert_path: Some(&self.tsa_cert),
            openssl_bin: &openssl(),
            work_dir: &repo().join("target/etp-time-tests/work"),
            timeout_ms: 30_000,
        })
        .expect("token creation");
        assert_eq!(report.status, TimeStatus::Verified);
        assert!(!report.external_trust);
        assert_eq!(report.policy_oid.as_deref(), Some(POLICY_OID));
        assert!(report.gen_time_unix.is_some());
        (
            token,
            request,
            report.gen_time_unix.expect("generation time"),
        )
    }
}

fn imprint_of_manifest() -> String {
    sha256_file(&repo().join("evaluation/earned-trust/MANIFEST.json"))
}

fn verify<'a>(
    token: &'a Path,
    imprint: &'a str,
    tsa: &'a TestTsa,
    now: u64,
    declared: Option<u64>,
    policy_oid: Option<&'a str>,
    verify_at: Option<u64>,
) -> frf_memorysafety::etp_time::TimeReport {
    verify_token(&VerifyTokenRequest {
        token_path: token,
        imprint_hex: imprint,
        tsa_cert_path: Some(&tsa.ca),
        untrusted_path: None,
        expected_policy_oid: policy_oid,
        expected_tsa_cert_sha256: None,
        trust_domain: Some(LOCAL_TEST_TSA_TRUST_DOMAIN),
        verify_at_unix: verify_at,
        now_unix: now,
        declared_execution_unix: declared,
        openssl_bin: &openssl(),
        work_dir: &repo().join("target/etp-time-tests/work"),
        timeout_ms: 30_000,
    })
    .expect("verification")
}

fn refusal_codes(report: &frf_memorysafety::etp_time::TimeReport) -> Vec<TimeRefusalCode> {
    report.refusals.iter().map(|refusal| refusal.code).collect()
}

#[test]
fn valid_token_verifies_with_separate_dimensions() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, _request, gen_time) = tsa.stamp(&imprint);
    let report = verify(
        &token,
        &imprint,
        &tsa,
        gen_time + 1,
        None,
        Some(POLICY_OID),
        None,
    );
    assert_eq!(report.status, TimeStatus::Verified, "{:?}", report.refusals);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.dimensions.imprint.as_str(), "valid");
    assert_eq!(report.dimensions.signature_chain.as_str(), "valid");
    assert_eq!(report.dimensions.hash_algorithm.as_str(), "valid");
    assert_eq!(report.dimensions.policy_oid.as_str(), "valid");
    assert_eq!(report.dimensions.gen_time.as_str(), "valid");
    assert_eq!(
        report.time_dimensions.trusted_timestamping.as_str(),
        "observed"
    );
    assert_eq!(
        report.time_dimensions.experimental_execution.as_str(),
        "not_observed"
    );
    assert_eq!(
        report.time_dimensions.transparency_inclusion.as_str(),
        "not_implemented"
    );
    assert!(!report.execution_time_established);
    assert!(!report.external_trust);
    assert_eq!(report.trust_domain, LOCAL_TEST_TSA_TRUST_DOMAIN);
    assert!(report.token_sha256.len() == 64);
}

#[test]
fn wrong_imprint_is_refused() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, _request, gen_time) = tsa.stamp(&imprint);
    let other = sha256_file(&repo().join("evaluation/earned-trust/protocol.json"));
    let report = verify(&token, &other, &tsa, gen_time + 1, None, None, None);
    assert_eq!(report.status, TimeStatus::Refused);
    assert_eq!(report.exit_code(), 4);
    assert!(refusal_codes(&report).contains(&TimeRefusalCode::ImprintMismatch));
}

#[test]
fn untrusted_tsa_is_refused() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, _request, gen_time) = tsa.stamp(&imprint);
    let report = verify_token(&VerifyTokenRequest {
        token_path: &token,
        imprint_hex: &imprint,
        tsa_cert_path: Some(&tsa.other_ca),
        untrusted_path: None,
        expected_policy_oid: None,
        expected_tsa_cert_sha256: None,
        trust_domain: Some("untrusted-test-ca"),
        verify_at_unix: None,
        now_unix: gen_time + 1,
        declared_execution_unix: None,
        openssl_bin: &openssl(),
        work_dir: &repo().join("target/etp-time-tests/work"),
        timeout_ms: 30_000,
    })
    .expect("verification");
    assert_eq!(report.status, TimeStatus::Refused);
    assert!(refusal_codes(&report).contains(&TimeRefusalCode::UntrustedTsa));
    assert_eq!(report.dimensions.signature_chain.as_str(), "invalid");
}

#[test]
fn expired_tsa_is_refused() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, _request, gen_time) = tsa.stamp(&imprint);
    let report = verify(
        &token,
        &imprint,
        &tsa,
        current_unix(),
        None,
        None,
        Some(gen_time + 10 * 365 * 24 * 60 * 60),
    );
    assert_eq!(report.status, TimeStatus::Refused);
    assert!(refusal_codes(&report).contains(&TimeRefusalCode::ExpiredTsa));
}

#[test]
fn missing_token_is_an_integrity_failure() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let missing = tsa.dir.join("does-not-exist.tsr");
    let error = verify_token(&VerifyTokenRequest {
        token_path: &missing,
        imprint_hex: &imprint,
        tsa_cert_path: Some(&tsa.ca),
        untrusted_path: None,
        expected_policy_oid: None,
        expected_tsa_cert_sha256: None,
        trust_domain: None,
        verify_at_unix: None,
        now_unix: current_unix(),
        declared_execution_unix: None,
        openssl_bin: &openssl(),
        work_dir: &repo().join("target/etp-time-tests/work"),
        timeout_ms: 30_000,
    })
    .expect_err("missing token");
    assert_eq!(error.exit_code(), 3);
}

#[test]
fn backdated_claim_is_refused() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, _request, gen_time) = tsa.stamp(&imprint);
    let report = verify(
        &token,
        &imprint,
        &tsa,
        gen_time + 1,
        Some(gen_time - 86_400),
        None,
        None,
    );
    assert_eq!(report.status, TimeStatus::Refused);
    assert_eq!(
        report.backdating.classification.as_str(),
        "declared_precedes_timestamp"
    );
    assert!(!report.backdating.execution_time_established);
    assert!(refusal_codes(&report).contains(&TimeRefusalCode::BackdatedClaim));
}

#[test]
fn missing_trust_anchor_is_refused() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, _request, gen_time) = tsa.stamp(&imprint);
    let report = verify_token(&VerifyTokenRequest {
        token_path: &token,
        imprint_hex: &imprint,
        tsa_cert_path: None,
        untrusted_path: None,
        expected_policy_oid: None,
        expected_tsa_cert_sha256: None,
        trust_domain: None,
        verify_at_unix: None,
        now_unix: gen_time + 1,
        declared_execution_unix: None,
        openssl_bin: &openssl(),
        work_dir: &repo().join("target/etp-time-tests/work"),
        timeout_ms: 30_000,
    })
    .expect("verification");
    assert_eq!(report.status, TimeStatus::Refused);
    assert!(refusal_codes(&report).contains(&TimeRefusalCode::NoTrustAnchor));
    assert_eq!(report.dimensions.signature_chain.as_str(), "not_checked");
}

#[test]
fn policy_oid_mismatch_is_refused() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, _request, gen_time) = tsa.stamp(&imprint);
    let report = verify(
        &token,
        &imprint,
        &tsa,
        gen_time + 1,
        None,
        Some("1.2.3.4"),
        None,
    );
    assert_eq!(report.status, TimeStatus::Refused);
    assert!(refusal_codes(&report).contains(&TimeRefusalCode::PolicyOidMismatch));
}

#[test]
fn token_binds_the_exact_evidence_digest() {
    let tsa = TestTsa::new();
    let imprint = imprint_of_manifest();
    let (token, request, gen_time) = tsa.stamp(&imprint);
    assert!(request.is_file());
    let report = verify(&token, &imprint, &tsa, gen_time + 1, None, None, None);
    assert_eq!(report.imprint_in_token.as_deref(), Some(imprint.as_str()));
    assert_eq!(report.imprint_expected, imprint);
    assert_eq!(
        report.time_dimensions.source_creation.as_str(),
        "not_observed"
    );
    assert_eq!(
        report.time_dimensions.evidence_production.as_str(),
        "not_observed"
    );
    assert_eq!(
        report.time_dimensions.statement_authentication.as_str(),
        "not_observed"
    );
    assert_eq!(
        report.time_dimensions.release_authorization.as_str(),
        "not_observed"
    );
}
