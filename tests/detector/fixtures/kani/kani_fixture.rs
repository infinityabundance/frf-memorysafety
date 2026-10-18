//! Test-only Kani fixture.
//!
//! `known_bad` contains a real bounded assertion failure. `proof_control` is a
//! tautology that Kani must verify successfully. Both are bounded and small.

#[kani::proof]
fn known_bad() {
    let value: u8 = kani::any();
    assert!(value < 128);
}

#[kani::proof]
fn proof_control() {
    let value: u8 = kani::any();
    assert!(value <= u8::MAX);
}
