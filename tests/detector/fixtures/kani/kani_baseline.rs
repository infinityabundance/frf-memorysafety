//! Test-only native baseline for the Kani adapter's separate build identity.

fn main() {
    let value: u8 = 7;
    assert!(value <= u8::MAX);
    println!("kani native baseline control");
}
