//! Test-only Miri specificity control: entirely safe Rust.

fn main() {
    let values: Vec<u32> = (0..8).collect();
    let total: u32 = values.iter().sum();
    assert_eq!(total, 28);
    println!("miri clean control");
}
