//! Test-only Miri harmless-unsafe control.
//!
//! The raw-pointer write below is valid: the pointer is derived from a live
//! mutable reference and is used while the referent is still alive. Miri must
//! not report undefined behavior for this fixture.

fn main() {
    let mut value = 7_u32;
    let pointer = &mut value as *mut u32;
    // SAFETY: `pointer` remains valid for this write.
    unsafe {
        *pointer += 1;
    }
    assert_eq!(value, 8);
    println!("miri harmless unsafe control");
}
