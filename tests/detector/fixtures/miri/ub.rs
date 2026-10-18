//! Test-only Miri canary: dereference a pointer after its allocation was freed.
//!
//! This fixture is intentionally unsound. It exists only to confirm that the
//! live Miri adapter reports a real undefined-behavior diagnostic with a
//! nonzero exit status. It must never be promoted or shipped.

fn main() {
    let mut values = vec![1_u8, 2, 3];
    let pointer = values.as_mut_ptr();
    drop(values);
    // SAFETY: deliberately invalid; the allocation has been freed.
    unsafe {
        *pointer = 9;
    }
    println!("miri ub fixture completed");
}
