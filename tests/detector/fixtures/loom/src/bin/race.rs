//! Test-only loom canary: two unsynchronized increments lose an update under
//! at least one modeled interleaving.

use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

fn main() {
    loom::model(|| {
        let cell = Arc::new(UnsafeCell::new(0_usize));
        let first = cell.clone();
        let second = cell.clone();
        let left = thread::spawn(move || {
            // SAFETY: deliberately unsynchronized test-only fixture.
            let observed = unsafe { first.with(|value| *value) };
            loom::thread::yield_now();
            unsafe {
                first.with_mut(|value| *value = observed + 1);
            }
        });
        let right = thread::spawn(move || {
            // SAFETY: deliberately unsynchronized test-only fixture.
            let observed = unsafe { second.with(|value| *value) };
            loom::thread::yield_now();
            unsafe {
                second.with_mut(|value| *value = observed + 1);
            }
        });
        left.join().unwrap();
        right.join().unwrap();
        // SAFETY: the model is complete; reading the final value is sound in
        // this test-only model even though the fixture intentionally races.
        let observed = unsafe { *cell.with(|value| value) };
        if observed != 2 {
            panic!("loom race witness: lost update observed {observed}");
        }
    });
}
