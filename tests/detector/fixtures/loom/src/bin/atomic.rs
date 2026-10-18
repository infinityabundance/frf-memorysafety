//! Test-only loom harmless control: the same shape with a sequentially
//! consistent atomic increment. Loom must not report a lost update.

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread;

fn main() {
    loom::model(|| {
        let counter = Arc::new(AtomicUsize::new(0));
        let first = counter.clone();
        let second = counter.clone();
        let left = thread::spawn(move || {
            first.fetch_add(1, Ordering::SeqCst);
        });
        let right = thread::spawn(move || {
            second.fetch_add(1, Ordering::SeqCst);
        });
        left.join().unwrap();
        right.join().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    });
}
