//! Test-only loom fixture crate.
//!
//! `race` models two unsynchronized increments of a shared cell; loom explores
//! the interleaving that loses an update. `atomic` is the harmless control and
//! uses a sequentially consistent atomic increment.
