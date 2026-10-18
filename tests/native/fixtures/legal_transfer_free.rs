// Phase 4.2 positive Rust fixture: create, initialize, use, transfer, use, free.
// The event stream is a scripted deterministic schedule.

fn event(thread: &str, seq: u64, fields: &str) {
    println!("{{\"record\":\"event\",\"thread\":\"{thread}\",\"seq\":{seq},{fields}}}");
}

fn main() {
    event(
        "t0",
        0,
        r#""kind":"create","object":"obj","token":"tok0","owner":"task-a","generation":0"#,
    );
    event(
        "t0",
        1,
        r#""kind":"init_complete","object":"obj","token":"tok0""#,
    );
    event(
        "t0",
        2,
        r#""kind":"use","object":"obj","token":"tok0","access":"write""#,
    );
    event(
        "t0",
        3,
        r#""kind":"transfer","object":"obj","from_token":"tok0","to_token":"tok1","to_owner":"task-b""#,
    );
    event(
        "t0",
        4,
        r#""kind":"use","object":"obj","token":"tok1","access":"read""#,
    );
    event("t0", 5, r#""kind":"free","object":"obj","token":"tok1""#);
}
