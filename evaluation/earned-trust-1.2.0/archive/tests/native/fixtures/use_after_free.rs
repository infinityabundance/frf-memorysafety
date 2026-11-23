// Phase 4.2 negative Rust fixture: free followed by a use of the same token.

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
    event("t0", 2, r#""kind":"free","object":"obj","token":"tok0""#);
    event(
        "t0",
        3,
        r#""kind":"use","object":"obj","token":"tok0","access":"read""#,
    );
}
