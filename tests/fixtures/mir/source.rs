#![allow(dead_code)]

extern "C" {
    fn foreign_work(ptr: *mut u8) -> i32;
}

struct Holder {
    value: u8,
}

fn add(a: i32, b: i32) -> i32 {
    let c = a + b;
    c
}

fn use_ref(input: &mut Holder) -> i32 {
    input.value = 7;
    i32::from(input.value)
}

fn maybe_drop(flag: bool) {
    let holder = Holder { value: 1 };
    if flag {
        drop(holder);
    }
}

fn callback_use(f: fn(i32) -> i32) -> i32 {
    f(3)
}

fn raw(ptr: *mut u8) -> i32 {
    unsafe { foreign_work(ptr) }
}

fn main() {
    let mut holder = Holder { value: 2 };
    let _ = add(1, 2);
    let _ = use_ref(&mut holder);
    maybe_drop(true);
    let _ = callback_use(|value| value + 1);
    let mut byte = 0_u8;
    let _ = raw(&mut byte);
}
