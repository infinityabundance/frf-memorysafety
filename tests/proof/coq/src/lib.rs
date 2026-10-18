use std::os::raw::c_int;

extern "C" {
    pub fn frf_foreign_create(value: c_int) -> *mut c_int;
    pub fn frf_foreign_free(ptr: *mut c_int);
}

pub type FrfCallback = unsafe extern "C" fn(*mut std::ffi::c_void);

#[no_mangle]
pub unsafe extern "C" fn frf_wrapper_callback(callback: FrfCallback) {
    callback(std::ptr::null_mut());
}

pub fn frf_safe_create(value: c_int) -> *mut c_int {
    // The wrapper is separately checked by correspondence evidence.
    unsafe { frf_foreign_create(value) }
}
