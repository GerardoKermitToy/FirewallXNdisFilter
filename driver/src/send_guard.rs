use core::ffi::c_void;

unsafe extern "C" {
    fn fwx_send_guard_lock(guard: *mut c_void) -> u32;
    fn fwx_send_guard_unlock(guard: *mut c_void);
}

// The caller holds PolicyLock. The native guard takes only the adapter lock;
// cancellation releases it before entering policy or completing any NBL.
pub(crate) fn with_send_guard<R>(guard: *mut c_void, f: impl FnOnce(bool) -> R) -> R {
    if guard.is_null() {
        return f(false);
    }
    let cancelled = unsafe { fwx_send_guard_lock(guard) != 0 };
    let result = f(cancelled);
    unsafe { fwx_send_guard_unlock(guard) };
    result
}
