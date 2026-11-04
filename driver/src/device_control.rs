//! Buffered control-request validation and byte responses, independent of IRPs.
//! Native dispatch retains session/IRP ownership and performs shutdown/snapshot
//! actions only after this function accepts the command.
use core::ptr;
use hyperv_protocol as wire;
mod constants {
    include!(concat!(env!("OUT_DIR"), "/device_constants.rs"));
}
use constants::{
    STATUS_BUFFER_TOO_SMALL, STATUS_INTEGER_OVERFLOW, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

/// # Safety
/// `transferred` is writable and disjoint from `out`. A non-null `out` holds
/// `capacity` writable bytes. The caller owns the buffered IRP and session gate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvDeviceControl(
    code: u32,
    input: u32,
    out: *mut u8,
    capacity: u32,
    count: u64,
    transferred: *mut u32,
) -> i32 {
    unsafe {
        transferred.write(0);
    }
    if !matches!(
        code,
        wire::IOCTL_VERSION
            | wire::IOCTL_SHUTDOWN
            | wire::IOCTL_FILTERED_DEVICE_COUNT
            | wire::IOCTL_ADAPTER_INFO
    ) {
        return STATUS_NOT_SUPPORTED;
    }
    if input != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    match code {
        wire::IOCTL_VERSION | wire::IOCTL_FILTERED_DEVICE_COUNT => {
            if capacity < 4 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if out.is_null() {
                return STATUS_INVALID_PARAMETER;
            }
            let bytes = if code == wire::IOCTL_VERSION {
                wire::VERSION
            } else {
                let Ok(value) = u32::try_from(count) else {
                    return STATUS_INTEGER_OVERFLOW;
                };
                value.to_le_bytes()
            };
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), out, 4);
                transferred.write(4);
            }
        }
        // Native code must still check/copy the lock-protected adapter list or
        // close classification/read rundown; neither action belongs to this codec.
        wire::IOCTL_SHUTDOWN | wire::IOCTL_ADAPTER_INFO => {}
        _ => return STATUS_NOT_SUPPORTED,
    }
    STATUS_SUCCESS
}
