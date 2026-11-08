#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// The same modules as the SYS, without WDK layouts.
#[path = "../../../driver/src/adapter_info.rs"]
mod adapter_info;
#[path = "../../../driver/src/device_control.rs"]
mod device_control;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn fwx_bugcheck() -> !;
    }
    unsafe { fwx_bugcheck() }
}
