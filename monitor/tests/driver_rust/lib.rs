#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// The same modules as the SYS, without WDK layouts.
#[path = "../../../driver/src/adapter_info.rs"]
mod adapter_info;
#[path = "../../../driver/src/device_control.rs"]
mod device_control;
#[path = "../../../driver/src/target_config.rs"]
mod target_config;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn hv_bugcheck() -> !;
    }
    unsafe { hv_bugcheck() }
}
