#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[path = "../../../driver/src/wfp.rs"]
mod wfp;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn hv_bugcheck() -> !;
    }
    unsafe { hv_bugcheck() }
}
