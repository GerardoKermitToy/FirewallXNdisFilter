#![cfg(test)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

#[path = "../../../driver/src/adapter_info.rs"]
mod adapter_info;
#[path = "../../../driver/src/device_control.rs"]
mod device_control;
#[path = "../../../driver/src/native.rs"]
mod native;
#[path = "../../../driver/src/native_packet.rs"]
mod native_packet;
#[path = "../../../driver/src/native_wfp.rs"]
mod native_wfp;
#[path = "../../../driver/src/target_config.rs"]
mod target_config;
#[path = "../../../driver/src/wdk.rs"]
mod wdk;
#[path = "../../../driver/src/wfp.rs"]
mod wfp;
