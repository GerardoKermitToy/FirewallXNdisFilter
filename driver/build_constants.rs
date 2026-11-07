use std::{env, fs, path::PathBuf};
use windows_sys::Win32::Foundation::{
    STATUS_BUFFER_TOO_SMALL, STATUS_INTEGER_OVERFLOW, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

pub fn generate() -> PathBuf {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let mut device = String::new();
    for (name, value) in [
        ("STATUS_SUCCESS", STATUS_SUCCESS),
        ("STATUS_BUFFER_TOO_SMALL", STATUS_BUFFER_TOO_SMALL),
        ("STATUS_INTEGER_OVERFLOW", STATUS_INTEGER_OVERFLOW),
        ("STATUS_INVALID_PARAMETER", STATUS_INVALID_PARAMETER),
        ("STATUS_NOT_SUPPORTED", STATUS_NOT_SUPPORTED),
    ] {
        device.push_str(&format!(
            "pub const {name}: i32 = {value};
"
        ));
    }
    fs::write(output.join("device_constants.rs"), device).expect("write device constants");
    println!("cargo:rerun-if-changed={}", file!());
    output
}
