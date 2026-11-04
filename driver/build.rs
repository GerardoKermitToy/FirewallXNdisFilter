use std::{env, fs, path::PathBuf};
use windows_sys::Win32::{
    Foundation::{STATUS_DATA_ERROR, STATUS_DELETE_PENDING, STATUS_SUCCESS},
    NetworkManagement::WindowsFilteringPlatform::{
        FWP_CONDITION_FLAG_IS_FRAGMENT, FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP,
        FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU, FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
        FWP_CONDITION_FLAG_IS_REASSEMBLED,
    },
};

fn main() {
    // windows-sys raw-dylib imports can override identically named kernel WFP
    // exports even when only constants are used. Keep it a build dependency.
    let mut source = String::new();
    for (name, value) in [
        ("STATUS_SUCCESS", STATUS_SUCCESS),
        ("STATUS_DELETE_PENDING", STATUS_DELETE_PENDING),
        ("STATUS_DATA_ERROR", STATUS_DATA_ERROR),
    ] {
        source.push_str(&format!("pub const {name}: i32 = {value};\n"));
    }
    for (name, value) in [
        (
            "FWP_CONDITION_FLAG_IS_FRAGMENT",
            FWP_CONDITION_FLAG_IS_FRAGMENT,
        ),
        (
            "FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP",
            FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP,
        ),
        (
            "FWP_CONDITION_FLAG_IS_REASSEMBLED",
            FWP_CONDITION_FLAG_IS_REASSEMBLED,
        ),
        (
            "FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU",
            FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU,
        ),
        (
            "FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU",
            FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
        ),
    ] {
        source.push_str(&format!("pub const {name}: u32 = {value};\n"));
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    fs::write(output.join("wfp_constants.rs"), source).expect("write WFP constants");
    println!("cargo:rerun-if-changed={}", file!());
}
