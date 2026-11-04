use std::{env, path::PathBuf};
mod build_constants;
fn main() {
    let output = build_constants::generate();
    #[cfg(feature = "native-wdk")]
    generate_wdk(&output);
    #[cfg(not(feature = "native-wdk"))]
    let _ = output;
}

#[cfg(feature = "native-wdk")]
fn generate_wdk(output: &std::path::Path) {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = if env::var("CARGO_PKG_NAME").unwrap() == "hyperv-native-tests" {
        manifest.join("../../../driver")
    } else {
        manifest
    };
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
    println!("cargo:rerun-if-env-changed=HYPERVXNDISFILTER_SDK_VERSION");
    let sdk = env::var("HYPERVXNDISFILTER_SDK_VERSION").unwrap_or_else(|_| "10.0.28000.0".into());
    // These settings affect only this Windows build-script process. They are not
    // driver globals or persisted machine configuration.
    unsafe { env::set_var("Version_Number", sdk) };
    if env::var_os("LIBCLANG_PATH").is_none() {
        let llvm =
            PathBuf::from(env::var_os("ProgramFiles").expect("ProgramFiles")).join("LLVM/bin");
        unsafe { env::set_var("LIBCLANG_PATH", llvm) };
    }
    use wdk_build::BuilderExt;
    let config = wdk_build::Config::new();
    let builder = bindgen::Builder::wdk_default(&config)
        .expect("configure installed WDK using windows-drivers-rs")
        .header(root.join("wdk.h").to_string_lossy())
        .clang_args([
            "--target=x86_64-pc-windows-msvc",
            "-DNDIS689=1",
            "-DWINVER=0x0A00",
            "-D_WIN32_WINNT=0x0A00",
            "-DNTDDI_VERSION=NTDDI_WIN10_NI",
            "-Wno-pragma-pack",
        ])
        .ctypes_prefix("core::ffi")
        .generate_comments(false)
        .layout_tests(false)
        .default_enum_style(bindgen::EnumVariation::Consts)
        .prepend_enum_name(false)
        // These SDK enum values share names with unrelated bitfield constructor
        // arguments. Keep them scoped, as windows-drivers-rs does by default.
        .constified_enum_module(
            "_DEVICE_RESET_TYPE|_ERROR_SEVERITY_VALUE|_NPEM_CONTROL_STANDARD_CONTROL_BIT",
        )
        .allowlist_type(".*")
        .allowlist_function(
            "(Ndis|Ke|Ex|Io|Iof|Mm|Zw|Rtl|Ob|Obf|Fwps|Fwpm|Wdmlib|ConvertInterface|DbgPrintEx).*",
        )
        .allowlist_var(".*")
        .blocklist_function(".*Interlocked.*");
    builder
        .generate()
        .expect("generate installed x64 WDK ABI")
        .write_to_file(output.join("wdk.rs"))
        .expect("write WDK bindings");
}
