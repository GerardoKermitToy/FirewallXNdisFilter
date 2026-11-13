//! Offline tests of the actual entry-gate assembly with simulated CPU features.

extern crate std;

use super::*;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

type Gate = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;

const DRIVER: usize = 0x1234_5000;
const REGISTRY: usize = 0x9876_5000;
const ALL_OS_FEATURES: u32 = 0b1111;
static SERIAL: Mutex<()> = Mutex::new(());
static OS_FEATURES: AtomicU32 = AtomicU32::new(0);
static OS_QUERIED: AtomicU32 = AtomicU32::new(0);
static INITIALIZED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn os_feature(feature: u32) -> u8 {
    let bit = match feature {
        wdk::PF_SSE3_INSTRUCTIONS_AVAILABLE => 1,
        wdk::PF_SSSE3_INSTRUCTIONS_AVAILABLE => 2,
        wdk::PF_SSE4_1_INSTRUCTIONS_AVAILABLE => 4,
        wdk::PF_SSE4_2_INSTRUCTIONS_AVAILABLE => 8,
        _ => 0,
    };
    OS_QUERIED.fetch_or(bit, Ordering::SeqCst);
    u8::from(OS_FEATURES.load(Ordering::SeqCst) & bit != 0)
}

unsafe extern "system" fn initialize(driver: *mut c_void, registry: *mut c_void) -> i32 {
    INITIALIZED.fetch_add(1, Ordering::SeqCst);
    if driver as usize == DRIVER && registry as usize == REGISTRY {
        wdk::FWX_WDK_STATUS_SUCCESS as i32
    } else {
        wdk::FWX_WDK_STATUS_INVALID_PARAMETER as i32
    }
}

macro_rules! test_entry {
    ($name:ident, $features:literal) => {
        checked_entry!(
            $name,
            "mov eax, 1\nmov ebx, -1\nmov ecx, -1\nmov edx, -1",
            $features,
            os_feature,
            initialize
        );
    };
}

test_entry!(
    with_sse42,
    "mov eax, -1\nmov ebx, -1\nmov ecx, 0x180201\nmov edx, -1"
);
test_entry!(
    without_sse3,
    "mov eax, -1\nmov ebx, -1\nmov ecx, 0x180200\nmov edx, -1"
);
test_entry!(
    without_ssse3,
    "mov eax, -1\nmov ebx, -1\nmov ecx, 0x180001\nmov edx, -1"
);
test_entry!(
    without_sse41,
    "mov eax, -1\nmov ebx, -1\nmov ecx, 0x100201\nmov edx, -1"
);
test_entry!(
    without_sse42,
    "mov eax, -1\nmov ebx, -1\nmov ecx, 0x080201\nmov edx, -1"
);
checked_entry!(
    without_cpuid_leaf1,
    "xor eax, eax\nmov ebx, -1\nmov ecx, -1\nmov edx, -1",
    "mov eax, -1\nmov ebx, -1\nmov ecx, 0x180201\nmov edx, -1",
    os_feature,
    initialize
);

// Exercise the Windows x64 nonvolatile-RBX contract as well as both epilogues.
#[unsafe(naked)]
unsafe extern "system" fn check_rbx(
    _gate: Gate,
    _driver: *mut c_void,
    _registry: *mut c_void,
) -> i32 {
    core::arch::naked_asm!(
        ".seh_proc {function}",
        "push rbx",
        ".seh_pushreg rbx",
        "sub rsp, 32",
        ".seh_stackalloc 32",
        ".seh_endprologue",
        "mov rax, rcx",
        "mov rcx, rdx",
        "mov rdx, r8",
        "mov rbx, 0x123456789abcdef0",
        "call rax",
        "mov r10, 0x123456789abcdef0",
        "cmp rbx, r10",
        "je 2f",
        "mov eax, {invalid_parameter}",
        "2:",
        "add rsp, 32",
        "pop rbx",
        "ret",
        ".seh_endproc",
        function = sym check_rbx,
        invalid_parameter = const wdk::FWX_WDK_STATUS_INVALID_PARAMETER as u32,
    );
}

fn reset(mask: u32) {
    OS_FEATURES.store(mask, Ordering::SeqCst);
    OS_QUERIED.store(0, Ordering::SeqCst);
    INITIALIZED.store(0, Ordering::SeqCst);
}

fn invoke(gate: Gate) -> i32 {
    // SAFETY: Test initializers compare these sentinel values without dereferencing them.
    unsafe { check_rbx(gate, DRIVER as *mut c_void, REGISTRY as *mut c_void) }
}

#[test]
fn unavailable_cpuid_leaf_or_any_required_cpu_feature_rejects_before_os_calls() {
    let _guard = SERIAL.lock().unwrap();
    assert_eq!(REQUIRED_CPUID_ECX, 0x180201);
    for gate in [
        without_cpuid_leaf1 as Gate,
        without_sse3,
        without_ssse3,
        without_sse41,
        without_sse42,
    ] {
        reset(ALL_OS_FEATURES);
        assert_eq!(invoke(gate), STATUS_NOT_SUPPORTED);
        assert_eq!(OS_QUERIED.load(Ordering::SeqCst), 0);
        assert_eq!(INITIALIZED.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn any_missing_system_feature_rejects_without_initialization() {
    let _guard = SERIAL.lock().unwrap();
    for missing in [1, 2, 4, 8] {
        reset(ALL_OS_FEATURES & !missing);
        assert_eq!(invoke(with_sse42), STATUS_NOT_SUPPORTED);
        assert_ne!(OS_QUERIED.load(Ordering::SeqCst) & missing, 0);
        assert_eq!(INITIALIZED.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn supported_features_forward_arguments_and_preserve_initialization_status() {
    let _guard = SERIAL.lock().unwrap();
    reset(ALL_OS_FEATURES);
    assert_eq!(invoke(with_sse42), wdk::FWX_WDK_STATUS_SUCCESS as i32);
    assert_eq!(OS_QUERIED.load(Ordering::SeqCst), ALL_OS_FEATURES);
    assert_eq!(INITIALIZED.load(Ordering::SeqCst), 1);

    reset(ALL_OS_FEATURES);
    // SAFETY: The test initializer does not dereference either argument.
    let status = unsafe { check_rbx(with_sse42, core::ptr::null_mut(), core::ptr::null_mut()) };
    assert_eq!(status, wdk::FWX_WDK_STATUS_INVALID_PARAMETER as i32);
    assert_eq!(OS_QUERIED.load(Ordering::SeqCst), ALL_OS_FEATURES);
    assert_eq!(INITIALIZED.load(Ordering::SeqCst), 1);
}
