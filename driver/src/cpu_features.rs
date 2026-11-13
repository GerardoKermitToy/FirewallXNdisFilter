//! Baseline x64 entry gate executed before any SSE4.2-compiled driver code.

use crate::{device_control::STATUS_NOT_SUPPORTED, wdk};
use core::ffi::c_void;

// CPUID.1:ECX feature bits. LLVM enables the earlier SSE generations when
// compiling with +sse4.2, so inconsistent virtual CPU masks must fail closed.
const CPUID_SSE3: u32 = 1 << 0;
const CPUID_SSSE3: u32 = 1 << 9;
const CPUID_SSE41: u32 = 1 << 19;
const CPUID_SSE42: u32 = 1 << 20;
const REQUIRED_CPUID_ECX: u32 = CPUID_SSE3 | CPUID_SSSE3 | CPUID_SSE41 | CPUID_SSE42;

// The gate itself must remain entirely baseline assembly, even when every
// Rust crate in the kernel image is compiled with +sse4.2. The OS feature
// query is also checked before entering the WDK security-cookie initializer.
macro_rules! checked_entry {
    ($(#[$attribute:meta])* $name:ident, $cpuid_max:literal, $cpuid_features:literal,
     $os_feature:path, $initialize:path) => {
        $(#[$attribute])*
        #[unsafe(naked)]
        unsafe extern "system" fn $name(_driver: *mut c_void, _registry: *mut c_void) -> i32 {
            core::arch::naked_asm!(
                ".seh_proc {function}",
                "push rbx",
                ".seh_pushreg rbx",
                "sub rsp, 48",
                ".seh_stackalloc 48",
                ".seh_endprologue",
                // 32-byte call shadow space, then the two original arguments.
                "mov qword ptr [rsp + 32], rcx",
                "mov qword ptr [rsp + 40], rdx",
                "xor eax, eax",
                $cpuid_max,
                "cmp eax, 1",
                "jb 2f",
                "mov eax, 1",
                "xor ecx, ecx",
                $cpuid_features,
                "and ecx, {required_ecx}",
                "cmp ecx, {required_ecx}",
                "jne 2f",
                "mov ecx, {sse3}",
                "call {os_feature}",
                "test al, al",
                "jz 2f",
                "mov ecx, {ssse3}",
                "call {os_feature}",
                "test al, al",
                "jz 2f",
                "mov ecx, {sse41}",
                "call {os_feature}",
                "test al, al",
                "jz 2f",
                "mov ecx, {sse42}",
                "call {os_feature}",
                "test al, al",
                "jz 2f",
                "mov rcx, qword ptr [rsp + 32]",
                "mov rdx, qword ptr [rsp + 40]",
                "add rsp, 48",
                "pop rbx",
                "jmp {initialize}",
                "2:",
                "mov eax, {not_supported}",
                "add rsp, 48",
                "pop rbx",
                "ret",
                ".seh_endproc",
                function = sym $name,
                required_ecx = const REQUIRED_CPUID_ECX,
                sse3 = const wdk::PF_SSE3_INSTRUCTIONS_AVAILABLE,
                ssse3 = const wdk::PF_SSSE3_INSTRUCTIONS_AVAILABLE,
                sse41 = const wdk::PF_SSE4_1_INSTRUCTIONS_AVAILABLE,
                sse42 = const wdk::PF_SSE4_2_INSTRUCTIONS_AVAILABLE,
                os_feature = sym $os_feature,
                initialize = sym $initialize,
                not_supported = const STATUS_NOT_SUPPORTED as u32,
            );
        }
    };
}

#[cfg(not(test))]
unsafe extern "system" {
    fn GsDriverEntry(driver: *mut c_void, registry: *mut c_void) -> i32;
}

#[cfg(not(test))]
checked_entry!(
    #[unsafe(export_name = "FwxCpuCheckedEntry")]
    cpu_checked_entry,
    "cpuid",
    "cpuid",
    wdk::ExIsProcessorFeaturePresent,
    GsDriverEntry
);

#[cfg(test)]
#[path = "cpu_features_tests.rs"]
mod tests;
