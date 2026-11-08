//! Kernel OS boundary in Rust. All WDK layouts come from the installed headers.
//! Static storage is accessed only under its existing WDK lock/rundown contract.
use crate::adapter_info::AdapterInfo;
use crate::wdk::*;
use core::{
    mem::{offset_of, size_of, zeroed},
    ptr::{self, addr_of, addr_of_mut, null_mut},
    sync::atomic::{AtomicI32, AtomicI64, AtomicPtr, Ordering},
};

#[path = "native_device.rs"]
mod device;
#[path = "native_ndis.rs"]
mod ndis;
#[cfg(not(test))]
#[path = "native_registry.rs"]
mod registry;

const TAG: u32 = 0x67564848;
const CACHE_TAG: u32 = 0x63564848;
const INFO_TAG: u32 = 0x69564848;
const SEND: u32 = 0;
const RECEIVE: u32 = 1;
const PENDING_CHECK_MS: i32 = 1000;
const CACHE_CHECK_MS: i32 = 10000;
const DEFAULT_TIMEOUT_MS: u32 = 8000;
const DEFAULT_FAIL_CLOSED: u32 = 1;

#[repr(C)]
struct Adapter {
    filter: NDIS_HANDLE,
    nbl_pool: NDIS_HANDLE,
    nb_pool: NDIS_HANDLE,
    lock: NDIS_SPIN_LOCK,
    classification_lock: PNDIS_RW_LOCK_EX,
    send_batches: *mut ndis::SendBatch,
    oid_rundown: EX_RUNDOWN_REF,
    adapter_link: LIST_ENTRY,
    info: AdapterInfo,
    id: u64,
    active: u64,
    interface_index: u32,
    running: u8,
    pause_pending: u8,
}

static mut DRIVER_HANDLE: NDIS_HANDLE = null_mut();
static mut DEVICE_HANDLE: NDIS_HANDLE = null_mut();
static mut CONTROL_DEVICE: PDEVICE_OBJECT = null_mut();
static mut FILTER_NDIS_VERSION: u32 = 0;
static mut READY_EVENT_HANDLE: HANDLE = null_mut();
static mut READY_EVENT: PKEVENT = null_mut();
static mut POLICY_LOCK: KSPIN_LOCK = 0;
static mut ADAPTER_INFO_LOCK: KSPIN_LOCK = 0;
static mut ADAPTERS: LIST_ENTRY = unsafe { zeroed() };
static mut ADAPTER_COUNT: u64 = 0;
static mut IO_MUTEX: FAST_MUTEX = unsafe { zeroed() };
static mut CLIENT: PFILE_OBJECT = null_mut();
static STOPPING: AtomicI32 = AtomicI32::new(0);
static mut PENDING_TIMER: KTIMER = unsafe { zeroed() };
static mut CACHE_TIMER: KTIMER = unsafe { zeroed() };
static mut PENDING_DPC: KDPC = unsafe { zeroed() };
static mut CACHE_DPC: KDPC = unsafe { zeroed() };
static mut PENDING_TIMER_ARMED: bool = false;
static mut CACHE_TIMER_ARMED: bool = false;
static NEXT_ADAPTER: AtomicI64 = AtomicI64::new(0);
static FILTERED_DEVICE_COUNT: AtomicI64 = AtomicI64::new(0);
static mut READ_CSQ: IO_CSQ = unsafe { zeroed() };
static mut READ_IRPS: LIST_ENTRY = unsafe { zeroed() };
static mut READ_LOCK: KSPIN_LOCK = 0;
static mut READ_CLIENT: PFILE_OBJECT = null_mut();
static mut CLASSIFICATION_RUNDOWN: EX_RUNDOWN_REF = unsafe { zeroed() };
static mut READ_RUNDOWN: EX_RUNDOWN_REF = unsafe { zeroed() };
static mut CACHE_RUNDOWN: EX_RUNDOWN_REF = unsafe { zeroed() };
static mut CLASSIFICATION_CLOSED: bool = false;
static READ_WORK_ITEM: AtomicPtr<_IO_WORKITEM> = AtomicPtr::new(null_mut());
static mut CACHE_WORK_ITEM: PIO_WORKITEM = null_mut();
static READ_PENDING: AtomicI32 = AtomicI32::new(0);
static READ_READY: AtomicI32 = AtomicI32::new(0);
static READ_ONLINE: AtomicI32 = AtomicI32::new(0);
static READ_SCHEDULED: AtomicI32 = AtomicI32::new(0);
static CACHE_SCHEDULED: AtomicI32 = AtomicI32::new(0);

fn nt_success(status: i32) -> bool {
    status >= 0
}
pub(crate) fn is_stopping() -> bool {
    STOPPING.load(Ordering::SeqCst) != 0
}
#[cfg(not(test))]
unsafe fn spin_lock(lock: *mut KSPIN_LOCK) -> KIRQL {
    unsafe { KeAcquireSpinLockRaiseToDpc(lock) }
}
#[cfg(not(test))]
unsafe fn spin_unlock(lock: *mut KSPIN_LOCK, irql: KIRQL) {
    unsafe { KeReleaseSpinLock(lock, irql) }
}
unsafe fn ndis_lock(lock: *mut NDIS_SPIN_LOCK) {
    unsafe {
        (*lock).OldIrql = spin_lock(addr_of_mut!((*lock).SpinLock));
    }
}
unsafe fn ndis_unlock(lock: *mut NDIS_SPIN_LOCK) {
    unsafe {
        spin_unlock(addr_of_mut!((*lock).SpinLock), (*lock).OldIrql);
    }
}
unsafe fn list_init(head: *mut LIST_ENTRY) {
    unsafe {
        (*head).Flink = head;
        (*head).Blink = head;
    }
}
unsafe fn list_empty(head: *const LIST_ENTRY) -> bool {
    unsafe { (*head).Flink == head.cast_mut() }
}
unsafe fn list_insert_tail(head: *mut LIST_ENTRY, entry: *mut LIST_ENTRY) {
    unsafe {
        let tail = (*head).Blink;
        (*entry).Flink = head;
        (*entry).Blink = tail;
        (*tail).Flink = entry;
        (*head).Blink = entry;
    }
}
unsafe fn list_remove(entry: *mut LIST_ENTRY) {
    unsafe {
        (*(*entry).Blink).Flink = (*entry).Flink;
        (*(*entry).Flink).Blink = (*entry).Blink;
    }
}
const fn unicode(text: &'static [u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: ((text.len() - 1) * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_ptr().cast_mut(),
    }
}
macro_rules! wide {
    ($s:literal) => {{
        const TEXT: &str = concat!($s, "\0");
        const DATA: [u16; TEXT.len()] = {
            let bytes = TEXT.as_bytes();
            let mut out = [0; TEXT.len()];
            let mut i = 0;
            while i < bytes.len() {
                out[i] = bytes[i] as u16;
                i += 1;
            }
            out
        };
        unicode(&DATA)
    }};
}
use wide;

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub(crate) extern "C" fn fwx_bugcheck() -> ! {
    unsafe {
        KeBugCheckEx(
            FWX_WDK_DRIVER_VERIFIER_DETECTED_VIOLATION as u32,
            0x48565253,
            0,
            0,
            0,
        )
    }
}
#[cold]
#[inline(never)]
fn pool_allocation_failed() -> ! {
    #[cfg(not(test))]
    unsafe {
        KeBugCheckEx(FWX_WDK_NO_PAGES_AVAILABLE as u32, 0, 0, 0, 0)
    }
    #[cfg(test)]
    panic!("ExAllocatePool2 failed")
}

#[inline]
pub(crate) fn pool_allocation(pointer: PVOID) -> PVOID {
    if pointer.is_null() {
        pool_allocation_failed();
    }
    pointer
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn fwx_lock() -> usize {
    unsafe { spin_lock(addr_of_mut!(POLICY_LOCK)) as usize }
}
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn fwx_unlock(irql: usize) {
    unsafe { spin_unlock(addr_of_mut!(POLICY_LOCK), irql as u8) }
}
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn fwx_now() -> u64 {
    // The precise DDI requires a writable QPC timestamp output, even when only
    // interrupt time is consumed by policy.
    let mut qpc = 0;
    unsafe { KeQueryInterruptTimePrecise(&mut qpc) / 10000 }
}
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn fwx_allocate(size: usize) -> *mut u8 {
    unsafe {
        if size == 0 {
            null_mut()
        } else {
            pool_allocation(ExAllocatePool2(
                (FWX_WDK_POOL_FLAG_NON_PAGED | FWX_WDK_POOL_FLAG_UNINITIALIZED) as u64,
                size as u64,
                TAG,
            ))
            .cast()
        }
    }
}
#[cfg(not(test))]
#[unsafe(no_mangle)]
unsafe extern "C" fn fwx_free(data: *mut u8, _: usize) {
    unsafe { ExFreePoolWithTag(data.cast(), TAG) }
}
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn fwx_cache_allocate(size: usize) -> *mut u8 {
    unsafe {
        if size == 0 {
            null_mut()
        } else {
            pool_allocation(ExAllocatePool2(
                (FWX_WDK_POOL_FLAG_NON_PAGED | FWX_WDK_POOL_FLAG_UNINITIALIZED) as u64,
                size as u64,
                CACHE_TAG,
            ))
            .cast()
        }
    }
}
#[cfg(not(test))]
#[unsafe(no_mangle)]
unsafe extern "C" fn fwx_cache_free(data: *mut u8, _: usize) {
    unsafe { ExFreePoolWithTag(data.cast(), CACHE_TAG) }
}
unsafe fn close_classification_session() {
    unsafe {
        if CLASSIFICATION_CLOSED {
            return;
        }
        CLASSIFICATION_CLOSED = true;
        #[cfg(not(test))]
        {
            ExWaitForRundownProtectionRelease(addr_of_mut!(CLASSIFICATION_RUNDOWN));
            crate::FwxDisconnect();
        }
        #[cfg(test)]
        {
            device::tests::calls::ExWaitForRundownProtectionRelease(addr_of_mut!(
                CLASSIFICATION_RUNDOWN
            ));
            device::tests::calls::FwxDisconnect();
        }
    }
}
unsafe fn open_classification_session() {
    unsafe {
        if CLASSIFICATION_CLOSED {
            #[cfg(not(test))]
            ExReInitializeRundownProtection(addr_of_mut!(CLASSIFICATION_RUNDOWN));
            #[cfg(test)]
            device::tests::calls::ExReInitializeRundownProtection(addr_of_mut!(
                CLASSIFICATION_RUNDOWN
            ));
            CLASSIFICATION_CLOSED = false;
        }
        #[cfg(not(test))]
        {
            crate::FwxConnect();
        }
        #[cfg(test)]
        {
            device::tests::calls::FwxConnect();
        }
    }
}
#[cfg(not(test))]
fn request_cache_cleanup() {
    unsafe {
        if is_stopping() || CACHE_WORK_ITEM.is_null() {
            return;
        }
        if ExAcquireRundownProtection(addr_of_mut!(CACHE_RUNDOWN)) == 0 {
            return;
        }
        if CACHE_SCHEDULED
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            IoQueueWorkItem(
                CACHE_WORK_ITEM,
                Some(cache_worker),
                DelayedWorkQueue,
                null_mut(),
            );
        } else {
            ExReleaseRundownProtection(addr_of_mut!(CACHE_RUNDOWN));
        }
    }
}
#[cfg(not(test))]
unsafe extern "C" fn cache_worker(_: PDEVICE_OBJECT, _: PVOID) {
    unsafe {
        if !is_stopping() {
            crate::FwxCleanCaches();
        }
        CACHE_SCHEDULED.store(0, Ordering::SeqCst);
        ExReleaseRundownProtection(addr_of_mut!(CACHE_RUNDOWN));
    }
}
#[cfg(not(test))]
unsafe fn update_timer(
    timer: *mut KTIMER,
    dpc: *mut KDPC,
    armed: *mut bool,
    interval: i32,
    candidates: bool,
) {
    unsafe {
        let next = !is_stopping() && candidates;
        if *armed == next {
            return;
        }
        *armed = next;
        if next {
            let due = LARGE_INTEGER {
                QuadPart: -(interval as i64) * 10000,
            };
            KeSetTimerEx(timer, due, interval, dpc);
        } else {
            KeCancelTimer(timer);
        }
    }
}
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn fwx_publish_state(ready: u32, online: u32, pending: u32, cached: u32) {
    unsafe {
        // Caller holds POLICY_LOCK; timer state has that same owner.
        if READ_READY.load(Ordering::SeqCst) != ready as i32 {
            READ_READY.store(ready as i32, Ordering::SeqCst);
        }
        if READ_ONLINE.load(Ordering::SeqCst) != online as i32 {
            READ_ONLINE.store(online as i32, Ordering::SeqCst);
        }
        update_timer(
            addr_of_mut!(PENDING_TIMER),
            addr_of_mut!(PENDING_DPC),
            addr_of_mut!(PENDING_TIMER_ARMED),
            PENDING_CHECK_MS,
            pending != 0,
        );
        update_timer(
            addr_of_mut!(CACHE_TIMER),
            addr_of_mut!(CACHE_DPC),
            addr_of_mut!(CACHE_TIMER_ARMED),
            CACHE_CHECK_MS,
            cached != 0,
        );
        device::schedule_read();
    }
}
#[cfg(not(test))]
unsafe extern "C" fn pending_dpc(_: *mut KDPC, _: PVOID, _: PVOID, _: PVOID) {
    if !is_stopping() {
        crate::FwxDrain();
    }
}
#[cfg(not(test))]
unsafe extern "C" fn cache_dpc(_: *mut KDPC, _: PVOID, _: PVOID, _: PVOID) {
    request_cache_cleanup();
}

#[cfg(test)]
#[test]
fn pool_allocation_failure_bugchecks_instead_of_returning_null() {
    let mut byte = 0u8;
    let pointer = (&mut byte as *mut u8).cast();
    assert_eq!(pool_allocation(pointer), pointer);
    assert!(std::panic::catch_unwind(|| pool_allocation(null_mut())).is_err());
}

#[cfg(test)]
pub(crate) fn fwx_bugcheck() -> ! {
    panic!("kernel invariant violated")
}
#[cfg(test)]
unsafe fn spin_lock(_: *mut KSPIN_LOCK) -> KIRQL {
    0
}
#[cfg(test)]
unsafe fn spin_unlock(_: *mut KSPIN_LOCK, _: KIRQL) {}
#[cfg(test)]
mod registry {
    use super::*;
    pub(super) static TARGET_ALLOWED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(true);
    pub(super) unsafe fn target_adapter(
        _: PNDIS_FILTER_ATTACH_PARAMETERS,
        guid: *mut GUID,
    ) -> bool {
        unsafe { guid.write(GUID::default()) };
        TARGET_ALLOWED.load(Ordering::SeqCst)
    }
}
