//! A machine-wide NETIO unicast/anycast inventory for the NDIS fast path.
//!
//! `start` and `stop` are serialized by the driver lifecycle at PASSIVE_LEVEL.
//! Start before admitting packet callbacks; stop only after packet admission is
//! closed. A failed start, registration, or snapshot leaves lookups Unknown.
//! The worker is the sole owner of the registration and cancels it before exit.
//! No interface index participates in address matching.
//!
//! NETIO notifications are asynchronous: a unicast address change cannot be
//! detected before NETIO invokes its callback. Anycast has no corresponding
//! change notification here and is polled; changes can remain invisible until
//! the next successful refresh. Thus neither inventory is instantaneously
//! consistent with OS address changes. Once invoked, a callback invalidates the
//! published snapshot before returning. Snapshot/lookup races with callbacks
//! are resolved under STATE_LOCK.

use core::{
    mem::{size_of, zeroed},
    ptr::{self, addr_of, addr_of_mut},
    slice,
};

#[cfg(test)]
use self::tests::api;
#[cfg(not(test))]
use crate::wdk as api;
use crate::wdk::*;

const POOL_TAG: u32 = u32::from_le_bytes(*b"aIvH");
// A failed query/registration or a race is retried, but never in a tight loop.
const RETRY_100NS: i64 = -10_000_000;
const DEBOUNCE_100NS: i64 = -1_000_000;
const REFRESH_100NS: i64 = -50_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalMatch {
    Local,
    Transit,
    Unknown,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
enum Family {
    V4,
    V6,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Address {
    family: Family,
    bytes: [u8; 16],
}

impl Address {
    fn v4(bytes: [u8; 4]) -> Self {
        let mut all = [0; 16];
        all[..4].copy_from_slice(&bytes);
        Self {
            family: Family::V4,
            bytes: all,
        }
    }
    fn v6(bytes: [u8; 16]) -> Self {
        Self {
            family: Family::V6,
            bytes,
        }
    }
}

// One nonpaged allocation contains the header followed by `len` sorted
// addresses. Only the worker constructs and frees snapshots. The rundown
// reference is acquired under STATE_LOCK before a fast-path reader sees it.
#[repr(C)]
struct Snapshot {
    rundown: EX_RUNDOWN_REF,
    len: usize,
    addresses: [Address; 0],
}

static mut STATE_LOCK: KSPIN_LOCK = 0;
static mut WAKE: KEVENT = unsafe { zeroed() };
static mut THREAD: HANDLE = ptr::null_mut();
// All fields below are protected by STATE_LOCK.
static mut CURRENT: *mut Snapshot = ptr::null_mut();
static mut DIRTY: bool = true;
static mut CHANGED_DURING_CAPTURE: bool = false;
static mut STOPPING: bool = false;

unsafe fn lock() -> KIRQL {
    unsafe { api::KeAcquireSpinLockRaiseToDpc(addr_of_mut!(STATE_LOCK)) }
}
unsafe fn unlock(irql: KIRQL) {
    unsafe { api::KeReleaseSpinLock(addr_of_mut!(STATE_LOCK), irql) }
}

/// Must be called exactly once before any lookup and serialized with `stop`.
/// A negative status means the worker could not be created; lookups stay Unknown.
pub(crate) unsafe fn start() -> NTSTATUS {
    unsafe {
        api::KeInitializeSpinLock(addr_of_mut!(STATE_LOCK));
        api::KeInitializeEvent(addr_of_mut!(WAKE), SynchronizationEvent, 0);
        CURRENT = ptr::null_mut();
        DIRTY = true;
        CHANGED_DURING_CAPTURE = false;
        STOPPING = false;
        THREAD = ptr::null_mut();
        let mut attributes: OBJECT_ATTRIBUTES = zeroed();
        attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.Attributes = OBJ_KERNEL_HANDLE;
        let mut thread: HANDLE = ptr::null_mut();
        let status = api::PsCreateSystemThread(
            &mut thread,
            SYNCHRONIZE,
            &mut attributes,
            ptr::null_mut(),
            ptr::null_mut(),
            Some(worker),
            ptr::null_mut(),
        );
        if status >= 0 {
            THREAD = thread;
        }
        status
    }
}

/// Close admission before calling, then join the worker at PASSIVE_LEVEL.
/// Even after a start failure this leaves the inventory Unknown. If NETIO
/// cancellation fails, the worker retries until it succeeds: unloading with a
/// live callback into this image would be unsafe.
pub(crate) unsafe fn stop() {
    unsafe {
        let irql = lock();
        STOPPING = true;
        DIRTY = true;
        unlock(irql);
        api::KeSetEvent(addr_of_mut!(WAKE), 0, 0);
        let thread = THREAD;
        if !thread.is_null() {
            // An infinite, nonalertable wait on our valid thread handle must
            // succeed. Do not unload on an unexpected wait failure.
            while api::ZwWaitForSingleObject(thread, 0, ptr::null_mut())
                != HV_WDK_STATUS_SUCCESS as NTSTATUS
            {
                delay_retry();
            }
            let _ = api::ZwClose(thread);
            THREAD = ptr::null_mut();
        }
    }
}

/// Sample on a diagnostic/control thread and report transitions there, never
/// log per packet. A failed start or either NETIO query reports unavailable.
pub(crate) fn available() -> bool {
    unsafe {
        let irql = lock();
        let result = !DIRTY && !STOPPING && !CURRENT.is_null();
        unlock(irql);
        result
    }
}

pub(crate) fn lookup_v4(source: [u8; 4], destination: [u8; 4]) -> LocalMatch {
    lookup(Address::v4(source), Address::v4(destination))
}
pub(crate) fn lookup_v6(source: [u8; 16], destination: [u8; 16]) -> LocalMatch {
    lookup(Address::v6(source), Address::v6(destination))
}

fn lookup(source: Address, destination: Address) -> LocalMatch {
    unsafe {
        let irql = lock();
        let snapshot = CURRENT;
        if DIRTY
            || STOPPING
            || snapshot.is_null()
            || api::ExAcquireRundownProtection(addr_of_mut!((*snapshot).rundown)) == 0
        {
            unlock(irql);
            return LocalMatch::Unknown;
        }
        unlock(irql);

        let addresses = slice::from_raw_parts(
            addr_of!((*snapshot).addresses).cast::<Address>(),
            (*snapshot).len,
        );
        let found = addresses.binary_search(&source).is_ok()
            || addresses.binary_search(&destination).is_ok();
        #[cfg(test)]
        api::lookup_checkpoint();

        // A callback or a new snapshot racing the lookup invalidates its
        // answer. The held rundown ref also prevents pointer-address reuse.
        let irql = lock();
        let valid = !DIRTY && !STOPPING && CURRENT == snapshot;
        unlock(irql);
        api::ExReleaseRundownProtection(addr_of_mut!((*snapshot).rundown));
        if !valid {
            LocalMatch::Unknown
        } else if found {
            LocalMatch::Local
        } else {
            LocalMatch::Transit
        }
    }
}

unsafe extern "C" fn changed(
    _context: PVOID,
    _row: PMIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    unsafe {
        let irql = lock();
        if !STOPPING {
            DIRTY = true;
            CHANGED_DURING_CAPTURE = true;
        }
        unlock(irql);
        api::KeSetEvent(addr_of_mut!(WAKE), 0, 0);
    }
}

unsafe fn stopping() -> bool {
    unsafe {
        let irql = lock();
        let value = STOPPING;
        unlock(irql);
        value
    }
}
unsafe fn dirty() -> bool {
    unsafe {
        let irql = lock();
        let value = DIRTY;
        unlock(irql);
        value
    }
}
unsafe fn mark_dirty() {
    unsafe {
        let irql = lock();
        DIRTY = true;
        unlock(irql);
    }
}
unsafe fn delay_retry() {
    unsafe { delay(RETRY_100NS) }
}
unsafe fn delay(relative_100ns: i64) {
    unsafe {
        let mut due = LARGE_INTEGER {
            QuadPart: relative_100ns,
        };
        let _ = api::KeDelayExecutionThread(KernelMode as KPROCESSOR_MODE, 0, &mut due);
    }
}

unsafe extern "C" fn worker(_context: PVOID) {
    unsafe {
        let mut registration: HANDLE = ptr::null_mut();
        let mut periodic_refresh = false;
        #[cfg(not(test))]
        let mut last_reported = None;
        while !stopping() {
            // Report state changes on the worker, never in the packet path or
            // the NETIO notification callback. A new controller also samples
            // availability when it connects.
            #[cfg(not(test))]
            {
                let ready = available();
                if last_reported != Some(ready) {
                    crate::local_address_status(ready);
                    last_reported = Some(ready);
                }
            }
            if registration.is_null() {
                let status = api::NotifyUnicastIpAddressChange(
                    AF_UNSPEC as ADDRESS_FAMILY,
                    Some(changed),
                    ptr::null_mut(),
                    0,
                    &mut registration,
                );
                if status < 0 || registration.is_null() {
                    registration = ptr::null_mut();
                    delay_retry();
                    continue;
                }
            }
            let changed = dirty();
            if changed || periodic_refresh {
                if changed {
                    // Coalesce rapid notifications while the inventory is
                    // already Unknown, including the initial capture.
                    delay(DEBOUNCE_100NS);
                }
                periodic_refresh = false;
                if !capture() {
                    delay_retry();
                }
            } else {
                let mut due = LARGE_INTEGER {
                    QuadPart: REFRESH_100NS,
                };
                let status = api::KeWaitForSingleObject(
                    addr_of_mut!(WAKE).cast(),
                    Executive,
                    KernelMode as KPROCESSOR_MODE,
                    0,
                    &mut due,
                );
                if status < 0 {
                    mark_dirty();
                    delay_retry();
                } else if status != HV_WDK_STATUS_SUCCESS as NTSTATUS {
                    // Poll anycast without disrupting a valid snapshot. A
                    // failed capture invalidates that snapshot immediately.
                    periodic_refresh = true;
                }
            }
        }
        if !registration.is_null() {
            // Cancel blocks for all callbacks. It must never hold STATE_LOCK.
            while api::CancelMibChangeNotify2(registration) < 0 {
                delay_retry();
            }
        }
        let irql = lock();
        let old = CURRENT;
        CURRENT = ptr::null_mut();
        DIRTY = true;
        unlock(irql);
        free_snapshot(old);
        let _ = api::PsTerminateSystemThread(HV_WDK_STATUS_SUCCESS as NTSTATUS);
    }
}

// Runs only on the worker. Reject any result raced by a notification.
unsafe fn capture() -> bool {
    unsafe {
        let irql = lock();
        if STOPPING {
            unlock(irql);
            return true;
        }
        CHANGED_DURING_CAPTURE = false;
        unlock(irql);

        let mut unicast: PMIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        let status = api::GetUnicastIpAddressTable(AF_UNSPEC as ADDRESS_FAMILY, &mut unicast);
        if status != HV_WDK_STATUS_SUCCESS as NTSTATUS {
            let empty = status == HV_WDK_STATUS_NOT_FOUND as NTSTATUS;
            if !empty {
                mark_dirty();
            }
            if !unicast.is_null() {
                api::FreeMibTable(unicast.cast());
                unicast = ptr::null_mut();
            }
            if !empty {
                return false;
            }
        } else if unicast.is_null() {
            mark_dirty();
            return false;
        }
        let mut anycast: PMIB_ANYCASTIPADDRESS_TABLE = ptr::null_mut();
        let status = api::GetAnycastIpAddressTable(AF_UNSPEC as ADDRESS_FAMILY, &mut anycast);
        if status != HV_WDK_STATUS_SUCCESS as NTSTATUS {
            let empty = status == HV_WDK_STATUS_NOT_FOUND as NTSTATUS;
            if !empty {
                mark_dirty();
            }
            if !anycast.is_null() {
                api::FreeMibTable(anycast.cast());
                anycast = ptr::null_mut();
            }
            if !empty {
                if !unicast.is_null() {
                    api::FreeMibTable(unicast.cast());
                }
                return false;
            }
        } else if anycast.is_null() {
            mark_dirty();
            if !unicast.is_null() {
                api::FreeMibTable(unicast.cast());
            }
            return false;
        }
        let next = snapshot_from_tables(unicast, anycast);
        if next.is_null() {
            mark_dirty();
        }
        if !anycast.is_null() {
            api::FreeMibTable(anycast.cast());
        }
        if !unicast.is_null() {
            api::FreeMibTable(unicast.cast());
        }
        if next.is_null() {
            return false;
        }
        let irql = lock();
        if STOPPING || CHANGED_DURING_CAPTURE {
            unlock(irql);
            free_snapshot(next);
            return false;
        }
        let old = CURRENT;
        CURRENT = next;
        DIRTY = false;
        unlock(irql);
        free_snapshot(old);
        true
    }
}

unsafe fn read_address(address: &SOCKADDR_INET) -> Option<Address> {
    unsafe {
        match address.si_family as u32 {
            AF_INET => Some(Address::v4(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())),
            AF_INET6 => Some(Address::v6(address.Ipv6.sin6_addr.u.Byte)),
            _ => None,
        }
    }
}

unsafe fn snapshot_from_tables(
    unicast: PMIB_UNICASTIPADDRESS_TABLE,
    anycast: PMIB_ANYCASTIPADDRESS_TABLE,
) -> *mut Snapshot {
    unsafe {
        let unicast_count = if unicast.is_null() {
            0
        } else {
            (*unicast).NumEntries as usize
        };
        let anycast_count = if anycast.is_null() {
            0
        } else {
            (*anycast).NumEntries as usize
        };
        let Some((count, size)) = unicast_count.checked_add(anycast_count).and_then(|count| {
            count
                .checked_mul(size_of::<Address>())
                .and_then(|n| size_of::<Snapshot>().checked_add(n))
                .filter(|n| *n <= isize::MAX as usize)
                .map(|size| (count, size))
        }) else {
            return ptr::null_mut();
        };
        let snapshot = crate::native::pool_allocation(api::ExAllocatePool2(
            HV_WDK_POOL_FLAG_NON_PAGED as POOL_FLAGS,
            size as SIZE_T,
            POOL_TAG,
        ))
        .cast::<Snapshot>();
        api::ExInitializeRundownProtection(addr_of_mut!((*snapshot).rundown));
        (*snapshot).len = 0;
        let unicast_rows = if unicast.is_null() {
            ptr::null()
        } else {
            addr_of!((*unicast).Table).cast::<MIB_UNICASTIPADDRESS_ROW>()
        };
        let anycast_rows = if anycast.is_null() {
            ptr::null()
        } else {
            addr_of!((*anycast).Table).cast::<MIB_ANYCASTIPADDRESS_ROW>()
        };
        let addresses = addr_of_mut!((*snapshot).addresses).cast::<Address>();
        for i in 0..count {
            let address = if i < unicast_count {
                &(*unicast_rows.add(i)).Address
            } else {
                &(*anycast_rows.add(i - unicast_count)).Address
            };
            let Some(value) = read_address(address) else {
                free_snapshot(snapshot);
                return ptr::null_mut();
            };
            addresses.add(i).write(value);
        }
        (*snapshot).len = count;
        slice::from_raw_parts_mut(addresses, count).sort_unstable();
        snapshot
    }
}

unsafe fn free_snapshot(snapshot: *mut Snapshot) {
    unsafe {
        if !snapshot.is_null() {
            api::ExWaitForRundownProtectionRelease(addr_of_mut!((*snapshot).rundown));
            api::ExFreePoolWithTag(snapshot.cast(), POOL_TAG);
        }
    }
}

#[cfg(test)]
#[path = "native_local_address_tests.rs"]
mod tests;
