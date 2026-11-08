use super::*;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    collections::HashMap,
    sync::{
        Condvar, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
enum Row {
    V4([u8; 4], u32),
    V6([u8; 16], u32),
    Invalid,
}

#[derive(Default)]
struct Fake {
    rows: Vec<Row>,
    anycast_rows: Vec<Row>,
    callback: PUNICAST_IPADDRESS_CHANGE_CALLBACK,
    notify_calls: usize,
    table_calls: usize,
    anycast_calls: usize,
    cancel_calls: usize,
    notify_failures: usize,
    table_failures: usize,
    anycast_failures: usize,
    thread_failure: bool,
    cancel_failures: usize,
    active_callbacks: usize,
    mutate_during_get: Option<Vec<Row>>,
    checkpoint_change: bool,
    pause_get: bool,
    get_entered: bool,
    allocations: HashMap<usize, Layout>,
    mib_allocations: HashMap<usize, Layout>,
    wake: bool,
}

fn shared() -> &'static (Mutex<Fake>, Condvar) {
    static SHARED: OnceLock<(Mutex<Fake>, Condvar)> = OnceLock::new();
    SHARED.get_or_init(|| (Mutex::new(Fake::default()), Condvar::new()))
}
fn fake() -> MutexGuard<'static, Fake> {
    shared().0.lock().unwrap()
}
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap()
}
fn reset() {
    let mut state = fake();
    assert!(state.allocations.is_empty());
    assert!(state.mib_allocations.is_empty());
    *state = Fake::default();
}
fn wait_for(mut predicate: impl FnMut(&Fake) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if predicate(&fake()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for fake kernel"
        );
        thread::sleep(Duration::from_millis(2));
    }
}
fn wait_match(expected: LocalMatch, src: [u8; 4], dst: [u8; 4]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while lookup_v4(src, dst) != expected {
        assert!(
            Instant::now() < deadline,
            "lookup did not become {expected:?}"
        );
        thread::sleep(Duration::from_millis(2));
    }
}
fn begin_callback() -> PUNICAST_IPADDRESS_CHANGE_CALLBACK {
    let mut state = fake();
    let callback = state.callback;
    assert!(callback.is_some());
    state.active_callbacks += 1;
    callback
}
fn finish_callback(callback: PUNICAST_IPADDRESS_CHANGE_CALLBACK) {
    unsafe { callback.unwrap()(ptr::null_mut(), ptr::null_mut(), 0) };
    let mut state = fake();
    state.active_callbacks -= 1;
    shared().1.notify_all();
}
fn change(rows: Vec<Row>) {
    fake().rows = rows;
    finish_callback(begin_callback());
}
fn start_test() {
    assert!(unsafe { start() } >= 0);
}
fn stop_test() {
    unsafe { stop() };
    let state = fake();
    assert!(state.allocations.is_empty());
    assert!(state.mib_allocations.is_empty());
    assert!(state.callback.is_none());
}
const A: [u8; 4] = [192, 168, 7, 11];
const B: [u8; 4] = [10, 9, 8, 7];
const C: [u8; 4] = [198, 51, 100, 3];
const V6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4];

#[test]
fn snapshot_matches_either_endpoint_across_all_interfaces_and_families() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1), Row::V4(A, 999), Row::V6(V6, 42)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    assert_eq!(lookup_v4(C, A), LocalMatch::Local);
    assert_eq!(lookup_v4(B, C), LocalMatch::Transit);
    assert_eq!(lookup_v6([0; 16], V6), LocalMatch::Local);
    let mut disguised = [0; 16];
    disguised[..4].copy_from_slice(&A);
    assert_eq!(lookup_v6(disguised, [0; 16]), LocalMatch::Transit);
    // Removing one of two identical addresses does not remove the other.
    change(vec![Row::V4(A, 999), Row::V6(V6, 42)]);
    wait_match(LocalMatch::Local, A, C);
    change(vec![Row::V6(V6, 42)]);
    wait_match(LocalMatch::Transit, A, C);
    stop_test();
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
}

#[test]
fn callback_during_initial_snapshot_cannot_publish_stale_table() {
    let _serial = serial();
    reset();
    {
        let mut state = fake();
        state.rows = vec![Row::V4(A, 1)];
        state.mutate_during_get = Some(vec![Row::V4(B, 2)]);
    }
    start_test();
    wait_for(|s| s.table_calls >= 1);
    // The first table was captured before the injected callback; it must not
    // become a valid answer while the worker is delayed before retrying.
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
    wait_match(LocalMatch::Local, B, C);
    assert_eq!(lookup_v4(A, C), LocalMatch::Transit);
    assert!(fake().notify_calls >= 1);
    assert!(fake().table_calls >= 2);
    stop_test();
}

#[test]
fn dirty_failure_and_retry_never_report_transit_from_old_state() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    fake().table_failures = 10_000;
    change(vec![Row::V4(B, 4)]);
    wait_for(|s| s.table_calls >= 2);
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
    assert_eq!(lookup_v4(B, C), LocalMatch::Unknown);
    fake().table_failures = 0;
    wait_match(LocalMatch::Local, B, C);
    assert_eq!(lookup_v4(A, C), LocalMatch::Transit);
    stop_test();
}

#[test]
fn registration_failure_is_unknown_and_retries_without_a_notification() {
    let _serial = serial();
    reset();
    {
        let mut state = fake();
        state.rows = vec![Row::V4(A, 1)];
        state.notify_failures = 10_000;
    }
    start_test();
    wait_for(|s| s.notify_calls >= 1);
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
    assert_eq!(fake().table_calls, 0);
    fake().notify_failures = 0;
    wait_match(LocalMatch::Local, A, C);
    stop_test();
}

#[test]
fn lookup_racing_callback_returns_unknown() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    // Inject a callback after binary search, before the final validity check.
    fake().checkpoint_change = true;
    assert_eq!(lookup_v4(B, C), LocalMatch::Unknown);
    stop_test();
}

#[test]
fn stop_waits_for_inflight_snapshot_and_callback_then_reclaims() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    {
        let mut state = fake();
        state.pause_get = true;
        state.get_entered = false;
    }
    change(vec![Row::V4(B, 2)]);
    wait_for(|s| s.get_entered);
    let callback = begin_callback();
    let (tx, rx) = mpsc::channel();
    let join = thread::spawn(move || {
        unsafe { stop() };
        tx.send(()).unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
    {
        let mut state = fake();
        state.pause_get = false;
        shared().1.notify_all();
    }
    wait_for(|s| s.cancel_calls != 0);
    assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
    finish_callback(callback);
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    join.join().unwrap();
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
    assert!(fake().allocations.is_empty());
    assert!(fake().mib_allocations.is_empty());
    assert!(fake().callback.is_none());
}

#[test]
fn anycast_is_refreshed_without_a_notification_and_failures_are_unknown() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    fake().anycast_rows = vec![Row::V6(V6, 87)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    assert!(available());
    assert_eq!(lookup_v6([0; 16], V6), LocalMatch::Local);
    assert_eq!(lookup_v4(B, C), LocalMatch::Transit);
    // Anycast has no callback; the next timed reconciliation discovers it.
    fake().anycast_rows.push(Row::V4(B, 456));
    wait_match(LocalMatch::Local, B, C);
    fake().anycast_failures = 10_000;
    wait_for(|s| s.anycast_calls >= 3);
    wait_match(LocalMatch::Unknown, B, C);
    assert!(!available());
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
    fake().anycast_failures = 0;
    wait_match(LocalMatch::Local, A, C);
    stop_test();
}

#[test]
fn malformed_table_never_publishes_a_partial_inventory() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    fake().anycast_rows = vec![Row::Invalid];
    start_test();
    wait_for(|s| s.anycast_calls >= 1);
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
    assert!(!available());
    fake().anycast_rows.clear();
    wait_match(LocalMatch::Local, A, C);
    stop_test();
}

#[test]
fn empty_table_status_is_a_valid_complete_snapshot() {
    let _serial = serial();
    reset();
    fake().anycast_rows = vec![Row::V4(B, 87)];
    start_test();
    wait_match(LocalMatch::Local, B, C);
    assert_eq!(lookup_v4(A, C), LocalMatch::Transit);
    assert!(available());
    fake().anycast_rows.clear();
    change(vec![Row::V4(A, 1)]);
    wait_match(LocalMatch::Local, A, C);
    assert_eq!(lookup_v4(B, C), LocalMatch::Transit);
    change(vec![]);
    wait_match(LocalMatch::Transit, A, C);
    assert!(available());
    stop_test();
}

#[test]
fn successful_periodic_refresh_keeps_snapshot_available() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    {
        let mut state = fake();
        state.pause_get = true;
        state.get_entered = false;
    }
    // A timer-driven refresh is paused within the NETIO call. It must not
    // invalidate the previously published inventory merely for being due.
    wait_for(|s| s.get_entered);
    assert!(available());
    assert_eq!(lookup_v4(A, C), LocalMatch::Local);
    assert_eq!(lookup_v4(B, C), LocalMatch::Transit);
    {
        let mut state = fake();
        state.pause_get = false;
        shared().1.notify_all();
    }
    wait_for(|s| s.anycast_calls >= 2);
    wait_match(LocalMatch::Local, A, C);
    fake().table_failures = 10_000;
    wait_match(LocalMatch::Unknown, A, C);
    assert!(!available());
    fake().table_failures = 0;
    wait_match(LocalMatch::Local, A, C);
    stop_test();
}

#[test]
fn failed_thread_start_leaves_inventory_unknown() {
    let _serial = serial();
    reset();
    fake().thread_failure = true;
    assert!(unsafe { start() } < 0);
    assert!(!available());
    assert_eq!(lookup_v4(A, C), LocalMatch::Unknown);
    stop_test();
}

#[test]
fn retired_snapshot_waits_for_rundown_without_blocking_new_lookups() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    let snapshot = unsafe {
        let irql = lock();
        let snapshot = CURRENT;
        assert_ne!(
            api::ExAcquireRundownProtection(addr_of_mut!((*snapshot).rundown)),
            0
        );
        unlock(irql);
        snapshot
    };
    change(vec![Row::V4(B, 2)]);
    wait_match(LocalMatch::Local, B, C);
    assert_eq!(fake().allocations.len(), 2);
    unsafe {
        api::ExReleaseRundownProtection(addr_of_mut!((*snapshot).rundown));
    }
    wait_for(|s| s.allocations.len() == 1);
    stop_test();
}

#[test]
fn cancellation_failure_is_retried_before_unload() {
    let _serial = serial();
    reset();
    fake().rows = vec![Row::V4(A, 1)];
    start_test();
    wait_match(LocalMatch::Local, A, C);
    fake().cancel_failures = 2;
    stop_test();
    assert_eq!(fake().cancel_calls, 3);
}

#[allow(non_snake_case)]
pub(super) mod api {
    use super::*;
    const CLOSED: usize = 1usize << (usize::BITS - 1);
    fn atomic<T>(p: *mut T) -> &'static AtomicUsize {
        unsafe { &*p.cast::<AtomicUsize>() }
    }
    pub unsafe fn KeInitializeSpinLock(lock: PKSPIN_LOCK) {
        atomic(lock).store(0, Ordering::SeqCst);
    }
    pub unsafe fn KeAcquireSpinLockRaiseToDpc(lock: PKSPIN_LOCK) -> KIRQL {
        while atomic(lock)
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            thread::yield_now();
        }
        0
    }
    pub unsafe fn KeReleaseSpinLock(lock: PKSPIN_LOCK, _irql: KIRQL) {
        atomic(lock).store(0, Ordering::Release);
    }
    pub unsafe fn KeInitializeEvent(_event: PRKEVENT, _ty: EVENT_TYPE, _state: BOOLEAN) {
        fake().wake = false;
    }
    pub unsafe fn KeSetEvent(_event: PRKEVENT, _increment: KPRIORITY, _wait: BOOLEAN) -> LONG {
        let mut state = fake();
        state.wake = true;
        shared().1.notify_all();
        0
    }
    pub unsafe fn KeWaitForSingleObject(
        _object: PVOID,
        _reason: KWAIT_REASON,
        _mode: KPROCESSOR_MODE,
        _alertable: BOOLEAN,
        _timeout: PLARGE_INTEGER,
    ) -> NTSTATUS {
        let state = fake();
        let (mut state, _) = shared()
            .1
            .wait_timeout_while(state, Duration::from_millis(150), |s| !s.wake)
            .unwrap();
        if state.wake {
            state.wake = false;
            0
        } else {
            0x102
        }
    }
    pub unsafe fn KeDelayExecutionThread(
        _mode: KPROCESSOR_MODE,
        _alertable: BOOLEAN,
        _due: PLARGE_INTEGER,
    ) -> NTSTATUS {
        thread::sleep(Duration::from_millis(30));
        0
    }
    pub unsafe fn PsCreateSystemThread(
        handle: *mut HANDLE,
        _access: ACCESS_MASK,
        _attributes: POBJECT_ATTRIBUTES,
        _process: HANDLE,
        _client: PCLIENT_ID,
        start: PKSTART_ROUTINE,
        _context: PVOID,
    ) -> NTSTATUS {
        if fake().thread_failure {
            return -1;
        }
        let start = start.unwrap();
        let join = thread::spawn(move || unsafe { start(ptr::null_mut()) });
        unsafe {
            *handle = Box::into_raw(Box::new(join)).cast();
        }
        0
    }
    pub unsafe fn PsTerminateSystemThread(_status: NTSTATUS) -> NTSTATUS {
        0
    }
    pub unsafe fn ZwWaitForSingleObject(
        handle: HANDLE,
        _alertable: BOOLEAN,
        _timeout: PLARGE_INTEGER,
    ) -> NTSTATUS {
        unsafe { (*handle.cast::<thread::JoinHandle<()>>()).thread().unpark() };
        // JoinHandle is consumed by ZwClose after this wait. Polling preserves
        // the handle so the API contract matches the native calls.
        while !unsafe { (*handle.cast::<thread::JoinHandle<()>>()).is_finished() } {
            thread::sleep(Duration::from_millis(1));
        }
        0
    }
    pub unsafe fn ZwClose(handle: HANDLE) -> NTSTATUS {
        let join = unsafe { Box::from_raw(handle.cast::<thread::JoinHandle<()>>()) };
        join.join().unwrap();
        0
    }
    pub unsafe fn ExInitializeRundownProtection(rundown: PEX_RUNDOWN_REF) {
        atomic(rundown).store(0, Ordering::SeqCst);
    }
    pub unsafe fn ExAcquireRundownProtection(rundown: PEX_RUNDOWN_REF) -> BOOLEAN {
        let a = atomic(rundown);
        let mut current = a.load(Ordering::Acquire);
        loop {
            if current & CLOSED != 0 {
                return 0;
            }
            match a.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return 1,
                Err(next) => current = next,
            }
        }
    }
    pub unsafe fn ExReleaseRundownProtection(rundown: PEX_RUNDOWN_REF) {
        atomic(rundown).fetch_sub(1, Ordering::Release);
    }
    pub unsafe fn ExWaitForRundownProtectionRelease(rundown: PEX_RUNDOWN_REF) {
        let a = atomic(rundown);
        a.fetch_or(CLOSED, Ordering::AcqRel);
        while a.load(Ordering::Acquire) != CLOSED {
            thread::yield_now();
        }
    }
    pub unsafe fn ExAllocatePool2(_flags: POOL_FLAGS, size: SIZE_T, _tag: ULONG) -> PVOID {
        let layout = Layout::from_size_align(size as usize, 16).unwrap();
        let ptr = unsafe { alloc_zeroed(layout) };
        fake().allocations.insert(ptr as usize, layout);
        ptr.cast()
    }
    pub unsafe fn ExFreePoolWithTag(p: PVOID, _tag: ULONG) {
        let layout = fake().allocations.remove(&(p as usize)).unwrap();
        unsafe { dealloc(p.cast(), layout) };
    }
    pub unsafe fn NotifyUnicastIpAddressChange(
        family: ADDRESS_FAMILY,
        callback: PUNICAST_IPADDRESS_CHANGE_CALLBACK,
        _context: PVOID,
        _initial: BOOLEAN,
        handle: *mut HANDLE,
    ) -> NTSTATUS {
        assert_eq!(family as u32, AF_UNSPEC);
        let mut state = fake();
        state.notify_calls += 1;
        if state.notify_failures != 0 {
            state.notify_failures -= 1;
            return -1;
        }
        state.callback = callback;
        unsafe { *handle = 1usize as HANDLE };
        0
    }
    pub unsafe fn CancelMibChangeNotify2(_handle: HANDLE) -> NTSTATUS {
        let mut state = fake();
        state.cancel_calls += 1;
        shared().1.notify_all();
        if state.cancel_failures != 0 {
            state.cancel_failures -= 1;
            return -1;
        }
        while state.active_callbacks != 0 {
            state = shared().1.wait(state).unwrap();
        }
        state.callback = None;
        0
    }
    pub unsafe fn GetUnicastIpAddressTable(
        family: ADDRESS_FAMILY,
        table: *mut PMIB_UNICASTIPADDRESS_TABLE,
    ) -> NTSTATUS {
        assert_eq!(family as u32, AF_UNSPEC);
        let mut state = fake();
        state.table_calls += 1;
        state.get_entered = true;
        shared().1.notify_all();
        while state.pause_get {
            state = shared().1.wait(state).unwrap();
        }
        if state.table_failures != 0 {
            state.table_failures -= 1;
            return -1;
        }
        assert!(
            state.callback.is_some(),
            "must register before first snapshot"
        );
        let rows = state.rows.clone();
        let update = state.mutate_during_get.take();
        if rows.is_empty() {
            drop(state);
            if let Some(rows) = update {
                change(rows);
            }
            return FWX_WDK_STATUS_NOT_FOUND as NTSTATUS;
        }
        let size = (core::mem::offset_of!(MIB_UNICASTIPADDRESS_TABLE, Table)
            + rows.len() * size_of::<MIB_UNICASTIPADDRESS_ROW>())
        .max(size_of::<MIB_UNICASTIPADDRESS_TABLE>());
        let layout =
            Layout::from_size_align(size, core::mem::align_of::<MIB_UNICASTIPADDRESS_TABLE>())
                .unwrap();
        let result = unsafe { alloc_zeroed(layout).cast::<MIB_UNICASTIPADDRESS_TABLE>() };
        state.mib_allocations.insert(result as usize, layout);
        unsafe {
            (*result).NumEntries = rows.len() as u32;
            let target = addr_of_mut!((*result).Table).cast::<MIB_UNICASTIPADDRESS_ROW>();
            for (i, row) in rows.into_iter().enumerate() {
                let entry = &mut *target.add(i);
                match row {
                    Row::V4(bytes, index) => {
                        entry.Address.Ipv4.sin_family = AF_INET as ADDRESS_FAMILY;
                        entry.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(bytes);
                        entry.InterfaceIndex = index;
                    }
                    Row::V6(bytes, index) => {
                        entry.Address.Ipv6.sin6_family = AF_INET6 as ADDRESS_FAMILY;
                        entry.Address.Ipv6.sin6_addr.u.Byte = bytes;
                        entry.InterfaceIndex = index;
                    }
                    Row::Invalid => entry.Address.si_family = AF_UNSPEC as ADDRESS_FAMILY,
                }
            }
            *table = result;
        }
        drop(state);
        if let Some(rows) = update {
            change(rows);
        }
        0
    }
    pub unsafe fn GetAnycastIpAddressTable(
        family: ADDRESS_FAMILY,
        table: *mut PMIB_ANYCASTIPADDRESS_TABLE,
    ) -> NTSTATUS {
        assert_eq!(family as u32, AF_UNSPEC);
        let mut state = fake();
        state.anycast_calls += 1;
        if state.anycast_failures != 0 {
            state.anycast_failures -= 1;
            return -1;
        }
        assert!(
            state.callback.is_some(),
            "must register before first snapshot"
        );
        let rows = state.anycast_rows.clone();
        if rows.is_empty() {
            return FWX_WDK_STATUS_NOT_FOUND as NTSTATUS;
        }
        let size = (core::mem::offset_of!(MIB_ANYCASTIPADDRESS_TABLE, Table)
            + rows.len() * size_of::<MIB_ANYCASTIPADDRESS_ROW>())
        .max(size_of::<MIB_ANYCASTIPADDRESS_TABLE>());
        let layout =
            Layout::from_size_align(size, core::mem::align_of::<MIB_ANYCASTIPADDRESS_TABLE>())
                .unwrap();
        let result = unsafe { alloc_zeroed(layout).cast::<MIB_ANYCASTIPADDRESS_TABLE>() };
        state.mib_allocations.insert(result as usize, layout);
        unsafe {
            (*result).NumEntries = rows.len() as u32;
            let target = addr_of_mut!((*result).Table).cast::<MIB_ANYCASTIPADDRESS_ROW>();
            for (i, row) in rows.into_iter().enumerate() {
                let entry = &mut *target.add(i);
                match row {
                    Row::V4(bytes, index) => {
                        entry.Address.Ipv4.sin_family = AF_INET as ADDRESS_FAMILY;
                        entry.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(bytes);
                        entry.InterfaceIndex = index;
                    }
                    Row::V6(bytes, index) => {
                        entry.Address.Ipv6.sin6_family = AF_INET6 as ADDRESS_FAMILY;
                        entry.Address.Ipv6.sin6_addr.u.Byte = bytes;
                        entry.InterfaceIndex = index;
                    }
                    Row::Invalid => entry.Address.si_family = AF_UNSPEC as ADDRESS_FAMILY,
                }
            }
            *table = result;
        }
        0
    }
    pub unsafe fn FreeMibTable(table: PVOID) {
        let layout = fake().mib_allocations.remove(&(table as usize)).unwrap();
        unsafe {
            dealloc(table.cast(), layout);
        }
    }
    pub fn lookup_checkpoint() {
        let fire = {
            let mut state = fake();
            core::mem::take(&mut state.checkpoint_change)
        };
        if fire {
            finish_callback(begin_callback());
        }
    }
}
