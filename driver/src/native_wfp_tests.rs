//! Offline checks of native_wfp's production ABI boundary using real WDK types.
//! Only native imports and the policy collaborator are fake. The checksum module
//! is the production module, not a second checksum or packet implementation.
#![allow(non_snake_case)]

extern crate std;
use self::std::{
    boxed::Box,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Mutex, MutexGuard},
    vec::Vec,
};
use super::*;
// The parent host crate includes the production wfp.rs (feature wfp-test), which
// owns the one production wfp_checksum.rs module used by both test modes.

#[derive(Default)]
struct State {
    calls: Vec<&'static str>,
    live: BTreeSet<usize>,
    clone_status: i32,
    injection_status: i32,
    fail_device: bool,
    fail_work: bool,
    admission: u8,
    permit: u8,
    classify_calls: usize,
    observed: Option<(usize, ForwardValues, u8, u8)>,
    injection: Option<(u32, u32, u32, u32, u32)>,
    inline: bool,
    completions: usize,
    completed_status: i32,
    self_state: FWPS_PACKET_INJECTION_STATE,
    weight: u16,
    filters: usize,
    requests: usize,
    workers: usize,
    reset: Option<u8>,
    integration: bool,
    failure: Option<(&'static str, usize)>,
    rundowns: BTreeMap<usize, (usize, bool)>,
    locked: bool,
    timer_armed: bool,
    queue: VecDeque<(PIO_WORKITEM_ROUTINE, usize)>,
    work_live: bool,
    devices: usize,
    subscribed: bool,
    bfe_state: FWPM_SERVICE_STATE,
    bfe_callback: FWPM_SERVICE_STATE_CHANGE_CALLBACK0,
    notify_inside_subscribe: bool,
    subscribing: bool,
    callout_ids: BTreeSet<u32>,
    injection_handles: BTreeMap<usize, (ADDRESS_FAMILY, u32)>,
    engine_ids: BTreeSet<usize>,
    serial: usize,
    staged: BTreeMap<usize, Vec<usize>>,
    active: Vec<(usize, usize)>,
    handoff_request: bool,
    policy_result: i32,
    policy_early_allow: bool,
    policy_observation: Option<(u32, u32, u32, u32, u32)>,
    pending: usize,
    session_available: bool,
    session_references: usize,
    driver_stopping: bool,
    resource_drops: usize,
    status_reports: usize,
    injection_errors: Vec<(u32, u32, u32, u32, u32, u32)>,
    self_family: Option<ADDRESS_FAMILY>,
    self_kind: Option<u32>,
    last_injection: Option<(usize, FWPS_INJECT_COMPLETE0, usize)>,
    #[cfg(feature = "wfp-fragment-diagnostic")]
    diagnostic_logs: usize,
}
std::thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
static SERIAL: Mutex<()> = Mutex::new(());
fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}
fn begin() -> MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap();
    state(|s| {
        assert!(s.live.is_empty(), "leaked native WFP NBL");
        *s = State {
            admission: 1,
            bfe_state: FWPM_SERVICE_RUNNING,
            session_available: true,
            policy_result: 1,
            ..State::default()
        };
    });
    guard
}
fn call(name: &'static str) {
    state(|s| s.calls.push(name));
}

fn fail(name: &'static str) -> bool {
    state(|s| {
        let Some((point, remaining)) = s.failure.as_mut() else {
            return false;
        };
        if *point != name {
            return false;
        }
        if *remaining != 0 {
            *remaining -= 1;
            return false;
        }
        s.failure = None;
        true
    })
}
fn failed_status() -> i32 {
    HV_WDK_STATUS_INSUFFICIENT_RESOURCES
}
fn drain_work() {
    while let Some((worker, context)) = state(|s| s.queue.pop_front()) {
        assert!(state(|s| s.work_live));
        unsafe { worker.unwrap()(ptr::null_mut(), context as PVOID) };
    }
}
fn fire_retry() {
    assert!(state(|s| s.timer_armed));
    state(|s| s.timer_armed = false);
    unsafe {
        retry_registration(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    drain_work();
}
fn set_bfe(service: FWPM_SERVICE_STATE) {
    let callback = state(|s| {
        s.bfe_state = service;
        s.bfe_callback
    });
    if let Some(callback) = callback {
        unsafe { callback(ptr::null_mut(), service) };
    }
}

#[repr(C)]
#[derive(Default)]
struct ManagerState {
    healthy: u32,
    dirty: u32,
    work_queued: u32,
    reset_engine: u32,
    notifications_ready: u32,
}
unsafe extern "C" {
    #[link_name = "HvWfpInitialize"]
    fn actual_initialize(driver: Handle) -> i32;
    #[link_name = "HvWfpStop"]
    fn actual_stop();
    #[link_name = "HvWfpUninitialize"]
    fn actual_uninitialize();
    #[link_name = "HvWfpRequestReconcile"]
    fn actual_request_reconcile();
    #[link_name = "HvWfpReconcileWorker"]
    fn actual_reconcile_worker();
    #[link_name = "HvWfpBfeChanged"]
    fn actual_bfe_changed(reset: u8);
    #[link_name = "HvWfpEnterClassify"]
    fn actual_enter_classify() -> u8;
    #[link_name = "HvWfpClassify"]
    fn actual_classify(original: Handle, route: *const ForwardValues, ipv6: u8, valid: u8) -> u8;
    #[link_name = "HvWfpInjectionComplete"]
    fn actual_injection_complete(nbl: Handle, status: i32);
    #[link_name = "HvWfpFinish"]
    fn actual_finish(nbl: Handle, finish: u32);
    #[link_name = "HvWfpTestState"]
    fn actual_test_state() -> ManagerState;
    #[link_name = "HvWfpReportStatus"]
    fn actual_report_status();
    #[link_name = "HvWfpReportInjectionFailure"]
    fn actual_report_failure(status: i32, ipv6: u8, flags: u32, destination: u32, completion: u8);
    #[link_name = "ForwardChecksum"]
    fn actual_checksum(
        nb: Handle,
        start: u32,
        length: u32,
        field: u32,
        seed: u32,
        checksum: *mut u16,
    ) -> u8;
    #[link_name = "RestoreForwardChecksums"]
    fn actual_restore(nbl: Handle, ipv6: u8, segmented: u8) -> u8;
    #[link_name = "HvWfpInject"]
    fn actual_inject(
        nbl: Handle,
        ipv6: u8,
        compartment: u32,
        destination: u32,
        sub_interface: u32,
        flags: u32,
        segmented: u8,
        completion: Option<unsafe extern "system" fn(Handle, Handle, u8)>,
        context: Handle,
    ) -> i32;
    #[link_name = "HvWfpIsSelfInjected"]
    fn actual_is_self(nbl: Handle, ipv6: u8) -> u8;
}
#[path = "native_wfp_integration_tests.rs"]
mod integration_tests;

pub(super) unsafe fn rust_request_reconcile() {
    state(|s| s.requests += 1);
    if state(|s| s.integration) {
        unsafe { actual_request_reconcile() };
    }
}
pub(super) unsafe fn rust_reconcile_worker() {
    state(|s| s.workers += 1);
    if state(|s| s.integration) {
        unsafe { actual_reconcile_worker() };
    }
}
pub(super) unsafe fn rust_bfe_changed(reset: u8) {
    state(|s| s.reset = Some(reset));
    if state(|s| s.integration) {
        unsafe { actual_bfe_changed(reset) };
    }
}
pub(super) unsafe fn rust_enter_classify() -> u8 {
    if state(|s| s.integration) {
        unsafe { actual_enter_classify() }
    } else {
        state(|s| s.admission)
    }
}
pub(super) unsafe fn rust_classify(
    original: Handle,
    route: *const ForwardValues,
    ipv6: u8,
    valid: u8,
) -> u8 {
    state(|s| {
        s.classify_calls += 1;
        s.observed = Some((original as usize, unsafe { *route }, ipv6, valid));
    });
    if state(|s| s.integration) {
        unsafe { actual_classify(original, route, ipv6, valid) }
    } else {
        state(|s| s.permit)
    }
}
pub(super) unsafe fn rust_injection_complete(nbl: Handle, status: i32) {
    state(|s| {
        s.completions += 1;
        s.completed_status = status;
    });
    if state(|s| s.integration) {
        unsafe { actual_injection_complete(nbl, status) };
    } else {
        unsafe { hv_wfp_free_packet(nbl.cast()) };
    }
}

#[unsafe(no_mangle)]
extern "C" fn hv_wfp_driver_stopping() -> u8 {
    u8::from(state(|s| s.driver_stopping))
}
#[unsafe(no_mangle)]
extern "C" fn hv_wfp_session_acquire() -> u8 {
    state(|s| {
        if s.session_available {
            s.session_references += 1;
            1
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
extern "C" fn hv_wfp_session_release() {
    state(|s| {
        assert!(s.session_references != 0);
        s.session_references -= 1;
    });
}
#[unsafe(no_mangle)]
extern "C" fn HvResourceDrop() {
    state(|s| s.resource_drops += 1);
}
#[unsafe(no_mangle)]
extern "C" fn HvClassifyIp(
    packet: usize,
    interface: u32,
    direction: u32,
    family: u32,
    cacheable: u32,
    session: u32,
) -> i32 {
    let (result, early) = state(|s| {
        s.policy_observation = Some((interface, direction, family, cacheable, session));
        s.pending = if s.policy_result < 0 { packet } else { 0 };
        (s.policy_result, s.policy_early_allow)
    });
    if early {
        unsafe { actual_finish(packet as Handle, 0) };
        state(|s| s.pending = 0);
    }
    result
}
#[unsafe(no_mangle)]
extern "C" fn HvForwardStop() {
    call("forward_stop");
    let packet = state(|s| core::mem::take(&mut s.pending));
    if packet != 0 {
        unsafe { actual_finish(packet as Handle, 1) };
    }
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpStatus(_healthy: u32) {
    state(|s| s.status_reports += 1);
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpInjectionError(
    status: u32,
    ipv6: u32,
    route: u32,
    completion: u32,
    destination: u32,
    failures: u32,
) {
    state(|s| {
        s.injection_errors
            .push((status, ipv6, route, completion, destination, failures))
    });
}
#[unsafe(no_mangle)]
extern "C" fn hv_wfp_test_handoff() {
    if state(|s| core::mem::take(&mut s.handoff_request)) {
        unsafe { actual_request_reconcile() };
    }
}
#[cfg(feature = "wfp-fragment-diagnostic")]
pub(super) unsafe fn rust_fragment_diagnostic(
    _kind: u32,
    _flags: u32,
    _source: u32,
    _destination: u32,
    _length: u32,
    _chained: u32,
    count: u32,
) {
    assert!(count <= 32);
    state(|s| s.diagnostic_logs += 1);
}

pub(super) unsafe fn KeInitializeMutex(_mutex: PRKMUTEX, level: ULONG) {
    assert_eq!(level, 0);
}
pub(super) unsafe fn KeInitializeDpc(_dpc: PRKDPC, callback: PKDEFERRED_ROUTINE, context: PVOID) {
    assert!(callback.is_some());
    assert!(context.is_null());
}
pub(super) unsafe fn KeInitializeTimer(_timer: PKTIMER) {}
pub(super) unsafe fn KeFlushQueuedDpcs() {
    call("flush_dpcs");
}
pub(super) unsafe fn KeSetTimer(_timer: PKTIMER, due: LARGE_INTEGER, _dpc: PKDPC) -> BOOLEAN {
    assert_eq!(unsafe { due.QuadPart }, -10_000_000);
    state(|s| s.timer_armed = true);
    call("arm_timer");
    0
}
pub(super) unsafe fn KeCancelTimer(_timer: PKTIMER) -> BOOLEAN {
    state(|s| s.timer_armed = false);
    call("cancel_timer");
    0
}
pub(super) unsafe fn KeWaitForSingleObject(
    _object: PVOID,
    reason: KWAIT_REASON,
    mode: KPROCESSOR_MODE,
    alertable: BOOLEAN,
    timeout: PLARGE_INTEGER,
) -> NTSTATUS {
    assert_eq!(reason, Executive);
    assert_eq!(mode, KernelMode as KPROCESSOR_MODE);
    assert_eq!(alertable, 0);
    assert!(timeout.is_null());
    state(|s| {
        assert!(!s.locked, "management mutex reentry");
        s.locked = true;
    });
    call("lock");
    0
}
pub(super) unsafe fn KeReleaseMutex(_mutex: PRKMUTEX, wait: BOOLEAN) -> LONG {
    assert_eq!(wait, 0);
    state(|s| {
        assert!(s.locked);
        s.locked = false;
    });
    call("unlock");
    0
}
pub(super) unsafe fn KeDelayExecutionThread(
    mode: KPROCESSOR_MODE,
    alertable: BOOLEAN,
    interval: PLARGE_INTEGER,
) -> NTSTATUS {
    assert_eq!(mode, KernelMode as KPROCESSOR_MODE);
    assert_eq!(alertable, 0);
    assert_eq!(unsafe { (*interval).QuadPart }, -1_000_000);
    call("delay");
    0
}
pub(super) unsafe fn ExInitializeRundownProtection(_rundown: PEX_RUNDOWN_REF) {
    state(|s| {
        s.rundowns.insert(_rundown as usize, (0, false));
    });
    call("initialize_rundown");
}
pub(super) unsafe fn ExAcquireRundownProtection(_rundown: PEX_RUNDOWN_REF) -> BOOLEAN {
    call("acquire_rundown");
    state(|s| {
        if !s.integration {
            return 1;
        }
        let r = s.rundowns.get_mut(&(_rundown as usize)).unwrap();
        if r.1 {
            0
        } else {
            r.0 += 1;
            1
        }
    })
}
pub(super) unsafe fn ExReleaseRundownProtection(_rundown: PEX_RUNDOWN_REF) {
    state(|s| {
        if s.integration {
            let r = s.rundowns.get_mut(&(_rundown as usize)).unwrap();
            assert!(r.0 > 0);
            r.0 -= 1;
        }
    });
    call("release_rundown");
}
pub(super) unsafe fn ExWaitForRundownProtectionRelease(_rundown: PEX_RUNDOWN_REF) {
    if state(|s| s.integration) {
        if _rundown == rundown(0) {
            drain_work();
        }
        state(|s| {
            let r = s.rundowns.get_mut(&(_rundown as usize)).unwrap();
            assert_eq!(r.0, 0, "rundown waited with live references");
            assert!(!r.1, "rundown waited more than once");
            r.1 = true;
        });
    }
    call("wait_rundown");
}
pub(super) unsafe fn IoCreateDevice(
    _driver: PDRIVER_OBJECT,
    size: ULONG,
    name: PUNICODE_STRING,
    kind: ULONG,
    characteristics: ULONG,
    exclusive: BOOLEAN,
    out: *mut PDEVICE_OBJECT,
) -> NTSTATUS {
    assert_eq!(size, 0);
    assert!(name.is_null());
    assert_eq!(kind, FILE_DEVICE_UNKNOWN);
    assert_eq!((characteristics, exclusive), (0, 0));
    if state(|s| s.fail_device) || fail("create_device") {
        return failed_status();
    }
    let device = Box::into_raw(Box::new(DEVICE_OBJECT {
        Flags: DO_DEVICE_INITIALIZING,
        ..unsafe { zeroed() }
    }));
    unsafe { out.write(device) };
    state(|s| s.devices += 1);
    call("create_device");
    0
}
pub(super) unsafe fn IoDeleteDevice(device: PDEVICE_OBJECT) {
    state(|s| {
        assert!(!s.work_live);
        assert!(s.devices > 0);
        s.devices -= 1;
    });
    unsafe { drop(Box::from_raw(device)) };
    call("delete_device");
}
pub(super) unsafe fn IoAllocateWorkItem(device: PDEVICE_OBJECT) -> PIO_WORKITEM {
    assert_eq!(unsafe { (*device).Flags } & DO_DEVICE_INITIALIZING, 0);
    call("allocate_work");
    if state(|s| s.fail_work) || fail("allocate_work") {
        ptr::null_mut()
    } else {
        state(|s| s.work_live = true);
        0x123usize as PIO_WORKITEM
    }
}
pub(super) unsafe fn IoFreeWorkItem(work: PIO_WORKITEM) {
    assert_eq!(work as usize, 0x123);
    state(|s| {
        assert!(s.work_live);
        assert!(s.queue.is_empty());
        assert!(!s.timer_armed);
        s.work_live = false;
    });
    call("free_work");
}
pub(super) unsafe fn IoQueueWorkItem(
    work: PIO_WORKITEM,
    worker: PIO_WORKITEM_ROUTINE,
    queue: WORK_QUEUE_TYPE,
    context: PVOID,
) {
    assert_eq!(work as usize, 0x123);
    assert!(worker.is_some());
    assert_eq!(queue, DelayedWorkQueue);
    assert!(context.is_null());
    state(|s| {
        assert!(s.work_live);
        assert!(!s.subscribing);
        if s.integration {
            s.queue.push_back((worker, context as usize));
        }
    });
    call("queue_work");
}
pub(super) unsafe fn FwpmBfeStateGet0() -> FWPM_SERVICE_STATE {
    state(|s| {
        assert!(!s.subscribing);
        s.bfe_state
    })
}
pub(super) unsafe fn FwpmBfeStateSubscribeChanges0(
    device: Handle,
    callback: FWPM_SERVICE_STATE_CHANGE_CALLBACK0,
    context: Handle,
    out: *mut HANDLE,
) -> NTSTATUS {
    assert!(!device.is_null());
    assert!(callback.is_some());
    assert!(context.is_null());
    if fail("subscribe") {
        return failed_status();
    }
    state(|s| s.subscribing = true);
    if state(|s| s.notify_inside_subscribe) {
        unsafe { callback.unwrap()(context, FWPM_SERVICE_RUNNING) };
    }
    state(|s| {
        s.subscribing = false;
        s.subscribed = true;
        s.bfe_callback = callback;
    });
    unsafe { out.write(0x456usize as HANDLE) };
    call("subscribe");
    0
}
pub(super) unsafe fn FwpmBfeStateUnsubscribeChanges0(subscription: HANDLE) -> NTSTATUS {
    assert_eq!(subscription as usize, 0x456);
    state(|s| {
        assert!(!s.locked);
        assert!(s.subscribed);
        s.subscribed = false;
        s.bfe_callback = None;
    });
    call("unsubscribe");
    0
}
pub(super) unsafe fn FwpsCalloutRegister0(
    device: Handle,
    callout: *const FWPS_CALLOUT0,
    id: *mut UINT32,
) -> NTSTATUS {
    assert!(!device.is_null());
    call("register_callout");
    if fail("register_callout") {
        return failed_status();
    }
    let next = state(|s| {
        if !s.integration {
            return 42;
        }
        let next = 42 + s.callout_ids.len() as u32;
        assert!(s.callout_ids.insert(next));
        next
    });
    unsafe {
        assert!((*callout).classifyFn.is_some());
        assert!((*callout).notifyFn.is_some());
        id.write(next);
    }
    0
}
pub(super) unsafe fn FwpsCalloutUnregisterById0(id: UINT32) -> NTSTATUS {
    state(|s| {
        if s.integration {
            assert!(s.callout_ids.remove(&id));
        } else {
            assert_eq!(id, 42);
        }
    });
    call("unregister_callout");
    0
}
pub(super) unsafe fn FwpsInjectionHandleCreate0(
    family: ADDRESS_FAMILY,
    flags: UINT32,
    out: *mut HANDLE,
) -> NTSTATUS {
    assert!(FAMILIES.contains(&family));
    assert!(flags == FWPS_INJECTION_TYPE_NETWORK || flags == FWPS_INJECTION_TYPE_FORWARD);
    call("create_injection");
    if fail("create_injection") {
        return failed_status();
    }
    let handle = state(|s| {
        if !s.integration {
            return 0x789;
        }
        s.serial += 1;
        let h = 0x789 + s.serial;
        s.injection_handles.insert(h, (family, flags));
        h
    });
    unsafe { out.write(handle as HANDLE) };
    0
}
pub(super) unsafe fn FwpsInjectionHandleDestroy0(handle: HANDLE) -> NTSTATUS {
    state(|s| {
        if s.integration {
            assert!(s.injection_handles.remove(&(handle as usize)).is_some());
        } else {
            assert_eq!(handle as usize, 0x789);
        }
    });
    call("destroy_injection");
    0
}
pub(super) unsafe fn FwpmEngineOpen0(
    server: *const wchar_t,
    authentication: UINT32,
    identity: *mut SEC_WINNT_AUTH_IDENTITY_W,
    session: *const FWPM_SESSION0,
    out: *mut HANDLE,
) -> NTSTATUS {
    assert!(server.is_null());
    assert_eq!(authentication, RPC_C_AUTHN_WINNT);
    assert!(identity.is_null());
    assert_eq!(unsafe { (*session).flags }, FWPM_SESSION_FLAG_DYNAMIC);
    call("open_engine");
    if fail("open_engine") {
        return failed_status();
    }
    let h = state(|s| {
        if !s.integration {
            return 0xabc;
        }
        s.serial += 1;
        let h = 0xabc + s.serial;
        assert!(s.engine_ids.insert(h));
        h
    });
    unsafe { out.write(h as HANDLE) };
    0
}
pub(super) unsafe fn FwpmEngineClose0(_engine: HANDLE) -> NTSTATUS {
    call("close_engine");
    if fail("close_engine") {
        return failed_status();
    }
    state(|s| {
        if s.integration {
            assert!(s.engine_ids.remove(&(_engine as usize)));
            s.staged.remove(&(_engine as usize));
            s.active.retain(|(engine, _)| *engine != _engine as usize);
        }
    });
    0
}
pub(super) unsafe fn FwpmTransactionBegin0(_engine: HANDLE, flags: UINT32) -> NTSTATUS {
    assert_eq!(flags, 0);
    call("begin_transaction");
    if fail("begin_transaction") {
        return failed_status();
    }
    state(|s| {
        if s.integration {
            assert!(s.engine_ids.contains(&(_engine as usize)));
            assert!(s.staged.insert(_engine as usize, Vec::new()).is_none());
        }
    });
    0
}
pub(super) unsafe fn FwpmTransactionCommit0(_engine: HANDLE) -> NTSTATUS {
    call("commit_transaction");
    if fail("commit_transaction") {
        return failed_status();
    }
    state(|s| {
        if s.integration {
            let filters = s.staged.remove(&(_engine as usize)).unwrap();
            assert_eq!(filters.len(), 2);
            s.active
                .extend(filters.into_iter().map(|family| (_engine as usize, family)));
        }
    });
    0
}
pub(super) unsafe fn FwpmTransactionAbort0(_engine: HANDLE) -> NTSTATUS {
    call("abort_transaction");
    state(|s| {
        s.staged.remove(&(_engine as usize));
    });
    0
}
fn guid_eq(left: &GUID, right: &GUID) -> bool {
    left.Data1 == right.Data1
        && left.Data2 == right.Data2
        && left.Data3 == right.Data3
        && left.Data4 == right.Data4
}
pub(super) unsafe fn FwpmProviderAdd0(
    _engine: HANDLE,
    provider: *const FWPM_PROVIDER0,
    sd: PSECURITY_DESCRIPTOR,
) -> NTSTATUS {
    assert!(sd.is_null());
    assert!(guid_eq(unsafe { &(*provider).providerKey }, &PROVIDER_KEY));
    assert_eq!(unsafe { (*provider).flags }, 0);
    call("add_provider");
    if fail("add_provider") {
        failed_status()
    } else {
        0
    }
}
pub(super) unsafe fn FwpmSubLayerAdd0(
    _engine: HANDLE,
    sublayer: *const FWPM_SUBLAYER0,
    sd: PSECURITY_DESCRIPTOR,
) -> NTSTATUS {
    assert!(sd.is_null());
    assert!(guid_eq(unsafe { &(*sublayer).subLayerKey }, &SUBLAYER_KEY));
    state(|s| s.weight = unsafe { (*sublayer).weight });
    call("add_sublayer");
    if fail("add_sublayer") {
        failed_status()
    } else {
        0
    }
}
pub(super) unsafe fn FwpmCalloutAdd0(
    _engine: HANDLE,
    callout: *const FWPM_CALLOUT0,
    sd: PSECURITY_DESCRIPTOR,
    id: *mut UINT32,
) -> NTSTATUS {
    assert!(sd.is_null());
    assert!(id.is_null());
    assert!(
        LAYERS
            .iter()
            .any(|layer| guid_eq(layer, unsafe { &(*callout).applicableLayer }))
    );
    call("add_callout");
    if fail("add_callout") {
        failed_status()
    } else {
        0
    }
}
pub(super) unsafe fn ExUuidCreate(uuid: *mut UUID) -> NTSTATUS {
    if fail("uuid") {
        return failed_status();
    }
    unsafe {
        uuid.write(GUID {
            Data1: 1,
            Data2: 2,
            Data3: 3,
            Data4: [4; 8],
        })
    };
    0
}
pub(super) unsafe fn FwpmFilterAdd0(
    _engine: HANDLE,
    filter: *const FWPM_FILTER0,
    sd: PSECURITY_DESCRIPTOR,
    id: *mut UINT64,
) -> NTSTATUS {
    assert!(sd.is_null());
    assert!(id.is_null());
    unsafe {
        assert_eq!((*filter).flags, 0);
        assert_eq!((*filter).numFilterConditions, 0);
        assert!((*filter).filterCondition.is_null());
        assert_eq!((*filter).weight.type_, FWP_EMPTY);
        assert_eq!((*filter).action.type_, FWP_ACTION_CALLOUT_TERMINATING);
        let family = LAYERS
            .iter()
            .position(|layer| guid_eq(layer, &(*filter).layerKey))
            .unwrap();
        assert!(guid_eq(
            &(*filter).action.__bindgen_anon_1.calloutKey,
            &CALLOUT_KEYS[family]
        ));
        assert!(guid_eq(&(*filter).subLayerKey, &SUBLAYER_KEY));
    }
    call("add_filter");
    if fail("add_filter") {
        return failed_status();
    }
    let family = LAYERS
        .iter()
        .position(|layer| guid_eq(layer, unsafe { &(*filter).layerKey }))
        .unwrap();
    state(|s| {
        s.filters += 1;
        if s.integration {
            s.staged.get_mut(&(_engine as usize)).unwrap().push(family);
        }
    });
    0
}
// Stable Rust cannot define a C-variadic function. This fake checks the exact
// five arguments at the sole production DbgPrintEx call site.
pub(super) unsafe fn DbgPrintEx(
    component: ULONG,
    level: ULONG,
    _format: PCSTR,
    _operation: *const c_char,
    _status: ULONG,
) -> ULONG {
    assert_eq!(component, DPFLTR_IHVNETWORK_ID as u32);
    assert_eq!(level, DPFLTR_ERROR_LEVEL);
    0
}
pub(super) unsafe fn FwpsQueryPacketInjectionState0(
    _handle: HANDLE,
    _nbl: *const NET_BUFFER_LIST,
    _context: *mut HANDLE,
) -> FWPS_PACKET_INJECTION_STATE {
    state(|s| {
        if !s.integration {
            return s.self_state;
        }
        let (family, kind) = s
            .injection_handles
            .get(&(_handle as usize))
            .copied()
            .unwrap();
        if s.self_family.is_none_or(|f| f == family) && s.self_kind.is_none_or(|k| k == kind) {
            s.self_state
        } else {
            FWPS_PACKET_NOT_INJECTED
        }
    })
}
unsafe fn make_clone(original: *mut NET_BUFFER_LIST, out: *mut *mut NET_BUFFER_LIST) -> NTSTATUS {
    let status = state(|s| s.clone_status);
    if status < 0 {
        return status;
    }
    let nbl = Box::into_raw(Box::<NET_BUFFER_LIST>::default());
    unsafe {
        crate::native_packet::set_first_nb(nbl, first_nb(original));
        out.write(nbl);
    }
    state(|s| assert!(s.live.insert(nbl as usize)));
    0
}
pub(super) unsafe fn FwpsAllocateCloneNetBufferList0(
    original: *mut NET_BUFFER_LIST,
    nbl_pool: NDIS_HANDLE,
    nb_pool: NDIS_HANDLE,
    flags: ULONG,
    out: *mut *mut NET_BUFFER_LIST,
) -> NTSTATUS {
    assert!(nbl_pool.is_null() && nb_pool.is_null());
    assert_eq!(flags, 0);
    call("clone");
    unsafe { make_clone(original, out) }
}
pub(super) unsafe fn FwpsReassembleForwardFragmentGroup0(
    family: ADDRESS_FAMILY,
    original: *mut NET_BUFFER_LIST,
    pool: NDIS_HANDLE,
    backfill: ULONG,
    flags: ULONG,
    out: *mut *mut NET_BUFFER_LIST,
) -> NTSTATUS {
    assert!(FAMILIES.contains(&family));
    assert!(pool.is_null());
    assert_eq!((backfill, flags), (0, 0));
    call("reassemble");
    unsafe { make_clone(original, out) }
}
unsafe fn free(nbl: *mut NET_BUFFER_LIST, name: &'static str) {
    assert!(
        unsafe { (*nbl).Context }.is_null(),
        "context must be freed before NBL"
    );
    state(|s| assert!(s.live.remove(&(nbl as usize)), "foreign/double NBL free"));
    unsafe { drop(Box::from_raw(nbl)) };
    call(name);
}
pub(super) unsafe fn FwpsFreeNetBufferList0(nbl: *mut NET_BUFFER_LIST) {
    unsafe { free(nbl, "free_reassembly") };
}
pub(super) unsafe fn FwpsFreeCloneNetBufferList0(nbl: *mut NET_BUFFER_LIST, flags: ULONG) {
    assert_eq!(flags, 0);
    unsafe { free(nbl, "free_clone") };
}
#[allow(clippy::too_many_arguments)] // The fake preserves the WDK call arguments.
unsafe fn inject(
    route: u32,
    family: u32,
    compartment: u32,
    destination: u32,
    sub_interface: u32,
    nbl: *mut NET_BUFFER_LIST,
    completion: FWPS_INJECT_COMPLETE0,
    context: HANDLE,
) -> NTSTATUS {
    let (status, inline) = state(|s| {
        s.injection = Some((route, family, compartment, destination, sub_interface));
        s.last_injection = Some((nbl as usize, completion, context as usize));
        (s.injection_status, s.inline)
    });
    if status >= 0 && inline {
        unsafe { completion.unwrap()(context, nbl, 1) };
    }
    status
}
#[allow(clippy::too_many_arguments)] // Exact WDK signature.
pub(super) unsafe fn FwpsInjectForwardAsync0(
    _handle: HANDLE,
    context: HANDLE,
    flags: UINT32,
    family: ADDRESS_FAMILY,
    compartment: COMPARTMENT_ID,
    destination: IF_INDEX,
    nbl: *mut NET_BUFFER_LIST,
    completion: FWPS_INJECT_COMPLETE0,
    done: HANDLE,
) -> NTSTATUS {
    assert!(context.is_null());
    assert_eq!(flags, 0);
    unsafe {
        inject(
            0,
            u32::from(family),
            compartment as u32,
            destination,
            0,
            nbl,
            completion,
            done,
        )
    }
}
#[allow(clippy::too_many_arguments)] // Exact WDK signature.
pub(super) unsafe fn FwpsInjectNetworkReceiveAsync0(
    _handle: HANDLE,
    context: HANDLE,
    flags: UINT32,
    compartment: COMPARTMENT_ID,
    destination: IF_INDEX,
    sub_interface: IF_INDEX,
    nbl: *mut NET_BUFFER_LIST,
    completion: FWPS_INJECT_COMPLETE0,
    done: HANDLE,
) -> NTSTATUS {
    assert!(context.is_null());
    assert_eq!(flags, 0);
    unsafe {
        inject(
            1,
            0,
            compartment as u32,
            destination,
            sub_interface,
            nbl,
            completion,
            done,
        )
    }
}
pub(super) unsafe fn FwpsInjectNetworkSendAsync0(
    _handle: HANDLE,
    context: HANDLE,
    flags: UINT32,
    compartment: COMPARTMENT_ID,
    nbl: *mut NET_BUFFER_LIST,
    completion: FWPS_INJECT_COMPLETE0,
    done: HANDLE,
) -> NTSTATUS {
    assert!(context.is_null());
    assert_eq!(flags, 0);
    unsafe { inject(2, 0, compartment as u32, 0, 0, nbl, completion, done) }
}
#[cfg(feature = "wfp-fragment-diagnostic")]
pub(super) unsafe fn NdisGetDataBuffer(
    nb: *mut NET_BUFFER,
    length: ULONG,
    storage: PVOID,
    alignment: ULONG,
    offset: ULONG,
) -> PVOID {
    assert_eq!((alignment, offset), (1, 0));
    if unsafe { ForwardRead(nb, 0, storage.cast(), length) } != 0 {
        storage
    } else {
        ptr::null_mut()
    }
}

fn fixed_values(ipv6: bool, flags: u32) -> Vec<FWPS_INCOMING_VALUE0> {
    let count = if ipv6 {
        FWPS_FIELD_IPFORWARD_V6_MAX
    } else {
        FWPS_FIELD_IPFORWARD_V4_MAX
    } as usize;
    let mut values = self::std::vec![FWPS_INCOMING_VALUE0::default(); count];
    let fields = if ipv6 {
        [
            FWPS_FIELD_IPFORWARD_V6_SOURCE_INTERFACE_INDEX,
            FWPS_FIELD_IPFORWARD_V6_DESTINATION_INTERFACE_INDEX,
            FWPS_FIELD_IPFORWARD_V6_DESTINATION_SUB_INTERFACE_INDEX,
            FWPS_FIELD_IPFORWARD_V6_FLAGS,
        ]
    } else {
        [
            FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX,
            FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX,
            FWPS_FIELD_IPFORWARD_V4_DESTINATION_SUB_INTERFACE_INDEX,
            FWPS_FIELD_IPFORWARD_V4_FLAGS,
        ]
    };
    for (field, value) in fields.into_iter().zip([19, 23, 29, flags]) {
        values[field as usize].value.type_ = FWP_UINT32;
        values[field as usize].value.__bindgen_anon_1.uint32 = value;
    }
    values
}
fn route(flags: u32) -> ForwardValues {
    ForwardValues {
        source: 19,
        destination: 23,
        sub_interface: 29,
        compartment: 31,
        flags,
    }
}
unsafe extern "C" fn complete(context: Handle, nbl: *mut NET_BUFFER_LIST, dispatch: u8) {
    unsafe { hv_wfp_complete(context, nbl, dispatch) };
}

#[test]
fn forward_values_preserve_both_families_and_require_typed_nonzero_indices() {
    let _guard = begin();
    for ipv6 in [false, true] {
        let mut values = fixed_values(ipv6, FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU);
        let mut incoming = FWPS_INCOMING_VALUES0 {
            incomingValue: values.as_mut_ptr(),
            valueCount: values.len() as u32,
            ..Default::default()
        };
        let metadata = FWPS_INCOMING_METADATA_VALUES0 {
            currentMetadataValues: FWPS_METADATA_FIELD_COMPARTMENT_ID,
            compartmentId: 31,
            ..Default::default()
        };
        let mut decoded = ForwardValues::default();
        assert!(unsafe { decode_forward(&incoming, &metadata, ipv6, &mut decoded) });
        assert_eq!(
            (
                decoded.source,
                decoded.destination,
                decoded.sub_interface,
                decoded.compartment
            ),
            (19, 23, 29, 31)
        );
        assert!(unsafe { decode_forward(&incoming, ptr::null(), ipv6, &mut decoded) });
        assert_eq!(decoded.compartment, UNSPECIFIED_COMPARTMENT_ID as u32);
        let source = if ipv6 {
            FWPS_FIELD_IPFORWARD_V6_SOURCE_INTERFACE_INDEX
        } else {
            FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX
        } as usize;
        values[source].value.type_ = FWP_UINT16;
        assert!(!unsafe { decode_forward(&incoming, &metadata, ipv6, &mut decoded) });
        values[source].value.type_ = FWP_UINT32;
        values[source].value.__bindgen_anon_1.uint32 = 0;
        assert!(!unsafe { decode_forward(&incoming, &metadata, ipv6, &mut decoded) });
        incoming.valueCount = 0;
        assert!(!unsafe { decode_forward(&incoming, &metadata, ipv6, &mut decoded) });
        incoming.incomingValue = ptr::null_mut();
        assert!(!unsafe { decode_forward(&incoming, &metadata, ipv6, &mut decoded) });
    }
}

#[test]
fn classify_action_rights_admission_and_absorb_are_preserved() {
    let _guard = begin();
    let mut values = fixed_values(false, 0);
    let incoming = FWPS_INCOMING_VALUES0 {
        layerId: FWPS_LAYER_IPFORWARD_V4 as u16,
        valueCount: values.len() as u32,
        incomingValue: values.as_mut_ptr(),
    };
    let mut out = FWPS_CLASSIFY_OUT0 {
        actionType: FWP_ACTION_CONTINUE,
        ..Default::default()
    };
    unsafe {
        classify(
            &incoming,
            ptr::null(),
            0x123usize as Handle,
            ptr::null(),
            0,
            &mut out,
        )
    };
    assert_eq!(out.actionType, FWP_ACTION_CONTINUE);
    assert_eq!(state(|s| s.classify_calls), 0);
    out.rights = FWPS_RIGHT_ACTION_WRITE;
    unsafe {
        classify(
            &incoming,
            ptr::null(),
            0x123usize as Handle,
            ptr::null(),
            0,
            &mut out,
        )
    };
    assert_eq!(out.actionType, FWP_ACTION_BLOCK);
    assert_ne!(out.flags & FWPS_CLASSIFY_OUT_FLAG_ABSORB, 0);
    assert_eq!(out.rights & FWPS_RIGHT_ACTION_WRITE, 0);
    state(|s| s.permit = 1);
    out.rights = FWPS_RIGHT_ACTION_WRITE;
    unsafe {
        classify(
            &incoming,
            ptr::null(),
            0x123usize as Handle,
            ptr::null(),
            0,
            &mut out,
        )
    };
    assert_eq!(out.actionType, FWP_ACTION_PERMIT);
    assert_eq!(out.flags & FWPS_CLASSIFY_OUT_FLAG_ABSORB, 0);
    assert_eq!(
        state(|s| s.observed.as_ref().map(|(_, route, _, valid)| (
            route.source,
            route.destination,
            *valid
        ))),
        Some((19, 23, 1))
    );
    state(|s| s.admission = 0);
    let before = state(|s| s.classify_calls);
    unsafe {
        classify(
            &incoming,
            ptr::null(),
            0x123usize as Handle,
            ptr::null(),
            0,
            &mut out,
        )
    };
    assert_eq!(out.actionType, FWP_ACTION_BLOCK);
    assert_eq!(state(|s| s.classify_calls), before);
}

#[test]
fn native_device_work_retry_and_passive_management_lifetime() {
    let _guard = begin();
    unsafe {
        state(|s| s.fail_device = true);
        assert!(hv_wfp_native_initialize(ptr::null_mut()) < 0);
        hv_wfp_free_work();
        hv_wfp_delete_device();
        state(|s| {
            s.fail_device = false;
            s.fail_work = true;
        });
        assert!(hv_wfp_native_initialize(ptr::null_mut()) < 0);
        hv_wfp_free_work();
        hv_wfp_delete_device();
        state(|s| s.fail_work = false);
        assert_eq!(hv_wfp_native_initialize(ptr::null_mut()), 0);
        hv_wfp_lock();
        hv_wfp_unlock();
        hv_wfp_queue_work();
        hv_wfp_timer(1);
        hv_wfp_timer(0);
        hv_wfp_flush_dpcs();
        hv_wfp_delay();
        assert_eq!(hv_wfp_acquire(0), 1);
        hv_wfp_release(0);
        hv_wfp_wait(0);
        retry_registration(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        reconcile_worker(ptr::null_mut(), ptr::null_mut());
        bfe_changed(ptr::null_mut(), FWPM_SERVICE_STOPPED);
        let mut subscription = ptr::null_mut();
        assert_eq!(hv_wfp_subscribe(&mut subscription), 0);
        assert_eq!(hv_wfp_unsubscribe(subscription), 0);
        assert_eq!(hv_wfp_bfe_running(), 1);
        hv_wfp_free_work();
        hv_wfp_delete_device();
    }
    assert_eq!(state(|s| (s.requests, s.workers, s.reset)), (1, 1, Some(1)));
    assert!(state(|s| s
        .calls
        .ends_with(&["free_work", "delete_device"])));
}

#[test]
fn native_descriptors_are_dynamic_and_exactly_two_unconditional_forward_filters() {
    let _guard = begin();
    unsafe {
        assert_eq!(hv_wfp_native_initialize(ptr::null_mut()), 0);
        let mut engine = ptr::null_mut();
        assert_eq!(hv_wfp_engine_open(&mut engine), 0);
        assert_eq!(hv_wfp_transaction_begin(engine), 0);
        assert_eq!(hv_wfp_provider_add(engine), 0);
        assert_eq!(hv_wfp_sublayer_add(engine, 0x7100), 0);
        for family in 0..2 {
            assert_eq!(hv_wfp_callout_add(engine, family), 0);
            assert_eq!(hv_wfp_filter_add(engine, family), 0);
            let mut id = 0;
            assert_eq!(hv_wfp_callout_register(family, &mut id), 0);
            assert_eq!(hv_wfp_callout_unregister(id), 0);
            for network in 0..2 {
                let mut injection = ptr::null_mut();
                assert_eq!(hv_wfp_injection_create(family, network, &mut injection), 0);
                assert_eq!(hv_wfp_injection_destroy(injection), 0);
            }
        }
        assert!(hv_wfp_filter_add(engine, 2) < 0);
        assert!(hv_wfp_callout_add(engine, 2) < 0);
        assert_eq!(hv_wfp_transaction_commit(engine), 0);
        hv_wfp_transaction_abort(engine);
        assert_eq!(hv_wfp_engine_close(engine), 0);
        hv_wfp_free_work();
        hv_wfp_delete_device();
    }
    assert_eq!(state(|s| (s.filters, s.weight)), (2, 0x7100));
}

#[test]
fn split_mdl_read_sum_and_checksum_write_do_not_move_offsets() {
    let _guard = begin();
    let mut a = [0xeeu8, 1, 2, 3];
    let mut b = [4u8, 5];
    let mut c = [6u8, 7, 8];
    let mut mdl_c = MDL {
        ByteCount: 3,
        MappedSystemVa: c.as_mut_ptr().cast(),
        MdlFlags: MDL_MAPPED_TO_SYSTEM_VA as CSHORT,
        ..Default::default()
    };
    let mut mdl_b = MDL {
        ByteCount: 2,
        MappedSystemVa: b.as_mut_ptr().cast(),
        MdlFlags: MDL_MAPPED_TO_SYSTEM_VA as CSHORT,
        Next: &mut mdl_c,
        ..Default::default()
    };
    let mut empty = MDL {
        Next: &mut mdl_b,
        ..Default::default()
    };
    let mut mdl_a = MDL {
        ByteCount: 4,
        MappedSystemVa: a.as_mut_ptr().cast(),
        MdlFlags: MDL_MAPPED_TO_SYSTEM_VA as CSHORT,
        Next: &mut empty,
        ..Default::default()
    };
    let mut nb = NET_BUFFER::default();
    unsafe {
        nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdl = &mut mdl_a;
        nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset = 1;
        nb.__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_1
            .DataLength = 8;
        let mut bytes = [0u8; 8];
        assert_eq!(ForwardRead(&mut nb, 0, bytes.as_mut_ptr(), 8), 1);
        assert_eq!(bytes, [1, 2, 3, 4, 5, 6, 7, 8]);
        let mut sum = 99;
        assert_eq!(hv_wfp_sum(&mut nb, 0, 8, u32::MAX, &mut sum), 1);
        assert_eq!(sum, 0x1014);
        assert_eq!(hv_wfp_sum(&mut nb, 1, 6, 1, &mut sum), 1);
        assert_eq!(sum, 0x080c);
        assert_eq!(WriteForwardChecksum(&mut nb, 2, 0xaabb), 1);
        assert_eq!(a, [0xee, 1, 2, 0xaa]);
        assert_eq!(b, [0xbb, 5]);
        assert_eq!(c, [6, 7, 8]);
        assert_eq!(current_mdl_offset(&mut nb), 1);
        assert_eq!(data_length(&mut nb), 8);
        assert_eq!(WriteForwardChecksum(&mut nb, u32::MAX, 0), 0);
        assert_eq!(ForwardRead(&mut nb, 8, bytes.as_mut_ptr(), 1), 0);
        assert_eq!(ForwardRead(&mut nb, 8, ptr::null_mut(), 0), 1);
        mdl_b.MappedSystemVa = ptr::null_mut();
        assert!(mdl_b.MappedSystemVa.is_null());
        assert_eq!(ForwardRead(&mut nb, 0, bytes.as_mut_ptr(), 8), 0);
        sum = 77;
        assert_eq!(hv_wfp_sum(&mut nb, 0, 8, 0, &mut sum), 0);
        assert_eq!(sum, 77);
        mdl_a.ByteCount = 0;
        assert_eq!(mdl_a.ByteCount, 0);
        assert_eq!(ForwardRead(&mut nb, 0, bytes.as_mut_ptr(), 8), 0);
    }
}

#[test]
fn clone_reassembly_owner_route_and_scalar_offload_profile_survive_oob_loss() {
    let _guard = begin();
    let mut original = NET_BUFFER_LIST::default();
    for slot in [
        TcpLargeSendNetBufferListInfo,
        TcpRecvSegCoalesceInfo,
        TcpReceiveBytesTransferred,
    ] {
        original.NetBufferListInfo[slot as usize] = 1usize as PVOID;
        let route = route(0);
        unsafe {
            let clone = hv_wfp_clone(&mut original, &route, 1);
            assert!(!clone.is_null());
            let context = packet_context(clone);
            assert_eq!((*context).owner, OWNER_WFP_CLONE);
            assert_eq!((*context).segmented, 1);
            assert_eq!((*context).adapter, ptr::null_mut());
            let mut info = PacketInfo::default();
            hv_wfp_packet_info(clone, &mut info);
            assert_eq!(
                (
                    info.route.destination,
                    info.route.sub_interface,
                    info.route.compartment,
                    info.ipv6
                ),
                (23, 29, 31, 1)
            );
            assert!((*clone).NetBufferListInfo.iter().all(|p| p.is_null()));
            hv_wfp_free_packet(clone);
        }
        original.NetBufferListInfo[slot as usize] = ptr::null_mut();
    }
    let mut second = NET_BUFFER_LIST::default();
    unsafe {
        crate::native_packet::set_next_nbl(&mut original, &mut second);
        assert!(hv_wfp_clone(&mut original, &route(0), 0).is_null());
        let clone = hv_wfp_clone(
            &mut original,
            &route(FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP),
            0,
        );
        assert!(!clone.is_null());
        assert_eq!((*packet_context(clone)).owner, OWNER_WFP_REASSEMBLED);
        hv_wfp_free_packet(clone);
    }
    assert!(state(|s| s.live.is_empty()));
    assert_eq!(
        state(|s| s.calls.iter().filter(|&&c| c == "free_clone").count()),
        3
    );
    assert_eq!(
        state(|s| s.calls.iter().filter(|&&c| c == "free_reassembly").count()),
        1
    );
}

#[test]
fn clone_ignores_high_dword_only_tcp_offload_values() {
    let _guard = begin();
    let mut original = NET_BUFFER_LIST::default();
    for slot in [TcpLargeSendNetBufferListInfo, TcpRecvSegCoalesceInfo] {
        original.NetBufferListInfo[slot as usize] = (1usize << 32) as PVOID;
        unsafe {
            let clone = hv_wfp_clone(&mut original, &route(0), 0);
            assert!(!clone.is_null());
            assert_eq!((*packet_context(clone)).segmented, 0);
            hv_wfp_free_packet(clone);
        }
        original.NetBufferListInfo[slot as usize] = ptr::null_mut();
    }
    assert!(state(|s| s.live.is_empty()));
}

#[test]
fn clone_native_failures_do_not_allocate_or_free_unowned_packets() {
    let _guard = begin();
    state(|s| s.clone_status = HV_WDK_STATUS_INSUFFICIENT_RESOURCES);
    let mut original = NET_BUFFER_LIST::default();
    unsafe {
        assert!(hv_wfp_clone(&mut original, &route(0), 0).is_null());
        assert!(
            hv_wfp_clone(
                &mut original,
                &route(FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP),
                1
            )
            .is_null()
        );
    }
    assert!(state(|s| s.live.is_empty()));
    assert_eq!(state(|s| s.calls.len()), 2);
}

#[test]
fn clone_context_allocation_failure_frees_the_correct_native_owner_once() {
    let _guard = begin();
    let mut original = NET_BUFFER_LIST::default();
    for flags in [0, FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP] {
        crate::native_packet::fail_next_context_allocation();
        assert!(unsafe { hv_wfp_clone(&mut original, &route(flags), 0) }.is_null());
    }
    assert!(state(|s| s.live.is_empty()));
    assert_eq!(
        state(|s| s.calls.iter().filter(|&&name| name == "free_clone").count()),
        1
    );
    assert_eq!(
        state(|s| s
            .calls
            .iter()
            .filter(|&&name| name == "free_reassembly")
            .count()),
        1
    );
}

#[test]
fn injection_routes_preserve_destination_subinterface_and_inline_completion_is_safe() {
    let _guard = begin();
    let mut original = NET_BUFFER_LIST::default();
    unsafe {
        for (injection_route, expected) in [
            (InjectionRoute::Forward, (0, AF_INET6, 31, 23, 0)),
            (InjectionRoute::NetworkReceive, (1, 0, 31, 23, 29)),
            (InjectionRoute::NetworkSend, (2, 0, 31, 0, 0)),
        ] {
            let nbl = hv_wfp_clone(&mut original, &route(0), 1);
            state(|s| s.injection_status = HV_WDK_STATUS_INSUFFICIENT_RESOURCES);
            assert!(
                hv_wfp_inject(
                    ptr::null_mut(),
                    injection_route,
                    1,
                    31,
                    23,
                    29,
                    nbl,
                    Some(complete),
                    nbl.cast()
                ) < 0
            );
            assert_eq!(state(|s| s.injection), Some(expected));
            assert_eq!(state(|s| s.completions), 0);
            state(|s| {
                s.injection_status = 0;
                s.inline = true;
            });
            assert_eq!(
                hv_wfp_inject(
                    ptr::null_mut(),
                    injection_route,
                    1,
                    31,
                    23,
                    29,
                    nbl,
                    Some(complete),
                    nbl.cast()
                ),
                0
            );
            assert_eq!(state(|s| s.completed_status), 0);
            assert!(state(|s| s.live.is_empty()));
            state(|s| s.completions = 0);
        }
    }
}

#[test]
fn checksum_oob_and_self_injection_checks_use_only_the_correct_native_fields() {
    let _guard = begin();
    let mut nbl = NET_BUFFER_LIST::default();
    nbl.NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize] = 1usize as PVOID;
    nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] = 2usize as PVOID;
    unsafe { hv_wfp_clear_checksum(&mut nbl) };
    assert!(nbl.NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize].is_null());
    assert_eq!(
        nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] as usize,
        2
    );
    for (injection_state, expected) in [
        (FWPS_PACKET_NOT_INJECTED, 0),
        (FWPS_PACKET_INJECTED_BY_SELF, 1),
        (FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF, 1),
        (FWPS_PACKET_INJECTED_BY_OTHER, 0),
    ] {
        state(|s| s.self_state = injection_state);
        assert_eq!(
            unsafe { hv_wfp_is_self(ptr::null_mut(), &mut nbl) },
            expected
        );
    }
}

#[test]
fn diagnostic_default_is_off_and_reset_has_no_packet_side_effects() {
    let _guard = begin();
    hv_wfp_reset_diagnostics();
    assert_eq!(
        unsafe { hv_wfp_diagnostic_permit(ptr::null_mut(), ptr::null(), 1) },
        0
    );
    #[cfg(not(feature = "wfp-fragment-diagnostic"))]
    assert_eq!(
        unsafe { hv_wfp_diagnostic_permit(ptr::null_mut(), ptr::null(), 0) },
        0
    );
}

fn integration_begin() -> MutexGuard<'static, ()> {
    let guard = begin();
    state(|s| s.integration = true);
    guard
}
fn start_manager() {
    assert_eq!(unsafe { actual_initialize(ptr::null_mut()) }, 0);
}
fn assert_global_filters() {
    state(|s| {
        assert_eq!(s.active.len(), 2);
        assert!(s.active.iter().any(|(_, family)| *family == 0));
        assert!(s.active.iter().any(|(_, family)| *family == 1));
        assert_eq!(s.weight, 0x7100);
        assert_eq!(s.engine_ids.len(), 1);
        assert_eq!(s.callout_ids.len(), 2);
        assert_eq!(s.injection_handles.len(), 4);
    });
    assert_eq!(unsafe { actual_test_state() }.healthy, 1);
}
fn stop_and_check() {
    unsafe { actual_uninitialize() };
    state(|s| {
        assert!(s.live.is_empty());
        assert_eq!(s.devices, 0);
        assert!(!s.work_live);
        assert!(!s.subscribed);
        assert!(s.callout_ids.is_empty());
        assert!(s.injection_handles.is_empty());
        assert!(s.engine_ids.is_empty());
        assert!(s.active.is_empty());
        assert!(s.staged.is_empty());
        assert!(s.queue.is_empty());
        assert!(!s.timer_armed);
        assert!(!s.locked);
        assert_eq!(s.pending, 0);
        assert_eq!(s.session_references, 0);
        assert!(s.rundowns.values().all(|(references, _)| *references == 0));
    });
}

#[test]
fn manager_global_registration_bfe_restart_burst_and_callback_during_subscribe() {
    let _guard = integration_begin();
    state(|s| s.notify_inside_subscribe = true);
    start_manager();
    assert_global_filters();
    let snapshot = unsafe { actual_test_state() };
    assert_eq!(
        (
            snapshot.notifications_ready,
            snapshot.dirty,
            snapshot.work_queued
        ),
        (1, 1, 1)
    );
    assert_eq!(state(|s| s.queue.len()), 1);
    drain_work();
    let old = state(|s| s.active[0].0);
    set_bfe(FWPM_SERVICE_STOPPED);
    set_bfe(FWPM_SERVICE_START_PENDING);
    set_bfe(FWPM_SERVICE_RUNNING);
    assert_eq!(state(|s| s.queue.len()), 1);
    drain_work();
    assert_global_filters();
    assert_ne!(state(|s| s.active[0].0), old);
    set_bfe(FWPM_SERVICE_STOPPED);
    drain_work();
    assert!(state(|s| s.active.is_empty()));
    assert!(!state(|s| s.timer_armed));
    assert_eq!(unsafe { actual_test_state() }.healthy, 0);
    set_bfe(FWPM_SERVICE_RUNNING);
    drain_work();
    assert_global_filters();
    stop_and_check();
}

#[test]
fn manager_paused_start_private_failures_and_partial_initialization_unwind() {
    let _guard = integration_begin();
    for failure in ["create_device", "allocate_work", "subscribe"] {
        state(|s| s.failure = Some((failure, 0)));
        assert!(unsafe { actual_initialize(ptr::null_mut()) } < 0);
        stop_and_check();
    }
    state(|s| s.bfe_state = FWPM_SERVICE_STOPPED);
    start_manager();
    assert!(state(|s| s.active.is_empty()));
    assert!(state(|s| s.callout_ids.is_empty()));
    set_bfe(FWPM_SERVICE_RUNNING);
    drain_work();
    assert_global_filters();
    stop_and_check();
}

#[test]
fn manager_failure_retry_and_partial_family_transactions_do_not_publish() {
    let _guard = integration_begin();
    for failure in [
        "register_callout",
        "create_injection",
        "open_engine",
        "begin_transaction",
        "add_provider",
        "add_sublayer",
        "add_callout",
        "uuid",
        "add_filter",
        "commit_transaction",
    ] {
        state(|s| s.failure = Some((failure, 0)));
        start_manager();
        assert!(state(|s| s.active.is_empty()));
        assert_eq!(unsafe { actual_test_state() }.healthy, 0);
        fire_retry();
        assert_global_filters();
        assert!(!state(|s| s.timer_armed));
        stop_and_check();
    }
    for before_failure in 0..2 {
        state(|s| s.failure = Some(("add_filter", before_failure)));
        start_manager();
        assert!(state(|s| s.active.is_empty()));
        assert!(state(|s| s.staged.is_empty()));
        fire_retry();
        assert_global_filters();
        stop_and_check();
    }
    for before_failure in 0..4 {
        state(|s| s.failure = Some(("create_injection", before_failure)));
        start_manager();
        assert!(state(|s| s.active.is_empty()));
        assert_eq!(state(|s| s.injection_handles.len()), before_failure);
        fire_retry();
        assert_global_filters();
        stop_and_check();
    }
}

#[test]
fn manager_close_failure_preserves_session_then_rebuilds_and_unload_retries() {
    let _guard = integration_begin();
    start_manager();
    assert_global_filters();
    let old = state(|s| s.active[0].0);
    state(|s| s.failure = Some(("close_engine", 0)));
    set_bfe(FWPM_SERVICE_STOPPED);
    set_bfe(FWPM_SERVICE_RUNNING);
    drain_work();
    assert_eq!(state(|s| s.active[0].0), old);
    assert_eq!(unsafe { actual_test_state() }.reset_engine, 1);
    assert_eq!(unsafe { actual_test_state() }.healthy, 0);
    fire_retry();
    assert_global_filters();
    assert_ne!(state(|s| s.active[0].0), old);
    state(|s| s.failure = Some(("close_engine", 0)));
    stop_and_check();
    assert!(state(|s| s.calls.contains(&"delay")));
}

#[test]
fn manager_work_handoff_and_stop_drain_before_native_destruction() {
    let _guard = integration_begin();
    start_manager();
    state(|s| s.handoff_request = true);
    unsafe { actual_request_reconcile() };
    drain_work();
    assert_eq!(state(|s| s.workers), 2);
    let snapshot = unsafe { actual_test_state() };
    assert_eq!((snapshot.dirty, snapshot.work_queued), (0, 0));
    unsafe { actual_request_reconcile() };
    assert_eq!(state(|s| s.queue.len()), 1);
    stop_and_check();
    let calls = state(|s| s.calls.clone());
    let unsubscribe = calls.iter().rposition(|&c| c == "unsubscribe").unwrap();
    let work_free = calls.iter().rposition(|&c| c == "free_work").unwrap();
    let forward_stop = calls.iter().rposition(|&c| c == "forward_stop").unwrap();
    let device_free = calls.iter().rposition(|&c| c == "delete_device").unwrap();
    assert!(unsubscribe < work_free && work_free < forward_stop && forward_stop < device_free);
}

struct PacketFixture {
    bytes: Vec<u8>,
    mdls: Vec<MDL>,
    nb: Box<NET_BUFFER>,
    nbl: Box<NET_BUFFER_LIST>,
}
impl PacketFixture {
    fn new(bytes: Vec<u8>, chunks: &[usize]) -> Self {
        assert!(!bytes.is_empty());
        let mut fixture = Self {
            bytes,
            mdls: Vec::new(),
            nb: Box::default(),
            nbl: Box::default(),
        };
        let mut offset = 0;
        for chunk in chunks.iter().copied().chain(core::iter::repeat(usize::MAX)) {
            if offset == fixture.bytes.len() {
                break;
            }
            let take = chunk.min(fixture.bytes.len() - offset);
            fixture.mdls.push(MDL {
                ByteCount: take as u32,
                MappedSystemVa: unsafe { fixture.bytes.as_mut_ptr().add(offset) }.cast(),
                MdlFlags: MDL_MAPPED_TO_SYSTEM_VA as CSHORT,
                ..Default::default()
            });
            offset += take;
        }
        for index in 0..fixture.mdls.len() - 1 {
            fixture.mdls[index].Next = &mut fixture.mdls[index + 1];
        }
        unsafe {
            fixture.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdl = fixture.mdls.as_mut_ptr();
            fixture.nb.__bindgen_anon_1.__bindgen_anon_1.MdlChain = fixture.mdls.as_mut_ptr();
            fixture
                .nb
                .__bindgen_anon_1
                .__bindgen_anon_1
                .__bindgen_anon_1
                .DataLength = fixture.bytes.len() as u32;
            crate::native_packet::set_first_nb(fixture.nbl.as_mut(), fixture.nb.as_mut());
        }
        fixture
    }
    fn classify(&mut self, ipv6: bool, flags: u32) -> FWPS_CLASSIFY_OUT0 {
        let mut fields = fixed_values(ipv6, flags);
        let values = FWPS_INCOMING_VALUES0 {
            layerId: if ipv6 {
                FWPS_LAYER_IPFORWARD_V6
            } else {
                FWPS_LAYER_IPFORWARD_V4
            } as u16,
            valueCount: fields.len() as u32,
            incomingValue: fields.as_mut_ptr(),
        };
        let metadata = FWPS_INCOMING_METADATA_VALUES0 {
            currentMetadataValues: FWPS_METADATA_FIELD_COMPARTMENT_ID,
            compartmentId: 31,
            ..Default::default()
        };
        let mut out = FWPS_CLASSIFY_OUT0 {
            rights: FWPS_RIGHT_ACTION_WRITE,
            ..Default::default()
        };
        unsafe {
            classify(
                &values,
                &metadata,
                self.nbl.as_mut() as *mut _ as Handle,
                ptr::null(),
                0,
                &mut out,
            )
        };
        out
    }
}
fn udp_packet(ipv6: bool, payload: usize) -> Vec<u8> {
    let transport = if ipv6 { 40 } else { 20 };
    let mut bytes = self::std::vec![0u8; transport + 8 + payload];
    if ipv6 {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
        bytes[6] = 17;
        bytes[7] = 64;
        bytes[8] = 0x20;
        bytes[9] = 1;
        bytes[23] = 1;
        bytes[24] = 0x20;
        bytes[25] = 1;
        bytes[39] = 2;
    } else {
        bytes[0] = 0x45;
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..20].copy_from_slice(&[10, 0, 0, 1, 8, 8, 8, 8]);
    }
    bytes[transport..transport + 2].copy_from_slice(&1234u16.to_be_bytes());
    bytes[transport + 2..transport + 4].copy_from_slice(&443u16.to_be_bytes());
    bytes[transport + 4..transport + 6].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    bytes[transport + 6..transport + 8].copy_from_slice(&0x1234u16.to_be_bytes());
    for (index, byte) in bytes[transport + 8..].iter_mut().enumerate() {
        *byte = index.wrapping_mul(73).wrapping_add(19) as u8;
    }
    bytes
}
fn blocked(out: &FWPS_CLASSIFY_OUT0) -> bool {
    out.actionType == FWP_ACTION_BLOCK
        && out.flags & FWPS_CLASSIFY_OUT_FLAG_ABSORB != 0
        && out.rights & FWPS_RIGHT_ACTION_WRITE == 0
}

#[test]
fn manager_classification_synchronous_fragment_pending_and_early_inline_verdicts() {
    let _guard = integration_begin();
    start_manager();
    for ipv6 in [false, true] {
        for policy in [0, 1] {
            state(|s| s.policy_result = policy);
            let mut packet = PacketFixture::new(udp_packet(ipv6, 3), &[1, 2, 4]);
            let out = packet.classify(ipv6, 0);
            assert!(if policy == 0 {
                out.actionType == FWP_ACTION_PERMIT
            } else {
                blocked(&out)
            });
            assert_eq!(
                state(|s| s.policy_observation),
                Some((19, 0, if ipv6 { 6 } else { 4 }, 1, 1))
            );
            assert!(state(|s| s.live.is_empty()));
        }
    }
    for flags in [
        0,
        FWP_CONDITION_FLAG_IS_FRAGMENT,
        FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP,
        FWP_CONDITION_FLAG_IS_REASSEMBLED,
    ] {
        state(|s| {
            s.policy_result = -1;
            s.session_available = false;
        });
        let mut packet = PacketFixture::new(udp_packet(false, 3), &[3, 5]);
        packet.nbl.NetBufferListInfo[TcpRecvSegCoalesceInfo as usize] = 1usize as PVOID;
        assert!(blocked(&packet.classify(false, flags)));
        let nbl = state(|s| s.pending) as *mut NET_BUFFER_LIST;
        assert!(!nbl.is_null());
        assert_eq!(
            state(|s| s.policy_observation),
            Some((19, 0, 4, u32::from(flags == 0), 0))
        );
        unsafe {
            assert_eq!((*packet_context(nbl)).segmented, 1);
            actual_finish(nbl.cast(), 1);
        }
        state(|s| s.pending = 0);
    }
    state(|s| {
        s.session_available = true;
        s.policy_early_allow = true;
        s.inline = true;
    });
    let mut packet = PacketFixture::new(udp_packet(false, 3), &[3, 4, 9]);
    assert!(blocked(
        &packet.classify(false, FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU)
    ));
    assert_eq!(state(|s| s.injection), Some((1, 0, 31, 23, 29)));
    assert!(state(|s| s.live.is_empty()));
    assert_eq!(state(|s| s.session_references), 0);
    stop_and_check();
}

#[test]
fn accepted_ipv6_with_nine_extensions_reaches_forward_injection() {
    let _guard = integration_begin();
    start_manager();
    state(|s| {
        s.policy_result = -1;
        s.inline = true;
    });
    let base = udp_packet(true, 3);
    let extensions = 9usize;
    let mut bytes = self::std::vec![0u8; base.len() + extensions * 8];
    bytes[..40].copy_from_slice(&base[..40]);
    let payload = (bytes.len() - 40) as u16;
    bytes[4..6].copy_from_slice(&payload.to_be_bytes());
    bytes[6] = 60;
    for index in 0..extensions {
        bytes[40 + index * 8] = if index + 1 == extensions { 17 } else { 60 };
    }
    bytes[40 + extensions * 8..].copy_from_slice(&base[40..]);
    let mut packet = PacketFixture::new(bytes, &[1, 2, 4, 8, 16]);
    assert!(blocked(&packet.classify(true, 0)));
    let nbl = state(|s| {
        let nbl = s.pending;
        s.pending = 0;
        nbl as *mut NET_BUFFER_LIST
    });
    assert!(!nbl.is_null());
    unsafe { actual_finish(nbl.cast(), 0) };
    assert_eq!(state(|s| s.injection), Some((0, 23, 31, 23, 0)));
    assert!(state(|s| s.live.is_empty()));
    stop_and_check();
}

#[test]
fn manager_pending_submit_completion_failures_and_stop_drain_are_accounted_once() {
    let _guard = integration_begin();
    start_manager();
    state(|s| s.policy_result = -1);
    for submit_failure in [true, false] {
        let mut packet = PacketFixture::new(udp_packet(false, 3), &[1, 3]);
        assert!(blocked(&packet.classify(false, 0)));
        let nbl = state(|s| s.pending) as *mut NET_BUFFER_LIST;
        state(|s| {
            s.injection_status = if submit_failure { failed_status() } else { 0 };
            s.pending = 0;
        });
        unsafe { actual_finish(nbl.cast(), 0) };
        if !submit_failure {
            let (nbl, completion, context) = state(|s| s.last_injection.unwrap());
            unsafe {
                (*(nbl as *mut NET_BUFFER_LIST)).__bindgen_anon_2.Status = failed_status();
                completion.unwrap()(context as Handle, nbl as *mut NET_BUFFER_LIST, 0);
            }
        }
        assert!(state(|s| s.live.is_empty()));
    }
    assert_eq!(state(|s| s.injection_errors.len()), 2);
    assert_eq!(state(|s| s.injection_errors[0].3), 0);
    assert_eq!(state(|s| s.injection_errors[1].3), 1);
    let mut packet = PacketFixture::new(udp_packet(false, 3), &[1, 2]);
    assert!(blocked(&packet.classify(false, 0)));
    assert!(!state(|s| s.live.is_empty()));
    stop_and_check();
    assert!(state(|s| s.calls.contains(&"forward_stop")));
}

#[test]
fn manager_injection_failure_log_is_bounded_and_controller_session_resettable() {
    let _guard = integration_begin();
    start_manager();
    for _ in 1..=17 {
        unsafe {
            actual_report_failure(
                failed_status(),
                1,
                FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU,
                23,
                1,
            )
        };
    }
    assert_eq!(
        state(|s| s
            .injection_errors
            .iter()
            .map(|entry| entry.5)
            .collect::<Vec<_>>()),
        [1, 2, 4, 8, 16]
    );
    unsafe {
        actual_report_status();
        actual_report_failure(
            failed_status(),
            0,
            FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
            7,
            0,
        );
    }
    assert_eq!(
        state(|s| s.injection_errors.last().copied()),
        Some((failed_status() as u32, 0, 2, 0, 7, 1))
    );
    stop_and_check();
}
