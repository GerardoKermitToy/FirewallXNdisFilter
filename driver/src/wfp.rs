use core::{
    ffi::{CStr, c_void},
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering::SeqCst},
};

#[path = "wfp_checksum.rs"]
mod checksum;

type Handle = *mut c_void;
type Completion = Option<unsafe extern "system" fn(Handle, Handle, u8)>;
mod constants {
    include!(concat!(env!("OUT_DIR"), "/wfp_constants.rs"));
}
use constants::{
    FWP_CONDITION_FLAG_IS_FRAGMENT, FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP,
    FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU, FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
    FWP_CONDITION_FLAG_IS_REASSEMBLED, STATUS_DATA_ERROR, STATUS_DELETE_PENDING, STATUS_SUCCESS,
};

const WORK: u32 = 0;
const CLASSIFY: u32 = 1;
const PACKET: u32 = 2;
const UNCACHEABLE: u32 = FWP_CONDITION_FLAG_IS_FRAGMENT
    | FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP
    | FWP_CONDITION_FLAG_IS_REASSEMBLED;
const IPV4_VERSION: u32 = 4;
const IPV6_VERSION: u32 = 6;
const HV_FORWARD_SOURCE_DIRECTION: u32 = 0;
const HV_FINISH_ALLOW: u32 = 0;
#[repr(u32)]
#[derive(Clone, Copy)]
enum InjectionRoute {
    Forward,
    NetworkReceive,
    NetworkSend,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ForwardValues {
    source: u32,
    destination: u32,
    sub_interface: u32,
    flags: u32,
    compartment: u32,
}
#[repr(C)]
#[derive(Default)]
struct PacketInfo {
    route: ForwardValues,
    ipv6: u8,
    segmented: u8,
    reserved: [u8; 2],
}
const _: () = {
    assert!(size_of::<ForwardValues>() == 20);
    assert!(align_of::<ForwardValues>() == 4);
    assert!(core::mem::offset_of!(ForwardValues, compartment) == 16);
    assert!(size_of::<PacketInfo>() == 24);
    assert!(core::mem::offset_of!(PacketInfo, ipv6) == 20);
};

unsafe extern "C" {
    fn hv_wfp_native_initialize(driver: Handle) -> i32;
    fn hv_wfp_delete_device();
    fn hv_wfp_lock();
    fn hv_wfp_unlock();
    fn hv_wfp_acquire(kind: u32) -> u8;
    fn hv_wfp_release(kind: u32);
    fn hv_wfp_wait(kind: u32);
    fn hv_wfp_queue_work();
    fn hv_wfp_free_work();
    fn hv_wfp_timer(arm: u8);
    fn hv_wfp_flush_dpcs();
    fn hv_wfp_delay();
    fn hv_wfp_subscribe(subscription: *mut Handle) -> i32;
    fn hv_wfp_unsubscribe(subscription: Handle) -> i32;
    fn hv_wfp_bfe_running() -> u8;
    fn hv_wfp_callout_register(family: u32, id: *mut u32) -> i32;
    fn hv_wfp_callout_unregister(id: u32) -> i32;
    fn hv_wfp_injection_create(family: u32, network: u8, handle: *mut Handle) -> i32;
    fn hv_wfp_injection_destroy(handle: Handle) -> i32;
    fn hv_wfp_engine_open(engine: *mut Handle) -> i32;
    fn hv_wfp_engine_close(engine: Handle) -> i32;
    fn hv_wfp_transaction_begin(engine: Handle) -> i32;
    fn hv_wfp_transaction_commit(engine: Handle) -> i32;
    fn hv_wfp_transaction_abort(engine: Handle);
    fn hv_wfp_provider_add(engine: Handle) -> i32;
    fn hv_wfp_sublayer_add(engine: Handle, weight: u16) -> i32;
    fn hv_wfp_callout_add(engine: Handle, family: u32) -> i32;
    fn hv_wfp_filter_add(engine: Handle, family: u32) -> i32;
    fn hv_wfp_report(operation: *const core::ffi::c_char, status: i32);
    fn hv_wfp_is_self(handle: Handle, nbl: Handle) -> u8;
    fn hv_wfp_inject(
        handle: Handle,
        route: InjectionRoute,
        ipv6: u8,
        compartment: u32,
        destination: u32,
        sub_interface: u32,
        nbl: Handle,
        completion: Completion,
        context: Handle,
    ) -> i32;
    fn hv_wfp_driver_stopping() -> u8;
    fn hv_wfp_session_acquire() -> u8;
    fn hv_wfp_session_release();
    fn hv_wfp_clone(original: Handle, route: *const ForwardValues, ipv6: u8) -> Handle;
    fn hv_wfp_packet_info(nbl: Handle, info: *mut PacketInfo);
    fn hv_wfp_free_packet(nbl: Handle);
    fn hv_wfp_diagnostic_permit(nbl: Handle, route: *const ForwardValues, ipv6: u8) -> u8;
    fn hv_wfp_reset_diagnostics();
    fn HvClassifyIp(
        packet: usize,
        interface: u32,
        direction: u32,
        family: u32,
        cacheable: u32,
        session: u32,
    ) -> i32;
    fn HvResourceDrop();
    fn HvForwardStop();
    fn HvWfpStatus(healthy: u32);
    fn HvWfpInjectionError(
        status: u32,
        ipv6: u32,
        route: u32,
        completion: u32,
        destination: u32,
        failures: u32,
    );
    fn hv_bugcheck() -> !;
}

unsafe extern "system" {
    fn hv_wfp_complete(context: Handle, nbl: Handle, dispatch: u8);
}

// Native management operations are serialized by a PASSIVE-level KMUTEX. Handles
// read by classifiers/completions are atomic; no mutable borrow crosses a callback.
static ENGINE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static SUBSCRIPTION: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static INJECTION: [AtomicPtr<c_void>; 2] = [const { AtomicPtr::new(ptr::null_mut()) }; 2];
static NETWORK: [AtomicPtr<c_void>; 2] = [const { AtomicPtr::new(ptr::null_mut()) }; 2];
static CALLOUTS: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
static STOPPING: AtomicBool = AtomicBool::new(false);
static WORK_QUEUED: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicBool = AtomicBool::new(false);
static RESET_ENGINE: AtomicBool = AtomicBool::new(false);
static HEALTHY: AtomicBool = AtomicBool::new(false);
static NOTIFICATIONS_READY: AtomicBool = AtomicBool::new(false);
static FAILURES: AtomicU32 = AtomicU32::new(0);

struct Management;
impl Management {
    fn lock() -> Self {
        unsafe { hv_wfp_lock() };
        Self
    }
}
impl Drop for Management {
    fn drop(&mut self) {
        unsafe { hv_wfp_unlock() };
    }
}
fn report(operation: &CStr, status: i32) {
    unsafe { hv_wfp_report(operation.as_ptr(), status) };
}
fn health(healthy: bool) {
    if HEALTHY.swap(healthy, SeqCst) != healthy {
        unsafe { HvWfpStatus(u32::from(healthy)) };
    }
}
fn close_engine() -> i32 {
    let engine = ENGINE.load(SeqCst);
    if !engine.is_null() {
        let status = unsafe { hv_wfp_engine_close(engine) };
        if status < 0 {
            report(c"close engine", status);
            RESET_ENGINE.store(true, SeqCst);
            return status;
        }
        ENGINE.store(ptr::null_mut(), SeqCst);
    }
    STATUS_SUCCESS
}
fn populate_engine(engine: Handle) -> i32 {
    let mut status = unsafe { hv_wfp_provider_add(engine) };
    if status >= 0 {
        status = unsafe { hv_wfp_sublayer_add(engine, 0x7fff) };
    }
    for family in 0..2 {
        if status < 0 {
            return status;
        }
        status = unsafe { hv_wfp_callout_add(engine, family) };
    }
    for family in 0..2 {
        if status < 0 {
            return status;
        }
        status = unsafe { hv_wfp_filter_add(engine, family) };
    }
    if status >= 0 {
        status = unsafe { hv_wfp_transaction_commit(engine) };
    }
    status
}
fn open_engine() -> i32 {
    let mut engine = ptr::null_mut();
    let status = unsafe { hv_wfp_engine_open(&mut engine) };
    if status < 0 {
        return status;
    }
    ENGINE.store(engine, SeqCst);
    let status = unsafe { hv_wfp_transaction_begin(engine) };
    if status < 0 {
        close_engine();
        return status;
    }
    let status = populate_engine(engine);
    if status < 0 {
        unsafe { hv_wfp_transaction_abort(engine) };
        close_engine();
    }
    status
}
fn reconcile() -> i32 {
    let running = unsafe { hv_wfp_bfe_running() } != 0;
    if RESET_ENGINE.swap(false, SeqCst) || !running {
        let status = close_engine();
        if status < 0 {
            health(false);
            return status;
        }
    }
    if !running {
        health(false);
        unsafe { hv_wfp_timer(0) };
        return STATUS_SUCCESS;
    }
    for family in 0..2 {
        if CALLOUTS[family].load(SeqCst) == 0 {
            let mut id = 0;
            let status = unsafe { hv_wfp_callout_register(family as u32, &mut id) };
            if status < 0 {
                health(false);
                return status;
            }
            CALLOUTS[family].store(id, SeqCst);
        }
        for (handles, network) in [(&INJECTION, 0), (&NETWORK, 1)] {
            if handles[family].load(SeqCst).is_null() {
                let mut handle = ptr::null_mut();
                let status =
                    unsafe { hv_wfp_injection_create(family as u32, network, &mut handle) };
                if status < 0 {
                    health(false);
                    return status;
                }
                handles[family].store(handle, SeqCst);
            }
        }
    }
    let status = if ENGINE.load(SeqCst).is_null() {
        open_engine()
    } else {
        STATUS_SUCCESS
    };
    health(status >= 0);
    if status >= 0 {
        unsafe { hv_wfp_timer(0) };
    }
    status
}
fn queue_reconcile() {
    if STOPPING.load(SeqCst) || !NOTIFICATIONS_READY.load(SeqCst) || !DIRTY.load(SeqCst) {
        return;
    }
    if unsafe { hv_wfp_acquire(WORK) } == 0 {
        return;
    }
    if !WORK_QUEUED.swap(true, SeqCst) {
        unsafe { hv_wfp_queue_work() };
    } else {
        unsafe { hv_wfp_release(WORK) };
    }
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpRequestReconcile() {
    DIRTY.store(true, SeqCst);
    queue_reconcile();
}
fn retry_after_failure() {
    let _lock = Management::lock();
    if !STOPPING.load(SeqCst) && !HEALTHY.load(SeqCst) {
        unsafe { hv_wfp_timer(1) };
    }
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpReconcileWorker() {
    while !STOPPING.load(SeqCst) && DIRTY.swap(false, SeqCst) {
        let status = {
            let _lock = Management::lock();
            if STOPPING.load(SeqCst) {
                STATUS_SUCCESS
            } else {
                reconcile()
            }
        };
        if status < 0 {
            report(c"reconcile filters", status);
            retry_after_failure();
        }
    }
    WORK_QUEUED.store(false, SeqCst);
    #[cfg(feature = "wfp-test")]
    unsafe {
        hv_wfp_test_handoff()
    };
    queue_reconcile();
    unsafe { hv_wfp_release(WORK) };
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpBfeChanged(reset: u8) {
    if reset != 0 {
        RESET_ENGINE.store(true, SeqCst);
    }
    HvWfpRequestReconcile();
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpInitialize(driver: Handle) -> i32 {
    for flag in [
        &STOPPING,
        &WORK_QUEUED,
        &DIRTY,
        &RESET_ENGINE,
        &HEALTHY,
        &NOTIFICATIONS_READY,
    ] {
        flag.store(false, SeqCst);
    }
    FAILURES.store(0, SeqCst);
    let status = unsafe { hv_wfp_native_initialize(driver) };
    if status < 0 {
        HvWfpUninitialize();
        return status;
    }
    let mut subscription = ptr::null_mut();
    let status = unsafe { hv_wfp_subscribe(&mut subscription) };
    if status < 0 {
        HvWfpUninitialize();
        return status;
    }
    SUBSCRIPTION.store(subscription, SeqCst);
    NOTIFICATIONS_READY.store(true, SeqCst);
    let status = {
        let _lock = Management::lock();
        reconcile()
    };
    if status < 0 {
        report(c"initial registration", status);
        retry_after_failure();
    }
    queue_reconcile();
    STATUS_SUCCESS
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpStop() {
    if STOPPING.swap(true, SeqCst) {
        return;
    }
    let subscription = SUBSCRIPTION.swap(ptr::null_mut(), SeqCst);
    if !subscription.is_null() && unsafe { hv_wfp_unsubscribe(subscription) } < 0 {
        unsafe { hv_bugcheck() };
    }
    {
        let _lock = Management::lock();
        unsafe { hv_wfp_timer(0) };
    }
    unsafe {
        hv_wfp_flush_dpcs();
        hv_wfp_wait(WORK);
        hv_wfp_free_work();
        hv_wfp_wait(CLASSIFY);
        HvForwardStop();
        hv_wfp_wait(PACKET);
    }
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpUninitialize() {
    HvWfpStop();
    loop {
        let _lock = Management::lock();
        if close_engine() >= 0 {
            health(false);
            break;
        }
        drop(_lock);
        unsafe { hv_wfp_delay() };
    }
    for id in &CALLOUTS {
        let value = id.swap(0, SeqCst);
        if value != 0 && unsafe { hv_wfp_callout_unregister(value) } < 0 {
            unsafe { hv_bugcheck() };
        }
    }
    unsafe { hv_wfp_wait(CLASSIFY) };
    for handles in [&INJECTION, &NETWORK] {
        for handle in handles {
            let value = handle.swap(ptr::null_mut(), SeqCst);
            if !value.is_null() && unsafe { hv_wfp_injection_destroy(value) } < 0 {
                unsafe { hv_bugcheck() };
            }
        }
    }
    unsafe { hv_wfp_delete_device() };
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpEnterClassify() -> u8 {
    u8::from(!STOPPING.load(SeqCst) && unsafe { hv_wfp_acquire(CLASSIFY) } != 0)
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpRetainPacket() -> u8 {
    u8::from(!STOPPING.load(SeqCst) && unsafe { hv_wfp_acquire(PACKET) } != 0)
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpReleasePacket() {
    unsafe { hv_wfp_release(PACKET) };
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpReportStatus() {
    FAILURES.store(0, SeqCst);
    unsafe {
        hv_wfp_reset_diagnostics();
        HvWfpStatus(u32::from(HEALTHY.load(SeqCst)))
    };
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpIsSelfInjected(nbl: Handle, ipv6: u8) -> u8 {
    let family = usize::from(ipv6 != 0);
    for handle in [&INJECTION[family], &NETWORK[family]] {
        let value = handle.load(SeqCst);
        if !value.is_null() && unsafe { hv_wfp_is_self(value, nbl) } != 0 {
            return 1;
        }
    }
    0
}
fn injection_route(flags: u32) -> InjectionRoute {
    if flags & FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU != 0 {
        InjectionRoute::NetworkReceive
    } else if flags & FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU != 0 {
        InjectionRoute::NetworkSend
    } else {
        InjectionRoute::Forward
    }
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpInject(
    nbl: Handle,
    ipv6: u8,
    compartment: u32,
    destination: u32,
    sub_interface: u32,
    flags: u32,
    segmented: u8,
    completion: Completion,
    context: Handle,
) -> i32 {
    let route = injection_route(flags);
    let family = usize::from(ipv6 != 0);
    let handle = if matches!(route, InjectionRoute::Forward) {
        &INJECTION[family]
    } else {
        &NETWORK[family]
    }
    .load(SeqCst);
    if STOPPING.load(SeqCst) || handle.is_null() {
        return STATUS_DELETE_PENDING;
    }
    if !checksum::restore_nbl(nbl, ipv6 != 0, segmented != 0) {
        return STATUS_DATA_ERROR;
    }
    unsafe {
        hv_wfp_inject(
            handle,
            route,
            ipv6,
            compartment,
            destination,
            sub_interface,
            nbl,
            completion,
            context,
        )
    }
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpReportInjectionFailure(
    status: i32,
    ipv6: u8,
    flags: u32,
    destination: u32,
    completion: u8,
) {
    report(
        if completion != 0 {
            c"injection completion"
        } else {
            c"inject packet"
        },
        status,
    );
    let count = FAILURES.fetch_add(1, SeqCst).wrapping_add(1);
    if count.is_power_of_two() {
        unsafe {
            HvWfpInjectionError(
                status as u32,
                u32::from(ipv6 != 0),
                injection_route(flags) as u32,
                u32::from(completion != 0),
                destination,
                count,
            )
        };
    }
}
fn free_packet(nbl: Handle) {
    unsafe { hv_wfp_free_packet(nbl) };
    HvWfpReleasePacket();
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpClassify(
    original: Handle,
    route: *const ForwardValues,
    ipv6: u8,
    valid: u8,
) -> u8 {
    if original.is_null() {
        unsafe { HvResourceDrop() };
        return 0;
    }
    if HvWfpIsSelfInjected(original, ipv6) != 0 {
        return 1;
    }
    if valid == 0 || unsafe { hv_wfp_driver_stopping() } != 0 {
        unsafe { HvResourceDrop() };
        return 0;
    }
    let route = unsafe { *route };
    if unsafe { hv_wfp_diagnostic_permit(original, &route, ipv6) } != 0 {
        return 1;
    }
    let session = unsafe { hv_wfp_session_acquire() };
    let nbl = if HvWfpRetainPacket() != 0 {
        let nbl = unsafe { hv_wfp_clone(original, &route, ipv6) };
        if nbl.is_null() {
            HvWfpReleasePacket();
        }
        nbl
    } else {
        ptr::null_mut()
    };
    let mut permit = false;
    if nbl.is_null() {
        unsafe { HvResourceDrop() };
    } else {
        let result = unsafe {
            HvClassifyIp(
                nbl as usize,
                route.source,
                HV_FORWARD_SOURCE_DIRECTION,
                if ipv6 != 0 {
                    IPV6_VERSION
                } else {
                    IPV4_VERSION
                },
                u32::from(route.flags & UNCACHEABLE == 0),
                u32::from(session != 0),
            )
        };
        // A negative result publishes ownership. An early verdict can already
        // have injected/freed the NBL; never inspect it after that handoff.
        if result >= 0 {
            permit = result == 0 && unsafe { hv_wfp_driver_stopping() } == 0;
            free_packet(nbl);
        }
    }
    if session != 0 {
        unsafe { hv_wfp_session_release() };
    }
    u8::from(permit)
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpFinish(nbl: Handle, finish: u32) {
    let mut info = PacketInfo::default();
    unsafe { hv_wfp_packet_info(nbl, &mut info) };
    if finish == HV_FINISH_ALLOW && unsafe { hv_wfp_driver_stopping() } == 0 {
        let status = HvWfpInject(
            nbl,
            info.ipv6,
            info.route.compartment,
            info.route.destination,
            info.route.sub_interface,
            info.route.flags,
            info.segmented,
            Some(hv_wfp_complete),
            nbl,
        );
        if status >= 0 {
            return;
        } // Completion can run inline and free nbl.
        HvWfpReportInjectionFailure(
            status,
            info.ipv6,
            info.route.flags,
            info.route.destination,
            0,
        );
    }
    free_packet(nbl);
}
#[unsafe(no_mangle)]
extern "C" fn HvWfpInjectionComplete(nbl: Handle, status: i32) {
    if status < 0 {
        let mut info = PacketInfo::default();
        unsafe { hv_wfp_packet_info(nbl, &mut info) };
        HvWfpReportInjectionFailure(
            status,
            info.ipv6,
            info.route.flags,
            info.route.destination,
            1,
        );
    }
    free_packet(nbl);
}

#[cfg(feature = "wfp-test")]
unsafe extern "C" {
    fn hv_wfp_test_handoff();
}
#[cfg(feature = "wfp-test")]
#[repr(C)]
struct TestState {
    healthy: u32,
    dirty: u32,
    work_queued: u32,
    reset_engine: u32,
    notifications_ready: u32,
}
#[cfg(feature = "wfp-test")]
#[unsafe(no_mangle)]
extern "C" fn HvWfpTestState() -> TestState {
    TestState {
        healthy: u32::from(HEALTHY.load(SeqCst)),
        dirty: u32::from(DIRTY.load(SeqCst)),
        work_queued: u32::from(WORK_QUEUED.load(SeqCst)),
        reset_engine: u32::from(RESET_ENGINE.load(SeqCst)),
        notifications_ready: u32::from(NOTIFICATIONS_READY.load(SeqCst)),
    }
}
