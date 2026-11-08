//! Offline execution of the production NDIS callbacks with generated WDK types.
//! Only OS/policy imports are fake; no packet/adapter ownership code is duplicated.

extern crate std;

use self::std::{
    alloc::{Layout, alloc, alloc_zeroed, dealloc},
    boxed::Box,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, MutexGuard},
    vec,
    vec::Vec,
};
use super::*;

static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Send(usize, u32),
    Indicate(usize, u32),
    Complete(usize, NDIS_STATUS, u32),
    Return(usize, u32),
    PauseComplete,
    Classify(u32, u32, usize, u32),
    Cancel(u32, usize),
    LowerCancel(usize),
    Invalidate(u32),
    Drain,
    Attach(u32),
    RollbackAttach(u32),
    Detach(u32),
    OidComplete(usize, NDIS_STATUS),
    OidCancel(usize),
    Status,
    Pnp,
}

struct State {
    events: Vec<Event>,
    allocations: BTreeMap<usize, (Layout, u32)>,
    allocation_attempts: usize,
    fail_at: Option<usize>,
    rw_depth: usize,
    irql: u8,
    inline: bool,
    send_complete_extra_flags: u32,
    receive_return_extra_flags: u32,
    free_original: bool,
    adapter: usize,
    classify_result: i32,
    split_results: Vec<i32>,
    split_seen: Vec<usize>,
    split_early_finish: Option<u32>,
    early_finish: Option<u32>,
    cancel_during_classify: Option<usize>,
    cancel_after_publish: Option<usize>,
    publishing: bool,
    pending: Vec<usize>,
    invalidated: BTreeSet<u32>,
    session_open: bool,
    oid_open: bool,
    rundown_count: BTreeMap<usize, usize>,
    oid_status: NDIS_STATUS,
    clones: BTreeSet<usize>,
    last_clone: usize,
    attach_ok: bool,
    restart_ok: bool,
    attributes_status: NDIS_STATUS,
    next_index: u32,
    detach_on_pause: bool,
    pause_after_forward: bool,
    cancel_after_pause: Option<usize>,
    paused_drops: u32,
    resource_drops: u32,
    invalid_lso_warnings: Vec<u32>,
    send_failure_warnings: Vec<(u32, NDIS_STATUS)>,
    snapshot_growth: usize,
    nbl_pools: usize,
    nb_pools: usize,
    rw_locks: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            allocations: BTreeMap::new(),
            allocation_attempts: 0,
            fail_at: None,
            rw_depth: 0,
            irql: 0,
            inline: true,
            send_complete_extra_flags: 0,
            receive_return_extra_flags: 0,
            free_original: false,
            adapter: 0,
            classify_result: 0,
            split_results: Vec::new(),
            split_seen: Vec::new(),
            split_early_finish: None,
            early_finish: None,
            cancel_during_classify: None,
            cancel_after_publish: None,
            publishing: false,
            pending: Vec::new(),
            invalidated: BTreeSet::new(),
            session_open: true,
            oid_open: true,
            rundown_count: BTreeMap::new(),
            oid_status: FWX_WDK_NDIS_SUCCESS as NDIS_STATUS,
            clones: BTreeSet::new(),
            last_clone: 0,
            attach_ok: true,
            restart_ok: true,
            attributes_status: FWX_WDK_NDIS_SUCCESS as NDIS_STATUS,
            next_index: 100,
            detach_on_pause: false,
            pause_after_forward: false,
            cancel_after_pause: None,
            paused_drops: 0,
            resource_drops: 0,
            invalid_lso_warnings: Vec::new(),
            send_failure_warnings: Vec::new(),
            snapshot_growth: 0,
            nbl_pools: 0,
            nb_pools: 0,
            rw_locks: 0,
        }
    }
}

std::thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

fn assert_unlocked() {
    state(|s| {
        assert!(
            s.rw_depth == 0 || s.publishing,
            "NDIS/retirement under classify lock"
        )
    });
}

fn fail() -> bool {
    state(|s| {
        s.allocation_attempts += 1;
        s.fail_at == Some(s.allocation_attempts)
    })
}

struct Fixture(MutexGuard<'static, ()>);

impl Fixture {
    fn new() -> Self {
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        state(|s| *s = State::default());
        packet::reset_test_allocator(None);
        unsafe {
            list_init(addr_of_mut!(ADAPTERS));
            ADAPTER_COUNT = 0;
            FILTER_NDIS_VERSION = NDIS_RUNTIME_VERSION_689;
            FILTERED_DEVICE_COUNT.store(0, Ordering::SeqCst);
            NEXT_ADAPTER.store(0, Ordering::SeqCst);
        }
        registry::TARGET_ALLOWED.store(true, Ordering::SeqCst);
        Self(guard)
    }

    fn adapter(&self) -> Box<Adapter> {
        let mut a: Box<Adapter> = Box::new(unsafe { zeroed() });
        a.filter = 0x303usize as NDIS_HANDLE;
        a.nbl_pool = 0x101usize as NDIS_HANDLE;
        a.nb_pool = 0x202usize as NDIS_HANDLE;
        a.classification_lock = 0x404usize as PNDIS_RW_LOCK_EX;
        a.interface_index = 77;
        state(|s| s.adapter = (&mut *a as *mut Adapter) as usize);
        a
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = &self.0;
        packet::assert_test_allocator_no_leaks();
        state(|s| {
            assert!(s.allocations.is_empty(), "native pool allocation leak");
            assert!(s.pending.is_empty(), "pending NBL leak");
            assert!(s.clones.is_empty(), "OID clone leak");
            assert!(s.rundown_count.values().all(|&n| n == 0), "rundown leak");
            assert_eq!(
                (s.rw_depth, s.nbl_pools, s.nb_pools, s.rw_locks),
                (0, 0, 0, 0)
            );
        });
        unsafe {
            let count = ADAPTER_COUNT;
            assert_eq!(count, 0);
        }
        assert_eq!(FILTERED_DEVICE_COUNT.load(Ordering::SeqCst), 0);
    }
}

unsafe fn start(a: *mut Adapter) {
    unsafe { set_filter_running(a, true) }
}

unsafe fn stop(a: *mut Adapter) {
    unsafe { set_filter_running(a, false) }
}

unsafe fn attach_one() -> *mut Adapter {
    unsafe {
        let mut p: NDIS_FILTER_ATTACH_PARAMETERS = zeroed();
        p.MiniportMediaType = NdisMedium802_3;
        p.BaseMiniportIfIndex = state(|s| {
            s.next_index += 1;
            s.next_index
        });
        p.BaseMiniportNetLuid.Value = u64::from(p.BaseMiniportIfIndex);
        assert_eq!(
            filter_attach(0x303usize as NDIS_HANDLE, null_mut(), &mut p),
            FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
        );
        state(|s| s.adapter as *mut Adapter)
    }
}

#[allow(clippy::while_immutable_condition)] // filter_detach unlinks the head node.
unsafe fn detach_all() {
    unsafe {
        let head = addr_of_mut!(ADAPTERS);
        while (*head).Flink != head {
            let a = (*head)
                .Flink
                .cast::<u8>()
                .sub(offset_of!(Adapter, adapter_link))
                .cast::<Adapter>();
            filter_detach(a.cast());
        }
    }
}

/// Own a real generated NB/MDL graph without involving the fake copy allocator.
struct Source {
    data: Vec<u8>,
    _mdl: Box<MDL>,
    _nb: Box<NET_BUFFER>,
    nbl: Box<NET_BUFFER_LIST>,
}

impl Source {
    fn new() -> Self {
        let mut data = vec![0x5a; 128];
        let mut mdl = Box::new(MDL {
            MdlFlags: MDL_SOURCE_IS_NONPAGED_POOL as i16,
            MappedSystemVa: data.as_mut_ptr().cast(),
            ByteCount: data.len() as u32,
            ..MDL::default()
        });
        let mut nb = Box::<NET_BUFFER>::default();
        let mut nbl = Box::<NET_BUFFER_LIST>::default();
        unsafe {
            nb.__bindgen_anon_1.__bindgen_anon_1.MdlChain = &mut *mdl;
            nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdl = &mut *mdl;
            nb.__bindgen_anon_1
                .__bindgen_anon_1
                .__bindgen_anon_1
                .DataLength = data.len() as u32;
            packet::set_first_nb(&mut *nbl, &mut *nb);
        }
        nbl.SourceHandle = 0x909usize as NDIS_HANDLE;
        Self {
            data,
            _mdl: mdl,
            _nb: nb,
            nbl,
        }
    }
}

#[allow(non_snake_case)]
pub(super) mod calls {
    use super::*;

    pub(crate) unsafe fn KeGetCurrentIrql() -> KIRQL {
        state(|s| s.irql)
    }
    pub(crate) unsafe fn KeInitializeSpinLock(lock: PKSPIN_LOCK) {
        unsafe {
            *lock = 0;
        }
    }
    pub(crate) unsafe fn ExInitializeRundownProtection(r: PEX_RUNDOWN_REF) {
        state(|s| {
            s.rundown_count.insert(r as usize, 0);
        });
    }
    pub(crate) unsafe fn ExAcquireRundownProtection(r: PEX_RUNDOWN_REF) -> BOOLEAN {
        state(|s| {
            let open = if r == addr_of_mut!(CLASSIFICATION_RUNDOWN) {
                s.session_open
            } else {
                s.oid_open
            };
            if open {
                *s.rundown_count.entry(r as usize).or_default() += 1;
            }
            u8::from(open)
        })
    }
    pub(crate) unsafe fn ExReleaseRundownProtection(r: PEX_RUNDOWN_REF) {
        state(|s| {
            let n = s
                .rundown_count
                .get_mut(&(r as usize))
                .expect("rundown was never acquired");
            assert!(*n > 0);
            *n -= 1;
        });
    }
    pub(crate) unsafe fn ExWaitForRundownProtectionRelease(r: PEX_RUNDOWN_REF) {
        state(|s| assert_eq!(s.rundown_count.get(&(r as usize)).copied().unwrap_or(0), 0));
    }
    pub(crate) unsafe fn NdisAllocateRWLock(_: NDIS_HANDLE) -> PNDIS_RW_LOCK_EX {
        if fail() {
            return null_mut();
        }
        state(|s| s.rw_locks += 1);
        0x404usize as PNDIS_RW_LOCK_EX
    }
    pub(crate) unsafe fn NdisFreeRWLock(_: PNDIS_RW_LOCK_EX) {
        state(|s| {
            assert!(s.rw_locks > 0);
            s.rw_locks -= 1;
        });
    }
    pub(crate) unsafe fn NdisAcquireRWLockRead(_: PNDIS_RW_LOCK_EX, _: PLOCK_STATE_EX, _: UCHAR) {
        let (cancel, a) = state(|s| {
            s.rw_depth += 1;
            let paused = s.cancel_after_pause.is_some()
                && s.adapter != 0
                && unsafe { (*(s.adapter as *mut Adapter)).running == 0 };
            let cancel = if paused {
                s.cancel_after_pause.take()
            } else {
                None
            };
            (cancel, s.adapter)
        });
        if let Some(cancel) = cancel {
            // Model cancellation on another CPU after this NBL became current.
            state(|s| s.publishing = true);
            unsafe { cancel_send(a as NDIS_HANDLE, cancel as PVOID) };
            state(|s| s.publishing = false);
        }
    }
    pub(crate) unsafe fn NdisAcquireRWLockWrite(_: PNDIS_RW_LOCK_EX, _: PLOCK_STATE_EX, _: UCHAR) {
        state(|s| s.rw_depth += 1);
    }
    pub(crate) unsafe fn NdisReleaseRWLock(_: PNDIS_RW_LOCK_EX, _: PLOCK_STATE_EX) {
        state(|s| {
            assert!(s.rw_depth > 0);
            s.rw_depth -= 1;
        });
    }
    pub(crate) unsafe fn ExAllocatePool2(flags: POOL_FLAGS, bytes: SIZE_T, tag: ULONG) -> PVOID {
        assert_unlocked();
        assert!(bytes > 0);
        assert!(tag == TAG || tag == INFO_TAG);
        if fail() {
            return null_mut();
        }
        let layout = Layout::from_size_align(bytes as usize, 16).unwrap();
        let pointer = if flags & FWX_WDK_POOL_FLAG_UNINITIALIZED as u64 == 0 {
            unsafe { alloc_zeroed(layout) }
        } else {
            unsafe { alloc(layout) }
        };
        assert!(!pointer.is_null());
        let grow = state(|s| {
            assert!(
                s.allocations
                    .insert(pointer as usize, (layout, tag))
                    .is_none()
            );
            if tag == INFO_TAG && s.snapshot_growth > 0 {
                s.snapshot_growth -= 1;
                true
            } else {
                false
            }
        });
        if grow {
            unsafe {
                attach_one();
            }
        }
        pointer.cast()
    }
    pub(crate) unsafe fn ExFreePoolWithTag(pointer: PVOID, tag: ULONG) {
        assert_unlocked();
        let (layout, allocated_tag) = state(|s| {
            s.allocations
                .remove(&(pointer as usize))
                .expect("foreign/double native pool free")
        });
        assert_eq!(tag, allocated_tag);
        unsafe {
            dealloc(pointer.cast(), layout);
        }
    }
    pub(crate) unsafe fn NdisAllocateNetBufferListPool(
        _: NDIS_HANDLE,
        p: *const NET_BUFFER_LIST_POOL_PARAMETERS,
    ) -> NDIS_HANDLE {
        unsafe {
            assert_eq!((*p).Header.Size, FWX_WDK_NBL_POOL_SIZE as u16);
            assert_eq!((*p).PoolTag, TAG);
        }
        if fail() {
            return null_mut();
        }
        state(|s| s.nbl_pools += 1);
        0x101usize as NDIS_HANDLE
    }
    pub(crate) unsafe fn NdisFreeNetBufferListPool(_: NDIS_HANDLE) {
        state(|s| {
            assert!(s.nbl_pools > 0);
            s.nbl_pools -= 1;
        });
    }
    pub(crate) unsafe fn NdisAllocateNetBufferPool(
        _: NDIS_HANDLE,
        p: *const NET_BUFFER_POOL_PARAMETERS,
    ) -> NDIS_HANDLE {
        unsafe {
            assert_eq!((*p).Header.Size, FWX_WDK_NB_POOL_SIZE as u16);
            assert_eq!((*p).PoolTag, TAG);
        }
        if fail() {
            return null_mut();
        }
        state(|s| s.nb_pools += 1);
        0x202usize as NDIS_HANDLE
    }
    pub(crate) unsafe fn NdisFreeNetBufferPool(_: NDIS_HANDLE) {
        state(|s| {
            assert!(s.nb_pools > 0);
            s.nb_pools -= 1;
        });
    }
    pub(crate) unsafe fn NdisFSetAttributes(
        _: NDIS_HANDLE,
        a: NDIS_HANDLE,
        p: PNDIS_FILTER_ATTRIBUTES,
    ) -> NDIS_STATUS {
        unsafe {
            assert_eq!((*p).Header.Size, FWX_WDK_FILTER_ATTRIBUTES_SIZE as u16);
        }
        state(|s| {
            s.adapter = a as usize;
            s.attributes_status
        })
    }
    fn pause_after_forward(a: usize, pause: bool) {
        if !pause {
            return;
        }
        let mut parameters = NDIS_FILTER_PAUSE_PARAMETERS::default();
        assert_eq!(
            unsafe { filter_pause(a as NDIS_HANDLE, &mut parameters) },
            FWX_WDK_NDIS_PENDING as NDIS_STATUS
        );
    }
    pub(crate) unsafe fn NdisFSendNetBufferLists(
        _: NDIS_HANDLE,
        nbl: PNET_BUFFER_LIST,
        _: NDIS_PORT_NUMBER,
        flags: ULONG,
    ) {
        assert_unlocked();
        let (inline, a, pause, extra_flags) = state(|s| {
            s.events.push(Event::Send(nbl as usize, flags));
            (
                s.inline,
                s.adapter,
                core::mem::take(&mut s.pause_after_forward),
                s.send_complete_extra_flags,
            )
        });
        if inline {
            unsafe {
                send_complete(
                    a as NDIS_HANDLE,
                    nbl,
                    (flags & NDIS_SEND_FLAGS_DISPATCH_LEVEL) | extra_flags,
                );
            }
        }
        pause_after_forward(a, pause);
    }
    pub(crate) unsafe fn NdisFSendNetBufferListsComplete(
        _: NDIS_HANDLE,
        nbl: PNET_BUFFER_LIST,
        flags: ULONG,
    ) {
        assert_unlocked();
        unsafe {
            assert!(
                (*nbl).Context.is_null(),
                "context must be removed before upper completion"
            );
        }
        let free = state(|s| {
            s.events.push(Event::Complete(
                nbl as usize,
                unsafe { (*nbl).__bindgen_anon_2.Status },
                flags,
            ));
            s.free_original
        });
        if free {
            unsafe {
                drop(Box::from_raw(nbl));
            }
        }
    }
    pub(crate) unsafe fn NdisFIndicateReceiveNetBufferLists(
        _: NDIS_HANDLE,
        nbl: PNET_BUFFER_LIST,
        _: NDIS_PORT_NUMBER,
        count: ULONG,
        flags: ULONG,
    ) {
        assert_unlocked();
        assert_eq!(count, 1);
        assert_eq!(flags & NDIS_RECEIVE_FLAGS_RESOURCES, 0);
        let (inline, a, pause, extra_flags) = state(|s| {
            s.events.push(Event::Indicate(nbl as usize, flags));
            (
                s.inline,
                s.adapter,
                core::mem::take(&mut s.pause_after_forward),
                s.receive_return_extra_flags,
            )
        });
        if inline {
            unsafe {
                return_receive(
                    a as NDIS_HANDLE,
                    nbl,
                    (flags & NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL) | extra_flags,
                );
            }
        }
        pause_after_forward(a, pause);
    }
    pub(crate) unsafe fn NdisFReturnNetBufferLists(
        _: NDIS_HANDLE,
        nbl: PNET_BUFFER_LIST,
        flags: ULONG,
    ) {
        assert_unlocked();
        unsafe {
            assert!(
                (*nbl).Context.is_null(),
                "context must be removed before lower return"
            );
            assert_ne!(
                (*nbl).SourceHandle,
                0x303usize as NDIS_HANDLE,
                "private NBL returned lower"
            );
        }
        let free = state(|s| {
            s.events.push(Event::Return(nbl as usize, flags));
            s.free_original
        });
        if free {
            unsafe {
                drop(Box::from_raw(nbl));
            }
        }
    }
    pub(crate) unsafe fn NdisFPauseComplete(_: NDIS_HANDLE) {
        assert_unlocked();
        let (detach, a) = state(|s| {
            s.events.push(Event::PauseComplete);
            (s.detach_on_pause, s.adapter)
        });
        if detach {
            unsafe {
                filter_detach(a as NDIS_HANDLE);
            }
        }
    }
    pub(crate) unsafe fn NdisFCancelSendNetBufferLists(_: NDIS_HANDLE, id: PVOID) {
        state(|s| s.events.push(Event::LowerCancel(id as usize)));
    }
    pub(crate) unsafe fn NdisAllocateCloneOidRequest(
        _: NDIS_HANDLE,
        r: PNDIS_OID_REQUEST,
        tag: UINT,
        out: *mut PNDIS_OID_REQUEST,
    ) -> NDIS_STATUS {
        assert_eq!(tag, TAG);
        if fail() {
            return FWX_WDK_NDIS_RESOURCES as NDIS_STATUS;
        }
        let clone = Box::into_raw(Box::new(unsafe { *r }));
        state(|s| {
            assert!(s.clones.insert(clone as usize));
            s.last_clone = clone as usize;
        });
        unsafe {
            *out = clone;
        }
        FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
    }
    pub(crate) unsafe fn NdisFreeCloneOidRequest(_: NDIS_HANDLE, r: PNDIS_OID_REQUEST) {
        state(|s| {
            assert!(
                s.clones.remove(&(r as usize)),
                "foreign/double OID clone free"
            )
        });
        unsafe {
            drop(Box::from_raw(r));
        }
    }
    pub(crate) unsafe fn NdisFOidRequest(_: NDIS_HANDLE, _: PNDIS_OID_REQUEST) -> NDIS_STATUS {
        state(|s| s.oid_status)
    }
    pub(crate) unsafe fn NdisFOidRequestComplete(
        _: NDIS_HANDLE,
        original: PNDIS_OID_REQUEST,
        status: NDIS_STATUS,
    ) {
        state(|s| s.events.push(Event::OidComplete(original as usize, status)));
    }
    pub(crate) unsafe fn NdisFCancelOidRequest(_: NDIS_HANDLE, id: PVOID) {
        state(|s| s.events.push(Event::OidCancel(id as usize)));
    }
    pub(crate) unsafe fn NdisFIndicateStatus(_: NDIS_HANDLE, _: PNDIS_STATUS_INDICATION) {
        assert_unlocked();
        state(|s| s.events.push(Event::Status));
    }
    pub(crate) unsafe fn NdisFNetPnPEvent(
        _: NDIS_HANDLE,
        _: PNET_PNP_EVENT_NOTIFICATION,
    ) -> NDIS_STATUS {
        state(|s| s.events.push(Event::Pnp));
        FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
    }

    pub(crate) fn FwxAttach(index: u32) -> u32 {
        state(|s| {
            s.events.push(Event::Attach(index));
            u32::from(s.attach_ok)
        })
    }
    pub(crate) fn FwxRestart(_: u32) -> u32 {
        state(|s| u32::from(s.restart_ok))
    }
    pub(crate) fn FwxRollbackAttach(index: u32) {
        state(|s| s.events.push(Event::RollbackAttach(index)));
    }
    pub(crate) fn FwxDetach(index: u32) {
        state(|s| s.events.push(Event::Detach(index)));
    }
    pub(crate) fn FwxInvalidate(index: u32, pause: u32) {
        assert_eq!(pause, 1);
        state(|s| {
            assert!(s.rw_depth > 0);
            s.events.push(Event::Invalidate(index));
            s.invalidated.insert(index);
        });
    }
    pub(crate) fn FwxDrain() {
        assert_unlocked();
        let pending = state(|s| {
            s.events.push(Event::Drain);
            let mut claimed = Vec::new();
            let invalidated = &s.invalidated;
            s.pending.retain(|&n| {
                let a = unsafe {
                    (*packet::packet_context(n as PNET_BUFFER_LIST))
                        .adapter
                        .cast::<Adapter>()
                };
                if invalidated.contains(&unsafe { (*a).interface_index }) {
                    claimed.push(n);
                    false
                } else {
                    true
                }
            });
            claimed
        });
        for n in pending {
            unsafe {
                fwx_finish(n, 1);
            }
        }
    }
    pub(crate) fn FwxPausedDrop(_index: u32) {
        state(|s| s.paused_drops += 1);
    }
    pub(crate) fn FwxResourceDrop(_index: u32) {
        state(|s| s.resource_drops += 1);
    }
    pub(crate) fn FwxInvalidLso(index: u32) {
        state(|s| s.invalid_lso_warnings.push(index));
    }
    pub(crate) fn FwxSendFailure(index: u32, status: i32) {
        state(|s| s.send_failure_warnings.push((index, status)));
    }
    pub(crate) fn FwxClassify(
        nbl: usize,
        index: u32,
        direction: u32,
        cancel: usize,
        session: u32,
        split: u32,
        guard: PVOID,
    ) -> i32 {
        let (cancel_during_classify, adapter) =
            state(|s| (s.cancel_during_classify.take(), s.adapter));
        if let Some(id) = cancel_during_classify {
            // Model cancellation on another CPU while this classifier holds
            // the read lock and has not yet published ownership to policy.
            state(|s| s.publishing = true);
            unsafe { cancel_send(adapter as NDIS_HANDLE, id as PVOID) };
            state(|s| s.publishing = false);
        }
        if !guard.is_null() {
            let cancelled = unsafe { fwx_send_guard_lock(guard) != 0 };
            unsafe { fwx_send_guard_unlock(guard) };
            if cancelled {
                return FINISH_CANCEL as i32;
            }
        }
        let (result, early) = state(|s| {
            assert!(s.rw_depth > 0);
            s.events
                .push(Event::Classify(index, direction, cancel, session));
            let result = if split != 0 {
                s.split_seen
                    .push(unsafe { packet::first_nb(nbl as PNET_BUFFER_LIST) } as usize);
                if s.split_results.is_empty() {
                    0
                } else {
                    s.split_results.remove(0)
                }
            } else {
                s.classify_result
            };
            let early = if split != 0 && result < 0 {
                s.split_early_finish.take()
            } else {
                s.early_finish
            };
            if result < 0 && early.is_none() {
                s.pending.push(nbl);
            }
            (result, early)
        });
        if let Some(id) = state(|s| s.cancel_after_publish.take()) {
            assert!(result < 0 && early.is_none());
            state(|s| s.publishing = true);
            unsafe { cancel_send(adapter as NDIS_HANDLE, id as PVOID) };
            state(|s| s.publishing = false);
        }
        if let Some(finish) = early {
            // Model the userspace verdict racing publication on another CPU.
            // This CPU does not own the classifier's RW-lock acquisition.
            state(|s| s.publishing = true);
            unsafe {
                fwx_finish(nbl, finish);
            }
            state(|s| s.publishing = false);
            assert!(result < 0);
        }
        result
    }
    pub(crate) fn FwxCancel(index: u32, cancel: usize) {
        let claimed = state(|s| {
            s.events.push(Event::Cancel(index, cancel));
            let mut claimed = Vec::new();
            s.pending.retain(|&n| {
                let context = unsafe { packet::packet_context(n as PNET_BUFFER_LIST) };
                let a = unsafe { (*context).adapter.cast::<Adapter>() };
                let matches = unsafe {
                    (*a).interface_index == index
                        && (*context).direction == SEND
                        && (*(n as PNET_BUFFER_LIST)).NetBufferListInfo
                            [NetBufferListCancelId as usize] as usize
                            == cancel
                };
                if matches {
                    claimed.push(n);
                    false
                } else {
                    true
                }
            });
            claimed
        });
        for n in claimed {
            unsafe {
                fwx_finish(n, 2);
            }
        }
    }
}

#[test]
fn supported_ndis_versions_and_characteristics_use_runtime_revision_and_optional_bypass() {
    let _fixture = Fixture::new();
    assert_eq!(ndis_version(NDIS_RUNTIME_VERSION_640 - 1), 0);
    for version in [
        NDIS_RUNTIME_VERSION_640,
        NDIS_RUNTIME_VERSION_650,
        NDIS_RUNTIME_VERSION_651,
        NDIS_RUNTIME_VERSION_660,
        NDIS_RUNTIME_VERSION_670,
        NDIS_RUNTIME_VERSION_680,
        NDIS_RUNTIME_VERSION_681,
        NDIS_RUNTIME_VERSION_682,
        NDIS_RUNTIME_VERSION_683,
        NDIS_RUNTIME_VERSION_684,
        NDIS_RUNTIME_VERSION_685,
        NDIS_RUNTIME_VERSION_686,
        NDIS_RUNTIME_VERSION_687,
        NDIS_RUNTIME_VERSION_688,
        NDIS_RUNTIME_VERSION_689,
    ] {
        assert_eq!(ndis_version(version), version);
        let mut c: NDIS_FILTER_DRIVER_CHARACTERISTICS = unsafe { zeroed() };
        assert!(configure_characteristics(&mut c, version));
        assert_eq!((c.MajorNdisVersion, c.MinorNdisVersion), (6, version as u8));
        assert_eq!(
            c.Header.Size,
            if version >= NDIS_RUNTIME_VERSION_680 {
                FWX_WDK_FILTER_REV3_SIZE as u16
            } else {
                FWX_WDK_FILTER_REV2_SIZE as u16
            }
        );
        assert!(
            c.AttachHandler.is_some()
                && c.DetachHandler.is_some()
                && c.PauseHandler.is_some()
                && c.RestartHandler.is_some()
        );
        assert!(
            c.SendNetBufferListsHandler.is_some()
                && c.ReturnNetBufferListsHandler.is_some()
                && c.OidRequestHandler.is_some()
        );
        assert!(
            c.DirectOidRequestHandler.is_none()
                && c.DirectOidRequestCompleteHandler.is_none()
                && c.CancelDirectOidRequestHandler.is_none()
        );
        assert!(
            c.SynchronousOidRequestHandler.is_none()
                && c.SynchronousOidRequestCompleteHandler.is_none()
        );
        assert_eq!(c.Flags, 0);
    }
    assert_eq!(ndis_version(u32::MAX), NDIS_RUNTIME_VERSION_689);
    assert_eq!(
        ndis_version(NDIS_RUNTIME_VERSION_650 - 1),
        NDIS_RUNTIME_VERSION_640
    );
    assert_eq!(
        nbl_info_count(NDIS_RUNTIME_VERSION_640),
        RscTcpTimestampDelta as u32 + 1
    );
    assert_eq!(
        nbl_info_count(NDIS_RUNTIME_VERSION_650),
        GftFlowEntryId as u32 + 1
    );
    assert_eq!(
        nbl_info_count(NDIS_RUNTIME_VERSION_689),
        FWX_WDK_NBL_INFO_COUNT as u32
    );
    let mut c: NDIS_FILTER_DRIVER_CHARACTERISTICS = unsafe { zeroed() };
    assert!(!configure_characteristics(&mut c, 0));
    assert!(!configure_characteristics(
        &mut c,
        NDIS_RUNTIME_VERSION_689 + 1
    ));
}

#[test]
fn running_count_is_idempotent_and_keeps_snapshot_flag_consistent() {
    let f = Fixture::new();
    let mut a = f.adapter();
    unsafe {
        start(&mut *a);
        start(&mut *a);
        assert_eq!(FILTERED_DEVICE_COUNT.load(Ordering::SeqCst), 1);
        assert_ne!(a.info.flags & wire::ADAPTER_RUNNING, 0);
        stop(&mut *a);
        stop(&mut *a);
        assert_eq!(a.info.flags & wire::ADAPTER_RUNNING, 0);
    }
}

#[test]
fn send_inline_completion_preserves_flags_and_drops_context_before_upper_ownership() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut nbl = Box::<NET_BUFFER_LIST>::default();
    unsafe {
        start(&mut *a);
        send(
            (&mut *a as *mut Adapter).cast(),
            &mut *nbl,
            9,
            NDIS_SEND_FLAGS_DISPATCH_LEVEL | NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK,
        );
        assert!(nbl.Context.is_null());
        assert_eq!(a.active, 0);
        stop(&mut *a);
    }
    state(|s| {
        assert!(s.events.iter().any(
            |e| matches!(e, Event::Send(_, flags) if *flags == NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK)
        ));
        assert!(
            s.events
                .iter()
                .any(|e| matches!(e, Event::Complete(_, _, 0)))
        );
    });
}

#[test]
fn failed_lower_send_is_reported_without_changing_completion_status() {
    for (status, report) in [
        (FWX_WDK_NDIS_SUCCESS as NDIS_STATUS, false),
        (FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS, false),
        (FWX_WDK_NDIS_RESOURCES as NDIS_STATUS, true),
    ] {
        let f = Fixture::new();
        let mut a = f.adapter();
        let mut source = Source::new();
        state(|s| s.inline = false);
        unsafe {
            start(&mut *a);
            send((&mut *a as *mut Adapter).cast(), &mut *source.nbl, 0, 0);
            assert_eq!(a.active, 1);
            source.nbl.__bindgen_anon_2.Status = status;
            send_complete((&mut *a as *mut Adapter).cast(), &mut *source.nbl, 0);
            assert_eq!(source.nbl.__bindgen_anon_2.Status, status);
            assert_eq!(a.active, 0);
            stop(&mut *a);
        }
        let warnings = state(|s| s.send_failure_warnings.clone());
        assert_eq!(warnings.len(), usize::from(report));
        if report {
            assert_eq!(warnings[0], (77, status));
        }
    }
}

#[test]
fn locally_dropped_lso_uses_completion_metadata() {
    let f = Fixture::new();
    let mut a = f.adapter();
    state(|s| s.classify_result = 1);
    unsafe { start(&mut *a) };
    for version in [
        NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE,
        NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE,
    ] {
        let mut source = Source::new();
        let offset = 34;
        source.data[offset + 12] = 5 << 4;
        let mut info: NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO = unsafe { zeroed() };
        unsafe {
            info.__bindgen_anon_1.LsoV1Transmit.set_MSS(64);
            info.__bindgen_anon_1
                .LsoV1Transmit
                .set_TcpHeaderOffset(offset as u32);
            info.__bindgen_anon_1.LsoV1Transmit.set_Type(version);
            source.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] =
                info.__bindgen_anon_1.Value;
            send((&mut *a as *mut Adapter).cast(), &mut *source.nbl, 0, 0);
            info.__bindgen_anon_1.Value =
                source.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize];
            if version == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE {
                assert_eq!(info.__bindgen_anon_1.LsoV1TransmitComplete.TcpPayload(), 74);
                assert_eq!(info.__bindgen_anon_1.LsoV1TransmitComplete.Type(), version);
            } else {
                assert_eq!(info.__bindgen_anon_1.LsoV2TransmitComplete.Type(), version);
                assert_eq!(info.__bindgen_anon_1.LsoV2TransmitComplete.Reserved(), 0);
                assert_eq!(info.__bindgen_anon_1.LsoV2TransmitComplete.Reserved2(), 0);
            }
            assert_eq!(
                source.nbl.__bindgen_anon_2.Status,
                FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
            );
        }
    }
    // An unreadable/malformed LSOv1 TCP header fails safely without passing
    // the transmit-form bitfields back as a successful completion.
    let mut malformed = Source::new();
    let mut info: NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO = unsafe { zeroed() };
    unsafe {
        info.__bindgen_anon_1.LsoV1Transmit.set_MSS(64);
        info.__bindgen_anon_1.LsoV1Transmit.set_TcpHeaderOffset(120);
        malformed.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] =
            info.__bindgen_anon_1.Value;
        send((&mut *a as *mut Adapter).cast(), &mut *malformed.nbl, 0, 0);
        assert_eq!(
            malformed.nbl.__bindgen_anon_2.Status,
            FWX_WDK_NDIS_RESOURCES as NDIS_STATUS
        );
        assert!(malformed.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize].is_null());
        assert_eq!(state(|s| s.invalid_lso_warnings.clone()), [77]);
        stop(&mut *a);
    }
}

#[test]
fn paused_lso_sends_return_completion_metadata_with_or_without_cancellation() {
    for version in [
        NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE,
        NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE,
    ] {
        for cancelled in [false, true] {
            let f = Fixture::new();
            let mut a = f.adapter();
            let mut first = Box::<NET_BUFFER_LIST>::default();
            let mut second = Source::new();
            let mut info: NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO = unsafe { zeroed() };
            let cancel = 0x1234usize;
            state(|s| {
                s.pause_after_forward = true;
                s.cancel_after_pause = cancelled.then_some(cancel);
            });
            unsafe {
                second.data[34 + 12] = 5 << 4;
                info.__bindgen_anon_1.LsoV1Transmit.set_MSS(64);
                info.__bindgen_anon_1.LsoV1Transmit.set_TcpHeaderOffset(34);
                info.__bindgen_anon_1.LsoV1Transmit.set_Type(version);
                if version == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE {
                    info.__bindgen_anon_1
                        .LsoV2Transmit
                        .set_IPVersion(NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6);
                }
                second.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] =
                    info.__bindgen_anon_1.Value;
                second.nbl.NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
                start(&mut *a);
                packet::set_next_nbl(&mut *first, &mut *second.nbl);
                send((&mut *a as *mut Adapter).cast(), &mut *first, 0, 0);
                assert_eq!(
                    second.nbl.__bindgen_anon_2.Status,
                    if cancelled {
                        FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
                    } else {
                        FWX_WDK_NDIS_PAUSED as NDIS_STATUS
                    }
                );
                info.__bindgen_anon_1.Value =
                    second.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize];
                if version == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE {
                    assert_eq!(info.__bindgen_anon_1.LsoV1TransmitComplete.Type(), version);
                    assert_eq!(info.__bindgen_anon_1.LsoV1TransmitComplete.TcpPayload(), 74);
                } else {
                    assert_eq!(info.__bindgen_anon_1.LsoV2TransmitComplete.Type(), version);
                    assert_eq!(info.__bindgen_anon_1.LsoV2TransmitComplete.Reserved(), 0);
                    assert_eq!(info.__bindgen_anon_1.LsoV2TransmitComplete.Reserved2(), 0);
                }
                assert_eq!(a.active, 0);
            }
        }
    }
}

#[test]
fn paused_malformed_lso_keeps_pause_status_and_clears_transmit_metadata() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut source = Source::new();
    let mut info: NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO = unsafe { zeroed() };
    unsafe {
        info.__bindgen_anon_1.LsoV1Transmit.set_MSS(64);
        info.__bindgen_anon_1.LsoV1Transmit.set_TcpHeaderOffset(120);
        source.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] =
            info.__bindgen_anon_1.Value;
        send((&mut *a as *mut Adapter).cast(), &mut *source.nbl, 0, 0);
        assert_eq!(
            source.nbl.__bindgen_anon_2.Status,
            FWX_WDK_NDIS_PAUSED as NDIS_STATUS
        );
        assert!(source.nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize].is_null());
        assert_eq!(state(|s| s.invalid_lso_warnings.clone()), [77]);
    }
}

#[test]
fn early_verdict_can_complete_and_free_original_before_classify_returns() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let nbl = Box::into_raw(Box::<NET_BUFFER_LIST>::default());
    state(|s| {
        s.classify_result = -1;
        s.early_finish = Some(0);
        s.free_original = true;
    });
    unsafe {
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), nbl, 0, 0);
        assert_eq!(a.active, 0);
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Complete(_, _, _)))
                .count(),
            1
        )
    });
}

#[test]
fn cancellation_after_publication_can_free_nbl_before_classify_returns() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let nbl = Box::into_raw(Box::<NET_BUFFER_LIST>::default());
    let cancel: usize = 0xabc;
    unsafe { (*nbl).NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID };
    state(|s| {
        s.classify_result = -1;
        s.cancel_after_publish = Some(cancel);
        s.free_original = true;
    });
    unsafe {
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), nbl, 0, 0);
        // The fake upper driver freed nbl during cancellation; do not inspect it.
        assert_eq!(a.active, 0);
        assert!(a.send_batches.is_null());
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(s.events.iter().filter(|event| matches!(event,
            Event::Complete(_, status, _) if *status == FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
        )).count(), 1);
        assert!(
            !s.events
                .iter()
                .any(|event| matches!(event, Event::Send(_, _)))
        );
    });
}

#[test]
fn original_receive_allow_returns_lower_and_recomputes_dispatch_flags() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut source = Source::new();
    state(|s| s.irql = DISPATCH_LEVEL as u8);
    unsafe {
        start(&mut *a);
        receive(
            (&mut *a as *mut Adapter).cast(),
            &mut *source.nbl,
            3,
            1,
            NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE,
        );
        assert_eq!(a.active, 0);
        stop(&mut *a);
    }
    assert!(source.data.iter().all(|&b| b == 0x5a));
    state(|s| {
        assert!(s.events.iter().any(|e| matches!(e, Event::Indicate(_, flags) if *flags == NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE | NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL)));
        assert!(s.events.iter().any(
            |e| matches!(e, Event::Return(_, flags) if *flags == NDIS_RETURN_FLAGS_DISPATCH_LEVEL)
        ));
    });
}

#[test]
fn resources_receive_uses_private_deep_copy_and_never_returns_original_or_private_lower() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut source = Source::new();
    let mut tail = Box::<NET_BUFFER_LIST>::default();
    source.nbl.NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] = 3usize as PVOID;
    let address = (&mut *source.nbl as *mut NET_BUFFER_LIST) as usize;
    // Use one owned source with an external next link while directly testing
    // CreateNdisPacket: RESOURCES must not alter the original chain or context.
    unsafe {
        packet::set_next_nbl(&mut *source.nbl, &mut *tail);
        start(&mut *a);
        let copied = create_ndis_packet(
            &mut *a,
            &mut *source.nbl,
            4,
            NDIS_RECEIVE_FLAGS_RESOURCES,
            RECEIVE,
            true,
        )
        .expect("receive copy should succeed");
        assert!(!copied.is_null());
        assert_ne!(copied as usize, address);
        assert_eq!(
            packet::next_nbl(&mut *source.nbl),
            &mut *tail as *mut NET_BUFFER_LIST
        );
        assert!(source.nbl.Context.is_null());
        assert_eq!(
            (*copied).NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] as usize,
            3
        );
        let copied_nb = packet::first_nb(copied);
        let copied_mdl = packet::first_mdl(copied_nb);
        assert_ne!(
            (*copied_mdl).MappedSystemVa,
            source.data.as_mut_ptr().cast()
        );
        fwx_finish(copied as usize, 0);
        assert_eq!(a.active, 0);
        stop(&mut *a);
    }
    assert!(source.data.iter().all(|&b| b == 0x5a));
    state(|s| assert!(!s.events.iter().any(|e| matches!(e, Event::Return(_, _)))));
}

#[test]
fn mixed_send_completes_original_after_independent_children_and_restores_order() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local = Source::new();
    let mut transit1 = Source::new();
    let mut transit2 = Source::new();
    let parent = (&mut *local.nbl as *mut NET_BUFFER_LIST) as usize;
    let first = &mut *local._nb as *mut NET_BUFFER;
    let second = &mut *transit1._nb as *mut NET_BUFFER;
    let third = &mut *transit2._nb as *mut NET_BUFFER;
    state(|s| {
        s.classify_result = CLASSIFY_SPLIT;
        s.split_results = vec![0, -1, -1];
    });
    unsafe {
        packet::set_next_nb(first, second);
        packet::set_next_nb(second, third);
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *local.nbl, 0, 0);
        assert_eq!(a.active, 3); // parent plus two outstanding transit children
        state(|s| {
            assert_eq!(s.split_seen.len(), 3);
            assert_ne!(s.split_seen[0], first as usize);
            assert_ne!(s.split_seen[1], second as usize);
            assert_ne!(s.split_seen[2], third as usize);
            assert_eq!(packet::next_nb(first), second);
            assert_eq!(packet::next_nb(second), third);
            assert_eq!(s.pending.len(), 2);
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Send(_, _)))
                    .count(),
                1
            );
            assert!(
                !s.events
                    .iter()
                    .any(|e| matches!(e, Event::Complete(p, _, _) if *p == parent))
            );
        });
        let blocked = state(|s| s.pending.remove(0));
        fwx_finish(blocked, 1);
        state(|s| {
            assert!(
                !s.events
                    .iter()
                    .any(|e| matches!(e, Event::Complete(p, _, _) if *p == parent))
            )
        });
        let allowed = state(|s| s.pending.remove(0));
        fwx_finish(allowed, 0);
        assert_eq!(a.active, 0);
        assert_eq!(packet::first_nb(&mut *local.nbl), first);
        assert_eq!(packet::next_nb(first), second);
        assert_eq!(packet::next_nb(second), third);
        assert!(packet::next_nb(third).is_null());
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Send(_, _)))
                .count(),
            2
        );
        assert_eq!(s.events.iter().filter(|e| matches!(e, Event::Complete(p, status, _) if *p == parent && *status == FWX_WDK_NDIS_SUCCESS as NDIS_STATUS)).count(), 1);
    });
}

#[test]
fn mixed_send_aggregates_lower_completion_flags() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local = Source::new();
    let mut transit = Source::new();
    let parent = (&mut *local.nbl as *mut NET_BUFFER_LIST) as usize;
    state(|s| {
        s.classify_result = CLASSIFY_SPLIT;
        s.split_results = vec![0, -1];
        s.send_complete_extra_flags =
            NDIS_SEND_COMPLETE_FLAGS_SINGLE_QUEUE | NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE;
    });
    unsafe {
        packet::set_next_nb(&mut *local._nb, &mut *transit._nb);
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *local.nbl, 0, 0);
        state(|s| s.send_complete_extra_flags = NDIS_SEND_COMPLETE_FLAGS_SINGLE_QUEUE);
        let child = state(|s| s.pending.remove(0));
        fwx_finish(child, 0);
        assert_eq!(a.active, 0);
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(s.events.iter().filter(|e| matches!(e,
            Event::Complete(p, _, flags) if *p == parent && *flags == NDIS_SEND_COMPLETE_FLAGS_SINGLE_QUEUE
        )).count(), 1);
    });
}

#[test]
fn mixed_send_early_verdict_and_inline_completion_keep_parent_alive() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local1 = Source::new();
    let mut transit = Source::new();
    let mut local2 = Source::new();
    let parent = (&mut *local1.nbl as *mut NET_BUFFER_LIST) as usize;
    let first = &mut *local1._nb as *mut NET_BUFFER;
    let second = &mut *transit._nb as *mut NET_BUFFER;
    let third = &mut *local2._nb as *mut NET_BUFFER;
    state(|s| {
        s.classify_result = CLASSIFY_SPLIT;
        s.split_results = vec![0, -1, 0];
        s.split_early_finish = Some(1);
    });
    unsafe {
        packet::set_next_nb(first, second);
        packet::set_next_nb(second, third);
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *local1.nbl, 0, 0);
        assert_eq!(a.active, 0);
        assert_eq!(packet::next_nb(first), second);
        assert_eq!(packet::next_nb(second), third);
        stop(&mut *a);
    }
    state(|s| {
        assert!(s.pending.is_empty());
        assert_eq!(s.split_seen.len(), 3);
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Complete(p, _, _) if *p == parent))
                .count(),
            1
        );
    });
}

#[test]
fn mixed_send_cancellation_completes_parent_once_after_all_children() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local = Source::new();
    let mut transit1 = Source::new();
    let mut transit2 = Source::new();
    let parent = (&mut *local.nbl as *mut NET_BUFFER_LIST) as usize;
    let first = &mut *local._nb as *mut NET_BUFFER;
    let second = &mut *transit1._nb as *mut NET_BUFFER;
    let third = &mut *transit2._nb as *mut NET_BUFFER;
    let cancel = 0x1234usize;
    local.nbl.NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
    state(|s| {
        s.classify_result = CLASSIFY_SPLIT;
        s.split_results = vec![0, -1, -1];
    });
    unsafe {
        packet::set_next_nb(first, second);
        packet::set_next_nb(second, third);
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *local.nbl, 0, 0);
        cancel_send((&mut *a as *mut Adapter).cast(), cancel as PVOID);
        assert_eq!(a.active, 0);
        assert_eq!(packet::next_nb(first), second);
        assert_eq!(packet::next_nb(second), third);
        stop(&mut *a);
    }
    state(|s| {
        assert!(s.pending.is_empty());
        assert_eq!(s.events.iter().filter(|e| matches!(e, Event::Complete(p, status, _) if *p == parent && *status == FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS)).count(), 1);
    });
}

#[test]
fn mixed_send_with_opaque_metadata_drops_without_detaching_original() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local = Source::new();
    let mut transit = Source::new();
    let parent = (&mut *local.nbl as *mut NET_BUFFER_LIST) as usize;
    let first = &mut *local._nb as *mut NET_BUFFER;
    let second = &mut *transit._nb as *mut NET_BUFFER;
    local.nbl.NetBufferListInfo[MediaSpecificInformation as usize] = 1usize as PVOID;
    state(|s| s.classify_result = CLASSIFY_SPLIT);
    unsafe {
        packet::set_next_nb(first, second);
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *local.nbl, 0, 0);
        assert_eq!(a.active, 0);
        assert_eq!(packet::next_nb(first), second);
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(s.resource_drops, 1);
        assert!(s.split_seen.is_empty());
        assert!(!s.events.iter().any(|e| matches!(e, Event::Send(_, _))));
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Complete(p, _, _) if *p == parent))
                .count(),
            1
        );
    });
}

#[test]
fn mixed_send_pause_drains_unprocessed_children_and_completes_once() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local = Source::new();
    let mut transit = Source::new();
    let parent = (&mut *local.nbl as *mut NET_BUFFER_LIST) as usize;
    let first = &mut *local._nb as *mut NET_BUFFER;
    let second = &mut *transit._nb as *mut NET_BUFFER;
    state(|s| {
        s.classify_result = CLASSIFY_SPLIT;
        s.split_results = vec![0, -1];
        s.pause_after_forward = true;
    });
    unsafe {
        packet::set_next_nb(first, second);
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *local.nbl, 0, 0);
        assert_eq!(a.running, 0);
        assert_eq!(a.active, 0);
        assert_eq!(packet::next_nb(first), second);
    }
    state(|s| {
        assert_eq!(s.paused_drops, 1);
        assert!(s.pending.is_empty());
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::PauseComplete))
                .count(),
            1
        );
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Complete(p, _, _) if *p == parent))
                .count(),
            1
        );
    });
}

#[test]
fn mixed_receive_returns_original_only_after_all_children_finish() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local = Source::new();
    let mut transit = Source::new();
    let parent = (&mut *local.nbl as *mut NET_BUFFER_LIST) as usize;
    let first = &mut *local._nb as *mut NET_BUFFER;
    let second = &mut *transit._nb as *mut NET_BUFFER;
    state(|s| {
        s.classify_result = CLASSIFY_SPLIT;
        s.split_results = vec![0, -1];
        s.receive_return_extra_flags =
            NDIS_RETURN_FLAGS_SINGLE_QUEUE | NDIS_RETURN_FLAGS_SWITCH_SINGLE_SOURCE;
    });
    unsafe {
        packet::set_next_nb(first, second);
        start(&mut *a);
        receive((&mut *a as *mut Adapter).cast(), &mut *local.nbl, 0, 1, 0);
        state(|s| {
            assert_eq!(s.pending.len(), 1);
            assert!(
                !s.events
                    .iter()
                    .any(|e| matches!(e, Event::Return(p, _) if *p == parent))
            );
            s.receive_return_extra_flags = NDIS_RETURN_FLAGS_SINGLE_QUEUE;
        });
        let child = state(|s| s.pending.remove(0));
        fwx_finish(child, 0);
        assert_eq!(a.active, 0);
        assert_eq!(packet::next_nb(first), second);
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Indicate(_, _)))
                .count(),
            2
        );
        assert_eq!(s.events.iter().filter(|e| matches!(e, Event::Return(p, flags) if *p == parent && *flags == NDIS_RETURN_FLAGS_SINGLE_QUEUE)).count(), 1);
    });
}

#[test]
fn mixed_resources_receive_keeps_original_untouched_until_transit_finishes() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut local = Source::new();
    let mut transit = Source::new();
    let first = &mut *local._nb as *mut NET_BUFFER;
    let second = &mut *transit._nb as *mut NET_BUFFER;
    state(|s| {
        s.classify_result = CLASSIFY_SPLIT;
        s.split_results = vec![0, -1];
    });
    unsafe {
        packet::set_next_nb(first, second);
        start(&mut *a);
        receive(
            (&mut *a as *mut Adapter).cast(),
            &mut *local.nbl,
            0,
            1,
            NDIS_RECEIVE_FLAGS_RESOURCES,
        );
        assert_eq!(packet::next_nb(first), second);
        assert!(local.nbl.Context.is_null());
        state(|s| {
            assert_eq!(s.pending.len(), 1);
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Indicate(_, _)))
                    .count(),
                1
            );
            assert!(!s.events.iter().any(|e| matches!(e, Event::Return(_, _))));
        });
        let child = state(|s| s.pending.remove(0));
        fwx_finish(child, 1);
        assert_eq!(a.active, 0);
        assert_eq!(packet::next_nb(first), second);
        stop(&mut *a);
    }
}

#[test]
fn resource_receive_data_view_failure_never_retains_original() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut source = Source::new();
    unsafe {
        start(&mut *a);
    }
    packet::reset_test_allocator(Some(3));
    unsafe {
        receive(
            (&mut *a as *mut Adapter).cast(),
            &mut *source.nbl,
            0,
            1,
            NDIS_RECEIVE_FLAGS_RESOURCES,
        );
        assert_eq!(a.active, 0);
        assert!(source.nbl.Context.is_null());
    }
    packet::assert_test_allocator_no_leaks();
    unsafe {
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(s.paused_drops, 0);
        assert_eq!(s.resource_drops, 1);
        assert!(
            !s.events
                .iter()
                .any(|e| matches!(e, Event::Return(_, _) | Event::Indicate(_, _)))
        )
    });
}

#[test]
fn paused_callbacks_complete_sends_return_owned_receives_and_leave_resource_chain_untouched() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut send_nbl = Box::<NET_BUFFER_LIST>::default();
    let mut receive_nbl = Box::<NET_BUFFER_LIST>::default();
    let mut resources = Box::<NET_BUFFER_LIST>::default();
    let mut tail = Box::<NET_BUFFER_LIST>::default();
    unsafe {
        send((&mut *a as *mut Adapter).cast(), &mut *send_nbl, 0, 0);
        assert_eq!(
            send_nbl.__bindgen_anon_2.Status,
            FWX_WDK_NDIS_PAUSED as NDIS_STATUS
        );
        receive((&mut *a as *mut Adapter).cast(), &mut *receive_nbl, 0, 1, 0);
        packet::set_next_nbl(&mut *resources, &mut *tail);
        receive(
            (&mut *a as *mut Adapter).cast(),
            &mut *resources,
            0,
            2,
            NDIS_RECEIVE_FLAGS_RESOURCES,
        );
        assert_eq!(
            packet::next_nbl(&mut *resources),
            &mut *tail as *mut NET_BUFFER_LIST
        );
        assert_eq!(a.active, 0);
    }
    state(|s| {
        assert_eq!(s.paused_drops, 4);
        assert_eq!(s.resource_drops, 0);
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Return(_, _)))
                .count(),
            1
        );
        assert!(
            !s.events
                .iter()
                .any(|e| matches!(e, Event::Classify(_, _, _, _)))
        );
    });
}

#[test]
fn pause_between_send_chain_members_reports_pause_or_cancellation() {
    for cancelled in [false, true] {
        let f = Fixture::new();
        let mut a = f.adapter();
        let mut first = Box::<NET_BUFFER_LIST>::default();
        let mut second = Box::<NET_BUFFER_LIST>::default();
        let second_address = (&mut *second as *mut NET_BUFFER_LIST) as usize;
        let cancel = 0x1234usize;
        state(|s| {
            s.pause_after_forward = true;
            s.cancel_after_pause = cancelled.then_some(cancel);
        });
        let expected = if cancelled {
            FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
        } else {
            FWX_WDK_NDIS_PAUSED as NDIS_STATUS
        };
        unsafe {
            second.NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
            start(&mut *a);
            packet::set_next_nbl(&mut *first, &mut *second);
            send((&mut *a as *mut Adapter).cast(), &mut *first, 0, 0);
            assert_eq!(second.__bindgen_anon_2.Status, expected);
            assert_eq!(a.active, 0);
        }
        state(|s| {
            assert_eq!(s.paused_drops, 1);
            assert_eq!(s.resource_drops, 0);
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Classify(_, _, _, _)))
                    .count(),
                1
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Send(_, _)))
                    .count(),
                1
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Complete(address, status, _) if *address == second_address && *status == expected))
                    .count(),
                1
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Cancel(77, id) if *id == cancel))
                    .count(),
                usize::from(cancelled)
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::PauseComplete))
                    .count(),
                1
            );
        });
    }
}

#[test]
fn pause_between_receive_chain_members_preserves_ownership_without_resource_drops() {
    for resources in [false, true] {
        let f = Fixture::new();
        let mut a = f.adapter();
        let mut first = Source::new();
        let mut second = Source::new();
        let second_address = (&mut *second.nbl as *mut NET_BUFFER_LIST) as usize;
        state(|s| s.pause_after_forward = true);
        unsafe {
            start(&mut *a);
            packet::set_next_nbl(&mut *first.nbl, &mut *second.nbl);
            receive(
                (&mut *a as *mut Adapter).cast(),
                &mut *first.nbl,
                0,
                2,
                if resources {
                    NDIS_RECEIVE_FLAGS_RESOURCES
                } else {
                    0
                },
            );
            if resources {
                assert_eq!(
                    packet::next_nbl(&mut *first.nbl),
                    &mut *second.nbl as *mut _
                );
            } else {
                assert!(packet::next_nbl(&mut *first.nbl).is_null());
            }
            assert!(first.nbl.Context.is_null());
            assert!(second.nbl.Context.is_null());
            assert_eq!(a.active, 0);
        }
        state(|s| {
            assert_eq!(s.paused_drops, 1);
            assert_eq!(s.resource_drops, 0);
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Classify(_, _, _, _)))
                    .count(),
                1
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Indicate(_, _)))
                    .count(),
                1
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Return(_, _)))
                    .count(),
                if resources { 0 } else { 2 }
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(
                        |e| matches!(e, Event::Return(address, _) if *address == second_address)
                    )
                    .count(),
                usize::from(!resources)
            );
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::PauseComplete))
                    .count(),
                1
            );
        });
    }
}

#[test]
fn disconnected_session_still_calls_policy_with_zero_session_and_non_ip_bypass_can_allow() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut nbl = Box::<NET_BUFFER_LIST>::default();
    state(|s| s.session_open = false);
    unsafe {
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *nbl, 0, 0);
        stop(&mut *a);
    }
    state(|s| {
        assert!(s.events.contains(&Event::Classify(77, SEND, 0, 0)));
        assert!(s.events.iter().any(|e| matches!(e, Event::Send(_, _))));
    });
}

#[test]
fn pause_invalidates_pending_under_write_lock_and_finishes_only_after_unlock() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut nbl = Box::<NET_BUFFER_LIST>::default();
    state(|s| s.classify_result = -1);
    unsafe {
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *nbl, 0, 0);
        assert_eq!(a.active, 1);
        let mut p = NDIS_FILTER_PAUSE_PARAMETERS {
            PauseReason: 7,
            Flags: 9,
            ..NDIS_FILTER_PAUSE_PARAMETERS::default()
        };
        assert_eq!(
            filter_pause((&mut *a as *mut Adapter).cast(), &mut p),
            FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
        );
        assert_eq!(
            (a.active, a.info.pause_reason, a.info.pause_flags),
            (0, 7, 9)
        );
        assert!(nbl.Context.is_null());
    }
    state(|s| {
        let invalidate = s
            .events
            .iter()
            .position(|e| matches!(e, Event::Invalidate(77)))
            .unwrap();
        let drain = s
            .events
            .iter()
            .position(|e| matches!(e, Event::Drain))
            .unwrap();
        let complete = s
            .events
            .iter()
            .position(|e| matches!(e, Event::Complete(_, _, _)))
            .unwrap();
        assert!(invalidate < drain && drain < complete);
    });
}

#[test]
fn last_send_completion_can_synchronously_pause_complete_and_detach_adapter() {
    let _f = Fixture::new();
    let mut nbl = Box::<NET_BUFFER_LIST>::default();
    state(|s| {
        s.inline = false;
        s.detach_on_pause = true;
    });
    unsafe {
        let a = attach_one();
        start(a);
        send(a.cast(), &mut *nbl, 0, 0);
        let mut pause = NDIS_FILTER_PAUSE_PARAMETERS::default();
        assert_eq!(
            filter_pause(a.cast(), &mut pause),
            FWX_WDK_NDIS_PENDING as NDIS_STATUS
        );
        assert_eq!((*a).pause_pending, 1);
        send_complete(a.cast(), &mut *nbl, 0);
        // a is freed by the inline detach. Do not inspect it here.
        let count = ADAPTER_COUNT;
        assert_eq!(count, 0);
    }
    state(|s| {
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::PauseComplete))
                .count(),
            1
        )
    });
}

#[test]
fn send_batch_registration_unlinks_any_position() {
    fn empty(a: *mut Adapter) -> SendBatch {
        SendBatch {
            adapter: a,
            previous: null_mut(),
            next: null_mut(),
            remaining: null_mut(),
            current_cancel: 0,
            current: false,
            cancelled: false,
        }
    }
    let f = Fixture::new();
    let mut a = f.adapter();
    let adapter = &mut *a as *mut Adapter;
    let mut first = empty(adapter);
    let mut middle = empty(adapter);
    let mut last = empty(adapter);
    unsafe {
        ndis_lock(addr_of_mut!((*adapter).lock));
        register_send_batch(adapter, &mut first);
        register_send_batch(adapter, &mut middle);
        register_send_batch(adapter, &mut last);
        unregister_send_batch(adapter, &mut middle);
        assert_eq!(a.send_batches, &mut last as *mut SendBatch);
        assert_eq!(last.next, &mut first as *mut SendBatch);
        assert_eq!(first.previous, &mut last as *mut SendBatch);
        unregister_send_batch(adapter, &mut last);
        assert_eq!(a.send_batches, &mut first as *mut SendBatch);
        assert!(first.previous.is_null());
        unregister_send_batch(adapter, &mut first);
        assert!(a.send_batches.is_null());
        ndis_unlock(addr_of_mut!((*adapter).lock));
    }
}

#[test]
fn cancel_during_classification_aborts_current_and_matching_chain_members() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut first = Box::<NET_BUFFER_LIST>::default();
    let mut other = Box::<NET_BUFFER_LIST>::default();
    let mut last = Box::<NET_BUFFER_LIST>::default();
    let mut reused = Box::<NET_BUFFER_LIST>::default();
    let cancel = 0xabcusize;
    first.NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
    other.NetBufferListInfo[NetBufferListCancelId as usize] = 0xdefusize as PVOID;
    last.NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
    reused.NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
    state(|s| {
        s.classify_result = -1;
        s.cancel_during_classify = Some(cancel);
    });
    unsafe {
        packet::set_next_nbl(&mut *first, &mut *other);
        packet::set_next_nbl(&mut *other, &mut *last);
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *first, 0, 0);
        assert_eq!(
            first.__bindgen_anon_2.Status,
            FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
        );
        assert_eq!(
            last.__bindgen_anon_2.Status,
            FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
        );
        assert!(first.Context.is_null());
        assert!(last.Context.is_null());
        assert!(!other.Context.is_null());
        assert!((*a).send_batches.is_null());
        assert_eq!(a.active, 1);

        // A new send with the same ID, after cancellation returns, is not stale.
        send((&mut *a as *mut Adapter).cast(), &mut *reused, 0, 0);
        assert!(!reused.Context.is_null());
        let pending = state(|s| core::mem::take(&mut s.pending));
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&((&mut *other as *mut NET_BUFFER_LIST) as usize)));
        assert!(pending.contains(&((&mut *reused as *mut NET_BUFFER_LIST) as usize)));
        for nbl in pending {
            fwx_finish(nbl, 0);
        }
        assert_eq!(a.active, 0);
        stop(&mut *a);
    }
    state(|s| {
        let aborted = s.events.iter().filter(|event| {
            matches!(event, Event::Complete(_, status, _) if *status == FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS)
        }).count();
        assert_eq!(aborted, 2);
        assert!(s.events.contains(&Event::LowerCancel(cancel)));
    });
}

#[test]
fn cancellation_can_free_current_and_unprocessed_nbls_inline() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let first = Box::into_raw(Box::<NET_BUFFER_LIST>::default());
    let last = Box::into_raw(Box::<NET_BUFFER_LIST>::default());
    let cancel: usize = 0x456;
    unsafe {
        (*first).NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
        (*last).NetBufferListInfo[NetBufferListCancelId as usize] = cancel as PVOID;
        packet::set_next_nbl(first, last);
    }
    state(|s| {
        s.classify_result = -1;
        s.cancel_during_classify = Some(cancel);
        s.free_original = true;
    });
    unsafe {
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), first, 0, 0);
        // Both NBLs were freed by the fake upper driver; do not inspect them.
        assert_eq!(a.active, 0);
        assert!(a.send_batches.is_null());
        stop(&mut *a);
    }
    state(|s| {
        assert_eq!(s.events.iter().filter(|event| matches!(event,
            Event::Complete(_, status, _) if *status == FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
        )).count(), 2);
        assert!(
            !s.events
                .iter()
                .any(|event| matches!(event, Event::Send(_, _)))
        );
    });
}

#[test]
fn cancel_send_is_interface_scoped_and_does_not_claim_receive_with_equal_numeric_cancel_id() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut send_nbl = Box::<NET_BUFFER_LIST>::default();
    let mut receive_nbl = Box::<NET_BUFFER_LIST>::default();
    send_nbl.NetBufferListInfo[NetBufferListCancelId as usize] = 0xabcusize as PVOID;
    receive_nbl.NetBufferListInfo[NetBufferListCancelId as usize] = 0xabcusize as PVOID;
    state(|s| s.classify_result = -1);
    unsafe {
        start(&mut *a);
        send((&mut *a as *mut Adapter).cast(), &mut *send_nbl, 0, 0);
        receive((&mut *a as *mut Adapter).cast(), &mut *receive_nbl, 0, 1, 0);
        cancel_send((&mut *a as *mut Adapter).cast(), 0xabcusize as PVOID);
        assert_eq!(
            send_nbl.__bindgen_anon_2.Status,
            FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
        );
        assert!(send_nbl.Context.is_null());
        assert!(!receive_nbl.Context.is_null());
        state(|s| s.pending.clear());
        fwx_finish((&mut *receive_nbl as *mut NET_BUFFER_LIST) as usize, 1);
        assert_eq!(a.active, 0);
        stop(&mut *a);
    }
    state(|s| {
        assert!(s.events.contains(&Event::Classify(77, RECEIVE, 0, 1)));
        assert!(s.events.contains(&Event::Cancel(77, 0xabc)));
        assert!(s.events.contains(&Event::LowerCancel(0xabc)));
    });
}

#[test]
fn oid_sync_pending_and_closed_rundown_preserve_single_completion() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut request = NDIS_OID_REQUEST::default();
    unsafe {
        assert_eq!(
            oid((&mut *a as *mut Adapter).cast(), &mut request),
            FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
        );
        state(|s| {
            assert!(
                s.events
                    .iter()
                    .all(|e| !matches!(e, Event::OidComplete(_, _)))
            )
        });
        state(|s| s.oid_status = FWX_WDK_NDIS_PENDING as NDIS_STATUS);
        assert_eq!(
            oid((&mut *a as *mut Adapter).cast(), &mut request),
            FWX_WDK_NDIS_PENDING as NDIS_STATUS
        );
        let clone = state(|s| s.last_clone as PNDIS_OID_REQUEST);
        (*clone).DATA.QUERY_INFORMATION.BytesWritten = 123;
        (*clone).DATA.QUERY_INFORMATION.BytesNeeded = 456;
        oid_complete(
            (&mut *a as *mut Adapter).cast(),
            clone,
            FWX_WDK_NDIS_FAILURE as NDIS_STATUS,
        );
        assert_eq!(
            (
                request.DATA.QUERY_INFORMATION.BytesWritten,
                request.DATA.QUERY_INFORMATION.BytesNeeded
            ),
            (123, 456)
        );
        state(|s| s.oid_open = false);
        assert_eq!(
            oid((&mut *a as *mut Adapter).cast(), &mut request),
            FWX_WDK_NDIS_CLOSING as NDIS_STATUS
        );
        cancel_oid((&mut *a as *mut Adapter).cast(), 99usize as PVOID);
    }
    state(|s| {
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::OidComplete(_, _)))
                .count(),
            1
        )
    });
}

#[test]
fn oid_copy_result_copies_only_request_kind_specific_result_fields() {
    let _f = Fixture::new();
    let mut original = NDIS_OID_REQUEST::default();
    let mut clone = NDIS_OID_REQUEST::default();
    unsafe {
        clone.RequestType = NdisRequestMethod;
        clone.DATA.METHOD_INFORMATION.OutputBufferLength = 11;
        clone.DATA.METHOD_INFORMATION.BytesRead = 12;
        clone.DATA.METHOD_INFORMATION.BytesWritten = 13;
        clone.DATA.METHOD_INFORMATION.BytesNeeded = 14;
        oid_copy_result(&mut original, &mut clone);
        assert_eq!(
            (
                original.DATA.METHOD_INFORMATION.OutputBufferLength,
                original.DATA.METHOD_INFORMATION.BytesRead,
                original.DATA.METHOD_INFORMATION.BytesWritten,
                original.DATA.METHOD_INFORMATION.BytesNeeded
            ),
            (11, 12, 13, 14)
        );
        original = NDIS_OID_REQUEST::default();
        clone.RequestType = NdisRequestSetInformation;
        clone.DATA.SET_INFORMATION.BytesRead = 21;
        clone.DATA.SET_INFORMATION.BytesNeeded = 22;
        oid_copy_result(&mut original, &mut clone);
        assert_eq!(
            (
                original.DATA.SET_INFORMATION.BytesRead,
                original.DATA.SET_INFORMATION.BytesNeeded
            ),
            (21, 22)
        );
    }
}

#[test]
fn attach_rejects_gate_or_media_and_unwinds_nonallocation_failures() {
    let _f = Fixture::new();
    let mut p = NDIS_FILTER_ATTACH_PARAMETERS::default();
    unsafe {
        p.MiniportMediaType = NdisMedium802_3;
        registry::TARGET_ALLOWED.store(false, Ordering::SeqCst);
        assert_eq!(
            filter_attach(null_mut(), null_mut(), &mut p),
            FWX_WDK_NDIS_NOT_SUPPORTED as NDIS_STATUS
        );
        registry::TARGET_ALLOWED.store(true, Ordering::SeqCst);
        p.MiniportMediaType = NdisMediumNative802_11;
        assert_eq!(
            filter_attach(null_mut(), null_mut(), &mut p),
            FWX_WDK_NDIS_NOT_SUPPORTED as NDIS_STATUS
        );
        state(|s| assert_eq!(s.allocation_attempts, 0));
        p.MiniportMediaType = NdisMedium802_3;
        p.BaseMiniportIfIndex = 8;
        state(|s| {
            s.attach_ok = false;
        });
        assert_eq!(
            filter_attach(null_mut(), null_mut(), &mut p),
            FWX_WDK_NDIS_RESOURCES as NDIS_STATUS
        );
        state(|s| {
            s.attach_ok = true;
            s.attributes_status = FWX_WDK_NDIS_FAILURE as NDIS_STATUS;
        });
        assert_eq!(
            filter_attach(null_mut(), null_mut(), &mut p),
            FWX_WDK_NDIS_FAILURE as NDIS_STATUS
        );
    }
    state(|s| {
        assert!(s.events.contains(&Event::RollbackAttach(8)));
        assert!(!s.events.contains(&Event::Detach(8)));
    });
}

#[test]
fn adapter_snapshot_has_no_32_adapter_ceiling_and_header_only_reply_never_stages() {
    let _f = Fixture::new();
    unsafe {
        for _ in 0..35 {
            attach_one();
        }
        let before = state(|s| s.allocation_attempts);
        let mut header = [0u8; wire::ADAPTER_INFO_HEADER_SIZE];
        let mut transferred = 999;
        assert_eq!(
            query_adapter_info(header.as_mut_ptr(), header.len() as u32, &mut transferred),
            FWX_WDK_STATUS_BUFFER_OVERFLOW as NTSTATUS
        );
        assert_eq!(transferred, wire::ADAPTER_INFO_HEADER_SIZE);
        assert_eq!(u32::from_le_bytes(header[8..12].try_into().unwrap()), 35);
        state(|s| assert_eq!(s.allocation_attempts, before));
        let size = wire::ADAPTER_INFO_HEADER_SIZE + 35 * wire::ADAPTER_INFO_ENTRY_SIZE;
        let mut out = vec![0; size];
        assert_eq!(
            query_adapter_info(out.as_mut_ptr(), out.len() as u32, &mut transferred),
            FWX_WDK_STATUS_SUCCESS as NTSTATUS
        );
        assert_eq!(transferred, size);
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 35);
        assert_eq!(
            u32::from_le_bytes(out[16 + 8..16 + 12].try_into().unwrap()),
            101
        );
        detach_all();
    }
}

#[test]
fn snapshot_errors_do_not_invent_partial_success_or_allocate_arithmetic_maximum() {
    let _f = Fixture::new();
    let mut out = vec![0; 32 * wire::ADAPTER_INFO_ENTRY_SIZE + wire::ADAPTER_INFO_HEADER_SIZE];
    let mut transferred = 123;
    unsafe {
        assert_eq!(
            query_adapter_info(out.as_mut_ptr(), 15, &mut transferred),
            FWX_WDK_STATUS_BUFFER_TOO_SMALL as NTSTATUS
        );
        assert_eq!(
            query_adapter_info(null_mut(), 16, &mut transferred),
            FWX_WDK_STATUS_INVALID_PARAMETER as NTSTATUS
        );
        ADAPTER_COUNT = wire::ADAPTER_INFO_MAX_ADAPTERS as u64 + 1;
        assert_eq!(
            query_adapter_info(out.as_mut_ptr(), out.len() as u32, &mut transferred),
            FWX_WDK_STATUS_INTEGER_OVERFLOW as NTSTATUS
        );
        ADAPTER_COUNT = 0;
        attach_one();
        state(|s| {
            s.snapshot_growth = MAX_STAGING_ATTEMPTS as usize;
        });
        assert_eq!(
            query_adapter_info(out.as_mut_ptr(), out.len() as u32, &mut transferred),
            FWX_WDK_STATUS_RETRY as NTSTATUS
        );
        assert_eq!(transferred, 123);
        detach_all();
    }
}

#[test]
fn attach_snapshot_copies_counted_names_guid_mac_and_revision_gated_connector() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let mut name = vec![0x41u16; 260];
    let mut counted = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let mut p = NDIS_FILTER_ATTACH_PARAMETERS::default();
    p.Header.Revision = NDIS_FILTER_ATTACH_PARAMETERS_REVISION_4 as u8;
    p.Header.Size = FWX_WDK_ATTACH_REV4_SIZE as u16;
    p.BaseMiniportIfIndex = 88;
    p.BaseMiniportInstanceName = &mut counted;
    p.BaseMiniportIfConnectorPresent = 1;
    p.MacAddressLength = u16::MAX;
    p.CurrentMacAddress.fill(0xee);
    let guid = GUID {
        Data1: 0x1234_5678,
        Data2: 0xabcd,
        Data3: 0xef01,
        Data4: [2, 3, 4, 5, 6, 7, 8, 9],
    };
    unsafe {
        capture_attach_info(&mut *a, &mut p, &guid);
    }
    name.fill(0x42);
    assert_eq!(a.info.instance_name_length, 255);
    assert_eq!(a.info.instance_name[0], 0x41);
    assert_eq!(a.info.instance_name[255], 0);
    assert_eq!(a.info.connector_present, 1);
    assert_ne!(a.info.flags & wire::ADAPTER_CONNECTOR_VALID, 0);
    assert_ne!(a.info.flags & wire::ADAPTER_INSTANCE_NAME_TRUNCATED, 0);
    assert_eq!(
        a.info.mac_address_length as usize,
        wire::ADAPTER_INFO_MAC_CAPACITY
    );
    assert_eq!(
        a.info.interface_guid,
        [
            0x78, 0x56, 0x34, 0x12, 0xcd, 0xab, 0x01, 0xef, 2, 3, 4, 5, 6, 7, 8, 9
        ]
    );
}

#[test]
fn restart_attribute_validation_and_link_status_capture_use_real_wdk_headers() {
    let f = Fixture::new();
    let mut a = f.adapter();
    let bytes =
        offset_of!(NDIS_RESTART_ATTRIBUTES, Data) + size_of::<NDIS_RESTART_GENERAL_ATTRIBUTES>();
    let layout =
        Layout::from_size_align(bytes, core::mem::align_of::<NDIS_RESTART_ATTRIBUTES>()).unwrap();
    let storage = unsafe { alloc_zeroed(layout) };
    assert!(!storage.is_null());
    unsafe {
        let attribute = storage.cast::<NDIS_RESTART_ATTRIBUTES>();
        (*attribute).Oid = OID_GEN_MINIPORT_RESTART_ATTRIBUTES;
        (*attribute).DataLength = FWX_WDK_RESTART_GENERAL_SIZE as u32;
        let general = addr_of_mut!((*attribute).Data).cast::<NDIS_RESTART_GENERAL_ATTRIBUTES>();
        (*general).Header.Type = NDIS_OBJECT_TYPE_RESTART_GENERAL_ATTRIBUTES as u8;
        (*general).Header.Revision = NDIS_RESTART_GENERAL_ATTRIBUTES_REVISION_1 as u8;
        (*general).Header.Size = FWX_WDK_RESTART_GENERAL_SIZE as u16;
        (*general).MtuSize = 1500;
        (*general).MaxXmitLinkSpeed = 10_000;
        let mut p = NDIS_FILTER_RESTART_PARAMETERS {
            RestartAttributes: attribute,
            ..NDIS_FILTER_RESTART_PARAMETERS::default()
        };
        assert_eq!(
            filter_restart((&mut *a as *mut Adapter).cast(), &mut p),
            FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
        );
        assert_eq!(a.info.mtu, 1500);
        assert_ne!(a.info.flags & wire::ADAPTER_GENERAL_VALID, 0);
        (*general).Header.Size = u16::MAX;
        capture_restart_info(&mut *a, &mut p);
        assert_eq!(a.info.flags & wire::ADAPTER_GENERAL_VALID, 0);
        assert_eq!(a.info.mtu, 0);
        stop(&mut *a);
        dealloc(storage, layout);
        let link = NDIS_LINK_STATE {
            Header: NDIS_OBJECT_HEADER {
                Type: NDIS_OBJECT_TYPE_DEFAULT as u8,
                Revision: NDIS_LINK_STATE_REVISION_1 as u8,
                Size: FWX_WDK_LINK_STATE_SIZE as u16,
            },
            XmitLinkSpeed: 12345,
            RcvLinkSpeed: 67890,
            ..NDIS_LINK_STATE::default()
        };
        let mut unaligned = vec![0u8; size_of::<NDIS_LINK_STATE>() + 1];
        ptr::copy_nonoverlapping(
            addr_of!(link).cast::<u8>(),
            unaligned.as_mut_ptr().add(1),
            size_of::<NDIS_LINK_STATE>(),
        );
        let mut indication = NDIS_STATUS_INDICATION {
            StatusCode: FWX_WDK_NDIS_LINK_STATE as NDIS_STATUS,
            StatusBuffer: unaligned.as_mut_ptr().add(1).cast(),
            StatusBufferSize: FWX_WDK_LINK_STATE_SIZE as u32,
            ..NDIS_STATUS_INDICATION::default()
        };
        status((&mut *a as *mut Adapter).cast(), &mut indication);
        assert_ne!(a.info.flags & wire::ADAPTER_LINK_STATE_VALID, 0);
        assert_eq!(
            (a.info.xmit_link_speed, a.info.rcv_link_speed),
            (12345, 67890)
        );
        indication.StatusBufferSize = 1;
        status((&mut *a as *mut Adapter).cast(), &mut indication);
        assert_eq!(a.info.xmit_link_speed, 12345);
        assert_eq!(
            pnp(
                (&mut *a as *mut Adapter).cast(),
                &mut NET_PNP_EVENT_NOTIFICATION::default()
            ),
            FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
        );
    }
    state(|s| {
        assert_eq!(
            s.events
                .iter()
                .filter(|e| matches!(e, Event::Status))
                .count(),
            2
        )
    });
}
