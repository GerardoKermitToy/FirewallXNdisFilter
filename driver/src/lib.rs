#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(debug_assertions)]
compile_error!("Build the kernel driver with --release only.");
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("The driver supports Windows x64 only.");

extern crate alloc;

mod adapter_info;
mod device_control;
#[cfg(feature = "native-wdk")]
mod native;
#[cfg(feature = "native-wdk")]
mod native_packet;
#[cfg(feature = "native-wdk")]
mod native_wfp;
mod packet_snapshot;
mod send_guard;
mod target_config;
#[cfg(feature = "native-wdk")]
mod wdk;
mod wfp;

use alloc::vec::Vec;
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ffi::c_void,
    panic::PanicInfo,
};
use hyperv_policy::{
    cache::{CLEANUP_SLOTS_PER_BATCH, CacheAllocator, CacheWork},
    engine::{
        Action, BandwidthTable, BandwidthWork, Engine, Finish, Submission, VerdictError,
        allocate_record,
    },
    packet::{self, NdisPath, Packet, SNAPSHOT},
};
use hyperv_protocol::{self as wire, Command};
use likely_stable::unlikely;
use packet_snapshot::{ParserScratch, Snapshot, SnapshotError};
use send_guard::with_send_guard;

type Handle = *mut c_void;
const SUCCESS: i32 = 0;
const INVALID_PARAMETER: i32 = 0xc000000du32 as i32;
const NOT_SUPPORTED: i32 = 0xc00000bbu32 as i32;

#[unsafe(no_mangle)]
pub static HV_API_VERSION: [u8; 4] = wire::VERSION;

unsafe extern "C" {
    fn hv_initialize(driver: Handle, registry: Handle) -> i32;
    fn hv_lock() -> usize;
    fn hv_unlock(irql: usize);
    fn hv_publish_state(ready: u32, online: u32, pending: u32, cached: u32);
    fn hv_request_cache_cleanup();
    fn hv_now() -> u64;
    fn hv_allocate(size: usize) -> *mut u8;
    fn hv_free(data: *mut u8, size: usize);
    fn hv_cache_allocate(size: usize) -> *mut u8;
    fn hv_cache_free(data: *mut u8, size: usize);
    fn hv_finish(nbl: usize, finish: u32);
    fn hv_first_nb(nbl: usize) -> Handle;
    fn hv_next_nb(nb: Handle) -> Handle;
    fn hv_snapshot(
        nb: Handle,
        nbl: usize,
        out: *mut u8,
        cap: u32,
        copied: *mut u32,
        trusted: *mut u32,
        frame_len: *mut u32,
        offload: *mut u32,
    ) -> u32;
    fn hv_snapshot_view(
        nb: Handle,
        nbl: usize,
        storage: *mut u8,
        cap: u32,
        copied: *mut u32,
        trusted: *mut u32,
        frame_len: *mut u32,
        offload: *mut u32,
    ) -> *const u8;
    fn hv_bugcheck() -> !;
}
struct NonPagedAllocator;
// SAFETY: the shim returns nonpaged pool aligned to at least 16 bytes and
// bugchecks if ExAllocatePool2 fails.
unsafe impl GlobalAlloc for NonPagedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if unlikely(layout.align() > 16) {
            return core::ptr::null_mut();
        }
        unsafe { hv_allocate(layout.size()) }
    }
    unsafe fn dealloc(&self, data: *mut u8, layout: Layout) {
        unsafe { hv_free(data, layout.size()) }
    }
}
#[global_allocator]
static ALLOCATOR: NonPagedAllocator = NonPagedAllocator;

struct State(UnsafeCell<Engine>);
// The native Rust layer initializes the spin lock before ANY callback or control device is
// published. Every engine access is under it; no references escape with_state.
unsafe impl Sync for State {}
unsafe fn cache_allocate(size: usize) -> *mut u8 {
    unsafe { hv_cache_allocate(size) }
}
unsafe fn cache_free(data: *mut u8, size: usize) {
    unsafe { hv_cache_free(data, size) }
}
// SAFETY: matching nonpaged pool functions; buffers are freed unlocked.
const CACHE_ALLOCATOR: CacheAllocator = unsafe { CacheAllocator::new(cache_allocate, cache_free) };
static STATE: State = State(UnsafeCell::new(Engine::with_cache_allocator(
    CACHE_ALLOCATOR,
)));
fn with_state<R>(f: impl FnOnce(&mut Engine) -> R) -> R {
    // SAFETY: no recursion into this lock; no NDIS forwarding/completion while held.
    unsafe {
        let irql = hv_lock();
        let engine = &mut *STATE.0.get();
        let result = f(engine);
        // Publish read readiness and O(1) maintenance candidates while locked.
        // Only level transitions arm/cancel timers; no NDIS calls occur here.
        hv_publish_state(
            engine.has_events() as u32,
            engine.is_online() as u32,
            (engine.pending_count() != 0) as u32,
            (engine.cache_candidates() != 0) as u32,
        );
        hv_unlock(irql);
        result
    }
}
// Decide once under PolicyLock. Only a genuinely missing bandwidth resource
// causes synchronous unlocked preparation and a retry of accounting alone.
fn with_bandwidth<R>(f: impl FnOnce(&mut Engine, &mut BandwidthWork, u64) -> R) -> R {
    let mut work = BandwidthWork::defer_missing();
    let result = with_state(|engine| f(engine, &mut work, unsafe { hv_now() }));
    if let Some(deferred) = work.take_deferred() {
        let mut plan = deferred.plan();
        loop {
            // Unused reserves and retired indexes are freed outside PolicyLock.
            drop(work);
            work = BandwidthWork::prepare(Some(plan));
            match with_state(|engine| engine.complete_bandwidth(&deferred, &mut work)) {
                Some(next) => plan = next,
                None => break,
            }
        }
    }
    result
}
fn finish_value(finish: Finish) -> u32 {
    match finish {
        Finish::Allow => 0,
        Finish::Drop => 1,
        Finish::Cancel => 2,
    }
}
fn finish_code(finish: Finish) -> i32 {
    finish_value(finish) as i32
}
fn finish(a: Action) {
    // SAFETY: claiming a pending entry transfers its one owned NBL. The native Rust
    // layer retains its NDIS module or independent WFP packet rundown until finish.
    unsafe { hv_finish(a.nbl, finish_value(a.finish)) }
}
// Old per-interface cache banks move out one at a time, keeping the kernel
// stack fixed-size. No cache pool allocation/free occurs under PolicyLock.
fn reclaim_retired() {
    while let Some(retired) = with_state(|e| e.take_retired_caches()) {
        drop(retired);
    }
    while let Some(retired) = with_state(|e| e.take_retired_storage()) {
        drop(retired);
    }
}
fn drain() {
    loop {
        let action = with_bandwidth(|e, work, now| e.take_due_with_work(now, work));
        if let Some(action) = action {
            finish(action)
        } else {
            break;
        }
    }
}
fn report_bandwidth() {
    let mut table = BandwidthTable::new();
    if !with_state(|e| e.begin_bandwidth(&mut table)) {
        return;
    }
    let epoch = table.epoch();
    table.report(
        |data| match with_state(|e| e.queue_bandwidth(epoch, data)) {
            Ok(()) => true,
            Err(data) => {
                drop(data);
                false
            }
        },
    );
    let _ = with_state(|e| e.finish_bandwidth(&mut table));
    reclaim_retired();
}
/// # Safety
/// Only the kernel loader may call this with valid DRIVER_OBJECT/UNICODE_STRING.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DriverEntry(driver: Handle, registry: Handle) -> i32 {
    // SAFETY: opaque WDK-owned objects, validated and used by the ABI shim only.
    unsafe { hv_initialize(driver, registry) }
}
#[unsafe(no_mangle)]
pub extern "C" fn HvConfigure(timeout: u32, cache_ttl: u32, fail_closed: u32) {
    with_state(|e| e.configure(timeout, cache_ttl, fail_closed != 0));
}
#[unsafe(no_mangle)]
pub extern "C" fn HvAttach(interface_index: u32) -> u32 {
    with_state(|e| e.attach(interface_index) as u32)
}
#[unsafe(no_mangle)]
pub extern "C" fn HvRestart(interface_index: u32) -> u32 {
    with_state(|e| e.restart(interface_index) as u32)
}
#[unsafe(no_mangle)]
pub extern "C" fn HvInvalidate(interface_index: u32, pause: u32) {
    with_state(|e| e.invalidate(interface_index, pause != 0));
}
#[unsafe(no_mangle)]
pub extern "C" fn HvDetach(interface_index: u32) {
    with_state(|e| e.detach(interface_index));
}
#[unsafe(no_mangle)]
pub extern "C" fn HvDrain() {
    reclaim_retired();
    drain();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvForwardStop() {
    with_state(|e| e.stop_forward());
    reclaim_retired();
    drain();
}
fn clean_caches() {
    // Fixed cutoff and bounds finish a full pass without chasing new insertions.
    // Migration only moves entries still live at a later time, so concurrent
    // growth cannot hide an entry expired at this cutoff in its new table.
    let now = unsafe { hv_now() };
    let limit = with_state(|e| e.cache_cleanup_limit());
    let mut after = 0;
    while let Some((index, slots)) = with_state(|e| e.next_cache_candidate(after, limit)) {
        after = index;
        for start in (0..slots).step_by(CLEANUP_SLOTS_PER_BATCH) {
            let mut work = CacheWork::empty();
            let active = with_state(|e| e.clean_range_with_work(index, start, now, &mut work));
            drop(work); // Retired buffers are always freed outside PolicyLock.
            if !active {
                break;
            }
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn HvCleanCaches() {
    clean_caches();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvConnect() {
    with_state(|e| e.connect());
    reclaim_retired();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvDisconnect() {
    with_state(|e| e.disconnect());
    reclaim_retired();
    drain();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvCancel(interface_index: u32, cancel: usize) {
    loop {
        let a = with_state(|e| e.cancel(interface_index, cancel));
        if let Some(a) = a {
            finish(a)
        } else {
            break;
        }
    }
}

// Copy the first NB directly into the final record allocation. Ethernet input
// leaves link-header space for the prefix; IPFORWARD input has no link header.
// No packet-sized local arrays or buffer accesses under the policy lock.
fn capture_packet(nb: Handle, nbl: usize, packet: &Packet) -> Result<Option<Vec<u8>>, ()> {
    let layout = packet.capture_layout().ok_or(())?;
    let Some(mut data) = allocate_record(layout.record_len) else {
        return Ok(None);
    };
    let (mut copied, mut trusted, mut frame_len, mut offload) = (0, 0, 0, 0);
    // SAFETY: the C caller owns this NB until HvClassify returns or publishes its
    // pending NBL. The destination is an exclusively owned nonpaged allocation.
    let ok = unsafe {
        hv_snapshot(
            nb,
            nbl,
            data[layout.frame_start..].as_mut_ptr(),
            layout.frame_len as u32,
            &mut copied,
            &mut trusted,
            &mut frame_len,
            &mut offload,
        )
    };
    if unlikely(
        ok == 0 || copied as usize != layout.frame_len || trusted < copied || frame_len < copied,
    ) {
        return Err(());
    }
    Ok(Some(data))
}

#[derive(Clone, Copy)]
enum PacketInput {
    Ethernet(NdisPath, usize),
    Ip(wire::Direction, bool, bool),
}
impl PacketInput {
    fn is_forward(self) -> bool {
        matches!(self, Self::Ip(..))
    }
    fn direction(self) -> wire::Direction {
        match self {
            Self::Ethernet(path, _) => path.direction(),
            Self::Ip(direction, _, _) => direction,
        }
    }
    fn cancel(self) -> Option<usize> {
        match self {
            Self::Ethernet(NdisPath::Send, cancel) => Some(cancel),
            _ => None,
        }
    }
    fn parse(
        self,
        bytes: &[u8],
        trusted: usize,
        length: usize,
        offload: bool,
    ) -> Result<Option<Packet>, packet::ParseError> {
        match self {
            Self::Ethernet(_, _) => packet::parse(bytes, trusted, length, offload),
            Self::Ip(_, ipv6, cacheable) => {
                let mut packet = packet::parse_ip(bytes, trusted, length, ipv6, offload)?;
                packet.cacheable &= cacheable;
                Ok(Some(packet))
            }
        }
    }
}

// Return -1 when policy owns the nbl; otherwise the caller finishes it after
// releasing the per-module classification lock. Ownership stays in the native Rust layer.
#[unsafe(no_mangle)]
pub extern "C" fn HvClassify(
    nbl: usize,
    interface_index: u32,
    path: u32,
    cancel: usize,
    session: u32,
    send_guard: Handle,
) -> i32 {
    let Some(path) = NdisPath::decode(path) else {
        with_state(|e| e.malformed());
        return 1;
    };
    classify(
        nbl,
        interface_index,
        PacketInput::Ethernet(path, cancel),
        session,
        send_guard,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn HvClassifyIp(
    nbl: usize,
    interface_index: u32,
    direction: u32,
    family: u32,
    cacheable: u32,
    session: u32,
) -> i32 {
    let Some(direction) = wire::Direction::decode(direction) else {
        with_state(|e| e.malformed());
        return 1;
    };
    if !matches!(family, 4 | 6) || cacheable > 1 {
        with_state(|e| e.malformed());
        return 1;
    }
    classify(
        nbl,
        interface_index,
        PacketInput::Ip(direction, family == 6, cacheable != 0),
        session,
        core::ptr::null_mut(),
    )
}
fn classify(
    nbl: usize,
    interface_index: u32,
    input: PacketInput,
    session: u32,
    send_guard: Handle,
) -> i32 {
    let mut first: Option<Packet> = None;
    let mut saw_non_ip = false;
    let mut nb = unsafe { hv_first_nb(nbl) };
    if unlikely(nb.is_null()) {
        with_state(|e| e.malformed());
        return 1;
    }
    // Borrow a contiguous prefix; lazily reuse nonpaged scratch for split MDLs.
    // Packet owns every field that survives parsing, including its L2 identity.
    let mut scratch = ParserScratch::default();
    while !nb.is_null() {
        let view = scratch.read(
            |storage| {
                let mut view = Snapshot::default();
                view.data = unsafe {
                    hv_snapshot_view(
                        nb,
                        nbl,
                        storage,
                        SNAPSHOT as u32,
                        &mut view.copied,
                        &mut view.trusted,
                        &mut view.frame_len,
                        &mut view.offload,
                    )
                };
                view
            },
            |length| alloc::vec![0; length],
        );
        let view = match view {
            Ok(view) => view,
            Err(error) => {
                with_state(|e| match error {
                    SnapshotError::Resource => e.resource_drop(),
                    SnapshotError::Malformed => e.malformed(),
                });
                return 1;
            }
        };
        // SAFETY: the shim returns the readable bounded NB prefix or our own
        // scratch. No view escapes parsing or survives pending publication.
        let data = unsafe { core::slice::from_raw_parts(view.data, view.copied as usize) };
        let parsed = input.parse(
            data,
            view.trusted as usize,
            view.frame_len as usize,
            view.offload != 0,
        );
        match parsed {
            Ok(Some(p)) => {
                if unlikely(saw_non_ip) {
                    with_state(|e| e.malformed());
                    return 1;
                }
                if let Some(f) = &mut first {
                    // A single legacy request cannot describe two different flows.
                    if unlikely(f.merge(&p).is_err()) {
                        with_state(|e| e.malformed());
                        return 1;
                    }
                } else {
                    first = Some(p);
                }
            }
            Ok(None) => {
                if unlikely(first.is_some()) {
                    with_state(|e| e.malformed());
                    return 1;
                }
                saw_non_ip = true;
            }
            Err(packet::ParseError::TooLarge) => {
                with_state(|e| e.resource_drop());
                return 1;
            }
            Err(_) => {
                with_state(|e| e.malformed());
                return 1;
            }
        }
        nb = unsafe { hv_next_nb(nb) };
    }
    let Some(mut packet) = first else {
        return with_state(|e| {
            with_send_guard(send_guard, |cancelled| {
                if cancelled {
                    finish_code(Finish::Cancel)
                } else {
                    e.non_ip();
                    finish_code(Finish::Allow)
                }
            })
        });
    };
    packet.orient_direction(input.direction());
    if session == 0 {
        // The native Rust layer can close the policy rundown while the LWF remains bound.
        // Do not publish a pending event into a session that is being torn down;
        // use the configured immediate fallback instead.
        return with_state(|e| {
            with_send_guard(send_guard, |cancelled| {
                finish_code(if cancelled {
                    Finish::Cancel
                } else {
                    e.fallback()
                })
            })
        });
    }
    // Only NDIS sends have a cancel ID; WFP route metadata stays in the shim.
    let cancel = input.cancel();
    let wants_event = match with_bandwidth(|e, work, now| {
        with_send_guard(send_guard, |cancelled| {
            if cancelled {
                return Err(Action {
                    nbl,
                    finish: Finish::Cancel,
                });
            }
            if input.is_forward() {
                if !e.is_online() {
                    return Err(Action {
                        nbl,
                        finish: e.fallback(),
                    });
                }
                if !e.ensure_forward(interface_index) {
                    e.resource_drop();
                    return Err(Action {
                        nbl,
                        finish: Finish::Drop,
                    });
                }
            }
            e.preflight_with_work(interface_index, &packet, nbl, now, work)
        })
    }) {
        Ok(wants_event) => wants_event,
        Err(action) => return finish_code(action.finish),
    };
    let mut record = if wants_event {
        match capture_packet(unsafe { hv_first_nb(nbl) }, nbl, &packet) {
            Ok(record) => record,
            Err(()) => {
                with_state(|e| {
                    e.malformed();
                    if input.is_forward() {
                        e.reap_idle_forward(interface_index);
                    }
                });
                return 1;
            }
        }
    } else {
        None
    };
    match with_bandwidth(|e, work, now| {
        with_send_guard(send_guard, |cancelled| {
            if cancelled {
                Submission::Finish(Action {
                    nbl,
                    finish: Finish::Cancel,
                })
            } else if input.is_forward() {
                e.submit_forward_with_work(interface_index, packet, nbl, now, record.take(), work)
            } else {
                e.submit_with_work(
                    interface_index,
                    packet,
                    nbl,
                    cancel,
                    now,
                    record.take(),
                    work,
                )
            }
        })
    }) {
        Submission::Pending(_) => -1,
        Submission::Finish(a) => finish_code(a.finish),
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn HvWfpInjectionError(
    status: u32,
    ipv6: u32,
    route: u32,
    completion: u32,
    destination_interface: u32,
    failures: u32,
) {
    let family = if ipv6 != 0 { "IPv6" } else { "IPv4" };
    let route = match route {
        1 => "network-receive",
        2 => "network-send",
        _ => "forward",
    };
    let stage = if completion != 0 {
        "completion"
    } else {
        "submit"
    };
    with_state(|e| {
        e.log_args(
            4,
            format_args!(
                "WFP {family} {route} injection {stage} failed: status=0x{status:08X} destination_interface={destination_interface} failures={failures}"
            ),
        );
    });
}
#[unsafe(no_mangle)]
pub extern "C" fn HvWfpFragmentDiagnostic(
    kind: u32,
    flags: u32,
    source_interface: u32,
    destination_interface: u32,
    first_nb_bytes: u32,
    chained: u32,
    count: u32,
) {
    let kind = match kind {
        0 => "fragment-permit-original",
        1 => "fragment-group-normal-policy",
        _ => "large-packet-normal-policy",
    };
    with_state(|e| {
        e.log_args(
            3,
            format_args!(
                "WFP DIAGNOSTIC IPv4 {kind}: flags=0x{flags:08X} source_interface={source_interface} destination_interface={destination_interface} first_nb_bytes={first_nb_bytes} chained={chained} count={count}"
            ),
        );
    });
}
#[unsafe(no_mangle)]
pub extern "C" fn HvWfpStatus(healthy: u32) {
    with_state(|e| {
        if healthy != 0 {
            e.log(
                3,
                "WFP IPFORWARD V4/V6 registration is ready for all forwarding interfaces",
            );
        } else {
            e.log(
                4,
                "WFP IPFORWARD is unavailable (BFE or registration); NDIS filtering is independent",
            );
        }
    });
}
#[unsafe(no_mangle)]
pub extern "C" fn HvResourceDrop() {
    with_state(|e| e.resource_drop());
}

// Nonblocking stream copy for the native Rust layer's cancel-safe read worker. Empty
// streams stay pending in the shim; This policy stream never waits; the native Rust module owns read IRPs.
/// # Safety
/// `out` is an exclusively writable nonpaged system buffer of at least `len`
/// bytes, valid for the entire call, supplied by the buffered IRP shim.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvRead(out: *mut u8, len: u32) -> u32 {
    if unlikely(out.is_null() || len == 0) {
        return 0;
    }
    // SAFETY: the shim provides the system buffer and its exact validated size.
    let out = unsafe { core::slice::from_raw_parts_mut(out, len as usize) };
    let mut written = 0;
    // Bound work under PolicyLock, not the read size. One completion can span
    // as many chunks/records as fit the caller's Windows I/O buffer.
    for chunk in out.chunks_mut(64 * 1024) {
        let n = with_state(|e| e.read(chunk));
        written += n;
        if n < chunk.len() {
            break;
        }
    }
    written as u32
}
/// # Safety
/// `data` is a readable nonpaged system buffer of at least `len` bytes, immutable
/// for the call and serialized with client cleanup by the native Rust layer's I/O mutex.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvWrite(data: *const u8, len: u32) -> i32 {
    if unlikely(data.is_null() || len == 0) {
        return INVALID_PARAMETER;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, len as usize) };
    if let Err(error) = wire::validate_commands(bytes) {
        return match error {
            wire::Error::Unsupported => NOT_SUPPORTED,
            _ => INVALID_PARAMETER,
        };
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let Ok((command, next)) = wire::next_command(rest) else {
            return INVALID_PARAMETER;
        };
        match command {
            Command::Shutdown => {
                with_state(|e| e.disconnect());
                reclaim_retired();
                drain();
            }
            Command::Verdict { id, verdict } => loop {
                // Expiry and topology changes may win the race. A stale ID is a
                // harmless no-op (never a cache write), as on asynchronous kext I/O.
                let plan = with_state(|e| e.cache_plan(id, verdict, unsafe { hv_now() }));
                let mut work = CacheWork::prepare(plan);
                let result = with_bandwidth(|e, bandwidth, now| {
                    e.verdict_with_work(id, verdict, now, &mut work, bandwidth)
                });
                drop(work);
                match result {
                    Ok(action) => {
                        finish(action);
                        break;
                    }
                    Err(VerdictError::RetryCache) => reclaim_retired(),
                    Err(VerdictError::NotFound) => {
                        drain();
                        break;
                    }
                }
            },
            Command::ClearCache => {
                with_state(|e| e.clear_cache());
                reclaim_retired();
            }
            Command::GetLogs => {} // Log records are already queued.
            Command::GetBandwidth => report_bandwidth(),
            Command::MemoryStats => with_state(|e| e.memory_stats()),
            Command::CleanEnded => {
                reclaim_retired();
                if with_state(|e| e.cache_candidates() != 0) {
                    // The shim coalesces explicit requests with periodic work.
                    unsafe { hv_request_cache_cleanup() };
                }
            }
        }
        rest = next;
    }
    SUCCESS
}
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    unsafe { hv_bugcheck() }
}
// MSVC's kernel CRT archive supplies the actual memory primitives.
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;
