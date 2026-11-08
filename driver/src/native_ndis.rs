//! Native NDIS registration, adapter lifetime and packet ownership.
//!
//! WDK descriptors/callbacks use the generated ABI. Policy receives only the
//! observed interface index and owns an NBL only after a negative classify result.

use super::*;
use crate::{
    adapter_info::{self, AdapterInfoAction},
    native_packet as packet,
};
use firewallx_protocol as wire;
use likely_stable::unlikely;

#[cfg(not(test))]
use crate::{self as policy, wdk as api};
#[cfg(test)]
use tests::calls as api;
#[cfg(test)]
use tests::calls as policy;

#[cfg(test)]
#[path = "native_ndis_tests.rs"]
mod tests;

const MAX_STAGING_ATTEMPTS: u32 = 8;
const FINISH_CANCEL: u32 = 2;

// A send callback owns this stack node until it has processed its whole chain.
// The adapter lock protects the list, the unprocessed NBL links, and the
// current classification's cancellation flag. Published NBLs are never kept
// here: policy owns them and an early verdict may already have freed them.
pub(super) struct SendBatch {
    adapter: *mut Adapter,
    previous: *mut SendBatch,
    next: *mut SendBatch,
    remaining: PNET_BUFFER_LIST,
    current_cancel: usize,
    current: bool,
    cancelled: bool,
}

// Policy calls these only while holding PolicyLock. Cancellation never takes
// PolicyLock while holding the adapter lock, so publication and cancellation
// are serialized without completing NBLs under either lock.
#[unsafe(no_mangle)]
unsafe extern "C" fn fwx_send_guard_lock(guard: *mut core::ffi::c_void) -> u32 {
    unsafe {
        let batch = guard.cast::<SendBatch>();
        ndis_lock(addr_of_mut!((*(*batch).adapter).lock));
        u32::from((*batch).cancelled)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn fwx_send_guard_unlock(guard: *mut core::ffi::c_void) {
    unsafe {
        let batch = guard.cast::<SendBatch>();
        ndis_unlock(addr_of_mut!((*(*batch).adapter).lock));
    }
}

/// Choose the greatest supported runtime, rather than advertising the build
/// machine's WDK version on an older NDIS runtime.
pub(super) fn ndis_version(runtime: u32) -> u32 {
    const VERSIONS: [u32; 15] = [
        NDIS_RUNTIME_VERSION_689,
        NDIS_RUNTIME_VERSION_688,
        NDIS_RUNTIME_VERSION_687,
        NDIS_RUNTIME_VERSION_686,
        NDIS_RUNTIME_VERSION_685,
        NDIS_RUNTIME_VERSION_684,
        NDIS_RUNTIME_VERSION_683,
        NDIS_RUNTIME_VERSION_682,
        NDIS_RUNTIME_VERSION_681,
        NDIS_RUNTIME_VERSION_680,
        NDIS_RUNTIME_VERSION_670,
        NDIS_RUNTIME_VERSION_660,
        NDIS_RUNTIME_VERSION_651,
        NDIS_RUNTIME_VERSION_650,
        NDIS_RUNTIME_VERSION_640,
    ];
    VERSIONS.into_iter().find(|&v| runtime >= v).unwrap_or(0)
}

/// The OOB array ends at a different named SDK slot on older runtimes.
pub(super) fn nbl_info_count(version: u32) -> u32 {
    if version >= NDIS_RUNTIME_VERSION_680 {
        FWX_WDK_NBL_INFO_COUNT as u32
    } else if version >= NDIS_RUNTIME_VERSION_650 {
        GftFlowEntryId as u32 + 1
    } else {
        RscTcpTimestampDelta as u32 + 1
    }
}

pub(super) fn configure_characteristics(
    c: &mut NDIS_FILTER_DRIVER_CHARACTERISTICS,
    version: u32,
) -> bool {
    if !(NDIS_RUNTIME_VERSION_640..=NDIS_RUNTIME_VERSION_689).contains(&version) {
        return false;
    }
    // No direct/synchronous OID interception, switch extension or URO opt-out.
    *c = unsafe { zeroed() };
    c.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS as u8;
    if version >= NDIS_RUNTIME_VERSION_680 {
        c.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_3 as u8;
        c.Header.Size = FWX_WDK_FILTER_REV3_SIZE as u16;
    } else {
        c.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2 as u8;
        c.Header.Size = FWX_WDK_FILTER_REV2_SIZE as u16;
    }
    c.MajorNdisVersion = (version >> 16) as u8;
    c.MinorNdisVersion = version as u8;
    c.MajorDriverVersion = 0;
    c.MinorDriverVersion = 3;
    c.FriendlyName = wide!("FirewallXNdisFilter Rust Host Adapter LWF");
    c.UniqueName = wide!("{6E76EAD1-7BCB-49C4-9547-D3E6B3488F71}");
    c.ServiceName = wide!("FirewallXNdisFilter");
    c.AttachHandler = Some(filter_attach);
    c.DetachHandler = Some(filter_detach);
    c.RestartHandler = Some(filter_restart);
    c.PauseHandler = Some(filter_pause);
    c.SendNetBufferListsHandler = Some(send);
    c.SendNetBufferListsCompleteHandler = Some(send_complete);
    c.CancelSendNetBufferListsHandler = Some(cancel_send);
    c.ReceiveNetBufferListsHandler = Some(receive);
    c.ReturnNetBufferListsHandler = Some(return_receive);
    c.OidRequestHandler = Some(oid);
    c.OidRequestCompleteHandler = Some(oid_complete);
    c.CancelOidRequestHandler = Some(cancel_oid);
    c.NetPnPEventHandler = Some(pnp);
    c.StatusHandler = Some(status);
    true
}

unsafe fn send_complete_flags() -> u32 {
    if unsafe { api::KeGetCurrentIrql() } == DISPATCH_LEVEL as u8 {
        NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL
    } else {
        0
    }
}

unsafe fn return_flags() -> u32 {
    if unsafe { api::KeGetCurrentIrql() } == DISPATCH_LEVEL as u8 {
        NDIS_RETURN_FLAGS_DISPATCH_LEVEL
    } else {
        0
    }
}

/// Caller holds the adapter admission lock. Overflow must not lose ownership.
unsafe fn retain_active_locked(a: *mut Adapter) {
    unsafe {
        (*a).active = (*a).active.checked_add(1).unwrap_or_else(|| fwx_bugcheck());
    }
}

unsafe fn release_active(a: *mut Adapter, count: u64) {
    unsafe {
        // PauseComplete can synchronously detach/free the adapter. Capture the
        // filter first, and never touch a again after making that final call.
        let filter = (*a).filter;
        ndis_lock(addr_of_mut!((*a).lock));
        (*a).active = (*a)
            .active
            .checked_sub(count)
            .unwrap_or_else(|| fwx_bugcheck());
        let complete = (*a).active == 0 && (*a).pause_pending != 0;
        if complete {
            (*a).pause_pending = 0;
        }
        ndis_unlock(addr_of_mut!((*a).lock));
        if complete {
            api::NdisFPauseComplete(filter);
        }
    }
}

unsafe fn set_filter_running(a: *mut Adapter, running: bool) {
    unsafe {
        ndis_lock(addr_of_mut!((*a).lock));
        let irql = spin_lock(addr_of_mut!(ADAPTER_INFO_LOCK));
        let delta = i64::from(running) - i64::from((*a).running != 0);
        let old = FILTERED_DEVICE_COUNT.load(Ordering::SeqCst);
        if old < 0 || old.checked_add(delta).is_none_or(|n| n < 0) {
            fwx_bugcheck();
        }
        (*a).running = u8::from(running);
        FILTERED_DEVICE_COUNT.fetch_add(delta, Ordering::SeqCst);
        if running {
            (*a).info.flags |= wire::ADAPTER_RUNNING;
        } else {
            (*a).info.flags &= !wire::ADAPTER_RUNNING;
        }
        spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
        ndis_unlock(addr_of_mut!((*a).lock));
    }
}

unsafe fn begin_io(a: *mut Adapter) -> (bool, bool) {
    unsafe {
        // Cleanup closes this shared session before waiting for classifiers.
        // Even a rejected callback retains its adapter until EndIo.
        let session = api::ExAcquireRundownProtection(addr_of_mut!(CLASSIFICATION_RUNDOWN)) != 0;
        ndis_lock(addr_of_mut!((*a).lock));
        let running = (*a).running != 0;
        retain_active_locked(a);
        ndis_unlock(addr_of_mut!((*a).lock));
        (running, session)
    }
}

unsafe fn end_io(a: *mut Adapter, session: bool) {
    unsafe {
        if session {
            api::ExReleaseRundownProtection(addr_of_mut!(CLASSIFICATION_RUNDOWN));
        }
        release_active(a, 1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketCreateError {
    Paused,
    Resource,
}

unsafe fn create_ndis_packet(
    a: *mut Adapter,
    original: PNET_BUFFER_LIST,
    port: NDIS_PORT_NUMBER,
    flags: u32,
    direction: u32,
    resources: bool,
) -> Result<PNET_BUFFER_LIST, PacketCreateError> {
    unsafe {
        ndis_lock(addr_of_mut!((*a).lock));
        if (*a).running == 0 {
            ndis_unlock(addr_of_mut!((*a).lock));
            return Err(PacketCreateError::Paused);
        }
        retain_active_locked(a);
        ndis_unlock(addr_of_mut!((*a).lock));
        let nbl = if resources {
            packet::copy_receive(
                (*a).filter,
                (*a).nbl_pool,
                (*a).nb_pool,
                original,
                nbl_info_count(FILTER_NDIS_VERSION),
            )
        } else {
            original
        };
        if unlikely(nbl.is_null()) {
            release_active(a, 1);
            return Err(PacketCreateError::Resource);
        }
        let context = packet::allocate_packet_context(nbl);
        (*context).adapter = a.cast();
        (*context).port = port;
        (*context).flags = if resources { 0 } else { flags };
        (*context).direction = direction;
        (*context).owner = packet::OWNER_NDIS;
        (*context).copied = u8::from(resources);
        Ok(nbl)
    }
}

/// Convert the TCP LSO transmit OOB to its completion form when this filter
/// completes a send locally. Normal forwarded sends retain lower-driver OOB.
unsafe fn complete_local_lso(nbl: PNET_BUFFER_LIST) -> bool {
    unsafe {
        let value = (*nbl).NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize];
        if value as usize as u32 == 0 {
            return true;
        }
        let mut info: NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO = zeroed();
        info.__bindgen_anon_1.Value = value;
        let version = info.__bindgen_anon_1.Transmit.Type();
        let mut completion: NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO = zeroed();
        if version == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE {
            completion
                .__bindgen_anon_1
                .LsoV2TransmitComplete
                .set_Type(version);
        } else if version == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE {
            // Even an unsuccessful completion must not return transmit-form
            // metadata as the TCP-payload completion field.
            (*nbl).NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] = null_mut();
            let nb = packet::first_nb(nbl);
            if nb.is_null() || !packet::next_nb(nb).is_null() {
                return false;
            }
            let offset = info.__bindgen_anon_1.LsoV1Transmit.TcpHeaderOffset();
            let length = packet::data_length(nb);
            if offset > length || length - offset < 20 {
                return false;
            }
            let Some(data_offset) = packet::read_byte(nb, offset + 12) else {
                return false;
            };
            let header = u32::from(data_offset >> 4) * 4;
            if header < 20 || header > length - offset {
                return false;
            }
            let payload = length - offset - header;
            completion
                .__bindgen_anon_1
                .LsoV1TransmitComplete
                .set_TcpPayload(payload);
            if completion
                .__bindgen_anon_1
                .LsoV1TransmitComplete
                .TcpPayload()
                != payload
            {
                return false;
            }
            completion
                .__bindgen_anon_1
                .LsoV1TransmitComplete
                .set_Type(version);
        } else {
            return false;
        }
        (*nbl).NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] =
            completion.__bindgen_anon_1.Value;
        true
    }
}

/// Finish one claimed NBL. Publishing a pending NBL transfers its ownership to
/// policy; the classifier must not inspect it after that publication.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn fwx_finish(nbl_address: usize, finish: u32) {
    unsafe {
        let nbl = nbl_address as PNET_BUFFER_LIST;
        let context = packet::packet_context(nbl);
        if (*context).owner != packet::OWNER_NDIS {
            fwx_bugcheck();
        }
        let a = (*context).adapter.cast::<Adapter>();
        ndis_lock(addr_of_mut!((*a).lock));
        let allow = finish == 0 && (*a).running != 0;
        if allow {
            (*context).forwarded = 1;
        }
        ndis_unlock(addr_of_mut!((*a).lock));
        let send = (*context).direction == SEND;
        if allow {
            let port = (*context).port;
            if send {
                let mut flags = (*context).flags & !NDIS_SEND_FLAGS_DISPATCH_LEVEL;
                if api::KeGetCurrentIrql() == DISPATCH_LEVEL as u8 {
                    flags |= NDIS_SEND_FLAGS_DISPATCH_LEVEL;
                }
                // These calls may complete inline and free context, nbl and a.
                api::NdisFSendNetBufferLists((*a).filter, nbl, port, flags);
            } else {
                let mut flags = (*context).flags
                    & !(NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL | NDIS_RECEIVE_FLAGS_RESOURCES);
                if api::KeGetCurrentIrql() == DISPATCH_LEVEL as u8 {
                    flags |= NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL;
                }
                api::NdisFIndicateReceiveNetBufferLists((*a).filter, nbl, port, 1, flags);
            }
            return;
        }
        let copied = (*context).copied != 0;
        // Upper/lower may free the original immediately. Remove our context
        // before transferring ownership, and keep the adapter reference till last.
        packet::free_packet_context(nbl);
        if send {
            let lso_complete = complete_local_lso(nbl);
            if !lso_complete {
                policy::FwxInvalidLso((*a).interface_index);
            }
            (*nbl).__bindgen_anon_2.Status = if finish == FINISH_CANCEL {
                FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
            } else if !lso_complete {
                FWX_WDK_NDIS_RESOURCES as NDIS_STATUS
            } else {
                FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
            };
            api::NdisFSendNetBufferListsComplete((*a).filter, nbl, send_complete_flags());
        } else if copied {
            packet::free_receive_copy(nbl);
        } else {
            api::NdisFReturnNetBufferLists((*a).filter, nbl, return_flags());
        }
        release_active(a, 1);
    }
}

unsafe fn register_send_batch(a: *mut Adapter, batch: *mut SendBatch) {
    unsafe {
        (*batch).next = (*a).send_batches;
        if !(*batch).next.is_null() {
            (*(*batch).next).previous = batch;
        }
        (*a).send_batches = batch;
    }
}

unsafe fn unregister_send_batch(a: *mut Adapter, batch: *mut SendBatch) {
    unsafe {
        if !(*batch).remaining.is_null() || (*batch).current {
            fwx_bugcheck();
        }
        let previous = (*batch).previous;
        let next = (*batch).next;
        if previous.is_null() {
            if (*a).send_batches != batch {
                fwx_bugcheck();
            }
            (*a).send_batches = next;
        } else {
            if (*previous).next != batch {
                fwx_bugcheck();
            }
            (*previous).next = next;
        }
        if !next.is_null() {
            if (*next).previous != batch {
                fwx_bugcheck();
            }
            (*next).previous = previous;
        }
    }
}

unsafe fn next_send(batch: *mut SendBatch) -> PNET_BUFFER_LIST {
    unsafe {
        let a = (*batch).adapter;
        ndis_lock(addr_of_mut!((*a).lock));
        let original = (*batch).remaining;
        if !original.is_null() {
            (*batch).remaining = packet::next_nbl(original);
            packet::set_next_nbl(original, null_mut());
            (*batch).current_cancel =
                (*original).NetBufferListInfo[NetBufferListCancelId as usize] as usize;
            (*batch).current = true;
            (*batch).cancelled = false;
        }
        ndis_unlock(addr_of_mut!((*a).lock));
        original
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn classify_chain(
    a: *mut Adapter,
    mut chain: PNET_BUFFER_LIST,
    port: NDIS_PORT_NUMBER,
    flags: u32,
    direction: u32,
    resources: bool,
    admitted: bool,
    session: bool,
    batch: *mut SendBatch,
) {
    unsafe {
        loop {
            let original = if batch.is_null() {
                let original = chain;
                if !original.is_null() {
                    chain = packet::next_nbl(original);
                    if !resources {
                        packet::set_next_nbl(original, null_mut());
                    }
                }
                original
            } else {
                next_send(batch)
            };
            if original.is_null() {
                break;
            }
            let mut nbl = Err(PacketCreateError::Paused);
            let mut result = 1;
            // A closed controller session still parses non-IP frames and selects
            // immediate policy fallback for IP; it does not close NDIS admission.
            if admitted {
                let mut state: LOCK_STATE_EX = zeroed();
                api::NdisAcquireRWLockRead((*a).classification_lock, &mut state, 0);
                nbl = create_ndis_packet(a, original, port, flags, direction, resources);
                if let Ok(nbl) = nbl {
                    let cancel = if direction == SEND {
                        (*original).NetBufferListInfo[NetBufferListCancelId as usize] as usize
                    } else {
                        0
                    };
                    result = policy::FwxClassify(
                        nbl as usize,
                        (*a).interface_index,
                        direction,
                        cancel,
                        u32::from(session),
                        batch.cast(),
                    );
                }
                api::NdisReleaseRWLock((*a).classification_lock, &mut state);
            }
            let cancelled = if batch.is_null() {
                false
            } else {
                ndis_lock(addr_of_mut!((*a).lock));
                let cancelled = (*batch).cancelled;
                (*batch).current = false;
                ndis_unlock(addr_of_mut!((*a).lock));
                cancelled
            };
            match nbl {
                Err(reason) => {
                    match reason {
                        PacketCreateError::Paused => policy::FwxPausedDrop((*a).interface_index),
                        PacketCreateError::Resource => {
                            policy::FwxResourceDrop((*a).interface_index)
                        }
                    }
                    if direction == SEND {
                        // Preserve cancellation/pause status even if LSO metadata is malformed.
                        if !complete_local_lso(original) {
                            policy::FwxInvalidLso((*a).interface_index);
                        }
                        (*original).__bindgen_anon_2.Status = if cancelled {
                            FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
                        } else if reason == PacketCreateError::Paused {
                            FWX_WDK_NDIS_PAUSED as NDIS_STATUS
                        } else {
                            FWX_WDK_NDIS_RESOURCES as NDIS_STATUS
                        };
                        api::NdisFSendNetBufferListsComplete(
                            (*a).filter,
                            original,
                            send_complete_flags(),
                        );
                    } else if !resources {
                        api::NdisFReturnNetBufferLists((*a).filter, original, return_flags());
                    }
                }
                Ok(nbl) if result >= 0 => {
                    let finish = if cancelled && result != 0 {
                        FINISH_CANCEL
                    } else {
                        result as u32
                    };
                    fwx_finish(nbl as usize, finish);
                }
                Ok(_) => {} // Policy owns the NBL; it may already have been freed.
            }
        }
    }
}

pub(super) unsafe extern "C" fn send(
    context: NDIS_HANDLE,
    chain: PNET_BUFFER_LIST,
    port: NDIS_PORT_NUMBER,
    flags: u32,
) {
    unsafe {
        let a = context.cast::<Adapter>();
        let mut batch = SendBatch {
            adapter: a,
            previous: null_mut(),
            next: null_mut(),
            remaining: chain,
            current_cancel: 0,
            current: false,
            cancelled: false,
        };
        let batch = addr_of_mut!(batch);
        let session = api::ExAcquireRundownProtection(addr_of_mut!(CLASSIFICATION_RUNDOWN)) != 0;
        ndis_lock(addr_of_mut!((*a).lock));
        let admitted = (*a).running != 0;
        retain_active_locked(a);
        register_send_batch(a, batch);
        ndis_unlock(addr_of_mut!((*a).lock));
        classify_chain(
            a,
            null_mut(),
            port,
            flags,
            SEND,
            false,
            admitted,
            session,
            batch,
        );
        ndis_lock(addr_of_mut!((*a).lock));
        unregister_send_batch(a, batch);
        ndis_unlock(addr_of_mut!((*a).lock));
        end_io(a, session);
    }
}

pub(super) unsafe extern "C" fn send_complete(
    context: NDIS_HANDLE,
    mut chain: PNET_BUFFER_LIST,
    flags: u32,
) {
    unsafe {
        let a = context.cast::<Adapter>();
        ndis_lock(addr_of_mut!((*a).lock));
        retain_active_locked(a);
        ndis_unlock(addr_of_mut!((*a).lock));
        while !chain.is_null() {
            let nbl = chain;
            chain = packet::next_nbl(nbl);
            packet::set_next_nbl(nbl, null_mut());
            let owned = packet::packet_context(nbl);
            if (*owned).adapter != a.cast()
                || (*owned).owner != packet::OWNER_NDIS
                || (*owned).forwarded == 0
                || (*owned).direction != SEND
            {
                fwx_bugcheck();
            }
            let status = (*nbl).__bindgen_anon_2.Status;
            if status != FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
                && status != FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS
            {
                policy::FwxSendFailure((*a).interface_index, status);
            }
            packet::free_packet_context(nbl);
            api::NdisFSendNetBufferListsComplete((*a).filter, nbl, flags);
            release_active(a, 1);
        }
        release_active(a, 1);
    }
}

pub(super) unsafe extern "C" fn cancel_send(context: NDIS_HANDLE, cancel: PVOID) {
    unsafe {
        let a = context.cast::<Adapter>();
        let mut cancelled = null_mut();
        let mut tail: PNET_BUFFER_LIST = null_mut();
        ndis_lock(addr_of_mut!((*a).lock));
        retain_active_locked(a);
        let mut batch = (*a).send_batches;
        while !batch.is_null() {
            if (*batch).current && (*batch).current_cancel == cancel as usize {
                (*batch).cancelled = true;
            }
            let mut previous: PNET_BUFFER_LIST = null_mut();
            let mut nbl = (*batch).remaining;
            while !nbl.is_null() {
                let next = packet::next_nbl(nbl);
                if ptr::eq(
                    (*nbl).NetBufferListInfo[NetBufferListCancelId as usize],
                    cancel,
                ) {
                    if previous.is_null() {
                        (*batch).remaining = next;
                    } else {
                        packet::set_next_nbl(previous, next);
                    }
                    packet::set_next_nbl(nbl, null_mut());
                    if tail.is_null() {
                        cancelled = nbl;
                    } else {
                        packet::set_next_nbl(tail, nbl);
                    }
                    tail = nbl;
                } else {
                    previous = nbl;
                }
                nbl = next;
            }
            batch = (*batch).next;
        }
        ndis_unlock(addr_of_mut!((*a).lock));
        policy::FwxCancel((*a).interface_index, cancel as usize);
        while !cancelled.is_null() {
            let nbl = cancelled;
            cancelled = packet::next_nbl(nbl);
            packet::set_next_nbl(nbl, null_mut());
            if !complete_local_lso(nbl) {
                policy::FwxInvalidLso((*a).interface_index);
            }
            (*nbl).__bindgen_anon_2.Status = FWX_WDK_NDIS_SEND_ABORTED as NDIS_STATUS;
            api::NdisFSendNetBufferListsComplete((*a).filter, nbl, send_complete_flags());
        }
        api::NdisFCancelSendNetBufferLists((*a).filter, cancel);
        release_active(a, 1);
    }
}

pub(super) unsafe extern "C" fn receive(
    context: NDIS_HANDLE,
    chain: PNET_BUFFER_LIST,
    port: NDIS_PORT_NUMBER,
    _count: u32,
    flags: u32,
) {
    unsafe {
        let a = context.cast::<Adapter>();
        let (admitted, session) = begin_io(a);
        classify_chain(
            a,
            chain,
            port,
            flags,
            RECEIVE,
            flags & NDIS_RECEIVE_FLAGS_RESOURCES != 0,
            admitted,
            session,
            null_mut(),
        );
        end_io(a, session);
    }
}

pub(super) unsafe extern "C" fn return_receive(
    context: NDIS_HANDLE,
    mut chain: PNET_BUFFER_LIST,
    flags: u32,
) {
    unsafe {
        let a = context.cast::<Adapter>();
        ndis_lock(addr_of_mut!((*a).lock));
        retain_active_locked(a);
        ndis_unlock(addr_of_mut!((*a).lock));
        while !chain.is_null() {
            let nbl = chain;
            chain = packet::next_nbl(nbl);
            packet::set_next_nbl(nbl, null_mut());
            let owned = packet::packet_context(nbl);
            if (*owned).adapter != a.cast()
                || (*owned).owner != packet::OWNER_NDIS
                || (*owned).forwarded == 0
                || (*owned).direction != RECEIVE
            {
                fwx_bugcheck();
            }
            let copied = (*owned).copied != 0;
            packet::free_packet_context(nbl);
            if copied {
                packet::free_receive_copy(nbl);
            } else {
                api::NdisFReturnNetBufferLists((*a).filter, nbl, flags);
            }
            release_active(a, 1);
        }
        release_active(a, 1);
    }
}

unsafe fn invalidate(a: *mut Adapter) {
    unsafe {
        let mut state: LOCK_STATE_EX = zeroed();
        api::NdisAcquireRWLockWrite((*a).classification_lock, &mut state, 0);
        policy::FwxInvalidate((*a).interface_index, 1);
        api::NdisReleaseRWLock((*a).classification_lock, &mut state);
        // NDIS completion and bulk retired-cache free happen outside both locks.
        policy::FwxDrain();
    }
}

// Match the named WDK request constants without renaming their SDK spelling.
#[allow(non_upper_case_globals)]
unsafe fn oid_copy_result(original: PNDIS_OID_REQUEST, clone: PNDIS_OID_REQUEST) {
    unsafe {
        match (*clone).RequestType {
            NdisRequestMethod => {
                let result = (*clone).DATA.METHOD_INFORMATION;
                (*original).DATA.METHOD_INFORMATION.OutputBufferLength = result.OutputBufferLength;
                (*original).DATA.METHOD_INFORMATION.BytesRead = result.BytesRead;
                (*original).DATA.METHOD_INFORMATION.BytesWritten = result.BytesWritten;
                (*original).DATA.METHOD_INFORMATION.BytesNeeded = result.BytesNeeded;
            }
            NdisRequestSetInformation => {
                let result = (*clone).DATA.SET_INFORMATION;
                (*original).DATA.SET_INFORMATION.BytesRead = result.BytesRead;
                (*original).DATA.SET_INFORMATION.BytesNeeded = result.BytesNeeded;
            }
            _ => {
                let result = (*clone).DATA.QUERY_INFORMATION;
                (*original).DATA.QUERY_INFORMATION.BytesWritten = result.BytesWritten;
                (*original).DATA.QUERY_INFORMATION.BytesNeeded = result.BytesNeeded;
            }
        }
    }
}

unsafe fn oid_free_clone(a: *mut Adapter, clone: PNDIS_OID_REQUEST) -> PNDIS_OID_REQUEST {
    unsafe {
        let original = addr_of!((*clone).SourceReserved)
            .cast::<PNDIS_OID_REQUEST>()
            .read_unaligned();
        oid_copy_result(original, clone);
        api::NdisFreeCloneOidRequest((*a).filter, clone);
        original
    }
}

pub(super) unsafe extern "C" fn oid(
    context: NDIS_HANDLE,
    request: PNDIS_OID_REQUEST,
) -> NDIS_STATUS {
    unsafe {
        let a = context.cast::<Adapter>();
        if api::ExAcquireRundownProtection(addr_of_mut!((*a).oid_rundown)) == 0 {
            return FWX_WDK_NDIS_CLOSING as NDIS_STATUS;
        }
        let mut clone = null_mut();
        api::NdisAllocateCloneOidRequest((*a).filter, request, TAG, &mut clone);
        addr_of_mut!((*clone).SourceReserved)
            .cast::<PNDIS_OID_REQUEST>()
            .write_unaligned(request);
        let status = api::NdisFOidRequest((*a).filter, clone);
        if status != FWX_WDK_NDIS_PENDING as NDIS_STATUS {
            oid_free_clone(a, clone);
            api::ExReleaseRundownProtection(addr_of_mut!((*a).oid_rundown));
        }
        status
    }
}

pub(super) unsafe extern "C" fn oid_complete(
    context: NDIS_HANDLE,
    clone: PNDIS_OID_REQUEST,
    status: NDIS_STATUS,
) {
    unsafe {
        let a = context.cast::<Adapter>();
        let original = oid_free_clone(a, clone);
        api::NdisFOidRequestComplete((*a).filter, original, status);
        api::ExReleaseRundownProtection(addr_of_mut!((*a).oid_rundown));
    }
}

pub(super) unsafe extern "C" fn cancel_oid(context: NDIS_HANDLE, id: PVOID) {
    unsafe { api::NdisFCancelOidRequest((*context.cast::<Adapter>()).filter, id) }
}

pub(super) unsafe extern "C" fn pnp(
    context: NDIS_HANDLE,
    event: PNET_PNP_EVENT_NOTIFICATION,
) -> NDIS_STATUS {
    unsafe { api::NdisFNetPnPEvent((*context.cast::<Adapter>()).filter, event) }
}

unsafe fn copy_adapter_name(
    out: *mut u16,
    name: PNDIS_STRING,
    flags: *mut u32,
    truncated: u32,
) -> u32 {
    unsafe {
        let (source, length) = if name.is_null() {
            (ptr::null(), 0)
        } else {
            ((*name).Buffer.cast_const(), u32::from((*name).Length) / 2)
        };
        adapter_info::FwxCopyAdapterName(out, source, length, flags, truncated)
    }
}

unsafe fn capture_attach_info(
    a: *mut Adapter,
    p: PNDIS_FILTER_ATTACH_PARAMETERS,
    guid: *const GUID,
) {
    unsafe {
        let info = addr_of_mut!((*a).info);
        (*info).module_id = (*a).id;
        (*info).interface_index = (*p).BaseMiniportIfIndex;
        (*info).filter_interface_index = (*p).IfIndex;
        (*info).lower_interface_index = (*p).LowerIfIndex;
        (*info).interface_luid = (*p).BaseMiniportNetLuid.Value;
        (*info).filter_interface_luid = (*p).NetLuid.Value;
        (*info).lower_interface_luid = (*p).LowerIfNetLuid.Value;
        let bytes = addr_of_mut!((*info).interface_guid).cast::<u8>();
        ptr::copy_nonoverlapping((*guid).Data1.to_le_bytes().as_ptr(), bytes, 4);
        ptr::copy_nonoverlapping((*guid).Data2.to_le_bytes().as_ptr(), bytes.add(4), 2);
        ptr::copy_nonoverlapping((*guid).Data3.to_le_bytes().as_ptr(), bytes.add(6), 2);
        ptr::copy_nonoverlapping(addr_of!((*guid).Data4).cast::<u8>(), bytes.add(8), 8);
        (*info).media_type = (*p).MiniportMediaType as u32;
        (*info).physical_medium = (*p).MiniportPhysicalMediaType as u32;
        (*info).media_connect_state = (*p).MediaConnectState as u32;
        (*info).media_duplex_state = (*p).MediaDuplexState as u32;
        (*info).xmit_link_speed = (*p).XmitLinkSpeed;
        (*info).rcv_link_speed = (*p).RcvLinkSpeed;
        (*info).attach_flags = (*p).Flags;
        let mac_length = usize::from((*p).MacAddressLength).min(wire::ADAPTER_INFO_MAC_CAPACITY);
        (*info).mac_address_length = mac_length as u32;
        ptr::copy_nonoverlapping(
            addr_of!((*p).CurrentMacAddress).cast::<u8>(),
            addr_of_mut!((*info).mac_address).cast::<u8>(),
            mac_length,
        );
        if (*p).Header.Revision >= NDIS_FILTER_ATTACH_PARAMETERS_REVISION_4 as u8
            && (*p).Header.Size >= FWX_WDK_ATTACH_REV4_SIZE as u16
        {
            (*info).flags |= wire::ADAPTER_CONNECTOR_VALID;
            (*info).connector_present = u32::from((*p).BaseMiniportIfConnectorPresent != 0);
        }
        // NDIS strings are borrowed for this callback only.
        (*info).instance_name_length = copy_adapter_name(
            addr_of_mut!((*info).instance_name).cast(),
            (*p).BaseMiniportInstanceName,
            addr_of_mut!((*info).flags),
            wire::ADAPTER_INSTANCE_NAME_TRUNCATED,
        );
        (*info).base_name_length = copy_adapter_name(
            addr_of_mut!((*info).base_name).cast(),
            (*p).BaseMiniportName,
            addr_of_mut!((*info).flags),
            wire::ADAPTER_BASE_NAME_TRUNCATED,
        );
        (*info).filter_module_name_length = copy_adapter_name(
            addr_of_mut!((*info).filter_module_name).cast(),
            (*p).FilterModuleGuidName,
            addr_of_mut!((*info).flags),
            wire::ADAPTER_FILTER_NAME_TRUNCATED,
        );
    }
}

unsafe fn capture_restart_info(a: *mut Adapter, p: PNDIS_FILTER_RESTART_PARAMETERS) {
    unsafe {
        let mut general: NDIS_RESTART_GENERAL_ATTRIBUTES = zeroed();
        let mut have_general = false;
        let media = (*p).MiniportMediaType as u32;
        let physical = (*p).MiniportPhysicalMediaType as u32;
        let lower_index = (*p).LowerIfIndex;
        let lower_luid = (*p).LowerIfNetLuid.Value;
        // Traverse borrowed attributes before taking our diagnostic spin lock.
        let mut attribute = (*p).RestartAttributes;
        while !attribute.is_null() {
            if (*attribute).Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES
                && (*attribute).DataLength >= FWX_WDK_RESTART_GENERAL_SIZE as u32
            {
                let candidate =
                    addr_of!((*attribute).Data).cast::<NDIS_RESTART_GENERAL_ATTRIBUTES>();
                let header = addr_of!((*candidate).Header).read_unaligned();
                if header.Type == NDIS_OBJECT_TYPE_RESTART_GENERAL_ATTRIBUTES as u8
                    && header.Revision >= NDIS_RESTART_GENERAL_ATTRIBUTES_REVISION_1 as u8
                    && header.Size >= FWX_WDK_RESTART_GENERAL_SIZE as u16
                    && u32::from(header.Size) <= (*attribute).DataLength
                {
                    ptr::copy_nonoverlapping(
                        candidate.cast::<u8>(),
                        addr_of_mut!(general).cast::<u8>(),
                        FWX_WDK_RESTART_GENERAL_SIZE as usize,
                    );
                    have_general = true;
                    break;
                }
            }
            attribute = (*attribute).Next;
        }
        let irql = spin_lock(addr_of_mut!(ADAPTER_INFO_LOCK));
        let info = addr_of_mut!((*a).info);
        (*info).media_type = media;
        (*info).physical_medium = physical;
        (*info).lower_interface_index = lower_index;
        (*info).lower_interface_luid = lower_luid;
        adapter_info::FwxClearGeneralAttributes(info);
        if have_general {
            (*info).flags |= wire::ADAPTER_GENERAL_VALID;
            (*info).mtu = general.MtuSize;
            (*info).max_xmit_link_speed = general.MaxXmitLinkSpeed;
            (*info).max_rcv_link_speed = general.MaxRcvLinkSpeed;
            (*info).lookahead_size = general.LookaheadSize;
            (*info).mac_options = general.MacOptions;
            (*info).supported_packet_filters = general.SupportedPacketFilters;
            (*info).max_multicast_list_size = general.MaxMulticastListSize;
            (*info).access_type = general.AccessType as u32;
            (*info).restart_flags = general.Flags;
            (*info).connection_type = general.ConnectionType as u32;
            (*info).supported_statistics = general.SupportedStatistics;
            (*info).data_back_fill_size = general.DataBackFillSize;
            (*info).context_back_fill_size = general.ContextBackFillSize;
        }
        spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
    }
}

pub(super) unsafe fn query_adapter_info(
    out: *mut u8,
    capacity: u32,
    transferred: *mut usize,
) -> NTSTATUS {
    unsafe {
        if capacity < wire::ADAPTER_INFO_HEADER_SIZE as u32 {
            return FWX_WDK_STATUS_BUFFER_TOO_SMALL as NTSTATUS;
        }
        if out.is_null() {
            return FWX_WDK_STATUS_INVALID_PARAMETER as NTSTATUS;
        }
        let mut snapshot: *mut AdapterInfo = null_mut();
        let mut allocated_count = 0;
        let mut status = FWX_WDK_STATUS_RETRY as NTSTATUS;
        for _ in 0..MAX_STAGING_ATTEMPTS {
            let mut size = 0;
            let irql = spin_lock(addr_of_mut!(ADAPTER_INFO_LOCK));
            let action = adapter_info::FwxPlanAdapterInfo(
                ADAPTER_COUNT,
                capacity,
                allocated_count,
                &mut size,
            );
            if matches!(action, AdapterInfoAction::CountOverflow) {
                status = FWX_WDK_STATUS_INTEGER_OVERFLOW as NTSTATUS;
                spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
                break;
            }
            let mut count = ADAPTER_COUNT as u32;
            let running = FILTERED_DEVICE_COUNT.load(Ordering::SeqCst);
            if running < 0 || running as u64 > ADAPTER_COUNT || size == 0 {
                fwx_bugcheck();
            }
            match action {
                AdapterInfoAction::HeaderOnly => {
                    // METHOD_BUFFERED warning replies contain the sizing header.
                    adapter_info::FwxEncodeAdapterInfoHeader(out, count, running as u32);
                    *transferred = wire::ADAPTER_INFO_HEADER_SIZE;
                    status = FWX_WDK_STATUS_BUFFER_OVERFLOW as NTSTATUS;
                    spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
                    break;
                }
                AdapterInfoAction::GrowStaging => {
                    spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
                    if !snapshot.is_null() {
                        api::ExFreePoolWithTag(snapshot.cast(), INFO_TAG);
                        snapshot = null_mut();
                    }
                    let Some(bytes) = (count as usize).checked_mul(size_of::<AdapterInfo>()) else {
                        status = FWX_WDK_STATUS_INTEGER_OVERFLOW as NTSTATUS;
                        break;
                    };
                    snapshot = pool_allocation(api::ExAllocatePool2(
                        (FWX_WDK_POOL_FLAG_NON_PAGED | FWX_WDK_POOL_FLAG_UNINITIALIZED) as u64,
                        bytes as u64,
                        INFO_TAG,
                    ))
                    .cast();
                    allocated_count = u64::from(count);
                    continue;
                }
                AdapterInfoAction::Encode => {}
                AdapterInfoAction::TooSmall | AdapterInfoAction::CountOverflow => fwx_bugcheck(),
            }
            // One lock protects list lifetime, metadata and running_count. Never
            // allocate, encode every field or take an adapter lock under it.
            count = 0;
            let head = addr_of_mut!(ADAPTERS);
            let mut entry = (*head).Flink;
            while entry != head {
                if u64::from(count) >= ADAPTER_COUNT {
                    fwx_bugcheck();
                }
                let a = entry
                    .cast::<u8>()
                    .sub(offset_of!(Adapter, adapter_link))
                    .cast::<Adapter>();
                ptr::copy_nonoverlapping(addr_of!((*a).info), snapshot.add(count as usize), 1);
                count += 1;
                entry = (*entry).Flink;
            }
            if u64::from(count) != ADAPTER_COUNT {
                fwx_bugcheck();
            }
            spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
            adapter_info::FwxEncodeAdapterInfoHeader(out, count, running as u32);
            for i in 0..count as usize {
                adapter_info::FwxEncodeAdapterInfo(
                    out.add(wire::ADAPTER_INFO_HEADER_SIZE + i * wire::ADAPTER_INFO_ENTRY_SIZE),
                    snapshot.add(i),
                );
            }
            *transferred = size as usize;
            status = FWX_WDK_STATUS_SUCCESS as NTSTATUS;
            break;
        }
        if !snapshot.is_null() {
            api::ExFreePoolWithTag(snapshot.cast(), INFO_TAG);
        }
        status
    }
}

pub(super) unsafe extern "C" fn status(context: NDIS_HANDLE, status: PNDIS_STATUS_INDICATION) {
    unsafe {
        let a = context.cast::<Adapter>();
        if (*status).StatusCode == FWX_WDK_NDIS_LINK_STATE as NDIS_STATUS
            && !(*status).StatusBuffer.is_null()
            && (*status).StatusBufferSize >= FWX_WDK_LINK_STATE_SIZE as u32
        {
            let link = (*status).StatusBuffer.cast::<NDIS_LINK_STATE>();
            let header = addr_of!((*link).Header).read_unaligned();
            if header.Type == NDIS_OBJECT_TYPE_DEFAULT as u8
                && header.Revision >= NDIS_LINK_STATE_REVISION_1 as u8
                && header.Size >= FWX_WDK_LINK_STATE_SIZE as u16
                && u32::from(header.Size) <= (*status).StatusBufferSize
            {
                // Copy borrowed link fields before locking; no NDIS pointers are
                // retained and an unaligned status buffer remains safe to read.
                let connect = addr_of!((*link).MediaConnectState).read_unaligned();
                let duplex = addr_of!((*link).MediaDuplexState).read_unaligned();
                let xmit = addr_of!((*link).XmitLinkSpeed).read_unaligned();
                let receive = addr_of!((*link).RcvLinkSpeed).read_unaligned();
                let flags = addr_of!((*link).AutoNegotiationFlags).read_unaligned();
                let irql = spin_lock(addr_of_mut!(ADAPTER_INFO_LOCK));
                (*a).info.flags |= wire::ADAPTER_LINK_STATE_VALID;
                (*a).info.media_connect_state = connect as u32;
                (*a).info.media_duplex_state = duplex as u32;
                (*a).info.xmit_link_speed = xmit;
                (*a).info.rcv_link_speed = receive;
                (*a).info.auto_negotiation_flags = flags;
                spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
            }
        }
        api::NdisFIndicateStatus((*a).filter, status);
    }
}

/// Free an unpublished adapter, including every successfully prepared pool.
unsafe fn free_adapter(a: *mut Adapter) {
    unsafe {
        if !(*a).nb_pool.is_null() {
            api::NdisFreeNetBufferPool((*a).nb_pool);
        }
        if !(*a).nbl_pool.is_null() {
            api::NdisFreeNetBufferListPool((*a).nbl_pool);
        }
        if !(*a).classification_lock.is_null() {
            api::NdisFreeRWLock((*a).classification_lock);
        }
        // NdisFreeSpinLock is an empty inline in the native WDK.
        api::ExFreePoolWithTag(a.cast(), TAG);
    }
}

pub(super) unsafe extern "C" fn filter_attach(
    filter: NDIS_HANDLE,
    _driver_context: NDIS_HANDLE,
    p: PNDIS_FILTER_ATTACH_PARAMETERS,
) -> NDIS_STATUS {
    unsafe {
        let mut guid: GUID = zeroed();
        // Only armed, identity-valid Ethernet miniports may attach.
        if (*p).MiniportMediaType != NdisMedium802_3 || !registry::target_adapter(p, &mut guid) {
            return FWX_WDK_NDIS_NOT_SUPPORTED as NDIS_STATUS;
        }
        let a = pool_allocation(api::ExAllocatePool2(
            FWX_WDK_POOL_FLAG_NON_PAGED as u64,
            size_of::<Adapter>() as u64,
            TAG,
        ))
        .cast::<Adapter>();
        (*a).filter = filter;
        (*a).interface_index = (*p).BaseMiniportIfIndex;
        (*a).id = NEXT_ADAPTER.fetch_add(1, Ordering::SeqCst).wrapping_add(1) as u64;
        capture_attach_info(a, p, &guid);
        // Native NdisAllocateSpinLock is exactly KeInitializeSpinLock.
        api::KeInitializeSpinLock(addr_of_mut!((*a).lock.SpinLock));
        api::ExInitializeRundownProtection(addr_of_mut!((*a).oid_rundown));
        (*a).classification_lock = api::NdisAllocateRWLock(filter);
        let mut nbl_pool: NET_BUFFER_LIST_POOL_PARAMETERS = zeroed();
        nbl_pool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT as u8;
        nbl_pool.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 as u8;
        nbl_pool.Header.Size = FWX_WDK_NBL_POOL_SIZE as u16;
        nbl_pool.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT as u8;
        nbl_pool.PoolTag = TAG;
        (*a).nbl_pool = api::NdisAllocateNetBufferListPool(filter, &nbl_pool);
        let mut nb_pool: NET_BUFFER_POOL_PARAMETERS = zeroed();
        nb_pool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT as u8;
        nb_pool.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1 as u8;
        nb_pool.Header.Size = FWX_WDK_NB_POOL_SIZE as u16;
        nb_pool.PoolTag = TAG;
        (*a).nb_pool = api::NdisAllocateNetBufferPool(filter, &nb_pool);
        let attached = policy::FwxAttach((*a).interface_index);
        policy::FwxDrain();
        if attached == 0 {
            free_adapter(a);
            return FWX_WDK_NDIS_RESOURCES as NDIS_STATUS;
        }
        let mut attributes: NDIS_FILTER_ATTRIBUTES = zeroed();
        attributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES as u8;
        attributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1 as u8;
        attributes.Header.Size = FWX_WDK_FILTER_ATTRIBUTES_SIZE as u16;
        let status = api::NdisFSetAttributes(filter, a.cast(), &mut attributes);
        if status == FWX_WDK_NDIS_SUCCESS as NDIS_STATUS {
            let irql = spin_lock(addr_of_mut!(ADAPTER_INFO_LOCK));
            ADAPTER_COUNT = ADAPTER_COUNT
                .checked_add(1)
                .unwrap_or_else(|| fwx_bugcheck());
            list_insert_tail(addr_of_mut!(ADAPTERS), addr_of_mut!((*a).adapter_link));
            spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
            return status;
        }
        policy::FwxRollbackAttach((*a).interface_index);
        policy::FwxDrain();
        free_adapter(a);
        status
    }
}

pub(super) unsafe extern "C" fn filter_restart(
    context: NDIS_HANDLE,
    p: PNDIS_FILTER_RESTART_PARAMETERS,
) -> NDIS_STATUS {
    unsafe {
        let a = context.cast::<Adapter>();
        if policy::FwxRestart((*a).interface_index) == 0 {
            return FWX_WDK_NDIS_FAILURE as NDIS_STATUS;
        }
        capture_restart_info(a, p);
        set_filter_running(a, true);
        FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
    }
}

pub(super) unsafe extern "C" fn filter_pause(
    context: NDIS_HANDLE,
    p: PNDIS_FILTER_PAUSE_PARAMETERS,
) -> NDIS_STATUS {
    unsafe {
        let a = context.cast::<Adapter>();
        set_filter_running(a, false);
        let irql = spin_lock(addr_of_mut!(ADAPTER_INFO_LOCK));
        (*a).info.flags |= wire::ADAPTER_PAUSE_VALID;
        (*a).info.pause_reason = (*p).PauseReason;
        (*a).info.pause_flags = (*p).Flags;
        spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
        invalidate(a);
        ndis_lock(addr_of_mut!((*a).lock));
        let status = if (*a).active == 0 {
            FWX_WDK_NDIS_SUCCESS as NDIS_STATUS
        } else {
            (*a).pause_pending = 1;
            FWX_WDK_NDIS_PENDING as NDIS_STATUS
        };
        ndis_unlock(addr_of_mut!((*a).lock));
        status
    }
}

pub(super) unsafe extern "C" fn filter_detach(context: NDIS_HANDLE) {
    unsafe {
        let a = context.cast::<Adapter>();
        if (*a).running != 0 || (*a).active != 0 {
            fwx_bugcheck();
        }
        let irql = spin_lock(addr_of_mut!(ADAPTER_INFO_LOCK));
        list_remove(addr_of_mut!((*a).adapter_link));
        ADAPTER_COUNT = ADAPTER_COUNT
            .checked_sub(1)
            .unwrap_or_else(|| fwx_bugcheck());
        spin_unlock(addr_of_mut!(ADAPTER_INFO_LOCK), irql);
        api::ExWaitForRundownProtectionRelease(addr_of_mut!((*a).oid_rundown));
        policy::FwxDetach((*a).interface_index);
        policy::FwxDrain();
        free_adapter(a);
    }
}
