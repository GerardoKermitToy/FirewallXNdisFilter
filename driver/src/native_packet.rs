//! Native NDIS packet storage, metadata and snapshots using the generated WDK ABI.
//!
//! These helpers do not transfer ownership or change an NB's data offsets. The
//! caller must own each NBL/NB for the entire operation, including borrowed views.

use core::{
    ffi::c_void,
    mem::{align_of, offset_of, size_of},
    ptr::{self, null_mut},
};

use crate::wdk::*;

#[cfg(not(test))]
use crate::wdk as api;
#[cfg(test)]
use tests::calls as api;

/// MSVC's multi-character pool tag 'gVHH' (not the little-endian byte spelling).
pub(crate) const TAG: u32 = u32::from_be_bytes(*b"gVHH");
const CONTEXT_TAG: u32 = u32::from_be_bytes(*b"nVHH");

pub(crate) const OWNER_NDIS: u32 = 0;
const NDIS_PATH_SEND: u32 = 0;

/// Driver-owned NBL context for NDIS ownership and completion.
/// NDIS context backfill guarantees pointer alignment, not 16-byte alignment.
#[repr(C)]
pub(crate) struct PacketContext {
    pub(crate) adapter: *mut c_void,
    pub(crate) signature: u32,
    pub(crate) flags: u32,
    pub(crate) direction: u32,
    pub(crate) port: NDIS_PORT_NUMBER,
    pub(crate) owner: u32,
    pub(crate) copied: u8,
    pub(crate) forwarded: u8,
}

const _: () = {
    assert!(align_of::<PacketContext>() <= align_of::<*mut c_void>());
    assert!(size_of::<PacketContext>().is_multiple_of(size_of::<*mut c_void>()));
    assert!(size_of::<PacketContext>() <= u16::MAX as usize);
    assert!(size_of::<PacketContext>() == 32);
    assert!(offset_of!(PacketContext, signature) == 8);
    assert!(offset_of!(PacketContext, port) == 20);
    assert!(offset_of!(PacketContext, owner) == 24);
    assert!(offset_of!(PacketContext, copied) == 28);
};

#[inline]
unsafe fn context_data(nbl: *mut NET_BUFFER_LIST) -> *mut PacketContext {
    // NET_BUFFER_LIST_CONTEXT_DATA_START: the offset is relative to the end of
    // the actual WDK context header, not to its ContextData member's address.
    unsafe {
        let header = (*nbl).Context;
        if header.is_null() {
            crate::native::fwx_bugcheck();
        }
        header
            .add(1)
            .cast::<u8>()
            .add((*header).Offset as usize)
            .cast()
    }
}

#[inline]
pub(crate) unsafe fn packet_context(nbl: *mut NET_BUFFER_LIST) -> *mut PacketContext {
    unsafe {
        let context = context_data(nbl);
        if (*context).signature != CONTEXT_TAG {
            crate::native::fwx_bugcheck();
        }
        context
    }
}

#[inline]
pub(crate) unsafe fn allocate_packet_context(nbl: *mut NET_BUFFER_LIST) -> *mut PacketContext {
    unsafe {
        api::NdisAllocateNetBufferListContext(
            nbl,
            size_of::<PacketContext>() as u16,
            0,
            CONTEXT_TAG,
        );
        let context = context_data(nbl);
        ptr::write_bytes(context, 0, 1);
        (*context).signature = CONTEXT_TAG;
        context
    }
}

#[inline]
pub(crate) unsafe fn free_packet_context(nbl: *mut NET_BUFFER_LIST) {
    unsafe { api::NdisFreeNetBufferListContext(nbl, size_of::<PacketContext>() as u16) }
}

#[inline]
pub(crate) unsafe fn first_nb(nbl: *mut NET_BUFFER_LIST) -> *mut NET_BUFFER {
    unsafe { (*nbl).__bindgen_anon_1.__bindgen_anon_1.FirstNetBuffer }
}

#[inline]
pub(crate) unsafe fn set_first_nb(nbl: *mut NET_BUFFER_LIST, nb: *mut NET_BUFFER) {
    unsafe { (*nbl).__bindgen_anon_1.__bindgen_anon_1.FirstNetBuffer = nb }
}

#[inline]
pub(crate) unsafe fn next_nbl(nbl: *mut NET_BUFFER_LIST) -> *mut NET_BUFFER_LIST {
    unsafe { (*nbl).__bindgen_anon_1.__bindgen_anon_1.Next }
}

#[inline]
pub(crate) unsafe fn set_next_nbl(nbl: *mut NET_BUFFER_LIST, next: *mut NET_BUFFER_LIST) {
    unsafe { (*nbl).__bindgen_anon_1.__bindgen_anon_1.Next = next }
}

#[inline]
pub(crate) unsafe fn next_nb(nb: *mut NET_BUFFER) -> *mut NET_BUFFER {
    unsafe { (*nb).__bindgen_anon_1.__bindgen_anon_1.Next }
}

#[inline]
pub(crate) unsafe fn set_next_nb(nb: *mut NET_BUFFER, next: *mut NET_BUFFER) {
    unsafe { (*nb).__bindgen_anon_1.__bindgen_anon_1.Next = next }
}

#[inline]
pub(crate) unsafe fn data_length(nb: *mut NET_BUFFER) -> u32 {
    unsafe {
        (*nb)
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_1
            .DataLength
    }
}

#[inline]
pub(crate) unsafe fn first_mdl(nb: *mut NET_BUFFER) -> *mut MDL {
    unsafe { (*nb).__bindgen_anon_1.__bindgen_anon_1.MdlChain }
}

#[inline]
pub(crate) unsafe fn current_mdl(nb: *mut NET_BUFFER) -> *mut MDL {
    unsafe { (*nb).__bindgen_anon_1.__bindgen_anon_1.CurrentMdl }
}

#[inline]
pub(crate) unsafe fn current_mdl_offset(nb: *mut NET_BUFFER) -> u32 {
    unsafe { (*nb).__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset }
}

/// Rust implementation of MmGetSystemAddressForMdlSafe. Mapping failure is
/// fallible; never ask the kernel to bugcheck or create an executable mapping.
#[inline]
pub(crate) unsafe fn map_mdl(mdl: *mut MDL) -> *mut u8 {
    #[cfg(test)]
    tests::record_map_mdl_call();
    unsafe {
        if mdl.is_null() {
            return null_mut();
        }
        if (*mdl).MdlFlags as u32 & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) != 0 {
            (*mdl).MappedSystemVa.cast()
        } else {
            api::MmMapLockedPagesSpecifyCache(
                mdl,
                KernelMode as KPROCESSOR_MODE,
                MmCached,
                null_mut(),
                0,
                NormalPagePriority as u32 | MdlMappingNoExecute,
            )
            .cast()
        }
    }
}

/// Read one byte relative to the current NB data start without changing offsets.
/// Used for local TCP LSO completion, including split MDL chains.
pub(crate) unsafe fn read_byte(nb: *mut NET_BUFFER, mut offset: u32) -> Option<u8> {
    unsafe {
        if nb.is_null() || offset >= data_length(nb) {
            return None;
        }
        let mut mdl = current_mdl(nb);
        let mut skip = current_mdl_offset(nb);
        while !mdl.is_null() {
            let length = (*mdl).ByteCount;
            if skip > length {
                return None;
            }
            let available = length - skip;
            if offset < available {
                let data = map_mdl(mdl);
                return (!data.is_null()).then(|| *data.add((skip + offset) as usize));
            }
            offset -= available;
            skip = 0;
            mdl = (*mdl).Next;
        }
        None
    }
}

#[inline]
pub(crate) unsafe fn receive_coalesced(nbl: *mut NET_BUFFER_LIST) -> bool {
    unsafe {
        // The WDK predicates interpret these scalar OOB values as a DWORD.
        (*nbl).NetBufferListInfo[TcpRecvSegCoalesceInfo as usize] as usize as u32 != 0
            || (*nbl).NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] as usize as u32 != 0
    }
}

#[inline]
pub(crate) unsafe fn send_segmented(nbl: *mut NET_BUFFER_LIST) -> bool {
    unsafe {
        (*nbl).NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] as usize as u32 != 0
            || (*nbl).NetBufferListInfo[UdpSegmentationOffloadInfo as usize] as usize as u32 != 0
    }
}

#[allow(non_upper_case_globals)] // Match the generated SDK enum names verbatim.
pub(crate) unsafe fn copy_receive_metadata_supported(
    nbl: *mut NET_BUFFER_LIST,
    info_count: u32,
) -> bool {
    unsafe {
        // The negotiated runtime version supplies this bound. Do not inspect
        // newer slots on older NDIS versions, or accept an impossible bound.
        if info_count as usize > (*nbl).NetBufferListInfo.len() {
            return false;
        }
        for i in 0..info_count as usize {
            if (*nbl).NetBufferListInfo[i].is_null() {
                continue;
            }
            match i as NDIS_NET_BUFFER_LIST_INFO {
                TcpIpChecksumNetBufferListInfo
                | TcpReceiveNoPush
                | Ieee8021QNetBufferListInfo
                | NetBufferListFrameType
                | NetBufferListHashValue
                | NetBufferListHashInfo
                | UdpRecvSegCoalesceOffloadInfo => {}
                _ => return false,
            }
        }
        true
    }
}

/// Free only a private resources-receive copy built by copy_receive. Every NB
/// owns exactly one MDL and one pool allocation; even a partial chain is valid.
pub(crate) unsafe fn free_receive_copy(nbl: *mut NET_BUFFER_LIST) {
    unsafe {
        let mut nb = first_nb(nbl);
        while !nb.is_null() {
            let next = next_nb(nb);
            let mdl = first_mdl(nb);
            // MmGetMdlVirtualAddress. StartVa is page-aligned and may precede
            // the allocation, so use wrapping pointer arithmetic to recover it.
            let data = (*mdl)
                .StartVa
                .cast::<u8>()
                .wrapping_add((*mdl).ByteOffset as usize);
            api::NdisFreeNetBuffer(nb);
            api::IoFreeMdl(mdl);
            api::ExFreePoolWithTag(data.cast(), TAG);
            nb = next;
        }
        api::NdisFreeNetBufferList(nbl);
    }
}

/// Synchronously deep-copy all NBs before a RESOURCES indication returns. No
/// original NBL/MDL/borrowed OOB ownership escapes the callback on either path.
pub(crate) unsafe fn copy_receive(
    filter: NDIS_HANDLE,
    nbl_pool: NDIS_HANDLE,
    nb_pool: NDIS_HANDLE,
    source: *mut NET_BUFFER_LIST,
    info_count: u32,
) -> *mut NET_BUFFER_LIST {
    unsafe {
        if !copy_receive_metadata_supported(source, info_count) || first_nb(source).is_null() {
            return null_mut();
        }
        let copy = api::NdisAllocateNetBufferList(nbl_pool, 0, 0);
        set_first_nb(copy, null_mut());
        set_next_nbl(copy, null_mut());
        let mut tail: *mut NET_BUFFER = null_mut();
        let mut nb = first_nb(source);
        while !nb.is_null() {
            let length = data_length(nb);
            if length == 0 {
                free_receive_copy(copy);
                return null_mut();
            }
            let storage = crate::native::pool_allocation(api::ExAllocatePool2(
                FWX_WDK_POOL_FLAG_NON_PAGED as POOL_FLAGS,
                length as SIZE_T,
                TAG,
            ));
            let data = api::NdisGetDataBuffer(nb, length, storage, 1, 0);
            if data.is_null() {
                api::ExFreePoolWithTag(storage, TAG);
                free_receive_copy(copy);
                return null_mut();
            }
            if data != storage {
                ptr::copy_nonoverlapping(data.cast::<u8>(), storage.cast::<u8>(), length as usize);
            }
            let mdl = api::IoAllocateMdl(storage, length, 0, 0, null_mut());
            api::MmBuildMdlForNonPagedPool(mdl);
            let created = api::NdisAllocateNetBuffer(nb_pool, mdl, 0, length as SIZE_T);
            set_next_nb(created, null_mut());
            if tail.is_null() {
                set_first_nb(copy, created);
            } else {
                set_next_nb(tail, created);
            }
            tail = created;
            nb = next_nb(nb);
        }
        api::NdisCopyReceiveNetBufferListInfo(copy, source);
        // NdisCopyReceiveNetBufferListInfo does not guarantee copying URO's
        // scalar SegCount/SegSize. Preserve the complete inline slot explicitly.
        (*copy).NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] =
            (*source).NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize];
        (*copy).NblFlags = (*source).NblFlags
            & (NDIS_NBL_FLAGS_IS_IPV4
                | NDIS_NBL_FLAGS_IS_IPV6
                | NDIS_NBL_FLAGS_IS_TCP
                | NDIS_NBL_FLAGS_IS_UDP
                | NDIS_NBL_FLAGS_IS_LOOPBACK_PACKET);
        (*copy).SourceHandle = filter;
        copy
    }
}

#[inline]
pub(crate) unsafe fn snapshot_offload(nbl: *mut NET_BUFFER_LIST) -> u32 {
    unsafe {
        let context = packet_context(nbl);
        u32::from(if (*context).direction == NDIS_PATH_SEND {
            send_segmented(nbl)
        } else {
            receive_coalesced(nbl)
        })
    }
}

#[inline]
unsafe fn snapshot_view(
    nb: *mut NET_BUFFER,
    storage: *mut u8,
    cap: u32,
    copied: *mut u32,
    frame_length: *mut u32,
) -> *const u8 {
    unsafe {
        *copied = 0;
        *frame_length = if nb.is_null() { 0 } else { data_length(nb) };
        let length = cap.min(*frame_length);
        if length == 0 {
            return ptr::null();
        }
        let data = api::NdisGetDataBuffer(nb, length, storage.cast(), 1, 0);
        if data.is_null() {
            return ptr::null();
        }
        *copied = length;
        data.cast()
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fwx_first_nb(packet: usize) -> *mut c_void {
    unsafe { first_nb(packet as *mut NET_BUFFER_LIST).cast() }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fwx_next_nb(nb: *mut c_void) -> *mut c_void {
    unsafe { next_nb(nb.cast()).cast() }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fwx_snapshot_view(
    nb: *mut c_void,
    packet: usize,
    storage: *mut u8,
    cap: u32,
    copied: *mut u32,
    trusted: *mut u32,
    frame_length: *mut u32,
    offload: *mut u32,
) -> *const u8 {
    unsafe {
        let data = snapshot_view(nb.cast(), storage, cap, copied, frame_length);
        *trusted = *copied;
        *offload = snapshot_offload(packet as *mut NET_BUFFER_LIST);
        data
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fwx_snapshot(
    nb: *mut c_void,
    packet: usize,
    out: *mut u8,
    cap: u32,
    copied: *mut u32,
    trusted: *mut u32,
    frame_length: *mut u32,
    offload: *mut u32,
) -> u32 {
    unsafe {
        let data = snapshot_view(
            nb.cast(),
            out,
            if out.is_null() { 0 } else { cap },
            copied,
            frame_length,
        );
        let result = if data.is_null() {
            0
        } else {
            if data != out {
                ptr::copy_nonoverlapping(data, out, *copied as usize);
            }
            1
        };
        *trusted = *copied;
        *offload = snapshot_offload(packet as *mut NET_BUFFER_LIST);
        result
    }
}

#[cfg(test)]
pub(crate) fn reset_test_allocator(fail_at: Option<usize>) {
    tests::reset(fail_at);
}

#[cfg(test)]
pub(crate) fn assert_test_allocator_no_leaks() {
    tests::assert_no_leaks();
}

#[cfg(test)]
pub(crate) fn reset_map_mdl_call_count() {
    tests::reset_map_mdl_call_count();
}

#[cfg(test)]
pub(crate) fn map_mdl_call_count() -> usize {
    tests::map_mdl_call_count()
}

#[cfg(test)]
#[path = "native_packet_tests.rs"]
mod tests;
