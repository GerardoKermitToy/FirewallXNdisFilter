//! Offline tests of native_packet's production code with real bindgen WDK types.
//! Only native imports are fake; no copy/snapshot/offload algorithm is duplicated.

extern crate std;

use self::std::{
    alloc::{Layout, alloc, alloc_zeroed, dealloc},
    boxed::Box,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use super::*;

#[derive(Default)]
struct State {
    attempts: usize,
    fail_at: Option<usize>,
    pools: BTreeMap<usize, Layout>,
    mdls: BTreeSet<usize>,
    nbs: BTreeSet<usize>,
    nbls: BTreeSet<usize>,
    contexts: BTreeMap<usize, Layout>,
    metadata_calls: usize,
    map_mdl_calls: usize,
    maps: Vec<(KPROCESSOR_MODE, MEMORY_CACHING_TYPE, usize, u32, u32)>,
    map_result: usize,
}

std::thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|state| f(&mut state.borrow_mut()))
}

pub(super) fn assert_no_leaks() {
    state(|s| {
        assert!(s.pools.is_empty(), "pool leak");
        assert!(s.mdls.is_empty(), "MDL leak");
        assert!(s.nbs.is_empty(), "NB leak");
        assert!(s.nbls.is_empty(), "NBL leak");
        assert!(s.contexts.is_empty(), "context leak");
    });
}

pub(super) fn reset(fail_at: Option<usize>) {
    assert_no_leaks();
    state(|s| {
        *s = State {
            fail_at,
            ..State::default()
        };
    });
}

pub(super) fn record_map_mdl_call() {
    state(|s| s.map_mdl_calls += 1);
}

pub(super) fn reset_map_mdl_call_count() {
    state(|s| s.map_mdl_calls = 0);
}

pub(super) fn map_mdl_call_count() -> usize {
    state(|s| s.map_mdl_calls)
}

fn fail() -> bool {
    state(|s| {
        s.attempts += 1;
        s.fail_at == Some(s.attempts)
    })
}

/// Fake imports have the exact generated WDK argument and result types. The
/// production module aliases this module only in the offline Rust test harness.
#[allow(non_snake_case)]
pub(super) mod calls {
    use super::*;

    pub(crate) unsafe fn ExAllocatePool2(flags: POOL_FLAGS, bytes: SIZE_T, tag: ULONG) -> PVOID {
        assert_eq!(flags, FWX_WDK_POOL_FLAG_NON_PAGED as POOL_FLAGS);
        assert_eq!(tag, TAG);
        assert!(bytes > 0);
        if fail() {
            return null_mut();
        }
        let layout = Layout::from_size_align(bytes as usize, 16).unwrap();
        let pointer = unsafe { alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        state(|s| assert!(s.pools.insert(pointer as usize, layout).is_none()));
        pointer.cast()
    }

    pub(crate) unsafe fn ExFreePoolWithTag(pointer: PVOID, tag: ULONG) {
        assert_eq!(tag, TAG);
        let layout = state(|s| {
            s.pools
                .remove(&(pointer as usize))
                .expect("foreign/double pool free")
        });
        unsafe { dealloc(pointer.cast(), layout) };
    }

    pub(crate) unsafe fn NdisAllocateNetBufferList(
        pool: NDIS_HANDLE,
        context_size: USHORT,
        context_backfill: USHORT,
    ) -> *mut NET_BUFFER_LIST {
        assert_eq!(pool as usize, 0x101);
        assert_eq!((context_size, context_backfill), (0, 0));
        if fail() {
            return null_mut();
        }
        let nbl = Box::into_raw(Box::<NET_BUFFER_LIST>::default());
        state(|s| assert!(s.nbls.insert(nbl as usize)));
        nbl
    }

    pub(crate) unsafe fn NdisAllocateCloneNetBufferList(
        source: *mut NET_BUFFER_LIST,
        nbl_pool: NDIS_HANDLE,
        nb_pool: NDIS_HANDLE,
        flags: ULONG,
    ) -> *mut NET_BUFFER_LIST {
        assert_eq!(nb_pool as usize, 0x202);
        assert_eq!(flags, 0);
        unsafe {
            let clone = NdisAllocateNetBufferList(nbl_pool, 0, 0);
            assert!(!clone.is_null());
            (*clone).ParentNetBufferList = source;
            let mut source_nb = first_nb(source);
            let mut tail: *mut NET_BUFFER = null_mut();
            while !source_nb.is_null() {
                let mut nb = Box::<NET_BUFFER>::default();
                ptr::copy_nonoverlapping(source_nb, &mut *nb, 1);
                let nb = Box::into_raw(nb);
                state(|s| assert!(s.nbs.insert(nb as usize)));
                set_next_nb(nb, null_mut());
                let mut source_mdl = first_mdl(source_nb);
                let original_current = current_mdl(source_nb);
                let mut first: *mut MDL = null_mut();
                let mut last: *mut MDL = null_mut();
                let mut current = null_mut();
                while !source_mdl.is_null() {
                    let mut mdl = Box::<MDL>::default();
                    ptr::copy_nonoverlapping(source_mdl, &mut *mdl, 1);
                    mdl.Next = null_mut();
                    let mdl = Box::into_raw(mdl);
                    state(|s| assert!(s.mdls.insert(mdl as usize)));
                    if first.is_null() {
                        first = mdl;
                    } else {
                        (*last).Next = mdl;
                    }
                    if source_mdl == original_current {
                        current = mdl;
                    }
                    last = mdl;
                    source_mdl = (*source_mdl).Next;
                }
                (*nb).__bindgen_anon_1.__bindgen_anon_1.MdlChain = first;
                (*nb).__bindgen_anon_1.__bindgen_anon_1.CurrentMdl = current;
                if tail.is_null() {
                    set_first_nb(clone, nb);
                } else {
                    set_next_nb(tail, nb);
                }
                tail = nb;
                source_nb = next_nb(source_nb);
            }
            clone
        }
    }

    pub(crate) unsafe fn NdisFreeCloneNetBufferList(clone: *mut NET_BUFFER_LIST, flags: ULONG) {
        assert_eq!(flags, 0);
        unsafe {
            let mut nb = first_nb(clone);
            while !nb.is_null() {
                let next = next_nb(nb);
                let mut mdl = first_mdl(nb);
                while !mdl.is_null() {
                    let next_mdl = (*mdl).Next;
                    IoFreeMdl(mdl);
                    mdl = next_mdl;
                }
                NdisFreeNetBuffer(nb);
                nb = next;
            }
            NdisFreeNetBufferList(clone);
        }
    }

    pub(crate) unsafe fn NdisFreeNetBufferList(nbl: *mut NET_BUFFER_LIST) {
        state(|s| assert!(s.nbls.remove(&(nbl as usize)), "foreign/double NBL free"));
        unsafe { drop(Box::from_raw(nbl)) };
    }

    pub(crate) unsafe fn IoAllocateMdl(
        address: PVOID,
        length: ULONG,
        secondary: BOOLEAN,
        charge: BOOLEAN,
        irp: PIRP,
    ) -> PMDL {
        assert_eq!((secondary, charge), (0, 0));
        assert!(irp.is_null());
        if fail() {
            return null_mut();
        }
        let mdl = Box::into_raw(Box::new(MDL {
            StartVa: ((address as usize) & !4095) as PVOID,
            ByteOffset: (address as usize & 4095) as u32,
            ByteCount: length,
            ..MDL::default()
        }));
        state(|s| assert!(s.mdls.insert(mdl as usize)));
        mdl
    }

    pub(crate) unsafe fn MmBuildMdlForNonPagedPool(mdl: PMDL) {
        unsafe {
            (*mdl).MdlFlags |= MDL_SOURCE_IS_NONPAGED_POOL as CSHORT;
            (*mdl).MappedSystemVa = (*mdl)
                .StartVa
                .cast::<u8>()
                .wrapping_add((*mdl).ByteOffset as usize)
                .cast();
        }
    }

    pub(crate) unsafe fn IoFreeMdl(mdl: PMDL) {
        state(|s| assert!(s.mdls.remove(&(mdl as usize)), "foreign/double MDL free"));
        unsafe { drop(Box::from_raw(mdl)) };
    }

    pub(crate) unsafe fn NdisAllocateNetBuffer(
        pool: NDIS_HANDLE,
        mdl: *mut MDL,
        offset: ULONG,
        length: SIZE_T,
    ) -> *mut NET_BUFFER {
        assert_eq!(pool as usize, 0x202);
        assert_eq!(offset, 0);
        if fail() {
            return null_mut();
        }
        let mut nb = Box::<NET_BUFFER>::default();
        nb.__bindgen_anon_1.__bindgen_anon_1.MdlChain = mdl;
        nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdl = mdl;
        nb.__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_1
            .DataLength = length as u32;
        let nb = Box::into_raw(nb);
        state(|s| assert!(s.nbs.insert(nb as usize)));
        nb
    }

    pub(crate) unsafe fn NdisFreeNetBuffer(nb: *mut NET_BUFFER) {
        state(|s| assert!(s.nbs.remove(&(nb as usize)), "foreign/double NB free"));
        unsafe { drop(Box::from_raw(nb)) };
    }

    pub(crate) unsafe fn NdisGetDataBuffer(
        nb: *mut NET_BUFFER,
        length: ULONG,
        storage: PVOID,
        alignment: ULONG,
        alignment_offset: ULONG,
    ) -> PVOID {
        assert_eq!((alignment, alignment_offset), (1, 0));
        if fail() {
            return null_mut();
        }
        // Fake the native API's documented contiguous/optional-scratch contract.
        // The graph here is made of actual generated NB and MDL fields.
        unsafe {
            assert!(length <= data_length(nb));
            let mut mdl = current_mdl(nb);
            let mut offset = current_mdl_offset(nb);
            if !mdl.is_null() && offset <= (*mdl).ByteCount && length <= (*mdl).ByteCount - offset {
                return (*mdl)
                    .MappedSystemVa
                    .cast::<u8>()
                    .add(offset as usize)
                    .cast();
            }
            if storage.is_null() {
                return null_mut();
            }
            let mut written = 0;
            while written < length && !mdl.is_null() {
                if offset > (*mdl).ByteCount {
                    return null_mut();
                }
                let take = (length - written).min((*mdl).ByteCount - offset);
                ptr::copy_nonoverlapping(
                    (*mdl).MappedSystemVa.cast::<u8>().add(offset as usize),
                    storage.cast::<u8>().add(written as usize),
                    take as usize,
                );
                written += take;
                mdl = (*mdl).Next;
                offset = 0;
            }
            if written == length {
                storage
            } else {
                null_mut()
            }
        }
    }

    pub(crate) unsafe fn NdisCopySendNetBufferListInfo(
        destination: *mut NET_BUFFER_LIST,
        source: *const NET_BUFFER_LIST,
    ) {
        state(|s| s.metadata_calls += 1);
        for index in [
            TcpIpChecksumNetBufferListInfo,
            Ieee8021QNetBufferListInfo,
            NetBufferListCancelId,
            NetBufferListProtocolId,
        ] {
            unsafe {
                (*destination).NetBufferListInfo[index as usize] =
                    (*source).NetBufferListInfo[index as usize];
            }
        }
    }

    pub(crate) unsafe fn NdisCopyReceiveNetBufferListInfo(
        destination: *mut NET_BUFFER_LIST,
        source: *const NET_BUFFER_LIST,
    ) {
        state(|s| s.metadata_calls += 1);
        // Intentionally omit URO so the explicit production scalar copy is tested.
        for index in [
            TcpIpChecksumNetBufferListInfo,
            TcpReceiveNoPush,
            Ieee8021QNetBufferListInfo,
            NetBufferListFrameType,
            NetBufferListHashValue,
            NetBufferListHashInfo,
        ] {
            unsafe {
                (*destination).NetBufferListInfo[index as usize] =
                    (*source).NetBufferListInfo[index as usize];
            }
        }
    }

    pub(crate) unsafe fn NdisAllocateNetBufferListContext(
        nbl: *mut NET_BUFFER_LIST,
        size: USHORT,
        backfill: USHORT,
        tag: ULONG,
    ) -> NDIS_STATUS {
        assert_eq!(size as usize, size_of::<PacketContext>());
        assert_eq!(backfill, 0);
        assert_eq!(tag, CONTEXT_TAG);
        if fail() {
            return 0xc000009au32 as NDIS_STATUS;
        }
        // Exercise pointer-aligned but not 16-byte-aligned context backfill.
        let layout =
            Layout::from_size_align(size_of::<NET_BUFFER_LIST_CONTEXT>() + 8 + size as usize, 16)
                .unwrap();
        unsafe {
            let header = alloc(layout).cast::<NET_BUFFER_LIST_CONTEXT>();
            assert!(!header.is_null());
            ptr::write_bytes(header.cast::<u8>(), 0xa5, layout.size());
            ptr::write(header, NET_BUFFER_LIST_CONTEXT::default());
            (*header).Offset = 8;
            (*header).Size = size;
            (*header).Next = (*nbl).Context;
            (*nbl).Context = header;
            state(|s| assert!(s.contexts.insert(header as usize, layout).is_none()));
        }
        FWX_WDK_NDIS_STATUS_SUCCESS as NDIS_STATUS
    }

    pub(crate) unsafe fn NdisFreeNetBufferListContext(nbl: *mut NET_BUFFER_LIST, size: USHORT) {
        unsafe {
            let header = (*nbl).Context;
            assert_eq!((*header).Size, size);
            (*nbl).Context = (*header).Next;
            let layout = state(|s| {
                s.contexts
                    .remove(&(header as usize))
                    .expect("foreign context free")
            });
            dealloc(header.cast(), layout);
        }
    }

    pub(crate) unsafe fn MmMapLockedPagesSpecifyCache(
        _mdl: PMDL,
        mode: KPROCESSOR_MODE,
        cache: MEMORY_CACHING_TYPE,
        requested: PVOID,
        bugcheck: ULONG,
        priority: ULONG,
    ) -> PVOID {
        state(|s| {
            s.maps
                .push((mode, cache, requested as usize, bugcheck, priority));
            s.map_result as PVOID
        })
    }
}

struct Input {
    data: Vec<Box<[u8]>>,
    mdls: Vec<MDL>,
    nb: Box<NET_BUFFER>,
}

impl Input {
    fn new(segments: &[&[u8]], offset: u32, length: u32) -> Self {
        let mut data: Vec<Box<[u8]>> = segments
            .iter()
            .map(|s| s.to_vec().into_boxed_slice())
            .collect();
        // Complete the allocation before linking; this Vec never grows again.
        let mut mdls: Vec<MDL> = data
            .iter_mut()
            .map(|s| MDL {
                MappedSystemVa: s.as_mut_ptr().cast(),
                StartVa: s.as_mut_ptr().cast(),
                ByteCount: s.len() as u32,
                MdlFlags: MDL_SOURCE_IS_NONPAGED_POOL as CSHORT,
                ..MDL::default()
            })
            .collect();
        for i in 1..mdls.len() {
            mdls[i - 1].Next = &mut mdls[i];
        }
        let mut nb = Box::<NET_BUFFER>::default();
        let first = mdls.first_mut().map_or(null_mut(), |mdl| mdl);
        nb.__bindgen_anon_1.__bindgen_anon_1.MdlChain = first;
        nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdl = first;
        nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset = offset;
        nb.__bindgen_anon_1.__bindgen_anon_1.DataOffset = offset;
        nb.__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_1
            .DataLength = length;
        Self { data, mdls, nb }
    }
}

fn source(inputs: &mut [Input]) -> Box<NET_BUFFER_LIST> {
    let mut source = Box::<NET_BUFFER_LIST>::default();
    unsafe {
        for i in 1..inputs.len() {
            set_next_nb(&mut *inputs[i - 1].nb, &mut *inputs[i].nb);
        }
        if let Some(first) = inputs.first_mut() {
            set_first_nb(&mut *source, &mut *first.nb);
        }
    }
    source
}

unsafe fn copy(source: &mut NET_BUFFER_LIST) -> *mut NET_BUFFER_LIST {
    unsafe {
        copy_receive(
            0x303 as NDIS_HANDLE,
            0x101 as NDIS_HANDLE,
            0x202 as NDIS_HANDLE,
            source,
            MaxNetBufferListInfo as u32,
        )
    }
}

unsafe fn bytes(nb: *mut NET_BUFFER) -> &'static [u8] {
    unsafe {
        core::slice::from_raw_parts(
            (*first_mdl(nb)).MappedSystemVa.cast(),
            data_length(nb) as usize,
        )
    }
}

#[test]
fn context_uses_exact_owner_layout_and_pointer_aligned_backfill() {
    reset(None);
    assert_eq!(TAG, 0x6756_4848);
    assert_eq!(CONTEXT_TAG, 0x6e56_4848);
    assert_eq!(OWNER_NDIS, 0);
    let mut nbl = NET_BUFFER_LIST::default();
    unsafe {
        let context = allocate_packet_context(&mut nbl);
        assert!(!context.is_null());
        assert_eq!(context as usize % 16, 8);
        assert_eq!(packet_context(&mut nbl), context);
        assert_eq!((*context).signature, CONTEXT_TAG);
        let raw = core::slice::from_raw_parts(context.cast::<u8>(), size_of::<PacketContext>());
        for (i, &byte) in raw.iter().enumerate() {
            if !(offset_of!(PacketContext, signature)..offset_of!(PacketContext, signature) + 4)
                .contains(&i)
            {
                assert_eq!(byte, 0, "context byte {i} was not cleared");
            }
        }
        free_packet_context(&mut nbl);
        assert!(nbl.Context.is_null());
    }
    assert_no_leaks();
}

#[test]
fn mdl_mapping_is_fallible_cached_nx_and_reuses_existing_mapping() {
    reset(None);
    let mut mdl = MDL {
        MappedSystemVa: 0x1234 as PVOID,
        ..MDL::default()
    };
    unsafe {
        for flags in [MDL_MAPPED_TO_SYSTEM_VA, MDL_SOURCE_IS_NONPAGED_POOL] {
            mdl.MdlFlags = flags as CSHORT;
            assert_eq!(map_mdl(&mut mdl) as usize, 0x1234);
        }
        state(|s| assert!(s.maps.is_empty()));
        assert_eq!(super::map_mdl_call_count(), 2);
        super::reset_map_mdl_call_count();
        assert_eq!(super::map_mdl_call_count(), 0);
        mdl.MdlFlags = 0;
        state(|s| s.map_result = 0x5678);
        assert_eq!(map_mdl(&mut mdl) as usize, 0x5678);
        state(|s| {
            assert_eq!(
                s.maps,
                vec![(
                    KernelMode as KPROCESSOR_MODE,
                    MmCached,
                    0,
                    0,
                    NormalPagePriority as u32 | MdlMappingNoExecute
                )]
            )
        });
        state(|s| s.map_result = 0);
        assert!(map_mdl(&mut mdl).is_null());
        assert!(map_mdl(null_mut()).is_null());
        assert_eq!(super::map_mdl_call_count(), 3);
    }
}

#[test]
fn receive_copy_deep_copies_all_nbs_preserves_scalar_oob_and_original_offsets() {
    reset(None);
    let mut inputs = [
        Input::new(&[b"xxabc", b"defyy"], 2, 6),
        Input::new(&[b"ghi"], 0, 3),
    ];
    let mut source = source(&mut inputs);
    let mut following = NET_BUFFER_LIST::default();
    let allowed =
        NDIS_NBL_FLAGS_IS_IPV4 | NDIS_NBL_FLAGS_IS_TCP | NDIS_NBL_FLAGS_IS_LOOPBACK_PACKET;
    source.NblFlags = allowed | NDIS_NBL_FLAGS_SEND_READ_ONLY | NDIS_NBL_FLAGS_HD_SPLIT;
    source.SourceHandle = 0x999 as NDIS_HANDLE;
    let uro = 0x1234_5678_0555_0003usize;
    source.NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] = uro as PVOID;
    for index in [
        TcpIpChecksumNetBufferListInfo,
        TcpReceiveNoPush,
        Ieee8021QNetBufferListInfo,
        NetBufferListFrameType,
        NetBufferListHashValue,
        NetBufferListHashInfo,
    ] {
        source.NetBufferListInfo[index as usize] = (index as usize + 1) as PVOID;
    }
    unsafe {
        set_next_nbl(&mut *source, &mut following);
        let first_original = first_nb(&mut *source);
        let original_mdl = current_mdl(first_original);
        let copy = copy(&mut source);
        assert!(!copy.is_null());
        assert!(next_nbl(copy).is_null());
        assert_eq!((*copy).SourceHandle as usize, 0x303);
        assert_eq!((*copy).NblFlags, allowed);
        assert_eq!((*copy).NetBufferListInfo, source.NetBufferListInfo);
        let first = first_nb(copy);
        let second = next_nb(first);
        assert_eq!(bytes(first), b"abcdef");
        assert_eq!(bytes(second), b"ghi");
        assert!(next_nb(second).is_null());
        assert_eq!(current_mdl_offset(first), 0);
        inputs[0].data[0][2] = b'Z';
        assert_eq!(bytes(first), b"abcdef");
        assert_eq!(current_mdl(first_original), original_mdl);
        assert_eq!(current_mdl_offset(first_original), 2);
        assert_eq!(
            (*first_original)
                .__bindgen_anon_1
                .__bindgen_anon_1
                .DataOffset,
            2
        );
        assert_eq!(data_length(first_original), 6);
        assert_eq!(first_nb(&mut *source), first_original);
        assert_eq!(next_nbl(&mut *source), &mut following as *mut _);
        assert_eq!(source.SourceHandle as usize, 0x999);
        free_receive_copy(copy);
    }
    state(|s| assert_eq!(s.metadata_calls, 1));
    assert_eq!(inputs[0].mdls.len(), 2);
    assert_no_leaks();
}

#[test]
fn split_wrapper_uses_cloned_descriptors_and_rejects_opaque_send_metadata() {
    reset(None);
    let mut inputs = [Input::new(&[b"abcdef"], 0, 6)];
    let mut parent = source(&mut inputs);
    let nb = &mut *inputs[0].nb as *mut NET_BUFFER;
    parent.NetBufferListInfo[NetBufferListCancelId as usize] = 0x55usize as PVOID;
    parent.NetBufferListInfo[Ieee8021QNetBufferListInfo as usize] = 0x123usize as PVOID;
    unsafe {
        assert!(split_metadata_supported(
            &mut *parent,
            NDIS_PATH_SEND,
            MaxNetBufferListInfo as u32
        ));
        let clone = allocate_split_clone(&mut *parent, 0x101 as NDIS_HANDLE, 0x202 as NDIS_HANDLE);
        let cloned_nb = first_nb(clone);
        assert_ne!(cloned_nb, nb);
        let child = allocate_split_nbl(
            0x303 as NDIS_HANDLE,
            0x101 as NDIS_HANDLE,
            &mut *parent,
            cloned_nb,
            NDIS_PATH_SEND,
        );
        assert!((*child).ParentNetBufferList.is_null());
        assert_eq!((*child).SourceHandle, 0x303 as NDIS_HANDLE);
        assert_ne!((*child).NblFlags & NDIS_NBL_FLAGS_SEND_READ_ONLY, 0);
        assert_eq!(first_nb(child), cloned_nb);
        assert_eq!(
            (*child).NetBufferListInfo[NetBufferListCancelId as usize] as usize,
            0x55
        );
        assert_eq!(
            (*child).NetBufferListInfo[Ieee8021QNetBufferListInfo as usize] as usize,
            0x123
        );
        assert_ne!(first_mdl(cloned_nb), inputs[0].mdls.as_mut_ptr());
        assert_eq!(
            (*first_mdl(cloned_nb)).MappedSystemVa,
            (*first_mdl(nb)).MappedSystemVa
        );
        free_split_nbl(child);
        parent.NetBufferListInfo[NetBufferListCancelId as usize] = null_mut();
        const RECEIVE_PATH: u32 = 1;
        let receive = allocate_split_nbl(
            0x303 as NDIS_HANDLE,
            0x101 as NDIS_HANDLE,
            &mut *parent,
            cloned_nb,
            RECEIVE_PATH,
        );
        assert_ne!((*receive).NblFlags & NDIS_NBL_FLAGS_RECV_READ_ONLY, 0);
        free_split_nbl(receive);
        free_split_clone(clone);
        assert_eq!(first_nb(&mut *parent), nb);
        parent.NetBufferListInfo[MediaSpecificInformation as usize] = 1usize as PVOID;
        assert!(!split_metadata_supported(
            &mut *parent,
            NDIS_PATH_SEND,
            MaxNetBufferListInfo as u32
        ));
        parent.NetBufferListInfo[MediaSpecificInformation as usize] = null_mut();
        parent.NblFlags = NDIS_NBL_FLAGS_CAPTURE_TIMESTAMP_ON_TRANSMIT;
        assert!(!split_metadata_supported(
            &mut *parent,
            NDIS_PATH_SEND,
            MaxNetBufferListInfo as u32
        ));
        parent.NblFlags = NDIS_NBL_FLAGS_HD_SPLIT;
        assert!(!split_metadata_supported(
            &mut *parent,
            RECEIVE_PATH,
            MaxNetBufferListInfo as u32
        ));
    }
    assert_no_leaks();
}

#[test]
fn receive_metadata_rejects_borrowed_slots_and_respects_runtime_bound() {
    reset(None);
    let mut inputs = [Input::new(&[b"a"], 0, 1)];
    let mut source = source(&mut inputs);
    let allowed = [
        TcpIpChecksumNetBufferListInfo,
        TcpReceiveNoPush,
        Ieee8021QNetBufferListInfo,
        NetBufferListFrameType,
        NetBufferListHashValue,
        NetBufferListHashInfo,
        UdpRecvSegCoalesceOffloadInfo,
    ];
    for index in 0..MaxNetBufferListInfo as usize {
        source.NetBufferListInfo[index] = 1 as PVOID;
        let supported = allowed.contains(&(index as NDIS_NET_BUFFER_LIST_INFO));
        assert_eq!(
            unsafe { copy_receive_metadata_supported(&mut *source, MaxNetBufferListInfo as u32) },
            supported
        );
        if !supported {
            assert!(unsafe { copy(&mut source) }.is_null());
        }
        source.NetBufferListInfo[index] = null_mut();
    }
    state(|s| assert_eq!(s.attempts, 0));
    source.NetBufferListInfo[NetBufferListInfoReserved3 as usize] = 1 as PVOID;
    assert!(unsafe {
        copy_receive_metadata_supported(&mut *source, (RscTcpTimestampDelta + 1) as u32)
    });
    assert!(!unsafe { copy_receive_metadata_supported(&mut *source, MaxNetBufferListInfo as u32) });
    assert!(!unsafe { copy_receive_metadata_supported(&mut *source, u32::MAX) });
    assert_no_leaks();
}

#[test]
fn data_view_failures_clean_partial_copy_exactly_once() {
    let mut inputs = [
        Input::new(&[b"abcd"], 0, 4),
        Input::new(&[b"a", b"bcd"], 0, 4),
        Input::new(&[b"xy"], 0, 2),
    ];
    let mut source = source(&mut inputs);
    // Mapping/view failures remain recoverable; allocations are assumed to succeed.
    for failure in [3, 7, 11] {
        reset(Some(failure));
        assert!(
            unsafe { copy(&mut source) }.is_null(),
            "failure {failure} was ignored"
        );
        state(|s| assert_eq!(s.attempts, failure));
        assert_no_leaks();
        assert_eq!(inputs[0].data[0].as_ref(), b"abcd");
        assert_eq!(unsafe { current_mdl_offset(&mut *inputs[0].nb) }, 0);
    }
    reset(None);
    let copy = unsafe { copy(&mut source) };
    assert!(!copy.is_null());
    state(|s| assert_eq!(s.attempts, 13));
    unsafe { free_receive_copy(copy) };
    assert_no_leaks();
}

#[test]
fn empty_and_zero_length_nbs_fail_without_leaking_prior_copies() {
    reset(None);
    let mut empty = NET_BUFFER_LIST::default();
    assert!(unsafe { copy(&mut empty) }.is_null());
    state(|s| assert_eq!(s.attempts, 0));
    let mut inputs = [Input::new(&[b"abc"], 0, 3), Input::new(&[b""], 0, 0)];
    let mut source = source(&mut inputs);
    assert!(unsafe { copy(&mut source) }.is_null());
    assert_no_leaks();
}

#[test]
fn receive_copy_has_no_fixed_nb_count_quota() {
    reset(None);
    let mut inputs: Vec<Input> = (0..513).map(|_| Input::new(&[b"a"], 0, 1)).collect();
    let mut source = source(&mut inputs);
    unsafe {
        let copy = copy(&mut source);
        assert!(!copy.is_null());
        let mut count = 0;
        let mut nb = first_nb(copy);
        while !nb.is_null() {
            assert_eq!(bytes(nb), b"a");
            count += 1;
            nb = next_nb(nb);
        }
        assert_eq!(count, 513);
        free_receive_copy(copy);
    }
    assert_no_leaks();
}

#[test]
fn snapshots_borrow_contiguous_bytes_or_copy_owned_bytes_without_advancing_offsets() {
    reset(None);
    let mut inputs = [Input::new(&[b"xxabcdefyy"], 2, 6)];
    let mut source = source(&mut inputs);
    unsafe {
        assert!(!allocate_packet_context(&mut *source).is_null());
        let packet = &mut *source as *mut NET_BUFFER_LIST as usize;
        let nb = fwx_first_nb(packet);
        assert_eq!(nb, (&mut *inputs[0].nb as *mut NET_BUFFER).cast());
        assert!(fwx_next_nb(nb).is_null());
        let (mut copied, mut trusted, mut length, mut offload) = (99, 99, 99, 99);
        let borrowed = fwx_snapshot_view(
            nb,
            packet,
            null_mut(),
            4,
            &mut copied,
            &mut trusted,
            &mut length,
            &mut offload,
        );
        assert_eq!(borrowed, inputs[0].data[0].as_ptr().add(2));
        assert_eq!((copied, trusted, length, offload), (4, 4, 6, 0));
        let mut output = [0u8; 8];
        assert_eq!(
            fwx_snapshot(
                nb,
                packet,
                output.as_mut_ptr(),
                8,
                &mut copied,
                &mut trusted,
                &mut length,
                &mut offload
            ),
            1
        );
        assert_eq!(&output, b"abcdef\0\0");
        assert_eq!((copied, trusted, length, offload), (6, 6, 6, 0));
        assert_eq!(
            fwx_snapshot(
                nb,
                packet,
                null_mut(),
                100,
                &mut copied,
                &mut trusted,
                &mut length,
                &mut offload
            ),
            0
        );
        assert_eq!((copied, trusted, length, offload), (0, 0, 6, 0));
        assert!(
            fwx_snapshot_view(
                null_mut(),
                packet,
                null_mut(),
                100,
                &mut copied,
                &mut trusted,
                &mut length,
                &mut offload
            )
            .is_null()
        );
        assert_eq!((copied, trusted, length, offload), (0, 0, 0, 0));
        assert_eq!(current_mdl_offset(nb.cast()), 2);
        assert_eq!(
            (*nb.cast::<NET_BUFFER>())
                .__bindgen_anon_1
                .__bindgen_anon_1
                .DataOffset,
            2
        );
        free_packet_context(&mut *source);
    }
    assert_no_leaks();
}

#[test]
fn split_snapshots_require_scratch_and_report_observed_length_on_mapping_failure() {
    reset(None);
    let mut inputs = [Input::new(&[b"xxabc", b"defyy"], 2, 6)];
    let mut source = source(&mut inputs);
    unsafe {
        allocate_packet_context(&mut *source);
        let packet = &mut *source as *mut NET_BUFFER_LIST as usize;
        let nb = fwx_first_nb(packet);
        let (mut copied, mut trusted, mut length, mut offload) = (99, 99, 99, 99);
        assert!(
            fwx_snapshot_view(
                nb,
                packet,
                null_mut(),
                5,
                &mut copied,
                &mut trusted,
                &mut length,
                &mut offload
            )
            .is_null()
        );
        assert_eq!((copied, trusted, length, offload), (0, 0, 6, 0));
        let mut scratch = [0u8; 5];
        assert_eq!(
            fwx_snapshot_view(
                nb,
                packet,
                scratch.as_mut_ptr(),
                5,
                &mut copied,
                &mut trusted,
                &mut length,
                &mut offload
            ),
            scratch.as_ptr()
        );
        assert_eq!(&scratch, b"abcde");
        assert_eq!((copied, trusted, length, offload), (5, 5, 6, 0));
        (*packet_context(&mut *source)).direction = 1;
        source.NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] = 2 as PVOID;
        state(|s| s.fail_at = Some(s.attempts + 1));
        assert_eq!(
            fwx_snapshot(
                nb,
                packet,
                scratch.as_mut_ptr(),
                5,
                &mut copied,
                &mut trusted,
                &mut length,
                &mut offload
            ),
            0
        );
        assert_eq!((copied, trusted, length, offload), (0, 0, 6, 1));
        assert_eq!(current_mdl_offset(nb.cast()), 2);
        free_packet_context(&mut *source);
    }
    assert_no_leaks();
}

#[test]
fn single_byte_reads_walk_split_mdls_without_mutating_offsets() {
    reset(None);
    let mut input = Input::new(&[b"xxabc", b"defyy"], 2, 6);
    let nb = &mut *input.nb as *mut NET_BUFFER;
    unsafe {
        assert_eq!(read_byte(nb, 0), Some(b'a'));
        assert_eq!(read_byte(nb, 2), Some(b'c'));
        assert_eq!(read_byte(nb, 3), Some(b'd'));
        assert_eq!(read_byte(nb, 5), Some(b'f'));
        assert_eq!(read_byte(nb, 6), None);
        assert_eq!(read_byte(null_mut(), 0), None);
        assert_eq!(current_mdl_offset(nb), 2);
        assert_eq!((*nb).__bindgen_anon_1.__bindgen_anon_1.DataOffset, 2);
        input.mdls[1].MdlFlags = 0;
        assert_eq!(read_byte(nb, 3), None); // failed mapping
        (*nb).__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset = 6;
        assert_eq!(read_byte(nb, 0), None); // invalid current offset
    }
    assert_no_leaks();
}

#[test]
fn offload_detection_preserves_ndis_path_and_uso_uro_low_dword_semantics() {
    reset(None);
    let mut nbl = NET_BUFFER_LIST::default();
    unsafe {
        let context = allocate_packet_context(&mut nbl);
        nbl.NetBufferListInfo[UdpSegmentationOffloadInfo as usize] = (1usize << 32) as PVOID;
        assert!(!send_segmented(&mut nbl));
        assert!(!receive_coalesced(&mut nbl)); // Same slot is TCP RSC on receive.
        assert_eq!(snapshot_offload(&mut nbl), 0);
        (*context).direction = 1;
        assert_eq!(snapshot_offload(&mut nbl), 0);
        nbl.NetBufferListInfo[UdpSegmentationOffloadInfo as usize] = null_mut();
        nbl.NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] = (1usize << 32) as PVOID;
        assert!(!receive_coalesced(&mut nbl));
        assert_eq!(snapshot_offload(&mut nbl), 0);
        nbl.NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] = 3 as PVOID;
        assert_eq!(snapshot_offload(&mut nbl), 1);
        nbl.NetBufferListInfo[UdpRecvSegCoalesceOffloadInfo as usize] = null_mut();
        nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] = (1usize << 32) as PVOID;
        assert!(!send_segmented(&mut nbl));
        nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] = 1 as PVOID;
        assert_eq!(snapshot_offload(&mut nbl), 0); // ReceiveNoPush is not coalescing.
        (*context).direction = 0;
        assert_eq!(snapshot_offload(&mut nbl), 1);
        nbl.NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize] = null_mut();
        nbl.NetBufferListInfo[UdpSegmentationOffloadInfo as usize] = 1 as PVOID;
        assert_eq!(snapshot_offload(&mut nbl), 1);
        free_packet_context(&mut nbl);
    }
    assert_no_leaks();
}
