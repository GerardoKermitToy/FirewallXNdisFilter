// Native WDK WFP boundary. Policy, management state, checksum algorithms and
// pending/injection ownership decisions remain in wfp.rs and wfp_checksum.rs.
// Native layouts come exclusively from the installed x64 WDK headers.

#[cfg(not(test))]
use crate::wdk as sys;
use crate::{
    native::hv_bugcheck,
    native_packet::{
        OWNER_WFP_CLONE, OWNER_WFP_REASSEMBLED, allocate_packet_context, current_mdl,
        current_mdl_offset, data_length, first_nb, free_packet_context, map_mdl, next_nb, next_nbl,
        packet_context,
    },
    wdk::*,
};
#[cfg(feature = "wfp-fragment-diagnostic")]
use core::sync::atomic::{AtomicU32, Ordering::SeqCst};
use core::{
    ffi::{c_char, c_void},
    mem::{align_of, offset_of, size_of, zeroed},
    ptr::{self, addr_of_mut},
};
#[cfg(test)]
#[path = "native_wfp_tests.rs"]
mod tests;
#[cfg(test)]
use tests as sys;
#[cfg(all(test, feature = "wfp-fragment-diagnostic"))]
use tests::rust_fragment_diagnostic;
#[cfg(test)]
use tests::{
    rust_bfe_changed, rust_classify, rust_enter_classify, rust_injection_complete,
    rust_reconcile_worker, rust_request_reconcile,
};

type Handle = *mut c_void;

// This normalized ABI matches the private types in wfp.rs. Native FWPS
// structures never cross that interface.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct ForwardValues {
    source: u32,
    destination: u32,
    sub_interface: u32,
    flags: u32,
    compartment: u32,
}
#[repr(C)]
#[derive(Default)]
pub(crate) struct PacketInfo {
    route: ForwardValues,
    ipv6: u8,
    segmented: u8,
    reserved: [u8; 2],
}
#[repr(u32)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // Constructed by wfp.rs across the normalized C ABI.
pub(crate) enum InjectionRoute {
    Forward,
    NetworkReceive,
    NetworkSend,
}
const _: () = {
    assert!(size_of::<ForwardValues>() == 20);
    assert!(align_of::<ForwardValues>() == 4);
    assert!(offset_of!(ForwardValues, compartment) == 16);
    assert!(size_of::<PacketInfo>() == 24);
    assert!(offset_of!(PacketInfo, ipv6) == 20);
    assert!(size_of::<InjectionRoute>() == 4);
    assert!(FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU == 0x80000);
    assert!(FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU == 0x40000);
    assert!(FWP_CONDITION_FLAG_IS_FRAGMENT == 0x20);
    assert!(FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP == 0x40);
    assert!(FWP_CONDITION_FLAG_IS_REASSEMBLED == 0x400);
};

#[cfg(not(test))]
unsafe extern "C" {
    #[link_name = "HvWfpRequestReconcile"]
    fn rust_request_reconcile();
    #[link_name = "HvWfpReconcileWorker"]
    fn rust_reconcile_worker();
    #[link_name = "HvWfpBfeChanged"]
    fn rust_bfe_changed(reset: u8);
    #[link_name = "HvWfpEnterClassify"]
    fn rust_enter_classify() -> u8;
    #[link_name = "HvWfpClassify"]
    fn rust_classify(original: Handle, route: *const ForwardValues, ipv6: u8, valid: u8) -> u8;
    #[link_name = "HvWfpInjectionComplete"]
    fn rust_injection_complete(nbl: Handle, status: i32);
    #[cfg(feature = "wfp-fragment-diagnostic")]
    #[link_name = "HvWfpFragmentDiagnostic"]
    fn rust_fragment_diagnostic(
        kind: u32,
        flags: u32,
        source: u32,
        destination: u32,
        length: u32,
        chained: u32,
        count: u32,
    );
}

unsafe extern "C" {
    #[link_name = "HvWfpChecksumSpan"]
    fn rust_checksum_span(bytes: *const u8, length: u32, position: u32, field: u32) -> u64;
}

static PROVIDER_KEY: GUID = GUID {
    Data1: 0xdabca0a1,
    Data2: 0xf4bc,
    Data3: 0x4bf3,
    Data4: [0x83, 0x32, 0x36, 0xa3, 0x45, 0xa0, 0x42, 0xa8],
};
static SUBLAYER_KEY: GUID = GUID {
    Data1: 0xeb7769b1,
    Data2: 0x00b4,
    Data3: 0x4284,
    Data4: [0x9e, 0xc9, 0x88, 0x59, 0x38, 0x90, 0x01, 0x3d],
};
static CALLOUT_KEYS: [GUID; 2] = [
    GUID {
        Data1: 0x534c42b4,
        Data2: 0xf219,
        Data3: 0x4f7c,
        Data4: [0xb2, 0x32, 0x54, 0xe9, 0x03, 0x8e, 0xf8, 0x66],
    },
    GUID {
        Data1: 0xdf905bbf,
        Data2: 0xe38a,
        Data3: 0x4347,
        Data4: [0x9b, 0xe0, 0x72, 0x58, 0x4c, 0xd2, 0xa1, 0x27],
    },
];
// fwpmk.h DEFINE_GUID values, not unresolved import-library GUID symbols.
static LAYERS: [GUID; 2] = [
    GUID {
        Data1: 0xa82acc24,
        Data2: 0x4ee1,
        Data3: 0x4ee1,
        Data4: [0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4],
    },
    GUID {
        Data1: 0x7b964818,
        Data2: 0x19c7,
        Data3: 0x493a,
        Data4: [0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c],
    },
];
const FAMILIES: [ADDRESS_FAMILY; 2] = [AF_INET as ADDRESS_FAMILY, AF_INET6 as ADDRESS_FAMILY];

// Initialized before publishing callouts/work. Teardown drains work, classify
// and packet rundown before deleting native objects. No Rust references to
// mutable dispatcher objects survive a WDK callback.
static mut MANAGEMENT_MUTEX: KMUTEX = unsafe { zeroed() };
static mut CLASSIFY_RUNDOWN: EX_RUNDOWN_REF = unsafe { zeroed() };
static mut WORK_RUNDOWN: EX_RUNDOWN_REF = unsafe { zeroed() };
static mut PACKET_RUNDOWN: EX_RUNDOWN_REF = unsafe { zeroed() };
static mut WORK_ITEM: PIO_WORKITEM = ptr::null_mut();
static mut RETRY_TIMER: KTIMER = unsafe { zeroed() };
static mut RETRY_DPC: KDPC = unsafe { zeroed() };
static mut WFP_DEVICE: PDEVICE_OBJECT = ptr::null_mut();
#[cfg(feature = "wfp-fragment-diagnostic")]
static DIAGNOSTIC_COUNTS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

fn rundown(kind: u32) -> *mut EX_RUNDOWN_REF {
    match kind {
        0 => addr_of_mut!(WORK_RUNDOWN),
        1 => addr_of_mut!(CLASSIFY_RUNDOWN),
        2 => addr_of_mut!(PACKET_RUNDOWN),
        _ => hv_bugcheck(),
    }
}
fn family_index(family: u32) -> Option<usize> {
    match family {
        0 => Some(0),
        1 => Some(1),
        _ => None,
    }
}
unsafe extern "C" fn retry_registration(
    _dpc: *mut KDPC,
    _context: Handle,
    _first: Handle,
    _second: Handle,
) {
    unsafe {
        rust_request_reconcile();
    }
}
unsafe extern "C" fn reconcile_worker(_device: PDEVICE_OBJECT, _context: Handle) {
    unsafe {
        rust_reconcile_worker();
    }
}
unsafe extern "C" fn bfe_changed(_context: Handle, state: FWPM_SERVICE_STATE) {
    unsafe {
        rust_bfe_changed(u8::from(
            state == FWPM_SERVICE_STOP_PENDING || state == FWPM_SERVICE_STOPPED,
        ));
    }
}
unsafe fn forward_u32(values: *const FWPS_INCOMING_VALUES0, field: u32, out: *mut u32) -> bool {
    unsafe {
        if field >= (*values).valueCount {
            return false;
        }
        let value = &(*(*values).incomingValue.add(field as usize)).value;
        if value.type_ != FWP_UINT32 {
            return false;
        }
        out.write(value.__bindgen_anon_1.uint32);
        true
    }
}
unsafe fn decode_forward(
    values: *const FWPS_INCOMING_VALUES0,
    metadata: *const FWPS_INCOMING_METADATA_VALUES0,
    ipv6: bool,
    route: &mut ForwardValues,
) -> bool {
    unsafe {
        if (*values).incomingValue.is_null()
            || !forward_u32(
                values,
                if ipv6 {
                    FWPS_FIELD_IPFORWARD_V6_SOURCE_INTERFACE_INDEX as u32
                } else {
                    FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX as u32
                },
                &mut route.source,
            )
            || !forward_u32(
                values,
                if ipv6 {
                    FWPS_FIELD_IPFORWARD_V6_DESTINATION_INTERFACE_INDEX as u32
                } else {
                    FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX as u32
                },
                &mut route.destination,
            )
            || !forward_u32(
                values,
                if ipv6 {
                    FWPS_FIELD_IPFORWARD_V6_FLAGS as u32
                } else {
                    FWPS_FIELD_IPFORWARD_V4_FLAGS as u32
                },
                &mut route.flags,
            )
            || route.source == 0
            || route.destination == 0
        {
            return false;
        }
        if route.flags & FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU != 0
            && !forward_u32(
                values,
                if ipv6 {
                    FWPS_FIELD_IPFORWARD_V6_DESTINATION_SUB_INTERFACE_INDEX as u32
                } else {
                    FWPS_FIELD_IPFORWARD_V4_DESTINATION_SUB_INTERFACE_INDEX as u32
                },
                &mut route.sub_interface,
            )
        {
            return false;
        }
        route.compartment = if !metadata.is_null()
            && (*metadata).currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID != 0
        {
            (*metadata).compartmentId
        } else {
            UNSPECIFIED_COMPARTMENT_ID as u32
        };
        true
    }
}
unsafe extern "C" fn classify(
    values: *const FWPS_INCOMING_VALUES0,
    metadata: *const FWPS_INCOMING_METADATA_VALUES0,
    layer_data: Handle,
    _filter: *const FWPS_FILTER0,
    _flow_context: u64,
    out: *mut FWPS_CLASSIFY_OUT0,
) {
    unsafe {
        if (*out).rights & FWPS_RIGHT_ACTION_WRITE == 0 {
            return;
        }
        let mut permit = false;
        if rust_enter_classify() != 0 {
            let mut route = ForwardValues::default();
            let layer = !values.is_null()
                && !layer_data.is_null()
                && (u32::from((*values).layerId) == FWPS_LAYER_IPFORWARD_V4 as u32
                    || u32::from((*values).layerId) == FWPS_LAYER_IPFORWARD_V6 as u32);
            let ipv6 = layer && u32::from((*values).layerId) == FWPS_LAYER_IPFORWARD_V6 as u32;
            let valid = layer && decode_forward(values, metadata, ipv6, &mut route);
            permit = rust_classify(
                if layer { layer_data } else { ptr::null_mut() },
                &route,
                u8::from(ipv6),
                u8::from(valid),
            ) != 0;
            // No NBL dereference after policy publication, even for inline completion.
            sys::ExReleaseRundownProtection(addr_of_mut!(CLASSIFY_RUNDOWN));
        }
        if permit {
            (*out).actionType = FWP_ACTION_PERMIT;
            (*out).flags &= !FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        } else {
            (*out).actionType = FWP_ACTION_BLOCK;
            (*out).flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            (*out).rights &= !FWPS_RIGHT_ACTION_WRITE;
        }
    }
}
unsafe extern "C" fn notify(
    _kind: FWPS_CALLOUT_NOTIFY_TYPE,
    _key: *const GUID,
    _filter: *mut FWPS_FILTER0,
) -> NTSTATUS {
    HV_WDK_STATUS_SUCCESS as NTSTATUS
}
unsafe fn forward_byte(nb: *mut NET_BUFFER, mut index: u32) -> *mut u8 {
    unsafe {
        if index >= data_length(nb) {
            return ptr::null_mut();
        }
        let mut mdl = current_mdl(nb);
        let mut offset = current_mdl_offset(nb);
        while !mdl.is_null() {
            let length = (*mdl).ByteCount;
            if offset > length {
                return ptr::null_mut();
            }
            let available = length - offset;
            if index < available {
                let data = map_mdl(mdl);
                return if data.is_null() {
                    ptr::null_mut()
                } else {
                    data.add(offset as usize + index as usize)
                };
            }
            index -= available;
            offset = 0;
            mdl = (*mdl).Next;
        }
        ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ForwardRead(
    nb: *mut NET_BUFFER,
    mut offset: u32,
    bytes: *mut u8,
    length: u32,
) -> u8 {
    unsafe {
        let nb_length = data_length(nb);
        if offset > nb_length || length > nb_length - offset {
            return 0;
        }
        let mut mdl = current_mdl(nb);
        let mut skip = current_mdl_offset(nb);
        let mut copied = 0;
        while !mdl.is_null() && copied != length {
            let size = (*mdl).ByteCount;
            if skip > size {
                return 0;
            }
            let mut available = size - skip;
            if offset >= available {
                offset -= available;
            } else {
                skip += offset;
                available -= offset;
                let take = available.min(length - copied);
                if take != 0 {
                    let data = map_mdl(mdl);
                    if data.is_null() {
                        return 0;
                    }
                    ptr::copy_nonoverlapping(
                        data.add(skip as usize),
                        bytes.add(copied as usize),
                        take as usize,
                    );
                    copied += take;
                }
                offset = 0;
            }
            skip = 0;
            mdl = (*mdl).Next;
        }
        u8::from(copied == length)
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_sum(
    nb: *mut NET_BUFFER,
    start: u32,
    length: u32,
    field: u32,
    result: *mut u64,
) -> u8 {
    unsafe {
        let nb_length = data_length(nb);
        if start > nb_length || length > nb_length - start {
            return 0;
        }
        let mut mdl = current_mdl(nb);
        let mut skip = current_mdl_offset(nb);
        let mut position = 0;
        let mut range = start;
        let mut sum = 0;
        while !mdl.is_null() && position != length {
            let size = (*mdl).ByteCount;
            if skip > size {
                return 0;
            }
            let mut available = size - skip;
            if range >= available {
                range -= available;
            } else {
                skip += range;
                available -= range;
                let take = available.min(length - position);
                if take != 0 {
                    let bytes = map_mdl(mdl);
                    if bytes.is_null() {
                        return 0;
                    }
                    sum += rust_checksum_span(bytes.add(skip as usize), take, position, field);
                    position += take;
                }
                range = 0;
            }
            skip = 0;
            mdl = (*mdl).Next;
        }
        if position != length {
            return 0;
        }
        result.write(sum);
        1
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn WriteForwardChecksum(
    nb: *mut NET_BUFFER,
    offset: u32,
    checksum: u16,
) -> u8 {
    unsafe {
        let Some(next) = offset.checked_add(1) else {
            return 0;
        };
        let high = forward_byte(nb, offset);
        let low = forward_byte(nb, next);
        if high.is_null() || low.is_null() {
            return 0;
        }
        high.write((checksum >> 8) as u8);
        low.write(checksum as u8);
        1
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_native_initialize(driver: PDRIVER_OBJECT) -> NTSTATUS {
    unsafe {
        sys::KeInitializeMutex(addr_of_mut!(MANAGEMENT_MUTEX), 0);
        for kind in 0..3 {
            sys::ExInitializeRundownProtection(rundown(kind));
        }
        sys::KeInitializeTimer(addr_of_mut!(RETRY_TIMER));
        sys::KeInitializeDpc(
            addr_of_mut!(RETRY_DPC),
            Some(retry_registration),
            ptr::null_mut(),
        );
        WFP_DEVICE = ptr::null_mut();
        WORK_ITEM = ptr::null_mut();
        let status = sys::IoCreateDevice(
            driver,
            0,
            ptr::null_mut(),
            FILE_DEVICE_UNKNOWN,
            0,
            0,
            addr_of_mut!(WFP_DEVICE),
        );
        if status < 0 {
            return status;
        }
        (*WFP_DEVICE).Flags &= !DO_DEVICE_INITIALIZING;
        WORK_ITEM = sys::IoAllocateWorkItem(WFP_DEVICE);
        if WORK_ITEM.is_null() {
            HV_WDK_STATUS_INSUFFICIENT_RESOURCES as NTSTATUS
        } else {
            HV_WDK_STATUS_SUCCESS as NTSTATUS
        }
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_delete_device() {
    unsafe {
        if !WFP_DEVICE.is_null() {
            sys::IoDeleteDevice(WFP_DEVICE);
            WFP_DEVICE = ptr::null_mut();
        }
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_lock() {
    unsafe {
        // A FAST_MUTEX would raise IRQL above PASSIVE_LEVEL, invalid for FWPM.
        let _ = sys::KeWaitForSingleObject(
            addr_of_mut!(MANAGEMENT_MUTEX).cast(),
            Executive,
            KernelMode as KPROCESSOR_MODE,
            0,
            ptr::null_mut(),
        );
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_unlock() {
    unsafe {
        sys::KeReleaseMutex(addr_of_mut!(MANAGEMENT_MUTEX), 0);
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_acquire(kind: u32) -> u8 {
    unsafe { sys::ExAcquireRundownProtection(rundown(kind)) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_release(kind: u32) {
    unsafe {
        sys::ExReleaseRundownProtection(rundown(kind));
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_wait(kind: u32) {
    unsafe {
        sys::ExWaitForRundownProtectionRelease(rundown(kind));
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_queue_work() {
    unsafe {
        sys::IoQueueWorkItem(
            WORK_ITEM,
            Some(reconcile_worker),
            DelayedWorkQueue,
            ptr::null_mut(),
        );
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_free_work() {
    unsafe {
        if !WORK_ITEM.is_null() {
            sys::IoFreeWorkItem(WORK_ITEM);
            WORK_ITEM = ptr::null_mut();
        }
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_timer(arm: u8) {
    unsafe {
        if arm != 0 {
            let due = LARGE_INTEGER {
                QuadPart: -10_000_000,
            };
            sys::KeSetTimer(addr_of_mut!(RETRY_TIMER), due, addr_of_mut!(RETRY_DPC));
        } else {
            sys::KeCancelTimer(addr_of_mut!(RETRY_TIMER));
        }
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_flush_dpcs() {
    unsafe {
        sys::KeFlushQueuedDpcs();
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_delay() {
    unsafe {
        let mut delay = LARGE_INTEGER {
            QuadPart: -1_000_000,
        };
        let _ = sys::KeDelayExecutionThread(KernelMode as KPROCESSOR_MODE, 0, &mut delay);
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_subscribe(subscription: *mut Handle) -> NTSTATUS {
    unsafe {
        sys::FwpmBfeStateSubscribeChanges0(
            WFP_DEVICE.cast(),
            Some(bfe_changed),
            ptr::null_mut(),
            subscription,
        )
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_unsubscribe(subscription: Handle) -> NTSTATUS {
    unsafe { sys::FwpmBfeStateUnsubscribeChanges0(subscription) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_bfe_running() -> u8 {
    unsafe { u8::from(sys::FwpmBfeStateGet0() == FWPM_SERVICE_RUNNING) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_callout_register(family: u32, id: *mut u32) -> NTSTATUS {
    unsafe {
        let Some(index) = family_index(family) else {
            return HV_WDK_STATUS_INVALID_PARAMETER as NTSTATUS;
        };
        let callout = FWPS_CALLOUT0 {
            calloutKey: CALLOUT_KEYS[index],
            classifyFn: Some(classify),
            notifyFn: Some(notify),
            ..zeroed()
        };
        sys::FwpsCalloutRegister0(WFP_DEVICE.cast(), &callout, id)
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_callout_unregister(id: u32) -> NTSTATUS {
    unsafe { sys::FwpsCalloutUnregisterById0(id) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_injection_create(
    family: u32,
    network: u8,
    handle: *mut Handle,
) -> NTSTATUS {
    unsafe {
        let Some(index) = family_index(family) else {
            return HV_WDK_STATUS_INVALID_PARAMETER as NTSTATUS;
        };
        sys::FwpsInjectionHandleCreate0(
            FAMILIES[index],
            if network != 0 {
                FWPS_INJECTION_TYPE_NETWORK
            } else {
                FWPS_INJECTION_TYPE_FORWARD
            },
            handle,
        )
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_injection_destroy(handle: Handle) -> NTSTATUS {
    unsafe { sys::FwpsInjectionHandleDestroy0(handle) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_engine_open(engine: *mut Handle) -> NTSTATUS {
    unsafe {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..zeroed()
        };
        sys::FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_WINNT,
            ptr::null_mut(),
            &session,
            engine,
        )
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_engine_close(engine: Handle) -> NTSTATUS {
    unsafe { sys::FwpmEngineClose0(engine) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_transaction_begin(engine: Handle) -> NTSTATUS {
    unsafe { sys::FwpmTransactionBegin0(engine, 0) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_transaction_commit(engine: Handle) -> NTSTATUS {
    unsafe { sys::FwpmTransactionCommit0(engine) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_transaction_abort(engine: Handle) {
    unsafe {
        let _ = sys::FwpmTransactionAbort0(engine);
    }
}

// These exact display names are ASCII; encode without allocation/std imports.
const fn wide<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut result = [0; N];
    let mut index = 0;
    while index < N {
        result[index] = bytes[index] as u16;
        index += 1;
    }
    result
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_provider_add(engine: Handle) -> NTSTATUS {
    unsafe {
        let mut name = wide(b"HyperVXNdisFilter\0");
        let mut provider: FWPM_PROVIDER0 = zeroed();
        provider.providerKey = PROVIDER_KEY;
        provider.displayData.name = name.as_mut_ptr();
        sys::FwpmProviderAdd0(engine, &provider, ptr::null_mut())
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_sublayer_add(engine: Handle, weight: u16) -> NTSTATUS {
    unsafe {
        let mut name = wide(b"HyperVXNdisFilter forwarding\0");
        let mut sublayer: FWPM_SUBLAYER0 = zeroed();
        sublayer.subLayerKey = SUBLAYER_KEY;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.providerKey = ptr::addr_of!(PROVIDER_KEY).cast_mut();
        sublayer.weight = weight;
        sys::FwpmSubLayerAdd0(engine, &sublayer, ptr::null_mut())
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_callout_add(engine: Handle, family: u32) -> NTSTATUS {
    unsafe {
        let Some(index) = family_index(family) else {
            return HV_WDK_STATUS_INVALID_PARAMETER as NTSTATUS;
        };
        let mut name = wide(b"HyperVXNdisFilter IPFORWARD\0");
        let mut callout: FWPM_CALLOUT0 = zeroed();
        callout.calloutKey = CALLOUT_KEYS[index];
        callout.displayData.name = name.as_mut_ptr();
        callout.providerKey = ptr::addr_of!(PROVIDER_KEY).cast_mut();
        callout.applicableLayer = LAYERS[index];
        sys::FwpmCalloutAdd0(engine, &callout, ptr::null_mut(), ptr::null_mut())
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_filter_add(engine: Handle, family: u32) -> NTSTATUS {
    unsafe {
        let Some(index) = family_index(family) else {
            return HV_WDK_STATUS_INVALID_PARAMETER as NTSTATUS;
        };
        let mut filter: FWPM_FILTER0 = zeroed();
        let status = sys::ExUuidCreate(&mut filter.filterKey);
        if status < 0 {
            return status;
        }
        let mut name = wide(b"HyperVXNdisFilter global forwarding\0");
        filter.displayData.name = name.as_mut_ptr();
        filter.providerKey = ptr::addr_of!(PROVIDER_KEY).cast_mut();
        filter.layerKey = LAYERS[index];
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.type_ = FWP_EMPTY;
        filter.action.type_ = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.__bindgen_anon_1.calloutKey = CALLOUT_KEYS[index];
        // Zero conditions. wfp.rs requests exactly two global forwarding filters,
        // without interface inventories, HNS target conditions or persistent state.
        sys::FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut())
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_report(operation: *const c_char, status: NTSTATUS) {
    unsafe {
        sys::DbgPrintEx(
            DPFLTR_IHVNETWORK_ID as u32,
            DPFLTR_ERROR_LEVEL,
            c"HyperVXNdisFilter: WFP %s failed: 0x%08lX\n".as_ptr(),
            operation,
            status as u32,
        );
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_is_self(handle: Handle, nbl: *mut NET_BUFFER_LIST) -> u8 {
    unsafe {
        let state = sys::FwpsQueryPacketInjectionState0(handle, nbl, ptr::null_mut());
        u8::from(
            state == FWPS_PACKET_INJECTED_BY_SELF
                || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF,
        )
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_inject(
    handle: Handle,
    route: InjectionRoute,
    ipv6: u8,
    compartment: u32,
    destination: u32,
    sub_interface: u32,
    nbl: *mut NET_BUFFER_LIST,
    completion: FWPS_INJECT_COMPLETE0,
    context: Handle,
) -> NTSTATUS {
    unsafe {
        // The generated C callback ABI and NTAPI/system ABI are identical on x64.
        // Callback/context pass through intact. No NBL access after submission:
        // injection completion is permitted to run inline and free the NBL.
        match route {
            InjectionRoute::NetworkReceive => sys::FwpsInjectNetworkReceiveAsync0(
                handle,
                ptr::null_mut(),
                0,
                compartment as COMPARTMENT_ID,
                destination,
                sub_interface,
                nbl,
                completion,
                context,
            ),
            InjectionRoute::NetworkSend => sys::FwpsInjectNetworkSendAsync0(
                handle,
                ptr::null_mut(),
                0,
                compartment as COMPARTMENT_ID,
                nbl,
                completion,
                context,
            ),
            InjectionRoute::Forward => sys::FwpsInjectForwardAsync0(
                handle,
                ptr::null_mut(),
                0,
                FAMILIES[usize::from(ipv6 != 0)],
                compartment as COMPARTMENT_ID,
                destination,
                nbl,
                completion,
                context,
            ),
        }
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_first_nb(nbl: *mut NET_BUFFER_LIST) -> *mut NET_BUFFER {
    unsafe { first_nb(nbl) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_next_nb(nb: *mut NET_BUFFER) -> *mut NET_BUFFER {
    unsafe { next_nb(nb) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_nb_length(nb: *mut NET_BUFFER) -> u32 {
    unsafe { data_length(nb) }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_clear_checksum(nbl: *mut NET_BUFFER_LIST) {
    unsafe {
        (*nbl).NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize] = ptr::null_mut();
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_packet_info(
    nbl: *mut NET_BUFFER_LIST,
    info: *mut PacketInfo,
) {
    unsafe {
        let packet = packet_context(nbl);
        info.write(PacketInfo {
            route: ForwardValues {
                destination: (*packet).forward_interface,
                sub_interface: (*packet).forward_sub_interface,
                flags: (*packet).flags,
                compartment: (*packet).compartment,
                ..ForwardValues::default()
            },
            ipv6: (*packet).ipv6,
            segmented: (*packet).segmented,
            reserved: [0; 2],
        });
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_free_packet(nbl: *mut NET_BUFFER_LIST) {
    unsafe {
        let owner = (*packet_context(nbl)).owner;
        free_packet_context(nbl);
        if owner == OWNER_WFP_REASSEMBLED {
            sys::FwpsFreeNetBufferList0(nbl);
        } else {
            sys::FwpsFreeCloneNetBufferList0(nbl, 0);
        }
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn hv_wfp_complete(
    context: Handle,
    nbl: *mut NET_BUFFER_LIST,
    _dispatch: u8,
) {
    unsafe {
        if context != nbl.cast() {
            hv_bugcheck();
        }
        rust_injection_complete(nbl.cast(), (*nbl).__bindgen_anon_2.Status as NTSTATUS);
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_clone(
    original: *mut NET_BUFFER_LIST,
    route: *const ForwardValues,
    ipv6: u8,
) -> *mut NET_BUFFER_LIST {
    unsafe {
        let grouped = (*route).flags & FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP != 0;
        // Preserve scalar segmentation/coalescing before clone/reassembly drops OOB.
        let segmented = !(*original).NetBufferListInfo[TcpLargeSendNetBufferListInfo as usize]
            .is_null()
            || !(*original).NetBufferListInfo[TcpRecvSegCoalesceInfo as usize].is_null()
            || !(*original).NetBufferListInfo[TcpReceiveBytesTransferred as usize].is_null();
        if !grouped && !next_nbl(original).is_null() {
            return ptr::null_mut();
        }
        let mut nbl = ptr::null_mut();
        let status = if grouped {
            sys::FwpsReassembleForwardFragmentGroup0(
                FAMILIES[usize::from(ipv6 != 0)],
                original,
                ptr::null_mut(),
                0,
                0,
                &mut nbl,
            )
        } else {
            sys::FwpsAllocateCloneNetBufferList0(
                original,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut nbl,
            )
        };
        if status < 0 {
            return ptr::null_mut();
        }
        let context = allocate_packet_context(nbl);
        if context.is_null() {
            if grouped {
                sys::FwpsFreeNetBufferList0(nbl);
            } else {
                sys::FwpsFreeCloneNetBufferList0(nbl, 0);
            }
            return ptr::null_mut();
        }
        (*context).owner = if grouped {
            OWNER_WFP_REASSEMBLED
        } else {
            OWNER_WFP_CLONE
        };
        (*context).ipv6 = ipv6;
        (*context).segmented = u8::from(segmented);
        (*context).forward_interface = (*route).destination;
        (*context).forward_sub_interface = (*route).sub_interface;
        (*context).flags = (*route).flags;
        (*context).compartment = (*route).compartment;
        nbl
    }
}
#[unsafe(no_mangle)]
pub(crate) extern "C" fn hv_wfp_reset_diagnostics() {
    #[cfg(feature = "wfp-fragment-diagnostic")]
    for count in &DIAGNOSTIC_COUNTS {
        count.store(0, SeqCst);
    }
}
#[cfg(feature = "wfp-fragment-diagnostic")]
unsafe fn diagnostic_ipv4_fragment(ip: *const u8, length: u32, grouped: bool) -> bool {
    unsafe {
        if grouped || ip.is_null() || length < 20 || *ip >> 4 != 4 {
            return false;
        }
        let header = u32::from(*ip & 15) * 4;
        let total = u32::from(*ip.add(2)) << 8 | u32::from(*ip.add(3));
        header >= 20
            && header <= total
            && total <= length
            && (u32::from(*ip.add(6)) << 8 | u32::from(*ip.add(7))) & 0x3fff != 0
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn hv_wfp_diagnostic_permit(
    _original: *mut NET_BUFFER_LIST,
    _route: *const ForwardValues,
    _ipv6: u8,
) -> u8 {
    #[cfg(feature = "wfp-fragment-diagnostic")]
    if _ipv6 == 0 {
        unsafe {
            let nb = first_nb(_original);
            let length = if nb.is_null() { 0 } else { data_length(nb) };
            let mut header = [0u8; 20];
            let ip = if nb.is_null() || length < header.len() as u32 {
                ptr::null()
            } else {
                sys::NdisGetDataBuffer(nb, header.len() as u32, header.as_mut_ptr().cast(), 1, 0)
                    .cast_const()
                    .cast::<u8>()
            };
            let grouped = (*_route).flags & FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP != 0;
            let permit = diagnostic_ipv4_fragment(ip, length, grouped);
            let kind = if permit {
                0
            } else if grouped {
                1
            } else {
                2
            };
            if permit || grouped || length > 1500 {
                let count = DIAGNOSTIC_COUNTS[kind].fetch_add(1, SeqCst).wrapping_add(1);
                if count <= 32 {
                    rust_fragment_diagnostic(
                        kind as u32,
                        (*_route).flags,
                        (*_route).source,
                        (*_route).destination,
                        length,
                        u32::from(!next_nbl(_original).is_null()),
                        count,
                    );
                }
            }
            return u8::from(permit);
        }
    }
    0
}
