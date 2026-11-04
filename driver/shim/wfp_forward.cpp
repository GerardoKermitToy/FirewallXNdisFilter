// Native WDK layouts and calls only. State, checksums and ownership decisions are Rust.
#ifdef HV_WFP_OFFLINE_TEST
#include "../../monitor/tests/wfp_fake_api.h"
#else
#include <ntifs.h>
#include <ndis.h>
#include <initguid.h>
#endif
#include "wfp_forward.h"
#include "nbl_context.h"

extern "C" __declspec(noreturn) void hv_bugcheck(void);
#ifdef HV_WFP_FRAGMENT_PERMIT_DIAGNOSTIC
extern "C" void HvWfpFragmentDiagnostic(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
static volatile LONG ForwardDiagnosticCounts[3];
#endif

namespace {
const GUID ProviderKey = {0xdabca0a1, 0xf4bc, 0x4bf3, {0x83, 0x32, 0x36, 0xa3, 0x45, 0xa0, 0x42, 0xa8}};
const GUID SublayerKey = {0xeb7769b1, 0x00b4, 0x4284, {0x9e, 0xc9, 0x88, 0x59, 0x38, 0x90, 0x01, 0x3d}};
const GUID CalloutKeys[2] = {
    {0x534c42b4, 0xf219, 0x4f7c, {0xb2, 0x32, 0x54, 0xe9, 0x03, 0x8e, 0xf8, 0x66}},
    {0xdf905bbf, 0xe38a, 0x4347, {0x9b, 0xe0, 0x72, 0x58, 0x4c, 0xd2, 0xa1, 0x27}}
};
const GUID* const Layers[2] = {&FWPM_LAYER_IPFORWARD_V4, &FWPM_LAYER_IPFORWARD_V6};
const ADDRESS_FAMILY Families[2] = {AF_INET, AF_INET6};
KMUTEX ManagementMutex;
EX_RUNDOWN_REF ClassifyRundown, WorkRundown, PacketRundown;
EX_RUNDOWN_REF* const Rundowns[] = {&WorkRundown, &ClassifyRundown, &PacketRundown};
PIO_WORKITEM WorkItem;
KTIMER RetryTimer;
KDPC RetryDpc;
PDEVICE_OBJECT WfpDevice;

void NTAPI RetryRegistration(KDPC* dpc, void* context, void* first, void* second) {
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(first); UNREFERENCED_PARAMETER(second);
    HvWfpRequestReconcile();
}
_Use_decl_annotations_
void ReconcileWorker(PDEVICE_OBJECT device, void* context) {
    UNREFERENCED_PARAMETER(device); UNREFERENCED_PARAMETER(context);
    HvWfpReconcileWorker();
}
void NTAPI BfeChanged(void* context, FWPM_SERVICE_STATE state) {
    UNREFERENCED_PARAMETER(context);
    HvWfpBfeChanged(state == FWPM_SERVICE_STOP_PENDING || state == FWPM_SERVICE_STOPPED);
}
BOOLEAN ForwardU32(const FWPS_INCOMING_VALUES0* values, ULONG field, ULONG* out) {
    if (field >= values->valueCount || values->incomingValue[field].value.type != FWP_UINT32) return FALSE;
    *out = values->incomingValue[field].value.uint32;
    return TRUE;
}
BOOLEAN DecodeForward(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, BOOLEAN ipv6, HV_FORWARD_VALUES* route) {
    if (values->incomingValue == NULL ||
        !ForwardU32(values, ipv6 ? FWPS_FIELD_IPFORWARD_V6_SOURCE_INTERFACE_INDEX : FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX, &route->SourceIndex) ||
        !ForwardU32(values, ipv6 ? FWPS_FIELD_IPFORWARD_V6_DESTINATION_INTERFACE_INDEX : FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX, &route->DestinationIndex) ||
        !ForwardU32(values, ipv6 ? FWPS_FIELD_IPFORWARD_V6_FLAGS : FWPS_FIELD_IPFORWARD_V4_FLAGS, &route->Flags) ||
        route->SourceIndex == 0 || route->DestinationIndex == 0) return FALSE;
    if ((route->Flags & FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU) != 0 &&
        !ForwardU32(values, ipv6 ? FWPS_FIELD_IPFORWARD_V6_DESTINATION_SUB_INTERFACE_INDEX :
            FWPS_FIELD_IPFORWARD_V4_DESTINATION_SUB_INTERFACE_INDEX, &route->DestinationSubIndex)) return FALSE;
    route->Compartment = metadata != NULL &&
        (metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) != 0 ?
        metadata->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
    return TRUE;
}
void NTAPI Classify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, void* layerData,
    const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flowContext);
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    BOOLEAN permit = FALSE;
    if (HvWfpEnterClassify()) {
        HV_FORWARD_VALUES route = {};
        BOOLEAN layer = values != NULL && layerData != NULL &&
            (values->layerId == FWPS_LAYER_IPFORWARD_V4 || values->layerId == FWPS_LAYER_IPFORWARD_V6);
        BOOLEAN ipv6 = layer && values->layerId == FWPS_LAYER_IPFORWARD_V6;
        BOOLEAN valid = layer && DecodeForward(values, metadata, ipv6, &route);
        permit = HvWfpClassify(layer ? static_cast<PNET_BUFFER_LIST>(layerData) : NULL, &route, ipv6, valid);
        ExReleaseRundownProtection(&ClassifyRundown);
    }
    if (permit) {
        out->actionType = FWP_ACTION_PERMIT;
        out->flags &= ~FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    } else {
        out->actionType = FWP_ACTION_BLOCK;
        out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}
NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER0* filter) {
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}
UCHAR* ForwardByte(PNET_BUFFER nb, ULONG index) {
    if (index >= NET_BUFFER_DATA_LENGTH(nb)) return NULL;
    PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
    ULONG offset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    while (mdl != NULL) {
        ULONG length = MmGetMdlByteCount(mdl);
        if (offset > length) return NULL;
        ULONG available = length - offset;
        if (index < available) {
            auto* data = static_cast<UCHAR*>(MmGetSystemAddressForMdlSafe(mdl,
                NormalPagePriority | MdlMappingNoExecute));
            return data == NULL ? NULL : data + offset + index;
        }
        index -= available;
        offset = 0;
        mdl = mdl->Next;
    }
    return NULL;
}
} // namespace

extern "C" BOOLEAN ForwardRead(PNET_BUFFER nb, ULONG offset, UCHAR* bytes, ULONG length) {
    if (offset > NET_BUFFER_DATA_LENGTH(nb) || length > NET_BUFFER_DATA_LENGTH(nb) - offset) return FALSE;
    PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
    ULONG skip = NET_BUFFER_CURRENT_MDL_OFFSET(nb), copied = 0;
    while (mdl != NULL && copied != length) {
        ULONG size = MmGetMdlByteCount(mdl);
        if (skip > size) return FALSE;
        ULONG available = size - skip;
        if (offset >= available) offset -= available;
        else {
            skip += offset;
            available -= offset;
            ULONG take = available;
            if (take > length - copied) take = length - copied;
            if (take != 0) {
                const auto* data = static_cast<const UCHAR*>(MmGetSystemAddressForMdlSafe(mdl,
                    NormalPagePriority | MdlMappingNoExecute));
                if (data == NULL) return FALSE;
                RtlCopyMemory(bytes + copied, data + skip, take);
                copied += take;
            }
            offset = 0;
        }
        skip = 0;
        mdl = mdl->Next;
    }
    return copied == length;
}
extern "C" BOOLEAN hv_wfp_sum(PNET_BUFFER nb, ULONG start, ULONG length, ULONG field, UINT64* result) {
    if (start > NET_BUFFER_DATA_LENGTH(nb) || length > NET_BUFFER_DATA_LENGTH(nb) - start) return FALSE;
    PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
    ULONG skip = NET_BUFFER_CURRENT_MDL_OFFSET(nb), position = 0, range = start;
    UINT64 sum = 0;
    while (mdl != NULL && position != length) {
        ULONG size = MmGetMdlByteCount(mdl);
        if (skip > size) return FALSE;
        ULONG available = size - skip;
        if (range >= available) range -= available;
        else {
            skip += range;
            available -= range;
            ULONG take = available;
            if (take > length - position) take = length - position;
            if (take != 0) {
                const auto* bytes = static_cast<const UCHAR*>(MmGetSystemAddressForMdlSafe(mdl,
                    NormalPagePriority | MdlMappingNoExecute));
                if (bytes == NULL) return FALSE;
                sum += HvWfpChecksumSpan(bytes + skip, take, position, field);
                position += take;
            }
            range = 0;
        }
        skip = 0;
        mdl = mdl->Next;
    }
    if (position != length) return FALSE;
    *result = sum;
    return TRUE;
}
extern "C" BOOLEAN WriteForwardChecksum(PNET_BUFFER nb, ULONG offset, USHORT checksum) {
    UCHAR* high = ForwardByte(nb, offset);
    UCHAR* low = ForwardByte(nb, offset + 1);
    if (high == NULL || low == NULL) return FALSE;
    *high = (UCHAR)(checksum >> 8);
    *low = (UCHAR)checksum;
    return TRUE;
}
extern "C" NTSTATUS hv_wfp_native_initialize(PDRIVER_OBJECT driver) {
    KeInitializeMutex(&ManagementMutex, 0);
    for (auto* rundown : Rundowns) ExInitializeRundownProtection(rundown);
    KeInitializeTimer(&RetryTimer);
    KeInitializeDpc(&RetryDpc, RetryRegistration, NULL);
    WfpDevice = NULL;
    WorkItem = NULL;
    NTSTATUS status = IoCreateDevice(driver, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &WfpDevice);
    if (!NT_SUCCESS(status)) return status;
    WfpDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    WorkItem = IoAllocateWorkItem(WfpDevice);
    return WorkItem == NULL ? STATUS_INSUFFICIENT_RESOURCES : STATUS_SUCCESS;
}
extern "C" void hv_wfp_delete_device() {
    if (WfpDevice != NULL) { IoDeleteDevice(WfpDevice); WfpDevice = NULL; }
}
extern "C" void hv_wfp_lock() {
    // A FAST_MUTEX would raise IRQL above PASSIVE_LEVEL, invalid for FWPM.
    (void)KeWaitForSingleObject(&ManagementMutex, Executive, KernelMode, FALSE, NULL);
}
extern "C" void hv_wfp_unlock() { KeReleaseMutex(&ManagementMutex, FALSE); }
extern "C" BOOLEAN hv_wfp_acquire(ULONG kind) { return ExAcquireRundownProtection(Rundowns[kind]); }
extern "C" void hv_wfp_release(ULONG kind) { ExReleaseRundownProtection(Rundowns[kind]); }
extern "C" void hv_wfp_wait(ULONG kind) { ExWaitForRundownProtectionRelease(Rundowns[kind]); }
extern "C" void hv_wfp_queue_work() { IoQueueWorkItem(WorkItem, ReconcileWorker, DelayedWorkQueue, NULL); }
extern "C" void hv_wfp_free_work() {
    if (WorkItem != NULL) { IoFreeWorkItem(WorkItem); WorkItem = NULL; }
}
extern "C" void hv_wfp_timer(BOOLEAN arm) {
    if (arm) {
        LARGE_INTEGER due;
        due.QuadPart = -10000000;
        KeSetTimer(&RetryTimer, due, &RetryDpc);
    } else KeCancelTimer(&RetryTimer);
}
extern "C" void hv_wfp_flush_dpcs() { KeFlushQueuedDpcs(); }
extern "C" void hv_wfp_delay() {
    LARGE_INTEGER delay;
    delay.QuadPart = -1000000;
    (void)KeDelayExecutionThread(KernelMode, FALSE, &delay);
}
extern "C" NTSTATUS hv_wfp_subscribe(HANDLE* subscription) {
    return FwpmBfeStateSubscribeChanges0(WfpDevice, BfeChanged, NULL, subscription);
}
extern "C" NTSTATUS hv_wfp_unsubscribe(HANDLE subscription) { return FwpmBfeStateUnsubscribeChanges0(subscription); }
extern "C" BOOLEAN hv_wfp_bfe_running() { return FwpmBfeStateGet0() == FWPM_SERVICE_RUNNING; }
extern "C" NTSTATUS hv_wfp_callout_register(ULONG family, UINT32* id) {
    FWPS_CALLOUT0 callout = {};
    callout.calloutKey = CalloutKeys[family];
    callout.classifyFn = Classify;
    callout.notifyFn = Notify;
    return FwpsCalloutRegister0(WfpDevice, &callout, id);
}
extern "C" NTSTATUS hv_wfp_callout_unregister(UINT32 id) { return FwpsCalloutUnregisterById0(id); }
extern "C" NTSTATUS hv_wfp_injection_create(ULONG family, BOOLEAN network, HANDLE* handle) {
    return FwpsInjectionHandleCreate0(Families[family], network ? FWPS_INJECTION_TYPE_NETWORK : FWPS_INJECTION_TYPE_FORWARD, handle);
}
extern "C" NTSTATUS hv_wfp_injection_destroy(HANDLE handle) { return FwpsInjectionHandleDestroy0(handle); }
extern "C" NTSTATUS hv_wfp_engine_open(HANDLE* engine) {
    FWPM_SESSION0 session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    return FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, engine);
}
extern "C" NTSTATUS hv_wfp_engine_close(HANDLE engine) { return FwpmEngineClose0(engine); }
extern "C" NTSTATUS hv_wfp_transaction_begin(HANDLE engine) { return FwpmTransactionBegin0(engine, 0); }
extern "C" NTSTATUS hv_wfp_transaction_commit(HANDLE engine) { return FwpmTransactionCommit0(engine); }
extern "C" void hv_wfp_transaction_abort(HANDLE engine) { (void)FwpmTransactionAbort0(engine); }
extern "C" NTSTATUS hv_wfp_provider_add(HANDLE engine) {
    FWPM_PROVIDER0 provider = {};
    provider.providerKey = ProviderKey;
    provider.displayData.name = const_cast<PWSTR>(L"HyperVXNdisFilter");
    return FwpmProviderAdd0(engine, &provider, NULL);
}
extern "C" NTSTATUS hv_wfp_sublayer_add(HANDLE engine, USHORT weight) {
    FWPM_SUBLAYER0 sublayer = {};
    sublayer.subLayerKey = SublayerKey;
    sublayer.displayData.name = const_cast<PWSTR>(L"HyperVXNdisFilter forwarding");
    sublayer.providerKey = const_cast<GUID*>(&ProviderKey);
    sublayer.weight = weight;
    return FwpmSubLayerAdd0(engine, &sublayer, NULL);
}
extern "C" NTSTATUS hv_wfp_callout_add(HANDLE engine, ULONG family) {
    FWPM_CALLOUT0 callout = {};
    callout.calloutKey = CalloutKeys[family];
    callout.displayData.name = const_cast<PWSTR>(L"HyperVXNdisFilter IPFORWARD");
    callout.providerKey = const_cast<GUID*>(&ProviderKey);
    callout.applicableLayer = *Layers[family];
    return FwpmCalloutAdd0(engine, &callout, NULL, NULL);
}
extern "C" NTSTATUS hv_wfp_filter_add(HANDLE engine, ULONG family) {
    FWPM_FILTER0 filter = {};
    NTSTATUS status = ExUuidCreate(&filter.filterKey);
    if (!NT_SUCCESS(status)) return status;
    filter.displayData.name = const_cast<PWSTR>(L"HyperVXNdisFilter global forwarding");
    filter.providerKey = const_cast<GUID*>(&ProviderKey);
    filter.layerKey = *Layers[family];
    filter.subLayerKey = SublayerKey;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = CalloutKeys[family];
    return FwpmFilterAdd0(engine, &filter, NULL, NULL);
}
extern "C" void hv_wfp_report(const char* operation, NTSTATUS status) {
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
        "HyperVXNdisFilter: WFP %s failed: 0x%08lX\n", operation, (ULONG)status);
}
extern "C" BOOLEAN hv_wfp_is_self(HANDLE handle, PNET_BUFFER_LIST nbl) {
    FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState0(handle, nbl, NULL);
    return state == FWPS_PACKET_INJECTED_BY_SELF || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF;
}
extern "C" NTSTATUS hv_wfp_inject(HANDLE handle, HV_WFP_INJECTION_ROUTE route, BOOLEAN ipv6, ULONG compartment,
    ULONG destination, ULONG subInterface, PNET_BUFFER_LIST nbl, FWPS_INJECT_COMPLETE0 completion, void* context) {
    if (route == HvWfpNetworkReceive) return FwpsInjectNetworkReceiveAsync0(handle, NULL, 0, (COMPARTMENT_ID)compartment,
        destination, subInterface, nbl, completion, context);
    if (route == HvWfpNetworkSend) return FwpsInjectNetworkSendAsync0(handle, NULL, 0, (COMPARTMENT_ID)compartment, nbl, completion, context);
    return FwpsInjectForwardAsync0(handle, NULL, 0, Families[ipv6 ? 1 : 0], (COMPARTMENT_ID)compartment,
        destination, nbl, completion, context);
}
extern "C" PNET_BUFFER hv_wfp_first_nb(PNET_BUFFER_LIST nbl) { return NET_BUFFER_LIST_FIRST_NB(nbl); }
extern "C" PNET_BUFFER hv_wfp_next_nb(PNET_BUFFER nb) { return NET_BUFFER_NEXT_NB(nb); }
extern "C" ULONG hv_wfp_nb_length(PNET_BUFFER nb) { return NET_BUFFER_DATA_LENGTH(nb); }
extern "C" void hv_wfp_clear_checksum(PNET_BUFFER_LIST nbl) { NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo) = NULL; }
extern "C" void hv_wfp_packet_info(PNET_BUFFER_LIST nbl, HV_WFP_PACKET_INFO* info) {
    const auto* packet = PacketContext(nbl);
    *info = {};
    info->Route.DestinationIndex = packet->ForwardInterface;
    info->Route.DestinationSubIndex = packet->ForwardSubInterface;
    info->Route.Flags = packet->Flags;
    info->Route.Compartment = packet->Compartment;
    info->Ipv6 = packet->Ipv6;
    info->Segmented = packet->Segmented;
}
extern "C" void hv_wfp_free_packet(PNET_BUFFER_LIST nbl) {
    HV_PACKET_OWNER owner = PacketContext(nbl)->Owner;
    FreePacketContext(nbl);
    if (owner == HvOwnerWfpReassembled) FwpsFreeNetBufferList0(nbl);
    else FwpsFreeCloneNetBufferList0(nbl, 0);
}
extern "C" void NTAPI hv_wfp_complete(void* context, PNET_BUFFER_LIST nbl, BOOLEAN dispatch) {
    UNREFERENCED_PARAMETER(dispatch);
    if (context != nbl) hv_bugcheck();
    HvWfpInjectionComplete(nbl, (NTSTATUS)NET_BUFFER_LIST_STATUS(nbl));
}
extern "C" PNET_BUFFER_LIST hv_wfp_clone(PNET_BUFFER_LIST original, const HV_FORWARD_VALUES* route, BOOLEAN ipv6) {
    BOOLEAN grouped = (route->Flags & FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP) != 0;
    BOOLEAN segmented = NET_BUFFER_LIST_INFO(original, TcpLargeSendNetBufferListInfo) != NULL ||
        NET_BUFFER_LIST_INFO(original, TcpRecvSegCoalesceInfo) != NULL ||
        NET_BUFFER_LIST_INFO(original, TcpReceiveBytesTransferred) != NULL;
    if (!grouped && NET_BUFFER_LIST_NEXT_NBL(original) != NULL) return NULL;
    PNET_BUFFER_LIST nbl = NULL;
    NTSTATUS status;
    if (grouped) status = FwpsReassembleForwardFragmentGroup0(ipv6 ? AF_INET6 : AF_INET, original, NULL, 0, 0, &nbl);
    else status = FwpsAllocateCloneNetBufferList0(original, NULL, NULL, 0, &nbl);
    if (!NT_SUCCESS(status)) return NULL;
    HV_NBL_CONTEXT* context = AllocatePacketContext(nbl);
    if (context == NULL) {
        if (grouped) FwpsFreeNetBufferList0(nbl);
        else FwpsFreeCloneNetBufferList0(nbl, 0);
        return NULL;
    }
    context->Owner = grouped ? HvOwnerWfpReassembled : HvOwnerWfpClone;
    context->Ipv6 = ipv6;
    context->Segmented = segmented;
    context->ForwardInterface = route->DestinationIndex;
    context->ForwardSubInterface = route->DestinationSubIndex;
    context->Flags = route->Flags;
    context->Compartment = route->Compartment;
    return nbl;
}
extern "C" void hv_wfp_reset_diagnostics() {
#ifdef HV_WFP_FRAGMENT_PERMIT_DIAGNOSTIC
    for (ULONG i = 0; i != RTL_NUMBER_OF(ForwardDiagnosticCounts); ++i) InterlockedExchange(&ForwardDiagnosticCounts[i], 0);
#endif
}
extern "C" BOOLEAN hv_wfp_diagnostic_permit(PNET_BUFFER_LIST original, const HV_FORWARD_VALUES* route, BOOLEAN ipv6) {
#ifdef HV_WFP_FRAGMENT_PERMIT_DIAGNOSTIC
    if (!ipv6) {
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(original);
        ULONG length = nb == NULL ? 0 : NET_BUFFER_DATA_LENGTH(nb);
        UCHAR header[20];
        const auto* ip = nb == NULL || length < sizeof(header) ? NULL :
            static_cast<const UCHAR*>(NdisGetDataBuffer(nb, sizeof(header), header, 1, 0));
        BOOLEAN grouped = (route->Flags & FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP) != 0;
        BOOLEAN permit = HvForwardDiagnosticIpv4Fragment(ip, length, grouped);
        ULONG kind = permit ? 0u : grouped ? 1u : 2u;
        if (permit || grouped || length > 1500) {
            ULONG count = (ULONG)InterlockedIncrement(&ForwardDiagnosticCounts[kind]);
            if (count <= 32) HvWfpFragmentDiagnostic(kind, route->Flags, route->SourceIndex,
                route->DestinationIndex, length, NET_BUFFER_LIST_NEXT_NBL(original) != NULL, count);
        }
        return permit;
    }
#else
    UNREFERENCED_PARAMETER(original); UNREFERENCED_PARAMETER(route); UNREFERENCED_PARAMETER(ipv6);
#endif
    return FALSE;
}
