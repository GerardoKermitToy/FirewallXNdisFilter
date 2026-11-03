// Dynamic, global IPFORWARD filters. This file never owns policy decisions.
#ifdef HV_WFP_OFFLINE_TEST
#include "../../monitor/tests/wfp_fake_api.h"
#else
#include <ntifs.h>
#include <ndis.h>
#include <initguid.h>
#include "wfp_forward.h"
#endif

extern "C" __declspec(noreturn) void hv_bugcheck(void);
extern "C" void HvWfpStatus(ULONG healthy);
extern "C" void HvWfpInjectionError(ULONG status, ULONG ipv6, ULONG route, ULONG completion,
    ULONG destinationInterface, ULONG failures);
extern "C" void HvForwardStop(void);

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
PIO_WORKITEM WorkItem;
KTIMER RetryTimer;
KDPC RetryDpc;
volatile LONG WorkQueued, Dirty, ResetEngine, Healthy, NotificationsReady;
PDEVICE_OBJECT WfpDevice;
HANDLE Engine, Subscription, Injection[2], NetworkInjection[2];
volatile LONG InjectionFailures;
UINT32 CalloutIds[2];
volatile LONG Stopping;

void LockManagement() {
    // Unlike a FAST_MUTEX, this leaves IRQL at PASSIVE_LEVEL for FWPM APIs.
    (void)KeWaitForSingleObject(&ManagementMutex, Executive, KernelMode, FALSE, NULL);
}
void UnlockManagement() { KeReleaseMutex(&ManagementMutex, FALSE); }
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
BOOLEAN ForwardRead(PNET_BUFFER nb, ULONG offset, UCHAR* bytes, ULONG length) {
    if (offset > NET_BUFFER_DATA_LENGTH(nb) || length > NET_BUFFER_DATA_LENGTH(nb) - offset) return FALSE;
    PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
    ULONG skip = NET_BUFFER_CURRENT_MDL_OFFSET(nb), copied = 0;
    while (mdl != NULL && copied != length) {
        ULONG size = MmGetMdlByteCount(mdl);
        if (skip > size) return FALSE;
        ULONG available = size - skip;
        if (offset >= available) {
            offset -= available;
        } else {
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
ULONG ForwardU16(const UCHAR* bytes) { return ((ULONG)bytes[0] << 8) | bytes[1]; }
ULONG AddressSum(const UCHAR* bytes, ULONG length) {
    ULONG sum = 0;
    for (ULONG i = 0; i != length; i += 2) sum += ForwardU16(bytes + i);
    return sum;
}
// Preserve checksum-range parity across odd MDL boundaries, without a branch
// for every payload byte. Byte loads do not require alignment or overread.
UINT64 ChecksumBytes(const UCHAR* bytes, ULONG length, ULONG position) {
    UINT64 sum = 0;
    if ((position & 1u) != 0 && length != 0) {
        sum += *bytes++;
        --length;
    }
    while (length >= 2) {
        sum += ForwardU16(bytes);
        bytes += 2;
        length -= 2;
    }
    if (length != 0) sum += (UINT64)*bytes << 8;
    return sum;
}
UINT64 ChecksumSpan(const UCHAR* bytes, ULONG length, ULONG position, ULONG checksumOffset) {
    UINT64 sum = ChecksumBytes(bytes, length, position);
    // Remove the old field once per span, including a field split over MDLs.
    for (ULONG field = checksumOffset; field != checksumOffset + 2; ++field) {
        if (field >= position && field - position < length)
            sum -= (UINT64)bytes[field - position] << ((field & 1u) == 0 ? 8 : 0);
    }
    return sum;
}
USHORT FinishChecksum(UINT64 sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (USHORT)~sum;
}

BOOLEAN ForwardChecksum(PNET_BUFFER nb, ULONG start, ULONG length, ULONG checksumOffset,
    ULONG seed, USHORT* checksum) {
    if (start > NET_BUFFER_DATA_LENGTH(nb) || length > NET_BUFFER_DATA_LENGTH(nb) - start) return FALSE;
    PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
    ULONG skip = NET_BUFFER_CURRENT_MDL_OFFSET(nb), position = 0, range = start;
    UINT64 sum = seed;
    while (mdl != NULL && position != length) {
        ULONG size = MmGetMdlByteCount(mdl);
        if (skip > size) return FALSE;
        ULONG available = size - skip;
        if (range >= available) {
            range -= available;
        } else {
            skip += range;
            available -= range;
            ULONG take = available;
            if (take > length - position) take = length - position;
            if (take != 0) {
                const auto* bytes = static_cast<const UCHAR*>(MmGetSystemAddressForMdlSafe(mdl,
                    NormalPagePriority | MdlMappingNoExecute));
                if (bytes == NULL) return FALSE;
                sum += ChecksumSpan(bytes + skip, take, position, checksumOffset);
                position += take;
            }
            range = 0;
        }
        skip = 0;
        mdl = mdl->Next;
    }
    if (position != length) return FALSE;
    *checksum = FinishChecksum(sum);
    return TRUE;
}
BOOLEAN WriteForwardChecksum(PNET_BUFFER nb, ULONG offset, USHORT checksum) {
    UCHAR* high = ForwardByte(nb, offset);
    UCHAR* low = ForwardByte(nb, offset + 1);
    if (high == NULL || low == NULL) return FALSE;
    *high = (UCHAR)(checksum >> 8);
    *low = (UCHAR)checksum;
    return TRUE;
}
BOOLEAN RestorePacketChecksums(PNET_BUFFER nb, BOOLEAN ipv6, BOOLEAN segmented, BOOLEAN* complete) {
    UCHAR ip[60];
    ULONG total, transport, protocol, seed;
    const ULONG initial = ipv6 ? 40u : 20u;
    if (!ForwardRead(nb, 0, ip, initial) || ip[0] >> 4 != (ipv6 ? 6 : 4)) return FALSE;
    if (!ipv6) {
        transport = (ip[0] & 15u) * 4u;
        total = ForwardU16(ip + 2);
        if (transport < 20 || !ForwardRead(nb, 20, ip + 20, transport - 20)) return FALSE;
        if (!segmented && (total < transport || total > NET_BUFFER_DATA_LENGTH(nb))) return FALSE;
        const USHORT checksum = FinishChecksum(ChecksumSpan(ip, transport, 0, 10));
        if (!WriteForwardChecksum(nb, 10, checksum)) return FALSE;
        if (segmented || (ForwardU16(ip + 6) & 0x3fffu) != 0) {
            *complete = FALSE;
            return TRUE; // A fragment/LSO buffer is not a complete transport datagram.
        }
        protocol = ip[9];
        seed = AddressSum(ip + 12, 8);
        // Source-route options change the pseudo-header destination until the
        // route is exhausted. Do not checksum against an intermediate hop.
        for (ULONG option = 20; option < transport;) {
            UCHAR kind = ip[option];
            if (kind == 0) break;
            if (kind == 1) { ++option; continue; }
            if (transport - option < 2) return FALSE;
            ULONG length = ip[option + 1];
            if (length < 2 || length > transport - option) return FALSE;
            if (kind == 131 || kind == 137) {
                if (length < 7 || (length - 3) % 4 != 0 || ip[option + 2] < 4) return FALSE;
                if (ip[option + 2] <= length)
                    seed = AddressSum(ip + 12, 4) + AddressSum(ip + option + length - 4, 4);
            }
            option += length;
        }
    } else {
        if (segmented) { *complete = FALSE; return TRUE; }
        total = 40 + ForwardU16(ip + 4);
        if (total > NET_BUFFER_DATA_LENGTH(nb)) return FALSE;
        transport = 40;
        protocol = ip[6];
        UCHAR addresses[32];
        RtlCopyMemory(addresses, ip + 8, sizeof(addresses));
        ULONG steps = 0;
        while (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 44 || protocol == 51) {
            UCHAR extension[8];
            if (++steps > 8 || total - transport < 8 || !ForwardRead(nb, transport, extension, 8)) return FALSE;
            ULONG length = protocol == 44 ? 8u : protocol == 51 ?
                ((ULONG)extension[1] + 2) * 4 : ((ULONG)extension[1] + 1) * 8;
            if (length > total - transport) return FALSE;
            if (protocol == 44 && (ForwardU16(extension + 2) & 0xfff9u) != 0) {
                *complete = FALSE;
                return TRUE; // Non-atomic fragments must retain their end-to-end checksum.
            }
            if (protocol == 43 && extension[3] != 0) {
                ULONG destination;
                if ((extension[2] == 0 && length >= 24 && (length - 8) % 16 == 0 && extension[3] <= (length - 8) / 16) ||
                    (extension[2] == 2 && length == 24 && extension[3] == 1)) destination = transport + length - 16;
                else if (extension[2] == 4 && length >= 8u + ((ULONG)extension[4] + 1) * 16 &&
                    extension[3] <= (ULONG)extension[4] + 1) destination = transport + 8;
                else return FALSE; // Unknown active routing cannot supply a safe pseudo-header.
                if (!ForwardRead(nb, destination, addresses + 16, 16)) return FALSE;
            }
            if (protocol == 60) {
                for (ULONG option = 2; option < length;) {
                    UCHAR item[2];
                    if (!ForwardRead(nb, transport + option, item, 1)) return FALSE;
                    if (item[0] == 0) { ++option; continue; }
                    if (length - option < 2 || !ForwardRead(nb, transport + option, item, 2) ||
                        (ULONG)item[1] > length - option - 2) return FALSE;
                    if (item[0] == 201 && (item[1] != 16 ||
                        !ForwardRead(nb, transport + option + 2, addresses, 16))) return FALSE;
                    option += 2 + (ULONG)item[1];
                }
            }
            protocol = extension[0];
            transport += length;
        }
        seed = AddressSum(addresses, sizeof(addresses));
    }
    ULONG length = total - transport, field;
    UCHAR header[20];
    if (protocol == 6) {
        if (length < 20 || !ForwardRead(nb, transport, header, 20)) return FALSE;
        ULONG size = (header[12] >> 4) * 4u;
        if (size < 20 || size > length) return FALSE;
        field = 16;
    } else if (protocol == 17) {
        if (length < 8 || !ForwardRead(nb, transport, header, 8)) return FALSE;
        ULONG udp = ForwardU16(header + 4);
        if (udp < 8 || udp > length) return FALSE;
        length = udp; // IP trailing bytes are not part of the UDP datagram.
        field = 6;
    } else if (protocol == (ipv6 ? 58u : 1u)) {
        if (length < 4) return FALSE;
        field = 2;
    } else return TRUE; // Opaque upper-layer protocols are not checksum-offloaded.
    if (protocol == 1) seed = 0;
    else seed += protocol + (length >> 16) + (length & 0xffffu);
    USHORT checksum;
    if (!ForwardChecksum(nb, transport, length, field, seed, &checksum)) return FALSE;
    if (protocol == 17 && checksum == 0) checksum = 0xffffu;
    return WriteForwardChecksum(nb, transport + field, checksum);
}
BOOLEAN RestoreForwardChecksums(PNET_BUFFER_LIST nbl, BOOLEAN ipv6, BOOLEAN segmented) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL) return FALSE;
    BOOLEAN complete = TRUE;
    for (; nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
        if (!RestorePacketChecksums(nb, ipv6, segmented, &complete)) return FALSE;
    }
    // Software-completed datagrams must not retain a partial-checksum request.
    // Logical LSO/RSC buffers and fragments retain their original offload profile.
    if (complete) NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo) = NULL;
    return TRUE;
}
void ReportFailure(const char* operation, NTSTATUS status) {
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
        "HyperVXNdisFilter: WFP %s failed: 0x%08lX\n", operation, (ULONG)status);
}
NTSTATUS CloseEngine() {
    if (Engine != NULL) {
        NTSTATUS status = FwpmEngineClose0(Engine);
        if (!NT_SUCCESS(status)) {
            ReportFailure("close engine", status);
            InterlockedExchange(&ResetEngine, 1);
            return status; // Retain ownership; never orphan a live dynamic session.
        }
        Engine = NULL;
    }
    return STATUS_SUCCESS;
}
NTSTATUS AddForwardFilters() {
    for (ULONG family = 0; family != 2; ++family) {
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
        status = FwpmFilterAdd0(Engine, &filter, NULL, NULL);
        if (!NT_SUCCESS(status)) return status;
    }
    return STATUS_SUCCESS;
}
NTSTATUS OpenEngine() {
    FWPM_SESSION0 session = {};
    FWPM_PROVIDER0 provider = {};
    FWPM_SUBLAYER0 sublayer = {};
    NTSTATUS status;
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, 10 /* RPC_C_AUTHN_WINNT */, NULL, &session, &Engine);
    if (!NT_SUCCESS(status)) { Engine = NULL; return status; }
    status = FwpmTransactionBegin0(Engine, 0);
    if (!NT_SUCCESS(status)) { CloseEngine(); return status; }
    provider.providerKey = ProviderKey;
    provider.displayData.name = const_cast<PWSTR>(L"HyperVXNdisFilter");
    status = FwpmProviderAdd0(Engine, &provider, NULL);
    if (!NT_SUCCESS(status)) goto Abort;
    sublayer.subLayerKey = SublayerKey;
    sublayer.displayData.name = const_cast<PWSTR>(L"HyperVXNdisFilter forwarding");
    sublayer.providerKey = const_cast<GUID*>(&ProviderKey);
    sublayer.weight = 0x100;
    status = FwpmSubLayerAdd0(Engine, &sublayer, NULL);
    if (!NT_SUCCESS(status)) goto Abort;
    for (ULONG family = 0; family != 2; ++family) {
        FWPM_CALLOUT0 callout = {};
        callout.calloutKey = CalloutKeys[family];
        callout.displayData.name = const_cast<PWSTR>(L"HyperVXNdisFilter IPFORWARD");
        callout.providerKey = const_cast<GUID*>(&ProviderKey);
        callout.applicableLayer = *Layers[family];
        status = FwpmCalloutAdd0(Engine, &callout, NULL, NULL);
        if (!NT_SUCCESS(status)) goto Abort;
    }
    status = AddForwardFilters();
    if (!NT_SUCCESS(status)) goto Abort;
    status = FwpmTransactionCommit0(Engine);
    if (NT_SUCCESS(status)) return status;
Abort:
    (void)FwpmTransactionAbort0(Engine);
    CloseEngine();
    return status;
}
void NTAPI Classify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, void* layerData,
    const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* out);
NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER0* filter);
void PublishHealth(BOOLEAN healthy) {
    if (InterlockedExchange(&Healthy, healthy ? 1 : 0) != (healthy ? 1 : 0)) HvWfpStatus(healthy ? 1u : 0u);
}
NTSTATUS Reconcile() {
    FWPM_SERVICE_STATE state = FwpmBfeStateGet0();
    if (InterlockedExchange(&ResetEngine, 0) || state != FWPM_SERVICE_RUNNING) {
        NTSTATUS closed = CloseEngine();
        if (!NT_SUCCESS(closed)) { PublishHealth(FALSE); return closed; }
    }
    if (state != FWPM_SERVICE_RUNNING) {
        PublishHealth(FALSE);
        KeCancelTimer(&RetryTimer);
        return STATUS_SUCCESS;
    }
    NTSTATUS status = STATUS_SUCCESS;
    for (ULONG family = 0; family != 2; ++family) {
        if (CalloutIds[family] == 0) {
            FWPS_CALLOUT0 callout = {};
            callout.calloutKey = CalloutKeys[family];
            callout.classifyFn = Classify;
            callout.notifyFn = Notify;
            status = FwpsCalloutRegister0(WfpDevice, &callout, &CalloutIds[family]);
            if (!NT_SUCCESS(status)) { PublishHealth(FALSE); return status; }
        }
        if (Injection[family] == NULL) {
            // TCP/IP may not be ready during DriverEntry. Preserve NDIS and
            // retry at PASSIVE rather than making an optional LWF disappear.
            status = FwpsInjectionHandleCreate0(Families[family], FWPS_INJECTION_TYPE_FORWARD, &Injection[family]);
            if (!NT_SUCCESS(status)) { Injection[family] = NULL; PublishHealth(FALSE); return status; }
        }
        if (NetworkInjection[family] == NULL) {
            status = FwpsInjectionHandleCreate0(Families[family], FWPS_INJECTION_TYPE_NETWORK, &NetworkInjection[family]);
            if (!NT_SUCCESS(status)) { NetworkInjection[family] = NULL; PublishHealth(FALSE); return status; }
        }
    }
    if (Engine == NULL) status = OpenEngine();
    PublishHealth(NT_SUCCESS(status));
    if (NT_SUCCESS(status)) KeCancelTimer(&RetryTimer);
    return status;
}
IO_WORKITEM_ROUTINE ReconcileWorker;
void QueueReconcile() {
    if (Stopping || !NotificationsReady || WorkItem == NULL || !Dirty) return;
    if (!ExAcquireRundownProtection(&WorkRundown)) return;
    if (InterlockedCompareExchange(&WorkQueued, 1, 0) == 0)
        IoQueueWorkItem(WorkItem, ReconcileWorker, DelayedWorkQueue, NULL);
    else ExReleaseRundownProtection(&WorkRundown);
}
void RequestReconcile() {
    InterlockedExchange(&Dirty, 1);
    QueueReconcile();
}
void RetryAfterFailure() {
    LockManagement();
    if (!Stopping && !Healthy) {
        LARGE_INTEGER due;
        due.QuadPart = -10000000; // Only failed registration retries; no packet polling.
        KeSetTimer(&RetryTimer, due, &RetryDpc);
    }
    UnlockManagement();
}
void NTAPI RetryRegistration(KDPC* dpc, void* context, void* first, void* second) {
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(first); UNREFERENCED_PARAMETER(second);
    RequestReconcile();
}
_Use_decl_annotations_
void ReconcileWorker(PDEVICE_OBJECT device, void* context) {
    UNREFERENCED_PARAMETER(device); UNREFERENCED_PARAMETER(context);
    while (!Stopping && InterlockedExchange(&Dirty, 0)) {
        LockManagement();
        NTSTATUS status = Stopping ? STATUS_SUCCESS : Reconcile();
        UnlockManagement();
        if (!NT_SUCCESS(status)) { ReportFailure("reconcile filters", status); RetryAfterFailure(); }
    }
    InterlockedExchange(&WorkQueued, 0);
    QueueReconcile(); // Requests arriving at the ownership handoff cannot be lost.
    ExReleaseRundownProtection(&WorkRundown);
}
void NTAPI BfeChanged(void* context, FWPM_SERVICE_STATE state) {
    UNREFERENCED_PARAMETER(context);
    // Never wait for management/RPC from a BFE notification. A worker checks the
    // current state; a stop/start pair must also retire the old session's IDs.
    if (state == FWPM_SERVICE_STOP_PENDING || state == FWPM_SERVICE_STOPPED)
        InterlockedExchange(&ResetEngine, 1);
    RequestReconcile();
}
void NTAPI Classify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, void* layerData,
    const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    if (Stopping || !ExAcquireRundownProtection(&ClassifyRundown)) {
        out->actionType = FWP_ACTION_BLOCK;
        out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }
    HvForwardClassify(values, metadata, layerData, filter, flowContext, out);
    ExReleaseRundownProtection(&ClassifyRundown);
}
NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER0* filter) {
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}
} // namespace

extern "C" NTSTATUS HvWfpInitialize(PDRIVER_OBJECT driver) {
    NTSTATUS status;
    KeInitializeMutex(&ManagementMutex, 0);
    ExInitializeRundownProtection(&ClassifyRundown);
    ExInitializeRundownProtection(&WorkRundown);
    ExInitializeRundownProtection(&PacketRundown);
    KeInitializeTimer(&RetryTimer);
    KeInitializeDpc(&RetryDpc, RetryRegistration, NULL);
    Stopping = WorkQueued = Dirty = ResetEngine = Healthy = NotificationsReady = InjectionFailures = 0;
    // NDIS can attach during registration, before its public control device is
    // available. This unnamed object is private to the callout/BFE registrations.
    status = IoCreateDevice(driver, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &WfpDevice);
    if (!NT_SUCCESS(status)) return status;
    WfpDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    WorkItem = IoAllocateWorkItem(WfpDevice);
    if (WorkItem == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Failed; }
    // Subscribe first to close the startup race with BFE service transitions.
    status = FwpmBfeStateSubscribeChanges0(WfpDevice, BfeChanged, NULL, &Subscription);
    if (!NT_SUCCESS(status)) goto Failed;
    InterlockedExchange(&NotificationsReady, 1);
    LockManagement();
    status = Reconcile();
    UnlockManagement();
    if (!NT_SUCCESS(status)) { ReportFailure("initial registration", status); RetryAfterFailure(); }
    QueueReconcile(); // Include any notification delivered inside Subscribe.
    return STATUS_SUCCESS;
Failed:
    HvWfpUninitialize();
    return status;
}
extern "C" void HvWfpStop() {
    if (InterlockedExchange(&Stopping, TRUE)) return;
    if (Subscription != NULL) {
        NTSTATUS status = FwpmBfeStateUnsubscribeChanges0(Subscription);
        if (!NT_SUCCESS(status)) hv_bugcheck(); // The callback must not outlive this image.
        Subscription = NULL;
    }
    LockManagement();
    KeCancelTimer(&RetryTimer);
    UnlockManagement();
    KeFlushQueuedDpcs();
    ExWaitForRundownProtectionRelease(&WorkRundown);
    if (WorkItem != NULL) { IoFreeWorkItem(WorkItem); WorkItem = NULL; }
    ExWaitForRundownProtectionRelease(&ClassifyRundown);
    HvForwardStop();
    ExWaitForRundownProtectionRelease(&PacketRundown);
}
extern "C" void HvWfpUninitialize() {
    HvWfpStop();
    LockManagement();
    while (!NT_SUCCESS(CloseEngine())) {
        // An unload callback cannot fail. Keep the image and dynamic-session
        // ownership alive rather than leaving orphan rules or dangling callouts.
        LARGE_INTEGER delay;
        delay.QuadPart = -1000000;
        UnlockManagement();
        (void)KeDelayExecutionThread(KernelMode, FALSE, &delay);
        LockManagement();
    }
    PublishHealth(FALSE);
    UnlockManagement();
    for (ULONG family = 0; family != 2; ++family) {
        if (CalloutIds[family] != 0) {
            NTSTATUS status = FwpsCalloutUnregisterById0(CalloutIds[family]);
            if (!NT_SUCCESS(status)) hv_bugcheck();
            CalloutIds[family] = 0;
        }
    }
    ExWaitForRundownProtectionRelease(&ClassifyRundown);
    for (ULONG family = 0; family != 2; ++family) {
        if (Injection[family] != NULL) {
            // WFP waits for every asynchronous injection completion.
            NTSTATUS status = FwpsInjectionHandleDestroy0(Injection[family]);
            if (!NT_SUCCESS(status)) hv_bugcheck();
            Injection[family] = NULL;
        }
        if (NetworkInjection[family] != NULL) {
            NTSTATUS status = FwpsInjectionHandleDestroy0(NetworkInjection[family]);
            if (!NT_SUCCESS(status)) hv_bugcheck();
            NetworkInjection[family] = NULL;
        }
    }
    if (WfpDevice != NULL) { IoDeleteDevice(WfpDevice); WfpDevice = NULL; }
}
extern "C" BOOLEAN HvWfpRetainPacket() {
    return !Stopping && ExAcquireRundownProtection(&PacketRundown);
}
extern "C" void HvWfpReleasePacket() { ExReleaseRundownProtection(&PacketRundown); }
extern "C" void HvWfpReportStatus() {
    InterlockedExchange(&InjectionFailures, 0);
    HvWfpStatus(InterlockedCompareExchange(&Healthy, 0, 0) ? 1u : 0u);
}
extern "C" BOOLEAN HvWfpIsSelfInjected(PNET_BUFFER_LIST nbl, BOOLEAN ipv6) {
    HANDLE handles[2] = {Injection[ipv6 ? 1 : 0], NetworkInjection[ipv6 ? 1 : 0]};
    for (HANDLE handle : handles) {
        if (handle == NULL) continue;
        FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState0(handle, nbl, NULL);
        if (state == FWPS_PACKET_INJECTED_BY_SELF || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) return TRUE;
    }
    return FALSE;
}
extern "C" NTSTATUS HvWfpInject(PNET_BUFFER_LIST nbl, BOOLEAN ipv6, ULONG compartment,
    ULONG destinationInterface, ULONG destinationSubInterface, ULONG flags, BOOLEAN segmented,
    FWPS_INJECT_COMPLETE0 completion, void* context) {
    BOOLEAN receive = (flags & FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU) != 0;
    BOOLEAN send = !receive && (flags & FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU) != 0;
    HANDLE handle = receive || send ? NetworkInjection[ipv6 ? 1 : 0] : Injection[ipv6 ? 1 : 0];
    if (Stopping || handle == NULL) return STATUS_DELETE_PENDING;
    // Pending clones can lose checksum-offload OOB even without receive-success.
    // Complete ordinary IP/transport checksums before any injection API consumes them.
    if (!RestoreForwardChecksums(nbl, ipv6, segmented)) return STATUS_DATA_ERROR;
    // Weak-host traffic appears at IPFORWARD but is locally received/sourced.
    // Forward injection would complete it with STATUS_INVALID_PARAMETER.
    if (receive) return FwpsInjectNetworkReceiveAsync0(handle, NULL, 0, (COMPARTMENT_ID)compartment,
        destinationInterface, destinationSubInterface, nbl, completion, context);
    if (send) return FwpsInjectNetworkSendAsync0(handle, NULL, 0, (COMPARTMENT_ID)compartment,
        nbl, completion, context);
    return FwpsInjectForwardAsync0(handle, NULL, 0, Families[ipv6 ? 1 : 0],
        (COMPARTMENT_ID)compartment, destinationInterface, nbl, completion, context);
}
extern "C" void HvWfpReportInjectionFailure(NTSTATUS status, BOOLEAN ipv6, ULONG flags,
    ULONG destinationInterface, BOOLEAN completion) {
    ReportFailure(completion ? "injection completion" : "inject packet", status);
    ULONG failures = (ULONG)InterlockedIncrement(&InjectionFailures);
    // First failure and powers of two per controller session: don't flood the
    // policy event queue if a broken route rejects every packet.
    if (failures != 0 && (failures & (failures - 1)) == 0) {
        ULONG route = (flags & FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU) != 0 ? 1u :
            (flags & FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU) != 0 ? 2u : 0u;
        HvWfpInjectionError((ULONG)status, ipv6 ? 1u : 0u, route, completion ? 1u : 0u,
            destinationInterface, failures);
    }
}
