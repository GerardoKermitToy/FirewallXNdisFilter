#ifndef HYPERV_XNDIS_FILTER_WFP_FAKE_API_H
#define HYPERV_XNDIS_FILTER_WFP_FAKE_API_H

// Deliberately small, deterministic user-mode model for wfp_forward.cpp tests.
// It models only the WFP/NT primitives used by that translation unit.

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <new>
#include <utility>
#include <vector>

#ifndef _MSC_VER
#define __declspec(x)
#endif
#ifndef NTAPI
#define NTAPI
#endif
#ifndef _Use_decl_annotations_
#define _Use_decl_annotations_
#endif

namespace hv_wfp_fake {
struct PacketWork {
    std::size_t mdl_counts = 0, mdl_maps = 0, data_requests = 0, copied_bytes = 0;
};
inline PacketWork packet_work;
}

using UCHAR = std::uint8_t;
using USHORT = std::uint16_t;
inline void RtlCopyMemory(void* target, const void* source, std::size_t size) {
    hv_wfp_fake::packet_work.copied_bytes += size;
    std::memcpy(target, source, size);
}
using BOOLEAN = UCHAR;
using ULONG = std::uint32_t;
using NDIS_PORT_NUMBER = ULONG;
using ULONG_PTR = std::uintptr_t;
using LONG = std::int32_t;
using UINT32 = std::uint32_t;
using UINT64 = std::uint64_t;
using UINT16_t = std::uint16_t;
using NTSTATUS = LONG;
using HANDLE = void*;
using PWSTR = wchar_t*;
using ADDRESS_FAMILY = std::uint16_t;
using COMPARTMENT_ID = ULONG;

constexpr BOOLEAN FALSE = 0;
constexpr BOOLEAN TRUE = 1;
constexpr NTSTATUS STATUS_SUCCESS = static_cast<NTSTATUS>(0x00000000u);
constexpr NTSTATUS STATUS_DATA_ERROR = static_cast<NTSTATUS>(0xC000003Eu);
constexpr NTSTATUS STATUS_UNSUCCESSFUL = static_cast<NTSTATUS>(0xC0000001u);
constexpr NTSTATUS STATUS_INSUFFICIENT_RESOURCES = static_cast<NTSTATUS>(0xC000009Au);
constexpr NTSTATUS STATUS_INVALID_PARAMETER = static_cast<NTSTATUS>(0xC000000Du);
constexpr NTSTATUS STATUS_OBJECT_NAME_COLLISION = static_cast<NTSTATUS>(0xC0000035u);
constexpr NTSTATUS STATUS_DELETE_PENDING = static_cast<NTSTATUS>(0xC0000056u);
constexpr NTSTATUS STATUS_NOT_FOUND = static_cast<NTSTATUS>(0xC0000225u);
constexpr NTSTATUS STATUS_INVALID_HANDLE = static_cast<NTSTATUS>(0xC0000008u);

inline bool NT_SUCCESS(NTSTATUS status) { return status >= 0; }

constexpr ADDRESS_FAMILY AF_INET = 2;
constexpr ADDRESS_FAMILY AF_INET6 = 23;
constexpr ULONG FILE_DEVICE_UNKNOWN = 0x00000022u;
constexpr ULONG DO_DEVICE_INITIALIZING = 0x00000080u;
constexpr ULONG DPFLTR_IHVNETWORK_ID = 0;
constexpr ULONG DPFLTR_ERROR_LEVEL = 0;
constexpr ULONG Executive = 0;
constexpr ULONG KernelMode = 0;
constexpr ULONG DelayedWorkQueue = 0;

struct GUID {
    UINT32 Data1;
    std::uint16_t Data2;
    std::uint16_t Data3;
    UCHAR Data4[8];
};

inline bool operator==(const GUID& left, const GUID& right) {
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}
inline bool operator!=(const GUID& left, const GUID& right) { return !(left == right); }

inline const GUID FWPM_LAYER_IPFORWARD_V4 =
    {0x869f1a0a, 0xb8d4, 0x4d0f, {0x9b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x60, 0x01}};
inline const GUID FWPM_LAYER_IPFORWARD_V6 =
    {0x7b964818, 0x19c7, 0x493a, {0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8a}};
inline const GUID FWPM_CONDITION_IP_FORWARD_INTERFACE =
    {0x3f47b2e8, 0x4a1e, 0x4e68, {0x9f, 0x13, 0x71, 0x1b, 0x55, 0x10, 0xa1, 0x01}};
inline const GUID FWPM_CONDITION_IP_LOCAL_INTERFACE =
    {0x4c8f8c36, 0x1f49, 0x4e2a, {0x92, 0x7c, 0x4a, 0x66, 0x33, 0x10, 0xb2, 0x02}};
inline const GUID FWPM_CONDITION_DESTINATION_INTERFACE_INDEX =
    {0x9f8e532c, 0xa4aa, 0x4f5b, {0xae, 0x46, 0x53, 0x20, 0x8f, 0x12, 0xc3, 0x03}};
inline const GUID FWPM_CONDITION_SOURCE_INTERFACE_INDEX =
    {0x4ee77a6d, 0x6fd1, 0x4bf4, {0xaa, 0x27, 0x2d, 0x78, 0x64, 0x55, 0xd4, 0x04}};

struct LIST_ENTRY {
    LIST_ENTRY* Flink;
    LIST_ENTRY* Blink;
};

inline void InitializeListHead(LIST_ENTRY* entry) {
    entry->Flink = entry;
    entry->Blink = entry;
}
inline BOOLEAN IsListEmpty(const LIST_ENTRY* entry) { return entry->Flink == entry ? TRUE : FALSE; }
inline void InsertTailList(LIST_ENTRY* head, LIST_ENTRY* entry) {
    entry->Blink = head->Blink;
    entry->Flink = head;
    head->Blink->Flink = entry;
    head->Blink = entry;
}
inline BOOLEAN RemoveEntryList(LIST_ENTRY* entry) {
    entry->Blink->Flink = entry->Flink;
    entry->Flink->Blink = entry->Blink;
    return FALSE;
}

#define CONTAINING_RECORD(address, type, field) \
    reinterpret_cast<type*>(reinterpret_cast<unsigned char*>(address) - offsetof(type, field))
#define RTL_NUMBER_OF(array) (sizeof(array) / sizeof((array)[0]))
#define RtlZeroMemory(destination, length) std::memset((destination), 0, (length))
#define UNREFERENCED_PARAMETER(parameter) (void)(parameter)

struct KMUTEX { LONG depth = 0; };
struct EX_RUNDOWN_REF { BOOLEAN accepting = FALSE; ULONG acquired = 0; };
struct LARGE_INTEGER { std::int64_t QuadPart; };
struct KDPC;
using PKDEFERRED_ROUTINE = void (NTAPI *)(KDPC*, void*, void*, void*);
struct KDPC {
    PKDEFERRED_ROUTINE DeferredRoutine = nullptr;
    void* DeferredContext = nullptr;
};
struct KTIMER {
    BOOLEAN armed = FALSE;
    KDPC* dpc = nullptr;
};

struct _DRIVER_OBJECT {};
using PDRIVER_OBJECT = _DRIVER_OBJECT*;
struct _DEVICE_OBJECT {
    ULONG Flags = DO_DEVICE_INITIALIZING;
    BOOLEAN deleted = FALSE;
};
using PDEVICE_OBJECT = _DEVICE_OBJECT*;
struct _IO_WORKITEM {
    PDEVICE_OBJECT device = nullptr;
    BOOLEAN freed = FALSE;
};
using PIO_WORKITEM = _IO_WORKITEM*;
using IO_WORKITEM_ROUTINE = void NTAPI(PDEVICE_OBJECT, void*);

struct MDL {
    MDL* Next = nullptr;
    UCHAR* Data = nullptr;
    ULONG Length = 0;
    BOOLEAN Mappable = TRUE;
};
using PMDL = MDL*;
struct NET_BUFFER {
    NET_BUFFER* Next = nullptr;
    PMDL CurrentMdl = nullptr;
    ULONG CurrentMdlOffset = 0, DataLength = 0;
};
using PNET_BUFFER = NET_BUFFER*;
struct alignas(16) NET_BUFFER_LIST_CONTEXT {
    NET_BUFFER_LIST_CONTEXT* Next;
    USHORT Size, Offset;
};
struct _NET_BUFFER_LIST {
    PNET_BUFFER FirstNb = nullptr;
    void* ChecksumInfo = nullptr;
    _NET_BUFFER_LIST* Next = nullptr;
    NET_BUFFER_LIST_CONTEXT* Context = nullptr;
    NTSTATUS Status = STATUS_SUCCESS;
    void* LsoInfo = nullptr;
    void* RscInfo = nullptr;
    void* ReceiveBytes = nullptr;
    BOOLEAN Reassembled = FALSE;
};
using PNET_BUFFER_LIST = _NET_BUFFER_LIST*;
union NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO {
    void* Value;
    struct {
        ULONG TcpChecksumFailed : 1, UdpChecksumFailed : 1, IpChecksumFailed : 1;
        ULONG TcpChecksumSucceeded : 1, UdpChecksumSucceeded : 1, IpChecksumSucceeded : 1;
        ULONG Reserved : 26;
    } Receive;
};
constexpr ULONG TcpIpChecksumNetBufferListInfo = 0;
constexpr ULONG TcpLargeSendNetBufferListInfo = 1;
constexpr ULONG TcpRecvSegCoalesceInfo = 2;
constexpr ULONG TcpReceiveBytesTransferred = 3;
constexpr NTSTATUS NDIS_STATUS_SUCCESS = STATUS_SUCCESS;
#define NET_BUFFER_LIST_NEXT_NBL(nbl) ((nbl)->Next)
#define NET_BUFFER_LIST_STATUS(nbl) ((nbl)->Status)
#define NET_BUFFER_LIST_CONTEXT_DATA_START(nbl) \
    (reinterpret_cast<UCHAR*>((nbl)->Context + 1) + (nbl)->Context->Offset)
inline void*& FakeNblInfo(PNET_BUFFER_LIST nbl, ULONG kind) {
    switch (kind) {
    case TcpLargeSendNetBufferListInfo: return nbl->LsoInfo;
    case TcpRecvSegCoalesceInfo: return nbl->RscInfo;
    case TcpReceiveBytesTransferred: return nbl->ReceiveBytes;
    default: return nbl->ChecksumInfo;
    }
}
constexpr ULONG NormalPagePriority = 0, MdlMappingNoExecute = 0;
#define NET_BUFFER_LIST_FIRST_NB(nbl) ((nbl)->FirstNb)
#define NET_BUFFER_NEXT_NB(nb) ((nb)->Next)
#define NET_BUFFER_DATA_LENGTH(nb) ((nb)->DataLength)
#define NET_BUFFER_CURRENT_MDL(nb) ((nb)->CurrentMdl)
#define NET_BUFFER_CURRENT_MDL_OFFSET(nb) ((nb)->CurrentMdlOffset)
#define NET_BUFFER_LIST_INFO(nbl, info) FakeNblInfo((nbl), (info))
inline ULONG MmGetMdlByteCount(PMDL mdl) {
    ++hv_wfp_fake::packet_work.mdl_counts;
    return mdl->Length;
}
inline void* MmGetSystemAddressForMdlSafe(PMDL mdl, ULONG) {
    ++hv_wfp_fake::packet_work.mdl_maps;
    return mdl->Mappable ? mdl->Data : nullptr;
}
inline void* NdisGetDataBuffer(PNET_BUFFER nb, ULONG bytes, void* storage, ULONG, ULONG) {
    ++hv_wfp_fake::packet_work.data_requests;
    if (bytes > nb->DataLength) return nullptr;
    PMDL mdl = nb->CurrentMdl;
    ULONG offset = nb->CurrentMdlOffset, copied = 0;
    while (mdl != nullptr && copied != bytes) {
        if (offset > mdl->Length) return nullptr;
        const ULONG take = std::min(bytes - copied, mdl->Length - offset);
        if (take != 0) {
            if (!mdl->Mappable) return nullptr;
            if (copied == 0 && take == bytes) return mdl->Data + offset;
            if (storage == nullptr) return nullptr;
            hv_wfp_fake::packet_work.copied_bytes += take;
            std::memcpy(static_cast<UCHAR*>(storage) + copied, mdl->Data + offset, take);
            copied += take;
        }
        mdl = mdl->Next;
        offset = 0;
    }
    return copied == bytes ? storage : nullptr;
}

using FWP_DATA_TYPE = UINT32;
using FWP_MATCH_TYPE = UINT32;
using FWP_ACTION_TYPE = UINT32;
constexpr FWP_DATA_TYPE FWP_EMPTY = 0;
constexpr FWP_DATA_TYPE FWP_UINT32 = 1;
constexpr FWP_DATA_TYPE FWP_UINT64 = 2;
constexpr FWP_MATCH_TYPE FWP_MATCH_EQUAL = 0;
constexpr FWP_ACTION_TYPE FWP_ACTION_CALLOUT_TERMINATING = 1;
constexpr FWP_ACTION_TYPE FWP_ACTION_BLOCK = 2;
constexpr FWP_ACTION_TYPE FWP_ACTION_PERMIT = 3;

struct FWP_VALUE0 {
    FWP_DATA_TYPE type = FWP_EMPTY;
    UINT32 uint32 = 0;
};
struct FWP_CONDITION_VALUE0 {
    FWP_DATA_TYPE type = FWP_EMPTY;
    union {
        UINT64* uint64;
        UINT32 uint32;
    };
};
struct FWPM_DISPLAY_DATA0 {
    PWSTR name = nullptr;
};
struct FWPM_FILTER_CONDITION0 {
    GUID fieldKey{};
    FWP_MATCH_TYPE matchType = 0;
    FWP_CONDITION_VALUE0 conditionValue{};
};
struct FWPM_ACTION0 {
    FWP_ACTION_TYPE type = 0;
    GUID calloutKey{};
};
struct FWPM_FILTER0 {
    GUID filterKey{};
    FWPM_DISPLAY_DATA0 displayData{};
    GUID* providerKey = nullptr;
    GUID layerKey{};
    GUID subLayerKey{};
    FWP_VALUE0 weight{};
    ULONG numFilterConditions = 0;
    FWPM_FILTER_CONDITION0* filterCondition = nullptr;
    FWPM_ACTION0 action{};
    UINT64 rawContext = 0;
};
struct FWPM_SESSION0 { ULONG flags = 0; };
struct FWPM_PROVIDER0 {
    GUID providerKey{};
    FWPM_DISPLAY_DATA0 displayData{};
};
struct FWPM_SUBLAYER0 {
    GUID subLayerKey{};
    FWPM_DISPLAY_DATA0 displayData{};
    GUID* providerKey = nullptr;
    UINT16_t weight = 0;
};
struct FWPM_CALLOUT0 {
    GUID calloutKey{};
    FWPM_DISPLAY_DATA0 displayData{};
    GUID* providerKey = nullptr;
    GUID applicableLayer{};
};

constexpr UINT32 RPC_C_AUTHN_WINNT = 10;
constexpr ULONG FWPM_SESSION_FLAG_DYNAMIC = 0x00000001u;

enum FWPM_SERVICE_STATE : UINT32 {
    FWPM_SERVICE_STOPPED = 0,
    FWPM_SERVICE_STOP_PENDING = 1,
    FWPM_SERVICE_START_PENDING = 2,
    FWPM_SERVICE_RUNNING = 3,
};

constexpr ULONG FWPS_LAYER_IPFORWARD_V4 = 1, FWPS_LAYER_IPFORWARD_V6 = 2;
constexpr ULONG FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX = 0;
constexpr ULONG FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX = 1;
constexpr ULONG FWPS_FIELD_IPFORWARD_V4_DESTINATION_SUB_INTERFACE_INDEX = 2;
constexpr ULONG FWPS_FIELD_IPFORWARD_V4_FLAGS = 3;
constexpr ULONG FWPS_FIELD_IPFORWARD_V6_SOURCE_INTERFACE_INDEX = 0;
constexpr ULONG FWPS_FIELD_IPFORWARD_V6_DESTINATION_INTERFACE_INDEX = 1;
constexpr ULONG FWPS_FIELD_IPFORWARD_V6_DESTINATION_SUB_INTERFACE_INDEX = 2;
constexpr ULONG FWPS_FIELD_IPFORWARD_V6_FLAGS = 3;
constexpr UINT64 FWPS_METADATA_FIELD_COMPARTMENT_ID = 1;
constexpr COMPARTMENT_ID UNSPECIFIED_COMPARTMENT_ID = 0;
struct FWPS_INCOMING_VALUE0 { FWP_VALUE0 value; };
struct FWPS_INCOMING_VALUES0 {
    ULONG layerId = 0, valueCount = 0;
    FWPS_INCOMING_VALUE0* incomingValue = nullptr;
};
struct FWPS_INCOMING_METADATA_VALUES0 {
    UINT64 currentMetadataValues = 0;
    COMPARTMENT_ID compartmentId = UNSPECIFIED_COMPARTMENT_ID;
};
struct FWPS_FILTER0 { UINT64 rawContext = 0; };
struct FWPS_CLASSIFY_OUT0 {
    UINT32 rights = 0;
    FWP_ACTION_TYPE actionType = 0;
    UINT32 flags = 0;
};
constexpr UINT32 FWPS_RIGHT_ACTION_WRITE = 0x00000001u;
constexpr UINT32 FWPS_CLASSIFY_OUT_FLAG_ABSORB = 0x00000001u;

enum FWPS_CALLOUT_NOTIFY_TYPE : UINT32 {
    FWPS_CALLOUT_NOTIFY_ADD_FILTER = 0,
    FWPS_CALLOUT_NOTIFY_DELETE_FILTER = 1,
};
using FWPS_CALLOUT_CLASSIFY_FN = void (NTAPI *)(const FWPS_INCOMING_VALUES0*,
    const FWPS_INCOMING_METADATA_VALUES0*, void*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
using FWPS_CALLOUT_NOTIFY_FN = NTSTATUS (NTAPI *)(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER0*);
struct FWPS_CALLOUT0 {
    GUID calloutKey{};
    FWPS_CALLOUT_CLASSIFY_FN classifyFn = nullptr;
    FWPS_CALLOUT_NOTIFY_FN notifyFn = nullptr;
};

enum FWPS_PACKET_INJECTION_STATE : UINT32 {
    FWPS_PACKET_NOT_INJECTED = 0,
    FWPS_PACKET_INJECTED_BY_SELF = 1,
    FWPS_PACKET_INJECTED_BY_OTHER = 2,
    FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF = 3,
};
constexpr UINT32 FWPS_INJECTION_TYPE_NETWORK = 4;
constexpr UINT32 FWPS_INJECTION_TYPE_FORWARD = 8;
constexpr ULONG FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU = 0x00040000;
constexpr ULONG FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU = 0x00080000;
constexpr ULONG FWP_CONDITION_FLAG_IS_FRAGMENT = 0x20;
constexpr ULONG FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP = 0x40;
constexpr ULONG FWP_CONDITION_FLAG_IS_REASSEMBLED = 0x400;
using FWPS_INJECT_COMPLETE0 = void (NTAPI *)(void*, PNET_BUFFER_LIST, BOOLEAN);
using FWPM_BFE_STATE_CHANGE_CALLBACK0 = void (NTAPI *)(void*, FWPM_SERVICE_STATE);

namespace hv_wfp_fake {

enum class FailurePoint : unsigned {
    clone, reassemble, context_allocate,
    uuid_create,
    create_device,
    allocate_work_item,
    injection_create,
    callout_register,
    bfe_subscribe,
    engine_open,
    transaction_begin,
    provider_add,
    sublayer_add,
    management_callout_add,
    filter_add,
    transaction_commit,
    filter_delete,
    engine_close,
    injection_forward,
    injection_receive,
    injection_send,
    count,
};

struct Failure {
    FailurePoint point;
    unsigned successful_calls_before_failure;
    NTSTATUS status;
};

struct FilterRecord {
    UINT64 engine_serial = 0;
    UINT64 id = 0;
    GUID layer{};
    GUID callout{};
    GUID sublayer{};
    UINT16_t sublayer_weight = 0;
    ULONG condition_count = 0;
    BOOLEAN has_condition_pointer = FALSE;
    FWP_ACTION_TYPE action_type = 0;
    UINT64 raw_context = 0;
};

struct FakeEngine {
    UINT64 serial = 0;
    BOOLEAN live = FALSE;
    BOOLEAN in_transaction = FALSE;
    GUID sublayer{};
    UINT16_t sublayer_weight = 0;
    std::vector<FilterRecord> staged_filters;
};
struct FakeSubscription {
    FWPM_BFE_STATE_CHANGE_CALLBACK0 callback = nullptr;
    void* context = nullptr;
    BOOLEAN live = FALSE;
};
struct FakeInjection {
    UINT32 type = 0;
    ADDRESS_FAMILY family = 0;
    BOOLEAN live = FALSE;
};
struct CalloutRegistration {
    UINT32 id = 0;
    GUID key{};
    FWPS_CALLOUT_NOTIFY_FN notify = nullptr;
    BOOLEAN live = FALSE;
};
struct QueuedWork {
    PIO_WORKITEM item = nullptr;
    IO_WORKITEM_ROUTINE* routine = nullptr;
    void* context = nullptr;
};
struct InjectionCall {
    HANDLE handle = nullptr;
    ADDRESS_FAMILY family = 0;
    COMPARTMENT_ID compartment = 0;
    ULONG destination_interface = 0;
    PNET_BUFFER_LIST nbl = nullptr;
    FWPS_INJECT_COMPLETE0 completion = nullptr;
    void* context = nullptr;
    ULONG route = 0, sub_interface = 0;
};
struct InjectionState {
    PNET_BUFFER_LIST nbl = nullptr;
    ADDRESS_FAMILY family = 0;
    FWPS_PACKET_INJECTION_STATE state = FWPS_PACKET_NOT_INJECTED;
    UINT32 type = FWPS_INJECTION_TYPE_FORWARD;
};

struct State {
    unsigned clones = 0, clone_frees = 0, reassemblies = 0, reassembly_frees = 0;
    unsigned context_allocations = 0, context_frees = 0, live_packets = 0;
    BOOLEAN complete_inline = FALSE;
    NTSTATUS completion_status = STATUS_SUCCESS;
    FWPM_SERVICE_STATE bfe_state = FWPM_SERVICE_RUNNING;
    std::vector<Failure> failures;
    std::array<unsigned, static_cast<unsigned>(FailurePoint::count)> operation_calls{};
    std::vector<std::unique_ptr<FakeEngine>> engines;
    std::vector<std::unique_ptr<FakeSubscription>> subscriptions;
    std::vector<std::unique_ptr<FakeInjection>> injections;
    std::vector<std::unique_ptr<_DEVICE_OBJECT>> devices;
    std::vector<std::unique_ptr<_IO_WORKITEM>> work_items;
    std::vector<CalloutRegistration> callouts;
    std::vector<FilterRecord> active_filters;
    std::vector<QueuedWork> work_queue;
    std::vector<KTIMER*> timers;
    std::vector<InjectionCall> injection_calls;
    std::vector<InjectionState> injection_states;
    UINT64 next_engine_serial = 1;
    UINT64 next_filter_serial = 1;
    UINT32 next_callout_id = 1;
    UINT32 next_uuid = 1;
    unsigned live_engines = 0;
    unsigned live_subscriptions = 0;
    unsigned live_injections = 0;
    unsigned live_callouts = 0;
    unsigned live_devices = 0;
    unsigned live_work_items = 0;
    unsigned engine_close_calls = 0;
    unsigned transaction_abort_calls = 0;
    unsigned transaction_commit_calls = 0;
    unsigned bfe_notifications = 0;
    unsigned notify_add_calls = 0;
    unsigned notify_delete_calls = 0;
    unsigned work_queue_calls = 0;
    unsigned work_run_calls = 0;
    unsigned timer_set_calls = 0;
    unsigned timer_cancel_calls = 0;
    unsigned timer_fire_calls = 0;
    unsigned dpc_flush_calls = 0;
    unsigned unsubscribe_calls = 0;
    unsigned rundown_wait_calls = 0;
    unsigned assertion_failures = 0;
    unsigned dbg_print_calls = 0;
    BOOLEAN mutex_reentry = FALSE;
    BOOLEAN mutex_release_without_acquire = FALSE;
    BOOLEAN unsubscribe_while_management_locked = FALSE;
    BOOLEAN stale_engine_use = FALSE;
    BOOLEAN stale_engine_id_use = FALSE;
    BOOLEAN work_after_free = FALSE;
    BOOLEAN work_freed_while_queued = FALSE;
    BOOLEAN device_deleted_with_work = FALSE;
    BOOLEAN timer_armed_at_work_free = FALSE;
    BOOLEAN rundown_not_drained = FALSE;
    BOOLEAN subscribe_in_progress = FALSE;
    BOOLEAN subscribe_callback_pending = FALSE;
    BOOLEAN run_work_immediately_inside_subscribe = FALSE;
    BOOLEAN bfe_state_queried_during_subscribe = FALSE;
    FWPM_SERVICE_STATE subscribe_callback_state = FWPM_SERVICE_RUNNING;
    unsigned work_queues_during_subscribe = 0;
    LONG management_mutex_depth = 0;
    BOOLEAN draining_work = FALSE;
    void (*forward_stop_hook)() = nullptr;
};

inline State& state() {
    static State value;
    return value;
}

inline volatile LONG* g_exchange_hook_address = nullptr;
inline LONG g_exchange_hook_value = 0;
inline void (*g_exchange_hook)() = nullptr;

inline void Reset() {
    state() = State{};
    packet_work = {};
    g_exchange_hook_address = nullptr;
    g_exchange_hook_value = 0;
    g_exchange_hook = nullptr;
}
inline void FailNext(FailurePoint point, NTSTATUS status = STATUS_UNSUCCESSFUL) {
    state().failures.push_back({point, 0, status});
}
inline void FailAfter(FailurePoint point, unsigned successful_calls, NTSTATUS status = STATUS_UNSUCCESSFUL) {
    state().failures.push_back({point, successful_calls, status});
}
inline unsigned Calls(FailurePoint point) {
    return state().operation_calls[static_cast<unsigned>(point)];
}
inline bool TakeFailure(FailurePoint point, NTSTATUS* status) {
    State& current = state();
    ++current.operation_calls[static_cast<unsigned>(point)];
    for (auto it = current.failures.begin(); it != current.failures.end(); ++it) {
        if (it->point != point) continue;
        if (it->successful_calls_before_failure != 0) {
            --it->successful_calls_before_failure;
            continue;
        }
        *status = it->status;
        current.failures.erase(it);
        return true;
    }
    return false;
}
inline bool AnyTimerArmed() {
    for (KTIMER* timer : state().timers) {
        if (timer != nullptr && timer->armed) return true;
    }
    return false;
}
inline std::size_t QueuedWorkCount() { return state().work_queue.size(); }
inline void SetExchangeHook(volatile LONG* address, LONG value, void (*hook)()) {
    g_exchange_hook_address = address;
    g_exchange_hook_value = value;
    g_exchange_hook = hook;
}
inline void ClearExchangeHook() {
    g_exchange_hook_address = nullptr;
    g_exchange_hook = nullptr;
}

inline FakeEngine* FindEngine(HANDLE handle) {
    if (handle == nullptr) return nullptr;
    for (const auto& engine : state().engines) {
        if (engine.get() == handle) return engine.get();
    }
    return nullptr;
}
inline FakeEngine* RequireLiveEngine(HANDLE handle) {
    FakeEngine* engine = FindEngine(handle);
    if (engine == nullptr || !engine->live) {
        state().stale_engine_use = TRUE;
        return nullptr;
    }
    return engine;
}
inline CalloutRegistration* FindCallout(const GUID& key) {
    for (CalloutRegistration& callout : state().callouts) {
        if (callout.live && callout.key == key) return &callout;
    }
    return nullptr;
}
inline NTSTATUS NotifyFilter(const GUID& callout_key, FWPS_CALLOUT_NOTIFY_TYPE type, UINT64 raw_context) {
    CalloutRegistration* callout = FindCallout(callout_key);
    if (callout == nullptr || callout->notify == nullptr) return STATUS_SUCCESS;
    FWPS_FILTER0 filter{};
    filter.rawContext = raw_context;
    if (type == FWPS_CALLOUT_NOTIFY_ADD_FILTER) ++state().notify_add_calls;
    else ++state().notify_delete_calls;
    return callout->notify(type, &callout_key, &filter);
}
inline void SetBfeState(FWPM_SERVICE_STATE next, BOOLEAN notify = TRUE) {
    State& current = state();
    current.bfe_state = next;
    if (!notify) return;
    for (const auto& subscription : current.subscriptions) {
        if (!subscription->live || subscription->callback == nullptr) continue;
        ++current.bfe_notifications;
        subscription->callback(subscription->context, next);
    }
}
inline void NotifyInsideSubscribe(FWPM_SERVICE_STATE state) {
    State& current = hv_wfp_fake::state();
    current.subscribe_callback_pending = TRUE;
    current.run_work_immediately_inside_subscribe = TRUE;
    current.subscribe_callback_state = state;
}
inline void SetInjectionState(PNET_BUFFER_LIST nbl, ADDRESS_FAMILY family,
    FWPS_PACKET_INJECTION_STATE injection_state, UINT32 type = FWPS_INJECTION_TYPE_FORWARD) {
    State& current = state();
    for (InjectionState& value : current.injection_states) {
        if (value.nbl == nbl && value.family == family && value.type == type) {
            value.state = injection_state;
            return;
        }
    }
    current.injection_states.push_back({nbl, family, injection_state, type});
}
inline void FireTimers() {
    for (;;) {
        KTIMER* fired = nullptr;
        for (KTIMER* timer : state().timers) {
            if (timer != nullptr && timer->armed) {
                fired = timer;
                break;
            }
        }
        if (fired == nullptr) return;
        fired->armed = FALSE;
        ++state().timer_fire_calls;
        if (fired->dpc != nullptr && fired->dpc->DeferredRoutine != nullptr)
            fired->dpc->DeferredRoutine(fired->dpc, fired->dpc->DeferredContext, nullptr, nullptr);
    }
}
inline void DrainWork() {
    State& current = state();
    if (current.draining_work) return;
    current.draining_work = TRUE;
    while (!current.work_queue.empty()) {
        QueuedWork work = current.work_queue.front();
        current.work_queue.erase(current.work_queue.begin());
        if (work.item == nullptr || work.item->freed || work.routine == nullptr) {
            current.work_after_free = TRUE;
            continue;
        }
        ++current.work_run_calls;
        work.routine(work.item->device, work.context);
    }
    current.draining_work = FALSE;
}

} // namespace hv_wfp_fake

inline LONG InterlockedExchange(volatile LONG* destination, LONG value) {
    LONG& storage = const_cast<LONG&>(*destination);
    std::atomic_ref<LONG> atomic(storage);
    const LONG old = atomic.exchange(value, std::memory_order_seq_cst);
    if (destination == hv_wfp_fake::g_exchange_hook_address && value == hv_wfp_fake::g_exchange_hook_value &&
        hv_wfp_fake::g_exchange_hook != nullptr) {
        void (*hook)() = hv_wfp_fake::g_exchange_hook;
        hv_wfp_fake::ClearExchangeHook();
        hook();
    }
    return old;
}
inline LONG InterlockedIncrement(volatile LONG* destination) {
    LONG& storage = const_cast<LONG&>(*destination);
    std::atomic_ref<LONG> atomic(storage);
    return atomic.fetch_add(1) + 1;
}
inline LONG InterlockedCompareExchange(volatile LONG* destination, LONG exchange, LONG comparand) {
    LONG& storage = const_cast<LONG&>(*destination);
    std::atomic_ref<LONG> atomic(storage);
    LONG expected = comparand;
    atomic.compare_exchange_strong(expected, exchange, std::memory_order_seq_cst);
    return expected;
}

inline void KeInitializeMutex(KMUTEX* mutex, ULONG) { mutex->depth = 0; }
inline NTSTATUS KeWaitForSingleObject(KMUTEX* mutex, ULONG, ULONG, BOOLEAN, void*) {
    if (mutex->depth != 0) hv_wfp_fake::state().mutex_reentry = TRUE;
    ++mutex->depth;
    ++hv_wfp_fake::state().management_mutex_depth;
    return STATUS_SUCCESS;
}
inline LONG KeReleaseMutex(KMUTEX* mutex, BOOLEAN) {
    if (mutex->depth == 0 || hv_wfp_fake::state().management_mutex_depth == 0) {
        hv_wfp_fake::state().mutex_release_without_acquire = TRUE;
        return 0;
    }
    --mutex->depth;
    --hv_wfp_fake::state().management_mutex_depth;
    return 0;
}
inline void ExInitializeRundownProtection(EX_RUNDOWN_REF* rundown) {
    rundown->accepting = TRUE;
    rundown->acquired = 0;
}
inline BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF* rundown) {
    if (!rundown->accepting) return FALSE;
    ++rundown->acquired;
    return TRUE;
}
inline void ExReleaseRundownProtection(EX_RUNDOWN_REF* rundown) {
    if (rundown->acquired == 0) {
        hv_wfp_fake::state().rundown_not_drained = TRUE;
        return;
    }
    --rundown->acquired;
}
inline void ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF* rundown) {
    ++hv_wfp_fake::state().rundown_wait_calls;
    rundown->accepting = FALSE;
    hv_wfp_fake::DrainWork();
    if (rundown->acquired != 0) hv_wfp_fake::state().rundown_not_drained = TRUE;
}

inline void KeInitializeTimer(KTIMER* timer) {
    timer->armed = FALSE;
    timer->dpc = nullptr;
    auto& timers = hv_wfp_fake::state().timers;
    if (std::find(timers.begin(), timers.end(), timer) == timers.end()) timers.push_back(timer);
}
inline void KeInitializeDpc(KDPC* dpc, PKDEFERRED_ROUTINE routine, void* context) {
    dpc->DeferredRoutine = routine;
    dpc->DeferredContext = context;
}
inline BOOLEAN KeSetTimer(KTIMER* timer, LARGE_INTEGER, KDPC* dpc) {
    const BOOLEAN was_armed = timer->armed;
    timer->armed = TRUE;
    timer->dpc = dpc;
    ++hv_wfp_fake::state().timer_set_calls;
    return was_armed;
}
inline BOOLEAN KeCancelTimer(KTIMER* timer) {
    const BOOLEAN was_armed = timer->armed;
    timer->armed = FALSE;
    ++hv_wfp_fake::state().timer_cancel_calls;
    return was_armed;
}
inline NTSTATUS KeDelayExecutionThread(ULONG, BOOLEAN, LARGE_INTEGER*) {
    // The real unload retry sleeps. Draining deterministic fake work preserves
    // ordering without making the offline suite wait.
    hv_wfp_fake::DrainWork();
    return STATUS_SUCCESS;
}
inline void KeFlushQueuedDpcs() { ++hv_wfp_fake::state().dpc_flush_calls; }

inline ULONG DbgPrintEx(ULONG, ULONG, const char*, ...) {
    ++hv_wfp_fake::state().dbg_print_calls;
    return 0;
}
#define NT_ASSERT(expression) do { if (!(expression)) ++::hv_wfp_fake::state().assertion_failures; } while (false)

inline NTSTATUS ExUuidCreate(GUID* guid) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::uuid_create, &failure)) return failure;
    const UINT32 sequence = hv_wfp_fake::state().next_uuid++;
    *guid = {sequence, static_cast<std::uint16_t>(sequence), 0xfeed,
        {0xca, 0x11, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x1u}};
    return STATUS_SUCCESS;
}

inline NTSTATUS IoCreateDevice(PDRIVER_OBJECT, ULONG, void*, ULONG, ULONG, BOOLEAN, PDEVICE_OBJECT* device) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::create_device, &failure)) return failure;
    auto object = std::make_unique<_DEVICE_OBJECT>();
    if (!object) return STATUS_INSUFFICIENT_RESOURCES;
    *device = object.get();
    hv_wfp_fake::state().devices.push_back(std::move(object));
    ++hv_wfp_fake::state().live_devices;
    return STATUS_SUCCESS;
}
inline void IoDeleteDevice(PDEVICE_OBJECT device) {
    if (device == nullptr || device->deleted) return;
    for (const hv_wfp_fake::QueuedWork& work : hv_wfp_fake::state().work_queue) {
        if (work.item != nullptr && work.item->device == device) {
            hv_wfp_fake::state().device_deleted_with_work = TRUE;
            break;
        }
    }
    device->deleted = TRUE;
    --hv_wfp_fake::state().live_devices;
}
inline PIO_WORKITEM IoAllocateWorkItem(PDEVICE_OBJECT device) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::allocate_work_item, &failure)) return nullptr;
    auto work_item = std::make_unique<_IO_WORKITEM>();
    if (!work_item) return nullptr;
    work_item->device = device;
    PIO_WORKITEM raw = work_item.get();
    hv_wfp_fake::state().work_items.push_back(std::move(work_item));
    ++hv_wfp_fake::state().live_work_items;
    return raw;
}
inline void IoFreeWorkItem(PIO_WORKITEM work_item) {
    if (work_item == nullptr || work_item->freed) return;
    for (const hv_wfp_fake::QueuedWork& queued : hv_wfp_fake::state().work_queue) {
        if (queued.item == work_item) {
            hv_wfp_fake::state().work_freed_while_queued = TRUE;
            break;
        }
    }
    if (hv_wfp_fake::AnyTimerArmed()) hv_wfp_fake::state().timer_armed_at_work_free = TRUE;
    work_item->freed = TRUE;
    --hv_wfp_fake::state().live_work_items;
}
inline void IoQueueWorkItem(PIO_WORKITEM work_item, IO_WORKITEM_ROUTINE* routine, ULONG, void* context) {
    if (work_item == nullptr || work_item->freed || work_item->device == nullptr || work_item->device->deleted) {
        hv_wfp_fake::state().work_after_free = TRUE;
        return;
    }
    hv_wfp_fake::State& current = hv_wfp_fake::state();
    if (current.subscribe_in_progress) ++current.work_queues_during_subscribe;
    current.work_queue.push_back({work_item, routine, context});
    ++current.work_queue_calls;
}

inline NTSTATUS FwpsInjectionHandleCreate0(ADDRESS_FAMILY family, UINT32 type, HANDLE* handle) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::injection_create, &failure)) return failure;
    auto injection = std::make_unique<hv_wfp_fake::FakeInjection>();
    if (!injection) return STATUS_INSUFFICIENT_RESOURCES;
    injection->type = type;
    injection->family = family;
    injection->live = TRUE;
    *handle = injection.get();
    hv_wfp_fake::state().injections.push_back(std::move(injection));
    ++hv_wfp_fake::state().live_injections;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpsInjectionHandleDestroy0(HANDLE handle) {
    auto* injection = static_cast<hv_wfp_fake::FakeInjection*>(handle);
    if (injection == nullptr || !injection->live) return STATUS_INVALID_HANDLE;
    injection->live = FALSE;
    --hv_wfp_fake::state().live_injections;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpsCalloutRegister0(PDEVICE_OBJECT, const FWPS_CALLOUT0* callout, UINT32* id) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::callout_register, &failure)) return failure;
    const UINT32 new_id = hv_wfp_fake::state().next_callout_id++;
    hv_wfp_fake::state().callouts.push_back({new_id, callout->calloutKey, callout->notifyFn, TRUE});
    *id = new_id;
    ++hv_wfp_fake::state().live_callouts;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpsCalloutUnregisterById0(UINT32 id) {
    for (hv_wfp_fake::CalloutRegistration& callout : hv_wfp_fake::state().callouts) {
        if (callout.id == id && callout.live) {
            callout.live = FALSE;
            --hv_wfp_fake::state().live_callouts;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}
inline FWPS_PACKET_INJECTION_STATE FwpsQueryPacketInjectionState0(HANDLE handle, PNET_BUFFER_LIST nbl, void*) {
    auto* injection = static_cast<hv_wfp_fake::FakeInjection*>(handle);
    if (injection == nullptr || !injection->live) return FWPS_PACKET_NOT_INJECTED;
    for (const hv_wfp_fake::InjectionState& value : hv_wfp_fake::state().injection_states) {
        if (value.nbl == nbl && value.family == injection->family && value.type == injection->type) return value.state;
    }
    return FWPS_PACKET_NOT_INJECTED;
}
inline NTSTATUS FwpsInjectForwardAsync0(HANDLE handle, void*, UINT32 flags, ADDRESS_FAMILY family,
    COMPARTMENT_ID compartment, ULONG destination_interface, PNET_BUFFER_LIST nbl,
    FWPS_INJECT_COMPLETE0 completion, void* context) {
    hv_wfp_fake::state().injection_calls.push_back(
        {handle, family, compartment, destination_interface, nbl, completion, context});
    auto* injection = static_cast<hv_wfp_fake::FakeInjection*>(handle);
    if (injection == nullptr || !injection->live) return STATUS_INVALID_HANDLE;
    NTSTATUS failure = STATUS_SUCCESS;
    if (injection->type != FWPS_INJECTION_TYPE_FORWARD || injection->family != family || flags != 0)
        return STATUS_INVALID_PARAMETER;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::injection_forward, &failure)) return failure;
    if (hv_wfp_fake::state().complete_inline) {
        nbl->Status = hv_wfp_fake::state().completion_status;
        completion(context, nbl, FALSE);
    }
    return STATUS_SUCCESS;
}

inline NTSTATUS FakeNetworkInject(HANDLE handle, UINT32 flags, COMPARTMENT_ID compartment,
    ULONG interface_index, ULONG sub_interface, PNET_BUFFER_LIST nbl,
    FWPS_INJECT_COMPLETE0 completion, void* context, ULONG route) {
    auto* injection = static_cast<hv_wfp_fake::FakeInjection*>(handle);
    if (injection == nullptr || !injection->live) return STATUS_INVALID_HANDLE;
    if (injection->type != FWPS_INJECTION_TYPE_NETWORK || flags != 0) return STATUS_INVALID_PARAMETER;
    hv_wfp_fake::state().injection_calls.push_back(
        {handle, injection->family, compartment, interface_index, nbl, completion, context, route, sub_interface});
    NTSTATUS failure = STATUS_SUCCESS;
    auto point = route == 1 ? hv_wfp_fake::FailurePoint::injection_receive : hv_wfp_fake::FailurePoint::injection_send;
    if (hv_wfp_fake::TakeFailure(point, &failure)) return failure;
    if (hv_wfp_fake::state().complete_inline) {
        nbl->Status = hv_wfp_fake::state().completion_status;
        completion(context, nbl, FALSE);
    }
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpsInjectNetworkReceiveAsync0(HANDLE handle, void*, UINT32 flags,
    COMPARTMENT_ID compartment, ULONG interface_index, ULONG sub_interface, PNET_BUFFER_LIST nbl,
    FWPS_INJECT_COMPLETE0 completion, void* context) {
    return FakeNetworkInject(handle, flags, compartment, interface_index, sub_interface, nbl, completion, context, 1);
}
inline NTSTATUS FwpsInjectNetworkSendAsync0(HANDLE handle, void*, UINT32 flags,
    COMPARTMENT_ID compartment, PNET_BUFFER_LIST nbl, FWPS_INJECT_COMPLETE0 completion, void* context) {
    return FakeNetworkInject(handle, flags, compartment, 0, 0, nbl, completion, context, 2);
}

inline FWPM_SERVICE_STATE FwpmBfeStateGet0() {
    hv_wfp_fake::State& current = hv_wfp_fake::state();
    if (current.subscribe_in_progress) current.bfe_state_queried_during_subscribe = TRUE;
    return current.bfe_state;
}
inline NTSTATUS FwpmBfeStateSubscribeChanges0(PDEVICE_OBJECT, FWPM_BFE_STATE_CHANGE_CALLBACK0 callback,
    void* context, HANDLE* subscription) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::bfe_subscribe, &failure)) return failure;
    auto value = std::make_unique<hv_wfp_fake::FakeSubscription>();
    if (!value) return STATUS_INSUFFICIENT_RESOURCES;
    value->callback = callback;
    value->context = context;
    value->live = TRUE;
    *subscription = value.get();
    hv_wfp_fake::State& current = hv_wfp_fake::state();
    current.subscriptions.push_back(std::move(value));
    ++current.live_subscriptions;
    if (!current.subscribe_callback_pending) return STATUS_SUCCESS;

    current.subscribe_callback_pending = FALSE;
    current.bfe_state = current.subscribe_callback_state;
    current.subscribe_in_progress = TRUE;
    ++current.bfe_notifications;
    callback(context, current.subscribe_callback_state);
    if (current.run_work_immediately_inside_subscribe) hv_wfp_fake::DrainWork();
    current.subscribe_in_progress = FALSE;
    current.run_work_immediately_inside_subscribe = FALSE;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmBfeStateUnsubscribeChanges0(HANDLE subscription) {
    if (hv_wfp_fake::state().management_mutex_depth != 0)
        hv_wfp_fake::state().unsubscribe_while_management_locked = TRUE;
    ++hv_wfp_fake::state().unsubscribe_calls;
    auto* value = static_cast<hv_wfp_fake::FakeSubscription*>(subscription);
    if (value == nullptr || !value->live) return STATUS_INVALID_HANDLE;
    value->live = FALSE;
    --hv_wfp_fake::state().live_subscriptions;
    return STATUS_SUCCESS;
}

inline NTSTATUS FwpmEngineOpen0(const wchar_t*, UINT32, void*, const FWPM_SESSION0*, HANDLE* engine_handle) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::engine_open, &failure)) return failure;
    auto engine = std::make_unique<hv_wfp_fake::FakeEngine>();
    if (!engine) return STATUS_INSUFFICIENT_RESOURCES;
    engine->serial = hv_wfp_fake::state().next_engine_serial++;
    engine->live = TRUE;
    *engine_handle = engine.get();
    hv_wfp_fake::state().engines.push_back(std::move(engine));
    ++hv_wfp_fake::state().live_engines;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmEngineClose0(HANDLE engine_handle) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::engine_close, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    if (engine == nullptr) return STATUS_INVALID_HANDLE;
    engine->live = FALSE;
    engine->in_transaction = FALSE;
    engine->staged_filters.clear();
    auto& filters = hv_wfp_fake::state().active_filters;
    filters.erase(std::remove_if(filters.begin(), filters.end(), [engine](const hv_wfp_fake::FilterRecord& filter) {
        return filter.engine_serial == engine->serial;
    }), filters.end());
    --hv_wfp_fake::state().live_engines;
    ++hv_wfp_fake::state().engine_close_calls;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmTransactionBegin0(HANDLE engine_handle, UINT32) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::transaction_begin, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    if (engine == nullptr) return STATUS_INVALID_HANDLE;
    if (engine->in_transaction) return STATUS_UNSUCCESSFUL;
    engine->in_transaction = TRUE;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmTransactionAbort0(HANDLE engine_handle) {
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    if (engine == nullptr) return STATUS_INVALID_HANDLE;
    engine->staged_filters.clear();
    engine->in_transaction = FALSE;
    ++hv_wfp_fake::state().transaction_abort_calls;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmTransactionCommit0(HANDLE engine_handle) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::transaction_commit, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    if (engine == nullptr || !engine->in_transaction) return STATUS_INVALID_HANDLE;
    auto& active = hv_wfp_fake::state().active_filters;
    active.insert(active.end(), engine->staged_filters.begin(), engine->staged_filters.end());
    engine->staged_filters.clear();
    engine->in_transaction = FALSE;
    ++hv_wfp_fake::state().transaction_commit_calls;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmProviderAdd0(HANDLE engine_handle, const FWPM_PROVIDER0*, void*) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::provider_add, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    return engine != nullptr && engine->in_transaction ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
}
inline NTSTATUS FwpmSubLayerAdd0(HANDLE engine_handle, const FWPM_SUBLAYER0* sublayer, void*) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::sublayer_add, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    if (engine == nullptr || !engine->in_transaction || sublayer == nullptr) return STATUS_INVALID_PARAMETER;
    engine->sublayer = sublayer->subLayerKey;
    engine->sublayer_weight = sublayer->weight;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmCalloutAdd0(HANDLE engine_handle, const FWPM_CALLOUT0*, void*, UINT32*) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::management_callout_add, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    return engine != nullptr && engine->in_transaction ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
}
inline NTSTATUS FwpmFilterAdd0(HANDLE engine_handle, const FWPM_FILTER0* filter, void*, UINT64* id) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::filter_add, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    if (engine == nullptr || !engine->in_transaction || filter == nullptr ||
        !(filter->subLayerKey == engine->sublayer) ||
        (filter->numFilterConditions != 0 && filter->filterCondition == nullptr)) return STATUS_INVALID_PARAMETER;
    hv_wfp_fake::FilterRecord record{};
    record.engine_serial = engine->serial;
    record.id = (engine->serial << 32) | hv_wfp_fake::state().next_filter_serial++;
    record.layer = filter->layerKey;
    record.callout = filter->action.calloutKey;
    record.sublayer = filter->subLayerKey;
    record.sublayer_weight = engine->sublayer_weight;
    record.condition_count = filter->numFilterConditions;
    record.has_condition_pointer = filter->filterCondition != nullptr;
    record.action_type = filter->action.type;
    record.raw_context = filter->rawContext;
    const NTSTATUS notify = hv_wfp_fake::NotifyFilter(record.callout, FWPS_CALLOUT_NOTIFY_ADD_FILTER, record.raw_context);
    if (!NT_SUCCESS(notify)) return notify;
    engine->staged_filters.push_back(record);
    if (id != nullptr) *id = record.id;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpmFilterDeleteById0(HANDLE engine_handle, UINT64 id) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::filter_delete, &failure)) return failure;
    hv_wfp_fake::FakeEngine* engine = hv_wfp_fake::RequireLiveEngine(engine_handle);
    if (engine == nullptr) return STATUS_INVALID_HANDLE;
    auto& filters = hv_wfp_fake::state().active_filters;
    auto it = std::find_if(filters.begin(), filters.end(), [engine, id](const hv_wfp_fake::FilterRecord& filter) {
        return filter.engine_serial == engine->serial && filter.id == id;
    });
    if (it == filters.end()) {
        hv_wfp_fake::state().stale_engine_id_use = TRUE;
        return STATUS_NOT_FOUND;
    }
    const NTSTATUS notify = hv_wfp_fake::NotifyFilter(it->callout, FWPS_CALLOUT_NOTIFY_DELETE_FILTER, it->raw_context);
    if (!NT_SUCCESS(notify)) return notify;
    filters.erase(it);
    return STATUS_SUCCESS;
}

inline NTSTATUS NdisAllocateNetBufferListContext(PNET_BUFFER_LIST nbl, USHORT size, USHORT backfill, ULONG) {
    NTSTATUS failure = STATUS_SUCCESS;
    if (hv_wfp_fake::TakeFailure(hv_wfp_fake::FailurePoint::context_allocate, &failure)) return failure;
    auto* memory = new (std::nothrow) UCHAR[sizeof(NET_BUFFER_LIST_CONTEXT) + size + backfill];
    if (memory == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    auto* context = reinterpret_cast<NET_BUFFER_LIST_CONTEXT*>(memory);
    context->Next = nbl->Context;
    context->Size = static_cast<USHORT>(size + backfill);
    context->Offset = backfill;
    nbl->Context = context;
    ++hv_wfp_fake::state().context_allocations;
    return STATUS_SUCCESS;
}
inline void NdisFreeNetBufferListContext(PNET_BUFFER_LIST nbl, USHORT size) {
    auto* context = nbl->Context;
    if (context == nullptr || context->Size - context->Offset != size) std::abort();
    nbl->Context = context->Next;
    delete[] reinterpret_cast<UCHAR*>(context);
    ++hv_wfp_fake::state().context_frees;
}
inline NTSTATUS FakeClone(PNET_BUFFER_LIST original, BOOLEAN reassembled, PNET_BUFFER_LIST* out) {
    NTSTATUS failure = STATUS_SUCCESS;
    const auto point = reassembled ? hv_wfp_fake::FailurePoint::reassemble : hv_wfp_fake::FailurePoint::clone;
    if (hv_wfp_fake::TakeFailure(point, &failure)) return failure;
    auto* packet = new (std::nothrow) _NET_BUFFER_LIST{};
    if (packet == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    packet->FirstNb = original->FirstNb;
    packet->Reassembled = reassembled;
    *out = packet;
    if (reassembled) ++hv_wfp_fake::state().reassemblies;
    else ++hv_wfp_fake::state().clones;
    ++hv_wfp_fake::state().live_packets;
    return STATUS_SUCCESS;
}
inline NTSTATUS FwpsAllocateCloneNetBufferList0(PNET_BUFFER_LIST original, void*, void*, ULONG, PNET_BUFFER_LIST* out) {
    return FakeClone(original, FALSE, out);
}
inline NTSTATUS FwpsReassembleForwardFragmentGroup0(ADDRESS_FAMILY, PNET_BUFFER_LIST original, void*, ULONG, ULONG, PNET_BUFFER_LIST* out) {
    return FakeClone(original, TRUE, out);
}
inline void FwpsFreeCloneNetBufferList0(PNET_BUFFER_LIST packet, ULONG) {
    if (packet->Reassembled || packet->Context != nullptr) std::abort();
    ++hv_wfp_fake::state().clone_frees;
    --hv_wfp_fake::state().live_packets;
    delete packet;
}
inline void FwpsFreeNetBufferList0(PNET_BUFFER_LIST packet) {
    if (!packet->Reassembled || packet->Context != nullptr) std::abort();
    ++hv_wfp_fake::state().reassembly_frees;
    --hv_wfp_fake::state().live_packets;
    delete packet;
}

#endif
