#include <cstdio>
#include <cstdlib>

#define HV_WFP_OFFLINE_TEST
#include "../../driver/shim/wfp_forward.cpp"

namespace {

unsigned g_status_reports = 0;
unsigned g_forward_calls = 0;

#define CHECK(expression) do { \
    if (!(expression)) { \
        std::fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #expression); \
        return false; \
    } \
} while (false)

extern "C" __declspec(noreturn) void hv_bugcheck(void) {
    std::fputs("unexpected hv_bugcheck\n", stderr);
    std::abort();
}

extern "C" void HvWfpStatus(ULONG) { ++g_status_reports; }
struct InjectionError {
    ULONG status, ipv6, route, completion, destination, failures;
};
std::vector<InjectionError> g_injection_errors;
extern "C" void HvWfpInjectionError(ULONG status, ULONG ipv6, ULONG route, ULONG completion,
    ULONG destination, ULONG failures) {
    g_injection_errors.push_back({status, ipv6, route, completion, destination, failures});
}

extern "C" void HvForwardStop() {
    auto hook = hv_wfp_fake::state().forward_stop_hook;
    if (hook != nullptr) hook();
}

struct WfpTestState {
    ULONG Healthy, Dirty, WorkQueued, ResetEngine, NotificationsReady;
};
extern "C" WfpTestState HvWfpTestState();
static void (*WorkHandoffHook)() = nullptr;
extern "C" void hv_wfp_test_handoff() {
    auto hook = WorkHandoffHook;
    WorkHandoffHook = nullptr;
    if (hook != nullptr) hook();
}
struct PolicyCall {
    ULONG InterfaceIndex, Direction, Family, Cacheable, Session;
};
static PolicyCall PolicyObservation{};
static LONG PolicyResult = 1;
static BOOLEAN DriverStopping = FALSE, SessionAvailable = TRUE;
static ULONG ResourceDrops = 0, SessionReferences = 0;
static PNET_BUFFER_LIST PendingPacket = nullptr;
static void (*PolicyHook)(PNET_BUFFER_LIST) = nullptr;
extern "C" BOOLEAN hv_wfp_driver_stopping() { return DriverStopping; }
extern "C" BOOLEAN hv_wfp_session_acquire() {
    if (SessionAvailable) ++SessionReferences;
    return SessionAvailable;
}
extern "C" void hv_wfp_session_release() { --SessionReferences; }
extern "C" void HvResourceDrop() { ++ResourceDrops; }
extern "C" int HvClassifyIp(ULONG_PTR packet, ULONG index, ULONG direction, ULONG family, ULONG cacheable, ULONG session) {
    PolicyObservation = {index, direction, family, cacheable, session};
    ++g_forward_calls;
    PendingPacket = reinterpret_cast<PNET_BUFFER_LIST>(packet);
    if (PolicyHook != nullptr) PolicyHook(PendingPacket);
    return PolicyResult;
}

void NTAPI InjectionComplete(void*, PNET_BUFFER_LIST, BOOLEAN) {}
void RequestAtWorkHandoff() { HvWfpRequestReconcile(); }

bool HasGlobalFilters() {
    const auto& filters = hv_wfp_fake::state().active_filters;
    if (filters.size() != 2) return false;
    unsigned v4 = 0, v6 = 0;
    for (const auto& filter : filters) {
        if (filter.condition_count != 0 || filter.has_condition_pointer || filter.raw_context != 0 ||
            filter.action_type != FWP_ACTION_CALLOUT_TERMINATING ||
            !(filter.sublayer == SublayerKey) || filter.sublayer_weight != 0x7FFF) return false;
        if (filter.layer == FWPM_LAYER_IPFORWARD_V4 && filter.callout == CalloutKeys[0]) ++v4;
        else if (filter.layer == FWPM_LAYER_IPFORWARD_V6 && filter.callout == CalloutKeys[1]) ++v6;
        else return false;
    }
    return v4 == 1 && v6 == 1;
}

bool Start(_DRIVER_OBJECT* driver) {
    CHECK(NT_SUCCESS(HvWfpInitialize(driver)));
    return true;
}

bool StopAndVerifyClean() {
    HvWfpUninitialize();
    const auto& fake = hv_wfp_fake::state();
    CHECK(fake.live_packets == 0);
    CHECK(fake.clones == fake.clone_frees && fake.reassemblies == fake.reassembly_frees);
    CHECK(fake.context_allocations == fake.context_frees);
    CHECK(SessionReferences == 0);
    CHECK(fake.live_devices == 0);
    CHECK(fake.live_work_items == 0);
    CHECK(fake.live_injections == 0);
    CHECK(fake.live_callouts == 0);
    CHECK(fake.live_subscriptions == 0);
    CHECK(fake.live_engines == 0);
    CHECK(fake.active_filters.empty());
    CHECK(fake.work_queue.empty());
    CHECK(!hv_wfp_fake::AnyTimerArmed());
    CHECK(!fake.stale_engine_use);
    CHECK(!fake.stale_engine_id_use);
    CHECK(!fake.mutex_reentry);
    CHECK(!fake.mutex_release_without_acquire);
    CHECK(!fake.unsubscribe_while_management_locked);
    CHECK(!fake.work_after_free);
    CHECK(!fake.work_freed_while_queued);
    CHECK(!fake.device_deleted_with_work);
    CHECK(!fake.timer_armed_at_work_free);
    CHECK(!fake.rundown_not_drained);
    CHECK(fake.assertion_failures == 0);
    return true;
}

bool TestGlobalRegistrationWithoutAnyNdisModules() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    const auto& fake = hv_wfp_fake::state();
    CHECK(fake.live_devices == 1);
    CHECK(fake.live_work_items == 1);
    CHECK(fake.live_injections == 4);
    CHECK(fake.live_callouts == 2);
    CHECK(fake.live_subscriptions == 1);
    CHECK(fake.live_engines == 1);
    CHECK(HasGlobalFilters());
    CHECK(HvWfpTestState().Healthy == 1);

    FWPS_CLASSIFY_OUT0 out{};
    out.rights = FWPS_RIGHT_ACTION_WRITE;
    const unsigned before = g_forward_calls;
    Classify(nullptr, nullptr, nullptr, nullptr, 0, &out);
    CHECK(g_forward_calls == before);
    CHECK(out.actionType == FWP_ACTION_BLOCK);
    out.rights = 0;
    Classify(nullptr, nullptr, nullptr, nullptr, 0, &out);
    CHECK(g_forward_calls == before);
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestPrivateInitializationFailuresUnwind() {
    for (auto failure : {hv_wfp_fake::FailurePoint::create_device,
                         hv_wfp_fake::FailurePoint::allocate_work_item,
                         hv_wfp_fake::FailurePoint::bfe_subscribe}) {
        hv_wfp_fake::Reset();
        hv_wfp_fake::FailNext(failure);
        _DRIVER_OBJECT driver{};
        CHECK(!NT_SUCCESS(HvWfpInitialize(&driver)));
        CHECK(StopAndVerifyClean());
    }
    return true;
}

bool TestSubscribeCallbackDefersReconcileUntilReady() {
    hv_wfp_fake::Reset();
    hv_wfp_fake::NotifyInsideSubscribe(FWPM_SERVICE_RUNNING);
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    const auto& fake = hv_wfp_fake::state();
    CHECK(fake.bfe_notifications == 1);
    CHECK(!fake.subscribe_in_progress);
    CHECK(fake.work_queues_during_subscribe == 0);
    CHECK(!fake.bfe_state_queried_during_subscribe);
    CHECK(HvWfpTestState().NotificationsReady == 1);
    CHECK(HvWfpTestState().Dirty == 1 && HvWfpTestState().WorkQueued == 1);
    CHECK(hv_wfp_fake::QueuedWorkCount() == 1);
    CHECK(fake.work_queue_calls == 1);
    CHECK(HasGlobalFilters());
    hv_wfp_fake::DrainWork();
    CHECK(HvWfpTestState().Dirty == 0 && HvWfpTestState().WorkQueued == 0);
    CHECK(HvWfpTestState().Healthy == 1);
    CHECK(HasGlobalFilters());
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestBfePausedStartAndStop() {
    hv_wfp_fake::Reset();
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_STOPPED, FALSE);
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    CHECK(hv_wfp_fake::state().live_callouts == 0);
    CHECK(hv_wfp_fake::state().live_injections == 0);
    CHECK(hv_wfp_fake::state().live_engines == 0);
    CHECK(hv_wfp_fake::state().active_filters.empty());
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_RUNNING);
    hv_wfp_fake::DrainWork();
    CHECK(HasGlobalFilters());
    CHECK(HvWfpTestState().Healthy == 1);
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_STOPPED);
    hv_wfp_fake::DrainWork();
    CHECK(hv_wfp_fake::state().active_filters.empty());
    CHECK(hv_wfp_fake::state().live_engines == 0);
    CHECK(HvWfpTestState().Healthy == 0);
    CHECK(!hv_wfp_fake::AnyTimerArmed());
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_RUNNING);
    hv_wfp_fake::DrainWork();
    CHECK(HasGlobalFilters());
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestBfeStopStartBurstReplacesSession() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    CHECK(HasGlobalFilters());
    const UINT64 old_engine = hv_wfp_fake::state().active_filters.front().engine_serial;
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_STOPPED);
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_START_PENDING);
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_RUNNING);
    CHECK(hv_wfp_fake::QueuedWorkCount() == 1);
    hv_wfp_fake::DrainWork();
    CHECK(HasGlobalFilters());
    CHECK(hv_wfp_fake::state().active_filters.front().engine_serial != old_engine);
    CHECK(hv_wfp_fake::state().live_engines == 1);
    CHECK(hv_wfp_fake::state().engines.size() == 2);
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestRegistrationFailuresRetryWithoutNdisAttachments() {
    const hv_wfp_fake::FailurePoint failures[] = {
        hv_wfp_fake::FailurePoint::callout_register,
        hv_wfp_fake::FailurePoint::injection_create,
        hv_wfp_fake::FailurePoint::engine_open,
        hv_wfp_fake::FailurePoint::transaction_begin,
        hv_wfp_fake::FailurePoint::provider_add,
        hv_wfp_fake::FailurePoint::sublayer_add,
        hv_wfp_fake::FailurePoint::management_callout_add,
        hv_wfp_fake::FailurePoint::uuid_create,
        hv_wfp_fake::FailurePoint::filter_add,
        hv_wfp_fake::FailurePoint::transaction_commit,
    };
    for (const auto failure : failures) {
        hv_wfp_fake::Reset();
        hv_wfp_fake::FailNext(failure);
        _DRIVER_OBJECT driver{};
        CHECK(Start(&driver));
        CHECK(hv_wfp_fake::state().live_devices == 1);
        CHECK(hv_wfp_fake::state().live_work_items == 1);
        CHECK(hv_wfp_fake::state().live_subscriptions == 1);
        CHECK(hv_wfp_fake::state().active_filters.empty());
        CHECK(HvWfpTestState().Healthy == 0);
        CHECK(hv_wfp_fake::AnyTimerArmed());
        hv_wfp_fake::FireTimers();
        hv_wfp_fake::DrainWork();
        CHECK(hv_wfp_fake::state().live_callouts == 2);
        CHECK(hv_wfp_fake::state().live_injections == 4);
        CHECK(hv_wfp_fake::state().live_engines == 1);
        CHECK(HasGlobalFilters());
        CHECK(HvWfpTestState().Healthy == 1);
        CHECK(!hv_wfp_fake::AnyTimerArmed());
        CHECK(StopAndVerifyClean());
    }
    return true;
}

bool TestPartialFamilyTransactionsAreNeverPublished() {
    for (unsigned successful = 0; successful != 2; ++successful) {
        hv_wfp_fake::Reset();
        hv_wfp_fake::FailAfter(hv_wfp_fake::FailurePoint::filter_add, successful);
        _DRIVER_OBJECT driver{};
        CHECK(Start(&driver));
        CHECK(hv_wfp_fake::state().active_filters.empty());
        CHECK(hv_wfp_fake::AnyTimerArmed());
        hv_wfp_fake::FireTimers();
        hv_wfp_fake::DrainWork();
        CHECK(HasGlobalFilters());
        CHECK(StopAndVerifyClean());
    }
    return true;
}

bool TestCloseFailurePreservesThenRebuildsAndUnloads() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    CHECK(HasGlobalFilters());
    const UINT64 old_id = hv_wfp_fake::state().active_filters.front().id;
    hv_wfp_fake::FailNext(hv_wfp_fake::FailurePoint::engine_close);
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_STOPPED);
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_RUNNING);
    hv_wfp_fake::DrainWork();
    CHECK(HasGlobalFilters());
    CHECK(hv_wfp_fake::state().active_filters.front().id == old_id);
    CHECK(hv_wfp_fake::state().live_engines == 1);
    CHECK(hv_wfp_fake::AnyTimerArmed());
    CHECK(HvWfpTestState().ResetEngine == 1);
    hv_wfp_fake::FireTimers();
    hv_wfp_fake::DrainWork();
    CHECK(HasGlobalFilters());
    CHECK(hv_wfp_fake::state().active_filters.front().id != old_id);
    const unsigned closes = hv_wfp_fake::Calls(hv_wfp_fake::FailurePoint::engine_close);
    hv_wfp_fake::FailNext(hv_wfp_fake::FailurePoint::engine_close);
    HvWfpUninitialize();
    CHECK(hv_wfp_fake::Calls(hv_wfp_fake::FailurePoint::engine_close) == closes + 2);
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestWorkHandoffDoesNotLoseRequest() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    const unsigned before = hv_wfp_fake::state().work_run_calls;
    WorkHandoffHook = RequestAtWorkHandoff;
    HvWfpRequestReconcile();
    CHECK(hv_wfp_fake::QueuedWorkCount() == 1);
    hv_wfp_fake::DrainWork();
    CHECK(hv_wfp_fake::QueuedWorkCount() == 0);
    CHECK(hv_wfp_fake::state().work_run_calls == before + 2);
    CHECK(HvWfpTestState().WorkQueued == 0 && HvWfpTestState().Dirty == 0);
    CHECK(HasGlobalFilters());
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestStopUnsubscribesAndDrainsBeforeDestruction() {
    hv_wfp_fake::Reset();
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_STOPPED, FALSE);
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    hv_wfp_fake::FailNext(hv_wfp_fake::FailurePoint::engine_open);
    hv_wfp_fake::SetBfeState(FWPM_SERVICE_RUNNING);
    hv_wfp_fake::DrainWork();
    CHECK(hv_wfp_fake::AnyTimerArmed());
    HvWfpRequestReconcile();
    CHECK(hv_wfp_fake::QueuedWorkCount() == 1);
    HvWfpStop();
    const auto& fake = hv_wfp_fake::state();
    CHECK(fake.live_subscriptions == 0);
    CHECK(fake.live_work_items == 0);
    CHECK(fake.work_queue.empty());
    CHECK(!hv_wfp_fake::AnyTimerArmed());
    CHECK(!fake.unsubscribe_while_management_locked);
    CHECK(!fake.work_freed_while_queued);
    CHECK(!fake.timer_armed_at_work_free);
    CHECK(fake.dpc_flush_calls != 0 && fake.rundown_wait_calls != 0);
    CHECK(StopAndVerifyClean());
    return true;
}

void ReleasePendingPacketOnStop() {
    HvWfpReleasePacket();
    hv_wfp_fake::state().forward_stop_hook = nullptr;
}

bool TestStopResolvesPendingBeforeWaitingForPacketRundown() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    CHECK(HvWfpRetainPacket());
    CHECK(PacketRundown.acquired == 1);
    hv_wfp_fake::state().forward_stop_hook = ReleasePendingPacketOnStop;
    HvWfpStop();
    CHECK(PacketRundown.acquired == 0);
    CHECK(!HvWfpRetainPacket());
    CHECK(StopAndVerifyClean());
    return true;
}

#include "wfp_checksum_cases.h"
#include "wfp_cpu_cases.h"
#include "wfp_packet_cases.h"

bool TestInjectionWrapperPreservesArgumentsAndFailure() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    InjectionPacket fixture;
    auto& packet = fixture.Packet;
    int completion_context = 7;
    hv_wfp_fake::SetInjectionState(&packet, AF_INET, FWPS_PACKET_INJECTED_BY_SELF);
    CHECK(HvWfpIsSelfInjected(&packet, FALSE));
    CHECK(!HvWfpIsSelfInjected(&packet, TRUE));
    CHECK(NT_SUCCESS(HvWfpInject(&packet, FALSE, 37, 71, 0, 0, FALSE, InjectionComplete, &completion_context)));
    CHECK(hv_wfp_fake::state().injection_calls.size() == 1);
    const auto& v4 = hv_wfp_fake::state().injection_calls.back();
    CHECK(v4.family == AF_INET && v4.compartment == static_cast<COMPARTMENT_ID>(37));
    CHECK(v4.destination_interface == 71);
    CHECK(v4.nbl == &packet && v4.completion == InjectionComplete && v4.context == &completion_context);
    fixture.SetFamily(TRUE);
    hv_wfp_fake::FailNext(hv_wfp_fake::FailurePoint::injection_forward);
    CHECK(HvWfpInject(&packet, TRUE, 99, 303, 0, 0, FALSE, InjectionComplete, &packet) == STATUS_UNSUCCESSFUL);
    CHECK(hv_wfp_fake::state().injection_calls.size() == 2);
    const auto& v6 = hv_wfp_fake::state().injection_calls.back();
    CHECK(v6.family == AF_INET6 && v6.compartment == static_cast<COMPARTMENT_ID>(99));
    CHECK(v6.destination_interface == 303);
    CHECK(v6.nbl == &packet && v6.completion == InjectionComplete && v6.context == &packet);
    HvWfpStop();
    CHECK(HvWfpInject(&packet, FALSE, 0, 71, 0, 0, FALSE, InjectionComplete, &packet) == STATUS_DELETE_PENDING);
    CHECK(StopAndVerifyClean());
    return true;
}


ULONG HeaderSum(const UCHAR* bytes, unsigned length) {
    ULONG sum = 0;
    for (unsigned i = 0; i < length; i += 2)
        sum += (static_cast<ULONG>(bytes[i]) << 8) | bytes[i + 1];
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}
bool TestPendingCloneNeedsSoftwareTransportChecksumWithoutReceiveOffload() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    // An ordinary outbound TCP packet with a partial pseudo-header checksum.
    // The pending clone has neither receive-success nor transmit-offload OOB.
    std::array<UCHAR, 43> bytes{};
    bytes[0] = 0x45; bytes[3] = static_cast<UCHAR>(bytes.size());
    bytes[8] = 63; bytes[9] = 6;
    bytes[12] = 10; bytes[15] = 1; bytes[16] = 8; bytes[17] = 8; bytes[18] = 8; bytes[19] = 8;
    bytes[20] = 0x12; bytes[21] = 0x34; bytes[22] = 1; bytes[23] = 0xbb;
    bytes[32] = 0x50; bytes[33] = 2; bytes[36] = 0x12; bytes[37] = 0x34;
    bytes[40] = 1; bytes[41] = 2; bytes[42] = 3;
    MDL mdl{nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), TRUE};
    NET_BUFFER nb{nullptr, &mdl, 0, static_cast<ULONG>(bytes.size())};
    _NET_BUFFER_LIST packet{&nb, nullptr};
    CHECK(NT_SUCCESS(HvWfpInject(&packet, FALSE, 37, 71, 0, 0, FALSE, InjectionComplete, &packet)));
    CHECK(HeaderSum(bytes.data(), 20) == 0xffffu);
    ULONG sum = HeaderSum(bytes.data() + 12, 8) + 6 + 23;
    for (unsigned i = 20; i != 42; i += 2)
        sum += (static_cast<ULONG>(bytes[i]) << 8) | bytes[i + 1];
    sum += static_cast<ULONG>(bytes[42]) << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    CHECK(sum == 0xffffu);
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestWeakHostInjectionUsesNetworkHandlesAndOriginalRoute() {
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        for (ULONG flags : {0u, FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU,
                 FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
                 FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU | FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU}) {
            hv_wfp_fake::Reset();
            _DRIVER_OBJECT driver{};
            CHECK(Start(&driver));
            InjectionPacket fixture(ipv6);
            auto& packet = fixture.Packet;
            ULONG route = (flags & FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU) ? 1u :
                (flags & FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU) ? 2u : 0u;
            CHECK(NT_SUCCESS(HvWfpInject(&packet, ipv6, 37, 71, 19, flags, FALSE, InjectionComplete, &packet)));
            const auto& call = hv_wfp_fake::state().injection_calls.back();
            CHECK(call.route == route && call.family == (ipv6 ? AF_INET6 : AF_INET));
            CHECK(call.compartment == 37 && call.nbl == &packet && call.context == &packet);
            CHECK(call.completion == InjectionComplete);
            CHECK(call.destination_interface == (route == 2 ? 0u : 71u));
            CHECK(call.sub_interface == (route == 1 ? 19u : 0u));
            auto* handle = static_cast<hv_wfp_fake::FakeInjection*>(call.handle);
            CHECK(handle->type == (route == 0 ? FWPS_INJECTION_TYPE_FORWARD : FWPS_INJECTION_TYPE_NETWORK));
            auto point = route == 1 ? hv_wfp_fake::FailurePoint::injection_receive :
                route == 2 ? hv_wfp_fake::FailurePoint::injection_send : hv_wfp_fake::FailurePoint::injection_forward;
            hv_wfp_fake::FailNext(point);
            CHECK(HvWfpInject(&packet, ipv6, 37, 71, 19, flags, FALSE, InjectionComplete, &packet) == STATUS_UNSUCCESSFUL);
            hv_wfp_fake::SetInjectionState(&packet, ipv6 ? AF_INET6 : AF_INET,
                FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF, handle->type);
            CHECK(HvWfpIsSelfInjected(&packet, ipv6));
            CHECK(!HvWfpIsSelfInjected(&packet, !ipv6));
            HvWfpStop();
            CHECK(HvWfpInject(&packet, ipv6, 37, 71, 19, flags, FALSE, InjectionComplete, &packet) == STATUS_DELETE_PENDING);
            CHECK(StopAndVerifyClean());
        }
    }
    return true;
}
bool TestEveryInjectionHandleFailureCanRetryAndUnwind() {
    for (unsigned successful = 0; successful != 4; ++successful) {
        hv_wfp_fake::Reset();
        hv_wfp_fake::FailAfter(hv_wfp_fake::FailurePoint::injection_create, successful);
        _DRIVER_OBJECT driver{};
        CHECK(Start(&driver));
        CHECK(!HvWfpTestState().Healthy && hv_wfp_fake::state().active_filters.empty());
        CHECK(hv_wfp_fake::state().live_injections == successful);
        hv_wfp_fake::FireTimers();
        hv_wfp_fake::DrainWork();
        CHECK(HvWfpTestState().Healthy && hv_wfp_fake::state().live_injections == 4 && HasGlobalFilters());
        CHECK(StopAndVerifyClean());
    }
    return true;
}
bool TestInjectionFailureLogIsBoundedAndSessionResettable() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    g_injection_errors.clear();
    for (unsigned i = 1; i <= 17; ++i)
        HvWfpReportInjectionFailure(STATUS_DATA_ERROR, TRUE, FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU, 71, TRUE);
    CHECK(g_injection_errors.size() == 5);
    for (unsigned i = 0; i != g_injection_errors.size(); ++i) {
        const auto& error = g_injection_errors[i];
        CHECK(error.status == static_cast<ULONG>(STATUS_DATA_ERROR));
        CHECK(error.ipv6 == 1 && error.route == 1 && error.completion == 1 && error.destination == 71);
        CHECK(error.failures == (1u << i));
    }
    HvWfpReportStatus();
    HvWfpReportInjectionFailure(STATUS_UNSUCCESSFUL, FALSE, FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU, 7, FALSE);
    CHECK(g_injection_errors.size() == 6);
    const auto& error = g_injection_errors.back();
    CHECK(error.failures == 1 && error.ipv6 == 0 && error.route == 2 && error.completion == 0);
    CHECK(StopAndVerifyClean());
    return true;
}

} // namespace

int main() {
    if (!TestGlobalRegistrationWithoutAnyNdisModules()) return 1;
    if (!TestPrivateInitializationFailuresUnwind()) return 1;
    if (!TestSubscribeCallbackDefersReconcileUntilReady()) return 1;
    if (!TestBfePausedStartAndStop()) return 1;
    if (!TestBfeStopStartBurstReplacesSession()) return 1;
    if (!TestRegistrationFailuresRetryWithoutNdisAttachments()) return 1;
    if (!TestPartialFamilyTransactionsAreNeverPublished()) return 1;
    if (!TestCloseFailurePreservesThenRebuildsAndUnloads()) return 1;
    if (!TestWorkHandoffDoesNotLoseRequest()) return 1;
    if (!TestStopUnsubscribesAndDrainsBeforeDestruction()) return 1;
    if (!TestStopResolvesPendingBeforeWaitingForPacketRundown()) return 1;
    if (!TestInjectionWrapperPreservesArgumentsAndFailure()) return 1;
    if (!TestPendingCloneNeedsSoftwareTransportChecksumWithoutReceiveOffload()) return 1;
    if (!TestCompleteSoftwareChecksumsAcrossEveryMdlBoundary()) return 1;
    if (!TestChecksumFailuresPreventEveryInjectionRoute()) return 1;
    if (!TestFragmentsAndSegmentationDoNotInventTransportChecksums()) return 1;
    if (!TestRoutingAndAtomicFragmentPseudoHeaders()) return 1;
    if (!TestMultipleBuffersOddLargePacketsAndUdpZeroChecksum()) return 1;
    if (!TestRangeReadWorkAndFailureBoundaries()) return 1;
    if (!TestWordChecksumAgainstIndependentByteReference()) return 1;
    if (!TestScatteredChecksumsIdempotenceAndRetainedOffloads()) return 1;
    if (!TestWeakHostInjectionUsesNetworkHandlesAndOriginalRoute()) return 1;
    if (!TestEveryInjectionHandleFailureCanRetryAndUnwind()) return 1;
    if (!TestInjectionFailureLogIsBoundedAndSessionResettable()) return 1;
    if (!TestRustClassifyRightsValidationAndSelfInjection()) return 1;
    if (!TestRustClassifySynchronousDecisionsAndMetadata()) return 1;
    if (!TestRustClassifyAllocationFailuresAndChains()) return 1;
    if (!TestRustPendingFragmentOwnershipAndOffloadSnapshot()) return 1;
    if (!TestRustEarlyVerdictAndInlineInjectionCompletion()) return 1;
    if (!TestRustPendingInjectionFailureAndCompletionFailure()) return 1;
    if (!TestRustStopDrainsActualPendingPacket()) return 1;
    if (!TestRustLargeChecksumSpans()) return 1;
    std::puts("PASS global WFP filters without NDIS attachments, BFE retries, teardown and injection");
    return 0;
}
