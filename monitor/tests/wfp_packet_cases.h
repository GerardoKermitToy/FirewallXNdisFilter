// Included by wfp_management_tests.cpp. All calls reach the production Rust module.
constexpr int PolicyAllow = 0, PolicyDrop = 1, PolicyPending = -1;
constexpr ULONG FinishAllow = 0, FinishDrop = 1;
struct ForwardInput {
    FWPS_INCOMING_VALUE0 Fields[4]{};
    FWPS_INCOMING_VALUES0 Values{};
    FWPS_INCOMING_METADATA_VALUES0 Metadata{};
    explicit ForwardInput(BOOLEAN ipv6 = FALSE, ULONG flags = 0) {
        Values.layerId = ipv6 ? FWPS_LAYER_IPFORWARD_V6 : FWPS_LAYER_IPFORWARD_V4;
        Values.valueCount = RTL_NUMBER_OF(Fields);
        Values.incomingValue = Fields;
        for (auto& field : Fields) field.value.type = FWP_UINT32;
        Fields[FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX].value.uint32 = 71;
        Fields[FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX].value.uint32 = 303;
        Fields[FWPS_FIELD_IPFORWARD_V4_DESTINATION_SUB_INTERFACE_INDEX].value.uint32 = 19;
        Fields[FWPS_FIELD_IPFORWARD_V4_FLAGS].value.uint32 = flags;
        Metadata.currentMetadataValues = FWPS_METADATA_FIELD_COMPARTMENT_ID;
        Metadata.compartmentId = 37;
    }
    FWPS_CLASSIFY_OUT0 Run(PNET_BUFFER_LIST packet) {
        FWPS_CLASSIFY_OUT0 out{};
        out.rights = FWPS_RIGHT_ACTION_WRITE;
        Classify(&Values, &Metadata, packet, nullptr, 0, &out);
        return out;
    }
};
void ResetPolicy() {
    PolicyResult = PolicyDrop;
    DriverStopping = FALSE;
    SessionAvailable = TRUE;
    ResourceDrops = 0;
    PendingPacket = nullptr;
    PolicyHook = nullptr;
    PolicyObservation = {};
}
bool Blocked(const FWPS_CLASSIFY_OUT0& out) {
    return out.actionType == FWP_ACTION_BLOCK && (out.flags & FWPS_CLASSIFY_OUT_FLAG_ABSORB) != 0 &&
        (out.rights & FWPS_RIGHT_ACTION_WRITE) == 0;
}
bool TestRustClassifyRightsValidationAndSelfInjection() {
    hv_wfp_fake::Reset();
    ResetPolicy();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    InjectionPacket packet;
    ForwardInput input;
    FWPS_CLASSIFY_OUT0 unchanged{};
    constexpr ULONG UnrelatedRight = 0x100, UnrelatedFlag = 0x200;
    unchanged.rights = UnrelatedRight;
    unchanged.flags = UnrelatedFlag;
    unchanged.actionType = FWP_ACTION_CALLOUT_TERMINATING;
    const auto calls = g_forward_calls;
    Classify(&input.Values, &input.Metadata, &packet.Packet, nullptr, 0, &unchanged);
    CHECK(unchanged.rights == UnrelatedRight && unchanged.flags == UnrelatedFlag);
    CHECK(unchanged.actionType == FWP_ACTION_CALLOUT_TERMINATING && g_forward_calls == calls);

    input.Fields[FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX].value.type = FWP_EMPTY;
    CHECK(Blocked(input.Run(&packet.Packet)));
    CHECK(ResourceDrops == 1 && hv_wfp_fake::state().clones == 0);
    // Even malformed route metadata must not defeat the self-injection exemption.
    hv_wfp_fake::SetInjectionState(&packet.Packet, AF_INET, FWPS_PACKET_INJECTED_BY_SELF);
    CHECK(input.Run(&packet.Packet).actionType == FWP_ACTION_PERMIT);
    CHECK(ResourceDrops == 1 && g_forward_calls == calls);
    CHECK(StopAndVerifyClean());
    return true;
}
bool TestRustClassifySynchronousDecisionsAndMetadata() {
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        for (int result : {PolicyAllow, PolicyDrop}) {
            hv_wfp_fake::Reset();
            ResetPolicy();
            _DRIVER_OBJECT driver{};
            CHECK(Start(&driver));
            InjectionPacket packet(ipv6);
            ForwardInput input(ipv6);
            PolicyResult = result;
            const auto out = input.Run(&packet.Packet);
            CHECK(result == PolicyAllow ? out.actionType == FWP_ACTION_PERMIT : Blocked(out));
            CHECK(PolicyObservation.InterfaceIndex == 71 && PolicyObservation.Direction == HV_FORWARD_SOURCE_DIRECTION);
            CHECK(PolicyObservation.Family == (ipv6 ? 6u : 4u));
            CHECK(PolicyObservation.Cacheable == 1 && PolicyObservation.Session == 1);
            CHECK(hv_wfp_fake::state().clones == 1 && hv_wfp_fake::state().clone_frees == 1);
            CHECK(hv_wfp_fake::state().injection_calls.empty() && PacketRundown.acquired == 0);
            CHECK(StopAndVerifyClean());
        }
    }
    return true;
}
bool TestRustClassifyAllocationFailuresAndChains() {
    for (auto failure : {hv_wfp_fake::FailurePoint::clone, hv_wfp_fake::FailurePoint::reassemble,
                         hv_wfp_fake::FailurePoint::context_allocate}) {
        hv_wfp_fake::Reset();
        ResetPolicy();
        _DRIVER_OBJECT driver{};
        CHECK(Start(&driver));
        InjectionPacket packet;
        const ULONG flags = failure == hv_wfp_fake::FailurePoint::reassemble ? FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP : 0;
        ForwardInput input(FALSE, flags);
        hv_wfp_fake::FailNext(failure);
        const auto calls = g_forward_calls;
        CHECK(Blocked(input.Run(&packet.Packet)));
        CHECK(ResourceDrops == 1 && g_forward_calls == calls && PacketRundown.acquired == 0);
        CHECK(StopAndVerifyClean());
    }
    hv_wfp_fake::Reset();
    ResetPolicy();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    InjectionPacket packet, second;
    packet.Packet.Next = &second.Packet;
    ForwardInput input;
    CHECK(Blocked(input.Run(&packet.Packet)));
    CHECK(hv_wfp_fake::state().clones == 0 && ResourceDrops == 1);
    CHECK(StopAndVerifyClean());
    return true;
}
bool TestRustPendingFragmentOwnershipAndOffloadSnapshot() {
    for (ULONG flags : {0u, FWP_CONDITION_FLAG_IS_FRAGMENT, FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP,
                        FWP_CONDITION_FLAG_IS_REASSEMBLED}) {
        hv_wfp_fake::Reset();
        ResetPolicy();
        _DRIVER_OBJECT driver{};
        CHECK(Start(&driver));
        InjectionPacket packet;
        packet.Packet.RscInfo = reinterpret_cast<void*>(1);
        ForwardInput input(FALSE, flags);
        PolicyResult = PolicyPending;
        SessionAvailable = FALSE;
        CHECK(Blocked(input.Run(&packet.Packet)));
        CHECK(PolicyObservation.Cacheable == (flags == 0 ? 1u : 0u));
        CHECK(PolicyObservation.Session == 0 && SessionReferences == 0);
        CHECK(PendingPacket != nullptr && PacketRundown.acquired == 1);
        const auto* context = PacketContext(PendingPacket);
        CHECK(context->Segmented && context->ForwardInterface == 303 && context->Compartment == 37);
        CHECK(context->Owner == ((flags & FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP) ? HvOwnerWfpReassembled : HvOwnerWfpClone));
        HvWfpFinish(PendingPacket, FinishDrop);
        PendingPacket = nullptr;
        CHECK(PacketRundown.acquired == 0);
        CHECK(StopAndVerifyClean());
    }
    return true;
}
void AllowInsidePolicy(PNET_BUFFER_LIST packet) { HvWfpFinish(packet, FinishAllow); }
bool TestRustEarlyVerdictAndInlineInjectionCompletion() {
    hv_wfp_fake::Reset();
    ResetPolicy();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    InjectionPacket packet;
    ForwardInput input(FALSE, FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU);
    PolicyResult = PolicyPending;
    PolicyHook = AllowInsidePolicy;
    hv_wfp_fake::state().complete_inline = TRUE;
    CHECK(Blocked(input.Run(&packet.Packet)));
    CHECK(hv_wfp_fake::state().injection_calls.size() == 1);
    const auto& call = hv_wfp_fake::state().injection_calls.back();
    CHECK(call.route == HvWfpNetworkReceive && call.compartment == 37 && call.destination_interface == 303);
    CHECK(call.sub_interface == 19);
    CHECK(hv_wfp_fake::state().clone_frees == 1 && PacketRundown.acquired == 0 && SessionReferences == 0);
    CHECK(StopAndVerifyClean());
    return true;
}
bool TestRustPendingInjectionFailureAndCompletionFailure() {
    for (bool submit_failure : {false, true}) {
        hv_wfp_fake::Reset();
        ResetPolicy();
        _DRIVER_OBJECT driver{};
        CHECK(Start(&driver));
        InjectionPacket packet;
        ForwardInput input;
        PolicyResult = PolicyPending;
        CHECK(Blocked(input.Run(&packet.Packet)));
        g_injection_errors.clear();
        if (submit_failure) hv_wfp_fake::FailNext(hv_wfp_fake::FailurePoint::injection_forward);
        HvWfpFinish(PendingPacket, FinishAllow);
        if (!submit_failure) {
            CHECK(hv_wfp_fake::state().clone_frees == 0 && PacketRundown.acquired == 1);
            const auto call = hv_wfp_fake::state().injection_calls.back();
            call.nbl->Status = STATUS_UNSUCCESSFUL;
            call.completion(call.context, call.nbl, FALSE);
        }
        CHECK(g_injection_errors.size() == 1 && g_injection_errors.back().destination == 303);
        CHECK(g_injection_errors.back().completion == (submit_failure ? 0u : 1u));
        CHECK(hv_wfp_fake::state().clone_frees == 1 && PacketRundown.acquired == 0);
        CHECK(StopAndVerifyClean());
    }
    return true;
}
void DropPendingOnStop() {
    HvWfpFinish(PendingPacket, FinishDrop);
    PendingPacket = nullptr;
    hv_wfp_fake::state().forward_stop_hook = nullptr;
}
bool TestRustStopDrainsActualPendingPacket() {
    hv_wfp_fake::Reset();
    ResetPolicy();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    InjectionPacket packet;
    ForwardInput input;
    PolicyResult = PolicyPending;
    CHECK(Blocked(input.Run(&packet.Packet)));
    hv_wfp_fake::state().forward_stop_hook = DropPendingOnStop;
    CHECK(StopAndVerifyClean());
    CHECK(PendingPacket == nullptr && hv_wfp_fake::state().clone_frees == 1);
    return true;
}
bool TestRustLargeChecksumSpans() {
    constexpr ULONG LogicalPacketSize = 1u << 20;
    std::vector<UCHAR> bytes(LogicalPacketSize);
    for (ULONG i = 0; i < LogicalPacketSize; ++i) bytes[i] = static_cast<UCHAR>(i * 73 + 19);
    for (ULONG start : {0u, 1u}) {
        for (ULONG field : {0u, 65533u, LogicalPacketSize - start - 2}) {
            auto reference = bytes;
            reference[start + field] = reference[start + field + 1] = 0;
            const ULONG length = LogicalPacketSize - start;
            const auto expected = static_cast<USHORT>(~ReferenceSum(reference.data() + start, length));
            for (const auto& chunks : {std::vector<ULONG>{LogicalPacketSize}, std::vector<ULONG>{65535, 65534, 3}}) {
                ScatteredPacket packet(bytes, chunks);
                USHORT checksum = 0;
                CHECK(ForwardChecksum(&packet.Nb, start, length, field, 0, &checksum));
                CHECK(checksum == expected && packet.Matches(bytes));
            }
        }
    }
    return true;
}
