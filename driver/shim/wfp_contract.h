// Portable packet ownership and classify-publication contract.
#ifndef HYPERV_XNDIS_FILTER_WFP_CONTRACT_H
#define HYPERV_XNDIS_FILTER_WFP_CONTRACT_H

// Global forwarding observes the source interface, without guessing a guest side.
#define HV_FORWARD_SOURCE_DIRECTION 0u

typedef enum _HV_PACKET_OWNER {
    HvOwnerNdis,
    HvOwnerWfpClone,
    HvOwnerWfpReassembled
} HV_PACKET_OWNER;

// Header-only predicate for the opt-in IPv4 fragment-permit diagnostic build.
static inline bool HvForwardDiagnosticIpv4Fragment(const unsigned char* ip,
    unsigned int length, bool grouped) {
    if (grouped || ip == nullptr || length < 20 || ip[0] >> 4 != 4) return false;
    unsigned int header = (ip[0] & 15u) * 4u;
    unsigned int total = ((unsigned int)ip[2] << 8) | ip[3];
    return header >= 20 && header <= total && total <= length &&
        ((((unsigned int)ip[6] << 8) | ip[7]) & 0x3fffu) != 0;
}

// A negative result publishes the actual NBL to pending policy ownership. It may
// already be completed before classify returns; never inspect or finish it here.
template <typename Packet, typename Finish>
static inline void HvFinishClassifyPacket(Packet packet, int result, Finish finish) {
    if (result >= 0) finish(packet, (unsigned int)result);
}

#endif
