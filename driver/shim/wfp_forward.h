// WDK layouts stay here; Rust owns WFP state and packet decisions.
#ifndef HYPERV_XNDIS_FILTER_WFP_FORWARD_H
#define HYPERV_XNDIS_FILTER_WFP_FORWARD_H

#include <stddef.h>

#ifndef HV_WFP_OFFLINE_TEST
#include <fwpsk.h>
#include <fwpmk.h>
#endif

enum HV_WFP_INJECTION_ROUTE : ULONG {
    HvWfpForward, HvWfpNetworkReceive, HvWfpNetworkSend
};

struct HV_FORWARD_VALUES {
    ULONG SourceIndex, DestinationIndex, DestinationSubIndex, Flags, Compartment;
};
struct HV_WFP_PACKET_INFO {
    HV_FORWARD_VALUES Route;
    UCHAR Ipv6, Segmented, Reserved[2];
};
static_assert(sizeof(HV_FORWARD_VALUES) == 20 && alignof(HV_FORWARD_VALUES) == 4);
static_assert(offsetof(HV_FORWARD_VALUES, Compartment) == 16);
static_assert(sizeof(HV_WFP_PACKET_INFO) == 24 && offsetof(HV_WFP_PACKET_INFO, Ipv6) == 20);
static_assert(FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU == 0x80000);
static_assert(FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU == 0x40000);
static_assert(FWP_CONDITION_FLAG_IS_FRAGMENT == 0x20 && FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP == 0x40);
static_assert(FWP_CONDITION_FLAG_IS_REASSEMBLED == 0x400);

extern "C" {
NTSTATUS HvWfpInitialize(PDRIVER_OBJECT driver);
void HvWfpStop(void);
void HvWfpUninitialize(void);
void HvWfpReportStatus(void);
BOOLEAN HvWfpRetainPacket(void);
void HvWfpReleasePacket(void);
BOOLEAN HvWfpIsSelfInjected(PNET_BUFFER_LIST nbl, BOOLEAN ipv6);
NTSTATUS HvWfpInject(PNET_BUFFER_LIST nbl, BOOLEAN ipv6, ULONG compartment,
    ULONG destinationInterface, ULONG destinationSubInterface, ULONG flags, BOOLEAN segmented,
    FWPS_INJECT_COMPLETE0 completion, void* context);
void HvWfpReportInjectionFailure(NTSTATUS status, BOOLEAN ipv6, ULONG flags,
    ULONG destinationInterface, BOOLEAN completion);
void HvWfpRequestReconcile(void);
void HvWfpReconcileWorker(void);
void HvWfpBfeChanged(BOOLEAN reset);
BOOLEAN HvWfpEnterClassify(void);
BOOLEAN HvWfpClassify(PNET_BUFFER_LIST original, const HV_FORWARD_VALUES* route, BOOLEAN ipv6, BOOLEAN valid);
void HvWfpFinish(PNET_BUFFER_LIST nbl, ULONG finish);
void HvWfpInjectionComplete(PNET_BUFFER_LIST nbl, NTSTATUS status);
UINT64 HvWfpChecksumSpan(const UCHAR* bytes, ULONG length, ULONG position, ULONG field);
BOOLEAN ForwardChecksum(PNET_BUFFER nb, ULONG start, ULONG length, ULONG field, ULONG seed, USHORT* checksum);
BOOLEAN RestoreForwardChecksums(PNET_BUFFER_LIST nbl, BOOLEAN ipv6, BOOLEAN segmented);
}

#endif
