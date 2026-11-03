// Kernel-only WFP management boundary. Packet policy remains in Rust.
#ifndef HYPERV_XNDIS_FILTER_WFP_FORWARD_H
#define HYPERV_XNDIS_FILTER_WFP_FORWARD_H

#include <fwpsk.h>
#include <fwpmk.h>

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
void NTAPI HvForwardClassify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, void* layerData,
    const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* out);
}

#endif
