#ifndef HYPERV_XNDIS_FILTER_NBL_CONTEXT_H
#define HYPERV_XNDIS_FILTER_NBL_CONTEXT_H

#include "wfp_contract.h"

struct _HV_ADAPTER;
// NDIS guarantees only sizeof(void*) alignment for context data, including when
// reusing another driver's backfill. Do not require pool/SIMD alignment here.
typedef struct _HV_NBL_CONTEXT {
    _HV_ADAPTER* Adapter;
    ULONG Signature, Flags, Direction, ForwardInterface, ForwardSubInterface, Compartment;
    NDIS_PORT_NUMBER Port;
    HV_PACKET_OWNER Owner;
    BOOLEAN Copied, Forwarded, Ipv6, Segmented;
} HV_NBL_CONTEXT;
static_assert(alignof(HV_NBL_CONTEXT) <= alignof(void*));
static_assert(sizeof(HV_NBL_CONTEXT) % sizeof(void*) == 0);
static_assert(sizeof(HV_NBL_CONTEXT) <= 0xffffu);
#define NBL_CONTEXT_TAG 'nVHH'

extern "C" __declspec(noreturn) void hv_bugcheck(void);

static inline HV_NBL_CONTEXT* PacketContext(PNET_BUFFER_LIST nbl) {
    if (nbl->Context == NULL) hv_bugcheck();
    auto* context = reinterpret_cast<HV_NBL_CONTEXT*>(NET_BUFFER_LIST_CONTEXT_DATA_START(nbl));
    if (context->Signature != NBL_CONTEXT_TAG) hv_bugcheck();
    return context;
}
static inline HV_NBL_CONTEXT* AllocatePacketContext(PNET_BUFFER_LIST nbl) {
    if (NdisAllocateNetBufferListContext(nbl, (USHORT)sizeof(HV_NBL_CONTEXT), 0, NBL_CONTEXT_TAG) != NDIS_STATUS_SUCCESS)
        return NULL;
    auto* context = reinterpret_cast<HV_NBL_CONTEXT*>(NET_BUFFER_LIST_CONTEXT_DATA_START(nbl));
    RtlZeroMemory(context, sizeof(*context));
    context->Signature = NBL_CONTEXT_TAG;
    return context;
}
static inline void FreePacketContext(PNET_BUFFER_LIST nbl) {
    NdisFreeNetBufferListContext(nbl, (USHORT)sizeof(HV_NBL_CONTEXT));
}

#endif
