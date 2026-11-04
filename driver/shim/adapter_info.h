// Bounded diagnostic IOCTL codec, shared with offline tests. Never copy native
// structure layout to userspace; every integer and UTF-16 code unit is LE.
#ifndef HYPERV_XNDIS_FILTER_ADAPTER_INFO_H
#define HYPERV_XNDIS_FILTER_ADAPTER_INFO_H

#include <stdint.h>

#define HV_ADAPTER_INFO_VERSION 1u
#define HV_ADAPTER_INFO_HEADER_SIZE 16u
#define HV_ADAPTER_INFO_ENTRY_SIZE 1760u
// Arithmetic wire/DWORD-size bound only, not an attachment/admission quota.
#define HV_ADAPTER_INFO_MAX_ADAPTERS ((UINT32_MAX - HV_ADAPTER_INFO_HEADER_SIZE) / HV_ADAPTER_INFO_ENTRY_SIZE)
#define HV_ADAPTER_INFO_NAME_CAPACITY 256u
#define HV_ADAPTER_INFO_MAC_CAPACITY 32u
#define HV_ADAPTER_INFO_MAX_SIZE (HV_ADAPTER_INFO_HEADER_SIZE + \
    HV_ADAPTER_INFO_MAX_ADAPTERS * HV_ADAPTER_INFO_ENTRY_SIZE)
#define HV_ADAPTER_INFO_MAX_STAGING_ATTEMPTS 8u

#define HV_ADAPTER_RUNNING 0x01u
#define HV_ADAPTER_GENERAL_VALID 0x02u
#define HV_ADAPTER_CONNECTOR_VALID 0x04u
#define HV_ADAPTER_INSTANCE_NAME_TRUNCATED 0x08u
#define HV_ADAPTER_BASE_NAME_TRUNCATED 0x10u
#define HV_ADAPTER_FILTER_NAME_TRUNCATED 0x20u
#define HV_ADAPTER_LINK_STATE_VALID 0x40u
#define HV_ADAPTER_PAUSE_VALID 0x80u
#define HV_ADAPTER_INFO_KNOWN_FLAGS 0xffu

// Storage only, not a wire structure. GUID bytes use Windows GUID field order:
// Data1:u32 LE, Data2:u16 LE, Data3:u16 LE, Data4:8 bytes.
typedef struct _HV_ADAPTER_INFO {
    uint64_t ModuleId;
    uint32_t InterfaceIndex, FilterInterfaceIndex, LowerInterfaceIndex, Flags;
    uint64_t InterfaceLuid, FilterInterfaceLuid, LowerInterfaceLuid;
    uint8_t InterfaceGuid[16];
    uint32_t MediaType, PhysicalMedium, MediaConnectState, MediaDuplexState;
    uint64_t XmitLinkSpeed, RcvLinkSpeed;
    uint32_t Mtu, MacOptions, SupportedPacketFilters, MaxMulticastListSize;
    uint64_t MaxXmitLinkSpeed, MaxRcvLinkSpeed;
    uint32_t LookaheadSize, AccessType, ConnectionType, SupportedStatistics;
    uint32_t DataBackFillSize, ContextBackFillSize, RestartFlags, AttachFlags;
    uint32_t ConnectorPresent, MacAddressLength;
    uint8_t MacAddress[HV_ADAPTER_INFO_MAC_CAPACITY];
    uint32_t InstanceNameLength, BaseNameLength, FilterModuleNameLength;
    uint32_t AutoNegotiationFlags, PauseReason, PauseFlags;
    uint16_t InstanceName[HV_ADAPTER_INFO_NAME_CAPACITY];
    uint16_t BaseName[HV_ADAPTER_INFO_NAME_CAPACITY];
    uint16_t FilterModuleName[HV_ADAPTER_INFO_NAME_CAPACITY];
} HV_ADAPTER_INFO;

// Portable behavior is implemented in production Rust, also linked by offline
// fixture tests. This structure is an internal ABI, never a wire memcpy.
#ifdef __cplusplus
#include <stddef.h>
static_assert(sizeof(HV_ADAPTER_INFO) == 1760 && alignof(HV_ADAPTER_INFO) == 8);
static_assert(offsetof(HV_ADAPTER_INFO, InterfaceGuid) == 48);
static_assert(offsetof(HV_ADAPTER_INFO, MacAddress) == 168);
static_assert(offsetof(HV_ADAPTER_INFO, InstanceName) == 224);
static_assert(offsetof(HV_ADAPTER_INFO, BaseName) == 736);
static_assert(offsetof(HV_ADAPTER_INFO, FilterModuleName) == 1248);
extern "C" {
#endif
typedef enum _HV_ADAPTER_INFO_ACTION {
    HvAdapterInfoTooSmall,
    HvAdapterInfoCountOverflow,
    HvAdapterInfoHeaderOnly,
    HvAdapterInfoGrowStaging,
    HvAdapterInfoEncode
} HV_ADAPTER_INFO_ACTION;
void HvClearGeneralAttributes(HV_ADAPTER_INFO* info);
uint32_t HvCopyAdapterName(uint16_t* out, const uint16_t* source, uint32_t length,
    uint32_t* flags, uint32_t truncatedFlag);
void HvInfoWrite32(uint8_t* out, uint32_t value);
void HvInfoWrite64(uint8_t* out, uint64_t value);
uint32_t HvAdapterInfoSize(uint32_t count);
HV_ADAPTER_INFO_ACTION HvPlanAdapterInfo(uint64_t count, uint32_t capacity,
    uint64_t stagedCount, uint32_t* required);
void HvEncodeAdapterInfoHeader(uint8_t* out, uint32_t count, uint32_t running);
void HvEncodeAdapterInfo(uint8_t* out, const HV_ADAPTER_INFO* info);
#ifdef __cplusplus
}
#endif
#endif
