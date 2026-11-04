#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>

// Only the scalar slots consumed by the production helper; no WDK ABI crosses
// this offline model. Preserve the SDK's send/receive slot aliases.
using BOOLEAN = unsigned char;
using ULONG = unsigned long;
constexpr BOOLEAN TRUE = 1, FALSE = 0;
enum {
    TcpIpChecksumNetBufferListInfo,
    TcpLargeSendNetBufferListInfo,
    TcpReceiveNoPush = TcpLargeSendNetBufferListInfo,
    Ieee8021QNetBufferListInfo,
    NetBufferListFrameType,
    NetBufferListHashValue,
    NetBufferListHashInfo,
    TcpReceiveBytesTransferred,
    UdpRecvSegCoalesceOffloadInfo = TcpReceiveBytesTransferred,
    TcpRecvSegCoalesceInfo,
    UdpSegmentationOffloadInfo = TcpRecvSegCoalesceInfo,
    MediaSpecificInformation,
    WfpNetBufferListInfo,
    RscTcpTimestampDelta,
    GftOffloadInformation,
    GftFlowEntryId,
    NetBufferListInfoReserved3,
    MaxNetBufferListInfo
};
struct NET_BUFFER_LIST { std::array<void*, MaxNetBufferListInfo> Info{}; };
using PNET_BUFFER_LIST = NET_BUFFER_LIST*;
#define NET_BUFFER_LIST_INFO(nbl, slot) ((nbl)->Info[slot])
#define NET_BUFFER_LIST_IS_URO_SET(nbl) \
    ((reinterpret_cast<std::uintptr_t>((nbl)->Info[UdpRecvSegCoalesceOffloadInfo]) & 0xffffffffu) != 0)
#define NET_BUFFER_LIST_IS_USO_SET(nbl) \
    ((reinterpret_cast<std::uintptr_t>((nbl)->Info[UdpSegmentationOffloadInfo]) & 0xffffffffu) != 0)
#include "../../driver/shim/nbl_offload.h"

using UCHAR = unsigned char;
using UINT = unsigned int;
struct NDIS_OBJECT_HEADER { UCHAR Type, Revision; unsigned short Size; };
struct NDIS_FILTER_DRIVER_CHARACTERISTICS {
    NDIS_OBJECT_HEADER Header{};
    UCHAR MajorNdisVersion = 0, MinorNdisVersion = 0;
};
constexpr UCHAR NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS = 0x8b;
constexpr UCHAR NDIS_FILTER_CHARACTERISTICS_REVISION_2 = 2, NDIS_FILTER_CHARACTERISTICS_REVISION_3 = 3;
// Distinct fake sizes verify selection; these are not native layouts.
constexpr unsigned short NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2 = 64;
constexpr unsigned short NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_3 = 80;
constexpr UINT NDIS_RUNTIME_VERSION_640 = (6u << 16) | 40u;
constexpr UINT NDIS_RUNTIME_VERSION_650 = (6u << 16) | 50u;
constexpr UINT NDIS_RUNTIME_VERSION_651 = (6u << 16) | 51u;
constexpr UINT NDIS_RUNTIME_VERSION_660 = (6u << 16) | 60u;
constexpr UINT NDIS_RUNTIME_VERSION_670 = (6u << 16) | 70u;
constexpr UINT NDIS_RUNTIME_VERSION_680 = (6u << 16) | 80u;
constexpr UINT NDIS_RUNTIME_VERSION_681 = (6u << 16) | 81u;
constexpr UINT NDIS_RUNTIME_VERSION_682 = (6u << 16) | 82u;
constexpr UINT NDIS_RUNTIME_VERSION_683 = (6u << 16) | 83u;
constexpr UINT NDIS_RUNTIME_VERSION_684 = (6u << 16) | 84u;
constexpr UINT NDIS_RUNTIME_VERSION_685 = (6u << 16) | 85u;
constexpr UINT NDIS_RUNTIME_VERSION_686 = (6u << 16) | 86u;
constexpr UINT NDIS_RUNTIME_VERSION_687 = (6u << 16) | 87u;
constexpr UINT NDIS_RUNTIME_VERSION_688 = (6u << 16) | 88u;
constexpr UINT NDIS_RUNTIME_VERSION_689 = (6u << 16) | 89u;
#include "../../driver/shim/ndis_version.h"


#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return false; } } while (false)

namespace {
bool TestEveryRuntimeVersion() {
    for (UINT minor : {40u, 50u, 51u, 60u, 70u, 80u, 81u, 82u, 83u, 84u, 85u, 86u, 87u, 88u, 89u}) {
        const UINT version = (6u << 16) | minor;
        CHECK(HvNdisVersion(version) == version);
        NDIS_FILTER_DRIVER_CHARACTERISTICS c;
        CHECK(HvSetNdisVersion(&c, version));
        CHECK(c.Header.Type == NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS);
        CHECK(c.MajorNdisVersion == 6 && c.MinorNdisVersion == minor);
        CHECK(c.Header.Revision == (minor >= 80 ? 3 : 2));
        CHECK(c.Header.Size == (minor >= 80 ? NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_3 :
                                            NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2));
        const ULONG count = minor >= 80 ? MaxNetBufferListInfo : minor >= 50 ? GftFlowEntryId + 1 : RscTcpTimestampDelta + 1;
        CHECK(HvNblInfoCount(version) == count);
    }
    CHECK(HvNdisVersion((6u << 16) | 39u) == 0);
    CHECK(HvNdisVersion((6u << 16) | 49u) == NDIS_RUNTIME_VERSION_640);
    CHECK(HvNdisVersion((6u << 16) | 79u) == NDIS_RUNTIME_VERSION_670);
    CHECK(HvNdisVersion((6u << 16) | 90u) == NDIS_RUNTIME_VERSION_689);
    CHECK(HvNdisVersion(7u << 16) == NDIS_RUNTIME_VERSION_689);
    NDIS_FILTER_DRIVER_CHARACTERISTICS c;
    CHECK(!HvSetNdisVersion(&c, 0) && c.MajorNdisVersion == 0);
    return true;
}

bool TestSendAndReceiveOffloads() {
    NET_BUFFER_LIST nbl;
    CHECK(!HvNblSendSegmented(&nbl) && !HvNblReceiveCoalesced(&nbl));
    for (auto slot : {TcpLargeSendNetBufferListInfo, UdpSegmentationOffloadInfo}) {
        nbl.Info.fill(nullptr);
        nbl.Info[slot] = reinterpret_cast<void*>(1);
        CHECK(HvNblSendSegmented(&nbl));
    }
    for (auto slot : {TcpRecvSegCoalesceInfo, UdpRecvSegCoalesceOffloadInfo}) {
        nbl.Info.fill(nullptr);
        nbl.Info[slot] = reinterpret_cast<void*>(1);
        CHECK(HvNblReceiveCoalesced(&nbl));
    }
    nbl.Info.fill(nullptr);
    nbl.Info[UdpRecvSegCoalesceOffloadInfo] = reinterpret_cast<void*>(std::uintptr_t{1} << 32);
    CHECK(!HvNblReceiveCoalesced(&nbl)); // Unused upper x64 bits are not URO.
    return true;
}

bool TestUroResourcesMetadata() {
    for (std::uint16_t count : {std::uint16_t{1}, std::uint16_t{4}, std::numeric_limits<std::uint16_t>::max()}) {
        for (std::uint16_t size : {std::uint16_t{1}, std::uint16_t{1200}, std::numeric_limits<std::uint16_t>::max()}) {
            NET_BUFFER_LIST original, copy;
            const auto value = std::uintptr_t{count} | (std::uintptr_t{size} << 16);
            original.Info[UdpRecvSegCoalesceOffloadInfo] = reinterpret_cast<void*>(value);
            original.Info[TcpIpChecksumNetBufferListInfo] = reinterpret_cast<void*>(0x30);
            const auto raw = original.Info;
            CHECK(HvCopyReceiveMetadataSupported(&original, MaxNetBufferListInfo));
            HvCopyReceiveUroInfo(&copy, &original);
            CHECK(HvNblReceiveCoalesced(&copy));
            CHECK(copy.Info[UdpRecvSegCoalesceOffloadInfo] == reinterpret_cast<void*>(value));
            CHECK(original.Info == raw);
            // Copy metadata has independent storage, not a pointer to the source.
            original.Info[UdpRecvSegCoalesceOffloadInfo] = nullptr;
            CHECK(copy.Info[UdpRecvSegCoalesceOffloadInfo] == reinterpret_cast<void*>(value));
            HvCopyReceiveUroInfo(&copy, &original);
            CHECK(!HvNblReceiveCoalesced(&copy));
        }
    }
    return true;
}

bool TestUnknownMetadataStillRejected() {
    NET_BUFFER_LIST nbl;
    CHECK(HvCopyReceiveMetadataSupported(&nbl, MaxNetBufferListInfo));
    for (ULONG slot = 0; slot < MaxNetBufferListInfo; ++slot) {
        nbl.Info.fill(nullptr);
        nbl.Info[slot] = reinterpret_cast<void*>(1);
        const bool supported = slot == TcpIpChecksumNetBufferListInfo || slot == TcpReceiveNoPush ||
            slot == Ieee8021QNetBufferListInfo || slot == NetBufferListFrameType ||
            slot == NetBufferListHashValue || slot == NetBufferListHashInfo ||
            slot == UdpRecvSegCoalesceOffloadInfo;
        CHECK((HvCopyReceiveMetadataSupported(&nbl, MaxNetBufferListInfo) != FALSE) == supported);
    }
    return true;
}
} // namespace

int main() {
    if (!TestEveryRuntimeVersion() || !TestSendAndReceiveOffloads() || !TestUroResourcesMetadata() || !TestUnknownMetadataStillRejected()) return 1;
    std::puts("PASS: every NDIS 6.40-6.89 registration/OOB bound, URO/USO detection, scalar URO resource-copy preservation, unknown OOB rejection");
    return 0;
}
