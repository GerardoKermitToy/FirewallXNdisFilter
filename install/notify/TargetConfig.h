#pragma once
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <cguid.h>
#include <iphlpapi.h>
#include <netioapi.h>

namespace firewallx_ndis_filter {
inline constexpr wchar_t kConfigKey[] = L"SOFTWARE\\FirewallXNdisFilter\\Lwf";
// Version 4 deliberately cannot be confused with the older ICS allowlist.
// While armed, the standard Ethernet LWF may bind newly enabled paths too.
inline constexpr DWORD kBindingConfigVersion = 4;

enum class AdapterEligibility { Compatible, Unsupported, Unavailable };

struct AdapterQuery {
    decltype(&ConvertInterfaceGuidToLuid) guid_to_luid = ConvertInterfaceGuidToLuid;
    decltype(&ConvertInterfaceLuidToGuid) luid_to_guid = ConvertInterfaceLuidToGuid;
    decltype(&GetIfEntry2) get_if_entry = GetIfEntry2;
};

// NETIO can report Native 802.11 for a Wi-Fi adapter whose LWF binding has
// an Ethernet miniport below the media converter. Preserve those existing
// paths; FilterAttach independently admits only NdisMedium802_3.
inline AdapterEligibility QueryAdapter(const GUID& guid, NET_LUID& output, const AdapterQuery& api = {}) {
    NET_LUID luid{};
    GUID round_trip{};
    if (guid == GUID_NULL || api.guid_to_luid(&guid, &luid) != NO_ERROR || !luid.Value ||
        api.luid_to_guid(&luid, &round_trip) != NO_ERROR || round_trip != guid) {
        return AdapterEligibility::Unavailable;
    }
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = luid;
    if (api.get_if_entry(&row) != NO_ERROR || row.InterfaceGuid != guid || row.InterfaceLuid.Value != luid.Value) {
        return AdapterEligibility::Unavailable;
    }
    if (row.MediaType != NdisMedium802_3 && row.MediaType != NdisMediumNative802_11) {
        return AdapterEligibility::Unsupported;
    }
    output = luid;
    return AdapterEligibility::Compatible;
}

struct TargetConfig {
    bool armed = false;

    static bool IsCurrentAdapter(const GUID& guid) {
        NET_LUID luid{};
        return QueryAdapter(guid, luid) == AdapterEligibility::Compatible;
    }
};

using TargetConfigReader = LSTATUS (*)(const wchar_t*, DWORD, void*, DWORD*);
inline LSTATUS QueryTargetConfig(const wchar_t* name, DWORD flags, void* data, DWORD* size) {
    return RegGetValueW(HKEY_LOCAL_MACHINE, kConfigKey, name, flags | RRF_SUBKEY_WOW6464KEY,
        nullptr, data, size);
}

inline LSTATUS ReadTargetConfig(TargetConfig& output, bool require_armed,
                               TargetConfigReader read = QueryTargetConfig) {
    DWORD version = 0, allowed = 0, size = sizeof(DWORD);
    LSTATUS result = read(L"ConfigVersion", RRF_RT_REG_DWORD, &version, &size);
    if (result != ERROR_SUCCESS) return result;
    if (size != sizeof(DWORD) || version != kBindingConfigVersion) return ERROR_INVALID_DATA;
    size = sizeof(DWORD);
    result = read(L"AllowBindings", RRF_RT_REG_DWORD, &allowed, &size);
    if (result != ERROR_SUCCESS) return result;
    if (size != sizeof(DWORD) || allowed > 1 || (require_armed && allowed != 1)) return ERROR_INVALID_DATA;
    output.armed = allowed == 1;
    return ERROR_SUCCESS;
}
}
