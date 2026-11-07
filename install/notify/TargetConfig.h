#pragma once
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <cguid.h>
#include <iphlpapi.h>
#include <netioapi.h>

namespace hyperv_xndis_filter {
inline constexpr wchar_t kConfigKey[] = L"SOFTWARE\\HyperVXNdisFilter\\Lwf";
// Version 4 deliberately cannot be confused with the older ICS allowlist.
// While armed, the standard Ethernet LWF may bind newly enabled paths too.
inline constexpr DWORD kBindingConfigVersion = 4;

struct TargetConfig {
    bool armed = false;

    static bool IsCurrentAdapter(const GUID& guid) {
        NET_LUID luid{};
        GUID round_trip{};
        return guid != GUID_NULL && ConvertInterfaceGuidToLuid(&guid, &luid) == NO_ERROR && luid.Value != 0 &&
            ConvertInterfaceLuidToGuid(&luid, &round_trip) == NO_ERROR && round_trip == guid;
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
