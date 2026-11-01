#pragma once
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cstdint>
#include <new>
#include <utility>
#include <vector>
#include "../../driver/shim/target_config.h"

namespace hyperv_xndis_filter {
inline constexpr wchar_t kConfigKey[] = L"SOFTWARE\\HyperVXNdisFilter\\Lwf";

// REG_BINARY: count:u32 LE, then Windows GUID bytes + NET_LUID:u64 LE.
// One atomic value prevents readers from observing half of a target pair/list.
struct TargetConfig {
    std::vector<unsigned char> data;

    bool Matches(const GUID& guid, uint64_t luid) const {
        return data.size() <= MAXDWORD && HvTargetsMatch(data.data(), static_cast<DWORD>(data.size()),
            reinterpret_cast<const unsigned char*>(&guid), luid) != 0;
    }
    bool MatchesCurrentAdapter(const GUID& guid) const {
        NET_LUID luid{};
        GUID round_trip{};
        return ConvertInterfaceGuidToLuid(&guid, &luid) == NO_ERROR &&
            ConvertInterfaceLuidToGuid(&luid, &round_trip) == NO_ERROR && round_trip == guid && Matches(guid, luid.Value);
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
    if (size != sizeof(DWORD) || version != HV_TARGET_CONFIG_VERSION) return ERROR_INVALID_DATA;
    size = sizeof(DWORD);
    result = read(L"AllowBindings", RRF_RT_REG_DWORD, &allowed, &size);
    if (result != ERROR_SUCCESS) return result;
    if (size != sizeof(DWORD) || allowed > 1 || (require_armed && allowed != 1)) return ERROR_INVALID_DATA;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        DWORD needed = 0;
        result = read(L"TargetAdapters", RRF_RT_REG_BINARY, nullptr, &needed);
        if (result != ERROR_SUCCESS) return result;
        if (needed < 4 || (needed - 4) % HV_TARGET_ENTRY_SIZE != 0) return ERROR_INVALID_DATA;
        TargetConfig config;
        try { config.data.resize(needed); }
        catch (const std::bad_alloc&) { return ERROR_NOT_ENOUGH_MEMORY; }
        size = needed;
        result = read(L"TargetAdapters", RRF_RT_REG_BINARY, config.data.data(), &size);
        if (result == ERROR_MORE_DATA) continue;
        if (result != ERROR_SUCCESS) return result;
        if (size > needed || !HvTargetsValid(config.data.data(), size)) return ERROR_INVALID_DATA;
        config.data.resize(size);
        output = std::move(config);
        return ERROR_SUCCESS;
    }
    return ERROR_RETRY;
}
}
