#pragma once
#include "BindingPolicy.h"
#include "NetCfgTrace.h"
#include <cwchar>
#include <string>

namespace firewallx_ndis_filter {

inline std::wstring NotifyClassKey() {
    wchar_t guid[39]{};
    if (!StringFromGUID2(kNotifyClsid, guid, 39)) return {};
    return std::wstring(L"CLSID\\") + guid;
}

// The notify CLSID is shared with previous product names. Never overwrite or
// remove a registration whose server belongs to a different package.
inline HRESULT ReadNotifyOwnership(const std::wstring& key, bool& owned) {
    owned = false;
    const auto server = key + L"\\InprocServer32";
    wchar_t path[MAX_PATH]{};
    DWORD bytes = sizeof(path);
    const LSTATUS status = RegGetValueW(HKEY_CLASSES_ROOT, server.c_str(), nullptr,
                                       RRF_RT_REG_SZ, nullptr, path, &bytes);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return S_OK;
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);
    if (bytes < sizeof(wchar_t) || bytes > sizeof(path) || bytes % sizeof(wchar_t) != 0 ||
        path[bytes / sizeof(wchar_t) - 1] != L'\0' || path[0] == L'\0') return E_UNEXPECTED;
    const std::wstring value(path);
    const auto separator = value.find_last_of(L"\\/");
    const auto* filename = value.c_str() + (separator == std::wstring::npos ? 0 : separator + 1);
    if (_wcsicmp(filename, L"FirewallXNdisFilterNotify.dll") != 0) {
        return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
    }
    owned = true;
    return S_OK;
}

inline HRESULT RegisterNotifyServer(HMODULE module) {
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (length == 0) return HRESULT_FROM_WIN32(GetLastError());
    if (length >= MAX_PATH) return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    const auto key = NotifyClassKey();
    if (key.empty()) return E_UNEXPECTED;
    bool owned = false;
    const HRESULT ownership = ReadNotifyOwnership(key, owned);
    if (FAILED(ownership)) return ownership;
    const auto server = key + L"\\InprocServer32";
    // Use COM's registration root, including NetCfg's redirected classes view.
    // An explicit HKLM path can conflict with the installer's registry transaction.
    const wchar_t description[] = L"FirewallXNdisFilter target-adapter binding policy";
    LSTATUS status = RegSetKeyValueW(HKEY_CLASSES_ROOT, key.c_str(), nullptr, REG_SZ,
                                     description, sizeof(description));
    TraceNetCfg("Register notify class", HRESULT_FROM_WIN32(status));
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);
    status = RegSetKeyValueW(HKEY_CLASSES_ROOT, server.c_str(), nullptr, REG_SZ,
                            path, (length + 1) * sizeof(wchar_t));
    TraceNetCfg("Register notify server", HRESULT_FROM_WIN32(status));
    if (status == ERROR_SUCCESS) {
        const wchar_t threading[] = L"Both";
        status = RegSetKeyValueW(HKEY_CLASSES_ROOT, server.c_str(), L"ThreadingModel", REG_SZ,
                                threading, sizeof(threading));
        TraceNetCfg("Register notify threading model", HRESULT_FROM_WIN32(status));
    }
    if (status != ERROR_SUCCESS && !owned) {
        const LSTATUS cleanup = RegDeleteTreeW(HKEY_CLASSES_ROOT, key.c_str());
        TraceNetCfg("Rollback notify registration", HRESULT_FROM_WIN32(cleanup));
    }
    return HRESULT_FROM_WIN32(status);
}

inline HRESULT UnregisterNotifyServer() {
    const auto key = NotifyClassKey();
    if (key.empty()) return E_UNEXPECTED;
    bool owned = false;
    const HRESULT ownership = ReadNotifyOwnership(key, owned);
    if (FAILED(ownership) || !owned) return ownership;
    const LSTATUS status = RegDeleteTreeW(HKEY_CLASSES_ROOT, key.c_str());
    TraceNetCfg("Unregister notify class", HRESULT_FROM_WIN32(status));
    return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND ? S_OK : HRESULT_FROM_WIN32(status);
}

} // namespace firewallx_ndis_filter
