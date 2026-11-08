#pragma once
#include <windows.h>
#include <cstdio>

namespace firewallx_ndis_filter {

// Opt-in setup diagnostics only; never writes to a file or changes bindings.
inline void TraceNetCfg(const char* operation, HRESULT result, DWORD flags = 0) noexcept {
    wchar_t enabled[2]{};
    if (GetEnvironmentVariableW(L"FIREWALLXNDISFILTER_NETCFG_TRACE", enabled, 2) != 1 || enabled[0] != L'1') return;
    char text[256]{};
    const int size = _snprintf_s(text, sizeof(text), _TRUNCATE,
                                 "FirewallXNdisFilter NetCfg: %s, result=0x%08lX, flags=0x%08lX\r\n",
                                 operation, static_cast<unsigned long>(result), flags);
    if (size <= 0) return;
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), text, static_cast<DWORD>(size), &written, nullptr);
}

} // namespace firewallx_ndis_filter
