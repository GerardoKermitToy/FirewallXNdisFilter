#include "DriverLoader.h"

#include <cstdio>
#include <cstring>
#include <cwchar>

namespace fake {
bool exists, running;
DWORD start_error, stop_error, delete_error, config_error;
unsigned starts, stops, deletes, scm_handles, files;
std::wstring opened_path;
std::wstring existing_path = L"C:\\drivers\\HyperVXNdisFilter.sys";
SC_HANDLE manager = reinterpret_cast<SC_HANDLE>(1), service = reinterpret_cast<SC_HANDLE>(2);

void Reset(bool installed = false, bool started = false) {
    exists = installed; running = started;
    start_error = stop_error = delete_error = config_error = 0;
    starts = stops = deletes = scm_handles = files = 0;
    opened_path.clear();
    existing_path = L"C:\\drivers\\HyperVXNdisFilter.sys";
}
SC_HANDLE WINAPI OpenManager(LPCWSTR, LPCWSTR, DWORD) { ++scm_handles; return manager; }
SC_HANDLE WINAPI OpenService(SC_HANDLE, LPCWSTR, DWORD) {
    if (!exists) { SetLastError(ERROR_SERVICE_DOES_NOT_EXIST); return nullptr; }
    ++scm_handles;
    return service;
}
BOOL WINAPI QueryStatus(SC_HANDLE, LPSERVICE_STATUS status) {
    status->dwServiceType = SERVICE_KERNEL_DRIVER;
    status->dwCurrentState = running ? SERVICE_RUNNING : SERVICE_STOPPED;
    return TRUE;
}
BOOL WINAPI QueryConfig(SC_HANDLE, LPQUERY_SERVICE_CONFIGW config, DWORD, LPDWORD needed) {
    *needed = sizeof(QUERY_SERVICE_CONFIGW);
    if (config == nullptr) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    *config = {};
    config->lpBinaryPathName = const_cast<LPWSTR>(existing_path.c_str());
    return TRUE;
}
SC_HANDLE WINAPI CreateService(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD type, DWORD start,
    DWORD, LPCWSTR image, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR) {
    if (type != SERVICE_KERNEL_DRIVER || start != SERVICE_DEMAND_START || image[0] == L'"') return nullptr;
    exists = true;
    ++scm_handles;
    return service;
}
BOOL WINAPI Start(SC_HANDLE, DWORD, LPCWSTR*) {
    ++starts;
    if (start_error) { SetLastError(start_error); return FALSE; }
    running = true;
    return TRUE;
}
BOOL WINAPI Stop(SC_HANDLE, DWORD control, LPSERVICE_STATUS) {
    ++stops;
    if (stop_error || control != SERVICE_CONTROL_STOP) { SetLastError(stop_error); return FALSE; }
    running = false;
    return TRUE;
}
BOOL WINAPI Delete(SC_HANDLE) {
    ++deletes;
    if (delete_error) { SetLastError(delete_error); return FALSE; }
    exists = false;
    return TRUE;
}
BOOL WINAPI CloseService(SC_HANDLE) { --scm_handles; return TRUE; }
HANDLE WINAPI OpenFile(LPCWSTR path, DWORD, DWORD share, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) {
    opened_path = path;
    if (share != FILE_SHARE_READ) return INVALID_HANDLE_VALUE;
    ++files;
    return reinterpret_cast<HANDLE>(3);
}
BOOL WINAPI CloseFile(HANDLE) { --files; return TRUE; }
LSTATUS WINAPI CreateKey(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES,
    PHKEY key, LPDWORD) {
    *key = reinterpret_cast<HKEY>(4);
    return ERROR_SUCCESS;
}
LSTATUS WINAPI SetValue(HKEY, LPCWSTR name, DWORD, DWORD type, const BYTE* value, DWORD size) {
    if (std::wcscmp(name, L"StandaloneWfp") || type != REG_DWORD || size != 4 || *value != 1)
        return ERROR_INVALID_DATA;
    return config_error;
}
LSTATUS WINAPI CloseKey(HKEY) { return ERROR_SUCCESS; }
} // namespace fake

#define OpenSCManagerW fake::OpenManager
#define OpenServiceW fake::OpenService
#define QueryServiceStatus fake::QueryStatus
#define QueryServiceConfigW fake::QueryConfig
#define CreateServiceW fake::CreateService
#define StartServiceW fake::Start
#define ControlService fake::Stop
#define DeleteService fake::Delete
#define CloseServiceHandle fake::CloseService
#define CreateFileW fake::OpenFile
#define CloseHandle fake::CloseFile
#define RegCreateKeyExW fake::CreateKey
#define RegSetValueExW fake::SetValue
#define RegCloseKey fake::CloseKey
#include "../src/DriverLoader.cpp"

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)

int main() {
    using pmkext::monitor::DriverLoader;
    std::string error;
    fake::Reset();
    {
        DriverLoader loader;
        CHECK(loader.Load(L"C:/path with spaces/filter.sys", error));
        CHECK(loader.Created() && loader.Started());
        CHECK(fake::opened_path == L"C:\\path with spaces\\filter.sys");
        CHECK(loader.Cleanup(error));
        CHECK(loader.Cleanup(error));
    }
    CHECK(!fake::exists && !fake::running && fake::starts == 1 && fake::stops == 1 && fake::deletes == 1);
    CHECK(fake::scm_handles == 0 && fake::files == 0);

    fake::Reset();
    {
        DriverLoader loader;
        CHECK(loader.Load(L"", error));
        CHECK(fake::opened_path.ends_with(L"\\HyperVXNdisFilter.sys"));
        std::vector<wchar_t> module(32768);
        CHECK(GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size())) != 0);
        std::wstring directory(module.data());
        directory.resize(directory.find_last_of(L"\\/") + 1);
        CHECK(fake::opened_path == directory + L"HyperVXNdisFilter.sys");
    }
    CHECK(!fake::exists && fake::stops == 1 && fake::deletes == 1);

    for (bool running : {false, true}) {
        fake::Reset(true, running);
        {
            DriverLoader loader;
            CHECK(loader.Load(L"", error));
            CHECK(!loader.Created() && loader.Started() == !running);
        }
        CHECK(fake::exists && fake::running == running);
        CHECK(fake::starts == !running && fake::stops == !running && fake::deletes == 0);
        CHECK(fake::scm_handles == 0 && fake::files == 0);
    }
    for (const wchar_t* path : {L"\\??\\C:\\drivers\\filter.sys", L"\\SystemRoot\\System32\\drivers\\filter.sys",
                               L"System32\\drivers\\filter.sys", L"%SystemRoot%\\System32\\drivers\\filter.sys"}) {
        fake::Reset(true, false);
        fake::existing_path = path;
        {
            DriverLoader loader;
            CHECK(loader.Load(L"", error));
            CHECK(!fake::opened_path.starts_with(L"\\") && fake::opened_path.find(L'%') == std::wstring::npos);
        }
        CHECK(fake::exists && !fake::running && fake::deletes == 0);
    }
    fake::Reset(true, false);
    {
        DriverLoader loader;
        CHECK(!loader.Load(L"C:/different.sys", error));
    }
    CHECK(fake::exists && fake::starts == 0 && fake::deletes == 0);

    for (bool config_failure : {false, true}) {
        fake::Reset();
        if (config_failure) fake::config_error = ERROR_ACCESS_DENIED;
        else fake::start_error = ERROR_GEN_FAILURE;
        {
            DriverLoader loader;
            CHECK(!loader.Load(L"C:/filter.sys", error));
        }
        CHECK(!fake::exists && fake::stops == 0 && fake::deletes == 1);
        CHECK(fake::scm_handles == 0 && fake::files == 0);
    }
    fake::Reset(true, false);
    fake::start_error = ERROR_SERVICE_ALREADY_RUNNING;
    {
        DriverLoader loader;
        CHECK(loader.Load(L"", error));
        CHECK(!loader.Started());
    }
    CHECK(fake::stops == 0 && fake::deletes == 0);

    for (bool stop_failure : {false, true}) {
        fake::Reset();
        DriverLoader loader;
        CHECK(loader.Load(L"C:/filter.sys", error));
        if (stop_failure) fake::stop_error = ERROR_ACCESS_DENIED;
        else fake::delete_error = ERROR_ACCESS_DENIED;
        CHECK(!loader.Cleanup(error) && !error.empty());
        CHECK(fake::exists && fake::running == stop_failure);
        CHECK(fake::deletes == !stop_failure);
        CHECK(fake::scm_handles == 0 && fake::files == 0);
    }
    std::puts("PASS: monitor driver paths, ownership, rollback and cleanup failures (no real SCM/device access)");
    return 0;
}
