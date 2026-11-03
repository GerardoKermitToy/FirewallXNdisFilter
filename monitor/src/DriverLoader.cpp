#include "DriverLoader.h"

#include <cstdio>
#include <vector>

namespace pmkext::monitor {
namespace {
constexpr wchar_t ServiceName[] = L"HyperVXNdisFilter";

bool Fail(const char* operation, DWORD status, std::string& error) {
    error = std::string(operation) + ": Windows error " + std::to_string(status);
    return false;
}

bool FullPath(const std::wstring& input, std::wstring& path, std::string& error) {
    DWORD size = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (size == 0) return Fail("resolve SYS path", GetLastError(), error);
    std::vector<wchar_t> buffer(size);
    const DWORD copied = GetFullPathNameW(input.c_str(), size, buffer.data(), nullptr);
    if (copied == 0) return Fail("resolve SYS path", GetLastError(), error);
    if (copied >= size) return Fail("SYS path changed", ERROR_RETRY, error);
    path.assign(buffer.data(), copied);
    return true;
}

bool ImagePath(const std::wstring& requested, std::wstring& path, std::string& error) {
    if (!requested.empty()) return FullPath(requested, path, error);
    std::vector<wchar_t> module(256);
    for (;;) {
        const DWORD copied = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
        if (copied == 0) return Fail("get monitor path", GetLastError(), error);
        if (copied < module.size()) {
            std::wstring name(module.data(), copied);
            const auto slash = name.find_last_of(L"\\/");
            if (slash == std::wstring::npos) return Fail("get monitor directory", ERROR_INVALID_NAME, error);
            return FullPath(name.substr(0, slash + 1) + L"HyperVXNdisFilter.sys", path, error);
        }
        if (module.size() > MAXDWORD / 2) return Fail("monitor path too long", ERROR_FILENAME_EXCED_RANGE, error);
        module.resize(module.size() * 2);
    }
}

DWORD WaitStopped(SC_HANDLE service) {
    const ULONGLONG deadline = GetTickCount64() + 30000;
    for (;;) {
        SERVICE_STATUS status{};
        if (!QueryServiceStatus(service, &status)) return GetLastError();
        if (status.dwCurrentState == SERVICE_STOPPED) return ERROR_SUCCESS;
        if (GetTickCount64() >= deadline) return ERROR_TIMEOUT;
        Sleep(50);
    }
}
} // namespace

DriverLoader::~DriverLoader() {
    try {
        std::string error;
        if (!Cleanup(error)) std::fprintf(stderr, "ERROR: driver cleanup: %s\n", error.c_str());
    } catch (...) {
        std::fputs("ERROR: unexpected driver cleanup failure\n", stderr);
    }
}

bool DriverLoader::Load(const std::wstring& sys_path, std::string& error) {
    error.clear();
    manager_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (manager_ == nullptr) return Fail("OpenSCManager", GetLastError(), error);
    service_ = OpenServiceW(manager_, ServiceName,
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START | SERVICE_STOP);
    std::wstring path;
    if (service_ != nullptr) {
        SERVICE_STATUS status{};
        if (!QueryServiceStatus(service_, &status)) return Fail("query driver service", GetLastError(), error);
        if (status.dwServiceType != SERVICE_KERNEL_DRIVER) return Fail("service is not a kernel driver", ERROR_INVALID_DATA, error);
        if (status.dwCurrentState == SERVICE_RUNNING) return true;
        if (status.dwCurrentState != SERVICE_STOPPED) return Fail("driver service is transitioning", ERROR_SERVICE_CANNOT_ACCEPT_CTRL, error);
        DWORD size = 0;
        QueryServiceConfigW(service_, nullptr, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return Fail("query service image", GetLastError(), error);
        std::vector<BYTE> bytes(size);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
        if (!QueryServiceConfigW(service_, config, size, &size)) return Fail("query service image", GetLastError(), error);
        path = config->lpBinaryPathName;
        if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"') path = path.substr(1, path.size() - 2);
        if (path.starts_with(L"\\??\\")) path.erase(0, 4);
        if (_wcsnicmp(path.c_str(), L"\\SystemRoot\\", 12) == 0) path = L"%SystemRoot%\\" + path.substr(12);
        if (_wcsnicmp(path.c_str(), L"System32\\", 9) == 0) path = L"%SystemRoot%\\" + path;
        const DWORD expanded_size = ExpandEnvironmentStringsW(path.c_str(), nullptr, 0);
        if (expanded_size == 0) return Fail("expand service image", GetLastError(), error);
        std::vector<wchar_t> expanded(expanded_size);
        const DWORD expanded_length = ExpandEnvironmentStringsW(path.c_str(), expanded.data(), expanded_size);
        if (expanded_length == 0) return Fail("expand service image", GetLastError(), error);
        if (expanded_length > expanded_size) return Fail("service image changed", ERROR_RETRY, error);
        path = expanded.data();
        if (!sys_path.empty()) {
            std::wstring requested;
            if (!FullPath(sys_path, requested, error)) return false;
            if (CompareStringOrdinal(path.c_str(), -1, requested.c_str(), -1, TRUE) != CSTR_EQUAL)
                return Fail("existing service uses another SYS; refusing replacement", ERROR_INVALID_PARAMETER, error);
        }
    } else {
        const DWORD status = GetLastError();
        if (status != ERROR_SERVICE_DOES_NOT_EXIST) return Fail("OpenService", status, error);
        if (!ImagePath(sys_path, path, error)) return false;
    }
    image_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (image_ == INVALID_HANDLE_VALUE) return Fail("open SYS image", GetLastError(), error);
    if (service_ == nullptr) {
        service_ = CreateServiceW(manager_, ServiceName, ServiceName,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (service_ == nullptr) return Fail("CreateService", GetLastError(), error);
        created_ = true;
        HKEY key = nullptr;
        LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\HyperVXNdisFilter\\Parameters",
            0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr);
        if (status != ERROR_SUCCESS) return Fail("create driver parameters", status, error);
        const DWORD enabled = 1;
        status = RegSetValueExW(key, L"StandaloneWfp", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&enabled), sizeof(enabled));
        RegCloseKey(key);
        if (status != ERROR_SUCCESS) return Fail("set StandaloneWfp", status, error);
    }
    if (!StartServiceW(service_, 0, nullptr)) {
        const DWORD status = GetLastError();
        if (status == ERROR_SERVICE_ALREADY_RUNNING && !created_) return true;
        return Fail("StartService", status, error);
    }
    started_ = true;
    std::wprintf(L"Driver started from %ls%s\n", path.c_str(), created_ ? L" (temporary WFP-only service)" : L" (existing service)");
    return true;
}

bool DriverLoader::Cleanup(std::string& error) {
    DWORD status = ERROR_SUCCESS;
    const char* operation = "stop monitor-started driver";
    if (started_) {
        SERVICE_STATUS service_status{};
        if (!ControlService(service_, SERVICE_CONTROL_STOP, &service_status)) {
            status = GetLastError();
            if (status == ERROR_SERVICE_NOT_ACTIVE) status = ERROR_SUCCESS;
        }
        if (status == ERROR_SUCCESS) status = WaitStopped(service_);
    }
    if (created_ && !started_) {
        SERVICE_STATUS current{};
        if (!QueryServiceStatus(service_, &current)) status = GetLastError();
        else if (current.dwCurrentState != SERVICE_STOPPED) status = ERROR_SERVICE_ALREADY_RUNNING;
        operation = "created service was started externally; leaving it untouched";
    }
    const bool remove = created_ && status == ERROR_SUCCESS;
    if (remove && !DeleteService(service_)) {
        status = GetLastError();
        operation = "delete monitor-created service";
    }
    if (service_ != nullptr) { CloseServiceHandle(service_); service_ = nullptr; }
    if (remove && status == ERROR_SUCCESS) {
        operation = "confirm service deletion";
        const ULONGLONG deadline = GetTickCount64() + 5000;
        for (;;) {
            SC_HANDLE service = OpenServiceW(manager_, ServiceName, SERVICE_QUERY_STATUS);
            const DWORD state = service == nullptr ? GetLastError() : ERROR_SUCCESS;
            if (service != nullptr) CloseServiceHandle(service);
            if (state == ERROR_SERVICE_DOES_NOT_EXIST) break;
            if (state != ERROR_SUCCESS && state != ERROR_SERVICE_MARKED_FOR_DELETE) { status = state; break; }
            if (GetTickCount64() >= deadline) { status = ERROR_TIMEOUT; break; }
            Sleep(50);
        }
    }
    if (manager_ != nullptr) { CloseServiceHandle(manager_); manager_ = nullptr; }
    if (image_ != INVALID_HANDLE_VALUE) { CloseHandle(image_); image_ = INVALID_HANDLE_VALUE; }
    created_ = started_ = false;
    if (status != ERROR_SUCCESS) return Fail(operation, status, error);
    error.clear();
    return true;
}

} // namespace pmkext::monitor
