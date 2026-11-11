#pragma once
#include "Management.h"

#include <wrl/client.h>
#include <array>
#include <utility>

namespace firewallx_ndis_filter::setup {
using Microsoft::WRL::ComPtr;

// RegFlushKey requires KEY_QUERY_VALUE, including on write-only operations.
inline constexpr wchar_t kServiceKey[] = L"SYSTEM\\CurrentControlSet\\Services\\FirewallXNdisFilter";
inline constexpr REGSAM kDurableConfigAccess = KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY;
static_assert((kDurableConfigAccess & (KEY_QUERY_VALUE | KEY_SET_VALUE)) == (KEY_QUERY_VALUE | KEY_SET_VALUE));

inline std::wstring ErrorCode(DWORD code) {
    wchar_t number[16]{};
    swprintf_s(number, L"0x%08lX", code);
    wchar_t* message = nullptr;
    const DWORD size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                     FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
                                     reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::wstring result(number);
    if (size && message) {
        std::wstring text(message, size);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n')) text.pop_back();
        result += L" (" + text + L")";
    }
    LocalFree(message);
    return result;
}

inline void Check(HRESULT result, const wchar_t* operation) {
    if (FAILED(result)) throw Error{std::wstring(operation) + L": " + ErrorCode(static_cast<DWORD>(result))};
}

inline void CheckWin32(LSTATUS result, const wchar_t* operation) {
    if (result != ERROR_SUCCESS) throw Error{std::wstring(operation) + L": " + ErrorCode(static_cast<DWORD>(result))};
}

inline std::wstring GuidText(const GUID& guid) {
    std::array<wchar_t, 39> text{};
    if (!StringFromGUID2(guid, text.data(), static_cast<int>(text.size()))) throw Error{L"GUID formatting failed."};
    return text.data();
}

class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

struct RegistryKey {
    HKEY value = nullptr;
    ~RegistryKey() { if (value) RegCloseKey(value); }
    RegistryKey() = default;
    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;
};

struct CoString {
    LPWSTR value = nullptr;
    ~CoString() { CoTaskMemFree(value); }
    CoString() = default;
    CoString(const CoString&) = delete;
    CoString& operator=(const CoString&) = delete;
};

void ValidateInfFile(const std::filesystem::path& inf);
void ValidateRemovalInfFile(const std::filesystem::path& inf);
bool IsPublishedInfName(const std::wstring& name);
struct ServiceControlApi {
    decltype(&OpenSCManagerW) open_manager = OpenSCManagerW;
    decltype(&OpenServiceW) open_service = OpenServiceW;
    decltype(&QueryServiceStatusEx) query_status = QueryServiceStatusEx;
    decltype(&ControlService) control = ControlService;
    decltype(&DeleteService) remove = DeleteService;
    decltype(&CloseServiceHandle) close = CloseServiceHandle;
    decltype(&RegDeleteTreeW) delete_tree = RegDeleteTreeW;
    decltype(&GetTickCount64) ticks = GetTickCount64;
    decltype(&Sleep) sleep = Sleep;
};
enum class ServiceRemoval { Absent, Deleted, RebootRequired };
ServiceRemoval RemoveWindowsDriverService(const ServiceControlApi& api = {});
std::vector<std::wstring> ReadWindowsDriverPackages();
Change RemoveWindowsDriverPackage(const std::wstring& published_inf);
inline constexpr std::array<const wchar_t*, 4> kPackageFiles = {
    L"FirewallXNdisFilter.inf", kDriverFileName, L"FirewallXNdisFilterNotify.dll", L"FirewallXNdisFilter.cat"
};
std::vector<Handle> LockPackageFiles(const std::filesystem::path& package);
std::vector<Handle> LockAndVerifyPackage(const std::filesystem::path& package);
std::vector<Handle> LockMatchingPackage(const std::filesystem::path& package, const std::vector<Handle>& expected);
std::vector<Handle> LockMatchingWindowsDriverPackages(const std::vector<Handle>& expected);
std::vector<Handle> StageVerifiedWindowsDriverPackage(const std::filesystem::path& package, const std::vector<Handle>& expected);

} // namespace firewallx_ndis_filter::setup
