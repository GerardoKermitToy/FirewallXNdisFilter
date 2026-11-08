#include "../../install/notify/BindingPolicy.h"
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

namespace {
struct Write { HKEY root; std::wstring key, name, value; DWORD type, bytes; };
std::vector<Write> writes;
unsigned fail_write = 0, deletes = 0;
LSTATUS write_error = ERROR_ACCESS_DENIED, delete_error = ERROR_SUCCESS;
LSTATUS read_error = ERROR_FILE_NOT_FOUND;
std::wstring registered_path = L"C:\\private\\FirewallXNdisFilterNotify.dll";
HKEY delete_root = nullptr;
std::wstring delete_key;
std::wstring module_path = L"C:\\private\\FirewallXNdisFilterNotify.dll";
DWORD path_result = 1;

DWORD WINAPI FakeGetModuleFileNameW(HMODULE, LPWSTR path, DWORD capacity) {
    if (path_result == 0) { SetLastError(ERROR_ACCESS_DENIED); return 0; }
    if (path_result == MAX_PATH) return MAX_PATH;
    if (module_path.size() + 1 > capacity) return capacity;
    std::wmemcpy(path, module_path.c_str(), module_path.size() + 1);
    return static_cast<DWORD>(module_path.size());
}
LSTATUS WINAPI FakeRegGetValueW(HKEY root, LPCWSTR, LPCWSTR, DWORD flags, LPDWORD, PVOID data, LPDWORD bytes) {
    if (root != HKEY_CLASSES_ROOT || flags != RRF_RT_REG_SZ) return ERROR_TRANSACTIONAL_CONFLICT;
    if (read_error != ERROR_SUCCESS) return read_error;
    const DWORD required = static_cast<DWORD>((registered_path.size() + 1) * sizeof(wchar_t));
    if (*bytes < required) { *bytes = required; return ERROR_MORE_DATA; }
    std::wmemcpy(static_cast<wchar_t*>(data), registered_path.c_str(), registered_path.size() + 1);
    *bytes = required;
    return ERROR_SUCCESS;
}
LSTATUS WINAPI FakeRegSetKeyValueW(HKEY root, LPCWSTR key, LPCWSTR name, DWORD type, LPCVOID data, DWORD bytes) {
    writes.push_back({root, key, name ? name : L"", static_cast<LPCWSTR>(data), type, bytes});
    // Model an installer-owned classes transaction. Explicit HKLM bypass is an error.
    if (root != HKEY_CLASSES_ROOT) return ERROR_TRANSACTIONAL_CONFLICT;
    return writes.size() == fail_write ? write_error : ERROR_SUCCESS;
}
LSTATUS WINAPI FakeRegDeleteTreeW(HKEY root, LPCWSTR key) {
    ++deletes; delete_root = root; delete_key = key;
    return root == HKEY_CLASSES_ROOT ? delete_error : ERROR_TRANSACTIONAL_CONFLICT;
}
void Reset() {
    writes.clear(); fail_write = deletes = 0;
    write_error = ERROR_ACCESS_DENIED; delete_error = ERROR_SUCCESS;
    read_error = ERROR_FILE_NOT_FOUND; registered_path = module_path;
    delete_root = nullptr; delete_key.clear(); path_result = 1;
}
} // namespace

// Exercise the exact production registration logic without any registry writes,
// COM registration, NetCfg calls, or loading the production DLL.
#define GetModuleFileNameW FakeGetModuleFileNameW
#define RegGetValueW FakeRegGetValueW
#define RegSetKeyValueW FakeRegSetKeyValueW
#define RegDeleteTreeW FakeRegDeleteTreeW
#include "../../install/notify/NotifyRegistration.h"
#undef RegDeleteTreeW
#undef RegSetKeyValueW
#undef RegGetValueW
#undef GetModuleFileNameW

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return false; } } while (false)

namespace {
const std::wstring class_key = L"CLSID\\{1CFED41E-4579-42CF-962C-2A7E04C6DBC8}";

bool TestRedirectableClassesRoot() {
    Reset();
    CHECK(firewallx_ndis_filter::RegisterNotifyServer(nullptr) == S_OK);
    CHECK(writes.size() == 3 && deletes == 0);
    CHECK(writes[0].key == class_key && writes[0].name.empty());
    CHECK(writes[0].value == L"FirewallXNdisFilter target-adapter binding policy");
    CHECK(writes[1].key == class_key + L"\\InprocServer32" && writes[1].name.empty());
    CHECK(writes[1].value == module_path);
    CHECK(writes[2].key == writes[1].key && writes[2].name == L"ThreadingModel");
    CHECK(writes[2].value == L"Both");
    for (const auto& write : writes) {
        CHECK(write.root == HKEY_CLASSES_ROOT && write.type == REG_SZ);
        CHECK(write.bytes == (write.value.size() + 1) * sizeof(wchar_t));
    }
    CHECK(firewallx_ndis_filter::RegisterNotifyServer(nullptr) == S_OK);
    CHECK(writes.size() == 6 && deletes == 0);
    return true;
}

bool TestWriteFailuresAndRollback() {
    for (unsigned failure : {1u, 2u, 3u}) {
        Reset(); fail_write = failure;
        // A failed cleanup must not hide the original registration error.
        delete_error = ERROR_TRANSACTIONAL_CONFLICT;
        CHECK(firewallx_ndis_filter::RegisterNotifyServer(nullptr) == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
        CHECK(writes.size() == failure);
        CHECK(deletes == (failure == 1 ? 0u : 1u));
        if (deletes) CHECK(delete_root == HKEY_CLASSES_ROOT && delete_key == class_key);
    }
    return true;
}

bool TestModulePathFailuresDoNotWrite() {
    for (DWORD result : {0ul, static_cast<DWORD>(MAX_PATH)}) {
        Reset(); path_result = result;
        CHECK(firewallx_ndis_filter::RegisterNotifyServer(nullptr) ==
              HRESULT_FROM_WIN32(result == 0 ? ERROR_ACCESS_DENIED : ERROR_INSUFFICIENT_BUFFER));
        CHECK(writes.empty() && deletes == 0);
    }
    return true;
}

bool TestUnregisterUsesSameRoot() {
    for (LSTATUS status : {ERROR_SUCCESS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED}) {
        Reset(); read_error = ERROR_SUCCESS; delete_error = status;
        CHECK(firewallx_ndis_filter::UnregisterNotifyServer() ==
              (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND ? S_OK : HRESULT_FROM_WIN32(status)));
        CHECK(writes.empty() && deletes == 1);
        CHECK(delete_root == HKEY_CLASSES_ROOT && delete_key == class_key);
    }
    return true;
}
bool TestRegistrationOwnership() {
    Reset();
    CHECK(firewallx_ndis_filter::UnregisterNotifyServer() == S_OK);
    CHECK(writes.empty() && deletes == 0);

    for (const auto* legacy : {L"C:\\old\\HyperVXNdisFilterNotify.dll",
                               L"C:\\old\\HyperVGuardNotify.dll",
                               L"C:\\other\\OtherFirewallXNdisFilterNotify.dll"}) {
        Reset(); read_error = ERROR_SUCCESS; registered_path = legacy;
        CHECK(firewallx_ndis_filter::RegisterNotifyServer(nullptr) == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS));
        CHECK(firewallx_ndis_filter::UnregisterNotifyServer() == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS));
        CHECK(writes.empty() && deletes == 0);
    }
    for (LSTATUS error : {ERROR_ACCESS_DENIED, ERROR_MORE_DATA}) {
        Reset(); read_error = error;
        CHECK(firewallx_ndis_filter::RegisterNotifyServer(nullptr) == HRESULT_FROM_WIN32(error));
        CHECK(firewallx_ndis_filter::UnregisterNotifyServer() == HRESULT_FROM_WIN32(error));
        CHECK(writes.empty() && deletes == 0);
    }
    Reset(); read_error = ERROR_SUCCESS; registered_path = L"C:\\private\\FIREWALLXNDISFILTERNOTIFY.DLL";
    CHECK(firewallx_ndis_filter::UnregisterNotifyServer() == S_OK && deletes == 1);
    Reset(); read_error = ERROR_SUCCESS; fail_write = 2;
    CHECK(firewallx_ndis_filter::RegisterNotifyServer(nullptr) == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
    CHECK(writes.size() == 2 && deletes == 0);
    return true;
}
} // namespace

int main() {
    if (!TestRedirectableClassesRoot() || !TestWriteFailuresAndRollback() ||
        !TestModulePathFailuresDoNotWrite() || !TestUnregisterUsesSameRoot() ||
        !TestRegistrationOwnership()) return 1;
    std::puts("PASS notify registration root, values, failures and cleanup (fake registry only)");
    return 0;
}
