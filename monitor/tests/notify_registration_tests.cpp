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
HKEY delete_root = nullptr;
std::wstring delete_key;
std::wstring module_path = L"C:\\private\\HyperVXNdisFilterNotify.dll";
DWORD path_result = 1;

DWORD WINAPI FakeGetModuleFileNameW(HMODULE, LPWSTR path, DWORD capacity) {
    if (path_result == 0) { SetLastError(ERROR_ACCESS_DENIED); return 0; }
    if (path_result == MAX_PATH) return MAX_PATH;
    if (module_path.size() + 1 > capacity) return capacity;
    std::wmemcpy(path, module_path.c_str(), module_path.size() + 1);
    return static_cast<DWORD>(module_path.size());
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
    delete_root = nullptr; delete_key.clear(); path_result = 1;
}
} // namespace

// Exercise the exact production registration logic without any registry writes,
// COM registration, NetCfg calls, or loading the production DLL.
#define GetModuleFileNameW FakeGetModuleFileNameW
#define RegSetKeyValueW FakeRegSetKeyValueW
#define RegDeleteTreeW FakeRegDeleteTreeW
#include "../../install/notify/NotifyRegistration.h"
#undef RegDeleteTreeW
#undef RegSetKeyValueW
#undef GetModuleFileNameW

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return false; } } while (false)

namespace {
const std::wstring class_key = L"CLSID\\{1CFED41E-4579-42CF-962C-2A7E04C6DBC8}";

bool TestRedirectableClassesRoot() {
    Reset();
    CHECK(hyperv_xndis_filter::RegisterNotifyServer(nullptr) == S_OK);
    CHECK(writes.size() == 3 && deletes == 0);
    CHECK(writes[0].key == class_key && writes[0].name.empty());
    CHECK(writes[0].value == L"HyperVXNdisFilter target-adapter binding policy");
    CHECK(writes[1].key == class_key + L"\\InprocServer32" && writes[1].name.empty());
    CHECK(writes[1].value == module_path);
    CHECK(writes[2].key == writes[1].key && writes[2].name == L"ThreadingModel");
    CHECK(writes[2].value == L"Both");
    for (const auto& write : writes) {
        CHECK(write.root == HKEY_CLASSES_ROOT && write.type == REG_SZ);
        CHECK(write.bytes == (write.value.size() + 1) * sizeof(wchar_t));
    }
    CHECK(hyperv_xndis_filter::RegisterNotifyServer(nullptr) == S_OK);
    CHECK(writes.size() == 6 && deletes == 0);
    return true;
}

bool TestWriteFailuresAndRollback() {
    for (unsigned failure : {1u, 2u, 3u}) {
        Reset(); fail_write = failure;
        // A failed cleanup must not hide the original registration error.
        delete_error = ERROR_TRANSACTIONAL_CONFLICT;
        CHECK(hyperv_xndis_filter::RegisterNotifyServer(nullptr) == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
        CHECK(writes.size() == failure);
        CHECK(deletes == (failure == 1 ? 0u : 1u));
        if (deletes) CHECK(delete_root == HKEY_CLASSES_ROOT && delete_key == class_key);
    }
    return true;
}

bool TestModulePathFailuresDoNotWrite() {
    for (DWORD result : {0ul, static_cast<DWORD>(MAX_PATH)}) {
        Reset(); path_result = result;
        CHECK(hyperv_xndis_filter::RegisterNotifyServer(nullptr) ==
              HRESULT_FROM_WIN32(result == 0 ? ERROR_ACCESS_DENIED : ERROR_INSUFFICIENT_BUFFER));
        CHECK(writes.empty() && deletes == 0);
    }
    return true;
}

bool TestUnregisterUsesSameRoot() {
    for (LSTATUS status : {ERROR_SUCCESS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED}) {
        Reset(); delete_error = status;
        CHECK(hyperv_xndis_filter::UnregisterNotifyServer() ==
              (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND ? S_OK : HRESULT_FROM_WIN32(status)));
        CHECK(writes.empty() && deletes == 1);
        CHECK(delete_root == HKEY_CLASSES_ROOT && delete_key == class_key);
    }
    return true;
}
} // namespace

int main() {
    if (!TestRedirectableClassesRoot() || !TestWriteFailuresAndRollback() ||
        !TestModulePathFailuresDoNotWrite() || !TestUnregisterUsesSameRoot()) return 1;
    std::puts("PASS notify registration root, values, failures and cleanup (fake registry only)");
    return 0;
}
