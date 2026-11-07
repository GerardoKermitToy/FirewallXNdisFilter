#include "../../install/notify/TargetConfig.h"

#include <cstdio>
#include <cwchar>
#include <cstring>
#include <initializer_list>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)

using namespace hyperv_xndis_filter;
namespace {
struct FakeRegistry {
    DWORD version = kBindingConfigVersion;
    DWORD allowed = 1;
    DWORD version_size = sizeof(DWORD);
    DWORD allowed_size = sizeof(DWORD);
    LSTATUS version_error = ERROR_SUCCESS;
    LSTATUS allowed_error = ERROR_SUCCESS;
    unsigned reads = 0;
} registry;

LSTATUS ReadFake(const wchar_t* name, DWORD flags, void* data, DWORD* size) {
    const bool version = std::wcscmp(name, L"ConfigVersion") == 0;
    const bool allowed = std::wcscmp(name, L"AllowBindings") == 0;
    if ((!version && !allowed) || flags != RRF_RT_REG_DWORD || !data || *size < sizeof(DWORD)) {
        return ERROR_INVALID_PARAMETER;
    }
    ++registry.reads;
    const auto error = version ? registry.version_error : registry.allowed_error;
    if (error != ERROR_SUCCESS) return error;
    const DWORD value = version ? registry.version : registry.allowed;
    std::memcpy(data, &value, sizeof(value));
    *size = version ? registry.version_size : registry.allowed_size;
    return ERROR_SUCCESS;
}
} // namespace

int main() {
    // Only fake registry callbacks; no production keys or network APIs.
    TargetConfig output;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_SUCCESS && output.armed);
    CHECK(registry.reads == 2);
    for (DWORD version : {0ul, 2ul, 3ul, 5ul}) {
        registry = {};
        registry.version = version;
        CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && output.armed);
        CHECK(registry.reads == 1);
    }
    registry = {};
    registry.allowed = 0;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && output.armed);
    CHECK(ReadTargetConfig(output, false, ReadFake) == ERROR_SUCCESS && !output.armed);
    registry.allowed = 2;
    CHECK(ReadTargetConfig(output, false, ReadFake) == ERROR_INVALID_DATA && !output.armed);
    registry = {};
    registry.version_size = 3;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && !output.armed);
    registry = {};
    registry.allowed_size = 3;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && !output.armed);
    for (LSTATUS error : {ERROR_FILE_NOT_FOUND, ERROR_UNSUPPORTED_TYPE, ERROR_ACCESS_DENIED}) {
        registry = {};
        registry.version_error = error;
        CHECK(ReadTargetConfig(output, true, ReadFake) == error && !output.armed);
        registry = {};
        registry.allowed_error = error;
        CHECK(ReadTargetConfig(output, true, ReadFake) == error && !output.armed);
    }
    std::puts("PASS schema-4 all-Ethernet binding configuration and fail-closed validation");
    return 0;
}
