#include "../../install/notify/TargetConfig.h"

#include <cstdio>
#include <cwchar>
#include <cstring>
#include <initializer_list>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)

using namespace firewallx_ndis_filter;
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

const GUID adapter_guid = {0x9eb6ca05, 0x3905, 0x4420, {0xa3, 0x4f, 0x4f, 0xa0, 0x9d, 0xcc, 0x6a, 0x2d}};
const GUID other_guid = {1, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
struct FakeAdapter {
    ULONG64 luid = 123;
    GUID round_trip = adapter_guid;
    GUID row_guid = adapter_guid;
    ULONG64 row_luid = 123;
    NDIS_MEDIUM media = NdisMedium802_3;
    DWORD guid_error = NO_ERROR, luid_error = NO_ERROR, row_error = NO_ERROR;
    unsigned row_reads = 0;
} adapter;

DWORD WINAPI GuidToLuid(const GUID* guid, NET_LUID* luid) {
    if (*guid != adapter_guid) return ERROR_NOT_FOUND;
    luid->Value = adapter.luid;
    return adapter.guid_error;
}
DWORD WINAPI LuidToGuid(const NET_LUID* luid, GUID* guid) {
    if (luid->Value != adapter.luid) return ERROR_NOT_FOUND;
    *guid = adapter.round_trip;
    return adapter.luid_error;
}
DWORD WINAPI GetEntry(MIB_IF_ROW2* row) {
    ++adapter.row_reads;
    if (row->InterfaceLuid.Value != adapter.luid) return ERROR_NOT_FOUND;
    row->InterfaceGuid = adapter.row_guid;
    row->InterfaceLuid.Value = adapter.row_luid;
    row->MediaType = adapter.media;
    return adapter.row_error;
}
const AdapterQuery fake_adapter_query{GuidToLuid, LuidToGuid, GetEntry};

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
    // All NETIO calls are faked: VMware-like Ethernet and existing Wi-Fi
    // representations are eligible; IP tunnels and unknown media are not.
    NET_LUID luid{};
    for (const auto media : {NdisMedium802_3, NdisMediumNative802_11}) {
        adapter = {};
        adapter.media = media;
        CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Compatible);
        CHECK(luid.Value == adapter.luid && adapter.row_reads == 1);
    }
    for (const auto media : {NdisMediumIP, NdisMediumWan, NdisMediumMax}) {
        adapter = {};
        adapter.media = media;
        luid.Value = 456;
        CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unsupported);
        CHECK(luid.Value == 456);
    }
    adapter = {};
    CHECK(QueryAdapter(GUID_NULL, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    CHECK(QueryAdapter(other_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    CHECK(adapter.row_reads == 0);
    adapter = {}; adapter.guid_error = ERROR_ACCESS_DENIED;
    CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    adapter = {}; adapter.luid = 0;
    CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    adapter = {}; adapter.luid_error = ERROR_NOT_FOUND;
    CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    adapter = {}; adapter.round_trip = other_guid;
    CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    adapter = {}; adapter.row_error = ERROR_ACCESS_DENIED;
    CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    adapter = {}; adapter.row_guid = other_guid;
    CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    adapter = {}; adapter.row_luid++;
    CHECK(QueryAdapter(adapter_guid, luid, fake_adapter_query) == AdapterEligibility::Unavailable);
    std::puts("PASS schema-4 binding configuration and fail-closed adapter identity/media validation");
    return 0;
}
