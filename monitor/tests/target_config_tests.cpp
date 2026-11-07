#include "../../install/notify/TargetConfig.h"

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)

using hyperv_xndis_filter::TargetConfig;
using hyperv_xndis_filter::ReadTargetConfig;
namespace {

TargetConfig MakeConfig(unsigned count) {
    TargetConfig config;
    unsigned size = 0;
    if (!HvTargetsSize(count, &size)) return config;
    config.data.resize(size);
    HvTargetsWrite32(config.data.data(), count);
    for (unsigned i = 0; i < count; ++i) {
        const GUID guid{i + 1, 0, 0, {}};
        auto* entry = config.data.data() + 4 + i * HV_TARGET_ENTRY_SIZE;
        std::memcpy(entry, &guid, sizeof(guid));
        HvTargetsWrite64(entry + 16, 0x1000ull + i);
    }
    return config;
}

struct FakeRegistry {
    DWORD version = HV_TARGET_CONFIG_VERSION, allowed = 1;
    std::vector<unsigned char> bytes = MakeConfig(3).data;
    bool grow_once = false, grow_always = false, shrink_once = false, oversize_reply = false;
    LSTATUS binary_error = ERROR_SUCCESS;
    unsigned probes = 0, reads = 0;
} registry;

LSTATUS ReadFake(const wchar_t* name, DWORD flags, void* data, DWORD* size) {
    const bool version = std::wcscmp(name, L"ConfigVersion") == 0;
    const bool allowed = std::wcscmp(name, L"AllowBindings") == 0;
    if (version || allowed) {
        if (flags != RRF_RT_REG_DWORD || !data || *size < sizeof(DWORD)) return ERROR_INVALID_PARAMETER;
        const DWORD value = version ? registry.version : registry.allowed;
        std::memcpy(data, &value, sizeof(value));
        *size = sizeof(value);
        return ERROR_SUCCESS;
    }
    if (std::wcscmp(name, L"TargetAdapters") != 0 || flags != RRF_RT_REG_BINARY) return ERROR_INVALID_PARAMETER;
    if (registry.binary_error != ERROR_SUCCESS) return registry.binary_error;
    if (!data) {
        ++registry.probes;
        *size = static_cast<DWORD>(registry.bytes.size());
        return ERROR_SUCCESS;
    }
    ++registry.reads;
    if (registry.grow_once || registry.grow_always) {
        registry.bytes = MakeConfig(HvTargetsRead32(registry.bytes.data()) + 1).data;
        registry.grow_once = false;
    }
    if (registry.shrink_once) {
        registry.bytes = MakeConfig(1).data;
        registry.shrink_once = false;
    }
    const DWORD capacity = *size;
    *size = static_cast<DWORD>(registry.bytes.size());
    if (capacity < *size) return ERROR_MORE_DATA;
    std::memcpy(data, registry.bytes.data(), *size);
    if (registry.oversize_reply) *size = capacity + 1;
    return ERROR_SUCCESS;
}
} // namespace

int main() {
    // Pure shared-codec tests and fake registry callbacks only. Never open a
    // production registry key, NETIO adapter, driver device or readiness event.
    unsigned size = 77;
    CHECK(HvTargetsSize(0, &size) && size == 4);
    CHECK(HvTargetsSize(1, &size) && size == 28);
    CHECK(HvTargetsSize(3, &size) && size == 76);
    const unsigned max_count = (~0u - 4u) / HV_TARGET_ENTRY_SIZE;
    CHECK(HvTargetsSize(max_count, &size));
    const unsigned unchanged = size;
    CHECK(!HvTargetsSize(max_count + 1, &size) && size == unchanged);
    CHECK(!HvTargetsSize(~0u, &size) && size == unchanged);

    const auto empty = MakeConfig(0);
    const GUID candidate{1, 0, 0, {}};
    CHECK(empty.data.size() == 4 && HvTargetsValid(empty.data.data(), 4));
    CHECK(!empty.Matches(candidate, 0x1000));
    for (const unsigned count : {1u, 2u, 3u, 129u, 3000u}) {
        const auto config = MakeConfig(count);
        CHECK(HvTargetsValid(config.data.data(), static_cast<unsigned>(config.data.size())));
        const GUID first{1, 0, 0, {}}, last{count, 0, 0, {}}, foreign{count + 1, 0, 0, {}};
        CHECK(config.Matches(first, 0x1000));
        CHECK(config.Matches(last, 0x1000ull + count - 1));
        CHECK(!config.Matches(first, 0));
        CHECK(!config.Matches(foreign, 0x1000));
        CHECK(!config.Matches(last, 0x1000ull + count));
    }
    auto config = MakeConfig(3);
    HvTargetsWrite64(config.data.data() + 20, 0x0123456789abcdefull);
    CHECK(config.data[20] == 0xef && config.data[27] == 0x01);
    CHECK(!HvTargetsValid(nullptr, 76));
    CHECK(!HvTargetsValid(config.data.data(), 3));
    CHECK(!HvTargetsValid(config.data.data(), 75));
    CHECK(!HvTargetsValid(config.data.data(), 77));
    for (const unsigned count : {0u, 2u, ~0u}) {
        auto bad = config;
        HvTargetsWrite32(bad.data.data(), count);
        CHECK(!HvTargetsValid(bad.data.data(), static_cast<unsigned>(bad.data.size())));
    }
    for (const unsigned offset : {4u, 28u, 52u}) {
        auto bad = config;
        std::fill_n(bad.data.data() + offset, 16, static_cast<unsigned char>(0));
        CHECK(!HvTargetsValid(bad.data.data(), 76));
        bad = config;
        HvTargetsWrite64(bad.data.data() + offset + 16, 0);
        CHECK(!HvTargetsValid(bad.data.data(), 76));
    }
    auto bad = config;
    std::copy_n(bad.data.data() + 4, 16, bad.data.data() + 52);
    CHECK(!HvTargetsValid(bad.data.data(), 76));
    bad = config;
    HvTargetsWrite64(bad.data.data() + 68, HvTargetsRead64(bad.data.data() + 20));
    CHECK(!HvTargetsValid(bad.data.data(), 76));

    TargetConfig output = MakeConfig(1);
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_SUCCESS);
    CHECK(output.data == registry.bytes && registry.probes == 1 && registry.reads == 1);
    registry = {};
    registry.bytes = empty.data;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_SUCCESS);
    CHECK(output.data == empty.data && !output.Matches(candidate, 0x1000));
    registry = {};
    registry.bytes = MakeConfig(3000).data;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_SUCCESS && output.data.size() > 65536);
    CHECK(output.data == registry.bytes);
    registry = {};
    registry.grow_once = true;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_SUCCESS);
    CHECK(output.data == registry.bytes && registry.probes == 2 && registry.reads == 2);
    registry = {};
    registry.shrink_once = true;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_SUCCESS && output.data.size() == 28);

    const auto retained = output.data;
    registry = {};
    registry.grow_always = true;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_RETRY);
    CHECK(output.data == retained && registry.reads == 3);
    for (DWORD version : {0ul, 2ul}) {
        registry = {};
        registry.version = version;
        CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && output.data == retained);
        CHECK(registry.probes == 0);
    }
    registry = {};
    registry.allowed = 0;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && output.data == retained);
    CHECK(ReadTargetConfig(output, false, ReadFake) == ERROR_SUCCESS);
    output.data = retained;
    registry.allowed = 2;
    CHECK(ReadTargetConfig(output, false, ReadFake) == ERROR_INVALID_DATA && output.data == retained);
    for (LSTATUS error : {ERROR_FILE_NOT_FOUND, ERROR_UNSUPPORTED_TYPE}) {
        registry = {};
        registry.binary_error = error;
        CHECK(ReadTargetConfig(output, true, ReadFake) == error && output.data == retained);
    }
    registry = {};
    registry.bytes.pop_back();
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && output.data == retained);
    registry = {};
    HvTargetsWrite32(registry.bytes.data(), ~0u);
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && output.data == retained);
    registry = {};
    registry.oversize_reply = true;
    CHECK(ReadTargetConfig(output, true, ReadFake) == ERROR_INVALID_DATA && output.data == retained);
    std::puts("PASS dynamic ICS allowlist codec, >64KiB registry reads, sizing/churn and fail-closed validation");
    return 0;
}
