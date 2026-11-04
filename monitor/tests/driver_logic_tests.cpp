#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include "DriverProtocol.h"
#include "../../driver/shim/driver_logic.h"
#include "../../driver/shim/target_config.h"
#include <array>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

#define CHECK(test) do { if (!(test)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #test); return false; } } while (false)

namespace {
namespace wire = pmkext::wire;
bool TestControlRequests() {
    std::array<uint8_t, 16> data{};
    uint32_t bytes = 99;
    for (auto code : {wire::kIoctlVersion, wire::kIoctlShutdown, wire::kIoctlFilteredDeviceCount, wire::kIoctlAdapterInfo}) {
        data.fill(0xa5); bytes = 99;
        CHECK(HvDeviceControl(code, 1, data.data(), 16, 7, &bytes) == STATUS_INVALID_PARAMETER);
        CHECK(bytes == 0 && std::all_of(data.begin(), data.end(), [](auto b) { return b == 0xa5; }));
    }
    for (auto code : {wire::kIoctlVersion, wire::kIoctlFilteredDeviceCount}) {
        for (uint32_t capacity = 0; capacity < 4; ++capacity) {
            data.fill(0xa5); bytes = 99;
            CHECK(HvDeviceControl(code, 0, data.data(), capacity, 0, &bytes) == STATUS_BUFFER_TOO_SMALL);
            CHECK(bytes == 0 && data[0] == 0xa5);
        }
        CHECK(HvDeviceControl(code, 0, nullptr, 4, 0, &bytes) == STATUS_INVALID_PARAMETER && bytes == 0);
    }
    data.fill(0xa5);
    CHECK(HvDeviceControl(wire::kIoctlVersion, 0, data.data() + 1, 4, 0, &bytes) == STATUS_SUCCESS);
    CHECK(bytes == 4 && data[0] == 0xa5 && data[5] == 0xa5);
    CHECK(data[1] == 0 && data[2] == 3 && data[3] == 3 && data[4] == 0);
    for (uint64_t count : {0ull, 1ull, 32ull, 2048ull, 0xffffffffull}) {
        data.fill(0xa5);
        CHECK(HvDeviceControl(wire::kIoctlFilteredDeviceCount, 0, data.data() + 1, 4, count, &bytes) == STATUS_SUCCESS);
        CHECK(bytes == 4 && data[0] == 0xa5 && data[5] == 0xa5);
        for (unsigned i = 0; i < 4; ++i) CHECK(data[i + 1] == static_cast<uint8_t>(count >> (8 * i)));
    }
    for (uint64_t count : {0x100000000ull, std::numeric_limits<uint64_t>::max()}) {
        data.fill(0xa5); bytes = 99;
        CHECK(HvDeviceControl(wire::kIoctlFilteredDeviceCount, 0, data.data(), 16, count, &bytes) == STATUS_INTEGER_OVERFLOW);
        CHECK(bytes == 0 && std::all_of(data.begin(), data.end(), [](auto b) { return b == 0xa5; }));
    }
    // Native code owns shutdown and locked snapshot staging, not this codec.
    for (auto code : {wire::kIoctlShutdown, wire::kIoctlAdapterInfo}) {
        bytes = 99;
        CHECK(HvDeviceControl(code, 0, nullptr, 0, 0, &bytes) == STATUS_SUCCESS && bytes == 0);
    }
    for (uint32_t input : {0u, 1u}) {
        bytes = 99;
        CHECK(HvDeviceControl(0xffffffffu, input, nullptr, 0, 0, &bytes) == STATUS_NOT_SUPPORTED && bytes == 0);
    }
    return true;
}
std::vector<uint8_t> Targets(uint32_t count) {
    uint32_t size = 0;
    if (!HvTargetsSize(count, &size)) return {};
    std::vector<uint8_t> data(size);
    HvTargetsWrite32(data.data(), count);
    for (uint32_t i = 0; i < count; ++i) {
        auto* entry = data.data() + 4 + i * HV_TARGET_ENTRY_SIZE;
        HvTargetsWrite32(entry, i + 1);
        HvTargetsWrite64(entry + 16, 0x1000ull + i);
    }
    return data;
}
bool TestTargetAdmission() {
    for (uint32_t count : {1u, 2u, 3u, 129u, 3000u}) {
        const auto data = Targets(count);
        for (uint32_t index : {0u, count - 1}) {
            const auto* guid = data.data() + 4 + index * HV_TARGET_ENTRY_SIZE;
            CHECK(HvTargetAdapterMatch(data.data(), static_cast<uint32_t>(data.size()), guid, 0x1000ull + index));
            CHECK(!HvTargetAdapterMatch(data.data(), static_cast<uint32_t>(data.size()), guid, 0x2000ull + index));
        }
    }
    auto data = Targets(3);
    std::array<uint8_t,16> guid{};
    std::copy_n(data.data() + 4, 16, guid.data());
    CHECK(!HvTargetAdapterMatch(nullptr, 76, guid.data(), 0x1000));
    CHECK(!HvTargetAdapterMatch(data.data(), 76, nullptr, 0x1000));
    CHECK(!HvTargetAdapterMatch(data.data(), 76, guid.data(), 0));
    CHECK(!HvTargetAdapterMatch(data.data(), 3, guid.data(), 0x1000));
    // An early matching entry must not bypass malformed later entries.
    for (unsigned failure = 0; failure < 7; ++failure) {
        auto bad = data;
        if (failure == 0) bad.pop_back();
        if (failure == 1) bad.push_back(0);
        if (failure == 2) HvTargetsWrite32(bad.data(), 0);
        if (failure == 3) HvTargetsWrite32(bad.data(), 0xffffffffu);
        if (failure == 4) std::fill_n(bad.data() + 52, 16, uint8_t{0});
        if (failure == 5) std::copy_n(bad.data() + 4, 16, bad.data() + 52);
        if (failure == 6) HvTargetsWrite64(bad.data() + 68, 0x1000);
        CHECK(!HvTargetAdapterMatch(bad.data(), static_cast<uint32_t>(bad.size()), guid.data(), 0x1000));
    }
    // Independently compiled setup/notify codec and production kernel Rust must
    // agree on complete malformed blobs; no registry or adapter calls are used.
    uint32_t random = 1234567;
    for (unsigned n = 0; n < 1000; ++n) {
        auto candidate = data;
        random = random * 1664525u + 1013904223u;
        const size_t offset = random % candidate.size();
        candidate[offset] ^= static_cast<uint8_t>(random >> 16);
        if (n % 5 == 0) candidate.resize(n % (candidate.size() + 1));
        CHECK((HvTargetAdapterMatch(candidate.data(), static_cast<uint32_t>(candidate.size()), guid.data(), 0x1000) != 0) ==
            (HvTargetsMatch(candidate.data(), static_cast<uint32_t>(candidate.size()), guid.data(), 0x1000) != 0));
    }
    return true;
}
}
int main() {
    if (!TestControlRequests() || !TestTargetAdmission()) return 1;
    std::puts("PASS production Rust IOCTL codec and kernel target admission; no device/registry access");
    return 0;
}
