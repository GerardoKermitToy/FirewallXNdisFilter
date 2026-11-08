#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include "DriverProtocol.h"
#include "../../driver/shim/driver_logic.h"
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
        CHECK(FwxDeviceControl(code, 1, data.data(), 16, 7, &bytes) == STATUS_INVALID_PARAMETER);
        CHECK(bytes == 0 && std::all_of(data.begin(), data.end(), [](auto b) { return b == 0xa5; }));
    }
    for (auto code : {wire::kIoctlVersion, wire::kIoctlFilteredDeviceCount}) {
        for (uint32_t capacity = 0; capacity < 4; ++capacity) {
            data.fill(0xa5); bytes = 99;
            CHECK(FwxDeviceControl(code, 0, data.data(), capacity, 0, &bytes) == STATUS_BUFFER_TOO_SMALL);
            CHECK(bytes == 0 && data[0] == 0xa5);
        }
        CHECK(FwxDeviceControl(code, 0, nullptr, 4, 0, &bytes) == STATUS_INVALID_PARAMETER && bytes == 0);
    }
    data.fill(0xa5);
    CHECK(FwxDeviceControl(wire::kIoctlVersion, 0, data.data() + 1, 4, 0, &bytes) == STATUS_SUCCESS);
    CHECK(bytes == 4 && data[0] == 0xa5 && data[5] == 0xa5);
    CHECK(data[1] == 0 && data[2] == 3 && data[3] == 3 && data[4] == 0);
    for (uint64_t count : {0ull, 1ull, 32ull, 2048ull, 0xffffffffull}) {
        data.fill(0xa5);
        CHECK(FwxDeviceControl(wire::kIoctlFilteredDeviceCount, 0, data.data() + 1, 4, count, &bytes) == STATUS_SUCCESS);
        CHECK(bytes == 4 && data[0] == 0xa5 && data[5] == 0xa5);
        for (unsigned i = 0; i < 4; ++i) CHECK(data[i + 1] == static_cast<uint8_t>(count >> (8 * i)));
    }
    for (uint64_t count : {0x100000000ull, std::numeric_limits<uint64_t>::max()}) {
        data.fill(0xa5); bytes = 99;
        CHECK(FwxDeviceControl(wire::kIoctlFilteredDeviceCount, 0, data.data(), 16, count, &bytes) == STATUS_INTEGER_OVERFLOW);
        CHECK(bytes == 0 && std::all_of(data.begin(), data.end(), [](auto b) { return b == 0xa5; }));
    }
    // Native code owns shutdown and locked snapshot staging, not this codec.
    for (auto code : {wire::kIoctlShutdown, wire::kIoctlAdapterInfo}) {
        bytes = 99;
        CHECK(FwxDeviceControl(code, 0, nullptr, 0, 0, &bytes) == STATUS_SUCCESS && bytes == 0);
    }
    for (uint32_t input : {0u, 1u}) {
        bytes = 99;
        CHECK(FwxDeviceControl(0xffffffffu, input, nullptr, 0, 0, &bytes) == STATUS_NOT_SUPPORTED && bytes == 0);
    }
    return true;
}
}
int main() {
    if (!TestControlRequests()) return 1;
    std::puts("PASS production Rust IOCTL codec; no device/registry access");
    return 0;
}
