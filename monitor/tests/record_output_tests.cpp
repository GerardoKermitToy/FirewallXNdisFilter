// FirewallXNdisFilter adaptation, 2026-10-25: keep test files in the build directory.
// Original source provenance/license: ../README.md and ../LICENSE.
#include "RecordOutput.h"
#include "DriverProtocol.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <cstdio>
#include <future>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using File = std::unique_ptr<FILE, decltype(&std::fclose)>;

std::string ReadOutput(FILE* file) {
    std::rewind(file);
    std::string text;
    char buffer[1024];
    while (const size_t count = std::fread(buffer, 1, sizeof(buffer), file)) {
        text.append(buffer, count);
    }
    return text;
}

void Emit(FILE* file, std::mutex& mutex, const char* format, ...) {
    pmkext::RecordOutput record(file, mutex);
    va_list args;
    va_start(args, format);
    record.WriteV(format, args);
    va_end(args);
}

bool CheckFormattingAndNullOutput() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    Emit(file.get(), mutex, "[VERDICT] id=%llu -> %s\n", 1234567890123ULL, "Accept");
    if (ReadOutput(file.get()) != "[VERDICT] id=1234567890123 -> Accept\n") return false;
    {
        pmkext::RecordOutput record(nullptr, mutex);
        record.Write("ignored %u\n", 1u);
    }
    std::unique_lock<std::mutex> lock(mutex, std::try_to_lock);
    return lock.owns_lock();
}

bool CheckConnectionInterfaceIndices() {
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    std::string expected;
    pmkext::Connection c;
    c.id = 1234567890123ULL;
    c.protocol = 17;
    c.local_port = 12345;
    c.remote_port = 53;
    for (bool ipv6 : {false, true}) {
        c.ipv6 = ipv6;
        c.direction = ipv6 ? 1 : 0;
        c.payload_size = ipv6 ? 48 : 28;
        c.local_ip[0] = c.remote_ip[0] = ipv6 ? 0x20 : 10;
        c.local_ip[1] = c.remote_ip[1] = ipv6 ? 1 : 0;
        c.local_ip[3] = c.remote_ip[3] = 0;
        c.local_ip[ipv6 ? 15 : 3] = 1;
        c.remote_ip[ipv6 ? 15 : 3] = 2;
        const char* prefix = ipv6 ? "[12:34:56] " : "";
        const char* local = ipv6 ? "2001:0000:0000:0000:0000:0000:0000:0001" : "10.0.0.1";
        const char* remote = ipv6 ? "2001:0000:0000:0000:0000:0000:0000:0002" : "10.0.0.2";
        for (const uint32_t index : {0u, 101u, 0x87654321u, 101u, 0xffffffffu}) {
            c.interface_index = index;
            {
                pmkext::RecordOutput record(file.get(), mutex);
                record.WriteConnection(c, prefix);
            }
            expected += std::string(prefix) + "[CONN " + (ipv6 ? "v6" : "v4") +
                "] id=1234567890123 interface_index=" + std::to_string(index) +
                (ipv6 ? " inbound" : " outbound") + " proto=17(UDP) layer=3(network)\n" +
                "          local=" + local + ":12345  remote=" + remote +
                ":53  payload=" + (ipv6 ? "48" : "28") + " bytes\n";
        }
    }
    return ReadOutput(file.get()) == expected;
}

bool CheckConnectionsPreserveDriverOrientation() {
    pmkext::Connection c;
    c.id = 101;
    c.interface_index = 42;
    c.protocol = 6;
    c.local_port = 80;
    c.remote_port = 28436;
    c.payload.resize(pmkext::wire::kMaxPayloadSize, 0xA5);
    c.payload_size = static_cast<uint32_t>(c.payload.size());
    const auto* payload = c.payload.data();
    std::mutex mutex;
    for (bool ipv6 : {false, true}) {
        c.ipv6 = ipv6;
        std::memset(c.local_ip, 0, sizeof(c.local_ip));
        std::memset(c.remote_ip, 0, sizeof(c.remote_ip));
        c.local_ip[0] = ipv6 ? 0x20 : 203;
        c.remote_ip[0] = ipv6 ? 0x20 : 192;
        c.local_ip[1] = c.remote_ip[1] = ipv6 ? 1 : 0;
        c.local_ip[ipv6 ? 15 : 3] = 80;
        c.remote_ip[ipv6 ? 15 : 3] = 26;
        const std::string raw_local = c.LocalIpString(), raw_remote = c.RemoteIpString();
        for (uint8_t direction : {uint8_t{0}, uint8_t{1}, uint8_t{7}}) {
            c.direction = direction;
            File file(std::fopen("record_output_orientation.tmp", "w+b"), std::fclose);
            if (!file) return false;
            {
                pmkext::RecordOutput output(file.get(), mutex);
                output.WriteConnection(c, "[time] ");
            }
            const char* raw_direction = direction == 0 ? "outbound" : direction == 1 ? "inbound" : "unknown";
            const auto expected = std::string("[time] [CONN ") + (ipv6 ? "v6" : "v4") +
                "] id=101 interface_index=42 " + raw_direction + " proto=6(TCP) layer=3(network)\n" +
                "          local=" + raw_local + ":80  remote=" + raw_remote +
                ":28436  payload=" + std::to_string(c.payload_size) + " bytes\n";
            if (ReadOutput(file.get()) != expected) return false;
            if (c.direction != direction || c.LocalIpString() != raw_local || c.RemoteIpString() != raw_remote ||
                c.local_port != 80 || c.remote_port != 28436 || c.id != 101 || c.interface_index != 42 ||
                c.payload.data() != payload || c.payload.size() != pmkext::wire::kMaxPayloadSize ||
                !std::all_of(c.payload.begin(), c.payload.end(), [](uint8_t byte) { return byte == 0xA5; })) return false;
        }
    }
    return true;
}

bool CheckBandwidthPreservesEndpointsAndCounters() {
    std::mutex mutex;
    for (bool ipv6 : {false, true}) {
        pmkext::BandwidthEntry entry;
        entry.ipv6 = ipv6;
        entry.local_ip[0] = ipv6 ? 0x20 : 203;
        entry.remote_ip[0] = ipv6 ? 0x20 : 192;
        entry.local_ip[1] = entry.remote_ip[1] = ipv6 ? 1 : 0;
        entry.local_ip[ipv6 ? 15 : 3] = 80;
        entry.remote_ip[ipv6 ? 15 : 3] = 26;
        entry.local_port = 80;
        entry.remote_port = 28436;
        const std::string local = entry.LocalIpString(), remote = entry.RemoteIpString();
        for (uint64_t tx : {uint64_t{381}, std::numeric_limits<uint64_t>::max()}) {
            entry.transmitted_bytes = tx;
            entry.received_bytes = tx == 381 ? 0 : tx - 1;
            const auto rx = entry.received_bytes;
            File file(std::fopen("record_output_orientation.tmp", "w+b"), std::fclose);
            if (!file) return false;
            {
                pmkext::RecordOutput output(file.get(), mutex);
                output.WriteBandwidthEntry(entry);
            }
            const auto expected = "            " + local + ":80 <-> " + remote + ":28436  tx=" +
                std::to_string(tx) + " rx=" + std::to_string(rx) + "\n";
            if (ReadOutput(file.get()) != expected || entry.LocalIpString() != local || entry.RemoteIpString() != remote ||
                entry.local_port != 80 || entry.remote_port != 28436 ||
                entry.transmitted_bytes != tx || entry.received_bytes != rx) return false;
        }
    }
    return true;
}

bool CheckWholeRecordLock() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    std::promise<bool> attempted;
    auto attempt = attempted.get_future();
    std::thread contender;
    bool locked_for_record = false;
    {
        pmkext::RecordOutput record(file.get(), mutex);
        record.Write("[CONN] id=13\n");
        contender = std::thread([&]() {
            const bool acquired = mutex.try_lock();
            if (acquired) mutex.unlock();
            attempted.set_value(acquired);
            Emit(file.get(), mutex, "[VERDICT] id=12\n");
        });
        if (attempt.wait_for(2s) == std::future_status::ready) {
            locked_for_record = !attempt.get();
        }
        record.Write("  payload: 1234\n");
        record.Write("  -> verdict Accept scheduled\n");
    }
    contender.join();
    return locked_for_record && ReadOutput(file.get()) ==
        "[CONN] id=13\n  payload: 1234\n  -> verdict Accept scheduled\n[VERDICT] id=12\n";
}

bool CheckExceptionReleasesLock() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    try {
        pmkext::RecordOutput record(file.get(), mutex);
        record.Write("first\n");
        throw std::runtime_error("test unwind");
    } catch (const std::runtime_error&) {
    }
    std::unique_lock<std::mutex> lock(mutex, std::try_to_lock);
    if (!lock.owns_lock()) return false;
    lock.unlock();
    Emit(file.get(), mutex, "second\n");
    return ReadOutput(file.get()) == "first\nsecond\n";
}

bool CheckConcurrentRecords() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    constexpr unsigned kItems = 250;
    std::vector<std::thread> producers;
    for (unsigned producer = 0; producer < 4; ++producer) {
        producers.emplace_back([&, producer]() {
            for (unsigned item = 0; item < kItems; ++item) {
                if (producer < 2) {
                    pmkext::RecordOutput record(file.get(), mutex);
                    record.Write("[CONN] p=%u i=%u\n", producer, item);
                    std::this_thread::yield();
                    record.Write("  payload=%u/%u\n", producer, item);
                    std::this_thread::yield();
                    record.Write("  verdict=%u/%u\n", producer, item);
                } else if (producer == 2) {
                    pmkext::RecordOutput record(file.get(), mutex);
                    record.Write("[BANDWIDTH] p=%u i=%u entries=2\n", producer, item);
                    std::this_thread::yield();
                    record.Write("  row=0 value=%u\n", item);
                    std::this_thread::yield();
                    record.Write("  row=1 value=%u\n", item);
                } else {
                    Emit(file.get(), mutex, "[VERDICT] p=%u i=%u\n", producer, item);
                }
            }
        });
    }
    for (auto& producer : producers) producer.join();
    std::istringstream stream(ReadOutput(file.get()));
    bool seen[4][kItems] = {};
    unsigned records = 0;
    std::string line;
    while (std::getline(stream, line)) {
        unsigned producer = 0;
        unsigned item = 0;
        if (std::sscanf(line.c_str(), "[CONN] p=%u i=%u", &producer, &item) == 2) {
            if (producer >= 2 || item >= kItems || seen[producer][item]) return false;
            const std::string tag = std::to_string(producer) + "/" + std::to_string(item);
            if (!std::getline(stream, line) || line != "  payload=" + tag) return false;
            if (!std::getline(stream, line) || line != "  verdict=" + tag) return false;
        } else if (std::sscanf(line.c_str(), "[BANDWIDTH] p=%u i=%u entries=2", &producer, &item) == 2) {
            if (producer != 2 || item >= kItems || seen[producer][item]) return false;
            if (!std::getline(stream, line) || line != "  row=0 value=" + std::to_string(item)) return false;
            if (!std::getline(stream, line) || line != "  row=1 value=" + std::to_string(item)) return false;
        } else if (std::sscanf(line.c_str(), "[VERDICT] p=%u i=%u", &producer, &item) == 2) {
            if (producer != 3 || item >= kItems || seen[producer][item]) return false;
        } else {
            return false;
        }
        seen[producer][item] = true;
        ++records;
    }
    return records == 4 * kItems;
}

int main() {
    const struct {
        const char* name;
        bool (*run)();
    } tests[] = {
        {"formatting and null output", CheckFormattingAndNullOutput},
        {"IPv4/IPv6 connection output includes each unsigned interface index after id", CheckConnectionInterfaceIndices},
        {"direction/endpoints and 1 MiB payload preserve driver data", CheckConnectionsPreserveDriverOrientation},
        {"IPv4/IPv6 bandwidth endpoints and full u64 counters preserve driver data", CheckBandwidthPreservesEndpointsAndCounters},
        {"whole-record lock against a concurrent verdict", CheckWholeRecordLock},
        {"exception releases lock", CheckExceptionReleasesLock},
        {"1000 concurrent CONN/BANDWIDTH/VERDICT records", CheckConcurrentRecords},
    };
    for (const auto& test : tests) {
        if (!test.run()) {
            std::fprintf(stderr, "FAIL: %s\n", test.name);
            return 1;
        }
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
