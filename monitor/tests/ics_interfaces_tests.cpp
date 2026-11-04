#include "IcsInterfaces.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <limits>
#include <new>
#include <thread>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return false; } } while (false)

namespace {
std::vector<uint32_t> public_indices;
bool query_available = true, query_oom = false;
unsigned query_calls = 0;

bool FakeQuery(std::vector<uint32_t>& indices, std::string& error) {
    ++query_calls;
    if (query_oom) throw std::bad_alloc();
    indices = public_indices;
    if (!query_available) {
        error = "fake ICS discovery failure";
        return false;
    }
    error.clear();
    return true;
}

bool TestPublicIdentitySnapshot() {
    public_indices = {77, 42, 77, std::numeric_limits<uint32_t>::max()};
    query_available = true;
    query_oom = false;
    query_calls = 0;
    pmkext::monitor::IcsInterfaces ics(FakeQuery);
    CHECK(query_calls == 0 && ics.Snapshot().empty());
    std::string error;
    bool changed = false;
    CHECK(ics.Refresh(error, changed) && changed && error.empty());
    CHECK(query_calls == 1);
    CHECK((ics.Snapshot() == std::vector<uint32_t>{42, 77, std::numeric_limits<uint32_t>::max()}));
    CHECK(ics.IsPublic(42) && ics.IsPublic(77) && ics.IsPublic(std::numeric_limits<uint32_t>::max()));
    CHECK(!ics.IsPublic(0) && !ics.IsPublic(7) && !ics.IsPublic(8));
    public_indices = {42, std::numeric_limits<uint32_t>::max(), 77};
    CHECK(ics.Refresh(error, changed) && !changed);
    CHECK(query_calls == 2);
    return true;
}

bool TestRefreshFailureAndRecovery() {
    pmkext::monitor::IcsInterfaces ics(FakeQuery);
    public_indices = {41};
    std::string error;
    bool changed = false;
    CHECK(ics.Refresh(error, changed) && ics.IsPublic(41));
    // Even a provider that returns partial results before failing must not
    // retain a stale public role or publish the partial replacement.
    public_indices = {99};
    query_available = false;
    CHECK(!ics.Refresh(error, changed) && changed && !error.empty());
    CHECK(!ics.IsPublic(41) && !ics.IsPublic(99) && ics.Snapshot().empty());
    CHECK(!ics.Refresh(error, changed) && !changed);
    query_available = true;
    CHECK(ics.Refresh(error, changed) && changed && error.empty() && ics.IsPublic(99));
    query_oom = true;
    CHECK(!ics.Refresh(error, changed) && changed && ics.Snapshot().empty());
    query_oom = false;
    public_indices = {0, 99};
    CHECK(!ics.Refresh(error, changed) && !error.empty() && ics.Snapshot().empty());
    public_indices.clear();
    CHECK(ics.Refresh(error, changed) && !changed && error.empty());
    return true;
}

bool TestNoInterfaceCountQuota() {
    public_indices.clear();
    for (uint32_t index = 1; index <= 257; ++index) public_indices.push_back(index * 13);
    pmkext::monitor::IcsInterfaces ics(FakeQuery);
    std::string error;
    bool changed = false;
    CHECK(ics.Refresh(error, changed) && changed && ics.Snapshot().size() == public_indices.size());
    for (uint32_t index : public_indices) CHECK(ics.IsPublic(index));
    CHECK(!ics.IsPublic(8));
    return true;
}

bool TestConcurrentSnapshotPublication() {
    public_indices = {41, 43};
    pmkext::monitor::IcsInterfaces ics(FakeQuery);
    std::string error;
    bool changed = false;
    CHECK(ics.Refresh(error, changed));
    std::atomic<bool> done{false}, valid{true};
    std::thread reader([&]() {
        while (!done.load()) {
            const auto snapshot = ics.Snapshot();
            if (snapshot != std::vector<uint32_t>{41, 43} && snapshot != std::vector<uint32_t>{42})
                valid.store(false);
            if (ics.IsPublic(0) || ics.IsPublic(7)) valid.store(false);
        }
    });
    for (unsigned iteration = 0; iteration < 1000; ++iteration) {
        public_indices = iteration % 2 ? std::vector<uint32_t>{41, 43} : std::vector<uint32_t>{42};
        if (!ics.Refresh(error, changed)) valid.store(false);
    }
    done.store(true);
    reader.join();
    CHECK(valid.load());
    return true;
}
} // namespace

int main() {
    const struct { const char* name; bool (*run)(); } tests[] = {
        {"public interface identity without a fixed index", TestPublicIdentitySnapshot},
        {"refresh, failed discovery, OOM and recovery", TestRefreshFailureAndRecovery},
        {"no fixed public interface count quota", TestNoInterfaceCountQuota},
        {"atomic complete snapshots for concurrent readers", TestConcurrentSnapshotPublication},
    };
    for (const auto& test : tests) {
        if (!test.run()) return 1;
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
