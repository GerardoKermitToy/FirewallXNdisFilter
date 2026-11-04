#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace pmkext::monitor {

// Read-only user-mode ICS discovery. Names, addresses and routes do not establish
// the public/upstream role; connection GUIDs are resolved through NETIO.
bool QueryPublicIcsInterfaces(std::vector<uint32_t>& indices, std::string& error);

class IcsInterfaces {
public:
    using Query = bool (*)(std::vector<uint32_t>&, std::string&);
    explicit IcsInterfaces(Query query = QueryPublicIcsInterfaces) : query_(query) {}

    // Call on the monitor's control thread. Failed discovery clears stale roles.
    bool Refresh(std::string& error, bool& changed);
    bool IsPublic(uint32_t interface_index) const;
    std::vector<uint32_t> Snapshot() const;

private:
    Query query_;
    mutable std::mutex mutex_;
    std::vector<uint32_t> indices_;
};

} // namespace pmkext::monitor
