#include "../../driver/shim/wfp_contract.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>

#define CHECK(test) do { if (!(test)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #test); std::abort(); } } while (0)

struct Counts {
    std::atomic<int> ndis{0}, clones{0}, reassembled{0}, injections{0}, synchronous{0};
};
struct Nbl {
    HV_PACKET_OWNER owner;
    Counts* counts;
};
static void Complete(Nbl* nbl, bool allow) {
    Counts* counts = nbl->counts;
    if (nbl->owner == HvOwnerNdis) ++counts->ndis;
    else {
        if (allow) ++counts->injections;
        if (nbl->owner == HvOwnerWfpClone) ++counts->clones;
        else { CHECK(nbl->owner == HvOwnerWfpReassembled); ++counts->reassembled; }
    }
    delete nbl;
}
static void Synchronous(Nbl* nbl, unsigned decision) {
    ++nbl->counts->synchronous;
    Complete(nbl, decision == 0);
}
static void CheckOwner(const Counts& counts, HV_PACKET_OWNER owner) {
    CHECK(counts.ndis == (owner == HvOwnerNdis ? 1 : 0));
    CHECK(counts.clones == (owner == HvOwnerWfpClone ? 1 : 0));
    CHECK(counts.reassembled == (owner == HvOwnerWfpReassembled ? 1 : 0));
}
int main() {
    CHECK(HV_FORWARD_SOURCE_DIRECTION == 0);
    unsigned char ip[20] = {};
    ip[0] = 0x45; ip[2] = 5; ip[3] = 220;
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 1500, false));
    ip[6] = 0x20;
    CHECK(HvForwardDiagnosticIpv4Fragment(ip, 1500, false));
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 1500, true));
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 1499, false));
    CHECK(!HvForwardDiagnosticIpv4Fragment(nullptr, 1500, false));
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 19, false));
    ip[6] = 0; ip[7] = 1;
    CHECK(HvForwardDiagnosticIpv4Fragment(ip, 1500, false));
    ip[6] = 0x40; ip[7] = 0;
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 1500, false));
    ip[6] = 0x20; ip[0] = 0x60;
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 1500, false));
    ip[0] = 0x44;
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 1500, false));
    ip[0] = 0x4f; ip[2] = 0; ip[3] = 40;
    CHECK(!HvForwardDiagnosticIpv4Fragment(ip, 1500, false));
    for (auto owner : {HvOwnerNdis, HvOwnerWfpClone, HvOwnerWfpReassembled}) {
        for (bool allow : {false, true}) {
            Counts synchronous;
            HvFinishClassifyPacket(new Nbl{owner, &synchronous}, allow ? 0 : 1, Synchronous);
            CheckOwner(synchronous, owner);
            CHECK(synchronous.synchronous == 1);

            Counts early;
            auto* nbl = new Nbl{owner, &early};
            Complete(nbl, allow);
            HvFinishClassifyPacket(nbl, -1, Synchronous);
            CheckOwner(early, owner);
            CHECK(early.synchronous == 0);
        }
    }
    // Pending publication must not inspect NBL/context storage, including while
    // a verdict completes that NBL. No CAS token or generation is required.
    for (int i = 0; i != 512; ++i) {
        Counts counts;
        auto owner = static_cast<HV_PACKET_OWNER>(i % 3);
        auto* nbl = new Nbl{owner, &counts};
        std::thread verdict([=] {
            if (i & 1) std::this_thread::yield();
            Complete(nbl, (i & 2) != 0);
        });
        if (i & 4) std::this_thread::yield();
        HvFinishClassifyPacket(nbl, -1, Synchronous);
        verdict.join();
        CheckOwner(counts, owner);
        CHECK(counts.synchronous == 0);
    }
    std::puts("PASS direct NBL publication, early verdicts, inline NDIS/WFP completion and ownership routes");
    return 0;
}
