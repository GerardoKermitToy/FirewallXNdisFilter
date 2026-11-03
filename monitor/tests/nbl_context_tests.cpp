#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using NDIS_PORT_NUMBER = ULONG;
using NDIS_STATUS = LONG;
constexpr NDIS_STATUS NDIS_STATUS_SUCCESS = 0;
constexpr NDIS_STATUS NDIS_STATUS_RESOURCES = static_cast<LONG>(0xc000009au);
struct alignas(16) NET_BUFFER_LIST_CONTEXT {
    NET_BUFFER_LIST_CONTEXT* Next;
    USHORT Size, Offset;
};
static_assert(sizeof(NET_BUFFER_LIST_CONTEXT) == 16);
struct NET_BUFFER_LIST { NET_BUFFER_LIST_CONTEXT* Context; };
using PNET_BUFFER_LIST = NET_BUFFER_LIST*;
#define NET_BUFFER_LIST_CONTEXT_DATA_START(nbl) \
    (reinterpret_cast<UCHAR*>((nbl)->Context + 1) + (nbl)->Context->Offset)

static unsigned Allocations, Frees;
static bool FailAllocation;
static void Check(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::abort(); }
}
static NDIS_STATUS NdisAllocateNetBufferListContext(PNET_BUFFER_LIST nbl,
    USHORT size, USHORT backfill, ULONG tag) {
    (void)tag;
    Check(size != 0 && size % sizeof(void*) == 0, "invalid context size");
    Check(backfill % sizeof(void*) == 0, "invalid context backfill");
    if (nbl->Context != nullptr && nbl->Context->Offset >= size) {
        nbl->Context->Offset -= size;
        return NDIS_STATUS_SUCCESS;
    }
    if (FailAllocation) return NDIS_STATUS_RESOURCES;
    const auto total = static_cast<unsigned>(size) + backfill;
    Check(total <= 0xffffu, "context size overflow");
    auto* context = static_cast<NET_BUFFER_LIST_CONTEXT*>(
        std::malloc(sizeof(NET_BUFFER_LIST_CONTEXT) + total));
    Check(context != nullptr, "fake allocation failed");
    context->Next = nbl->Context;
    context->Size = static_cast<USHORT>(total);
    context->Offset = backfill;
    std::memset(context + 1, 0xa5, total);
    nbl->Context = context;
    ++Allocations;
    return NDIS_STATUS_SUCCESS;
}
static void NdisFreeNetBufferListContext(PNET_BUFFER_LIST nbl, USHORT size) {
    auto* context = nbl->Context;
    Check(context != nullptr && size <= context->Size - context->Offset,
        "invalid context free");
    context->Offset += size;
    if (context->Offset == context->Size) {
        nbl->Context = context->Next;
        std::free(context);
        ++Frees;
    }
}
extern "C" __declspec(noreturn) void hv_bugcheck(void) { std::abort(); }

// These are the production allocation/access/free helpers, not a second model
// of the context layout or its initialization.
#include "../../driver/shim/nbl_context.h"

struct alignas(16) ExistingContext {
    NET_BUFFER_LIST_CONTEXT Header;
    std::array<UCHAR, 256> Data;
};
static_assert(offsetof(ExistingContext, Data) == sizeof(NET_BUFFER_LIST_CONTEXT));

static void CheckInitialized(const HV_NBL_CONTEXT* context) {
    std::array<UCHAR, sizeof(HV_NBL_CONTEXT)> expected{};
    const ULONG signature = NBL_CONTEXT_TAG;
    std::memcpy(expected.data() + offsetof(HV_NBL_CONTEXT, Signature),
        &signature, sizeof(signature));
    Check(std::memcmp(context, expected.data(), expected.size()) == 0,
        "context was not fully initialized");
}
static void CheckOwner(PNET_BUFFER_LIST nbl, HV_PACKET_OWNER owner) {
    auto* context = PacketContext(nbl);
    context->Owner = owner;
    context->Flags = 0x12345678;
    context->Direction = 1;
    context->ForwardInterface = 7;
    context->ForwardSubInterface = 19;
    context->Compartment = 3;
    context->Port = 2;
    context->Copied = TRUE;
    context->Forwarded = TRUE;
    context->Ipv6 = TRUE;
    context->Segmented = TRUE;
    Check(PacketContext(nbl) == context && context->Owner == owner &&
        context->Flags == 0x12345678 && context->Direction == 1 &&
        context->ForwardInterface == 7 && context->ForwardSubInterface == 19 && context->Compartment == 3 &&
        context->Port == 2 && context->Copied && context->Forwarded && context->Ipv6 &&
        context->Segmented,
        "context fields did not round-trip");
}
static void CheckForeignContextPushPop(PNET_BUFFER_LIST nbl, HV_NBL_CONTEXT* owned) {
    Check(NdisAllocateNetBufferListContext(nbl, sizeof(void*), 0, 0) == NDIS_STATUS_SUCCESS,
        "foreign context allocation failed");
    std::memset(NET_BUFFER_LIST_CONTEXT_DATA_START(nbl), 0x5a, sizeof(void*));
    NdisFreeNetBufferListContext(nbl, sizeof(void*));
    Check(PacketContext(nbl) == owned, "foreign context did not restore our context");
}
static void TestReusedBackfill(HV_PACKET_OWNER owner, USHORT offset) {
    ExistingContext storage{};
    storage.Data.fill(0xa5);
    const auto originalOffset = static_cast<USHORT>(offset + sizeof(HV_NBL_CONTEXT));
    storage.Header.Size = static_cast<USHORT>(storage.Data.size());
    storage.Header.Offset = originalOffset;
    NET_BUFFER_LIST nbl{&storage.Header};
    const auto before = storage.Data;
    const auto allocations = Allocations;
    auto* context = AllocatePacketContext(&nbl);
    Check(context != nullptr && Allocations == allocations, "backfill was not reused");
    Check(reinterpret_cast<UCHAR*>(context) == storage.Data.data() + offset,
        "wrong context offset");
    Check(reinterpret_cast<std::uintptr_t>(context) % alignof(void*) == 0,
        "fake did not provide pointer alignment");
    if (offset % 16 == 8) {
        Check(reinterpret_cast<std::uintptr_t>(context) % 16 == 8,
            "missing crash regression: context must be 8 mod 16");
    }
    CheckInitialized(context);
    CheckOwner(&nbl, owner);
    for (std::size_t i = 0; i != before.size(); ++i) {
        if (i < offset || i >= originalOffset)
            Check(storage.Data[i] == before[i], "foreign context/backfill was overwritten");
    }
    CheckForeignContextPushPop(&nbl, context);
    FreePacketContext(&nbl);
    Check(nbl.Context == &storage.Header && storage.Header.Offset == originalOffset,
        "free did not restore original backfill");
}
static void TestNewContext(HV_PACKET_OWNER owner, bool existing) {
    ExistingContext storage{};
    storage.Data.fill(0xa5);
    storage.Header.Size = static_cast<USHORT>(storage.Data.size());
    const auto before = storage.Data;
    NET_BUFFER_LIST nbl{existing ? &storage.Header : nullptr};
    auto* original = nbl.Context;
    const auto allocations = Allocations, frees = Frees;
    auto* context = AllocatePacketContext(&nbl);
    Check(context != nullptr && Allocations == allocations + 1,
        "new context was not allocated");
    Check(nbl.Context->Next == original, "existing context chain was lost");
    CheckInitialized(context);
    CheckOwner(&nbl, owner);
    CheckForeignContextPushPop(&nbl, context);
    FreePacketContext(&nbl);
    Check(nbl.Context == original && Frees == frees + 2,
        "allocated contexts were not freed/restored exactly once");
    Check(storage.Data == before && storage.Header.Offset == 0,
        "existing context was modified");
}
static void TestAllocationFailure(bool existing) {
    ExistingContext storage{};
    storage.Data.fill(0xa5);
    storage.Header.Size = static_cast<USHORT>(storage.Data.size());
    const auto before = storage.Data;
    NET_BUFFER_LIST nbl{existing ? &storage.Header : nullptr};
    auto* original = nbl.Context;
    const auto allocations = Allocations, frees = Frees;
    FailAllocation = true;
    Check(AllocatePacketContext(&nbl) == nullptr, "OOM did not fail closed");
    FailAllocation = false;
    Check(nbl.Context == original && Allocations == allocations && Frees == frees &&
        storage.Header.Offset == 0 && storage.Data == before,
        "OOM changed another driver's context");
}
int main() {
    static_assert(alignof(HV_NBL_CONTEXT) <= sizeof(void*));
    static_assert(sizeof(HV_NBL_CONTEXT) % sizeof(void*) == 0);
    for (auto owner : {HvOwnerNdis, HvOwnerWfpClone, HvOwnerWfpReassembled}) {
        for (USHORT offset = 0; offset <= 200; offset += sizeof(void*))
            TestReusedBackfill(owner, offset);
        TestNewContext(owner, false);
        TestNewContext(owner, true);
    }
    TestAllocationFailure(false);
    TestAllocationFailure(true);
    Check(Allocations == Frees, "context allocation leak");
    std::puts("PASS: pointer-aligned NDIS/WFP contexts, shared backfill, chained contexts and OOM");
}
