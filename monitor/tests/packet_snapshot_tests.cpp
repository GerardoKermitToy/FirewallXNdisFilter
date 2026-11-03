#include "wfp_fake_api.h"
#include "../../driver/shim/packet_snapshot.h"
#include <cstdio>
#include <cstdlib>

#define CHECK(test) do { if (!(test)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #test); std::abort(); } } while (0)

static void CheckContiguous() {
    for (ULONG length : {14u, 319u, 320u, 321u, 1500u}) {
        std::vector<UCHAR> source(length + 10, 0xa5), scratch(322, 0x5a);
        for (ULONG i = 0; i != length; ++i) source[3 + i] = static_cast<UCHAR>(i);
        const auto original = source;
        MDL mdl{nullptr, source.data(), static_cast<ULONG>(source.size()), TRUE};
        NET_BUFFER nb{nullptr, &mdl, 3, length};
        ULONG copied = 0, frame = 0;
        hv_wfp_fake::packet_work = {};
        CHECK(HvSnapshotView(&nb, nullptr, 320, &copied, &frame) == source.data() + 3);
        CHECK(copied == std::min(length, 320u) && frame == length);
        CHECK(HvSnapshotView(&nb, scratch.data() + 1, 320, &copied, &frame) == source.data() + 3);
        CHECK(std::all_of(scratch.begin(), scratch.end(), [](UCHAR b) { return b == 0x5a; }));
        CHECK(hv_wfp_fake::packet_work.data_requests == 2 && hv_wfp_fake::packet_work.copied_bytes == 0);
        CHECK(HvSnapshotCopy(&nb, scratch.data() + 1, 320, &copied, &frame) == 1);
        CHECK(std::equal(source.begin() + 3, source.begin() + 3 + copied, scratch.begin() + 1));
        CHECK(scratch.front() == 0x5a && scratch[copied + 1] == 0x5a);
        CHECK(hv_wfp_fake::packet_work.copied_bytes == copied);
        CHECK(source == original && nb.CurrentMdl == &mdl && nb.CurrentMdlOffset == 3 && nb.DataLength == length);
    }
}

static void CheckEverySplit() {
    for (ULONG length : {28u, 320u, 1500u}) {
        const ULONG cap = std::min(length, 320u);
        for (ULONG split = 0; split <= cap; ++split) {
            std::vector<UCHAR> source(length + 10, 0xa5), scratch(cap + 2, 0x5a);
            for (ULONG i = 0; i != length; ++i) source[3 + i] = static_cast<UCHAR>(i * 19);
            const auto original = source;
            MDL tail{nullptr, source.data() + 3 + split, length + 7 - split, TRUE};
            MDL head{&tail, source.data(), 3 + split, TRUE};
            NET_BUFFER nb{nullptr, &head, 3, length};
            ULONG copied = 17, frame = 0;
            hv_wfp_fake::packet_work = {};
            const auto* data = HvSnapshotView(&nb, nullptr, 320, &copied, &frame);
            CHECK(frame == length);
            if (split != 0 && split != cap) CHECK(data == nullptr && copied == 0);
            else CHECK(data == source.data() + 3 && copied == cap);
            CHECK(hv_wfp_fake::packet_work.copied_bytes == 0);
            data = HvSnapshotView(&nb, scratch.data() + 1, 320, &copied, &frame);
            CHECK(data != nullptr && copied == cap && frame == length);
            CHECK(std::equal(source.begin() + 3, source.begin() + 3 + cap, data));
            CHECK(hv_wfp_fake::packet_work.copied_bytes == (split != 0 && split != cap ? cap : 0));
            CHECK(HvSnapshotCopy(&nb, scratch.data() + 1, 320, &copied, &frame) == 1);
            CHECK(std::equal(source.begin() + 3, source.begin() + 3 + cap, scratch.begin() + 1));
            CHECK(scratch.front() == 0x5a && scratch.back() == 0x5a && source == original);
            CHECK(nb.CurrentMdl == &head && nb.CurrentMdlOffset == 3 && nb.DataLength == length);
            CHECK(head.Next == &tail && head.Length == 3 + split && tail.Next == nullptr);
        }
    }
}

static void CheckEmptyMdlsAndFailures() {
    std::array<UCHAR, 40> bytes{}, scratch{};
    MDL data{nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), TRUE};
    MDL empty{&data, nullptr, 0, FALSE};
    MDL head{&empty, bytes.data(), 3, FALSE};
    NET_BUFFER nb{nullptr, &head, 3, static_cast<ULONG>(bytes.size())};
    ULONG copied = 17, frame = 17;
    CHECK(HvSnapshotView(&nb, nullptr, 320, &copied, &frame) == bytes.data());
    CHECK(copied == bytes.size() && frame == bytes.size());
    for (unsigned failure = 0; failure != 5; ++failure) {
        MDL tail{nullptr, bytes.data() + 20, 20, TRUE};
        MDL first{&tail, bytes.data(), 20, TRUE};
        NET_BUFFER broken{nullptr, &first, 0, 40};
        if (failure == 0) first.Mappable = FALSE;
        if (failure == 1) tail.Mappable = FALSE;
        if (failure == 2) first.Next = nullptr;
        if (failure == 3) broken.CurrentMdlOffset = 21;
        if (failure == 4) broken.CurrentMdl = nullptr;
        CHECK(HvSnapshotView(&broken, nullptr, 320, &copied, &frame) == nullptr && copied == 0);
        CHECK(HvSnapshotView(&broken, scratch.data(), 320, &copied, &frame) == nullptr && copied == 0);
        CHECK(HvSnapshotCopy(&broken, scratch.data(), 320, &copied, &frame) == 0 && copied == 0);
    }
    hv_wfp_fake::packet_work = {};
    CHECK(HvSnapshotView(nullptr, nullptr, 320, &copied, &frame) == nullptr && copied == 0 && frame == 0);
    CHECK(HvSnapshotView(&nb, nullptr, 0, &copied, &frame) == nullptr && copied == 0 && frame == bytes.size());
    CHECK(HvSnapshotCopy(&nb, nullptr, 320, &copied, &frame) == 0 && copied == 0);
    nb.DataLength = 0;
    CHECK(HvSnapshotView(&nb, nullptr, 320, &copied, &frame) == nullptr && copied == 0 && frame == 0);
    CHECK(hv_wfp_fake::packet_work.data_requests == 0);
}

int main() {
    CheckContiguous();
    CheckEverySplit();
    CheckEmptyMdlsAndFailures();
    std::puts("PASS borrowed bounded prefixes, owned captures, all splits, guards and failure paths");
}
