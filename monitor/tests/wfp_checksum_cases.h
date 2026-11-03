// Included by wfp_management_tests.cpp: exercise the real injection/checksum path.
struct InjectionPacket {
    std::array<UCHAR, 40> Bytes{};
    MDL Mdl{nullptr, Bytes.data(), static_cast<ULONG>(Bytes.size()), TRUE};
    NET_BUFFER Nb{nullptr, &Mdl, 0, static_cast<ULONG>(Bytes.size())};
    _NET_BUFFER_LIST Packet{&Nb, nullptr};
    explicit InjectionPacket(BOOLEAN ipv6 = FALSE) { SetFamily(ipv6); }
    void SetFamily(BOOLEAN ipv6) {
        Bytes.fill(0);
        Bytes[0] = ipv6 ? 0x60 : 0x45;
        if (ipv6) Bytes[6] = 59;
        else { Bytes[3] = static_cast<UCHAR>(Bytes.size()); Bytes[9] = 254; }
    }
};

ULONG ReferenceSum(const UCHAR* bytes, std::size_t length, ULONG seed = 0) {
    std::uint64_t sum = seed;
    for (std::size_t i = 0; i < length; ++i)
        sum += static_cast<std::uint64_t>(bytes[i]) << (i % 2 == 0 ? 8 : 0);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return static_cast<ULONG>(sum);
}
void PutWord(std::vector<UCHAR>& bytes, unsigned offset, ULONG word) {
    bytes[offset] = static_cast<UCHAR>(word >> 8);
    bytes[offset + 1] = static_cast<UCHAR>(word);
}
unsigned ChecksumField(UCHAR protocol) { return protocol == 6 ? 16 : protocol == 17 ? 6 : 2; }
ULONG PseudoSum(const std::vector<UCHAR>& bytes, BOOLEAN ipv6, UCHAR protocol, unsigned length) {
    if (!ipv6 && protocol == 1) return 0;
    return ReferenceSum(bytes.data() + (ipv6 ? 8 : 12), ipv6 ? 32 : 8) + protocol +
        (length >> 16) + (length & 0xffffu);
}
std::vector<UCHAR> CheckedDatagram(BOOLEAN ipv6, UCHAR protocol, unsigned header = 20,
    unsigned extensions = 0, unsigned payload = 17) {
    const unsigned transport = ipv6 ? 40 + extensions * 8 : header;
    const unsigned length = (protocol == 6 ? 20 : 8) + payload;
    std::vector<UCHAR> bytes(transport + length, 0);
    bytes[0] = ipv6 ? 0x60 : static_cast<UCHAR>(0x40 | header / 4);
    if (ipv6) {
        PutWord(bytes, 4, static_cast<ULONG>(bytes.size() - 40));
        bytes[6] = extensions ? 0 : protocol;
        bytes[7] = 61;
        for (unsigned i = 8; i != 40; ++i) bytes[i] = static_cast<UCHAR>(i * 3);
        for (unsigned i = 0; i != extensions; ++i)
            bytes[40 + i * 8] = i + 1 == extensions ? protocol : UCHAR{60};
    } else {
        PutWord(bytes, 2, static_cast<ULONG>(bytes.size()));
        bytes[8] = 61; bytes[9] = protocol;
        bytes[12] = 10; bytes[13] = 94; bytes[14] = 59; bytes[15] = 5;
        bytes[16] = 8; bytes[17] = 8; bytes[18] = 8; bytes[19] = 8;
        for (unsigned i = 20; i != header; ++i) bytes[i] = 1; // NOP options.
    }
    if (protocol == 6 || protocol == 17) {
        PutWord(bytes, transport, 12345); PutWord(bytes, transport + 2, 443);
        if (protocol == 6) { bytes[transport + 12] = 0x50; bytes[transport + 13] = 2; }
        else PutWord(bytes, transport + 4, length);
    } else {
        bytes[transport] = ipv6 ? 128 : 8;
        PutWord(bytes, transport + 4, 512); PutWord(bytes, transport + 6, 1);
    }
    for (unsigned i = protocol == 6 ? 20 : 8; i != length; ++i)
        bytes[transport + i] = static_cast<UCHAR>(i * 19);
    ULONG checksum = (~ReferenceSum(bytes.data() + transport, length, PseudoSum(bytes, ipv6, protocol, length))) & 0xffffu;
    if (protocol == 17 && checksum == 0) checksum = 0xffffu;
    PutWord(bytes, transport + ChecksumField(protocol), checksum);
    if (!ipv6) PutWord(bytes, 10, (~ReferenceSum(bytes.data(), header)) & 0xffffu);
    return bytes;
}

bool TestCompleteSoftwareChecksumsAcrossEveryMdlBoundary() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        for (UCHAR protocol : {UCHAR{6}, UCHAR{17}, ipv6 ? UCHAR{58} : UCHAR{1}}) {
            for (unsigned layout = 0; layout != 3; ++layout) {
                const unsigned header = layout == 0 ? 20 : layout == 1 ? 24 : 60;
                const unsigned extensions = layout == 0 ? 0 : layout == 1 ? 2 : 8;
                const unsigned transport = ipv6 ? 40 + extensions * 8 : header;
                for (unsigned payload : {0u, 17u, 18u}) {
                    const auto expected = CheckedDatagram(ipv6, protocol, header, extensions, payload);
                    for (unsigned split = 0; split <= expected.size(); ++split) {
                        for (ULONG partial : {0u, 0x1234u}) {
                            constexpr unsigned offset = 3, suffix = 7;
                            std::vector<UCHAR> storage(offset + expected.size() + suffix, 0xa5);
                            std::copy(expected.begin(), expected.end(), storage.begin() + offset);
                            if (!ipv6) { storage[offset + 10] = 0; storage[offset + 11] = 0; }
                            storage[offset + transport + ChecksumField(protocol)] = static_cast<UCHAR>(partial >> 8);
                            storage[offset + transport + ChecksumField(protocol) + 1] = static_cast<UCHAR>(partial);
                            MDL tail{nullptr, storage.data() + offset + split,
                                static_cast<ULONG>(expected.size() + suffix - split), TRUE};
                            MDL head{&tail, storage.data(), offset + split, TRUE};
                            NET_BUFFER nb{nullptr, &head, offset, static_cast<ULONG>(expected.size())};
                            _NET_BUFFER_LIST packet{&nb, reinterpret_cast<void*>(0x1f)};
                            CHECK(NT_SUCCESS(HvWfpInject(&packet, ipv6, 37, 71, 0, 0, FALSE, InjectionComplete, &packet)));
                            CHECK(std::equal(expected.begin(), expected.end(), storage.begin() + offset));
                            CHECK(std::all_of(storage.begin(), storage.begin() + offset, [](UCHAR b) { return b == 0xa5; }));
                            CHECK(std::all_of(storage.end() - suffix, storage.end(), [](UCHAR b) { return b == 0xa5; }));
                            CHECK(packet.ChecksumInfo == nullptr);
                            CHECK(nb.CurrentMdl == &head && nb.CurrentMdlOffset == offset && nb.DataLength == expected.size());
                        }
                    }
                }
            }
        }
    }
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestChecksumFailuresPreventEveryInjectionRoute() {
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        for (ULONG flags : {0u, FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU, FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU}) {
            hv_wfp_fake::Reset();
            _DRIVER_OBJECT driver{};
            CHECK(Start(&driver));
            for (unsigned failure = 0; failure != 10; ++failure) {
                auto bytes = CheckedDatagram(ipv6, 6);
                const unsigned transport = ipv6 ? 40 : 20;
                MDL tail{nullptr, bytes.data() + transport, static_cast<ULONG>(bytes.size() - transport), TRUE};
                MDL head{&tail, bytes.data(), transport, TRUE};
                NET_BUFFER nb{nullptr, &head, 0, static_cast<ULONG>(bytes.size())};
                _NET_BUFFER_LIST packet{&nb, nullptr};
                if (failure == 0) bytes[0] = ipv6 ? 0x45 : 0x60;
                if (failure == 1) nb.DataLength = ipv6 ? 39 : 19;
                if (failure == 2) head.Mappable = FALSE;
                if (failure == 3) tail.Mappable = FALSE;
                if (failure == 4) nb.CurrentMdlOffset = head.Length + 1;
                if (failure == 5) packet.FirstNb = nullptr;
                if (failure == 6) PutWord(bytes, ipv6 ? 4 : 2, 60000);
                if (failure == 7) bytes[transport + 12] = 0x40;
                if (failure == 8) tail.Length = 19;
                if (failure == 9) head.Next = nullptr;
                const auto calls = hv_wfp_fake::state().injection_calls.size();
                CHECK(HvWfpInject(&packet, ipv6, 37, 71, 19, flags, FALSE, InjectionComplete, &packet) == STATUS_DATA_ERROR);
                CHECK(hv_wfp_fake::state().injection_calls.size() == calls);
            }
            for (ULONG length : {0u, 7u, 60000u}) {
                auto bytes = CheckedDatagram(ipv6, 17);
                PutWord(bytes, (ipv6 ? 40 : 20) + 4, length);
                MDL mdl{nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), TRUE};
                NET_BUFFER nb{nullptr, &mdl, 0, static_cast<ULONG>(bytes.size())};
                _NET_BUFFER_LIST packet{&nb, nullptr};
                CHECK(HvWfpInject(&packet, ipv6, 37, 71, 19, flags, FALSE, InjectionComplete, &packet) == STATUS_DATA_ERROR);
            }
            CHECK(StopAndVerifyClean());
        }
    }
    return true;
}

bool TestFragmentsAndSegmentationDoNotInventTransportChecksums() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        for (BOOLEAN segmented : {FALSE, TRUE}) {
            auto bytes = CheckedDatagram(ipv6, 17, 20, ipv6 ? 1 : 0);
            const unsigned transport = ipv6 ? 48 : 20;
            if (ipv6) {
                if (!segmented) { bytes[6] = 44; bytes[43] = 1; }
            } else {
                bytes[10] = 0; bytes[11] = 0;
                if (!segmented) bytes[6] = 0x20;
                else PutWord(bytes, 2, 0); // Unfinished LSO IP length is not a wire length.
            }
            PutWord(bytes, transport + 6, 0x1234);
            auto expected = bytes;
            if (!ipv6) PutWord(expected, 10, (~ReferenceSum(expected.data(), 20)) & 0xffffu);
            MDL mdl{nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), TRUE};
            NET_BUFFER nb{nullptr, &mdl, 0, static_cast<ULONG>(bytes.size())};
            _NET_BUFFER_LIST packet{&nb, reinterpret_cast<void*>(0x1f)};
            CHECK(NT_SUCCESS(HvWfpInject(&packet, ipv6, 37, 71, 0, 0, segmented, InjectionComplete, &packet)));
            CHECK(bytes == expected && packet.ChecksumInfo == reinterpret_cast<void*>(0x1f));
        }
    }
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestRoutingAndAtomicFragmentPseudoHeaders() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        for (unsigned layout = 0; layout != (ipv6 ? 6u : 2u); ++layout) {
            const unsigned transport = ipv6 ? (layout == 4 ? 48 : layout == 5 ? 56 : 64) : 28;
            auto bytes = CheckedDatagram(ipv6, 17, 28, ipv6 ? (transport - 40) / 8 : 0);
            auto pseudo = bytes;
            if (!ipv6) {
                bytes[20] = layout == 0 ? 131 : 137; bytes[21] = 7; bytes[22] = 4;
                bytes[23] = 1; bytes[24] = 1; bytes[25] = 1; bytes[26] = 1; bytes[27] = 0;
                std::copy(bytes.begin() + 23, bytes.begin() + 27, pseudo.begin() + 16);
                PutWord(bytes, 10, 0);
                PutWord(bytes, 10, (~ReferenceSum(bytes.data(), 28)) & 0xffffu);
            } else {
                std::fill(bytes.begin() + 40, bytes.begin() + transport, UCHAR{0});
                bytes[40] = 17;
                if (layout < 3) {
                    bytes[6] = 43; bytes[41] = 2;
                    bytes[42] = layout == 0 ? 0 : layout == 1 ? 2 : 4;
                    bytes[43] = 1;
                    std::fill(bytes.begin() + 48, bytes.begin() + 64, UCHAR{0x77});
                    std::copy(bytes.begin() + 48, bytes.begin() + 64, pseudo.begin() + 24);
                } else if (layout == 3) {
                    bytes[6] = 60; bytes[41] = 2; bytes[42] = 201; bytes[43] = 16;
                    std::fill(bytes.begin() + 44, bytes.begin() + 60, UCHAR{0x55});
                    std::copy(bytes.begin() + 44, bytes.begin() + 60, pseudo.begin() + 8);
                } else if (layout == 4) bytes[6] = 44; // Atomic fragment, complete UDP payload.
                else { bytes[6] = 51; bytes[41] = 2; } // AH is not part of the UDP pseudo length.
            }
            PutWord(bytes, transport + 6, 0);
            ULONG checksum = (~ReferenceSum(bytes.data() + transport, bytes.size() - transport,
                PseudoSum(pseudo, ipv6, 17, static_cast<unsigned>(bytes.size() - transport)))) & 0xffffu;
            auto expected = bytes;
            PutWord(expected, transport + 6, checksum == 0 ? 0xffffu : checksum);
            for (unsigned split = 0; split <= bytes.size(); ++split) {
                MDL tail{nullptr, bytes.data() + split, static_cast<ULONG>(bytes.size() - split), TRUE};
                MDL head{&tail, bytes.data(), split, TRUE};
                NET_BUFFER nb{nullptr, &head, 0, static_cast<ULONG>(bytes.size())};
                _NET_BUFFER_LIST packet{&nb, nullptr};
                CHECK(NT_SUCCESS(HvWfpInject(&packet, ipv6, 37, 71, 0, 0, FALSE, InjectionComplete, &packet)));
                CHECK(bytes == expected);
                CHECK(nb.CurrentMdl == &head && nb.CurrentMdlOffset == 0 && nb.DataLength == bytes.size());
            }
        }
    }
    for (unsigned failure = 0; failure != 4; ++failure) {
        auto bytes = CheckedDatagram(TRUE, 17, 20, failure == 0 ? 9 : 1);
        if (failure == 1) bytes[41] = 255; // Extension beyond the IP length.
        if (failure == 2) { bytes[6] = 43; bytes[42] = 99; bytes[43] = 1; }
        if (failure == 3) { bytes[6] = 60; bytes[42] = 201; bytes[43] = 16; }
        MDL mdl{nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), TRUE};
        NET_BUFFER nb{nullptr, &mdl, 0, static_cast<ULONG>(bytes.size())};
        _NET_BUFFER_LIST packet{&nb, nullptr};
        const auto calls = hv_wfp_fake::state().injection_calls.size();
        CHECK(HvWfpInject(&packet, TRUE, 37, 71, 0, 0, FALSE, InjectionComplete, &packet) == STATUS_DATA_ERROR);
        CHECK(hv_wfp_fake::state().injection_calls.size() == calls);
    }
    CHECK(StopAndVerifyClean());
    return true;
}

bool TestMultipleBuffersOddLargePacketsAndUdpZeroChecksum() {
    hv_wfp_fake::Reset();
    _DRIVER_OBJECT driver{};
    CHECK(Start(&driver));
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        auto first = CheckedDatagram(ipv6, 17, 20, 0, ipv6 ? 65527 : 65507);
        auto second = CheckedDatagram(ipv6, 6);
        const auto firstExpected = first, secondExpected = second;
        first[(ipv6 ? 40 : 20) + 6] = 0; first[(ipv6 ? 40 : 20) + 7] = 0;
        second[(ipv6 ? 40 : 20) + 16] = 0; second[(ipv6 ? 40 : 20) + 17] = 0;
        MDL firstMdl{nullptr, first.data(), static_cast<ULONG>(first.size()), TRUE};
        MDL secondMdl{nullptr, second.data(), static_cast<ULONG>(second.size()), TRUE};
        NET_BUFFER secondNb{nullptr, &secondMdl, 0, static_cast<ULONG>(second.size())};
        NET_BUFFER firstNb{&secondNb, &firstMdl, 0, static_cast<ULONG>(first.size())};
        _NET_BUFFER_LIST packet{&firstNb, nullptr};
        CHECK(NT_SUCCESS(HvWfpInject(&packet, ipv6, 37, 71, 0, 0, FALSE, InjectionComplete, &packet)));
        CHECK(first == firstExpected && second == secondExpected);
        secondNb.DataLength = 1;
        const auto calls = hv_wfp_fake::state().injection_calls.size();
        CHECK(HvWfpInject(&packet, ipv6, 37, 71, 0, 0, FALSE, InjectionComplete, &packet) == STATUS_DATA_ERROR);
        CHECK(hv_wfp_fake::state().injection_calls.size() == calls);

        auto zero = CheckedDatagram(ipv6, 17, 20, 0, 2);
        const unsigned transport = ipv6 ? 40 : 20;
        PutWord(zero, transport + 6, 0); PutWord(zero, transport + 8, 0);
        const auto complement = (~ReferenceSum(zero.data() + transport, 10, PseudoSum(zero, ipv6, 17, 10))) & 0xffffu;
        PutWord(zero, transport + 8, complement);
        MDL mdl{nullptr, zero.data(), static_cast<ULONG>(zero.size()), TRUE};
        NET_BUFFER nb{nullptr, &mdl, 0, static_cast<ULONG>(zero.size())};
        _NET_BUFFER_LIST udp{&nb, nullptr};
        CHECK(NT_SUCCESS(HvWfpInject(&udp, ipv6, 37, 71, 0, 0, FALSE, InjectionComplete, &udp)));
        CHECK(zero[transport + 6] == 0xff && zero[transport + 7] == 0xff);
        CHECK(ReferenceSum(zero.data() + transport, 10, PseudoSum(zero, ipv6, 17, 10)) == 0xffffu);
    }
    CHECK(StopAndVerifyClean());
    return true;
}
