// Included after wfp_checksum_cases.h. These are operation counts, not timings.
struct ScatteredPacket {
    static constexpr ULONG Prefix = 8, Suffix = 7;
    std::vector<UCHAR> Bytes;
    std::vector<MDL> Mdls;
    NET_BUFFER Nb{};
    _NET_BUFFER_LIST Packet{};
    ScatteredPacket(const std::vector<UCHAR>& bytes, const std::vector<ULONG>& chunks)
        : Bytes(Prefix + bytes.size() + Suffix, 0xa5) {
        std::copy(bytes.begin(), bytes.end(), Bytes.begin() + Prefix);
        Mdls.push_back({nullptr, Bytes.data(), Prefix, FALSE});
        Mdls.push_back({nullptr, nullptr, 0, FALSE});
        ULONG position = 0;
        for (std::size_t index = 0; position != bytes.size(); ++index) {
            const ULONG take = std::min(chunks[index % chunks.size()], static_cast<ULONG>(bytes.size() - position));
            Mdls.push_back({nullptr, Bytes.data() + Prefix + position, take, TRUE});
            Mdls.push_back({nullptr, nullptr, 0, FALSE});
            position += take;
        }
        for (std::size_t i = 1; i < Mdls.size(); ++i) Mdls[i - 1].Next = &Mdls[i];
        Nb = {nullptr, Mdls.data(), Prefix, static_cast<ULONG>(bytes.size())};
        Packet = {&Nb, reinterpret_cast<void*>(0x1f)};
    }
    bool Matches(const std::vector<UCHAR>& expected) const {
        return std::equal(expected.begin(), expected.end(), Bytes.begin() + Prefix) &&
            std::all_of(Bytes.begin(), Bytes.begin() + Prefix, [](UCHAR b) { return b == 0xa5; }) &&
            std::all_of(Bytes.end() - Suffix, Bytes.end(), [](UCHAR b) { return b == 0xa5; }) &&
            Nb.CurrentMdl == Mdls.data() && Nb.CurrentMdlOffset == Prefix && Nb.DataLength == expected.size();
    }
};

bool TestRangeReadWorkAndFailureBoundaries() {
    std::vector<UCHAR> bytes(1500);
    for (ULONG i = 0; i != bytes.size(); ++i) bytes[i] = static_cast<UCHAR>(i * 19);
    MDL mdl{nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), TRUE};
    NET_BUFFER nb{nullptr, &mdl, 0, static_cast<ULONG>(bytes.size())};
    UCHAR header[60];
    hv_wfp_fake::packet_work = {};
    CHECK(ForwardRead(&nb, 0, header, sizeof(header)));
    CHECK(std::equal(header, header + sizeof(header), bytes.begin()));
    CHECK(hv_wfp_fake::packet_work.mdl_maps == 1 && hv_wfp_fake::packet_work.mdl_counts == 1);
    CHECK(!ForwardRead(&nb, 1499, header, 2));
    CHECK(!ForwardRead(&nb, 0xffffffffu, header, 2));
    CHECK(ForwardRead(&nb, 1500, header, 0));
    CHECK(!ForwardRead(&nb, 1501, header, 0));
    CHECK(hv_wfp_fake::packet_work.mdl_maps == 1);

    ScatteredPacket scattered(bytes, {3, 5, 1, 7});
    hv_wfp_fake::packet_work = {};
    CHECK(ForwardRead(&scattered.Nb, 1, header, sizeof(header)));
    CHECK(std::equal(header, header + sizeof(header), bytes.begin() + 1));
    CHECK(hv_wfp_fake::packet_work.mdl_maps < sizeof(header));
    CHECK(scattered.Matches(bytes));
    // Unmapped MDLs outside the requested range are not read.
    scattered.Mdls[2].Mappable = FALSE;
    CHECK(ForwardRead(&scattered.Nb, 3, header, 8));
    CHECK(!ForwardRead(&scattered.Nb, 2, header, 8));
    scattered.Nb.CurrentMdlOffset = ScatteredPacket::Prefix + 1;
    CHECK(!ForwardRead(&scattered.Nb, 0, header, 1));
    scattered.Nb.CurrentMdlOffset = ScatteredPacket::Prefix;
    scattered.Mdls[1].Next = nullptr;
    CHECK(!ForwardRead(&scattered.Nb, 0, header, 1));

    auto tcp = CheckedDatagram(FALSE, 6);
    const auto expected = tcp;
    PutWord(tcp, 10, 0x1234); PutWord(tcp, 36, 0xffff);
    MDL tcpMdl{nullptr, tcp.data(), static_cast<ULONG>(tcp.size()), TRUE};
    NET_BUFFER tcpNb{nullptr, &tcpMdl, 0, static_cast<ULONG>(tcp.size())};
    _NET_BUFFER_LIST packet{&tcpNb, nullptr};
    hv_wfp_fake::packet_work = {};
    CHECK(RestoreForwardChecksums(&packet, FALSE, FALSE));
    CHECK(tcp == expected);
    CHECK(hv_wfp_fake::packet_work.mdl_maps == 7);
    std::printf("CPU_WORK IPv4/TCP single-MDL checksum path: %zu mapping-helper calls\n", hv_wfp_fake::packet_work.mdl_maps);
    return true;
}

bool TestWordChecksumAgainstIndependentByteReference() {
    for (ULONG length : {2u, 3u, 7u, 8u, 17u, 320u, 1501u, 65535u}) {
        for (ULONG start : {0u, 1u, 3u}) {
            std::vector<UCHAR> bytes(start + length + 5, 0xff);
            for (ULONG i = 0; i < length; i += 5) bytes[start + i] = static_cast<UCHAR>(i * 37);
            for (ULONG field : {0u, (length - 2) / 2, length - 2}) {
                auto reference = bytes;
                reference[start + field] = reference[start + field + 1] = 0;
                const USHORT expected = static_cast<USHORT>(~ReferenceSum(reference.data() + start, length, 0xfffffff0u));
                for (const auto& chunks : {std::vector<ULONG>{1}, std::vector<ULONG>{3, 5, 1, 7},
                                           std::vector<ULONG>{8, 9, 2, 1}}) {
                    ScatteredPacket scattered(bytes, chunks);
                    USHORT checksum = 0;
                    CHECK(ForwardChecksum(&scattered.Nb, start, length, field, 0xfffffff0u, &checksum));
                    CHECK(checksum == expected && scattered.Matches(bytes));
                }
            }
        }
    }
    return true;
}

bool TestScatteredChecksumsIdempotenceAndRetainedOffloads() {
    for (BOOLEAN ipv6 : {FALSE, TRUE}) {
        for (UCHAR protocol : {UCHAR{6}, UCHAR{17}, ipv6 ? UCHAR{58} : UCHAR{1}}) {
            const unsigned transport = ipv6 ? 56 : 60;
            const auto expected = CheckedDatagram(ipv6, protocol, 60, 2, 33);
            for (ULONG partial : {0u, 1u, 0x00ffu, 0xff00u, 0xffffu, 0x1234u}) {
                for (const auto& chunks : {std::vector<ULONG>{1}, std::vector<ULONG>{3, 5, 1, 7}}) {
                    auto bytes = expected;
                    if (!ipv6) PutWord(bytes, 10, partial);
                    PutWord(bytes, transport + ChecksumField(protocol), partial);
                    ScatteredPacket scattered(bytes, chunks);
                    CHECK(RestoreForwardChecksums(&scattered.Packet, ipv6, FALSE));
                    CHECK(scattered.Matches(expected) && scattered.Packet.ChecksumInfo == nullptr);
                    CHECK(RestoreForwardChecksums(&scattered.Packet, ipv6, FALSE));
                    CHECK(scattered.Matches(expected));
                }
            }
        }
        // UDP datagram length, not trailing IP bytes, defines its checksum.
        auto udp = CheckedDatagram(ipv6, 17, 20, 0, 3);
        const unsigned transport = ipv6 ? 40 : 20;
        udp.insert(udp.end(), {0xaa, 0x55, 0xff, 0x99});
        PutWord(udp, ipv6 ? 4 : 2, static_cast<ULONG>(udp.size() - (ipv6 ? 40 : 0)));
        if (!ipv6) {
            PutWord(udp, 10, 0);
            PutWord(udp, 10, (~ReferenceSum(udp.data(), 20)) & 0xffffu);
        }
        const auto expected = udp;
        PutWord(udp, transport + 6, 0x1234);
        ScatteredPacket scattered(udp, {1, 3, 5});
        CHECK(RestoreForwardChecksums(&scattered.Packet, ipv6, FALSE));
        CHECK(scattered.Matches(expected));

        // A fragment makes the NBL's incomplete/OOB state sticky in either order.
        for (bool fragmentFirst : {false, true}) {
            auto fragment = CheckedDatagram(ipv6, 17, 20, ipv6 ? 1 : 0);
            if (ipv6) { fragment[6] = 44; fragment[43] = 1; }
            else {
                fragment[6] = 0x20;
                PutWord(fragment, 10, 0);
                PutWord(fragment, 10, (~ReferenceSum(fragment.data(), 20)) & 0xffffu);
            }
            PutWord(fragment, (ipv6 ? 48 : 20) + 6, 0x1234);
            auto ordinary = CheckedDatagram(ipv6, 6);
            ScatteredPacket first(fragmentFirst ? fragment : ordinary, {1, 3, 5});
            ScatteredPacket second(fragmentFirst ? ordinary : fragment, {3, 1, 7});
            first.Nb.Next = &second.Nb;
            CHECK(RestoreForwardChecksums(&first.Packet, ipv6, FALSE));
            CHECK(first.Packet.ChecksumInfo == reinterpret_cast<void*>(0x1f));
            CHECK(first.Matches(fragmentFirst ? fragment : ordinary));
            CHECK(second.Matches(fragmentFirst ? ordinary : fragment));
        }
    }
    return true;
}
