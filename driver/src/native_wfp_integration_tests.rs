//! Regression families migrated from the former C++ WFP suites. All policy,
//! checksum, native MDL/clone and manager code under test is production Rust.
use super::*;

fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 2].copy_from_slice(&(value as u16).to_be_bytes());
}
fn reference_sum(bytes: &[u8], seed: u32) -> u16 {
    let mut sum = u64::from(seed);
    for (index, byte) in bytes.iter().copied().enumerate() {
        sum += u64::from(byte) << if index & 1 == 0 { 8 } else { 0 };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}
fn checksum_field(protocol: u8) -> usize {
    match protocol {
        6 => 16,
        17 => 6,
        _ => 2,
    }
}
fn pseudo_sum(bytes: &[u8], ipv6: bool, protocol: u8, length: usize) -> u32 {
    if !ipv6 && protocol == 1 {
        return 0;
    }
    u32::from(reference_sum(
        if ipv6 { &bytes[8..40] } else { &bytes[12..20] },
        0,
    )) + u32::from(protocol)
        + (length >> 16) as u32
        + (length & 0xffff) as u32
}
fn datagram(ipv6: bool, protocol: u8, header: usize, extensions: usize, payload: usize) -> Vec<u8> {
    let transport = if ipv6 { 40 + extensions * 8 } else { header };
    let length = if protocol == 6 { 20 } else { 8 } + payload;
    let mut bytes = std::vec![0; transport+length];
    if ipv6 {
        bytes[0] = 0x60;
        let size = bytes.len() - 40;
        put_word(&mut bytes, 4, size as u32);
        bytes[6] = if extensions != 0 { 0 } else { protocol };
        bytes[7] = 61;
        for (index, byte) in bytes[8..40].iter_mut().enumerate() {
            *byte = (index as u8 + 8) * 3;
        }
        for index in 0..extensions {
            bytes[40 + index * 8] = if index + 1 == extensions {
                protocol
            } else {
                60
            };
        }
    } else {
        bytes[0] = 0x40 | (header / 4) as u8;
        let size = bytes.len();
        put_word(&mut bytes, 2, size as u32);
        bytes[8] = 61;
        bytes[9] = protocol;
        bytes[12..20].copy_from_slice(&[10, 94, 59, 5, 8, 8, 8, 8]);
        bytes[20..header].fill(1);
    }
    if protocol == 6 || protocol == 17 {
        put_word(&mut bytes, transport, 12345);
        put_word(&mut bytes, transport + 2, 443);
        if protocol == 6 {
            bytes[transport + 12] = 0x50;
            bytes[transport + 13] = 2;
        } else {
            put_word(&mut bytes, transport + 4, length as u32);
        }
    } else {
        bytes[transport] = if ipv6 { 128 } else { 8 };
        put_word(&mut bytes, transport + 4, 512);
        put_word(&mut bytes, transport + 6, 1);
    }
    for index in if protocol == 6 { 20 } else { 8 }..length {
        bytes[transport + index] = index.wrapping_mul(19) as u8;
    }
    let mut checksum = !reference_sum(
        &bytes[transport..],
        pseudo_sum(&bytes, ipv6, protocol, length),
    );
    if protocol == 17 && checksum == 0 {
        checksum = 0xffff;
    }
    put_word(
        &mut bytes,
        transport + checksum_field(protocol),
        u32::from(checksum),
    );
    if !ipv6 {
        let checksum = !reference_sum(&bytes[..header], 0);
        put_word(&mut bytes, 10, u32::from(checksum));
    }
    bytes
}

impl PacketFixture {
    fn scattered(bytes: &[u8], chunks: &[usize]) -> Self {
        let mut storage = std::vec![0xa5; 8 + bytes.len() + 7];
        storage[8..8 + bytes.len()].copy_from_slice(bytes);
        let mut fixture = Self {
            bytes: storage,
            mdls: Vec::new(),
            nb: Box::default(),
            nbl: Box::default(),
        };
        fixture.mdls.push(MDL {
            ByteCount: 8,
            MdlFlags: MDL_MAPPED_TO_SYSTEM_VA as CSHORT,
            ..Default::default()
        });
        fixture.mdls.push(MDL::default());
        let mut position = 0;
        let mut index = 0;
        while position != bytes.len() {
            let take = chunks[index % chunks.len()].min(bytes.len() - position);
            assert!(take != 0);
            fixture.mdls.push(MDL {
                ByteCount: take as u32,
                MappedSystemVa: unsafe { fixture.bytes.as_mut_ptr().add(8 + position) }.cast(),
                MdlFlags: MDL_MAPPED_TO_SYSTEM_VA as CSHORT,
                ..Default::default()
            });
            fixture.mdls.push(MDL::default());
            position += take;
            index += 1;
        }
        for index in 0..fixture.mdls.len() - 1 {
            fixture.mdls[index].Next = &mut fixture.mdls[index + 1];
        }
        unsafe {
            fixture.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdl = fixture.mdls.as_mut_ptr();
            fixture
                .nb
                .__bindgen_anon_1
                .__bindgen_anon_1
                .CurrentMdlOffset = 8;
            fixture.nb.__bindgen_anon_1.__bindgen_anon_1.MdlChain = fixture.mdls.as_mut_ptr();
            fixture
                .nb
                .__bindgen_anon_1
                .__bindgen_anon_1
                .__bindgen_anon_1
                .DataLength = bytes.len() as u32;
            crate::native_packet::set_first_nb(fixture.nbl.as_mut(), fixture.nb.as_mut());
        }
        fixture.nbl.NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize] = 0x1fusize as PVOID;
        fixture
    }
    fn matches(&self, expected: &[u8]) -> bool {
        self.bytes[8..8 + expected.len()] == *expected
            && self.bytes[..8].iter().all(|&b| b == 0xa5)
            && self.bytes[8 + expected.len()..].iter().all(|&b| b == 0xa5)
            && unsafe {
                self.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdl
                    == self.mdls.as_ptr().cast_mut()
                    && self.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset == 8
                    && self
                        .nb
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .DataLength as usize
                        == expected.len()
            }
    }
    fn restore(&mut self, ipv6: bool, segmented: bool) -> u8 {
        unsafe {
            actual_restore(
                self.nbl.as_mut() as *mut _ as Handle,
                u8::from(ipv6),
                u8::from(segmented),
            )
        }
    }
}

#[test]
fn software_checksums_across_every_mdl_boundary_options_extensions_and_odd_payloads() {
    let _guard = begin();
    for ipv6 in [false, true] {
        for protocol in [6, 17, if ipv6 { 58 } else { 1 }] {
            for (header, extensions) in [(20, 0), (24, 2), (60, 8)] {
                let transport = if ipv6 { 40 + extensions * 8 } else { header };
                for payload in [0, 17, 18] {
                    let expected = datagram(ipv6, protocol, header, extensions, payload);
                    for split in 0..=expected.len() {
                        for partial in [0, 0x1234] {
                            let mut storage = std::vec![0xa5; 3+expected.len()+7];
                            storage[3..3 + expected.len()].copy_from_slice(&expected);
                            if !ipv6 {
                                put_word(&mut storage, 13, 0);
                            }
                            put_word(
                                &mut storage,
                                3 + transport + checksum_field(protocol),
                                partial,
                            );
                            let mut packet = PacketFixture::new(storage, &[3 + split]);
                            packet.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset = 3;
                            packet
                                .nb
                                .__bindgen_anon_1
                                .__bindgen_anon_1
                                .__bindgen_anon_1
                                .DataLength = expected.len() as u32;
                            packet.nbl.NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize] =
                                0x1fusize as PVOID;
                            assert_eq!(packet.restore(ipv6, false), 1);
                            assert_eq!(&packet.bytes[3..3 + expected.len()], expected);
                            assert!(
                                packet.bytes[..3]
                                    .iter()
                                    .chain(&packet.bytes[3 + expected.len()..])
                                    .all(|&b| b == 0xa5)
                            );
                            assert!(
                                packet.nbl.NetBufferListInfo
                                    [TcpIpChecksumNetBufferListInfo as usize]
                                    .is_null()
                            );
                            assert_eq!(unsafe { current_mdl_offset(packet.nb.as_mut()) }, 3);
                            assert_eq!(
                                unsafe { data_length(packet.nb.as_mut()) },
                                expected.len() as u32
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn range_reads_validate_before_mapping_and_skip_unrequested_unmapped_mdls() {
    let _guard = begin();
    let bytes: Vec<u8> = (0..1500usize).map(|i| i.wrapping_mul(19) as u8).collect();
    let mut packet = PacketFixture::scattered(&bytes, &[3, 5, 1, 7]);
    let mut header = [0u8; 60];
    unsafe {
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 1, header.as_mut_ptr(), 60),
            1
        );
        assert_eq!(header, bytes[1..61]);
        assert!(packet.matches(&bytes));
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 1499, header.as_mut_ptr(), 2),
            0
        );
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), u32::MAX, header.as_mut_ptr(), 2),
            0
        );
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 1500, header.as_mut_ptr(), 0),
            1
        );
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 1501, header.as_mut_ptr(), 0),
            0
        );
        packet.mdls[2].MappedSystemVa = ptr::null_mut();
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 3, header.as_mut_ptr(), 8),
            1
        );
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 2, header.as_mut_ptr(), 8),
            0
        );
        packet.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset = 9;
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 0, header.as_mut_ptr(), 1),
            0
        );
        packet.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset = 8;
        packet.mdls[1].Next = ptr::null_mut();
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 0, header.as_mut_ptr(), 1),
            0
        );
    }
}

#[test]
fn word_checksum_matches_independent_byte_reference_including_one_mib_spans() {
    let _guard = begin();
    for length in [2usize, 3, 7, 8, 17, 320, 1501, 65535, 1 << 20] {
        for start in [0usize, 1, 3] {
            let mut bytes = std::vec![0xff; start+length+5];
            for index in (0..length).step_by(5) {
                bytes[start + index] = index.wrapping_mul(37) as u8;
            }
            for field in [0usize, (length - 2) / 2, length - 2, 65533.min(length - 2)] {
                let mut reference = bytes[start..start + length].to_vec();
                reference[field] = 0;
                reference[field + 1] = 0;
                let expected = !reference_sum(&reference, 0xfffffff0);
                let patterns: &[&[usize]] = if length == 1 << 20 {
                    &[&[1 << 20], &[65535, 65534, 3]]
                } else {
                    &[&[1], &[3, 5, 1, 7], &[8, 9, 2, 1]]
                };
                for chunks in patterns {
                    let mut packet = PacketFixture::scattered(&bytes, chunks);
                    let mut checksum = 0;
                    assert_eq!(
                        unsafe {
                            actual_checksum(
                                packet.nb.as_mut() as *mut _ as Handle,
                                start as u32,
                                length as u32,
                                field as u32,
                                0xfffffff0,
                                &mut checksum,
                            )
                        },
                        1
                    );
                    assert_eq!(checksum, expected);
                    assert!(packet.matches(&bytes));
                }
            }
        }
    }
}

#[test]
fn scattered_checksum_idempotence_udp_length_and_sticky_fragment_oob() {
    let _guard = begin();
    for ipv6 in [false, true] {
        for protocol in [6, 17, if ipv6 { 58 } else { 1 }] {
            let transport = if ipv6 { 56 } else { 60 };
            let expected = datagram(ipv6, protocol, 60, 2, 33);
            for partial in [0, 1, 0x00ff, 0xff00, 0xffff, 0x1234] {
                for chunks in [&[1usize][..], &[3, 5, 1, 7][..]] {
                    let mut bytes = expected.clone();
                    if !ipv6 {
                        put_word(&mut bytes, 10, partial);
                    }
                    put_word(&mut bytes, transport + checksum_field(protocol), partial);
                    let mut packet = PacketFixture::scattered(&bytes, chunks);
                    assert_eq!(packet.restore(ipv6, false), 1);
                    assert!(packet.matches(&expected));
                    assert!(
                        packet.nbl.NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize]
                            .is_null()
                    );
                    assert_eq!(packet.restore(ipv6, false), 1);
                    assert!(packet.matches(&expected));
                }
            }
        }
        let mut udp = datagram(ipv6, 17, 20, 0, 3);
        udp.extend_from_slice(&[0xaa, 0x55, 0xff, 0x99]);
        let length = udp.len() - if ipv6 { 40 } else { 0 };
        put_word(&mut udp, if ipv6 { 4 } else { 2 }, length as u32);
        if !ipv6 {
            put_word(&mut udp, 10, 0);
            let sum = !reference_sum(&udp[..20], 0);
            put_word(&mut udp, 10, u32::from(sum));
        }
        let expected = udp.clone();
        put_word(&mut udp, if ipv6 { 46 } else { 26 }, 0x1234);
        let mut packet = PacketFixture::scattered(&udp, &[1, 3, 5]);
        assert_eq!(packet.restore(ipv6, false), 1);
        assert!(packet.matches(&expected));
        for fragment_first in [false, true] {
            let mut fragment = datagram(ipv6, 17, 20, usize::from(ipv6), 17);
            if ipv6 {
                fragment[6] = 44;
                fragment[43] = 1;
            } else {
                fragment[6] = 0x20;
                put_word(&mut fragment, 10, 0);
                let sum = !reference_sum(&fragment[..20], 0);
                put_word(&mut fragment, 10, u32::from(sum));
            }
            put_word(&mut fragment, if ipv6 { 54 } else { 26 }, 0x1234);
            let ordinary = datagram(ipv6, 6, 20, 0, 17);
            let (a, b) = if fragment_first {
                (&fragment, &ordinary)
            } else {
                (&ordinary, &fragment)
            };
            let mut first = PacketFixture::scattered(a, &[1, 3, 5]);
            let mut second = PacketFixture::scattered(b, &[3, 1, 7]);
            unsafe {
                crate::native_packet::set_next_nb(first.nb.as_mut(), second.nb.as_mut());
            }
            assert_eq!(first.restore(ipv6, false), 1);
            assert!(first.matches(a));
            assert!(second.matches(b));
            assert!(
                !first.nbl.NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize].is_null()
            );
        }
    }
}

#[test]
fn fragments_and_unfinished_segmentation_keep_transport_checksums_and_oob() {
    let _guard = begin();
    for ipv6 in [false, true] {
        for segmented in [false, true] {
            let mut bytes = datagram(ipv6, 17, 20, usize::from(ipv6), 17);
            let transport = if ipv6 { 48 } else { 20 };
            if ipv6 {
                if !segmented {
                    bytes[6] = 44;
                    bytes[43] = 1;
                }
            } else {
                put_word(&mut bytes, 10, 0);
                if !segmented {
                    bytes[6] = 0x20;
                } else {
                    put_word(&mut bytes, 2, 0);
                }
            }
            put_word(&mut bytes, transport + 6, 0x1234);
            let mut expected = bytes.clone();
            if !ipv6 {
                let sum = !reference_sum(&expected[..20], 0);
                put_word(&mut expected, 10, u32::from(sum));
            }
            let mut packet = PacketFixture::scattered(&bytes, &[1, 3, 5]);
            assert_eq!(packet.restore(ipv6, segmented), 1);
            assert!(packet.matches(&expected));
            assert!(
                !packet.nbl.NetBufferListInfo[TcpIpChecksumNetBufferListInfo as usize].is_null()
            );
        }
    }
}

#[test]
fn routing_options_home_address_atomic_fragment_and_ah_use_correct_pseudo_header() {
    let _guard = begin();
    for ipv6 in [false, true] {
        for layout in 0..if ipv6 { 6 } else { 2 } {
            let transport = if ipv6 {
                if layout == 4 {
                    48
                } else if layout == 5 {
                    56
                } else {
                    64
                }
            } else {
                28
            };
            let mut bytes = datagram(
                ipv6,
                17,
                28,
                if ipv6 { (transport - 40) / 8 } else { 0 },
                17,
            );
            let mut pseudo = bytes.clone();
            if !ipv6 {
                bytes[20] = if layout == 0 { 131 } else { 137 };
                bytes[21] = 7;
                bytes[22] = 4;
                bytes[23..27].fill(1);
                bytes[27] = 0;
                pseudo[16..20].copy_from_slice(&bytes[23..27]);
                put_word(&mut bytes, 10, 0);
                let sum = !reference_sum(&bytes[..28], 0);
                put_word(&mut bytes, 10, u32::from(sum));
            } else {
                bytes[40..transport].fill(0);
                bytes[40] = 17;
                if layout < 3 {
                    bytes[6] = 43;
                    bytes[41] = 2;
                    bytes[42] = if layout == 0 {
                        0
                    } else if layout == 1 {
                        2
                    } else {
                        4
                    };
                    bytes[43] = 1;
                    bytes[48..64].fill(0x77);
                    pseudo[24..40].copy_from_slice(&bytes[48..64]);
                } else if layout == 3 {
                    bytes[6] = 60;
                    bytes[41] = 2;
                    bytes[42] = 201;
                    bytes[43] = 16;
                    bytes[44..60].fill(0x55);
                    pseudo[8..24].copy_from_slice(&bytes[44..60]);
                } else if layout == 4 {
                    bytes[6] = 44;
                } else {
                    bytes[6] = 51;
                    bytes[41] = 2;
                }
            }
            put_word(&mut bytes, transport + 6, 0);
            let checksum = !reference_sum(
                &bytes[transport..],
                pseudo_sum(&pseudo, ipv6, 17, bytes.len() - transport),
            );
            let mut expected = bytes.clone();
            put_word(
                &mut expected,
                transport + 6,
                u32::from(if checksum == 0 { 0xffff } else { checksum }),
            );
            for split in 0..=bytes.len() {
                let mut packet = PacketFixture::new(bytes.clone(), &[split]);
                assert_eq!(packet.restore(ipv6, false), 1);
                assert_eq!(packet.bytes, expected);
            }
        }
    }
    for failure in 0..4 {
        let mut bytes = datagram(true, 17, 20, if failure == 0 { 9 } else { 1 }, 17);
        if failure == 1 {
            bytes[41] = 255;
        }
        if failure == 2 {
            bytes[6] = 43;
            bytes[42] = 99;
            bytes[43] = 1;
        }
        if failure == 3 {
            bytes[6] = 60;
            bytes[42] = 201;
            bytes[43] = 16;
        }
        let mut packet = PacketFixture::new(bytes, &[1, 3, 5]);
        assert_eq!(packet.restore(true, false), 0);
    }
}

#[test]
fn mapping_work_stays_range_based_not_per_byte() {
    let _guard = begin();
    let mut packet = PacketFixture::new(std::vec![1;1500], &[1500]);
    let mut header = [0u8; 60];
    crate::native_packet::reset_map_mdl_call_count();
    unsafe {
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 0, header.as_mut_ptr(), 60),
            1
        );
    }
    assert_eq!(crate::native_packet::map_mdl_call_count(), 1);
    unsafe {
        assert_eq!(
            ForwardRead(packet.nb.as_mut(), 1499, header.as_mut_ptr(), 2),
            0
        );
    }
    assert_eq!(crate::native_packet::map_mdl_call_count(), 1);
    let expected = datagram(false, 6, 20, 0, 17);
    let mut bytes = expected.clone();
    put_word(&mut bytes, 10, 0x1234);
    put_word(&mut bytes, 36, 0xffff);
    let mut packet = PacketFixture::new(bytes, &[65535]);
    crate::native_packet::reset_map_mdl_call_count();
    assert_eq!(packet.restore(false, false), 1);
    assert_eq!(packet.bytes, expected);
    assert_eq!(crate::native_packet::map_mdl_call_count(), 7);
}

unsafe extern "system" fn no_completion(_context: Handle, _nbl: Handle, _dispatch: u8) {}
fn submit(packet: &mut PacketFixture, ipv6: bool, flags: u32) -> i32 {
    unsafe {
        actual_inject(
            packet.nbl.as_mut() as *mut _ as Handle,
            u8::from(ipv6),
            37,
            71,
            19,
            flags,
            0,
            Some(no_completion),
            packet.nbl.as_mut() as *mut _ as Handle,
        )
    }
}

#[test]
fn weak_host_routes_network_handles_self_injection_family_and_post_stop_failure() {
    let _guard = integration_begin();
    start_manager();
    for ipv6 in [false, true] {
        for flags in [
            0,
            FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU,
            FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
            FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU | FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
        ] {
            let mut packet = PacketFixture::new(datagram(ipv6, 17, 20, 0, 3), &[1, 3]);
            assert_eq!(submit(&mut packet, ipv6, flags), 0);
            let route = if flags & FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU != 0 {
                1
            } else if flags & FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU != 0 {
                2
            } else {
                0
            };
            assert_eq!(
                state(|s| s.injection),
                Some((
                    route,
                    if route == 0 {
                        if ipv6 { AF_INET6 } else { AF_INET }
                    } else {
                        0
                    },
                    37,
                    if route == 2 { 0 } else { 71 },
                    if route == 1 { 19 } else { 0 }
                ))
            );
            state(|s| {
                s.injection_status = failed_status();
                s.self_state = FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF;
                s.self_family = Some(if ipv6 { AF_INET6 } else { AF_INET } as ADDRESS_FAMILY);
                s.self_kind = Some(if route == 0 {
                    FWPS_INJECTION_TYPE_FORWARD
                } else {
                    FWPS_INJECTION_TYPE_NETWORK
                });
            });
            assert_eq!(submit(&mut packet, ipv6, flags), failed_status());
            let nbl = packet.nbl.as_mut() as *mut _ as Handle;
            assert_eq!(unsafe { actual_is_self(nbl, u8::from(ipv6)) }, 1);
            assert_eq!(unsafe { actual_is_self(nbl, u8::from(!ipv6)) }, 0);
            state(|s| {
                s.injection_status = 0;
                s.self_state = FWPS_PACKET_NOT_INJECTED;
            });
        }
    }
    unsafe {
        actual_stop();
    }
    let mut packet = PacketFixture::new(datagram(false, 17, 20, 0, 3), &[65535]);
    assert_eq!(submit(&mut packet, false, 0), 0xc0000056u32 as i32);
    stop_and_check();
}

#[test]
fn checksum_failures_prevent_every_injection_route_and_do_not_publish_completion() {
    let _guard = integration_begin();
    start_manager();
    for ipv6 in [false, true] {
        for flags in [
            0,
            FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU,
            FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU,
        ] {
            let transport = if ipv6 { 40 } else { 20 };
            for failure in 0..10 {
                let mut packet = PacketFixture::new(datagram(ipv6, 6, 20, 0, 17), &[transport]);
                match failure {
                    0 => packet.bytes[0] = if ipv6 { 0x45 } else { 0x60 },
                    1 => {
                        packet
                            .nb
                            .__bindgen_anon_1
                            .__bindgen_anon_1
                            .__bindgen_anon_1
                            .DataLength = if ipv6 { 39 } else { 19 }
                    }
                    2 => packet.mdls[0].MappedSystemVa = ptr::null_mut(),
                    3 => packet.mdls[1].MappedSystemVa = ptr::null_mut(),
                    4 => {
                        packet.nb.__bindgen_anon_1.__bindgen_anon_1.CurrentMdlOffset =
                            transport as u32 + 1
                    }
                    5 => unsafe {
                        crate::native_packet::set_first_nb(packet.nbl.as_mut(), ptr::null_mut());
                    },
                    6 => put_word(&mut packet.bytes, if ipv6 { 4 } else { 2 }, 60000),
                    7 => packet.bytes[transport + 12] = 0x40,
                    8 => packet.mdls[1].ByteCount = 19,
                    9 => packet.mdls[0].Next = ptr::null_mut(),
                    _ => unreachable!(),
                }
                state(|s| s.last_injection = None);
                assert_eq!(submit(&mut packet, ipv6, flags), 0xc000003eu32 as i32);
                assert!(state(|s| s.last_injection.is_none()));
            }
            for length in [0, 7, 60000] {
                let mut packet = PacketFixture::new(datagram(ipv6, 17, 20, 0, 17), &[transport]);
                put_word(&mut packet.bytes, transport + 4, length);
                state(|s| s.last_injection = None);
                assert_eq!(submit(&mut packet, ipv6, flags), 0xc000003eu32 as i32);
                assert!(state(|s| s.last_injection.is_none()));
            }
        }
    }
    stop_and_check();
}

#[test]
fn actual_classification_validation_self_exemption_allocation_failures_and_chains() {
    let _guard = integration_begin();
    start_manager();
    let mut packet = PacketFixture::new(datagram(false, 17, 20, 0, 3), &[65535]);
    let mut fields = fixed_values(false, 0);
    fields[FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX as usize]
        .value
        .type_ = FWP_EMPTY;
    let values = FWPS_INCOMING_VALUES0 {
        layerId: FWPS_LAYER_IPFORWARD_V4 as u16,
        valueCount: fields.len() as u32,
        incomingValue: fields.as_mut_ptr(),
    };
    let mut out = FWPS_CLASSIFY_OUT0 {
        rights: FWPS_RIGHT_ACTION_WRITE,
        ..Default::default()
    };
    unsafe {
        classify(
            &values,
            ptr::null(),
            packet.nbl.as_mut() as *mut _ as Handle,
            ptr::null(),
            0,
            &mut out,
        );
    }
    assert!(blocked(&out));
    assert_eq!(state(|s| s.resource_drops), 1);
    state(|s| s.self_state = FWPS_PACKET_INJECTED_BY_SELF);
    out.rights = FWPS_RIGHT_ACTION_WRITE;
    unsafe {
        classify(
            &values,
            ptr::null(),
            packet.nbl.as_mut() as *mut _ as Handle,
            ptr::null(),
            0,
            &mut out,
        );
    }
    assert_eq!(out.actionType, FWP_ACTION_PERMIT);
    assert_eq!(state(|s| s.resource_drops), 1);
    state(|s| s.self_state = FWPS_PACKET_NOT_INJECTED);
    for flags in [0, FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP] {
        state(|s| s.clone_status = failed_status());
        assert!(blocked(&packet.classify(false, flags)));
        state(|s| s.clone_status = 0);
        crate::native_packet::fail_next_context_allocation();
        assert!(blocked(&packet.classify(false, flags)));
        assert!(state(|s| s.live.is_empty()));
    }
    let mut second = NET_BUFFER_LIST::default();
    unsafe {
        crate::native_packet::set_next_nbl(packet.nbl.as_mut(), &mut second);
    }
    assert!(blocked(&packet.classify(false, 0)));
    assert!(state(|s| s.live.is_empty()));
    stop_and_check();
}

#[test]
fn multi_nb_large_packets_udp_zero_is_all_ones_and_malformed_next_nb_fails() {
    let _guard = begin();
    for ipv6 in [false, true] {
        let mut a = datagram(ipv6, 17, 20, 0, if ipv6 { 65527 } else { 65507 });
        let mut b = datagram(ipv6, 6, 20, 0, 17);
        let expected_a = a.clone();
        let expected_b = b.clone();
        let transport = if ipv6 { 40 } else { 20 };
        put_word(&mut a, transport + 6, 0);
        put_word(&mut b, transport + 16, 0);
        let mut first = PacketFixture::new(a, &[65535]);
        let mut second = PacketFixture::new(b, &[3, 5]);
        unsafe {
            crate::native_packet::set_next_nb(first.nb.as_mut(), second.nb.as_mut());
        }
        assert_eq!(first.restore(ipv6, false), 1);
        assert_eq!(first.bytes, expected_a);
        assert_eq!(second.bytes, expected_b);
        second
            .nb
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_1
            .DataLength = 1;
        assert_eq!(first.restore(ipv6, false), 0);
        let mut bytes = datagram(ipv6, 17, 20, 0, 2);
        put_word(&mut bytes, transport + 6, 0);
        put_word(&mut bytes, transport + 8, 0);
        let complement = !reference_sum(&bytes[transport..], pseudo_sum(&bytes, ipv6, 17, 10));
        put_word(&mut bytes, transport + 8, u32::from(complement));
        let mut packet = PacketFixture::scattered(&bytes, &[1, 3, 5]);
        assert_eq!(packet.restore(ipv6, false), 1);
        let output = &packet.bytes[8..8 + bytes.len()];
        assert_eq!(&output[transport + 6..transport + 8], &[0xff, 0xff]);
        assert_eq!(
            reference_sum(&output[transport..], pseudo_sum(output, ipv6, 17, 10)),
            0xffff
        );
    }
}
