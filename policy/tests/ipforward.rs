use hyperv_policy::{
    engine::{Engine, Finish, Submission, allocate_record},
    packet::{self, NdisPath, Packet},
};
use hyperv_protocol::{Direction, Verdict, connection_header_len};

fn datagram(ipv6: bool, protocol: u8) -> Vec<u8> {
    let header = if ipv6 { 40 } else { 20 };
    let transport = if protocol == 6 { 20 } else { 8 };
    let mut bytes = vec![0u8; header + transport + 8];
    if ipv6 {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&((transport + 8) as u16).to_be_bytes());
        bytes[6] = protocol;
        bytes[8..24].copy_from_slice(&[0x20; 16]);
        bytes[24..40].copy_from_slice(&[0x30; 16]);
    } else {
        bytes[0] = 0x45;
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&[172, 28, 192, 8]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 10]);
    }
    bytes[header..header + 2].copy_from_slice(&49714u16.to_be_bytes());
    bytes[header + 2..header + 4].copy_from_slice(&9000u16.to_be_bytes());
    if protocol == 6 {
        bytes[header + 12] = 0x50;
    } else if protocol == 17 {
        bytes[header + 4..header + 6].copy_from_slice(&((transport + 8) as u16).to_be_bytes());
    } else {
        bytes[header] = if ipv6 { 128 } else { 8 };
        bytes[header + 1..header + 4].fill(0);
        bytes[header + 4..header + 6].copy_from_slice(&1234u16.to_be_bytes());
        bytes[header + 6..header + 8].copy_from_slice(&1u16.to_be_bytes());
    }
    bytes[header + transport..].fill(0xa5);
    bytes
}
fn reply(bytes: &[u8], ipv6: bool) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let (source, destination, width, header) = if ipv6 {
        (8, 24, 16, 40)
    } else {
        (12, 16, 4, 20)
    };
    for i in 0..width {
        bytes.swap(source + i, destination + i);
    }
    let protocol = bytes[if ipv6 { 6 } else { 9 }];
    if matches!(protocol, 1 | 58) {
        bytes[header] = if ipv6 { 129 } else { 0 };
    } else {
        bytes.swap(header, header + 2);
        bytes.swap(header + 1, header + 3);
    }
    bytes
}
fn parse(bytes: &[u8], ipv6: bool, direction: Direction) -> Packet {
    let mut packet = packet::parse_ip(bytes, bytes.len(), bytes.len(), ipv6, false).unwrap();
    packet.orient_direction(direction);
    packet
}
fn engine() -> Box<Engine> {
    let mut engine = Box::new(Engine::new());
    for index in [101, 102] {
        assert!(engine.attach(index));
        assert!(engine.restart(index));
    }
    engine.connect();
    engine
}
fn submit(
    engine: &mut Engine,
    packet: Packet,
    bytes: &[u8],
    index: u32,
    nbl: usize,
    cancel: Option<usize>,
) -> u64 {
    let layout = packet.capture_layout().unwrap();
    let mut record = allocate_record(layout.record_len).unwrap();
    record[layout.frame_start..].copy_from_slice(&bytes[..layout.frame_len]);
    let Submission::Pending(id) = engine.submit(index, packet, nbl, cancel, 100, Some(record))
    else {
        panic!("expected pending packet");
    };
    id
}
fn record(engine: &mut Engine, kind: u8) -> Vec<u8> {
    let mut bytes = [0u8; 4096];
    let count = engine.read(&mut bytes);
    let mut offset = 0;
    while offset < count {
        let size = u32::from_le_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
        let end = offset + 5 + size;
        if bytes[offset] == kind {
            return bytes[offset..end].to_vec();
        }
        offset = end;
    }
    panic!("missing record {kind}");
}

#[test]
fn raw_ip_verdicts_preserve_complete_packets_guest_direction_and_host_index() {
    for ipv6 in [false, true] {
        for protocol in [6, 17] {
            for direction in [Direction::Outbound, Direction::Inbound] {
                for verdict in [
                    Verdict::Accept,
                    Verdict::PermanentAccept,
                    Verdict::Block,
                    Verdict::PermanentBlock,
                    Verdict::Drop,
                    Verdict::PermanentDrop,
                ] {
                    let request = datagram(ipv6, protocol);
                    let bytes = if direction == Direction::Inbound {
                        reply(&request, ipv6)
                    } else {
                        request
                    };
                    let packet = parse(&bytes, ipv6, direction);
                    let mut engine = engine();
                    let id = submit(&mut engine, packet, &bytes, 101, 11, None);
                    let event = record(&mut engine, if ipv6 { 2 } else { 1 });
                    assert_eq!(u64::from_le_bytes(event[5..13].try_into().unwrap()), id);
                    assert_eq!(u32::from_le_bytes(event[13..17].try_into().unwrap()), 101);
                    assert_eq!(event[17], direction as u8);
                    assert_eq!(event[18], protocol);
                    assert_eq!(packet.connection.local_port, 49714);
                    assert_eq!(packet.connection.remote_port, 9000);
                    assert_eq!(&event[connection_header_len(&packet.connection)..], &bytes);
                    let action = engine.verdict(id, verdict, 101).unwrap();
                    assert_eq!(action.nbl, 11);
                    assert_eq!(
                        action.finish,
                        if verdict.allows() {
                            Finish::Allow
                        } else {
                            Finish::Drop
                        }
                    );
                    assert!(engine.verdict(id, verdict, 102).is_err());
                }
            }
        }
    }
}

#[test]
fn ethernet_and_forwarding_share_only_the_same_interface_protocol_family_tuple_cache() {
    for ipv6 in [false, true] {
        for protocol in [6, 17] {
            let bytes = datagram(ipv6, protocol);
            let mut frame = vec![0u8; 14];
            frame[12..14].copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
            frame.extend_from_slice(&bytes);
            let mut ethernet = packet::parse(&frame, frame.len(), frame.len(), false)
                .unwrap()
                .unwrap();
            ethernet.orient(NdisPath::Receive);
            let mut engine = engine();
            let id = submit(&mut engine, ethernet, &frame, 101, 1, Some(55));
            engine.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            let incoming = parse(&reply(&bytes, ipv6), ipv6, Direction::Inbound);
            assert_eq!(
                engine.preflight(101, &incoming, 2, 102).unwrap_err().finish,
                Finish::Allow
            );
            assert!(engine.preflight(102, &incoming, 3, 102).unwrap());
            let other_protocol = parse(
                &datagram(ipv6, if protocol == 6 { 17 } else { 6 }),
                ipv6,
                Direction::Outbound,
            );
            assert!(engine.preflight(101, &other_protocol, 4, 102).unwrap());
        }
    }
}

#[test]
fn forwarding_has_no_ndis_send_cancel_id_and_pause_invalidates_both_owners() {
    let bytes = datagram(false, 17);
    let packet = parse(&bytes, false, Direction::Inbound);
    let mut engine = engine();
    let ndis = submit(&mut engine, packet, &bytes, 101, 1, Some(55));
    let wfp = submit(&mut engine, packet, &bytes, 101, 2, None);
    assert_eq!(engine.cancel(101, 55).unwrap().nbl, 1);
    assert!(engine.cancel(101, 55).is_none());
    assert!(engine.verdict(ndis, Verdict::PermanentAccept, 101).is_err());
    assert_eq!(engine.verdict(wfp, Verdict::Accept, 101).unwrap().nbl, 2);
    let first = submit(&mut engine, packet, &bytes, 101, 3, Some(55));
    let second = submit(&mut engine, packet, &bytes, 101, 4, None);
    let unrelated = submit(&mut engine, packet, &bytes, 102, 5, None);
    engine.invalidate(101, true);
    let mut tokens = Vec::new();
    while let Some(action) = engine.take_due(102) {
        assert_eq!(action.finish, Finish::Drop);
        tokens.push(action.nbl);
    }
    tokens.sort_unstable();
    assert_eq!(tokens, [3, 4]);
    assert!(engine.restart(101));
    for id in [first, second] {
        assert!(engine.verdict(id, Verdict::PermanentAccept, 103).is_err());
    }
    assert!(engine.preflight(101, &packet, 6, 104).unwrap());
    assert_eq!(
        engine.verdict(unrelated, Verdict::Accept, 104).unwrap().nbl,
        5
    );
}

#[test]
fn reassembled_forward_groups_cannot_seed_or_hit_permanent_cache() {
    for ipv6 in [false, true] {
        let bytes = datagram(ipv6, 6);
        let regular = parse(&bytes, ipv6, Direction::Outbound);
        let mut reassembled = regular;
        reassembled.cacheable = false;
        let mut engine = engine();
        let id = submit(&mut engine, reassembled, &bytes, 101, 1, None);
        engine.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        assert!(engine.preflight(101, &regular, 2, 102).unwrap());
        let id = submit(&mut engine, regular, &bytes, 101, 3, None);
        engine.verdict(id, Verdict::PermanentAccept, 103).unwrap();
        assert!(engine.preflight(101, &reassembled, 4, 104).unwrap());
    }
}

#[test]
fn forwarded_bandwidth_counts_admitted_ip_bytes_in_guest_tx_rx_direction() {
    for ipv6 in [false, true] {
        let request = datagram(ipv6, 17);
        let response = reply(&request, ipv6);
        let mut engine = engine();
        for (bytes, direction) in [
            (&request, Direction::Outbound),
            (&response, Direction::Inbound),
        ] {
            let packet = parse(bytes, ipv6, direction);
            let id = submit(&mut engine, packet, bytes, 101, 1, None);
            engine.verdict(id, Verdict::Accept, 101).unwrap();
        }
        engine.bandwidth();
        let event = record(&mut engine, if ipv6 { 6 } else { 5 });
        assert_eq!(event[5], 17);
        assert_eq!(u32::from_le_bytes(event[6..10].try_into().unwrap()), 101);
        assert_eq!(u32::from_le_bytes(event[10..14].try_into().unwrap()), 1);
        let counters = if ipv6 { 50 } else { 26 };
        assert_eq!(
            u64::from_le_bytes(event[counters..counters + 8].try_into().unwrap()),
            request.len() as u64
        );
        assert_eq!(
            u64::from_le_bytes(event[counters + 8..counters + 16].try_into().unwrap()),
            response.len() as u64
        );
    }
}

#[test]
fn global_forwarding_needs_no_ndis_attachment_and_keeps_source_interface_statistics() {
    for ipv6 in [false, true] {
        let request = datagram(ipv6, 17);
        let response = reply(&request, ipv6);
        let mut engine = Engine::new();
        assert!(!engine.ensure_forward(0));
        assert!(engine.ensure_forward(7));
        assert!(engine.ensure_forward(49));
        assert!(!engine.restart(7));
        engine.connect();
        for (index, bytes) in [(7, &request), (49, &response)] {
            let packet = parse(bytes, ipv6, Direction::Outbound);
            let id = submit(&mut engine, packet, bytes, index, index as usize, None);
            let event = record(&mut engine, if ipv6 { 2 } else { 1 });
            assert_eq!(u32::from_le_bytes(event[13..17].try_into().unwrap()), index);
            assert_eq!(event[17], 0);
            let action = engine.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            assert_eq!(action.nbl, index as usize);
            assert_eq!(action.finish, Finish::Allow);
        }
        engine.bandwidth();
        let mut bytes = [0u8; 4096];
        let count = engine.read(&mut bytes);
        let mut offset = 0;
        let mut indices = Vec::new();
        while offset < count {
            let size =
                u32::from_le_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
            if bytes[offset] == if ipv6 { 6 } else { 5 } {
                let frame = &bytes[offset..offset + 5 + size];
                let index = u32::from_le_bytes(frame[6..10].try_into().unwrap());
                indices.push(index);
                let counters = if ipv6 { 50 } else { 26 };
                assert_eq!(
                    u64::from_le_bytes(frame[counters..counters + 8].try_into().unwrap()),
                    request.len() as u64
                );
                assert_eq!(
                    u64::from_le_bytes(frame[counters + 8..counters + 16].try_into().unwrap()),
                    0
                );
            }
            offset += 5 + size;
        }
        indices.sort_unstable();
        assert_eq!(indices, [7, 49]);
    }
}

#[test]
fn ndis_and_forwarding_use_one_policy_row_without_extra_packet_ids_or_lifetime_keys() {
    let bytes = datagram(false, 6);
    let packet = parse(&bytes, false, Direction::Outbound);
    let mut engine = Engine::new();
    assert!(engine.ensure_forward(7));
    engine.connect();
    let id = submit(&mut engine, packet, &bytes, 7, 123, None);
    for _ in 0..100 {
        assert!(engine.ensure_forward(7));
    }
    assert!(engine.attach(7));
    assert!(!engine.attach(7));
    assert!(engine.restart(7));
    let action = engine.verdict(id, Verdict::PermanentAccept, 101).unwrap();
    assert_eq!(action.nbl, 123);
    assert_eq!(
        engine.preflight(7, &packet, 124, 102).unwrap_err().finish,
        Finish::Allow
    );
    engine.invalidate(7, true);
    assert!(engine.preflight(7, &packet, 125, 103).unwrap());
    engine.detach(7);
    let next = submit(&mut engine, packet, &bytes, 7, 126, None);
    assert_eq!(engine.verdict(next, Verdict::Accept, 104).unwrap().nbl, 126);
    assert!(engine.attach(7));
    engine.stop_forward();
    assert_eq!(
        engine.preflight(7, &packet, 127, 105).unwrap_err().finish,
        Finish::Drop
    );
    assert!(engine.restart(7));
    assert!(engine.preflight(7, &packet, 128, 106).unwrap());
}

#[test]
fn forwarding_shutdown_releases_only_forward_membership_and_invalidates_its_pending_nbls() {
    let bytes = datagram(false, 17);
    let packet = parse(&bytes, false, Direction::Outbound);
    let mut engine = Engine::new();
    assert!(engine.attach(52));
    assert!(engine.restart(52));
    for index in 1..=100 {
        assert!(engine.ensure_forward(index));
    }
    engine.connect();
    let id = submit(&mut engine, packet, &bytes, 7, 1, None);
    engine.stop_forward();
    assert!(engine.verdict(id, Verdict::PermanentAccept, 101).is_err());
    assert_eq!(engine.take_due(102).unwrap().nbl, 1);
    assert!(engine.take_due(102).is_none());
    assert!(engine.preflight(52, &packet, 2, 103).unwrap());
    assert_eq!(
        engine.preflight(7, &packet, 3, 103).unwrap_err().finish,
        Finish::Drop
    );
    assert!(engine.ensure_forward(7));
    assert!(engine.preflight(7, &packet, 4, 104).unwrap());
}

#[test]
fn icmp_echo_verdicts_allow_each_packet_without_cache_or_tcp_udp_bandwidth() {
    for ipv6 in [false, true] {
        for verdict in [
            Verdict::Accept,
            Verdict::PermanentAccept,
            Verdict::Block,
            Verdict::PermanentBlock,
            Verdict::Drop,
            Verdict::PermanentDrop,
        ] {
            let request = datagram(ipv6, if ipv6 { 58 } else { 1 });
            let response = reply(&request, ipv6);
            let mut engine = Engine::new();
            assert!(engine.ensure_forward(7));
            assert!(engine.ensure_forward(8));
            engine.connect();
            for sequence in 0..4 {
                for (index, bytes) in [(7, &request), (8, &response)] {
                    assert!(engine.ensure_forward(index));
                    let packet = parse(bytes, ipv6, Direction::Outbound);
                    assert!(!packet.cacheable);
                    assert_eq!(packet.flow.l2_len, 0);
                    assert_eq!(packet.connection.local_port, 0);
                    assert_eq!(packet.connection.remote_port, 0);
                    let nbl = 100 + sequence * 2 + index as usize;
                    assert!(engine.preflight(index, &packet, nbl, 100).unwrap());
                    let id = submit(&mut engine, packet, bytes, index, nbl, None);
                    let event = record(&mut engine, if ipv6 { 2 } else { 1 });
                    assert_eq!(u32::from_le_bytes(event[13..17].try_into().unwrap()), index);
                    assert_eq!(event[17], 0);
                    assert_eq!(event[18], if ipv6 { 58 } else { 1 });
                    assert_eq!(&event[connection_header_len(&packet.connection)..], bytes);
                    assert!(engine.cache_plan(id, verdict, 101).is_none());
                    let action = engine.verdict(id, verdict, 101).unwrap();
                    assert_eq!(action.nbl, nbl);
                    assert_eq!(
                        action.finish,
                        if verdict.allows() {
                            Finish::Allow
                        } else {
                            Finish::Drop
                        }
                    );
                    assert_eq!(engine.pending_count(), 0);
                    assert_eq!(engine.cache_candidates(), 0);
                }
            }
            assert_eq!(engine.stats().cache_hits, 0);
            engine.bandwidth();
            assert_eq!(engine.read(&mut [0; 512]), 0);
        }
    }
}

#[test]
fn formatted_injection_diagnostics_use_the_existing_bounded_log_record() {
    let mut engine = Engine::new();
    engine.connect();
    let _ = engine.read(&mut [0; 512]);
    let status = 0xc000000du32;
    engine.log_args(
        4,
        format_args!("WFP IPv4 forward injection completion failed: status=0x{status:08X}"),
    );
    let event = record(&mut engine, 0);
    assert_eq!(event[5], 4);
    assert_eq!(
        &event[6..],
        b"WFP IPv4 forward injection completion failed: status=0xC000000D"
    );
    engine.log_args(4, format_args!("{:0500}", 0));
    assert_eq!(engine.read(&mut [0; 512]), 0);
    engine.disconnect();
    engine.log_args(4, format_args!("offline failure"));
    assert_eq!(engine.read(&mut [0; 512]), 0);
}
