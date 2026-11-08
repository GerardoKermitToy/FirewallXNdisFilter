use firewallx_policy::{
    engine::{Engine, Finish, Submission, allocate_record},
    packet::{self, NdisPath, Packet, SNAPSHOT},
};
use firewallx_protocol::{MAX_PAYLOAD, MAX_RECORD, Verdict, connection_header_len};

fn frame(ipv6: bool, vlans: usize, ip_len: usize, offload: bool) -> Vec<u8> {
    let l2 = 14 + vlans * 4;
    let ip_header = if ipv6 { 40 } else { 20 };
    let mut frame = vec![0; l2 + ip_len];
    let ether_type: u16 = if ipv6 { 0x86dd } else { 0x0800 };
    frame[12..14].copy_from_slice(&(if vlans == 0 { ether_type } else { 0x8100 }).to_be_bytes());
    for tag in 0..vlans {
        let offset = 14 + tag * 4;
        frame[offset..offset + 2].copy_from_slice(&((tag + 1) as u16).to_be_bytes());
        frame[offset + 2..offset + 4]
            .copy_from_slice(&(if tag + 1 == vlans { ether_type } else { 0x8100 }).to_be_bytes());
    }
    let ip = &mut frame[l2..];
    for (i, byte) in ip.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    ip[..ip_header + 20].fill(0);
    if ipv6 {
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(if offload { 0 } else { (ip_len - 40) as u16 }).to_be_bytes());
        ip[6] = 6;
        ip[8] = 0x20;
        ip[9] = 1;
        ip[23] = 1;
        ip[24] = 0x20;
        ip[25] = 1;
        ip[39] = 2;
    } else {
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(if offload { 0 } else { ip_len as u16 }).to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);
    }
    ip[ip_header..ip_header + 2].copy_from_slice(&12345u16.to_be_bytes());
    ip[ip_header + 2..ip_header + 4].copy_from_slice(&443u16.to_be_bytes());
    ip[ip_header + 12] = 0x50;
    ip[ip_header + 13] = 0x10;
    frame
}

fn parse(frame: &[u8], path: NdisPath, offload: bool) -> Packet {
    let copied = frame.len().min(SNAPSHOT);
    let mut packet = packet::parse(&frame[..copied], copied, frame.len(), offload)
        .unwrap()
        .unwrap();
    packet.orient(path);
    packet
}

fn capture(packet: &Packet, frame: &[u8]) -> Vec<u8> {
    let layout = packet.capture_layout().unwrap();
    let mut data = allocate_record(layout.record_len).unwrap();
    // Exactly the range written by the kernel's NdisGetDataBuffer snapshot.
    data[layout.frame_start..].copy_from_slice(&frame[..layout.frame_len]);
    data
}

fn round_trip(packet: Packet, frame: &[u8], path: NdisPath, chunk_len: usize) -> Vec<u8> {
    let mut engine = Box::new(Engine::new());
    assert!(engine.attach(101));
    assert!(engine.restart(101));
    engine.connect();
    engine.read(&mut [0; 512]);
    assert!(engine.wants_event(101, &packet, 100));
    let data = capture(&packet, frame);
    let Submission::Pending(id) = engine.submit(
        101,
        packet,
        1,
        (path == NdisPath::Send).then_some(0),
        100,
        Some(data),
    ) else {
        panic!("expected a complete packet event");
    };
    let mut result = Vec::new();
    let mut chunk = vec![0; chunk_len];
    loop {
        let n = engine.read(&mut chunk);
        if n == 0 {
            break;
        }
        result.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(u64::from_le_bytes(result[5..13].try_into().unwrap()), id);
    assert_eq!(
        u32::from_le_bytes(result[1..5].try_into().unwrap()) as usize,
        result.len() - 5
    );
    assert_eq!(u32::from_le_bytes(result[13..17].try_into().unwrap()), 101);
    assert_eq!(result[17], packet.connection.direction as u8);
    let prefix = connection_header_len(&packet.connection);
    assert_eq!(
        u32::from_le_bytes(result[prefix - 4..prefix].try_into().unwrap()),
        packet.payload_len
    );
    assert_eq!(result.len(), prefix + packet.payload_len as usize);
    result
}

#[test]
fn complete_ipv4_and_ipv6_packets_preserve_vlan_direction_and_exclude_padding() {
    for ipv6 in [false, true] {
        for ip_len in [1500, if ipv6 { 65575 } else { 65535 }] {
            for vlans in 0..=2 {
                for path in [NdisPath::Receive, NdisPath::Send] {
                    let mut bytes = frame(ipv6, vlans, ip_len, false);
                    let original = bytes.clone();
                    bytes.extend_from_slice(&[0xcc; 31]); // Ethernet padding is not IP payload.
                    let packet = parse(&bytes, path, false);
                    assert_eq!(packet.payload_len as usize, ip_len);
                    assert_eq!(packet.flow.l2_len as usize, 14 + vlans * 4);
                    let event = round_trip(packet, &bytes, path, 65536);
                    let prefix = connection_header_len(&packet.connection);
                    assert_eq!(&event[prefix..], &original[14 + vlans * 4..]);
                    assert_eq!(&bytes[..original.len()], &original);
                }
            }
        }
    }
}

#[test]
fn maximum_offloaded_logical_packets_are_transferred_in_full() {
    for ipv6 in [false, true] {
        let bytes = frame(ipv6, 2, MAX_PAYLOAD, true);
        let packet = parse(&bytes, NdisPath::Send, true);
        assert!(!packet.cacheable);
        assert_eq!(packet.payload_len as usize, MAX_PAYLOAD);
        let event = round_trip(packet, &bytes, NdisPath::Send, 65536);
        let prefix = connection_header_len(&packet.connection);
        assert_eq!(&event[prefix..], &bytes[22..]);
        assert!(event.len() <= MAX_RECORD);
    }
}

#[test]
fn oversized_logical_packets_are_rejected_instead_of_truncated() {
    for ipv6 in [false, true] {
        let bytes = frame(ipv6, 0, 512, true);
        assert_eq!(
            packet::parse(&bytes[..SNAPSHOT], SNAPSHOT, 14 + MAX_PAYLOAD + 1, true).unwrap_err(),
            packet::ParseError::TooLarge,
        );
    }
}

#[test]
fn small_reads_do_not_drop_the_tail_of_a_full_packet() {
    let bytes = frame(true, 1, 5000, false);
    let packet = parse(&bytes, NdisPath::Receive, false);
    for chunk in [1, 3, 31, 512] {
        let event = round_trip(packet, &bytes, NdisPath::Receive, chunk);
        assert_eq!(
            &event[connection_header_len(&packet.connection)..],
            &bytes[18..]
        );
    }
}

#[test]
fn aggregate_nbl_accounting_does_not_concatenate_or_shorten_the_first_packet() {
    let bytes = frame(false, 0, 4096, false);
    let mut packet = parse(&bytes, NdisPath::Receive, false);
    packet.ip_len *= 2;
    packet.cacheable = false;
    let event = round_trip(packet, &bytes, NdisPath::Receive, 1024);
    assert_eq!(
        &event[connection_header_len(&packet.connection)..],
        &bytes[14..]
    );
}

fn coalesced_udp_frame(ipv6: bool, ip_len: usize) -> Vec<u8> {
    let mut bytes = frame(ipv6, 0, ip_len, true);
    let ip = &mut bytes[14..];
    let header = if ipv6 { 40 } else { 20 };
    ip[if ipv6 { 6 } else { 9 }] = 17;
    let length = if ipv6 { ip_len - 40 } else { ip_len };
    let offset = if ipv6 { 4 } else { 2 };
    ip[offset..offset + 2].copy_from_slice(&u16::try_from(length).unwrap_or(0).to_be_bytes());
    ip[header..header + 8].fill(0);
    ip[header..header + 2].copy_from_slice(&12345u16.to_be_bytes());
    ip[header + 2..header + 4].copy_from_slice(&443u16.to_be_bytes());
    ip[header + 4..header + 6]
        .copy_from_slice(&u16::try_from(ip_len - header).unwrap_or(0).to_be_bytes());
    // URO retains zero checksum fields; segmentation metadata is native OOB.
    bytes
}

#[test]
fn coalesced_udp_payload_is_complete_and_unchanged_in_both_directions() {
    for ipv6 in [false, true] {
        for length in [4096, 65535, MAX_PAYLOAD] {
            for path in [NdisPath::Receive, NdisPath::Send] {
                let bytes = coalesced_udp_frame(ipv6, length);
                let packet = parse(&bytes, path, true);
                assert!(!packet.cacheable);
                assert_eq!(packet.connection.protocol, 17);
                assert_eq!(packet.payload_len as usize, length);
                let event = round_trip(packet, &bytes, path, 65536);
                assert_eq!(
                    &event[connection_header_len(&packet.connection)..],
                    &bytes[14..]
                );
            }
        }
    }
}

#[test]
fn coalesced_udp_verdicts_do_not_cache_and_bandwidth_counts_logical_ip_bytes() {
    for ipv6 in [false, true] {
        for path in [NdisPath::Receive, NdisPath::Send] {
            let bytes = coalesced_udp_frame(ipv6, 4096);
            let packet = parse(&bytes, path, true);
            let mut engine = Engine::new();
            assert!(engine.attach(101));
            assert!(engine.restart(101));
            engine.connect();
            engine.read(&mut [0; 512]);
            let Submission::Pending(id) =
                engine.submit(101, packet, 123, None, 100, Some(capture(&packet, &bytes)))
            else {
                panic!("coalesced UDP must await a verdict");
            };
            let mut events = [0; 8192];
            assert!(engine.read(&mut events) > 0);
            assert!(
                engine
                    .cache_plan(id, Verdict::PermanentAccept, 101)
                    .is_none()
            );
            let action = engine.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            assert_eq!(action.nbl, 123);
            assert_eq!(action.finish, Finish::Allow);
            assert!(engine.preflight(101, &packet, 124, 102).unwrap());
            engine.bandwidth();
            let count = engine.read(&mut events);
            assert!(count > 0);
            assert_eq!(events[0], if ipv6 { 6 } else { 5 });
            assert_eq!(events[5], 17);
            let counters = if ipv6 { 50 } else { 26 };
            let tx = u64::from_le_bytes(events[counters..counters + 8].try_into().unwrap());
            let rx = u64::from_le_bytes(events[counters + 8..counters + 16].try_into().unwrap());
            assert_eq!(
                (tx, rx),
                if path == NdisPath::Receive {
                    (4096, 0)
                } else {
                    (0, 4096)
                }
            );
        }
    }
}
