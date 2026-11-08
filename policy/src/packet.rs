use firewallx_protocol::{Connection, Direction, MAX_PAYLOAD, connection_header_len};
use likely_stable::{likely, unlikely};

pub const SNAPSHOT: usize = 320;

// Raw native values describe NDIS ownership, not public wire direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NdisPath {
    Send = 0,
    Receive = 1,
}
impl NdisPath {
    pub const fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Send),
            1 => Some(Self::Receive),
            _ => None,
        }
    }
    pub const fn direction(self) -> Direction {
        // On a guest-facing adapter receive is guest outbound, but this mapping
        // applies to all adapters without claiming guest identity.
        match self {
            Self::Send => Direction::Inbound,
            Self::Receive => Direction::Outbound,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub l2: [u8; 22],
    pub l2_len: u8,
    pub ipv6: bool,
    pub protocol: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
}
impl Flow {
    pub const EMPTY: Self = Self {
        l2: [0; 22],
        l2_len: 0,
        ipv6: false,
        protocol: 0,
        source: [0; 16],
        destination: [0; 16],
        source_port: 0,
        destination_port: 0,
    };
}
#[derive(Clone, Copy, Debug)]
pub struct Packet {
    pub flow: Flow,
    pub connection: Connection,
    pub cacheable: bool,
    // IPv4 TTL or IPv6 Hop Limit; never part of the flow/cache identity.
    pub hop_limit: u8,
    // False for fragments or an incomplete bounded header parse.
    mergeable: bool,
    pub ip_len: u64,      // Total bytes for bandwidth; can aggregate same-flow NBs.
    pub payload_len: u32, // Complete IP packet in the first NB, without Ethernet padding.
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureLayout {
    pub record_len: usize,
    pub frame_start: usize,
    pub frame_len: usize,
}
impl Packet {
    pub const EMPTY: Self = Self {
        flow: Flow::EMPTY,
        connection: Connection::EMPTY,
        cacheable: false,
        hop_limit: 0,
        mergeable: false,
        ip_len: 0,
        payload_len: 0,
    };
    // Leave room for the wire prefix and copy Ethernet+IP straight into the final
    // allocation. Encoding the prefix later overwrites only the Ethernet bytes.
    pub fn capture_layout(&self) -> Option<CaptureLayout> {
        let payload_len = self.payload_len as usize;
        if unlikely(payload_len > MAX_PAYLOAD) {
            return None;
        }
        let prefix = connection_header_len(&self.connection);
        let l2_len = usize::from(self.flow.l2_len);
        Some(CaptureLayout {
            record_len: prefix + payload_len,
            frame_start: prefix.checked_sub(l2_len)?,
            frame_len: l2_len + payload_len,
        })
    }
    // One verdict covers a homogeneous NBL; only the first NB supplies payload.
    // Only TCP/UDP flow keys identify the transport in this parser.
    // The chain has no count quota and can account for more than u32::MAX bytes.
    pub fn merge(&mut self, other: &Self) -> Result<(), ParseError> {
        if unlikely(
            !self.mergeable
                || !other.mergeable
                || self.flow != other.flow
                || !matches!(self.flow.protocol, 6 | 17),
        ) {
            return Err(ParseError::Malformed);
        }
        self.ip_len = self.ip_len.saturating_add(other.ip_len);
        self.cacheable = false;
        Ok(())
    }
    pub fn orient(&mut self, path: NdisPath) {
        self.orient_direction(path.direction());
    }
    pub fn orient_direction(&mut self, direction: Direction) {
        self.connection.direction = direction;
        let (local_ip, remote_ip, local_port, remote_port) = match direction {
            Direction::Outbound => (
                self.flow.source,
                self.flow.destination,
                self.flow.source_port,
                self.flow.destination_port,
            ),
            Direction::Inbound => (
                self.flow.destination,
                self.flow.source,
                self.flow.destination_port,
                self.flow.source_port,
            ),
        };
        self.connection.local_ip = local_ip;
        self.connection.remote_ip = remote_ip;
        self.connection.local_port = local_port;
        self.connection.remote_port = remote_port;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    Malformed,
    TooManyVlans,
    TooLarge,
}

fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

// Only read policy fields from the readable NDIS host-memory prefix. Both headers
// and payload remain untrusted network input and all offsets are checked.
// None means a non-IP Ethernet control frame, outside the legacy L3 wire API.
// Hints favor valid IPv4 TCP/UDP, without excluding other traffic or errors.
pub fn parse(
    data: &[u8],
    trusted_len: usize,
    frame_len: usize,
    offload: bool,
) -> Result<Option<Packet>, ParseError> {
    let trusted = &data[..trusted_len.min(data.len())];
    if unlikely(trusted.len() < 14 || frame_len < 14) {
        return Err(ParseError::Truncated);
    }
    let mut offset = 14;
    let mut ether_type = be16(trusted, 12);
    let mut tags = 0;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if unlikely(tags == 2) {
            // The flow key stores at most two tags, but extra tags do not
            // make an otherwise identifiable non-IP control frame IP traffic.
            while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
                if unlikely(trusted.len() < offset + 4 || frame_len < offset + 4) {
                    return Err(ParseError::Truncated);
                }
                ether_type = be16(trusted, offset + 2);
                offset += 4;
            }
            return if matches!(ether_type, 0x0800 | 0x86dd) {
                Err(ParseError::TooManyVlans)
            } else {
                Ok(None)
            };
        }
        if unlikely(trusted.len() < offset + 4 || frame_len < offset + 4) {
            return Err(ParseError::Truncated);
        }
        ether_type = be16(trusted, offset + 2);
        offset += 4;
        tags += 1;
    }
    if unlikely(!matches!(ether_type, 0x0800 | 0x86dd)) {
        return Ok(None);
    }
    let mut p = parse_ip(
        &trusted[offset..],
        trusted.len() - offset,
        frame_len.checked_sub(offset).ok_or(ParseError::Truncated)?,
        ether_type == 0x86dd,
        offload,
    )?;
    p.flow.l2[..offset].copy_from_slice(&trusted[..offset]);
    p.flow.l2_len = offset as u8;
    Ok(Some(p))
}

// Parse at the IP header. Share all length/transport validation with
// Ethernet input without inventing a link header or changing captured bytes.
pub fn parse_ip(
    data: &[u8],
    trusted_len: usize,
    packet_len: usize,
    ipv6: bool,
    offload: bool,
) -> Result<Packet, ParseError> {
    let ip = &data[..trusted_len.min(data.len())];
    let logical = packet_len;
    let mut p = Packet::EMPTY;
    let (mut transport, mut proto, fragmented, ip_len) = if likely(!ipv6) {
        if unlikely(ip.len() < 20) {
            return Err(ParseError::Truncated);
        }
        let ihl = usize::from(ip[0] & 15) * 4;
        let total = usize::from(be16(ip, 2));
        if unlikely(ip[0] >> 4 != 4 || ihl < 20 || total < ihl && !offload) {
            return Err(ParseError::Malformed);
        }
        if unlikely(ip.len() < ihl || logical < ihl) {
            return Err(ParseError::Truncated);
        }
        if unlikely(total > logical && !offload) {
            return Err(ParseError::Truncated);
        }
        p.hop_limit = ip[8];
        p.flow.source[..4].copy_from_slice(&ip[12..16]);
        p.flow.destination[..4].copy_from_slice(&ip[16..20]);
        (
            ihl,
            ip[9],
            be16(ip, 6) & 0x3fff != 0,
            if offload { logical } else { total },
        )
    } else {
        if unlikely(ip.len() < 40 || logical < 40) {
            return Err(ParseError::Truncated);
        }
        if unlikely(ip[0] >> 4 != 6) {
            return Err(ParseError::Malformed);
        }
        let payload = usize::from(be16(ip, 4));
        // This bounded parser does not decode the Jumbo Payload option. For a
        // non-offload zero length, keep only the base header so Ethernet padding
        // cannot be mistaken for transport data; offload keeps its logical length.
        let total = if offload {
            logical
        } else if payload == 0 {
            40
        } else {
            40 + payload
        };
        if unlikely(total > logical) {
            return Err(ParseError::Truncated);
        }
        p.hop_limit = ip[7];
        p.flow.ipv6 = true;
        p.flow.source.copy_from_slice(&ip[8..24]);
        p.flow.destination.copy_from_slice(&ip[24..40]);
        (40, ip[6], false, total)
    };
    if unlikely(ip_len > MAX_PAYLOAD) {
        return Err(ParseError::TooLarge);
    }
    let mut fragment = fragmented;
    let mut fully_parsed = true;
    if unlikely(p.flow.ipv6) {
        let mut steps = 0;
        while matches!(proto, 0 | 43 | 60 | 44 | 51) {
            steps += 1;
            // An unavailable snapshot is not necessarily malformed, but the
            // advertised extension must fit in the logical IPv6 packet.
            if transport + 2 > ip_len {
                return Err(ParseError::Malformed);
            }
            if steps > 8 || transport + 2 > ip.len() {
                fully_parsed = false;
                break;
            }
            let len = match proto {
                44 => 8,
                51 => (usize::from(ip[transport + 1]) + 2) * 4,
                _ => (usize::from(ip[transport + 1]) + 1) * 8,
            };
            if transport + len > ip_len {
                return Err(ParseError::Malformed);
            }
            if transport + len > ip.len() {
                fully_parsed = false;
                break;
            }
            let next = ip[transport];
            let non_initial = proto == 44 && be16(ip, transport + 2) & 0xfff8 != 0;
            fragment |= proto == 44;
            transport += len;
            proto = next;
            if non_initial {
                fully_parsed = false;
                break;
            }
        }
    }
    if fully_parsed && !fragment && likely(matches!(proto, 6 | 17)) {
        let min = if proto == 6 { 20 } else { 8 };
        if unlikely(transport + min > ip_len) {
            return Err(ParseError::Malformed);
        }
        if transport + min <= ip.len() {
            if proto == 6 {
                let tcp_len = usize::from(ip[transport + 12] >> 4) * 4;
                if unlikely(tcp_len < 20 || transport + tcp_len > ip_len) {
                    return Err(ParseError::Malformed);
                }
            } else {
                let udp_len = usize::from(be16(ip, transport + 4));
                if unlikely(!offload && (udp_len < 8 || udp_len > ip_len - transport)) {
                    return Err(ParseError::Malformed);
                }
            }
            p.flow.source_port = be16(ip, transport);
            p.flow.destination_port = be16(ip, transport + 2);
            p.cacheable = !offload;
        } else {
            // The logical packet can be complete while the bounded snapshot
            // does not contain its transport header.
            fully_parsed = false;
        }
    }
    p.mergeable = fully_parsed && !fragment;
    p.flow.protocol = proto;
    p.ip_len = ip_len as u64;
    p.connection.ipv6 = p.flow.ipv6;
    p.connection.protocol = proto;
    p.connection.local_ip = p.flow.source;
    p.connection.remote_ip = p.flow.destination;
    p.connection.local_port = p.flow.source_port;
    p.connection.remote_port = p.flow.destination_port;
    p.payload_len = ip_len as u32;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn udp() -> [u8; 64] {
        let mut b = [0; 64];
        b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        b[14] = 0x45;
        b[16..18].copy_from_slice(&28u16.to_be_bytes());
        b[23] = 17;
        b[26..30].copy_from_slice(&[10, 0, 0, 1]);
        b[30..34].copy_from_slice(&[10, 0, 0, 2]);
        b[34..36].copy_from_slice(&1234u16.to_be_bytes());
        b[36..38].copy_from_slice(&53u16.to_be_bytes());
        b[38..40].copy_from_slice(&8u16.to_be_bytes());
        b
    }
    #[test]
    fn raw_ip_uses_the_same_parser_without_a_synthetic_ethernet_header() {
        for ipv6 in [false, true] {
            let mut frame = udp();
            if ipv6 {
                frame = [0; 64];
                frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
                frame[14] = 0x60;
                frame[18..20].copy_from_slice(&8u16.to_be_bytes());
                frame[20] = 17;
                frame[22..38].copy_from_slice(&[0x20; 16]);
                frame[38..54].copy_from_slice(&[0x30; 16]);
                frame[54..56].copy_from_slice(&1234u16.to_be_bytes());
                frame[56..58].copy_from_slice(&53u16.to_be_bytes());
                frame[58..60].copy_from_slice(&8u16.to_be_bytes());
            }
            let ethernet = parse(&frame, frame.len(), frame.len(), false)
                .unwrap()
                .unwrap();
            let ip = &frame[14..];
            let raw = parse_ip(ip, ip.len(), ip.len(), ipv6, false).unwrap();
            assert_eq!(raw.flow.l2_len, 0);
            assert_eq!(raw.payload_len, ethernet.payload_len);
            assert_eq!(raw.ip_len, ethernet.ip_len);
            assert_eq!(raw.cacheable, ethernet.cacheable);
            assert!(raw.cacheable);
            for direction in [Direction::Outbound, Direction::Inbound] {
                let mut raw = raw;
                let mut ethernet = ethernet;
                raw.orient_direction(direction);
                ethernet.orient_direction(direction);
                assert_eq!(raw.connection, ethernet.connection);
                let layout = raw.capture_layout().unwrap();
                assert_eq!(layout.frame_start, connection_header_len(&raw.connection));
                assert_eq!(layout.frame_len, raw.payload_len as usize);
                assert_eq!(layout.record_len, layout.frame_start + layout.frame_len);
            }
            assert_eq!(
                parse_ip(ip, ip.len(), ip.len(), !ipv6, false).unwrap_err(),
                ParseError::Malformed
            );
            assert_eq!(
                parse_ip(ip, 19, ip.len(), ipv6, false).unwrap_err(),
                ParseError::Truncated
            );
            assert_eq!(
                parse_ip(ip, ip.len(), 19, ipv6, false).unwrap_err(),
                ParseError::Truncated
            );
        }
    }
    #[test]
    fn ipv4_udp_network_payload_and_ports() {
        let b = udp();
        let p = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
        assert!(p.cacheable);
        assert_eq!(p.flow.source_port, 1234);
        assert_eq!(p.payload_len, 28);
        assert_eq!(p.ip_len, 28);
    }
    #[test]
    fn udp_lengths_are_bounded_by_ip_not_ethernet_padding() {
        for ipv6 in [false, true] {
            let mut b = udp();
            let port = if ipv6 {
                b = [0; 64];
                b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
                b[14] = 0x60;
                b[18..20].copy_from_slice(&8u16.to_be_bytes());
                b[20] = 17;
                b[54..56].copy_from_slice(&1234u16.to_be_bytes());
                b[56..58].copy_from_slice(&53u16.to_be_bytes());
                54
            } else {
                34
            };
            b[port + 4..port + 6].copy_from_slice(&8u16.to_be_bytes());
            let valid = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
            assert!(valid.cacheable);
            assert_eq!(valid.flow.source_port, 1234);
            assert_eq!(valid.flow.destination_port, 53);
            for length in [0u16, 7, 9, 100, u16::MAX] {
                b[port + 4..port + 6].copy_from_slice(&length.to_be_bytes());
                assert_eq!(
                    parse(&b, b.len(), b.len(), false).unwrap_err(),
                    ParseError::Malformed
                );
                // Offload headers may have unfinished lengths, but cannot cache.
                let offload = parse(&b, b.len(), b.len(), true).unwrap().unwrap();
                assert!(!offload.cacheable);
            }
        }
    }
    #[test]
    fn ipv6_zero_payload_is_rejected_without_offload() {
        let mut b = [0; 64];
        b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        b[14] = 0x60;
        b[20] = 17;
        b[22..38].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        b[38..54].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        b[54..56].copy_from_slice(&1234u16.to_be_bytes());
        b[56..58].copy_from_slice(&53u16.to_be_bytes());
        b[58..60].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(
            parse(&b, b.len(), b.len(), false).unwrap_err(),
            ParseError::Malformed
        );
        let offload = parse(&b, b.len(), b.len(), true).unwrap().unwrap();
        assert_eq!(offload.payload_len, 50);
        assert!(!offload.cacheable);

        b[20] = 59; // No Next Header: a valid empty IPv6 payload.
        let empty = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
        assert_eq!(empty.payload_len, 40);
        assert_eq!(empty.flow.protocol, 59);
        assert!(!empty.cacheable);
    }
    #[test]
    fn homogeneous_batch_has_no_nb_quota_and_preserves_first_payload() {
        let b = udp();
        let first = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
        let mut batch = first;
        for _ in 1..4097 {
            batch.merge(&first).unwrap();
        }
        assert_eq!(batch.ip_len, 4097 * first.ip_len);
        assert_eq!(batch.payload_len, first.payload_len);
        assert_eq!(batch.capture_layout(), first.capture_layout());
        assert!(!batch.cacheable);
        let original = batch;
        let mut other = first;
        other.flow.source_port += 1;
        assert_eq!(batch.merge(&other), Err(ParseError::Malformed));
        assert_eq!(batch.ip_len, original.ip_len);
        assert_eq!(batch.payload_len, original.payload_len);
    }
    fn merged(mut first: Packet, second: &Packet) -> Result<(), ParseError> {
        first.merge(second)
    }
    #[test]
    fn unidentified_transport_flows_cannot_be_merged() {
        for ipv6 in [false, true] {
            // ICMP, ESP and SCTP have no transport identity in this parser.
            for protocol in [if ipv6 { 58 } else { 1 }, 50, 132] {
                for offload in [false, true] {
                    let ip_header = if ipv6 { 40 } else { 20 };
                    let ip_len = ip_header + 16;
                    let mut frame = [0u8; 14 + 40 + 16];
                    frame[12..14]
                        .copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800u16 }).to_be_bytes());
                    let ip = &mut frame[14..14 + ip_len];
                    if ipv6 {
                        ip[0] = 0x60;
                        ip[4..6].copy_from_slice(&16u16.to_be_bytes());
                        ip[6] = protocol;
                        ip[23] = 1;
                        ip[39] = 2;
                    } else {
                        ip[0] = 0x45;
                        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
                        ip[9] = protocol;
                        ip[15] = 1;
                        ip[19] = 2;
                    }
                    // These are distinct SCTP destination ports when protocol=132.
                    ip[ip_header..ip_header + 2].copy_from_slice(&5000u16.to_be_bytes());
                    ip[ip_header + 2..ip_header + 4].copy_from_slice(&5001u16.to_be_bytes());
                    let mut second = frame;
                    second[14 + ip_header + 2..14 + ip_header + 4]
                        .copy_from_slice(&5002u16.to_be_bytes());
                    let length = 14 + ip_len;
                    for raw_ip in [false, true] {
                        let parse_frame = |bytes: &[u8]| {
                            if raw_ip {
                                parse_ip(&bytes[14..length], ip_len, ip_len, ipv6, offload).unwrap()
                            } else {
                                parse(bytes, length, length, offload).unwrap().unwrap()
                            }
                        };
                        let first = parse_frame(&frame);
                        let other = parse_frame(&second);
                        assert_eq!(first.flow, other.flow);
                        assert_eq!(first.flow.protocol, protocol);
                        assert_eq!(
                            (first.flow.source_port, first.flow.destination_port),
                            (0, 0)
                        );
                        assert_eq!(first.payload_len as usize, ip_len);
                        assert!(!first.cacheable);
                        assert_eq!(merged(first, &other), Err(ParseError::Malformed));
                        assert_eq!(merged(other, &first), Err(ParseError::Malformed));
                        assert_eq!(merged(first, &first), Err(ParseError::Malformed));
                    }
                }
            }
        }
    }
    #[test]
    fn complete_tcp_udp_flows_still_merge() {
        for ipv6 in [false, true] {
            for protocol in [6u8, 17] {
                for offload in [false, true] {
                    let ip_header = if ipv6 { 40 } else { 20 };
                    let transport_len = if protocol == 6 { 20 } else { 8 };
                    let ip_len = ip_header + transport_len;
                    let mut frame = [0u8; 14 + 40 + 20];
                    frame[12..14]
                        .copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800u16 }).to_be_bytes());
                    let ip = &mut frame[14..14 + ip_len];
                    if ipv6 {
                        ip[0] = 0x60;
                        ip[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
                        ip[6] = protocol;
                        ip[23] = 1;
                        ip[39] = 2;
                    } else {
                        ip[0] = 0x45;
                        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
                        ip[9] = protocol;
                        ip[15] = 1;
                        ip[19] = 2;
                    }
                    ip[ip_header..ip_header + 2].copy_from_slice(&1234u16.to_be_bytes());
                    ip[ip_header + 2..ip_header + 4].copy_from_slice(&53u16.to_be_bytes());
                    if protocol == 6 {
                        ip[ip_header + 12] = 0x50;
                    } else {
                        ip[ip_header + 4..ip_header + 6].copy_from_slice(&8u16.to_be_bytes());
                    }
                    let mut second = frame;
                    second[14 + ip_header + 2..14 + ip_header + 4]
                        .copy_from_slice(&443u16.to_be_bytes());
                    let length = 14 + ip_len;
                    for raw_ip in [false, true] {
                        let parse_frame = |bytes: &[u8]| {
                            if raw_ip {
                                parse_ip(&bytes[14..length], ip_len, ip_len, ipv6, offload).unwrap()
                            } else {
                                parse(bytes, length, length, offload).unwrap().unwrap()
                            }
                        };
                        let first = parse_frame(&frame);
                        let other = parse_frame(&second);
                        assert_eq!(first.cacheable, !offload);
                        assert_eq!(
                            (first.flow.source_port, first.flow.destination_port),
                            (1234, 53)
                        );
                        let mut batch = first;
                        assert_eq!(batch.merge(&first), Ok(()));
                        assert_eq!(batch.ip_len, 2 * first.ip_len);
                        assert_eq!(batch.payload_len, first.payload_len);
                        assert!(!batch.cacheable);
                        assert_eq!(batch.merge(&other), Err(ParseError::Malformed));
                    }
                }
            }
        }
    }
    #[test]
    fn incomplete_flow_keys_never_merge_even_when_their_fields_match() {
        let mut frame = udp();
        // Zero is a valid parsed port value, so the port values alone cannot
        // distinguish a complete key from an unavailable transport header.
        frame[34..38].fill(0);
        let complete = parse(&frame, frame.len(), frame.len(), false)
            .unwrap()
            .unwrap();
        let incomplete = parse(&frame, 34, frame.len(), false).unwrap().unwrap();
        assert_eq!(complete.flow, incomplete.flow);
        assert!(complete.mergeable);
        assert!(!incomplete.mergeable);
        assert_eq!(merged(complete, &incomplete), Err(ParseError::Malformed));
        assert_eq!(merged(incomplete, &complete), Err(ParseError::Malformed));
        assert_eq!(merged(incomplete, &incomplete), Err(ParseError::Malformed));
        assert_eq!(merged(complete, &complete), Ok(()));
    }
    #[test]
    fn incomplete_ipv6_extension_keys_reject_mixed_nbls_for_both_paths() {
        const EXTENSION: usize = 320;
        let mut first = [0u8; 40 + EXTENSION + 8];
        first[0] = 0x60;
        first[4..6].copy_from_slice(&((EXTENSION + 8) as u16).to_be_bytes());
        first[6] = 60; // Destination Options
        first[8..24].copy_from_slice(&[0x20; 16]);
        first[24..40].copy_from_slice(&[0x30; 16]);
        first[40] = 17; // UDP after the complete extension
        first[41] = (EXTENSION / 8 - 1) as u8;
        first[40 + EXTENSION..42 + EXTENSION].copy_from_slice(&1234u16.to_be_bytes());
        first[42 + EXTENSION..44 + EXTENSION].copy_from_slice(&53u16.to_be_bytes());
        first[44 + EXTENSION..46 + EXTENSION].copy_from_slice(&8u16.to_be_bytes());
        let mut second = first;
        second[42 + EXTENSION..44 + EXTENSION].copy_from_slice(&443u16.to_be_bytes());

        // Parsing without an Ethernet header starts at the IP header.
        let first_ip = parse_ip(&first[..SNAPSHOT], SNAPSHOT, first.len(), true, false).unwrap();
        let second_ip = parse_ip(&second[..SNAPSHOT], SNAPSHOT, second.len(), true, false).unwrap();
        assert_eq!(first_ip.flow, second_ip.flow);
        assert_eq!(first_ip.flow.protocol, 60);
        assert_eq!(first_ip.flow.destination_port, 0);
        assert_eq!(first_ip.payload_len as usize, first.len());
        assert!(!first_ip.mergeable);
        assert_eq!(merged(first_ip, &second_ip), Err(ParseError::Malformed));

        // NDIS sees the same IP packet after its Ethernet header.
        let mut first_frame = [0u8; 14 + 40 + EXTENSION + 8];
        first_frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        first_frame[14..].copy_from_slice(&first);
        let mut second_frame = first_frame;
        second_frame[14..].copy_from_slice(&second);
        let first_ndis = parse(&first_frame[..SNAPSHOT], SNAPSHOT, first_frame.len(), false)
            .unwrap()
            .unwrap();
        let second_ndis = parse(
            &second_frame[..SNAPSHOT],
            SNAPSHOT,
            second_frame.len(),
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(first_ndis.flow, second_ndis.flow);
        assert!(!first_ndis.mergeable);
        assert_eq!(merged(first_ndis, &second_ndis), Err(ParseError::Malformed));
    }
    #[test]
    fn ipv6_transport_beyond_snapshot_cannot_form_a_batch() {
        const EXTENSION: usize = 280;
        for protocol in [6u8, 17] {
            let mut ip = [0u8; 40 + EXTENSION + 20];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&((EXTENSION + 20) as u16).to_be_bytes());
            ip[6] = 60;
            ip[40] = protocol;
            ip[41] = (EXTENSION / 8 - 1) as u8;
            let transport = 40 + EXTENSION;
            ip[transport..transport + 2].copy_from_slice(&1234u16.to_be_bytes());
            ip[transport + 2..transport + 4].copy_from_slice(&53u16.to_be_bytes());
            if protocol == 6 {
                ip[transport + 12] = 0x50;
            } else {
                ip[transport + 4..transport + 6].copy_from_slice(&20u16.to_be_bytes());
            }
            let complete = parse_ip(&ip, ip.len(), ip.len(), true, false).unwrap();
            assert!(complete.mergeable);
            assert_eq!(complete.flow.destination_port, 53);
            let incomplete = parse_ip(&ip[..SNAPSHOT], SNAPSHOT, ip.len(), true, false).unwrap();
            assert!(!incomplete.mergeable);
            assert_eq!(incomplete.flow.protocol, protocol);
            assert_eq!(incomplete.flow.destination_port, 0);
            assert_eq!(merged(incomplete, &incomplete), Err(ParseError::Malformed));
        }
    }
    #[test]
    fn fragment_flow_keys_cannot_be_merged() {
        let mut ipv4 = udp();
        ipv4[20] = 0x20; // More Fragments
        let fragment = parse(&ipv4, ipv4.len(), ipv4.len(), false)
            .unwrap()
            .unwrap();
        assert!(!fragment.mergeable);
        assert_eq!(merged(fragment, &fragment), Err(ParseError::Malformed));

        let mut ipv6 = [0u8; 40 + 8 + 8];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&16u16.to_be_bytes());
        ipv6[6] = 44; // Fragment
        ipv6[40] = 17;
        ipv6[42..44].copy_from_slice(&1u16.to_be_bytes()); // More Fragments
        let fragment = parse_ip(&ipv6, ipv6.len(), ipv6.len(), true, false).unwrap();
        assert!(!fragment.mergeable);
        assert_eq!(merged(fragment, &fragment), Err(ParseError::Malformed));
    }
    #[test]
    fn large_batch_bandwidth_is_64_bit_and_saturates_without_wrapping() {
        let b = udp();
        let first = parse(&b, b.len(), 14 + MAX_PAYLOAD, true).unwrap().unwrap();
        let mut batch = first;
        for _ in 1..8193 {
            batch.merge(&first).unwrap();
        }
        assert_eq!(batch.ip_len, 8193 * MAX_PAYLOAD as u64);
        assert!(batch.ip_len > u64::from(u32::MAX));
        assert_eq!(batch.payload_len as usize, MAX_PAYLOAD);
        batch.ip_len = u64::MAX;
        batch.merge(&first).unwrap();
        assert_eq!(batch.ip_len, u64::MAX);
    }
    #[test]
    fn host_send_normalizes_guest_endpoints_without_changing_capture() {
        let b = udp();
        let mut p = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
        let original = p;
        p.orient(NdisPath::Send);
        assert_eq!(p.connection.direction, Direction::Inbound);
        assert_eq!(p.connection.local_ip, p.flow.destination);
        assert_eq!(p.connection.remote_ip, p.flow.source);
        assert_eq!(p.connection.local_port, 53);
        assert_eq!(p.connection.remote_port, 1234);
        assert_eq!(p.payload_len, original.payload_len);
        assert_eq!(p.capture_layout(), original.capture_layout());
        assert_eq!(p.flow, original.flow);
        p.orient(NdisPath::Receive);
        assert_eq!(p.connection, original.connection);
    }
    #[test]
    fn replies_have_the_same_guest_tuple_for_ipv4_and_ipv6() {
        for ipv6 in [false, true] {
            let mut b = udp();
            let (source, destination, size, port) = if ipv6 {
                b = [0; 64];
                b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
                b[14] = 0x60;
                b[18..20].copy_from_slice(&8u16.to_be_bytes());
                b[20] = 17;
                b[22] = 0x20;
                b[23] = 1;
                b[37] = 1;
                b[38] = 0x20;
                b[39] = 1;
                b[53] = 2;
                b[54..56].copy_from_slice(&1234u16.to_be_bytes());
                b[56..58].copy_from_slice(&53u16.to_be_bytes());
                b[58..60].copy_from_slice(&8u16.to_be_bytes());
                (22, 38, 16, 54)
            } else {
                (26, 30, 4, 34)
            };
            let mut outbound = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
            outbound.orient(NdisPath::Receive);
            assert_eq!(outbound.connection.direction, Direction::Outbound);
            for i in 0..size {
                b.swap(source + i, destination + i);
            }
            b.swap(port, port + 2);
            b.swap(port + 1, port + 3);
            let mut inbound = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
            inbound.orient(NdisPath::Send);
            assert_eq!(inbound.connection.direction, Direction::Inbound);
            assert_eq!(inbound.connection.local_ip, outbound.connection.local_ip);
            assert_eq!(inbound.connection.remote_ip, outbound.connection.remote_ip);
            assert_eq!(
                inbound.connection.local_port,
                outbound.connection.local_port
            );
            assert_eq!(
                inbound.connection.remote_port,
                outbound.connection.remote_port
            );
            assert_ne!(inbound.flow.source, outbound.flow.source);
            assert_eq!(inbound.payload_len, outbound.payload_len);
        }
    }
    #[test]
    fn every_truncation_is_bounded() {
        let b = udp();
        for i in 0..b.len() {
            let _ = parse(&b[..i], i, i, false);
        }
        for i in 0..b.len() {
            let _ = parse(&b, i, b.len(), false);
        }
        assert!(parse(&b, 14, b.len(), false).is_err());
    }
    #[test]
    fn fragments_and_offload_cannot_seed_cache() {
        let mut b = udp();
        b[20] = 0x20;
        let p = parse(&b, 64, 64, false).unwrap().unwrap();
        assert!(!p.cacheable);
        assert_eq!(p.flow.destination_port, 0);
        b[20] = 0;
        assert!(!parse(&b, 64, 64, true).unwrap().unwrap().cacheable);
    }
    #[test]
    fn vlan_and_non_ip() {
        let b = udp();
        let mut v = [0; 68];
        v[..12].copy_from_slice(&b[..12]);
        v[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        v[14..16].copy_from_slice(&123u16.to_be_bytes());
        v[16..].copy_from_slice(&b[12..]);
        let p = parse(&v, 68, 68, false).unwrap().unwrap();
        assert_eq!(p.flow.l2_len, 18);
        assert_eq!(p.flow.destination_port, 53);
        v[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(parse(&v, 68, 68, false).unwrap().is_none());
    }
    #[test]
    fn deeply_tagged_non_ip_bypasses_without_letting_ip_escape() {
        for tags in [3usize, 4, 16] {
            for ether_type in [0x0806u16, 0x88cc, 0x888e, 0x8863, 0x0800, 0x86dd] {
                let mut frame = [0u8; 14 + 16 * 4];
                frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
                for tag in 0..tags {
                    let next = if tag + 1 == tags { ether_type } else { 0x8100 };
                    frame[16 + tag * 4..18 + tag * 4].copy_from_slice(&next.to_be_bytes());
                }
                let len = 14 + tags * 4;
                let parsed = parse(&frame[..len], len, len, false);
                if matches!(ether_type, 0x0800 | 0x86dd) {
                    assert_eq!(parsed.unwrap_err(), ParseError::TooManyVlans);
                } else {
                    assert!(parsed.unwrap().is_none());
                }
                assert!(parse(&frame[..len - 1], len - 1, len - 1, false).is_err());
            }
        }
    }
    #[test]
    fn ipv6_extensions_and_fragment() {
        let mut b = [0; 90];
        b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        b[14] = 0x60;
        b[18..20].copy_from_slice(&16u16.to_be_bytes());
        b[20] = 0;
        b[54] = 17;
        b[62..64].copy_from_slice(&123u16.to_be_bytes());
        b[64..66].copy_from_slice(&53u16.to_be_bytes());
        b[66..68].copy_from_slice(&8u16.to_be_bytes());
        let p = parse(&b, 90, 90, false).unwrap().unwrap();
        assert!(p.cacheable);
        assert_eq!(p.flow.protocol, 17);
        b[20] = 44;
        assert!(!parse(&b, 90, 90, false).unwrap().unwrap().cacheable);
    }
    #[test]
    fn nine_ipv6_extensions_are_admitted_without_caching() {
        let mut ip = [0u8; 40 + 9 * 8 + 8];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&80u16.to_be_bytes());
        ip[6] = 60;
        for index in 0..9 {
            ip[40 + index * 8] = if index == 8 { 17 } else { 60 };
        }
        ip[40 + 9 * 8 + 4..40 + 9 * 8 + 6].copy_from_slice(&8u16.to_be_bytes());
        let p = parse_ip(&ip, ip.len(), ip.len(), true, false).unwrap();
        assert!(!p.cacheable);
        assert!(!p.mergeable);
        assert_eq!(merged(p, &p), Err(ParseError::Malformed));
        assert_eq!(p.payload_len as usize, ip.len());
    }
    #[test]
    fn advertised_ipv6_extension_must_fit_declared_packet() {
        for payload in 0..=1 {
            let mut ip = [0u8; 48];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
            ip[6] = 0; // Hop-by-Hop Options
            assert_eq!(
                parse_ip(&ip, 40 + payload, 40 + payload, true, false).unwrap_err(),
                ParseError::Malformed
            );
        }
        // A short capture is distinct from a logically truncated packet.
        let mut ip = [0u8; 48];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&8u16.to_be_bytes());
        ip[6] = 0;
        let p = parse_ip(&ip, 40, ip.len(), true, false).unwrap();
        assert!(!p.cacheable);
    }
    #[test]
    fn no_cache_from_untrusted_transport() {
        let b = udp();
        let p = parse(&b, 34, 64, false).unwrap().unwrap();
        assert!(!p.cacheable);
        assert_eq!(p.flow.source_port, 0);
    }
    #[test]
    fn malformed_lengths_are_rejected() {
        let mut b = udp();
        b[14] = 0x41;
        assert_eq!(parse(&b, 64, 64, false).unwrap_err(), ParseError::Malformed);
        b = udp();
        b[38..40].copy_from_slice(&1u16.to_be_bytes());
        assert!(parse(&b, 64, 64, false).is_err());
        b = udp();
        b[38..40].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(parse(&b, 64, 64, false).unwrap_err(), ParseError::Malformed);
        b = udp();
        b[16..18].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse(&b, 64, 64, false).is_err());
    }
}
