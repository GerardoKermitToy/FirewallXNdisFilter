//! Track whether an owned NBL contains local or transit IP packets.
//!
//! Each NB must first pass the ordinary bounded Ethernet/IP parser. A mixed
//! NBL must be split before its local and transit NBs get independent decisions.

use firewallx_policy::packet::Packet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpScope {
    Local,
    Transit,
    Unknown,
}

/// DHCP client broadcasts use addresses and ports only. The other destination
/// exceptions require IPv4 TTL or IPv6 Hop Limit 1.
pub(crate) fn ip_scope(packet: &Packet, lookup: impl FnOnce() -> IpScope) -> IpScope {
    const IPV4_UNSPECIFIED: [u8; 4] = [0; 4];
    const IPV4_LIMITED_BROADCAST: [u8; 4] = [255; 4];
    const IP_PROTOCOL_UDP: u8 = 17;
    const DHCP_CLIENT_PORT: u16 = 68;
    const DHCP_SERVER_PORT: u16 = 67;

    if !packet.flow.ipv6
        && packet.flow.protocol == IP_PROTOCOL_UDP
        && packet.flow.source.starts_with(&IPV4_UNSPECIFIED)
        && packet.flow.destination.starts_with(&IPV4_LIMITED_BROADCAST)
        && packet.flow.source_port == DHCP_CLIENT_PORT
        && packet.flow.destination_port == DHCP_SERVER_PORT
    {
        return IpScope::Local;
    }
    if packet.hop_limit != 1 {
        return lookup();
    }

    const IPV4_LOCAL_MULTICAST: [u8; 3] = [224, 0, 0];
    const IPV4_DISCOVERY_MULTICAST: [u8; 4] = [239, 255, 255, 250];
    const IPV6_MULTICAST: u8 = 0xff;
    const IPV6_SCOPE_MASK: u8 = 0x0f;
    const IPV6_INTERFACE_LOCAL: u8 = 1;
    const IPV6_LINK_LOCAL: u8 = 2;

    let destination = &packet.flow.destination;
    let exempt = if packet.flow.ipv6 {
        destination[0] == IPV6_MULTICAST
            && matches!(
                destination[1] & IPV6_SCOPE_MASK,
                IPV6_INTERFACE_LOCAL | IPV6_LINK_LOCAL
            )
    } else {
        destination.starts_with(&IPV4_LOCAL_MULTICAST)
            || destination.starts_with(&IPV4_LIMITED_BROADCAST)
            || (destination.starts_with(&IPV4_DISCOVERY_MULTICAST)
                && packet.flow.protocol == IP_PROTOCOL_UDP)
    };
    if exempt { IpScope::Local } else { lookup() }
}

/// Local or unavailable inventory already bypasses policy, so only inspect
/// DHCP server replies when the inventory has identified transit traffic.
pub(crate) fn inventory_then_dhcp(scope: IpScope, is_dhcp: impl FnOnce() -> bool) -> IpScope {
    if scope == IpScope::Transit && is_dhcp() {
        IpScope::Local
    } else {
        scope
    }
}

fn dhcp_server_to_client(packet: &Packet) -> bool {
    const UDP: u8 = 17;
    const DHCPV4_SERVER_PORT: u16 = 67;
    const DHCPV4_CLIENT_PORT: u16 = 68;
    const DHCPV6_SERVER_PORT: u16 = 547;
    const DHCPV6_CLIENT_PORT: u16 = 546;
    let ports = if packet.flow.ipv6 {
        (DHCPV6_SERVER_PORT, DHCPV6_CLIENT_PORT)
    } else {
        (DHCPV4_SERVER_PORT, DHCPV4_CLIENT_PORT)
    };
    packet.flow.protocol == UDP && (packet.flow.source_port, packet.flow.destination_port) == ports
}

/// DHCPv6 clients use this link-scoped group to find servers and relays.
pub(crate) fn dhcpv6_client_multicast(packet: &Packet) -> bool {
    const UDP: u8 = 17;
    const DHCPV6_CLIENT_PORT: u16 = 546;
    const DHCPV6_SERVER_PORT: u16 = 547;
    const ALL_DHCP_RELAYS_AND_SERVERS: [u8; 16] =
        [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2];
    packet.flow.ipv6
        && packet.flow.protocol == UDP
        && packet.flow.source_port == DHCPV6_CLIENT_PORT
        && packet.flow.destination_port == DHCPV6_SERVER_PORT
        && packet.flow.destination == ALL_DHCP_RELAYS_AND_SERVERS
}

/// Broadcast replies are permitted based on the IP/UDP tuple alone.
pub(crate) fn dhcp_server_broadcast(packet: &Packet) -> bool {
    const IPV4_LIMITED_BROADCAST: [u8; 4] = [255; 4];
    !packet.flow.ipv6
        && dhcp_server_to_client(packet)
        && packet.flow.destination.starts_with(&IPV4_LIMITED_BROADCAST)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DhcpReply {
    Match,
    NoMatch,
    NeedMore,
}

/// Recognize DHCPv4 Offer/ACK or DHCPv6 Advertise/Reply within the UDP datagram.
/// `frame` is the readable prefix; a longer prefix is needed only when an
/// option needed for the decision is not present yet.
pub(crate) fn dhcp_reply(packet: &Packet, frame: &[u8], offload: bool) -> DhcpReply {
    const BOOTREPLY: u8 = 2;
    const BOOTP_HEADER_LEN: usize = 236;
    const COOKIE: [u8; 4] = [99, 130, 83, 99];
    const PAD: u8 = 0;
    const END: u8 = 255;
    const MESSAGE_TYPE: u8 = 53;
    const OFFER: u8 = 2;
    const ACK: u8 = 5;

    if !dhcp_server_to_client(packet) || offload {
        return DhcpReply::NoMatch;
    }
    if packet.flow.ipv6 {
        return dhcpv6_reply(packet, frame);
    }

    let ip = usize::from(packet.flow.l2_len);
    let Some(&version_ihl) = frame.get(ip) else {
        return DhcpReply::NeedMore;
    };
    let ip_header_len = usize::from(version_ihl & 15) * 4;
    let udp = ip + ip_header_len;
    let ip_end = ip + packet.payload_len as usize;
    if version_ihl >> 4 != 4 || ip_header_len < 20 || udp + 8 > ip_end {
        return DhcpReply::NoMatch;
    }
    let Some(length) = frame.get(udp + 4..udp + 6) else {
        return DhcpReply::NeedMore;
    };
    let udp_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let end = udp + udp_len;
    let bootp = udp + 8;
    let options = bootp + BOOTP_HEADER_LEN + COOKIE.len();
    if udp_len < 8 + BOOTP_HEADER_LEN + COOKIE.len() || end > ip_end {
        return DhcpReply::NoMatch;
    }
    if frame.len() < options {
        return DhcpReply::NeedMore;
    }
    if frame[bootp] != BOOTREPLY || frame[bootp + BOOTP_HEADER_LEN..options] != COOKIE {
        return DhcpReply::NoMatch;
    }

    let mut cursor = options;
    let mut found_reply = false;
    while cursor < end {
        let Some(&kind) = frame.get(cursor) else {
            return DhcpReply::NeedMore;
        };
        cursor += 1;
        match kind {
            PAD => continue,
            END => {
                return if found_reply {
                    DhcpReply::Match
                } else {
                    DhcpReply::NoMatch
                };
            }
            _ => {}
        }
        if cursor >= end {
            return DhcpReply::NoMatch;
        }
        let Some(&length) = frame.get(cursor) else {
            return DhcpReply::NeedMore;
        };
        cursor += 1;
        let next = cursor + usize::from(length);
        if next > end {
            return DhcpReply::NoMatch;
        }
        if next > frame.len() {
            return DhcpReply::NeedMore;
        }
        if kind == MESSAGE_TYPE {
            if found_reply || length != 1 || !matches!(frame[cursor], OFFER | ACK) {
                return DhcpReply::NoMatch;
            }
            found_reply = true;
        }
        cursor = next;
    }
    DhcpReply::NoMatch
}

/// Locate UDP through the same IPv6 extension types as the bounded parser,
/// then validate the DHCPv6 message header and option lengths.
fn dhcpv6_reply(packet: &Packet, frame: &[u8]) -> DhcpReply {
    const IPV6_HEADER_LEN: usize = 40;
    const UDP_HEADER_LEN: usize = 8;
    const DHCPV6_HEADER_LEN: usize = 4;
    const DHCPV6_OPTION_HEADER_LEN: usize = 4;
    const UDP: u8 = 17;
    const ADVERTISE: u8 = 2;
    const REPLY: u8 = 7;

    let ip = usize::from(packet.flow.l2_len);
    let ip_end = ip + packet.payload_len as usize;
    let mut udp = ip + IPV6_HEADER_LEN;
    if udp > ip_end {
        return DhcpReply::NoMatch;
    }
    let Some(header) = frame.get(ip..udp) else {
        return DhcpReply::NeedMore;
    };
    if header[0] >> 4 != 6 {
        return DhcpReply::NoMatch;
    }
    let mut next_header = header[6];
    let mut steps = 0;
    while matches!(next_header, 0 | 43 | 60 | 51) {
        steps += 1;
        if steps > 8 || udp + 2 > ip_end {
            return DhcpReply::NoMatch;
        }
        let Some(extension) = frame.get(udp..udp + 2) else {
            return DhcpReply::NeedMore;
        };
        let extension_len = if next_header == 51 {
            (usize::from(extension[1]) + 2) * 4
        } else {
            (usize::from(extension[1]) + 1) * 8
        };
        let end = udp + extension_len;
        if end > ip_end {
            return DhcpReply::NoMatch;
        }
        if end > frame.len() {
            return DhcpReply::NeedMore;
        }
        next_header = extension[0];
        udp = end;
    }
    // Fragment headers are intentionally not followed: ports on fragmented
    // packets are not validated by the ordinary parser.
    if next_header != UDP || udp + UDP_HEADER_LEN > ip_end {
        return DhcpReply::NoMatch;
    }
    let Some(length) = frame.get(udp + 4..udp + 6) else {
        return DhcpReply::NeedMore;
    };
    let udp_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let end = udp + udp_len;
    let mut option = udp + UDP_HEADER_LEN + DHCPV6_HEADER_LEN;
    if udp_len < UDP_HEADER_LEN + DHCPV6_HEADER_LEN || end > ip_end {
        return DhcpReply::NoMatch;
    }
    if frame.len() < option {
        return DhcpReply::NeedMore;
    }
    if !matches!(frame[udp + UDP_HEADER_LEN], ADVERTISE | REPLY) {
        return DhcpReply::NoMatch;
    }
    while option < end {
        if option + DHCPV6_OPTION_HEADER_LEN > end {
            return DhcpReply::NoMatch;
        }
        let Some(header) = frame.get(option..option + DHCPV6_OPTION_HEADER_LEN) else {
            return DhcpReply::NeedMore;
        };
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        option += DHCPV6_OPTION_HEADER_LEN + length;
        if option > end {
            return DhcpReply::NoMatch;
        }
        if option > frame.len() {
            return DhcpReply::NeedMore;
        }
    }
    DhcpReply::Match
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchScope {
    Empty,
    Local,
    Transit,
    Mixed,
    Unknown,
}

impl BatchScope {
    pub(crate) fn observe(self, next: IpScope) -> Self {
        match (self, next) {
            (_, IpScope::Unknown) | (Self::Unknown, _) => Self::Unknown,
            (Self::Mixed, _) => Self::Mixed,
            (Self::Empty | Self::Local, IpScope::Local) => Self::Local,
            (Self::Empty | Self::Transit, IpScope::Transit) => Self::Transit,
            (Self::Local, IpScope::Transit) | (Self::Transit, IpScope::Local) => Self::Mixed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchError {
    MixedIpAndNonIp,
    IncompatibleFlows,
}

#[derive(Debug)]
pub(crate) enum BatchDecision {
    NonIp,
    Local,
    Transit(Packet),
    Mixed,
    Unknown,
}

/// Collect the results of parsing every NB before choosing the NBL disposition.
/// Different transit flows can precede the first local NB, so their merge failure
/// is deferred until we know whether the entire batch needs a policy decision.
pub(crate) struct PacketBatch {
    scope: BatchScope,
    first: Option<Packet>,
    saw_non_ip: bool,
    incompatible_flows: bool,
}

impl PacketBatch {
    pub(crate) fn new() -> Self {
        Self {
            scope: BatchScope::Empty,
            first: None,
            saw_non_ip: false,
            incompatible_flows: false,
        }
    }

    pub(crate) fn observe_ip(&mut self, packet: Packet, scope: IpScope) -> Result<(), BatchError> {
        if self.saw_non_ip {
            return Err(BatchError::MixedIpAndNonIp);
        }
        self.scope = self.scope.observe(scope);
        if self.scope != BatchScope::Transit {
            return Ok(());
        }
        if let Some(first) = &mut self.first {
            if first.merge(&packet).is_err() {
                self.incompatible_flows = true;
            }
        } else {
            self.first = Some(packet);
        }
        Ok(())
    }

    pub(crate) fn observe_non_ip(&mut self) -> Result<(), BatchError> {
        if self.scope != BatchScope::Empty {
            return Err(BatchError::MixedIpAndNonIp);
        }
        self.saw_non_ip = true;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<BatchDecision, BatchError> {
        match self.scope {
            BatchScope::Empty => Ok(BatchDecision::NonIp),
            BatchScope::Local => Ok(BatchDecision::Local),
            BatchScope::Mixed => Ok(BatchDecision::Mixed),
            BatchScope::Unknown => Ok(BatchDecision::Unknown),
            BatchScope::Transit if self.incompatible_flows => Err(BatchError::IncompatibleFlows),
            BatchScope::Transit => self
                .first
                .map(BatchDecision::Transit)
                .ok_or(BatchError::IncompatibleFlows),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firewallx_policy::packet::{self, ParseError};

    fn ipv4() -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&28u16.to_be_bytes());
        frame[22] = 1;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[192, 168, 219, 15]);
        frame[30..34].copy_from_slice(&[34, 160, 111, 145]);
        frame[38..40].copy_from_slice(&8u16.to_be_bytes());
        frame
    }

    #[test]
    fn scope_never_treats_local_and_transit_as_one_verdict() {
        assert_eq!(BatchScope::Empty.observe(IpScope::Local), BatchScope::Local);
        assert_eq!(BatchScope::Local.observe(IpScope::Local), BatchScope::Local);
        assert_eq!(
            BatchScope::Empty.observe(IpScope::Transit),
            BatchScope::Transit
        );
        assert_eq!(
            BatchScope::Transit.observe(IpScope::Transit),
            BatchScope::Transit
        );
        assert_eq!(
            BatchScope::Local.observe(IpScope::Transit),
            BatchScope::Mixed
        );
        assert_eq!(
            BatchScope::Transit.observe(IpScope::Local),
            BatchScope::Mixed
        );
        assert_eq!(
            BatchScope::Local.observe(IpScope::Unknown),
            BatchScope::Unknown
        );
        assert_eq!(
            BatchScope::Transit.observe(IpScope::Unknown),
            BatchScope::Unknown
        );
    }

    fn parsed(port: u16) -> Packet {
        let mut frame = ipv4();
        frame[36..38].copy_from_slice(&port.to_be_bytes());
        packet::parse(&frame, frame.len(), frame.len(), false)
            .expect("valid frame")
            .expect("IPv4 packet")
    }

    fn ipv6() -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 40 + 8];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&8u16.to_be_bytes());
        frame[20] = 17;
        frame[21] = 1;
        frame[22] = 0x20;
        frame[38] = 0x20;
        frame[58..60].copy_from_slice(&8u16.to_be_bytes());
        frame
    }

    fn parsed_v6() -> Packet {
        let frame = ipv6();
        packet::parse(&frame, frame.len(), frame.len(), false)
            .expect("valid frame")
            .expect("IPv6 packet")
    }

    fn with_v4_destination(destination: [u8; 4]) -> Packet {
        let mut frame = ipv4();
        frame[30..34].copy_from_slice(&destination);
        packet::parse(&frame, frame.len(), frame.len(), false)
            .expect("valid IPv4 frame")
            .expect("IPv4 packet")
    }

    fn with_v6_destination(destination: [u8; 16]) -> Packet {
        let mut frame = ipv6();
        frame[38..54].copy_from_slice(&destination);
        packet::parse(&frame, frame.len(), frame.len(), false)
            .expect("valid IPv6 frame")
            .expect("IPv6 packet")
    }

    #[test]
    fn mdns_packet_bypasses_policy_in_both_ndis_directions() {
        let frame = mdns_udp_frame();
        let packet = parsed_frame(&frame);
        assert_eq!(&packet.flow.destination[..4], &[224, 0, 0, 251]);
        for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
            let mut packet = packet;
            packet.orient(path);
            let scope = ip_scope(&packet, || panic!("local group needs no inventory"));
            let mut batch = PacketBatch::new();
            batch.observe_ip(packet, scope).unwrap();
            assert!(matches!(batch.finish(), Ok(BatchDecision::Local)));
        }
    }

    fn discovery_frame() -> Vec<u8> {
        let mut frame = ipv4();
        frame[30..34].copy_from_slice(&[239, 255, 255, 250]);
        frame[34..36].copy_from_slice(&1900u16.to_be_bytes());
        frame[36..38].copy_from_slice(&1900u16.to_be_bytes());
        frame
    }

    fn parsed_frame(frame: &[u8]) -> Packet {
        packet::parse(frame, frame.len(), frame.len(), false)
            .expect("valid frame")
            .expect("IP packet")
    }

    fn mdns_udp_frame() -> Vec<u8> {
        let mut frame = ipv4();
        frame[30..34].copy_from_slice(&[224, 0, 0, 251]);
        frame[36..38].copy_from_slice(&5353u16.to_be_bytes());
        frame
    }

    // Synthetic headers only: the DHCP exception does not inspect UDP payload.
    fn dhcp_frame() -> Vec<u8> {
        let mut frame = ipv4();
        frame[22] = 255;
        frame[26..30].copy_from_slice(&[0; 4]);
        frame[30..34].copy_from_slice(&[255; 4]);
        frame[34..36].copy_from_slice(&68u16.to_be_bytes());
        frame[36..38].copy_from_slice(&67u16.to_be_bytes());
        frame
    }

    fn dhcp_reply_frame(options: &[u8]) -> Vec<u8> {
        let mut frame = ipv4();
        frame[22] = 64;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[255; 4]);
        frame[34..36].copy_from_slice(&67u16.to_be_bytes());
        frame[36..38].copy_from_slice(&68u16.to_be_bytes());
        frame.resize(14 + 20 + 8 + 240, 0);
        frame[42] = 2;
        frame[278..282].copy_from_slice(&[99, 130, 83, 99]);
        frame.extend_from_slice(options);
        let ip_len = (frame.len() - 14) as u16;
        let udp_len = (frame.len() - 34) as u16;
        frame[16..18].copy_from_slice(&ip_len.to_be_bytes());
        frame[38..40].copy_from_slice(&udp_len.to_be_bytes());
        frame
    }

    fn dhcp_scope(packet: &Packet, frame: &[u8]) -> IpScope {
        ip_scope(packet, || {
            inventory_then_dhcp(IpScope::Transit, || {
                dhcp_server_broadcast(packet)
                    || dhcpv6_client_multicast(packet)
                    || dhcp_reply(packet, frame, false) == DhcpReply::Match
            })
        })
    }

    #[test]
    fn local_or_unknown_inventory_never_inspects_dhcp_reply() {
        for scope in [IpScope::Local, IpScope::Unknown] {
            assert_eq!(
                inventory_then_dhcp(scope, || panic!("inventory already bypasses policy")),
                scope
            );
        }
        assert_eq!(
            inventory_then_dhcp(IpScope::Transit, || true),
            IpScope::Local
        );
        assert_eq!(
            inventory_then_dhcp(IpScope::Transit, || false),
            IpScope::Transit
        );
    }

    #[test]
    fn dhcp_offer_and_ack_bypass_policy_at_any_ttl_and_direction() {
        for message_type in [2, 5] {
            for destination in [[255; 4], [192, 0, 2, 99]] {
                for ttl in [0, 1, 2, 64, 128, 255] {
                    let mut frame = dhcp_reply_frame(&[0, 1, 2, 0, 1, 53, 1, message_type, 255]);
                    frame[22] = ttl;
                    frame[30..34].copy_from_slice(&destination);
                    let packet = parsed_frame(&frame);
                    for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
                        let mut packet = packet;
                        packet.orient(path);
                        assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::Match);
                        assert_eq!(dhcp_scope(&packet, &frame), IpScope::Local);
                    }
                }
            }
        }
    }

    #[test]
    fn dhcp_reply_accepts_vlan_ipv4_options_and_late_options() {
        let mut options = vec![0; 100];
        options.extend_from_slice(&[53, 1, 2, 255]);
        let mut frame = dhcp_reply_frame(&options);
        frame.splice(34..34, [0; 40]);
        frame[14] = 0x4f;
        let ip_len = frame.len() - 14;
        frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
        frame.splice(12..12, [0x81, 0, 0, 0]);
        frame.splice(12..12, [0x88, 0xa8, 0, 0]);
        let packet = parsed_frame(&frame);
        assert_eq!(packet.flow.l2_len, 22);
        assert_eq!(
            dhcp_reply(&packet, &frame[..320], false),
            DhcpReply::NeedMore
        );
        assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::Match);
    }

    #[test]
    fn dhcp_reply_handles_the_largest_ipv4_datagram() {
        let mut options = vec![0; 65_263];
        options.extend_from_slice(&[53, 1, 2, 255]);
        let frame = dhcp_reply_frame(&options);
        let packet = parsed_frame(&frame);
        assert_eq!(packet.payload_len, u16::MAX as u32);
        assert_eq!(
            dhcp_reply(&packet, &frame[..320], false),
            DhcpReply::NeedMore
        );
        assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::Match);
    }

    #[test]
    fn dhcp_reply_needs_complete_readable_option_bytes() {
        let frame = dhcp_reply_frame(&[0, 1, 3, 11, 22, 33, 53, 1, 2, 255]);
        let packet = parsed_frame(&frame);
        for end in 0..frame.len() {
            assert_eq!(
                dhcp_reply(&packet, &frame[..end], false),
                DhcpReply::NeedMore,
                "prefix {end}"
            );
        }
        assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::Match);
        assert_eq!(dhcp_reply(&packet, &frame, true), DhcpReply::NoMatch);
    }

    #[test]
    fn dhcp_reply_rejects_other_or_malformed_messages() {
        let mut other_source_port = dhcp_reply_frame(&[53, 1, 2, 255]);
        other_source_port[34..36].copy_from_slice(&68u16.to_be_bytes());
        let mut other_destination_port = dhcp_reply_frame(&[53, 1, 2, 255]);
        other_destination_port[36..38].copy_from_slice(&67u16.to_be_bytes());
        let mut wrong_op = dhcp_reply_frame(&[53, 1, 2, 255]);
        wrong_op[42] = 1;
        let mut wrong_cookie = dhcp_reply_frame(&[53, 1, 2, 255]);
        wrong_cookie[278] = 0;
        let mut fragmented = dhcp_reply_frame(&[53, 1, 2, 255]);
        fragmented[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut non_initial_fragment = fragmented.clone();
        non_initial_fragment[20..22].copy_from_slice(&1u16.to_be_bytes());
        let mut tcp = dhcp_reply_frame(&[53, 1, 2, 255]);
        tcp[23] = 6;
        tcp[46] = 0x50;
        for mut frame in [
            other_source_port,
            other_destination_port,
            wrong_op,
            wrong_cookie,
            fragmented,
            non_initial_fragment,
            tcp,
            dhcp_reply_frame(&[53, 1, 1, 255]),
            dhcp_reply_frame(&[53, 1, 6, 255]),
            dhcp_reply_frame(&[53, 0, 255]),
            dhcp_reply_frame(&[53, 2, 2, 0, 255]),
            dhcp_reply_frame(&[53, 1, 2]),
            dhcp_reply_frame(&[53, 1, 2, 53, 1, 2, 255]),
            dhcp_reply_frame(&[53, 1, 2, 53, 1, 5, 255]),
            dhcp_reply_frame(&[53, 1, 2, 1, 4, 0, 255]),
            dhcp_reply_frame(&[1, 4, 53, 1, 2]),
            dhcp_reply_frame(&[255, 53, 1, 2]),
            dhcp_reply_frame(&[]),
        ] {
            frame[30..34].copy_from_slice(&[192, 0, 2, 99]);
            let packet = parsed_frame(&frame);
            assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::NoMatch);
            assert_eq!(dhcp_scope(&packet, &frame), IpScope::Transit);
        }
        let mut ipv6 = ipv6();
        ipv6[54..56].copy_from_slice(&67u16.to_be_bytes());
        ipv6[56..58].copy_from_slice(&68u16.to_be_bytes());
        assert_eq!(
            dhcp_reply(&parsed_frame(&ipv6), &ipv6, false),
            DhcpReply::NoMatch
        );
    }

    #[test]
    fn dhcp_reply_never_uses_bytes_beyond_udp_length() {
        let mut frame = dhcp_reply_frame(&[53, 1, 2, 255]);
        frame[38..40].copy_from_slice(&(248u16).to_be_bytes());
        let packet = parsed_frame(&frame);
        assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::NoMatch);

        frame[38..40].copy_from_slice(&(250u16).to_be_bytes());
        let packet = parsed_frame(&frame);
        assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::NoMatch);
    }

    #[test]
    fn dhcp_reply_and_other_transit_packets_split_in_either_order() {
        let mut reply_frame = dhcp_reply_frame(&[53, 1, 5, 255]);
        let mut other_frame = dhcp_reply_frame(&[53, 1, 6, 255]);
        reply_frame[30..34].copy_from_slice(&[192, 0, 2, 99]);
        other_frame[30..34].copy_from_slice(&[192, 0, 2, 99]);
        let reply = parsed_frame(&reply_frame);
        let other = parsed_frame(&other_frame);
        for packets in [
            [(reply, &reply_frame), (other, &other_frame)],
            [(other, &other_frame), (reply, &reply_frame)],
        ] {
            let mut batch = PacketBatch::new();
            for (packet, frame) in packets {
                batch
                    .observe_ip(packet, dhcp_scope(&packet, frame))
                    .unwrap();
            }
            assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));
        }
    }

    #[test]
    fn dhcp_server_broadcast_uses_only_ipv4_addresses_and_ports() {
        for source in [[0, 0, 0, 0], [192, 0, 2, 1]] {
            for ttl in [0, 1, 2, 64, 128, 255] {
                for payload in [&[][..], &[3, 1, 4, 1, 5][..]] {
                    let mut frame = ipv4();
                    frame[22] = ttl;
                    frame[26..30].copy_from_slice(&source);
                    frame[30..34].copy_from_slice(&[255; 4]);
                    frame[34..36].copy_from_slice(&67u16.to_be_bytes());
                    frame[36..38].copy_from_slice(&68u16.to_be_bytes());
                    frame.extend_from_slice(payload);
                    let ip_len = (28 + payload.len()) as u16;
                    let udp_len = (8 + payload.len()) as u16;
                    frame[16..18].copy_from_slice(&ip_len.to_be_bytes());
                    frame[38..40].copy_from_slice(&udp_len.to_be_bytes());
                    for offload in [false, true] {
                        let packet = packet::parse(&frame, frame.len(), frame.len(), offload)
                            .unwrap()
                            .unwrap();
                        for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
                            let mut packet = packet;
                            packet.orient(path);
                            assert!(dhcp_server_broadcast(&packet));
                            assert_eq!(dhcp_scope(&packet, &frame), IpScope::Local);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn dhcp_server_broadcast_requires_the_exact_tuple() {
        let mut valid = dhcp_reply_frame(&[]);
        valid[22] = 64;
        let mut wrong_destination = valid.clone();
        wrong_destination[33] = 254;
        let mut directed_broadcast = valid.clone();
        directed_broadcast[30..34].copy_from_slice(&[192, 0, 2, 255]);
        let mut wrong_source_port = valid.clone();
        wrong_source_port[34..36].copy_from_slice(&68u16.to_be_bytes());
        let mut wrong_destination_port = valid.clone();
        wrong_destination_port[36..38].copy_from_slice(&67u16.to_be_bytes());
        let mut fragment = valid.clone();
        fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut tcp = valid;
        tcp[23] = 6;
        tcp[46] = 0x50;
        for frame in [
            wrong_destination,
            directed_broadcast,
            wrong_source_port,
            wrong_destination_port,
            fragment,
            tcp,
        ] {
            let packet = parsed_frame(&frame);
            assert!(!dhcp_server_broadcast(&packet));
            assert_eq!(dhcp_scope(&packet, &frame), IpScope::Transit);
        }
        let mut ipv6 = ipv6();
        ipv6[54..56].copy_from_slice(&67u16.to_be_bytes());
        ipv6[56..58].copy_from_slice(&68u16.to_be_bytes());
        assert!(!dhcp_server_broadcast(&parsed_frame(&ipv6)));
    }

    fn dhcpv6_frame(message_type: u8, options: &[u8]) -> Vec<u8> {
        let mut frame = ipv6();
        frame[21] = 64;
        frame[54..56].copy_from_slice(&547u16.to_be_bytes());
        frame[56..58].copy_from_slice(&546u16.to_be_bytes());
        frame.extend_from_slice(&[message_type, 1, 2, 3]);
        frame.extend_from_slice(options);
        let length = (frame.len() - 54) as u16;
        frame[18..20].copy_from_slice(&length.to_be_bytes());
        frame[58..60].copy_from_slice(&length.to_be_bytes());
        frame
    }

    fn dhcpv6_multicast_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = ipv6();
        frame[21] = 64;
        frame[38..54].copy_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2]);
        frame[54..56].copy_from_slice(&546u16.to_be_bytes());
        frame[56..58].copy_from_slice(&547u16.to_be_bytes());
        frame.extend_from_slice(payload);
        let length = (frame.len() - 54) as u16;
        frame[18..20].copy_from_slice(&length.to_be_bytes());
        frame[58..60].copy_from_slice(&length.to_be_bytes());
        frame
    }

    #[test]
    fn dhcpv6_client_multicast_uses_only_addresses_and_ports() {
        for hop in [0, 1, 2, 64, 128, 255] {
            for payload in [&[][..], &[7, 1, 4, 1, 5][..]] {
                let mut frame = dhcpv6_multicast_frame(payload);
                frame[21] = hop;
                for offload in [false, true] {
                    let packet = packet::parse(&frame, frame.len(), frame.len(), offload)
                        .unwrap()
                        .unwrap();
                    for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
                        let mut packet = packet;
                        packet.orient(path);
                        assert!(dhcpv6_client_multicast(&packet));
                        assert_eq!(dhcp_scope(&packet, &frame), IpScope::Local);
                    }
                }
            }
        }
    }

    #[test]
    fn dhcpv6_client_multicast_requires_exact_group_and_ports() {
        let base = dhcpv6_multicast_frame(&[]);
        let mut other_group = base.clone();
        other_group[53] = 3;
        let mut other_scope = base.clone();
        other_scope[39] = 5;
        let mut unicast = base.clone();
        unicast[38..54].copy_from_slice(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut wrong_source_port = base.clone();
        wrong_source_port[54..56].copy_from_slice(&547u16.to_be_bytes());
        let mut wrong_destination_port = base.clone();
        wrong_destination_port[56..58].copy_from_slice(&546u16.to_be_bytes());
        let mut fragmented = base.clone();
        fragmented[20] = 44;
        fragmented.splice(54..54, [17, 0, 0, 0, 0, 0, 0, 0]);
        let payload_len = (fragmented.len() - 54) as u16;
        fragmented[18..20].copy_from_slice(&payload_len.to_be_bytes());
        let mut tcp = base;
        tcp[20] = 6;
        tcp.resize(14 + 40 + 20, 0);
        tcp[18..20].copy_from_slice(&20u16.to_be_bytes());
        tcp[66] = 0x50;
        for frame in [
            other_group,
            other_scope,
            unicast,
            wrong_source_port,
            wrong_destination_port,
            fragmented,
            tcp,
        ] {
            let packet = parsed_frame(&frame);
            assert!(!dhcpv6_client_multicast(&packet));
            assert_eq!(dhcp_scope(&packet, &frame), IpScope::Transit);
        }
        assert!(!dhcpv6_client_multicast(&parsed_frame(&dhcp_reply_frame(
            &[]
        ))));
    }

    #[test]
    fn dhcpv6_advertise_and_reply_bypass_policy_at_any_hop_limit() {
        for message_type in [2, 7] {
            for hop in [0, 1, 2, 64, 128, 255] {
                let mut frame = dhcpv6_frame(message_type, &[0, 1, 0, 2, 0x12, 0x34]);
                frame[21] = hop;
                let packet = parsed_frame(&frame);
                for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
                    let mut packet = packet;
                    packet.orient(path);
                    assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::Match);
                    assert_eq!(dhcp_scope(&packet, &frame), IpScope::Local);
                }
            }
        }
    }

    #[test]
    fn dhcpv6_reply_supports_extension_headers_and_late_options() {
        let mut options = vec![0, 23, 1, 0];
        options.extend_from_slice(&[0; 256]);
        for extension_type in [0, 43, 60, 51] {
            let mut frame = dhcpv6_frame(7, &options);
            frame[20] = extension_type;
            frame.splice(54..54, [17, 0, 0, 0, 0, 0, 0, 0]);
            let payload_len = (frame.len() - 54) as u16;
            frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
            let packet = packet::parse(&frame[..320], 320, frame.len(), false)
                .unwrap()
                .unwrap();
            assert_eq!(
                dhcp_reply(&packet, &frame[..320], false),
                DhcpReply::NeedMore
            );
            assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::Match);
        }
    }

    #[test]
    fn dhcpv6_reply_rejects_wrong_type_ports_fragments_and_malformed_options() {
        let mut wrong_source_port = dhcpv6_frame(7, &[]);
        wrong_source_port[54..56].copy_from_slice(&546u16.to_be_bytes());
        let mut wrong_destination_port = dhcpv6_frame(7, &[]);
        wrong_destination_port[56..58].copy_from_slice(&547u16.to_be_bytes());
        let mut fragmented = dhcpv6_frame(7, &[]);
        fragmented[20] = 44;
        fragmented.splice(54..54, [17, 0, 0, 0, 0, 0, 0, 0]);
        let payload_len = (fragmented.len() - 54) as u16;
        fragmented[18..20].copy_from_slice(&payload_len.to_be_bytes());
        for frame in [
            wrong_source_port,
            wrong_destination_port,
            fragmented,
            dhcpv6_frame(1, &[]),
            dhcpv6_frame(10, &[]),
            dhcpv6_frame(7, &[0, 1, 0]),
            dhcpv6_frame(7, &[0, 1, 0, 4, 1, 2]),
        ] {
            let packet = parsed_frame(&frame);
            assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::NoMatch);
            assert_eq!(dhcp_scope(&packet, &frame), IpScope::Transit);
        }
        let frame = dhcpv6_frame(7, &[0, 1, 0, 2, 1, 2]);
        let packet = parsed_frame(&frame);
        for end in 0..frame.len() {
            assert_eq!(
                dhcp_reply(&packet, &frame[..end], false),
                DhcpReply::NeedMore,
                "prefix {end}"
            );
        }
        assert_eq!(dhcp_reply(&packet, &frame, true), DhcpReply::NoMatch);
    }

    #[test]
    fn dhcpv6_reply_never_uses_bytes_beyond_udp_length() {
        let mut frame = dhcpv6_frame(7, &[0, 1, 0, 2, 1, 2]);
        for udp_len in [11u16, 13] {
            frame[58..60].copy_from_slice(&udp_len.to_be_bytes());
            let packet = parsed_frame(&frame);
            assert_eq!(dhcp_reply(&packet, &frame, false), DhcpReply::NoMatch);
        }
    }

    #[test]
    fn dhcpv6_reply_and_other_transit_packets_split_in_either_order() {
        let reply_frame = dhcpv6_frame(7, &[]);
        let other_frame = dhcpv6_frame(10, &[]);
        let reply = parsed_frame(&reply_frame);
        let other = parsed_frame(&other_frame);
        for packets in [
            [(reply, &reply_frame), (other, &other_frame)],
            [(other, &other_frame), (reply, &reply_frame)],
        ] {
            let mut batch = PacketBatch::new();
            for (packet, frame) in packets {
                batch
                    .observe_ip(packet, dhcp_scope(&packet, frame))
                    .unwrap();
            }
            assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));
        }
    }

    #[test]
    fn dhcp_client_broadcast_bypasses_policy_at_any_ttl_and_direction() {
        for ttl in [0, 1, 2, 64, 128, 255] {
            for payload in [&[][..], &[3, 1, 4, 1, 5][..]] {
                let mut frame = dhcp_frame();
                frame[22] = ttl;
                frame.extend_from_slice(payload);
                let ip_len = 28 + payload.len() as u16;
                let udp_len = 8 + payload.len() as u16;
                frame[16..18].copy_from_slice(&ip_len.to_be_bytes());
                frame[38..40].copy_from_slice(&udp_len.to_be_bytes());
                let packet = parsed_frame(&frame);
                for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
                    let mut packet = packet;
                    packet.orient(path);
                    assert_eq!(
                        ip_scope(&packet, || panic!("DHCP tuple bypasses inventory")),
                        IpScope::Local
                    );
                }
            }
        }
        let frame = dhcp_frame();
        let offload = packet::parse(&frame, frame.len(), frame.len(), true)
            .unwrap()
            .unwrap();
        assert_eq!(ip_scope(&offload, || IpScope::Transit), IpScope::Local);
    }

    #[test]
    fn dhcp_exception_requires_exact_ipv4_udp_addresses_and_ports() {
        let mut other_source = dhcp_frame();
        other_source[26..30].copy_from_slice(&[192, 0, 2, 1]);
        let mut other_destination = dhcp_frame();
        other_destination[30..34].copy_from_slice(&[192, 0, 2, 255]);
        let mut other_source_port = dhcp_frame();
        other_source_port[34..36].copy_from_slice(&67u16.to_be_bytes());
        let mut other_destination_port = dhcp_frame();
        other_destination_port[36..38].copy_from_slice(&68u16.to_be_bytes());
        let mut tcp = dhcp_frame();
        tcp.resize(14 + 20 + 20, 0);
        tcp[16..18].copy_from_slice(&40u16.to_be_bytes());
        tcp[23] = 6;
        tcp[46] = 0x50;
        let mut fragmented = dhcp_frame();
        fragmented[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut ipv6 = ipv6();
        ipv6[21] = 255;
        ipv6[22..38].fill(0);
        ipv6[38..54].copy_from_slice(&[0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ipv6[54..56].copy_from_slice(&68u16.to_be_bytes());
        ipv6[56..58].copy_from_slice(&67u16.to_be_bytes());
        for frame in [
            other_source,
            other_destination,
            other_source_port,
            other_destination_port,
            tcp,
            fragmented,
            ipv6,
        ] {
            let packet = parsed_frame(&frame);
            for original in [IpScope::Local, IpScope::Transit, IpScope::Unknown] {
                assert_eq!(ip_scope(&packet, || original), original);
            }
        }
    }

    #[test]
    fn dhcp_and_transit_packets_split_in_either_order() {
        let dhcp = parsed_frame(&dhcp_frame());
        let mut other_frame = dhcp_frame();
        other_frame[36..38].copy_from_slice(&68u16.to_be_bytes());
        let transit = parsed_frame(&other_frame);
        for packets in [[dhcp, transit], [transit, dhcp]] {
            let mut batch = PacketBatch::new();
            for packet in packets {
                let scope = ip_scope(&packet, || IpScope::Transit);
                batch.observe_ip(packet, scope).unwrap();
            }
            assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));
        }
    }

    #[test]
    fn original_scope_applies_to_every_new_exemption_when_hop_limit_is_not_one() {
        let mdns = mdns_udp_frame();
        let mut fragmented_mdns = mdns.clone();
        fragmented_mdns[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut other_multicast = ipv4();
        other_multicast[30..34].copy_from_slice(&[224, 0, 0, 252]);
        let mut broadcast = ipv4();
        broadcast[30..34].copy_from_slice(&[255; 4]);
        let mut ipv6_link = ipv6();
        ipv6_link[38..40].copy_from_slice(&[0xff, 0x02]);
        ipv6_link[53] = 1;
        let mut ipv6_interface = ipv6_link.clone();
        ipv6_interface[39] = 0x01;

        for (base, hop_offset) in [
            (mdns, 22),
            (fragmented_mdns, 22),
            (other_multicast, 22),
            (broadcast, 22),
            (discovery_frame(), 22),
            (ipv6_link, 21),
            (ipv6_interface, 21),
        ] {
            assert_eq!(
                ip_scope(&parsed_frame(&base), || panic!(
                    "unit-hop exemption needs no inventory"
                )),
                IpScope::Local
            );
            for hop_limit in [0, 2, 64, 255] {
                let mut frame = base.clone();
                frame[hop_offset] = hop_limit;
                let packet = parsed_frame(&frame);
                assert_eq!(packet.hop_limit, hop_limit);
                for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
                    let mut packet = packet;
                    packet.orient(path);
                    for original in [IpScope::Local, IpScope::Transit, IpScope::Unknown] {
                        assert_eq!(ip_scope(&packet, || original), original);
                    }
                }
            }
        }
    }

    #[test]
    fn identical_discovery_flows_with_different_hop_limits_split() {
        for base in [mdns_udp_frame(), discovery_frame()] {
            let unit_hop = parsed_frame(&base);
            let mut non_unit_frame = base;
            non_unit_frame[22] = 2;
            let non_unit_hop = parsed_frame(&non_unit_frame);
            assert_eq!(unit_hop.flow, non_unit_hop.flow);
            for packets in [[unit_hop, non_unit_hop], [non_unit_hop, unit_hop]] {
                let mut batch = PacketBatch::new();
                for packet in packets {
                    let scope = ip_scope(&packet, || IpScope::Transit);
                    batch.observe_ip(packet, scope).unwrap();
                }
                assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));
            }
        }
    }

    #[test]
    fn transit_flow_merge_does_not_include_hop_limit_in_identity() {
        let mut first = discovery_frame();
        first[22] = 2;
        let mut second = first.clone();
        second[22] = 3;
        let mut batch = PacketBatch::new();
        for frame in [first, second] {
            let packet = parsed_frame(&frame);
            let scope = ip_scope(&packet, || IpScope::Transit);
            batch.observe_ip(packet, scope).unwrap();
        }
        let Ok(BatchDecision::Transit(packet)) = batch.finish() else {
            panic!("matching transit flows should merge");
        };
        assert_eq!(packet.ip_len, 56);
        assert!(!packet.cacheable);
    }

    #[test]
    fn discovery_packet_bypasses_policy_in_both_ndis_directions() {
        let frame = discovery_frame();
        let packet = parsed_frame(&frame);
        assert_eq!(&packet.flow.destination[..4], &[239, 255, 255, 250]);
        assert_eq!(packet.flow.protocol, 17);
        for path in [packet::NdisPath::Send, packet::NdisPath::Receive] {
            let mut packet = packet;
            packet.orient(path);
            let scope = ip_scope(&packet, || panic!("discovery group needs no inventory"));
            let mut batch = PacketBatch::new();
            batch.observe_ip(packet, scope).unwrap();
            assert!(matches!(batch.finish(), Ok(BatchDecision::Local)));
        }
    }

    #[test]
    fn discovery_exemption_requires_exact_group_and_udp_but_no_port() {
        for source_port in [0u16, 1900, 49152, u16::MAX] {
            for destination_port in [0u16, 1900, 3702, u16::MAX] {
                let mut frame = discovery_frame();
                frame[34..36].copy_from_slice(&source_port.to_be_bytes());
                frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
                assert_eq!(
                    ip_scope(&parsed_frame(&frame), || panic!(
                        "discovery needs no inventory"
                    )),
                    IpScope::Local
                );
            }
        }
        let mut other_group = discovery_frame();
        other_group[33] = 249;
        let mut tcp = discovery_frame();
        tcp.resize(14 + 20 + 20, 0);
        tcp[16..18].copy_from_slice(&40u16.to_be_bytes());
        tcp[23] = 6;
        tcp[46] = 0x50;
        let mut ipv6 = ipv6();
        ipv6[38..54].copy_from_slice(&[0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c]);
        ipv6[56..58].copy_from_slice(&1900u16.to_be_bytes());
        for frame in [other_group, tcp, ipv6] {
            let packet = parsed_frame(&frame);
            for expected in [IpScope::Local, IpScope::Transit, IpScope::Unknown] {
                assert_eq!(ip_scope(&packet, || expected), expected);
            }
        }
    }

    #[test]
    fn fragmented_discovery_needs_no_transport_port() {
        for fragment in [0x2000u16, 0x0001] {
            let mut frame = discovery_frame();
            frame[20..22].copy_from_slice(&fragment.to_be_bytes());
            let packet = parsed_frame(&frame);
            assert_eq!(packet.flow.destination_port, 0);
            assert_eq!(ip_scope(&packet, || IpScope::Transit), IpScope::Local);
        }
    }

    #[test]
    fn malformed_discovery_is_rejected_before_scope_classification() {
        let mut frame = discovery_frame();
        frame[38..40].copy_from_slice(&200u16.to_be_bytes());
        assert!(matches!(
            packet::parse(&frame, frame.len(), frame.len(), false),
            Err(ParseError::Malformed)
        ));
    }

    #[test]
    fn ipv4_local_multicast_and_limited_broadcast_bypass_inventory() {
        for destination in [
            [224, 0, 0, 0],
            [224, 0, 0, 251],
            [224, 0, 0, 252],
            [224, 0, 0, 255],
            [255, 255, 255, 255],
        ] {
            let packet = with_v4_destination(destination);
            assert_eq!(
                ip_scope(&packet, || panic!("local group needs no inventory")),
                IpScope::Local,
                "{destination:?}"
            );
        }
        // Directed broadcast cannot be inferred without a prefix; other
        // administratively scoped multicast must still use the inventory.
        for destination in [
            [223, 255, 255, 255],
            [224, 0, 1, 0],
            [224, 1, 0, 0],
            [192, 168, 0, 255],
            [255, 255, 255, 254],
        ] {
            let packet = with_v4_destination(destination);
            for expected in [IpScope::Local, IpScope::Transit, IpScope::Unknown] {
                assert_eq!(ip_scope(&packet, || expected), expected, "{destination:?}");
            }
        }
    }

    #[test]
    fn only_ipv6_interface_and_link_scoped_multicast_bypass_inventory() {
        for second in [0x01, 0x02, 0x11, 0x12, 0x32] {
            let mut destination = [0; 16];
            destination[..2].copy_from_slice(&[0xff, second]);
            destination[15] = 0xfb;
            let packet = with_v6_destination(destination);
            assert_eq!(
                ip_scope(&packet, || panic!("local group needs no inventory")),
                IpScope::Local,
                "{destination:?}"
            );
        }
        for prefix in [
            [0xff, 0x00],
            [0xff, 0x03],
            [0xff, 0x05],
            [0xff, 0x0e],
            [0xff, 0x1e],
            [0xfe, 0x80],
            [0x20, 0x01],
        ] {
            let mut destination = [0; 16];
            destination[..2].copy_from_slice(&prefix);
            let packet = with_v6_destination(destination);
            for expected in [IpScope::Local, IpScope::Transit, IpScope::Unknown] {
                assert_eq!(ip_scope(&packet, || expected), expected, "{prefix:?}");
            }
        }
    }

    #[test]
    fn group_source_does_not_exempt_a_unicast_destination() {
        let mut v4 = with_v4_destination([192, 0, 2, 1]);
        v4.flow.source[..4].copy_from_slice(&[224, 0, 0, 251]);
        let mut v6 = with_v6_destination([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.flow.source[..2].copy_from_slice(&[0xff, 0x02]);
        for packet in [v4, v6] {
            assert_eq!(ip_scope(&packet, || IpScope::Transit), IpScope::Transit);
        }
    }

    #[test]
    fn exempt_group_and_transit_batch_still_splits_in_either_order() {
        let transit = parsed(20);
        for group in [
            with_v4_destination([224, 0, 0, 251]),
            parsed_frame(&discovery_frame()),
        ] {
            for packets in [[group, transit], [transit, group]] {
                let mut batch = PacketBatch::new();
                for packet in packets {
                    let scope = ip_scope(&packet, || IpScope::Transit);
                    batch.observe_ip(packet, scope).unwrap();
                }
                assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));
            }
            // Reclassification of each split child retains its independent scope.
            assert_eq!(ip_scope(&group, || IpScope::Transit), IpScope::Local);
            assert_eq!(ip_scope(&transit, || IpScope::Transit), IpScope::Transit);
        }
    }

    #[test]
    fn invalid_link_group_packet_is_rejected_before_scope_classification() {
        let mut frame = ipv4();
        frame[30..34].copy_from_slice(&[224, 0, 0, 251]);
        frame[16..18].copy_from_slice(&19u16.to_be_bytes());
        assert!(matches!(
            packet::parse(&frame, frame.len(), frame.len(), false),
            Err(ParseError::Malformed)
        ));
    }

    #[test]
    fn mixed_local_and_transit_require_split_after_all_buffers_are_classified() {
        for first in [IpScope::Local, IpScope::Transit] {
            let second = if first == IpScope::Local {
                IpScope::Transit
            } else {
                IpScope::Local
            };
            let mut batch = PacketBatch::new();
            batch.observe_ip(parsed(10), first).unwrap();
            batch.observe_ip(parsed(20), second).unwrap();
            assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));
        }
        // A pair of different transit flows must not cause an early drop before
        // a later NB reveals that the NBL has local as well as transit data.
        let mut batch = PacketBatch::new();
        batch.observe_ip(parsed(10), IpScope::Transit).unwrap();
        batch.observe_ip(parsed(20), IpScope::Transit).unwrap();
        batch.observe_ip(parsed(30), IpScope::Local).unwrap();
        assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));

        // The rule also applies to IPv6 and to an NBL with both IP families.
        for local in [parsed(10), parsed_v6()] {
            for transit in [parsed(20), parsed_v6()] {
                let mut batch = PacketBatch::new();
                batch.observe_ip(local, IpScope::Local).unwrap();
                batch.observe_ip(transit, IpScope::Transit).unwrap();
                assert!(matches!(batch.finish(), Ok(BatchDecision::Mixed)));
            }
        }
    }

    #[test]
    fn transit_batches_still_require_matching_transport_flows() {
        let mut same = PacketBatch::new();
        same.observe_ip(parsed(10), IpScope::Transit).unwrap();
        same.observe_ip(parsed(10), IpScope::Transit).unwrap();
        let Ok(BatchDecision::Transit(packet)) = same.finish() else {
            panic!("matching transit flow should be eligible for policy");
        };
        assert_eq!(packet.ip_len, 56);
        assert!(!packet.cacheable);

        let mut different = PacketBatch::new();
        different.observe_ip(parsed(10), IpScope::Transit).unwrap();
        different.observe_ip(parsed(20), IpScope::Transit).unwrap();
        assert!(matches!(
            different.finish(),
            Err(BatchError::IncompatibleFlows)
        ));
    }

    #[test]
    fn ip_and_non_ip_batches_are_rejected_in_either_order() {
        for scope in [IpScope::Local, IpScope::Transit, IpScope::Unknown] {
            let mut first_ip = PacketBatch::new();
            first_ip.observe_ip(parsed(10), scope).unwrap();
            assert_eq!(first_ip.observe_non_ip(), Err(BatchError::MixedIpAndNonIp));
            let mut first_non_ip = PacketBatch::new();
            first_non_ip.observe_non_ip().unwrap();
            assert_eq!(
                first_non_ip.observe_ip(parsed(10), scope),
                Err(BatchError::MixedIpAndNonIp)
            );
        }
    }

    #[test]
    fn unknown_inventory_never_becomes_a_mixed_or_transit_decision() {
        for unknown_first in [false, true] {
            let mut batch = PacketBatch::new();
            let scopes = if unknown_first {
                [IpScope::Unknown, IpScope::Local, IpScope::Transit]
            } else {
                [IpScope::Local, IpScope::Transit, IpScope::Unknown]
            };
            for scope in scopes {
                batch.observe_ip(parsed(10), scope).unwrap();
            }
            assert!(matches!(batch.finish(), Ok(BatchDecision::Unknown)));
        }
    }

    #[test]
    fn regular_parser_provides_raw_endpoints_for_scope_lookup() {
        let frame = ipv4();
        let parsed = packet::parse(&frame, frame.len(), frame.len(), false)
            .expect("valid frame")
            .expect("IPv4 packet");
        assert_eq!(&parsed.flow.source[..4], &[192, 168, 219, 15]);
        assert_eq!(&parsed.flow.destination[..4], &[34, 160, 111, 145]);
    }

    #[test]
    fn invalid_ip_length_cannot_reach_local_scope_lookup() {
        let mut frame = ipv4();
        frame[16..18].copy_from_slice(&19u16.to_be_bytes());
        assert!(matches!(
            packet::parse(&frame, frame.len(), frame.len(), false),
            Err(ParseError::Malformed)
        ));
        frame[16..18].copy_from_slice(&80u16.to_be_bytes());
        assert!(matches!(
            packet::parse(&frame, frame.len(), frame.len(), false),
            Err(ParseError::Truncated)
        ));
    }
}
