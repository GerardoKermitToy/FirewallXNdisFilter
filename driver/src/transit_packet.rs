//! Track whether an owned NBL contains local or transit IP packets.
//!
//! Each NB must first pass the ordinary bounded Ethernet/IP parser. A single
//! NBL cannot carry different policy decisions for a local and a transit NB.

use firewallx_policy::packet::Packet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpScope {
    Local,
    Transit,
    Unknown,
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

    fn parsed_v6() -> Packet {
        let mut frame = vec![0u8; 14 + 40 + 8];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&8u16.to_be_bytes());
        frame[20] = 17;
        frame[22] = 0x20;
        frame[38] = 0x20;
        frame[58..60].copy_from_slice(&8u16.to_be_bytes());
        packet::parse(&frame, frame.len(), frame.len(), false)
            .expect("valid frame")
            .expect("IPv6 packet")
    }

    #[test]
    fn mixed_local_and_transit_are_permitted_after_all_buffers_are_classified() {
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
