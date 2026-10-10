use std::{collections::HashMap, net::SocketAddr};

use qbase::{
    frame::{AddAddressFrame, RemoveAddressFrame},
    net::{NatType, addr::EndpointAddr},
};

/// One local address advertised to this peer. `bound` selects the local UDP socket;
/// `frame` carries the address and NAT information visible to the peer.
#[derive(Clone)]
pub struct LocalAddress {
    pub bound: SocketAddr,
    pub endpoint: EndpointAddr,
    pub frame: AddAddressFrame,
}

/// Only the per-connection ADD_ADDRESS state. Local endpoint publication belongs to qprotocol.
#[derive(Default)]
pub struct PunchAddresses {
    local: HashMap<u32, LocalAddress>,
    remote: HashMap<u32, AddAddressFrame>,
    next_local_seq: u32,
}

impl PunchAddresses {
    pub fn add_local(
        &mut self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
        outer: SocketAddr,
        tire: u32,
        nat: NatType,
    ) -> AddAddressFrame {
        let seq = self.next_local_seq;
        self.next_local_seq += 1;
        let frame = AddAddressFrame::new(seq, outer, tire, nat);
        self.local.insert(
            seq,
            LocalAddress {
                bound,
                endpoint,
                frame,
            },
        );
        frame
    }

    pub fn remove_local_endpoint(&mut self, endpoint: EndpointAddr) -> Vec<RemoveAddressFrame> {
        let seqs = self
            .local
            .iter()
            .filter_map(|(&seq, local)| (local.endpoint == endpoint).then_some(seq))
            .collect::<Vec<_>>();
        for seq in &seqs {
            self.local.remove(seq);
        }
        seqs.into_iter()
            .map(|seq| RemoveAddressFrame {
                seq_num: seq.into(),
            })
            .collect()
    }

    pub fn add_remote(&mut self, frame: AddAddressFrame) -> bool {
        if self.remote.contains_key(&frame.seq_num()) {
            return false;
        }
        self.remote.insert(frame.seq_num(), frame);
        true
    }

    pub fn remove_remote(&mut self, seq: u32) -> Option<AddAddressFrame> {
        self.remote.remove(&seq)
    }

    pub fn local_for_seq(&self, seq: u32) -> Option<LocalAddress> {
        self.local.get(&seq).cloned()
    }

    pub fn remote_frames(&self) -> Vec<AddAddressFrame> {
        self.remote.values().copied().collect()
    }

    pub fn local_frames(&self) -> Vec<AddAddressFrame> {
        self.local.values().map(|address| address.frame).collect()
    }

    pub fn pick_local(&self, remote: AddAddressFrame) -> Option<LocalAddress> {
        const PRIORITY: [NatType; 5] = [
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::RestrictedPort,
            NatType::Dynamic,
            NatType::Symmetric,
        ];
        self.local
            .values()
            .filter(|local| {
                local.frame.tire() == remote.tire()
                    && EndpointAddr::direct(*local.frame)
                        .matches_peer(EndpointAddr::direct(*remote))
            })
            .min_by_key(|local| {
                (
                    PRIORITY
                        .iter()
                        .position(|&nat| nat == local.frame.nat_type())
                        .unwrap_or(usize::MAX),
                    std::cmp::Reverse(local.frame.seq_num()),
                )
            })
            .cloned()
    }

    pub fn len_local(&self) -> usize {
        self.local.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_group_prefers_nat_priority_and_falls_back_to_another_binding() {
        let mut addresses = PunchAddresses::default();
        let restricted = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
        let cone = EndpointAddr::direct("127.0.0.1:5001".parse().unwrap());
        for (endpoint, nat) in [
            (restricted, NatType::RestrictedPort),
            (cone, NatType::FullCone),
        ] {
            addresses.add_local(endpoint.addr(), endpoint, endpoint.addr(), 0, nat);
        }
        let remote =
            AddAddressFrame::new(9, "127.0.0.1:6000".parse().unwrap(), 0, NatType::FullCone);
        assert_eq!(addresses.pick_local(remote).unwrap().endpoint, cone);
        addresses.remove_local_endpoint(cone);
        assert_eq!(addresses.pick_local(remote).unwrap().endpoint, restricted);
        let other_group = AddAddressFrame::new(9, *remote, 1, NatType::FullCone);
        assert!(addresses.pick_local(other_group).is_none());
        let other_family =
            AddAddressFrame::new(9, "[::1]:6000".parse().unwrap(), 0, NatType::FullCone);
        assert!(addresses.pick_local(other_family).is_none());
    }

    #[test]
    fn a_shared_address_is_not_a_punch_target_even_with_a_different_peer_sequence() {
        let mut addresses = PunchAddresses::default();
        let endpoint = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
        addresses.add_local(
            endpoint.addr(),
            endpoint,
            endpoint.addr(),
            0,
            NatType::FullCone,
        );
        let remote = AddAddressFrame::new(9, endpoint.addr(), 0, NatType::FullCone);
        assert!(addresses.pick_local(remote).is_none());
    }

    #[test]
    fn local_and_remote_addresses_keep_connection_sequences() {
        let mut addresses = PunchAddresses::default();
        let bound: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let endpoint = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
        let local = addresses.add_local(
            bound,
            endpoint,
            "198.51.100.1:5000".parse().unwrap(),
            7,
            NatType::RestrictedCone,
        );
        let remote = AddAddressFrame::new(
            9,
            "198.51.100.2:6000".parse().unwrap(),
            7,
            NatType::FullCone,
        );
        assert_eq!(addresses.pick_local(remote).unwrap().frame, local);
        assert!(addresses.add_remote(remote));
        assert!(!addresses.add_remote(remote));
        assert_eq!(addresses.remove_local_endpoint(endpoint).len(), 1);
        assert!(addresses.pick_local(remote).is_none());
    }

    #[test]
    fn loopback_and_bridge_candidates_cannot_pair_in_either_direction() {
        let loopback = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
        let bridge = EndpointAddr::direct("192.168.215.0:5001".parse().unwrap());
        for (local, remote) in [(loopback, bridge), (bridge, loopback)] {
            let mut addresses = PunchAddresses::default();
            addresses.add_local(
                local.addr(),
                local,
                local.addr(),
                0,
                NatType::RestrictedPort,
            );
            let remote = AddAddressFrame::new(9, remote.addr(), 0, NatType::RestrictedPort);
            assert!(addresses.pick_local(remote).is_none());
        }
        let mut addresses = PunchAddresses::default();
        addresses.add_local(
            bridge.addr(),
            bridge,
            bridge.addr(),
            0,
            NatType::RestrictedPort,
        );
        let public = AddAddressFrame::new(
            9,
            "8.8.8.8:6000".parse().unwrap(),
            0,
            NatType::RestrictedPort,
        );
        assert!(
            addresses.pick_local(public).is_some(),
            "private-to-public NAT candidates remain valid"
        );
    }
}
