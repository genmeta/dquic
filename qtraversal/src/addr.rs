use std::collections::HashMap;

use qbase::{
    frame::{AddAddressFrame, RemoveAddressFrame},
    net::{NatType, addr::EndpointAddr, route::Link},
};

/// One local address advertised to this peer. `link.src` selects the local UDP socket;
/// `frame` carries the address and NAT information visible to the peer.
#[derive(Clone)]
pub struct LocalAddress {
    pub link: Link,
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
    pub fn add_local(&mut self, link: Link, tire: u32, nat: NatType) -> AddAddressFrame {
        let seq = self.next_local_seq;
        self.next_local_seq += 1;
        let frame = AddAddressFrame::new(seq, link.dst, tire, nat);
        self.local.insert(seq, LocalAddress { link, frame });
        frame
    }

    pub fn remove_local_link(&mut self, link: Link) -> Vec<RemoveAddressFrame> {
        let seqs = self.local.iter().filter_map(|(&seq, local)| (local.link == link).then_some(seq)).collect::<Vec<_>>();
        for seq in &seqs {
            self.local.remove(seq);
        }
        seqs.into_iter().map(|seq| RemoveAddressFrame { seq_num: seq.into() }).collect()
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
        const PRIORITY: [NatType; 5] =
            [NatType::FullCone, NatType::RestrictedCone, NatType::RestrictedPort, NatType::Dynamic, NatType::Symmetric];
        self.local
            .values()
            .filter(|local| {
                local.frame.tire() == remote.tire() && EndpointAddr::direct(*local.frame).can_connect_to(EndpointAddr::direct(*remote))
            })
            .min_by_key(|local| {
                (
                    PRIORITY.iter().position(|&nat| nat == local.frame.nat_type()).unwrap_or(usize::MAX),
                    std::cmp::Reverse(local.frame.seq_num()),
                )
            })
            .cloned()
    }

    pub fn len_local(&self) -> usize {
        self.local.len()
    }
}
