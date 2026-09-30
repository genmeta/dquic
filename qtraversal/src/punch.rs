mod packet;
mod predictor;
mod puncher;
mod scheduler;
mod tx;

use std::{collections::HashMap, future::Future, net::SocketAddr};

pub use packet::ProbeEncoder;
pub use puncher::{ArcPuncher, PunchPacketEncoder};
use qbase::{
    frame::{ReliableFrame, io::SendFrame},
    net::addr::EndpointAddr,
};
use qprotocol::{DockEvent, DockSubscription, LocalEndpoint};

impl<TX, PE> ArcPuncher<TX, PE>
where
    TX: SendFrame<ReliableFrame> + Clone + Send + Sync + 'static,
    PE: PunchPacketEncoder,
{
    /// Announce queued Dock state before returning, then process ordered updates until closure.
    /// The caller handles path retirement when a local address is removed.
    pub fn observe_endpoints(
        &self,
        mut subscription: DockSubscription,
        closed: impl Future + Send + 'static,
        on_removed: impl Fn(EndpointAddr) + Send + 'static,
    ) {
        let puncher = self.clone();
        let mut advertised = HashMap::<SocketAddr, LocalEndpoint>::new();
        let mut apply = move |event| match event {
            DockEvent::Added {
                binding,
                mapping: current,
            }
            | DockEvent::Updated {
                binding, current, ..
            } => {
                let Ok(bound) = binding.local_addr() else {
                    return;
                };
                let address = current.address(&binding);
                if advertised.get(&bound) == address.as_ref() {
                    return;
                }
                if let Some(previous) = advertised.remove(&bound) {
                    puncher.on_local_removed(previous.endpoint);
                    on_removed(previous.endpoint);
                }
                if let Some(address) = address {
                    puncher.on_local_added(
                        address.bind.clone(),
                        address.endpoint,
                        address.outer,
                        0,
                        address.nat,
                    );
                    advertised.insert(bound, address);
                }
            }
            DockEvent::Removed(binding) => {
                let Ok(bound) = binding.local_addr() else {
                    return;
                };
                if let Some(previous) = advertised.remove(&bound) {
                    puncher.on_local_removed(previous.endpoint);
                }
            }
            DockEvent::SocketRemoved(socket) => {
                if let Ok(bound) = socket.local_addr() {
                    on_removed(EndpointAddr::direct(bound));
                }
            }
        };
        while let Ok(event) = subscription.try_recv() {
            apply(event);
        }
        tokio::spawn(async move {
            tokio::pin!(closed);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut closed => break,
                    change = subscription.recv() => match change {
                        Some(change) => apply(change),
                        None => break,
                    },
                }
            }
        });
    }
}
