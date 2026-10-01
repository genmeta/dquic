mod packet;
mod predictor;
mod puncher;
mod scheduler;
mod tx;

use std::future::Future;

pub use packet::ProbeEncoder;
pub use puncher::{ArcPuncher, PunchPacketEncoder};
use qbase::{
    frame::{ReliableFrame, io::SendFrame},
    net::addr::EndpointAddr,
};
use qprotocol::AddressEvent;
use tokio::{sync::mpsc, task::JoinHandle};

impl<TX, PE> ArcPuncher<TX, PE>
where
    TX: SendFrame<ReliableFrame> + Clone + Send + Sync + 'static,
    PE: PunchPacketEncoder,
{
    /// Consume AddressBook's queued replay before returning, then observe ordered changes.
    /// Socket aliases must be registered with QuicProtocol before directory publication.
    /// Removal callbacks also cover unadvertised endpoints and the binding's Direct address;
    /// callers should retire paths idempotently. NAT changes alone do not retire paths.
    /// The returned task ends and drops the subscription when closed resolves or the book drops.
    pub fn observe_endpoints(
        &self,
        mut subscription: mpsc::UnboundedReceiver<AddressEvent>,
        closed: impl Future + Send + 'static,
        on_removed: impl Fn(EndpointAddr) + Send + 'static,
    ) -> JoinHandle<()> {
        let puncher = self.clone();
        let apply = move |event| match event {
            AddressEvent::Added {
                bound,
                endpoint,
                nat,
            } => {
                puncher.on_local_removed(endpoint);
                puncher.on_local_added(bound, endpoint, endpoint.addr(), 0, nat);
            }
            AddressEvent::Removed { endpoint, .. } => {
                puncher.on_local_removed(endpoint);
                on_removed(endpoint);
            }
            AddressEvent::BoundRemoved { bound } => {
                // AddressBook has already emitted Removed for each endpoint of this binding.
                on_removed(EndpointAddr::direct(bound));
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
        })
    }
}
