mod predictor;
mod puncher;
mod scheduler;
mod tx;

use std::future::Future;

pub use puncher::{ArcPuncher, PunchPacketEncoder};
use qbase::{
    frame::{ReliableFrame, io::SendFrame},
    net::{addr::EndpointAddr, route::Scopes},
};
use qprotocol::addr_book::Candidate;
use tokio::{sync::mpsc, task::JoinHandle};

impl<TX, PE> ArcPuncher<TX, PE>
where
    TX: SendFrame<ReliableFrame> + Clone + Send + Sync + 'static,
    PE: PunchPacketEncoder,
{
    /// Consume AddrBook's queued candidates before returning, then observe ordered changes.
    /// Scope filtering belongs to this connection; endpoints and candidates are independent.
    /// The task drops the subscription when closed resolves or the book drops.
    pub fn observe_candidates(
        &self,
        mut subscription: mpsc::UnboundedReceiver<Candidate>,
        scopes: Scopes,
        closed: impl Future + Send + 'static,
    ) -> JoinHandle<()> {
        let puncher = self.clone();
        let apply = move |event| {
            let link = match event {
                Candidate::New { link, .. } | Candidate::Invalid { link } => link,
            };
            let outer = EndpointAddr::direct(link.dst);
            if !outer.is_usable() || !outer.scope().is_some_and(|scope| scopes.contains(scope)) {
                return;
            }
            puncher.on_local_removed(link);
            if let Candidate::New { nat, .. } = event {
                puncher.on_local_added(link, 0, nat);
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
