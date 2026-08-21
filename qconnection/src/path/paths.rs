use std::{
    future::Future,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use dashmap::DashMap;
use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    net::{route::Pathway, tx::ArcSendWakers},
};
use qcongestion::Transport;
use qevent::telemetry::Instrument;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument as _;

use super::Path;
use crate::{
    ArcRemoteCids,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{CreatePathFailure, PathDeactivated},
};

#[derive(Deref)]
pub struct PathContext {
    #[deref]
    path: Arc<Path>,
    _task: AbortOnDropHandle<()>,
    _send_waker_entry: PathSendWakerEntry,
}

struct PathSendWakerEntry {
    pathway: Pathway,
    tx_wakers: ArcSendWakers,
}

impl PathSendWakerEntry {
    fn insert(
        pathway: Pathway,
        tx_wakers: &ArcSendWakers,
        tx_waker: &qbase::net::tx::ArcSendWaker,
    ) -> Self {
        tx_wakers.insert(pathway, tx_waker);
        Self {
            pathway,
            tx_wakers: tx_wakers.clone(),
        }
    }
}

impl Drop for PathSendWakerEntry {
    fn drop(&mut self) {
        self.tx_wakers.remove(&self.pathway);
    }
}

#[derive(Clone)]
pub struct ArcPathContexts {
    paths: Arc<DashMap<Pathway, PathContext>>,
    tx_wakers: ArcSendWakers,
    broker: ArcEventBroker,
    state: Arc<RwLock<State>>,
}

#[derive(Default)]
struct State {
    accepting_paths: bool,
    initial_path: Option<Weak<Path>>,
    last_path_pto: Option<Duration>,
}

impl ArcPathContexts {
    pub fn new(tx_wakers: ArcSendWakers, broker: ArcEventBroker) -> Self {
        Self {
            paths: Default::default(),
            tx_wakers,
            broker,
            state: Arc::new(RwLock::new(State {
                accepting_paths: true,
                initial_path: None,
                last_path_pto: None,
            })),
        }
    }

    pub fn assign_handshake_path(
        &self,
        path: &Arc<Path>,
        remote_cids: &ArcRemoteCids,
        initial_dcid: ConnectionId,
    ) -> bool {
        let mut state = self.state.write().unwrap();
        if !state.accepting_paths {
            tracing::trace!(
                target: "dquic",
                pathway = %path.pathway,
                initial_dcid = %initial_dcid,
                "ignored handshake path assignment after path contexts closed"
            );
            return false;
        }
        if state.initial_path.is_some() {
            tracing::trace!(
                target: "dquic",
                pathway = %path.pathway,
                initial_dcid = %initial_dcid,
                "handshake path already assigned"
            );
            return false;
        }
        remote_cids.apply_initial_dcid(initial_dcid, &path.dcid_cell);
        state.initial_path = Some(Arc::downgrade(path));
        drop(state);
        tracing::debug!(
            target: "dquic",
            pathway = %path.pathway,
            initial_dcid = %initial_dcid,
            "assigned handshake path"
        );
        true
    }

    pub fn handshake_path(&self) -> Option<Arc<Path>> {
        self.state
            .read()
            .unwrap()
            .initial_path
            .clone()
            .and_then(|path| path.upgrade())
    }

    pub fn get_or_try_create_with<T>(
        &self,
        pathway: Pathway,
        try_create: impl FnOnce() -> Result<(Arc<Path>, T), CreatePathFailure>,
    ) -> Result<Arc<Path>, CreatePathFailure>
    where
        T: Future<Output = Result<(), PathDeactivated>> + Send + 'static,
    {
        let state = self.state.read().unwrap();
        if !state.accepting_paths {
            let error = QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                "connection path set is closed",
            );
            return Err(CreatePathFailure::ConnectionClosed(error.into()));
        }

        match self.paths.entry(pathway) {
            dashmap::Entry::Occupied(occupied_entry) => Ok(occupied_entry.get().path.clone()),
            dashmap::Entry::Vacant(vacant_entry) => {
                let (path, task) = try_create()?;
                let send_waker_entry =
                    PathSendWakerEntry::insert(pathway, &self.tx_wakers, &path.tx_waker);
                // Register the path before its worker can create recovery state. Handshake
                // confirmation relies on the map containing every worker it must retire.
                let (start_tx, start_rx) = tokio::sync::oneshot::channel();
                let paths = self.clone();
                let task = AbortOnDropHandle::new(tokio::spawn(
                    async move {
                        if start_rx.await.is_err() {
                            return;
                        }
                        let reason = task.await.unwrap_err();
                        paths.remove(&pathway, &reason);
                    }
                    .instrument_in_current()
                    .in_current_span(),
                ));
                let path = vacant_entry
                    .insert(PathContext {
                        path,
                        _task: task,
                        _send_waker_entry: send_waker_entry,
                    })
                    .clone();
                drop(state);
                _ = start_tx.send(());
                Ok(path)
            }
        }
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.paths.get(pathway).map(|p| p.path.clone())
    }

    pub fn remove(&self, pathway: &Pathway, reason: &PathDeactivated) {
        let Some((_, path_context)) = self.paths.remove(pathway) else {
            return;
        };
        let path = path_context.path.clone();
        path.deactivate();
        // Stop this path's sender and unregister its waker before loss feedback wakes the
        // surviving paths. Otherwise the removed sender can consume the recovered data again.
        drop(path_context);
        path.cc().on_path_lost();
        tracing::debug!(target: "dquic", %pathway, %reason, "path deactivated");

        let mut state = self.state.write().unwrap();
        if state.accepting_paths && self.is_empty() {
            state.last_path_pto = Some(path.cc().get_pto(Epoch::Data));
            let error = QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                format!("No viable path exist, last path removed because: {reason}"),
            );
            drop(state);
            self.broker.emit(Event::Failed(error));
        }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.paths
            .iter()
            .map(|path| path.cc().get_pto(Epoch::Data))
            .max()
            .or_else(|| self.state.read().unwrap().last_path_pto)
    }

    pub fn paths<C: FromIterator<(Pathway, Arc<Path>)>>(&self) -> C {
        self.paths
            .iter()
            .map(|p| (*p.key(), p.path.clone()))
            .collect()
    }

    pub fn discard_initial_space(&self) {
        self.paths.iter().for_each(|p| {
            p.cc().discard_epoch(Epoch::Initial);
        });
    }

    pub fn discard_handshake_space(&self) {
        self.paths.iter().for_each(|p| {
            p.cc().discard_epoch(Epoch::Handshake);
        });
    }

    pub fn close(&self) {
        {
            let mut state = self.state.write().unwrap();
            state.accepting_paths = false;
            state.initial_path = None;
        }
        self.paths.iter().for_each(|path| path.deactivate());
        self.paths.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Ready, net::SocketAddr, time::Duration};

    use qbase::net::{
        route::Pathway,
        tx::{ArcSendWaker, ArcSendWakers, Signals},
    };
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use crate::{events::ArcEventBroker, state::ArcConnState};

    fn test_pathway() -> Pathway {
        Pathway::new(
            SocketAddr::from(([127, 0, 0, 1], 9000)).into(),
            SocketAddr::from(([127, 0, 0, 1], 4433)).into(),
        )
    }

    #[test]
    fn close_rejects_new_paths() {
        let tx_wakers = ArcSendWakers::default();
        let (tx, _rx) = mpsc::unbounded_channel();
        let broker = ArcEventBroker::new(ArcConnState::new(), tx);
        let contexts = ArcPathContexts::new(tx_wakers, broker);

        contexts.close();

        let result = contexts
            .get_or_try_create_with::<Ready<Result<(), PathDeactivated>>>(test_pathway(), || {
                unreachable!("closed path contexts must not create new paths")
            });

        assert!(matches!(
            result,
            Err(CreatePathFailure::ConnectionClosed(..))
        ));
    }

    #[tokio::test]
    async fn path_send_waker_entry_removes_waker_on_drop() {
        let tx_wakers = ArcSendWakers::default();
        let send_waker = ArcSendWaker::new();
        let pathway = test_pathway();
        let entry = PathSendWakerEntry::insert(pathway, &tx_wakers, &send_waker);

        let (done_tx, done_rx) = oneshot::channel();
        let waiter = tokio::spawn(
            async move {
                send_waker.wait_for(Signals::PING).await;
                _ = done_tx.send(());
            }
            .in_current_span(),
        );
        tokio::task::yield_now().await;

        drop(entry);
        tx_wakers.wake_all_by(Signals::PING);

        assert!(
            tokio::time::timeout(Duration::from_millis(50), done_rx)
                .await
                .is_err(),
            "dropping the path-owned send waker entry should unlink it from connection wakeups"
        );

        waiter.abort();
    }
}
