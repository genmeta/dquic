use std::{
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use dashmap::DashMap;
use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    net::{addr::EndpointAddr, route::Pathway, tx::ArcSendWakers},
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
}

#[derive(Clone)]
pub struct ArcPathContexts {
    paths: Arc<DashMap<Pathway, PathContext>>,
    tx_wakers: ArcSendWakers,
    broker: ArcEventBroker,
    initial_path: Arc<Mutex<Option<Weak<Path>>>>,
}

impl ArcPathContexts {
    pub fn new(tx_wakers: ArcSendWakers, broker: ArcEventBroker) -> Self {
        Self {
            paths: Default::default(),
            tx_wakers,
            broker,
            initial_path: Arc::default(),
        }
    }

    pub fn assign_handshake_path(
        &self,
        path: &Arc<Path>,
        remote_cids: &ArcRemoteCids,
        initial_dcid: ConnectionId,
    ) -> bool {
        let mut handshake_path = self.initial_path.lock().unwrap();
        if handshake_path.is_some() {
            tracing::trace!(
                pathway = %path.pathway,
                initial_dcid = %initial_dcid,
                "handshake path already assigned"
            );
            return false;
        }
        remote_cids.apply_initial_dcid(initial_dcid, &path.dcid_cell);
        *handshake_path = Some(Arc::downgrade(path));
        tracing::debug!(
            pathway = %path.pathway,
            initial_dcid = %initial_dcid,
            "assigned handshake path"
        );
        true
    }

    pub fn handshake_path(&self) -> Option<Arc<Path>> {
        self.initial_path
            .lock()
            .unwrap()
            .clone()
            .expect("unreachable: Handshake packet received before first initial packet processed")
            .upgrade()
    }

    pub fn get_or_try_create_with<T>(
        &self,
        pathway: Pathway,
        try_create: impl FnOnce() -> Result<(Arc<Path>, T), CreatePathFailure>,
    ) -> Result<Arc<Path>, CreatePathFailure>
    where
        T: Future<Output = Result<(), PathDeactivated>> + Send + 'static,
    {
        match self.paths.entry(pathway) {
            dashmap::Entry::Occupied(occupied_entry) => Ok(occupied_entry.get().path.clone()),
            dashmap::Entry::Vacant(vacant_entry) => {
                let (path, task) = try_create()?;
                self.tx_wakers.insert(pathway, &path.tx_waker);
                let paths = self.clone();
                let task = AbortOnDropHandle::new(tokio::spawn(
                    async move {
                        let reason = task.await.unwrap_err();
                        paths.remove(&pathway, &reason);
                    }
                    .instrument_in_current()
                    .in_current_span(),
                ));
                Ok(vacant_entry
                    .insert(PathContext { path, _task: task })
                    .clone())
            }
        }
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.paths.get(pathway).map(|p| p.path.clone())
    }

    pub fn remove(&self, pathway: &Pathway, reason: &PathDeactivated) {
        if self.paths.remove(pathway).is_some() {
            self.tx_wakers.remove(pathway);
            tracing::debug!(target: "quic", %pathway, %reason, "path deactivated");
            if self.is_empty() {
                let error = QuicError::with_default_fty(
                    ErrorKind::NoViablePath,
                    format!("No viable path exist, last path removed because: {reason}"),
                );
                self.broker.emit(Event::Failed(error));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.paths.iter().map(|p| p.cc().get_pto(Epoch::Data)).max()
    }

    pub fn paths<C: FromIterator<(Pathway, Arc<Path>)>>(&self) -> C {
        self.paths
            .iter()
            .map(|p| (*p.key(), p.path.clone()))
            .collect()
    }

    pub fn discard_initial_and_handshake_space(&self) {
        self.paths.iter().for_each(|p| {
            p.cc().discard_epoch(Epoch::Initial);
            p.cc().discard_epoch(Epoch::Handshake);
        });
    }

    pub fn clear(&self) {
        self.paths.clear();
    }

    pub fn on_path_validated(&self, pathway: Pathway) {
        if matches!(pathway.remote(), EndpointAddr::Direct { .. }) {
            self.paths.iter().for_each(|p| {
                if matches!(p.pathway.remote(), EndpointAddr::Direct { .. }) {
                    p.path.deactivate();
                }
            });
        }
    }
}
