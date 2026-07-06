use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Poll},
};

use qbase::{
    net::addr::EndpointAddr,
    util::{UniqueId, UniqueIdGenerator},
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    BindUri, Interface, WeakInterface,
    component::Component,
    io::{IO, RefIO},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum InterfaceEndpointKey {
    Direct,
    Agent(SocketAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceEndpointUpdate {
    Upsert {
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
    },
    Remove {
        key: InterfaceEndpointKey,
    },
    Close,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClaimInterfaceEndpointError {
    #[error("local endpoint publisher generation is closed for {bind_uri}")]
    Closed { bind_uri: BindUri },
    #[error("local endpoint key {key:?} is already claimed for {bind_uri}")]
    AlreadyClaimed {
        bind_uri: BindUri,
        key: InterfaceEndpointKey,
    },
}

type SubscriberEvent = (BindUri, InterfaceEndpointUpdate);
type EventSender = mpsc::UnboundedSender<SubscriberEvent>;
type EventReceiver = mpsc::UnboundedReceiver<SubscriberEvent>;

enum EndpointEvent {
    OpenGeneration {
        bind_uri: BindUri,
        generation: UniqueId,
    },
    Update {
        bind_uri: BindUri,
        generation: UniqueId,
        update: InterfaceEndpointUpdate,
    },
}

enum ControlMessage {
    Subscribe {
        subscriber_id: UniqueId,
        subscriber: EventSender,
    },
    Unsubscribe {
        subscriber_id: UniqueId,
    },
    #[cfg(test)]
    SubscriberCount {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
}

#[derive(Debug)]
pub struct LocalEndpoints {
    generation_ids: UniqueIdGenerator,
    subscriber_ids: UniqueIdGenerator,
    event_tx: mpsc::UnboundedSender<EndpointEvent>,
    control_tx: mpsc::UnboundedSender<ControlMessage>,
    _publisher_task: AbortOnDropHandle<()>,
}

impl Default for LocalEndpoints {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalEndpoints {
    pub fn new() -> Self {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<EndpointEvent>();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel::<ControlMessage>();
        let _publisher_task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let mut state = LocalEndpointsHubState::default();
                loop {
                    tokio::select! {
                        Some(event) = event_rx.recv() => {
                            state.apply_event(event);
                        }
                        Some(control) = control_rx.recv() => {
                            state.apply_control(control);
                        }
                        else => break,
                    }
                }
            }
            .in_current_span(),
        ));

        Self {
            generation_ids: UniqueIdGenerator::new(),
            subscriber_ids: UniqueIdGenerator::new(),
            event_tx,
            control_tx,
            _publisher_task,
        }
    }

    pub fn publisher(&self, bind_uri: BindUri) -> InterfaceEndpointsPublishers {
        let generation = self.generation_ids.generate();
        let state =
            InterfaceEndpointsState::new(bind_uri.clone(), generation, self.event_tx.clone());
        let _ = self.event_tx.send(EndpointEvent::OpenGeneration {
            bind_uri,
            generation,
        });
        InterfaceEndpointsPublishers { state }
    }

    pub fn subscribe(&self) -> LocalEndpointSubscriber {
        let subscriber_id = self.subscriber_ids.generate();
        let (sender, receiver) = mpsc::unbounded_channel();
        let _ = self.control_tx.send(ControlMessage::Subscribe {
            subscriber_id,
            subscriber: sender,
        });
        LocalEndpointSubscriber {
            subscriber_id,
            receiver,
            control_tx: self.control_tx.clone(),
        }
    }

    #[cfg(test)]
    async fn subscriber_count(&self) -> usize {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let _ = self
            .control_tx
            .send(ControlMessage::SubscriberCount { reply });
        rx.await.expect("subscriber count request must succeed")
    }
}

#[derive(Default)]
struct LocalEndpointsHubState {
    current_generation: HashMap<BindUri, UniqueId>,
    endpoints: HashMap<BindUri, BTreeMap<InterfaceEndpointKey, EndpointAddr>>,
    subscribers: HashMap<UniqueId, EventSender>,
}

impl LocalEndpointsHubState {
    fn apply_event(&mut self, event: EndpointEvent) {
        match event {
            EndpointEvent::OpenGeneration {
                bind_uri,
                generation,
            } => self.open_generation(bind_uri, generation),
            EndpointEvent::Update {
                bind_uri,
                generation,
                update,
            } => self.apply_update(bind_uri, generation, update),
        }
    }

    fn open_generation(&mut self, bind_uri: BindUri, generation: UniqueId) {
        let previous = self.current_generation.insert(bind_uri.clone(), generation);
        self.endpoints.remove(&bind_uri);
        if previous.is_some_and(|previous| previous != generation) {
            self.forward(bind_uri, InterfaceEndpointUpdate::Close);
        }
    }

    fn apply_update(
        &mut self,
        bind_uri: BindUri,
        generation: UniqueId,
        update: InterfaceEndpointUpdate,
    ) {
        if self.current_generation.get(&bind_uri).copied() != Some(generation) {
            return;
        }
        match update {
            InterfaceEndpointUpdate::Close => {
                self.current_generation.remove(&bind_uri);
                self.endpoints.remove(&bind_uri);
                self.forward(bind_uri, InterfaceEndpointUpdate::Close);
            }
            InterfaceEndpointUpdate::Upsert { key, endpoint } => {
                self.endpoints
                    .entry(bind_uri.clone())
                    .or_default()
                    .insert(key, endpoint);
                self.forward(bind_uri, InterfaceEndpointUpdate::Upsert { key, endpoint });
            }
            InterfaceEndpointUpdate::Remove { key } => {
                if let Some(endpoints) = self.endpoints.get_mut(&bind_uri) {
                    endpoints.remove(&key);
                    if endpoints.is_empty() {
                        self.endpoints.remove(&bind_uri);
                    }
                }
                self.forward(bind_uri, InterfaceEndpointUpdate::Remove { key });
            }
        }
    }

    fn apply_control(&mut self, control: ControlMessage) {
        match control {
            ControlMessage::Subscribe {
                subscriber_id,
                subscriber,
            } => {
                for (bind_uri, endpoints) in &self.endpoints {
                    for (key, endpoint) in endpoints {
                        let update = InterfaceEndpointUpdate::Upsert {
                            key: *key,
                            endpoint: *endpoint,
                        };
                        if subscriber.send((bind_uri.clone(), update)).is_err() {
                            return;
                        }
                    }
                }
                self.subscribers.insert(subscriber_id, subscriber);
            }
            ControlMessage::Unsubscribe { subscriber_id } => {
                self.subscribers.remove(&subscriber_id);
            }
            #[cfg(test)]
            ControlMessage::SubscriberCount { reply } => {
                let _ = reply.send(self.subscribers.len());
            }
        }
    }

    fn forward(&mut self, bind_uri: BindUri, update: InterfaceEndpointUpdate) {
        self.subscribers
            .retain(|_, subscriber| subscriber.send((bind_uri.clone(), update)).is_ok());
    }
}

pub struct LocalEndpointSubscriber {
    subscriber_id: UniqueId,
    receiver: EventReceiver,
    control_tx: mpsc::UnboundedSender<ControlMessage>,
}

impl LocalEndpointSubscriber {
    pub async fn recv(&mut self) -> Option<SubscriberEvent> {
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> Result<SubscriberEvent, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
}

impl Drop for LocalEndpointSubscriber {
    fn drop(&mut self) {
        let _ = self.control_tx.send(ControlMessage::Unsubscribe {
            subscriber_id: self.subscriber_id,
        });
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceEndpointsPublishers {
    state: Arc<InterfaceEndpointsState>,
}

#[derive(Debug)]
pub struct InterfaceDirectEndpointPublisher {
    lease: Arc<InterfaceEndpointClaim>,
}

#[derive(Debug)]
pub struct InterfaceAgentEndpointPublisher {
    lease: Arc<InterfaceEndpointClaim>,
}

#[derive(Debug)]
struct InterfaceEndpointsState {
    bind_uri: BindUri,
    generation: UniqueId,
    event_tx: mpsc::UnboundedSender<EndpointEvent>,
    inner: Mutex<InterfaceEndpointsStateInner>,
}

#[derive(Debug, Default)]
struct InterfaceEndpointsStateInner {
    closed: bool,
    entries: BTreeMap<InterfaceEndpointKey, InterfaceEndpointEntry>,
}

#[derive(Debug)]
struct InterfaceEndpointEntry {
    claim: Weak<InterfaceEndpointClaim>,
    endpoint: Option<EndpointAddr>,
}

#[derive(Debug)]
struct InterfaceEndpointClaim {
    state: Weak<InterfaceEndpointsState>,
    key: InterfaceEndpointKey,
    this: Weak<InterfaceEndpointClaim>,
}

impl InterfaceEndpointsState {
    fn new(
        bind_uri: BindUri,
        generation: UniqueId,
        event_tx: mpsc::UnboundedSender<EndpointEvent>,
    ) -> Arc<Self> {
        Arc::new(Self {
            bind_uri,
            generation,
            event_tx,
            inner: Mutex::new(InterfaceEndpointsStateInner::default()),
        })
    }

    fn lock_inner(&self) -> MutexGuard<'_, InterfaceEndpointsStateInner> {
        self.inner
            .lock()
            .expect("InterfaceEndpoints state mutex poisoned")
    }

    fn publish(&self, update: InterfaceEndpointUpdate) {
        let _ = self.event_tx.send(EndpointEvent::Update {
            bind_uri: self.bind_uri.clone(),
            generation: self.generation,
            update,
        });
    }

    fn claim(
        self: &Arc<Self>,
        key: InterfaceEndpointKey,
    ) -> Result<Arc<InterfaceEndpointClaim>, ClaimInterfaceEndpointError> {
        let mut inner = self.lock_inner();
        if inner.closed {
            return Err(ClaimInterfaceEndpointError::Closed {
                bind_uri: self.bind_uri.clone(),
            });
        }
        if inner
            .entries
            .get(&key)
            .and_then(|entry| entry.claim.upgrade())
            .is_some()
        {
            return Err(ClaimInterfaceEndpointError::AlreadyClaimed {
                bind_uri: self.bind_uri.clone(),
                key,
            });
        }

        let claim = Arc::new_cyclic(|this| InterfaceEndpointClaim {
            state: Arc::downgrade(self),
            key,
            this: this.clone(),
        });
        inner.entries.insert(
            key,
            InterfaceEndpointEntry {
                claim: Arc::downgrade(&claim),
                endpoint: None,
            },
        );
        Ok(claim)
    }

    fn upsert_if_owned(
        &self,
        key: &InterfaceEndpointKey,
        claim: &Weak<InterfaceEndpointClaim>,
        endpoint: EndpointAddr,
    ) -> bool {
        {
            let mut inner = self.lock_inner();
            if inner.closed {
                return false;
            }
            let Some(entry) = inner.entries.get_mut(key) else {
                return false;
            };
            if !entry.claim.ptr_eq(claim) {
                return false;
            }
            if entry.endpoint == Some(endpoint) {
                return true;
            }
            entry.endpoint = Some(endpoint);
        }
        self.publish(InterfaceEndpointUpdate::Upsert {
            key: *key,
            endpoint,
        });
        true
    }

    fn clear_if_owned(
        &self,
        key: &InterfaceEndpointKey,
        claim: &Weak<InterfaceEndpointClaim>,
    ) -> bool {
        {
            let mut inner = self.lock_inner();
            if inner.closed {
                return false;
            }
            let Some(entry) = inner.entries.get_mut(key) else {
                return false;
            };
            if !entry.claim.ptr_eq(claim) {
                return false;
            }
            if entry.endpoint.is_none() {
                return true;
            }
            entry.endpoint = None;
        }
        self.publish(InterfaceEndpointUpdate::Remove { key: *key });
        true
    }

    fn remove_if_owned(&self, key: &InterfaceEndpointKey, claim: &Weak<InterfaceEndpointClaim>) {
        let removed_endpoint = {
            let mut inner = self.lock_inner();
            if inner.closed {
                return;
            }
            let owned = inner
                .entries
                .get(key)
                .is_some_and(|entry| entry.claim.ptr_eq(claim));
            if !owned {
                return;
            }
            inner
                .entries
                .remove(key)
                .and_then(|entry| entry.endpoint)
                .is_some()
        };
        if removed_endpoint {
            self.publish(InterfaceEndpointUpdate::Remove { key: *key });
        }
    }

    fn close(&self) {
        {
            let mut inner = self.lock_inner();
            if inner.closed {
                return;
            }
            inner.closed = true;
            inner.entries.clear();
        }
        self.publish(InterfaceEndpointUpdate::Close);
    }
}

impl Drop for InterfaceEndpointClaim {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        state.remove_if_owned(&self.key, &self.this);
    }
}

impl InterfaceEndpointClaim {
    fn upsert(&self, endpoint: EndpointAddr) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        state.upsert_if_owned(&self.key, &self.this, endpoint)
    }

    fn remove(&self) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        state.clear_if_owned(&self.key, &self.this)
    }
}

impl InterfaceEndpointsPublishers {
    pub fn direct_endpoint_publisher(
        &self,
    ) -> Result<InterfaceDirectEndpointPublisher, ClaimInterfaceEndpointError> {
        self.state
            .claim(InterfaceEndpointKey::Direct)
            .map(|lease| InterfaceDirectEndpointPublisher { lease })
    }

    pub fn agent_endpoint_publisher(
        &self,
        agent: SocketAddr,
    ) -> Result<InterfaceAgentEndpointPublisher, ClaimInterfaceEndpointError> {
        self.state
            .claim(InterfaceEndpointKey::Agent(agent))
            .map(|lease| InterfaceAgentEndpointPublisher { lease })
    }

    pub fn close(&self) {
        self.state.close();
    }
}

impl InterfaceDirectEndpointPublisher {
    pub fn upsert(&mut self, addr: SocketAddr) -> bool {
        self.lease.upsert(EndpointAddr::direct(addr))
    }

    pub fn remove(&mut self) -> bool {
        self.lease.remove()
    }
}

impl InterfaceAgentEndpointPublisher {
    pub fn agent(&self) -> SocketAddr {
        match self.lease.key {
            InterfaceEndpointKey::Agent(agent) => agent,
            InterfaceEndpointKey::Direct => unreachable!("agent endpoint cannot use direct key"),
        }
    }

    pub fn upsert(&mut self, outer: SocketAddr) -> bool {
        self.lease
            .upsert(EndpointAddr::with_agent(self.agent(), outer))
    }

    pub fn remove(&mut self) -> bool {
        self.lease.remove()
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceLocalEndpoints<I> {
    current: Arc<Mutex<CurrentInterfaceLocalEndpoints<I>>>,
}

#[derive(Debug)]
struct CurrentInterfaceLocalEndpoints<I> {
    ref_iface: I,
    local_endpoints: Arc<LocalEndpoints>,
    publishers: InterfaceEndpointsPublishers,
    _direct: Option<InterfaceDirectEndpointPublisher>,
}

impl<I: RefIO + 'static> CurrentInterfaceLocalEndpoints<I> {
    fn new(ref_iface: I, local_endpoints: Arc<LocalEndpoints>) -> Self {
        let bind_uri = ref_iface.iface().bind_uri();
        let publishers = local_endpoints.publisher(bind_uri.clone());
        let mut direct = match publishers.direct_endpoint_publisher() {
            Ok(direct) => Some(direct),
            Err(error) => {
                tracing::debug!(target: "dquic", ?error, "failed to claim direct endpoint publisher");
                None
            }
        };
        match (direct.as_mut(), ref_iface.iface().bound_addr()) {
            (Some(direct), Ok(addr)) => {
                direct.upsert(addr);
            }
            (_, Err(error)) => {
                tracing::trace!(
                    target: "dquic",
                    bind_uri = %bind_uri,
                    ?error,
                    "local interface has no direct endpoint"
                );
            }
            (None, Ok(addr)) => {
                tracing::trace!(
                    target: "dquic",
                    bind_uri = %bind_uri,
                    %addr,
                    "direct endpoint publisher unavailable"
                );
            }
        }

        Self {
            ref_iface,
            local_endpoints,
            publishers,
            _direct: direct,
        }
    }
}

impl<I: RefIO + 'static> InterfaceLocalEndpoints<I> {
    pub fn new(ref_iface: I, local_endpoints: Arc<LocalEndpoints>) -> Self {
        Self {
            current: Arc::new(Mutex::new(CurrentInterfaceLocalEndpoints::new(
                ref_iface,
                local_endpoints,
            ))),
        }
    }

    fn lock_current(&self) -> MutexGuard<'_, CurrentInterfaceLocalEndpoints<I>> {
        self.current
            .lock()
            .expect("InterfaceLocalEndpoints current mutex poisoned")
    }

    pub fn agent_endpoint_publisher(
        &self,
        agent: SocketAddr,
    ) -> Result<InterfaceAgentEndpointPublisher, ClaimInterfaceEndpointError> {
        self.lock_current()
            .publishers
            .agent_endpoint_publisher(agent)
    }
}

pub type IfaceLocalEndpoints<I> = InterfaceLocalEndpoints<I>;
pub type LocalEndpointsComponent = InterfaceLocalEndpoints<WeakInterface>;

impl Component for LocalEndpointsComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        let _ = cx;
        self.lock_current().publishers.close();
        Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        let mut current = self.lock_current();
        if iface.downgrade().same_io(&current.ref_iface) {
            return;
        }

        let local_endpoints = current.local_endpoints.clone();
        current.publishers.close();
        *current = CurrentInterfaceLocalEndpoints::new(iface.downgrade(), local_endpoints);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::time::{Duration, sleep};

    use super::LocalEndpoints;

    #[tokio::test]
    async fn subscriber_drop_unsubscribes_without_publish() {
        let local_endpoints = Arc::new(LocalEndpoints::new());
        let subscriber = local_endpoints.subscribe();

        wait_for_subscriber_count(&local_endpoints, 1).await;

        drop(subscriber);

        wait_for_subscriber_count(&local_endpoints, 0).await;
    }

    async fn wait_for_subscriber_count(local_endpoints: &LocalEndpoints, expected: usize) {
        for _ in 0..20 {
            if local_endpoints.subscriber_count().await == expected {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(local_endpoints.subscriber_count().await, expected);
    }
}
