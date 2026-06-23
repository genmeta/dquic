use std::{
    any::{Any, TypeId},
    collections::{BTreeMap, HashMap, hash_map},
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex, MutexGuard, Weak},
    task::{Context, Poll},
};

use qbase::{
    net::addr::EndpointAddr,
    util::{UniqueId, UniqueIdGenerator},
};
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    BindUri, Interface, WeakInterface,
    component::Component,
    io::{IO, RefIO},
};

#[derive(Debug)]
pub enum AddressEvent<D: ?Sized = dyn Any + Send + Sync> {
    Upsert(Arc<D>),
    Remove(TypeId),
    Closed,
}

impl<D: ?Sized> Clone for AddressEvent<D> {
    fn clone(&self) -> Self {
        match self {
            Self::Upsert(arg0) => Self::Upsert(arg0.clone()),
            Self::Remove(arg0) => Self::Remove(*arg0),
            Self::Closed => Self::Closed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEndpointSet {
    endpoints: Arc<[EndpointAddr]>,
}

impl LocalEndpointSet {
    pub fn from_endpoints(endpoints: impl IntoIterator<Item = EndpointAddr>) -> Self {
        let endpoints = endpoints.into_iter().collect::<Vec<_>>();
        Self::new(Arc::from(endpoints.into_boxed_slice()))
    }

    fn new(endpoints: Arc<[EndpointAddr]>) -> Self {
        Self { endpoints }
    }

    pub fn endpoints(&self) -> &[EndpointAddr] {
        &self.endpoints
    }
}

// TODO： 固定类型
impl AddressEvent {
    pub fn downcast<D: Any + Send + Sync>(self) -> Result<AddressEvent<D>, Self> {
        match self {
            AddressEvent::Upsert(data) => match data.downcast::<D>() {
                Ok(data) => Ok(AddressEvent::Upsert(data)),
                Err(data) => Err(AddressEvent::Upsert(data)),
            },
            AddressEvent::Remove(type_id) => match TypeId::of::<D>() == type_id {
                true => Ok(AddressEvent::Remove(type_id)),
                false => Err(AddressEvent::Remove(type_id)),
            },
            AddressEvent::Closed => Ok(AddressEvent::Closed),
        }
    }
}

type EventSender = mpsc::UnboundedSender<(BindUri, AddressEvent)>;
type EventReceiver = mpsc::UnboundedReceiver<(BindUri, AddressEvent)>;

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

struct EventPublisher {
    datas: HashMap<BindUri, HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
    subscribers: HashMap<UniqueId, EventSender>,
}

impl EventPublisher {
    pub fn new() -> Self {
        Self {
            datas: HashMap::new(),
            subscribers: HashMap::new(),
        }
    }

    pub fn publish_event(&mut self, bind_uri: BindUri, event: AddressEvent) {
        // 1. update state
        match event.clone() {
            AddressEvent::Upsert(data) => {
                let type_id = data.as_ref().type_id();
                self.datas
                    .entry(bind_uri.clone())
                    .or_default()
                    .insert(type_id, data);
            }
            AddressEvent::Remove(type_id) => {
                let entry = self.datas.entry(bind_uri.clone());
                if let hash_map::Entry::Occupied(mut entry) = entry {
                    entry.get_mut().remove(&type_id);
                    if entry.get().is_empty() {
                        entry.remove_entry();
                    }
                }
            }
            AddressEvent::Closed => _ = self.datas.remove(&bind_uri),
        }
        // 2. forward event to subscribers
        self.subscribers
            .retain(|_, subscriber| subscriber.send((bind_uri.clone(), event.clone())).is_ok());
    }

    pub fn register_subscriber(&mut self, subscriber_id: UniqueId, subscriber: EventSender) {
        for (bind_uri, datas) in &self.datas {
            for (.., data) in datas {
                let event = AddressEvent::Upsert(data.clone());
                if subscriber.send((bind_uri.clone(), event)).is_err() {
                    // EventReceiver disconnected, so we skip registering this subscriber.
                    return;
                }
            }
        }
        self.subscribers.insert(subscriber_id, subscriber);
    }

    pub fn unregister_subscriber(&mut self, subscriber_id: UniqueId) {
        self.subscribers.remove(&subscriber_id);
    }
}

#[derive(Debug)]
pub struct Locations {
    subscriber_id_generator: UniqueIdGenerator,
    new_event_tx: EventSender,
    control_tx: mpsc::UnboundedSender<ControlMessage>,
    _publisher_task: AbortOnDropHandle<()>,
}

impl Default for Locations {
    fn default() -> Self {
        Self::new()
    }
}

impl Locations {
    pub fn new() -> Self {
        let (new_event_tx, mut new_event_rx) = mpsc::unbounded_channel::<(BindUri, AddressEvent)>();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();

        let _publisher_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut publisher = EventPublisher::new();

            loop {
                tokio::select! {
                    Some((bind_uri, event)) = new_event_rx.recv() => {
                        publisher.publish_event(bind_uri, event);
                    }
                    Some(control) = control_rx.recv() => {
                        match control {
                            ControlMessage::Subscribe {
                                subscriber_id,
                                subscriber,
                            } => {
                                publisher.register_subscriber(subscriber_id, subscriber);
                            }
                            ControlMessage::Unsubscribe { subscriber_id } => {
                                publisher.unregister_subscriber(subscriber_id);
                            }
                            #[cfg(test)]
                            ControlMessage::SubscriberCount { reply } => {
                                let _ = reply.send(publisher.subscribers.len());
                            }
                        }
                    }
                    else => break
                }
            }
        }));

        Self {
            subscriber_id_generator: UniqueIdGenerator::new(),
            new_event_tx,
            control_tx,
            _publisher_task,
        }
    }

    pub fn global() -> &'static Arc<Self> {
        static GLOBAL: LazyLock<Arc<Locations>> = LazyLock::new(|| Arc::new(Locations::new()));
        &GLOBAL
    }

    pub fn publish(&self, bind_uri: BindUri, event: AddressEvent) {
        _ = self.new_event_tx.send((bind_uri, event));
    }

    pub fn upsert<D: Any + Send + Sync + Debug>(&self, bind_uri: BindUri, data: Arc<D>) {
        self.publish(bind_uri, AddressEvent::Upsert(data));
    }

    pub fn remove<D: Any + Send + Sync>(&self, bind_uri: BindUri) {
        self.publish(bind_uri, AddressEvent::Remove(TypeId::of::<D>()));
    }

    pub fn close(&self, bind_uri: BindUri) {
        self.publish(bind_uri, AddressEvent::Closed);
    }

    pub fn subscribe(&self) -> Observer {
        let subscriber_id = self.subscriber_id_generator.generate();
        let (tx, rx) = mpsc::unbounded_channel();
        // Register the new subscriber.
        _ = self.control_tx.send(ControlMessage::Subscribe {
            subscriber_id,
            subscriber: tx,
        });
        Observer {
            subscriber_id,
            receiver: rx,
            control_tx: self.control_tx.clone(),
        }
    }

    #[cfg(test)]
    async fn subscriber_count(&self) -> usize {
        let (reply, rx) = tokio::sync::oneshot::channel();
        _ = self
            .control_tx
            .send(ControlMessage::SubscriberCount { reply });
        rx.await.expect("subscriber count request must succeed")
    }
}

pub struct Observer {
    subscriber_id: UniqueId,
    receiver: EventReceiver,
    control_tx: mpsc::UnboundedSender<ControlMessage>,
}

impl Observer {
    pub async fn recv(&mut self) -> Option<(BindUri, AddressEvent)> {
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> Result<(BindUri, AddressEvent), mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        _ = self.control_tx.send(ControlMessage::Unsubscribe {
            subscriber_id: self.subscriber_id,
        });
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceLocations<I> {
    current: Arc<Mutex<CurrentInterfaceLocations<I>>>,
}

#[derive(Debug)]
struct CurrentInterfaceLocations<I> {
    ref_iface: I,
    state: Arc<InterfaceLocationsState>,
    _direct: InterfaceDirectLocation,
}

#[derive(Debug, Clone)]
pub struct InterfaceDirectLocation {
    lease: Arc<InterfaceLocationLease>,
}

#[derive(Debug, Clone)]
pub struct InterfaceAgentLocation {
    lease: Arc<InterfaceLocationLease>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum InterfaceLocationKey {
    Direct,
    Agent(SocketAddr),
}

#[derive(Debug)]
struct InterfaceLocationLease {
    state: Weak<InterfaceLocationsState>,
    key: InterfaceLocationKey,
    this: Weak<InterfaceLocationLease>,
}

#[derive(Debug)]
struct InterfaceLocationsState {
    bind_uri: BindUri,
    locations: Arc<Locations>,
    inner: Mutex<InterfaceLocationsStateInner>,
}

#[derive(Debug)]
struct InterfaceLocationsStateInner {
    closed: bool,
    entries: BTreeMap<InterfaceLocationKey, InterfaceLocationEntry>,
    published: Arc<[EndpointAddr]>,
}

#[derive(Debug)]
struct InterfaceLocationEntry {
    lease: Weak<InterfaceLocationLease>,
    endpoint: Option<EndpointAddr>,
}

impl Default for InterfaceLocationsStateInner {
    fn default() -> Self {
        Self {
            closed: false,
            entries: BTreeMap::new(),
            published: Arc::from([]),
        }
    }
}

impl InterfaceLocationsState {
    fn new(bind_uri: BindUri, locations: Arc<Locations>) -> Arc<Self> {
        Arc::new(Self {
            bind_uri,
            locations,
            inner: Mutex::new(InterfaceLocationsStateInner::default()),
        })
    }

    fn lock_inner(&self) -> MutexGuard<'_, InterfaceLocationsStateInner> {
        self.inner
            .lock()
            .expect("InterfaceLocations state mutex poisoned")
    }

    fn claim(self: &Arc<Self>, key: InterfaceLocationKey) -> Arc<InterfaceLocationLease> {
        let lease = Arc::new_cyclic(|this| InterfaceLocationLease {
            state: Arc::downgrade(self),
            key: key.clone(),
            this: this.clone(),
        });

        let mut inner = self.lock_inner();
        if !inner.closed {
            inner.entries.insert(
                key,
                InterfaceLocationEntry {
                    lease: Arc::downgrade(&lease),
                    endpoint: None,
                },
            );
        }
        lease
    }

    fn upsert_if_owned(
        &self,
        key: &InterfaceLocationKey,
        lease: &Weak<InterfaceLocationLease>,
        endpoint: EndpointAddr,
    ) -> bool {
        let mut inner = self.lock_inner();
        if inner.closed {
            return false;
        }
        let Some(entry) = inner.entries.get_mut(key) else {
            return false;
        };
        if !entry.lease.ptr_eq(lease) {
            return false;
        }
        if entry.endpoint == Some(endpoint) {
            return true;
        }
        entry.endpoint = Some(endpoint);
        self.publish_if_changed(&mut inner);
        true
    }

    fn clear_if_owned(
        &self,
        key: &InterfaceLocationKey,
        lease: &Weak<InterfaceLocationLease>,
    ) -> bool {
        let mut inner = self.lock_inner();
        if inner.closed {
            return false;
        }
        let Some(entry) = inner.entries.get_mut(key) else {
            return false;
        };
        if !entry.lease.ptr_eq(lease) {
            return false;
        }
        if entry.endpoint.is_none() {
            return true;
        }
        entry.endpoint = None;
        self.publish_if_changed(&mut inner);
        true
    }

    fn remove_if_owned(&self, key: &InterfaceLocationKey, lease: &Weak<InterfaceLocationLease>) {
        let mut inner = self.lock_inner();
        if inner.closed
            || !inner
                .entries
                .get(key)
                .is_some_and(|entry| entry.lease.ptr_eq(lease))
        {
            return;
        }
        inner.entries.remove(key);
        self.publish_if_changed(&mut inner);
    }

    fn close(&self) {
        let mut inner = self.lock_inner();
        if inner.closed {
            return;
        }
        inner.closed = true;
        inner.entries.clear();
        inner.published = Arc::from([]);
        self.locations.close(self.bind_uri.clone());
    }

    fn publish_if_changed(&self, inner: &mut InterfaceLocationsStateInner) {
        let endpoints = inner
            .entries
            .values()
            .filter_map(|entry| entry.endpoint)
            .collect::<Vec<_>>();
        let endpoints: Arc<[EndpointAddr]> = Arc::from(endpoints.into_boxed_slice());
        if endpoints == inner.published {
            return;
        }
        inner.published = endpoints.clone();
        if endpoints.is_empty() {
            self.locations
                .remove::<LocalEndpointSet>(self.bind_uri.clone());
        } else {
            self.locations.upsert(
                self.bind_uri.clone(),
                Arc::new(LocalEndpointSet::new(endpoints)),
            );
        }
    }
}

impl Drop for InterfaceLocationLease {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        state.remove_if_owned(&self.key, &self.this);
    }
}

impl InterfaceLocationLease {
    fn upsert(&self, endpoint: EndpointAddr) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        state.upsert_if_owned(&self.key, &self.this, endpoint)
    }

    fn clear(&self) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        state.clear_if_owned(&self.key, &self.this)
    }
}

impl InterfaceDirectLocation {
    fn new(state: Arc<InterfaceLocationsState>) -> Self {
        Self {
            lease: state.claim(InterfaceLocationKey::Direct),
        }
    }

    pub fn upsert(&self, addr: SocketAddr) -> bool {
        self.lease.upsert(EndpointAddr::direct(addr))
    }

    pub fn clear(&self) -> bool {
        self.lease.clear()
    }
}

impl InterfaceAgentLocation {
    fn new(state: Arc<InterfaceLocationsState>, agent: SocketAddr) -> Self {
        Self {
            lease: state.claim(InterfaceLocationKey::Agent(agent)),
        }
    }

    pub fn agent(&self) -> SocketAddr {
        match self.lease.key {
            InterfaceLocationKey::Agent(agent) => agent,
            InterfaceLocationKey::Direct => unreachable!("agent location cannot use direct key"),
        }
    }

    pub fn upsert(&self, outer: SocketAddr) -> bool {
        self.lease
            .upsert(EndpointAddr::with_agent(self.agent(), outer))
    }

    pub fn clear(&self) -> bool {
        self.lease.clear()
    }
}

impl<I: RefIO + 'static> CurrentInterfaceLocations<I> {
    fn new(ref_iface: I, locations: Arc<Locations>) -> Self {
        let bind_uri = ref_iface.iface().bind_uri();
        let state = InterfaceLocationsState::new(bind_uri.clone(), locations.clone());
        let direct = InterfaceDirectLocation::new(state.clone());
        match ref_iface.iface().bound_addr() {
            Ok(addr) => {
                direct.upsert(addr);
            }
            Err(error) => {
                tracing::trace!(
                    bind_uri = %bind_uri,
                    ?error,
                    "local interface has no direct endpoint"
                );
            }
        }

        locations.upsert(bind_uri, Arc::new(ref_iface.iface().bound_addr()));

        Self {
            ref_iface,
            state,
            _direct: direct,
        }
    }
}

impl<I: RefIO + 'static> InterfaceLocations<I> {
    pub fn new(ref_iface: I, locations: Arc<Locations>) -> Self {
        Self {
            current: Arc::new(Mutex::new(CurrentInterfaceLocations::new(
                ref_iface, locations,
            ))),
        }
    }

    fn lock_current(&self) -> MutexGuard<'_, CurrentInterfaceLocations<I>> {
        self.current
            .lock()
            .expect("InterfaceLocations current mutex poisoned")
    }

    pub fn agent_location(&self, agent: SocketAddr) -> InterfaceAgentLocation {
        let current = self.lock_current();
        InterfaceAgentLocation::new(current.state.clone(), agent)
    }

    /// Scope operation to the newest interface.
    pub fn r#for<R>(&self, ref_iface: &R, f: impl FnOnce(&Locations, BindUri))
    where
        R: RefIO + 'static,
    {
        let current = self.lock_current();
        let current_iface = &current.ref_iface;
        if !(ref_iface as &dyn Any)
            .downcast_ref::<I>()
            .is_some_and(|ref_iface| ref_iface.same_io(current_iface))
        {
            return;
        }
        f(&current.state.locations, current.state.bind_uri.clone());
    }
}

pub type IfaceLocations<I> = InterfaceLocations<I>;

pub type LocationsComponent = InterfaceLocations<WeakInterface>;

impl Component for LocationsComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        _ = cx;
        self.lock_current().state.close();
        Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        let mut current = self.lock_current();
        if iface.downgrade().same_io(&current.ref_iface) {
            return;
        }

        let locations = current.state.locations.clone();
        current.state.close();
        *current = CurrentInterfaceLocations::new(iface.downgrade(), locations);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::time::{Duration, sleep};

    use super::{AddressEvent, Locations};
    use crate::BindUri;

    #[tokio::test]
    async fn observer_drop_unsubscribes_without_publish() {
        let locations = Arc::new(Locations::new());
        let observer = locations.subscribe();

        wait_for_subscriber_count(&locations, 1).await;

        drop(observer);

        wait_for_subscriber_count(&locations, 0).await;
    }

    #[tokio::test]
    async fn dropped_observer_is_not_retained_by_later_publish() {
        let locations = Arc::new(Locations::new());
        let bind_uri: BindUri = "inet://127.0.0.1:1".parse().expect("bind uri must parse");
        let observer = locations.subscribe();

        wait_for_subscriber_count(&locations, 1).await;
        drop(observer);
        wait_for_subscriber_count(&locations, 0).await;

        locations.upsert(bind_uri.clone(), Arc::new("addr".to_string()));

        sleep(Duration::from_millis(50)).await;

        assert_eq!(locations.subscriber_count().await, 0);
    }

    async fn wait_for_subscriber_count(locations: &Locations, expected: usize) {
        for _ in 0..20 {
            if locations.subscriber_count().await == expected {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(locations.subscriber_count().await, expected);
    }

    #[tokio::test]
    async fn subscribe_replays_current_locations() {
        let locations = Locations::new();
        let bind_uri: BindUri = "inet://127.0.0.1:2".parse().expect("bind uri must parse");

        locations.upsert(bind_uri.clone(), Arc::new("addr".to_string()));

        let mut observer = locations.subscribe();
        let (observed_bind_uri, event) = observer.recv().await.expect("observer must receive");

        assert_eq!(observed_bind_uri, bind_uri);
        assert!(matches!(event, AddressEvent::Upsert(_)));
    }
}
