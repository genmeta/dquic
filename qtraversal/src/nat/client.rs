use std::{
    collections::HashMap,
    fmt,
    io::{self},
    net::SocketAddr,
    ops::{ControlFlow, Deref},
    pin::pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU8, Ordering::SeqCst},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use qbase::net::{Family, addr::EndpointAddr};
pub use qbase::net::{NatType, NetFeature};
use qinterface::{
    Interface, WeakInterface,
    bind_uri::BindUri,
    component::{
        Component,
        local_endpoint::{
            IfaceLocalEndpoints, InterfaceAgentEndpointPublisher, LocalEndpointsComponent,
        },
    },
    io::{IO, RefIO},
};
use qresolve::Resolve;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::{sync::Notify, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::{router::StunRouter, tx::Transaction};
use crate::{
    future::Future,
    nat::{
        iface::StunIO,
        msg::{Attr, Request, Response},
        router::StunRouterComponent,
    },
};

const NAT_MAPPING_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatDetectionStep {
    Access,
    Mapping,
    Filtering,
    Dynamic,
}

impl fmt::Display for NatDetectionStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Access => f.write_str("access test"),
            Self::Mapping => f.write_str("mapping test"),
            Self::Filtering => f.write_str("filtering test"),
            Self::Dynamic => f.write_str("dynamic test"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunResponseAttribute {
    MappedAddress,
    ChangedAddress,
    SourceAddress,
}

impl fmt::Display for StunResponseAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MappedAddress => f.write_str("mapped address"),
            Self::ChangedAddress => f.write_str("changed address"),
            Self::SourceAddress => f.write_str("source address"),
        }
    }
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum StunProbeError {
    #[snafu(display("failed to send stun request to {stun_server}"))]
    SendRequest {
        stun_server: SocketAddr,
        #[snafu(source(from(io::Error, Arc::new)))]
        source: Arc<io::Error>,
    },

    #[snafu(display("stun server {stun_server} did not respond"))]
    NoResponse {
        stun_server: SocketAddr,
        retry_times: u8,
        timeout: Duration,
    },
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum StunResponseError {
    #[snafu(display("stun response from {stun_server} is missing {attribute}"))]
    MissingAttribute {
        stun_server: SocketAddr,
        attribute: StunResponseAttribute,
    },
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum DetectOuterAddrError {
    #[snafu(display("stun client interface `{bind_uri}` was rebinded"))]
    Rebinded { bind_uri: BindUri },

    #[snafu(display("failed to detect outer address"))]
    Probe { source: StunProbeError },

    #[snafu(display("failed to read outer address response"))]
    Response { source: StunResponseError },
}

impl From<StunProbeError> for DetectOuterAddrError {
    fn from(source: StunProbeError) -> Self {
        Self::Probe { source }
    }
}

impl From<DetectOuterAddrError> for io::Error {
    fn from(source: DetectOuterAddrError) -> Self {
        io::Error::other(source)
    }
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum DetectNatTypeError {
    #[snafu(display("stun client interface `{bind_uri}` was rebinded"))]
    Rebinded { bind_uri: BindUri },

    #[snafu(display("failed to get local address for NAT detection on `{bind_uri}`"))]
    LocalAddr {
        bind_uri: BindUri,
        #[snafu(source(from(io::Error, Arc::new)))]
        source: Arc<io::Error>,
    },

    #[snafu(display("failed to run NAT detection {step}"))]
    Probe {
        step: NatDetectionStep,
        source: StunProbeError,
    },

    #[snafu(display("failed to read NAT detection {step} response"))]
    Response {
        step: NatDetectionStep,
        source: StunResponseError,
    },
}

impl From<DetectNatTypeError> for io::Error {
    fn from(source: DetectNatTypeError) -> Self {
        io::Error::other(source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    Active = 0,
    Inactive = 1,
    Closing = 2,
}

#[derive(Debug, Clone)]
struct ArcClientState {
    state: Arc<AtomicU8>,
    observers: [Arc<Notify>; 3],
}

impl ArcClientState {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(ClientState::Active as u8)),
            observers: <[_; 3]>::default(),
        }
    }

    pub fn try_update(&self, old_state: ClientState, new_state: ClientState) -> bool {
        match self
            .state
            .compare_exchange(old_state as u8, new_state as u8, SeqCst, SeqCst)
        {
            Ok(_old) => {
                self.observers[new_state as usize].notify_waiters();
                true
            }
            Err(_current) => false,
        }
    }

    pub fn get(&self) -> ClientState {
        match self.state.load(SeqCst) {
            0 => ClientState::Active,
            1 => ClientState::Inactive,
            2 => ClientState::Closing,
            _ => unreachable!(),
        }
    }

    pub fn set(&self, new_state: ClientState) -> ClientState {
        let old_state = self.state.swap(new_state as u8, SeqCst);
        if old_state != new_state as u8 {
            self.observers[new_state as usize].notify_waiters();
        }
        match old_state {
            0 => ClientState::Active,
            1 => ClientState::Inactive,
            2 => ClientState::Closing,
            _ => unreachable!(),
        }
    }

    pub fn wait(&self, expect: ClientState) -> impl futures::Future<Output = ()> + use<> {
        let notify = self.observers[expect as usize].clone();
        let state = self.state.clone();
        async move {
            let mut notified = pin!(notify.notified());
            loop {
                notified.as_mut().enable();
                if state.load(SeqCst) == expect as u8 {
                    return;
                }
                notified.as_mut().await;
                notified.set(notify.notified());
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct StunClient<I: RefIO + 'static> {
    #[allow(clippy::type_complexity)]
    outer_addr: Arc<Future<Result<SocketAddr, DetectOuterAddrError>>>,
    nat_type: Arc<Future<Result<NatType, DetectNatTypeError>>>,
    ref_iface: I,
    // 可能被复制进keep_alive_task
    stun_router: StunRouter,
    stun_agent: SocketAddr,
    endpoint_publisher: Arc<Mutex<Option<InterfaceAgentEndpointPublisher>>>,

    state: ArcClientState,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl<I: RefIO + 'static> StunClient<I> {
    pub fn new(
        ref_iface: I,
        stun_router: StunRouter,
        stun_agent: SocketAddr,
        local_endpoints: Option<IfaceLocalEndpoints<I>>,
    ) -> Self {
        let endpoint_publisher = local_endpoints.as_ref().and_then(|local_endpoints| {
            match local_endpoints.agent_endpoint_publisher(stun_agent) {
                Ok(publisher) => Some(publisher),
                Err(error) => {
                    tracing::debug!(target: "stun", %stun_agent, ?error, "failed to claim STUN agent endpoint publisher");
                    None
                }
            }
        });
        let client = Self {
            nat_type: Default::default(),
            outer_addr: Default::default(),
            stun_agent,
            ref_iface,
            stun_router,
            endpoint_publisher: Arc::new(Mutex::new(endpoint_publisher)),
            state: ArcClientState::new(),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
        };
        tracing::debug!(target: "stun", %stun_agent, "created new STUN client");
        {
            let mut tasks = client.lock_tasks();
            tasks.spawn(client.keep_alive_task());
            if !client.ref_iface.iface().bind_uri().is_temporary() {
                tasks.spawn(client.nat_detect_task());
            }
        }
        client
    }

    fn lock_tasks(&self) -> MutexGuard<'_, JoinSet<()>> {
        self.tasks.lock().expect("StunClient tasks lock poisoned")
    }

    fn keep_alive_task(&self) -> impl futures::Future<Output = ()> + use<I> {
        let outer_addr = self.outer_addr.clone();
        let stun_agent = self.stun_agent;
        let stun_router = self.stun_router.clone();
        tracing::debug!(target: "stun", %stun_agent, "starting STUN client keep alive task");
        let ref_iface = self.ref_iface.clone();
        let bind_uri = ref_iface.iface().bind_uri();

        let endpoint_publisher = self.endpoint_publisher.clone();

        let client_state = self.state.clone();

        let keep_alive_task = async move {
            let log_detect_result = |detect_result: &Result<SocketAddr, DetectOuterAddrError>| {
                match &detect_result {
                    Ok(new_outer_addr) => match outer_addr.try_get().as_deref().cloned() {
                        Some(Ok(old_outer)) if old_outer == *new_outer_addr => {
                            tracing::trace!(target: "stun", %new_outer_addr,  "keep alive, outer addr unchanged");
                        }
                        Some(Ok(old_outer)) => {
                            tracing::debug!(target: "stun", %old_outer, %new_outer_addr, "keep alive, outer addr changed");
                        }
                        Some(Err(error)) => {
                            tracing::debug!(
                                target: "stun",
                                error = %snafu::Report::from_error(&error),
                                %new_outer_addr,
                                "outer addr detection recovered"
                            );
                        }
                        None => {
                            tracing::debug!(target: "stun", %new_outer_addr, "detected outer addr");
                        }
                    },
                    Err(error) => {
                        tracing::trace!(target: "stun", error = %snafu::Report::from_error(error), "detect outer addr failed");
                    }
                }
            };
            tracing::trace!(target: "stun", "starting keep alive task");
            loop {
                let detect_result = detect_outer_addr(
                    ref_iface.clone(),
                    stun_router.clone(),
                    stun_agent,
                    3,
                    Duration::from_millis(300),
                )
                .await;

                match &detect_result {
                    Ok(_) => client_state.try_update(ClientState::Inactive, ClientState::Active),
                    Err(_) => client_state.try_update(ClientState::Active, ClientState::Inactive),
                };

                log_detect_result(&detect_result);

                let timeout = match &detect_result {
                    Ok(_) => NAT_MAPPING_REFRESH_INTERVAL,
                    Err(_) => Duration::from_secs(1),
                };

                if !bind_uri.is_temporary() {
                    let mut guard = endpoint_publisher
                        .lock()
                        .expect("STUN endpoint publisher mutex poisoned");
                    if let Some(publisher) = guard.as_mut() {
                        match &detect_result {
                            Ok(outer) => {
                                publisher.upsert(*outer);
                            }
                            Err(_) => {
                                publisher.remove();
                            }
                        }
                    }
                }

                outer_addr.assign(detect_result);
                tokio::time::sleep(timeout).await;
            }
        };
        let bind_uri = self.ref_iface.iface().bind_uri();
        keep_alive_task.instrument(tracing::debug_span!(
            target: "stun",
            "keep_alive_task",
            %bind_uri,
            %stun_agent,
        ))
    }

    pub fn poll_outer_addr(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<SocketAddr, DetectOuterAddrError>> {
        if self.state.get() == ClientState::Closing {
            return Poll::Ready(Err(DetectOuterAddrError::Rebinded {
                bind_uri: self.ref_iface.iface().bind_uri(),
            }));
        }
        self.outer_addr.poll_get(cx).map(|result| result.clone())
    }

    pub async fn outer_addr(&self) -> Result<SocketAddr, DetectOuterAddrError> {
        core::future::poll_fn(|cx| self.poll_outer_addr(cx)).await
    }

    pub fn agent_addr(&self) -> SocketAddr {
        self.stun_agent
    }

    pub fn get_outer_addr(&self) -> Option<Result<SocketAddr, DetectOuterAddrError>> {
        if self.state.get() == ClientState::Closing {
            return Some(Err(DetectOuterAddrError::Rebinded {
                bind_uri: self.ref_iface.iface().bind_uri(),
            }));
        }

        self.outer_addr.try_get().map(|result| result.clone())
    }

    fn nat_detect_task(&self) -> impl futures::Future<Output = ()> + use<I> {
        let nat_type = self.nat_type.clone();
        let ref_iface = self.ref_iface.clone();
        let stun_router = self.stun_router.clone();
        let stun_agent = self.stun_agent;
        let bind_uri = ref_iface.iface().bind_uri();
        // Note: 原来的逻辑是 nat 探测会新建 iface，但是有的服务器只能开放指定端口，所以还是用监听的端口进行探测
        // 又因为Dynamic 总是会新建 iface 进行打洞，所以这里污染了影响不会很大
        let task = async move {
            tracing::debug!(target: "stun", "starting NAT type detection");
            // NAT classification uses changed-address responses that may
            // traverse another STUN server and Docker/router conntrack before
            // reaching this socket. A 100ms per-attempt budget is too close to
            // the normal response latency under load and can misclassify a
            // full-cone NAT as restricted after a transient late response.
            let timeout = Duration::from_millis(300);
            _ = nat_type
                .assign(detect_nat_type(ref_iface, stun_router, stun_agent, 30, timeout).await);
        };

        task.instrument(tracing::debug_span!(
            target: "stun",
            "nat_type_task",
            %bind_uri,
            %stun_agent,
        ))
    }

    pub fn poll_nat_type(&self, cx: &mut Context) -> Poll<Result<NatType, DetectNatTypeError>> {
        if self.state.get() == ClientState::Closing {
            return Poll::Ready(Err(DetectNatTypeError::Rebinded {
                bind_uri: self.ref_iface.iface().bind_uri(),
            }));
        }
        self.nat_type.poll_get(cx).map(|result| result.clone())
    }

    pub async fn nat_type(&self) -> Result<NatType, DetectNatTypeError> {
        core::future::poll_fn(|cx| self.poll_nat_type(cx)).await
    }

    pub fn get_nat_type(&self) -> Option<Result<NatType, DetectNatTypeError>> {
        if self.state.get() == ClientState::Closing {
            return Some(Err(DetectNatTypeError::Rebinded {
                bind_uri: self.ref_iface.iface().bind_uri(),
            }));
        }
        self.nat_type.try_get().map(|result| result.clone())
    }

    // fn restart(&mut self) -> io::Result<()> {
    //     self.stun_router.clear();
    //     *self = RunningClient::new(
    //         self.ref_iface.clone(),
    //         self.stun_router.clone(),
    //         self.stun_agent,
    //     );
    //     Ok(())
    // }

    pub fn poll_close(&self, cx: &mut Context) -> Poll<()> {
        if self.state.set(ClientState::Closing) == ClientState::Closing {
            return Poll::Ready(());
        }
        self.lock_tasks().abort_all();
        while ready!(self.lock_tasks().poll_join_next(cx)).is_some() {}
        if let Some(publisher) = self
            .endpoint_publisher
            .lock()
            .expect("STUN endpoint publisher mutex poisoned")
            .as_mut()
        {
            publisher.remove();
        }
        self.nat_type.clear();
        self.outer_addr.clear();
        Poll::Ready(())
    }
}

#[derive(Debug)]
pub struct StunClientComponent {
    client: Mutex<StunClient<WeakInterface>>,
}

impl StunClientComponent {
    pub fn new(client: StunClient<WeakInterface>) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }

    fn lock_client(&self) -> MutexGuard<'_, StunClient<WeakInterface>> {
        self.client.lock().expect("StunClient lock poisoned")
    }

    pub fn client(&self) -> StunClient<WeakInterface> {
        self.lock_client().clone()
    }
}

impl Component for StunClientComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.lock_client().poll_close(cx)
    }

    fn reinit(&self, iface: &Interface) {
        let mut client = self.lock_client();
        if client.ref_iface.same_io(&iface.downgrade()) {
            return;
        }

        let Ok(Some((router, local_endpoints))) = iface.with_components(|components| {
            let router = components.with(|router: &StunRouterComponent| {
                router.reinit(iface);
                router.router()
            })?;
            let local_endpoints = components.with(|local_endpoints: &LocalEndpointsComponent| {
                local_endpoints.reinit(iface);
                local_endpoints.clone()
            });
            Some((router, local_endpoints))
        }) else {
            return;
        };

        let new_client = StunClient::new(
            iface.downgrade(),
            router,
            client.stun_agent,
            local_endpoints,
        );
        *client = new_client;
    }
}

type StunClientsMap<I> = HashMap<SocketAddr, StunClient<I>>;

#[derive(Debug)]
struct StunClientsInner<I: RefIO + 'static> {
    ref_iface: I,
    clients: Arc<Mutex<StunClientsMap<I>>>,
    resolver: Arc<dyn Resolve + Send + Sync>,
    server: Arc<str>,
    task: Option<AbortOnDropHandle<()>>,
}

pub const DEFAULT_STUN_SERVER: &str = "nat.genmeta.net:20004";

impl<I: RefIO + 'static> StunClientsInner<I> {
    pub const MIN_AGENTS: usize = 3;

    pub fn new(
        ref_iface: I,
        router: StunRouter,
        resolver: Arc<dyn Resolve + Send + Sync>,
        server: Arc<str>,
        agents: impl IntoIterator<Item = SocketAddr>,
        local_endpoints: Option<IfaceLocalEndpoints<I>>,
    ) -> Self {
        let new_stun_client = {
            let ref_iface = ref_iface.clone();
            move |agent_addr: SocketAddr| {
                let local_addr = ref_iface.iface().local_addr().ok()?;
                if local_addr.is_ipv4() != agent_addr.is_ipv4() {
                    return None;
                }
                let stun_router = router.clone();
                Some(StunClient::new(
                    ref_iface.clone(),
                    stun_router,
                    agent_addr,
                    local_endpoints.clone(),
                ))
            }
        };

        let clients: Arc<Mutex<StunClientsMap<I>>> = Arc::new(Mutex::new(
            agents
                .into_iter()
                .filter_map(|agent| {
                    tracing::trace!(target: "stun", %agent, "initializing STUN client for agent");
                    new_stun_client(agent).map(|client| (agent, client))
                })
                .collect(),
        ));
        let task = AbortOnDropHandle::new(tokio::spawn({
            let clients = clients.clone();
            let resolver = resolver.clone();
            let server = server.clone();
            let ref_iface = ref_iface.clone();
            async move {
                let lock_clients = || clients.lock().expect("StunClients mutex poisoned");

                let should_lookup_agents = |clients: &StunClientsMap<I>| match clients
                    .values()
                    .try_fold((0, 0), |(active, inactive), client| {
                        match client.state.get() {
                            ClientState::Active => ControlFlow::Continue((active + 1, inactive)),
                            ClientState::Inactive => ControlFlow::Continue((active, inactive + 1)),
                            ClientState::Closing => ControlFlow::Break(()),
                        }
                    }) {
                    ControlFlow::Continue((active, _inactive)) => active < Self::MIN_AGENTS,
                    ControlFlow::Break(_) => false,
                };

                let wait_too_few_agents = |clients: &StunClientsMap<I>| {
                    let clients_len = clients.len();
                    debug_assert!(clients_len >= Self::MIN_AGENTS);
                    let mut stream = clients
                        .iter()
                        .map(|(.., client)| client.state.wait(ClientState::Inactive))
                        .collect::<FuturesUnordered<_>>()
                        .skip(clients_len.saturating_sub(Self::MIN_AGENTS));
                    async move { _ = stream.next().await }
                };

                loop {
                    while !{ should_lookup_agents(&lock_clients()) } {
                        { wait_too_few_agents(&lock_clients()) }.await;
                    }

                    // 保证两次 lookup 至少间隔 10s，同时限时 10s 防止 resolver 卡住
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                    _ = tokio::time::timeout_at(deadline, async {
                        let Ok(stream) = resolver.lookup(server.as_ref()).await else { return };
                        let is_ipv4 = ref_iface.iface().bind_uri().family() == Family::V4;
                        let mut stream = std::pin::pin!(stream);
                        while let Some((_, addr)) = stream.next().await {
                            let EndpointAddr::Direct { addr } = addr else { continue };
                            if addr.is_ipv4() != is_ipv4 { continue }
                            let done = {
                                let mut clients = lock_clients();
                                if clients.contains_key(&addr) { continue }
                                if let Some(client) = new_stun_client(addr) {
                                    tracing::debug!(target: "stun", %addr, "discovered new STUN agent");
                                    clients.insert(addr, client);
                                    !should_lookup_agents(&clients)
                                } else { false }
                            };
                            if done { break }
                        }
                    }).await;
                    tokio::time::sleep_until(deadline).await;
                }
            }
            .in_current_span()
        }));

        Self {
            ref_iface,
            clients,
            resolver,
            server,
            task: Some(task),
        }
    }

    fn lock_clients(&self) -> MutexGuard<'_, StunClientsMap<I>> {
        self.clients
            .lock()
            .expect("StunClientsComponentInner lock poisoned")
    }

    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(task) = self.task.as_mut() {
            task.abort();
            _ = ready!(task.poll_unpin(cx));
            self.task.take();
        }

        for (.., client) in self.lock_clients().iter() {
            ready!(client.poll_close(cx))
        }

        Poll::Ready(())
    }
}

#[derive(Debug, Clone)]
pub struct StunClients<I: RefIO + 'static> {
    clients: Arc<Mutex<StunClientsInner<I>>>,
}

impl<I: RefIO + 'static> StunClients<I> {
    pub fn new(
        ref_iface: I,
        router: StunRouter,
        resolver: Arc<dyn Resolve + Send + Sync>,
        server: impl Into<Arc<str>>,
        agents: impl IntoIterator<Item = SocketAddr>,
        local_endpoints: Option<IfaceLocalEndpoints<I>>,
    ) -> Self {
        Self {
            clients: Arc::new(Mutex::new(StunClientsInner::new(
                ref_iface,
                router,
                resolver,
                server.into(),
                agents,
                local_endpoints,
            ))),
        }
    }

    fn lock_clients(&self) -> MutexGuard<'_, StunClientsInner<I>> {
        self.clients
            .lock()
            .expect("StunClientsComponent lock poisoned")
    }

    pub fn with_clients<T>(&self, f: impl FnOnce(&StunClientsMap<I>) -> T) -> T {
        f(self.lock_clients().lock_clients().deref())
    }

    pub fn poll_close(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.lock_clients().poll_close(cx)
    }
}

pub type StunClientsComponent = StunClients<WeakInterface>;

impl Component for StunClientsComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.lock_clients().poll_close(cx)
    }

    fn reinit(&self, iface: &Interface) {
        let mut clients = self.lock_clients();
        if clients.ref_iface.same_io(&iface.downgrade()) {
            return;
        }

        _ = iface.with_components(|components| {
            let Some(router) = components.with(|router: &StunRouterComponent| {
                router.reinit(iface);
                router.router()
            }) else {
                return;
            };
            let local_endpoints = components.with(|local_endpoints: &LocalEndpointsComponent| {
                local_endpoints.reinit(iface);
                local_endpoints.clone()
            });

            let new_clinets = StunClientsInner::new(
                iface.downgrade(),
                router,
                clients.resolver.clone(),
                clients.server.clone(),
                clients.lock_clients().keys().copied(),
                local_endpoints,
            );
            *clients = new_clinets;
        });
    }
}

async fn send_stun_request<I: RefIO>(
    ref_iface: I,
    stun_router: StunRouter,
    stun_server: SocketAddr,
    request: Request,
    retry_times: u8,
    timeout: Duration,
) -> Result<Option<Response>, StunProbeError> {
    Transaction::begin(ref_iface, stun_router, retry_times, timeout)
        .send_request(request, stun_server)
        .await
        .context(stun_probe_error::SendRequestSnafu { stun_server })
}

async fn send_required_stun_request<I: RefIO>(
    ref_iface: I,
    stun_router: StunRouter,
    stun_server: SocketAddr,
    request: Request,
    retry_times: u8,
    timeout: Duration,
) -> Result<Response, StunProbeError> {
    send_stun_request(
        ref_iface,
        stun_router,
        stun_server,
        request,
        retry_times,
        timeout,
    )
    .await?
    .context(stun_probe_error::NoResponseSnafu {
        stun_server,
        retry_times,
        timeout,
    })
}

fn response_attr(
    response: &Response,
    stun_server: SocketAddr,
    attribute: StunResponseAttribute,
) -> Result<SocketAddr, StunResponseError> {
    response
        .0
        .iter()
        .find_map(|attr| match (attribute, attr) {
            (StunResponseAttribute::MappedAddress, Attr::MappedAddress(addr))
            | (StunResponseAttribute::ChangedAddress, Attr::ChangedAddress(addr))
            | (StunResponseAttribute::SourceAddress, Attr::SourceAddress(addr)) => Some(*addr),
            _ => None,
        })
        .context(stun_response_error::MissingAttributeSnafu {
            stun_server,
            attribute,
        })
}

async fn nat_detection_request<I: RefIO>(
    ref_iface: I,
    stun_router: StunRouter,
    stun_server: SocketAddr,
    request: Request,
    retry_times: u8,
    timeout: Duration,
    step: NatDetectionStep,
) -> Result<Option<Response>, DetectNatTypeError> {
    send_stun_request(
        ref_iface,
        stun_router,
        stun_server,
        request,
        retry_times,
        timeout,
    )
    .await
    .context(detect_nat_type_error::ProbeSnafu { step })
}

async fn required_nat_detection_request<I: RefIO>(
    ref_iface: I,
    stun_router: StunRouter,
    stun_server: SocketAddr,
    request: Request,
    retry_times: u8,
    timeout: Duration,
    step: NatDetectionStep,
) -> Result<Response, DetectNatTypeError> {
    send_required_stun_request(
        ref_iface,
        stun_router,
        stun_server,
        request,
        retry_times,
        timeout,
    )
    .await
    .context(detect_nat_type_error::ProbeSnafu { step })
}

fn nat_response_attr(
    response: &Response,
    stun_server: SocketAddr,
    attribute: StunResponseAttribute,
    step: NatDetectionStep,
) -> Result<SocketAddr, DetectNatTypeError> {
    response_attr(response, stun_server, attribute)
        .context(detect_nat_type_error::ResponseSnafu { step })
}

async fn detect_outer_addr<I: RefIO>(
    ref_iface: I,
    stun_router: StunRouter,
    stun_agent: SocketAddr,
    retry_times: u8,
    timeout: Duration,
) -> Result<SocketAddr, DetectOuterAddrError> {
    let request = Request::default();
    let response = send_required_stun_request(
        ref_iface,
        stun_router,
        stun_agent,
        request,
        retry_times,
        timeout,
    )
    .await?;
    response_attr(&response, stun_agent, StunResponseAttribute::MappedAddress)
        .context(detect_outer_addr_error::ResponseSnafu)
}

pub static VISUALIZE_NAT_DETECTION: AtomicBool = AtomicBool::new(false);

macro_rules! visualize_nat_detection {
    ($($tt:tt)*) => {{
        if VISUALIZE_NAT_DETECTION.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::info!(target: "stun", $($tt)*);
        } else {
            tracing::trace!(target: "stun", $($tt)*);
        }
    }};
}

pub const RESTRICTED_RETRY_TIMES: u8 = 3;

async fn detect_nat_type<I: RefIO>(
    ref_iface: I,
    stun_router: StunRouter,
    stun_agent: SocketAddr,
    retry_times: u8,
    timeout: Duration,
) -> Result<NatType, DetectNatTypeError> {
    let bind_uri = ref_iface.iface().bind_uri();
    let local_addr =
        ref_iface
            .iface()
            .local_addr()
            .context(detect_nat_type_error::LocalAddrSnafu {
                bind_uri: bind_uri.clone(),
            })?;
    visualize_nat_detection!("Starting NAT detection with local address: {local_addr}");
    let stun_agent1 = stun_agent;

    visualize_nat_detection!("Access Test: probing server {stun_agent1}");
    let request = Request::default();
    let response = nat_detection_request(
        ref_iface.clone(),
        stun_router.clone(),
        stun_agent1,
        request,
        retry_times,
        timeout,
        NatDetectionStep::Access,
    )
    .await?;

    let Some(response) = response else {
        visualize_nat_detection!("result: no response after {retry_times} attempts");
        visualize_nat_detection!(
            "conclusion: The network feature is {:?}, NAT Type is {:?}\n",
            NetFeature::Blocked,
            NatType::Blocked
        );
        return Ok(NatType::Blocked);
    };

    let mut net_features = NetFeature::empty();

    let mapped_addr1 = nat_response_attr(
        &response,
        stun_agent1,
        StunResponseAttribute::MappedAddress,
        NatDetectionStep::Access,
    )?;
    let stun_agent2 = nat_response_attr(
        &response,
        stun_agent1,
        StunResponseAttribute::ChangedAddress,
        NatDetectionStep::Access,
    )?;
    visualize_nat_detection!("result: received from {stun_agent1}, external addr: {mapped_addr1}");
    if mapped_addr1 == local_addr {
        // Public IP
        visualize_nat_detection!(
            "conclusion: Address {local_addr} has public IP, Proceeding to filtering behavior test.\n"
        );
        visualize_nat_detection!(
            "filtering test: probing server {stun_agent2}. Request server to respond from a changed IP:port",
        );
        net_features |= NetFeature::Public;
        let request = Request::change_ip_and_port();
        let response = nat_detection_request(
            ref_iface.clone(),
            stun_router.clone(),
            stun_agent2,
            request,
            retry_times,
            timeout,
            NatDetectionStep::Filtering,
        )
        .await?;
        if let Some(response) = response {
            let mapped_addr2 = nat_response_attr(
                &response,
                stun_agent2,
                StunResponseAttribute::MappedAddress,
                NatDetectionStep::Filtering,
            )?;
            let source_addr = nat_response_attr(
                &response,
                stun_agent2,
                StunResponseAttribute::SourceAddress,
                NatDetectionStep::Filtering,
            )?;
            visualize_nat_detection!(
                "Result: received from {source_addr}, external addr: {mapped_addr2}",
            );
            visualize_nat_detection!("conclusion: Destination IP independent filtering\n");
        } else {
            net_features |= NetFeature::Restricted;
            visualize_nat_detection!("result: no response after {retry_times} attempts");
            visualize_nat_detection!("conclusion: Filters packets based on destination IP\n");
        }
        visualize_nat_detection!(
            "filtering test: probing server {stun_agent2}. Request server to respond from a changed port",
        );
        let request = Request::change_port();
        let response = nat_detection_request(
            ref_iface.clone(),
            stun_router.clone(),
            stun_agent2,
            request,
            retry_times,
            timeout,
            NatDetectionStep::Filtering,
        )
        .await?;
        if let Some(response) = response {
            let mapped_addr2 = nat_response_attr(
                &response,
                stun_agent2,
                StunResponseAttribute::MappedAddress,
                NatDetectionStep::Filtering,
            )?;
            let source_addr = nat_response_attr(
                &response,
                stun_agent2,
                StunResponseAttribute::SourceAddress,
                NatDetectionStep::Filtering,
            )?;
            visualize_nat_detection!(
                "Result: received from {source_addr}, external addr: {mapped_addr2}",
            );
            visualize_nat_detection!("conclusion: Destination port independent filtering\n");
        } else {
            net_features |= NetFeature::PortRestricted;
            visualize_nat_detection!("result: no response after {retry_times} attempts");
            visualize_nat_detection!("conclusion: Filters packets based on destination port\n");
        }
        let nat_type = NatType::from(net_features);
        visualize_nat_detection!(
            "NAT detection completed. Network features: {:?}, NAT Type: {:?}",
            net_features,
            nat_type
        );
        Ok(nat_type)
    } else {
        // Private IP
        visualize_nat_detection!("conclusion: Address {local_addr} has private IP.\n");
        visualize_nat_detection!("Mapping Test1: probing server {stun_agent2}");
        let request = Request::default();
        let response = required_nat_detection_request(
            ref_iface.clone(),
            stun_router.clone(),
            stun_agent2,
            request,
            retry_times,
            timeout,
            NatDetectionStep::Mapping,
        )
        .await?;

        let stun_agent3 = nat_response_attr(
            &response,
            stun_agent2,
            StunResponseAttribute::ChangedAddress,
            NatDetectionStep::Mapping,
        )?;
        let mapped_addr2 = nat_response_attr(
            &response,
            stun_agent2,
            StunResponseAttribute::MappedAddress,
            NatDetectionStep::Mapping,
        )?;
        if mapped_addr1 != mapped_addr2 {
            net_features |= NetFeature::Symmetric;
            visualize_nat_detection!(
                "result: received from {stun_agent2}, external addr: {mapped_addr2}"
            );
            visualize_nat_detection!(
                "conclusion: The mapped address is different and destination-dependent.\n"
            );

            // 判断规律
            visualize_nat_detection!("mapping test2: probing server {stun_agent3}");
            let request = Request::default();
            let response = nat_detection_request(
                ref_iface.clone(),
                stun_router.clone(),
                stun_agent3,
                request,
                retry_times,
                timeout,
                NatDetectionStep::Mapping,
            )
            .await?;

            let Some(response) = response else {
                visualize_nat_detection!("result: no response after {retry_times} attempts");
                visualize_nat_detection!(
                    "conclusion: Unable to determine port mapping behavior due to lack of response from third server.\n"
                );
                return Ok(NatType::from(net_features));
            };

            let mapped_addr3 = nat_response_attr(
                &response,
                stun_agent3,
                StunResponseAttribute::MappedAddress,
                NatDetectionStep::Mapping,
            )?;
            let step1 = mapped_addr2.port() as i32 - mapped_addr1.port() as i32;
            let step2 = mapped_addr3.port() as i32 - mapped_addr2.port() as i32;
            visualize_nat_detection!(
                "result: received from {stun_agent3}, external addr: {mapped_addr3}"
            );
            if step1 == step2 {
                visualize_nat_detection!(
                    "conclusion: The port changes regularly with step {step1}\n"
                );
            } else {
                visualize_nat_detection!("conclusion: The Ports change randomly.\n");
            }
            Ok(NatType::from(net_features))
        } else {
            // 不是对称型
            // Open test
            // 发给 server2 换 ip and port 即 server3 回, server3 可能不响应
            // server1: ip1:port1
            // server2: ip2:port2
            // server3: ip3:port1
            // server4: ip1:port2
            // server5: ip2:port1
            // server6: ip3:port2
            visualize_nat_detection!(
                "filtering test: probing server {stun_agent2}. Request server to respond from a changed IP and port",
            );
            let request = Request::change_ip_and_port();
            // 可能会不响应，超时太久会导致探测很久
            let response = nat_detection_request(
                ref_iface.clone(),
                stun_router.clone(),
                stun_agent2,
                request,
                RESTRICTED_RETRY_TIMES,
                timeout,
                NatDetectionStep::Filtering,
            )
            .await?;
            if let Some(response) = response {
                let mapped_addr2 = nat_response_attr(
                    &response,
                    stun_agent2,
                    StunResponseAttribute::MappedAddress,
                    NatDetectionStep::Filtering,
                )?;
                let source_addr = nat_response_attr(
                    &response,
                    stun_agent2,
                    StunResponseAttribute::SourceAddress,
                    NatDetectionStep::Filtering,
                )?;
                visualize_nat_detection!(
                    "Result: received from {source_addr}, external addr: {mapped_addr2}",
                );
                visualize_nat_detection!("conclusion: Destination IP independent filtering\n");
            } else {
                net_features |= NetFeature::Restricted;
                visualize_nat_detection!(
                    "result: no response after {RESTRICTED_RETRY_TIMES} attempts"
                );
                visualize_nat_detection!("conclusion: Filters packets based on destination IP\n");
            }
            visualize_nat_detection!(
                "filtering test: probing server {stun_agent2}. Request server to respond from a changed port",
            );
            // Restricted test
            // server2 换 port 即 server5 回，可能不响应
            // 可能会不响应，超时太久会导致探测很久
            let request = Request::change_port();
            let response = nat_detection_request(
                ref_iface.clone(),
                stun_router.clone(),
                stun_agent2,
                request,
                RESTRICTED_RETRY_TIMES,
                timeout,
                NatDetectionStep::Filtering,
            )
            .await?;
            if let Some(response) = response {
                let mapped_addr2 = nat_response_attr(
                    &response,
                    stun_agent2,
                    StunResponseAttribute::MappedAddress,
                    NatDetectionStep::Filtering,
                )?;
                let source_addr = nat_response_attr(
                    &response,
                    stun_agent2,
                    StunResponseAttribute::SourceAddress,
                    NatDetectionStep::Filtering,
                )?;
                visualize_nat_detection!(
                    "Result: received from {source_addr}, external addr: {mapped_addr2}",
                );
                visualize_nat_detection!("conclusion: Destination port independent filtering\n");
            } else {
                net_features |= NetFeature::PortRestricted;
                visualize_nat_detection!(
                    "result: no response after {RESTRICTED_RETRY_TIMES} attempts"
                );
                visualize_nat_detection!("conclusion: Filters packets based on destination port\n");
            }
            // dynamic test， 请求 server3
            visualize_nat_detection!("Dynamic Test: probing server {stun_agent3}",);
            let request = Request::default();
            let response = nat_detection_request(
                ref_iface.clone(),
                stun_router.clone(),
                stun_agent3,
                request,
                retry_times,
                timeout,
                NatDetectionStep::Dynamic,
            )
            .await?;

            if let Some(response) = response {
                // 回包，但是映射地址不一致，为动态型
                let mapped_addr3 = nat_response_attr(
                    &response,
                    stun_agent3,
                    StunResponseAttribute::MappedAddress,
                    NatDetectionStep::Dynamic,
                )?;
                let source_addr = nat_response_attr(
                    &response,
                    stun_agent3,
                    StunResponseAttribute::SourceAddress,
                    NatDetectionStep::Dynamic,
                )?;
                visualize_nat_detection!(
                    "Result: received from {source_addr}, external addr: {mapped_addr3}",
                );
                if mapped_addr1 != mapped_addr3 {
                    net_features |= NetFeature::Dynamic;
                    visualize_nat_detection!(
                        "conclusion: Mapping inconsistency indicates Address-Dependent Mapping, a Dynamic NAT type\n"
                    );
                } else {
                    visualize_nat_detection!(
                        "conclusion: The mapping address is consistent, not Dynamic\n"
                    );
                }
            } else {
                // 不回包也视为动态型
                net_features |= NetFeature::Dynamic;
                visualize_nat_detection!("result: no response after 3 attempts");
                visualize_nat_detection!(
                    "conclusion: Absence of server response may indicates Dynamic NAT behavior\n"
                );
            }
            let nat_type = NatType::from(net_features);
            visualize_nat_detection!(
                "NAT detection completed. Network features: {:?}, NAT Type: {:?}",
                net_features,
                nat_type
            );
            Ok(nat_type)
        }
    }
}
