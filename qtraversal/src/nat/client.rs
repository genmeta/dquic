use std::{
    fmt,
    io::{self},
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering::SeqCst},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use futures::{FutureExt, StreamExt};
use qbase::net::{AddrFamily, Family, addr::EndpointAddr};
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
use tokio::{sync::Notify, task::JoinSet, time::Instant};
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
const STUN_AGENT_DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);
const STUN_DISCOVERY_RETRY_INITIAL: Duration = Duration::from_secs(1);
const STUN_DISCOVERY_RETRY_MAX: Duration = Duration::from_secs(300);
const STUN_PROBE_RETRY_INITIAL: Duration = Duration::from_secs(1);
const STUN_PROBE_RETRY_MAX: Duration = Duration::from_secs(300);
const STUN_ENDPOINT_FAILURE_GRACE_PERIOD: Duration = Duration::from_secs(60);

fn retry_delay(retry_interval: &mut Duration, max: Duration) -> Duration {
    let delay = *retry_interval;
    *retry_interval = (*retry_interval * 2).min(max);
    delay
}

fn stun_probe_delay(probe_succeeded: bool, retry_interval: &mut Duration) -> Duration {
    if probe_succeeded {
        *retry_interval = STUN_PROBE_RETRY_INITIAL;
        NAT_MAPPING_REFRESH_INTERVAL
    } else {
        retry_delay(retry_interval, STUN_PROBE_RETRY_MAX)
    }
}

fn retain_last_stun_endpoint(last_success: Option<Instant>, now: Instant) -> bool {
    last_success.is_some_and(|last_success| {
        now.saturating_duration_since(last_success) < STUN_ENDPOINT_FAILURE_GRACE_PERIOD
    })
}

fn stun_interface_ready<I: RefIO>(ref_iface: &I, family: Family) -> bool {
    ref_iface
        .iface()
        .bound_addr()
        .is_ok_and(|bound_addr| bound_addr.family() == family)
}

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

struct StunKeepAliveState {
    outer_addr: Arc<Future<Result<SocketAddr, DetectOuterAddrError>>>,
    endpoint_publisher: Arc<Mutex<Option<InterfaceAgentEndpointPublisher>>>,
    outer_addr_ready: Arc<Notify>,
    refresh_agent: Arc<Notify>,
    publish_endpoint: bool,
    retry_interval: Duration,
    last_success: Option<Instant>,
}

impl StunKeepAliveState {
    fn new(
        outer_addr: Arc<Future<Result<SocketAddr, DetectOuterAddrError>>>,
        endpoint_publisher: Arc<Mutex<Option<InterfaceAgentEndpointPublisher>>>,
        outer_addr_ready: Arc<Notify>,
        refresh_agent: Arc<Notify>,
        publish_endpoint: bool,
    ) -> Self {
        Self {
            outer_addr,
            endpoint_publisher,
            outer_addr_ready,
            refresh_agent,
            publish_endpoint,
            retry_interval: STUN_PROBE_RETRY_INITIAL,
            last_success: None,
        }
    }

    fn apply(&mut self, detect_result: Result<SocketAddr, DetectOuterAddrError>) -> Duration {
        self.log_result(&detect_result);

        let now = Instant::now();
        let delay = stun_probe_delay(detect_result.is_ok(), &mut self.retry_interval);
        let retain_previous =
            detect_result.is_err() && retain_last_stun_endpoint(self.last_success, now);

        if self.publish_endpoint && !retain_previous {
            self.publish_result(&detect_result);
        }

        match detect_result {
            Ok(outer) => {
                self.last_success = Some(now);
                self.outer_addr.assign(Ok(outer));
                self.outer_addr_ready.notify_waiters();
            }
            Err(_) if retain_previous => {
                tracing::debug!(
                    target: "stun",
                    grace_ms = STUN_ENDPOINT_FAILURE_GRACE_PERIOD.as_millis(),
                    "retaining last STUN endpoint after transient probe failure"
                );
            }
            Err(error) => {
                let refresh_agent = matches!(
                    &error,
                    DetectOuterAddrError::Probe {
                        source: StunProbeError::NoResponse { .. }
                    } | DetectOuterAddrError::Response { .. }
                );
                if self.last_success.take().is_some() {
                    tracing::debug!(
                        target: "stun",
                        "withdrawing STUN endpoint after failure grace period"
                    );
                }
                self.outer_addr.assign(Err(error));
                if refresh_agent {
                    self.refresh_agent.notify_one();
                }
            }
        }

        delay
    }

    fn log_result(&self, detect_result: &Result<SocketAddr, DetectOuterAddrError>) {
        match detect_result {
            Ok(new_outer_addr) => match self.outer_addr.try_get().as_deref().cloned() {
                Some(Ok(old_outer)) if old_outer == *new_outer_addr => {
                    tracing::trace!(target: "stun", %new_outer_addr, "keep alive, outer addr unchanged");
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
    }

    fn publish_result(&self, detect_result: &Result<SocketAddr, DetectOuterAddrError>) {
        let mut guard = self
            .endpoint_publisher
            .lock()
            .expect("STUN endpoint publisher mutex poisoned");
        if let Some(publisher) = guard.as_mut() {
            match detect_result {
                Ok(outer) => publisher.upsert(*outer),
                Err(_) => publisher.remove(),
            };
        }
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
    outer_addr_ready: Arc<Notify>,
    refresh_agent: Arc<Notify>,

    closing: Arc<AtomicBool>,
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
            outer_addr_ready: Arc::new(Notify::new()),
            refresh_agent: Arc::new(Notify::new()),
            closing: Arc::new(AtomicBool::new(false)),
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
        let stun_agent = self.stun_agent;
        let stun_router = self.stun_router.clone();
        tracing::debug!(target: "stun", %stun_agent, "starting STUN client keep alive task");
        let ref_iface = self.ref_iface.clone();
        let bind_uri = ref_iface.iface().bind_uri();

        let mut state = StunKeepAliveState::new(
            self.outer_addr.clone(),
            self.endpoint_publisher.clone(),
            self.outer_addr_ready.clone(),
            self.refresh_agent.clone(),
            !bind_uri.is_temporary(),
        );

        let keep_alive_task = async move {
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
                let delay = state.apply(detect_result);
                tokio::time::sleep(delay).await;
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
        if self.closing.load(SeqCst) {
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
        if self.closing.load(SeqCst) {
            return Some(Err(DetectOuterAddrError::Rebinded {
                bind_uri: self.ref_iface.iface().bind_uri(),
            }));
        }

        self.outer_addr.try_get().map(|result| result.clone())
    }

    fn nat_detect_task(&self) -> impl futures::Future<Output = ()> + use<I> {
        let nat_type = self.nat_type.clone();
        let outer_addr = self.outer_addr.clone();
        let outer_addr_ready = self.outer_addr_ready.clone();
        let ref_iface = self.ref_iface.clone();
        let stun_router = self.stun_router.clone();
        let stun_agent = self.stun_agent;
        let bind_uri = ref_iface.iface().bind_uri();
        // Note: 原来的逻辑是 nat 探测会新建 iface，但是有的服务器只能开放指定端口，所以还是用监听的端口进行探测
        // 又因为Dynamic 总是会新建 iface 进行打洞，所以这里污染了影响不会很大
        let task = async move {
            loop {
                let notified = outer_addr_ready.notified();
                if outer_addr.try_get().as_deref().is_some_and(Result::is_ok) {
                    break;
                }
                notified.await;
            }
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
        if self.closing.load(SeqCst) {
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
        if self.closing.load(SeqCst) {
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

    fn clear_outputs(&self) {
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
    }

    fn begin_close(&self) {
        if self.closing.swap(true, SeqCst) {
            return;
        }
        self.lock_tasks().abort_all();
        self.clear_outputs();
    }

    pub fn poll_close(&self, cx: &mut Context) -> Poll<()> {
        self.begin_close();
        while ready!(self.lock_tasks().poll_join_next(cx)).is_some() {}
        self.clear_outputs();
        Poll::Ready(())
    }
}

impl Component for StunClient<WeakInterface> {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_close(cx)
    }

    fn reinit(&self, iface: &Interface) {
        debug_assert!(iface.bind_uri().is_temporary());
    }
}

async fn resolve_stun_agent(
    resolver: &(dyn Resolve + Send + Sync),
    server: &str,
    family: Family,
    excluded_agent: Option<SocketAddr>,
) -> io::Result<Option<SocketAddr>> {
    let (hostname, servname) = server.rsplit_once(':').unwrap_or((server, ""));
    let mut records = resolver.lookup(hostname, servname, Some(family)).await?;

    while let Some((_, endpoint)) = records.next().await {
        let EndpointAddr::Direct { addr } = endpoint else {
            continue;
        };
        if addr.family() == family && Some(addr) != excluded_agent {
            return Ok(Some(addr));
        }
    }

    Ok(None)
}

async fn lookup_stun_agent(
    resolver: &(dyn Resolve + Send + Sync),
    server: &str,
    family: Family,
    excluded_agent: Option<SocketAddr>,
) -> Option<SocketAddr> {
    match tokio::time::timeout(
        STUN_AGENT_DNS_LOOKUP_TIMEOUT,
        resolve_stun_agent(resolver, server, family, excluded_agent),
    )
    .await
    {
        Ok(Ok(Some(agent))) => Some(agent),
        Ok(Ok(None)) => {
            tracing::debug!(
                target: "stun",
                %server,
                ?family,
                "STUN agent lookup returned no compatible address"
            );
            None
        }
        Ok(Err(error)) => {
            tracing::debug!(
                target: "stun",
                %server,
                ?family,
                ?error,
                "failed to resolve STUN agents; retrying"
            );
            None
        }
        Err(_) => {
            tracing::debug!(
                target: "stun",
                %server,
                ?family,
                timeout_ms = STUN_AGENT_DNS_LOOKUP_TIMEOUT.as_millis(),
                "STUN agent lookup timed out; retrying"
            );
            None
        }
    }
}

async fn wait_for_stun_interface<I: RefIO>(ref_iface: &I, family: Family) {
    let mut retry_interval = STUN_DISCOVERY_RETRY_INITIAL;
    while !stun_interface_ready(ref_iface, family) {
        tracing::trace!(
            target: "stun",
            bind_uri = %ref_iface.iface().bind_uri(),
            ?family,
            "STUN discovery dormant until the interface has a local address"
        );
        tokio::time::sleep(retry_delay(&mut retry_interval, STUN_DISCOVERY_RETRY_MAX)).await;
    }
}

async fn discover_stun_agent(
    resolver: &(dyn Resolve + Send + Sync),
    server: &str,
    family: Family,
) -> SocketAddr {
    let mut retry_interval = STUN_DISCOVERY_RETRY_INITIAL;
    loop {
        if let Some(agent) = lookup_stun_agent(resolver, server, family, None).await {
            return agent;
        }
        tokio::time::sleep(retry_delay(&mut retry_interval, STUN_DISCOVERY_RETRY_MAX)).await;
    }
}

async fn replace_stun_client<I, F>(
    client: &Mutex<Option<StunClient<I>>>,
    active: &AtomicBool,
    agent: SocketAddr,
    new_stun_client: F,
) -> bool
where
    I: RefIO + 'static,
    F: Fn(SocketAddr) -> StunClient<I>,
{
    let stale_client = {
        let client = client.lock().expect("STUN client mutex poisoned");
        if !active.load(SeqCst) {
            return false;
        }
        if client
            .as_ref()
            .is_some_and(|client| client.agent_addr() == agent)
        {
            return false;
        }
        client.clone()
    };
    if let Some(stale_client) = stale_client {
        core::future::poll_fn(|cx| stale_client.poll_close(cx)).await;
    }
    let mut client = client.lock().expect("STUN client mutex poisoned");
    if !active.load(SeqCst) {
        return false;
    }
    *client = Some(new_stun_client(agent));
    true
}

#[derive(Debug)]
struct StunClientState<I: RefIO + 'static> {
    ref_iface: I,
    client: Arc<Mutex<Option<StunClient<I>>>>,
    active: Arc<AtomicBool>,
    resolver: Arc<dyn Resolve + Send + Sync>,
    server: Arc<str>,
    task: Option<AbortOnDropHandle<()>>,
}

pub const DEFAULT_STUN_SERVER: &str = "nat.genmeta.net:20004";

impl<I: RefIO + 'static> StunClientState<I> {
    pub fn new(
        ref_iface: I,
        router: StunRouter,
        resolver: Arc<dyn Resolve + Send + Sync>,
        server: Arc<str>,
        agent: Option<SocketAddr>,
        local_endpoints: Option<IfaceLocalEndpoints<I>>,
    ) -> Self {
        let family = ref_iface.iface().bind_uri().family();
        let interface_ready = stun_interface_ready(&ref_iface, family);
        let known_agent = agent.filter(|agent| agent.family() == family);
        let initial_client = known_agent.filter(|_| interface_ready).map(|agent| {
            StunClient::new(
                ref_iface.clone(),
                router.clone(),
                agent,
                local_endpoints.clone(),
            )
        });
        let client = Arc::new(Mutex::new(initial_client));
        let active = Arc::new(AtomicBool::new(true));
        let task = {
            let ref_iface = ref_iface.clone();
            let client = client.clone();
            let active = active.clone();
            let resolver = resolver.clone();
            let server = server.clone();
            AbortOnDropHandle::new(tokio::spawn(
                async move {
                    wait_for_stun_interface(&ref_iface, family).await;

                    let new_stun_client = |agent| {
                        StunClient::new(
                            ref_iface.clone(),
                            router.clone(),
                            agent,
                            local_endpoints.clone(),
                        )
                    };

                    if client.lock().expect("STUN client mutex poisoned").is_none() {
                        let agent = match known_agent {
                            Some(agent) => agent,
                            None => {
                                discover_stun_agent(resolver.as_ref(), server.as_ref(), family)
                                    .await
                            }
                        };
                        if replace_stun_client(&client, &active, agent, &new_stun_client).await {
                            tracing::debug!(target: "stun", %agent, "installed STUN client");
                        } else {
                            return;
                        }
                    }

                    loop {
                        let active_client = client
                            .lock()
                            .expect("STUN client mutex poisoned")
                            .clone()
                            .expect("STUN client must be installed before monitoring");
                        active_client.refresh_agent.notified().await;

                        let previous_agent = active_client.agent_addr();
                        let Some(agent) = lookup_stun_agent(
                            resolver.as_ref(),
                            server.as_ref(),
                            family,
                            Some(previous_agent),
                        )
                        .await
                        else {
                            continue;
                        };
                        if replace_stun_client(&client, &active, agent, &new_stun_client).await {
                            tracing::debug!(
                                target: "stun",
                                %previous_agent,
                                active_agent = %agent,
                                "replaced failed STUN client after DNS refresh"
                            );
                        }
                    }
                }
                .in_current_span(),
            ))
        };

        Self {
            ref_iface,
            client,
            active,
            resolver,
            server,
            task: Some(task),
        }
    }

    fn lock_client(&self) -> MutexGuard<'_, Option<StunClient<I>>> {
        self.client.lock().expect("STUN client mutex poisoned")
    }

    fn begin_close(&mut self) {
        self.active.store(false, SeqCst);
        if let Some(task) = self.task.as_mut() {
            task.abort();
        }

        let client = self.lock_client().clone();
        if let Some(client) = client {
            client.begin_close();
        }
    }

    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.begin_close();
        if let Some(task) = self.task.as_mut() {
            _ = ready!(task.poll_unpin(cx));
            self.task.take();
        }

        if let Some(client) = self.lock_client().as_ref() {
            ready!(client.poll_close(cx))
        }

        Poll::Ready(())
    }
}

#[derive(Debug, Clone)]
pub struct StunClientComponent<I: RefIO + 'static = WeakInterface> {
    state: Arc<Mutex<StunClientState<I>>>,
}

impl<I: RefIO + 'static> StunClientComponent<I> {
    pub fn new(
        ref_iface: I,
        router: StunRouter,
        resolver: Arc<dyn Resolve + Send + Sync>,
        server: impl Into<Arc<str>>,
        agent: Option<SocketAddr>,
        local_endpoints: Option<IfaceLocalEndpoints<I>>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(StunClientState::new(
                ref_iface,
                router,
                resolver,
                server.into(),
                agent,
                local_endpoints,
            ))),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, StunClientState<I>> {
        self.state.lock().expect("STUN client state mutex poisoned")
    }

    pub fn with_client<T>(&self, f: impl FnOnce(Option<&StunClient<I>>) -> T) -> T {
        let state = self.lock_state();
        f(state.lock_client().as_ref())
    }

    pub fn poll_close(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.lock_state().poll_close(cx)
    }
}

impl Component for StunClientComponent<WeakInterface> {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.lock_state().poll_close(cx)
    }

    fn reinit(&self, iface: &Interface) {
        let mut state = self.lock_state();
        if state.ref_iface.same_io(&iface.downgrade()) {
            return;
        }

        _ = iface.with_components(|components| {
            let Some(router_component) = components.get::<StunRouterComponent>() else {
                return;
            };
            state.begin_close();
            router_component.reinit(iface);
            let router = router_component.router();
            let local_endpoints = components.with(|local_endpoints: &LocalEndpointsComponent| {
                local_endpoints.reinit(iface);
                local_endpoints.clone()
            });

            let new_state = StunClientState::new(
                iface.downgrade(),
                router,
                state.resolver.clone(),
                state.server.clone(),
                None,
                local_endpoints,
            );
            *state = new_state;
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
        .attributes()
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

#[cfg(test)]
mod tests;
