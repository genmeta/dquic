// common is submod for both echo and auth tests
#![allow(unused)]

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc, LazyLock, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use dquic::{
    prelude::{handy::*, *},
    qbase::{self, net::route::Route, param::ClientParameters},
    qinterface::{
        bind_uri::BindUri,
        component::route::QuicRouter,
        io::{IO, ProductIO, handy::DEFAULT_IO_FACTORY},
    },
};
use futures::task::AtomicWaker;
use qevent::telemetry::QLog;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::time;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

pub fn qlogger() -> Arc<dyn QLog + Send + Sync> {
    static QLOGGER: OnceLock<Arc<dyn QLog + Send + Sync>> = OnceLock::new();
    QLOGGER.get_or_init(|| Arc::new(NoopLogger)).clone()
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Default)]
struct NetworkGateState {
    disabled: AtomicBool,
    sent_packets: AtomicUsize,
    recv_waker: AtomicWaker,
}

/// Test-only I/O factory that can turn a live interface into a silent network black hole.
#[derive(Default)]
pub struct NetworkGateFactory {
    states: Mutex<HashMap<BindUri, Arc<NetworkGateState>>>,
}

impl NetworkGateFactory {
    fn state(&self, bind_uri: &BindUri) -> Option<Arc<NetworkGateState>> {
        self.states.lock().unwrap().get(bind_uri).cloned()
    }

    pub fn disable(&self, bind_uri: &BindUri) -> bool {
        let Some(state) = self.state(bind_uri) else {
            return false;
        };
        state.disabled.store(true, Ordering::Release);
        state.recv_waker.wake();
        true
    }

    pub fn enable(&self, bind_uri: &BindUri) -> bool {
        let Some(state) = self.state(bind_uri) else {
            return false;
        };
        state.disabled.store(false, Ordering::Release);
        state.recv_waker.wake();
        true
    }

    pub fn disable_all(&self) {
        for state in self.states.lock().unwrap().values() {
            state.disabled.store(true, Ordering::Release);
            state.recv_waker.wake();
        }
    }

    pub fn sent_packets(&self, bind_uri: &BindUri) -> usize {
        self.state(bind_uri)
            .map(|state| state.sent_packets.load(Ordering::Acquire))
            .unwrap_or_default()
    }
}

impl ProductIO for NetworkGateFactory {
    fn bind(&self, bind_uri: BindUri) -> Box<dyn IO> {
        let state = Arc::new(NetworkGateState::default());
        self.states
            .lock()
            .unwrap()
            .insert(bind_uri.clone(), state.clone());
        Box::new(NetworkGateIo {
            inner: DEFAULT_IO_FACTORY.bind(bind_uri),
            state,
        })
    }
}

struct NetworkGateIo {
    inner: Box<dyn IO>,
    state: Arc<NetworkGateState>,
}

impl IO for NetworkGateIo {
    fn bind_uri(&self) -> BindUri {
        self.inner.bind_uri()
    }

    fn bound_addr(&self) -> io::Result<SocketAddr> {
        self.inner.bound_addr()
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        self.inner.max_segment_size()
    }

    fn max_segments(&self) -> io::Result<usize> {
        self.inner.max_segments()
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        route: Route,
    ) -> Poll<io::Result<usize>> {
        if self.state.disabled.load(Ordering::Acquire) {
            self.state
                .sent_packets
                .fetch_add(pkts.len(), Ordering::AcqRel);
            return Poll::Ready(Ok(pkts.len()));
        }
        match self.inner.poll_send(cx, pkts, route) {
            Poll::Ready(Ok(sent)) => {
                self.state.sent_packets.fetch_add(sent, Ordering::AcqRel);
                Poll::Ready(Ok(sent))
            }
            result => result,
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        route: &mut [Route],
    ) -> Poll<io::Result<usize>> {
        // Register before checking the flag so disable() cannot race a pending inner receive.
        self.state.recv_waker.register(cx.waker());
        if self.state.disabled.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        self.inner.poll_recv(cx, pkts, route)
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.inner.poll_close(cx)
    }
}

pub fn run<F: Future>(future: F) -> F::Output {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });

    static TRACING: LazyLock<WorkerGuard> = LazyLock::new(|| {
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

        tracing_subscriber::registry()
            // .with(console_subscriber::spawn())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(LevelFilter::DEBUG),
            )
            .with(tracing_subscriber::filter::filter_fn(|metadata| {
                !metadata.target().contains("netlink_packet_route")
            }))
            .init();
        guard
    });

    RT.block_on(async move {
        LazyLock::force(&TRACING);
        match time::timeout(Duration::from_secs(60), future).await {
            Ok(output) => output,
            Err(_timedout) => panic!("test timed out"),
        }
    })
}

pub fn launch_test_client(
    quic_router: Arc<QuicRouter>,
    parameters: ClientParameters,
) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let client = QuicClient::builder()
        .with_router(quic_router)
        .with_root_certificates(roots)
        .with_parameters(parameters)
        .without_cert()
        .with_qlog(qlogger())
        .enable_sslkeylog()
        .build();

    Arc::new(client)
}

pub fn get_server_addr(listeners: &QuicListeners) -> SocketAddr {
    let localhost = listeners
        .get_server("localhost")
        .expect("Server localhost must be registered");
    let localhost_bind_interface = localhost
        .bind_interfaces()
        .into_iter()
        .next()
        .map(|(_bind_uri, interface)| interface)
        .expect("Server should bind at least one address");
    localhost_bind_interface
        .borrow()
        .bound_addr()
        .expect("failed to get real addr")
}

pub const CA_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/ca.cert");
pub const SERVER_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.cert");
pub const SERVER_KEY: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.key");
pub const CLIENT_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/client.cert");
pub const CLIENT_KEY: &[u8] = include_bytes!("../../../tests/keychain/localhost/client.key");
pub const TEST_DATA: &[u8] = include_bytes!("mod.rs");
