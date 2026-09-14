use futures::FutureExt;
use qbase::error::Error;
use tokio::sync::watch;

/// The first close cause and cleanup completion are separate facts. Application
/// waiters are notified immediately; closed() waits for runtime cleanup as well.
pub(crate) struct CloseState {
    reason: watch::Sender<Option<Error>>,
    complete: watch::Sender<bool>,
}

impl CloseState {
    pub(crate) fn new() -> Self {
        Self {
            reason: watch::channel(None).0,
            complete: watch::channel(false).0,
        }
    }

    pub(crate) fn request(&self, error: Error) -> bool {
        self.reason.send_if_modified(|reason| {
            if reason.is_some() {
                return false;
            }
            *reason = Some(error);
            true
        })
    }

    pub(crate) fn reason(&self) -> Option<Error> {
        self.reason.borrow().clone()
    }

    pub(crate) fn ensure_open(&self) -> Result<(), Error> {
        self.reason().map_or(Ok(()), Err)
    }

    pub(crate) async fn closing(&self) -> Error {
        let mut reason = self.reason.subscribe();
        loop {
            if let Some(reason) = reason.borrow_and_update().clone() {
                return reason;
            }
            reason.changed().await.expect("CloseState owns the sender");
        }
    }

    pub(crate) fn finish(&self) {
        assert!(self.reason().is_some(), "cleanup must have a close cause");
        self.complete.send_replace(true);
    }

    pub(crate) async fn closed(&self) -> Error {
        let mut complete = self.complete.subscribe();
        while !*complete.borrow_and_update() {
            complete
                .changed()
                .await
                .expect("CloseState owns the sender");
        }
        self.reason().expect("cleanup has a close cause")
    }
}

use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use bytes::Bytes;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    role::Role,
};
use qcongestion::Transport as _;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    Connected, Endpoint, LocalAuthority, RemoteAuthority,
    connection::{Connection, promote},
    control::Phase,
    handshake::{
        connect::connect_initial,
        incoming::{Incoming, accept_initial},
    },
    network::Network,
    router::RouteLease,
    transport::Transport,
};

fn remote_authority(remote: qtls::RemoteAuthority) -> RemoteAuthority {
    RemoteAuthority::new(
        &rustls::crypto::ring::default_provider(),
        remote.name(),
        remote.certificates().to_vec(),
        None,
    )
}

pub(crate) async fn run_client(
    network: Arc<Network>,
    endpoint: Option<Endpoint>,
    name: String,
    cancel: CancellationToken,
    reply: oneshot::Sender<Result<Connected, Error>>,
) {
    let prepared = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(crate::internal("connect cancelled")),
        _ = network.stop.cancelled() => Err(crate::internal("network stopped")),
        prepared = connect_initial(&network, endpoint.as_ref(), &name) => prepared,
    };
    let (mut connecting, parameters, route, receiver, mut crypto) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = reply.send(Err(error));
            return;
        }
    };
    let transport = connecting.transport.clone();
    let _stop_on_exit = transport.stop.clone().drop_guard();
    let mut reply = Some(reply);
    let mut connection = Weak::new();
    let outcome = async {
        connecting
            .negotiate_parameters(parameters, &name, &mut crypto)
            .await?;
        let (summary, tls) = connecting.complete_handshake(&mut crypto).await?;
        let remote = summary
            .remote
            .ok_or_else(|| crate::internal("TLS did not authenticate the server"))?;
        let conn = promote(transport.clone(), summary.alpn)?;
        connection = conn.downgrade();
        let local = endpoint
            .as_ref()
            .map(|endpoint| LocalAuthority::from(endpoint.identity.clone()));
        reply
            .take()
            .unwrap()
            .send(Ok((local, remote_authority(remote), conn)))
            .map_err(|_| crate::internal("connect result was abandoned"))?;
        Err::<(), Error>(run_active(tls, transport.clone(), &mut crypto).await)
    };
    let error = tokio::select! {
        biased;
        _ = cancel.cancelled() => crate::internal("connect cancelled"),
        _ = network.stop.cancelled() => crate::internal("network stopped"),
        result = std::panic::AssertUnwindSafe(outcome).catch_unwind() => match result {
            Ok(result) => result.err().unwrap_or_else(|| crate::internal("connection task ended")),
            Err(_) => crate::internal("connection task panicked"),
        },
    };
    if let Some(reply) = reply {
        let _ = reply.send(Err(error.clone()));
    }
    shutdown(
        transport,
        receiver,
        connection,
        route,
        error,
        network.stop.is_cancelled(),
    )
    .await;
}

pub(crate) async fn run_server(
    network: Arc<Network>,
    incoming: Incoming,
    matured: mpsc::Sender<tokio::task::Id>,
) {
    let Incoming {
        mut route,
        packets,
        received_at,
    } = incoming;
    let original_dcid = route.initial_cid();
    let keys = match network
        .initial
        .initial_keys(qtls::QuicVersion::V1, &original_dcid)
    {
        Ok(keys) => keys,
        Err(_) => return,
    };
    let local_cid = loop {
        let cid = ConnectionId::random_gen(8);
        if route.insert(cid) {
            break cid;
        }
    };
    let (transport, topology, commands, mut crypto) = Transport::new(
        Role::Server,
        keys,
        original_dcid,
        local_cid,
        network.protocol.clone(),
        network.listener.idle_timeout(),
        received_at,
    );
    let _stop_on_exit = transport.stop.clone().drop_guard();
    let receiver = tokio::spawn(topology.run(transport.clone(), packets, commands));
    let mut connection = Weak::new();
    let outcome = async {
        let (mut connecting, parameters, registration, delivery) =
            accept_initial(&network, transport.clone(), &mut crypto).await?;
        let handshake = async {
            connecting
                .negotiate_parameters(parameters, registration.endpoint.name(), &mut crypto)
                .await?;
            connecting.complete_handshake(&mut crypto).await
        };
        let (summary, tls) = tokio::select! {
            biased;
            _ = registration.stop.cancelled() => return Err(crate::internal("endpoint stopped listening")),
            result = handshake => result?,
        };
        if summary
            .local
            .as_ref()
            .is_none_or(|local| local.name() != registration.endpoint.name())
        {
            return Err(crate::internal("TLS selected a different local authority"));
        }
        let conn = promote(transport.clone(), summary.alpn)?;
        connection = conn.downgrade();
        {
            let live = registration.live.lock().unwrap();
            if !*live {
                return Err(crate::internal("endpoint stopped listening"));
            }
            transport.close.ensure_open()?;
            let local = LocalAuthority::from(registration.endpoint.identity.clone());
            delivery.send((
                registration.clone(),
                (summary.remote.map(remote_authority), local, conn),
            ));
        }
        let _ = matured.send(tokio::task::id()).await;
        // Registration cancellation no longer governs an already delivered connection.
        Err::<(), Error>(run_active(tls, transport.clone(), &mut crypto).await)
    };
    let error = tokio::select! {
        _ = network.stop.cancelled() => crate::internal("network stopped"),
        result = std::panic::AssertUnwindSafe(outcome).catch_unwind() => match result {
            Ok(result) => result.err().unwrap_or_else(|| crate::internal("connection task ended")),
            Err(_) => crate::internal("connection task panicked"),
        },
    };
    shutdown(
        transport,
        receiver,
        connection,
        route,
        error,
        network.stop.is_cancelled(),
    )
    .await;
}

async fn run_active(
    mut tls: qtls::EstablishedTls,
    transport: Arc<Transport>,
    crypto: &mut mpsc::Receiver<(qtls::CryptoLevel, Bytes)>,
) -> Error {
    loop {
        tokio::select! {
            biased;
            error = transport.close.closing() => return error,
            received = crypto.recv() => {
                let Some((level, bytes)) = received else { return crate::internal("CRYPTO receive task stopped") };
                if level != qtls::CryptoLevel::OneRtt { return crate::internal("unexpected post-handshake CRYPTO level") }
                if let Err(error) = tls.receive_post_handshake(&bytes) {
                    return QuicError::with_default_fty(ErrorKind::Crypto(40), error.to_string()).into()
                }
            }
        }
    }
}

async fn shutdown(
    transport: Arc<Transport>,
    receiver: JoinHandle<()>,
    connection: Weak<Connection>,
    route: RouteLease,
    error: Error,
    immediate: bool,
) {
    transport.close.request(error);
    let error = transport.close.reason().unwrap();
    if let Some(data) = transport.data.get() {
        data.on_error(&error);
    }
    if let Some(connection) = connection.upgrade() {
        connection.release(&error);
    }
    if *transport.control.phase.borrow() != Phase::Draining {
        transport.control.phase.send_replace(Phase::Closing);
    }
    transport
        .wakers
        .wake_all_by(qbase::net::tx::Signals::TRANSPORT);
    let paths = transport.paths.snapshot();
    if !immediate {
        let grace = paths
            .iter()
            .map(|path| path.cc.get_pto(Epoch::Data).saturating_mul(3))
            .max()
            .unwrap_or(Duration::ZERO);
        tokio::time::sleep(grace).await;
    }
    transport.stop.cancel();
    let _ = receiver.await;
    for path in paths {
        let task = path.task.lock().unwrap().take();
        if let Some(task) = task {
            let _ = task.await;
        }
        transport.wakers.remove(&path.pathway);
    }
    for epoch in [Epoch::Initial, Epoch::Handshake, Epoch::Data] {
        transport.spaces.retire(epoch);
    }
    drop(route);
    transport.control.phase.send_replace(Phase::Closed);
    transport.close.finish();
}
