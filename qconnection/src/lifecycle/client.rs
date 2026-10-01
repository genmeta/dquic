use std::sync::Arc;

use futures::StreamExt;
use qbase::{
    ArcReceiving, Epoch,
    cid::ArcRemoteCids,
    error::{ErrorKind, QuicError},
    param::{ClientParameters, ParameterId, Requirements},
    role::Role,
    token::ArcTokenRegistry,
};
use qprotocol::{AddressBook, Dock, QuicProtocol};
use qtransport::{
    keys::ArcKeys, packet::channel::RcvdPacket, router::QuicRouterRegistry, space::Space,
};

use super::{any, close_error};
use crate::{
    ArcParameters, ArcReliableFrames, CloseReason, ConnPhase, Connected, Error, MaturePhase, Paths,
    TlsContext,
};

/// Grow an already routed client and discover paths from the DNS result stream.
/// The client owns discovery and cancels it before shutting down its paths.
/// The caller runs [`crate::recv::tick`] alongside this future.
#[allow(clippy::too_many_arguments)]
pub async fn client_growing(
    server_name: String,
    client_params: ClientParameters,
    paths: Arc<Paths>,
    rcvd_pkt: RcvdPacket,
    tls_context: TlsContext,
    router_registry: QuicRouterRegistry<ArcReliableFrames>,
    token_registry: ArcTokenRegistry,
    established: impl FnOnce(Result<Connected, Error>),
) -> CloseReason {
    let phase = paths.phase();
    let idle = paths.idle();
    let closed = paths.closed();
    let ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!("client_growing starts with InitialPhase")
    };

    let initial = &initial_phase.initial;
    let cid_registry = qbase::cid::Registry::new(
        Role::Client,
        initial_phase.odcid,
        crate::ArcLocalCids::new(initial_phase.scid, router_registry),
        ArcRemoteCids::new(
            client_params.get::<u64>(ParameterId::ActiveConnectionIdLimit),
            initial_phase.reliable_frames.clone(),
        ),
    );
    let discovery = tokio::spawn({
        let paths = paths.clone();
        let addresses = AddressBook::global().clone();
        let resolver = qresolve::Resolver::get();
        async move {
            if let Err(error) = resolve_paths(&paths, &addresses, resolver, &server_name).await {
                paths.on_error(error);
            }
        }
    });
    tokio::spawn(crate::tls::read_tls_to_space(
        tls_context.clone(),
        initial.as_ref(),
        closed.clone(),
    ));
    tokio::spawn(crate::tls::read_space_to_tls(
        tls_context.clone(),
        initial.as_ref(),
        closed.clone(),
    ));
    tokio::spawn(crate::recv::recv_client_ih_pkt_and_deliver_frames(
        rcvd_pkt.initial,
        initial.clone(),
        paths.clone(),
        closed.clone(),
    ));

    let result = {
        let establish = async {
            let handshake_keys = tls_context.read_keys().await?;
            let handshake = Arc::new(Space::new(Epoch::Handshake, ArcKeys::from(handshake_keys)));
            paths.handshake.got_handshake_key();
            phase.enter_handshake(handshake.clone());
            initial_phase.initial.crypto.recver.retire();
            initial_phase.initial.crypto.sender.retire();

            tokio::spawn(crate::tls::read_tls_to_space(
                tls_context.clone(),
                handshake.as_ref(),
                closed.clone(),
            ));
            tokio::spawn(crate::tls::read_space_to_tls(
                tls_context.clone(),
                handshake.as_ref(),
                closed.clone(),
            ));
            tokio::spawn(crate::recv::recv_client_ih_pkt_and_deliver_frames(
                rcvd_pkt.handshake,
                handshake.clone(),
                paths.clone(),
                closed.clone(),
            ));

            let parameters = ArcParameters::new(
                Role::Client,
                Arc::new(client_params),
                Arc::new(tls_context.read_server_parameters().await?),
            );
            parameters.authenticate_cids(Requirements::require_server(
                phase.get().dcid(),
                initial_phase.odcid,
            ))?;
            let server_scid = parameters.remote(ParameterId::InitialSourceConnectionId);
            let initial_dcid = cid_registry.remote.apply_dcid();
            cid_registry
                .remote
                .apply_initial_dcid(server_scid, &initial_dcid);

            let mature_phase = MaturePhase::new(
                &initial_phase,
                handshake.clone(),
                parameters.clone(),
                server_scid,
                initial_phase.reliable_frames.clone(),
                cid_registry.clone(),
                initial_dcid,
                qtransport::keys::ArcOneRttKeys::from(tls_context.read_keys().await?),
            );
            phase.enter_mature(mature_phase.clone());
            cid_registry
                .local
                .set_limit(parameters.remote::<u64>(ParameterId::ActiveConnectionIdLimit))?;
            idle.negotiate_max_idle_timeout(parameters.remote(ParameterId::MaxIdleTimeout));

            let handshake_done = ArcReceiving::default();
            tokio::spawn(crate::recv::receive_client_data(
                rcvd_pkt.one_rtt,
                mature_phase.clone(),
                paths.clone(),
                parameters,
                cid_registry.clone(),
                token_registry,
                closed.clone(),
                {
                    let handshake_done = handshake_done.clone();
                    move || handshake_done.set(true)
                },
            ));

            tokio::spawn(crate::tls::read_tls_to_space(
                tls_context.clone(),
                mature_phase.spaces.data.as_ref(),
                closed.clone(),
            ));
            tokio::spawn(crate::tls::read_space_to_tls(
                tls_context.clone(),
                mature_phase.spaces.data.as_ref(),
                closed.clone(),
            ));

            let summary = tls_context.finished().await?;
            handshake.crypto.recver.retire();
            let remote = summary.remote.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;

            Ok::<_, Error>((
                (
                    summary.local,
                    remote,
                    qtransport::ArcConnection::new(
                        summary.alpn.unwrap_or_default(),
                        mature_phase.spaces.data.streams.clone(),
                        closed.clone(),
                    )
                    .with_path_observer({
                        let paths = Arc::downgrade(&paths);
                        move || {
                            paths.upgrade().map_or_else(Vec::new, |paths| {
                                paths
                                    .snapshot()
                                    .into_iter()
                                    .filter(|path| path.is_validated())
                                    .map(|path| path.pathway)
                                    .collect()
                            })
                        }
                    }),
                ),
                handshake_done,
                mature_phase,
            ))
        };
        any(establish, closed.clone())
            .await
            .and_then(|result| result.map_err(CloseReason::from))
    };

    let (connected, handshake_done, mature_phase) = match result {
        Ok(established_connection) => established_connection,
        Err(reason) => {
            established(Err(close_error(&reason)));
            return shutdown(&paths, &tls_context, &cid_registry.local, reason, discovery).await;
        }
    };
    established(Ok(connected));

    let mut close = closed.clone();
    let reason = tokio::select! {
        Ok(Some(reason)) = &mut close => reason,
        Ok(Some(true)) = handshake_done => {
            mature_phase
                .spaces
                .data
                .keys
                .get()
                .expect("live Data keys")
                .allow_update();
            paths.handshake_confirmed();
            // A separate stop channel leaves the connection's close reason to this coroutine.
            // Dropping this coroutine also stops observation by dropping the sender.
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let observer = mature_phase.puncher.observe_endpoints(
                AddressBook::global().subscribe_punch(crate::Scopes::ALL),
                stopped,
                |_| {},
            );
            let reason = closed.clone().await.expect("growing owns close").expect("first close reason");
            drop(stop);
            let _ = observer.await;
            reason
        }
    };
    shutdown(&paths, &tls_context, &cid_registry.local, reason, discovery).await
}

async fn shutdown(
    paths: &Paths,
    tls: &TlsContext,
    local_cids: &crate::ArcLocalCids,
    reason: CloseReason,
    discovery: tokio::task::JoinHandle<()>,
) -> CloseReason {
    // Stop discovery before path cleanup so late DNS results cannot create senders.
    discovery.abort();
    let _ = discovery.await;
    tls.on_error(close_error(&reason));
    paths.finish(&reason).await;
    local_cids.clear();
    reason
}

async fn resolve_paths(
    paths: &Arc<Paths>,
    addresses: &AddressBook,
    resolver: Arc<dyn qresolve::Resolve>,
    server_name: &str,
) -> Result<(), Error> {
    let mut records = resolver
        .lookup(server_name, "", None)
        .await
        .map_err(|error| {
            QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                format!("DNS lookup for {server_name} failed: {error}"),
            )
        })?;
    while let Some((source, peer)) = records.next().await {
        for pathway in addresses.pathways_to(peer, &source) {
            let Some(socket) = QuicProtocol::global().find_socket(pathway.local()) else {
                continue;
            };
            let Ok(bound) = socket.local_addr() else {
                continue;
            };
            if !Dock::global()
                .find_socket(bound)
                .is_some_and(|registered| Arc::ptr_eq(&registered, &socket))
            {
                continue;
            }
            paths.add_path(pathway)?;
        }
    }
    if paths.snapshot().is_empty() {
        return Err(QuicError::with_default_fty(
            ErrorKind::NoViablePath,
            format!("DNS lookup for {server_name} ended without a usable path"),
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod discovery_tests;
