use std::sync::Arc;

use futures::StreamExt;
use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    handshake::ArcHandshake,
    param::{ClientParameters, ParameterId, Requirements},
    role::Role,
    sid::handy::ConsistentConcurrency,
    token::ArcTokenRegistry,
};
use qprotocol::{AddressBook, Dock, QuicProtocol};
use qtransport::{
    keys::{ArcKeys, ArcOneRttKeys},
    packet::channel::RcvdPacket,
    space::{DataSpace, Space, Spaces},
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};

use super::{any, close_error, finish};
use crate::{
    ArcParameters, CloseReason, ConnPhase, Connected, DataStreams, Error, FlowController,
    MaturePhase, Paths, TlsContext,
    recv::{receive_1rtt_pkt_and_deliver_frames, recv_ih_pkt_and_deliver_frames},
    tls::{read_space_to_tls, read_tls_to_space},
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
    token_registry: ArcTokenRegistry,
    established: impl FnOnce(Result<Connected, Error>),
) -> CloseReason {
    let idle = paths.idle();
    let phase = paths.phase();
    let close_reason = paths.close_reason();
    let ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!("client_growing starts with InitialPhase")
    };

    let initial = initial_phase.initial_space.clone();
    let reliable_frames = initial_phase.reliable_frames.clone();
    let terminator = initial_phase.terminator.clone();
    let cid_registry = initial_phase.cid_registry.clone();
    let trackers = initial_phase.trackers.clone();
    let scid = initial_phase.scid;
    let odcid = initial_phase.odcid;
    drop(initial_phase);

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
    tokio::spawn(read_tls_to_space(
        tls_context.clone(),
        initial.as_ref(),
        close_reason.clone(),
    ));
    tokio::spawn(read_space_to_tls(
        tls_context.clone(),
        initial.as_ref(),
        close_reason.clone(),
    ));
    tokio::spawn(recv_ih_pkt_and_deliver_frames(
        (rcvd_pkt.initial, None),
        initial.clone(),
        paths.clone(),
        close_reason.clone(),
    ));

    let result = {
        let establish = async {
            let handshake_keys = tls_context.read_keys().await?;
            let handshake = Arc::new(Space::new(Epoch::Handshake, ArcKeys::from(handshake_keys)));
            paths.handshake.got_handshake_key();
            phase.enter_handshake(handshake.clone());
            initial.crypto.recver.retire();
            initial.crypto.sender.retire();

            tokio::spawn(read_tls_to_space(
                tls_context.clone(),
                handshake.as_ref(),
                close_reason.clone(),
            ));
            tokio::spawn(read_space_to_tls(
                tls_context.clone(),
                handshake.as_ref(),
                close_reason.clone(),
            ));
            tokio::spawn(recv_ih_pkt_and_deliver_frames(
                (rcvd_pkt.handshake, None),
                handshake.clone(),
                paths.clone(),
                close_reason.clone(),
            ));

            let parameters = ArcParameters::new(
                Role::Client,
                Arc::new(client_params),
                Arc::new(tls_context.read_server_parameters().await?),
            );
            parameters
                .authenticate_cids(Requirements::require_server(phase.get().dcid(), odcid))?;
            let server_scid = parameters.remote(ParameterId::InitialSourceConnectionId);
            cid_registry.remote.set_initial_dcid(server_scid);
            let keys = ArcOneRttKeys::from(tls_context.read_keys().await?);
            let concurrency = Box::new(ConsistentConcurrency::new(
                parameters.local(ParameterId::InitialMaxStreamsBidi),
                parameters.local(ParameterId::InitialMaxStreamsUni),
            ));
            let streams = DataStreams::new(
                parameters.clone(),
                concurrency,
                reliable_frames.clone(),
                None,
            );
            let flow_ctrl = FlowController::new(
                parameters.remote(ParameterId::InitialMaxData),
                parameters.local(ParameterId::InitialMaxData),
                reliable_frames.clone(),
            );
            let data = Arc::new(DataSpace::new(keys, streams, reliable_frames.clone()));
            let puncher = ArcPuncher::new(
                reliable_frames.clone(),
                ProbeEncoder::new(data.clone(), server_scid),
            );
            phase.enter_mature(Arc::new(MaturePhase {
                spaces: Spaces {
                    initial: initial.clone(),
                    handshake: handshake.clone(),
                    data: data.clone(),
                },
                scid,
                dcid: server_scid,
                parameters: parameters.clone(),
                flow_ctrl: flow_ctrl.clone(),
                cid_registry: cid_registry.clone(),
                puncher: puncher.clone(),
                trackers: trackers.clone(),
                terminator: terminator.clone(),
            }));
            cid_registry
                .local
                .set_limit(parameters.remote::<u64>(ParameterId::ActiveConnectionIdLimit))?;
            idle.negotiate_max_idle_timeout(parameters.remote(ParameterId::MaxIdleTimeout));

            let handshake_done = ArcHandshake::new_client();
            tokio::spawn(receive_1rtt_pkt_and_deliver_frames(
                (rcvd_pkt.one_rtt, None),
                data.clone(),
                flow_ctrl,
                puncher.clone(),
                paths.clone(),
                parameters,
                cid_registry.clone(),
                token_registry,
                handshake_done.clone(),
            ));

            tokio::spawn(read_tls_to_space(
                tls_context.clone(),
                data.as_ref(),
                close_reason.clone(),
            ));
            tokio::spawn(read_space_to_tls(
                tls_context.clone(),
                data.as_ref(),
                close_reason.clone(),
            ));

            let summary = tls_context.finished().await?;
            handshake.crypto.recver.retire();
            let remote_authority = summary.remote.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;

            Ok::<_, Error>((
                (
                    summary.local,
                    remote_authority,
                    qtransport::ArcConnection::new(
                        summary.alpn.unwrap_or_default(),
                        data.streams.clone(),
                        close_reason.clone(),
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
                data,
                puncher,
            ))
        };
        any(establish, close_reason.clone())
            .await
            .and_then(|result| result.map_err(CloseReason::from))
    };

    let (connected, handshake_done, data, puncher) = match result {
        Ok(established_connection) => established_connection,
        Err(reason) => {
            established(Err(close_error(&reason)));
            return shutdown(&paths, &tls_context, &cid_registry.local, reason, discovery).await;
        }
    };
    established(Ok(connected));

    let mut close = close_reason.clone();
    let reason = tokio::select! {
        Ok(Some(reason)) = &mut close => reason,
        () = handshake_done => {
            data.keys
                .get()
                .expect("live Data keys")
                .allow_update();
            paths.handshake_confirmed();
            // A separate stop channel leaves the connection's close reason to this coroutine.
            // Dropping this coroutine also stops observation by dropping the sender.
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let observer = puncher.observe_endpoints(
                AddressBook::global().subscribe_punch(crate::Scopes::ALL),
                stopped,
                |_| {},
            );
            let reason = close_reason.clone().await.expect("growing owns close").expect("first close reason");
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
    finish(paths, &reason).await;
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
