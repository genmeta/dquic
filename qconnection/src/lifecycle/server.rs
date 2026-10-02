use std::sync::Arc;

use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    handshake::ArcHandshake,
    param::{ParameterId, Requirements},
    role::Role,
    sid::handy::ConsistentConcurrency,
    token::ArcTokenRegistry,
};
use qtransport::{
    keys::{ArcKeys, ArcOneRttKeys},
    packet::channel::RcvdPacket,
    space::{DataSpace, Space, Spaces},
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};
use tokio::io::AsyncWriteExt;

use super::{any, close_error, finish, interceptor::read_crypto_stream_to_interceptor};
use crate::{
    ArcParameters, CloseReason, DataStreams, Error, FlowController, Interceptor, MaturePhase,
    Paths, ServerRegistry, TlsContext,
    recv::{receive_1rtt_pkt_and_deliver_frames, recv_ih_pkt_and_deliver_frames},
    tls::{read_space_to_tls, read_tls_to_space},
};

/// Select a listening server from an already routed Initial, then grow the connection.
/// The caller runs [`crate::recv::tick`] alongside this future.
#[allow(clippy::too_many_arguments)]
pub async fn server_growing(
    rcvd_pkt: RcvdPacket,
    paths: Arc<Paths>,
    token: ArcTokenRegistry,
) -> CloseReason {
    let phase = paths.phase();
    let crate::ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!("server_growing starts with InitialPhase")
    };
    let idle = paths.idle();
    let closed = paths.close_reason();
    let initial = initial_phase.initial_space.clone();
    let reliable_frames = initial_phase.reliable_frames.clone();
    let terminator = initial_phase.terminator.clone();
    let cid_registry = initial_phase.cid_registry.clone();
    let trackers = initial_phase.trackers.clone();
    let scid = initial_phase.scid;
    let origin_dcid = initial_phase.odcid;
    drop(initial_phase);

    tokio::spawn(recv_ih_pkt_and_deliver_frames(
        (rcvd_pkt.initial, None),
        initial.clone(),
        paths.clone(),
        closed.clone(),
    ));

    let interceptor = Interceptor::new();
    tokio::spawn(read_crypto_stream_to_interceptor(
        interceptor.clone(),
        initial.crypto.clone(),
        closed.clone(),
    ));

    let hello = any(interceptor.read(), closed.clone())
        .await
        .and_then(|result| result.map_err(CloseReason::from));
    let hello = match hello {
        Ok(hello) => hello,
        Err(reason) => {
            return shutdown_initial(&paths, &cid_registry.local, reason).await;
        }
    };
    let Some(server_name) = hello.server_name() else {
        return shutdown_initial(
            &paths,
            &cid_registry.local,
            CloseReason::Internal(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "ClientHello has no server name",
            )),
        )
        .await;
    };
    let Some(server) = ServerRegistry::global().get(server_name) else {
        return shutdown_initial(
            &paths,
            &cid_registry.local,
            CloseReason::Internal(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "server name is not listening",
            )),
        )
        .await;
    };
    idle.negotiate_max_idle_timeout(
        server
            .server_parameters
            .get::<std::time::Duration>(ParameterId::MaxIdleTimeout),
    );
    let (tls_ctx, client_parameters, server_parameters) =
        match server.spawn_connection_with(qtls::QuicVersion::V1, hello, scid, origin_dcid) {
            Ok(ready) => ready,
            Err(error) => {
                (server.accept_cb)(Err(error.clone()));
                return shutdown_initial(&paths, &cid_registry.local, error.into()).await;
            }
        };
    let scopes = server.scopes;
    cid_registry
        .remote
        .set_limit(server_parameters.get::<u64>(ParameterId::ActiveConnectionIdLimit));
    let result = {
        let establish = async {
            let parameters = ArcParameters::new(Role::Server, client_parameters, server_parameters);
            parameters.authenticate_cids(Requirements::require_client(phase.get().dcid()))?;

            let handshake_keys = tls_ctx.read_keys().await?;
            let handshake = Arc::new(Space::new(Epoch::Handshake, ArcKeys::from(handshake_keys)));
            paths.handshake.got_handshake_key();
            initial.crypto.recver.retire();

            tokio::spawn(read_space_to_tls(
                tls_ctx.clone(),
                handshake.as_ref(),
                closed.clone(),
            ));
            tokio::spawn(recv_ih_pkt_and_deliver_frames(
                (rcvd_pkt.handshake, Some(scopes)),
                handshake.clone(),
                paths.clone(),
                closed.clone(),
            ));

            let client_scid = parameters.remote(ParameterId::InitialSourceConnectionId);
            cid_registry.remote.set_initial_dcid(client_scid);
            let keys = ArcOneRttKeys::from(tls_ctx.read_keys().await?);
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
                ProbeEncoder::new(data.clone(), client_scid),
            );
            cid_registry
                .local
                .set_limit(parameters.remote::<u64>(ParameterId::ActiveConnectionIdLimit))?;
            idle.negotiate_max_idle_timeout(parameters.remote(ParameterId::MaxIdleTimeout));

            for space in [initial.as_ref(), handshake.as_ref()] {
                let flight = tls_ctx.read_msg_at(space.epoch).await?;
                space
                    .crypto
                    .writer()
                    .write_all(&flight)
                    .await
                    .map_err(|error| {
                        QuicError::with_default_fty(ErrorKind::Internal, error.to_string())
                    })?;
                while let Some(bytes) = tls_ctx.try_read_msg_at(space.epoch)? {
                    space
                        .crypto
                        .writer()
                        .write_all(&bytes)
                        .await
                        .map_err(|error| {
                            QuicError::with_default_fty(ErrorKind::Internal, error.to_string())
                        })?;
                }
            }

            for space in [initial.as_ref(), handshake.as_ref()] {
                tokio::spawn(read_tls_to_space(tls_ctx.clone(), space, closed.clone()));
            }
            tokio::spawn(read_tls_to_space(
                tls_ctx.clone(),
                data.as_ref(),
                closed.clone(),
            ));
            tokio::spawn(read_space_to_tls(
                tls_ctx.clone(),
                data.as_ref(),
                closed.clone(),
            ));

            let handshake_done = ArcHandshake::new_server(reliable_frames.clone());
            tokio::spawn(receive_1rtt_pkt_and_deliver_frames(
                (rcvd_pkt.one_rtt, Some(scopes)),
                data.clone(),
                flow_ctrl.clone(),
                puncher.clone(),
                paths.clone(),
                parameters.clone(),
                cid_registry.clone(),
                token,
                handshake_done.clone(),
            ));

            phase.enter_mature(Arc::new(MaturePhase {
                spaces: Spaces {
                    initial: initial.clone(),
                    handshake: handshake.clone(),
                    data: data.clone(),
                },
                scid,
                dcid: client_scid,
                parameters,
                flow_ctrl,
                cid_registry: cid_registry.clone(),
                puncher: puncher.clone(),
                trackers: trackers.clone(),
                terminator: terminator.clone(),
            }));

            let summary = tls_ctx.finished().await?;
            data.keys.get().expect("live Data keys").allow_update();
            let local = summary.local.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;
            handshake_done.done();
            paths.handshake_confirmed();

            Ok::<_, Error>((
                (
                    summary.remote,
                    local,
                    qtransport::ArcConnection::new(
                        summary.alpn.unwrap_or_default(),
                        data.streams.clone(),
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
                puncher,
            ))
        };
        any(establish, closed.clone())
            .await
            .and_then(|result| result.map_err(CloseReason::from))
    };

    let (connection, puncher) = match result {
        Ok(connection) => connection,
        Err(reason) => {
            (server.accept_cb)(Err(close_error(&reason)));
            return shutdown(&paths, &tls_ctx, &cid_registry.local, reason).await;
        }
    };

    // The observer must not consume the connection's close reason.
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let observer = puncher.observe_endpoints(
        qprotocol::AddressBook::global().subscribe_punch(scopes),
        stopped,
        |_| {},
    );
    (server.accept_cb)(Ok(connection));
    let reason = closed
        .await
        .expect("growing owns close")
        .expect("first close reason");
    drop(stop);
    let _ = observer.await;
    shutdown(&paths, &tls_ctx, &cid_registry.local, reason).await
}

async fn shutdown(
    paths: &Paths,
    tls: &TlsContext,
    local_cids: &crate::ArcLocalCids,
    reason: CloseReason,
) -> CloseReason {
    tls.on_error(close_error(&reason));
    finish(paths, &reason).await;
    local_cids.clear();
    reason
}

async fn shutdown_initial(
    paths: &Paths,
    local_cids: &crate::ArcLocalCids,
    reason: CloseReason,
) -> CloseReason {
    finish(paths, &reason).await;
    local_cids.clear();
    reason
}
