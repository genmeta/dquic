use std::sync::Arc;

use futures::future::poll_fn;
use qbase::{
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
    space::{DataSpace, HandshakeSpace, InitialSpace},
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};
use tokio::io::AsyncWriteExt;

use super::{any, finish, interceptor::read_crypto_stream_to_interceptor};
use crate::{
    ArcParameters, DataStreams, Error, FlowController, Interceptor, MaturePhase, Paths,
    ServerRegistry,
    recv::{receive_1rtt_pkt_and_deliver_frames, recv_ih_pkt_and_deliver_frames},
    tls::{read_space_to_tls, read_tls_to_space},
};

/// Select a listening server from an already routed Initial, then grow the connection.
/// The caller runs [`crate::recv::tick`] alongside this future.
#[allow(clippy::too_many_arguments)]
pub async fn server_growing(
    initial_space: Arc<InitialSpace>,
    rcvd_pkt: RcvdPacket,
    paths: Arc<Paths>,
    token: ArcTokenRegistry,
) -> Error {
    let phase = paths.phase();
    let progress = &paths.progress;
    let crate::ConnPhase::Initial(_) = phase.get() else {
        unreachable!("server_growing starts with InitialPhase")
    };
    let terminator = paths.terminator.clone();
    let reliable_frames = paths.reliable_frames.clone();
    let cid_registry = &paths.cid_registry;
    let scid = initial_space.initial_scid;
    let origin_dcid = cid_registry.local.origin_dcid();
    let handshake_dcid = cid_registry.remote.apply_dcid();

    tokio::spawn(recv_ih_pkt_and_deliver_frames(
        (rcvd_pkt.initial, None),
        initial_space.clone(),
        paths.clone(),
    ));

    let interceptor = Interceptor::new();
    tokio::spawn(read_crypto_stream_to_interceptor(
        interceptor.clone(),
        initial_space.crypto.clone(),
        paths.clone(),
    ));

    let hello = any(interceptor.read(), terminator.clone())
        .await
        .and_then(std::convert::identity);
    let hello = match hello {
        Ok(hello) => hello,
        Err(reason) => {
            return shutdown(&paths, reason).await;
        }
    };
    let Some(server) = ServerRegistry::global().get(hello.server_name()) else {
        return shutdown(
            &paths,
            Error::from(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "no matching server is listening",
            )),
        )
        .await;
    };
    paths.update_max_idle_timeout(
        server
            .server_parameters
            .get::<std::time::Duration>(ParameterId::MaxIdleTimeout),
    );
    let (tls_ctx, client_parameters, server_parameters) =
        match server.spawn_connection_with(qtls::QuicVersion::V1, hello, scid, origin_dcid) {
            Ok(ready) => ready,
            Err(error) => {
                tracing::warn!(%error, "QUIC server handshake failed");
                return shutdown(&paths, error).await;
            }
        };
    terminator.register(Arc::new(tls_ctx.clone()));
    let scopes = server.scopes;
    let result = {
        let establish = async {
            let parameters = ArcParameters::new(Role::Server, client_parameters, server_parameters);
            let client_scid = poll_fn(|cx| handshake_dcid.poll_borrow(cx))
                .await
                .expect("handshake CID is available");
            handshake_dcid.refresh();
            parameters.authenticate_cids(Requirements::require_client(client_scid))?;
            cid_registry
                .local
                .set_limit(parameters.remote::<u64>(ParameterId::ActiveConnectionIdLimit))?;
            cid_registry
                .remote
                .set_limit(parameters.local(ParameterId::ActiveConnectionIdLimit));

            let hs_keys = tls_ctx.read_keys().await?;
            let hs_space = Arc::new(HandshakeSpace::new(
                scid,
                ArcKeys::from(hs_keys),
                paths.is_mp_handshaking.clone(),
            ));
            let _ = progress.install_handshake(hs_space.clone());

            tokio::spawn(read_space_to_tls(
                tls_ctx.clone(),
                hs_space.as_ref(),
                paths.clone(),
            ));
            tokio::spawn(recv_ih_pkt_and_deliver_frames(
                (rcvd_pkt.handshake, Some(scopes)),
                hs_space.clone(),
                paths.clone(),
            ));

            let keys = ArcOneRttKeys::from(tls_ctx.read_keys().await?);
            let concurrency = Box::new(ConsistentConcurrency::new(
                parameters.local(ParameterId::InitialMaxStreamsBidi),
                parameters.local(ParameterId::InitialMaxStreamsUni),
            ));
            let streams = DataStreams::new(
                parameters.clone(),
                concurrency,
                reliable_frames.clone(),
                Default::default(),
            );
            terminator.register(Arc::new(streams.clone()));
            let flow_ctrl = FlowController::new(
                parameters.remote(ParameterId::InitialMaxData),
                parameters.local(ParameterId::InitialMaxData),
                reliable_frames.clone(),
            );
            let data_space = Arc::new(DataSpace::new(
                scid,
                keys,
                streams,
                reliable_frames.clone(),
                paths.is_mp_handshaking.clone(),
            ));
            progress.install_data(data_space.clone());
            let puncher = ArcPuncher::new(
                reliable_frames.clone(),
                ProbeEncoder::new(data_space.clone(), client_scid),
            );
            paths.update_max_idle_timeout(parameters.negotiated_max_idle_timeout());

            for space in [&initial_space.space, &hs_space.0] {
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

            for space in [&initial_space.space, &hs_space.0] {
                tokio::spawn(read_tls_to_space(tls_ctx.clone(), space, paths.clone()));
            }
            tokio::spawn(read_tls_to_space(
                tls_ctx.clone(),
                data_space.as_ref(),
                paths.clone(),
            ));

            // Receiving Finished selects the handshake path before waking TLS.
            // Until then, Handshake keeps the first flight independent of path CIDs.
            let summary = tls_ctx.finished().await?;
            progress.on_tls_finished();
            let handshake = ArcHandshake::new_server(reliable_frames.clone());
            paths.enter_mature(Arc::new(MaturePhase {
                parameters: parameters.clone(),
                flow_ctrl: flow_ctrl.clone(),
                puncher: puncher.clone(),
            }));
            tokio::spawn(read_space_to_tls(
                tls_ctx.clone(),
                data_space.as_ref(),
                paths.clone(),
            ));
            tokio::spawn(receive_1rtt_pkt_and_deliver_frames(
                (rcvd_pkt.one_rtt, Some(scopes)),
                data_space.clone(),
                flow_ctrl.clone(),
                puncher.clone(),
                paths.clone(),
                parameters.clone(),
                token,
                handshake.clone(),
            ));
            handshake.done();

            let local = summary.local.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;
            progress.on_handshake_done(&paths);

            Ok::<_, Error>((
                (
                    summary.remote,
                    local,
                    qtransport::ArcConnection::new(
                        summary.alpn.unwrap_or_default(),
                        data_space.streams.clone(),
                        terminator.clone(),
                    )
                    .with_path_observer({
                        let paths = Arc::downgrade(&paths);
                        move |visit| {
                            if let Some(paths) = paths.upgrade() {
                                for path in paths.entries.lock().unwrap().values() {
                                    visit(path);
                                }
                            }
                        }
                    }),
                ),
                puncher,
            ))
        };
        any(establish, terminator.clone())
            .await
            .and_then(std::convert::identity)
    };

    let (connection, puncher) = match result {
        Ok(connection) => connection,
        Err(reason) => {
            tracing::warn!(error = %reason, "QUIC server handshake failed");
            return shutdown(&paths, reason).await;
        }
    };

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let observer = puncher.observe_endpoints(
        qprotocol::AddressBook::global().subscribe_punch(scopes),
        stopped,
        |_| {},
    );
    (server.accept_cb)(connection);
    let reason = terminator.await;
    drop(stop);
    let _ = observer.await;
    shutdown(&paths, reason).await
}

async fn shutdown(paths: &Paths, reason: Error) -> Error {
    let reason = finish(paths, reason).await;
    paths.cid_registry.local.clear();
    reason
}
