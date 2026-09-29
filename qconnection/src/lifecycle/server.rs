use std::sync::{Arc, OnceLock};

use qbase::{
    Epoch,
    cid::ArcRemoteCids,
    error::{ErrorKind, QuicError},
    frame::{HandshakeDoneFrame, io::SendFrame},
    param::ParameterId,
    role::Role,
    token::ArcTokenRegistry,
};
use qtls::CryptoLevel;
use qtransport::{
    keys::ArcKeys, packet::channel::RcvdPacket, router::QuicRouterEntry, space::Space,
};
use tokio::io::AsyncWriteExt;

use super::{any, close_error, interceptor::read_crypto_stream_to_interceptor};
use crate::{
    ArcParameters, CloseReason, Error, Interceptor, MaturePhase, Paths, ServerRegistry, TlsContext,
};

/// Select a listening server from an already routed Initial, then grow the connection.
#[allow(clippy::too_many_arguments)]
pub async fn server_growing(
    route: QuicRouterEntry,
    rcvd_pkt: RcvdPacket,
    paths: Arc<Paths>,
    token: ArcTokenRegistry,
) -> CloseReason {
    let phase = paths.phase();
    let crate::ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!("server_growing starts with InitialPhase")
    };
    let idle = paths.idle();
    let closed = paths.closed();
    let initial = &initial_phase.initial;
    let local_cids = crate::ArcLocalCids::new(
        initial_phase.scid,
        route
            .router()
            .registry_on_issuing_scid(route.inbox(), initial_phase.reliable_frames.clone()),
    );
    let scopes = Arc::new(OnceLock::new());
    tokio::spawn(crate::recv::recv_pending_server_initial(
        rcvd_pkt.initial,
        initial.clone(),
        paths.clone(),
        closed.clone(),
        scopes.clone(),
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
            return shutdown_initial(&paths, &local_cids, reason).await;
        }
    };
    let Some(server_name) = hello.server_name() else {
        return shutdown_initial(
            &paths,
            &local_cids,
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
            &local_cids,
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
    let (tls_ctx, client_parameters, server_parameters) = match server.spawn_connection_with(
        qtls::QuicVersion::V1,
        hello,
        initial_phase.scid,
        initial_phase.odcid,
    ) {
        Ok(ready) => ready,
        Err(error) => {
            (server.accept_cb)(Err(error.clone()));
            return shutdown_initial(&paths, &local_cids, error.into()).await;
        }
    };
    scopes
        .set(server.scopes)
        .expect("server scope is selected once");
    let scopes = server.scopes;
    let cid_registry = qbase::cid::Registry::new(
        Role::Server,
        initial_phase.odcid,
        local_cids,
        ArcRemoteCids::new(
            server_parameters.get::<u64>(ParameterId::ActiveConnectionIdLimit),
            initial_phase.reliable_frames.clone(),
        ),
    );
    let result = {
        let establish = async {
            let client_scid = client_parameters
                .get::<qbase::cid::ConnectionId>(ParameterId::InitialSourceConnectionId);
            if initial_phase.dcid() != client_scid {
                return Err(QuicError::with_default_fty(
                    ErrorKind::TransportParameter,
                    "client initial source connection ID mismatch",
                )
                .into());
            }

            let handshake_keys = tls_ctx.read_keys().await?;
            let handshake = Arc::new(Space::new(
                Epoch::Handshake,
                ArcKeys::from(handshake_keys),
            ));
            initial.crypto.recver.retire();

            tokio::spawn(crate::tls::read_crypto_stream_to_tls(
                tls_ctx.clone(),
                CryptoLevel::Handshake,
                handshake.crypto.clone(),
                closed.clone(),
            ));
            tokio::spawn(crate::recv::recv_server_ih_pkt_and_deliver_frames(
                rcvd_pkt.handshake,
                handshake.clone(),
                paths.clone(),
                closed.clone(),
                scopes,
            ));

            let parameters = ArcParameters::new(Role::Server, client_parameters, server_parameters);
            let initial_dcid = cid_registry.remote.apply_dcid();
            cid_registry
                .remote
                .apply_initial_dcid(client_scid, &initial_dcid);
            let (mature_phase, transport) = MaturePhase::new(
                &initial_phase,
                handshake.clone(),
                parameters.clone(),
                client_scid,
                initial_phase.reliable_frames.clone(),
                cid_registry.clone(),
                initial_dcid,
                qtransport::keys::ArcOneRttKeys::from(tls_ctx.read_keys().await?),
            )?;
            cid_registry
                .local
                .set_limit(parameters.remote::<u64>(ParameterId::ActiveConnectionIdLimit))?;
            idle.negotiate_max_idle_timeout(parameters.remote(ParameterId::MaxIdleTimeout));

            let initial_flight = tls_ctx.read_msg_at(CryptoLevel::Initial).await?;
            initial
                .crypto
                .writer()
                .write_all(&initial_flight)
                .await
                .map_err(|error| {
                    QuicError::with_default_fty(ErrorKind::Internal, error.to_string())
                })?;
            while let Some(bytes) = tls_ctx.try_read_msg_at(CryptoLevel::Initial)? {
                initial
                    .crypto
                    .writer()
                    .write_all(&bytes)
                    .await
                    .map_err(|error| {
                        QuicError::with_default_fty(ErrorKind::Internal, error.to_string())
                    })?;
            }
            let handshake_flight = tls_ctx.read_msg_at(CryptoLevel::Handshake).await?;
            handshake
                .crypto
                .writer()
                .write_all(&handshake_flight)
                .await
                .map_err(|error| {
                    QuicError::with_default_fty(ErrorKind::Internal, error.to_string())
                })?;
            while let Some(bytes) = tls_ctx.try_read_msg_at(CryptoLevel::Handshake)? {
                handshake
                    .crypto
                    .writer()
                    .write_all(&bytes)
                    .await
                    .map_err(|error| {
                        QuicError::with_default_fty(ErrorKind::Internal, error.to_string())
                    })?;
            }

            for (level, stream) in [
                (CryptoLevel::Initial, initial.crypto.clone()),
                (CryptoLevel::Handshake, handshake.crypto.clone()),
                (CryptoLevel::OneRtt, mature_phase.spaces.data.crypto.clone()),
            ] {
                tokio::spawn(crate::tls::read_tls_to_crypto_stream(
                    tls_ctx.clone(),
                    level,
                    stream,
                    closed.clone(),
                ));
            }
            tokio::spawn(crate::tls::read_crypto_stream_to_tls(
                tls_ctx.clone(),
                CryptoLevel::OneRtt,
                mature_phase.spaces.data.crypto.clone(),
                closed.clone(),
            ));

            tokio::spawn(crate::recv::receive_server_data(
                rcvd_pkt.one_rtt,
                mature_phase.clone(),
                paths.clone(),
                parameters,
                cid_registry.clone(),
                token,
                closed.clone(),
                scopes,
            ));
            phase.enter_mature(mature_phase.clone());

            let summary = tls_ctx.finished().await?;
            mature_phase.retire_handshake_spaces();
            mature_phase
                .spaces
                .data
                .keys
                .get()
                .expect("live Data keys")
                .allow_update();
            let local = summary.local.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;
            initial_phase
                .reliable_frames
                .send_frame([HandshakeDoneFrame]);
            paths.handshake_confirmed();

            Ok::<_, Error>((
                summary.remote,
                local,
                qtransport::ArcConnection::new(
                    transport,
                    summary.alpn.unwrap_or_default(),
                    closed.clone(),
                ),
            ))
        };
        any(establish, closed.clone())
            .await
            .and_then(|result| result.map_err(CloseReason::from))
    };

    match result {
        Ok(connection) => (server.accept_cb)(Ok(connection)),
        Err(reason) => {
            (server.accept_cb)(Err(close_error(&reason)));
            return shutdown(&paths, &tls_ctx, &cid_registry.local, reason).await;
        }
    }

    let reason = closed
        .await
        .expect("growing owns close")
        .expect("first close reason");
    shutdown(&paths, &tls_ctx, &cid_registry.local, reason).await
}

async fn shutdown(
    paths: &Paths,
    tls: &TlsContext,
    local_cids: &crate::ArcLocalCids,
    reason: CloseReason,
) -> CloseReason {
    tls.on_error(close_error(&reason));
    paths.finish(&reason).await;
    local_cids.clear();
    reason
}

async fn shutdown_initial(
    paths: &Paths,
    local_cids: &crate::ArcLocalCids,
    reason: CloseReason,
) -> CloseReason {
    paths.finish(&reason).await;
    local_cids.clear();
    reason
}
