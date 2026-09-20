use std::sync::{Arc, OnceLock};

use qbase::{
    ArcReceiving, Epoch,
    cid::ArcRemoteCids,
    error::{ErrorKind, QuicError},
    frame::{HandshakeDoneFrame, io::SendFrame},
    net::{route::Link, tx::Signals},
    param::ParameterId,
    role::Role,
    time::ArcConnIdle,
    token::ArcTokenRegistry,
};
use qtls::CryptoLevel;
use qtransport::{
    keys::ArcKeys, packet::channel::RcvdPacket, router::QuicRouterEntry, space::Space,
};
use tokio::io::AsyncReadExt;

use super::close_error;
use crate::{
    ArcConnPhase, ArcParameters, BelongsTo, CloseReason, ConnPhase, Error, Interceptor,
    MaturePhase, Paths, ServerRegistry, TlsContext,
};

/// Select a listening server from an already routed Initial, then grow the connection.
#[allow(clippy::too_many_arguments)]
pub async fn server_growing(
    phase: ArcConnPhase,
    route: QuicRouterEntry,
    rcvd_pkt: RcvdPacket,
    paths: Arc<Paths>,
    idle: ArcConnIdle,
    token: ArcTokenRegistry,
    initial_link: Link,
) -> CloseReason {
    let ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!("server_growing starts with InitialPhase")
    };

    let initial = &initial_phase.initial;
    let send_wakers = &initial.send_wakers;
    let closed = ArcReceiving::default();
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
    tokio::spawn({
        let interceptor = interceptor.clone();
        let stream = initial.crypto.clone();
        let closed = closed.clone();
        async move {
            let mut reader = stream.reader();
            let mut buffer = [0; 4096];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => {
                        closed.set(CloseReason::Internal(QuicError::with_default_fty(
                            ErrorKind::ProtocolViolation,
                            "Initial CRYPTO ended before ClientHello",
                        )));
                        break;
                    }
                    Ok(length) if interceptor.write(&buffer[..length]) => break,
                    Ok(_) => {}
                    Err(error) => {
                        closed.set(CloseReason::Internal(QuicError::with_default_fty(
                            ErrorKind::Internal,
                            error.to_string(),
                        )));
                        break;
                    }
                }
            }
        }
    });

    let hello = {
        let mut close = closed.clone();
        tokio::select! {
            Ok(Some(reason)) = &mut close => Err(reason),
            result = interceptor.read() => result.map_err(CloseReason::from),
        }
    };
    let hello = match hello {
        Ok(hello) => hello,
        Err(reason) => return shutdown_initial(&phase, &local_cids, &paths, reason),
    };
    let Some(server_name) = hello.server_name() else {
        return shutdown_initial(
            &phase,
            &local_cids,
            &paths,
            CloseReason::Internal(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "ClientHello has no server name",
            )),
        );
    };
    let Some(server) = ServerRegistry::global().get(server_name) else {
        return shutdown_initial(
            &phase,
            &local_cids,
            &paths,
            CloseReason::Internal(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "server name is not listening",
            )),
        );
    };
    if !initial_link.src.belongs_to(server.scopes) {
        return shutdown_initial(
            &phase,
            &local_cids,
            &paths,
            CloseReason::Internal(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "client address is outside the server listen scope",
            )),
        );
    }
    scopes
        .set(server.scopes)
        .expect("server scope is selected once");
    idle.negotiate_max_idle_timeout(
        server
            .server_parameters
            .get(ParameterId::MaxIdleTimeout)
            .unwrap(),
    );
    let (tls_ctx, client_parameters, server_parameters) = match server.start(
        qtls::QuicVersion::V1,
        hello,
        initial_phase.scid,
        initial_phase.odcid,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            (server.accept_cb)(Err(error.clone()));
            return shutdown_initial(&phase, &local_cids, &paths, error.into());
        }
    };
    let selected_scopes = server.scopes;
    let remote_cids = ArcRemoteCids::new(
        server_parameters
            .get(ParameterId::ActiveConnectionIdLimit)
            .unwrap(),
        initial_phase.reliable_frames.clone(),
    );
    tokio::spawn(crate::tls::read_tls_to_crypto_stream(
        tls_ctx.clone(),
        CryptoLevel::Initial,
        initial.crypto.clone(),
        closed.clone(),
    ));
    tokio::spawn(crate::tls::read_crypto_stream_to_tls(
        tls_ctx.clone(),
        CryptoLevel::Initial,
        initial.crypto.clone(),
        closed.clone(),
    ));

    let result = {
        let establish = async {
            let client_scid = client_parameters
                .get(ParameterId::InitialSourceConnectionId)
                .ok_or_else(|| {
                    QuicError::with_default_fty(
                        ErrorKind::TransportParameter,
                        "client initial source connection ID is missing",
                    )
                })?;
            if paths
                .snapshot()
                .iter()
                .any(|path| path.dcid() != client_scid)
            {
                return Err(QuicError::with_default_fty(
                    ErrorKind::TransportParameter,
                    "client initial source connection ID mismatch",
                )
                .into());
            }

            let handshake_keys = tls_ctx.read_keys().await?;
            let handshake = Arc::new(Space::<ArcKeys>::new(
                Epoch::Handshake,
                send_wakers.clone(),
                |_| {},
            ));
            handshake.install_hs_keys(handshake_keys)?;
            phase.enter_connecting(initial_phase.clone(), handshake.clone());
            initial.crypto.recver.retire();

            tokio::spawn(crate::tls::read_tls_to_crypto_stream(
                tls_ctx.clone(),
                CryptoLevel::Handshake,
                handshake.crypto.clone(),
                closed.clone(),
            ));
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
                selected_scopes,
            ));

            let parameters = ArcParameters::new(Role::Server, client_parameters, server_parameters);
            let initial_dcid = remote_cids.apply_dcid();
            remote_cids.apply_initial_dcid(client_scid, &initial_dcid);
            let (material, transport) = MaturePhase::new(
                &initial_phase,
                handshake.clone(),
                parameters.clone(),
                client_scid,
                initial_phase.reliable_frames.clone(),
                remote_cids.clone(),
                initial_dcid,
            )?;
            phase.enter_handshaking(material.clone());
            local_cids.set_limit(
                parameters
                    .remote::<u64>(ParameterId::ActiveConnectionIdLimit)
                    .unwrap()
                    .min(4),
            )?;
            idle.negotiate_max_idle_timeout(
                parameters.remote(ParameterId::MaxIdleTimeout).unwrap(),
            );

            tokio::spawn(crate::recv::receive_server_data(
                rcvd_pkt.one_rtt,
                material.clone(),
                paths.clone(),
                parameters,
                local_cids.clone(),
                remote_cids,
                token,
                closed.clone(),
                selected_scopes,
            ));

            material
                .spaces
                .data
                .install_1rtt_keys(tls_ctx.read_keys().await?)?;
            tokio::spawn(crate::tls::read_tls_to_crypto_stream(
                tls_ctx.clone(),
                CryptoLevel::OneRtt,
                material.spaces.data.crypto.clone(),
                closed.clone(),
            ));
            tokio::spawn(crate::tls::read_crypto_stream_to_tls(
                tls_ctx.clone(),
                CryptoLevel::OneRtt,
                material.spaces.data.crypto.clone(),
                closed.clone(),
            ));

            let summary = tls_ctx.finished().await?;
            initial.retire();
            handshake.retire();
            material
                .spaces
                .data
                .keys
                .try_get()
                .expect("live Data keys")
                .expect("installed Data keys")
                .allow_update();
            let local = summary.local.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;
            for path in paths.snapshot() {
                path.validate();
            }
            initial_phase
                .reliable_frames
                .send_frame([HandshakeDoneFrame]);
            send_wakers.wake_all_by(Signals::all());
            phase.enter_mature(material);

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
        let mut close = closed.clone();
        tokio::pin!(establish);
        tokio::select! {
            Ok(Some(reason)) = &mut close => Err(reason),
            result = &mut establish => result.map_err(CloseReason::from),
        }
    };

    match result {
        Ok(connection) => (server.accept_cb)(Ok(connection)),
        Err(reason) => {
            (server.accept_cb)(Err(close_error(&reason)));
            return shutdown(&phase, &tls_ctx, &local_cids, &paths, reason);
        }
    }

    let reason = closed
        .await
        .expect("growing owns close")
        .expect("first close reason");
    shutdown(&phase, &tls_ctx, &local_cids, &paths, reason)
}

fn shutdown(
    phase: &ArcConnPhase,
    tls: &TlsContext,
    local_cids: &crate::ArcLocalCids,
    paths: &Paths,
    reason: CloseReason,
) -> CloseReason {
    tls.on_error(close_error(&reason));
    close_spaces(&phase.get(), &reason);
    local_cids.clear();
    for path in paths.snapshot() {
        path.retire();
        paths.remove(&path);
    }
    reason
}

fn shutdown_initial(
    phase: &ArcConnPhase,
    local_cids: &crate::ArcLocalCids,
    paths: &Paths,
    reason: CloseReason,
) -> CloseReason {
    close_spaces(&phase.get(), &reason);
    local_cids.clear();
    for path in paths.snapshot() {
        path.retire();
        paths.remove(&path);
    }
    reason
}

fn close_spaces(phase: &ConnPhase, reason: &CloseReason) {
    let error = close_error(reason);
    phase.initial().crypto.on_error(&error);
    phase.initial().retire();
    if let Some(handshake) = phase.handshake() {
        handshake.crypto.on_error(&error);
        handshake.retire();
    }
    if let Some(material) = phase.material() {
        material.spaces.data.crypto.on_error(&error);
        material.streams.on_conn_error(&error);
        material.flow.on_conn_error(&error);
        material.spaces.data.keys.retire();
    }
}
