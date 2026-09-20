use std::sync::Arc;

use qbase::{
    ArcReceiving, Epoch,
    cid::ArcRemoteCids,
    error::{ErrorKind, QuicError},
    handshake::ClientHandshake,
    net::tx::Signals,
    param::{ClientParameters, ParameterId},
    role::Role,
    time::ArcConnIdle,
    token::ArcTokenRegistry,
};
use qtls::CryptoLevel;
use qtransport::{
    keys::ArcKeys, packet::channel::RcvdPacket, router::QuicRouterRegistry, space::Space,
};

use super::close_error;
use crate::{
    ArcConnPhase, ArcParameters, CloseReason, ConnPhase, Connected, Error, MaturePhase, Paths,
    ReliableFrames, TlsContext, recv::PacketReceiver,
};

/// Grow an already routed client. Path creation and packet sending are external.
#[allow(clippy::too_many_arguments)]
pub async fn client_growing(
    phase: ArcConnPhase,
    tls_ctx: TlsContext,
    client_parameters: ClientParameters,
    cid_registry: QuicRouterRegistry<ReliableFrames>,
    rcvd_pkt: RcvdPacket,
    paths: Arc<Paths>,
    idle: ArcConnIdle,
    token: ArcTokenRegistry,
    established: impl FnOnce(Result<Connected, Error>),
) -> CloseReason {
    let ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!("client_growing starts with InitialPhase")
    };

    let initial = &initial_phase.initial;
    let send_wakers = &initial.send_wakers;
    let closed = ArcReceiving::default();
    let local_cids = crate::ArcLocalCids::new(initial_phase.scid, cid_registry);
    let remote_cids = ArcRemoteCids::new(
        client_parameters
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
    tokio::spawn(crate::recv::recv_ih_pkt_and_deliver_frames(
        rcvd_pkt.initial,
        initial.clone(),
        paths.clone(),
        closed.clone(),
    ));

    let result = {
        let establish = async {
            let handshake_keys = tls_ctx.read_keys().await?;
            let handshake = Arc::new(Space::<ArcKeys>::new(
                Epoch::Handshake,
                send_wakers.clone(),
                |_| {},
            ));
            handshake.install_hs_keys(handshake_keys)?;
            phase.enter_connecting(initial_phase.clone(), handshake.clone());
            initial_phase.initial.crypto.recver.retire();
            initial_phase.initial.crypto.sender.retire();

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
            tokio::spawn(crate::recv::recv_ih_pkt_and_deliver_frames(
                rcvd_pkt.handshake,
                handshake.clone(),
                paths.clone(),
                closed.clone(),
            ));

            let parameters = ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters),
                Arc::new(tls_ctx.read_server_hello().await?),
            );
            let server_scid = parameters
                .remote(ParameterId::InitialSourceConnectionId)
                .ok_or_else(|| {
                    QuicError::with_default_fty(
                        ErrorKind::TransportParameter,
                        "server initial source connection ID is missing",
                    )
                })?;
            for path in paths.snapshot() {
                path.set_dcid(server_scid);
            }
            let initial_dcid = remote_cids.apply_dcid();
            remote_cids.apply_initial_dcid(server_scid, &initial_dcid);

            let (material, transport) = MaturePhase::new(
                &initial_phase,
                handshake.clone(),
                parameters.clone(),
                server_scid,
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

            let handshake_done = ArcReceiving::default();
            spawn_data_receiver(
                rcvd_pkt.one_rtt,
                material.clone(),
                parameters,
                local_cids.clone(),
                remote_cids.clone(),
                token,
                paths.clone(),
                closed.clone(),
                handshake_done.clone(),
            );

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
            handshake.crypto.recver.retire();
            let remote = summary.remote.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;
            for path in paths.snapshot() {
                path.validate();
            }
            send_wakers.wake_all_by(Signals::all());

            Ok::<_, Error>((
                (
                    summary.local,
                    remote,
                    qtransport::ArcConnection::new(
                        transport,
                        summary.alpn.unwrap_or_default(),
                        closed.clone(),
                    ),
                ),
                handshake_done,
                handshake,
                material,
            ))
        };
        let mut close = closed.clone();
        tokio::pin!(establish);
        tokio::select! {
            Ok(Some(reason)) = &mut close => Err(reason),
            result = &mut establish => result.map_err(CloseReason::from),
        }
    };

    let (connected, handshake_done, handshake, material) = match result {
        Ok(established_connection) => established_connection,
        Err(reason) => {
            established(Err(close_error(&reason)));
            return shutdown(&phase, &tls_ctx, &local_cids, &paths, reason);
        }
    };
    established(Ok(connected));

    let mut close = closed.clone();
    let reason = tokio::select! {
        Ok(Some(reason)) = &mut close => reason,
        Ok(Some(true)) = handshake_done => {
            initial_phase.initial.retire();
            handshake.retire();
            material
                .spaces
                .data
                .keys
                .try_get()
                .expect("live Data keys")
                .expect("installed Data keys")
                .allow_update();
            phase.enter_mature(material);
            closed.clone().await.expect("growing owns close").expect("first close reason")
        }
    };
    shutdown(&phase, &tls_ctx, &local_cids, &paths, reason)
}

#[allow(clippy::too_many_arguments)]
fn spawn_data_receiver(
    packets: PacketReceiver<qbase::packet::OneRttHeader>,
    material: Arc<MaturePhase>,
    parameters: ArcParameters,
    local_cids: crate::ArcLocalCids,
    remote_cids: ArcRemoteCids<ReliableFrames>,
    token: ArcTokenRegistry,
    paths: Arc<Paths>,
    closed: ArcReceiving<CloseReason>,
    handshake_done: ArcReceiving<bool>,
) {
    tokio::spawn(async move {
        let handshake = ClientHandshake::default();
        crate::recv::receive_client_data(
            packets,
            material,
            paths,
            parameters,
            local_cids,
            remote_cids,
            token,
            closed,
            || {
                if handshake.recv_handshake_done_frame(qbase::frame::HandshakeDoneFrame) {
                    handshake_done.set(true);
                }
            },
        )
        .await;
    });
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
