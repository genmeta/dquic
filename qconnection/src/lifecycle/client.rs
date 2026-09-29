use std::sync::{Arc, Mutex};

use qbase::{
    ArcReceiving, Epoch,
    cid::ArcRemoteCids,
    error::{ErrorKind, QuicError},
    param::{ClientParameters, ParameterId, Requirements},
    role::Role,
    token::ArcTokenRegistry,
};
use qtls::CryptoLevel;
use qtransport::{
    keys::ArcKeys, packet::channel::RcvdPacket, router::QuicRouterRegistry, space::Space,
};

use super::{any, close_error};
use crate::{
    ArcParameters, ArcReliableFrames, CloseReason, ConnPhase, Connected, Error, MaturePhase, Paths,
    TlsContext,
};

/// Grow an already routed client. Path creation and packet sending are external.
#[allow(clippy::too_many_arguments)]
pub async fn client_growing(
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

    let requirements = Arc::new(Mutex::new(Requirements::new_client(initial_phase.odcid)));
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
    tokio::spawn(crate::tls::read_tls_to_crypto_stream(
        tls_context.clone(),
        CryptoLevel::Initial,
        initial.crypto.clone(),
        closed.clone(),
    ));
    tokio::spawn(crate::tls::read_crypto_stream_to_tls(
        tls_context.clone(),
        CryptoLevel::Initial,
        initial.crypto.clone(),
        closed.clone(),
    ));
    tokio::spawn(crate::recv::recv_client_ih_pkt_and_deliver_frames(
        rcvd_pkt.initial,
        initial.clone(),
        paths.clone(),
        closed.clone(),
        requirements.clone(),
    ));

    let result = {
        let establish = async {
            let handshake_keys = tls_context.read_keys().await?;
            let handshake = Arc::new(Space::new(Epoch::Handshake, ArcKeys::from(handshake_keys)));
            phase.enter_handshake(handshake.clone());
            initial_phase.initial.crypto.recver.retire();
            initial_phase.initial.crypto.sender.retire();

            tokio::spawn(crate::tls::read_tls_to_crypto_stream(
                tls_context.clone(),
                CryptoLevel::Handshake,
                handshake.crypto.clone(),
                closed.clone(),
            ));
            tokio::spawn(crate::tls::read_crypto_stream_to_tls(
                tls_context.clone(),
                CryptoLevel::Handshake,
                handshake.crypto.clone(),
                closed.clone(),
            ));
            tokio::spawn(crate::recv::recv_client_ih_pkt_and_deliver_frames(
                rcvd_pkt.handshake,
                handshake.clone(),
                paths.clone(),
                closed.clone(),
                requirements.clone(),
            ));

            let parameters = ArcParameters::new(
                Role::Client,
                Arc::new(client_params),
                Arc::new(tls_context.read_server_parameters().await?),
            );
            parameters.authenticate_cids(*requirements.lock().unwrap())?;
            let server_scid = parameters.remote(ParameterId::InitialSourceConnectionId);
            let initial_dcid = cid_registry.remote.apply_dcid();
            cid_registry
                .remote
                .apply_initial_dcid(server_scid, &initial_dcid);

            let (mature_phase, transport) = MaturePhase::new(
                &initial_phase,
                handshake.clone(),
                parameters.clone(),
                server_scid,
                initial_phase.reliable_frames.clone(),
                cid_registry.clone(),
                initial_dcid,
                qtransport::keys::ArcOneRttKeys::from(tls_context.read_keys().await?),
            )?;
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

            tokio::spawn(crate::tls::read_tls_to_crypto_stream(
                tls_context.clone(),
                CryptoLevel::OneRtt,
                mature_phase.spaces.data.crypto.clone(),
                closed.clone(),
            ));
            tokio::spawn(crate::tls::read_crypto_stream_to_tls(
                tls_context.clone(),
                CryptoLevel::OneRtt,
                mature_phase.spaces.data.crypto.clone(),
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
                        transport,
                        summary.alpn.unwrap_or_default(),
                        closed.clone(),
                    ),
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
            return shutdown(&paths, &tls_context, &cid_registry.local, reason).await;
        }
    };
    established(Ok(connected));

    let mut close = closed.clone();
    let reason = tokio::select! {
        Ok(Some(reason)) = &mut close => reason,
        Ok(Some(true)) = handshake_done => {
            mature_phase.retire_handshake_spaces();
            mature_phase
                .spaces
                .data
                .keys
                .get()
                .expect("live Data keys")
                .allow_update();
            paths.handshake_confirmed();
            closed.clone().await.expect("growing owns close").expect("first close reason")
        }
    };
    shutdown(&paths, &tls_context, &cid_registry.local, reason).await
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
