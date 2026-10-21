use std::sync::Arc;

use futures::StreamExt;
use qbase::{
    Epoch,
    cid::ArcRemoteCids,
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
    space::{DataSpace, HandshakeSpace, InitialSpace},
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};

use super::{any, finish};
use crate::{
    ArcParameters, CidRegistry, ConnPhase, Connected, DataStreams, Error, FlowController,
    MaturePhase, Paths, TlsContext,
    recv::{receive_1rtt_pkt_and_deliver_frames, recv_ih_pkt_and_deliver_frames},
    tls::{read_space_to_tls, read_tls_to_space},
};

/// Grow an already routed client and discover paths from the DNS result stream.
/// The client owns discovery and cancels it before shutting down its paths.
/// The caller runs [`crate::recv::tick`] alongside this future.
#[allow(clippy::too_many_arguments)]
pub async fn client_growing(
    initial_space: Arc<InitialSpace>,
    server_name: String,
    client_params: ClientParameters,
    paths: Arc<Paths>,
    rcvd_pkt: RcvdPacket,
    tls_context: TlsContext,
    token_registry: ArcTokenRegistry,
    established: impl FnOnce(Result<Connected, Error>),
) -> Error {
    let phase = paths.phase();
    let terminator = paths.terminator.clone();
    terminator.register(Arc::new(tls_context.clone()));
    let ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!("client_growing starts with InitialPhase")
    };

    let spaces = paths.spaces.clone();
    let reliable_frames = paths.reliable_frames.clone();
    let local_cids = initial_phase.local_cids.clone();
    let loss_resender = paths.resender.clone();
    let scid = initial_space.initial_scid;
    let odcid = local_cids.origin_dcid();
    drop(initial_phase);

    let discovery = tokio::spawn({
        let paths = paths.clone();
        let terminator = terminator.clone();
        let addresses = AddressBook::global().clone();
        let resolver = qresolve::Resolver::get();
        async move {
            if let Err(error) = resolve_paths(&paths, &addresses, resolver, &server_name).await {
                terminator.close(error.into(), paths.closing_pto());
            }
        }
    });
    tokio::spawn(read_tls_to_space(
        tls_context.clone(),
        initial_space.as_ref(),
        paths.clone(),
    ));
    tokio::spawn(read_space_to_tls(
        tls_context.clone(),
        initial_space.as_ref(),
        paths.clone(),
    ));
    tokio::spawn(recv_ih_pkt_and_deliver_frames(
        (rcvd_pkt.initial, None),
        initial_space.clone(),
        paths.clone(),
    ));

    let result = {
        let establish = async {
            let handshake_keys = tls_context.read_keys().await?;
            let hs_space = Arc::new(HandshakeSpace::new(scid, ArcKeys::from(handshake_keys)));
            loss_resender
                .write_guard()
                .push_back(hs_space.clone())
                .expect("Handshake epoch");
            spaces
                .write_guard()
                .push_back(hs_space.clone())
                .expect("Handshake epoch");
            terminator.register(Arc::new(hs_space.crypto.clone()));
            paths.handshake.got_handshake_key();
            let server_scid = phase.enter_handshake();
            initial_space.crypto.recver.retire();
            initial_space.crypto.sender.retire();

            tokio::spawn(read_tls_to_space(
                tls_context.clone(),
                hs_space.as_ref(),
                paths.clone(),
            ));
            tokio::spawn(read_space_to_tls(
                tls_context.clone(),
                hs_space.as_ref(),
                paths.clone(),
            ));
            tokio::spawn(recv_ih_pkt_and_deliver_frames(
                (rcvd_pkt.handshake, None),
                hs_space.clone(),
                paths.clone(),
            ));

            let parameters = ArcParameters::new(
                Role::Client,
                Arc::new(client_params),
                Arc::new(tls_context.read_server_parameters().await?),
            );
            parameters.authenticate_cids(Requirements::require_server(server_scid, odcid))?;
            let remote_cids = ArcRemoteCids::new(
                server_scid,
                parameters.local(ParameterId::ActiveConnectionIdLimit),
                reliable_frames.clone(),
            );
            paths.cids.attach_remote(remote_cids.clone());
            let cid_registry = CidRegistry::new(local_cids.clone(), remote_cids);
            let keys = ArcOneRttKeys::from(tls_context.read_keys().await?);
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
            let data_space = Arc::new(DataSpace::new(scid, keys, streams, reliable_frames.clone()));
            loss_resender
                .write_guard()
                .push_back(data_space.clone())
                .expect("Data epoch");
            spaces
                .write_guard()
                .push_back(data_space.clone())
                .expect("Data epoch");
            terminator.register(Arc::new(data_space.crypto.clone()));
            let puncher = ArcPuncher::new(
                reliable_frames.clone(),
                ProbeEncoder::new(data_space.clone(), server_scid),
            );
            phase.enter_mature(Arc::new(MaturePhase {
                parameters: parameters.clone(),
                flow_ctrl: flow_ctrl.clone(),
                cid_registry: cid_registry.clone(),
                puncher: puncher.clone(),
            }));
            local_cids.set_limit(parameters.remote::<u64>(ParameterId::ActiveConnectionIdLimit))?;
            paths.update_max_idle_timeout(parameters.negotiated_max_idle_timeout());

            let handshake_done = ArcHandshake::new_client();
            tokio::spawn(receive_1rtt_pkt_and_deliver_frames(
                (rcvd_pkt.one_rtt, None),
                data_space.clone(),
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
                data_space.as_ref(),
                paths.clone(),
            ));
            tokio::spawn(read_space_to_tls(
                tls_context.clone(),
                data_space.as_ref(),
                paths.clone(),
            ));

            let summary = tls_context.finished().await?;
            hs_space.crypto.recver.retire();
            let remote_authority = summary.remote.ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::Crypto(120), "server identity is missing")
            })?;

            Ok::<_, Error>((
                (
                    summary.local,
                    remote_authority,
                    qtransport::ArcConnection::new(
                        summary.alpn.unwrap_or_default(),
                        data_space.streams.clone(),
                        terminator.clone(),
                    )
                    .with_path_observer({
                        let paths = Arc::downgrade(&paths);
                        move || {
                            paths
                                .upgrade()
                                .map_or_else(Vec::new, |paths| paths.snapshot())
                        }
                    }),
                ),
                handshake_done,
                data_space,
                puncher,
            ))
        };
        any(establish, terminator.clone())
            .await
            .and_then(std::convert::identity)
    };

    let (connected, handshake_done, data, puncher) = match result {
        Ok(established_connection) => established_connection,
        Err(reason) => {
            established(Err(reason.clone()));
            return shutdown(&paths, &local_cids, reason, discovery).await;
        }
    };
    established(Ok(connected));

    let reason = tokio::select! {
        biased;
        reason = terminator.clone() => reason,
        () = handshake_done => {
            data.keys.allow_update();
            {
                let mut spaces = spaces.write_guard();
                let mut loss_resender = loss_resender.write_guard();
                while spaces.front().is_some_and(|(epoch, _)| epoch < Epoch::Data as u64) {
                    let (_, space) = spaces.pop_front().unwrap();
                    space.retire();
                    loss_resender.pop_front();
                }
            }
            paths.handshake_confirmed();
            // Dropping this coroutine also stops observation by dropping the sender.
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let observer = puncher.observe_endpoints(
                AddressBook::global().subscribe_punch(crate::Scopes::ALL),
                stopped,
                |_| {},
            );
            let reason = terminator.clone().await;
            drop(stop);
            let _ = observer.await;
            reason
        }
    };
    shutdown(&paths, &local_cids, reason, discovery).await
}

async fn shutdown(
    paths: &Paths,
    local_cids: &crate::ArcLocalCids,
    error: Error,
    discovery: tokio::task::JoinHandle<()>,
) -> Error {
    // Stop discovery before path cleanup so late DNS results cannot create senders.
    discovery.abort();
    let _ = discovery.await;
    let reason = finish(paths, error).await;
    local_cids.clear();
    reason
}

pub(crate) async fn resolve_paths(
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
            paths.add_path(pathway);
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
