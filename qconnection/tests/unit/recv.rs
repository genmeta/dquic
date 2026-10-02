use std::{sync::Arc, task::Poll, time::Duration};

use bytes::BytesMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{AckFrame, PingFrame},
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    },
    packet::{DataHeader, LongHeaderBuilder, Packet, PacketReader, long},
    role::Role,
};
use qrecovery::journal::ArcSentJournal;
use qtransport::{keys::ArcKeys, packet::CipherPacket, path::Path, space::Space};

use crate::{
    ArcConnPhase, CloseReason, Paths, common::initial_keys as keys,
    recv::recv_ih_pkt_and_deliver_frames, terminate::Terminator,
};

fn seal<H, const N: usize>(
    header: H,
    keys: &qtls::DirectionalKeys,
    journal: &ArcSentJournal,
    sources: [&mut dyn for<'b> qbase::packet::assemble::Package<&'b mut BytesMut>; N],
) -> Result<BytesMut, crate::Error>
where
    H: qbase::packet::HeaderSize + qbase::packet::GetType,
    for<'a> &'a mut BytesMut: qbase::packet::header::io::WriteHeader<H>,
{
    use qbase::packet::assemble::Assemble;
    let mut buffer = BytesMut::with_capacity(1200);
    let pn = journal.next_pn().unwrap();
    let packet = crate::send::Packet::new(header, pn, &mut buffer)?;
    let mut limits = qbase::packet::assemble::Constraints {
        flow_ctrl: usize::MAX,
        send_quota: 1200,
        credit: 1200,
        min_size: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let mut packet = crate::send::SendingPacket {
        packet,
        keys,
        limits: &mut limits,
    };
    let mut frames = Vec::new();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        matches!(packet.assemble(&mut cx, sources.map(|source| source as &mut dyn qbase::packet::Package<&mut BytesMut>), &mut frames), Poll::Ready(Ok(n)) if n > 0)
    );
    packet.seal()?;
    journal.on_assembled(pn.0, None, frames.drain(..));
    Ok(buffer)
}

async fn receive_ping(
    role: Role,
    epoch: Epoch,
    corrupt: bool,
    paths: &Arc<Paths>,
    path: &Arc<Path>,
) {
    let space = Arc::new(Space::<ArcKeys>::new(
        epoch,
        ArcKeys::new(Arc::new(keys(role == Role::Server))),
    ));
    let keys = keys(role != Role::Server);
    let header = LongHeaderBuilder::with_cid(
        ConnectionId::from_slice(b"localcid"),
        ConnectionId::from_slice(b"peercid0"),
    );
    let journal = ArcSentJournal::default();
    let mut ping = PingFrame;
    let packet = if epoch == Epoch::Initial {
        seal(header.initial(vec![]), &keys.sealing, &journal, [&mut ping])
    } else {
        seal(header.handshake(), &keys.sealing, &journal, [&mut ping])
    }
    .unwrap();
    let mut bytes = BytesMut::from(packet.as_ref());
    if corrupt {
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
    }
    receive_bytes(bytes, space, paths, path).await
}

async fn receive_bytes(
    bytes: BytesMut,
    space: Arc<Space<ArcKeys>>,
    paths: &Arc<Paths>,
    path: &Arc<Path>,
) {
    let Packet::Data(packet) = PacketReader::new(bytes, 8).next().unwrap().unwrap() else {
        panic!()
    };
    let link = Link::new(
        "127.0.0.1:30001".parse().unwrap(),
        "127.0.0.1:30002".parse().unwrap(),
    );
    match packet.header {
        DataHeader::Long(long::DataHeader::Initial(header)) => {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.try_send((
                CipherPacket::new(header, packet.bytes, packet.offset),
                path.pathway,
                link,
            ))
            .unwrap();
            drop(tx);
            recv_ih_pkt_and_deliver_frames(
                (rx, None),
                space,
                paths.clone(),
                paths.close_reason(),
            )
            .await;
        }
        DataHeader::Long(long::DataHeader::Handshake(header)) => {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.try_send((
                CipherPacket::new(header, packet.bytes, packet.offset),
                path.pathway,
                link,
            ))
            .unwrap();
            drop(tx);
            recv_ih_pkt_and_deliver_frames(
                (rx, None),
                space,
                paths.clone(),
                paths.close_reason(),
            )
            .await;
        }
        _ => panic!(),
    }
}

fn paths(role: Role) -> (Arc<Paths>, Arc<Path>, Arc<Path>) {
    let phase = ArcConnPhase::initial(crate::common::initial_phase(
        role,
        ConnectionId::from_slice(b"localcid"),
        ConnectionId::from_slice(b"original"),
        keys(role == Role::Server),
    ));
    let paths = Paths::new(role, phase, Duration::ZERO, Duration::ZERO);
    let local = EndpointAddr::direct("127.0.0.1:30001".parse().unwrap());
    let first = paths
        .add_path(Pathway::new(
            local,
            EndpointAddr::direct("127.0.0.1:30002".parse().unwrap()),
        ))
        .unwrap();
    let second = paths
        .add_path(Pathway::new(
            local,
            EndpointAddr::direct("127.0.0.1:30003".parse().unwrap()),
        ))
        .unwrap();
    (paths, first, second)
}

#[tokio::test]
async fn initial_and_handshake_close_enter_draining_through_phase_terminator() {
    use tokio::io::AsyncReadExt;

    for role in [Role::Client, Role::Server] {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            let (paths, path, _) = paths(role);
            let phase = paths.phase();
            let crate::ConnPhase::Initial(initial) = phase.get() else {
                unreachable!()
            };
            let space = if epoch == Epoch::Initial {
                initial.initial_space.clone()
            } else {
                let space = Arc::new(Space::new(
                    Epoch::Handshake,
                    ArcKeys::new(Arc::new(keys(role == Role::Server))),
                ));
                phase.enter_handshake(space.clone());
                space
            };
            let peer_keys = keys(role != Role::Server);
            let header = LongHeaderBuilder::with_cid(
                ConnectionId::from_slice(b"localcid"),
                ConnectionId::from_slice(b"peercid0"),
            );
            let mut close = qbase::frame::ConnectionCloseFrame::from(crate::Error::from(
                QuicError::with_default_fty(ErrorKind::ConnectionRefused, "peer closed"),
            ));
            let journal = ArcSentJournal::default();
            let mut crypto = (
                qbase::frame::CryptoFrame::new(0u32.into(), 4u32.into()),
                b"data".as_slice(),
            );
            let bytes = if epoch == Epoch::Initial {
                seal(
                    header.initial(vec![]),
                    &peer_keys.sealing,
                    &journal,
                    [&mut crypto, &mut close],
                )
            } else {
                seal(
                    header.handshake(),
                    &peer_keys.sealing,
                    &journal,
                    [&mut crypto, &mut close],
                )
            }
            .unwrap();
            receive_bytes(bytes, space.clone(), &paths, &path).await;
            let mut received = [0; 4];
            tokio::time::timeout(
                Duration::from_secs(1),
                space.crypto.reader().read_exact(&mut received),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&received, b"data");
            let reason = tokio::time::timeout(Duration::from_secs(1), paths.close_reason())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(matches!(reason, CloseReason::Peer(frame) if frame == close));
            assert!(matches!(
                &*initial.terminator.lock_guard(),
                Terminator::Draining { frame, .. } if frame == &close
            ));
            paths.retire_all();
        }
    }
}

#[tokio::test]
async fn handshake_reception_admits_unknown_paths_only_after_authentication() {
    for role in [Role::Client, Role::Server] {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            let (paths, first, _) = paths(role);
            for path in paths.snapshot() {
                paths.remove(&path);
            }
            assert!(paths.snapshot().is_empty());

            receive_ping(role, epoch, true, &paths, &first).await;
            assert!(paths.snapshot().is_empty(), "forged packet admitted a path");

            receive_ping(role, epoch, false, &paths, &first).await;
            let admitted = paths.snapshot();
            assert_eq!(admitted.len(), 1);
            assert_eq!(admitted[0].pathway, first.pathway);
            assert!(!Arc::ptr_eq(&admitted[0], &first));
            if epoch == Epoch::Initial {
                assert!(matches!(
                    admitted[0].state(),
                    qtransport::path::PathState::AmplifyGuard {
                        rcvd_bytes: 1200,
                        sent_bytes: 0,
                    }
                ));
            }
            paths.retire_all();
        }
    }
}

#[tokio::test]
async fn only_authenticated_initial_packets_update_the_peer_cid() {
    for role in [Role::Client, Role::Server] {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            for corrupt in [true, false] {
                let (paths, first, _) = paths(role);
                receive_ping(role, epoch, corrupt, &paths, &first).await;
                assert_eq!(
                    paths.phase().get().dcid(),
                    ConnectionId::from_slice(if !corrupt && epoch == Epoch::Initial {
                        b"peercid0"
                    } else {
                        b"original"
                    })
                );
                paths.retire_all();
            }
        }
    }
}

#[tokio::test]
async fn client_selects_authenticated_initial_or_handshake_instead_of_first_added_path() {
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        let (paths, first, second) = paths(Role::Client);
        let original_dcid = paths.phase().get().dcid();
        assert_eq!(
            (first.selected(), second.selected()),
            (Path::MP_INITIAL, Path::MP_INITIAL)
        );
        receive_ping(Role::Client, epoch, true, &paths, &first).await;
        assert_eq!(
            (first.selected(), second.selected()),
            (Path::MP_INITIAL, Path::MP_INITIAL)
        );
        assert_eq!(paths.phase().get().dcid(), original_dcid);
        receive_ping(Role::Client, epoch, false, &paths, &second).await;
        assert_eq!(
            (first.selected(), second.selected()),
            (Path::SUSPEND, Path::SELECTED)
        );
        if epoch == Epoch::Initial {
            assert_eq!(
                paths.phase().get().dcid(),
                ConnectionId::from_slice(b"peercid0")
            );
        }
        receive_ping(Role::Client, epoch, false, &paths, &first).await;
        assert_eq!(
            (first.selected(), second.selected()),
            (Path::SUSPEND, Path::SELECTED)
        );
        paths.retire_all();
    }
}

#[tokio::test]
async fn server_initial_does_not_select_but_authenticated_handshake_does() {
    let (paths, first, second) = paths(Role::Server);
    receive_ping(Role::Server, Epoch::Initial, false, &paths, &first).await;
    assert_eq!(
        (first.selected(), second.selected()),
        (Path::MP_INITIAL, Path::MP_INITIAL)
    );
    receive_ping(Role::Server, Epoch::Handshake, true, &paths, &first).await;
    assert_eq!(
        (first.selected(), second.selected()),
        (Path::MP_INITIAL, Path::MP_INITIAL)
    );
    receive_ping(Role::Server, Epoch::Handshake, false, &paths, &second).await;
    assert_eq!(
        (first.selected(), second.selected()),
        (Path::SUSPEND, Path::SELECTED)
    );
    paths.retire_all();
}
#[tokio::test]
async fn server_selects_initial_ack_of_crypto_but_not_ack_of_ping() {
    use qcongestion::Transport as _;
    use tokio::io::AsyncWriteExt;

    let (paths, first, second) = paths(Role::Server);
    let space = Arc::new(Space::<ArcKeys>::new(
        Epoch::Initial,
        ArcKeys::new(Arc::new(keys(true))),
    ));
    let server_keys = keys(true);
    first.validate();
    let header = || {
        LongHeaderBuilder::with_cid(
            ConnectionId::from_slice(b"peercid0"),
            ConnectionId::from_slice(b"localcid"),
        )
    };
    space
        .crypto
        .writer()
        .write_all(b"server hello")
        .await
        .unwrap();
    let mut ping = PingFrame;
    let packet = seal(
        header().initial(vec![]),
        &server_keys.sealing,
        &space.sent_journal,
        [&mut ping],
    )
    .unwrap();
    drop(packet);
    let mut crypto = space.crypto.outgoing();
    let packet = seal(
        header().initial(vec![]),
        &server_keys.sealing,
        &space.sent_journal,
        [&mut crypto],
    )
    .unwrap();
    drop(packet);
    for pn in [0, 1] {
        space
            .sent_journal
            .on_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
    }
    let client_keys = keys(false);
    let journal = ArcSentJournal::default();
    for pn in [0u32, 1] {
        let mut ack = AckFrame::new(pn.into(), 0u32.into(), 0u32.into(), vec![], None);
        let packet = seal(
            header().initial(vec![]),
            &client_keys.sealing,
            &journal,
            [&mut ack],
        )
        .unwrap();
        receive_bytes(
            BytesMut::from(packet.as_ref()),
            space.clone(),
            &paths,
            &second,
        )
        .await;
        assert_eq!(
            (first.selected(), second.selected()),
            if pn == 1 {
                (Path::SUSPEND, Path::SELECTED)
            } else {
                (Path::MP_INITIAL, Path::MP_INITIAL)
            }
        );
    }
    assert!(second.cc.need_ack(Epoch::Initial).is_none());
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn handshake_packets_update_shared_idle_and_only_effective_payload_starts_heartbeat() {
    use qbase::{frame::CryptoFrame, packet::Package, time::heartbeat::ArcHeartbeat};
    use tokio::time::Instant;

    for epoch in [Epoch::Initial, Epoch::Handshake] {
        for kind in 0..3 {
            let phase = ArcConnPhase::initial(crate::common::initial_phase(
                Role::Server,
                ConnectionId::from_slice(b"localcid"),
                ConnectionId::from_slice(b"original"),
                keys(true),
            ));
            let paths = Paths::new(
                Role::Server,
                phase,
                Duration::from_secs(5),
                Duration::from_secs(60),
            );
            let link = Link::new(
                "127.0.0.1:30001".parse().unwrap(),
                "127.0.0.1:30002".parse().unwrap(),
            );
            let path = Arc::new(Path::new(
                link.into(),
                paths.handshake.clone(),
                ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
                paths.phase().get().trackers(),
            ));
            paths
                .entries
                .lock()
                .unwrap()
                .insert(path.pathway, path.clone());
            let space = Arc::new(Space::new(epoch, ArcKeys::new(Arc::new(keys(true)))));
            let pn = space.next_pn().unwrap().0;
            space.on_assembled(pn, []);
            space.on_sent(
                [(pn, false)],
                Duration::from_secs(1),
                Duration::from_secs(3),
            );
            let mut ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
            let mut ping = PingFrame;
            let mut crypto = (CryptoFrame::new(0u32.into(), 1u32.into()), b"x".as_slice());
            let source: &mut dyn for<'b> Package<&'b mut BytesMut> = match kind {
                0 => &mut ack,
                1 => &mut ping,
                _ => &mut crypto,
            };
            let header = LongHeaderBuilder::with_cid(
                ConnectionId::from_slice(b"localcid"),
                ConnectionId::from_slice(b"peercid0"),
            );
            let peer = keys(false);
            let journal = ArcSentJournal::default();
            let bytes = if epoch == Epoch::Initial {
                seal(header.initial(vec![]), &peer.sealing, &journal, [source])
            } else {
                seal(header.handshake(), &peer.sealing, &journal, [source])
            }
            .unwrap();
            let start = Instant::now();
            receive_bytes(bytes, space, &paths, &path).await;
            let reason = paths.close_reason().await.unwrap().unwrap();
            assert!(
                matches!(reason, CloseReason::Internal(error) if error.reason() == "connection idle timeout")
            );
            assert_eq!(Instant::now() - start, Duration::from_secs(5));
            tokio::time::advance(Duration::from_secs(15)).await;
            assert_eq!(super::take_heartbeat(&path), kind == 2);
            paths.retire_all();
        }
    }
}
