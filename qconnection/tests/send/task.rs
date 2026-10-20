use std::{sync::Arc, time::Duration};

use bytes::BytesMut;
use futures::FutureExt;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{Frame, FrameReader},
    net::{addr::EndpointAddr, route::Pathway},
    packet::{DataHeader, Packet as ParsedPacket, PacketReader, long},
    role::Role,
};
use qcongestion::Transport as _;
use qtransport::packet::CipherPacket;
use tokio::io::AsyncWriteExt;

use crate::common::{self, initial_keys as keys};

#[tokio::test(start_paused = true)]
async fn idle_sending_loop_waits_for_sources_and_exits_when_retired() {
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:30001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:30002".parse().unwrap()),
    );
    let path = paths.add_path(pathway);
    let watchdog = std::thread::spawn({
        let path = path.clone();
        move || {
            std::thread::sleep(Duration::from_millis(50));
            path.retire();
        }
    });
    tokio::task::yield_now().await;
    assert!(paths.get(&path.pathway).is_some());
    watchdog.join().unwrap();
    common::wait_for_sender_exit(&path).await;
    assert!(paths.snapshot().is_empty());
}

#[tokio::test(start_paused = true)]
async fn failed_submission_closes_crypto_and_waits_for_termination() {
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let space = crate::common::initial_space(&paths.spaces);
    space.crypto.writer().write_all(b"hello").await.unwrap();
    // No registered socket: collect succeeds, but submitting the batch fails.
    let path = paths.add_path(Pathway::new(
        EndpointAddr::direct("127.0.0.1:0".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
    ));
    paths.cids.select(&path.cid);
    common::wait_for_sender_exit(&path).await;
    assert!(paths.snapshot().is_empty());
    assert_eq!(path.state(), qtransport::path::PathState::Retired);

    assert!(
        space
            .crypto
            .writer()
            .write_all(b"after close")
            .await
            .is_err()
    );
    assert!(paths.terminator.clone().now_or_never().is_some());
}

#[tokio::test(start_paused = true)]
async fn submitting_an_ack_only_packet_starts_the_connection_idle_timer() {
    use qbase::net::route::{Line, Link};
    use qprotocol::{QuicProtocol, UdpSocket};
    use tokio::time::Instant;

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let paths = crate::common::initial_paths_with_timeouts(
        Role::Server,
        ConnectionId::from_slice(b"server00"),
        ConnectionId::from_slice(b"original"),
        keys(true),
        Duration::from_secs(5),
        Duration::ZERO,
    );
    let space = crate::common::initial_space(&paths.spaces);
    let path = paths.add_path(Pathway::new(
        local,
        EndpointAddr::direct(peer.local_addr().unwrap()),
    ));
    path.validate();
    paths.cids.select(&path.cid);
    space
        .rcvd_journal
        .on_rcvd_pn(0, true, Duration::from_secs(1));
    path.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    let start = Instant::now();
    let mut buffers = [BytesMut::zeroed(1500)];
    let mut lines = [Line::new(
        Link::new(local.addr(), peer.local_addr().unwrap()),
        64,
        None,
        1500,
    )];
    tokio::time::timeout(
        Duration::from_secs(1),
        peer.receive(&mut buffers, &mut lines),
    )
    .await
    .unwrap()
    .unwrap();
    let received = Instant::now();
    buffers[0].truncate(lines[0].seg_size as usize);
    let ParsedPacket::Data(packet) = PacketReader::new(buffers[0].clone(), 8)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
        panic!()
    };
    let opened = CipherPacket::new(header, packet.bytes, packet.offset)
        .decrypt_long_packet(&keys(false).opening, |_| Ok(0))
        .unwrap()
        .unwrap();
    use qbase::packet::GetType;
    assert!(
        FrameReader::new(opened.body(), opened.get_type())
            .all(|frame| matches!(frame.unwrap().0, Frame::Ack(_) | Frame::Padding(_)))
    );
    let reason = paths.terminator.clone().await;
    assert!(
        matches!(reason, qconnection::Error::Quic(error) if error.reason() == "connection idle timeout")
    );
    assert!(Instant::now() >= start + Duration::from_secs(5));
    assert!(Instant::now() <= received + Duration::from_secs(8));
    assert!(!common::take_heartbeat(&path));
    path.retire();
    common::wait_for_sender_exit(&path).await;
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn credit_blocked_sender_keeps_path_until_termination() {
    let paths = crate::common::initial_paths(
        Role::Server,
        ConnectionId::from_slice(b"localcid"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    );
    let terminator = paths.terminator.clone();
    let path = paths.add_path(Pathway::new(
        EndpointAddr::direct("127.0.0.1:49001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:49002".parse().unwrap()),
    ));
    tokio::task::yield_now().await;
    let pto = path.cc.pto_base(Epoch::Data);
    terminator.close(
        qconnection::CloseReason::Internal(QuicError::with_default_fty(
            ErrorKind::Internal,
            "closed while credit blocked",
        )),
        pto,
    );
    tokio::task::yield_now().await;
    assert!(paths.get(&path.pathway).is_some());
    assert_ne!(path.state(), qtransport::path::PathState::Retired);
    tokio::time::advance(3 * pto).await;
    terminator.await;
    tokio::task::yield_now().await;
    assert!(paths.get(&path.pathway).is_none());
    assert_eq!(path.state(), qtransport::path::PathState::Retired);
}

#[tokio::test(start_paused = true)]
async fn closed_source_does_not_stop_sending_close_responses_before_termination() {
    use qbase::{
        error::AppError,
        net::route::{Line, Link},
        packet::GetType,
    };
    use qprotocol::{QuicProtocol, UdpSocket};

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let path = paths.add_path(Pathway::new(
        local,
        EndpointAddr::direct(peer.local_addr().unwrap()),
    ));
    paths.cids.select(&path.cid);
    let terminator = paths.terminator.clone();
    let error: qconnection::Error = AppError::new(42u32.into(), "closed").into();
    // Component failure is observable to its writer, not a fresh send-task error.
    crate::common::initial_space(&paths.spaces)
        .crypto
        .on_error(&error);
    tokio::task::yield_now().await;
    assert!(paths.get(&path.pathway).is_some());
    assert!(
        crate::common::observe_close(&terminator)
            .notified()
            .is_none()
    );
    let pto = Duration::from_secs(10);
    terminator.close(error.clone().into(), pto);
    for retransmit in [false, true] {
        if retransmit {
            for _ in 0..5 {
                terminator.on_rcvd_packet(tokio::time::Instant::now());
            }
        }
        let mut bytes = [BytesMut::zeroed(1500)];
        let mut lines = [Line::new(
            Link::new(local.addr(), peer.local_addr().unwrap()),
            64,
            None,
            1500,
        )];
        tokio::time::timeout(Duration::from_secs(1), peer.receive(&mut bytes, &mut lines))
            .await
            .unwrap()
            .unwrap();
        bytes[0].truncate(lines[0].seg_size as usize);
        let ParsedPacket::Data(packet) = PacketReader::new(bytes[0].clone(), 8)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
            panic!()
        };
        let opened = CipherPacket::new(header, packet.bytes, packet.offset)
            .decrypt_long_packet(&keys(true).opening, |pn| Ok(pn.decode(0)))
            .unwrap()
            .unwrap();
        let decoded = FrameReader::new(opened.body(), opened.get_type())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            decoded
                .iter()
                .any(|(frame, _)| matches!(frame, Frame::Close(_)))
        );
        assert!(
            decoded
                .iter()
                .all(|(frame, _)| matches!(frame, Frame::Close(_) | Frame::Padding(_)))
        );
        assert!(paths.get(&path.pathway).is_some());
    }
    tokio::time::advance(3 * pto).await;
    common::wait_for_sender_exit(&path).await;
    assert_eq!(terminator.await, error);
    assert!(paths.snapshot().is_empty());
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn sending_runs_two_woken_bursts_and_exits_on_path_failure() {
    use qbase::{
        net::route::{Line, Link},
        packet::GetType,
    };
    use qprotocol::{QuicProtocol, UdpSocket};

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let space = crate::common::initial_space(&paths.spaces);
    let path = paths.add_path(Pathway::new(
        local,
        EndpointAddr::direct(peer.local_addr().unwrap()),
    ));
    paths.cids.select(&path.cid);
    for message in [b"first".as_slice(), b"second".as_slice()] {
        tokio::task::yield_now().await;
        assert!(paths.get(&path.pathway).is_some());
        space.crypto.writer().write_all(message).await.unwrap();
        let mut bytes = [BytesMut::zeroed(1500)];
        let mut lines = [Line::new(
            Link::new(local.addr(), peer.local_addr().unwrap()),
            64,
            None,
            1500,
        )];
        tokio::time::timeout(Duration::from_secs(1), peer.receive(&mut bytes, &mut lines))
            .await
            .unwrap()
            .unwrap();
        bytes[0].truncate(lines[0].seg_size as usize);
        let ParsedPacket::Data(packet) = PacketReader::new(bytes[0].clone(), 8)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!("expected an Initial packet");
        };
        let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
            panic!()
        };
        let opened = CipherPacket::new(header, packet.bytes, packet.offset)
            .decrypt_long_packet(&keys(true).opening, |pn| Ok(pn.decode(0)))
            .unwrap()
            .unwrap();
        assert!(FrameReader::new(opened.body(), opened.get_type()).any(
            |frame| matches!(frame.unwrap().0, Frame::Crypto(_, bytes) if bytes.as_ref() == message)
        ));
    }
    path.retire();
    common::wait_for_sender_exit(&path).await;
    assert!(paths.snapshot().is_empty());
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}
