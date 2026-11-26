use std::{io, io::IoSlice, sync::Arc, time::Duration};

use qbase::net::route::{Line, Link};
use qprotocol::{
    Dock, UdpSocket,
    protocol::{ForwardProtocol, QuicProtocol, StunProtocol},
    topology::Topology,
};

#[tokio::test]
async fn receive_delivers_every_segment_including_a_short_tail() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let quic = Arc::new(QuicProtocol::new());
        let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
        quic.on_receive(move |packet, _, link| {
            sent.send((packet, link)).unwrap();
        });
        let topology = Arc::new(Topology::new(Arc::new(StunProtocol::new()), Arc::new(ForwardProtocol::new()), quic));
        let dock = Dock::new(topology);
        let socket = dock.use_socket(bind.parse().unwrap())?;
        let peer = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let link = Link::new(peer.local_addr()?, socket.local_addr()?);
        let payload = b"\x40one\x40two\x40x";
        peer.send(&[IoSlice::new(payload)], Line::new(link, Line::DEFAULT_TTL, None, 4)).await?;

        let mut bytes = Vec::new();
        while bytes.len() < payload.len() {
            let (packet, received_link) = tokio::time::timeout(Duration::from_secs(1), received.recv()).await?.unwrap();
            assert_eq!(received_link, link.flip());
            // Without GSO this is one datagram; with GSO the boundaries must be preserved.
            assert!(matches!(packet.len(), 2 | 4 | 10));
            bytes.extend_from_slice(&packet);
        }
        assert_eq!(bytes, payload);
        assert!(received.try_recv().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn receive_delivers_quic_with_spin_bit_set() -> io::Result<()> {
    let quic = Arc::new(QuicProtocol::new());
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    quic.on_receive(move |packet, _, _| {
        sent.send(packet).unwrap();
    });
    let topology = Arc::new(Topology::new(Arc::new(StunProtocol::new()), Arc::new(ForwardProtocol::new()), quic));
    let dock = Dock::new(topology);
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap())?;
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), 0)?;
    let link = Link::new(peer.local_addr()?, socket.local_addr()?);
    // Short header, Spin Bit = 1, then an eight-byte marked dquic CID.
    let mut packet = [0; 40];
    packet[0] = 0x60;
    packet[1..9].copy_from_slice(b"\x80localid");
    peer.send(&[IoSlice::new(&packet)], Line::new(link, Line::DEFAULT_TTL, None, packet.len() as u16)).await?;
    let delivered = tokio::time::timeout(Duration::from_secs(1), received.recv()).await?.unwrap();
    assert_eq!(delivered, packet.as_slice());
    Ok(())
}

#[tokio::test]
async fn receive_accepts_a_full_burst_and_reuses_buffers() -> io::Result<()> {
    let quic = Arc::new(QuicProtocol::new());
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    quic.on_receive(move |packet, _, _| {
        sent.send(packet).unwrap();
    });
    let topology = Arc::new(Topology::new(Arc::new(StunProtocol::new()), Arc::new(ForwardProtocol::new()), quic));
    let dock = Dock::new(topology);
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap())?;
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), 0)?;
    let link = Link::new(peer.local_addr()?, socket.local_addr()?);
    for byte in [0x40, 0x41] {
        let payload = vec![byte; 1536 * 8];
        for packet in payload.chunks(1536) {
            peer.send(&[IoSlice::new(packet)], Line::new(link, Line::DEFAULT_TTL, None, 1536)).await?;
        }
        let mut bytes = Vec::new();
        while bytes.len() < payload.len() {
            let packet = tokio::time::timeout(Duration::from_secs(1), received.recv()).await?.unwrap();
            assert_eq!(packet.len(), 1536);
            bytes.extend_from_slice(&packet);
        }
        assert_eq!(bytes, payload);
        assert!(received.try_recv().is_err());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn receive_delivers_gro_aggregates_larger_than_a_send_burst() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let quic = Arc::new(QuicProtocol::new());
        let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
        quic.on_receive(move |packet, _, _| {
            sent.send(packet).unwrap();
        });
        let topology = Arc::new(Topology::new(Arc::new(StunProtocol::new()), Arc::new(ForwardProtocol::new()), quic));
        let dock = Dock::new(topology);
        let socket = dock.use_socket(bind.parse().unwrap())?;
        let peer = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let link = Link::new(peer.local_addr()?, socket.local_addr()?);
        for (segments, segment_size) in [(15, 1536), (32, 1536), (64, 1000)] {
            let mut payload = vec![0x40; segments * segment_size];
            for (index, packet) in payload.chunks_mut(segment_size).enumerate() {
                packet[1] = index as u8;
            }
            // Without offload, submit the same datagrams separately. With GSO,
            // one submission produces a GRO message larger than the old 12 KiB slot.
            let chunk_size = if qudp::MAX_GRO_SEGMENTS > 1 {
                payload.len()
            } else {
                segment_size
            };
            for chunk in payload.chunks(chunk_size) {
                peer.send(&[IoSlice::new(chunk)], Line::new(link, Line::DEFAULT_TTL, None, segment_size as u16)).await?;
            }
            for expected in payload.chunks(segment_size) {
                let packet = tokio::time::timeout(Duration::from_secs(1), received.recv()).await?.unwrap();
                assert_eq!(packet, expected);
            }
            assert!(received.try_recv().is_err());
        }
    }
    Ok(())
}
