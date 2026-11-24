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
