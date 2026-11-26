use std::{io, time::Duration};

use bytes::BytesMut;
use qbase::net::route::Line;
use qudp::UdpSocket;

#[tokio::test]
async fn truncated_datagrams_are_discarded_and_receive_buffers_can_be_reused() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        let mut buffers = [BytesMut::zeroed(1536)];
        let mut lines = [Line::default()];
        peer.send_to(&[0x40; 2048], socket.local_addr()?).await?;
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), socket.receive(&mut buffers, &mut lines)).await??, 1);
        assert!(buffers[0].is_empty());

        buffers[0].resize(1536, 0);
        peer.send_to(b"live", socket.local_addr()?).await?;
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), socket.receive(&mut buffers, &mut lines)).await??, 1);
        assert_eq!(buffers[0], b"live".as_slice());
        assert_eq!(lines[0].src, peer.local_addr()?);
        assert_eq!(lines[0].dst, socket.local_addr()?);
    }
    Ok(())
}
