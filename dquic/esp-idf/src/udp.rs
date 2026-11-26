use std::{io::IoSlice, time::Duration};

use bytes::BytesMut;
use dquic::{
    UdpSocket,
    qbase::net::route::{Line, Link},
};
use tokio::time::timeout;

pub async fn check() -> Result<(), dquic_esp_idf::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0".parse()?, 0)?;
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let line = Line::new(Link::new(socket.local_addr()?, peer.local_addr()?), 64, None, 3);
    let messages = [IoSlice::new(b"one"), IoSlice::new(b"two")];
    let mut sent = 0;
    while sent < messages.len() {
        sent += timeout(Duration::from_secs(5), socket.send(&messages[sent..], line)).await??;
    }
    let mut buffer = [0; 16];
    for expected in [b"one", b"two"] {
        let (length, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buffer)).await??;
        assert_eq!(&buffer[..length], expected);
    }
    let mut packets = [BytesMut::zeroed(32)];
    let mut lines = [Line::default()];
    peer.send_to(&[7; 64], socket.local_addr()?).await?;
    assert_eq!(timeout(Duration::from_secs(5), socket.receive(&mut packets, &mut lines)).await??, 1);
    assert!(packets[0].is_empty(), "truncated datagram must be dropped");
    packets[0].resize(32, 0);
    peer.send_to(b"after truncation", socket.local_addr()?).await?;
    assert_eq!(timeout(Duration::from_secs(5), socket.receive(&mut packets, &mut lines)).await??, 1);
    assert_eq!(packets[0].as_ref(), b"after truncation");
    assert_eq!(lines[0].link, Link::new(peer.local_addr()?, socket.local_addr()?));
    println!("PASS: qudp datagram boundaries, truncation and buffer reuse");
    Ok(())
}
