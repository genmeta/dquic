use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use bytes::BytesMut;
use qbase::net::route::{Line, Link};
use qudp::UdpSocket;

#[tokio::test(flavor = "current_thread")]
async fn ipv6_wildcard_socket_does_not_receive_ipv4_packets() -> io::Result<()> {
    let socket4 = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))?;
    let port = socket4.local_addr()?.port();

    let socket6 = std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    socket6.send_to(b"ping", SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))?;

    let mut iovecs = [BytesMut::with_capacity(1500); 1];
    let mut lines = [Line::default(); 1];
    let result = tokio::time::timeout(Duration::from_millis(200), socket4.receive(&mut iovecs, &mut lines)).await;
    assert!(result.is_err(), "unexpected ipv4 datagram arrived on ipv6 wildcard socket: {result:?}");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ipv4_and_ipv6_wildcard_sockets_can_bind_same_port() -> io::Result<()> {
    let v6 = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))?;
    let port = v6.local_addr()?.port();

    let v4 = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)))?;

    assert!(matches!(v6.local_addr()?, SocketAddr::V6(_)));
    assert!(matches!(v4.local_addr()?, SocketAddr::V4(_)));
    Ok(())
}

#[tokio::test]
async fn unreachable_peer_does_not_stop_reception_on_the_shared_socket() -> io::Result<()> {
    use std::io::IoSlice;

    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap())?;
        let local = socket.local_addr()?;
        let closed = std::net::UdpSocket::bind(bind)?;
        let unreachable = closed.local_addr()?;
        drop(closed);

        // A failed probe must not turn the peer's ICMP reply into a socket failure.
        let probe = [IoSlice::new(b"probe")];
        assert_eq!(socket.send(&probe, Line::new(Link::new(local, unreachable), 64, None, 5)).await?, 1);
        let mut packets = [BytesMut::zeroed(1500)];
        let mut lines = [Line::default()];
        let result = tokio::time::timeout(Duration::from_millis(100), socket.receive(&mut packets, &mut lines)).await;
        assert!(result.is_err(), "an unreachable peer must leave reception pending: {result:?}");

        let peer = tokio::net::UdpSocket::bind(bind).await?;
        peer.send_to(b"live", local).await?;
        let received = tokio::time::timeout(Duration::from_secs(1), socket.receive(&mut packets, &mut lines)).await??;
        assert_eq!(received, 1);
        assert_eq!(&packets[0][..lines[0].seg_size as usize], b"live");
        assert_eq!(lines[0].link, Link::new(peer.local_addr()?, local));
    }
    Ok(())
}
