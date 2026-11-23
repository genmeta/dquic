mod common;

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use bytes::BytesMut;
use qbase::net::route::{Line, Link};
use qudp::UdpSocket;

#[tokio::test]
async fn interface_selection_sends_and_receives_from_bound_or_wildcard_addresses() -> io::Result<()> {
    use std::io::IoSlice;

    for ifindex in [0, crate::common::loopback_ifindex()] {
        for (bind, peer_bind) in
            [("127.0.0.1:0", "127.0.0.1:0"), ("0.0.0.0:0", "127.0.0.1:0"), ("[::1]:0", "[::1]:0"), ("[::]:0", "[::1]:0")]
        {
            eprintln!("bind={bind}, ifindex={ifindex}");
            let socket = UdpSocket::bind(bind.parse().unwrap(), ifindex)?;
            assert_eq!(socket.ifindex(), ifindex);
            let peer = tokio::net::UdpSocket::bind(peer_bind).await?;
            let local = socket.local_addr()?;
            let source = SocketAddr::new(peer.local_addr()?.ip(), local.port());
            let line = Line::new(Link::new(local, peer.local_addr()?), 64, None, 5);
            assert_eq!(socket.send(&[IoSlice::new(b"first"), IoSlice::new(b"other")], line).await?, 2);
            for expected in [b"first", b"other"] {
                let mut bytes = [0; 16];
                let (size, received_source) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut bytes)).await??;
                assert_eq!(&bytes[..size], expected);
                assert_eq!(received_source, source);
            }

            peer.send_to(b"reply", source).await?;
            let mut packets = [BytesMut::zeroed(128)];
            let mut lines = [Line::default()];
            assert_eq!(tokio::time::timeout(Duration::from_secs(1), socket.receive(&mut packets, &mut lines)).await??, 1);
            assert_eq!(&packets[0][..lines[0].seg_size as usize], b"reply");
        }
    }
    Ok(())
}

// Windows can deliver loopback packets without validating the interface index.
#[cfg(unix)]
#[tokio::test]
async fn invalid_egress_does_not_filter_reception_or_fall_back_when_sending() -> io::Result<()> {
    use std::io::IoSlice;

    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap(), u32::MAX)?;
        let local = socket.local_addr()?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        peer.send_to(b"live", local).await?;
        let mut packets = [BytesMut::zeroed(1500)];
        let mut lines = [Line::default()];
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), socket.receive(&mut packets, &mut lines)).await??, 1);
        assert_eq!(&packets[0][..lines[0].seg_size as usize], b"live");

        let line = Line::new(Link::new(local, peer.local_addr()?), 64, None, 5);
        let buffers = [IoSlice::new(b"probe")];
        let result = tokio::time::timeout(Duration::from_secs(1), socket.send(&buffers, line)).await?;
        assert!(result.is_err(), "{bind}: a missing interface must not fall back to another egress: {result:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ipv6_wildcard_socket_does_not_receive_ipv4_packets() -> io::Result<()> {
    let socket4 = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)), crate::common::loopback_ifindex())?;
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
    let v6 = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)), crate::common::loopback_ifindex())?;
    let port = v6.local_addr()?.port();

    let v4 = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)), crate::common::loopback_ifindex())?;

    assert!(matches!(v6.local_addr()?, SocketAddr::V6(_)));
    assert!(matches!(v4.local_addr()?, SocketAddr::V4(_)));
    Ok(())
}

#[tokio::test]
async fn unreachable_peer_does_not_stop_reception_on_the_shared_socket() -> io::Result<()> {
    use std::io::IoSlice;

    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap(), crate::common::loopback_ifindex())?;
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
