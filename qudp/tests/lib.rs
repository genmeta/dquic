use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use bytes::BytesMut;
use qbase::net::route::Line;
use qudp::UdpSocket;

#[tokio::test(flavor = "current_thread")]
async fn ipv6_wildcard_socket_does_not_receive_ipv4_packets() -> io::Result<()> {
    let socket4 = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;
    let port = socket4.local_addr()?.port();

    let socket6 =
        std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    socket6.send_to(
        b"ping",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
    )?;

    let mut iovecs = [BytesMut::with_capacity(1500); 1];
    let mut lines = [Line::default(); 1];
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        socket4.receive(&mut iovecs, &mut lines),
    )
    .await;
    assert!(
        result.is_err(),
        "unexpected ipv4 datagram arrived on ipv6 wildcard socket: {result:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ipv4_and_ipv6_wildcard_sockets_can_bind_same_port() -> io::Result<()> {
    let v6 = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;
    let port = v6.local_addr()?.port();

    let v4 = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        port,
    )))?;

    assert!(matches!(v6.local_addr()?, SocketAddr::V6(_)));
    assert!(matches!(v4.local_addr()?, SocketAddr::V4(_)));
    Ok(())
}
