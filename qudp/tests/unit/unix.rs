use std::net::Ipv6Addr;

use ::nix::sys::socket::ControlMessageOwned;

use super::*;
use crate::nix::parse_cmsg;

#[tokio::test]
async fn packet_info_sends_batches_with_explicit_or_bound_source_addresses() {
    for index in [0, crate::common::loopback_ifindex()] {
        for (bind, unspecified) in [("127.0.0.1:0", "0.0.0.0:0"), ("[::1]:0", "[::]:0")] {
            let peer = std::net::UdpSocket::bind(bind).unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
            let socket = UdpSocket::bind(bind.parse().unwrap(), index).unwrap();
            let local = socket.local_addr().unwrap();
            for source in [local, unspecified.parse().unwrap()] {
                let link = qbase::net::route::Link::new(source, peer.local_addr().unwrap());
                let line = Line::new(link, 64, None, 5);
                let buffers = [IoSlice::new(b"first"), IoSlice::new(b"other")];
                assert_eq!(socket.sendmsg(&buffers, &line).unwrap(), 2);
                for expected in [b"first", b"other"] {
                    let mut bytes = [0; 16];
                    let (size, source) = peer.recv_from(&mut bytes).unwrap();
                    assert_eq!(&bytes[..size], expected);
                    assert_eq!(source, local);
                }
            }
        }
    }
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn partial_batch_preserves_the_successful_prefix() -> std::io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        let socket = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let link = qbase::net::route::Link::new(socket.local_addr()?, peer.local_addr()?);
        let line = Line::new(link, 64, None, 4);
        let oversized = vec![0; u16::MAX as usize + 1];
        let buffers = [IoSlice::new(b"live"), IoSlice::new(&oversized)];

        assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(1), socket.send(&buffers, line)).await??, 1);
        let mut bytes = [0; 16];
        let (len, source) = tokio::time::timeout(std::time::Duration::from_secs(1), peer.recv_from(&mut bytes)).await??;
        assert_eq!(&bytes[..len], b"live");
        assert_eq!(source, socket.local_addr()?);
        assert_eq!(peer.try_recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
    Ok(())
}

#[test]
fn ipv6_link_local_packet_info_preserves_the_interface_scope() {
    let mut line = Line::default();
    let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let packet_info = libc::in6_pktinfo { ipi6_addr: libc::in6_addr { s6_addr: address.octets() }, ipi6_ifindex: 7 };

    parse_cmsg(ControlMessageOwned::Ipv6PacketInfo(packet_info), &mut line);

    let SocketAddr::V6(destination) = line.link.dst else {
        panic!("IPv6 packet info must produce an IPv6 destination");
    };
    assert_eq!(*destination.ip(), address);
    assert_eq!(destination.scope_id(), 7);
}
