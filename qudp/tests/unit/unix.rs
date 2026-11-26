use std::net::Ipv6Addr;

use ::nix::sys::socket::ControlMessageOwned;

use super::*;
use crate::nix::parse_cmsg;

#[tokio::test]
async fn batches_stop_at_eight_and_resume_without_duplicates() -> std::io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let peer = std::net::UdpSocket::bind(bind)?;
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        let socket = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let line = Line::new(qbase::net::route::Link::new(socket.local_addr()?, peer.local_addr()?), 64, None, 1);
        let packets = std::array::from_fn::<_, 9, _>(|i| [i as u8]);
        let buffers = packets.each_ref().map(|packet| IoSlice::new(packet));

        for length in [0, 1, 8, 9] {
            let sent = socket.sendmsg(&buffers[..length], &line)?;
            assert_eq!(sent, length.min(8));
            if sent < length {
                assert_eq!(socket.sendmsg(&buffers[sent..length], &line)?, length - sent);
            }
            for expected in &packets[..length] {
                let mut bytes = [0; 4];
                let (len, source) = peer.recv_from(&mut bytes)?;
                assert_eq!(&bytes[..len], expected);
                assert_eq!(source, socket.local_addr()?);
            }
            peer.set_nonblocking(true)?;
            assert_eq!(peer.recv_from(&mut [0; 4]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            peer.set_nonblocking(false)?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn receive_batches_respect_buffer_and_metadata_capacity() -> std::io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for capacity in [2, 8] {
            let socket = UdpSocket::bind(bind.parse().unwrap(), 0)?;
            let peer = std::net::UdpSocket::bind(bind)?;
            for index in 0..9 {
                peer.send_to(&[index], socket.local_addr()?)?;
            }
            let mut packets = [[0; 4]; 9];
            let mut buffers = packets.each_mut().map(|packet| IoSliceMut::new(packet));
            let mut lines = [Line::default(); 8];
            assert_eq!(socket.recvmsg(&mut [], &mut lines)?, 0);
            assert_eq!(socket.recvmsg(&mut buffers, &mut [])?, 0);
            let mut first = 0;
            while first < 9 {
                let count = socket.recvmsg(&mut buffers, &mut lines[..capacity])?;
                assert_eq!(count, capacity.min(9 - first));
                for index in 0..count {
                    assert_eq!(&buffers[index][..lines[index].seg_size as usize], &[(first + index) as u8]);
                    assert_eq!(lines[index].src, peer.local_addr()?);
                    assert_eq!(lines[index].dst, socket.local_addr()?);
                }
                first += count;
            }
            assert_eq!(socket.recvmsg(&mut buffers, &mut lines).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn receive_preserves_empty_datagrams_and_discards_truncated_payloads() -> std::io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let peer = std::net::UdpSocket::bind(bind)?;
        peer.send_to(b"", socket.local_addr()?)?;
        peer.send_to(b"longer than the buffer", socket.local_addr()?)?;
        let mut packets = [[0; 4]; 2];
        let mut buffers = packets.each_mut().map(|packet| IoSliceMut::new(packet));
        let mut lines = [Line::default(); 2];

        assert_eq!(socket.recvmsg(&mut buffers, &mut lines)?, 2);
        assert_eq!(lines[0].seg_size, 0);
        assert_eq!(lines[1].seg_size, 0);
        assert!(buffers[1].is_empty());
        for line in lines {
            assert_eq!(line.src, peer.local_addr()?);
            assert_eq!(line.dst, socket.local_addr()?);
        }
    }
    Ok(())
}

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
