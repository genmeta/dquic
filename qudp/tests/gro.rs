#![cfg(all(feature = "udp_offload_opt", any(target_os = "linux", target_os = "android")))]

#[path = "support/offload.rs"]
mod offload;

use std::{io, net::SocketAddr, time::Duration};

use bytes::BytesMut;
use qbase::net::route::Line;
use qudp::UdpSocket;

#[tokio::test]
async fn receive_preserves_segment_boundaries_and_short_tails() -> io::Result<()> {
    for (bind, peer_bind) in [("127.0.0.1:0", "127.0.0.1:0"), ("[::1]:0", "[::1]:0"), ("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")] {
        let socket = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let peer = std::net::UdpSocket::bind(peer_bind)?;
        let other = std::net::UdpSocket::bind(peer_bind)?;
        let destination = SocketAddr::new(peer.local_addr()?.ip(), socket.local_addr()?.port());
        offload::send_segmented(&peer, destination, b"abcdEFGHij", 4)?;
        offload::send_segmented(&peer, destination, b"klmNOPqr", 3)?;
        other.send_to(b"ordinary", destination)?;
        let mut buffers = std::array::from_fn::<_, 8, _>(|_| BytesMut::zeroed(65_535));
        let mut lines = [Line::default(); 8];
        let count = tokio::time::timeout(Duration::from_secs(1), socket.receive(&mut buffers, &mut lines)).await??;
        assert_eq!(count, 3);
        assert_eq!((buffers[0].len(), lines[0].seg_size), (10, 4));
        assert_eq!((buffers[1].len(), lines[1].seg_size), (8, 3));
        let mut packets = Vec::new();
        for index in 0..count {
            assert_eq!(lines[index].dst, destination);
            assert_eq!(
                lines[index].src,
                if index == count - 1 {
                    other.local_addr()?
                } else {
                    peer.local_addr()?
                }
            );
            for packet in buffers[index].chunks(lines[index].seg_size as usize) {
                packets.push(packet.to_vec());
            }
        }
        assert_eq!(packets, [b"abcd".as_slice(), b"EFGH", b"ij", b"klm", b"NOP", b"qr", b"ordinary"]);
        assert_eq!(buffers[count].len(), 65_535);
    }
    Ok(())
}

#[tokio::test]
async fn truncated_gro_aggregate_is_discarded_and_later_datagrams_are_received() -> io::Result<()> {
    use std::io::IoSliceMut;

    use qudp::Io;

    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap(), 0)?;
        let peer = std::net::UdpSocket::bind(bind)?;
        let mut bytes = [0; 7];
        let mut lines = [Line::default()];
        offload::send_segmented(&peer, socket.local_addr()?, b"firstotherend", 5)?;
        {
            let mut buffers = [IoSliceMut::new(&mut bytes)];
            assert_eq!(socket.recvmsg(&mut buffers, &mut lines)?, 1);
            assert!(buffers[0].is_empty());
            assert_eq!(lines[0].seg_size, 5);
        }
        peer.send_to(b"live", socket.local_addr()?)?;
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        assert_eq!(socket.recvmsg(&mut buffers, &mut lines)?, 1);
        assert_eq!(&buffers[0][..], b"live");
        assert_eq!(lines[0].seg_size, 4);
        assert_eq!(lines[0].src, peer.local_addr()?);
    }
    Ok(())
}
