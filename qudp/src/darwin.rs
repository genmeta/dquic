use std::{
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
};

use nix::{cmsg_space, sys::socket::SockaddrStorage};
use qbase::net::route::Line;

use super::{PacketInfo, ToSocketAddr, parse_cmsg};
use crate::UdpSocket;

pub(super) fn sendmsg(socket: &UdpSocket, slices: &[IoSlice<'_>], send_line: &Line) -> io::Result<usize> {
    use nix::{
        errno::Errno,
        sys::socket::{MsgFlags, SockaddrIn, SockaddrIn6, sendmsg},
    };
    let src = if send_line.src.ip().is_unspecified() {
        socket.io.local_addr()?
    } else {
        send_line.src
    };
    let packet_info = PacketInfo::new(src.ip(), socket.ifindex);
    let mut cmsgs = Vec::new();
    if let Some(info) = &packet_info {
        cmsgs.push(info.control_message());
    }

    let mut sent_packet = 0;
    for slice in slices.iter() {
        macro_rules! send_batch {
            ($ty:ty, $addr:expr) => {{
                let sock_addr = <$ty>::from($addr);
                loop {
                    match sendmsg(socket.io.as_raw_fd(), &[*slice], &cmsgs, MsgFlags::empty(), Some(&sock_addr)) {
                        Ok(_send_bytes) => {
                            sent_packet += 1;
                            break;
                        }
                        Err(_) if sent_packet > 0 => return Ok(sent_packet),
                        Err(Errno::EINTR) => continue,
                        Err(e @ (Errno::EAGAIN | Errno::ENOBUFS)) => {
                            return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }
            }};
        }

        match send_line.dst {
            SocketAddr::V4(v4) => send_batch!(SockaddrIn, v4),
            SocketAddr::V6(v6) => send_batch!(SockaddrIn6, v6),
        }
    }
    Ok(sent_packet)
}

pub(super) fn recvmsg(socket: &UdpSocket, bufs: &mut [IoSliceMut<'_>], recv_lines: &mut [Line]) -> io::Result<usize> {
    use nix::sys::socket::{MsgFlags, recvmsg};
    let mut cmsg_space = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
    let result = recvmsg::<SockaddrStorage>(socket.io.as_raw_fd(), bufs, Some(&mut cmsg_space), MsgFlags::empty());

    match result {
        Ok(recv_msg) => {
            if let Ok(cmsgs) = recv_msg.cmsgs() {
                for cmsg in cmsgs {
                    parse_cmsg(cmsg, &mut recv_lines[0]);
                }
            }
            recv_lines[0].dst.set_port(socket.local_addr()?.port());
            recv_lines[0].src = recv_msg.address.unwrap().to_socketaddr();
            recv_lines[0].seg_size = recv_msg.bytes as u16;
            Ok(1)
        }
        Err(e) => {
            if matches!(e, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                // actually, it's not an error, just a signal to retry
                return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
            }
            Err(e.into())
        }
    }
}
