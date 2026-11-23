use std::{
    io::{self, IoSlice, IoSliceMut},
    os::fd::AsRawFd,
};

use ::nix::{
    cmsg_space,
    errno::Errno,
    sys::socket::{MsgFlags, SockaddrStorage, recvmsg as nix_recvmsg, sendmsg as nix_sendmsg},
};
use qbase::net::route::Line;

use super::{PacketInfo, ToSocketAddr, parse_cmsg};
use crate::UdpSocket;

pub(super) fn sendmsg(socket: &UdpSocket, slices: &[IoSlice<'_>], send_line: &Line) -> io::Result<usize> {
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

    let sock_addr = SockaddrStorage::from(send_line.dst);
    let mut sent_packet = 0;
    for slice in slices.iter() {
        loop {
            match nix_sendmsg(socket.io.as_raw_fd(), &[*slice], &cmsgs, MsgFlags::empty(), Some(&sock_addr)) {
                Ok(_) => break,
                Err(Errno::EINTR) => continue,
                Err(_) if sent_packet > 0 => return Ok(sent_packet),
                Err(e @ (Errno::EAGAIN | Errno::ENOBUFS)) => return Err(io::Error::new(io::ErrorKind::WouldBlock, e)),
                Err(e) => return Err(e.into()),
            }
        }
        sent_packet += 1;
    }
    Ok(sent_packet)
}

pub(super) fn recvmsg(socket: &UdpSocket, bufs: &mut [IoSliceMut<'_>], recv_lines: &mut [Line]) -> io::Result<usize> {
    let mut cmsg_space = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
    loop {
        match nix_recvmsg::<SockaddrStorage>(socket.io.as_raw_fd(), bufs, Some(&mut cmsg_space), MsgFlags::empty()) {
            Ok(recv_msg) => {
                if let Ok(cmsgs) = recv_msg.cmsgs() {
                    for cmsg in cmsgs {
                        parse_cmsg(cmsg, &mut recv_lines[0]);
                    }
                }
                recv_lines[0].dst.set_port(socket.local_addr()?.port());
                recv_lines[0].src = recv_msg.address.unwrap().to_socketaddr();
                recv_lines[0].seg_size = recv_msg.bytes as u16;
                return Ok(1);
            }
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
