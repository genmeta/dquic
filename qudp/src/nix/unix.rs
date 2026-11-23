use std::{
    io::{self, IoSlice},
    os::fd::AsRawFd,
};

use ::nix::sys::socket::SockaddrStorage;
use qbase::net::route::Line;

#[cfg(any(target_os = "android", target_os = "linux"))]
use super::PacketInfo;
use super::{ToSocketAddr, parse_cmsg};
use crate::UdpSocket;

pub(super) fn sendmsg(socket: &UdpSocket, buffers: &[IoSlice<'_>], line: &Line) -> io::Result<usize> {
    use ::nix::{
        errno::Errno,
        sys::socket::{ControlMessage, MsgFlags, MultiHeaders, sendmmsg},
    };

    use crate::BATCH_SIZE;
    let slices: Vec<_> = buffers.iter().take(BATCH_SIZE).map(std::slice::from_ref).collect();

    let batch_size = slices.len();
    if batch_size == 0 {
        return Ok(0);
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let packet_info = {
        let src = if line.src.ip().is_unspecified() {
            socket.io.local_addr()?
        } else {
            line.src
        };
        PacketInfo::new(src.ip(), socket.ifindex)
    };
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let (cmsgs, space) = {
        use ::nix::cmsg_space;

        let mut cmsgs = Vec::new();
        #[cfg(feature = "gso")]
        cmsgs.push(ControlMessage::UdpGsoSegments(&line.seg_size));
        if let Some(info) = &packet_info {
            cmsgs.push(info.control_message());
        }

        let space = match (cfg!(feature = "gso"), &packet_info) {
            (false, None) => None,
            (true, None) => Some(cmsg_space!(libc::c_int)),
            (false, Some(PacketInfo::V4(_))) => Some(cmsg_space!(libc::in_pktinfo)),
            (false, Some(PacketInfo::V6(_))) => Some(cmsg_space!(libc::in6_pktinfo)),
            (true, Some(PacketInfo::V4(_))) => Some(cmsg_space!(libc::c_int, libc::in_pktinfo)),
            (true, Some(PacketInfo::V6(_))) => Some(cmsg_space!(libc::c_int, libc::in6_pktinfo)),
        };
        (cmsgs, space)
    };
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    let (cmsgs, space) = (Vec::new(), None);

    let sock_addr = SockaddrStorage::from(line.dst);
    let addrs = vec![Some(sock_addr); BATCH_SIZE];
    let mut data = MultiHeaders::<SockaddrStorage>::preallocate(BATCH_SIZE, space);
    loop {
        match sendmmsg(socket.io.as_raw_fd(), &mut data, &slices, &addrs, &cmsgs, MsgFlags::empty()) {
            Ok(ret) => return Ok(ret.count()),
            Err(Errno::EINTR) => continue,
            Err(e @ (Errno::EAGAIN | Errno::ENOBUFS)) => return Err(io::Error::new(io::ErrorKind::WouldBlock, e)),
            Err(e) => return Err(e.into()),
        }
    }
}

pub(super) fn recvmsg(socket: &UdpSocket, bufs: &mut [IoSliceMut<'_>], recv_lines: &mut [Line]) -> io::Result<usize> {
    use ::nix::{
        cmsg_space,
        errno::Errno,
        sys::socket::{MsgFlags, MultiHeaders, recvmmsg},
    };

    use crate::BATCH_SIZE;
    let cmsg_buffer = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
    let mut data = MultiHeaders::<SockaddrStorage>::preallocate(BATCH_SIZE, Some(cmsg_buffer));

    loop {
        let mut msgs: Vec<_> = bufs.iter_mut().map(|buf| [IoSliceMut::new(&mut buf[..])]).collect();
        let results = match recvmmsg(socket.io.as_raw_fd(), &mut data, &mut msgs, MsgFlags::MSG_DONTWAIT, None) {
            Ok(results) => results,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        };
        let local_port = socket.local_addr()?.port();
        let mut count = 0;

        for recv_msg in results {
            let src_addr = recv_msg.address.unwrap().to_socketaddr();
            let link = Link::new(src_addr, recv_lines[count].dst);
            let mut recv_line = Line { link, ttl: 0, ecn: None, seg_size: recv_msg.bytes as u16 };
            for cmsg in recv_msg.cmsgs().unwrap() {
                parse_cmsg(cmsg, &mut recv_line);
            }
            recv_line.dst.set_port(local_port);
            recv_lines[count] = recv_line;
            count += 1;
        }

        return Ok(count);
    }
}
