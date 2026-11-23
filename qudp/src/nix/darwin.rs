use std::{
    io::{self, IoSlice, IoSliceMut},
    mem::{size_of, size_of_val},
    os::fd::AsRawFd,
    ptr,
};

use ::nix::{
    cmsg_space,
    errno::Errno,
    sys::socket::{MsgFlags, SockaddrLike, SockaddrStorage, recvmsg as nix_recvmsg},
};
use qbase::net::route::Line;

use super::{ExtractSocketAddr, PacketInfo, parse_cmsg};
use crate::{BATCH_SIZE, UdpSocket};

// CMSG_SPACE only computes the header, payload and padding size.
const CONTROL_BUFFER_SIZE: usize = unsafe { libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _) as usize };

#[repr(C)]
union ControlBuffer {
    _align: libc::cmsghdr,
    bytes: [u8; CONTROL_BUFFER_SIZE],
}

pub(super) fn sendmsg(socket: &UdpSocket, slices: &[IoSlice<'_>], send_line: &Line) -> io::Result<usize> {
    let src = if send_line.src.ip().is_unspecified() {
        socket.io.local_addr()?
    } else {
        send_line.src
    };
    let packet_info = PacketInfo::new(src.ip(), socket.ifindex);
    let sock_addr = SockaddrStorage::from(send_line.dst);
    let mut control = ControlBuffer { bytes: [0; CONTROL_BUFFER_SIZE] };
    let mut iov = [libc::iovec { iov_base: ptr::null_mut(), iov_len: 0 }];
    let mut msg = libc::msghdr {
        msg_name: sock_addr.as_ptr().cast_mut().cast(),
        msg_namelen: sock_addr.len(),
        msg_iov: iov.as_mut_ptr(),
        msg_iovlen: 1,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    if let Some(info) = &packet_info {
        let (level, kind, data, len) = match info {
            PacketInfo::V4(info) => (libc::IPPROTO_IP, libc::IP_PKTINFO, ptr::from_ref(info).cast::<u8>(), size_of_val(info)),
            PacketInfo::V6(info) => (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, ptr::from_ref(info).cast::<u8>(), size_of_val(info)),
        };
        // Both payloads fit the aligned, zeroed buffer; its address stays valid for the batch.
        unsafe {
            let header = control.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
            *header = libc::cmsghdr { cmsg_len: libc::CMSG_LEN(len as _), cmsg_level: level, cmsg_type: kind };
            ptr::copy_nonoverlapping(data, libc::CMSG_DATA(header), len);
            msg.msg_control = header.cast();
            msg.msg_controllen = libc::CMSG_SPACE(len as _);
        }
    }

    let fd = socket.io.as_raw_fd();
    let mut sent_packet = 0;
    for slice in slices.iter().take(BATCH_SIZE) {
        iov[0].iov_base = slice.as_ptr().cast_mut().cast();
        iov[0].iov_len = slice.len();
        loop {
            // The address, iovec, control buffer and payload remain valid throughout the call.
            match Errno::result(unsafe { libc::sendmsg(fd, &msg, 0) }) {
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
    if bufs.is_empty() || recv_lines.is_empty() {
        return Ok(0);
    }
    let mut cmsg_space = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
    loop {
        match nix_recvmsg::<SockaddrStorage>(socket.io.as_raw_fd(), &mut bufs[..1], Some(&mut cmsg_space), MsgFlags::empty()) {
            Ok(recv_msg) => {
                if let Ok(cmsgs) = recv_msg.cmsgs() {
                    for cmsg in cmsgs {
                        parse_cmsg(cmsg, &mut recv_lines[0]);
                    }
                }
                recv_lines[0].dst.set_port(socket.local_addr()?.port());
                recv_lines[0].src = recv_msg.address.unwrap().inner();
                recv_lines[0].seg_size = recv_msg.bytes as u16;
                let len = recv_msg.bytes;
                // The receive used only this buffer; expose exactly the copied bytes.
                let buffer = &mut bufs[0];
                *buffer = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr(), len) });
                return Ok(1);
            }
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
