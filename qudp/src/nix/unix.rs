use std::{
    io::{self, IoSlice, IoSliceMut},
    mem::{self, size_of},
    os::fd::AsRawFd,
    ptr,
};

use ::nix::sys::socket::{ControlMessageOwned, SockaddrLike, SockaddrStorage};
use qbase::net::route::{Line, Link};

#[cfg(any(target_os = "android", target_os = "linux"))]
use super::PacketInfo;
use super::{ExtractSocketAddr, parse_cmsg};
use crate::UdpSocket;

// Space for UDP_SEGMENT and the larger of the two packet-info payloads.
const SEND_CONTROL_BUFFER_SIZE: usize =
    unsafe { libc::CMSG_SPACE(size_of::<u16>() as _) as usize + libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _) as usize };

#[repr(C)]
union ControlBuffer<const N: usize> {
    _align: libc::cmsghdr,
    bytes: [u8; N],
}

pub(super) fn sendmsg(socket: &UdpSocket, buffers: &[IoSlice<'_>], line: &Line) -> io::Result<usize> {
    use ::nix::errno::Errno;

    use crate::BATCH_SIZE;

    let batch_size = buffers.len().min(BATCH_SIZE);
    if batch_size == 0 {
        return Ok(0);
    }
    let mut control = ControlBuffer { bytes: [0; SEND_CONTROL_BUFFER_SIZE] };
    let control_ptr = ptr::from_mut(&mut control).cast::<u8>();
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let control_len = {
        let src = if line.src.ip().is_unspecified() {
            socket.io.local_addr()?
        } else {
            line.src
        };
        let packet_info = PacketInfo::new(src.ip(), socket.ifindex);
        let mut len = 0;
        #[cfg(feature = "udp_offload_opt")]
        // The aligned, zeroed buffer has space for both GSO and packet info.
        unsafe {
            let header = control_ptr.cast::<libc::cmsghdr>();
            *header = libc::cmsghdr {
                cmsg_len: libc::CMSG_LEN(size_of::<u16>() as _) as _,
                cmsg_level: libc::SOL_UDP,
                cmsg_type: libc::UDP_SEGMENT,
            };
            ptr::copy_nonoverlapping(ptr::from_ref(&line.seg_size).cast::<u8>(), libc::CMSG_DATA(header), size_of::<u16>());
            len += libc::CMSG_SPACE(size_of::<u16>() as _) as usize;
        }
        if let Some(info) = &packet_info {
            let (level, kind, data, size) = match info {
                PacketInfo::V4(info) => (libc::IPPROTO_IP, libc::IP_PKTINFO, ptr::from_ref(info).cast::<u8>(), mem::size_of_val(info)),
                PacketInfo::V6(info) => (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, ptr::from_ref(info).cast::<u8>(), mem::size_of_val(info)),
            };
            // CMSG_SPACE keeps the offset aligned; either payload fits the remaining space.
            unsafe {
                let header = control_ptr.add(len).cast::<libc::cmsghdr>();
                *header = libc::cmsghdr { cmsg_len: libc::CMSG_LEN(size as _) as _, cmsg_level: level, cmsg_type: kind };
                ptr::copy_nonoverlapping(data, libc::CMSG_DATA(header), size);
                len += libc::CMSG_SPACE(size as _) as usize;
            }
        }
        len
    };
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    let control_len = 0;
    let control_ptr = if control_len == 0 {
        ptr::null_mut()
    } else {
        control_ptr.cast()
    };

    let sock_addr = SockaddrStorage::from(line.dst);
    let mut iovecs = [libc::iovec { iov_base: ptr::null_mut(), iov_len: 0 }; BATCH_SIZE];
    // mmsghdr contains only integers and pointers; zero also initializes ABI padding.
    let mut messages: [libc::mmsghdr; BATCH_SIZE] = unsafe { mem::zeroed() };
    for (index, buffer) in buffers.iter().take(batch_size).enumerate() {
        iovecs[index].iov_base = buffer.as_ptr().cast_mut().cast();
        iovecs[index].iov_len = buffer.len();
        let header = &mut messages[index].msg_hdr;
        header.msg_name = sock_addr.as_ptr().cast_mut().cast();
        header.msg_namelen = sock_addr.len();
        header.msg_iov = ptr::addr_of_mut!(iovecs[index]);
        header.msg_iovlen = 1;
        header.msg_control = control_ptr;
        header.msg_controllen = control_len as _;
    }

    let fd = socket.io.as_raw_fd();
    loop {
        // All headers, iovecs, payloads, the address and shared control buffer remain live.
        match Errno::result(unsafe { libc::sendmmsg(fd, messages.as_mut_ptr(), batch_size as _, 0) }) {
            Ok(sent) => return Ok(sent as usize),
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN | Errno::ENOBUFS) => return Err(io::ErrorKind::WouldBlock.into()),
            Err(e) => return Err(e.into()),
        }
    }
}

const RECV_CONTROL_BUFFER_SIZE: usize = unsafe {
    libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as _) as usize
        + libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _) as usize
        + libc::CMSG_SPACE(size_of::<libc::c_int>() as _) as usize
};

pub(super) fn recvmsg(socket: &UdpSocket, bufs: &mut [IoSliceMut<'_>], recv_lines: &mut [Line]) -> io::Result<usize> {
    use ::nix::errno::Errno;

    use crate::BATCH_SIZE;

    let batch_size = bufs.len().min(recv_lines.len()).min(BATCH_SIZE);
    if batch_size == 0 {
        return Ok(0);
    }
    let mut controls = std::array::from_fn::<_, BATCH_SIZE, _>(|_| ControlBuffer { bytes: [0; RECV_CONTROL_BUFFER_SIZE] });
    let mut iovecs = [libc::iovec { iov_base: ptr::null_mut(), iov_len: 0 }; BATCH_SIZE];
    // Both arrays contain only C-layout integers and pointers; zero is a valid initial value.
    let mut addresses: [SockaddrStorage; BATCH_SIZE] = unsafe { mem::zeroed() };
    let mut messages: [libc::mmsghdr; BATCH_SIZE] = unsafe { mem::zeroed() };
    for (index, buffer) in bufs.iter_mut().take(batch_size).enumerate() {
        iovecs[index].iov_base = buffer.as_mut_ptr().cast();
        iovecs[index].iov_len = buffer.len();
        let header = &mut messages[index].msg_hdr;
        header.msg_name = ptr::addr_of_mut!(addresses[index]).cast();
        header.msg_iov = ptr::addr_of_mut!(iovecs[index]);
        header.msg_iovlen = 1;
        header.msg_control = ptr::addr_of_mut!(controls[index]).cast();
    }

    let fd = socket.io.as_raw_fd();
    let received = loop {
        // These are value-result fields: restore capacities before each syscall attempt.
        for message in &mut messages[..batch_size] {
            message.msg_hdr.msg_namelen = SockaddrStorage::size();
            message.msg_hdr.msg_controllen = RECV_CONTROL_BUFFER_SIZE as _;
        }
        // Each writable payload, address and aligned control buffer remains live and disjoint.
        match Errno::result(unsafe { libc::recvmmsg(fd, messages.as_mut_ptr(), batch_size as _, libc::MSG_DONTWAIT, ptr::null_mut()) }) {
            Ok(count) => break count as usize,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let local_port = socket.local_addr()?.port();
    for index in 0..received {
        let header = &messages[index].msg_hdr;
        if header.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(Errno::ENOBUFS.into());
        }
        let link = Link::new(addresses[index].inner(), recv_lines[index].dst);
        let len = if header.msg_flags & libc::MSG_TRUNC != 0 {
            0
        } else {
            messages[index].msg_len as usize
        };
        let mut line = Line { link, ttl: 0, ecn: None, seg_size: len as u16 };
        // The kernel returned complete control data. CMSG macros bound the headers,
        // and fixed payload lengths are checked before copying potentially unaligned data.
        unsafe {
            let mut current = libc::CMSG_FIRSTHDR(header);
            while let Some(cmsg) = current.as_ref() {
                match (cmsg.cmsg_level, cmsg.cmsg_type) {
                    (libc::IPPROTO_IP, libc::IP_PKTINFO) if cmsg.cmsg_len >= libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as _) as _ => {
                        let info = ptr::read_unaligned(libc::CMSG_DATA(current).cast());
                        parse_cmsg(ControlMessageOwned::Ipv4PacketInfo(info), &mut line);
                    }
                    (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO)
                        if cmsg.cmsg_len >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as _ =>
                    {
                        let info = ptr::read_unaligned(libc::CMSG_DATA(current).cast());
                        parse_cmsg(ControlMessageOwned::Ipv6PacketInfo(info), &mut line);
                    }
                    #[cfg(any(target_os = "android", target_os = "linux"))]
                    (libc::SOL_UDP, libc::UDP_GRO) if cmsg.cmsg_len >= libc::CMSG_LEN(size_of::<libc::c_int>() as _) as _ => {
                        line.seg_size = ptr::read_unaligned::<libc::c_int>(libc::CMSG_DATA(current).cast()) as u16;
                    }
                    _ => {}
                }
                current = libc::CMSG_NXTHDR(header, current);
            }
        }
        line.dst.set_port(local_port);
        recv_lines[index] = line;
        // The syscall copied at most this buffer's length. Preserve its original
        // lifetime and start address while shortening the exclusive writable view.
        let buffer = &mut bufs[index];
        *buffer = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr(), len) });
    }
    Ok(received)
}
