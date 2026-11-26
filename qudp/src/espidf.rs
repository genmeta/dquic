use std::{
    io::{self, IoSlice, IoSliceMut},
    mem,
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::atomic::Ordering,
};

use qbase::net::route::{Line, Link};
use socket2::{SockAddr, SockRef, Socket};

use crate::{Io, UdpSocket};

pub(super) fn validate_bind(addr: SocketAddr, ifindex: u32) -> io::Result<()> {
    if addr.ip().is_unspecified() || ifindex != 0 {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "ESP-IDF requires a concrete local IP and interface index zero"));
    }
    Ok(())
}

impl Io for UdpSocket {
    fn setsockopt(socket: &Socket, addr: SocketAddr) -> io::Result<()> {
        if addr.is_ipv6() {
            socket.set_only_v6(true)?;
        } else {
            socket.set_ttl_v4(Line::DEFAULT_TTL.into())?;
        }
        Ok(())
    }

    fn sendmsg(&self, bufs: &[IoSlice<'_>], line: &Line) -> io::Result<usize> {
        let Some(buffer) = bufs.first() else {
            return Ok(0);
        };
        let local = self.local_addr()?;
        if !line.src.ip().is_unspecified() && line.src != local {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "ESP-IDF source address must match the bound socket"));
        }
        let socket = SockRef::from(&self.io);
        let destination = SockAddr::from(line.dst);
        loop {
            match socket.send_to(buffer, &destination) {
                Ok(length) if length == buffer.len() => return Ok(1),
                Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "incomplete UDP datagram")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], lines: &mut [Line]) -> io::Result<usize> {
        let (Some(buffer), Some(line)) = (bufs.first_mut(), lines.first_mut()) else {
            return Ok(0);
        };
        let local = self.local_addr()?;
        let mut iovec = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
        let ((length, flags), source) = loop {
            // Address storage and the writable payload live through recvmsg. There is
            // one iovec and no ancillary buffer; SockAddr validates the returned length.
            let received = unsafe {
                SockAddr::try_init(|address, address_len| {
                    let mut header: libc::msghdr = mem::zeroed();
                    header.msg_name = address.cast();
                    header.msg_namelen = *address_len;
                    header.msg_iov = &mut iovec;
                    header.msg_iovlen = 1;
                    let length = libc::recvmsg(self.io.as_raw_fd(), &mut header, 0);
                    if length < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    *address_len = header.msg_namelen;
                    Ok((length as usize, header.msg_flags))
                })
            };
            match received {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        let source = source.as_socket().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP UDP source"))?;
        // Do not pass a truncated authenticated packet or forwarded datagram upstream.
        let length = if flags & libc::MSG_TRUNC != 0 {
            0
        } else {
            length.min(buffer.len())
        };
        *line = Line { link: Link::new(source, local), ttl: 0, ecn: None, seg_size: length as u16 };
        // The new view is within the original exclusive payload slice. The old view
        // is immediately replaced and cannot be accessed again.
        *buffer = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr(), length) });
        Ok(1)
    }

    fn set_ttl(&self, ttl: i32) -> io::Result<()> {
        if ttl == self.ttl.load(Ordering::Acquire) {
            return Ok(());
        }
        let socket = SockRef::from(&self.io);
        if self.local_addr()?.is_ipv4() {
            socket.set_ttl_v4(ttl as u32)?;
        } else {
            socket.set_unicast_hops_v6(ttl as u32)?;
        }
        self.ttl.store(ttl, Ordering::SeqCst);
        Ok(())
    }
}
