#![cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]

extern crate libc as real_libc;
extern crate nix as real_nix;
extern crate self as libc;
extern crate self as nix;

use std::{
    cell::Cell,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    sync::atomic::AtomicI32,
    time::Duration,
};

use qbase::net::route::{Line, Link};
use qudp::{BATCH_SIZE, Io};
pub use real_libc::*;
pub use real_nix::{cmsg_space, errno};
use socket2::{Domain, Socket, Type};

#[path = "../src/nix.rs"]
mod backend;

thread_local! {
    static SEND_CALLS: Cell<usize> = const { Cell::new(0) };
    static RECV_CALLS: Cell<usize> = const { Cell::new(0) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static SEND_ERROR: Cell<Option<real_nix::errno::Errno>> = const { Cell::new(None) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static RECV_ERROR: Cell<Option<real_nix::errno::Errno>> = const { Cell::new(None) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static TRUNCATE_CONTROL: Cell<bool> = const { Cell::new(false) };
}

// Compile the real backend against forwarding syscalls with one injected EINTR.
/// # Safety
/// The message and its buffers must satisfy the contract of libc::sendmsg.
#[cfg(target_vendor = "apple")]
pub unsafe fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    let call = SEND_CALLS.get() + 1;
    SEND_CALLS.set(call);
    if call == 2 {
        real_nix::errno::Errno::EINTR.set();
        return -1;
    }
    unsafe { real_libc::sendmsg(fd, msg, flags) }
}

/// # Safety
/// The messages and their buffers must satisfy the contract of libc::sendmmsg.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub unsafe fn sendmmsg(fd: c_int, msgs: *mut mmsghdr, len: c_uint, flags: c_int) -> c_int {
    SEND_CALLS.set(SEND_CALLS.get() + 1);
    if let Some(error) = SEND_ERROR.take() {
        error.set();
        return -1;
    }
    unsafe { real_libc::sendmmsg(fd, msgs, len, flags) }
}

/// # Safety
/// The messages and their buffers must satisfy the contract of libc::recvmmsg.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub unsafe fn recvmmsg(fd: c_int, msgs: *mut mmsghdr, len: c_uint, flags: c_int, timeout: *mut timespec) -> c_int {
    RECV_CALLS.set(RECV_CALLS.get() + 1);
    if let Some(error) = RECV_ERROR.take() {
        for index in 0..len as usize {
            let header = unsafe { &mut (*msgs.add(index)).msg_hdr };
            header.msg_namelen = 0;
            header.msg_controllen = 0;
        }
        error.set();
        return -1;
    }
    let received = unsafe { real_libc::recvmmsg(fd, msgs, len, flags, timeout) };
    if received > 0 && TRUNCATE_CONTROL.take() {
        unsafe { (*msgs).msg_hdr.msg_flags |= MSG_CTRUNC };
    }
    received
}

pub mod sys {
    pub mod socket {
        pub use real_nix::sys::socket::*;

        pub fn recvmsg<'a, 'outer, 'inner: 'outer, S: SockaddrLike + 'a>(
            fd: std::os::fd::RawFd,
            iov: &'outer mut [std::io::IoSliceMut<'inner>],
            cmsgs: Option<&'a mut [u8]>,
            flags: MsgFlags,
        ) -> real_nix::Result<RecvMsg<'a, 'outer, S>> {
            let call = crate::RECV_CALLS.get() + 1;
            crate::RECV_CALLS.set(call);
            if call == 1 {
                return Err(real_nix::errno::Errno::EINTR);
            }
            real_nix::sys::socket::recvmsg(fd, iov, cmsgs, flags)
        }
    }
}

// Only the native socket and fields used by the production backend are needed.
struct UdpSocket {
    io: tokio::net::UdpSocket,
    ifindex: u32,
    ttl: AtomicI32,
}

impl UdpSocket {
    fn bind(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        Self::setsockopt(&socket, addr)?;
        socket.bind(&addr.into())?;
        Ok(Self { io: tokio::net::UdpSocket::from_std(socket.into())?, ifindex: 0, ttl: AtomicI32::new(Line::DEFAULT_TTL as i32) })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "current_thread")]
async fn interrupted_second_datagram_is_retried_without_losing_the_prefix() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap())?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        let line = Line::new(Link::new(socket.local_addr()?, peer.local_addr()?), 64, None, 5);
        SEND_CALLS.set(0);

        assert_eq!(socket.sendmsg(&[IoSlice::new(b"first"), IoSlice::new(b"other")], &line)?, 2);
        assert_eq!(SEND_CALLS.get(), 3);
        let mut bytes = [0; 16];
        for expected in [b"first", b"other"] {
            let (len, source) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut bytes)).await??;
            assert_eq!(&bytes[..len], expected);
            assert_eq!(source, socket.local_addr()?);
        }
        assert_eq!(peer.try_recv_from(&mut bytes).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "current_thread")]
async fn interrupted_receive_is_retried_at_the_syscall() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap())?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        peer.send_to(b"live", socket.local_addr()?).await?;
        socket.io.readable().await?;
        let mut bytes = [0; 16];
        let mut lines = [Line::default()];
        RECV_CALLS.set(0);

        {
            let mut buffers = [IoSliceMut::new(&mut bytes)];
            assert_eq!(socket.recvmsg(&mut buffers, &mut lines)?, 1);
        }
        assert_eq!(RECV_CALLS.get(), 2);
        assert_eq!(&bytes[..lines[0].seg_size as usize], b"live");
        assert_eq!(lines[0].src, peer.local_addr()?);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn interrupted_batch_is_retried_without_duplicate_datagrams() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap())?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        let line = Line::new(Link::new(socket.local_addr()?, peer.local_addr()?), 64, None, 5);
        SEND_CALLS.set(0);
        SEND_ERROR.set(Some(real_nix::errno::Errno::EINTR));

        assert_eq!(socket.sendmsg(&[IoSlice::new(b"first"), IoSlice::new(b"other")], &line)?, 2);
        assert_eq!(SEND_CALLS.get(), 2);
        for expected in [b"first", b"other"] {
            let mut bytes = [0; 16];
            let (len, source) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut bytes)).await??;
            assert_eq!(&bytes[..len], expected);
            assert_eq!(source, socket.local_addr()?);
        }
        assert_eq!(peer.try_recv_from(&mut [0; 16]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn batch_backpressure_returns_would_block_without_submitting_packets() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap())?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        let line = Line::new(Link::new(socket.local_addr()?, peer.local_addr()?), 64, None, 4);
        for error in [real_nix::errno::Errno::EAGAIN, real_nix::errno::Errno::ENOBUFS] {
            SEND_CALLS.set(0);
            SEND_ERROR.set(Some(error));
            assert_eq!(socket.sendmsg(&[IoSlice::new(b"live")], &line).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert_eq!(SEND_CALLS.get(), 1);
            assert_eq!(peer.try_recv_from(&mut [0; 16]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn interrupted_batch_receive_restores_capacities_before_retrying() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap())?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        peer.send_to(b"first", socket.local_addr()?).await?;
        peer.send_to(b"other", socket.local_addr()?).await?;
        socket.io.readable().await?;
        let mut packets = [[0; 16]; 2];
        let mut buffers = packets.each_mut().map(|packet| IoSliceMut::new(packet));
        let mut lines = [Line::default(); 2];
        RECV_CALLS.set(0);
        RECV_ERROR.set(Some(real_nix::errno::Errno::EINTR));

        assert_eq!(socket.recvmsg(&mut buffers, &mut lines)?, 2);
        assert_eq!(RECV_CALLS.get(), 2);
        for (index, expected) in [b"first", b"other"].iter().enumerate() {
            assert_eq!(&buffers[index][..lines[index].seg_size as usize], *expected);
            assert_eq!(lines[index].src, peer.local_addr()?);
            assert_eq!(lines[index].dst, socket.local_addr()?);
        }
        assert_eq!(socket.recvmsg(&mut buffers, &mut lines).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "current_thread")]
async fn truncated_control_returns_an_error_and_allows_later_receives() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind.parse().unwrap())?;
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        let mut bytes = [0; 16];
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let mut lines = [Line::default()];
        peer.send_to(b"lost", socket.local_addr()?).await?;
        socket.io.readable().await?;
        TRUNCATE_CONTROL.set(true);
        assert_eq!(socket.recvmsg(&mut buffers, &mut lines).unwrap_err().raw_os_error(), Some(ENOBUFS));

        peer.send_to(b"next", socket.local_addr()?).await?;
        socket.io.readable().await?;
        assert_eq!(socket.recvmsg(&mut buffers, &mut lines)?, 1);
        assert_eq!(&buffers[0][..lines[0].seg_size as usize], b"next");
        assert_eq!(lines[0].src, peer.local_addr()?);
        assert_eq!(lines[0].dst, socket.local_addr()?);
    }
    Ok(())
}
