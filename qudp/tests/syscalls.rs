#![cfg(target_vendor = "apple")]

extern crate nix as real_nix;
extern crate self as nix;

use std::{
    cell::Cell,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    sync::atomic::AtomicI32,
    time::Duration,
};

use qbase::net::route::{Line, Link};
use qudp::Io;
pub use real_nix::{cmsg_space, errno};
use socket2::{Domain, Socket, Type};

#[path = "../src/nix.rs"]
mod backend;

thread_local! {
    static SEND_CALLS: Cell<usize> = const { Cell::new(0) };
    static RECV_CALLS: Cell<usize> = const { Cell::new(0) };
}

// Compile the real backend against forwarding syscalls with one injected EINTR.
pub mod sys {
    pub mod socket {
        pub use real_nix::sys::socket::*;

        pub fn sendmsg<S: SockaddrLike>(
            fd: std::os::fd::RawFd,
            iov: &[std::io::IoSlice<'_>],
            cmsgs: &[ControlMessage<'_>],
            flags: MsgFlags,
            addr: Option<&S>,
        ) -> real_nix::Result<usize> {
            let call = crate::SEND_CALLS.get() + 1;
            crate::SEND_CALLS.set(call);
            if call == 2 {
                return Err(real_nix::errno::Errno::EINTR);
            }
            real_nix::sys::socket::sendmsg(fd, iov, cmsgs, flags, addr)
        }

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
