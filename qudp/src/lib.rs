use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, atomic::AtomicI32},
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use qbase::{net::route::Line, util::Wakers};
use socket2::{Domain, Socket, Type};
use tokio::io::Interest;
pub const BATCH_SIZE: usize = 64;
cfg_if::cfg_if! {
    if #[cfg(unix)]{
        #[path = "unix.rs"]
        mod unix;
    } else if #[cfg(windows)] {
        #[path = "windows.rs"]
        mod windows;
    } else {
        compile_error!("Unsupported platform");
    }
}

#[derive(Debug)]
pub struct UdpSocket {
    io: tokio::net::UdpSocket,
    send_wakers: Arc<Wakers>,
    ttl: AtomicI32,
    ifindex: NonZeroU32,
}

impl UdpSocket {
    /// Bind a local address and use the given interface for every outgoing packet.
    /// Reception is not restricted to that interface. An unavailable interface
    /// is reported when sending. IPv6 link-local scopes must match the index;
    /// a missing scope is filled without changing the address's flowinfo.
    pub fn bind(addr: SocketAddr, ifindex: NonZeroU32) -> io::Result<Self> {
        let addr = scope_addr(addr, ifindex)?;
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        Self::setsockopt(&socket, addr)?;
        socket.bind(&addr.into())?;
        let io = tokio::net::UdpSocket::from_std(socket.into())?;
        let usc = Self { io, send_wakers: Arc::new(Wakers::new()), ttl: AtomicI32::new(Line::DEFAULT_TTL as i32), ifindex };
        Ok(usc)
    }

    pub fn ifindex(&self) -> NonZeroU32 {
        self.ifindex
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    /// Wake all concurrent senders through Tokio's single send-readiness waker.
    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send_wakers.combine_with(cx, |cx| self.io.poll_send_ready(cx))
    }

    pub fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_recv_ready(cx)
    }

    pub fn poll_send(&self, cx: &mut Context<'_>, bufs: &[IoSlice<'_>], line: &Line) -> Poll<io::Result<usize>> {
        let mut line = *line;
        line.link.src = scope_addr(line.src, self.ifindex)?;
        line.link.dst = scope_addr(line.dst, self.ifindex)?;
        loop {
            ready!(self.poll_send_ready(cx))?;
            self.set_ttl(line.ttl as i32)?;
            match self.io.try_io(Interest::WRITABLE, || self.sendmsg(bufs, &line)) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    pub fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], lines: &mut [Line]) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.poll_recv_ready(cx)?);
            let f = || self.recvmsg(bufs, lines);
            let ret = self.io.try_io(Interest::READABLE, f);
            if matches!(&ret, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
                continue;
            } else {
                return Poll::Ready(ret);
            }
        }
    }
}

fn scope_addr(mut addr: SocketAddr, ifindex: NonZeroU32) -> io::Result<SocketAddr> {
    if let SocketAddr::V6(v6) = &mut addr
        && v6.ip().is_unicast_link_local()
    {
        match v6.scope_id() {
            0 => v6.set_scope_id(ifindex.get()),
            scope if scope != ifindex.get() => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "IPv6 scope does not match the socket interface"));
            }
            _ => {}
        }
    }
    Ok(addr)
}

pub trait Io {
    fn setsockopt(io: &socket2::Socket, addr: SocketAddr) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], line: &Line) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], line: &mut [Line]) -> io::Result<usize>;

    fn set_ttl(&self, ttl: i32) -> io::Result<()>;
}

impl UdpSocket {
    pub fn send<'a>(&'a self, iovecs: &'a [IoSlice<'a>], line: Line) -> Send<'a> {
        Send { socket: self, iovecs, line }
    }

    pub fn receive<'a>(&'a self, iovecs: &'a mut [BytesMut], lines: &'a mut [Line]) -> Receive<'a> {
        Receive { socket: self, iovecs, lines }
    }
}

pub struct Send<'a> {
    socket: &'a UdpSocket,
    iovecs: &'a [IoSlice<'a>],
    line: Line,
}

impl Future for Send<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.socket.poll_send(cx, this.iovecs, &this.line)
    }
}

pub struct Receive<'a> {
    socket: &'a UdpSocket,
    iovecs: &'a mut [BytesMut],
    lines: &'a mut [Line],
}

impl Future for Receive<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut bufs = this.iovecs.iter_mut().map(|b| IoSliceMut::new(b)).collect::<Vec<_>>();
        this.socket.poll_recv(cx, &mut bufs, this.lines)
    }
}
