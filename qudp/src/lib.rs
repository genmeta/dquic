use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
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
        #[path = "nix.rs"]
        mod nix;
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
    ifindex: u32,
}

impl UdpSocket {
    /// Bind a local UDP address and configure outgoing interface selection.
    ///
    /// - `ifindex == 0`: let the OS choose the outgoing interface using its
    ///   routing policy, the destination, and the source address.
    /// - `ifindex != 0`: select that interface for outgoing packets. An invalid
    ///   or unusable interface can cause binding or sending to fail.
    ///
    /// Neither value filters reception by interface. The bound local address
    /// and the source address supplied when sending still apply.
    ///
    /// For IPv6 link-local addresses, a nonzero index fills a missing scope ID
    /// and must match any existing scope. With index zero, the address's scope
    /// is preserved; supply a valid zone where required. Flowinfo is preserved.
    ///
    /// ```no_run
    /// # async fn example() -> std::io::Result<()> {
    /// let socket = qudp::UdpSocket::bind("127.0.0.1:0".parse().unwrap(), 0)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn bind(addr: SocketAddr, ifindex: u32) -> io::Result<Self> {
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

    /// Configured outgoing interface index, or zero for OS selection.
    pub fn ifindex(&self) -> u32 {
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
            match self.io.try_io(Interest::READABLE, || self.recvmsg(bufs, lines)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
}

fn scope_addr(mut addr: SocketAddr, ifindex: u32) -> io::Result<SocketAddr> {
    if let SocketAddr::V6(v6) = &mut addr
        && v6.ip().is_unicast_link_local()
        && ifindex != 0
    {
        match v6.scope_id() {
            0 => v6.set_scope_id(ifindex),
            scope if scope != ifindex => {
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
