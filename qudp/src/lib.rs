use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    num::NonZeroU32,
    pin::Pin,
    sync::atomic::AtomicI32,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use qbase::net::route::Line;
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
    ttl: AtomicI32,
    bound_device: Option<BoundDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundDevice {
    name: String,
    index: NonZeroU32,
}

impl BoundDevice {
    pub fn new(name: impl Into<String>, index: u32) -> io::Result<Self> {
        let index = NonZeroU32::new(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface index must be non-zero",
            )
        })?;
        Ok(Self {
            name: name.into(),
            index,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> NonZeroU32 {
        self.index
    }
}

impl UdpSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        Self::bind_scoped(addr, None)
    }

    pub fn bind_to_device(addr: SocketAddr, device: BoundDevice) -> io::Result<Self> {
        Self::bind_scoped(addr, Some(device))
    }

    fn bind_scoped(addr: SocketAddr, bound_device: Option<BoundDevice>) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        Self::config(&socket, addr)?;
        if let Some(device) = bound_device.as_ref() {
            let socket_ref = socket2::SockRef::from(&socket);
            Self::bind_device_to_socket(&socket_ref, addr, device)?;
        }
        let io = tokio::net::UdpSocket::from_std(socket.into())?;
        let usc = Self {
            io,
            ttl: AtomicI32::new(Line::DEFAULT_TTL as i32),
            bound_device,
        };
        Ok(usc)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn bound_device(&self) -> Option<&BoundDevice> {
        self.bound_device.as_ref()
    }

    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }

    pub fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_recv_ready(cx)
    }

    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
        line: &Line,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.poll_send_ready(cx))?;
            self.set_ttl(line.ttl as i32)?;
            match self
                .io
                .try_io(Interest::WRITABLE, || self.sendmsg(bufs, line))
            {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        lines: &mut [Line],
    ) -> Poll<io::Result<usize>> {
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

    pub fn bind_device(&self, device: &str) -> io::Result<()> {
        #[cfg(not(unix))]
        {
            let _ = device;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "binding an existing UDP socket by interface name is unsupported on this platform",
            ));
        }
        #[cfg(unix)]
        {
            let index = nix::net::if_::if_nametoindex(device)?;
            let device = BoundDevice::new(device, index)?;
            let socket = socket2::SockRef::from(&self.io);
            Self::bind_device_to_socket(&socket, self.io.local_addr()?, &device)
        }
    }
}

pub trait Io {
    fn config(io: &socket2::Socket, addr: SocketAddr) -> io::Result<()>;

    fn bind_device_to_socket(
        io: &socket2::SockRef<'_>,
        addr: SocketAddr,
        device: &BoundDevice,
    ) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], line: &Line) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], line: &mut [Line]) -> io::Result<usize>;

    fn set_ttl(&self, ttl: i32) -> io::Result<()>;
}

impl UdpSocket {
    pub fn send<'a>(&'a self, iovecs: &'a [IoSlice<'a>], line: Line) -> Send<'a> {
        Send {
            socket: self,
            iovecs,
            line,
        }
    }

    pub fn receiver(&self) -> Receiver<'_> {
        Receiver {
            socket: self,
            iovecs: (0..BATCH_SIZE)
                .map(|_| {
                    let mut buf = BytesMut::with_capacity(1500);
                    buf.resize(1500, 0);
                    buf
                })
                .collect::<Vec<_>>(),
            lines: (0..BATCH_SIZE).map(|_| Line::default()).collect::<Vec<_>>(),
        }
    }
}

pub struct Send<'a> {
    pub socket: &'a UdpSocket,
    pub iovecs: &'a [IoSlice<'a>],
    pub line: Line,
}

impl Future for Send<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.socket.poll_send(cx, this.iovecs, &this.line)
    }
}

pub struct Receiver<'u> {
    pub socket: &'u UdpSocket,
    pub iovecs: Vec<BytesMut>,
    pub lines: Vec<Line>,
}

impl Receiver<'_> {
    #[inline]
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut bufs = self
            .iovecs
            .iter_mut()
            .map(|b| IoSliceMut::new(b))
            .collect::<Vec<_>>();

        self.socket.poll_recv(cx, &mut bufs, &mut self.lines)
    }

    #[inline]
    pub async fn recv(&mut self) -> io::Result<usize> {
        core::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
        time::Duration,
    };

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn ipv6_wildcard_socket_does_not_receive_ipv4_packets() -> io::Result<()> {
        let socket = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))?;
        let port = socket.local_addr()?.port();

        let sender =
            std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        sender.send_to(
            b"ping",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        )?;

        let mut receiver = socket.receiver();
        let result = tokio::time::timeout(Duration::from_millis(200), receiver.recv()).await;
        assert!(
            result.is_err(),
            "unexpected ipv4 datagram arrived on ipv6 wildcard socket: {result:?}"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ipv4_and_ipv6_wildcard_sockets_can_bind_same_port() -> io::Result<()> {
        let v6 = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))?;
        let port = v6.local_addr()?.port();

        let v4 = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            port,
        )))?;

        assert!(matches!(v6.local_addr()?, SocketAddr::V6(_)));
        assert!(matches!(v4.local_addr()?, SocketAddr::V4(_)));
        Ok(())
    }
}
