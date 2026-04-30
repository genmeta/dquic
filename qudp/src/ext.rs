use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use qbase::{
    net::route::{Line, Link, Pathway, Route},
    util::Wakers,
};

pub struct UdpSocket {
    send_wakers: Arc<Wakers<64>>,
    io: io::Result<super::UdpSocket>,
}

impl UdpSocket {
    pub fn bind(addr: SocketAddr) -> Self {
        UdpSocket {
            send_wakers: Arc::new(Wakers::new()),
            io: super::UdpSocket::bind(addr),
        }
    }

    fn socket(&self) -> io::Result<&super::UdpSocket> {
        self.io
            .as_ref()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket()?.local_addr()
    }

    pub fn max_segments(&self) -> io::Result<usize> {
        Ok(super::BATCH_SIZE)
    }

    pub fn max_segment_size(&self) -> io::Result<usize> {
        Ok(1500)
    }

    pub fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        route: Route,
    ) -> Poll<io::Result<usize>> {
        let io = self.socket()?;
        let waker = cx.waker();
        let waker_group = self.send_wakers.together_with(waker);
        let cx = &mut Context::from_waker(&waker_group);

        debug_assert_eq!(route.ecn(), None);
        let result = io.poll_send(cx, pkts, &route);
        if result.is_ready() {
            self.send_wakers.remove(waker);
        }
        result
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        route: &mut [Route],
    ) -> Poll<io::Result<usize>> {
        let io = self.socket()?;
        let dst = io.local_addr()?;
        let len = route.len().min(pkts.len());
        let mut rcvd_lines = Vec::with_capacity(len);
        rcvd_lines.resize_with(route.len(), Line::default);
        let mut bufs = pkts[..len]
            .iter_mut()
            .map(|p| IoSliceMut::new(p.as_mut()))
            .collect::<Vec<_>>();
        debug_assert_eq!(rcvd_lines.len(), bufs.len());
        let nrcvd = ready!(io.poll_recv(cx, &mut bufs, &mut rcvd_lines))?;

        for (idx, mut line) in rcvd_lines.into_iter().take(nrcvd).enumerate() {
            let pathway = Pathway::new(line.link.src.into(), dst.into());
            line.link = Link::new(line.src, io.local_addr()?).flip();
            route[idx] = Route::new(pathway.flip(), line);
        }

        Poll::Ready(Ok(nrcvd))
    }

    pub fn close(&mut self) {
        self.io = Err(io::Error::new(io::ErrorKind::NotFound, "socket closed"));
        self.send_wakers.wake_all();
    }
}
