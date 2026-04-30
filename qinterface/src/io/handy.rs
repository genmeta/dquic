use crate::BindUri;

#[cfg(all(feature = "qudp", any(unix, windows)))]
pub mod qudp {
    use std::{
        error::{Error, Error as StdError},
        fmt::Display,
        io::{self, IoSliceMut},
        net::SocketAddr,
        sync::Arc,
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::{
        net::route::{Line, Pathway},
        util::Wakers,
    };
    use qudp::BATCH_SIZE;
    use thiserror::Error;

    use crate::{BindUri, IO, Route};

    pub struct UdpSocketController {
        bind_uri: BindUri,
        send_wakers: Arc<Wakers<64>>,
        recv_wakers: Arc<Wakers>,
        io: Result<Result<qudp::UdpSocket, Closed>, BindFailed>,
    }

    #[derive(Debug, Clone, Copy, Error)]
    #[error("UdpSocketController closed")]
    pub struct Closed(());

    impl From<Closed> for io::Error {
        fn from(error: Closed) -> Self {
            io::Error::other(error)
        }
    }

    #[derive(Debug, Clone)]
    pub struct BindFailed(Arc<io::Error>);

    impl Display for BindFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "failed to bind UdpSocketController")
        }
    }

    impl StdError for BindFailed {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    impl From<BindFailed> for io::Error {
        fn from(error: BindFailed) -> Self {
            io::Error::other(error)
        }
    }

    impl UdpSocketController {
        pub fn bind(bind_uri: BindUri) -> Self {
            let io = bind_uri
                .resolve_binding()
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Failed to bind {bind_uri}: {e}"),
                    )
                })
                .and_then(|binding| match binding.device {
                    Some(device) => {
                        let device = qudp::BoundDevice::new(device.name, device.index)?;
                        qudp::UdpSocket::bind_to_device(binding.addr, device)
                    }
                    None => qudp::UdpSocket::bind(binding.addr),
                });
            UdpSocketController {
                bind_uri,
                send_wakers: Arc::new(Wakers::new()),
                recv_wakers: Arc::new(Wakers::new()),
                io: io.map(Ok).map_err(|e| BindFailed(Arc::new(e))),
            }
        }

        fn socket(&self) -> io::Result<&qudp::UdpSocket> {
            self.io
                .as_ref()
                .map_err(|e| io::Error::from(e.clone()))
                .and_then(|result| result.as_ref().map_err(|e| (*e).into()))
        }
    }

    impl IO for UdpSocketController {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn bound_addr(&self) -> io::Result<SocketAddr> {
            self.socket()?.local_addr()
        }

        fn max_segments(&self) -> io::Result<usize> {
            Ok(BATCH_SIZE)
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Ok(1500)
        }

        fn poll_send(
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

        fn poll_recv(
            &self,
            cx: &mut Context,
            pkts: &mut [BytesMut],
            route: &mut [Route],
        ) -> Poll<io::Result<usize>> {
            let io = self.socket()?;
            self.recv_wakers.combine_with(cx, |cx| {
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
                    let link = line.link.flip();
                    let pathway = Pathway::from(link);
                    line.link = link;
                    route[idx] = Route::new(pathway, line);
                }

                Poll::Ready(Ok(nrcvd))
            })
        }

        fn poll_close(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
            self.socket()?;
            self.send_wakers.wake_all();
            self.recv_wakers.wake_all();
            self.io = Ok(Err(Closed(())));
            Poll::Ready(Ok(()))
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    mod tests {
        use std::net::Ipv4Addr;

        use super::*;
        use crate::io::IoExt as _;

        #[tokio::test]
        async fn wildcard_receive_preserves_packet_destination() {
            let controller =
                UdpSocketController::bind("inet://0.0.0.0:0".parse().expect("bind URI"));
            let mut destination = controller.bound_addr().expect("bound address");
            destination.set_ip(Ipv4Addr::LOCALHOST.into());

            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender socket");
            let sender_addr = sender.local_addr().expect("sender address");
            sender
                .send_to(b"route", destination)
                .expect("send datagram");

            let mut bufs = Vec::new();
            let mut routes = Vec::new();
            let (_, route) = controller
                .recvmmsg(&mut bufs, &mut routes)
                .await
                .expect("receive datagram")
                .next()
                .expect("one datagram");

            assert_eq!(route.line.link.src, destination);
            assert_eq!(route.line.link.dst, sender_addr);
            assert_eq!(route.pathway.local().addr(), destination);
            assert_eq!(route.pathway.remote().addr(), sender_addr);
        }
    }
}

pub mod unsupported {
    use std::{
        io,
        net::SocketAddr,
        task::{Context, Poll},
    };

    use bytes::BytesMut;
    use qbase::net::route::Route;
    use thiserror::Error;

    use crate::{BindUri, IO};

    #[derive(Debug, Clone)]
    pub struct Unsupported {
        bind_uri: BindUri,
    }

    #[derive(Debug, Clone, Copy, Error)]
    #[error(
        "qudp feature is not enabled or target platform is not supported, you should use your own ProductQuicIO implementation, not the default"
    )]
    pub struct UnsupportedError(());

    impl From<UnsupportedError> for io::Error {
        fn from(error: UnsupportedError) -> Self {
            io::Error::new(io::ErrorKind::Unsupported, error)
        }
    }

    impl Unsupported {
        pub fn bind(bind_uri: BindUri) -> Self {
            Unsupported { bind_uri }
        }
    }

    impl IO for Unsupported {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn bound_addr(&self) -> io::Result<SocketAddr> {
            Err(UnsupportedError(()).into())
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Err(UnsupportedError(()).into())
        }

        fn max_segments(&self) -> io::Result<usize> {
            Err(UnsupportedError(()).into())
        }

        fn poll_send(
            &self,
            _: &mut Context,
            _: &[io::IoSlice],
            _: Route,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(UnsupportedError(()).into()))
        }

        fn poll_recv(
            &self,
            _: &mut Context,
            _: &mut [BytesMut],
            _: &mut [Route],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(UnsupportedError(()).into()))
        }

        fn poll_close(&mut self, _: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(all(feature = "qudp", any(unix, windows)))]
pub static DEFAULT_IO_FACTORY: fn(BindUri) -> qudp::UdpSocketController =
    |bind_uri| qudp::UdpSocketController::bind(bind_uri);

#[cfg(not(all(feature = "qudp", any(unix, windows))))]
pub static DEFAULT_IO_FACTORY: fn(BindUri) -> unsupported::Unsupported =
    |bind_uri| unsupported::Unsupported::bind(bind_uri);

const _: () = {
    use super::ProductIO;
    const fn assert_product_interface_factory<F: ProductIO + Copy>(_: &F) {}
    assert_product_interface_factory(&DEFAULT_IO_FACTORY);
};
