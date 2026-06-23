mod common;

use std::{
    io,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use common::*;
use qbase::net::route::Route;
use qinterface::{io::IO, manager::InterfaceManager};
use tokio::time;

#[test]
fn unbind_destroys_and_weak_upgrade_fails() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());
        let state = factory.state.clone();

        let bind_uri = test_bind_uri();
        let bind_iface: qinterface::BindInterface = manager.bind(bind_uri.clone(), factory).await;
        let weak_bind = bind_iface.downgrade();
        let weak_iface = bind_iface.borrow_weak();

        // unbind is async; ensure it completes
        manager.unbind(bind_uri.clone()).await;

        // existing strong handle remains upgradeable, but should be unusable
        let err = bind_iface.borrow().bound_addr().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotConnected);

        // ensure IO was actually closed
        time::timeout(Duration::from_secs(2), async {
            while state.close_calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("unbind did not close IO in time");

        drop(bind_iface);

        time::timeout(Duration::from_secs(2), async {
            loop {
                if weak_bind.upgrade().is_err() && weak_iface.upgrade().is_err() {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("weak upgrade should eventually fail after unbind + drop");
    })
}

#[test]
fn auto_drop_when_last_ref_gone_allows_rebind() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());
        let state = factory.state.clone();

        let bind_uri = test_bind_uri();

        // Bind and create a borrowed Interface (strong ref)
        let bind_iface: qinterface::BindInterface =
            manager.bind(bind_uri.clone(), factory.clone()).await;
        let iface = bind_iface.borrow();
        drop(bind_iface);
        drop(iface);

        // Binding again must wait for the dropped signal, so this also verifies auto-drop.
        let _bind_iface2 = time::timeout(Duration::from_secs(2), async {
            manager.bind(bind_uri.clone(), factory.clone()).await
        })
        .await
        .expect("rebind after auto-drop timed out");

        assert!(state.close_calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
    })
}

#[test]
fn bind_replaces_closed_binding_even_if_old_handle_still_exists() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());

        let bind_uri = test_bind_uri();
        let original = manager.bind(bind_uri.clone(), factory.clone()).await;
        let original_weak = original.downgrade();

        manager.unbind(bind_uri.clone()).await;

        let err = original.borrow().bound_addr().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotConnected);

        let rebound = manager.bind(bind_uri.clone(), factory).await;

        assert!(
            !original_weak.same_io(&rebound.downgrade()),
            "bind must replace a closed binding instead of reusing the stale interface"
        );
        rebound
            .borrow()
            .bound_addr()
            .expect("replacement binding should be usable");
    })
}

#[test]
fn bind_replaces_manually_closed_binding_even_if_old_handle_still_exists() {
    run(async {
        #[derive(Debug)]
        struct ClosingFactory {
            bind_count: AtomicUsize,
        }

        #[derive(Debug)]
        struct ClosingIo {
            bind_uri: qinterface::bind_uri::BindUri,
            addr: SocketAddr,
            closed: AtomicBool,
        }

        impl qinterface::io::ProductIO for ClosingFactory {
            fn bind(&self, bind_uri: qinterface::bind_uri::BindUri) -> Box<dyn IO> {
                let bind_count = self.bind_count.fetch_add(1, Ordering::SeqCst);
                Box::new(ClosingIo {
                    bind_uri,
                    addr: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        51000 + bind_count as u16,
                    ),
                    closed: AtomicBool::new(false),
                })
            }
        }

        impl IO for ClosingIo {
            fn bind_uri(&self) -> qinterface::bind_uri::BindUri {
                self.bind_uri.clone()
            }

            fn bound_addr(&self) -> io::Result<SocketAddr> {
                if self.closed.load(Ordering::SeqCst) {
                    Err(io::Error::new(
                        ErrorKind::NotConnected,
                        "closed test interface",
                    ))
                } else {
                    Ok(self.addr)
                }
            }

            fn max_segment_size(&self) -> io::Result<usize> {
                Ok(1500)
            }

            fn max_segments(&self) -> io::Result<usize> {
                Ok(1)
            }

            fn poll_send(
                &self,
                _cx: &mut Context<'_>,
                _pkts: &[io::IoSlice<'_>],
                _route: Route,
            ) -> Poll<io::Result<usize>> {
                if self.closed.load(Ordering::SeqCst) {
                    Poll::Ready(Err(io::Error::new(
                        ErrorKind::NotConnected,
                        "closed test interface",
                    )))
                } else {
                    Poll::Ready(Ok(1))
                }
            }

            fn poll_recv(
                &self,
                _cx: &mut Context<'_>,
                _pkts: &mut [BytesMut],
                _route: &mut [Route],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.closed.store(true, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
        }

        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(ClosingFactory {
            bind_count: AtomicUsize::new(0),
        });

        let bind_uri = test_bind_uri();
        let original = manager.bind(bind_uri.clone(), factory.clone()).await;
        let original_weak = original.downgrade();

        original.close().await.expect("close should succeed");

        let err = original.borrow().bound_addr().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotConnected);

        let rebound = manager.bind(bind_uri.clone(), factory).await;

        assert!(
            !original_weak.same_io(&rebound.downgrade()),
            "bind must replace a manually closed binding instead of reusing the stale interface"
        );
        rebound
            .borrow()
            .bound_addr()
            .expect("replacement binding should be usable");
    })
}
