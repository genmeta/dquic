use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll, ready},
};

use qinterface::{Interface, WeakInterface, component::Component, io::RefIO};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument as _, info, trace};

use super::{
    msg::{Attr, Request, Response},
    router::StunRouter,
};
use crate::nat::{
    iface::StunIO,
    msg::{CHANGE_IP, CHANGE_PORT, Packet},
    router::StunRouterComponent,
};

#[derive(Debug, Clone, Default)]
pub struct StunServerConfig {
    change_port: Option<u16>,
    change_address: Option<SocketAddr>,
}

#[bon::bon]
impl StunServerConfig {
    #[builder(finish_fn = init)]
    pub fn new(change_port: Option<u16>, change_address: Option<SocketAddr>) -> Self {
        Self {
            change_port,
            change_address,
        }
    }
}

#[derive(Debug)]
pub struct StunServer<I: RefIO + 'static> {
    ref_iface: I,
    stun_router: StunRouter,
    config: StunServerConfig,
}

impl<I: RefIO + 'static> StunServer<I> {
    pub fn new(ref_iface: I, stun_router: StunRouter, config: StunServerConfig) -> Self {
        info!(
            target: "stun",
            local_addr = ?ref_iface.iface().local_addr(),
            change_port = ?config.change_port,
            change_address = ?config.change_address,
            "new stun server",
        );
        Self {
            ref_iface,
            stun_router,
            config,
        }
    }

    pub fn spawn(self) -> AbortOnDropHandle<io::Result<()>> {
        AbortOnDropHandle::new(tokio::spawn(
            async move { serve_loop(self.ref_iface, self.stun_router, self.config).await }
                .in_current_span(),
        ))
    }
}

async fn serve_loop<I: RefIO>(
    ref_iface: I,
    stun_router: StunRouter,
    config: StunServerConfig,
) -> io::Result<()> {
    info!(target: "stun", "server started");
    let local_addr = ref_iface.iface().local_addr()?;

    while let Some((request, txid, src)) = stun_router.receive_request().await {
        trace!(target: "stun", ?request, "recv request");
        match (request.change_request(), request.response_address()) {
            (Some(changes), _) => {
                let Ok(addr) = select_change_target(src, changes, local_addr, &config) else {
                    trace!(
                        target: "stun",
                        changes,
                        change_port = ?config.change_port,
                        change_address = ?config.change_address,
                        "drop request: server lacks requested change capability",
                    );
                    continue;
                };
                let request = Request::with_response_addr(src);
                trace!(target: "stun", ?request, to = %addr, "send request");
                ref_iface
                    .iface()
                    .send_stun_packet(Packet::Request(request), txid, addr)
                    .await?;
            }
            (None, Some(&response_addr)) => {
                let mut attrs = vec![
                    Attr::SourceAddress(local_addr),
                    Attr::MappedAddress(response_addr),
                ];
                if let Some(addr) = config.change_address {
                    attrs.push(Attr::ChangedAddress(addr));
                }
                let response = Response::with(attrs);
                trace!(target: "stun", ?response, to = %response_addr, "send response");
                ref_iface
                    .iface()
                    .send_stun_packet(Packet::Response(response), txid, response_addr)
                    .await?;
            }
            _ => {
                let mut attrs = vec![Attr::SourceAddress(local_addr), Attr::MappedAddress(src)];
                if let Some(addr) = config.change_address {
                    attrs.push(Attr::ChangedAddress(addr));
                }
                let response = Response::with(attrs);
                trace!(target: "stun", ?response, to = %src, "send response");
                ref_iface
                    .iface()
                    .send_stun_packet(Packet::Response(response), txid, src)
                    .await?;
            }
        }
    }

    trace!(target: "stun", "request handler finished with no more requests");
    Ok(())
}

fn select_change_target(
    src: SocketAddr,
    changes: u8,
    local_addr: SocketAddr,
    config: &StunServerConfig,
) -> io::Result<SocketAddr> {
    let wants_ip = changes & CHANGE_IP != 0;
    let wants_port = changes & CHANGE_PORT != 0;

    match (wants_ip, wants_port) {
        (false, false) => Ok(src),
        (true, false) => {
            // CHANGE_IP: respond from a different IP (complete change_address, port may differ)
            config.change_address.ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "CHANGE_IP not supported")
            })
        }
        (false, true) => {
            let port = config.change_port.ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "CHANGE_PORT not supported")
            })?;
            Ok(SocketAddr::new(local_addr.ip(), port))
        }
        (true, true) => {
            let addr = config.change_address.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "CHANGE_IP and CHANGE_PORT not supported",
                )
            })?;
            Ok(addr)
        }
    }
}

#[derive(Debug)]
struct StunServerComponentInner {
    ref_iface: WeakInterface,
    config: StunServerConfig,
    task: Option<AbortOnDropHandle<io::Result<()>>>,
}

#[derive(Debug)]
pub struct StunServerComponent {
    inner: Mutex<StunServerComponentInner>,
}

impl StunServerComponent {
    pub fn new(
        ref_iface: WeakInterface,
        stun_router: StunRouter,
        config: StunServerConfig,
    ) -> Self {
        let task =
            Some(StunServer::new(ref_iface.clone(), stun_router.clone(), config.clone()).spawn());
        Self {
            inner: Mutex::new(StunServerComponentInner {
                ref_iface,
                config,
                task,
            }),
        }
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, StunServerComponentInner> {
        self.inner.lock().unwrap()
    }
}

impl Component for StunServerComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.lock_inner();
        if let Some(task) = inner.task.as_mut() {
            task.abort();
            _ = ready!(Pin::new(task).poll(cx));
            inner.task = None;
        }
        Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        let mut inner = self.lock_inner();
        if inner.ref_iface.same_io(&iface.downgrade()) {
            return;
        }

        _ = iface.with_components(|components| {
            let Some(router) = components.with(|router: &StunRouterComponent| {
                router.reinit(iface);
                router.router()
            }) else {
                return;
            };
            if let Some(task) = inner.task.take() {
                task.abort();
            }

            inner.ref_iface = iface.downgrade();
            inner.task = Some(
                StunServer::new(inner.ref_iface.clone(), router, inner.config.clone()).spawn(),
            );
        });
    }
}
