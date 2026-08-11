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
    /// Port of the other listener on the same public IP.
    change_port: Option<u16>,
    /// Public listener on another IP used for CHANGE_IP requests and advertised
    /// as CHANGED-ADDRESS.
    change_address: Option<SocketAddr>,
    /// Public address of this listener, used as SOURCE-ADDRESS when the bind
    /// address is private (for example, an EC2 instance behind an Elastic IP).
    outer_address: Option<SocketAddr>,
}

#[bon::bon]
impl StunServerConfig {
    #[builder(finish_fn = init)]
    pub fn new(
        change_port: Option<u16>,
        change_address: Option<SocketAddr>,
        outer_address: Option<SocketAddr>,
    ) -> Self {
        Self {
            change_port,
            change_address,
            outer_address,
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
            outer_address = ?config.outer_address,
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
    let source_addr = config.outer_address.unwrap_or(local_addr);

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
                let response = Response::with(response_attributes(
                    source_addr,
                    response_addr,
                    config.change_address,
                ));
                trace!(target: "stun", ?response, to = %response_addr, "send response");
                ref_iface
                    .iface()
                    .send_stun_packet(Packet::Response(response), txid, response_addr)
                    .await?;
            }
            _ => {
                let response =
                    Response::with(response_attributes(source_addr, src, config.change_address));
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

fn response_attributes(
    source_addr: SocketAddr,
    mapped_addr: SocketAddr,
    changed_addr: Option<SocketAddr>,
) -> Vec<Attr> {
    let mut attrs = vec![
        Attr::SourceAddress(source_addr),
        Attr::MappedAddress(mapped_addr),
    ];
    if let Some(addr) = changed_addr {
        attrs.push(Attr::ChangedAddress(addr));
    }
    attrs
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_advertises_outer_instead_of_private_bind_address() {
        let outer = "198.51.100.10:20002".parse().unwrap();
        let mapped = "203.0.113.20:45000".parse().unwrap();
        let changed = "198.51.100.11:20003".parse().unwrap();

        assert_eq!(
            response_attributes(outer, mapped, Some(changed)),
            vec![
                Attr::SourceAddress(outer),
                Attr::MappedAddress(mapped),
                Attr::ChangedAddress(changed),
            ]
        );
    }

    #[test]
    fn change_targets_preserve_requested_address_and_port_relationship() {
        let local = "10.0.0.10:20002".parse().unwrap();
        let client = "203.0.113.20:45000".parse().unwrap();
        let changed = "198.51.100.11:20003".parse().unwrap();
        let config = StunServerConfig::builder()
            .change_port(20003)
            .change_address(changed)
            .outer_address("198.51.100.10:20002".parse().unwrap())
            .init();

        assert_eq!(
            select_change_target(client, CHANGE_PORT, local, &config).unwrap(),
            "10.0.0.10:20003".parse().unwrap()
        );
        assert_eq!(
            select_change_target(client, CHANGE_IP | CHANGE_PORT, local, &config).unwrap(),
            changed
        );
    }
}
