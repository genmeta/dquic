use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{
        Context,
        Poll::{self, Ready},
        ready,
    },
};

use bytes::BytesMut;
use qbase::{
    net::{
        addr::EndpointAddr,
        route::{Line, Link, Pathway, Route},
    },
    util::ArcAsyncDeque,
};
use qinterface::{
    Interface, WeakInterface,
    component::{
        Component,
        route::{QuicRouter, QuicRouterComponent},
    },
    io::{IO, IoExt, RefIO},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument as _;

pub type ArcRecvQueue = ArcAsyncDeque<(BytesMut, Pathway, Link)>;

use crate::{
    nat::{
        client::StunClientComponent,
        router::{StunRouter, StunRouterComponent},
    },
    packet::{ForwardHeader, StunHeader},
};

#[derive(Debug, Clone)]
pub enum Forwarder<I: RefIO + 'static> {
    Client { stun_client: StunClientComponent<I> },
    Server { outer_addr: SocketAddr },
}

impl<I: RefIO> Forwarder<I> {
    pub fn outer(&self) -> Option<SocketAddr> {
        match self {
            Forwarder::Client { stun_client } => stun_client
                .with_client(|client| client.and_then(|client| client.get_outer_addr()?.ok())),
            Forwarder::Server { outer_addr } => Some(*outer_addr),
        }
    }

    pub fn should_forward(&self, dst: EndpointAddr) -> Option<SocketAddr> {
        let outer = self.outer()?;

        let EndpointAddr::Agent {
            agent,
            outer: dst_outer,
        } = dst
        else {
            return None;
        };

        if outer == dst_outer {
            return None;
        }

        Some(if outer == agent { dst_outer } else { agent })
    }
}

#[derive(Debug)]
pub struct ForwardersComponent {
    forward: Mutex<Forwarder<WeakInterface>>,
}

impl ForwardersComponent {
    pub fn new(forwarder: Forwarder<WeakInterface>) -> Self {
        Self {
            forward: Mutex::new(forwarder),
        }
    }

    pub fn new_client(stun_client: StunClientComponent<WeakInterface>) -> Self {
        Self::new(Forwarder::Client { stun_client })
    }

    pub fn new_server(outer_addr: SocketAddr) -> Self {
        Self::new(Forwarder::Server { outer_addr })
    }

    fn lock_forwarders(&self) -> MutexGuard<'_, Forwarder<WeakInterface>> {
        self.forward.lock().expect("Forwarder lock poisoned")
    }

    pub fn forwarder(&self) -> Forwarder<WeakInterface> {
        self.lock_forwarders().clone()
    }
}

impl Component for ForwardersComponent {
    fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        _ = iface.with_component(|component: &StunClientComponent| {
            component.reinit(iface);
            *self.lock_forwarders() = Forwarder::Client {
                stun_client: component.clone(),
            };
        });
    }
}

#[derive(Debug)]
pub struct ReceiveAndDeliverPacket<I: RefIO + 'static = WeakInterface> {
    ref_iface: Mutex<I>,
    task: Mutex<Option<AbortOnDropHandle<io::Result<()>>>>,
    quic: bool,
    stun: bool,
    forward: bool,
}

pub type ReceiveAndDeliverPacketComponent = ReceiveAndDeliverPacket<WeakInterface>;

#[bon::bon]
impl<I: RefIO + 'static> ReceiveAndDeliverPacket<I> {
    #[builder(finish_fn = init)]
    pub fn new(
        #[builder(start_fn)] ref_iface: I,
        quic_router: Option<Arc<QuicRouter>>,
        stun_router: Option<StunRouter>,
        forwarder: Option<Forwarder<I>>,
    ) -> Self {
        let enable_quic = quic_router.is_some();
        let enable_stun = stun_router.is_some();
        let enable_forward = forwarder.is_some();

        let task = ReceiveAndDeliverPacketComponent::task()
            .maybe_quic_router(quic_router)
            .maybe_stun_router(stun_router)
            .maybe_forwarder(forwarder)
            .iface_ref(ref_iface.clone())
            .spawn();
        Self {
            ref_iface: Mutex::new(ref_iface),
            task: Mutex::new(Some(task)),
            quic: enable_quic,
            stun: enable_stun,
            forward: enable_forward,
        }
    }
}

#[bon::bon]
impl ReceiveAndDeliverPacketComponent {
    #[builder(finish_fn = spawn)]
    pub fn task<I: RefIO + 'static>(
        quic_router: Option<Arc<QuicRouter>>,
        stun_router: Option<StunRouter>,
        forwarder: Option<Forwarder<I>>,
        iface_ref: I,
    ) -> AbortOnDropHandle<io::Result<()>> {
        AbortOnDropHandle::new(tokio::spawn(
            async move {
                let iface = iface_ref.iface();
                let bind_uri = iface.bind_uri();

            let deliver_quic_packet = async |pkt: BytesMut, route: Route| {
                let Some(quic_router) = quic_router.as_ref() else {
                    return;
                };

                use qbase::packet::{self, Packet, PacketReader};
                fn is_initial_packet(pkt: &Packet) -> bool {
                    matches!(pkt, Packet::Data(packet) if matches!(packet.header, packet::DataHeader::Long(packet::long::DataHeader::Initial(..))))
                }

                let size = pkt.len();
                let bind_uri = bind_uri.clone();
                for (packet, way) in PacketReader::new(pkt, 8)
                    .flatten()
                    .filter(move |pkt| !(is_initial_packet(pkt) && size < 1100))
                    .map(move |pkt| (pkt, (bind_uri.clone(), route.pathway(), route.link())))
                {
                    quic_router.deliver(packet, way).await;
                }
            };

            let deliver_stun_packet = async |mut pkt: BytesMut, route: Route| {
                let Some(stun_router) = stun_router.as_ref() else {
                    return;
                };

                use crate::nat::msg::be_packet;
                let pkt = pkt.split_off(StunHeader::encoding_size());
                let Ok((.., (txid, packet))) = be_packet(&pkt) else {
                    return;
                };

                stun_router.deliver_stun_packet(txid, packet, route.link());
            };

            let deliver_forward_packet =
                async |mut pkt: BytesMut, mut route: Route, fhdr: ForwardHeader| {
                    if let Some(forwarder) = forwarder.as_ref()
                        && let Some(target) = forwarder.should_forward(fhdr.pathway().remote())
                    {
                        let bufs = &[io::IoSlice::new(&pkt)];
                        let new_link = Link::new(iface.bound_addr()?, target);
                        let new_line = Line::new(new_link, 64, None, pkt.len() as u16);
                        let new_route = Route::new(route.link.into(), new_line);
                        return iface.sendmmsg(bufs, new_route).await;
                    };

                    // split_off forward header, deliver the rest as quic packet
                    let pkt = pkt.split_off(ForwardHeader::encoding_size(&fhdr.pathway()));
                    route.seg_size = pkt.len() as _;
                    let new_route = Route::new(fhdr.pathway().flip().map(Into::into), route.line);
                    deliver_quic_packet(pkt, new_route).await;
                    Ok(())
                };

            let (mut bufs, mut hdrs) = (vec![], vec![]);
                loop {
                    use crate::packet::{Header, be_header};
                    for (pkt, hdr) in iface.recvmmsg(&mut bufs, &mut hdrs).await? {
                        match be_header(&pkt) {
                            // quic
                            Err(_) => deliver_quic_packet(pkt, hdr).await,
                            // stun
                            Ok((_remain, Header::Stun(_stun_header))) => {
                                deliver_stun_packet(pkt, hdr).await
                            }
                            // forward
                            Ok((_remain, Header::Forward(forward_header))) => {
                                deliver_forward_packet(pkt, hdr, forward_header).await?
                            }
                        }
                    }
                }
            }
            .in_current_span(),
        ))
    }
}

impl<I: RefIO + 'static> ReceiveAndDeliverPacket<I> {
    fn lock_ref_iface(&self) -> MutexGuard<'_, I> {
        self.ref_iface
            .lock()
            .expect("receive and deliver packet ref_iface lock poisoned")
    }

    fn lock_task(&self) -> MutexGuard<'_, Option<AbortOnDropHandle<io::Result<()>>>> {
        self.task.lock().unwrap()
    }
}

impl ReceiveAndDeliverPacketComponent {
    pub fn reinit(&self, iface: &Interface) {
        let new_ref_iface = iface.downgrade();
        if self.lock_ref_iface().same_io(&new_ref_iface) {
            return;
        }

        _ = iface.with_components(|components| {
            let quic_router = self
                .quic
                .then(|| {
                    components.with(|router: &QuicRouterComponent| {
                        router.reinit(iface);
                        router.router()
                    })
                })
                .flatten();
            let stun_router = self
                .stun
                .then(|| {
                    components.with(|router: &StunRouterComponent| {
                        router.reinit(iface);
                        router.router()
                    })
                })
                .flatten();
            let forwarder = self
                .forward
                .then(|| {
                    components.with(|forwarder: &ForwardersComponent| {
                        forwarder.reinit(iface);
                        forwarder.forwarder()
                    })
                })
                .flatten();
            if (self.quic && quic_router.is_none())
                || (self.stun && stun_router.is_none())
                || (self.forward && forwarder.is_none())
            {
                return;
            }
            *self.lock_task() = Some(
                Self::task()
                    .maybe_quic_router(quic_router)
                    .maybe_stun_router(stun_router)
                    .maybe_forwarder(forwarder)
                    .iface_ref(new_ref_iface.clone())
                    .spawn(),
            );
            *self.lock_ref_iface() = new_ref_iface;
        });
    }
}

impl Component for ReceiveAndDeliverPacketComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> std::task::Poll<()> {
        let mut task_guard = self.lock_task();
        if let Some(task) = task_guard.as_mut() {
            task.abort();
            _ = ready!(Pin::new(task).poll(cx));
            *task_guard = None;
        }
        Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        self.reinit(iface);
    }
}
