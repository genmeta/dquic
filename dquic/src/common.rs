use std::{iter, net::SocketAddr, sync::Arc};

use futures::{Stream, stream::FuturesUnordered};
use qconnection::{
    prelude::handy,
    qinterface::{
        BindInterface, Interface,
        bind_uri::BindUri,
        component::{
            Components,
            alive::RebindOnNetworkChangedComponent,
            local_endpoint::{LocalEndpoints, LocalEndpointsComponent},
            route::{QuicRouter, QuicRouterComponent},
        },
        device::Devices,
        io::ProductIO,
        manager::InterfaceManager,
    },
    qtraversal::{
        nat::{client::StunClientsComponent, router::StunRouterComponent},
        route::{ForwardersComponent, ReceiveAndDeliverPacketComponent},
    },
};
use qresolve::{Resolve, SystemResolver};

#[derive(Clone)]
pub struct Network {
    pub resolver: Arc<dyn Resolve + Send + Sync>,
    pub devices: &'static Devices,
    pub iface_factory: Arc<dyn ProductIO>,
    pub iface_manager: Arc<InterfaceManager>,
    pub quic_router: Arc<QuicRouter>,
    pub stun_server: Option<Arc<str>>,
    pub local_endpoints: Arc<LocalEndpoints>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
            devices: Devices::global(),
            iface_factory: Arc::new(handy::DEFAULT_IO_FACTORY),
            iface_manager: InterfaceManager::global().clone(),
            quic_router: QuicRouter::global().clone(),
            stun_server: None,
            local_endpoints: Arc::new(LocalEndpoints::new()),
        }
    }
}

impl Network {
    fn init_iface_components(&self, bind_iface: &BindInterface, stun_server: Option<Arc<str>>) {
        bind_iface.with_components_mut(move |components: &mut Components, iface: &Interface| {
            // rebind interface on network changed
            components.init_with(|| RebindOnNetworkChangedComponent::new(iface, self.devices));
            // quic packet router
            let quic_router = components
                .init_with(|| QuicRouterComponent::new(self.quic_router.clone()))
                .router();

            let local_endpoints = components
                .init_with(|| {
                    LocalEndpointsComponent::new(iface.downgrade(), self.local_endpoints.clone())
                })
                .clone();

            match &stun_server {
                // stun enabled:
                Some(stun_server) => {
                    // initial stun router
                    let stun_router = components
                        .init_with(|| StunRouterComponent::new(iface.downgrade()))
                        .router();
                    // initial stun clients (DNS 解析推迟到后台 lookup 任务)
                    let stun_server = stun_server.clone();
                    let clients = components
                        .init_with(|| {
                            StunClientsComponent::new(
                                iface.downgrade(),
                                stun_router.clone(),
                                self.resolver.clone(),
                                stun_server,
                                iter::empty(),
                                Some(local_endpoints.clone()),
                            )
                        })
                        .clone();
                    // initial forwarder
                    let relay = bind_iface
                        .bind_uri()
                        .relay()
                        .and_then(|r| r.parse::<SocketAddr>().ok());

                    let forwarder = if let Some(relay) = relay {
                        components
                            .init_with(|| ForwardersComponent::new_server(relay))
                            .forwarder()
                    } else {
                        components
                            .init_with(|| ForwardersComponent::new_client(clients))
                            .forwarder()
                    };

                    // initial receive and deliver packet component(quic, stun and forwarder)
                    components.init_with(|| {
                        ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                            .quic_router(quic_router)
                            .stun_router(stun_router)
                            .forwarder(forwarder)
                            .init()
                    });
                }
                // no stun: receive and deliver quic only
                None => {
                    components.init_with(|| {
                        ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                            .quic_router(quic_router)
                            .init()
                    });
                }
            };
        });
    }

    pub async fn bind(&self, bind_uri: BindUri) -> BindInterface {
        let stun_server = if let Some(server) = bind_uri.stun_server() {
            Some(Arc::from(server))
        } else if let Some("false") = bind_uri.prop(BindUri::STUN_PROP).as_deref() {
            None
        } else {
            self.stun_server.clone()
        };

        // STUN agent 的 DNS 解析推迟到 StunClientsComponent 的后台任务（它会在
        // clients < MIN_AGENTS 时自动触发 lookup，且自带超时保护）。bind 自身
        // 不再在关键路径上等待 DNS，避免 resolver 挂起导致整个绑定流程锁死。

        let factory = self.iface_factory.clone();
        let bind_iface = self.iface_manager.bind(bind_uri, factory).await;
        self.init_iface_components(&bind_iface, stun_server);

        bind_iface
    }

    pub async fn bind_many(
        &self,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
    ) -> impl Stream<Item = BindInterface> {
        bind_uris
            .into_iter()
            .map(|bind_uri| {
                let network = self.clone();
                async move { network.bind(bind_uri.into()).await }
            })
            .collect::<FuturesUnordered<_>>()
    }
}
