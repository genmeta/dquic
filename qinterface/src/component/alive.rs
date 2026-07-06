use std::{
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Mutex, MutexGuard},
    task::{Context, Poll, ready},
};

use qbase::net::route::{Line, Link, Route};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument as _;

use crate::{
    Interface, RebindedError,
    component::Component,
    device::Devices,
    io::{IO, IoExt},
};

#[derive(Debug, Error)]
pub enum InterfaceFailure {
    #[error("Invalid QuicIO implementation")]
    InvalidImplementation,
    #[error("Interface is broken: {0}")]
    InterfaceBroken(io::Error),
    #[error("Real address does not match bind URI")]
    AddressMismatch,
    #[error("Failed to bind test socket: {0}")]
    TestSocketBindFailed(io::Error),
    #[error("Failed to send test packet: {0}")]
    SendTestFailed(io::Error),
}

impl From<io::Error> for InterfaceFailure {
    fn from(error: io::Error) -> Self {
        Self::TestSocketBindFailed(error)
    }
}

impl InterfaceFailure {
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::InterfaceBroken(..) | Self::AddressMismatch | Self::SendTestFailed(..)
        )
    }
}

pub async fn is_alive(iface: &(impl IO + ?Sized)) -> Result<(), InterfaceFailure> {
    let bound_addr = iface
        .bound_addr()
        .map_err(InterfaceFailure::InterfaceBroken)?;

    let socket_addr = SocketAddr::try_from(&iface.bind_uri())?;

    // Check if addresses match
    if !(bound_addr.ip() == socket_addr.ip()
        && (socket_addr.port() == 0 || bound_addr.port() == socket_addr.port()))
    {
        return Err(InterfaceFailure::AddressMismatch);
    }

    // Test connectivity with a local socket
    let localhost = match bound_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => Ipv4Addr::LOCALHOST.into(),
        IpAddr::V4(ip) => ip.into(),
        IpAddr::V6(ip) if ip.is_unspecified() => Ipv6Addr::LOCALHOST.into(),
        IpAddr::V6(ip) => ip.into(),
    };
    let socket = UdpSocket::bind(SocketAddr::new(localhost, 0))
        .await
        .map_err(InterfaceFailure::TestSocketBindFailed)?;
    let dst_addr = socket
        .local_addr()
        .map_err(InterfaceFailure::TestSocketBindFailed)?;

    // Send test packet
    let link = Link::new(bound_addr, dst_addr);
    let packets = [io::IoSlice::new(&[0; 1])];
    let line = Line::new(link, 64, None, packets[0].len() as u16);
    let header = Route::new(link.into(), line);

    iface
        .sendmmsg(&packets, header)
        .await
        .map_err(InterfaceFailure::SendTestFailed)?;

    Ok(())
}

#[derive(Debug)]
pub struct RebindOnNetworkChangedComponent {
    devices: &'static Devices,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl RebindOnNetworkChangedComponent {
    pub fn new(iface: &Interface, devices: &'static Devices) -> Self {
        let component = Self {
            devices,
            task: Mutex::new(None),
        };
        component.init(iface);
        component
    }

    fn lock_task(&self) -> MutexGuard<'_, Option<AbortOnDropHandle<()>>> {
        self.task
            .lock()
            .expect("RebindOnNetworkChanged task mutex poisoned")
    }

    fn init(&self, iface: &Interface) {
        let mut task = self.lock_task();
        if !task.as_ref().is_none_or(|t| t.is_finished()) {
            return;
        }

        let bind_uri = iface.bind_uri();
        if bind_uri.is_temporary() {
            return;
        }
        let Some((_, device, ..)) = bind_uri.as_iface_bind_uri() else {
            return;
        };

        let device = device.to_owned();
        let weak_iface = iface.bind_interface().downgrade();
        let mut event_receiver = self.devices.event_receiver();
        *task = Some(AbortOnDropHandle::new(tokio::spawn(
            async move {
                let try_rebind = async move || {
                    if let Ok(iface) = weak_iface.upgrade()
                        && let Err(error) = is_alive(&iface.borrow()).await
                        && error.is_recoverable()
                        && !RebindedError::is_source_of(&error)
                    {
                        iface.rebind().await;
                    }
                };

                try_rebind().await;
                while let Some(event) = event_receiver.recv().await {
                    if event.device() != device {
                        continue;
                    }
                    try_rebind().await;
                }
            }
            .in_current_span(),
        )));
    }
}

impl Component for RebindOnNetworkChangedComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut task_guard = self.lock_task();
        if let Some(task) = task_guard.as_mut() {
            task.abort();
            _ = ready!(Pin::new(task).poll(cx));
            *task_guard = None;
        }
        Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        self.init(iface);
    }
}
