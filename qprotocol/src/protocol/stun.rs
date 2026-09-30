use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use dashmap::{DashMap, mapref::entry::Entry};
pub use qbase::datagram::stun::{
    Attribute as Attr, BindingRequest, BindingRequest as Request, BindingResponse,
    BindingResponse as Response, Message, MessageType, TransactionId, Type, WriteStunMessage,
    WriteStunType, WriteTransactionId, be_stun_message, be_stun_type, be_transaction_id,
};
use qbase::{
    ArcReceiving, Cancelled,
    datagram::{Datagram, WriteDatagram},
    net::{
        NatType, NetFeature,
        route::{Line, Link},
    },
};
use thiserror::Error;
use tokio::time::timeout;

use crate::socket::UdpSocket;

const PROBE_ATTEMPTS: u8 = 30;
const FILTER_ATTEMPTS: u8 = 3;
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// Changed-source listeners for one registered local socket.
#[derive(Debug, Clone, Copy)]
pub struct ChangeServer {
    /// Alternate listener port on the same local IP.
    pub change_port: u16,
    /// Public listener on another IP and port.
    pub change_address: SocketAddr,
    /// This listener's public address, with the same port as its local bind.
    pub outer_address: SocketAddr,
}

#[derive(Debug, Error)]
pub enum StunError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Reset(#[from] Cancelled),
    #[error("invalid STUN header")]
    InvalidHeader,
    #[error("STUN transaction response has already been read")]
    Completed,
}

pub struct Transaction {
    txid: TransactionId,
    protocol: Arc<StunProtocol>,
    receving: ArcReceiving<(Link, Response)>,
}

impl Transaction {
    pub fn id(&self) -> TransactionId {
        self.txid
    }

    pub async fn request(
        &mut self,
        link: Link,
        request: Request,
    ) -> Result<(Link, Response), StunError> {
        self.protocol.send_request(self.txid, link, request).await?;
        (&mut self.receving).await?.ok_or(StunError::Completed)
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.protocol.transactions.remove(&self.txid);
    }
}

pub struct StunProtocol {
    transactions: DashMap<TransactionId, ArcReceiving<(Link, Response)>>,
    sockets: DashMap<SocketAddr, Weak<UdpSocket>>,
    service: Arc<AtomicBool>,
    change_servers: DashMap<SocketAddr, ChangeServer>,
}

impl Default for StunProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl StunProtocol {
    pub fn new() -> Self {
        Self {
            transactions: DashMap::new(),
            sockets: DashMap::new(),
            service: Arc::new(AtomicBool::new(true)),
            change_servers: DashMap::new(),
        }
    }

    pub fn enable_service(&self) {
        self.service.store(true, Ordering::Release);
    }

    pub fn disable_service(&self) {
        self.service.store(false, Ordering::Release);
    }

    /// Configures changed-source responses for a socket already registered in Dock.
    ///
    /// Public mappings must preserve the bound port. The alternate local port
    /// and the remote server must have active STUN listeners; IP-only changes
    /// also require the remote server to listen on this socket's public port.
    /// Without a configuration, an enabled server only answers ordinary binding
    /// and response-address requests using the receiving address as its source.
    pub fn set_change_server(&self, bound: SocketAddr, server: ChangeServer) -> io::Result<()> {
        if [bound, server.outer_address, server.change_address]
            .iter()
            .any(|addr| {
                addr.ip().is_unspecified() || addr.port() == 0 || addr.is_ipv4() != bound.is_ipv4()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "STUN server addresses must be concrete and use the same address family",
            ));
        }
        if server.outer_address.port() != bound.port()
            || server.change_port == 0
            || server.change_port == bound.port()
            || server.change_address.ip() == server.outer_address.ip()
            || server.change_address.port() == server.outer_address.port()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "STUN public mapping must preserve the port and change listeners must change the requested IP/port",
            ));
        }

        // Keep the registration locked until insertion so unregister cannot
        // remove it between checking the socket and installing its configuration.
        let _sockets_guard = self.sockets.get(&bound).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no STUN socket bound to {bound}"),
            )
        })?;
        self.change_servers.insert(bound, server);
        Ok(())
    }

    async fn on_request(
        &self,
        socket: &UdpSocket,
        transaction_id: TransactionId,
        request: Request,
        link: Link,
    ) -> io::Result<()> {
        use qbase::datagram::stun::{CHANGE_IP, CHANGE_PORT};

        if !self.service.load(Ordering::Acquire) {
            return Ok(());
        }

        let bound = socket.local_addr()?;
        let config = self.change_servers.get(&bound).map(|entry| *entry.value());
        let source_addr = config.map_or(link.src, |config| config.outer_address);
        let changes = request.change_request().unwrap_or(0);
        if changes != 0 {
            let Some(config) = config else {
                tracing::trace!(target: "stun", %bound, changes, "dropping unsupported STUN change request");
                return Ok(());
            };
            let target = match (changes & CHANGE_IP != 0, changes & CHANGE_PORT != 0) {
                (false, true) => SocketAddr::new(link.src.ip(), config.change_port),
                (true, false) => SocketAddr::new(config.change_address.ip(), source_addr.port()),
                (true, true) => config.change_address,
                (false, false) => return Ok(()),
            };
            // Preserve the client's transaction ID; the next listener replies
            // directly to the client instead of responding to this server.
            return send_datagram(
                socket,
                transaction_id,
                Message::Request(Request::with_response_addr(link.dst)),
                Link::new(link.src, target),
            )
            .await;
        }

        let client_addr = request.response_address().copied().unwrap_or(link.dst);
        let mut attributes = vec![
            Attr::SourceAddress(source_addr),
            Attr::MappedAddress(client_addr),
        ];
        if let Some(config) = config {
            attributes.push(Attr::ChangedAddress(config.change_address));
        }
        send_datagram(
            socket,
            transaction_id,
            Message::Response(Response::with(attributes)),
            Link::new(link.src, client_addr),
        )
        .await
    }

    pub fn new_transaction(self: &Arc<Self>) -> Transaction {
        loop {
            let transaction_id = TransactionId::random();
            if let Entry::Vacant(entry) = self.transactions.entry(transaction_id) {
                let response = ArcReceiving::default();
                entry.insert(response.clone());
                return Transaction {
                    txid: transaction_id,
                    protocol: self.clone(),
                    receving: response,
                };
            }
        }
    }

    /// Discover this socket's mapped address at one STUN server.
    ///
    /// The concrete bound address must belong to a socket registered in this
    /// protocol's Dock. A binding response with MAPPED-ADDRESS is sufficient;
    /// changed-source support is only required by [`Self::detect_nat`].
    ///
    /// Returns `None` when all attempts go unanswered. This can reflect blocked
    /// traffic, packet loss or server failure; no NAT classification is performed.
    /// The address is specific to this server, particularly for `Symmetric` and
    /// `Dynamic` NATs. This task is independent of [`Self::detect_nat`].
    pub async fn detect_outer(
        self: &Arc<Self>,
        local_addr: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<Option<SocketAddr>, StunError> {
        let Some(first) = probe(
            self,
            local_addr,
            stun_server,
            Request::default(),
            PROBE_ATTEMPTS,
        )
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(first.map_addr()?))
    }

    /// Classify this socket's NAT with its own complete sequence of probes.
    ///
    /// This task does not depend on [`Self::detect_outer`] or reuse its responses.
    /// The concrete bound address must belong to a socket registered in this
    /// protocol's Dock. Keep it registered and avoid concurrent probes or other
    /// traffic to the discovery servers until classification finishes.
    /// Servers must support the project's STUN encoding and changed-source
    /// responses. Private-address detection requires three distinct server IPs.
    /// An unanswered initial probe returns `Blocked`; an unanswered final probe
    /// is classified as `Dynamic`. These can also reflect packet loss or server
    /// failure.
    pub async fn detect_nat(
        self: &Arc<Self>,
        local_addr: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<NatType, StunError> {
        let Some(first) = probe(
            self,
            local_addr,
            stun_server,
            Request::default(),
            PROBE_ATTEMPTS,
        )
        .await?
        else {
            return Ok(NatType::Blocked);
        };
        let outer_addr = first.map_addr()?;
        let server2 = first.changed_addr()?;
        if server2.ip() == stun_server.ip() || server2.port() == stun_server.port() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CHANGED-ADDRESS must change both IP and port",
            )
            .into());
        }
        let mut features = NetFeature::empty();

        let (filter_server, dynamic_server) = if outer_addr == local_addr {
            features |= NetFeature::Public;
            (stun_server, None)
        } else {
            let second = probe(
                self,
                local_addr,
                server2,
                Request::default(),
                PROBE_ATTEMPTS,
            )
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("NAT mapping probe to {server2} timed out"),
                )
            })?;

            if second.map_addr()? != outer_addr {
                return Ok(NatType::Symmetric);
            }
            let server3 = second.changed_addr()?;
            if server3.ip() == stun_server.ip()
                || server3.ip() == server2.ip()
                || server3.port() == server2.port()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NAT detection requires a third IP and a changed port",
                )
                .into());
            }
            (server2, Some(server3))
        };

        // Preserve qtraversal's retry limits for public and private filtering.
        let attempts = if dynamic_server.is_some() {
            FILTER_ATTEMPTS
        } else {
            PROBE_ATTEMPTS
        };
        for (request, feature) in [
            (Request::change_ip_and_port(), NetFeature::Restricted),
            (Request::change_port(), NetFeature::PortRestricted),
        ] {
            if probe(self, local_addr, filter_server, request, attempts)
                .await?
                .is_none()
            {
                features |= feature;
            }
        }

        // Contacting server3 earlier would change the filtering test conditions.
        if let Some(server3) = dynamic_server {
            let response = probe(
                self,
                local_addr,
                server3,
                Request::default(),
                PROBE_ATTEMPTS,
            )
            .await?;
            match response {
                Some(response) if response.map_addr()? == outer_addr => {}
                _ => features |= NetFeature::Dynamic,
            }
        }

        Ok(NatType::from(features))
    }

    pub(crate) fn register_socket(&self, bound: SocketAddr, socket: &Arc<UdpSocket>) {
        let socket = Arc::downgrade(socket);
        match self.sockets.entry(bound) {
            Entry::Occupied(mut entry) => {
                if !Weak::ptr_eq(entry.get(), &socket) {
                    self.change_servers.remove(&bound);
                    entry.insert(socket);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(socket);
            }
        }
    }

    pub(crate) fn unregister_socket(&self, bound: SocketAddr, socket: &Weak<UdpSocket>) {
        self.sockets.remove_if(&bound, |_, registered| {
            if !Weak::ptr_eq(registered, socket) {
                return false;
            }
            self.change_servers.remove(&bound);
            true
        });
    }

    fn find_socket(&self, bound: SocketAddr) -> Option<Arc<UdpSocket>> {
        let registered = self.sockets.get(&bound)?.clone();
        let socket = registered.upgrade();
        if socket.is_none() {
            self.unregister_socket(bound, &registered);
        }
        socket
    }

    async fn send_request(
        &self,
        transaction_id: TransactionId,
        link: Link,
        request: Request,
    ) -> io::Result<()> {
        let socket = self.find_socket(link.src).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no STUN socket bound to {}", link.src),
            )
        })?;
        send_datagram(&socket, transaction_id, Message::Request(request), link).await
    }

    pub async fn on_datagram(
        &self,
        socket: &Arc<UdpSocket>,
        transaction_id: TransactionId,
        message: Message,
        link: Link,
    ) -> io::Result<()> {
        match message {
            Message::Response(response) => {
                let transaction = self
                    .transactions
                    .get(&transaction_id)
                    .map(|entry| entry.clone());
                if let Some(receiving) = transaction {
                    receiving.obtain((link, response));
                }
            }
            Message::Request(request) => {
                if let Err(error) = self.on_request(socket, transaction_id, request, link).await {
                    tracing::warn!(target: "stun", %link, %error, "failed to handle STUN request");
                }
            }
        }
        Ok(())
    }
}

async fn probe(
    protocol: &Arc<StunProtocol>,
    local_addr: SocketAddr,
    server: SocketAddr,
    request: Request,
    attempts: u8,
) -> Result<Option<Response>, StunError> {
    use qbase::datagram::stun::{CHANGE_IP, CHANGE_PORT};

    if local_addr.ip().is_unspecified() || local_addr.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "STUN detection requires a concrete bound socket address",
        )
        .into());
    }

    let mut transaction = protocol.new_transaction();
    let link = Link::new(local_addr, server);
    for _ in 0..attempts {
        match timeout(PROBE_TIMEOUT, transaction.request(link, request.clone())).await {
            Ok(result) => {
                let (received, response) = result?;
                // Topology delivers links in local -> remote orientation.
                let source = received.dst;
                let flags = request.change_request().unwrap_or(0);
                let valid_ip = if flags & CHANGE_IP != 0 {
                    source.ip() != server.ip()
                } else {
                    source.ip() == server.ip()
                };
                let valid_port = if flags & CHANGE_PORT != 0 {
                    source.port() != server.port()
                } else {
                    source.port() == server.port()
                };
                if received.src != local_addr || !valid_ip || !valid_port {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected STUN response link: {received}"),
                    )
                    .into());
                }
                response.map_addr()?;
                if flags != 0 && response.source_addr()? != source {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "STUN SOURCE-ADDRESS does not match the packet source",
                    )
                    .into());
                }
                return Ok(Some(response));
            }
            Err(_) => continue,
        }
    }
    Ok(None)
}

fn encode_datagram(transaction_id: TransactionId, message: &Message) -> io::Result<BytesMut> {
    let mut buffer = BytesMut::with_capacity(128);
    buffer
        .put_datagram(&Datagram::Stun(transaction_id, message.clone()))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(buffer)
}

async fn send_datagram(
    socket: &UdpSocket,
    transaction_id: TransactionId,
    message: Message,
    link: Link,
) -> io::Result<()> {
    let buffer = encode_datagram(transaction_id, &message)?;
    let line = Line::new(
        link,
        Line::DEFAULT_TTL,
        None,
        buffer.len().min(u16::MAX as usize) as u16,
    );
    let slices = [IoSlice::new(&buffer)];
    if socket.send(&slices, line).await? == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "STUN socket sent zero datagrams",
        ))
    }
}

#[cfg(test)]
mod tests {
    mod client;
    mod server;

    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::{
        dock::Dock,
        protocol::{ForwardProtocol, QuicProtocol},
        topology::Topology,
    };

    #[test]
    fn binding_request_encodes() {
        let txid = TransactionId::random();
        let message = Message::Request(Request::default());
        assert!(!encode_datagram(txid, &message).unwrap().is_empty());
    }

    #[test]
    fn transaction_is_registered_until_drop() {
        let protocol = Arc::new(StunProtocol::new());
        let transaction = protocol.new_transaction();
        let transaction_id = transaction.id();

        assert!(protocol.transactions.contains_key(&transaction_id));

        drop(transaction);

        assert!(!protocol.transactions.contains_key(&transaction_id));
    }

    #[test]
    fn new_transactions_do_not_overwrite_each_other() {
        let protocol = Arc::new(StunProtocol::new());
        let first = protocol.new_transaction();
        let second = protocol.new_transaction();

        assert_ne!(first.id(), second.id());
        assert_eq!(protocol.transactions.len(), 2);
    }

    #[tokio::test]
    async fn transaction_retries_with_the_same_id_after_timeout() {
        let protocol = Arc::new(StunProtocol::new());
        protocol.disable_service();
        let topology = Arc::new(Topology::new(
            protocol.clone(),
            Arc::new(ForwardProtocol::new()),
            Arc::new(QuicProtocol::new()),
        ));
        let dock = Dock::new(topology);
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let agent = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let client_addr = client.local_addr().unwrap();
        let link = Link::new(client_addr, agent.local_addr().unwrap());
        dock.add(client).unwrap();
        dock.add(agent).unwrap();

        let mut transaction = protocol.new_transaction();
        let transaction_id = transaction.id();
        assert!(
            timeout(
                Duration::from_millis(20),
                transaction.request(link, Request::default()),
            )
            .await
            .is_err()
        );
        assert_eq!(transaction.id(), transaction_id);

        protocol.enable_service();
        let (response_link, response) = timeout(
            Duration::from_secs(1),
            transaction.request(link, Request::default()),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(response_link, link);
        assert_eq!(response.map_addr().unwrap(), client_addr);
        assert!(protocol.transactions.contains_key(&transaction_id));

        drop(transaction);

        assert!(!protocol.transactions.contains_key(&transaction_id));
    }
}
