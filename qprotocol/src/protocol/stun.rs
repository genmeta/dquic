use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
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
    net::route::{Line, Link},
};
use thiserror::Error;

use crate::socket::UdpSocket;

type RequestHandler = dyn Fn(&Request, Link) -> Option<Response> + Send + Sync + 'static;

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
    server_enabled: Arc<AtomicBool>,
    request_handler: RwLock<Option<Arc<RequestHandler>>>,
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
            server_enabled: Arc::new(AtomicBool::new(false)),
            request_handler: RwLock::new(None),
        }
    }

    pub fn enable_server(&self, enabled: bool) {
        self.server_enabled.store(enabled, Ordering::Release);
    }

    pub fn server_enabled(&self) -> bool {
        self.server_enabled.load(Ordering::Acquire)
    }

    pub fn on_request(
        &self,
        handler: impl Fn(&Request, Link) -> Option<Response> + Send + Sync + 'static,
    ) {
        *self.request_handler.write().unwrap() = Some(Arc::new(handler));
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

    pub(crate) fn register_socket(&self, bound: SocketAddr, socket: &Arc<UdpSocket>) {
        self.sockets.insert(bound, Arc::downgrade(socket));
    }

    pub(crate) fn unregister_socket(&self, bound: SocketAddr, socket: &Weak<UdpSocket>) {
        self.sockets
            .remove_if(&bound, |_, registered| Weak::ptr_eq(registered, socket));
    }

    fn socket(&self, bound: SocketAddr) -> Option<Arc<UdpSocket>> {
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
        let socket = self.socket(link.src).ok_or_else(|| {
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
            Message::Response(body) => {
                let response = self
                    .transactions
                    .get(&transaction_id)
                    .map(|response| response.clone());
                if let Some(receiving) = response {
                    receiving.obtain((link, body));
                }
            }
            Message::Request(body) => {
                if !self.server_enabled() {
                    return Ok(());
                }
                let handler = self.request_handler.read().unwrap().clone();
                let Some(response) = handler.and_then(|handler| handler(&body, link)) else {
                    return Ok(());
                };
                send_datagram(socket, transaction_id, Message::Response(response), link).await?;
            }
        }
        Ok(())
    }
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

        protocol
            .on_request(move |_, link| Some(Response::with(vec![Attr::MappedAddress(link.dst)])));
        protocol.enable_server(true);
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
