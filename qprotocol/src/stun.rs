use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::BytesMut;
use dashmap::DashMap;
pub use qbase::datagram::stun::{
    Attribute as Attr, BindingRequest, BindingRequest as Request, BindingResponse,
    BindingResponse as Response, Message, MessageType, TransactionId, Type, WriteStunMessage,
    WriteStunType, WriteTransactionId, be_stun_message, be_stun_type, be_transaction_id,
};
use qbase::{
    datagram::{Datagram, WriteDatagram},
    net::route::{Line, Link},
};
use rand::RngExt;
use thiserror::Error;
use tokio::sync::SetOnce;

use crate::UdpSocket;

pub mod msg;

type RequestHandler = dyn Fn(&Request, Link) -> Option<Response> + Send + Sync + 'static;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CookieId([u8; 8]);

impl CookieId {
    pub fn random() -> Self {
        let mut id = [0; 8];
        rand::rng().fill(&mut id);
        Self(id)
    }
}

impl AsRef<[u8]> for CookieId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum StunError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid STUN header")]
    InvalidHeader,
}

#[derive(Debug)]
pub struct Transaction {
    socket: Arc<UdpSocket>,
    agent: SocketAddr,
    txid: TransactionId,
    cookie_id: CookieId,
    request: Request,
    result: SetOnce<(Response, Link)>,
}

impl Transaction {
    fn new(
        socket: Arc<UdpSocket>,
        agent: SocketAddr,
        request: Request,
        cookie_id: CookieId,
    ) -> Self {
        Self {
            socket,
            agent,
            txid: TransactionId::random(),
            cookie_id,
            request,
            result: SetOnce::new(),
        }
    }

    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    pub fn agent(&self) -> SocketAddr {
        self.agent
    }

    pub fn transaction_id(&self) -> TransactionId {
        self.txid
    }

    pub fn cookie_id(&self) -> CookieId {
        self.cookie_id
    }

    pub fn request(&self) -> &Request {
        &self.request
    }

    pub fn result(&self) -> Option<&(Response, Link)> {
        self.result.get()
    }

    pub async fn wait(&self) -> (Response, Link) {
        self.result.wait().await.clone()
    }

    fn complete(&self, response: Response, link: Link) {
        let _ = self.result.set((response, link));
    }
}

pub struct StunProtocol {
    transactions: DashMap<TransactionId, Arc<Transaction>>,
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

    pub async fn start_request(
        &self,
        socket: Arc<UdpSocket>,
        agent: SocketAddr,
        request: Request,
        cookie_id: CookieId,
    ) -> io::Result<Arc<Transaction>> {
        let transaction = Arc::new(Transaction::new(socket, agent, request, cookie_id));
        let txid = transaction.transaction_id();
        self.transactions.insert(txid, transaction.clone());
        if let Err(error) = send_datagram(
            transaction.socket(),
            txid,
            Message::Request(transaction.request().clone()),
            agent,
        )
        .await
        {
            self.transactions.remove(&txid);
            return Err(error);
        }
        Ok(transaction)
    }

    pub async fn request(
        &self,
        socket: Arc<UdpSocket>,
        agent: SocketAddr,
        request: Request,
        cookie_id: CookieId,
    ) -> io::Result<(Response, Link)> {
        let transaction = self
            .start_request(socket, agent, request, cookie_id)
            .await?;
        Ok(transaction.wait().await)
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
                let txid = transaction_id;
                let Some(transaction) = self
                    .transactions
                    .get(&txid)
                    .map(|transaction| transaction.clone())
                else {
                    return Ok(());
                };
                if transaction.agent() == link.dst && Arc::ptr_eq(transaction.socket(), socket) {
                    self.transactions
                        .remove_if(&txid, |_, registered| Arc::ptr_eq(registered, &transaction));
                    transaction.complete(body, link);
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
                send_datagram(
                    socket,
                    transaction_id,
                    Message::Response(response),
                    link.dst,
                )
                .await?;
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
    destination: SocketAddr,
) -> io::Result<()> {
    let buffer = encode_datagram(transaction_id, &message)?;
    let link = Link::new(socket.local_addr()?, destination);
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
    use super::*;

    #[test]
    fn binding_request_encodes() {
        let txid = TransactionId::random();
        let message = Message::Request(Request::default());
        assert!(!encode_datagram(txid, &message).unwrap().is_empty());
    }
}
