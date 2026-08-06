use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use qbase::net::route::{Line, Link};
use rand::RngExt;
use thiserror::Error;
use tokio::sync::SetOnce;

use crate::UdpSocket;

pub mod msg;

use msg::{Packet, WritePacket, be_packet};
pub use msg::{Request, Response, TransactionId};

const HEADER_MASK: u8 = 0b1111_1110;
const HEADER_BITS: u8 = 0b1100_0010;
const HEADER_LEN: usize = 9;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunHeader {
    version: u16,
}

impl StunHeader {
    pub fn new(version: u16) -> Self {
        Self { version }
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub const fn encoding_size() -> usize {
        HEADER_LEN
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
        if let Err(error) = send_packet(
            transaction.socket(),
            Packet::Request(transaction.request().clone()),
            txid,
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

    pub async fn on_packet(
        &self,
        socket: &Arc<UdpSocket>,
        payload: BytesMut,
        link: Link,
    ) -> io::Result<()> {
        let Ok((_, (txid, packet))) = be_packet(&payload) else {
            return Ok(());
        };

        match packet {
            Packet::Response(response) => {
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
                    transaction.complete(response, link);
                }
            }
            Packet::Request(request) => {
                if !self.server_enabled() {
                    return Ok(());
                }
                let handler = self.request_handler.read().unwrap().clone();
                let Some(response) = handler.and_then(|handler| handler(&request, link)) else {
                    return Ok(());
                };
                send_packet(socket, Packet::Response(response), txid, link.dst).await?;
            }
        }
        Ok(())
    }
}

pub fn looks_like_stun(input: &[u8]) -> bool {
    input
        .first()
        .is_some_and(|first| first & HEADER_MASK == HEADER_BITS)
}

pub fn decode_stun_header(input: &[u8]) -> Result<(StunHeader, usize), StunError> {
    if input.len() < HEADER_LEN
        || !looks_like_stun(input)
        || input[1..5] != [0; 4]
        || input[5] != 0
        || input[6] != 0
    {
        return Err(StunError::InvalidHeader);
    }
    Ok((
        StunHeader::new(u16::from_be_bytes([input[7], input[8]])),
        HEADER_LEN,
    ))
}

fn encode_packet(txid: TransactionId, packet: &Packet) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(128);
    buffer.put_u8(HEADER_BITS);
    buffer.put_u32(0);
    buffer.put_u8(0);
    buffer.put_u8(0);
    buffer.put_u16(0);
    buffer.put_packet(&txid, packet);
    buffer
}

async fn send_packet(
    socket: &UdpSocket,
    packet: Packet,
    txid: TransactionId,
    destination: SocketAddr,
) -> io::Result<()> {
    let buffer = encode_packet(txid, &packet);
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
    fn stun_header_round_trips() {
        let txid = TransactionId::random();
        let packet = encode_packet(txid, &Packet::Request(Request::default()));
        let (header, consumed) = decode_stun_header(&packet).unwrap();
        assert_eq!(header.version(), 0);
        assert_eq!(consumed, StunHeader::encoding_size());
        assert!(matches!(
            be_packet(&packet[consumed..]),
            Ok((_, (_, Packet::Request(_))))
        ));
    }
}
