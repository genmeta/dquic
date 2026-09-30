use std::{
    collections::HashSet,
    io::{self, IoSlice},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use dashmap::{DashMap, mapref::entry::Entry};
use qbase::{
    frame::{
        AddAddressFrame, PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, ReliableFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::{
        NatType,
        addr::EndpointAddr,
        route::{Line, Link, Pathway},
    },
    packet::assemble::Package,
};
use qprotocol::{BindUri, Dock, EphemeralSocket, QuicProtocol, UdpSocket, bind_uri::Scheme};
use tokio::task::AbortHandle;

use super::{
    predictor::PortPredictor,
    tx::{AsPunchId, PunchId, Transaction},
};
use crate::addr::{LocalAddress, PunchAddresses};

const HELLO_TTL: u8 = 64;
#[cfg(any(test, feature = "test-ttl"))]
const KNOCK_TTL: u8 = 1;
#[cfg(not(any(test, feature = "test-ttl")))]
const KNOCK_TTL: u8 = 5;
const DEFAULT_PROBE_ID: u32 = 0;
const MAX_RETRIES: usize = 5;
const COLLISION_PORTS: usize = 800;
const PUNCH_TIMEOUT: Duration = Duration::from_secs(3);
const BIRTHDAY_TIMEOUT: Duration = Duration::from_secs(8);
const COLLISION_TIMEOUT: Duration = Duration::from_secs(3);
const PUNCH_ME_NOW_TIMEOUT: Duration = Duration::from_secs(1);
const PUNCH_DONE_CONFIRM_RETRIES: usize = 3;
const PUNCH_DONE_CONFIRM_INTERVAL: Duration = Duration::from_millis(30);

/// Encodes one pathless 1-RTT packet using the connection's key and packet-number space.
pub trait PunchPacketEncoder: Clone + Send + Sync + 'static {
    fn encode_probe<P>(&self, frame: P) -> io::Result<BytesMut>
    where
        P: for<'b> Package<&'b mut BytesMut>;
}

pub struct ArcPuncher<TX, PE>(Arc<Puncher<TX, PE>>);

impl<TX, PE> Clone for ArcPuncher<TX, PE> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

struct Puncher<TX, PE> {
    addresses: Mutex<PunchAddresses>,
    transaction: DashMap<PunchId, (AbortHandle, Arc<Transaction>)>,
    punch_history: DashMap<PunchId, ()>,
    reliable_frames: TX,
    packet_encoder: PE,
    stun_servers: Arc<[SocketAddr]>,
    temporary_sockets: DashMap<EndpointAddr, EphemeralSocket>,
}

impl<TX, PE> ArcPuncher<TX, PE>
where
    TX: SendFrame<ReliableFrame> + Clone + Send + Sync + 'static,
    PE: PunchPacketEncoder,
{
    pub fn new(reliable_frames: TX, packet_encoder: PE, stun_servers: Arc<[SocketAddr]>) -> Self {
        Self(Arc::new(Puncher {
            addresses: Mutex::new(PunchAddresses::default()),
            transaction: DashMap::new(),
            punch_history: DashMap::new(),
            reliable_frames,
            packet_encoder,
            stun_servers,
            temporary_sockets: DashMap::new(),
        }))
    }

    pub fn on_local_added(
        &self,
        bind: BindUri,
        endpoint: EndpointAddr,
        outer: SocketAddr,
        tire: u32,
        nat: NatType,
    ) {
        let (local, remotes) = {
            let mut addresses = self.0.addresses.lock().unwrap();
            let frame = addresses.add_local(bind, endpoint, outer, tire, nat);
            self.0
                .reliable_frames
                .send_frame([ReliableFrame::AddAddress(frame)]);
            (
                addresses.local_for_seq(frame.seq_num()).unwrap(),
                addresses.remote_frames(),
            )
        };
        for remote in remotes {
            self.try_start_active(local.clone(), remote);
        }
    }

    pub fn on_local_removed(&self, endpoint: EndpointAddr) {
        let removed = {
            let mut addresses = self.0.addresses.lock().unwrap();
            let removed = addresses.remove_local_endpoint(endpoint);
            for frame in &removed {
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::RemoveAddress(*frame)]);
            }
            removed
        };
        for frame in removed {
            self.cancel_transactions_using_local(frame.seq_num.into_u64() as u32);
        }
    }

    pub fn recv_add_address(&self, frame: AddAddressFrame) {
        let added = self.0.addresses.lock().unwrap().add_remote(frame);
        if added {
            let local = self.0.addresses.lock().unwrap().pick_local(frame);
            if let Some(local) = local {
                self.try_start_active(local, frame);
            }
        }
    }

    pub fn recv_remove_address(&self, seq: u32) {
        if self
            .0
            .addresses
            .lock()
            .unwrap()
            .remove_remote(seq)
            .is_some()
        {
            self.cancel_transactions_using_remote(seq);
        }
    }

    fn try_start_active(&self, local: LocalAddress, remote: AddAddressFrame) {
        if local.frame.tire() != remote.tire()
            || local.frame.is_ipv4() != remote.is_ipv4()
            || *local.frame == *remote
        {
            return;
        }
        let id = (&local.frame, &remote).punch_id();
        if self.0.punch_history.contains_key(&id) {
            return;
        }
        if let Entry::Vacant(entry) = self.0.transaction.entry(id) {
            let tx = Arc::new(Transaction::new());
            let puncher = self.clone();
            let task_tx = tx.clone();
            let task = tokio::spawn(async move {
                let result = puncher.punch_actively(local, remote, task_tx).await;
                puncher.0.punch_history.insert(id, ());
                puncher.0.transaction.remove(&id);
                if let Err(error) = result {
                    tracing::debug!(target: "punch", %id, %error, "active punch ended");
                }
            });
            entry.insert((task.abort_handle(), tx));
        }
    }

    pub fn recv_punch_me_now(&self, pathway: Pathway, frame: PunchMeNowFrame) {
        let id = frame.punch_id().flip();
        if self.0.punch_history.contains_key(&id) {
            return;
        }
        let Some(local) = self
            .0
            .addresses
            .lock()
            .unwrap()
            .local_for_seq(frame.remote_seq())
        else {
            return;
        };
        match self.0.transaction.entry(id) {
            Entry::Occupied(mut entry) if pathway.local() < pathway.remote() => {
                entry.get().0.abort();
                let (abort, tx) = self.spawn_passive(id, local, frame);
                entry.insert((abort, tx));
            }
            Entry::Occupied(entry) => entry.get().1.store_punch_me_now(frame),
            Entry::Vacant(entry) => {
                let (abort, tx) = self.spawn_passive(id, local, frame);
                entry.insert((abort, tx));
            }
        }
    }

    fn spawn_passive(
        &self,
        id: PunchId,
        local: LocalAddress,
        frame: PunchMeNowFrame,
    ) -> (AbortHandle, Arc<Transaction>) {
        let tx = Arc::new(Transaction::new());
        tx.store_punch_me_now(frame);
        let puncher = self.clone();
        let task_tx = tx.clone();
        let task = tokio::spawn(async move {
            let result = puncher.punch_passively(local, frame, task_tx).await;
            puncher.0.punch_history.insert(id, ());
            puncher.0.transaction.remove(&id);
            if let Err(error) = result {
                tracing::debug!(target: "punch", %id, %error, "passive punch ended");
            }
        });
        (task.abort_handle(), tx)
    }

    pub fn recv_punch_hello(&self, pathway: Pathway, link: Link, frame: PunchHelloFrame) {
        let id = frame.punch_id().flip();
        if let Some(entry) = self.0.transaction.get(&id) {
            let tx = entry.value().1.clone();
            drop(entry);
            let _ = tx.recv_frame((link, frame));
        } else {
            self.0
                .reliable_frames
                .send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&frame))]);
        }
        let local = pathway.local();
        let puncher = self.clone();
        tokio::spawn(async move {
            let Some(socket) = QuicProtocol::global().find_socket(local) else {
                return;
            };
            let done = PunchDoneFrame::respond_to(&frame);
            for attempt in 0..PUNCH_DONE_CONFIRM_RETRIES {
                if let Err(error) = puncher.send_packet(&socket, link, HELLO_TTL, done).await {
                    tracing::debug!(target: "punch", %link, %error, "direct PunchDone failed");
                }
                if attempt + 1 < PUNCH_DONE_CONFIRM_RETRIES {
                    tokio::time::sleep(PUNCH_DONE_CONFIRM_INTERVAL).await;
                }
            }
        });
    }

    pub fn recv_punch_done(&self, link: Link, frame: PunchDoneFrame) {
        if let Some(entry) = self.0.transaction.get(&frame.punch_id().flip()) {
            let tx = entry.value().1.clone();
            drop(entry);
            let _ = tx.recv_frame((link, frame));
        }
    }

    fn cancel_transactions_using_local(&self, seq: u32) {
        let ids = self
            .0
            .transaction
            .iter()
            .filter_map(|entry| (entry.key().local_seq == seq).then_some(*entry.key()))
            .collect::<Vec<_>>();
        for id in ids {
            if let Some((_, (abort, _))) = self.0.transaction.remove(&id) {
                abort.abort();
            }
            self.0.punch_history.remove(&id);
        }
    }

    fn cancel_transactions_using_remote(&self, seq: u32) {
        let ids = self
            .0
            .transaction
            .iter()
            .filter_map(|entry| (entry.key().remote_seq == seq).then_some(*entry.key()))
            .collect::<Vec<_>>();
        for id in ids {
            if let Some((_, (abort, _))) = self.0.transaction.remove(&id) {
                abort.abort();
            }
            self.0.punch_history.remove(&id);
        }
    }

    pub fn abort_transactions(&self) {
        for entry in self.0.transaction.iter() {
            entry.value().0.abort();
        }
        self.0.transaction.clear();
    }

    pub fn release_temporary_sockets(&self) {
        self.0.temporary_sockets.clear();
    }

    pub async fn send_packet<P>(
        &self,
        socket: &UdpSocket,
        link: Link,
        ttl: u8,
        frame: P,
    ) -> io::Result<()>
    where
        P: for<'b> Package<&'b mut BytesMut>,
    {
        let bytes = self.0.packet_encoder.encode_probe(frame)?;
        socket
            .send(
                &[IoSlice::new(&bytes)],
                Line::new(link, ttl, None, bytes.len() as u16),
            )
            .await?;
        Ok(())
    }

    fn send_reliable_done(&self, hello: &PunchHelloFrame) {
        self.0
            .reliable_frames
            .send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(hello))]);
    }

    async fn wait_hello_or_done(&self, tx: &Transaction, delay: Duration) -> io::Result<()> {
        tokio::select! {
            (_, hello) = tx.wait_punch_hello() => {
                self.send_reliable_done(&hello);
                Ok(())
            }
            _ = tx.wait_punch_done() => Ok(()),
            _ = tokio::time::sleep(delay) => Err(timed_out()),
        }
    }

    async fn retry_hello(
        &self,
        socket: &UdpSocket,
        link: Link,
        id: PunchId,
        tx: &Transaction,
        hello_or_done: bool,
    ) -> io::Result<()> {
        let time = Duration::from_millis(100);
        for attempt in 0..MAX_RETRIES {
            self.send_packet(
                socket,
                link,
                HELLO_TTL,
                PunchHelloFrame::new(id.local_seq, id.remote_seq, DEFAULT_PROBE_ID),
            )
            .await?;
            let delay = time * (1 << attempt);
            if hello_or_done {
                if self.wait_hello_or_done(tx, delay).await.is_ok() {
                    return Ok(());
                }
            } else if tokio::time::timeout(delay, tx.wait_punch_done())
                .await
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(timed_out())
    }

    async fn collision(
        &self,
        socket: &UdpSocket,
        link: Link,
        id: PunchId,
        ttl: u8,
    ) -> io::Result<()> {
        let mut ports = HashSet::new();
        while ports.len() < COLLISION_PORTS {
            let port = 1024 + rand::random::<u16>() % (u16::MAX - 1024);
            if !ports.insert(port) {
                continue;
            }
            let target = Link::new(link.src, SocketAddr::new(link.dst.ip(), port));
            self.send_packet(
                socket,
                target,
                ttl,
                PunchHelloFrame::new(id.local_seq, id.remote_seq, DEFAULT_PROBE_ID),
            )
            .await?;
        }
        Ok(())
    }

    async fn dynamic_socket(&self, bind: &BindUri) -> io::Result<(EphemeralSocket, SocketAddr)> {
        let port = 1024 + rand::random::<u16>() % (u16::MAX - 1024);
        let uri = match bind.scheme() {
            Scheme::Iface => {
                let (family, device, _) = bind.as_iface_bind_uri().unwrap();
                format!(
                    "iface://{family}.{device}:{port}?{}=true",
                    BindUri::TEMPORARY_PROP
                )
            }
            Scheme::Inet => {
                let ip = bind.as_inet_bind_uri().unwrap().ip();
                format!("inet://{ip}:{port}?{}=true", BindUri::TEMPORARY_PROP)
            }
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        let uri = BindUri::from_str(&uri).map_err(io::Error::other)?;
        let mut socket =
            EphemeralSocket::bind_resolved(Dock::global().clone(), uri.resolve_binding()?)?;
        let local = socket.udp_socket().local_addr()?;
        socket.register_quic(EndpointAddr::direct(local))?;
        let server = self
            .0
            .stun_servers
            .iter()
            .copied()
            .find(|server| server.is_ipv4() == local.is_ipv4())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no STUN server for address family")
            })?;
        let outer = socket
            .outer_addr(Dock::global().topology().stun(), server)
            .await
            .map_err(io::Error::other)?;
        Ok((socket, outer))
    }

    fn retain_temporary(&self, socket: EphemeralSocket) -> io::Result<()> {
        let local = socket.udp_socket().local_addr()?;
        self.0
            .temporary_sockets
            .insert(EndpointAddr::direct(local), socket);
        Ok(())
    }

    async fn predict(
        &self,
        bind: BindUri,
        dst: SocketAddr,
        id: PunchId,
        tx: Arc<Transaction>,
    ) -> io::Result<EphemeralSocket> {
        let mut predictor = PortPredictor::new(bind, dst)?;
        let puncher = self.clone();
        predictor
            .predict(id, tx, move |socket, link, ttl, frame| {
                let puncher = puncher.clone();
                async move { puncher.send_packet(&socket, link, ttl, frame).await }
            })
            .await?
            .ok_or_else(timed_out)
    }

    async fn punch_actively(
        &self,
        local: LocalAddress,
        remote: AddAddressFrame,
        tx: Arc<Transaction>,
    ) -> io::Result<()> {
        use NatType::*;
        let id = (&local.frame, &remote).punch_id();
        let local_nat = local.frame.nat_type();
        let remote_nat = remote.nat_type();
        let dst = *remote;
        let local_addr = local.endpoint.addr();
        let link = Link::new(local_addr, dst);
        let socket = QuicProtocol::global()
            .find_socket(local.endpoint)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "local socket unavailable")
            })?;
        let mut now = PunchMeNowFrame::new(
            id.local_seq,
            id.remote_seq,
            *local.frame,
            local.frame.tire(),
            local_nat,
        );

        match (local_nat, remote_nat) {
            (Blocked, _) | (_, Blocked) | (Symmetric, Symmetric) => {
                Err(io::Error::other("unsupported NAT pair"))
            }
            (_, FullCone) => self.retry_hello(&socket, link, id, &tx, true).await,
            (Dynamic, Symmetric) => {
                let (temporary, outer) = self.dynamic_socket(&local.bind).await?;
                let temp_addr = temporary.udp_socket().local_addr()?;
                let temp_socket = temporary.udp_socket().clone();
                let temp_endpoint = EndpointAddr::direct(temp_addr);
                self.retain_temporary(temporary)?;
                now.set_addr(outer);
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                let temp_link = Link::new(temp_addr, dst);
                let result = async {
                    tokio::time::timeout(PUNCH_ME_NOW_TIMEOUT, tx.wait_punch_me_now())
                        .await
                        .map_err(|_| timed_out())?;
                    self.collision(&temp_socket, temp_link, id, KNOCK_TTL)
                        .await?;
                    self.wait_hello_or_done(&tx, BIRTHDAY_TIMEOUT).await
                }
                .await;
                if result.is_err() {
                    self.0.temporary_sockets.remove(&temp_endpoint);
                }
                result
            }
            (Symmetric, RestrictedPort) => {
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                tokio::time::timeout(COLLISION_TIMEOUT, tx.wait_punch_me_now())
                    .await
                    .map_err(|_| timed_out())?;
                let won = self.predict(local.bind, dst, id, tx).await?;
                self.retain_temporary(won)
            }
            (Symmetric, RestrictedCone) => {
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                let _ = tokio::time::timeout(PUNCH_ME_NOW_TIMEOUT, tx.wait_punch_me_now()).await;
                self.retry_hello(&socket, link, id, &tx, false).await
            }
            (Dynamic, _) => {
                let (temporary, outer) = self.dynamic_socket(&local.bind).await?;
                let temp_addr = temporary.udp_socket().local_addr()?;
                let temp_socket = temporary.udp_socket().clone();
                let temp_endpoint = EndpointAddr::direct(temp_addr);
                self.retain_temporary(temporary)?;
                now.set_addr(outer);
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                let temp_link = Link::new(temp_addr, dst);
                let result = self
                    .retry_hello(&temp_socket, temp_link, id, &tx, true)
                    .await;
                if result.is_err() {
                    self.0.temporary_sockets.remove(&temp_endpoint);
                }
                result
            }
            (FullCone | RestrictedCone, Symmetric)
            | (FullCone | RestrictedCone | RestrictedPort, Dynamic)
            | (_, RestrictedCone | RestrictedPort) => {
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                self.send_packet(
                    &socket,
                    link,
                    HELLO_TTL,
                    PunchHelloFrame::new(id.local_seq, id.remote_seq, DEFAULT_PROBE_ID),
                )
                .await?;
                let (_, hello) = tokio::time::timeout(PUNCH_TIMEOUT, tx.wait_punch_hello())
                    .await
                    .map_err(|_| timed_out())?;
                self.send_reliable_done(&hello);
                Ok(())
            }
            (RestrictedPort, Symmetric) => {
                self.collision(&socket, link, id, KNOCK_TTL).await?;
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                let (_, hello) = tokio::time::timeout(BIRTHDAY_TIMEOUT, tx.wait_punch_hello())
                    .await
                    .map_err(|_| timed_out())?;
                self.send_reliable_done(&hello);
                Ok(())
            }
            (Symmetric, Dynamic) => {
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                let won = self.predict(local.bind, dst, id, tx).await?;
                self.retain_temporary(won)
            }
        }
    }

    async fn punch_passively(
        &self,
        local: LocalAddress,
        remote: PunchMeNowFrame,
        tx: Arc<Transaction>,
    ) -> io::Result<()> {
        use NatType::*;
        let id = PunchId::new(local.frame.seq_num(), remote.local_seq());
        let local_nat = local.frame.nat_type();
        let remote_nat = remote.nat_type();
        let link = Link::new(local.endpoint.addr(), remote.address());
        let socket = QuicProtocol::global()
            .find_socket(local.endpoint)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "local socket unavailable")
            })?;
        let now = PunchMeNowFrame::new(
            id.local_seq,
            id.remote_seq,
            *local.frame,
            local.frame.tire(),
            local_nat,
        );
        if matches!(
            (local_nat, remote_nat),
            (Blocked, _) | (_, Blocked) | (Symmetric, Symmetric)
        ) {
            return Err(io::Error::other("unsupported NAT pair"));
        }
        match (local_nat, remote_nat) {
            (Dynamic, Symmetric) => {
                tokio::time::timeout(PUNCH_ME_NOW_TIMEOUT, tx.wait_punch_me_now())
                    .await
                    .map_err(|_| timed_out())?;
                self.collision(&socket, link, id, KNOCK_TTL).await?;
                self.wait_hello_or_done(&tx, BIRTHDAY_TIMEOUT).await
            }
            (RestrictedPort, Symmetric) => {
                self.collision(&socket, link, id, KNOCK_TTL).await?;
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                let (_, hello) = tokio::time::timeout(BIRTHDAY_TIMEOUT, tx.wait_punch_hello())
                    .await
                    .map_err(|_| timed_out())?;
                self.send_reliable_done(&hello);
                Ok(())
            }
            (Symmetric, RestrictedPort | Dynamic) => {
                let won = self.predict(local.bind, link.dst, id, tx).await?;
                self.retain_temporary(won)
            }
            (RestrictedCone, Symmetric) => {
                self.send_packet(
                    &socket,
                    link,
                    HELLO_TTL,
                    PunchHelloFrame::new(id.local_seq, id.remote_seq, DEFAULT_PROBE_ID),
                )
                .await?;
                self.0
                    .reliable_frames
                    .send_frame([ReliableFrame::PunchMeNow(now)]);
                let (_, hello) = tokio::time::timeout(PUNCH_TIMEOUT, tx.wait_punch_hello())
                    .await
                    .map_err(|_| timed_out())?;
                self.send_reliable_done(&hello);
                Ok(())
            }
            _ => self.retry_hello(&socket, link, id, &tx, true).await,
        }
    }
}

impl<TX, PE> Drop for Puncher<TX, PE> {
    fn drop(&mut self) {
        for entry in self.transaction.iter() {
            entry.value().0.abort();
        }
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "punch timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct RecordedFrames(Arc<Mutex<Vec<ReliableFrame>>>);

    impl SendFrame<ReliableFrame> for RecordedFrames {
        fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[derive(Clone)]
    struct UnusedEncoder;

    impl PunchPacketEncoder for UnusedEncoder {
        fn encode_probe<P>(&self, _: P) -> io::Result<BytesMut>
        where
            P: for<'b> Package<&'b mut BytesMut>,
        {
            unreachable!("this test only sends reliable address frames")
        }
    }

    #[test]
    fn local_addresses_are_announced_when_added_on_the_reliable_queue() {
        let frames = RecordedFrames::default();
        let puncher = ArcPuncher::new(frames.clone(), UnusedEncoder, Arc::from([]));
        let endpoint = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
        puncher.on_local_added(
            "inet://127.0.0.1:5000".parse().unwrap(),
            endpoint,
            "198.51.100.1:5000".parse().unwrap(),
            1,
            NatType::RestrictedCone,
        );
        assert!(matches!(
            frames.0.lock().unwrap().as_slice(),
            [ReliableFrame::AddAddress(frame)] if frame.seq_num() == 0
        ));
        puncher.on_local_removed(endpoint);
        assert!(matches!(
            frames.0.lock().unwrap().last(),
            Some(ReliableFrame::RemoveAddress(frame)) if frame.seq_num.into_u64() == 0
        ));
    }

    #[tokio::test]
    async fn dock_observation_announces_mapping_changes_and_detaches_on_close() {
        let dock = Dock::new(Arc::new(qprotocol::topology::Topology::new(
            Arc::new(qprotocol::StunProtocol::new()),
            Arc::new(qprotocol::ForwardProtocol::new()),
            Arc::new(QuicProtocol::new()),
        )));
        let endpoint = dock.bind("127.0.0.1:0").unwrap();
        let binding = dock.bindings().pop().unwrap();
        let socket = binding.socket().clone();
        let frames = RecordedFrames::default();
        let puncher = ArcPuncher::new(frames.clone(), UnusedEncoder, Arc::from([]));
        let (close, closed) = tokio::sync::oneshot::channel::<()>();
        let (removed, mut removals) = tokio::sync::mpsc::unbounded_channel();
        puncher.observe_endpoints(dock.subscribe(), closed, move |endpoint| {
            let _ = removed.send(endpoint);
        });
        assert!(matches!(
            frames.0.lock().unwrap().as_slice(),
            [ReliableFrame::AddAddress(frame)] if frame.seq_num() == 0
        ));

        let outer = "198.51.100.1:5000".parse().unwrap();
        dock.update_outer(&binding, "127.0.0.1:3478".parse().unwrap(), outer)
            .unwrap();
        dock.update_nat(&binding, NatType::RestrictedCone).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), removals.recv())
                .await
                .unwrap(),
            Some(endpoint)
        );
        assert!(matches!(
            frames.0.lock().unwrap().as_slice(),
            [ReliableFrame::AddAddress(_), ReliableFrame::RemoveAddress(old), ReliableFrame::AddAddress(new)]
                if old.seq_num.into_u64() == 0 && new.seq_num() == 1 && **new == outer
        ));

        // An alias-only update must not withdraw and re-advertise the same address.
        dock.register_endpoint(
            EndpointAddr::direct("203.0.113.1:5000".parse().unwrap()),
            &socket,
        )
        .unwrap();
        assert!(dock.remove(&socket));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), removals.recv())
                .await
                .unwrap(),
            Some(endpoint)
        );
        assert!(matches!(
            frames.0.lock().unwrap().as_slice(),
            [ReliableFrame::AddAddress(_), ReliableFrame::RemoveAddress(_), ReliableFrame::AddAddress(_), ReliableFrame::RemoveAddress(frame)]
                if frame.seq_num.into_u64() == 1
        ));

        close.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), removals.recv())
                .await
                .unwrap(),
            None
        );
        let replacement = dock.bind("127.0.0.1:0").unwrap();
        assert!(dock.find_socket(replacement.addr()).is_some());
        assert_eq!(frames.0.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn adding_another_default_group_binding_probes_that_specific_socket() {
        let puncher = ArcPuncher::new(RecordedFrames::default(), UnusedEncoder, Arc::from([]));
        let first = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
        let second = EndpointAddr::direct("127.0.0.1:5001".parse().unwrap());
        puncher.on_local_added(
            first.addr().into(),
            first,
            first.addr(),
            0,
            NatType::FullCone,
        );
        puncher.recv_add_address(AddAddressFrame::new(
            9,
            "127.0.0.1:6000".parse().unwrap(),
            0,
            NatType::FullCone,
        ));
        puncher.on_local_added(
            second.addr().into(),
            second,
            second.addr(),
            0,
            NatType::FullCone,
        );
        assert!(puncher.0.transaction.contains_key(&PunchId::new(0, 9)));
        assert!(puncher.0.transaction.contains_key(&PunchId::new(1, 9)));
        // Cancel before yielding: this verifies scheduling without sending a UDP probe.
        puncher.abort_transactions();
    }

    #[tokio::test]
    async fn unsolicited_direct_hello_gets_a_reliable_done_response() {
        let frames = RecordedFrames::default();
        let puncher = ArcPuncher::new(frames.clone(), UnusedEncoder, Arc::from([]));
        let link = Link::new(
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
        );
        let hello = PunchHelloFrame::new(1, 2, 3);
        puncher.recv_punch_hello(link.into(), link, hello);
        assert!(matches!(
            frames.0.lock().unwrap().as_slice(),
            [ReliableFrame::PunchDone(done)] if *done == PunchDoneFrame::respond_to(&hello)
        ));
    }
}
