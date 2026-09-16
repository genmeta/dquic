use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use qbase::{
    Epoch,
    error::{Error, ErrorKind, QuicError},
    frame::{
        Frame, FrameReader, HandshakeDoneFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::tx::Signals,
    packet::{
        DataHeader, DataPacket, GetScid, GetType, Packet, PacketContent, PacketContent as Content,
        long, number::take_pn_len,
    },
    role::Role,
};
use qcongestion::Transport as _;
use qrecovery::journal::ArcRcvdJournal;
use tokio::{
    sync::{mpsc, oneshot},
    time::Instant,
};

use crate::{
    control::{Command, Phase},
    path::Event,
    router::ReceivedPacket,
    transport::Transport,
};

/// Opening nodes owned exclusively by the connection's receive future. Packet
/// numbers are committed only after the component pipes have accepted the frames.
pub(crate) struct Topology {
    opening: [Option<(Arc<qtls::HeaderProtectionKey>, qtls::PacketKey)>; 3],
    journals: [Option<ArcRcvdJournal>; 3],
    enabled: [bool; 3],
    next_secret: Option<qtls::Secrets>,
    next: Option<qtls::PacketKey>,
    previous: Option<(qtls::PacketKey, Instant)>,
    generation: u64,
    generation_first_pn: u64,
    generation_largest_pn: Option<u64>,
    confirmed: bool,
}

impl Topology {
    pub(crate) fn new(initial: qtls::DirectionalKeys) -> Self {
        Self {
            opening: [Some((Arc::new(initial.header), initial.packet)), None, None],
            journals: [Some(ArcRcvdJournal::with_capacity(0, None)), None, None],
            enabled: [true; 3],
            next_secret: None,
            next: None,
            previous: None,
            generation: 0,
            generation_first_pn: 0,
            generation_largest_pn: None,
            confirmed: false,
        }
    }

    async fn retire(&mut self, transport: &Transport, epoch: Epoch) {
        transport
            .spaces
            .enabled
            .fetch_and(!(1 << epoch as usize), std::sync::atomic::Ordering::AcqRel);
        self.discard(epoch);
        for path in transport.paths.snapshot() {
            let (done, finished) = oneshot::channel();
            if path.events.send(Event::Retire(epoch, done)).await.is_ok() {
                let _ = finished.await;
            }
        }
        transport.spaces.retire(epoch);
    }

    async fn confirm_handshake(&mut self, transport: &Transport) {
        if self.confirmed {
            return;
        }
        self.confirm();
        transport.control.handshake.handshake_confirmed();
        self.retire(transport, Epoch::Handshake).await;
        if transport.control.role == Role::Client {
            for path in transport.paths.snapshot() {
                if transport.paths.selected.get() == Some(&path.pathway) {
                    path.validate();
                } else {
                    path.start_validation();
                }
            }
        }
    }

    async fn command(&mut self, command: Command, transport: &Transport) -> Result<(), Error> {
        match command {
            Command::InstallKeys(keys, done) => {
                let result = match keys {
                    qtls::InstalledKeys::Handshake(keys) => {
                        self.install_handshake(keys.opening)
                            .map_err(crate::internal)?;
                        transport
                            .spaces
                            .handshake
                            .install(
                                Arc::new(keys.sealing.header),
                                keys.sealing.packet,
                                self.journal(Epoch::Handshake).unwrap().clone(),
                                transport.wakers.clone(),
                            )
                            .map_err(crate::internal)?;
                        transport.control.handshake.got_handshake_key();
                        transport
                            .spaces
                            .enabled
                            .fetch_or(2, std::sync::atomic::Ordering::Release);
                        transport.control.phase.send_replace(Phase::Handshake);
                        Ok(())
                    }
                    qtls::InstalledKeys::OneRtt(keys) => {
                        self.install_one_rtt(
                            keys.opening_header,
                            keys.packet.opening,
                            keys.next_secret,
                        )
                        .map_err(crate::internal)?;
                        transport
                            .spaces
                            .data
                            .install(
                                Arc::new(keys.sealing_header),
                                keys.packet.sealing,
                                self.journal(Epoch::Data).unwrap().clone(),
                                transport.wakers.clone(),
                            )
                            .map_err(crate::internal)?;
                        transport
                            .spaces
                            .enabled
                            .fetch_or(4, std::sync::atomic::Ordering::Release);
                        Ok(())
                    }
                    qtls::InstalledKeys::ZeroRtt(_) => Err(crate::internal("0-RTT is not enabled")),
                };
                let _ = done.send(result.clone());
                result?;
            }
            Command::TlsComplete(done) => {
                if transport.data.get().is_none() || self.next_secret.is_none() {
                    let error =
                        crate::internal("TLS completed before data components and 1-RTT keys");
                    let _ = done.send(Err(error.clone()));
                    return Err(error);
                }
                transport.control.phase.send_replace(Phase::Active);
                if transport.control.role == Role::Server {
                    transport.reliable.send_frame([HandshakeDoneFrame]);
                    self.confirm_handshake(transport).await;
                }
                let _ = done.send(Ok(()));
            }
            Command::HandshakeSent => {
                if transport.control.role == Role::Client {
                    self.retire(transport, Epoch::Initial).await;
                }
            }
        }
        transport
            .wakers
            .wake_all_by(Signals::KEYS | Signals::TRANSPORT);
        Ok(())
    }

    /// One connection receive future owns opening keys, reassembly and component
    /// pipes from its first Initial until draining. Space never starts a task.
    pub(crate) async fn run(
        mut self,
        transport: Arc<Transport>,
        mut packets: mpsc::Receiver<ReceivedPacket>,
        mut commands: mpsc::Receiver<Command>,
    ) {
        let mut crypto = [
            qrecovery::recv::RecvBuf::default(),
            qrecovery::recv::RecvBuf::default(),
            qrecovery::recv::RecvBuf::default(),
        ];
        let mut future = std::collections::VecDeque::new();
        let result: Result<(), Error> = async {
            loop {
                while let Ok(command) = commands.try_recv() { self.command(command, &transport).await?; }
                // A full TLS pipe retains bytes in reassembly; receiving an ACK
                // for them is safe. Reserve capacity before removing any bytes.
                for (index, buffer) in crypto.iter_mut().enumerate() {
                    if !buffer.is_readable() || (index == 1 && self.opening[1].is_none())
                        || (index == 2 && *transport.control.phase.borrow() != Phase::Active) { continue }
                    let Ok(slot) = transport.crypto.try_reserve() else { break };
                    let mut bytes = vec![0; 16 * 1024];
                    let mut output = bytes.as_mut_slice();
                    buffer.try_read(&mut output);
                    let count = 16 * 1024 - output.len();
                    bytes.truncate(count);
                    slot.send(([qtls::CryptoLevel::Initial, qtls::CryptoLevel::Handshake, qtls::CryptoLevel::OneRtt][index], bytes.into()));
                }
                let buffered = future.iter().position(|(epoch, _)| self.opening[*epoch as usize].is_some())
                    .and_then(|index| future.remove(index)).map(|(_, packet)| packet);
                let received = if let Some(packet) = buffered { packet } else {
                    tokio::select! {
                        biased;
                        _ = transport.stop.cancelled() => return Ok(()),
                        command = commands.recv() => {
                            let Some(command) = command else { return Err(crate::internal("control owner stopped")) };
                            self.command(command, &transport).await?;
                            continue;
                        }
                        packet = packets.recv() => match packet { Some(packet) => packet, None => return Ok(()) },
                        _ = tokio::time::sleep(Duration::from_millis(10)), if crypto.iter().any(qrecovery::recv::RecvBuf::is_readable) => continue,
                    }
                };
                let (packet, pathway, link, credit) = received;
                if transport.scope.get().is_some_and(|scope| !scope.allows(pathway, link)) { continue }
                let Packet::Data(packet) = packet else { continue };
                let (epoch, scid) = match &packet.header {
                    DataHeader::Long(long::DataHeader::Initial(header)) => (Epoch::Initial, Some(*header.scid())),
                    DataHeader::Long(long::DataHeader::Handshake(header)) => (Epoch::Handshake, Some(*header.scid())),
                    DataHeader::Short(_) => (Epoch::Data, None),
                    _ => continue,
                };
                if !self.enabled[epoch as usize] { continue }
                if self.opening[epoch as usize].is_none() {
                    if future.len() < 16 { future.push_back((epoch, (Packet::Data(packet), pathway, link, credit))); }
                    continue;
                }
                let pto = transport.paths.get(&pathway).map_or(Duration::from_secs(1), |path| path.cc.get_pto(epoch));
                let Some((epoch, pn, frames)) = self.open(packet, pto).map_err(|reason| QuicError::with_default_fty(ErrorKind::ProtocolViolation, reason))? else { continue };
                if scid.zip(transport.peer_cid.get()).is_some_and(|(received, fixed)| received != *fixed) { continue }
                if transport.control.role == Role::Client {
                    if transport.paths.get(&pathway).is_none() { continue }
                    let selected = transport.paths.selected.get_or_init(|| pathway);
                    if epoch != Epoch::Data && *selected != pathway { continue }
                }
                if let Some(scid) = scid { let _ = transport.peer_cid.set(scid); }
                let _ = transport.received_route.set((pathway, link));
                let Some(path) = transport.paths.add(pathway, &transport) else { continue };
                path.received.fetch_add(credit as u64, std::sync::atomic::Ordering::AcqRel);
                let mut content = Content::default();
                let mut accepted = true;
                let mut handshake_done = false;
                for frame in frames {
                    let (frame, frame_type) = frame.map_err(|error| QuicError::with_default_fty(ErrorKind::FrameEncoding, error.to_string()))?;
                    content += Content::from(frame_type);
                    match frame {
                        Frame::Padding(_) | Frame::Ping(_) => {},
                        Frame::Crypto(frame, bytes) => {
                            let end = frame.offset().checked_add(bytes.len() as u64).ok_or_else(|| crate::internal("CRYPTO offset overflow"))?;
                            let buffer = &mut crypto[epoch as usize];
                            if end > buffer.nread().saturating_add(256 * 1024) || buffer.segment_count() >= 1024 {
                                return Err(QuicError::with_default_fty(ErrorKind::CryptoBufferExceeded, "CRYPTO reassembly budget exceeded").into())
                            }
                            buffer.recv(frame.offset(), Bytes::copy_from_slice(&bytes));
                        }
                        Frame::Ack(ack) => {
                            // The client's ACK identifies the response path it
                            // chose. Keep the remaining handshake flight there.
                            if transport.control.role == Role::Server && epoch == Epoch::Initial {
                                let _ = transport.paths.selected.set(pathway);
                            }
                            // Shared packet numbers may be acknowledged on another
                            // path. Each sender projects the ACK onto its own CC.
                            for owner in transport.paths.snapshot() {
                                if owner.failed.load(std::sync::atomic::Ordering::Acquire) { continue }
                                if owner.events.try_send(Event::Ack(epoch, ack.clone())).is_err() { accepted = false; break }
                                owner.wake.wake_by(Signals::TRANSPORT);
                            }
                            if !accepted { break }
                        }
                        Frame::HandshakeDone(_) => {
                            if transport.control.role != Role::Client {
                                return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "unexpected HANDSHAKE_DONE").into())
                            }
                            if *transport.control.phase.borrow() != Phase::Active { accepted = false; break }
                            handshake_done = true;
                        }
                        Frame::Stream(frame, bytes) => {
                            let Some(data) = transport.data.get() else { accepted = false; break };
                            let amount = data.streams.recv_frame((frame, Bytes::copy_from_slice(&bytes)))?;
                            data.flow.on_new_rcvd(frame_type, amount)?;
                        }
                        Frame::StreamCtl(frame) => {
                            let Some(data) = transport.data.get() else { accepted = false; break };
                            let amount = data.streams.recv_frame(frame)?;
                            data.flow.on_new_rcvd(frame_type, amount)?;
                        }
                        Frame::MaxData(frame) => {
                            let Some(data) = transport.data.get() else { accepted = false; break };
                            data.flow.sender.recv_frame(frame)?;
                        }
                        Frame::DataBlocked(frame) => {
                            let Some(data) = transport.data.get() else { accepted = false; break };
                            data.flow.recver.recv_frame(frame)?;
                        }
                        Frame::PathChallenge(frame) => {
                            let mut responses = path.responses.lock().unwrap();
                            if responses.len() == 8 { accepted = false; break }
                            responses.push_back(frame.into());
                            drop(responses);
                            if transport.control.role == Role::Server { path.start_validation(); }
                        }
                        Frame::PathResponse(frame) => {
                            if path.events.try_send(Event::Response(frame)).is_err() { accepted = false; break }
                        }
                        Frame::Close(frame) => {
                            transport.control.phase.send_replace(Phase::Draining);
                            transport.close.request(frame.into());
                        }
                        Frame::NewToken(_) if transport.control.role == Role::Client => {},
                        _ => return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "unnegotiated frame").into()),
                    }
                }
                if accepted {
                    self.commit(epoch, pn, content, pto);
                    path.cc.on_pkt_rcvd(epoch, pn, content.is_ack_eliciting());
                    path.idle.on_rcvd(content);
                    path.wake.wake_by(Signals::TRANSPORT | Signals::CREDIT);
                    if epoch == Epoch::Handshake && transport.control.role == Role::Server {
                        let _ = transport.paths.selected.set(pathway);
                        path.validate();
                        if self.enabled[0] { self.retire(&transport, Epoch::Initial).await; }
                    }
                    if handshake_done { self.confirm_handshake(&transport).await; }
                }
            }
        }.await;
        if let Err(error) = result {
            transport.close.request(error);
        }
    }

    pub(crate) fn install_handshake(
        &mut self,
        keys: qtls::DirectionalKeys,
    ) -> Result<(), &'static str> {
        if !self.enabled[1] || self.opening[1].is_some() {
            return Err("Handshake keys already installed or discarded");
        }
        self.opening[1] = Some((Arc::new(keys.header), keys.packet));
        self.journals[1] = Some(ArcRcvdJournal::with_capacity(0, None));
        Ok(())
    }

    pub(crate) fn install_one_rtt(
        &mut self,
        header: qtls::HeaderProtectionKey,
        opening: qtls::PacketKey,
        next_secret: qtls::Secrets,
    ) -> Result<(), &'static str> {
        if !self.enabled[2] || self.opening[2].is_some() {
            return Err("1-RTT keys already installed or discarded");
        }
        self.opening[2] = Some((Arc::new(header), opening));
        self.next_secret = Some(next_secret);
        self.journals[2] = Some(ArcRcvdJournal::with_capacity(
            0,
            Some(Duration::from_millis(25)),
        ));
        Ok(())
    }

    pub(crate) fn confirm(&mut self) {
        self.confirmed = true;
    }

    pub(crate) fn discard(&mut self, epoch: Epoch) {
        let i = epoch as usize;
        self.enabled[i] = false;
        self.opening[i] = None;
        self.journals[i] = None;
        if epoch == Epoch::Data {
            self.next_secret = None;
            self.next = None;
            self.previous = None;
        }
    }

    pub(crate) fn journal(&self, epoch: Epoch) -> Option<&ArcRcvdJournal> {
        self.journals[epoch as usize].as_ref()
    }

    pub(crate) fn commit(&self, epoch: Epoch, pn: u64, content: PacketContent, pto: Duration) {
        if let Some(journal) = self.journal(epoch) {
            journal.on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
        }
    }

    /// Synchronously pipe frames into their component sinks without collecting
    /// a second copy of the packet. A rejected reliable frame leaves the PN
    /// uncommitted, so a full inbox cannot cause an ACK for discarded data.
    #[cfg(test)]
    pub(crate) fn receive(
        &mut self,
        packet: DataPacket,
        pto: Duration,
        mut pipe: impl FnMut(Epoch, Frame<Bytes>) -> Result<(), &'static str>,
    ) -> Result<Option<(Epoch, u64, PacketContent)>, &'static str> {
        let Some((epoch, pn, frames)) = self.open(packet, pto)? else {
            return Ok(None);
        };
        let mut content = PacketContent::default();
        for frame in frames {
            let (frame, frame_type) = frame.map_err(|_| "invalid frame in packet")?;
            pipe(epoch, frame)?;
            content += PacketContent::from(frame_type);
        }
        self.commit(epoch, pn, content, pto);
        Ok(Some((epoch, pn, content)))
    }

    /// None means drop (unavailable keys, duplicate, malformed header or failed
    /// authentication). Errors are violations detected in authenticated plaintext.
    pub(crate) fn open(
        &mut self,
        mut packet: DataPacket,
        pto: Duration,
    ) -> Result<Option<(Epoch, u64, FrameReader)>, &'static str> {
        let epoch = match &packet.header {
            DataHeader::Long(long::DataHeader::Initial(_)) => Epoch::Initial,
            DataHeader::Long(long::DataHeader::Handshake(_)) => Epoch::Handshake,
            DataHeader::Short(_) => Epoch::Data,
            DataHeader::Long(long::DataHeader::ZeroRtt(_)) => return Ok(None),
        };
        let i = epoch as usize;
        let Some((header_key, current)) = self.opening[i].as_ref() else {
            return Ok(None);
        };
        let packet_type = packet.get_type();
        let sample_start = packet.offset + 4;
        if sample_start + header_key.sample_len() > packet.bytes.len() || packet.offset == 0 {
            return Ok(None);
        }
        let (header_pn, sample) = packet.bytes.split_at_mut(sample_start);
        let (prefix, pn_bytes) = header_pn.split_at_mut(packet.offset);
        if header_key
            .unprotect(&sample[..header_key.sample_len()], &mut prefix[0], pn_bytes)
            .is_err()
        {
            return Ok(None);
        }
        let first = packet.bytes[0];
        let pn_len = (first & 3) + 1;
        let (_, encoded) =
            take_pn_len(pn_len)(&packet.bytes[packet.offset..]).map_err(|_| "invalid PN length")?;
        let journal = self.journals[i]
            .as_ref()
            .expect("keys and journal installed together");
        let Ok(pn) = journal.decode_pn(encoded) else {
            return Ok(None);
        };
        let now = Instant::now();
        if self
            .previous
            .as_ref()
            .is_some_and(|(_, until)| now >= *until)
        {
            self.previous = None;
        }
        let phase_changed =
            epoch == Epoch::Data && ((first >> 2) & 1) as u64 != self.generation % 2;
        let updating = phase_changed
            && self
                .generation_largest_pn
                .is_none_or(|largest| pn > largest);
        let key = if updating {
            if self.next.is_none() {
                self.next = Some(
                    self.next_secret
                        .as_mut()
                        .expect("1-RTT secrets installed")
                        .next_packet_keys()
                        .opening,
                );
            }
            self.next.as_ref().unwrap().clone()
        } else if phase_changed {
            if pn >= self.generation_first_pn {
                return Ok(None);
            }
            let Some((key, _)) = &self.previous else {
                return Ok(None);
            };
            key.clone()
        } else {
            current.clone()
        };
        let body_offset = packet.offset + pn_len as usize;
        let (header, body) = packet.bytes.split_at_mut(body_offset);
        let Ok(plaintext) = key.open(pn, header, body) else {
            return Ok(None);
        };
        let plain_len = plaintext.len();
        if first & if epoch == Epoch::Data { 0x18 } else { 0x0c } != 0 {
            return Err("nonzero reserved packet bits");
        }
        if updating {
            if !self.confirmed {
                return Err("key update before handshake confirmation");
            }
            let old = std::mem::replace(
                &mut self.opening[i].as_mut().unwrap().1,
                self.next.take().unwrap(),
            );
            self.previous = Some((old, now + pto.saturating_mul(3)));
            self.generation += 1;
            self.generation_first_pn = pn;
            self.generation_largest_pn = Some(pn);
        } else if epoch == Epoch::Data && !phase_changed {
            self.generation_largest_pn = Some(
                self.generation_largest_pn
                    .map_or(pn, |largest| largest.max(pn)),
            );
            self.generation_first_pn = self.generation_first_pn.min(pn);
        }
        let payload = packet
            .bytes
            .freeze()
            .slice(body_offset..body_offset + plain_len);
        Ok(Some((epoch, pn, FrameReader::new(payload, packet_type))))
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use qbase::{
        cid::ConnectionId,
        frame::PingFrame,
        packet::{OneRttHeader, Packet, PacketReader},
    };

    use super::*;
    use crate::{
        send::{constraints::Constraints, packet::OneRttPacket},
        tls::tests::{handshake, initial_keys},
    };

    fn ready() -> (Topology, qtls::OneRttKeyMaterial) {
        let [client, server] = handshake(false);
        let mut topology = Topology::new(initial_keys().opening);
        topology
            .install_one_rtt(
                server.opening_header,
                server.packet.opening,
                server.next_secret,
            )
            .unwrap();
        (topology, client)
    }

    fn packet(
        header: &Arc<qtls::HeaderProtectionKey>,
        key: &qtls::PacketKey,
        pn: u64,
        phase: bool,
    ) -> BytesMut {
        let mut packet = OneRttPacket::new(
            BytesMut::zeroed(128),
            OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original")),
            header.clone(),
            key.clone(),
            pn,
            phase,
        )
        .unwrap();
        let mut constraints = Constraints {
            capacity: 128,
            congestion: 128,
            anti_amplification: 128,
        };
        packet.assemble(&mut constraints, [&mut PingFrame]).unwrap();
        packet.seal().unwrap().bytes
    }

    fn parse(bytes: BytesMut) -> DataPacket {
        let Packet::Data(packet) = PacketReader::new(bytes, 8).next().unwrap().unwrap() else {
            panic!()
        };
        packet
    }

    #[test]
    fn a_rejected_component_does_not_commit_the_packet_number() {
        let (mut topology, keys) = ready();
        let header = Arc::new(keys.sealing_header);
        let bytes = packet(&header, &keys.packet.sealing, 0, false);
        let pto = Duration::from_secs(1);
        assert!(
            topology
                .receive(parse(bytes.clone()), pto, |_, _| Err("component full"))
                .is_err()
        );
        let mut calls = 0;
        assert!(
            topology
                .receive(parse(bytes.clone()), pto, |_, _| {
                    calls += 1;
                    Ok(())
                })
                .unwrap()
                .is_some()
        );
        assert_eq!(calls, 1);
        assert!(
            topology
                .receive(parse(bytes), pto, |_, _| panic!(
                    "duplicate reached a component"
                ))
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn forged_next_phase_does_not_replace_current_keys_and_old_keys_expire() {
        let (mut topology, mut keys) = ready();
        let header = Arc::new(keys.sealing_header);
        topology.confirm();
        let pto = Duration::from_secs(1);
        let old = keys.packet.sealing;
        let next = keys.next_secret.next_packet_keys().sealing;
        let mut forged = packet(&header, &next, 4, true);
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(
            topology
                .receive(parse(forged), pto, |_, _| Ok(()))
                .unwrap()
                .is_none()
        );
        assert_eq!(topology.generation, 0);
        assert!(
            topology
                .receive(parse(packet(&header, &old, 0, false)), pto, |_, _| Ok(()))
                .unwrap()
                .is_some()
        );
        assert!(
            topology
                .receive(parse(packet(&header, &next, 5, true)), pto, |_, _| Ok(()))
                .unwrap()
                .is_some()
        );
        assert_eq!(topology.generation, 1);
        assert!(
            topology
                .receive(parse(packet(&header, &old, 1, false)), pto, |_, _| Ok(()))
                .unwrap()
                .is_some()
        );
        tokio::time::advance(pto * 3).await;
        assert!(
            topology
                .receive(parse(packet(&header, &old, 2, false)), pto, |_, _| Ok(()))
                .unwrap()
                .is_none()
        );
        assert!(
            topology
                .receive(parse(packet(&header, &next, 6, true)), pto, |_, _| Ok(()))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn authenticated_key_update_requires_handshake_confirmation() {
        let (mut topology, mut keys) = ready();
        let header = Arc::new(keys.sealing_header);
        let next = keys.next_secret.next_packet_keys().sealing;
        assert_eq!(
            topology
                .receive(
                    parse(packet(&header, &next, 1, true)),
                    Duration::from_secs(1),
                    |_, _| Ok(())
                )
                .err(),
            Some("key update before handshake confirmation")
        );
        assert_eq!(topology.generation, 0);
    }
}
