use std::sync::Arc;

use qbase::{
    Epoch, GetEpoch,
    error::{Error, QuicError},
    frame::{ConnectionCloseFrame, CryptoFrame, Frame},
    net::tx::Signals,
    packet::{header::long::HandshakeHeader, io::PacketSpace, keys::ArcKeys},
    util::BoundQueue,
};
use qcongestion::{Feedback, Transport};
use qevent::{
    quic::{
        PacketHeader, PacketType, QuicFramesCollector,
        recovery::{PacketLost, PacketLostTrigger},
    },
    telemetry::Instrument,
};
use qinterface::component::route::{CipherPacket, PlainPacket, Way};
use qrecovery::crypto::CryptoStream;
use tokio::sync::mpsc;

use crate::{
    Components, HandshakeJournal,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{self, Path, error::CreatePathFailure},
    space::{
        AckHandshakeSpace, assemble_closing_packet, filter_odcid_packet, pipe, read_plain_packet,
    },
    state,
    termination::Terminator,
    tx::{PacketWriter, TrivialPacketWriter},
};

pub type CipherHanshakePacket = CipherPacket<HandshakeHeader>;
pub type PlainHandshakePacket = PlainPacket<HandshakeHeader>;
pub type ReceivedFrom = (CipherHanshakePacket, Way);

pub struct HandshakeSpace {
    keys: ArcKeys,
    journal: HandshakeJournal,
}

impl AsRef<HandshakeJournal> for HandshakeSpace {
    fn as_ref(&self) -> &HandshakeJournal {
        &self.journal
    }
}

impl HandshakeSpace {
    pub fn new() -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            journal: HandshakeJournal::with_capacity(16, None),
        }
    }

    pub fn keys(&self) -> ArcKeys {
        self.keys.clone()
    }

    pub async fn decrypt_packet(
        &self,
        packet: CipherHanshakePacket,
    ) -> Option<Result<PlainHandshakePacket, QuicError>> {
        match self.keys.get_remote_keys().await {
            Some(keys) => packet.decrypt_long_packet(
                keys.remote.header.as_ref(),
                keys.remote.packet.as_ref(),
                |pn| self.journal.of_rcvd_packets().decode_pn(pn),
            ),
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub fn tracker(&self, crypto_stream: CryptoStream) -> HandshakeTracker {
        HandshakeTracker {
            journal: self.journal.clone(),
            crypto_stream,
        }
    }
}

impl Default for HandshakeSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl GetEpoch for HandshakeSpace {
    fn epoch(&self) -> Epoch {
        Epoch::Handshake
    }
}

impl path::PacketSpace<HandshakeHeader> for HandshakeSpace {
    type JournalFrame = CryptoFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: HandshakeHeader,
        cc: &qcongestion::ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, CryptoFrame>, Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Handshake);
        PacketWriter::new_long(
            header,
            buffer,
            keys.local.clone(),
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }
}

impl PacketSpace<HandshakeHeader> for HandshakeSpace {
    type PacketAssembler<'a> = TrivialPacketWriter<'a, 'a, CryptoFrame>;

    #[inline]
    fn new_packet<'a>(
        &'a self,
        header: HandshakeHeader,
        buffer: &'a mut [u8],
    ) -> Result<Self::PacketAssembler<'a>, Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        TrivialPacketWriter::new_long(header, buffer, keys.local, self.journal.as_ref())
    }
}

fn frame_dispathcer(
    space: &HandshakeSpace,
    components: &Components,
    event_broker: &ArcEventBroker,
) -> impl for<'p> Fn(Frame, &'p Path) + use<> {
    let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded_channel();
    let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded_channel();

    pipe(
        rcvd_crypto_frames,
        components.crypto_streams[space.epoch()].incoming(),
        event_broker.clone(),
    );
    pipe(
        rcvd_ack_frames,
        AckHandshakeSpace::new(&space.journal, &components.crypto_streams[space.epoch()]),
        event_broker.clone(),
    );

    let inform_cc = components.quic_handshake.status();
    let event_broker = event_broker.clone();
    let rcvd_joural = space.journal.of_rcvd_packets();
    move |frame: Frame, path: &Path| match frame {
        Frame::Ack(f) => {
            path.cc().on_ack_rcvd(Epoch::Handshake, &f);
            rcvd_joural.on_rcvd_ack(&f);
            _ = ack_frames_entry.send(f);
            inform_cc.received_handshake_ack();
        }
        Frame::Close(f) => event_broker.emit(Event::Closed(f)),
        Frame::Crypto(f, bytes) => _ = crypto_frames_entry.send((f, bytes)),
        Frame::Padding(_) | Frame::Ping(_) => {}
        _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
    }
}

async fn parse_normal_packet(
    (packet, (bind_uri, pathway, link)): ReceivedFrom,
    space: &HandshakeSpace,
    components: &Components,
    dispatch_frame: impl Fn(Frame, &Path),
) -> Result<(), Error> {
    let Some(packet) = space.decrypt_packet(packet).await.transpose()? else {
        return Ok(());
    };

    let path = match components.get_or_try_create_path((bind_uri, pathway, link), true) {
        Ok(path) => path,
        Err(CreatePathFailure::ConnectionClosed(..)) => {
            packet.drop_on_conenction_closed();
            return Ok(());
        }
        Err(CreatePathFailure::NoInterface(..)) => {
            packet.drop_on_interface_not_found();
            return Ok(());
        }
    };

    let Some(packet) = filter_odcid_packet(packet, &components.specific) else {
        return Ok(());
    };

    // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
    // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
    // address to have been validated.
    // It may have already been verified using tokens in the Handshake space
    path.grant_anti_amplification();

    let packet_content = read_plain_packet(&packet, |frame| dispatch_frame(frame, &path))?;

    space.journal.of_rcvd_packets().on_rcvd_pn(
        packet.pn(),
        packet_content.is_ack_eliciting(),
        path.cc().get_pto(Epoch::Handshake),
    );
    path.on_packet_rcvd(Epoch::Handshake, packet.pn(), packet.size(), packet_content);

    Result::<(), Error>::Ok(())
}

fn parse_closing_packet(
    space: &HandshakeSpace,
    packet: CipherHanshakePacket,
) -> Option<ConnectionCloseFrame> {
    // TOOD: improve Keys
    let remote_keys = space.keys.get_local_keys()?.remote;
    let packet = packet
        .decrypt_long_packet(
            remote_keys.header.as_ref(),
            remote_keys.packet.as_ref(),
            |pn| space.journal.of_rcvd_packets().decode_pn(pn),
        )
        .and_then(Result::ok)?;

    let mut ccf = None;
    _ = read_plain_packet(&packet, |frame| {
        ccf = ccf.take().or(match frame {
            Frame::Close(ccf) => Some(ccf),
            _ => None,
        });
    });
    ccf
}

pub async fn deliver_and_parse_packets(
    packets: BoundQueue<ReceivedFrom>,
    space: Arc<HandshakeSpace>,
    components: Components,
    event_broker: ArcEventBroker,
) {
    let conn_state = &components.conn_state;
    let dispatch_frame = frame_dispathcer(&space, &components, &event_broker);
    let normal_deliver_and_parse_loop = async {
        while let Some(form) = packets.recv().await {
            let span = qevent::span!(@current, path=form.1.2.to_string());
            let parse = parse_normal_packet(form, &space, &components, &dispatch_frame);
            if let Err(Error::Quic(error)) = Instrument::instrument(parse, span).await {
                event_broker.emit(Event::Failed(error));
            };
        }
    };

    let ccf = tokio::select! {
        // deliver and parse packets. complete when packet queue closed
        _ = normal_deliver_and_parse_loop => return,
        // connection terminated(enter closing/draining state)
        error = conn_state.terminated() => match conn_state.current() {
            // entered closing_state, keep receiving packets, and send ccf
            state if state == Some(state::CLOSING) => ConnectionCloseFrame::from(error),
            // entered other state, do nothing
            _ => return
        }
    };

    let terminator = Terminator::new(ccf, &components);
    // Release the primary connection state
    drop(components);

    while let Some((packet, (_bind_uri, pathway, _link))) = packets.recv().await {
        if let Some(ccf) = parse_closing_packet(&space, packet) {
            event_broker.emit(Event::Closed(ccf));
        }

        if terminator.should_send() {
            terminator
                .try_send_on(pathway, |buffer, ccf| {
                    assemble_closing_packet(space.as_ref(), &terminator, buffer, ccf)
                })
                .await
        }
    }
}

pub struct HandshakeTracker {
    journal: HandshakeJournal,
    crypto_stream: CryptoStream,
}

impl Feedback for HandshakeTracker {
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        let sent_jornal = self.journal.of_sent_packets();
        let outgoing = self.crypto_stream.outgoing();
        let mut sent_packets = sent_jornal.rotate();
        for pn in pns {
            let mut may_lost_frames = QuicFramesCollector::<PacketLost>::new();
            for frame in sent_packets.may_loss_packet(pn) {
                may_lost_frames.extend([&frame]);
                outgoing.may_loss_data(&frame);
            }
            qevent::event!(PacketLost {
                header: PacketHeader {
                    packet_type: PacketType::Handshake,
                    packet_number: pn
                },
                frames: may_lost_frames,
                trigger
            });
        }
    }
}
