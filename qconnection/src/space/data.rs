use std::sync::{Arc, LazyLock};

use qbase::{
    Epoch, GetEpoch,
    error::{Error, QuicError},
    frame::{
        ConnectionCloseFrame, Frame, ReliableFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::{
        route::{Link, Pathway},
        tx::Signals,
    },
    packet::{
        self,
        header::{GetType, OneRttHeader, long::ZeroRttHeader},
        io::PacketSpace,
        keys::{ArcOneRttKeys, ArcZeroRttKeys, DirectionalKeys},
        r#type::Type,
    },
    util::BoundQueue,
};
use qcongestion::{ArcCC, Feedback, Transport};
use qevent::{
    quic::{
        PacketHeader, PacketType, QuicFramesCollector,
        recovery::{PacketLost, PacketLostTrigger},
    },
    telemetry::Instrument,
};
use qinterface::{
    bind_uri::BindUri,
    component::route::{CipherPacket, PlainPacket},
};
use qrecovery::crypto::CryptoStream;
use tokio::sync::mpsc;

use crate::{
    ArcReliableFrameDeque, Components, DataJournal, DataStreams, GuaranteedFrame,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{self, Path, error::CreatePathFailure},
    space::{
        AckDataSpace, FlowControlledDataStreams, assemble_closing_packet, filter_odcid_packet,
        pipe, read_plain_packet,
    },
    state,
    termination::Terminator,
    tx::{PacketWriter, TrivialPacketWriter},
};

pub type CipherZeroRttPacket = CipherPacket<ZeroRttHeader>;
pub type PlainZeroRttPacket = PlainPacket<ZeroRttHeader>;
pub type ReceivedZeroRttFrom = (
    (CipherZeroRttPacket, Option<usize>),
    (BindUri, Pathway, Link),
);

pub type CipherOneRttPacket = CipherPacket<OneRttHeader>;
pub type PlainOneRttPacket = PlainPacket<OneRttHeader>;
pub type ReceivedOneRttFrom = (
    (CipherOneRttPacket, Option<usize>),
    (BindUri, Pathway, Link),
);

pub struct DataSpace {
    zero_rtt_keys: ArcZeroRttKeys,
    one_rtt_keys: ArcOneRttKeys,
    journal: DataJournal,
}

impl AsRef<DataJournal> for DataSpace {
    fn as_ref(&self) -> &DataJournal {
        &self.journal
    }
}

impl DataSpace {
    pub fn new(zero_rtt_keys: ArcZeroRttKeys) -> Self {
        Self {
            zero_rtt_keys,
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            journal: DataJournal::with_capacity(16, None),
        }
    }

    pub async fn decrypt_0rtt_packet(
        &self,
        packet: CipherZeroRttPacket,
    ) -> Option<Result<PlainZeroRttPacket, QuicError>> {
        // TODO: client should never received 0rtt packet...
        match self.zero_rtt_keys.get_decrypt_keys()?.await {
            Some(keys) => {
                packet.decrypt_long_packet(keys.header.as_ref(), keys.packet.as_ref(), |pn| {
                    self.journal.of_rcvd_packets().decode_pn(pn)
                })
            }
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub async fn decrypt_1rtt_packet(
        &self,
        packet: CipherOneRttPacket,
    ) -> Option<Result<PlainOneRttPacket, QuicError>> {
        match self.one_rtt_keys.get_remote_keys().await {
            Some((hpk, pk)) => packet.decrypt_short_packet(hpk.as_ref(), &pk, |pn| {
                self.journal.of_rcvd_packets().decode_pn(pn)
            }),
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub fn is_one_rtt_keys_ready(&self) -> bool {
        self.one_rtt_keys.get_local_keys().is_some()
    }

    pub fn is_zero_rtt_avaliable(&self) -> bool {
        self.zero_rtt_keys.get_encrypt_keys().is_some()
    }

    pub fn one_rtt_keys(&self) -> ArcOneRttKeys {
        self.one_rtt_keys.clone()
    }

    pub fn zero_rtt_keys(&self) -> ArcZeroRttKeys {
        self.zero_rtt_keys.clone()
    }

    pub fn tracker(
        &self,
        crypto_stream: CryptoStream,
        streams: DataStreams,
        reliable_frames: ArcReliableFrameDeque,
    ) -> DataTracker {
        DataTracker {
            journal: self.journal.clone(),
            crypto_stream,
            streams,
            reliable_frames,
        }
    }
}

impl GetEpoch for DataSpace {
    fn epoch(&self) -> Epoch {
        Epoch::Data
    }
}

impl path::PacketSpace<ZeroRttHeader> for DataSpace {
    type JournalFrame = GuaranteedFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: ZeroRttHeader,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, GuaranteedFrame>, Signals> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return Err(Signals::TLS_FIN); // should 1rtt
        }

        let Some(keys) = self.zero_rtt_keys.get_encrypt_keys() else {
            return Err(Signals::empty()); // no 0rtt keys, just skip 0rtt
        };

        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Data);
        PacketWriter::new_long(
            header,
            buffer,
            keys,
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }
}

impl PacketSpace<ZeroRttHeader> for DataSpace {
    type PacketAssembler<'a> = TrivialPacketWriter<'a, 'a, GuaranteedFrame>;

    #[inline]
    fn new_packet<'a>(
        &'a self,
        header: ZeroRttHeader,
        buffer: &'a mut [u8],
    ) -> Result<Self::PacketAssembler<'a>, Signals> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return Err(Signals::TLS_FIN); // should 1rtt
        }

        let Some(keys) = self.zero_rtt_keys.get_encrypt_keys() else {
            return Err(Signals::empty()); // no 0rtt keys, just skip 0rtt
        };

        TrivialPacketWriter::new_long(header, buffer, keys, self.journal.as_ref())
    }
}

impl path::PacketSpace<OneRttHeader> for DataSpace {
    type JournalFrame = GuaranteedFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: OneRttHeader,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, GuaranteedFrame>, Signals> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Data);
        PacketWriter::new_short(
            header,
            buffer,
            DirectionalKeys {
                header: hpk,
                packet: pk,
            },
            key_phase,
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }
}

impl PacketSpace<OneRttHeader> for DataSpace {
    type PacketAssembler<'a> = TrivialPacketWriter<'a, 'a, GuaranteedFrame>;

    #[inline]
    fn new_packet<'a>(
        &'a self,
        header: OneRttHeader,
        buffer: &'a mut [u8],
    ) -> Result<Self::PacketAssembler<'a>, Signals> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        TrivialPacketWriter::new_short(
            header,
            buffer,
            DirectionalKeys {
                header: hpk,
                packet: pk,
            },
            key_phase,
            self.journal.as_ref(),
        )
    }
}

fn frame_dispathcer(
    space: &DataSpace,
    components: &Components,
    event_broker: &ArcEventBroker,
) -> impl for<'p> Fn(Frame, Type, &'p Path) + use<> {
    let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded_channel();
    // 连接级的
    let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded_channel();
    let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded_channel();
    let (new_cid_frames_entry, rcvd_new_cid_frames) = mpsc::unbounded_channel();
    let (retire_cid_frames_entry, rcvd_retire_cid_frames) = mpsc::unbounded_channel();
    let (handshake_done_frames_entry, rcvd_handshake_done_frames) = mpsc::unbounded_channel();
    let (new_token_frames_entry, rcvd_new_token_frames) = mpsc::unbounded_channel();
    // 数据级的
    let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded_channel();
    let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded_channel();
    let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded_channel();
    #[cfg(feature = "datagram")]
    let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded_channel();
    let (punch_frames_entry, rcvd_punch_frames) = mpsc::unbounded_channel();
    let (punch_hello_frames_entry, rcvd_punch_hello_frames) = mpsc::unbounded_channel();

    let flow_controlled_data_streams = FlowControlledDataStreams::new(
        components.data_streams.clone(),
        components.flow_ctrl.clone(),
    );

    // Assemble the pipelines of frame processing
    pipe(
        rcvd_retire_cid_frames,
        components.cid_registry.local.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_new_cid_frames,
        components.cid_registry.remote.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_max_data_frames,
        components.flow_ctrl.sender.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_data_blocked_frames,
        components.flow_ctrl.recver.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_handshake_done_frames,
        components
            .quic_handshake
            .discard_spaces_on_client_handshake_done(
                components.paths.clone(),
                components.spaces.clone(),
            ),
        event_broker.clone(),
    );
    pipe(
        rcvd_crypto_frames,
        components.crypto_streams[space.epoch()].incoming(),
        event_broker.clone(),
    );
    pipe(
        rcvd_stream_ctrl_frames,
        flow_controlled_data_streams.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_stream_frames,
        flow_controlled_data_streams,
        event_broker.clone(),
    );
    #[cfg(feature = "datagram")]
    pipe(
        rcvd_datagram_frames,
        components.datagram_flow.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_ack_frames,
        AckDataSpace::new(
            &space.journal,
            components.data_streams.clone(),
            &components.crypto_streams[space.epoch()],
        ),
        event_broker.clone(),
    );
    pipe(
        rcvd_new_token_frames,
        components.token_registry.clone(),
        event_broker.clone(),
    );
    pipe(rcvd_punch_frames, components.clone(), event_broker.clone());
    pipe(
        rcvd_punch_hello_frames,
        components.clone(),
        event_broker.clone(),
    );
    let event_broker = event_broker.clone();
    move |frame: Frame, pty: packet::Type, path: &Path| match frame {
        Frame::Ack(f) => {
            path.cc().on_ack_rcvd(Epoch::Data, &f);
            _ = ack_frames_entry.send(f)
        }
        Frame::NewToken(f) => _ = new_token_frames_entry.send(f),
        Frame::MaxData(f) => _ = max_data_frames_entry.send(f),
        Frame::NewConnectionId(f) => _ = new_cid_frames_entry.send(f),
        Frame::RetireConnectionId(f) => _ = retire_cid_frames_entry.send(f),
        Frame::HandshakeDone(f) => {
            // See [Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc9001#handshake-confirmed)
            _ = handshake_done_frames_entry.send(f)
        }
        Frame::DataBlocked(f) => _ = data_blocked_frames_entry.send(f),
        Frame::PathChallenge(f) => _ = path.recv_frame(f),
        Frame::PathResponse(f) => _ = path.recv_frame(f),
        Frame::StreamCtl(f) => _ = stream_ctrl_frames_entry.send(f),
        Frame::Stream(f, data) => _ = stream_frames_entry.send((f, data)),
        Frame::Crypto(f, bytes) => _ = crypto_frames_entry.send((f, bytes)),
        #[cfg(feature = "datagram")]
        Frame::Datagram(f, data) => _ = datagram_frames_entry.send((f, data)),
        Frame::Close(f) if matches!(pty, Type::Short(_)) => event_broker.emit(Event::Closed(f)),
        Frame::AddAddress(frame) => {
            _ = punch_frames_entry.send((
                path.bind_uri().clone(),
                *path.pathway(),
                *path.link(),
                ReliableFrame::AddAddress(frame),
            ))
        }
        Frame::RemoveAddress(frame) => {
            _ = punch_frames_entry.send((
                path.bind_uri().clone(),
                *path.pathway(),
                *path.link(),
                ReliableFrame::RemoveAddress(frame),
            ))
        }
        Frame::PunchMeNow(frame) => {
            _ = punch_frames_entry.send((
                path.bind_uri().clone(),
                *path.pathway(),
                *path.link(),
                ReliableFrame::PunchMeNow(frame),
            ))
        }
        Frame::PunchHello(frame) => {
            _ = punch_hello_frames_entry.send((
                path.bind_uri().clone(),
                *path.pathway(),
                *path.link(),
                frame,
            ))
        }
        Frame::PunchDone(frame) => {
            _ = punch_frames_entry.send((
                path.bind_uri().clone(),
                *path.pathway(),
                *path.link(),
                ReliableFrame::PunchDone(frame),
            ))
        }
        _ => {}
    }
}

async fn parse_normal_zero_rtt_packet(
    ((packet, datagram_size), (bind_uri, pathway, link)): ReceivedZeroRttFrom,
    space: &DataSpace,
    components: &Components,
    dispatch_frame: impl Fn(Frame, Type, &Path),
) -> Result<(), Error> {
    let Some(packet) = space.decrypt_0rtt_packet(packet).await.transpose()? else {
        return Ok(());
    };

    let path = match components.get_or_try_create_path((bind_uri, pathway, link), true) {
        Ok(path) => path,
        Err(CreatePathFailure::ConnectionClosed(..)) => {
            packet.drop_on_conenction_closed();
            return Ok(());
        }
        Err(CreatePathFailure::InvalidWay(error)) => {
            tracing::trace!(target: "dquic", %error, "dropping 0-RTT packet on inadmissible path");
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

    let packet_content = read_plain_packet(&packet, |frame| {
        dispatch_frame(frame, packet.get_type(), &path);
    })?;

    space.journal.of_rcvd_packets().on_rcvd_pn(
        packet.pn(),
        packet_content.is_ack_eliciting(),
        path.cc().get_pto(Epoch::Data),
    );
    path.on_packet_rcvd(Epoch::Data, packet.pn(), datagram_size, packet_content);

    Result::<(), Error>::Ok(())
}

async fn parse_normal_one_rtt_packet(
    ((packet, datagram_size), (bind_uri, pathway, link)): ReceivedOneRttFrom,
    space: &DataSpace,
    components: &Components,
    dispatch_frame: impl Fn(Frame, Type, &Path),
) -> Result<(), Error> {
    let Some(packet) = space.decrypt_1rtt_packet(packet).await.transpose()? else {
        return Ok(());
    };

    let path = match components.get_or_try_create_path((bind_uri, pathway, link), true) {
        Ok(path) => path,
        Err(CreatePathFailure::ConnectionClosed(..)) => {
            packet.drop_on_conenction_closed();
            return Ok(());
        }
        Err(CreatePathFailure::InvalidWay(error)) => {
            tracing::trace!(target: "dquic", %error, "dropping 1-RTT packet on inadmissible path");
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

    components
        .quic_handshake
        .discard_spaces_on_server_handshake_done(&components.paths, &components.spaces);

    let packet_content = read_plain_packet(&packet, |frame| {
        dispatch_frame(frame, packet.get_type(), &path);
    })?;
    space.journal.of_rcvd_packets().on_rcvd_pn(
        packet.pn(),
        packet_content.is_ack_eliciting(),
        path.cc().get_pto(Epoch::Data),
    );
    path.on_packet_rcvd(Epoch::Data, packet.pn(), datagram_size, packet_content);

    Result::<(), Error>::Ok(())
}

fn parse_closing_one_rtt_packet(
    space: &DataSpace,
    packet: CipherOneRttPacket,
) -> Option<ConnectionCloseFrame> {
    let (hpk, pk) = space.one_rtt_keys.remote_keys()?;
    let packet = packet
        .decrypt_short_packet(hpk.as_ref(), &pk, |pn| {
            space.journal.of_rcvd_packets().decode_pn(pn)
        })
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
    zeor_rtt_packets: BoundQueue<ReceivedZeroRttFrom>,
    one_rtt_packets: BoundQueue<ReceivedOneRttFrom>,
    space: Arc<DataSpace>,
    components: Components,
    event_broker: ArcEventBroker,
) {
    let conn_state = &components.conn_state;
    let dispatch_frame = LazyLock::new(|| frame_dispathcer(&space, &components, &event_broker));
    let normal_deliver_and_parse_loops = async {
        let mut zero_rtt_open = true;
        let mut one_rtt_open = true;
        let mut one_rtt_tls_finished = false;

        while zero_rtt_open || one_rtt_open {
            tokio::select! {
                biased;

                form = one_rtt_packets.recv(), if one_rtt_open => {
                    let Some(form) = form else {
                        one_rtt_open = false;
                        continue;
                    };

                    if !one_rtt_tls_finished {
                        if components.tls_handshake.info().await.is_err() {
                            return;
                        }
                        one_rtt_tls_finished = true;
                    }

                    let span = qevent::span!(@current, path=form.1.2.to_string());
                    let parse = parse_normal_one_rtt_packet(form, &space, &components, |frame, pty, path| {
                        (*dispatch_frame)(frame, pty, path);
                    });
                    if let Err(Error::Quic(error)) = Instrument::instrument(parse, span).await {
                        event_broker.emit(Event::Failed(error));
                    };
                }

                form = zeor_rtt_packets.recv(), if zero_rtt_open => {
                    let Some(form) = form else {
                        zero_rtt_open = false;
                        continue;
                    };

                    let span = qevent::span!(@current, path=form.1.2.to_string());
                    let parse = parse_normal_zero_rtt_packet(form, &space, &components, |frame, pty, path| {
                        (*dispatch_frame)(frame, pty, path);
                    });
                    if let Err(Error::Quic(error)) = Instrument::instrument(parse, span).await {
                        event_broker.emit(Event::Failed(error));
                    };
                }
            }
        }
    };

    let ccf = tokio::select! {
        // deliver and parse packets. complete when packet queue closed
        _ = normal_deliver_and_parse_loops => return,
        // connection terminated(enter closing/draining state)
        error = conn_state.terminated() => match conn_state.current() {
            // entered closing_state, keep receiving packets, and send ccf
            state if state == Some(state::CLOSING) => ConnectionCloseFrame::from(error),
            // entered other state, do nothing
            _ => return
        }
    };

    let terminator = Terminator::new(ccf, &components);
    drop(dispatch_frame);
    // Release the primary connection state
    drop(components);
    zeor_rtt_packets.close();

    while let Some(((packet, _), (_bind_uri, pathway, _link))) = one_rtt_packets.recv().await {
        if let Some(ccf) = parse_closing_one_rtt_packet(&space, packet) {
            event_broker.emit(Event::Closed(ccf));
        }

        if terminator.should_send() {
            terminator
                .try_send_on(pathway, |buffer, ccf| {
                    assemble_closing_packet::<OneRttHeader, _>(
                        space.as_ref(),
                        &terminator,
                        buffer,
                        ccf,
                    )
                })
                .await
        }
    }
}

pub struct DataTracker {
    journal: DataJournal,
    crypto_stream: CryptoStream,
    streams: DataStreams,
    reliable_frames: ArcReliableFrameDeque,
}

impl Feedback for DataTracker {
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        let sent_jornal = self.journal.of_sent_packets();
        let crypto_outgoing = self.crypto_stream.outgoing();
        let mut sent_packets = sent_jornal.rotate();
        for pn in pns {
            let mut may_lost_frames = QuicFramesCollector::<PacketLost>::new();
            for frame in sent_packets.may_loss_packet(pn) {
                match frame {
                    GuaranteedFrame::Crypto(frame) => {
                        may_lost_frames.extend([&frame]);
                        crypto_outgoing.may_loss_data(&frame);
                    }
                    GuaranteedFrame::Stream(frame) => {
                        may_lost_frames.extend([&frame]);
                        self.streams.may_loss_data(&frame);
                    }
                    GuaranteedFrame::Reliable(frame) => {
                        may_lost_frames.extend([&frame]);
                        self.reliable_frames.send_frame([frame]);
                    }
                };
            }
            qevent::event!(PacketLost {
                header: PacketHeader {
                    // TOOD: 如果只有支持0rtt，这里就不一定是1rtt了
                    packet_type: PacketType::OneRTT,
                    packet_number: pn
                },
                frames: may_lost_frames,
                trigger
            });
        }
    }
}
