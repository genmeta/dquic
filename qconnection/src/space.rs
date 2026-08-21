pub mod data;
pub mod handshake;
pub mod initial;

use std::{borrow::Cow, fmt::Debug, sync::Arc};

use bytes::Bytes;
use qbase::{
    error::{Error, QuicError},
    frame::{
        AckFrame, ConnectionCloseFrame, CryptoFrame, FrameFeature, FrameReader, GetFrameType,
        ReliableFrame, StreamCtlFrame, StreamFrame, io::ReceiveFrame,
    },
    packet::{
        AssemblePacket, Package, PacketContent, PacketSpace, PacketWriter, ProductHeader,
        header::{GetDcid, GetType, short::OneRttHeader},
        io::{Packages, PadTo20},
    },
};
use qevent::{
    quic::{
        PacketHeaderBuilder, QuicFramesCollector,
        transport::{PacketReceived, PacketsAcked},
    },
    telemetry::Instrument,
};
use qinterface::component::route::PlainPacket;
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcSentJournal, Journal},
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::Instrument as _;

use crate::{
    Components, DataStreams, FlowController, GuaranteedFrame, SpecificComponents,
    events::{ArcEventBroker, EmitEvent, Event},
    termination::Terminator,
};

#[derive(Clone)]
pub struct Spaces {
    initial: Arc<initial::InitialSpace>,
    handshake: Arc<handshake::HandshakeSpace>,
    data: Arc<data::DataSpace>,
}

impl Spaces {
    pub fn new(
        initial: initial::InitialSpace,
        handshake: handshake::HandshakeSpace,
        data: data::DataSpace,
    ) -> Self {
        Self {
            initial: Arc::new(initial),
            handshake: Arc::new(handshake),
            data: Arc::new(data),
        }
    }

    pub fn initial(&self) -> &Arc<initial::InitialSpace> {
        &self.initial
    }

    pub fn handshake(&self) -> &Arc<handshake::HandshakeSpace> {
        &self.handshake
    }

    pub fn data(&self) -> &Arc<data::DataSpace> {
        &self.data
    }

    pub(crate) fn discard_initial_key(&self) -> bool {
        self.initial.keys().invalid().is_some()
    }

    pub(crate) fn discard_handshake_key(&self) {
        _ = self.handshake.keys().invalid();
    }
}

fn assemble_closing_packet<'s, 'b: 's, H, S>(
    space: &'s S,
    product_header: &impl ProductHeader<H>,
    buffer: &'b mut [u8],
    ccf: &ConnectionCloseFrame,
) -> Option<usize>
where
    S: PacketSpace<H>,
    S::PacketAssembler<'s>: AsRef<PacketWriter<'b>>,
    for<'f> &'f ConnectionCloseFrame: Package<S::PacketAssembler<'s>>,
{
    let header = product_header.new_header().ok()?;
    let mut packet = S::new_packet(space, header, buffer).ok()?;

    let ccf = match ccf.belongs_to(packet.as_ref().packet_type()) {
        true => Cow::Borrowed(ccf),
        false => Cow::Owned(ConnectionCloseFrame::from(match ccf {
            ConnectionCloseFrame::App(app_close_frame) => app_close_frame.conceal(),
            ConnectionCloseFrame::Quic(..) => unreachable!(),
        })),
    };

    packet
        .assemble_packet(&mut Packages((ccf.as_ref(), PadTo20)))
        .ok()?;
    Some(packet.encrypt_and_protect_packet().0)
}

impl Spaces {
    pub async fn send_ccf_packets(&self, t: &Terminator) {
        t.try_send(|mut buf, ccf| {
            let original_size = buf.len();
            let initial_size = assemble_closing_packet(self.initial().as_ref(), t, buf, ccf);
            buf = &mut buf[initial_size.unwrap_or(0)..];
            let handshake_size = assemble_closing_packet(self.handshake().as_ref(), t, buf, ccf);
            buf = &mut buf[handshake_size.unwrap_or(0)..];
            let one_rtt_size =
                assemble_closing_packet::<OneRttHeader, _>(self.data().as_ref(), t, buf, ccf);
            buf = &mut buf[one_rtt_size.unwrap_or(0)..];

            if initial_size.is_some() {
                buf.fill(0);
                Some(original_size)
            } else {
                (original_size != buf.len()).then_some(original_size - buf.len())
            }
        })
        .await;
    }
}

fn pipe<F: Send + Debug + 'static>(
    mut source: UnboundedReceiver<F>,
    destination: impl ReceiveFrame<F> + Send + 'static,
    broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some(f) = source.recv().await {
                if let Err(Error::Quic(e)) = destination.recv_frame(f) {
                    broker.emit(Event::Failed(e));
                    break;
                }
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}

/// When receiving a [`StreamFrame`] or [`StreamCtlFrame`],
/// flow control must be updated accordingly
#[derive(Clone)]
struct FlowControlledDataStreams {
    streams: DataStreams,
    flow_ctrl: FlowController,
}

impl FlowControlledDataStreams {
    fn new(streams: DataStreams, flow_ctrl: FlowController) -> Self {
        Self { streams, flow_ctrl }
    }
}

impl ReceiveFrame<(StreamFrame, Bytes)> for FlowControlledDataStreams {
    type Output = ();

    fn recv_frame(&self, data_frame: (StreamFrame, Bytes)) -> Result<Self::Output, Error> {
        let frame_type = data_frame.0.frame_type();
        let new_data_size = self.streams.recv_data(data_frame)?;
        self.flow_ctrl.on_new_rcvd(frame_type, new_data_size)?;
        Ok(())
    }
}

impl ReceiveFrame<StreamCtlFrame> for FlowControlledDataStreams {
    type Output = ();

    fn recv_frame(&self, frame: StreamCtlFrame) -> Result<Self::Output, Error> {
        let new_data_size = self.streams.recv_stream_control(frame)?;
        self.flow_ctrl
            .on_new_rcvd(frame.frame_type(), new_data_size)?;
        Ok(())
    }
}

struct AckInitialSpace {
    sent_journal: ArcSentJournal<CryptoFrame>,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckInitialSpace {
    fn new(journal: &Journal<CryptoFrame>, crypto_stream: &CryptoStream) -> Self {
        Self {
            sent_journal: journal.of_sent_packets(),
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckInitialSpace {
    type Output = ();

    fn recv_frame(&self, ack_frame: AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(&ack_frame)?;

        let acked = rotate_guard.acked_packet_numbers(&ack_frame);
        qevent::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Initial,
            packet_nubers: acked.clone(),
        });
        for frame in rotate_guard.on_packets_acked(&ack_frame) {
            self.crypto_stream_outgoing.on_data_acked(&frame);
        }

        Ok(())
    }
}

struct AckHandshakeSpace {
    sent_journal: ArcSentJournal<CryptoFrame>,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckHandshakeSpace {
    fn new(journal: &Journal<CryptoFrame>, crypto_stream: &CryptoStream) -> Self {
        Self {
            sent_journal: journal.of_sent_packets(),
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckHandshakeSpace {
    type Output = ();

    fn recv_frame(&self, ack_frame: AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(&ack_frame)?;

        let acked = rotate_guard.acked_packet_numbers(&ack_frame);
        qevent::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Handshake,
            packet_nubers: acked.clone(),
        });
        for frame in rotate_guard.on_packets_acked(&ack_frame) {
            self.crypto_stream_outgoing.on_data_acked(&frame);
        }

        Ok(())
    }
}

struct AckDataSpace {
    send_journal: ArcSentJournal<GuaranteedFrame>,
    data_streams: DataStreams,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckDataSpace {
    fn new(
        journal: &Journal<GuaranteedFrame>,
        data_streams: DataStreams,
        crypto_stream: &CryptoStream,
    ) -> Self {
        Self {
            send_journal: journal.of_sent_packets(),
            data_streams,
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckDataSpace {
    type Output = ();

    fn recv_frame(&self, ack_frame: AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.send_journal.rotate();
        rotate_guard.update_largest(&ack_frame)?;

        let acked = rotate_guard.acked_packet_numbers(&ack_frame);
        qevent::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Data,
            packet_nubers: acked.clone(),
        });
        for frame in rotate_guard.on_packets_acked(&ack_frame) {
            match frame {
                GuaranteedFrame::Stream(stream_frame) => {
                    self.data_streams.on_data_acked(stream_frame)
                }
                GuaranteedFrame::Crypto(crypto_frame) => {
                    self.crypto_stream_outgoing.on_data_acked(&crypto_frame)
                }
                GuaranteedFrame::Reliable(ReliableFrame::StreamCtl(
                    StreamCtlFrame::ResetStream(reset_frame),
                )) => self.data_streams.on_reset_acked(reset_frame),
                _ => { /* nothing to do */ }
            }
        }
        Ok(())
    }
}

pub fn spawn_deliver_and_parse(components: &Components) {
    let received_packets_queue = &components.rcvd_pkt_q;
    let initial = initial::deliver_and_parse_packets(
        received_packets_queue.initial().clone(),
        components.spaces.initial.clone(),
        components.clone(),
        components.event_broker.clone(),
    );
    let handshake = handshake::deliver_and_parse_packets(
        received_packets_queue.handshake().clone(),
        components.spaces.handshake.clone(),
        components.clone(),
        components.event_broker.clone(),
    );
    let data = data::deliver_and_parse_packets(
        received_packets_queue.zero_rtt().clone(),
        received_packets_queue.one_rtt().clone(),
        components.spaces.data.clone(),
        components.clone(),
        components.event_broker.clone(),
    );

    tokio::spawn(
        async move { tokio::join!(biased; data, handshake, initial) }
            .instrument_in_current()
            .in_current_span(),
    );
}

/// For server connection, the origin dcid doesnot own a sequences number, once we received a packet which dcid != odcid,
/// we should stop using the odcid, and drop the subsequent packets with odcid.
///
/// We do not remove the route to odcid, otherwise the server may establish multiple connections for packets with same odcid.
///
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
fn filter_odcid_packet<H: GetDcid>(
    packet: PlainPacket<H>,
    specific: &SpecificComponents,
) -> Option<PlainPacket<H>> {
    use std::sync::atomic::Ordering::SeqCst;
    if let SpecificComponents::Server {
        odcid_router_entry,
        using_odcid,
    } = &specific
    {
        let dcid = (*packet.dcid()).into();
        if odcid_router_entry.signpost() == dcid && !using_odcid.load(SeqCst) {
            drop(packet); // just drop the packet, It's like we never received this packet.
            return None;
        }

        if odcid_router_entry.signpost() != dcid {
            using_odcid.store(false, SeqCst);
        }
    }
    Some(packet)
}

fn read_plain_packet<H>(
    packet: &PlainPacket<H>,
    mut dispatch_frame: impl FnMut(qbase::frame::Frame),
) -> Result<PacketContent, Error>
where
    H: GetType,
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    let mut frames_collector = QuicFramesCollector::<PacketReceived>::new();
    let mut packet_content = PacketContent::default();
    let frame_reader = FrameReader::new(packet.body(), packet.get_type());
    for frame_result in frame_reader {
        let (frame, r#type) = frame_result.map_err(QuicError::from)?;
        frames_collector.extend([&frame]);
        packet_content += r#type;
        dispatch_frame(frame);
    }

    packet.log_received(frames_collector);
    Ok(packet_content)
}
