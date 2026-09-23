//! Shared sending material. Each path reads the current phase for every burst.
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::BufMut;
use qbase::{
    Epoch,
    cid::{ArcCidCell, ConnectionId},
    error::{ErrorKind, QuicError},
    frame::io::SendFrame,
    net::tx::{ArcSendWakers, Signals},
    packet::{Package, PacketContent, Type, io::Repeat},
    param::ParameterId,
    role::Role,
    sid::handy::ConsistentConcurrency,
};
use qtransport::{
    GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys},
    send::write::PacketWriter,
    space::{Space, Spaces},
    transport::Transport,
};

fn dump_sources<const N: usize>(
    packet: &mut PacketWriter<'_>,
    sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
) -> Result<PacketContent, Signals> {
    let remaining = packet.remaining_mut();
    let mut content = PacketContent::default();
    let mut signals = Signals::empty();
    for source in sources {
        match source.dump(packet) {
            Ok(loaded) => content += loaded,
            Err(blocked) => signals |= blocked,
        }
    }
    (remaining != packet.remaining_mut())
        .then_some(content)
        .ok_or(signals)
}

use crate::{
    ArcParameters, CidRegistry, DataStreams, Error, FlowController, ReliableFrames,
    terminate::ArcTerminator,
};

/// Frame sources available before peer transport parameters arrive.
pub struct InitialPhase {
    pub initial: Arc<Space<ArcKeys>>,
    pub scid: ConnectionId,
    pub odcid: ConnectionId,
    pub reliable_frames: ReliableFrames,
    pub(crate) terminator: ArcTerminator,
}

impl InitialPhase {
    pub fn new(scid: ConnectionId, odcid: ConnectionId, keys: qtls::BidirectionalKeys) -> Self {
        let wakers = ArcSendWakers::new();
        let reliable_frames = ReliableFrames::with_capacity_and_wakers(0, wakers.clone());
        Self::with_components(scid, odcid, keys, wakers, reliable_frames)
    }

    pub fn with_components(
        scid: ConnectionId,
        odcid: ConnectionId,
        keys: qtls::BidirectionalKeys,
        wakers: ArcSendWakers,
        reliable_frames: ReliableFrames,
    ) -> Self {
        let initial = Arc::new(Space::<ArcKeys>::new(Epoch::Initial, wakers, |_| {}));
        let terminator = ArcTerminator::normal(initial.send_wakers.clone());
        initial
            .install_initial_keys(keys)
            .expect("fresh Initial keys");
        Self {
            initial,
            scid,
            odcid,
            reliable_frames,
            terminator,
        }
    }
}

impl Package<PacketWriter<'_>> for &InitialPhase {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        use qbase::packet::r#type::long::{Type as Long, Ver1};
        if packet.packet_type() != Type::Long(Long::V1(Ver1::INITIAL)) {
            return Err(Signals::empty());
        }
        self.initial.crypto.outgoing().dump(packet)
    }
}

/// Complete frame sources. Identity verification remains the growing coroutine's job.
pub struct MaturePhase {
    pub spaces: Spaces,
    pub scid: ConnectionId,
    pub streams: DataStreams,
    pub flow: FlowController,
    pub reliable_frames: ReliableFrames,
    pub cid_registry: CidRegistry,
    pub initial_dcid: ArcCidCell<ReliableFrames>,
    pub peer_cid: ConnectionId,
    pub parameters: ArcParameters,
    pub(crate) terminator: ArcTerminator,
}

impl MaturePhase {
    pub(crate) fn new(
        early: &InitialPhase,
        handshake: Arc<Space<ArcKeys>>,
        parameters: ArcParameters,
        peer_cid: ConnectionId,
        reliable_frames: ReliableFrames,
        cid_registry: CidRegistry,
        initial_dcid: ArcCidCell<ReliableFrames>,
    ) -> Result<(Arc<Self>, Arc<Transport>), Error> {
        if parameters.remote::<ConnectionId>(ParameterId::InitialSourceConnectionId) != peer_cid {
            return Err(QuicError::with_default_fty(
                ErrorKind::TransportParameter,
                "peer Initial source CID mismatch",
            )
            .into());
        }
        if parameters.role() == Role::Client
            && (parameters.remote::<ConnectionId>(ParameterId::OriginalDestinationConnectionId)
                != early.odcid
                || parameters
                    .server()
                    .contains(ParameterId::RetrySourceConnectionId))
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::TransportParameter,
                "server original/retry CID mismatch",
            )
            .into());
        }
        let concurrency = Box::new(ConsistentConcurrency::new(
            parameters.local(ParameterId::InitialMaxStreamsBidi),
            parameters.local(ParameterId::InitialMaxStreamsUni),
        ));
        let streams = match parameters.role() {
            Role::Client => DataStreams::new(
                parameters.role(),
                parameters.client(),
                parameters.server(),
                concurrency,
                reliable_frames.clone(),
                early.initial.send_wakers.clone(),
                None,
            ),
            Role::Server => DataStreams::new(
                parameters.role(),
                parameters.server(),
                parameters.client(),
                concurrency,
                reliable_frames.clone(),
                early.initial.send_wakers.clone(),
                None,
            ),
        };
        let flow = FlowController::new(
            parameters.remote(ParameterId::InitialMaxData),
            parameters.local(ParameterId::InitialMaxData),
            reliable_frames.clone(),
            early.initial.send_wakers.clone(),
        );
        let recover_streams = streams.clone();
        let reliable = reliable_frames.clone();
        let data = Arc::new(Space::<ArcOneRttKeys>::new(
            Epoch::Data,
            early.initial.send_wakers.clone(),
            move |frame| match frame {
                GuaranteedFrame::Stream(frame) => recover_streams.may_loss_data(frame),
                GuaranteedFrame::Reliable(frame) => reliable.send_frame([frame.clone()]),
                GuaranteedFrame::Crypto(_) => unreachable!("Space recovers CRYPTO internally"),
            },
        ));
        let sender = Arc::new(Self {
            spaces: Spaces {
                initial: early.initial.clone(),
                handshake,
                data: data.clone(),
            },
            scid: early.scid,
            streams: streams.clone(),
            flow: flow.clone(),
            reliable_frames: reliable_frames.clone(),
            cid_registry,
            initial_dcid,
            peer_cid,
            parameters: parameters.clone(),
            terminator: early.terminator.clone(),
        });
        let transport = Arc::new(Transport::new(
            data,
            parameters,
            streams,
            flow,
            reliable_frames,
        ));
        Ok((sender, transport))
    }
}

impl Package<PacketWriter<'_>> for &MaturePhase {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        use qbase::packet::r#type::long::{Type as Long, Ver1};
        match packet.packet_type() {
            Type::Long(Long::V1(Ver1::INITIAL)) => {
                self.spaces.initial.crypto.outgoing().dump(packet)
            }
            Type::Long(Long::V1(Ver1::HANDSHAKE)) => {
                self.spaces.handshake.crypto.outgoing().dump(packet)
            }
            Type::Short(_) => {
                let mut crypto = self.spaces.data.crypto.outgoing();
                let mut reliable = self.reliable_frames.clone();
                let mut streams = Repeat(self.streams.package(self.flow.sender.clone(), false));
                dump_sources(packet, [&mut crypto, &mut reliable, &mut streams])
            }
            _ => Err(Signals::empty()),
        }
    }
}

/// Initial and Handshake packet sources available before peer parameters complete Data.
pub struct HandshakePhase {
    pub initial: Arc<InitialPhase>,
    pub handshake: Arc<Space<ArcKeys>>,
    pub(crate) terminator: ArcTerminator,
}

impl Package<PacketWriter<'_>> for &HandshakePhase {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        use qbase::packet::r#type::long::{Type as Long, Ver1};
        match packet.packet_type() {
            Type::Long(Long::V1(Ver1::INITIAL)) => {
                let mut initial = self.initial.as_ref();
                initial.dump(packet)
            }
            Type::Long(Long::V1(Ver1::HANDSHAKE)) => self.handshake.crypto.outgoing().dump(packet),
            _ => Err(Signals::empty()),
        }
    }
}

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Handshake(Arc<HandshakePhase>),
    Mature(Arc<MaturePhase>),
}

impl Package<PacketWriter<'_>> for &ConnPhase {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        match self {
            ConnPhase::Initial(phase) => phase.as_ref().dump(packet),
            ConnPhase::Handshake(phase) => phase.as_ref().dump(packet),
            ConnPhase::Mature(phase) => phase.as_ref().dump(packet),
        }
    }
}

#[derive(Clone)]
pub struct ArcConnPhase {
    phase: Arc<Mutex<ConnPhase>>,
    send_wakers: ArcSendWakers,
}

impl ArcConnPhase {
    pub fn initial(sender: InitialPhase) -> Self {
        let send_wakers = sender.initial.send_wakers.clone();
        Self {
            phase: Arc::new(Mutex::new(ConnPhase::Initial(Arc::new(sender)))),
            send_wakers,
        }
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, ConnPhase> {
        self.phase.lock().unwrap()
    }

    pub fn get(&self) -> ConnPhase {
        self.phase.lock().unwrap().clone()
    }

    pub(crate) fn send_wakers(&self) -> ArcSendWakers {
        self.send_wakers.clone()
    }

    pub(crate) fn terminator(&self) -> ArcTerminator {
        match &*self.phase.lock().unwrap() {
            ConnPhase::Initial(phase) => phase.terminator.clone(),
            ConnPhase::Handshake(phase) => phase.terminator.clone(),
            ConnPhase::Mature(phase) => phase.terminator.clone(),
        }
    }

    pub(crate) fn enter_handshake(
        &self,
        initial: Arc<InitialPhase>,
        handshake: Arc<Space<ArcKeys>>,
    ) {
        let wakers = initial.initial.send_wakers.clone();
        let terminator = initial.terminator.clone();
        *self.phase.lock().unwrap() = ConnPhase::Handshake(Arc::new(HandshakePhase {
            initial,
            handshake,
            terminator,
        }));
        wakers.wake_all_by(Signals::KEYS);
    }

    pub(crate) fn enter_mature(&self, sender: Arc<MaturePhase>) {
        let wakers = sender.spaces.initial.send_wakers.clone();
        *self.phase.lock().unwrap() = ConnPhase::Mature(sender);
        wakers.wake_all_by(Signals::all());
    }
}
