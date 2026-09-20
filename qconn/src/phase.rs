//! Shared sending material. Each path reads the current phase for every burst.
use std::sync::{Arc, Mutex};

use qbase::{
    Epoch,
    cid::{ArcCidCell, ArcRemoteCids, ConnectionId},
    error::{ErrorKind, QuicError},
    frame::io::SendFrame,
    net::tx::{ArcSendWakers, Signals},
    param::ParameterId,
    role::Role,
    sid::handy::ConsistentConcurrency,
};
use qtransport::{
    GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys},
    space::{Space, Spaces},
    transport::Transport,
};

use crate::{ArcParameters, DataStreams, Error, FlowController, ReliableFrames};

/// Frame sources available before peer transport parameters arrive.
pub struct InitialPhase {
    pub initial: Arc<Space<ArcKeys>>,
    pub scid: ConnectionId,
    pub odcid: ConnectionId,
    pub reliable_frames: ReliableFrames,
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
        initial
            .install_initial_keys(keys)
            .expect("fresh Initial keys");
        Self {
            initial,
            scid,
            odcid,
            reliable_frames,
        }
    }
}

/// Complete frame sources. Identity verification remains the growing coroutine's job.
pub struct MaturePhase {
    pub spaces: Spaces,
    pub scid: ConnectionId,
    pub streams: DataStreams,
    pub flow: FlowController,
    pub reliable_frames: ReliableFrames,
    pub remote_cids: ArcRemoteCids<ReliableFrames>,
    pub initial_dcid: ArcCidCell<ReliableFrames>,
    pub parameters: ArcParameters,
}

impl MaturePhase {
    pub(crate) fn new(
        early: &InitialPhase,
        handshake: Arc<Space<ArcKeys>>,
        parameters: ArcParameters,
        peer_cid: ConnectionId,
        reliable_frames: ReliableFrames,
        remote_cids: ArcRemoteCids<ReliableFrames>,
        initial_dcid: ArcCidCell<ReliableFrames>,
    ) -> Result<(Arc<Self>, Arc<Transport>), Error> {
        if parameters.remote::<ConnectionId>(ParameterId::InitialSourceConnectionId)
            != Some(peer_cid)
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::TransportParameter,
                "peer Initial source CID mismatch",
            )
            .into());
        }
        if parameters.role() == Role::Client
            && (parameters.remote::<ConnectionId>(ParameterId::OriginalDestinationConnectionId)
                != Some(early.odcid)
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
            parameters
                .local(ParameterId::InitialMaxStreamsBidi)
                .unwrap(),
            parameters.local(ParameterId::InitialMaxStreamsUni).unwrap(),
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
            parameters.remote(ParameterId::InitialMaxData).unwrap(),
            parameters.local(ParameterId::InitialMaxData).unwrap(),
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
            remote_cids,
            initial_dcid,
            parameters: parameters.clone(),
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

/// Negotiated frame sources are shared unchanged when Handshaking becomes Mature.
pub type HandshakingPhase = MaturePhase;

/// Initial and Handshake packet sources available before peer parameters complete Data.
pub struct ConnectingPhase {
    pub initial: Arc<InitialPhase>,
    pub handshake: Arc<Space<ArcKeys>>,
}

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Connecting(Arc<ConnectingPhase>),
    Handshaking(Arc<HandshakingPhase>),
    Mature(Arc<MaturePhase>),
}

impl ConnPhase {
    pub fn initial(&self) -> &Arc<Space<ArcKeys>> {
        match self {
            Self::Initial(sender) => &sender.initial,
            Self::Connecting(sender) => &sender.initial.initial,
            Self::Handshaking(sender) | Self::Mature(sender) => &sender.spaces.initial,
        }
    }

    pub(crate) fn handshake(&self) -> Option<&Arc<Space<ArcKeys>>> {
        match self {
            Self::Initial(_) => None,
            Self::Connecting(sender) => Some(&sender.handshake),
            Self::Handshaking(sender) | Self::Mature(sender) => Some(&sender.spaces.handshake),
        }
    }

    pub(crate) fn material(&self) -> Option<&Arc<MaturePhase>> {
        match self {
            Self::Handshaking(material) | Self::Mature(material) => Some(material),
            _ => None,
        }
    }

    pub(crate) fn scid(&self) -> ConnectionId {
        match self {
            Self::Initial(sender) => sender.scid,
            Self::Connecting(sender) => sender.initial.scid,
            Self::Handshaking(sender) | Self::Mature(sender) => sender.scid,
        }
    }
}

#[derive(Clone)]
pub struct ArcConnPhase(Arc<Mutex<ConnPhase>>);

impl ArcConnPhase {
    pub fn new(sender: InitialPhase) -> Self {
        Self(Arc::new(Mutex::new(ConnPhase::Initial(Arc::new(sender)))))
    }

    pub fn get(&self) -> ConnPhase {
        self.0.lock().unwrap().clone()
    }

    pub(crate) fn enter_connecting(
        &self,
        initial: Arc<InitialPhase>,
        handshake: Arc<Space<ArcKeys>>,
    ) {
        let wakers = initial.initial.send_wakers.clone();
        *self.0.lock().unwrap() =
            ConnPhase::Connecting(Arc::new(ConnectingPhase { initial, handshake }));
        wakers.wake_all_by(Signals::KEYS);
    }

    pub(crate) fn enter_handshaking(&self, material: Arc<MaturePhase>) {
        let wakers = material.spaces.initial.send_wakers.clone();
        *self.0.lock().unwrap() = ConnPhase::Handshaking(material);
        wakers.wake_all_by(Signals::all());
    }

    pub(crate) fn enter_mature(&self, sender: Arc<MaturePhase>) {
        let wakers = sender.spaces.initial.send_wakers.clone();
        *self.0.lock().unwrap() = ConnPhase::Mature(sender);
        wakers.wake_all_by(Signals::all());
    }
}
