use std::sync::Arc;

use bytes::BytesMut;
use qbase::{cid::ConnectionId, frame::Frame, packet::OneRttHeader, role::Role};
use qconnection::{ArcParameters, MaturePhase, Paths};
use qtransport::{keys::ArcKeys, space::HandshakeSpace};

/// Concrete handles owned by the receive side, including already retired spaces.
pub struct SpaceFixture {
    pub initial: std::sync::Arc<qtransport::space::Space<qtransport::keys::ArcKeys>>,
    pub handshake: std::sync::Arc<qtransport::space::HandshakeSpace>,
    pub data: std::sync::Arc<qtransport::space::DataSpace>,
}

pub struct MatureFixture {
    pub paths: std::sync::Arc<Paths>,
    pub phase: std::sync::Arc<qconnection::MaturePhase>,
    pub spaces: SpaceFixture,
}

impl MatureFixture {
    pub fn peer_cid(&self) -> qbase::cid::ConnectionId {
        self.parameters
            .remote(qbase::param::ParameterId::InitialSourceConnectionId)
    }
}

impl std::ops::Deref for MatureFixture {
    type Target = qconnection::MaturePhase;
    fn deref(&self) -> &Self::Target {
        &self.phase
    }
}

pub fn pair() -> [Arc<MatureFixture>; 2] {
    let [mut client, mut server] = super::backends(false);
    let mut material = [None, None];
    while material.iter().any(Option::is_none) {
        while let Some(event) = client.next_event() {
            match event {
                qtls::TlsEvent::WriteCrypto {
                    epoch: level,
                    bytes,
                } => {
                    server.receive_crypto(level, &bytes).unwrap();
                }
                qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(keys)) => {
                    material[0] = Some(keys);
                }
                _ => {}
            }
        }
        while let Some(event) = server.next_event() {
            match event {
                qtls::TlsEvent::WriteCrypto {
                    epoch: level,
                    bytes,
                } => {
                    client.receive_crypto(level, &bytes).unwrap();
                }
                qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(keys)) => {
                    material[1] = Some(keys);
                }
                _ => {}
            }
        }
    }
    let (client_params, server_params) = super::parameters();
    [Role::Client, Role::Server]
        .into_iter()
        .zip(material)
        .map(|(role, keys)| {
            let parameters = ArcParameters::new(
                role,
                Arc::new(client_params.clone()),
                Arc::new(server_params.clone()),
            );
            let scid = parameters.local(qbase::param::ParameterId::InitialSourceConnectionId);
            let peer = parameters.remote(qbase::param::ParameterId::InitialSourceConnectionId);
            let paths = super::initial_paths(
                role,
                scid,
                ConnectionId::from_slice(b"original"),
                super::initial_keys(role == Role::Server),
            );
            let registry = qconnection::CidRegistry::new(
                super::initial_phase(&paths).local_cids.clone(),
                qbase::cid::ArcRemoteCids::new(peer, 2, paths.reliable_frames.clone()),
            );
            let handshake = Arc::new(HandshakeSpace::new(
                Default::default(),
                ArcKeys::new(Arc::new(super::initial_keys(role == Role::Server))),
            ));
            let reliable_frames = paths.reliable_frames.clone();
            let streams = qconnection::DataStreams::new(
                parameters.clone(),
                Box::new(qbase::sid::handy::ConsistentConcurrency::new(
                    parameters.local(qbase::param::ParameterId::InitialMaxStreamsBidi),
                    parameters.local(qbase::param::ParameterId::InitialMaxStreamsUni),
                )),
                reliable_frames.clone(),
                None,
            );
            let flow = qconnection::FlowController::new(
                parameters.remote(qbase::param::ParameterId::InitialMaxData),
                parameters.local(qbase::param::ParameterId::InitialMaxData),
                reliable_frames.clone(),
            );
            let data = Arc::new(qtransport::space::DataSpace::new(
                Default::default(),
                keys.unwrap().into(),
                streams,
                reliable_frames.clone(),
            ));
            let puncher = qtraversal::punch::ArcPuncher::new(
                reliable_frames,
                qtraversal::punch::ProbeEncoder::new(data.clone(), peer),
            );
            let concrete = SpaceFixture {
                initial: super::initial_space(&paths.spaces),
                handshake,
                data,
            };
            let phase = Arc::new(MaturePhase {
                flow_ctrl: flow,
                cid_registry: registry,
                parameters,
                puncher,
            });
            let phase = Arc::new(MatureFixture {
                paths,
                phase,
                spaces: concrete,
            });
            // CID registration can queue NEW_CONNECTION_ID before any punch input.
            take_reliable(&phase);
            phase
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

pub fn take_reliable(phase: &MatureFixture) -> Vec<Frame> {
    use qbase::packet::{Constraints, GetType, Package, PacketBuffer};
    let mut bytes = BytesMut::with_capacity(1200);
    let mut limits = Constraints {
        flow_ctrl: usize::MAX,
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let mut frames = Vec::new();
    let _ = phase.spaces.data.reliable_frames.clone().poll_dump(
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut PacketBuffer::new(
            &mut bytes,
            &mut limits,
            &mut frames,
            OneRttHeader::new(Default::default(), phase.peer_cid()).get_type(),
            0,
            0,
        ),
    );
    frames.into_iter().map(Into::into).collect()
}
