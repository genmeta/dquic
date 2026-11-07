use std::sync::Arc;

use bytes::BytesMut;
use qbase::{cid::ConnectionId, frame::Frame, packet::OneRttHeader, role::Role};
use qtransport::{ArcParameters, Paths, keys::ArcKeys, space::HandshakeSpace};

/// Concrete handles owned by the receive side, including already retired spaces.
pub struct SpaceFixture {
    pub initial: std::sync::Arc<qtransport::space::Space<qtransport::keys::ArcKeys>>,
    pub handshake: std::sync::Arc<qtransport::space::HandshakeSpace>,
    pub data: std::sync::Arc<qtransport::space::DataSpace>,
}

pub struct DataFixture {
    pub paths: std::sync::Arc<Paths>,
    pub parameters: ArcParameters,
    pub spaces: SpaceFixture,
}

impl DataFixture {
    pub fn peer_cid(&self) -> qbase::cid::ConnectionId {
        self.parameters.remote(qbase::param::ParameterId::InitialSourceConnectionId)
    }
}

pub fn pair() -> [Arc<DataFixture>; 2] {
    let [mut client, mut server] = super::backends(false);
    let mut material = [None, None];
    while material.iter().any(Option::is_none) {
        while let Some(event) = client.next_event() {
            match event {
                qtls::TlsEvent::WriteCrypto { epoch: level, bytes } => {
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
                qtls::TlsEvent::WriteCrypto { epoch: level, bytes } => {
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
            let parameters = ArcParameters::new(role, Arc::new(client_params.clone()), Arc::new(server_params.clone()));
            let scid = parameters.local(qbase::param::ParameterId::InitialSourceConnectionId);
            let peer = parameters.remote(qbase::param::ParameterId::InitialSourceConnectionId);
            let facts = crate::common::handshake_facts(role, false);
            let paths = super::initial_paths_with_timeouts(
                role,
                scid,
                if role == Role::Server {
                    peer
                } else {
                    ConnectionId::from_slice(b"original")
                },
                super::initial_keys(role == Role::Server),
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                facts.clone(),
            );
            paths.cid_registry.remote.set_limit(2);
            paths.progress.on_initial_received(peer);
            let handshake = Arc::new(HandshakeSpace::new(
                Default::default(),
                ArcKeys::new(Arc::new(super::initial_keys(role == Role::Server))),
                facts.clone(),
            ));
            let reliable_frames = paths.reliable_frames.clone();
            let streams = qtransport::DataStreams::new(
                parameters.clone(),
                Box::new(qbase::sid::handy::ConsistentConcurrency::new(
                    parameters.local(qbase::param::ParameterId::InitialMaxStreamsBidi),
                    parameters.local(qbase::param::ParameterId::InitialMaxStreamsUni),
                )),
                reliable_frames.clone(),
                Default::default(),
            );
            let data = Arc::new(qtransport::space::DataSpace::new(
                Default::default(),
                keys.unwrap().into(),
                streams,
                reliable_frames.clone(),
                parameters.local::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
                parameters.remote::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
                facts,
            ));
            let concrete = SpaceFixture { initial: super::initial_space(&paths.spaces), handshake, data };
            let fixture = Arc::new(DataFixture { paths, parameters, spaces: concrete });
            // CID registration can queue NEW_CONNECTION_ID before any punch input.
            take_reliable(&fixture);
            fixture
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

pub fn take_reliable(phase: &DataFixture) -> Vec<Frame> {
    use qbase::packet::{GetType, Package, PacketBuffer};
    let mut bytes = BytesMut::with_capacity(1200);
    let limits_quota = 1200;
    let limits_length = 1200;
    let mut frames = Vec::new();
    let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
    let _ = phase.spaces.data.reliable_frames.clone().poll_dump(
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut PacketBuffer::new(
            &mut writer_0,
            limits_quota,
            &mut frames,
            OneRttHeader::new(Default::default(), phase.peer_cid()).get_type(),
            0,
            0,
        ),
    );
    frames.into_iter().map(Into::into).collect()
}
