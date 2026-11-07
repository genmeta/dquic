use std::sync::Arc;

use qbase::{
    handshake::HandshakeFacts,
    param::{ClientParameters, ParameterId, ServerParameters},
    sid::handy::DemandConcurrency,
};
use qrecovery::streams::ArcDataStreams;
use qtransport::{ArcParameters, ArcReliableFrames, Role, keys::ArcOneRttKeys, space::DataSpace};

use super::tls::handshake;

pub(crate) fn data() -> Arc<DataSpace> {
    let ([keys, _], _) = handshake();
    let client = ClientParameters::default();
    let mut server = ServerParameters::default();
    server.set(ParameterId::InitialMaxStreamsBidi, 1u32).unwrap();
    server.set(ParameterId::InitialMaxStreamsUni, 1u32).unwrap();
    let parameters = ArcParameters::new(Role::Client, Arc::new(client), Arc::new(server));
    let reliable = ArcReliableFrames::with_capacity(0);
    let streams = ArcDataStreams::new(parameters.clone(), Box::new(DemandConcurrency), reliable.clone(), Default::default());
    let facts = Arc::new(HandshakeFacts::with_role(Role::Client));
    facts.quit_mp_handshaking();
    Arc::new(DataSpace::new(
        Default::default(),
        ArcOneRttKeys::from(keys),
        streams,
        reliable,
        parameters.local::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
        parameters.remote::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
        facts,
    ))
}
