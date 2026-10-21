use std::sync::Arc;

use qbase::{
    param::{ClientParameters, ParameterId, ServerParameters},
    sid::handy::DemandConcurrency,
};
use qrecovery::streams::DataStreams;
use qtransport::{ArcParameters, ArcReliableFrames, Role, keys::ArcOneRttKeys, space::DataSpace};

use super::tls::handshake;

pub(crate) fn data() -> Arc<DataSpace> {
    let ([keys, _], _) = handshake();
    let client = ClientParameters::default();
    let mut server = ServerParameters::default();
    server
        .set(ParameterId::InitialMaxStreamsBidi, 1u32)
        .unwrap();
    server.set(ParameterId::InitialMaxStreamsUni, 1u32).unwrap();
    let parameters = ArcParameters::new(Role::Client, Arc::new(client), Arc::new(server));
    let reliable = ArcReliableFrames::with_capacity(0);
    let streams = DataStreams::new(
        parameters,
        Box::new(DemandConcurrency),
        reliable.clone(),
        Default::default(),
    );
    Arc::new(DataSpace::new(
        Default::default(),
        ArcOneRttKeys::from(keys),
        streams,
        reliable,
        Default::default(),
    ))
}
