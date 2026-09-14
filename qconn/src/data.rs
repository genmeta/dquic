use std::sync::Arc;

use qbase::{
    error::{Error, ErrorKind, QuicError},
    flow::FlowController,
    frame::ReliableFrame,
    net::tx::ArcSendWakers,
    param::{ArcParameters, ParameterId},
    role::Role,
    sid::handy::ConsistentConcurrency,
};
use qrecovery::{
    reliable::ArcReliableFrameDeque,
    streams::{DataStreams, Ext},
};

pub type StreamReader = qrecovery::recv::Reader<Ext<ArcReliableFrameDeque<ReliableFrame>>>;
pub type StreamWriter = qrecovery::send::Writer<Ext<ArcReliableFrameDeque<ReliableFrame>>>;

/// Created only after both parameter sets have passed CID and value checks.
/// Stream tables and payload buffers grow on use, not to advertised window size.
pub(crate) struct DataPlane {
    pub(crate) parameters: ArcParameters,
    pub(crate) streams: DataStreams<ArcReliableFrameDeque<ReliableFrame>>,
    pub(crate) flow: FlowController<ArcReliableFrameDeque<ReliableFrame>>,
}

impl DataPlane {
    pub(crate) fn new(
        parameters: ArcParameters,
        reliable: ArcReliableFrameDeque<ReliableFrame>,
        wakers: ArcSendWakers,
    ) -> Result<Arc<Self>, Error> {
        let params = parameters.lock_guard()?;
        if !params.is_remote_params_ready() {
            return Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "data components require validated parameters",
            )
            .into());
        }
        let client = params.client().unwrap();
        let server = params.server().unwrap();
        let concurrency = Box::new(ConsistentConcurrency::new(
            params
                .get_local(ParameterId::InitialMaxStreamsBidi)
                .unwrap(),
            params.get_local(ParameterId::InitialMaxStreamsUni).unwrap(),
        ));
        let streams = match params.role() {
            Role::Client => {
                let streams = DataStreams::new(
                    Role::Client,
                    client,
                    server,
                    concurrency,
                    reliable.clone(),
                    wakers.clone(),
                    None,
                );
                streams.revise_params(false, server);
                streams
            }
            Role::Server => {
                let streams = DataStreams::new(
                    Role::Server,
                    server,
                    client,
                    concurrency,
                    reliable.clone(),
                    wakers.clone(),
                    None,
                );
                streams.revise_params(false, client);
                streams
            }
        };
        let flow = FlowController::new(
            params.get_remote(ParameterId::InitialMaxData).unwrap(),
            params.get_local(ParameterId::InitialMaxData).unwrap(),
            reliable,
            wakers,
        );
        drop(params);
        Ok(Arc::new(Self {
            parameters,
            streams,
            flow,
        }))
    }

    pub(crate) fn on_error(&self, error: &Error) {
        self.streams.on_conn_error(error);
        self.flow.on_conn_error(error);
    }
}
