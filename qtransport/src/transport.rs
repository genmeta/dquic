use std::sync::Arc;

use qbase::flow::FlowController;
use tokio::time::Instant;

use crate::{ArcParameters, ArcReliableFrames, Error, space::DataSpace};

/// Fully constructed application-data components, shared with the original receive pipes.
pub struct Transport {
    pub data: Arc<DataSpace>,
    pub parameters: ArcParameters,
    pub flow: FlowController<ArcReliableFrames>,
}

impl Transport {
    pub fn new(
        data: Arc<DataSpace>,
        parameters: ArcParameters,
        flow: FlowController<ArcReliableFrames>,
    ) -> Self {
        Self {
            data,
            parameters,
            flow,
        }
    }

    /// Terminate business use. The external driver retains the receive route and close keys.
    pub fn close(&self, error: Error) {
        self.data.crypto.on_error(&error);
        self.data.streams.on_conn_error(&error);
        self.flow.on_conn_error(&error);
    }

    /// Drive recovery from the connection's timer while Data keys remain live.
    /// Keep ticking even when no path sender remains; recovered data can await a new path.
    pub fn on_tick(&self, now: Instant) {
        self.data.on_tick(now);
    }
}
