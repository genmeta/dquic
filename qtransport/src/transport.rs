use std::sync::Arc;

use qbase::flow::FlowController;
use qrecovery::streams::DataStreams;
use tokio::time::Instant;

use crate::{ArcParameters, Error, ReliableFrames, keys::ArcOneRttKeys, space::Space};

/// Fully constructed application-data components, shared with the original receive pipes.
pub struct Transport {
    pub data: Arc<Space<ArcOneRttKeys>>,
    pub parameters: ArcParameters,
    pub streams: DataStreams<ReliableFrames>,
    pub flow: FlowController<ReliableFrames>,
    pub reliable_frames: ReliableFrames,
}

impl Transport {
    pub fn new(
        data: Arc<Space<ArcOneRttKeys>>,
        parameters: ArcParameters,
        streams: DataStreams<ReliableFrames>,
        flow: FlowController<ReliableFrames>,
        reliable_frames: ReliableFrames,
    ) -> Self {
        Self {
            data,
            parameters,
            streams,
            flow,
            reliable_frames,
        }
    }

    /// Terminate business use. The external driver retains the receive route and close keys.
    pub fn close(&self, error: Error) {
        self.data.crypto.on_error(&error);
        self.streams.on_conn_error(&error);
        self.flow.on_conn_error(&error);
    }

    /// Drive recovery from the connection's timer while Data keys remain live.
    /// Keep ticking even when no path sender remains; recovered data can await a new path.
    pub fn on_tick(&self, now: Instant) {
        self.data.on_tick(now);
    }
}
