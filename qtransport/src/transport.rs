use std::sync::Arc;

use qbase::flow::FlowController;
use qrecovery::streams::DataStreams;
use tokio::time::Instant;

use crate::{ArcParameters, Error, ReliableFrames, keys::ArcOneRttKeys, path::Paths, space::Space};

/// Fully constructed application-data components, shared with the original receive pipes.
pub struct Transport {
    pub data: Arc<Space<ArcOneRttKeys>>,
    pub parameters: ArcParameters,
    pub streams: DataStreams<ReliableFrames>,
    pub flow: FlowController<ReliableFrames>,
    pub reliable_frames: ReliableFrames,
    pub paths: Arc<Paths>,
}

impl Transport {
    pub fn new(
        data: Arc<Space<ArcOneRttKeys>>,
        parameters: ArcParameters,
        streams: DataStreams<ReliableFrames>,
        flow: FlowController<ReliableFrames>,
        reliable_frames: ReliableFrames,
        paths: Arc<Paths>,
    ) -> Self {
        Self {
            data,
            parameters,
            streams,
            flow,
            reliable_frames,
            paths,
        }
    }

    /// Terminate business use. The external driver retains the receive route and close keys.
    pub fn close(&self, error: Error) {
        self.data.stop_sending();
        self.streams.on_conn_error(&error);
        self.flow.on_conn_error(&error);
    }

    /// Drive recovery from the connection's timer while Data sending is enabled.
    /// Keep ticking even when no path sender remains; recovered data can await a new path.
    pub fn on_tick(&self, now: Instant) {
        self.data.on_tick(now);
    }
}
