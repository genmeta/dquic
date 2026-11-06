use super::{ControlStreamsConcurrency, Dir};

/// Consistent concurrency strategy increase limits as streams are closed,
/// to keep the number of streams available to peers roughly consistent.
#[derive(Debug)]
pub struct ConsistentConcurrency {
    max_streams: [u64; 2],
}

impl ConsistentConcurrency {
    pub fn new(initial_max_bi: u64, initial_max_uni: u64) -> Self {
        Self { max_streams: [initial_max_bi, initial_max_uni] }
    }
}

impl ControlStreamsConcurrency for ConsistentConcurrency {
    fn on_accept_streams(&mut self, _dir: Dir, _sid: u64) -> Option<u64> {
        None
    }

    fn on_end_of_stream(&mut self, dir: Dir, _sid: u64) -> Option<u64> {
        let idx = dir as usize;
        let new_limit = self.max_streams[idx] + 1;

        self.max_streams[idx] = new_limit;
        Some(new_limit)
    }

    fn on_streams_blocked(&mut self, _dir: Dir, _max_streams: u64) -> Option<u64> {
        None
    }
}

/// Demand concurrency strategy increase limits as long as receiving a
/// [`StreamsBlockedFrame`](crate::frame::StreamsBlockedFrame).
#[derive(Debug)]
pub struct DemandConcurrency;

impl ControlStreamsConcurrency for DemandConcurrency {
    fn on_accept_streams(&mut self, _dir: Dir, _sid: u64) -> Option<u64> {
        None
    }

    fn on_end_of_stream(&mut self, _dir: Dir, _sid: u64) -> Option<u64> {
        None
    }

    fn on_streams_blocked(&mut self, _dir: Dir, max_streams: u64) -> Option<u64> {
        Some(max_streams + 1)
    }
}
