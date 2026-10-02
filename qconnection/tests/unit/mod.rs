mod discovery;
mod lifecycle;
mod paths;
mod punch;
mod recv;
mod send;
mod terminate;
mod tls;

use crate::Paths;

impl Paths {
    fn retire_all(&self) {
        self.phase().terminator().terminate();
        for path in self.snapshot() {
            self.remove(&path);
        }
    }
}

fn take_heartbeat(path: &qtransport::path::Path) -> bool {
    use std::task::{Context, Poll, Waker};

    use bytes::BytesMut;
    use qbase::{
        frame::Frame,
        packet::{ConstraintBuffer, Constraints, GetType, OneRttHeader, Package},
    };

    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 1,
        credit: 1,
        max_size: 1,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    match path.heartbeat.clone().poll_dump(
        &mut Context::from_waker(Waker::noop()),
        &mut ConstraintBuffer::new(&mut bytes, &mut limits, ty, 0, 0),
        &mut frames,
    ) {
        Poll::Ready(Ok(1)) => {
            assert!(matches!(&frames[..], [Frame::Ping(_)]));
            true
        }
        Poll::Pending => false,
        other => panic!("unexpected heartbeat result: {other:?}"),
    }
}
