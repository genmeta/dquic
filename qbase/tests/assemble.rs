use std::{
    cell::RefCell,
    task::{Context, Poll, Waker},
};

use bytes::BytesMut;
use qbase::{
    error::{Error, ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, PathChallengeFrame, PingFrame},
    packet::{Assemble, Constraints, GetType, LongHeaderBuilder, Package, PacketBuffer, Type},
};

enum Output {
    Ping,
    Pending,
    NoSpace,
    Close,
    Error,
}

struct Source<'a> {
    id: u8,
    priority: u32,
    allowed: bool,
    output: Output,
    calls: &'a RefCell<Vec<u8>>,
}

impl Package<BytesMut> for Source<'_> {
    fn belongs_to(&self, _: Type) -> bool {
        self.allowed
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, BytesMut>,
    ) -> Poll<Result<usize, Error>> {
        self.calls.borrow_mut().push(self.id);
        match self.output {
            Output::Ping => PingFrame.poll_dump(cx, buffer),
            Output::Pending => Poll::Pending,
            Output::NoSpace => Poll::Ready(Ok(0)),
            Output::Close => ConnectionCloseFrame::new_quic(
                ErrorKind::Internal,
                qbase::frame::FrameType::Padding.into(),
                "closed",
            )
            .poll_dump(cx, buffer),
            Output::Error => Poll::Ready(Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "source failed",
            )
            .into())),
        }
    }
}

fn buffer_test(test: impl FnOnce(&mut PacketBuffer<'_, BytesMut>, &mut Context<'_>)) {
    let mut bytes = BytesMut::with_capacity(128);
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 128,
        credit: 128,
        max_size: 128,
        ..Default::default()
    };
    let ty = LongHeaderBuilder::with_cid(Default::default(), Default::default())
        .initial(vec![])
        .get_type();
    let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
    test(&mut buffer, &mut Context::from_waker(Waker::noop()));
}

#[test]
fn filters_before_polling_and_preserves_equal_priority_order_through_wrappers() {
    buffer_test(|buffer, cx| {
        let calls = RefCell::new(Vec::new());
        let source = |id, priority, allowed| Source {
            id,
            priority,
            allowed,
            output: Output::Ping,
            calls: &calls,
        };
        let mut low = source(1, 0, true);
        let mut first = Some(source(2, 10, true));
        let mut first_ref = &mut first;
        let mut second = source(3, 10, true);
        let mut excluded = Some(source(4, u32::MAX, false));
        let mut excluded_ref = &mut excluded;
        assert_eq!(
            buffer.assemble(
                cx,
                &mut [&mut low, &mut excluded_ref, &mut first_ref, &mut second]
            ),
            Poll::Ready(Ok(3)),
        );
        assert_eq!(*calls.borrow(), [2, 3, 1]);
        assert!(first.is_none());
        assert!(excluded.is_some());
        assert_eq!(buffer.assemble(cx, &mut [&mut first]), Poll::Pending);
    });
}

#[test]
fn continues_past_pending_and_no_space_and_reports_earlier_writes() {
    buffer_test(|buffer, cx| {
        let calls = RefCell::new(Vec::new());
        let source = |id, output| Source {
            id,
            priority: 0,
            allowed: true,
            output,
            calls: &calls,
        };
        let mut pending = source(1, Output::Pending);
        let mut no_space = source(2, Output::NoSpace);
        let mut ping = source(3, Output::Ping);
        let mut last = source(4, Output::Pending);
        assert_eq!(
            buffer.assemble(cx, &mut [&mut pending, &mut no_space, &mut ping, &mut last]),
            Poll::Ready(Ok(1)),
        );
        assert_eq!(*calls.borrow(), [1, 2, 3, 4]);
    });
}

#[test]
fn close_prevents_lower_priority_sources_and_later_assembly() {
    buffer_test(|buffer, cx| {
        let calls = RefCell::new(Vec::new());
        let mut ping = Source {
            id: 1,
            priority: 0,
            allowed: true,
            output: Output::Ping,
            calls: &calls,
        };
        let mut close = Source {
            id: 2,
            priority: 10,
            allowed: true,
            output: Output::Close,
            calls: &calls,
        };
        assert_eq!(
            buffer.assemble(cx, &mut [&mut ping, &mut close]),
            Poll::Ready(Ok(1))
        );
        let written = buffer.written();
        assert_eq!(buffer.assemble(cx, &mut [&mut ping]), Poll::Ready(Ok(0)));
        assert_eq!(buffer.written(), written);
        assert_eq!(*calls.borrow(), [2]);
    });
}

#[test]
fn source_error_stops_assembly_and_preserves_written_metadata() {
    buffer_test(|buffer, cx| {
        let calls = RefCell::new(Vec::new());
        let source = |id, output| Source {
            id,
            priority: 0,
            allowed: true,
            output,
            calls: &calls,
        };
        let mut ping = source(1, Output::Ping);
        let mut error = source(2, Output::Error);
        let mut last = source(3, Output::Ping);
        assert!(matches!(
            buffer.assemble(cx, &mut [&mut ping, &mut error, &mut last]),
            Poll::Ready(Err(_)),
        ));
        assert_eq!(*calls.borrow(), [1, 2]);
        assert_eq!(buffer.meta.nframes, 1);
        assert_eq!(buffer.written(), 1);
    });
}

#[test]
fn initial_filters_data_only_frames_without_consuming_them() {
    buffer_test(|buffer, cx| {
        let mut validation = Some(PathChallengeFrame::random());
        let mut ping = PingFrame;
        assert_eq!(
            buffer.assemble(cx, &mut [&mut validation, &mut ping]),
            Poll::Ready(Ok(1))
        );
        assert!(validation.is_some());
        assert_eq!(buffer.written(), 1);
    });
}

#[test]
fn epoch_scoped_sources_keep_priority_and_only_consume_matching_sources() {
    use qbase::Epoch;

    buffer_test(|buffer, cx| {
        let calls = RefCell::new(Vec::new());
        let source = |id, priority| Source {
            id,
            priority,
            allowed: true,
            output: Output::Ping,
            calls: &calls,
        };
        let mut handshake = (Epoch::Handshake, Some(source(1, 100)));
        let mut initial = (Epoch::Initial, Some(source(2, 10)));
        let mut shared = Some(source(3, 0));
        assert_eq!(
            buffer.assemble(cx, &mut [&mut shared, &mut handshake, &mut initial]),
            Poll::Ready(Ok(2))
        );
        assert_eq!(*calls.borrow(), [2, 3]);
        assert!(handshake.1.is_some());
        assert!(initial.1.is_none());
        assert!(shared.is_none());
    });
}
