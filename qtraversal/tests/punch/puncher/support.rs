use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::BytesMut;
use qbase::{
    frame::{Frame, FrameReader, PunchHelloFrame},
    packet::{Constraints, PacketBuffer, Type, assemble::Package},
};
use qtraversal::punch::PunchPacketEncoder;
use tokio::{sync::Notify, task::Id};

pub(super) const PROBE: &[u8] = &[0x40, b'P'];

#[derive(Clone, Default)]
pub(super) struct Encoder(Arc<Mutex<Vec<(Id, PunchHelloFrame)>>>, Arc<Notify>);

impl Encoder {
    pub(super) fn hellos(&self) -> Vec<(Id, PunchHelloFrame)> {
        self.0.lock().unwrap().clone()
    }

    pub(super) async fn wait_for_hello(&self, matches: impl Fn(Id) -> bool) -> PunchHelloFrame {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let changed = self.1.notified();
                if let Some((_, hello)) = self.hellos().into_iter().find(|(id, _)| matches(*id)) {
                    return hello;
                }
                changed.await;
            }
        })
        .await
        .expect("selected strategy must send a HELLO")
    }
}

pub(super) fn decode(mut bytes: BytesMut) -> Vec<Frame<bytes::Bytes>> {
    assert!(bytes.starts_with(PROBE));
    FrameReader::new(bytes.split_off(PROBE.len()).freeze(), Type::Short(0.into()))
        .map(|frame| frame.unwrap().0)
        .collect()
}

impl PunchPacketEncoder for Encoder {
    fn encode_probe<P>(&self, mut frame: P) -> io::Result<BytesMut>
    where
        P: for<'b> Package<&'b mut BytesMut>,
    {
        let mut bytes = BytesMut::from(PROBE);
        let mut limits = Constraints {
            flow_ctrl: usize::MAX,
            send_quota: 128,
            credit: 128,
            max_size: 128,
            ..Default::default()
        };
        let mut output = &mut bytes;
        let mut frames = Vec::new();
        let mut buffer = PacketBuffer::new(
            &mut output,
            &mut limits,
            &mut frames,
            Type::Short(0.into()),
            0,
            0,
        );
        let result = frame.poll_dump(&mut Context::from_waker(Waker::noop()), &mut buffer);
        assert!(
            matches!(result, Poll::Ready(Ok(1))),
            "encode probe: {result:?}"
        );
        for frame in decode(bytes.clone()) {
            if let Frame::PunchHello(hello) = frame {
                self.0.lock().unwrap().push((tokio::task::id(), hello));
                self.1.notify_one();
            }
        }
        Ok(bytes)
    }
}
