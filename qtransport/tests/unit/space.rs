use std::{sync::Arc, time::Duration};

use qbase::{
    Epoch,
    frame::{AckFrame, Frame, io::SendFrame},
};
use qevent::quic::recovery::PacketLostTrigger;
use tokio::{io::AsyncWriteExt, time::Instant};

use crate::{
    keys::ArcKeys,
    space::{HandshakeSpace, Space},
};

fn metadata(epoch: Epoch, frames: &[Frame]) -> qbase::packet::assemble::Metadata {
    use qbase::packet::{GetType, LongHeaderBuilder, OneRttHeader};
    let header = LongHeaderBuilder::with_cid(Default::default(), Default::default());
    let packet_type = match epoch {
        Epoch::Initial => header.initial(vec![]).get_type(),
        Epoch::Handshake => header.handshake().get_type(),
        Epoch::Data => OneRttHeader::new(Default::default(), Default::default()).get_type(),
    };
    let mut meta = qbase::packet::assemble::Metadata::new(packet_type);
    for frame in frames {
        meta.record(frame);
    }
    meta
}

fn record(space: &Space<ArcKeys<()>>) -> u64 {
    let frames = crate::tests::take_frames(&mut space.crypto.outgoing());
    assert_eq!(frames.len(), 1);
    let (pn, _) = space.next_pn().unwrap();
    space.sent_journal.on_sealed(
        pn,
        None,
        0,
        metadata(space.epoch, &frames),
        frames.into_iter().map(|frame| frame.try_into().unwrap()),
    );
    space.on_sent([(pn, true)], Duration::from_secs(1), Duration::from_secs(3));
    pn
}

#[tokio::test]
async fn shared_space_recovers_once_and_stops_after_key_retirement() {
    let space = Arc::new(Space::new(
        Epoch::Initial,
        Default::default(),
        ArcKeys::new(()),
    ));
    let paths: [Arc<dyn qcongestion::Resend>; 2] = [space.clone(), space.clone()];
    space.crypto.writer().write_all(b"first").await.unwrap();
    let first = record(&space);
    paths[0].resend(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
    paths[1].resend(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
    assert_eq!(
        crate::tests::take_frames(&mut space.crypto.outgoing()).len(),
        1
    );
    assert!(crate::tests::take_frames(&mut space.crypto.outgoing()).is_empty());

    space.crypto.writer().write_all(b"second").await.unwrap();
    record(&space);
    space.on_tick(Instant::now() + Duration::from_secs(2));
    assert_eq!(
        crate::tests::take_frames(&mut space.crypto.outgoing()).len(),
        1
    );

    space.crypto.writer().write_all(b"third").await.unwrap();
    let third = record(&space);
    space.keys.retire();
    paths[0].resend(PacketLostTrigger::TimeThreshold, &mut [third].into_iter());
    space.on_tick(Instant::now() + Duration::from_secs(2));
    assert!(crate::tests::take_frames(&mut space.crypto.outgoing()).is_empty());
}

#[tokio::test]
async fn late_ack_cancels_crypto_recovery() {
    use qcongestion::Resend as _;

    let space = HandshakeSpace::new(Default::default(), ArcKeys::new(()));
    space.crypto.writer().write_all(b"crypto").await.unwrap();
    let pn = record(&space);
    space.resend(PacketLostTrigger::TimeThreshold, &mut [pn].into_iter());
    let ack = AckFrame::new(
        pn.try_into().unwrap(),
        0u32.into(),
        0u32.into(),
        vec![],
        None,
    );
    assert!(space.on_acked(&ack).unwrap());
    space.resend(PacketLostTrigger::TimeThreshold, &mut [pn].into_iter());
    space.on_tick(Instant::now() + Duration::from_secs(2));
    assert!(crate::tests::take_frames(&mut space.crypto.outgoing()).is_empty());
    assert!(!space.on_acked(&ack).unwrap());
}

#[tokio::test(start_paused = true)]
async fn batch_submission_allows_early_ack_and_leaves_suffix_pending() {
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        let space = Space::new(epoch, Default::default(), ArcKeys::new(()));
        let mut pns = Vec::new();
        for bytes in [b"first".as_slice(), b"second", b"third"] {
            space.crypto.writer().write_all(bytes).await.unwrap();
            let pn = space.next_pn().unwrap().0;
            let frames = crate::tests::take_frames(&mut space.crypto.outgoing());
            space.sent_journal.on_sealed(
                pn,
                None,
                0,
                metadata(epoch, &frames),
                frames.into_iter().map(|frame| frame.try_into().unwrap()),
            );
            pns.push(pn);
        }
        let ack = AckFrame::new(
            pns[0].try_into().unwrap(),
            0u32.into(),
            0u32.into(),
            vec![],
            None,
        );
        assert!(space.on_acked(&ack).unwrap());
        space.on_sent(
            pns[..2].iter().map(|&pn| (pn, true)),
            Duration::from_secs(1),
            Duration::from_secs(3),
        );
        space.on_tick(Instant::now() + Duration::from_secs(2));
        let recovered = crate::tests::take_frames(&mut space.crypto.outgoing());
        assert!(
            matches!(recovered.as_slice(), [Frame::Crypto(frame, _)] if frame.offset() == 5 && frame.len() == 6)
        );
        space.cancel(pns[2]);
        let recovered = crate::tests::take_frames(&mut space.crypto.outgoing());
        assert!(
            matches!(recovered.as_slice(), [Frame::Crypto(frame, _)] if frame.offset() == 11 && frame.len() == 5)
        );
        assert!(!space.on_acked(&ack).unwrap());
    }
}

#[tokio::test(start_paused = true)]
async fn data_pending_ack_reports_generation_and_prevents_retransmission() {
    use qbase::frame::MaxDataFrame;

    use crate::space::{Recover as _, Transmit};

    let data = crate::tests::data();
    let pn = data.next_pn().unwrap().0;
    Transmit::on_sealed(
        data.as_ref(),
        pn,
        Some(7),
        0,
        metadata(Epoch::Data, &[Frame::MaxData(MaxDataFrame::new(123u32.into()))]),
        &mut [qbase::frame::GuaranteedFrame::Reliable(MaxDataFrame::new(123u32.into()).into())].into_iter(),
    );
    let ack = AckFrame::new(
        pn.try_into().unwrap(),
        0u32.into(),
        0u32.into(),
        vec![],
        None,
    );
    assert_eq!(data.on_acked(&ack).unwrap(), Some(7));
    data.on_sent([(pn, true)], Duration::from_secs(1), Duration::from_secs(3));
    data.on_tick(Instant::now() + Duration::from_secs(2));
    assert!(crate::tests::take_frames(&mut data.reliable_frames.clone()).is_empty());
    assert!(data.on_acked(&ack).unwrap().is_none());
}

#[tokio::test]
async fn retired_data_keys_stop_loss_and_timer_recovery() {
    use qbase::frame::MaxDataFrame;
    use qcongestion::Resend as _;

    use crate::space::{Recover as _, Transmit};

    let data = crate::tests::data();
    data.reliable_frames
        .send_frame([MaxDataFrame::new(123u32.into())]);
    let mut frames = crate::tests::take_frames(&mut data.reliable_frames.clone());
    assert_eq!(frames.len(), 1);
    let (pn, _) = data.next_pn().unwrap();
    Transmit::on_sealed(
        data.as_ref(),
        pn,
        Some(0),
        0,
        metadata(Epoch::Data, &frames),
        &mut frames.drain(..).map(|frame| frame.try_into().unwrap()),
    );
    data.on_sent([(pn, true)], Duration::from_secs(1), Duration::from_secs(3));
    data.keys.retire();
    data.resend(PacketLostTrigger::TimeThreshold, &mut [pn].into_iter());
    data.on_tick(Instant::now() + Duration::from_secs(2));
    assert!(crate::tests::take_frames(&mut data.reliable_frames.clone()).is_empty());
}

#[tokio::test]
async fn data_trait_cancel_recovers_staged_and_sealed_frames() {
    use qbase::frame::{GuaranteedFrame, MaxDataFrame};

    for sealed in [false, true] {
        let data = crate::tests::data();
        let space: &dyn crate::space::Encapsulate = data.as_ref();
        let (_, mut writer) = data.streams.open_uni().await.unwrap().unwrap();
        writer.write_all(b"stream").await.unwrap();
        data.crypto.writer().write_all(b"crypto").await.unwrap();
        data.reliable_frames
            .send_frame([MaxDataFrame::new(123u32.into())]);
        assert_eq!(space.fresh_bytes(), 6);

        let prefix = Frame::MaxData(MaxDataFrame::new(1u32.into()));
        let mut frames = vec![prefix.clone()];
        frames.extend(crate::tests::take_frames(&mut data.crypto.outgoing()));
        frames.extend(crate::tests::take_frames(&mut data.reliable_frames.clone()));
        frames.extend(crate::tests::take_frames(&mut data.streams.clone()));
        assert_eq!(frames.len(), 4);
        assert_eq!(space.fresh_bytes(), 0);
        let (pn, _) = space.pn_and_keys().unwrap().unwrap();
        let meta = metadata(Epoch::Data, &frames[1..]);
        let mut frames: Vec<GuaranteedFrame> = frames
            .into_iter()
            .map(|frame| frame.try_into().unwrap())
            .collect();
        if sealed {
            space.on_sealed(pn.0, Some(0), 128, meta, &mut frames.drain(1..));
        }
        space.cancel(pn.0, &mut frames.drain(1..));
        assert_eq!(frames, vec![prefix.try_into().unwrap()]);
        assert_eq!(space.fresh_bytes(), 0);
        assert!(matches!(
            crate::tests::take_frames(&mut data.crypto.outgoing()).as_slice(),
            [Frame::Crypto(frame, _)] if frame.offset() == 0 && frame.len() == 6
        ));
        assert!(matches!(
            crate::tests::take_frames(&mut data.reliable_frames.clone()).as_slice(),
            [Frame::MaxData(_)]
        ));
        assert!(matches!(
            crate::tests::take_frames(&mut data.streams.clone()).as_slice(),
            [Frame::Stream(frame, _)] if frame.offset() == 0 && frame.len() == 6
        ));
    }
}

#[tokio::test]
async fn data_trait_unregister_removes_all_source_waiters() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
    };

    use bytes::BytesMut;
    use qbase::{
        frame::MaxDataFrame,
        packet::{PacketBuffer, Constraints, GetType, OneRttHeader, Package},
    };

    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    for unregister in [false, true] {
        let data = crate::tests::data();
        let space: &dyn crate::space::Encapsulate = data.as_ref();
        let (_, mut writer) = data.streams.open_uni().await.unwrap().unwrap();
        let counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        let mut crypto = data.crypto.outgoing();
        let mut ack = data.rcvd_journal.clone();
        let mut reliable = data.reliable_frames.clone();
        let mut streams = data.streams.clone();
        let sources: [&mut dyn Package<BytesMut>; 4] =
            [&mut crypto, &mut ack, &mut reliable, &mut streams];
        for source in sources {
            let mut bytes = BytesMut::new();
            let mut limits = Constraints {
                flow_ctrl: 1200,
                send_quota: 1200,
                credit: 1200,
                max_size: 1200,
                ..Default::default()
            };
            let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
            assert!(
                source
                    .poll_dump(
                        &mut Context::from_waker(&waker),
                        &mut PacketBuffer::new(&mut bytes, &mut limits, &mut Vec::new(), ty, 0, 0),
                    )
                    .is_pending()
            );
        }
        if unregister {
            space.unregister(&waker);
        }
        data.crypto.writer().write_all(b"crypto").await.unwrap();
        data.rcvd_journal.on_rcvd_pn(0, true, Duration::ZERO);
        data.reliable_frames
            .send_frame([MaxDataFrame::new(123u32.into())]);
        writer.write_all(b"stream").await.unwrap();
        assert_eq!(
            counter.0.load(Ordering::Relaxed),
            if unregister { 0 } else { 4 }
        );
    }
}
