use std::sync::{Arc, OnceLock, RwLock};

use qbase::{
    Epoch,
    frame::{Frame, ReliableFrame, io::SendFrame},
    net::tx::ArcSendWakers,
};
use qcongestion::Feedback;
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, ArcSentJournal},
    reliable::ArcReliableFrameDeque,
};

use crate::data::DataPlane;

// Space owns shared control/source handles, never a receive loop. Taking the
// optional handles on retirement also releases CRYPTO buffers from CC feedback.
macro_rules! space {
    ($name:ident) => {
        pub(crate) struct $name {
            state: RwLock<
                Option<(
                    Arc<qtls::HeaderProtectionKey>,
                    qtls::PacketKey,
                    CryptoStream,
                    ArcRcvdJournal,
                    ArcSentJournal<Frame<()>>,
                )>,
            >,
            retired: std::sync::atomic::AtomicBool,
            data: Arc<OnceLock<Arc<DataPlane>>>,
            reliable: ArcReliableFrameDeque<ReliableFrame>,
        }

        impl $name {
            fn new(
                data: Arc<OnceLock<Arc<DataPlane>>>,
                reliable: ArcReliableFrameDeque<ReliableFrame>,
            ) -> Arc<Self> {
                Arc::new(Self {
                    state: RwLock::new(None),
                    retired: false.into(),
                    data,
                    reliable,
                })
            }

            pub(crate) fn install(
                &self,
                header: Arc<qtls::HeaderProtectionKey>,
                packet: qtls::PacketKey,
                received: ArcRcvdJournal,
                wakers: ArcSendWakers,
            ) -> Result<(), &'static str> {
                let mut state = self.state.write().unwrap();
                if self.retired.load(std::sync::atomic::Ordering::Acquire) || state.is_some() {
                    return Err("space already installed or retired");
                }
                *state = Some((
                    header,
                    packet,
                    CryptoStream::new(wakers),
                    received,
                    ArcSentJournal::with_capacity(0),
                ));
                Ok(())
            }

            pub(crate) fn snapshot(
                &self,
            ) -> Option<(
                Arc<qtls::HeaderProtectionKey>,
                qtls::PacketKey,
                CryptoStream,
                ArcRcvdJournal,
                ArcSentJournal<Frame<()>>,
            )> {
                self.state.read().unwrap().clone()
            }

            pub(crate) fn retire(&self) {
                let mut state = self.state.write().unwrap();
                self.retired
                    .store(true, std::sync::atomic::Ordering::Release);
                state.take();
            }

            pub(crate) fn requeue(&self, frames: impl IntoIterator<Item = Frame<()>>) {
                let Some((_, _, crypto, _, _)) = self.snapshot() else {
                    return;
                };
                for frame in frames {
                    match frame {
                        Frame::Crypto(frame, ()) => crypto.outgoing().may_loss_data(&frame),
                        Frame::Stream(frame, ()) => {
                            if let Some(data) = self.data.get() {
                                data.streams.may_loss_data(&frame);
                            }
                        }
                        frame => {
                            if let Ok(frame) = ReliableFrame::try_from(&frame) {
                                self.reliable.send_frame([frame]);
                            }
                        }
                    }
                }
            }

            pub(crate) fn acked(&self, frames: impl IntoIterator<Item = Frame<()>>) {
                let Some((_, _, crypto, _, _)) = self.snapshot() else {
                    return;
                };
                for frame in frames {
                    match frame {
                        Frame::Crypto(frame, ()) => crypto.outgoing().on_data_acked(&frame),
                        Frame::Stream(frame, ()) => {
                            if let Some(data) = self.data.get() {
                                data.streams.on_data_acked(frame);
                            }
                        }
                        Frame::StreamCtl(qbase::frame::StreamCtlFrame::ResetStream(frame)) => {
                            if let Some(data) = self.data.get() {
                                data.streams.on_reset_acked(frame);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        impl Feedback for $name {
            fn may_loss(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
                let Some((_, _, _, _, sent)) = self.snapshot() else {
                    return;
                };
                let frames = {
                    let mut journal = sent.rotate();
                    pns.flat_map(|pn| journal.may_loss_packet(pn).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                };
                self.requeue(frames);
            }
        }
    };
}

space!(InitialSpace);
space!(HandshakeSpace);
space!(DataSpace);

pub(crate) struct Spaces {
    pub(crate) initial: Arc<InitialSpace>,
    pub(crate) handshake: Arc<HandshakeSpace>,
    pub(crate) data: Arc<DataSpace>,
    pub(crate) enabled: std::sync::atomic::AtomicU8,
    pub(crate) data_cursor: std::sync::Mutex<Option<qtls::SealingKeyCursor>>,
}

impl Spaces {
    pub(crate) fn new(
        data: Arc<OnceLock<Arc<DataPlane>>>,
        reliable: ArcReliableFrameDeque<ReliableFrame>,
    ) -> Arc<Self> {
        Arc::new(Self {
            initial: InitialSpace::new(data.clone(), reliable.clone()),
            handshake: HandshakeSpace::new(data.clone(), reliable.clone()),
            data: DataSpace::new(data, reliable),
            enabled: 1.into(),
            data_cursor: std::sync::Mutex::new(None),
        })
    }

    pub(crate) fn feedback(&self) -> [Arc<dyn Feedback>; 3] {
        [
            self.initial.clone(),
            self.handshake.clone(),
            self.data.clone(),
        ]
    }

    pub(crate) fn snapshot(
        &self,
        epoch: Epoch,
    ) -> Option<(
        Arc<qtls::HeaderProtectionKey>,
        qtls::PacketKey,
        CryptoStream,
        ArcRcvdJournal,
        ArcSentJournal<Frame<()>>,
    )> {
        match epoch {
            Epoch::Initial => self.initial.snapshot(),
            Epoch::Handshake => self.handshake.snapshot(),
            Epoch::Data => self.data.snapshot(),
        }
    }

    pub(crate) fn retire(&self, epoch: Epoch) {
        self.enabled
            .fetch_and(!(1 << epoch as usize), std::sync::atomic::Ordering::AcqRel);
        match epoch {
            Epoch::Initial => self.initial.retire(),
            Epoch::Handshake => self.handshake.retire(),
            Epoch::Data => self.data.retire(),
        }
    }

    pub(crate) fn requeue(&self, epoch: Epoch, frames: impl IntoIterator<Item = Frame<()>>) {
        match epoch {
            Epoch::Initial => self.initial.requeue(frames),
            Epoch::Handshake => self.handshake.requeue(frames),
            Epoch::Data => self.data.requeue(frames),
        }
    }

    pub(crate) fn acked(&self, epoch: Epoch, frames: impl IntoIterator<Item = Frame<()>>) {
        match epoch {
            Epoch::Initial => self.initial.acked(frames),
            Epoch::Handshake => self.handshake.acked(frames),
            Epoch::Data => self.data.acked(frames),
        }
    }
}
