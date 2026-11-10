use std::{
    ops::Bound::{Excluded, Included, Unbounded},
    task::{Context, Poll, Waker},
};

use bytes::BufMut;
use qbase::{
    frame::{Fin, FrameType, Len, Offset, StreamCtlFrame, io::SendFrame},
    net::tx::UnregisterWaker,
    packet::{Package, PacketBuffer},
};

use super::{ArcDataStreams, DataStreams, io::Output};

impl<TX: Clone> Output<TX> {
    /// Serve one stream per call, preserving its byte budget across packets and paths.
    fn poll_dump<B: BufMut + ?Sized>(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>, credit: &mut usize) -> Poll<usize> {
        const STREAM_QUANTUM: usize = 4096;
        let Some((current, remaining)) = self.turn.or_else(|| self.outgoings.last_key_value().map(|(&sid, _)| (sid, STREAM_QUANTUM)))
        else {
            return Poll::Pending;
        };
        // Resume a partial turn; exhausted turns start after the previous stream.
        let (before, after) = if remaining == 0 {
            (Excluded(current), Included(current))
        } else {
            (Included(current), Excluded(current))
        };
        let streams = self.outgoings.range((Unbounded, before)).rev().chain(self.outgoings.range((after, Unbounded)).rev());
        let mut availability = Poll::Pending;
        for (&sid, (outgoing, _)) in streams {
            let mut budget = if sid == current && remaining > 0 {
                remaining
            } else {
                STREAM_QUANTUM
            };
            match outgoing.poll_dump(cx, buffer, credit, &mut budget) {
                Poll::Ready(n) if n > 0 => {
                    self.turn = Some((sid, budget));
                    return Poll::Ready(n);
                }
                Poll::Ready(_) => availability = Poll::Ready(0),
                Poll::Pending => {}
            }
        }
        availability
    }
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Bound reservations by actual pending fresh bytes; idle polling must not reserve and refund flow credit.
    pub fn fresh_bytes(&self) -> usize {
        self.fresh_bytes_up_to(usize::MAX)
    }

    /// Stop counting once the caller has enough credit for its packet.
    pub fn fresh_bytes_up_to(&self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        let streams = self.output.streams();
        let Ok(output) = streams.as_ref() else {
            return 0;
        };
        let mut total = 0usize;
        for (stream, _) in output.values() {
            total = total.saturating_add(stream.fresh_bytes());
            if total >= limit {
                return limit;
            }
        }
        total
    }

    pub(crate) fn poll_dump<B: BufMut + ?Sized>(&self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
        buffer.for_frame(qbase::frame::FrameType::Stream(Offset::Zero, Len::Explicit, Fin::No));
        let requested = self.fresh_bytes_up_to(buffer.remaining_mut());
        let mut credit = self.flow_ctrl.sender.credit(requested);
        if requested > 0 && credit.available() == 0 {
            credit = std::task::ready!(self.flow_ctrl.sender.poll_credit(cx, requested));
        }
        // Refunding unused credit must only notify senders still waiting for flow credit.
        if requested == 0 || credit.available() > 0 {
            self.flow_ctrl.sender.unregister(cx.waker());
        }
        let available = credit.available();
        let mut remaining = available;
        // Hold the insertion lock through polling and the final waiter registration.
        let mut guard = self.output.streams();
        let Ok(output) = guard.as_mut() else {
            return Poll::Ready(0);
        };
        output.tx_wakers.remove(cx.waker());
        let start = buffer.meta.nframes;
        let result = loop {
            // A full packet or a lengthless STREAM cannot accept another frame.
            buffer.for_frame(FrameType::Stream(Offset::Zero, Len::Explicit, Fin::No));
            if buffer.remaining_mut() < 2 {
                break Poll::Ready(buffer.meta.nframes - start);
            }
            match output.poll_dump(cx, buffer, &mut remaining) {
                Poll::Ready(n) if n > 0 => {}
                _ if buffer.meta.nframes != start => break Poll::Ready(buffer.meta.nframes - start),
                Poll::Pending => {
                    output.tx_wakers.add(cx.waker());
                    break Poll::Pending;
                }
                result => break result,
            }
        };
        let fresh_bytes = available - remaining;
        credit.post_sent(fresh_bytes);
        if fresh_bytes > 0 {
            self.metrics.on_data_sent(fresh_bytes as u64);
        }
        result
    }

    pub(crate) fn unregister(&self, waker: &Waker) {
        self.flow_ctrl.sender.unregister(waker);
        if let Ok(output) = self.output.streams().as_mut() {
            output.tx_wakers.remove(waker);
            for (outgoing, _) in output.values() {
                outgoing.unregister(waker);
            }
        }
    }
}

impl<TX, B: bytes::BufMut + ?Sized> Package<B> for ArcDataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
        self.0.poll_dump(cx, buffer)
    }
}

impl<TX> UnregisterWaker for ArcDataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    fn unregister(&self, waker: &std::task::Waker) {
        self.0.unregister(waker);
    }
}
