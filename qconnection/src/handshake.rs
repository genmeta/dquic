use std::{ops::Deref, sync::Arc};

use qbase::{
    error::Error,
    frame::{
        HandshakeDoneFrame,
        io::{ReceiveFrame, SendFrame},
    },
    role::Role,
};
use qcongestion::HandshakeStatus;

use crate::{
    events::{ArcEventBroker, EmitEvent, Event},
    path::ArcPathContexts,
    space::Spaces,
};

pub type RawHandshake<T> = qbase::handshake::Handshake<T>;

/// A wrapper of [`qbase::handshake::Handshake`] that will emit [`Event::Handshaked`] when the handshake is done.
///
/// Read the documentation of [`qbase::handshake::Handshake`] for more information.
#[derive(Clone)]
pub struct Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    inner: RawHandshake<T>,
    inform_cc: Arc<HandshakeStatus>,
    broker: ArcEventBroker,
}

impl<T> Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    pub fn new(
        raw: RawHandshake<T>,
        inform_cc: Arc<HandshakeStatus>,
        broker: ArcEventBroker,
    ) -> Self {
        Self {
            inner: raw,
            inform_cc,
            broker,
        }
    }

    fn on_confirmed(&self, paths: &ArcPathContexts, spaces: &Spaces) {
        self.inform_cc.handshake_confirmed();
        spaces.discard_handshake_key();
        paths.discard_handshake_space();
        self.broker.emit(Event::Handshaked);
    }

    pub fn discard_spaces_on_server_handshake_done(
        &self,
        paths: &ArcPathContexts,
        spaces: &Spaces,
    ) -> bool {
        let is_server_done = self.inner.done();
        if is_server_done {
            self.on_confirmed(paths, spaces);
        }
        is_server_done
    }

    pub fn role(&self) -> Role {
        self.inner.role()
    }

    pub fn status(&self) -> Arc<HandshakeStatus> {
        self.inform_cc.clone()
    }

    pub fn discard_spaces_on_client_handshake_done(
        &self,
        paths: ArcPathContexts,
        spaces: Spaces,
    ) -> HandshakeDoneReceiver<T> {
        HandshakeDoneReceiver {
            handshake: self.clone(),
            paths,
            spaces,
        }
    }
}

pub struct HandshakeDoneReceiver<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    handshake: Handshake<T>,
    paths: ArcPathContexts,
    spaces: Spaces,
}

impl<T> ReceiveFrame<HandshakeDoneFrame> for HandshakeDoneReceiver<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    type Output = ();

    fn recv_frame(&self, frame: HandshakeDoneFrame) -> Result<(), Error> {
        if self.handshake.inner.recv_frame(frame)? {
            self.handshake.on_confirmed(&self.paths, &self.spaces);
        }
        Ok(())
    }
}

impl<T> Deref for Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    type Target = HandshakeStatus;

    fn deref(&self) -> &Self::Target {
        &self.inform_cc
    }
}
