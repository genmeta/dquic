use std::sync::Arc;

use qbase::{
    self,
    error::{AppError, QuicError},
    frame::ConnectionCloseFrame,
};
use tokio::sync::mpsc;

use crate::state::ArcConnState;

/// The events that can be emitted by a quic connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    // The connection is handshaked
    Handshaked,
    // An Error occurred during the connection, will enter the closing state
    Failed(QuicError),
    // The connection is closed by application, just a notification
    ApplicationClose(AppError),
    // Received a connection close frame, will enter the draining state
    Closed(ConnectionCloseFrame),
    // Received a stateless reset, will enter the draining state
    StatelessReset,
    // The connection is terminated completely
    Terminated,
}

pub trait EmitEvent: Send + Sync {
    fn emit(&self, event: Event);
}

#[derive(Clone)]
pub struct ArcEventBroker {
    conn_state: ArcConnState,
    raw_broker: Arc<dyn EmitEvent>,
}

impl ArcEventBroker {
    pub fn new<E: EmitEvent + 'static>(conn_state: ArcConnState, event_broker: E) -> Self {
        Self {
            conn_state,
            raw_broker: Arc::new(event_broker),
        }
    }
}

impl EmitEvent for ArcEventBroker {
    fn emit(&self, event: Event) {
        match &event {
            Event::Handshaked => {
                if self.conn_state.enter_handshaked().is_none() {
                    return;
                }
            }
            Event::Failed(_) | Event::ApplicationClose(_) | Event::Closed(_) => {}
            Event::Terminated => {
                if self.conn_state.enter_closed().is_none() {
                    return;
                }
            }
            Event::StatelessReset => todo!("unsupported"),
        };
        tracing::debug!(target: "dquic", new_state = ?event, "connection state changed");
        self.raw_broker.emit(event);
    }
}

impl EmitEvent for mpsc::UnboundedSender<Event> {
    fn emit(&self, event: Event) {
        _ = self.send(event);
    }
}

#[cfg(test)]
mod tests {
    use qbase::{
        error::{ErrorFrameType, ErrorKind, QuicError},
        frame::ConnectionCloseFrame,
        varint::VarInt,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::state;

    #[test]
    fn test_emit_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.emit(Event::Handshaked);
        assert_eq!(rx.try_recv().unwrap(), Event::Handshaked);
    }

    #[test]
    fn failed_event_is_forwarded_without_entering_closing() {
        let conn_state = ArcConnState::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let broker = ArcEventBroker::new(conn_state.clone(), tx);
        let error = QuicError::with_default_fty(ErrorKind::NoViablePath, "no path");

        broker.emit(Event::Failed(error.clone()));

        assert_eq!(rx.try_recv().unwrap(), Event::Failed(error));
        assert_ne!(conn_state.current(), Some(state::CLOSING));
    }

    #[test]
    fn closed_event_is_forwarded_without_entering_draining() {
        let conn_state = ArcConnState::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let broker = ArcEventBroker::new(conn_state.clone(), tx);
        let ccf = ConnectionCloseFrame::new_quic(
            ErrorKind::NoViablePath,
            ErrorFrameType::Ext(VarInt::from_u32(0)),
            "",
        );

        broker.emit(Event::Closed(ccf.clone()));

        assert_eq!(rx.try_recv().unwrap(), Event::Closed(ccf));
        assert_ne!(conn_state.current(), Some(state::DRAINING));
    }

    #[test]
    fn application_close_event_is_forwarded_without_entering_closing() {
        let conn_state = ArcConnState::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let broker = ArcEventBroker::new(conn_state.clone(), tx);
        let error = qbase::error::AppError::new(VarInt::from_u32(0), "");

        broker.emit(Event::ApplicationClose(error.clone()));

        assert_eq!(rx.try_recv().unwrap(), Event::ApplicationClose(error));
        assert_ne!(conn_state.current(), Some(state::CLOSING));
    }
}
