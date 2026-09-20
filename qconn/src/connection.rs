use std::{sync::Arc, time::Duration};

use qbase::error::Error;
use qtransport::transport::Transport;
use tokio::time::Instant;

use crate::handshake::{Connecting, incoming::Incoming};

/// Owned exclusively by lifecycle::drive. Application handles belong to qtransport.
pub(crate) enum Connection {
    Incoming(Incoming),
    Connecting(Box<Connecting>),
    Active {
        tls: Box<qtls::EstablishedTls>,
        transport: Arc<Transport>,
    },
    Closing {
        error: Error,
        until: Instant,
    },
    Draining {
        until: Instant,
    },
    Terminated,
}

impl Connection {
    pub(crate) fn close(&mut self, error: Error, grace: Duration) {
        if matches!(
            self,
            Self::Incoming(_) | Self::Connecting(_) | Self::Active { .. }
        ) {
            *self = Self::Closing {
                error,
                until: Instant::now() + grace,
            };
        }
    }

    pub(crate) fn drain(&mut self, grace: Duration) {
        let until = match self {
            Self::Closing { until, .. } => *until,
            Self::Draining { .. } | Self::Terminated => return,
            _ => Instant::now() + grace,
        };
        *self = Self::Draining { until };
    }
}

#[cfg(test)]
mod tests {
    use qbase::error::{ErrorKind, QuicError};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn late_errors_and_peer_close_preserve_the_first_closing_deadline() {
        let mut connection = Connection::Incoming(Incoming::default());
        let error = QuicError::with_default_fty(ErrorKind::ConnectionRefused, "first cause");
        connection.close(error.clone().into(), Duration::from_secs(3));
        let until = match &connection {
            Connection::Closing { until, .. } => *until,
            _ => panic!(),
        };
        tokio::time::advance(Duration::from_secs(1)).await;
        connection.close(
            QuicError::with_default_fty(ErrorKind::Internal, "late error").into(),
            Duration::from_secs(30),
        );
        assert!(
            matches!(&connection, Connection::Closing { error: first, until: end } if first.kind() == error.kind() && *end == until)
        );
        connection.drain(Duration::from_secs(30));
        connection.close(error.into(), Duration::from_secs(30));
        assert!(matches!(connection, Connection::Draining { until: end } if end == until));
    }
}
