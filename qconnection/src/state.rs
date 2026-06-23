use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use qbase::{error::Error, frame::ConnectionCloseFrame, net::route::Link, role::Role};
use qevent::{
    quic::{
        Owner,
        connectivity::{
            BaseConnectionStates, ConnectionStarted, ConnectionState as QlogConnectionState,
            ConnectionStateUpdated, GranularConnectionStates,
        },
        transport::ParametersSet,
    },
    telemetry::Instrument,
};
use tokio::sync::SetOnce;
use tracing::Instrument as _;

use crate::Components;

#[derive(Clone)]
pub struct ArcConnState {
    state: Arc<AtomicU8>,
    handshaked: Arc<SetOnce<()>>,
    terminated: Arc<SetOnce<Error>>,
    closed: Arc<SetOnce<()>>,
}

impl Default for ArcConnState {
    fn default() -> Self {
        Self {
            state: Default::default(),
            handshaked: Arc::new(SetOnce::new()),
            terminated: Arc::new(SetOnce::new()),
            closed: Arc::new(SetOnce::new()),
        }
    }
}

impl ArcConnState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to set the connection state from None to `BaseConnectionStates::Attempted`.
    ///
    /// Returns true if the state was successfully set to `BaseConnectionStates::Attempted`.
    ///
    /// Called when creating paths. If it returns true, it means that the path is the first path to connect.
    pub fn try_entry_attempted(&self, components: &Components, link: Link) -> Result<bool, Error> {
        let attempted = encode(BaseConnectionStates::Attempted.into());
        let success = self
            .state
            .compare_exchange(0, attempted, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();

        if success {
            // same as Self::update
            qevent::event!(ConnectionStateUpdated {
                new: BaseConnectionStates::Attempted,
            });
            qevent::event!(ConnectionStarted {
                socket: { (link.src, link.dst) } // cid不在这一层，未知
            });

            match components.role() {
                Role::Client => {
                    let lock_guard = components.parameters.lock_guard();
                    if let Some(local_parameters) =
                        lock_guard.as_ref().ok().and_then(|p| p.client())
                    {
                        qevent::event!(ParametersSet {
                            owner: Owner::Local,
                            client_parameters: local_parameters.as_ref(),
                        })
                    }
                }
                Role::Server => {
                    let lock_guard = components.parameters.lock_guard();
                    if let Some(local_parameters) =
                        lock_guard.as_ref().ok().and_then(|p| p.server())
                    {
                        qevent::event!(ParametersSet {
                            owner: Owner::Local,
                            server_parameters: local_parameters.as_ref(),
                        })
                    }
                }
            };
        }
        Ok(success)
    }

    /// Try to update the connection state, return the old state if successful.
    pub fn update(&self, state: QlogConnectionState) -> Option<QlogConnectionState> {
        let new_state_code = encode(state);
        let mut old_state_code = self.state.load(Ordering::Acquire);
        loop {
            if new_state_code <= old_state_code {
                return None;
            }
            match self.state.compare_exchange(
                old_state_code,
                new_state_code,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_old_state_code) => {
                    // when server received a initial packet but failed to decrypt it, connection state will
                    // enter Closing directly without enter Attempted.
                    let old_state =
                        decode(old_state_code).unwrap_or(BaseConnectionStates::Attempted.into());
                    qevent::event!(ConnectionStateUpdated {
                        new: state,
                        old: old_state
                    });
                    return Some(old_state);
                }
                Err(current_state_code) => old_state_code = current_state_code,
            }
        }
    }

    pub fn enter_handshaked(&self) -> Option<QlogConnectionState> {
        if let Some(old_state) = self.update(GranularConnectionStates::HandshakeConfirmed.into()) {
            self.handshaked.set(()).expect("Handshaked already set");
            return Some(old_state);
        }
        None
    }

    pub fn enter_closing(&self, error: &(impl Into<Error> + Clone)) -> Option<QlogConnectionState> {
        if let Some(old_state) = self.update(GranularConnectionStates::Closing.into()) {
            self.terminated
                .set(error.clone().into())
                .expect("Terminated error already set");
            return Some(old_state);
        }
        None
    }

    pub fn enter_draining(&self, ccf: &ConnectionCloseFrame) -> Option<QlogConnectionState> {
        if let Some(old_state) = self.update(GranularConnectionStates::Draining.into()) {
            if old_state != QlogConnectionState::Granular(GranularConnectionStates::Closing) {
                self.terminated
                    .set(ccf.clone().into())
                    .expect("Terminated error already set");
            }
            return Some(old_state);
        }
        None
    }

    pub fn enter_draining_with_error(
        &self,
        error: &(impl Into<Error> + Clone),
    ) -> Option<QlogConnectionState> {
        if let Some(old_state) = self.update(GranularConnectionStates::Draining.into()) {
            if old_state != QlogConnectionState::Granular(GranularConnectionStates::Closing) {
                self.terminated
                    .set(error.clone().into())
                    .expect("Terminated error already set");
            }
            return Some(old_state);
        }
        None
    }

    pub fn enter_closed(&self) -> Option<QlogConnectionState> {
        if let Some(old_state) = self.update(BaseConnectionStates::Closed.into()) {
            _ = self.closed.set(());
            return Some(old_state);
        }
        None
    }

    pub fn handshaked(&self) -> impl Future<Output = Result<(), Error>> + Send + use<> {
        let handshaked = self.handshaked.clone();
        let terminated = self.terminated.clone();
        async move {
            tokio::select! {
                _ = handshaked.wait() => Ok(()),
                error = terminated.wait() => Err(error.clone()),
            }
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn terminated(&self) -> impl Future<Output = Error> + Send + use<> {
        let terminated = self.terminated.clone();
        async move { terminated.wait().await.clone() }
            .instrument_in_current()
            .in_current_span()
    }

    pub fn closed(&self) -> impl Future<Output = ()> + Send + use<> {
        let closed = self.closed.clone();
        async move {
            closed.wait().await;
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn current(&self) -> Option<QlogConnectionState> {
        decode(self.state.load(Ordering::Acquire))
    }
}

macro_rules! mapping {
    ($( $a:ident ::$ b:ident ( $c:ident :: $d:ident ) => $number:literal, )*) => {
        pub fn decode(code: u8) -> Option<QlogConnectionState> {
            match code {
                $( $number => Some($a::$b($c::$d)), )*
                _ => None,
            }
        }

        pub fn encode(state: QlogConnectionState) -> u8 {
            match state {
                $( $a::$b($c::$d) => $number, )*
                _ => unreachable!("base closed and granular closed are repeated, use the base one"),
            }
        }
    };
}

mapping! {
    QlogConnectionState::Base(BaseConnectionStates::Attempted) => 1,
    QlogConnectionState::Base(BaseConnectionStates::HandshakeStarted) => 2, // miss
    QlogConnectionState::Granular(GranularConnectionStates::PeerValidated) => 3, // miss
    QlogConnectionState::Granular(GranularConnectionStates::EarlyWrite) => 4, // miss
    QlogConnectionState::Base(BaseConnectionStates::HandshakeComplete) => 5, // miss
    QlogConnectionState::Granular(GranularConnectionStates::HandshakeConfirmed) => 6,
    QlogConnectionState::Granular(GranularConnectionStates::Closing) => 7,
    QlogConnectionState::Granular(GranularConnectionStates::Draining) => 8,
    // QlogConnectionState::Granular(GranularConnectionStates::Closed) => 9,
    QlogConnectionState::Base(BaseConnectionStates::Closed) => 9,
}

pub const HANDSHAKE_CONFIRMED: QlogConnectionState =
    QlogConnectionState::Granular(GranularConnectionStates::HandshakeConfirmed);

pub const CLOSING: QlogConnectionState =
    QlogConnectionState::Granular(GranularConnectionStates::Closing);

pub const DRAINING: QlogConnectionState =
    QlogConnectionState::Granular(GranularConnectionStates::Draining);

pub const CLOSED: QlogConnectionState =
    QlogConnectionState::Granular(GranularConnectionStates::Closed);

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_waits_for_final_closed_state() {
        let conn_state = ArcConnState::new();
        let waiter = conn_state.closed();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), waiter)
                .await
                .is_err()
        );

        assert!(conn_state.enter_closed().is_some());

        tokio::time::timeout(std::time::Duration::from_secs(1), conn_state.closed())
            .await
            .expect("closed wait should complete after enter_closed");
        assert_eq!(
            conn_state.current(),
            Some(BaseConnectionStates::Closed.into())
        );
    }

    #[tokio::test]
    async fn draining_with_error_sets_draining_and_termination_error() {
        let conn_state = ArcConnState::new();
        let error = qbase::error::QuicError::with_default_fty(
            qbase::error::ErrorKind::ConnectionRefused,
            "silent refusal",
        );

        assert!(conn_state.enter_draining_with_error(&error).is_some());
        assert_eq!(conn_state.current(), Some(DRAINING));
        assert_eq!(
            conn_state.terminated().await.kind(),
            qbase::error::ErrorKind::ConnectionRefused
        );
    }
}
