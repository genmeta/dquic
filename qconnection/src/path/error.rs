use derive_more::From;
use qbase::{error::Error as QuicError, time::TimeOut};
use qcongestion::TooManyPtos;
use qinterface::bind_uri::BindUri;
use thiserror::Error;

use crate::path::validate::ValidateFailure;

#[derive(Debug, From, Error)]
pub enum CreatePathFailure {
    #[error(transparent)]
    InvalidWay(qinterface::component::route::InvalidWay),
    #[error("Network interface not found for bind URI: {0}")]
    NoInterface(BindUri),
    #[error("Connection is closed")]
    ConnectionClosed(QuicError),
}

#[derive(Debug, From, Error)]
pub enum PathDeactivated {
    #[error("Path validation failed")]
    Invalid(#[source] ValidateFailure),
    #[error(transparent)]
    Idle(TimeOut),
    #[error("Lost path state")]
    Lost(#[source] TooManyPtos),
    #[error("Failed to send packets on path")]
    Io(#[source] std::io::Error),
    #[error("Manually removed by application")]
    App,
}
