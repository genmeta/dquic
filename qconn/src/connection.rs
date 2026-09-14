use std::sync::{Arc, RwLock, Weak};

use bytes::Bytes;
use qbase::{
    error::{AppError, Error},
    param::{ClientParameters, ServerParameters},
    role::Role,
    sid::StreamId,
    varint::VarInt,
};

use crate::{
    data::{DataPlane, StreamReader, StreamWriter},
    lifecycle::CloseState,
    transport::Transport,
};

/// A mature QUIC connection. Keep a connection handle alive while using its
/// streams; dropping the last handle requests connection closure.
#[derive(Clone)]
pub struct ArcConnection(Arc<Connection>);

pub(crate) struct Connection {
    role: Role,
    alpn: Option<Bytes>,
    client_parameters: Arc<ClientParameters>,
    server_parameters: Arc<ServerParameters>,
    close: Arc<CloseState>,
    active: RwLock<Option<Active>>,
}

struct Active {
    data: Arc<DataPlane>,
    transport: Arc<Transport>,
}

pub(crate) fn promote(
    transport: Arc<Transport>,
    alpn: Option<Bytes>,
) -> Result<ArcConnection, Error> {
    transport.close.ensure_open()?;
    let data = transport
        .data
        .get()
        .ok_or_else(|| crate::internal("connection has no data components"))?
        .clone();
    let (client_parameters, server_parameters) = {
        let parameters = data.parameters.lock_guard()?;
        if !parameters.is_remote_params_ready() {
            return Err(crate::internal("connection parameters are incomplete"));
        }
        (
            parameters.client().unwrap().clone(),
            parameters.server().unwrap().clone(),
        )
    };
    if *transport.control.phase.borrow() != crate::control::Phase::Active {
        return Err(crate::internal("connection has not completed TLS"));
    }
    Ok(ArcConnection(Arc::new(Connection {
        role: transport.control.role,
        alpn,
        client_parameters,
        server_parameters,
        close: transport.close.clone(),
        active: RwLock::new(Some(Active { data, transport })),
    })))
}

impl ArcConnection {
    pub fn role(&self) -> Role {
        self.0.role
    }
    pub fn alpn(&self) -> Option<&[u8]> {
        self.0.alpn.as_deref()
    }
    pub fn client_parameters(&self) -> &ClientParameters {
        &self.0.client_parameters
    }
    pub fn server_parameters(&self) -> &ServerParameters {
        &self.0.server_parameters
    }

    fn data(&self) -> Result<Arc<DataPlane>, Error> {
        let active = self.0.active.read().unwrap();
        self.0.close.ensure_open()?;
        Ok(active
            .as_ref()
            .expect("open connection retains active components")
            .data
            .clone())
    }

    pub async fn open_bi_stream(
        &self,
    ) -> Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error> {
        let data = self.data()?;
        data.streams.open_bi(&data.parameters).await
    }

    pub async fn open_uni_stream(&self) -> Result<Option<(StreamId, StreamWriter)>, Error> {
        let data = self.data()?;
        data.streams.open_uni(&data.parameters).await
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), Error> {
        let data = self.data()?;
        data.streams.accept_bi(&data.parameters).await
    }

    pub async fn accept_uni_stream(&self) -> Result<(StreamId, StreamReader), Error> {
        self.data()?.streams.accept_uni().await
    }

    pub fn has_viable_path(&self) -> bool {
        self.0
            .active
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|active| {
                active
                    .transport
                    .paths
                    .snapshot()
                    .iter()
                    .any(|path| !path.failed.load(std::sync::atomic::Ordering::Acquire))
            })
    }

    pub fn close(&self, code: VarInt, reason: &str) -> Result<(), Error> {
        let error = Error::App(AppError::new(code, reason.to_owned()));
        if !self.0.close.request(error.clone()) {
            return Err(self.0.close.reason().unwrap());
        }
        self.0.release(&error);
        Ok(())
    }

    pub async fn closed(&self) -> Error {
        self.0.close.closed().await
    }

    pub(crate) fn downgrade(&self) -> Weak<Connection> {
        Arc::downgrade(&self.0)
    }

    #[cfg(test)]
    pub(crate) fn transport(&self) -> Arc<Transport> {
        self.0
            .active
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .transport
            .clone()
    }
}

impl Connection {
    pub(crate) fn release(&self, error: &Error) {
        let active = self.active.write().unwrap().take();
        if let Some(active) = active {
            active.data.on_error(error);
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close
            .request(AppError::new(0u32.into(), "last connection handle dropped").into());
        self.release(&self.close.reason().unwrap());
    }
}
