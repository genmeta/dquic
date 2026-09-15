//! Validated, immutable parameters for an established connection.
//!
//! The legacy `param::ArcParameters` remains available to handshake implementations.
//! This type contains neither a readiness future nor a connection error state.
use std::sync::Arc;

use super::{ClientParameters, ParameterId, ParameterValue, ServerParameters};
use crate::role::Role;

#[derive(Debug, Clone)]
pub struct ArcParameters {
    role: Role,
    client: Arc<ClientParameters>,
    server: Arc<ServerParameters>,
}

impl ArcParameters {
    /// The handshake owner must authenticate the supplied parameters before construction.
    pub fn new(role: Role, client: Arc<ClientParameters>, server: Arc<ServerParameters>) -> Self {
        Self {
            role,
            client,
            server,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }
    pub fn client(&self) -> &ClientParameters {
        &self.client
    }
    pub fn server(&self) -> &ServerParameters {
        &self.server
    }

    pub fn local<V: TryFrom<ParameterValue>>(&self, id: ParameterId) -> Option<V> {
        match self.role {
            Role::Client => self.client.get(id),
            Role::Server => self.server.get(id),
        }
    }

    pub fn remote<V: TryFrom<ParameterValue>>(&self, id: ParameterId) -> Option<V> {
        match self.role {
            Role::Client => self.server.get(id),
            Role::Server => self.client.get(id),
        }
    }
}
