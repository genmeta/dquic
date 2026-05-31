use std::{
    ops::{BitAnd, Deref},
    sync::Arc,
};

use tokio::sync::SetOnce;

use crate::prelude::{LocalAuthority, RemoteAuthority};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub enum ClientNameVerifyResult {
    #[default]
    Accept,
    /// Refuse the connection with a reason that will be sent to the client.
    Refuse(String),
    /// Refuse the connection silently without sending any reason to the client.
    ///
    /// Left a reason for logging purpose only.
    SilentRefuse(String),
}

impl BitAnd for ClientNameVerifyResult {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        use ClientNameVerifyResult::*;
        match (self, rhs) {
            (Accept, Accept) => Accept,
            (SilentRefuse(reason), ..) | (.., SilentRefuse(reason)) => SilentRefuse(reason),
            (Refuse(reason), ..) | (.., Refuse(reason)) => Refuse(reason),
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub enum ClientAuthorityVerifyResult {
    #[default]
    Accept,
    Refuse(String),
}

impl BitAnd for ClientAuthorityVerifyResult {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        use ClientAuthorityVerifyResult::*;
        match (self, rhs) {
            (Accept, Accept) => Accept,
            (Refuse(reason), ..) | (.., Refuse(reason)) => Refuse(reason),
        }
    }
}

pub trait AuthClient: Send + Sync {
    fn verify_client_name(
        &self,
        server_authority: &LocalAuthority,
        client_name: Option<&str>,
    ) -> ClientNameVerifyResult;

    fn verify_client_authority(
        &self,
        server_authority: &LocalAuthority,
        client_authority: &RemoteAuthority,
    ) -> ClientAuthorityVerifyResult;
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AcceptAllClientAuther;

impl AuthClient for AcceptAllClientAuther {
    fn verify_client_name(&self, _: &LocalAuthority, _: Option<&str>) -> ClientNameVerifyResult {
        ClientNameVerifyResult::Accept
    }

    fn verify_client_authority(&self, _: &LocalAuthority, _: &RemoteAuthority) -> ClientAuthorityVerifyResult {
        ClientAuthorityVerifyResult::Accept
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientNameAuther;

impl AuthClient for ClientNameAuther {
    fn verify_client_name(&self, _: &LocalAuthority, _: Option<&str>) -> ClientNameVerifyResult {
        ClientNameVerifyResult::Accept
    }

    fn verify_client_authority(
        &self,
        _: &LocalAuthority,
        client_authority: &RemoteAuthority,
    ) -> ClientAuthorityVerifyResult {
        use x509_parser::prelude::*;
        macro_rules! refuse {
            ($($tt:tt)*) => {
                return ClientAuthorityVerifyResult::Refuse(format!($($tt)*))
            };
        }

        let cert = match x509_parser::parse_x509_certificate(&client_authority.cert_chain()[0]) {
            Ok((_remain, cert)) => cert,
            Err(error) => refuse!("Invalid certificate: {error}"),
        };
        let san = match cert.subject_alternative_name() {
            Ok(Some(san)) => san,
            Ok(None) => refuse!("Missing SAN in certificate"),
            Err(error) => refuse!("Invalid SAN in certificate: {error}"),
        };

        if san.value.general_names.iter().any(|name| match name {
            GeneralName::DNSName(name) => *name == client_authority.name(),
            _ => false,
        }) {
            return ClientAuthorityVerifyResult::Accept;
        }

        refuse!("Client name not verified by client certificate")
    }
}

impl<A: AuthClient + ?Sized> AuthClient for &A {
    fn verify_client_name(
        &self,
        server_authority: &LocalAuthority,
        client_name: Option<&str>,
    ) -> ClientNameVerifyResult {
        A::verify_client_name(self, server_authority, client_name)
    }

    fn verify_client_authority(
        &self,
        server_authority: &LocalAuthority,
        client_authority: &RemoteAuthority,
    ) -> ClientAuthorityVerifyResult {
        A::verify_client_authority(self, server_authority, client_authority)
    }
}

impl<A: AuthClient + ?Sized> AuthClient for Box<A> {
    fn verify_client_name(
        &self,
        server_authority: &LocalAuthority,
        client_name: Option<&str>,
    ) -> ClientNameVerifyResult {
        self.deref().verify_client_name(server_authority, client_name)
    }

    fn verify_client_authority(
        &self,
        server_authority: &LocalAuthority,
        client_authority: &RemoteAuthority,
    ) -> ClientAuthorityVerifyResult {
        self.deref().verify_client_authority(server_authority, client_authority)
    }
}

impl<A: AuthClient + ?Sized> AuthClient for Arc<A> {
    fn verify_client_name(
        &self,
        server_authority: &LocalAuthority,
        client_name: Option<&str>,
    ) -> ClientNameVerifyResult {
        self.deref().verify_client_name(server_authority, client_name)
    }

    fn verify_client_authority(
        &self,
        server_authority: &LocalAuthority,
        client_authority: &RemoteAuthority,
    ) -> ClientAuthorityVerifyResult {
        self.deref().verify_client_authority(server_authority, client_authority)
    }
}

macro_rules! impl_auth_client_for_tuple {
    ($head:ident $($tail:ident)*) => {
        impl_auth_client_for_tuple!(@impl $head $($tail)*);
        impl_auth_client_for_tuple!($($tail)*);
    };
    (@impl $($t:ident)*) => {
        impl<$($t,)*> AuthClient for ($($t,)*)
        where
            $($t: AuthClient,)*
        {
            fn verify_client_name(
                &self,
                server_authority: &LocalAuthority,
                client_name: Option<&str>
            ) -> ClientNameVerifyResult {
                #[allow(non_snake_case)]
                let ($($t,)*) = self;
                $($t.verify_client_name(server_authority, client_name) &)* Default::default()
            }

            fn verify_client_authority(
                &self,
                server_authority: &LocalAuthority,
                client_authority: &RemoteAuthority
            ) -> ClientAuthorityVerifyResult {
                #[allow(non_snake_case)]
                let ($($t,)*) = self;
                $($t.verify_client_authority(server_authority, client_authority) &)* Default::default()
            }
        }
    };
    () => {}
}

impl_auth_client_for_tuple! {
    Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
}

/// A gate that controls server transmission permissions during parameter verification.
///
/// `SendLock` is used by the server to restrict data transmission until transport
/// parameter validation and server name verification are completed. It provides operations to:
/// - `request_permit()`: Request permission to send (public method)
/// - `grant_permit()`: Grant permission to send (internal method, pub(super) visibility)
///
/// This mechanism ensures that the server sends no data until it has properly validated
/// the client's transport parameters and verified the requested server name (SNI),
/// enhancing security by preventing premature data transmission before proper validation.
#[derive(Default, Debug, Clone)]
pub struct ArcSendLock(Arc<SetOnce<()>>);

impl ArcSendLock {
    /// Create a new `SendLock` in the restricted state.
    ///
    /// Transmission will be blocked until client parameters and server
    /// verification are completed, or when silent rejection is not enabled.
    ///
    /// Usually for server, which needs to do extra verify client name and certs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `SendLock` in the unrestricted state.
    ///
    /// Transmission is immediately permitted, used when silent rejection
    /// is disabled or verification has already been completed.
    ///
    /// Usually for client, which does not need to do extra verify server name and certs.
    pub fn unrestricted() -> Self {
        Self(Arc::new(SetOnce::new_with(Some(()))))
    }

    /// Request permission to send data.
    ///
    /// This method will block until client parameters and server verification
    /// are completed, or connection error occured.
    ///
    /// This method will not block when silent rejection is not enabled
    pub async fn request_permit(&self) {
        _ = self.0.wait().await
    }

    /// Check if transmission is currently permitted.
    pub fn is_permitted(&self) -> bool {
        self.0.get().is_some()
    }

    /// Grant permission for transmission.
    ///
    /// Called after client parameters and server verification are completed
    /// successfully. Unblocks all pending transmission requests.
    pub fn grant_permit(&self) {
        _ = self.0.set(());
    }
}
