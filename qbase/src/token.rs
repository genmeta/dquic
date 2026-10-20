use std::{ops::Deref, sync::Arc};

use bytes::BufMut;
use derive_more::Deref;
use nom::{IResult, bytes::complete::take};
use rand::RngExt;

use crate::{
    error::{ErrorKind, QuicError},
    frame::{GetFrameType, NewTokenFrame, io::ReceiveFrame},
};

pub const RESET_TOKEN_SIZE: usize = 16;

#[derive(Deref, Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.try_into().unwrap())
    }

    pub fn random_gen() -> Self {
        let mut bytes = [0; RESET_TOKEN_SIZE];
        rand::rng().fill(&mut bytes);
        Self(bytes)
    }

    pub fn encoding_size(&self) -> usize {
        RESET_TOKEN_SIZE
    }
}

pub fn be_reset_token(input: &[u8]) -> IResult<&[u8], ResetToken> {
    let (input, bytes) = take(RESET_TOKEN_SIZE)(input)?;
    Ok((input, ResetToken::new(bytes)))
}

pub trait WriteResetToken {
    fn put_reset_token(&mut self, token: &ResetToken);
}

impl<T: BufMut> WriteResetToken for T {
    fn put_reset_token(&mut self, token: &ResetToken) {
        self.put_slice(token.as_slice());
    }
}

pub trait TokenSink: Send + Sync {
    fn sink(&self, server_name: &str, token: Vec<u8>);

    fn fetch_token(&self, server_name: &str) -> Vec<u8>;
}

pub trait TokenProvider: Send + Sync {
    fn gen_new_token(&self, server_name: &str) -> Vec<u8>;

    fn gen_retry_token(&self, server_name: &str) -> Vec<u8>;

    // A token sent in a NEW_TOKEN frame or a Retry packet MUST be constructed in
    // a way that allows the server to identify how it was provided to a client
    fn verify_token(&self, server_name: &str, token: &[u8]) -> bool;
}

pub enum TokenRegistry {
    Client((String, Arc<dyn TokenSink>)),
    Server(Arc<dyn TokenProvider>),
}

#[derive(Clone)]
pub struct ArcTokenRegistry(Arc<TokenRegistry>);

impl ArcTokenRegistry {
    pub fn with_sink(server_name: String, sink: Arc<dyn TokenSink>) -> Self {
        Self(Arc::new(TokenRegistry::Client((server_name, sink))))
    }

    pub fn with_provider(provider: Arc<dyn TokenProvider>) -> Self {
        Self(Arc::new(TokenRegistry::Server(provider)))
    }
}

impl Deref for ArcTokenRegistry {
    type Target = TokenRegistry;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl ReceiveFrame<NewTokenFrame> for ArcTokenRegistry {
    type Output = ();

    fn recv_frame(&self, frame: NewTokenFrame) -> Result<Self::Output, crate::error::Error> {
        match self.deref() {
            TokenRegistry::Client((server_name, client)) => {
                client.sink(server_name, frame.token().to_vec());
                Ok(())
            }
            TokenRegistry::Server(_) => Err(QuicError::new(
                ErrorKind::ProtocolViolation,
                frame.frame_type().into(),
                "Server received NewTokenFrame",
            )
            .into()),
        }
    }
}

pub mod handy {
    pub struct NoopTokenRegistry;

    impl super::TokenSink for NoopTokenRegistry {
        fn sink(&self, _: &str, _: Vec<u8>) {}

        fn fetch_token(&self, _: &str) -> Vec<u8> {
            Vec::with_capacity(0)
        }
    }

    impl super::TokenProvider for NoopTokenRegistry {
        fn gen_new_token(&self, _: &str) -> Vec<u8> {
            Vec::new()
        }

        fn gen_retry_token(&self, _: &str) -> Vec<u8> {
            Vec::new()
        }

        fn verify_token(&self, _: &str, _: &[u8]) -> bool {
            false
        }
    }
}
