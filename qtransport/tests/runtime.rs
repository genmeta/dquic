//! White-box path and packet tests compile the transport source in this crate.

extern crate self as qtransport;

#[path = "../src/lib.rs"]
mod implementation;

pub use implementation::*;
use qbase::net::route::Scopes;
use qtransport::recv as receiving;

mod common;
mod unit;
