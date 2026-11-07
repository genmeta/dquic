//! White-box path and packet tests compile the transport source in this crate.
//! Mixed receive tests compile the existing connection receiver against the same types.

extern crate self as qtransport;

#[path = "../src/lib.rs"]
mod implementation;

pub use implementation::*;
use qbase::net::route::Scopes;

#[path = "../../qconnection/src/recv.rs"]
mod receiving;

mod common;
mod unit;
