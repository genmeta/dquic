//! White-box tests compile the library source in this test crate so internal
//! interfaces remain crate-private. Public API tests use the library normally.

extern crate self as qconnection;

#[path = "../src/lib.rs"]
mod implementation;

pub(crate) use implementation::lifecycle;
pub use implementation::*;

mod common;

mod unit;
