//! Compile the STUN implementation here to test private state without source-side test hooks.

pub use qprotocol::socket;

include!("../src/protocol/stun.rs");

#[path = "../../qudp/tests/common/mod.rs"]
mod common;

#[path = "unit/stun/mod.rs"]
mod tests;
