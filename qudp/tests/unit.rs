//! Compile the socket implementation here to keep private tests outside src.

include!("../src/lib.rs");

#[cfg(unix)]
mod common;

#[path = "unit/socket.rs"]
mod tests;

#[cfg(unix)]
#[path = "unit/unix.rs"]
mod unix_tests;
