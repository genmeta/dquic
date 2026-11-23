//! Compile the scheduler here to keep its private-state tests outside src.

include!("../src/punch/scheduler.rs");

#[path = "punch/scheduler.rs"]
mod tests;
