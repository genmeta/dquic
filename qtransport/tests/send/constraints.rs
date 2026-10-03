#[derive(Debug)]
pub struct Constraints {
    pub flow_ctrl: std::cell::Cell<usize>,
    pub capacity: usize,
    pub congestion: usize,
    pub anti_amplification: usize,
}

pub use crate::path::AntiAmplifier;
