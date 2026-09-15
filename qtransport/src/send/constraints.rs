/// Per-send budgets. Flow credit remains in qbase's shared flow controller;
/// STREAM sources acquire it there, rather than copying it into each Path.
#[derive(Debug)]
pub struct Constraints {
    pub capacity: usize,
    pub congestion: usize,
    pub anti_amplification: usize,
}
