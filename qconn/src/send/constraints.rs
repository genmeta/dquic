/// Per-send budgets. Flow credit remains in qbase's shared flow controller;
/// STREAM sources acquire it there, rather than copying it into each Path.
#[derive(Debug)]
pub(crate) struct Constraints {
    pub(crate) capacity: usize,
    pub(crate) congestion: usize,
    pub(crate) anti_amplification: usize,
}
