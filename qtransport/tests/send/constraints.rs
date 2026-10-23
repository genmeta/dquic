#[derive(Debug)]
pub struct Constraints {
    pub flow_ctrl: std::cell::Cell<usize>,
    pub capacity: usize,
    pub congestion: usize,
    pub anti_amplification: usize,
}

use std::task::{Context, Poll, Waker};

use qbase::validate::ArcValidation;

pub fn credit(validation: &ArcValidation) -> usize {
    match validation.poll_credit(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Ok(credit)) => credit.unwrap_or(usize::MAX),
        _ => 0,
    }
}
