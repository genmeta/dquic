use std::{sync::atomic::Ordering, time::Duration};

use qbase::{frame::PathChallengeFrame, net::tx::Signals};
use qcongestion::Transport;
use thiserror::Error;
use tokio::time::Instant;

#[derive(Debug, Error, Clone, Copy)]
pub enum ValidateFailure {
    #[error(
        "Path validation abort due to path inactivity by other reasons(usually connection closed)"
    )]
    PathInactive,
    #[error("Path validation failed after {0} ms", elapsed.as_millis())]
    Timeout { elapsed: Duration },
}

impl super::Path {
    pub fn validated(&self) {
        self.validated.store(true, Ordering::Release);
        self.tx_waker.wake_by(Signals::PATH_VALIDATE);
    }

    pub async fn validate(&self) -> Result<(), ValidateFailure> {
        let challenge = PathChallengeFrame::random();
        let start = Instant::now();
        for _ in 0..30 {
            let timeout_duration = self.cc().get_pto(qbase::Epoch::Data);
            self.challenge_sndbuf.write(challenge);
            match tokio::time::timeout(timeout_duration, self.response_rcvbuf.receive()).await {
                Ok(Some(response)) if *response == *challenge => {
                    self.validated();
                    self.anti_amplifier.grant();
                    tracing::debug!(target: "dquic", pathway=%self.pathway, "path validated successfully");
                    return Ok(());
                }
                // 外部发生变化，导致路径验证任务作废
                Ok(None) => return Err(ValidateFailure::PathInactive),
                // 超时或者收到不对的response，按"停-等协议"，继续再发一次Challenge，最多3次
                _ => continue,
            }
        }
        Err(ValidateFailure::Timeout {
            elapsed: start.elapsed(),
        })
    }
}
