use qcongestion::Transport;
use tokio::time::Duration;

use crate::{path::PathDeactivated, tls::ArcTlsHandshake};

impl super::Path {
    pub async fn drive(&self, tls_handshake: ArcTlsHandshake) -> Result<(), PathDeactivated> {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let now = tokio::time::Instant::now();
            let pto_base = self.cc.pto_base(qbase::Epoch::Data);
            if self.idle_timer.timed_out(now, pto_base)
                || self.idle_timer.path_timed_out(now, pto_base)
            {
                return Err(qbase::time::TimeOut.into());
            }
            self.wake_keep_alive_if_due(
                tls_handshake
                    .is_finished()
                    .is_ok_and(|is_finished| is_finished),
            );
            self.cc.do_tick()?;
        }
    }
}
