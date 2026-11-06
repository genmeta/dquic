use std::fmt;

use qbase::{
    frame::{AddAddressFrame, PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, io::ReceiveFrame},
    net::route::Link,
};
use tokio::sync::SetOnce;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PunchId {
    pub local_seq: u32,
    pub remote_seq: u32,
}

impl PunchId {
    pub fn new(local_seq: u32, remote_seq: u32) -> Self {
        Self { local_seq, remote_seq }
    }

    pub fn flip(self) -> Self {
        Self { local_seq: self.remote_seq, remote_seq: self.local_seq }
    }
}

impl fmt::Display for PunchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.local_seq, self.remote_seq)
    }
}

pub(crate) trait AsPunchId {
    fn punch_id(&self) -> PunchId;
}

impl AsPunchId for PunchHelloFrame {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.local_seq(), self.remote_seq())
    }
}

impl AsPunchId for PunchDoneFrame {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.local_seq(), self.remote_seq())
    }
}

impl AsPunchId for PunchMeNowFrame {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.local_seq(), self.remote_seq())
    }
}

impl AsPunchId for (&AddAddressFrame, &AddAddressFrame) {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.0.seq_num(), self.1.seq_num())
    }
}

pub(crate) struct Transaction {
    punch_me_now_frame: SetOnce<PunchMeNowFrame>,
    punch_hello_frame: SetOnce<(Link, PunchHelloFrame)>,
    punch_done_frame: SetOnce<(Link, PunchDoneFrame)>,
}

impl Transaction {
    pub fn new() -> Self {
        Self { punch_me_now_frame: SetOnce::new(), punch_hello_frame: SetOnce::new(), punch_done_frame: SetOnce::new() }
    }

    pub async fn wait_punch_done(&self) -> (Link, PunchDoneFrame) {
        *self.punch_done_frame.wait().await
    }

    pub fn try_punch_done(&self) -> Option<(Link, PunchDoneFrame)> {
        self.punch_done_frame.get().copied()
    }

    pub async fn wait_punch_hello(&self) -> (Link, PunchHelloFrame) {
        *self.punch_hello_frame.wait().await
    }

    pub async fn wait_punch_me_now(&self) -> PunchMeNowFrame {
        *self.punch_me_now_frame.wait().await
    }

    pub fn store_punch_me_now(&self, frame: PunchMeNowFrame) {
        _ = self.punch_me_now_frame.set(frame);
    }
}

impl ReceiveFrame<(Link, PunchHelloFrame)> for Transaction {
    type Output = ();

    fn recv_frame(&self, (link, frame): (Link, PunchHelloFrame)) -> Result<Self::Output, qbase::error::Error> {
        _ = self.punch_hello_frame.set((link, frame));
        Ok(())
    }
}

impl ReceiveFrame<(Link, PunchDoneFrame)> for Transaction {
    type Output = ();

    fn recv_frame(&self, (link, frame): (Link, PunchDoneFrame)) -> Result<Self::Output, qbase::error::Error> {
        _ = self.punch_done_frame.set((link, frame));
        Ok(())
    }
}

impl ReceiveFrame<(Link, PunchMeNowFrame)> for Transaction {
    type Output = ();

    fn recv_frame(&self, (_link, frame): (Link, PunchMeNowFrame)) -> Result<Self::Output, qbase::error::Error> {
        _ = self.punch_me_now_frame.set(frame);
        Ok(())
    }
}
