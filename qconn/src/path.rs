use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    },
    time::Duration,
};

use qbase::{
    Epoch,
    frame::{AckFrame, PathChallengeFrame, PathResponseFrame},
    net::{route::Pathway, tx::ArcSendWaker},
    role::Role,
    time::PathIdleTimer,
};
use qcongestion::{Algorithm, ArcCC, PathStatus, Transport as _};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use crate::transport::Transport;

pub(crate) enum Event {
    Ack(Epoch, AckFrame),
    Response(PathResponseFrame),
    Retire(Epoch, oneshot::Sender<()>),
}

pub(crate) struct Path {
    pub(crate) pathway: Pathway,
    pub(crate) cc: ArcCC,
    pub(crate) wake: ArcSendWaker,
    pub(crate) idle: PathIdleTimer,
    pub(crate) received: AtomicU64,
    pub(crate) sent: AtomicU64,
    pub(crate) validated: AtomicBool,
    pub(crate) verified: AtomicBool,
    pub(crate) failed: AtomicBool,
    pub(crate) challenge: Mutex<Option<(PathChallengeFrame, tokio::time::Instant, u8)>>,
    pub(crate) status: PathStatus,
    pub(crate) events: mpsc::Sender<Event>,
    pub(crate) task: Mutex<Option<JoinHandle<()>>>,
    pub(crate) responses: Mutex<std::collections::VecDeque<qbase::frame::PathResponseFrame>>,
}

impl Path {
    pub(crate) fn new(pathway: Pathway, transport: &Arc<Transport>) -> Arc<Self> {
        let wake = ArcSendWaker::new();
        let status = PathStatus::new(
            transport.control.handshake.clone(),
            Arc::new(AtomicU16::new(1200)),
        );
        let cc = ArcCC::new(
            Algorithm::NewReno,
            Duration::from_millis(25),
            transport.spaces.feedback(),
            status.clone(),
            wake.clone(),
        );
        let (events, receiver) = mpsc::channel(64);
        let path = Arc::new(Self {
            pathway,
            cc,
            wake,
            idle: transport.idle.timer(),
            received: 0.into(),
            sent: 0.into(),
            validated: (transport.control.role == Role::Client).into(),
            verified: false.into(),
            failed: false.into(),
            challenge: Mutex::new(None),
            status,
            events,
            task: Mutex::new(None),
            responses: Mutex::new(std::collections::VecDeque::new()),
        });
        if path.validated.load(Ordering::Acquire) {
            path.cc.grant_anti_amplification();
        }
        transport.wakers.insert(pathway, &path.wake);
        let task = tokio::spawn(crate::send::send_loop(
            transport.clone(),
            path.clone(),
            receiver,
        ));
        *path.task.lock().unwrap() = Some(task);
        path
    }

    pub(crate) fn validate(&self) {
        self.validated.store(true, Ordering::Release);
        self.verified.store(true, Ordering::Release);
        self.cc.grant_anti_amplification();
    }

    pub(crate) fn start_validation(&self) {
        if self.verified.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return;
        }
        self.challenge
            .lock()
            .unwrap()
            .get_or_insert_with(|| (PathChallengeFrame::random(), tokio::time::Instant::now(), 0));
        self.wake.wake_by(qbase::net::tx::Signals::PATH_VALIDATE);
    }

    pub(crate) fn on_response(&self, response: PathResponseFrame) {
        let mut challenge = self.challenge.lock().unwrap();
        if challenge.as_ref().is_some_and(|(frame, _, sent)| {
            *sent != 0 && PathResponseFrame::from(*frame) == response
        }) {
            challenge.take();
            self.validate();
        }
    }

    pub(crate) fn amplification_credit(&self) -> usize {
        if self.validated.load(Ordering::Acquire) {
            return usize::MAX;
        }
        self.received
            .load(Ordering::Acquire)
            .saturating_mul(3)
            .saturating_sub(self.sent.load(Ordering::Acquire))
            .min(usize::MAX as u64) as usize
    }
}

pub(crate) struct Paths {
    entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
    pub(crate) selected: OnceLock<Pathway>,
}

impl Paths {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            selected: OnceLock::new(),
        }
    }
    pub(crate) fn snapshot(&self) -> Vec<Arc<Path>> {
        self.entries.lock().unwrap().values().cloned().collect()
    }
    pub(crate) fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.entries.lock().unwrap().get(pathway).cloned()
    }

    pub(crate) fn preferred(&self) -> Option<Pathway> {
        let entries = self.entries.lock().unwrap();
        self.selected
            .get()
            .and_then(|selected| entries.get(selected))
            .filter(|path| !path.failed.load(Ordering::Acquire))
            .map(|path| path.pathway)
            .or_else(|| {
                entries
                    .values()
                    .find(|path| {
                        path.verified.load(Ordering::Acquire)
                            && !path.failed.load(Ordering::Acquire)
                    })
                    .map(|path| path.pathway)
            })
    }

    pub(crate) fn add(&self, pathway: Pathway, transport: &Arc<Transport>) -> Option<Arc<Path>> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(path) = entries.get(&pathway) {
            return Some(path.clone());
        }
        if entries.len() == 4 {
            return None;
        }
        let path = Path::new(pathway, transport);
        entries.insert(pathway, path.clone());
        Some(path)
    }
}
