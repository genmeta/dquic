use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use qbase::{
    cid::ConnectionId,
    frame::{NewConnectionIdFrame, io::ReceiveFrame},
    role::Role,
    time::heartbeat::ArcHeartbeat,
};
use qtransport::path::Path;

use crate::{
    Paths,
    common::path_fixtures::{paths, pathway},
};

fn path(paths: &Paths, port: u16) -> Arc<Path> {
    crate::common::registered_path(
        paths,
        Path::new(
            pathway(port),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.new_dcid(),
        ),
    )
}

fn negotiated(role: Role) -> (Arc<Paths>, super::MatureFixture) {
    super::send::mature_phase(role, Duration::ZERO)
}

fn ready(paths: &Paths, path: &Path) -> ConnectionId {
    let Poll::Ready(Some(cid)) = super::borrow(paths, path) else {
        panic!("expected a ready CID")
    };
    cid
}

#[tokio::test(start_paused = true)]
async fn first_flight_paths_keep_snapshots_and_new_paths_use_the_peer_scid() {
    let paths = paths(Role::Client);
    let a = path(&paths, 4001);
    let b = path(&paths, 4002);
    let original = ready(&paths, &a);
    assert_eq!(original, ready(&paths, &b));
    let peer = ConnectionId::from_slice(b"peer0000");
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    let phase = paths.phase();
    drop(phase.poll_phase(&mut Context::from_waker(&waker)));
    paths.update_initial_dcid(peer);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    paths.update_initial_dcid(ConnectionId::from_slice(b"ignored0"));
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert_ne!(original, peer);
    assert_eq!(ready(&paths, &a), peer);
    assert_eq!(ready(&paths, &b), peer);
    assert_eq!(ready(&paths, &path(&paths, 4003)), peer);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn selected_path_keeps_cell_zero_in_either_install_order_and_extra_cids_do_not_open_handshaking_paths()
 {
    for phase_first in [false, true] {
        let (paths, mature) = negotiated(Role::Server);
        let initial = mature.peer_cid();
        let next = ConnectionId::from_slice(b"peer0001");
        paths.update_initial_dcid(initial);
        let other = path(&paths, 4001);
        let selected = path(&paths, 4002);
        let remote = &mature.cid_registry.remote;
        remote
            .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
            .unwrap();
        if phase_first {
            super::enter_mature(&paths, &mature);
        }
        assert!(paths.select_path(&selected));
        if !phase_first {
            super::enter_mature(&paths, &mature);
        }
        assert_eq!(ready(&paths, &selected), initial);
        // Only the selected path is bound before confirmation, even when CID 1 is available.
        assert!(selected.dcid.is_allocated());
        assert!(!other.dcid.is_allocated());
        assert_eq!(
            other
                .dcid
                .poll_borrow(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(initial))
        );
        other.dcid.refresh();
        assert!(super::borrow(&paths, &other).is_pending());
        super::confirm_handshake(&paths);
        super::confirm_handshake(&paths);
        assert_eq!(ready(&paths, &other), next);
        assert_eq!(ready(&paths, &selected), initial);
        let later = path(&paths, 4003);
        assert!(super::borrow(&paths, &later).is_pending());
        let last = ConnectionId::from_slice(b"peer0002");
        remote
            .recv_frame(NewConnectionIdFrame::new(last, 2u32.into(), 0u32.into()))
            .unwrap();
        assert_eq!(ready(&paths, &later), last);
        paths.retire_all();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_selection_registry_installation_and_path_creation_preserve_cell_zero() {
    let (paths, mature) = negotiated(Role::Server);
    let selected = paths.add_path(pathway(4001));
    let initial = mature.peer_cid();
    let next = ConnectionId::from_slice(b"peer0001");
    let remote = &mature.cid_registry.remote;
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let selection = tokio::spawn({
        let paths = paths.clone();
        let selected = selected.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            assert!(paths.select_path(&selected));
        }
    });
    let installation = tokio::spawn({
        let paths = paths.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            super::enter_mature(&paths, &mature);
        }
    });
    let creation = tokio::spawn({
        let paths = paths.clone();
        async move {
            barrier.wait().await;
            paths.add_path(pathway(4002))
        }
    });
    selection.await.unwrap();
    installation.await.unwrap();
    let other = creation.await.unwrap();
    assert_eq!(ready(&paths, &selected), initial);
    assert!(super::borrow(&paths, &other).is_pending());
    super::confirm_handshake(&paths);
    assert_eq!(ready(&paths, &selected), initial);
    assert_eq!(ready(&paths, &other), next);
    paths.retire_all();
    crate::common::wait_for_sender_exit(&selected).await;
    crate::common::wait_for_sender_exit(&other).await;
}

#[tokio::test(start_paused = true)]
async fn replacement_at_the_selected_address_does_not_inherit_selection() {
    let paths = paths(Role::Server);
    let old = path(&paths, 4001);
    assert!(paths.select_path(&old));
    paths.del_path(&old.pathway);
    let replacement = path(&paths, 4001);
    assert!(!paths.is_selected(&replacement));
    assert!(!paths.select_path(&replacement));
    assert!(super::borrow(&paths, &replacement).is_pending());
    assert_eq!(super::borrow(&paths, &old), Poll::Ready(None));
    old.close();
    assert!(!paths.is_initial());
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn removal_before_registry_installation_still_reserves_zero_for_the_old_handshake_path() {
    let (paths, mature) = negotiated(Role::Server);
    let old = path(&paths, 4001);
    let other = path(&paths, 4002);
    paths.select_path(&old);
    paths.del_path(&old.pathway);
    let remote = &mature.cid_registry.remote;
    super::enter_mature(&paths, &mature);
    let next = ConnectionId::from_slice(b"peer0001");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    super::confirm_handshake(&paths);
    assert_eq!(ready(&paths, &other), next);
    paths.del_path(&other.pathway);
    assert!(paths.entries.lock().unwrap().is_empty());
    assert!(paths.is_confirmed());
    let replacement = path(&paths, 4001);
    assert!(super::borrow(&paths, &replacement).is_pending());
    assert!(!paths.is_selected(&replacement));
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn the_handshake_cell_rotates_before_confirmation_after_refresh() {
    let (paths, mature) = negotiated(Role::Server);
    let initial = mature.peer_cid();
    let selected = path(&paths, 4001);
    paths.select_path(&selected);
    let remote = &mature.cid_registry.remote;
    assert!(matches!(paths.phase().get(), crate::ConnPhase::Initial(_)));
    let pinned = selected
        .dcid
        .poll_borrow(&mut Context::from_waker(Waker::noop()));
    let next = ConnectionId::from_slice(b"peer0001");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 1u32.into()))
        .unwrap();
    assert_eq!(pinned, Poll::Ready(Some(initial)));
    selected.dcid.refresh();
    assert_eq!(ready(&paths, &selected), next);
    super::enter_mature(&paths, &mature);
    assert_eq!(ready(&paths, &selected), next);
    selected.close();
    assert_eq!(super::borrow(&paths, &selected), Poll::Ready(None));
    paths.retire_all();
}

#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test(start_paused = true)]
async fn confirmation_new_cid_and_closing_a_pending_path_wake_only_its_sender() {
    let (paths, mature) = negotiated(Role::Server);
    let selected = path(&paths, 4001);
    let other = path(&paths, 4002);
    paths.select_path(&selected);
    let remote = &mature.cid_registry.remote;
    super::enter_mature(&paths, &mature);
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    other.send_waker.register(cx.waker());
    assert!(super::borrow(&paths, &other).is_pending());
    super::confirm_handshake(&paths);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    super::confirm_handshake(&paths);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(other.dcid.poll_borrow(&mut cx).is_pending());
    remote
        .recv_frame(NewConnectionIdFrame::new(
            ConnectionId::from_slice(b"peer0001"),
            1u32.into(),
            0u32.into(),
        ))
        .unwrap();
    assert_eq!(counter.0.load(Ordering::Relaxed), 2);
    let last = path(&paths, 4003);
    last.send_waker.register(cx.waker());
    assert!(last.dcid.poll_borrow(&mut cx).is_pending());
    last.close();
    assert!(counter.0.load(Ordering::Relaxed) >= 3);
    assert_eq!(
        last.dcid
            .poll_borrow(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(None)
    );
    assert_eq!(ready(&paths, &selected), mature.peer_cid());
    paths.retire_all();
}

fn take_retired(mature: &super::MatureFixture) -> Vec<u64> {
    crate::common::phase::take_reliable(mature)
        .into_iter()
        .filter_map(|frame| {
            if let qbase::frame::Frame::RetireConnectionId(frame) = frame {
                Some(frame.sequence())
            } else {
                None
            }
        })
        .collect()
}

#[tokio::test]
async fn bursts_refresh_empty_polls_explicit_cancellation_and_drop_without_retiring_early() {
    use bytes::BytesMut;
    use tokio::io::AsyncWriteExt;

    use crate::send::{Burst, MAX_BURST_PACKETS};

    for finish in ["pending", "cancel", "drop"] {
        let (paths, mature) = super::send::mature_phase(Role::Server, Duration::ZERO);
        let selected = path(&paths, 4001);
        paths.select_path(&selected);
        super::enter_mature(&paths, &mature);
        selected.validation.enter_validated().unwrap();
        take_retired(&mature);
        if finish != "pending" {
            mature
                .spaces
                .data
                .crypto
                .writer()
                .write_all(b"batch snapshot")
                .await
                .unwrap();
        }
        let mut datagrams = [BytesMut::new()];
        let mut frames = Vec::new();
        let mut packets = [[None; 3]; MAX_BURST_PACKETS];
        let mut burst = Burst::new(&paths, &selected, &mut datagrams, &mut frames, &mut packets);
        let result = burst.poll_collect(&mut Context::from_waker(Waker::noop()));
        assert_eq!(result.is_pending(), finish == "pending");
        if finish == "pending" {
            assert!(burst.dcid.is_none());
        } else {
            assert!(matches!(result, Poll::Ready(Ok(n)) if n > 0));
            assert_eq!(burst.dcid, Some(mature.peer_cid()));
        }
        let next = ConnectionId::from_slice(b"client01");
        mature
            .cid_registry
            .remote
            .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 1u32.into()))
            .unwrap();
        if finish == "pending" {
            assert_eq!(take_retired(&mature), [0]);
        } else {
            assert!(
                take_retired(&mature).is_empty(),
                "a sealed batch still uses CID 0"
            );
        }
        if finish == "cancel" {
            burst.cancel();
            burst.cancel();
            assert_eq!(take_retired(&mature), [0]);
        }
        drop(burst);
        if finish == "drop" {
            assert_eq!(take_retired(&mature), [0]);
        } else {
            assert!(take_retired(&mature).is_empty());
        }
        assert_eq!(ready(&paths, &selected), next);
        paths.retire_all();
    }
}

#[tokio::test(start_paused = true)]
async fn closing_a_sender_waiting_for_a_cid_leaves_the_connection_and_other_sender_alive() {
    let (paths, mature) = super::send::mature_phase(Role::Client, Duration::ZERO);
    let selected = path(&paths, 4001);
    selected.validation.enter_validated().unwrap();
    paths.select_path(&selected);
    super::enter_mature(&paths, &mature);
    super::confirm_handshake(&paths);
    take_retired(&mature);
    let removed = paths.add_path(pathway(4002));
    let live = paths.add_path(pathway(4003));
    let close = crate::common::observe_close(&paths.terminator);
    tokio::task::yield_now().await;
    // Both extra paths await fresh CIDs; preserve the sending tasks' own wakers.
    paths.del_path(&removed.pathway);
    crate::common::wait_for_sender_exit(&removed).await;
    assert!(close.notified().is_none());
    assert!(paths.entries.lock().unwrap().contains_key(&live.pathway));
    let next = ConnectionId::from_slice(b"client01");
    mature
        .cid_registry
        .remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    assert_eq!(ready(&paths, &live), next);
    assert_eq!(super::borrow(&paths, &removed), Poll::Ready(None));
    paths.retire_all();
    crate::common::wait_for_sender_exit(&live).await;
}

#[tokio::test(start_paused = true)]
async fn closing_a_just_upgraded_sender_releases_its_handshake_cid_without_dropping_the_path() {
    let (paths, mature) = super::send::mature_phase(Role::Client, Duration::ZERO);
    let _other = path(&paths, 4001);
    let selected = paths.add_path(pathway(4002));
    paths.select_path(&selected);
    // Close before the sender polls its first batch after upgrade.
    paths.del_path(&selected.pathway);
    crate::common::wait_for_sender_exit(&selected).await;
    assert_eq!(take_retired(&mature), [0]);
    assert_eq!(super::borrow(&paths, &selected), Poll::Ready(None));
    paths.retire_all();
}
