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
            paths.cid_registry.remote.apply_dcid(),
            pathway(port),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    )
}

fn negotiated(role: Role) -> (Arc<Paths>, super::DataFixture) {
    super::send::data_spaces(role, Duration::ZERO)
}

fn ready(path: &Path) -> ConnectionId {
    let Poll::Ready(Some(cid)) = super::borrow(path) else {
        panic!("expected a ready CID")
    };
    cid
}

#[tokio::test(start_paused = true)]
async fn first_initial_wakes_only_the_selected_paths_cid_waiter() {
    let paths = paths(Role::Client);
    let selected = path(&paths, 4001);
    let other = path(&paths, 4002);
    assert!(paths.progress.on_path_selected(&paths, &selected));
    let selected_counter = Arc::new(Counter::default());
    let other_counter = Arc::new(Counter::default());
    let selected_waker = Waker::from(selected_counter.clone());
    selected.send_waker.register(&selected_waker);
    other.send_waker.register(&Waker::from(other_counter.clone()));
    assert!(selected.dcid.poll_borrow(&mut Context::from_waker(&selected_waker)).is_pending());
    let peer = ConnectionId::from_slice(b"peer0000");
    assert!(!paths.progress.facts().has_received_initial());
    assert!(paths.progress.on_initial_received(peer));
    assert!(paths.progress.facts().has_received_initial());
    assert_eq!(selected_counter.0.load(Ordering::Relaxed), 1);
    assert_eq!(other_counter.0.load(Ordering::Relaxed), 0);
    assert_eq!(ready(&selected), peer);
    assert!(!paths.progress.on_initial_received(ConnectionId::from_slice(b"ignored0")));
    assert_eq!(selected_counter.0.load(Ordering::Relaxed), 1);
    assert_eq!(other_counter.0.load(Ordering::Relaxed), 0);
    assert_eq!(ready(&selected), peer);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn first_flight_paths_keep_snapshots_and_new_paths_use_the_peer_scid() {
    for handshaking in [false, true] {
        let paths = paths(Role::Client);
        let a = path(&paths, 4001);
        let b = path(&paths, 4002);
        let original = ready(&a);
        assert_eq!(original, ready(&b));
        let peer = ConnectionId::from_slice(b"peer0000");
        let counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        if handshaking {
            paths.progress.facts().install_handshake_key();
        }
        a.send_waker.register(&waker);
        assert!(paths.progress.on_initial_received(peer));
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        assert!(!paths.progress.on_initial_received(ConnectionId::from_slice(b"ignored0")));
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        assert_ne!(original, peer);
        assert_eq!(ready(&a), peer);
        assert_eq!(ready(&b), peer);
        assert_eq!(ready(&path(&paths, 4003)), peer);
        paths.retire_all();
    }
}

#[tokio::test(start_paused = true)]
async fn selected_path_keeps_cell_zero_in_either_install_order_and_extra_cids_do_not_open_handshaking_paths() {
    for data_first in [false, true] {
        let (paths, mature) = negotiated(Role::Server);
        let initial = mature.peer_cid();
        let next = ConnectionId::from_slice(b"peer0001");
        paths.progress.on_initial_received(initial);
        let other = path(&paths, 4001);
        let selected = path(&paths, 4002);
        let remote = &paths.cid_registry.remote;
        remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into())).unwrap();
        if data_first {
            super::install_data(&paths, &mature);
        }
        assert!(paths.progress.on_path_selected(&paths, &selected));
        if !data_first {
            super::install_data(&paths, &mature);
        }
        assert_eq!(ready(&selected), initial);
        // Only the selected path is bound before confirmation, even when CID 1 is available.
        assert!(selected.dcid.is_allocated());
        assert!(!other.dcid.is_allocated());
        assert_eq!(other.dcid.poll_borrow(&mut Context::from_waker(Waker::noop())), Poll::Ready(Some(initial)));
        other.dcid.refresh();
        assert!(super::borrow(&other).is_pending());
        super::confirm_handshake(&paths);
        super::confirm_handshake(&paths);
        assert_eq!(ready(&other), next);
        assert_eq!(ready(&selected), initial);
        let later = path(&paths, 4003);
        assert!(super::borrow(&later).is_pending());
        let last = ConnectionId::from_slice(b"peer0002");
        remote.recv_frame(NewConnectionIdFrame::new(last, 2u32.into(), 0u32.into())).unwrap();
        assert_eq!(ready(&later), last);
        paths.retire_all();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_selection_data_installation_and_path_creation_preserve_cell_zero() {
    let (paths, mature) = negotiated(Role::Server);
    let selected = paths.add_path(pathway(4001));
    let initial = mature.peer_cid();
    let next = ConnectionId::from_slice(b"peer0001");
    let remote = &paths.cid_registry.remote;
    remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into())).unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let selection = tokio::spawn({
        let paths = paths.clone();
        let selected = selected.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            assert!(paths.progress.on_path_selected(&paths, &selected));
        }
    });
    let installation = tokio::spawn({
        let paths = paths.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            super::install_data(&paths, &mature);
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
    assert_eq!(ready(&selected), initial);
    assert!(super::borrow(&other).is_pending());
    super::confirm_handshake(&paths);
    assert_eq!(ready(&selected), initial);
    assert_eq!(ready(&other), next);
    paths.retire_all();
    crate::common::wait_for_sender_exit(&selected).await;
    crate::common::wait_for_sender_exit(&other).await;
}

#[tokio::test(start_paused = true)]
async fn replacement_at_the_selected_address_does_not_inherit_selection() {
    let paths = paths(Role::Server);
    let old = path(&paths, 4001);
    assert!(paths.progress.on_path_selected(&paths, &old));
    paths.del_path(&old.pathway);
    let replacement = path(&paths, 4001);
    assert!(paths.progress.facts().is_handshake_done() || !replacement.dcid.is_allocated());
    assert!(!paths.progress.on_path_selected(&paths, &replacement));
    assert!(super::borrow(&replacement).is_pending());
    assert_eq!(super::borrow(&old), Poll::Ready(None));
    old.close();
    assert!(paths.progress.facts().has_selected_path());
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn removal_before_data_installation_still_reserves_zero_for_the_old_handshake_path() {
    let (paths, mature) = negotiated(Role::Server);
    let old = path(&paths, 4001);
    let other = path(&paths, 4002);
    paths.progress.on_path_selected(&paths, &old);
    paths.del_path(&old.pathway);
    let remote = &paths.cid_registry.remote;
    super::install_data(&paths, &mature);
    let next = ConnectionId::from_slice(b"peer0001");
    remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into())).unwrap();
    super::confirm_handshake(&paths);
    assert_eq!(ready(&other), next);
    paths.del_path(&other.pathway);
    assert!(paths.entries.lock().unwrap().is_empty());
    assert!(paths.progress.facts().is_handshake_done());
    let replacement = path(&paths, 4001);
    assert!(super::borrow(&replacement).is_pending());
    assert!(paths.progress.facts().is_handshake_done() || !replacement.dcid.is_allocated());
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn the_handshake_cell_rotates_before_confirmation_after_refresh() {
    let (paths, mature) = negotiated(Role::Server);
    let initial = mature.peer_cid();
    let selected = path(&paths, 4001);
    paths.progress.on_path_selected(&paths, &selected);
    let remote = &paths.cid_registry.remote;
    assert!(!paths.progress.facts().has_handshake_key());
    let pinned = selected.dcid.poll_borrow(&mut Context::from_waker(Waker::noop()));
    let next = ConnectionId::from_slice(b"peer0001");
    remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 1u32.into())).unwrap();
    assert_eq!(pinned, Poll::Ready(Some(initial)));
    selected.dcid.refresh();
    assert_eq!(ready(&selected), next);
    super::install_data(&paths, &mature);
    assert_eq!(ready(&selected), next);
    selected.close();
    assert_eq!(super::borrow(&selected), Poll::Ready(None));
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
    paths.progress.on_path_selected(&paths, &selected);
    let remote = &paths.cid_registry.remote;
    super::install_data(&paths, &mature);
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    other.send_waker.register(cx.waker());
    assert!(super::borrow(&other).is_pending());
    super::confirm_handshake(&paths);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    super::confirm_handshake(&paths);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(other.dcid.poll_borrow(&mut cx).is_pending());
    remote.recv_frame(NewConnectionIdFrame::new(ConnectionId::from_slice(b"peer0001"), 1u32.into(), 0u32.into())).unwrap();
    assert_eq!(counter.0.load(Ordering::Relaxed), 2);
    let last = path(&paths, 4003);
    last.send_waker.register(cx.waker());
    assert!(last.dcid.poll_borrow(&mut cx).is_pending());
    last.close();
    assert!(counter.0.load(Ordering::Relaxed) >= 3);
    assert_eq!(last.dcid.poll_borrow(&mut Context::from_waker(Waker::noop())), Poll::Ready(None));
    assert_eq!(ready(&selected), mature.peer_cid());
    paths.retire_all();
}

fn take_retired(mature: &super::DataFixture) -> Vec<u64> {
    crate::common::spaces::take_reliable(mature)
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
async fn collect_releases_idle_cids_and_refresh_releases_collected_cids_once() {
    use futures::FutureExt;
    use tokio::io::AsyncWriteExt;

    use crate::path::Datagram;

    for collected in [false, true] {
        let (paths, mature) = super::send::data_spaces(Role::Server, Duration::ZERO);
        let selected = path(&paths, 4001);
        paths.progress.on_path_selected(&paths, &selected);
        super::install_data(&paths, &mature);
        selected.validation.enter_validated().unwrap();
        take_retired(&mature);
        if collected {
            mature.spaces.data.crypto.writer().write_all(b"CID snapshot").await.unwrap();
        }
        let mut datagrams = [Datagram::default()];
        let mut frames = Vec::new();
        let result = selected.collect(&mut datagrams, &mut frames).now_or_never();
        assert_eq!(result.is_some(), collected);
        if collected {
            let (count, dcid) = result.unwrap().unwrap();
            assert!(count > 0);
            assert_eq!(dcid, mature.peer_cid());
        }
        let next = ConnectionId::from_slice(b"client01");
        paths.cid_registry.remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 1u32.into())).unwrap();
        if collected {
            assert!(take_retired(&mature).is_empty(), "sealed datagrams still use CID 0");
        } else {
            assert_eq!(take_retired(&mature), [0]);
        }
        selected.refresh(&mut datagrams, &mut frames);
        assert_eq!(take_retired(&mature), if collected { vec![0] } else { vec![] });
        selected.refresh(&mut datagrams, &mut frames);
        assert!(take_retired(&mature).is_empty());
        assert_eq!(ready(&selected), next);
        paths.retire_all();
    }
}

#[tokio::test(start_paused = true)]
async fn closing_a_sender_waiting_for_a_cid_leaves_the_connection_and_other_sender_alive() {
    let (paths, mature) = super::send::data_spaces(Role::Client, Duration::ZERO);
    let selected = path(&paths, 4001);
    selected.validation.enter_validated().unwrap();
    paths.progress.on_path_selected(&paths, &selected);
    super::install_data(&paths, &mature);
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
    paths.cid_registry.remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into())).unwrap();
    assert_eq!(ready(&live), next);
    assert_eq!(super::borrow(&removed), Poll::Ready(None));
    paths.retire_all();
    crate::common::wait_for_sender_exit(&live).await;
}

#[tokio::test(start_paused = true)]
async fn closing_a_just_upgraded_sender_releases_its_handshake_cid_without_dropping_the_path() {
    let (paths, mature) = super::send::data_spaces(Role::Client, Duration::ZERO);
    let _other = path(&paths, 4001);
    let selected = paths.add_path(pathway(4002));
    paths.progress.on_path_selected(&paths, &selected);
    // Close before the sender polls its first batch after upgrade.
    paths.del_path(&selected.pathway);
    crate::common::wait_for_sender_exit(&selected).await;
    assert_eq!(take_retired(&mature), [0]);
    assert_eq!(super::borrow(&selected), Poll::Ready(None));
    paths.retire_all();
}
