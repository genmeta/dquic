use std::task::Poll;

use bytes::Bytes;
use qrecovery::send::SendBuf;

fn buffer(size: usize) -> SendBuf {
    let mut buf = SendBuf::with_capacity(size as u64);
    buf.write(Bytes::from(vec![0; size]));
    buf
}

#[test]
fn test_bufmap_empty() {
    let mut buf = SendBuf::default();
    assert!(buf.is_empty());
    assert_eq!(buf.written(), 0);
    assert!(buf.pick_up(|_| Some(20), usize::MAX).is_err());
}

#[test]
fn test_bufmap_extend_to() {
    let mut buf = buffer(100);
    assert_eq!(buf.written(), 100);
    assert_eq!(buf.pick_up(|_| Some(100), usize::MAX).unwrap().0, 0..100);
    buf.extend(200);
    buf.write(Bytes::from(vec![0; 100]));
    assert_eq!(buf.written(), 200);
    let (range, fresh, _) = buf.pick_up(|_| Some(200), usize::MAX).unwrap();
    assert_eq!(range, 100..200);
    assert!(fresh);
}

#[test]
fn test_bufmap_sent() {
    let mut buf = buffer(200);
    assert_eq!(buf.sent(), 0);
    assert!(buf.pick_up(|_| Some(120), usize::MAX).is_ok());
    assert_eq!(buf.sent(), 120);
    assert!(buf.pick_up(|_| Some(80), usize::MAX).is_ok());
    assert_eq!(buf.sent(), 200);
}

#[test]
#[should_panic]
fn test_bufmap_recved_overflow() {
    let mut buf = buffer(200);
    assert!(buf.pick_up(|_| Some(120), usize::MAX).is_ok());
    buf.on_data_acked(&(110..121));
}

#[test]
#[should_panic]
fn test_bufmap_recved_over_end() {
    let mut buf = buffer(200);
    assert!(buf.pick_up(|_| Some(200), usize::MAX).is_ok());
    buf.on_data_acked(&(0..201));
}

#[test]
fn test_bufmap_ack_and_lost_all2() {
    let mut buf = buffer(46);
    assert!(buf.pick_up(|_| Some(46), usize::MAX).is_ok());
    buf.on_data_acked(&(0..2));
    buf.may_loss_data(&(0..46));
    let (range, fresh, _) = buf.pick_up(|_| Some(46), usize::MAX).unwrap();
    assert_eq!(range, 2..46);
    assert!(!fresh);
}

#[test]
fn resending_flighting_preserves_unsent_and_acked_ranges() {
    let mut buf = SendBuf::with_capacity(30);
    buf.write(Bytes::from_static(&[42; 30]));
    assert_eq!(buf.pick_up(|_| Some(10), 30).unwrap().0, 0..10);
    assert_eq!(buf.pick_up(|_| Some(10), 30).unwrap().0, 10..20);

    buf.multipath_handshake();
    buf.on_data_acked(&(5..15));
    // Acknowledged bytes stay excluded from explicitly replayed ranges.
    for expected in [0..5, 15..20] {
        let (range, fresh, data) = buf.pick_up(|_| Some(30), 0).unwrap();
        assert_eq!(range, expected);
        assert!(!fresh);
        assert_eq!(data.concat(), [42; 5]);
    }
    // Unsent data remains fresh and subject to flow control.
    assert_eq!(buf.pick_up(|_| Some(30), 0), Err(Poll::Ready(())));
    let (range, fresh, _) = buf.pick_up(|_| Some(30), 30).unwrap();
    assert_eq!(range, 20..30);
    assert!(fresh);
    assert_eq!(buf.pick_up(|_| Some(30), 30), Err(Poll::Pending));

    buf.on_data_acked(&(0..30));
    buf.multipath_handshake();
    assert_eq!(buf.pick_up(|_| Some(30), 30), Err(Poll::Pending));
    assert!(buf.is_all_rcvd());
}
