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
