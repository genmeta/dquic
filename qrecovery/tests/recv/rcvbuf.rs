use bytes::{BufMut, Bytes};
use qrecovery::recv::RecvBuf;

#[test]
fn test_no_overlap() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
    assert_eq!(buf.recv(6, Bytes::from("world")), 6);

    assert_eq!(buf.segment_count(), 2);

    assert_eq!(buf.recv(5, Bytes::from(" ")), 0);
    assert_eq!(buf.segment_count(), 3);
    let mut offset = 0;
    for expected in [b"hello".as_slice(), b" ".as_slice(), b"world".as_slice()] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_left_partially_overlap() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("01234")), 5);
    assert_eq!(buf.recv(2, Bytes::from("2345")), 1); //left segment partially overlapped this
    assert_eq!(buf.recv(6, Bytes::from("6789")), 4); // no overlap

    assert_eq!(buf.segment_count(), 3);
    assert_eq!(buf.available(), 10);
    let mut offset = 0;
    for expected in [b"01234".as_slice(), b"5".as_slice(), b"6789".as_slice()] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_right_partially_overlap() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
    assert_eq!(buf.recv(6, Bytes::from("world!")), 7);
    assert_eq!(buf.recv(5, Bytes::from(" wor")), 0); // overlap right

    assert_eq!(buf.segment_count(), 3);
    assert_eq!(buf.available(), 12);
    let mut offset = 0;
    for expected in [b"hello".as_slice(), b" ".as_slice(), b"world!".as_slice()] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
#[doc(alias = "fully_overlap_left")]
fn test_same_offset() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("01234")), 5);
    assert_eq!(buf.recv(0, Bytes::from("0123456789")), 5);

    assert_eq!(buf.segment_count(), 2);
    assert_eq!(buf.available(), 10);
    let mut offset = 0;
    for expected in [b"01234".as_slice(), b"56789".as_slice()] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_fully_overlap_right() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
    assert_eq!(buf.recv(6, Bytes::from("world")), 6);
    assert_eq!(buf.recv(5, Bytes::from(" world!")), 1); // fully overlap right

    assert_eq!(buf.segment_count(), 4);
    assert_eq!(buf.available(), 12);
    let mut offset = 0;
    for expected in [
        b"hello".as_slice(),
        b" ".as_slice(),
        b"world".as_slice(),
        b"!".as_slice(),
    ] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_left_fully_overlap() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("114514")), 6);
    assert_eq!(buf.recv(2, Bytes::from("45")), 0); // left segment fully overlapped this
    assert_eq!(buf.recv(2, Bytes::from("4514")), 0); // left segment fully overlapped this
    assert_eq!(buf.segment_count(), 1);
    assert_eq!(buf.available(), 6);
    assert_eq!(buf.nread(), 0);
    assert_eq!(buf.try_next().unwrap().as_ref(), b"114514");
    assert_eq!(buf.nread(), 6);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_right_fully_overlapp() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("114514")), 6);
    assert_eq!(buf.recv(6, Bytes::from("1919810")), 7);
    assert_eq!(buf.recv(8, Bytes::from("1981")), 0); // right segment fully overlapped this
    assert_eq!(buf.recv(8, Bytes::from("19810")), 0); // right segment fully overlapped this

    assert_eq!(buf.segment_count(), 2);
    assert_eq!(buf.available(), 13);
    let mut offset = 0;
    for expected in [b"114514".as_slice(), b"1919810".as_slice()] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_left_right_partially_overlap() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("012345")), 6);
    assert_eq!(buf.recv(7, Bytes::from("789")), 4);
    assert_eq!(buf.recv(6, Bytes::from("6")), 0); // left and right partially overlapped this

    assert_eq!(buf.segment_count(), 3);
    assert_eq!(buf.available(), 10);
    let mut offset = 0;
    for expected in [b"012345".as_slice(), b"6".as_slice(), b"789".as_slice()] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_left_right_fully_overlap() {
    let mut buf = RecvBuf::default();
    assert_eq!(buf.recv(0, Bytes::from("01234")), 5);
    assert_eq!(buf.recv(5, Bytes::from("56789")), 5);
    assert_eq!(buf.recv(2, Bytes::from("2345678")), 0); // left and right fully overlapped this

    assert_eq!(buf.segment_count(), 2);
    assert_eq!(buf.available(), 10);
    let mut offset = 0;
    for expected in [b"01234".as_slice(), b"56789".as_slice()] {
        assert_eq!(buf.nread(), offset);
        let data = buf.try_next().unwrap();
        assert_eq!(data.as_ref(), expected);
        offset += expected.len() as u64;
    }
    assert_eq!(buf.nread(), offset);
    assert!(buf.try_next().is_none());
}

#[test]
fn test_recvbuf_read() {
    let mut rcvbuf = RecvBuf::default();
    assert_eq!(rcvbuf.recv(0, Bytes::from("hello")), 5);
    assert_eq!(rcvbuf.recv(6, Bytes::from("world")), 6);

    let mut dst = [0u8; 20];
    let mut buf = &mut dst[..];
    rcvbuf.try_read(&mut buf);
    assert_eq!(buf.remaining_mut(), 15);

    assert_eq!(rcvbuf.recv(5, Bytes::from(" ")), 0);
    rcvbuf.try_read(&mut buf);

    assert_eq!(buf.remaining_mut(), 9);
    assert_eq!(dst[..11], b"hello world"[..]);
}
