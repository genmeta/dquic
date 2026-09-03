use std::time::Duration;

use bytes::Bytes;
use qtls::{MemoryResumptionStore, ResumptionKey, ResumptionStore, StoredSession, UnixTime};

#[test]
fn takes_the_newest_session_for_a_key_exactly_once() {
    let store = MemoryResumptionStore::new(4);
    let key = ResumptionKey::from_bytes(Bytes::from_static(b"key"));
    store.put(key.clone(), session(1)).unwrap();
    store.put(key.clone(), session(2)).unwrap();

    assert_eq!(
        store.take(&key).unwrap().unwrap().sealed,
        Bytes::from_static(&[2])
    );
    assert_eq!(
        store.take(&key).unwrap().unwrap().sealed,
        Bytes::from_static(&[1])
    );
    assert!(store.take(&key).unwrap().is_none());
}

#[test]
fn evicts_the_globally_oldest_session_at_capacity() {
    let store = MemoryResumptionStore::new(2);
    let first = ResumptionKey::from_bytes(Bytes::from_static(b"first"));
    let second = ResumptionKey::from_bytes(Bytes::from_static(b"second"));
    let third = ResumptionKey::from_bytes(Bytes::from_static(b"third"));
    store.put(first.clone(), session(1)).unwrap();
    store.put(second.clone(), session(2)).unwrap();
    store.put(third.clone(), session(3)).unwrap();

    assert!(store.take(&first).unwrap().is_none());
    assert_eq!(
        store.take(&second).unwrap().unwrap().sealed,
        Bytes::from_static(&[2])
    );
    assert_eq!(
        store.take(&third).unwrap().unwrap().sealed,
        Bytes::from_static(&[3])
    );
}

#[test]
fn expired_sessions_are_removed_and_never_returned() {
    let store = MemoryResumptionStore::new(2);
    let key = ResumptionKey::from_bytes(Bytes::from_static(b"expired"));
    store
        .put(
            key.clone(),
            StoredSession {
                not_after: UnixTime::since_unix_epoch(Duration::ZERO),
                sealed: Bytes::from_static(b"expired"),
            },
        )
        .unwrap();

    assert!(store.take(&key).unwrap().is_none());
}

fn session(value: u8) -> StoredSession {
    StoredSession {
        not_after: UnixTime::since_unix_epoch(Duration::from_secs(u64::MAX)),
        sealed: Bytes::copy_from_slice(&[value]),
    }
}
