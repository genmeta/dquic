use qbase::util::*;

#[test]
fn test_insert() {
    let mut deque = IndexDeque::<u64, 19>::default();
    deque.insert(10, 11).unwrap();
    assert_eq!(deque.offset(), 0);
    assert_eq!(deque.len(), 11);

    for i in 0..10 {
        assert_eq!(deque[i], u64::default());
    }
    assert_eq!(deque[10], 11);
}

#[test]
fn test_skip() {
    let mut deque = IndexDeque::<u64, 19>::default();
    for i in 0..10 {
        assert_eq!(deque.push_back(i), Ok(i));
    }
    assert_eq!(deque.offset(), 0);

    deque.advance(5);
    assert_eq!(deque.offset(), 5);

    deque.enumerate().for_each(|(idx, item)| {
        assert_eq!(idx, *item);
    });
}

#[test]
fn test_reset_offset() {
    let mut deque = IndexDeque::<u64, 19>::default();
    deque.reset_offset(5);
    assert_eq!(deque.offset(), 5);
    for i in 0..10 {
        assert_eq!(deque.push_back(i), Ok(i + 5));
    }
    for i in 0..10 {
        assert_eq!(deque.pop_front(), Some((i + 5, i)));
    }
}

#[test]
fn test_reset_offset_with_content() {
    let mut deque = IndexDeque::<u64, 19>::default();
    for i in 0..5 {
        assert_eq!(deque.push_back(i), Ok(i));
    }
    deque.reset_offset(10);
    deque.enumerate().for_each(|(idx, item)| {
        assert_eq!(idx, *item + 10);
    });
}

#[test]
fn test_reset_offset_panic2() {
    let mut deque = IndexDeque::<u64, 19>::default();
    for i in 0..10 {
        assert_eq!(deque.push_back(i), Ok(i));
    }
    for i in 0..5 {
        assert_eq!(deque.pop_front(), Some((i, i)));
    }
    assert_eq!(deque.offset(), 5);
    deque.reset_offset(3);
    deque.enumerate().for_each(|(idx, item)| {
        assert_eq!(idx + 2, *item);
    });
}

#[test]
fn test_resize() {
    let mut deque = IndexDeque::<u64, 19>::default();
    for i in 0..10 {
        assert_eq!(deque.push_back(i), Ok(i));
    }
    assert_eq!(deque.offset(), 0);

    deque.resize(15, 10).unwrap();
    assert_eq!(deque.offset(), 0);
    assert_eq!(deque.len(), 15);
    for i in 10..15 {
        assert_eq!(deque[i], 10);
    }

    deque.resize(5, 10).unwrap();
    assert_eq!(deque.offset(), 0);
    assert_eq!(deque.len(), 5);
    for i in 0..5 {
        assert_eq!(deque[i], i);
    }

    assert_eq!(deque.resize(20, 10), Err(IndexError::ExceedLimit(20, 19)));

    for i in 0..5 {
        assert_eq!(deque.pop_front(), Some((i, i)));
    }
    assert_eq!(deque.resize(0, 10), Err(IndexError::TooSmall(0, 5)));
}
