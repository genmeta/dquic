use qbase::util::*;

#[test]
fn shared_guards_preserve_indexes_across_clones() {
    struct Entry(u64);

    let deque = ArcIndexDeque::from(IndexDeque::<Entry, 2>::with_capacity(3));
    let shared = deque.clone();
    {
        let mut guard = deque.write_guard();
        guard.extend([Entry(10), Entry(20)]);
        guard[1].0 += 1;
        assert_eq!(guard.pop_front().unwrap().0, 0);
    }

    {
        let guard = shared.read_guard();
        assert_eq!(guard.offset(), 1);
        assert_eq!(guard[1].0, 21);
        assert_eq!(guard.iter().map(|entry| entry.0).collect::<Vec<_>>(), [21]);
    }

    assert_eq!(shared.write_guard().push_back(Entry(30)), Ok(2));
    assert_eq!(
        deque.write_guard().push_back(Entry(40)),
        Err(IndexError::ExceedLimit(3, 2))
    );
    assert_eq!(deque.read_guard()[2].0, 30);
}

#[test]
fn cloned_guard_contents_keep_offset_and_are_independent() {
    let deque = ArcIndexDeque::from(IndexDeque::<u64, 2>::with_capacity(3));
    {
        let mut guard = deque.write_guard();
        guard.extend([10, 20, 30]);
        guard.pop_front();
    }

    let mut owned = deque.read_guard().clone();
    owned[1] = 99;
    deque.write_guard().pop_front();

    assert_eq!(owned.offset(), 1);
    assert_eq!(owned[1], 99);
    assert_eq!(owned[2], 30);
    assert_eq!(deque.read_guard().offset(), 2);
    assert_eq!(deque.read_guard()[2], 30);
}

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

#[test]
fn test_index_queue() {
    let mut deque = IndexDeque::<u64, 19>::default();
    for i in 0..10 {
        assert_eq!(deque.push_back(i + 1), Ok(i));
    }
    assert_eq!(deque.offset(), 0);

    for i in 0..10 {
        assert_eq!(deque.pop_front(), Some((i, i + 1)));
        assert_eq!(deque.offset(), i + 1);
    }
    assert_eq!(deque.pop_front(), None);
    assert_eq!(deque.offset(), 10);

    for i in 10..20 {
        assert_eq!(deque.push_back(i + 1), Ok(i));
    }
    assert_eq!(deque.push_back(21), Err(IndexError::ExceedLimit(20, 19)));
    assert_eq!(deque.offset(), 10);

    assert!(!deque.contain(0));
    assert!(!deque.contain(9));
    assert!(deque.contain(10));
    assert!(deque.contain(19));
    assert!(!deque.contain(21));

    assert_eq!(deque[10], 11);
    assert_eq!(deque[19], 20);

    assert_eq!(deque.drain_to(10).count(), 0);
    let mut i = 10;
    for item in deque.drain_to(15) {
        i += 1;
        assert_eq!(item, i);
    }
    assert_eq!(i, 15);
    assert!(deque.contain(15));
    assert_eq!(deque.offset(), 15);

    assert_eq!(deque.drain_to(20).count(), 5);
    assert_eq!(deque.offset(), 20);
    assert!(deque.is_empty());
}
