use std::{collections::HashSet, sync::Arc, thread};

use qbase::util::*;

#[test]
fn test_unique_id_basic() {
    let generator = UniqueIdGenerator::new();
    let id1 = generator.generate();
    let id2 = generator.generate();

    assert_ne!(id1, id2);
    assert_eq!(usize::from(id1), 1);
    assert_eq!(usize::from(id2), 2);
}

#[test]
fn test_unique_id_hash() {
    let generator = UniqueIdGenerator::new();
    let id1 = generator.generate();
    let id2 = generator.generate();

    let mut set = HashSet::new();
    set.insert(id1);
    set.insert(id2);

    assert_eq!(set.len(), 2);
}

#[test]
fn test_unique_id_clone_copy() {
    let generator = UniqueIdGenerator::new();
    let id1 = generator.generate();
    let id2 = id1; // Copy

    assert_eq!(id1, id2);
}

#[test]
fn test_thread_safety() {
    let generator = Arc::new(UniqueIdGenerator::new());
    let mut handles = vec![];

    // 启动多个线程同时生成ID
    for _ in 0..10 {
        let generator = Arc::clone(&generator);
        let handle = thread::spawn(move || {
            let mut ids = Vec::new();
            for _ in 0..100 {
                ids.push(generator.generate());
            }
            ids
        });
        handles.push(handle);
    }

    // 收集所有生成的ID
    let mut all_ids = HashSet::new();
    for handle in handles {
        let ids = handle.join().unwrap();
        for id in ids {
            assert!(all_ids.insert(id), "Duplicate ID found: {id:?}");
        }
    }

    // 应该有1000个唯一的ID
    assert_eq!(all_ids.len(), 1000);
}

#[test]
fn test_default_generator() {
    let gen1 = UniqueIdGenerator::new();
    let gen2 = UniqueIdGenerator::new();

    assert_eq!(gen1.generate(), gen2.generate())
}
