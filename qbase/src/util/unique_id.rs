use std::{
    hash::Hash,
    sync::atomic::{AtomicUsize, Ordering},
};

use derive_more::Into;

/// Opque, hashable, unique ID type.
#[derive(Debug, Clone, Copy, Into, PartialEq, Eq, Hash)]
pub struct UniqueId(usize);

/// Thread safe, lock free unique ID generator.
#[derive(Debug)]
pub struct UniqueIdGenerator(AtomicUsize);

impl Default for UniqueIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl UniqueIdGenerator {
    /// Create a new `UniqueIdGenerator`
    ///
    /// # Example
    ///
    /// ```
    /// use qbase::util::UniqueIdGenerator;
    ///
    /// let generator = UniqueIdGenerator::new();
    /// let id1 = generator.generate();
    /// let id2 = generator.generate();
    /// assert_ne!(id1, id2);
    /// ```
    pub const fn new() -> Self {
        UniqueIdGenerator(AtomicUsize::new(1))
    }

    /// Generated a new `UniqueId` starting from a specific value
    ///
    /// # Example
    ///
    /// ```
    /// use qbase::util::UniqueIdGenerator;
    ///
    /// let generator = UniqueIdGenerator::new();
    /// let id1 = generator.generate();
    /// let id2 = generator.generate();
    /// assert_ne!(id1, id2);
    /// ```
    pub fn generate(&self) -> UniqueId {
        let id = self.0.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, 0, "UniqueId overflow");
        UniqueId(id)
    }
}
