use std::{
    collections::VecDeque,
    ops::{Index, IndexMut},
};

use thiserror::Error;

/// The index error type for [`IndexDeque`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IndexError {
    #[error("The index {0} exceed the limit {1}")]
    ExceedLimit(u64, u64),
    #[error("The index {0} is less than the offset {1}")]
    TooSmall(u64, u64),
}

/// A first-in-first-out queue indexed by the enqueue sequence number.
///
/// For [`VecDeque`], the index of elements starts from 0 even after they are dequeued.
/// However, for [`IndexDeque`], the index is the enqueue sequence number.
/// Even if some elements have been dequeued,
/// the enqueue index of other elements in IndexDeque remains unchanged.
///
/// - `T` is the type of elements in the queue.
/// - `LIMIT` is the maximum limit of the enqueue index.
///
/// [`IndexDeque`] is useful in many places in QUIC implementation,
/// such as recording packet sending history.
#[derive(Debug)]
pub struct IndexDeque<T, const LIMIT: u64> {
    deque: VecDeque<T>,
    offset: u64,
}

impl<T, const LIMIT: u64> Default for IndexDeque<T, LIMIT> {
    fn default() -> Self {
        Self {
            deque: VecDeque::default(),
            offset: 0,
        }
    }
}

impl<T, const LIMIT: u64> IndexDeque<T, LIMIT> {
    /// Create a new empty IndexDeque with the specified capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let deque: IndexDeque<u64, 19> = IndexDeque::with_capacity(10);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            deque: VecDeque::with_capacity(capacity),
            offset: 0,
        }
    }

    /// Returns true if the queue is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// assert!(deque.is_empty());
    /// deque.push_back(1).unwrap();
    /// assert!(!deque.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    /// Returns the number of elements in the queue.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// assert_eq!(deque.len(), 0);
    /// deque.push_back(1).unwrap();
    /// assert_eq!(deque.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.deque.len()
    }

    /// Returns the enqueue sequence number of the first element in the queue.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// assert_eq!(deque.offset(), 0);
    /// deque.push_back(1).unwrap();
    /// assert_eq!(deque.offset(), 0);
    /// deque.pop_front();
    /// assert_eq!(deque.offset(), 1);
    /// ```
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the next enqueue sequence number of the queue.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// assert_eq!(deque.largest(), 0);
    /// deque.push_back(1).unwrap();
    /// assert_eq!(deque.largest(), 1);
    /// ```
    pub fn largest(&self) -> u64 {
        self.offset + self.deque.len() as u64
    }

    /// Returns true if the queue contains the specified enqueue index.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// assert!(!deque.contain(0));
    /// deque.push_back(1).unwrap();
    /// assert!(deque.contain(0));
    /// assert!(!deque.contain(1));
    /// ```
    pub fn contain(&self, idx: u64) -> bool {
        idx >= self.offset && idx < self.largest()
    }

    /// Provides a reference to an element at the specified enqueue index.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// assert_eq!(deque.get(1), Some(&2));
    /// assert_eq!(deque.get(3), None);
    /// ```
    pub fn get(&self, idx: u64) -> Option<&T> {
        if self.contain(idx) {
            Some(&self.deque[(idx - self.offset) as usize])
        } else {
            None
        }
    }

    /// Provides a mutable reference to an element at the specified enqueue index.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// assert_eq!(deque[1], 2);
    /// if let Some(v) = deque.get_mut(1) {
    ///    *v = 4;
    /// }
    /// assert_eq!(deque[1], 4);
    /// ```
    pub fn get_mut(&mut self, idx: u64) -> Option<&mut T> {
        if self.contain(idx) {
            Some(&mut self.deque[(idx - self.offset) as usize])
        } else {
            None
        }
    }

    /// Append an element to the end of the queue and return the enqueue index of the element.
    /// If it exceeds the maximum limit of the enqueue index, return [`IndexError`].
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::{IndexDeque, IndexError};
    ///
    /// let mut deque: IndexDeque<u64, 2> = IndexDeque::default();
    /// assert_eq!(deque.push_back(1), Ok(0));
    /// assert_eq!(deque.push_back(2), Ok(1));
    /// assert_eq!(deque.push_back(3), Ok(2));
    /// assert_eq!(deque.push_back(4), Err(IndexError::ExceedLimit(3, 2)));
    /// ```
    pub fn push_back(&mut self, value: T) -> Result<u64, IndexError> {
        let next_idx = self.offset.overflowing_add(self.deque.len() as u64);
        if next_idx.1 || next_idx.0 > LIMIT {
            Err(IndexError::ExceedLimit(next_idx.0, LIMIT))
        } else {
            self.deque.push_back(value);
            Ok(self.deque.len() as u64 - 1 + self.offset)
        }
    }

    /// Returns None if the queue is empty; otherwise, returns
    /// the first element in the queue along with its enqueue index.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// assert_eq!(deque.pop_front(), None);
    ///
    /// deque.push_back(1).unwrap();
    /// assert_eq!(deque.pop_front(), Some((0, 1)));
    /// assert!(deque.is_empty());
    /// ```
    pub fn pop_front(&mut self) -> Option<(u64, T)> {
        self.deque.pop_front().map(|v| {
            let offset = self.offset;
            self.offset += 1;
            (offset, v)
        })
    }

    pub fn front(&self) -> Option<(u64, &T)> {
        self.deque.front().map(|v| (self.offset, v))
    }

    pub fn back(&self) -> Option<(u64, &T)> {
        self.deque.back().map(|v| (self.largest() - 1, v))
    }

    /// Returns a front-to-back iterator.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// let b: &[_] = &[&1, &2, &3];
    /// let c: Vec<&u64> = deque.iter().collect();
    /// assert_eq!(b, c.as_slice());
    /// ```
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> {
        self.deque.iter()
    }

    /// Returns a front-to-back iterator that returns mutable references.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// for num in deque.iter_mut() {
    ///    *num += 1;
    /// }
    /// let b: &[_] = &[&mut 2, &mut 3, &mut 4];
    /// assert_eq!(deque.iter_mut().collect::<Vec<&mut u64>>().as_slice(), b);
    /// ```
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut T> {
        self.deque.iter_mut()
    }

    /// Returns a front-to-back iterator that returns the enqueue index along with the references.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// for (idx, num) in deque.enumerate() {
    ///    assert_eq!(idx + 1, *num);
    /// }
    /// ```
    pub fn enumerate(&self) -> impl DoubleEndedIterator<Item = (u64, &T)> {
        self.deque
            .iter()
            .enumerate()
            .map(|(idx, item)| (self.offset + idx as u64, item))
    }

    /// Returns a front-to-back iterator that returns
    /// the enqueue index along with the mutable references.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// for (idx, num) in deque.enumerate_mut() {
    ///     *num = *num + idx;
    /// }
    /// let b: &[_] = &[(0, &mut 1), (1, &mut 3), (2, &mut 5)];
    /// assert_eq!(deque.enumerate_mut().collect::<Vec<(u64, &mut u64)>>().as_slice(), b);
    /// ```
    pub fn enumerate_mut(&mut self) -> impl DoubleEndedIterator<Item = (u64, &mut T)> {
        self.deque
            .iter_mut()
            .enumerate()
            .map(|(idx, item)| (self.offset + idx as u64, item))
    }

    /// Shortens the queue, dropping the first `n` elements.
    ///
    /// If `n` is greater or equal to the queue's length, this method will clear the queue.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// deque.advance(2);
    /// assert_eq!(deque.len(), 1);
    /// assert_eq!(deque.offset(), 2);
    /// assert_eq!(deque[2], 3);
    /// ```
    pub fn advance(&mut self, n: usize) {
        self.offset += n as u64;
        let _ = self.deque.drain(..n);
    }

    /// Removes the elements from the queue until the enqueue index is equal to `end`.
    /// Returns a front-to-back iterator over the removed elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.push_back(1).unwrap();
    /// deque.push_back(2).unwrap();
    /// deque.push_back(3).unwrap();
    /// let b: &[_] = &[1, 2];
    /// assert_eq!(deque.drain_to(2).collect::<Vec<u64>>().as_slice(), b);
    /// assert_eq!(deque.offset(), 2);
    /// ```
    pub fn drain_to(&mut self, end: u64) -> impl DoubleEndedIterator<Item = T> + '_ {
        #[cfg(not(test))]
        debug_assert!(end >= self.offset && end <= self.offset + self.deque.len() as u64);
        // avoid end < self.offset
        let end = std::cmp::max(end, self.offset);
        let offset = self.offset;
        // avoid end > self.offset + self.deque.len()
        self.offset = std::cmp::min(end, offset + self.deque.len() as u64);
        let end = (self.offset - offset) as usize;
        self.deque.drain(..end)
    }

    /// Force to reset the first enqueue index of the queue to `new_offset`.
    /// Then, it will affect the enqueue sequence numbers of all subsequent elements.
    ///
    /// Be careful to use this method, you must know what you are doing.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::IndexDeque;
    ///
    /// let mut deque: IndexDeque<u64, 19> = IndexDeque::default();
    /// deque.reset_offset(5);
    /// assert_eq!(deque.largest(), 5);
    /// deque.push_back(1).unwrap();
    /// assert_eq!(deque[5], 1);
    /// ```
    pub fn reset_offset(&mut self, new_offset: u64) {
        // assert!(self.is_empty() && new_offset >= self.offset);
        self.offset = new_offset;
    }
}

impl<T, const LIMIT: u64> Extend<T> for IndexDeque<T, LIMIT> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.deque.extend(iter)
    }
}

impl<T: Default + Clone, const LIMIT: u64> IndexDeque<T, LIMIT> {
    /// Inserts an element at the specified enqueue index `idx`,
    /// returns the origin element at the index if it exists.
    ///
    /// It will insert the default value in the gap
    /// between the current largest index and the `idx`,
    /// if the `idx` is greater than the current largest index.
    ///
    /// Returns [`IndexError`] if the enqueue index is less than the offset or exceeds the maximum limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::{IndexDeque, IndexError};
    ///
    /// let mut deque: IndexDeque<u64, 3> = IndexDeque::default();
    /// let old_value = deque.insert(1, 2).unwrap();
    /// assert_eq!(old_value, None);
    /// assert_eq!(deque[0], u64::default());
    /// assert_eq!(deque[1], 2);
    ///
    /// let result = deque.insert(4, 5);
    /// assert_eq!(result, Err(IndexError::ExceedLimit(4, 3)));
    /// ```
    pub fn insert(&mut self, idx: u64, value: T) -> Result<Option<T>, IndexError> {
        if idx > LIMIT {
            Err(IndexError::ExceedLimit(idx, LIMIT))
        } else if idx < self.offset {
            Err(IndexError::TooSmall(idx, self.offset))
        } else {
            let pos = (idx - self.offset) as usize;
            if pos < self.deque.len() {
                return Ok(Some(std::mem::replace(&mut self.deque[pos], value)));
            }

            if pos > self.deque.len() {
                self.deque.resize(pos, T::default());
            }
            self.deque.push_back(value);
            Ok(None)
        }
    }

    /// Modifies the deque in-place so that offset() is equal to new_offset, either by
    /// removing excess elements from the back or by appending clones of value to the back.
    pub fn resize(&mut self, new_end: u64, value: T) -> Result<(), IndexError> {
        if new_end < self.offset {
            Err(IndexError::TooSmall(new_end, self.offset))
        } else if new_end > LIMIT {
            Err(IndexError::ExceedLimit(new_end, LIMIT))
        } else {
            let len = new_end.saturating_sub(self.offset);
            self.deque.resize(len as usize, value.clone());
            Ok(())
        }
    }
}

impl<T, const LIMIT: u64> Index<u64> for IndexDeque<T, LIMIT> {
    type Output = T;

    fn index(&self, index: u64) -> &Self::Output {
        &self.deque[(index - self.offset) as usize]
    }
}

impl<T, const LIMIT: u64> IndexMut<u64> for IndexDeque<T, LIMIT> {
    fn index_mut(&mut self, index: u64) -> &mut Self::Output {
        &mut self.deque[(index - self.offset) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_queue() {
        let mut deque = IndexDeque::<u64, 19>::default();
        for i in 0..10 {
            assert_eq!(deque.push_back(i + 1), Ok(i));
        }
        assert_eq!(deque.offset, 0);

        for i in 0..10 {
            assert_eq!(deque.pop_front(), Some((i, i + 1)));
            assert_eq!(deque.offset, i + 1);
        }
        assert_eq!(deque.pop_front(), None);
        assert_eq!(deque.offset, 10);

        for i in 10..20 {
            assert_eq!(deque.push_back(i + 1), Ok(i));
        }
        assert_eq!(deque.push_back(21), Err(IndexError::ExceedLimit(20, 19)));
        assert_eq!(deque.offset, 10);

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
        assert_eq!(deque.offset, 15);

        assert_eq!(deque.drain_to(30).count(), 5);
        assert_eq!(deque.offset, 20);
        assert!(deque.is_empty());
    }
}
