use std::ops::{Index, IndexMut};

/// The epoch of sending, usually been seen as the index of spaces.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

impl Epoch {
    pub const EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Data];
    /// An iterator for the epoch of each spaces.
    ///
    /// Equals to `Epoch::EPOCHES.iter()`
    pub fn iter() -> std::slice::Iter<'static, Epoch> {
        Self::EPOCHS.iter()
    }

    /// The number of epoches.
    pub const fn count() -> usize {
        Self::EPOCHS.len()
    }

    /// The next packet-number space in assembly order.
    ///
    /// # Panics
    ///
    /// Panics if this is [`Epoch::Data`], the last epoch.
    pub const fn next(self) -> Self {
        match self {
            Self::Initial => Self::Handshake,
            Self::Handshake => Self::Data,
            Self::Data => panic!("Data is the last epoch"),
        }
    }
}

impl<T> Index<Epoch> for [T]
where
    T: Sized,
{
    type Output = T;

    fn index(&self, index: Epoch) -> &Self::Output {
        self.index(index as usize)
    }
}

impl<T> IndexMut<Epoch> for [T]
where
    T: Sized,
{
    fn index_mut(&mut self, index: Epoch) -> &mut Self::Output {
        self.index_mut(index as usize)
    }
}
