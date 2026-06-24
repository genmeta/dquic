use std::{
    any::{Any, TypeId},
    collections::{HashMap, hash_map},
    fmt::Debug,
    hash::{BuildHasherDefault, Hasher},
    task::{Context, Poll, ready},
};

use crate::Interface;

pub mod alive;
pub mod local_endpoint;
pub mod location;
pub mod route;

pub trait Component: Any + Debug + Send + Sync {
    /// Gracefully shutdown the component when IO is unbound.
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()>;

    /// Re-initialize the component after the QuicIO has been rebound
    ///
    /// Normally, this method first shuts down the component,
    /// then re-initializes it with the new QuicIO.
    ///
    /// Implementation may override this method for optimization.
    fn reinit(&self, iface: &Interface);
}

// With TypeIds as keys, there's no need to hash them. They are already hashes
// themselves, coming from the compiler. The IdHasher just holds the u64 of
// the TypeId, and then returns it, instead of doing any bit fiddling.
#[derive(Default)]
pub(super) struct IdHasher(u64);

impl Hasher for IdHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("TypeId calls write_u64");
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

#[derive(Default)]
pub struct Components {
    pub(super) map: HashMap<TypeId, Box<dyn Component>, BuildHasherDefault<IdHasher>>,
}

impl Components {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<C: Component>(&self) -> Option<&C> {
        self.map
            .get(&TypeId::of::<C>())
            .and_then(|c| (c.as_ref() as &dyn Any).downcast_ref())
    }

    pub fn exist<C: Component>(&self) -> bool {
        self.map.contains_key(&TypeId::of::<C>())
    }

    pub fn with<C: Component, T>(&self, f: impl FnOnce(&C) -> T) -> Option<T> {
        self.get::<C>().map(f)
    }

    pub fn init_with<C: Component>(&mut self, init: impl FnOnce() -> C) -> &mut C {
        let ref_mut = self
            .map
            .entry(TypeId::of::<C>())
            .or_insert_with(|| Box::new(init()));
        (ref_mut.as_mut() as &mut dyn Any).downcast_mut().unwrap()
    }

    pub fn try_init_with<C: Component, E>(
        &mut self,
        init: impl FnOnce() -> Result<C, E>,
    ) -> Result<&mut C, E> {
        let entry = self.map.entry(TypeId::of::<C>());
        let ref_mut = match entry {
            hash_map::Entry::Occupied(entry) => entry.into_mut(),
            hash_map::Entry::Vacant(entry) => entry.insert(Box::new(init()?)),
        };
        Ok((ref_mut.as_mut() as &mut dyn Any).downcast_mut().unwrap())
    }

    pub fn poll_remove<C>(&mut self, cx: &mut Context<'_>) -> Poll<()>
    where
        C: Component,
    {
        let hash_map::Entry::Occupied(entry) = self.map.entry(TypeId::of::<C>()) else {
            return Poll::Ready(());
        };

        ready!(entry.get().poll_shutdown(cx));
        entry.remove();

        Poll::Ready(())
    }
}
