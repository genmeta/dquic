use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use qbase::net::route::Pathway;
use qtransport::path::Path;

use crate::ArcConnPhase;

/// Connection paths and the phase observed by every path sender.
pub struct Paths {
    phase: ArcConnPhase,
    entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
}

impl Paths {
    pub fn new(phase: ArcConnPhase) -> Self {
        Self {
            phase,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn phase(&self) -> ArcConnPhase {
        self.phase.clone()
    }

    pub fn insert(&self, path: Arc<Path>) -> bool {
        let mut entries = self.entries.lock().unwrap();
        match entries.entry(path.pathway) {
            std::collections::btree_map::Entry::Occupied(_) => false,
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(path);
                true
            }
        }
    }

    /// Register a path and start its sender exactly once while holding the path table.
    pub(crate) fn get_or_try_insert_with<E>(
        &self,
        pathway: Pathway,
        create: impl FnOnce() -> Result<Arc<Path>, E>,
    ) -> Result<Arc<Path>, E> {
        let mut entries = self.entries.lock().unwrap();
        match entries.entry(pathway) {
            std::collections::btree_map::Entry::Occupied(entry) => Ok(entry.get().clone()),
            std::collections::btree_map::Entry::Vacant(entry) => {
                Ok(entry.insert(create()?).clone())
            }
        }
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.entries.lock().unwrap().get(pathway).cloned()
    }

    pub fn snapshot(&self) -> Vec<Arc<Path>> {
        self.entries.lock().unwrap().values().cloned().collect()
    }

    /// Remove this exact retired instance, never a replacement at the same address.
    pub fn remove(&self, path: &Arc<Path>) -> bool {
        path.retire();
        let mut entries = self.entries.lock().unwrap();
        if entries
            .get(&path.pathway)
            .is_some_and(|current| Arc::ptr_eq(current, path))
        {
            entries.remove(&path.pathway);
            true
        } else {
            false
        }
    }
}
