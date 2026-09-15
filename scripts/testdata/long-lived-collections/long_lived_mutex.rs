// Fixture: long-lived Mutex<HashMap> growth without removal (issue #885).
// Registry lives behind the owning struct with insert growth and no
// bound/removal evidence in the scanned slice: an unbounded candidate.

use std::collections::HashMap;
use std::sync::Mutex;

pub struct Registry {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl Registry {
    pub fn register(&self, key: String, value: Vec<u8>) {
        self.inner.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.get(key).cloned()
    }
}
