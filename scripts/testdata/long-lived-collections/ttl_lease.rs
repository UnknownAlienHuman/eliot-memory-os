// Fixture: TTL/lease map with scheduled bounded cleanup (issue #885).

use std::collections::HashMap;

pub struct ExpiryWheel {
    ttl: HashMap<String, u64>,
}

impl ExpiryWheel {
    pub fn arm(&mut self, key: String, deadline: u64) {
        self.ttl.insert(key, deadline);
    }

    pub fn sweep(&mut self, now: u64) {
        self.ttl.retain(|_, expires| *expires > now); // scheduled cleanup sweep
    }
}
