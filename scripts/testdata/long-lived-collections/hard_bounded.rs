// Fixture: long-lived hard-bounded Vec (issue #885).
// Literal capacity plus same-slice removal bounds growth: hard-bounded.

pub struct Cache {
    entries: Vec<String>,
}

impl Cache {
    pub fn new() -> Self {
        Self { entries: Vec::with_capacity(64) }
    }

    pub fn add(&mut self, value: String) {
        self.entries.push(value);
    }

    pub fn prune(&mut self) {
        self.entries.retain(|entry| !entry.is_empty());
    }
}
