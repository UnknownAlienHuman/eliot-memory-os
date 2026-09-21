// Fixture: store whose removal lives in another file (issue #885).
// Growth is local; compaction is owned by store_compactor.rs.

pub struct CompactStore {
    records: Vec<String>,
}

impl CompactStore {
    pub fn stage(&mut self, record: String) {
        self.records.push(record);
    }
}
