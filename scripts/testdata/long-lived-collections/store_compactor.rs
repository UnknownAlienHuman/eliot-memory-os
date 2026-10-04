// Fixture: external compaction owner for CompactStore.records (issue #885).
// The retain callsite lives outside the declaring file and is receiver-exact:
// destructuring binds the exact CompactStore.records field, so this is genuine
// cross-file per-entry compaction, not a whole-collection clear. The
// compactor's own marker buffer is tracked as a separate row.

pub struct StoreCompactor {
    swept: Vec<String>,
}

impl StoreCompactor {
    pub fn compact(store: &mut CompactStore) { let CompactStore { records } = store; records.retain(|record| !record.is_empty()); }

    pub fn note(&mut self, marker: String) {
        self.swept.push(marker);
    }
}