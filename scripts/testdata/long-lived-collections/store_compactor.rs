// Fixture: external compaction owner for CompactStore.records (issue #885).
// The retain callsite lives outside the declaring file: cross-file removal
// evidence. The compactor's own marker buffer is tracked as a separate row.

pub struct StoreCompactor {
    swept: Vec<String>,
}

impl StoreCompactor {
    pub fn compact(store: &mut CompactStore) { store.records.retain(|record| !record.is_empty()); }

    pub fn note(&mut self, marker: String) {
        self.swept.push(marker);
    }
}
