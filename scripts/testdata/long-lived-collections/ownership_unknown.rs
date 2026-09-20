// Fixture: ownership/lifetime unknown (issue #885).
// Collection-typed fields with no growth callsite in the scanned slice.

use std::collections::BTreeMap;

pub struct CatalogEntry {
    pub tags: Vec<String>,
    pub scores: BTreeMap<String, f64>,
}
