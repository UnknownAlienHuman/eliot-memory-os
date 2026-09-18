// Fixture: static/global Vec growth without removal (issue #885).
// Process-global append with no bound or cleanup in the scanned slice: an
// unbounded candidate, never a request-local row.

use std::sync::Mutex;

pub static SEEN_MODELS: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn note_model(name: String) {
    SEEN_MODELS.push(name);
}
