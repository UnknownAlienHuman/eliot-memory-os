// Fixture: immutable DTO (issue #885).
// Scalar-only record with no collection field and no growth callsite. The
// scanner must not treat it as mutable growth: it yields zero candidates.

pub struct ModelQueryHit {
    pub model: String,
    pub score: f64,
    pub rank: u64,
    pub admitted: bool,
}
