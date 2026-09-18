//! Independent ceilings for the pure synthesis operation.
//!
//! Every bound is enforced separately and a one-over breach preserves the
//! exact omitted denominator instead of silently truncating.

/// Candidate schema revision implemented by this owner.
pub const SYNTHESIS_SCHEMA_REVISION: u32 = 1;

/// Closed job-class wire spelling accepted by this owner.
pub const SYNTHESIS_JOB_CLASS: &str = "research-synthesis";

/// Byte ceiling for one canonical input envelope.
pub const MAX_SYNTHESIS_INPUT_BYTES: u64 = 1_048_576;

/// Byte ceiling for one canonical output envelope.
pub const MAX_SYNTHESIS_OUTPUT_BYTES: u64 = 1_048_576;

/// Ceiling for identity/handle text fields.
pub const MAX_HANDLE_BYTES: usize = 256;

/// Ceiling for prose text fields (questions, positions, notes).
pub const MAX_TEXT_BYTES: usize = 8_192;

/// Ceiling for governed sources per pack.
pub const MAX_SOURCES: usize = 64;

/// Ceiling for material claims per draft.
pub const MAX_CLAIMS: usize = 128;

/// Ceiling for evidence references per claim (support plus counterclaims).
pub const MAX_REFERENCES_PER_CLAIM: u64 = 32;

/// Ceiling for rival positions per draft.
pub const MAX_RIVALS: usize = 64;

/// Ceiling for unknown entries per draft.
pub const MAX_UNKNOWNS: usize = 64;

/// Ceiling for probe proposals per draft.
pub const MAX_PROBES: usize = 64;

/// Ceiling for outcome alternatives that keep a probe discriminative.
pub const MAX_PROBE_OUTCOMES: u64 = 16;

/// Default work budget when the caller binds its own limits.
pub const DEFAULT_MAX_WORK: u64 = 100_000;

/// Characters of a field value retained in diagnostics; the rest is redacted.
pub const DIAGNOSTIC_VALUE_PREFIX: usize = 64;

/// Marker recorded when a diagnostic value is cut by the redaction ceiling.
pub const REDACTED_SUFFIX: &str = "[redacted]";
