//! Stable, redacted failures for the A-12 boundary.
use thiserror::Error;

/// A-12 validation failure. Caller payloads are never interpolated.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CueBindingError {
    #[error("input bound exceeded at {field}")]
    Bound { field: &'static str },
    #[error("invalid contract at {field}")]
    Contract { field: &'static str },
    #[error("missing evidence for {field}")]
    MissingEvidence { field: &'static str },
    #[error("binding identity conflict at {field}")]
    IdentityConflict { field: &'static str },
    #[error("unsupported cue kind at {field}")]
    UnsupportedKind { field: &'static str },
    #[error("canonicalization failed at {field}")]
    Canonicalization { field: &'static str },
}
