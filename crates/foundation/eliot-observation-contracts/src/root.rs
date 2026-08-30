//! ELIOT observation contracts with an explicit v1 compatibility surface and
//! the field-complete v2 record-family evidence contract.
//!
//! The original `src/lib.rs` remains byte-preserved as the v1 implementation.
//! New code should use `ObservationRecordEnvelopeV2` when exact record-family
//! evidence is required. Generic v1 ordinary records remain compatible hints or
//! ambiguous candidates through `import_legacy_v1`; they are never promoted by
//! event names or prose.

#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod legacy_v1;
pub use legacy_v1::*;

mod record_family_v2;
pub use record_family_v2::*;
