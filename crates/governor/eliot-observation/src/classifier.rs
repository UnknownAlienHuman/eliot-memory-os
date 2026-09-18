//! Private Governor-owned first-pass record-family classifier.
//!
//! Consumes only the validated, bounded, versioned foundation representation
//! ([`ObservationRecordEnvelopeV2`]) and applies only the mechanical
//! discriminators owned by the foundation contract
//! ([`ObservationRecordEnvelopeV2::classification`] plus
//! [`check_v1_v2_coherence`]). It never inspects free-form prose, recency,
//! producer role, or model judgement, and it never touches
//! `EpistemicStatus`/`Assertability`, evidence authority, influence, task
//! binding, lifecycle, relation, authority, finish, or request/idempotency
//! identity.
//!
//! Donor trace: retains only the small table-driven shape idea from
//! `crates/smart/eliot-memory::classify` — a closed `match` on the
//! already-typed foundation family result, never on hint text. The Smart
//! `MemoryPlane`/`MemoryId`/revision/dedup/retrieval/status/lifecycle/
//! influence/`UnderstandingView` state owner is rejected completely; nothing
//! from that crate is imported here.

use eliot_observation_contracts::{
    ObservationRecordEnvelope, ObservationRecordEnvelopeV2, ObservationRecordKind,
    RecordFamilyClassification, check_v1_v2_coherence,
};

/// Closed private first-pass result over one validated v2 envelope.
///
/// Maps one-to-one onto the foundation evidence without redefining public
/// fields or renaming foundation public types:
/// [`RecordFamilyClassification::Exact`] becomes [`Self::Exact`],
/// [`RecordFamilyClassification::CompatibleHint`] becomes [`Self::CompatibleHint`],
/// [`RecordFamilyClassification::AmbiguousCandidate`] becomes
/// [`Self::AmbiguousPreserveCandidate`], and the typed foundation errors
/// (`FamilyHintConflict`/`ShapeConflict`, or any other validation failure)
/// become [`Self::ConflictingHint`] with the typed error preserved so the
/// existing pre-stage rejection and safe-candidate fallback keep their exact
/// fail-closed identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FirstPassClassification {
    /// Exact field-complete family evidence is present.
    Exact {
        /// Mechanically established family.
        family: ObservationRecordKind,
    },
    /// A caller hint is retained but remains non-exact and cold.
    CompatibleHint {
        /// Caller-selected family retained as a hint.
        hinted_family: ObservationRecordKind,
    },
    /// No exact evidence is available; the record is preserved as a candidate.
    AmbiguousPreserveCandidate,
    /// Mechanical proof contradicts the hint or shape; fail closed.
    ConflictingHint {
        /// Typed foundation error preserved for the existing rejection path.
        error: eliot_observation_contracts::RecordFamilyContractError,
    },
}

/// Classifies one v2 envelope through the foundation mechanical discriminator.
///
/// Total over validated input (every foundation `Ok`/`Err` maps to exactly one
/// closed variant), deterministic, bounded, and side-effect free.
pub(crate) fn classify(record: &ObservationRecordEnvelopeV2) -> FirstPassClassification {
    match record.classification() {
        Ok(RecordFamilyClassification::Exact { family }) => {
            FirstPassClassification::Exact { family }
        }
        Ok(RecordFamilyClassification::CompatibleHint { hinted_family }) => {
            FirstPassClassification::CompatibleHint { hinted_family }
        }
        Ok(RecordFamilyClassification::AmbiguousCandidate) => {
            FirstPassClassification::AmbiguousPreserveCandidate
        }
        Err(error) => FirstPassClassification::ConflictingHint { error },
    }
}

/// Classifies one v1/v2 pair through both foundation mechanical
/// discriminators: fail-closed v1/v2 coherence first, then the v2 table.
///
/// Total, deterministic, bounded, and side-effect free. A coherence failure
/// becomes [`FirstPassClassification::ConflictingHint`] with the typed
/// foundation error preserved; otherwise the result equals [`classify`].
pub(crate) fn classify_coherent(
    v1: &ObservationRecordEnvelope,
    v2: &ObservationRecordEnvelopeV2,
) -> FirstPassClassification {
    if let Err(error) = check_v1_v2_coherence(v1, v2) {
        return FirstPassClassification::ConflictingHint { error };
    }
    classify(v2)
}
