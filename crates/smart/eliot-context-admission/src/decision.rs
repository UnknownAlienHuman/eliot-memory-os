//! Canonical closed retrieval-admission decision outcomes (I12.26).
//!
//! [`RetrievalAdmissionDecision`] is the typed `MemoryAdmissionDecision`
//! outcome set from I12.26 ("Memory admission and retrieval trace"): exactly
//! `include_exact`, `include_handle`, `include_with_warning`,
//! `require_revalidation`, `suppress`, and `quarantine`. It is a closed
//! operational result, never a confidence scalar, and it is derived by the
//! retrieval/admission owner from scope and State Fence, epistemic
//! status/freshness, source assurance, expected decision delta,
//! contradiction risk, cost, and repetition — never accepted from
//! bridge/model output.
//!
//! Boundary note: `eliot_types::MemoryAdmissionDecision` (memory-influence
//! vocabulary: `IncludeVerified`, `IncludeSupported`, and related variants)
//! is a separate pre-existing projection contract with different semantics.
//! This type does not replace it, duplicate its variants, or convert into it
//! (no `From`/`Into` bridge); convergence of the two vocabularies is owned
//! separately with the cognition contract owner. Likewise,
//! `eliot_context_contracts::AdmissionDisposition` remains the per-candidate
//! membership disposition; no mapping between the two sets is defined here
//! because I12.26 defines none.

#![forbid(unsafe_code)]

/// Closed retrieval-admission outcome for one evaluated candidate.
///
/// Exactly the six I12.26 outcomes. Wire spelling is `SCREAMING_SNAKE_CASE`,
/// matching the existing closed outcome enums (`RecallDisposition`,
/// `AdmissionDisposition`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetrievalAdmissionDecision {
    /// Admit the exact unit for direct use.
    IncludeExact,
    /// Admit a handle only; content loads through explicit expansion.
    IncludeHandle,
    /// Admit with an explicit warning attached (framing, staleness bound,
    /// or contradiction risk that stays below suppression).
    IncludeWithWarning,
    /// Withhold until the candidate is revalidated against current
    /// source/projection revisions and the State Fence.
    RequireRevalidation,
    /// Withhold under policy; suppression is explicit, never inferred.
    Suppress,
    /// Isolate as potentially harmful; never silently injectable.
    Quarantine,
}

impl RetrievalAdmissionDecision {
    /// Canonical wire value for this outcome.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::IncludeExact => "INCLUDE_EXACT",
            Self::IncludeHandle => "INCLUDE_HANDLE",
            Self::IncludeWithWarning => "INCLUDE_WITH_WARNING",
            Self::RequireRevalidation => "REQUIRE_REVALIDATION",
            Self::Suppress => "SUPPRESS",
            Self::Quarantine => "QUARANTINE",
        }
    }

    /// The exact six canonical wire values, in I12.26 contract order.
    #[must_use]
    pub const fn canonical_set() -> [&'static str; 6] {
        [
            "INCLUDE_EXACT",
            "INCLUDE_HANDLE",
            "INCLUDE_WITH_WARNING",
            "REQUIRE_REVALIDATION",
            "SUPPRESS",
            "QUARANTINE",
        ]
    }

    /// Resolve an exact canonical wire value to its outcome.
    ///
    /// Only the six [`Self::canonical_set`] spellings resolve; anything else
    /// — including historical confidence labels — returns `None` rather than
    /// coercing to a nearby outcome.
    #[must_use]
    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "INCLUDE_EXACT" => Some(Self::IncludeExact),
            "INCLUDE_HANDLE" => Some(Self::IncludeHandle),
            "INCLUDE_WITH_WARNING" => Some(Self::IncludeWithWarning),
            "REQUIRE_REVALIDATION" => Some(Self::RequireRevalidation),
            "SUPPRESS" => Some(Self::Suppress),
            "QUARANTINE" => Some(Self::Quarantine),
            _ => None,
        }
    }
}
