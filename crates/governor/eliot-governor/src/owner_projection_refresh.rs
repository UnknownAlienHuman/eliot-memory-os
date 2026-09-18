//! Coherence checks for live Governor owner-projection refresh.
//!
//! T1.1 (issue #18): pure helpers used by
//! `crate::GovernorComposition::refresh_from_kernel`. They compare real
//! Kernel-owned evidence and fail closed. They never fabricate state, infer a
//! new generation, authorize a write, or select a recovery path; every
//! mismatch is reported as typed evidence that the caller converts into
//! `crate::CompositionError::Recovery`, keeping the previously published
//! projection untouched.

use eliot_contracts::StateFence;
use eliot_store_api::ScopeRevisionView;

use crate::CompositionError;

/// Typed outcome of one canonical-head coherence comparison.
///
/// The outcome is deliberately not a bare boolean: `Churned` carries the exact
/// mismatch so the caller fails closed with evidence instead of a silent
/// false success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HeadCoherence {
    /// Both scope reads observed one stable head set under the active fence.
    Coherent,
    /// The heads moved between reads; publication is blocked.
    Churned {
        /// Exact mismatch that blocked publication.
        detail: String,
    },
}

/// Compares the pre/post canonical scope reads of one refresh.
///
/// Both views must validate through the existing
/// `ScopeRevisionView::validate` checks, stay bound to `expected_fence`, keep
/// one scope identity, and agree on every revision and ordering head. Any
/// movement returns `Churned`; only a fully stable pair is `Coherent`.
pub(crate) fn compare_scope_heads(
    before: &ScopeRevisionView,
    after: &ScopeRevisionView,
    expected_fence: &StateFence,
) -> HeadCoherence {
    if let Err(error) = before.validate() {
        return HeadCoherence::Churned {
            detail: format!("pre-read canonical scope is invalid: {error}"),
        };
    }
    if let Err(error) = after.validate() {
        return HeadCoherence::Churned {
            detail: format!("post-read canonical scope is invalid: {error}"),
        };
    }
    if before.state_fence != *expected_fence || after.state_fence != *expected_fence {
        return HeadCoherence::Churned {
            detail: "canonical scope reads are not bound to the active fence".to_owned(),
        };
    }
    if before.scope_id != after.scope_id {
        return HeadCoherence::Churned {
            detail: "canonical scope identity moved between reads".to_owned(),
        };
    }
    if before.revision_heads != after.revision_heads {
        return HeadCoherence::Churned {
            detail: "canonical revision heads moved mid-read; revision churn blocks publication"
                .to_owned(),
        };
    }
    if before.ordering_heads != after.ordering_heads {
        return HeadCoherence::Churned {
            detail: "canonical ordering heads moved mid-read; revision churn blocks publication"
                .to_owned(),
        };
    }
    HeadCoherence::Coherent
}

/// Converts a head-coherence outcome into the fail-closed refresh result.
pub(crate) fn coherence_result(outcome: HeadCoherence) -> Result<(), CompositionError> {
    match outcome {
        HeadCoherence::Coherent => Ok(()),
        HeadCoherence::Churned { detail } => Err(CompositionError::Recovery(detail)),
    }
}
