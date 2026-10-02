//! Bounded projection batches with shared-fence gating and coverage.
//!
//! A [`MemoryProjectionBatch`] carries one [`MemoryScopeBinding`]: every
//! record must declare exactly the batch binding — task, scope, session, and
//! the binding's own state fence — and the fence each record was actually read
//! under must be compatible with the batch fence. Those are two different
//! questions, and [`MemoryProjectionBatch::validate`] asks both. The batch also
//! carries the denominator context every consumer needs: how many canonical
//! records the read side observed, what was truncated or omitted, and whether
//! revalidation is required before use.
//!
//! Coverage is accounted exactly, not conservatively. Under a known
//! denominator every observed record lands in exactly one of three places —
//! a projected record, a named omission, or a deferred resume-frontier handle
//! — the three lists are pairwise disjoint, and their combined length equals
//! the denominator. Completeness is therefore a property the batch proves
//! about itself, not a claim a consumer has to take on trust; a remainder that
//! nobody can name is refused at the boundary instead of surfacing later as a
//! quietly short read. A read side that could not establish the denominator
//! says so, and an unprovable denominator is an incomplete state with its own
//! ceiling: it may never travel beside `revalidation_required: false`, and it
//! is never repaired by restating the returned count as the total.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contracts::error::MemoryProjectionError;
use crate::contracts::record::MemoryProjectionRecord;
use crate::contracts::record::MemoryScopeBinding;

/// Hard ceiling on records carried by one projection batch.
///
/// The provider truncates volume beyond this ceiling with an explicit
/// truncated flag and resume frontier, never silently.
pub const MEMORY_PROJECTION_MAX_RECORDS: usize = 256;
/// Hard ceiling on omission entries carried by one batch.
pub const MAX_BATCH_OMISSIONS: usize = 256;
/// Hard ceiling on frontier resume handles carried by one batch.
pub const MAX_BATCH_FRONTIER: usize = 256;

fn text(value: &str, field: &'static str) -> Result<(), MemoryProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MemoryProjectionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Denominator context of a projection batch.
///
/// `Known` is the normal case: the read side counted its observed records.
/// `Unknown` preserves an explicit unknown (A0.4): the batch stays
/// representable, but evaluation fails closed because applicability without a
/// denominator is unprovable. It is not a synonym for a smaller `Known`, and
/// it carries its own mandatory ceiling: an unprovable denominator is an
/// incomplete state, so a batch declaring one may never also declare that no
/// revalidation is required. See
/// [`MemoryProjectionBatch::validate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum DenominatorState {
    /// Exact canonical records observed by the read side.
    #[serde(rename = "KNOWN")]
    Known {
        /// Total observed records: projected, omitted, or deferred to the
        /// resume frontier, counted once each.
        total: usize,
    },
    /// The read side could not establish the denominator, with a reason.
    #[serde(rename = "UNKNOWN")]
    Unknown {
        /// Stable bounded reason class.
        reason: String,
    },
}

impl DenominatorState {
    /// Validate the denominator shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        match self {
            Self::Known { .. } => Ok(()),
            Self::Unknown { reason } => text(reason, "coverage.denominator.reason"),
        }
    }
}

/// One explicitly omitted record: handle plus the rule that omitted it.
///
/// Omissions are never silent loss: fence-incompatible, scope-mismatched, or
/// bound-truncated volume is named here with its exact reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageOmission {
    /// Handle of the omitted record.
    pub handle: eliot_contracts::ArtifactId,
    /// Stable bounded reason class for the omission.
    pub reason: String,
}

impl CoverageOmission {
    /// Validate the omission shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        text(&self.reason, "coverage.omissions.reason")
    }
}

/// Coverage accounting of one projection batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCoverage {
    /// Denominator context of the read side.
    pub denominator: DenominatorState,
    /// Whether volume truncation cut the projected records.
    pub truncated: bool,
    /// Resume handles for truncated volume; nonempty exactly when truncated.
    ///
    /// Each deferred record contributes one handle, so a truncated batch keeps
    /// the exact remainder it did not return and the place to resume from.
    pub frontier: Vec<String>,
    /// Named omissions with exact reasons.
    ///
    /// Handles are distinct from every projected record and from every other
    /// omission, so one observed record can never be both returned and lost.
    pub omissions: Vec<CoverageOmission>,
    /// Whether the consumer must revalidate before use.
    ///
    /// This is the completeness bit a consumer actually reads, so it is not
    /// optional on an incomplete batch. Truncation, any named omission, and an
    /// unprovable ([`DenominatorState::Unknown`]) denominator all force it to
    /// `true`; only a batch that accounts for every member of a known
    /// population may carry `false`.
    pub revalidation_required: bool,
}

impl ProjectionCoverage {
    /// Validate coverage shape (member accounting is checked by the batch,
    /// which sees the carried records).
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        self.denominator.validate()?;
        if self.frontier.len() > MAX_BATCH_FRONTIER {
            return Err(MemoryProjectionError::Bounds {
                field: "coverage.frontier",
            });
        }
        for handle in &self.frontier {
            text(handle, "coverage.frontier")?;
        }
        if self.omissions.len() > MAX_BATCH_OMISSIONS {
            return Err(MemoryProjectionError::Bounds {
                field: "coverage.omissions",
            });
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        Ok(())
    }
}

/// One bounded canonical memory projection read set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryProjectionBatch {
    /// Contract version this batch was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Shared task/scope/session/fence binding every record must satisfy.
    pub binding: MemoryScopeBinding,
    /// Bounded projected records in deterministic provider order.
    pub records: Vec<MemoryProjectionRecord>,
    /// Denominator, truncation, omission, and revalidation context.
    pub coverage: ProjectionCoverage,
}

impl MemoryProjectionBatch {
    /// Validate the batch: shapes, shared-fence gating, scope equality, handle
    /// uniqueness across records, omissions and frontier, and exact disjoint
    /// coverage accounting against a known denominator.
    ///
    /// A `Known` denominator is an equality, not a lower bound: the projected
    /// records, the named omissions and the deferred resume frontier together
    /// account for exactly `total` distinct handles. `Unknown` stays
    /// representable — it claims no count, so nothing here can contradict it,
    /// and the consumers that need a count fail closed on it instead — but it
    /// is an incomplete state rather than an absent one, so it must declare
    /// `revalidation_required` like any other: the ceiling of an unprovable
    /// denominator travels on the batch, and is never discharged by lowering
    /// the denominator to the number of records actually returned.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(MemoryProjectionError::VersionMismatch);
        }
        self.binding.validate()?;
        self.coverage.validate()?;
        if self.records.len() > MEMORY_PROJECTION_MAX_RECORDS {
            return Err(MemoryProjectionError::Bounds {
                field: "batch.records",
            });
        }
        let mut seen = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if !seen.insert(record.handle.as_str().to_owned()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "batch.records",
                    value: record.handle.as_str().to_owned(),
                });
            }
            self.validate_record_scope(record)?;
        }
        // Exact, disjoint member accounting. Every canonical record the read
        // side observed is projected, omitted, or deferred to the resume
        // frontier, and it is exactly one of those three. The same handle may
        // not appear in two of them, and a known denominator must equal the
        // volume those three lists carry — no more, and no less. A total larger
        // than the accounted volume with nothing deferred and nothing omitted
        // is unclaimed completeness, not evidence of it, so it is refused here
        // rather than discovered later by whichever consumer happens to look.
        //
        // This was deliberately stricter than the r7 freeze note at
        // `cognitive-rev12-contract-schema-freeze.toml` ("Known{total} must
        // cover projected plus omitted volume"), which stated a lower bound
        // and never mentioned the frontier, so that note alone was not proof of
        // completeness. It did not grant the remainder either. That divergence
        // is now reconciled rather than left standing: freeze revision r8
        // states this exact disjoint three-way accounting in the
        // `ProjectionCoverage` denominator_note, and the freeze's own
        // [readback] rule required a new candidate rather than an in-place
        // byte edit, so the r7 digest is superseded and every verdict bound to
        // it is invalidated. The rule below and the frozen note are one rule
        // again, at the same revision boundary. That note is still the current
        // one: revision r12 carries the r8 wording verbatim rather than
        // re-deriving it, so this comment names r8 for the correction's origin
        // and not as the artifact a reader would find today.
        for omission in &self.coverage.omissions {
            if !seen.insert(omission.handle.as_str().to_owned()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "coverage.omissions",
                    value: omission.handle.as_str().to_owned(),
                });
            }
        }
        for handle in &self.coverage.frontier {
            if !seen.insert(handle.clone()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "coverage.frontier",
                    value: handle.clone(),
                });
            }
        }
        if let DenominatorState::Known { total } = &self.coverage.denominator {
            let accounted =
                self.records.len() + self.coverage.omissions.len() + self.coverage.frontier.len();
            if accounted != *total {
                return Err(MemoryProjectionError::CoverageMismatch {
                    reason: "known denominator must equal projected plus omitted plus deferred volume",
                });
            }
        }
        // Volume truncation must name where to resume; a frontier without
        // truncation is unclaimed volume and is rejected.
        if self.coverage.truncated && self.coverage.frontier.is_empty() {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "truncated coverage must carry a resume frontier",
            });
        }
        if !self.coverage.truncated && !self.coverage.frontier.is_empty() {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "non-truncated coverage must not carry a frontier",
            });
        }
        // Truncation or omission always requires revalidation before use.
        let must_revalidate = self.coverage.truncated || !self.coverage.omissions.is_empty();
        if must_revalidate && !self.coverage.revalidation_required {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "truncated or lossy coverage requires revalidation",
            });
        }
        // An unprovable denominator is its own incomplete state, and it carries
        // its own ceiling. The exact accounting above cannot run without a
        // count, so `Unknown` leaves precisely the question the exact rule
        // closes: whether an observed member was neither projected, nor named
        // in `omissions`, nor deferred in the frontier. Nothing on the batch
        // can answer it, and the only honest move is to require revalidation,
        // not to substitute a count. Lowering the denominator to the returned
        // record length is the same defect wearing a different hat: it would
        // make the batch recheckable against itself and against nothing else.
        //
        // This is why the rule is a separate check rather than a fourth term in
        // `must_revalidate`: the failure attribution differs. Truncation and
        // omission are visible in the carried lists; an unknown denominator is
        // a declared inability to count, and a consumer reading
        // `revalidation_required: false` beside it is reading an unprovable
        // batch as complete — exactly what the frozen `ProjectionCoverage`
        // denominator_note forbids ("Unknown stays representable but no
        // consumer may read it as completeness").
        if matches!(self.coverage.denominator, DenominatorState::Unknown { .. })
            && !self.coverage.revalidation_required
        {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "an unknown denominator requires revalidation",
            });
        }
        Ok(())
    }

    /// Require one projected record to declare the batch's exact scope and to
    /// have been read under a fence compatible with it.
    ///
    /// Two independent questions are asked, and conflating them is the defect
    /// this gate closes.
    ///
    /// The record's **declared binding** is the scope it claims to belong to.
    /// Task, scope, session, and the binding's own `state_fence` must all equal
    /// the batch binding's. The fence field is compared by exact equality
    /// rather than left to the compatibility relaxation below, because
    /// compatibility is a relaxation and the declared scope is not one: a
    /// record whose declared binding fence differs is asserting a different
    /// scope. Checking only task/scope/session admitted exactly such a record
    /// whenever its own projection fence happened to be compatible, which is the
    /// wrong-scope-record-inside-a-valid-batch case this batch exists to refuse,
    /// and it contradicted the frozen `MemoryProjectionBatch` `denominator_note`,
    /// which requires the record binding to *equal* the batch binding.
    ///
    /// The record's **projection fence** is the fence it was actually read
    /// under, and compatibility is correct for it: a record observed before
    /// the batch's own fence is a legitimate read result, and requiring exact
    /// equality there would reject it. Both checks therefore have their own
    /// named `left`/`right` pair, so a refusal says which of the two failed.
    ///
    /// This is a gate over material the record already carries, not a new
    /// field: no shape, version, or wire surface changes, so the byte-pinned
    /// freeze and the generated serde boundary registry are untouched. The
    /// existing typed errors are reused rather than new variants added, and the
    /// distinction stays legible — an identity disagreement is
    /// [`MemoryProjectionError::ScopeMismatch`] and every fence disagreement is
    /// [`MemoryProjectionError::FenceMismatch`], so a consumer matching on the
    /// variant still refuses.
    fn validate_record_scope(
        &self,
        record: &MemoryProjectionRecord,
    ) -> Result<(), MemoryProjectionError> {
        if record.binding.task_id != self.binding.task_id
            || record.binding.scope_id != self.binding.scope_id
            || record.binding.session_id != self.binding.session_id
        {
            return Err(MemoryProjectionError::ScopeMismatch {
                reason: "record binding must equal the batch binding",
            });
        }
        if record.binding.state_fence != self.binding.state_fence {
            return Err(MemoryProjectionError::FenceMismatch {
                left: "record.binding.state_fence",
                right: "batch.binding.state_fence",
            });
        }
        if !record
            .state_fence
            .is_compatible_with(&self.binding.state_fence)
        {
            return Err(MemoryProjectionError::FenceMismatch {
                left: "record.state_fence",
                right: "batch.binding.state_fence",
            });
        }
        Ok(())
    }
}
