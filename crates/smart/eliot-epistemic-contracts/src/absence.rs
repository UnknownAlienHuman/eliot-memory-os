//! Scoped absence: proving a negative over a complete denominator.
//!
//! An [`AbsenceClaim`] states that a proposition has no match inside an exact domain, scope, time window, and
//! version. Absence needs a complete denominator plus a terminal receipt; a no-match probe, timeout, silence,
//! or exhausted budget never decodes as absence. Shape validation ties the claim to its receipt; closed
//! validation ([`AbsenceClaim::validate_closed`]) binds the exact frozen [`CoverageDenominator`] object, and
//! query, scope, fence, or snapshot drift invalidates the claim via [`AbsenceClaim::check_context`].

use std::collections::BTreeSet;

use eliot_contracts::{SourceId, StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::coverage::{CoverageDenominator, DenominatorKind, check_receipt_query_frontier};
use crate::error::{
    ContractError, MAX_PROOF_BYTES, MAX_SHORT_TEXT, check_frozen, shape_digest,
    validate_bounded_text, validate_digest,
};
use crate::identity::PropositionId;
use crate::receipt::CoverageReceipt;

/// Owner lookup proving who admits the scope an absence is claimed over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerLookup {
    /// Owner admitting the scope revision.
    pub owner: SourceId,
    /// Digest of the bounded lookup proof.
    pub lookup_proof: String,
}

impl OwnerLookup {
    /// Constructs an owner lookup after validation.
    pub fn new(owner: SourceId, lookup_proof: impl Into<String>) -> Result<Self, ContractError> {
        let lookup = Self {
            owner,
            lookup_proof: lookup_proof.into(),
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Validates the owner binding and lookup proof digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_digest(&self.lookup_proof, "absence.lookup_proof")?;
        Ok(())
    }

    /// Recomputes the expected lookup proof binding the actual denominator
    /// and receipt proofs.
    pub fn expected_proof(
        owner: &SourceId,
        denominator_digest: &str,
        receipt_proof: &str,
    ) -> Result<String, ContractError> {
        shape_digest(&(owner, denominator_digest, receipt_proof))
    }

    /// Validates this lookup against the actual denominator and receipt
    /// proofs it cites.
    pub fn validate_binding(
        &self,
        denominator_digest: &str,
        receipt_proof: &str,
    ) -> Result<(), ContractError> {
        self.validate()?;
        let expected = Self::expected_proof(&self.owner, denominator_digest, receipt_proof)?;
        if self.lookup_proof != expected {
            return Err(ContractError::DigestMismatch {
                field: "absence.lookup_proof",
            });
        }
        Ok(())
    }
}

/// A bounded proof payload reference: digest plus byte length ceiling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundedProof {
    /// Digest of the bounded proof payload.
    pub digest: String,
    /// Length of the proof payload in bytes.
    pub byte_len: u64,
}

impl BoundedProof {
    /// Constructs a bounded proof reference after validation.
    pub fn new(digest: impl Into<String>, byte_len: u64) -> Result<Self, ContractError> {
        let proof = Self {
            digest: digest.into(),
            byte_len,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Validates the digest form and the byte length ceiling.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_digest(&self.digest, "absence.proof_digest")?;
        if self.byte_len > MAX_PROOF_BYTES {
            return Err(ContractError::OutOfRange {
                field: "absence.proof_bytes",
            });
        }
        Ok(())
    }
}

/// A scoped absence claim over a complete denominator and terminal receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AbsenceClaim {
    /// Proposition claimed absent.
    pub proposition: PropositionId,
    /// Exact domain the absence is claimed over; must equal the frozen
    /// denominator member class.
    pub domain: String,
    /// Exact schema the absence is claimed under; must equal the frozen
    /// denominator schema.
    pub schema: String,
    /// Exact scope the absence is claimed over.
    pub scope: String,
    /// Start of the absence window in Unix milliseconds, when bounded.
    pub window_start_ms: Option<i64>,
    /// End of the absence window in Unix milliseconds, when bounded.
    pub window_end_ms: Option<i64>,
    /// Source or protocol version the absence is claimed under.
    pub version: String,
    /// Task binding of the inquiry.
    pub task_id: TaskId,
    /// Policy revision admitting the enumeration, in exact form.
    pub policy: String,
    /// Owner lookup admitting the scope revision.
    pub owner_lookup: OwnerLookup,
    /// Canonical digest of the complete denominator.
    pub denominator_digest: String,
    /// Kind of the denominator; only complete scope grounds absence.
    pub denominator_kind: DenominatorKind,
    /// Frozen query digest the denominator was enumerated under.
    pub query_digest: String,
    /// Frozen snapshot identity the denominator was enumerated from.
    pub snapshot_id: String,
    /// Terminal receipt closing every enumerated member.
    pub receipt: CoverageReceipt,
    /// Bounded proof behind the absence claim.
    pub proof: BoundedProof,
    /// Canonical digest of the absence shape, excluding this field.
    pub digest: String,
}

impl AbsenceClaim {
    /// Constructs an absence claim and freezes its canonical digest (shape closure only; binding to the
    /// frozen denominator object is deferred to [`AbsenceClaim::validate_closed`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposition: PropositionId,
        domain: impl Into<String>,
        schema: impl Into<String>,
        scope: impl Into<String>,
        window_start_ms: Option<i64>,
        window_end_ms: Option<i64>,
        version: impl Into<String>,
        task_id: TaskId,
        policy: impl Into<String>,
        owner_lookup: OwnerLookup,
        denominator_digest: impl Into<String>,
        denominator_kind: DenominatorKind,
        query_digest: impl Into<String>,
        snapshot_id: impl Into<String>,
        receipt: CoverageReceipt,
        proof: BoundedProof,
    ) -> Result<Self, ContractError> {
        let mut claim = Self {
            proposition,
            domain: domain.into(),
            schema: schema.into(),
            scope: scope.into(),
            window_start_ms,
            window_end_ms,
            version: version.into(),
            task_id,
            policy: policy.into(),
            owner_lookup,
            denominator_digest: denominator_digest.into(),
            denominator_kind,
            query_digest: query_digest.into(),
            snapshot_id: snapshot_id.into(),
            receipt,
            proof,
            digest: String::new(),
        };
        claim.validate_shape()?;
        claim.digest = claim.compute_digest()?;
        Ok(claim)
    }

    /// Recomputes the canonical digest of the absence shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.proposition,
            &self.domain,
            &self.schema,
            &self.scope,
            &self.window_start_ms,
            &self.window_end_ms,
            &self.version,
            &self.task_id,
            &self.policy,
            &self.owner_lookup,
            &self.denominator_digest,
            &self.denominator_kind,
            &self.query_digest,
            &self.snapshot_id,
            &self.receipt,
            &self.proof,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.domain, "absence.domain", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.schema, "absence.schema", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "absence.scope", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.version, "absence.version", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.policy, "absence.policy", MAX_SHORT_TEXT)?;
        if let (Some(start), Some(end)) = (self.window_start_ms, self.window_end_ms)
            && end < start
        {
            return Err(ContractError::InvertedInterval {
                field: "absence.window",
            });
        }
        self.owner_lookup.validate()?;
        validate_digest(&self.denominator_digest, "absence.denominator_digest")?;
        if self.denominator_kind != DenominatorKind::CompleteScope {
            return Err(ContractError::IncompleteDenominator {
                field: "absence.denominator_kind",
            });
        }
        validate_digest(&self.query_digest, "absence.query_digest")?;
        validate_bounded_text(&self.snapshot_id, "absence.snapshot_id", MAX_SHORT_TEXT)?;
        self.receipt.validate()?;
        if self.receipt.denominator != self.denominator_digest {
            return Err(ContractError::DigestMismatch {
                field: "absence.denominator_digest",
            });
        }
        if self.receipt.scope != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "absence.scope",
            });
        }
        if self.receipt.task_id != self.task_id {
            return Err(ContractError::TaskMismatch {
                field: "absence.task_id",
            });
        }
        if self.receipt.policy != self.policy {
            return Err(ContractError::ImpossibleCombination {
                field: "absence.policy",
            });
        }
        if !self.receipt.is_terminal() {
            return Err(ContractError::ImpossibleCombination {
                field: "absence.receipt",
            });
        }
        self.proof.validate()?;
        Ok(())
    }

    /// Validates the absence shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "absence.digest")
    }

    /// Closes the claim against the exact frozen denominator it cites (denominator,
    /// snapshot/scope, and member-arithmetic checks below).
    pub fn validate_closed(&self, denominator: &CoverageDenominator) -> Result<(), ContractError> {
        self.validate()?;
        denominator.validate()?;
        self.check_denominator(denominator)?;
        self.check_scope(denominator)?;
        self.check_members(denominator)?;
        Ok(())
    }

    fn check_denominator(&self, denominator: &CoverageDenominator) -> Result<(), ContractError> {
        if self.denominator_digest != denominator.digest {
            return Err(ContractError::DigestMismatch {
                field: "absence.denominator_digest",
            });
        }
        if self.denominator_kind != denominator.kind {
            return Err(ContractError::IncompleteDenominator {
                field: "absence.denominator_kind",
            });
        }
        check_receipt_query_frontier(
            denominator,
            &self.receipt,
            "absence.query_digest",
            "absence.frontier",
        )?;
        let frozen_query = shape_digest(&self.receipt.query)?;
        if self.query_digest != frozen_query {
            return Err(ContractError::DigestMismatch {
                field: "absence.query_digest",
            });
        }
        Ok(())
    }

    fn check_scope(&self, denominator: &CoverageDenominator) -> Result<(), ContractError> {
        if self.domain != denominator.class {
            return Err(ContractError::ScopeMismatch {
                field: "absence.domain",
            });
        }
        if self.schema != denominator.schema {
            return Err(ContractError::ScopeMismatch {
                field: "absence.schema",
            });
        }
        if self.snapshot_id != denominator.snapshot.snapshot_id {
            return Err(ContractError::StaleContext {
                field: "absence.snapshot",
            });
        }
        if self.owner_lookup.owner != denominator.snapshot.owner {
            return Err(ContractError::OutsideManifest {
                field: "absence.owner_lookup",
            });
        }
        self.owner_lookup.validate_binding(
            denominator.digest.as_str(),
            self.receipt.proof_digest.as_str(),
        )?;
        if self.scope != denominator.scope || self.scope != denominator.validity.scope {
            return Err(ContractError::ScopeMismatch {
                field: "absence.scope",
            });
        }
        if (self.window_start_ms, self.window_end_ms)
            != (
                denominator.validity.window_start_ms,
                denominator.validity.window_end_ms,
            )
        {
            return Err(ContractError::StaleContext {
                field: "absence.window",
            });
        }
        if self.version != denominator.validity.version {
            return Err(ContractError::StaleContext {
                field: "absence.version",
            });
        }
        if !denominator.fence.is_compatible_with(&self.receipt.fence)
            || !self.receipt.fence.is_compatible_with(&denominator.fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "absence.fence",
            });
        }
        Ok(())
    }

    fn check_members(&self, denominator: &CoverageDenominator) -> Result<(), ContractError> {
        if self.receipt.denominator_size != denominator.members.len() as u64 {
            return Err(ContractError::ArithmeticMismatch {
                field: "absence.denominator_size",
            });
        }
        let frozen_members: BTreeSet<_> = denominator.members.iter().collect();
        let receipt_members: BTreeSet<_> = self
            .receipt
            .members
            .iter()
            .map(|outcome| &outcome.member)
            .collect();
        if receipt_members != frozen_members {
            if !receipt_members.is_subset(&frozen_members) {
                return Err(ContractError::OutsideManifest {
                    field: "absence.receipt",
                });
            }
            return Err(ContractError::MissingReference {
                field: "absence.receipt",
            });
        }
        if !self.receipt.omissions.is_empty() || !self.receipt.is_terminal() {
            return Err(ContractError::ImpossibleCombination {
                field: "absence.receipt",
            });
        }
        Ok(())
    }

    /// Checks the claim against live context; any drift invalidates it
    /// ([`ContractError::StaleContext`]).
    pub fn check_context(
        &self,
        scope: &str,
        fence: &StateFence,
        query_digest: &str,
        snapshot_id: &str,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if self.scope != scope
            || self.query_digest != query_digest
            || self.snapshot_id != snapshot_id
            || !self.receipt.fence.is_compatible_with(fence)
        {
            return Err(ContractError::StaleContext {
                field: "absence.context",
            });
        }
        Ok(())
    }
}
