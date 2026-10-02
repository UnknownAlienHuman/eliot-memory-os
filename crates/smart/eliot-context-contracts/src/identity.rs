//! Canonical identity and source lineage used by every Context stage.

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, ContractVersion, DecisionId, OperationId, StateFence, TaskId, TaskRevision,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextError, validate_digest, validate_text};

/// Stable identity of the Context contract family.
pub const CONTEXT_CONTRACT_NAME: &str = "eliot.smart.context-contracts";
/// Current closed wire version.
pub const CONTEXT_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// A validated provider identity. Providers are labels in this contract; they
/// do not receive authority or become mutable owners.
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "String")]
pub struct ProviderId(String);

impl ProviderId {
    /// Construct a bounded provider identity.
    pub fn new(value: impl Into<String>) -> Result<Self, ContextError> {
        let value = value.into();
        validate_text(&value, "provider_id")?;
        if value.chars().count() > 128 {
            return Err(ContextError::Bounds {
                field: "provider_id",
            });
        }
        Ok(Self(value))
    }

    /// Return the canonical provider text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderId {
    type Error = ContextError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Semantic role of a whole Context unit — and, by decision, the CLOSED PROVIDER
/// CLASS SET of the Context family.
///
/// #196 membership decision: the provider axis IS the semantic role axis.
///
/// There is no second provider-class axis. The canonical pair names one closed
/// class axis over a context unit and names it twice, under two field labels:
///
/// - `docs/architecture/I07-11-context-payload-profiles-and-decision-safety-floor.md:5-15`
///   closes it as `ContextAtomPolicy.class`, enumerating
///   `AUTHORITY | GOAL | SCOPE | ACCEPTANCE | SOURCE | VERIFIER |
///   MATERIAL_UNKNOWN | NEGATIVE | SECURITY | OPTIONAL`;
/// - `docs/architecture/I12-13-context-compiler.md:55,59` budgets the same axis
///   as `ContextSectionBudget.semantic_role` — "Each semantic role is budgeted
///   in whole, addressable units rather than arbitrary token slices".
///
/// Neither document attaches a class to the PROVIDER. The provider identity is
/// [`ProviderId`], a validated free-text LABEL, and the class of what it
/// supplied is the role carried on [`ProviderRole`]. So the closed set this
/// enum declares IS the closed provider class set, and a separate provider
/// class enum is not owed and must not be created.
///
/// # Which members, and why fourteen
///
/// The documents do not name seven. `I7.11`'s enumeration names ten; the four
/// further members below are each required by normative prose in the same two
/// documents, so the closed set is their closure rather than one sentence of
/// one list:
///
/// - `CONFLICT` — `I7.11:23` "material unknowns, conflicts and negative
///   memory", `I7.11:25` "active recovery/conflict/security directives", and
///   `I12.13:96` "visibility of rivals, conflicts and unknowns";
/// - `CONSTRAINT` — `I7.11:5` "Every packet atom has a loss policy" together
///   with the `DecisionSafetyFloor` at `I7.11:17-25`, and `I12.13:7` "Critical
///   Attention and hard constraints";
/// - `INSTRUCTION` — `I12.13:100` "`instruction_sufficiency`: governing
///   instructions, active directives, non-goals and applicable negative
///   memory";
/// - `EVIDENCE` — `I12.13:12` "exact evidence and unknowns" and the
///   `PacketQualityScorecard` at `I12.13:89-103`.
///
/// # The seven-class claim is retired, and where the real catalogue is
///
/// Issue #196 §2 asserts a closed seven-class provider set from
/// `cognitive-rev12-coverage.toml`. That file has never existed in this
/// repository: `git grep -rn "cognitive-rev12-coverage"` returns nothing and
/// `git log --all -S "cognitive-rev12-coverage"` returns no commit. The real
/// catalogue is `crates/smart/cognitive-rev12-contract-schema-freeze.toml`,
/// which carries the claim as `[[not_frozen]] name = "rev12 closed seven-class
/// provider enum"` and as `[[family_disposition]] family =
/// "F6-rev12-closed-seven-class-provider-enum"`; that file is byte-pinned, so
/// this doc comment is the owner-side record and the freeze rows are corrected
/// in the repin that owns them. The seven member names in the issue body
/// (`GoalTask`, `CriticalAttention`, `EpistemicPosition`, `MemoryRecall`,
/// `AuthorityAffordance`, `SelfModel`, `DecisionTail`) name no referent on
/// `main` either. Four of them (`GoalTask`, `MemoryRecall`, `AuthorityAffordance`,
/// `SelfModel`) have no referent at all: `git grep -w` over the whole tree
/// returns only this paragraph. The other three collide with live owners of
/// their own — `DecisionTail` is already a member of `HeadroomConsumer` in this
/// same crate (`src/headroom.rs:206`) and a `ContextRole` in `eliot-context`
/// (`crates/smart/eliot-context/src/lib.rs:231`), and `CriticalAttention` is a
/// `ReviewEscalationOwner` in the Kernel
/// (`bins/eliot-kernel/src/anchored_review.rs:870`) and a Store read name —
/// so admitting any of them here would give one name two meanings across two
/// owners. Per the #196 C1 card, no old names are added for matching words.
///
/// # Closedness is enforced, not documented
///
/// The enum carries no catch-all variant, so an undeclared wire value fails to
/// decode rather than defaulting; and `ContextRecipe::validate` refuses a
/// required rule with no matching mandatory class as
/// `ContextError::DenominatorMismatch`
/// (`crates/smart/eliot-context-contracts/src/atom.rs:298`).
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticRole {
    Authority,
    Goal,
    Scope,
    Acceptance,
    Source,
    Verifier,
    MaterialUnknown,
    Negative,
    Security,
    Evidence,
    Instruction,
    Optional,
    Conflict,
    Constraint,
}

/// Provider/semantic-role slot in the exact requested denominator.
///
/// This is a SLOT, not a class: `provider` says which provider label supplied
/// the unit and `role` says in which semantic class. Per #196, the closed
/// provider class set IS [`SemanticRole`] — there is no separate provider-class
/// enum, so a slot can never name a class this struct cannot carry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRole {
    /// Provider that owns the projection.
    pub provider: ProviderId,
    /// Semantic role supplied by that provider.
    pub role: SemanticRole,
}

impl ProviderRole {
    /// Validate the slot identity.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.provider.as_str(), "provider_role.provider")
    }
}

/// Canonical foundation identity binding shared by packet, candidate, set,
/// view and receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextBinding {
    /// Durable task identity.
    pub task_id: TaskId,
    /// Attempt identity owned by the agent contract.
    pub attempt_id: AgentAttemptId,
    /// Exact work scope.
    pub scope_id: WorkScopeId,
    /// Fence that all material must satisfy.
    pub state_fence: StateFence,
    /// Decision identity for this compilation.
    pub decision_id: DecisionId,
    /// Idempotent operation identity, when a request is being observed.
    pub operation_id: Option<OperationId>,
}

impl ContextBinding {
    /// Validate all identity-bearing dependencies.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.scope_id.as_str(), "scope_id")?;
        validate_text(self.attempt_id.as_str(), "attempt_id")?;
        validate_text(self.task_id.as_str(), "task_id")?;
        validate_text(self.decision_id.as_str(), "decision_id")?;
        if let Some(operation) = &self.operation_id {
            validate_text(operation.as_str(), "operation_id")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        if self.scope_id.as_str().chars().count() > 256 {
            return Err(ContextError::Bounds { field: "scope_id" });
        }
        Ok(())
    }
}

/// Immutable source snapshot lineage for a whole atom.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    /// Stable source owner identity.
    pub source_id: eliot_contracts::SourceId,
    /// Source owner/provider label.
    pub owner: ProviderId,
    /// Snapshot identity within the source owner.
    pub snapshot_id: ArtifactId,
    /// Source revision used for this snapshot.
    pub revision: String,
    /// Content digest of the complete source snapshot.
    pub content_sha256: String,
    /// Prior snapshot in the immutable lineage.
    pub predecessor: Option<ArtifactId>,
}

impl SourceSnapshot {
    /// Validate source lineage and canonical digest shape.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.revision, "source.revision")?;
        validate_digest(&self.content_sha256, "source.content_sha256")?;
        validate_text(self.owner.as_str(), "source.owner")?;
        if self.predecessor.as_ref() == Some(&self.snapshot_id) {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// A reference to a decision revision used by an omission or measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRevision {
    /// Context decision binding.
    pub decision_id: DecisionId,
    /// Recipe revision under which it was admitted.
    pub recipe_revision: TaskRevision,
    /// Canonical digest of the decision policy.
    pub policy_sha256: String,
}

impl DecisionRevision {
    /// Validate decision revision identity.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_digest(&self.policy_sha256, "decision.policy_sha256")
    }
}

/// A compact identity/proof ceiling reference used by contract records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofBinding {
    /// Source evidence identity.
    pub evidence_id: ArtifactId,
    /// Maximum claim this package can support.
    pub ceiling: ProofCeiling,
}
