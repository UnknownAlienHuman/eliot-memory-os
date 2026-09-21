//! I14.14 module-generation cutover ownership (issue #1950, R1950 remainder).
//!
//! The thin [`eliot_runtime_contracts::GenerationCutoverRecord`] envelope
//! already stages and commits a route switch through the canonical ORS
//! operational projections. That envelope does not carry the durable
//! ownership fields I14.14 requires: immutable artifact identity, a declared
//! [`CapabilityRouteScope`] with a stable route-scope hash, the in-flight
//! disposition set, the state-migration decision, the health/readiness proof
//! reference, or the rollback boundary. Without them a restart cannot prove
//! that exactly one generation owns new effect admission for a route scope.
//!
//! This module owns the enriched Kernel/ORS cutover schemas. The ORS commit
//! in [`crate::RedbRecoveryStore`] is the durable linearization point: crash
//! before it leaves the old route active, crash after it reconstructs the
//! candidate route and its fencing from the committed record before any work
//! is accepted. Rollback is another cutover with a newer epoch; an old epoch
//! is never reactivated.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use eliot_runtime_contracts::GenerationCutoverState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::{OrsError, sha256_hex, validate_digest, validate_text};

/// Maximum retained in-flight dispositions on one cutover record.
pub const MAX_CUTOVER_IN_FLIGHT: usize = 256;
/// Maximum retained unresolved scopes on one cutover record.
pub const MAX_CUTOVER_UNRESOLVED_SCOPES: usize = 64;

/// Immutable module artifact identity for one cutover side.
///
/// Mirrors the I14.14 artifact layout
/// `modules/<module_id>/<semver>/<artifact_hash>/` without interpreting
/// packaging semantics; ORS stores the identity opaquely and binds it to the
/// cutover lineage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleArtifactIdentity {
    /// Stable module identity.
    pub module_id: String,
    /// Immutable module revision.
    pub semver: String,
    /// Content-addressed artifact digest (lowercase SHA-256).
    pub artifact_hash: String,
    /// Manifest digest (lowercase SHA-256).
    pub manifest_digest: String,
    /// Artifact layout root, e.g. `modules/<module_id>/<semver>/<hash>`.
    pub layout_root: String,
}

impl ModuleArtifactIdentity {
    /// Validates identity text, digest shapes, and the layout binding.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "cutover_artifact_module_id")?;
        validate_text(&self.semver, "cutover_artifact_semver")?;
        validate_semver(&self.semver)?;
        validate_digest(&self.artifact_hash, "cutover_artifact_hash")?;
        validate_digest(&self.manifest_digest, "cutover_artifact_manifest_digest")?;
        validate_text(&self.layout_root, "cutover_artifact_layout_root")?;
        let expected = format!(
            "modules/{}/{}/{}",
            self.module_id, self.semver, self.artifact_hash
        );
        if self.layout_root != expected {
            return Err(OrsError::InvalidField {
                field: "cutover_artifact_layout_root",
                reason: "must be modules/<module_id>/<semver>/<artifact_hash>",
            });
        }
        Ok(())
    }
}

fn validate_semver(value: &str) -> Result<(), OrsError> {
    if value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(OrsError::InvalidField {
            field: "cutover_artifact_semver",
            reason: "must be a bounded dot-separated revision",
        });
    }
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() < 2 || parts.iter().any(|part| part.is_empty()) {
        return Err(OrsError::InvalidField {
            field: "cutover_artifact_semver",
            reason: "must be a bounded dot-separated revision",
        });
    }
    Ok(())
}

/// Declared capability route scope of one cutover.
///
/// A cutover never pretends that every operation in a process changes owner
/// at one instant; it switches exactly one module plus capability plus
/// affected work scope plus effect domain, addressed by a stable hash.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRouteScope {
    /// Owning module identity.
    pub module_id: String,
    /// Capability whose route is switched.
    pub capability: String,
    /// Affected work scope.
    pub work_scope: String,
    /// Effect domain of the scope.
    pub effect_domain: String,
    /// Stable hash over the four scope coordinates.
    pub route_scope_hash: String,
}

impl CapabilityRouteScope {
    /// Declares a scope and binds its stable hash.
    pub fn declare(
        module_id: impl Into<String>,
        capability: impl Into<String>,
        work_scope: impl Into<String>,
        effect_domain: impl Into<String>,
    ) -> Result<Self, OrsError> {
        let scope = Self {
            module_id: module_id.into(),
            capability: capability.into(),
            work_scope: work_scope.into(),
            effect_domain: effect_domain.into(),
            route_scope_hash: String::new(),
        };
        let route_scope_hash = scope.compute_hash()?;
        Ok(Self {
            route_scope_hash,
            ..scope
        })
    }

    /// Computes the stable route-scope hash over the scope coordinates.
    pub fn compute_hash(&self) -> Result<String, OrsError> {
        validate_text(&self.module_id, "cutover_scope_module_id")?;
        validate_text(&self.capability, "cutover_scope_capability")?;
        validate_text(&self.work_scope, "cutover_scope_work_scope")?;
        validate_text(&self.effect_domain, "cutover_scope_effect_domain")?;
        let canonical = format!(
            "{}\0{}\0{}\0{}",
            self.module_id, self.capability, self.work_scope, self.effect_domain
        );
        Ok(sha256_hex(canonical.as_bytes()))
    }

    /// Validates the coordinates and the bound hash.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.route_scope_hash, "cutover_route_scope_hash")?;
        if self.compute_hash()? != self.route_scope_hash {
            return Err(OrsError::InvalidField {
                field: "cutover_route_scope_hash",
                reason: "must be the stable hash of the scope coordinates",
            });
        }
        Ok(())
    }
}

/// Exactly one in-flight disposition per accepted request (I14.14).
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum InFlightDispositionKind {
    /// Read/stream may finish while its input fence remains valid.
    DrainRead,
    /// Only the already admitted operation may finish under a committed
    /// `OperationContinuationPermit`; not general old-generation authority.
    FinishExactAuthorizedOperation,
    /// Candidate resumes from a compatible checkpoint under a new
    /// attempt/generation receipt.
    CheckpointTransfer,
    /// Cancellation accepted only when no external/canonical effect is proven.
    CancelProvenNoEffect,
    /// Outcome unresolved; conflicting new effects in the affected scope stay
    /// blocked until receipt/probe/reconciliation resolves them.
    BlockScopeUnknownOutcome,
}

impl std::fmt::Display for InFlightDispositionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DrainRead => "drain_read",
            Self::FinishExactAuthorizedOperation => "finish_exact_authorized_operation",
            Self::CheckpointTransfer => "checkpoint_transfer",
            Self::CancelProvenNoEffect => "cancel_proven_no_effect",
            Self::BlockScopeUnknownOutcome => "block_scope_unknown_outcome",
        })
    }
}

/// One classified in-flight operation: the bounded old-operation allowlist.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightDisposition {
    /// Durable operation identity classified at cutover.
    pub operation_id: String,
    /// Its exactly-one disposition.
    pub kind: InFlightDispositionKind,
}

impl InFlightDisposition {
    /// Validates the allowlist entry.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.operation_id, "cutover_in_flight_operation_id")?;
        Ok(())
    }
}

/// State-migration decision recorded at cutover (I14.14 upgrade sequence).
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum StateMigrationDecision {
    /// Compatible state is retained across the cutover.
    RetainCompatible,
    /// Candidate resumes from a compatible checkpoint.
    CheckpointTransfer,
    /// Candidate rebuilds from a snapshot; old state is retired.
    RebuildFromSnapshot,
    /// Migration is irreversible without a separately proven rollback path;
    /// only forward repair may follow.
    ForwardRepairRequired,
}

impl std::fmt::Display for StateMigrationDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RetainCompatible => "retain_compatible",
            Self::CheckpointTransfer => "checkpoint_transfer",
            Self::RebuildFromSnapshot => "rebuild_from_snapshot",
            Self::ForwardRepairRequired => "forward_repair_required",
        })
    }
}

/// Enriched durable Kernel/ORS cutover record.
///
/// Carries every ownership field I14.14 requires beyond the thin envelope:
/// immutable artifact identities for both sides, the declared route scope and
/// its stable hash, the in-flight disposition set fixed at the linearization
/// point, the migration decision, the health/readiness proof reference, the
/// rollback boundary, and the unresolved scopes. `linearization_record_id` is
/// assigned by the single ORS commit transaction and is `None` while staged.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverOwnership {
    /// Cutover identity.
    pub cutover_id: String,
    /// Candidate artifact becoming authoritative for new admission.
    pub candidate_artifact: ModuleArtifactIdentity,
    /// Incumbent artifact, if any.
    pub incumbent_artifact: Option<ModuleArtifactIdentity>,
    /// Declared route scope being switched.
    pub scope: CapabilityRouteScope,
    /// Previously active generation, if any.
    pub old_generation: Option<ResourceGeneration>,
    /// Candidate generation becoming active.
    pub new_generation: ResourceGeneration,
    /// Epoch before the switch.
    pub old_epoch: AuthorityEpoch,
    /// New epoch issued by the switch.
    pub new_epoch: AuthorityEpoch,
    /// Exact allowed old-operation dispositions, fixed at commit.
    pub in_flight: Vec<InFlightDisposition>,
    /// State-migration decision.
    pub migration: StateMigrationDecision,
    /// Health/readiness proof reference for the candidate.
    pub health_proof_ref: String,
    /// Rollback boundary: retained artifact or forward-repair reference.
    pub rollback_boundary: String,
    /// Scopes left unresolved at commit.
    pub unresolved_scopes: Vec<String>,
    /// ORS linearization identity; `None` while staged.
    pub linearization_record_id: Option<String>,
    /// Current ORS cutover state.
    pub state: GenerationCutoverState,
}

impl GenerationCutoverOwnership {
    /// Validates the full ownership record.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.cutover_id, "cutover_ownership_id")?;
        self.candidate_artifact.validate()?;
        if let Some(incumbent) = &self.incumbent_artifact {
            incumbent.validate()?;
        }
        self.scope.validate()?;
        if self.old_generation == Some(self.new_generation) {
            return Err(OrsError::InvalidField {
                field: "cutover_ownership_new_generation",
                reason: "cutover must select a distinct generation",
            });
        }
        if self.new_epoch.value() <= self.old_epoch.value() {
            return Err(OrsError::InvalidField {
                field: "cutover_ownership_new_epoch",
                reason: "cutover must raise the authority epoch",
            });
        }
        if self.in_flight.len() > MAX_CUTOVER_IN_FLIGHT {
            return Err(OrsError::InvalidField {
                field: "cutover_ownership_in_flight",
                reason: "in-flight disposition set exceeds its bound",
            });
        }
        let mut operations = BTreeSet::new();
        for entry in &self.in_flight {
            entry.validate()?;
            if !operations.insert(entry.operation_id.as_str()) {
                return Err(OrsError::InvalidField {
                    field: "cutover_ownership_in_flight",
                    reason: "one operation must receive exactly one disposition",
                });
            }
        }
        if self.unresolved_scopes.len() > MAX_CUTOVER_UNRESOLVED_SCOPES {
            return Err(OrsError::InvalidField {
                field: "cutover_ownership_unresolved_scopes",
                reason: "unresolved scope set exceeds its bound",
            });
        }
        for scope in &self.unresolved_scopes {
            validate_text(scope, "cutover_ownership_unresolved_scope")?;
            if operations.contains(scope.as_str()) {
                return Err(OrsError::InvalidField {
                    field: "cutover_ownership_unresolved_scopes",
                    reason: "a classified operation must not also be unresolved",
                });
            }
        }
        validate_text(&self.health_proof_ref, "cutover_ownership_health_proof")?;
        validate_text(
            &self.rollback_boundary,
            "cutover_ownership_rollback_boundary",
        )?;
        if let Some(linearization) = &self.linearization_record_id {
            validate_text(linearization, "cutover_ownership_linearization")?;
        }
        Ok(())
    }

    /// Returns the stable route-scope hash.
    #[must_use]
    pub fn route_scope_hash(&self) -> &str {
        &self.scope.route_scope_hash
    }
}

/// Durable proof emitted only from a committed ownership record.
///
/// Records old/new generations and epochs, the route-scope hash, the state
/// migration, all in-flight dispositions, the linearization record, the
/// health proof, the rollback boundary, and the unresolved scopes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverOwnershipReceipt {
    /// The exact cutover identity.
    pub cutover_id: String,
    /// Old and new generations.
    pub old_generation: Option<ResourceGeneration>,
    /// New active generation.
    pub new_generation: ResourceGeneration,
    /// Epoch before the switch.
    pub old_epoch: AuthorityEpoch,
    /// Epoch after the switch.
    pub new_epoch: AuthorityEpoch,
    /// Stable hash of the switched route scope.
    pub route_scope_hash: String,
    /// Recorded state migration.
    pub migration: StateMigrationDecision,
    /// All fixed in-flight dispositions.
    pub in_flight: Vec<InFlightDisposition>,
    /// ORS linearization identity.
    pub linearization_record_id: String,
    /// Health/readiness proof reference.
    pub health_proof_ref: String,
    /// Rollback boundary.
    pub rollback_boundary: String,
    /// Unresolved scopes retained for reconciliation.
    pub unresolved_scopes: Vec<String>,
    /// Final cutover state.
    pub state: GenerationCutoverState,
}

impl GenerationCutoverOwnershipReceipt {
    /// Derives the receipt from a committed record. Fails while staged so a
    /// receipt can never precede the durable linearization point.
    pub fn from_committed(record: &GenerationCutoverOwnership) -> Result<Self, OrsError> {
        record.validate()?;
        if record.state != GenerationCutoverState::Committed {
            return Err(OrsError::InvalidTransition);
        }
        let Some(linearization_record_id) = record.linearization_record_id.clone() else {
            return Err(OrsError::IntegrityProblem {
                record_type: "cutover_ownership",
                reason: "committed cutover has no linearization identity".to_owned(),
            });
        };
        Ok(Self {
            cutover_id: record.cutover_id.clone(),
            old_generation: record.old_generation,
            new_generation: record.new_generation,
            old_epoch: record.old_epoch,
            new_epoch: record.new_epoch,
            route_scope_hash: record.scope.route_scope_hash.clone(),
            migration: record.migration,
            in_flight: record.in_flight.clone(),
            linearization_record_id,
            health_proof_ref: record.health_proof_ref.clone(),
            rollback_boundary: record.rollback_boundary.clone(),
            unresolved_scopes: record.unresolved_scopes.clone(),
            state: record.state,
        })
    }
}

/// Durable stored form of one ownership record with its ORS order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredCutoverOwnership {
    pub(crate) operation_order: u64,
    pub(crate) record: GenerationCutoverOwnership,
}

impl StoredCutoverOwnership {
    pub(crate) fn validate_persisted(&self) -> Result<(), OrsError> {
        if self.operation_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: "cutover_ownership",
                reason: "stored cutover has no operation order".to_owned(),
            });
        }
        self.record.validate()
    }
}

/// One committed route entry of the in-memory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverRouteEntry {
    /// Generation owning new effect admission.
    pub active_generation: ResourceGeneration,
    /// Epoch owning new effect admission.
    pub authority_epoch: AuthorityEpoch,
    /// Fenced prior generation, if any.
    pub fenced_generation: Option<ResourceGeneration>,
    /// Fenced prior epoch.
    pub fenced_epoch: AuthorityEpoch,
    /// Bounded allowlist of pre-cutover operation identities.
    pub allowlist: BTreeMap<String, InFlightDispositionKind>,
}

/// In-memory route snapshot derived solely from committed ORS state.
///
/// The snapshot is immutable; holders replace it wholesale only after the
/// ORS commit transaction returns, so readers never observe a half-switched
/// route.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CutoverRouteSnapshot {
    entries: BTreeMap<String, CutoverRouteEntry>,
}

impl CutoverRouteSnapshot {
    /// Rebuilds the snapshot from committed records. Pre-commit candidates
    /// are never passed here, so they can never become active. When several
    /// committed records share one scope hash, the strictly newest epoch
    /// wins: rollback is another cutover with a newer epoch, and an old
    /// epoch is never reactivated.
    pub fn rebuild(committed: &[GenerationCutoverOwnership]) -> Result<Self, OrsError> {
        let mut entries = BTreeMap::new();
        for record in committed {
            record.validate()?;
            if record.state != GenerationCutoverState::Committed {
                return Err(OrsError::InvalidTransition);
            }
            let mut allowlist = BTreeMap::new();
            for entry in &record.in_flight {
                allowlist.insert(entry.operation_id.clone(), entry.kind);
            }
            let entry = CutoverRouteEntry {
                active_generation: record.new_generation,
                authority_epoch: record.new_epoch,
                fenced_generation: record.old_generation,
                fenced_epoch: record.old_epoch,
                allowlist,
            };
            let advances = entries.get(&record.scope.route_scope_hash).is_none_or(
                |prior: &CutoverRouteEntry| {
                    record.new_epoch.value() > prior.authority_epoch.value()
                },
            );
            if !advances {
                return Err(OrsError::IntegrityProblem {
                    record_type: "cutover_ownership",
                    reason: "committed cutover epoch does not advance its scope".to_owned(),
                });
            }
            entries.insert(record.scope.route_scope_hash.clone(), entry);
        }
        Ok(Self { entries })
    }

    /// Returns the entry for a route-scope hash, if the snapshot knows it.
    #[must_use]
    pub fn entry(&self, route_scope_hash: &str) -> Option<&CutoverRouteEntry> {
        self.entries.get(route_scope_hash)
    }

    /// Admits one request against the snapshot (I14.14 request pinning):
    /// a new request after cutover reaches the candidate generation and new
    /// epoch only; an old-generation request not named in the committed
    /// in-flight disposition set is rejected as stale.
    #[must_use]
    pub fn admit(
        &self,
        route_scope_hash: &str,
        generation: ResourceGeneration,
        epoch: AuthorityEpoch,
        operation_id: &str,
    ) -> CutoverAdmission {
        let Some(entry) = self.entries.get(route_scope_hash) else {
            return CutoverAdmission::RejectStale;
        };
        if generation == entry.active_generation && epoch == entry.authority_epoch {
            return CutoverAdmission::AdmitCandidate;
        }
        if Some(generation) == entry.fenced_generation
            && epoch == entry.fenced_epoch
            && let Some(kind) = entry.allowlist.get(operation_id)
        {
            return CutoverAdmission::AdmitAllowlistedOld { kind: *kind };
        }
        CutoverAdmission::RejectStale
    }
}

/// Admission verdict for one request under a committed cutover snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutoverAdmission {
    /// New request admitted to the recorded candidate generation and epoch.
    AdmitCandidate,
    /// Pre-cutover operation admitted only under its fixed disposition; this
    /// is not general old-generation authority.
    AdmitAllowlistedOld {
        /// The fixed disposition governing the operation.
        kind: InFlightDispositionKind,
    },
    /// Rejected as stale: old generation without an allowlist entry, an old
    /// epoch, or an unknown route scope.
    RejectStale,
}

/// Atomically swappable holder for the committed route snapshot.
///
/// The table starts empty (no route is active before the first commit) and
/// `swap_committed` replaces the whole map only with a snapshot rebuilt
/// from committed ORS state after the ORS transition commits.
#[derive(Debug, Default)]
pub struct CutoverRouteTable {
    inner: RwLock<CutoverRouteSnapshot>,
}

impl CutoverRouteTable {
    /// Creates an empty table: no route is active before the first commit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(CutoverRouteSnapshot::default()),
        }
    }

    /// Atomically swaps in a snapshot rebuilt from committed ORS state.
    pub fn swap_committed(&self, snapshot: CutoverRouteSnapshot) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = snapshot;
        }
    }

    /// Admits one request against the current snapshot.
    #[must_use]
    pub fn admit(
        &self,
        route_scope_hash: &str,
        generation: ResourceGeneration,
        epoch: AuthorityEpoch,
        operation_id: &str,
    ) -> CutoverAdmission {
        self.inner
            .read()
            .map_or(CutoverAdmission::RejectStale, |snapshot| {
                snapshot.admit(route_scope_hash, generation, epoch, operation_id)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(module: &str, semver: &str, hash_fill: &str) -> ModuleArtifactIdentity {
        let hash = hash_fill.repeat(64);
        ModuleArtifactIdentity {
            module_id: module.to_owned(),
            semver: semver.to_owned(),
            artifact_hash: hash.clone(),
            manifest_digest: "d".repeat(64),
            layout_root: format!("modules/{module}/{semver}/{hash}"),
        }
    }

    #[test]
    fn route_scope_hash_is_stable_and_coordinate_bound() -> Result<(), Box<dyn std::error::Error>> {
        let first = CapabilityRouteScope::declare("mod-a", "serve", "work", "effects")?;
        let second = CapabilityRouteScope::declare("mod-a", "serve", "work", "effects")?;
        assert_eq!(first.route_scope_hash, second.route_scope_hash);
        assert!(first.validate().is_ok());
        let other = CapabilityRouteScope::declare("mod-a", "serve", "work", "other")?;
        assert_ne!(first.route_scope_hash, other.route_scope_hash);
        let mut tampered = first.clone();
        tampered.route_scope_hash = other.route_scope_hash.clone();
        assert!(tampered.validate().is_err());
        Ok(())
    }

    #[test]
    fn ownership_rejects_duplicate_operation_dispositions() -> Result<(), Box<dyn std::error::Error>>
    {
        let scope = CapabilityRouteScope::declare("mod-a", "serve", "work", "effects")?;
        let mut record = GenerationCutoverOwnership {
            cutover_id: "cutover-dup".to_owned(),
            candidate_artifact: artifact("mod-a", "1.2.0", "a"),
            incumbent_artifact: Some(artifact("mod-a", "1.1.0", "b")),
            scope,
            old_generation: Some(ResourceGeneration::new(1)?),
            new_generation: ResourceGeneration::new(2)?,
            old_epoch: AuthorityEpoch::new(1)?,
            new_epoch: AuthorityEpoch::new(2)?,
            in_flight: vec![
                InFlightDisposition {
                    operation_id: "op-1".to_owned(),
                    kind: InFlightDispositionKind::DrainRead,
                },
                InFlightDisposition {
                    operation_id: "op-1".to_owned(),
                    kind: InFlightDispositionKind::CheckpointTransfer,
                },
            ],
            migration: StateMigrationDecision::CheckpointTransfer,
            health_proof_ref: "health-proof-1".to_owned(),
            rollback_boundary: "modules/mod-a/1.1.0/".to_owned() + &"b".repeat(64),
            unresolved_scopes: vec!["op-unknown".to_owned()],
            linearization_record_id: None,
            state: GenerationCutoverState::Armed,
        };
        assert!(record.validate().is_err());
        record.in_flight.remove(1);
        assert!(record.validate().is_ok());
        Ok(())
    }

    #[test]
    fn receipt_requires_a_committed_record() -> Result<(), Box<dyn std::error::Error>> {
        let scope = CapabilityRouteScope::declare("mod-a", "serve", "work", "effects")?;
        let record = GenerationCutoverOwnership {
            cutover_id: "cutover-staged".to_owned(),
            candidate_artifact: artifact("mod-a", "1.2.0", "a"),
            incumbent_artifact: None,
            scope,
            old_generation: None,
            new_generation: ResourceGeneration::new(2)?,
            old_epoch: AuthorityEpoch::new(1)?,
            new_epoch: AuthorityEpoch::new(2)?,
            in_flight: Vec::new(),
            migration: StateMigrationDecision::RetainCompatible,
            health_proof_ref: "health-proof-1".to_owned(),
            rollback_boundary: "forward-only".to_owned(),
            unresolved_scopes: Vec::new(),
            linearization_record_id: None,
            state: GenerationCutoverState::Armed,
        };
        assert!(GenerationCutoverOwnershipReceipt::from_committed(&record).is_err());
        Ok(())
    }
}
