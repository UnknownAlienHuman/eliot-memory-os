//! Governor restore coordination decision/record producer (issues
//! #959/#960, lane G).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! cutover under separate authority); A12.3 One Governed Write Path (the
//! coordination row commits through the single canonical write path —
//! gateway apply with unknown-commit recovery — never a second writer);
//! I1.8 Exact Ownership and Call Paths (the coordination decision digest
//! rides the existing `PreparedTransition` identity; mismatch conflicts,
//! never retries as the same decision); I5.6 Admission and staging (the
//! Governor semantic operation carries the decision as closed typed
//! parameters); I5.19 Write submission, execution and receipts (replay
//! follows operation identity; the committed receipt is re-fetched by
//! identity to prove bridge readback); I5.27 Canonical operation identity.
//!
//! What this module owns: the coordination DECISION value (built purely
//! from a Governor-minted [`KernelRestoreAdmission`](super::backup_restore_admission::KernelRestoreAdmission),
//! never from caller spelling) and its closed typed-parameter encoding
//! for the future coordination named operation. The COMMIT (gateway
//! apply, receipt binding verification, identity readback) lives on
//! [`CanonicalStoreImportClient`](super::backup_owner_clients::CanonicalStoreImportClient)
//! next to the admitted import wire, reusing its admission binding and
//! gateway handle.
//!
//! The coordination tuple bound here is exactly operation, destination,
//! payload digest, and fence: operation identity and payload hash come
//! from the admitted transition identity (`operation_id`,
//! `idempotency_key`, `canonical_request_hash`), the destination from the
//! admitted plan target, and the fence from the live fence at mint. The
//! full field binding is never weakened to satisfy a sender: every
//! parameter below must equal its decision field at commit time.
//!
//! Bridge contract conformance: the bridge reads the committed row back
//! by operation identity (the existing receipt/exact-reconcile mechanism)
//! and binds presented fields to its own anchors (completed live
//! source-capture row, deployment-provisioned destination record,
//! frame-enforced session capability and transport identity). The named
//! operation variant, its catalogue row, and the destination-side row
//! projection stay with the Store lane (M1B owner): this module names the
//! closed parameter vocabulary the future operation adopts (mirroring how
//! `RecordAuthorityRevocation` shipped typed parameters ahead of its
//! store-owned slice), and the commit path fail-closes at catalogue
//! validation until that slice activates. Nothing here mints Store
//! authority, reinterprets the catalogue, or weakens verification to fake
//! admittability.
//!
//! Owner-controlled fence/generation transition (F5) stays with the #961
//! installation-cutover owner: reprovision mints a fresh admission (stale
//! fences refuse), rotation never happens in place.
//!
//! Capability cell: Kernel restore ownership (coordination decision
//! producer). Forbidden authority: no Store named-operation variants, no
//! catalogue rows, no bridge/dispatch edits, no epoch minting, no
//! activation/retirement of any installation, no `Value`-based escapes
//! beyond the closed coordination parameter map.

use std::collections::BTreeMap;

use eliot_backup::BackupError;
use eliot_contracts::{OperationId, StateFence, canonical_json_bytes, sha256_hex};
use serde_json::Value;

use super::backup_restore_admission::KernelRestoreAdmission;

/// Decision-digest domain for coordination records. Distinct from both
/// the kernel admission domain and the Store admission domain: a
/// coordination digest validates nowhere else.
pub const COORDINATION_DECISION_DOMAIN: &str = "kernel-restore-coordination:v1";
/// Closed coordination parameter carrying the admitted operation identity.
pub const COORD_PARAM_OPERATION_ID: &str = "coordination_operation_id";
/// Closed coordination parameter carrying the admitted destination.
pub const COORD_PARAM_DESTINATION: &str = "coordination_destination";
/// Closed coordination parameter carrying the admitted payload digest
/// (the transition's canonical request hash).
pub const COORD_PARAM_PAYLOAD_DIGEST: &str = "coordination_payload_digest";
/// Closed coordination parameter carrying the admitted fence digest.
pub const COORD_PARAM_FENCE_DIGEST: &str = "coordination_fence_digest";
/// Closed coordination parameter carrying the coordination decision digest.
pub const COORD_PARAM_DECISION_DIGEST: &str = "coordination_decision_digest";
/// Closed coordination parameter carrying the Governor admission digest
/// this decision was built from.
pub const COORD_PARAM_ADMISSION_DIGEST: &str = "coordination_admission_digest";

fn non_blank(value: &str, field: &'static str) -> Result<(), BackupError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be non-blank with no control characters",
        });
    }
    Ok(())
}

fn hex64(value: &str, field: &'static str) -> Result<(), BackupError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be a lowercase 64-hex digest",
        });
    }
    Ok(())
}

/// Governor restore coordination decision: the issuance proof the bridge
/// reads back, keyed by operation identity.
///
/// Built purely from a Governor-minted admission: operation identity and
/// payload digest from the admitted transition identity, destination from
/// the admitted plan target, fence from the live fence at mint, and the
/// admission digest linking this decision to the enforced mint. The
/// decision digest covers the exact
/// operation/destination/payload-digest/fence tuple plus the link fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationDecision {
    operation_id: OperationId,
    idempotency_key: String,
    destination: String,
    payload_digest: String,
    fence: StateFence,
    admission_decision_digest: String,
    plan_id: String,
    bundle_sha256: String,
    decision_digest: String,
}

impl CoordinationDecision {
    /// Builds the coordination decision from a Governor-minted admission.
    ///
    /// Pure constructor: binds admission fields, computes the decision
    /// digest, and validates. No journal write, no store effect. The
    /// admission must already be minted and (at the commit site) enforced;
    /// this constructor binds its values onward, never re-proves them.
    pub fn from_admission(admission: &KernelRestoreAdmission) -> Result<Self, BackupError> {
        let decision = Self {
            operation_id: admission.identity().operation_id.clone(),
            idempotency_key: admission.identity().idempotency_key.clone(),
            destination: admission.target_id().to_owned(),
            payload_digest: admission.identity().canonical_request_hash.clone(),
            fence: admission.fence().clone(),
            admission_decision_digest: admission.decision_digest().to_owned(),
            plan_id: admission.plan_id().to_owned(),
            bundle_sha256: admission.bundle_sha256().to_owned(),
            decision_digest: String::new(),
        };
        let decision_digest = decision.recompute_decision()?;
        let decision = Self {
            decision_digest,
            ..decision
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Restore operation identity keying the coordination row the bridge
    /// reads back.
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Admitted destination this decision binds.
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// Admitted payload digest (canonical request hash) this decision binds.
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    /// Live fence at mint this decision binds.
    pub fn fence(&self) -> &StateFence {
        &self.fence
    }

    /// Governor admission digest this decision was built from.
    pub fn admission_decision_digest(&self) -> &str {
        &self.admission_decision_digest
    }

    /// Coordination decision digest over the exact tuple plus links.
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    /// Row key the bridge re-fetches: the operation identity string.
    pub fn row_key(&self) -> String {
        self.operation_id.to_string()
    }

    /// Recomputes the decision digest over the bound tuple and links.
    ///
    /// Pure over closed inputs. Recomputation proves self-consistency,
    /// never issuance — issuance is the Governor-minted admission this
    /// decision was built from plus the canonical commit receipt.
    pub fn recompute_decision(&self) -> Result<String, BackupError> {
        let fence_bytes = canonical_json_bytes(&self.fence)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let mut material = Vec::new();
        material.extend_from_slice(COORDINATION_DECISION_DOMAIN.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.operation_id.to_string().as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.idempotency_key.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.destination.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.payload_digest.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(&fence_bytes);
        material.push(b'\n');
        material.extend_from_slice(self.admission_decision_digest.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.plan_id.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.bundle_sha256.as_bytes());
        Ok(sha256_hex(&material))
    }

    /// Validates the closed decision without granting authority.
    pub fn validate(&self) -> Result<(), BackupError> {
        non_blank(&self.idempotency_key, "coordination.idempotency_key")?;
        non_blank(&self.destination, "coordination.destination")?;
        hex64(&self.payload_digest, "coordination.payload_digest")?;
        self.fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        hex64(
            &self.admission_decision_digest,
            "coordination.admission_decision_digest",
        )?;
        non_blank(&self.plan_id, "coordination.plan_id")?;
        hex64(&self.bundle_sha256, "coordination.bundle_sha256")?;
        let recomputed = self.recompute_decision()?;
        if recomputed != self.decision_digest {
            return Err(BackupError::PlanMismatch);
        }
        Ok(())
    }

    /// Encodes the closed typed parameters for the future coordination
    /// named operation (M1B owner adopts these exact keys).
    ///
    /// String-valued, fixed vocabulary: the bridge persists the values
    /// verbatim and binds them against the committed decision at readback.
    /// Values must equal the decision fields — enforced at commit time,
    /// never derived downstream.
    pub fn parameters(&self) -> Result<BTreeMap<String, Value>, BackupError> {
        let fence_bytes = canonical_json_bytes(&self.fence)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let mut parameters = BTreeMap::new();
        parameters.insert(
            COORD_PARAM_OPERATION_ID.to_owned(),
            Value::String(self.operation_id.to_string()),
        );
        parameters.insert(
            COORD_PARAM_DESTINATION.to_owned(),
            Value::String(self.destination.clone()),
        );
        parameters.insert(
            COORD_PARAM_PAYLOAD_DIGEST.to_owned(),
            Value::String(self.payload_digest.clone()),
        );
        parameters.insert(
            COORD_PARAM_FENCE_DIGEST.to_owned(),
            Value::String(sha256_hex(&fence_bytes)),
        );
        parameters.insert(
            COORD_PARAM_DECISION_DIGEST.to_owned(),
            Value::String(self.decision_digest.clone()),
        );
        parameters.insert(
            COORD_PARAM_ADMISSION_DIGEST.to_owned(),
            Value::String(self.admission_decision_digest.clone()),
        );
        Ok(parameters)
    }
}
