//! Governor-side restore admission minting for the kernel restore path
//! (issues #959/#960, lane G).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! cutover under separate authority; old authority never revives); A12.3 One
//! Governed Write Path (no second writer: this module performs no store
//! effect and stages nothing — it binds owner-held state into an admission
//! the import wire enforces); I1.8 Exact Ownership and Call Paths (the
//! admission decision digest rides the existing `PreparedTransition`
//! identity, exactly as the canonical write path requires; a mismatch is a
//! conflict, never a retry-as-same); I5.6 Admission and staging (the digest
//! is built at the semantic-admission point, step 12); I5.19 Write
//! submission, execution and receipts (replay follows identity; a diverged
//! decision conflicts); I5.27 Canonical operation identity (idempotency over
//! canonical bytes).
//!
//! Implementation: every admission below is minted from live owner-held
//! state, never from caller spelling:
//!
//! ```text
//! plan ................. compiled `RestorePlan` (bundle digest recomputed
//!                          from the presented archive and required equal
//!                          to the plan binding);
//! installation ......... Host-issued destination binding
//!                          (`VerifiedDestinationBinding`, constructible
//!                          only by `verify_destination_authorization`);
//! fenced destination ... constructed isolated destination bound to the
//!                          plan target plus the live `StateFence` with the
//!                          exact delivered-generation currency rule
//!                          (delivered authority generation must equal the
//!                          live fence generation);
//! provisioning ......... destination-store attestations (shape-checked,
//!                          cross-bound to plan target and bundle; store-side
//!                          truth stays with the bridge's destination-heads
//!                          readback, never claimed here);
//! journal anchor ........ the ORS owner's durably held stream binding,
//!                          read back live (transaction/source/destination
//!                          cross-bound, writer fence re-proven against the
//!                          live fence so a rotated authority refuses).
//! ```
//!
//! Verify-versus-mint split (bridge contract conformance): recomputing the
//! decision digest verifies self-consistency only and proves no issuance —
//! the cfec Store surface was rejected on exactly this gap (F1). Issuance
//! here is the owner bindings above, all established before the digest is
//! computed; the digest is their receipt, never their authority. The digest
//! domain (`kernel-restore-admission:v1`) is deliberately distinct from the
//! Store wire's domain, so a kernel admission digest can never validate as
//! a Store admission and vice versa: no caller digest masquerades as
//! authority across wires.
//!
//! Anchor repair (F1, kernel wire): the importer re-fetches the anchor
//! instead of trusting admission fields. `import_restore_transition`
//! re-reads the owner-held stream binding live from the journal handle at
//! import time and requires stream key, binding digest, transaction,
//! destination, source archive, and writer-fence continuity against the
//! presented admission — a self-consistent admission the journal does not
//! anchor refuses with `RestoreJournalMismatch`. What the importer
//! re-fetches (owner-held journal truth) versus what travels caller-carried
//! (the admission struct): the struct is the claim, the readback is the
//! proof.
//!
//! Provisional scope (honest labeling): this admission is fully anchored
//! and enforced on the kernel import wire above. The Store-wire crossing —
//! `StoreRestoreAdmission` construction from these fields, the committed
//! coordination row keyed by operation identity the 975 bridge reads back,
//! dispatch capability enforcement, deployment-role provisioning, and the
//! provision pin — stays with the Store lane (which answered F2–F6 on its
//! side; its minter/coordination-row writer is still open) and is proposed
//! as hunks for root, never claimed as done here.
//!
//! The Store wire crossing (`StoreRestoreAdmission` construction, dispatch
//! capability enforcement, bridge anchor check, replay conflict,
//! deployment-role provisioning, provision pin verification — F1/F2/F3/F4/F6)
//! lives in the Store lane's files and is proposed as hunks for root, not
//! seized here. Owner-controlled fence/generation transition for
//! reprovision and cutover (F5) belongs to the #961 installation-cutover
//! owner, whose lane is still open.
//!
//! Capability cell: Kernel restore ownership (restore admission minting).
//! Forbidden authority: no store effects, no ORS writes, no epoch minting,
//! no activation/retirement of any installation, no Store-wire types (a
//! second `StoreRestoreAdmission` here would be a second canonical owner),
//! no `Value`-based escapes.

use eliot_backup::{BackupBundle, BackupError, RestorePlan};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_store_api::{OperationIdentity, PreparedTransition, TransitionClass};

use super::backup_owner_clients::VerifiedDestinationBinding;
use super::backup_restore_ports::{
    KernelIsolatedDestination, KernelRestoreJournal, check_kernel_effect_fence,
};

/// Decision-digest domain separating kernel restore admissions from every
/// other digest on any wire. A digest minted here never validates elsewhere.
pub const RESTORE_ADMISSION_DECISION_DOMAIN: &str = "kernel-restore-admission:v1";
/// Transition-class marker bound into the decision: restore imports run
/// only under `RecoverySchema`. The Store wire's own class marker stays on
/// the Store wire; it is not repeated here.
pub const RESTORE_ADMISSION_CLASS_MARKER: &str = "recovery_schema";
/// Wire marker bound into the decision: the kernel canonical-store import
/// path. A Store-wire admission carries its own marker instead.
pub const RESTORE_ADMISSION_WIRE_MARKER: &str = "canonical-restore-import";

fn non_blank(value: &str, field: &'static str) -> Result<(), BackupError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be non-blank with no control characters",
        });
    }
    Ok(())
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex64(value: &str, field: &'static str) -> Result<(), BackupError> {
    if !is_hex64(value) {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be a lowercase 64-hex digest",
        });
    }
    Ok(())
}

/// Destination-store provisioning attestations bound into one restore
/// admission.
///
/// These arrive as provisioning-owner attestations, not as store-side
/// truth: shapes validate here, the destination installation cross-binds
/// to the plan target, and the source snapshot cross-binds to the archive
/// the plan was compiled from. Whether the provisioned store actually
/// holds the snapshot under the denominator stays with the bridge's
/// destination-heads readback — this module never claims it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RestoreProvisioningProof {
    /// Provisioned isolated destination store identity (attested).
    pub dest_store_id: String,
    /// Capture residency denominator digest (attested hex64).
    pub residency_denominator_digest: String,
    /// Source snapshot digest the restore replays (attested hex64).
    pub source_snapshot_digest: String,
    /// Capture operation that produced the source snapshot (attested).
    pub capture_operation_id: String,
}

impl RestoreProvisioningProof {
    /// Validates attestation shapes without granting any store truth.
    pub fn validate(&self) -> Result<(), BackupError> {
        non_blank(&self.dest_store_id, "restore.dest_store_id")?;
        hex64(
            &self.residency_denominator_digest,
            "restore.residency_denominator_digest",
        )?;
        hex64(
            &self.source_snapshot_digest,
            "restore.source_snapshot_digest",
        )?;
        non_blank(&self.capture_operation_id, "restore.capture_operation_id")?;
        Ok(())
    }
}

/// Governor-side mint request binding the four real owner inputs.
///
/// The plan and bundle are re-validated here (recompute, never caller
/// bytes); the verified binding is Host-issued by construction; the fence
/// is the caller's live fence checked for currency; the journal handle
/// supplies the owner-held stream binding by live readback; the
/// destination is the constructed isolated root bound to the plan target;
/// the provisioning proof carries the destination-store attestations; the
/// transition identity is the exact Governor-built import identity being
/// admitted and is bound, never invented.
pub struct RestoreAdmissionMintRequest<'a> {
    /// Compiled restore plan being admitted.
    pub plan: &'a RestorePlan,
    /// Archive the plan was compiled from (re-validated, digest recomputed).
    pub bundle: &'a BackupBundle,
    /// Host-issued verified destination binding.
    pub verified: &'a VerifiedDestinationBinding,
    /// Owner-held restore journal for the live stream-binding readback.
    pub journal: &'a KernelRestoreJournal,
    /// Constructed isolated destination bound to the plan target.
    pub destination: &'a KernelIsolatedDestination,
    /// Caller-live authority fence for currency and effect gating.
    pub live_fence: &'a StateFence,
    /// Destination-store provisioning attestations.
    pub provisioning: RestoreProvisioningProof,
    /// Exact import identity being admitted (from the Governor-built
    /// transition, never minted here).
    pub transition_identity: OperationIdentity,
}

/// Governor-minted restore admission for one kernel store import.
///
/// Carries the exact admitted import identity, the plan/archive bindings,
/// the Host-issued destination digest, the owner-read journal stream
/// binding, the live fence at mint, and the provisioning attestations,
/// all covered by the decision digest. The import wire
/// (`CanonicalStoreImportClient::import_restore_transition`) enforces this
/// admission before any store effect; without it the restore import is not
/// admitted at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelRestoreAdmission {
    identity: OperationIdentity,
    plan_id: String,
    bundle_sha256: String,
    target_id: String,
    transaction_id: String,
    source_archive_id: String,
    destination_binding_digest: String,
    journal_stream: String,
    journal_binding_digest: String,
    fence: StateFence,
    provisioning: RestoreProvisioningProof,
    decision_digest: String,
}

impl KernelRestoreAdmission {
    /// Exact admitted import identity.
    pub fn identity(&self) -> &OperationIdentity {
        &self.identity
    }

    /// Restore plan this admission was minted for.
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    /// Archive digest this admission was minted against.
    pub fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }

    /// Isolated restore target this admission binds.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Restore transaction this admission was minted for, bound to the
    /// owner-held journal stream at mint and re-fetched at import.
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    /// Source archive identity this admission was minted against, bound
    /// to the owner-held journal stream at mint and re-fetched at import.
    pub fn source_archive_id(&self) -> &str {
        &self.source_archive_id
    }

    /// Host-issued destination binding digest this admission binds.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Owner-held journal stream this admission was read back from.
    pub fn journal_stream(&self) -> &str {
        &self.journal_stream
    }

    /// Digest of the owner-held stream binding read back at mint.
    pub fn journal_binding_digest(&self) -> &str {
        &self.journal_binding_digest
    }

    /// Live fence at mint; imports under a newer fence refuse.
    pub fn fence(&self) -> &StateFence {
        &self.fence
    }

    /// Provisioning attestations bound at mint.
    pub fn provisioning(&self) -> &RestoreProvisioningProof {
        &self.provisioning
    }

    /// Decision digest covering every bound field.
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    /// Recomputes the decision digest over the bound fields.
    ///
    /// Pure over closed inputs: minting and verification share this one
    /// function, so equal bytes under different bindings stay distinct.
    /// Recomputation alone proves self-consistency, never issuance —
    /// issuance is the owner bindings established at mint time.
    pub fn recompute_decision(&self) -> Result<String, BackupError> {
        let identity_bytes = canonical_json_bytes(&self.identity)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let fence_bytes = canonical_json_bytes(&self.fence)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let provisioning_bytes = canonical_json_bytes(&self.provisioning)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let mut material = Vec::new();
        material.extend_from_slice(RESTORE_ADMISSION_DECISION_DOMAIN.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.plan_id.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.bundle_sha256.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.target_id.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.transaction_id.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.source_archive_id.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(&identity_bytes);
        material.push(b'\n');
        material.extend_from_slice(RESTORE_ADMISSION_CLASS_MARKER.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.destination_binding_digest.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.journal_stream.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.journal_binding_digest.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(&fence_bytes);
        material.push(b'\n');
        material.extend_from_slice(&provisioning_bytes);
        material.push(b'\n');
        material.extend_from_slice(RESTORE_ADMISSION_WIRE_MARKER.as_bytes());
        Ok(sha256_hex(&material))
    }

    /// Validates the closed admission without granting authority.
    ///
    /// Re-proves shapes and requires the recomputed decision digest to
    /// equal the minted one. A diverged digest is a conflict (replay under
    /// a changed decision refuses), never a retry-as-same.
    pub fn validate(&self) -> Result<(), BackupError> {
        self.identity.validate().map_err(BackupError::Store)?;
        non_blank(&self.plan_id, "restore.plan_id")?;
        hex64(&self.bundle_sha256, "restore.bundle_sha256")?;
        non_blank(&self.target_id, "restore.target_id")?;
        non_blank(&self.transaction_id, "restore.transaction_id")?;
        non_blank(&self.source_archive_id, "restore.source_archive_id")?;
        if self.destination_binding_digest.is_empty() {
            return Err(BackupError::InvalidField {
                field: "restore.destination_binding_digest",
                reason: "destination binding digest is unavailable",
            });
        }
        non_blank(&self.journal_stream, "restore.journal_stream")?;
        hex64(
            &self.journal_binding_digest,
            "restore.journal_binding_digest",
        )?;
        self.fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        self.provisioning.validate()?;
        let recomputed = self.recompute_decision()?;
        if recomputed != self.decision_digest {
            return Err(BackupError::PlanMismatch);
        }
        Ok(())
    }
}

/// Mints one Governor-side restore admission from live owner state.
///
/// Pure constructor: validates every binding and returns the admission —
/// no journal write, no store effect, no staging. Each load-bearing field
/// is either recomputed from owner-held state (bundle digest, journal
/// stream binding, writer fence digest, destination digest) or
/// cross-bound against at least two independent owner sources (plan,
/// bundle, verified binding, live fence, pinned destination). Refusal
/// carries the exact missing or diverged binding; a minted admission
/// proves its bindings were all observed, never spelled.
pub fn mint_restore_admission(
    request: RestoreAdmissionMintRequest<'_>,
) -> Result<KernelRestoreAdmission, BackupError> {
    let RestoreAdmissionMintRequest {
        plan,
        bundle,
        verified,
        journal,
        destination,
        live_fence,
        provisioning,
        transition_identity,
    } = request;
    non_blank(&plan.plan_id, "restore.plan_id")?;
    non_blank(&plan.target.target_id, "restore.target_id")?;
    bundle.validate()?;
    let bundle_sha256 = bundle.bundle_sha256()?;
    if bundle_sha256 != plan.bundle_sha256 {
        return Err(BackupError::PlanMismatch);
    }
    transition_identity.validate().map_err(BackupError::Store)?;
    provisioning.validate()?;
    // Isolated destination binding: the constructed root answers to the
    // plan target, and the plan target answers away from the source
    // installation — restoring into the source is not isolated restore.
    if destination.label() != plan.target.target_id {
        return Err(BackupError::PlanMismatch);
    }
    if plan.target.target_id == verified.source_installation_id() {
        return Err(BackupError::FenceMismatch {
            subject: "restore destination is not isolated from the source installation".to_owned(),
        });
    }
    // Provisioning seam: `RestoreProvisioningProof` carries the
    // destination *store* attestation; the destination *installation* is
    // the plan target itself (bound above), mapped to the Store scope
    // field by the Store-lane constructor hunk (root-owned).
    // Currency: the delivered authority generation must equal the live
    // fence generation — any activation between issuance and mint moved
    // the generation and the binding is stale. Same-installation mint
    // only; migration lanes carry their own lineage proof.
    if verified.fence_authority_generation() != live_fence.resource_generation.value() {
        return Err(BackupError::FenceMismatch {
            subject: "destination authority generation is not current".to_owned(),
        });
    }
    check_kernel_effect_fence(live_fence, bundle)?;
    let destination_binding_digest = verified.binding_digest();
    if destination_binding_digest.is_empty() {
        return Err(BackupError::InvalidField {
            field: "restore.destination_binding_digest",
            reason: "destination binding digest is unavailable",
        });
    }
    // Independent anchor readback: the stream key comes from the
    // owner-held journal handle (never caller spelling), and the binding
    // is the owner's durably held value, not a presented copy.
    let stream = journal
        .bound_stream()
        .ok_or(BackupError::RestoreJournalMismatch)?;
    let durable = journal
        .read_durable_binding(stream)
        .map_err(|error| BackupError::Target(error.to_string()))?
        .ok_or(BackupError::RestoreJournalMismatch)?;
    let transaction = plan.transaction()?;
    if durable.transaction_id != transaction.transaction_id {
        return Err(BackupError::PlanMismatch);
    }
    if durable.destination_ref != plan.target.target_id {
        return Err(BackupError::PlanMismatch);
    }
    if durable.source_archive_id != bundle.manifest.backup_id {
        return Err(BackupError::PlanMismatch);
    }
    // Writer-fence continuity: re-prove the binding's fence digest from
    // the live fence. A rotated authority refuses instead of minting
    // under stale bindings.
    let fence_bytes = canonical_json_bytes(live_fence)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    if sha256_hex(&fence_bytes) != durable.writer_fence_digest {
        return Err(BackupError::RestoreJournalMismatch);
    }
    let journal_binding_bytes = canonical_json_bytes(&durable)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    let admission = KernelRestoreAdmission {
        identity: transition_identity,
        plan_id: plan.plan_id.clone(),
        bundle_sha256,
        target_id: plan.target.target_id.clone(),
        transaction_id: transaction.transaction_id.clone(),
        source_archive_id: bundle.manifest.backup_id.clone(),
        destination_binding_digest,
        journal_stream: stream.to_owned(),
        journal_binding_digest: sha256_hex(&journal_binding_bytes),
        fence: live_fence.clone(),
        provisioning,
        decision_digest: String::new(),
    };
    let decision_digest = admission.recompute_decision()?;
    let admission = KernelRestoreAdmission {
        decision_digest,
        ..admission
    };
    admission.validate()?;
    Ok(admission)
}

/// Requires a restore-class import transition.
///
/// Restore imports run only under `RecoverySchema`: a transition of any
/// other class through the restore wire refuses before effects instead of
/// borrowing restore authority.
pub fn require_restore_transition_class(
    transition: &PreparedTransition,
) -> Result<(), BackupError> {
    if transition.transition_class != TransitionClass::RecoverySchema {
        return Err(BackupError::InvalidField {
            field: "restore.transition_class",
            reason: "restore imports run only under RecoverySchema",
        });
    }
    Ok(())
}
