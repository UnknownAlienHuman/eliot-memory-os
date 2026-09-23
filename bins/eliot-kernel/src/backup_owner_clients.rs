//! Live restore owner-effect channels (issue #962, lane G).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! purge-first, suspended ORS import, new lineage, separate cutover
//! authority); A13.6 Operational Recovery State (only identities, opaque
//! envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors); A12.3 One Governed Write Path (no second writer, no
//! database-protocol bypass); I1.8 Exact Ownership and Call Paths (one
//! logical Governor, two internal checks — this file invents no semantics,
//! authorizes none, and commits none alone); I5.13 backup classes;
//! I5.27 canonical operation identity (idempotency over canonical bytes;
//! database idempotency and external-effect idempotency stay separate);
//! I14.21 unknown-commit recovery (reconcile by identity, never blind
//! retry); I5.19 intent-before-effect ordering.
//!
//! Implementation: every effect below executes through its responsible
//! owner's accepted API with the exact bindings the coordinator supplies:
//!
//! ```text
//! purge ............ purge owner (`PurgeLedgerEntry::validate` from
//!                    `eliot-security-contracts`; staged tombstones preserved,
//!                    never resurrected into live authority);
//! canonical ........ canonical owner (`CanonicalRecord::validate`,
//!                    `WriteReceipt::validate`, receipt/event-chain coverage
//!                    over the exact staged members);
//! live store import  canonical-store owner (`KernelStoreGateway::apply` —
//!                    the accepted A12.3 write path with fixed Kernel
//!                    admission plus `recover_commit` unknown-commit
//!                    recovery; reconcile answers from
//!                    `KernelStoreGateway::receipt` by exact operation
//!                    identity). No Store wire, client, or dispatch hunk is
//!                    added here: the backup-specific Store edge is owned by
//!                    #975 (`eliot-store-api` wire, `store_backup_client`,
//!                    `backup_dispatch`);
//! sealed blobs ..... blob owner (`DestinationRestoreAdapter::
//!                    restore_blob_sealed` with backup-bound restoration
//!                    receipts from `issue_restoration_receipts`, the admitted
//!                    key manifest under exact `verify_key_coverage`, and the
//!                    destination scope; re-sealed bytes staged, never
//!                    plaintext);
//! ORS suspension ... ORS owner (`suspended_recovery_entries` — persisted as
//!                    suspended evidence, never runnable);
//! lease terminal ... supervision-lease authority
//!                    (`KernelSupervisionLeaseAuthority::commit_terminal`
//!                    with a caller-supplied terminal ticket, predecessor
//!                    proof, trust anchor, and signer); session detach,
//!                    broker fence, and route retirement execute through
//!                    `SessionOwnerClient`/`BrokerOwnerClient` plus the
//!                    router owner with journaled proofs; runtime
//!                    invalidation has no execution API in-tree and refuses
//!                    with its exact owner (prior-generation retirement
//!                    belongs to the #961 installation-cutover owner).
//! ```
//!
//! Verified destination authorization before effects: no client that performs
//! an effect can be constructed without a [`VerifiedDestinationBinding`]
//! produced by [`verify_destination_authorization`] over Host-issued owner
//! bytes (see `bins/eliot-host/src/restore_destination_auth.rs`). Bare digest
//! triples never authorize: the verifier checks wire/issuer identity, exact
//! target/transaction binding, digest shapes, work-root containment against
//! the Kernel's own root, and manifest agreement with the archive before any
//! effect method runs. Intent-before-effect plus reconcile-unknown hold
//! throughout: the coordinator journals the intent first, and every
//! reconciliation answers from owner readback (`Applied` on exact identity
//! match, `NotApplied` on absence, `Unknown` on transport/owner refusal —
//! never a fabricated outcome, never a blind re-apply).
//!
//! Capability cell: Kernel restore ownership (owner-channel execution).
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no archive/phase
//! algorithm, no invented target methods, no `Value`-based escapes, no
//! self-authorized Kernel writes (every store effect crosses the gateway's
//! fixed admission), no invented Host lease (the authorization is
//! Host-issued and verified, never minted here).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_backup::{
    BackupBlob, BackupBundle, BackupError, BlobRestorationReceipt, CanonicalRecord, CutoverReceipt,
    DestinationRestoreAdapter, DestinationScope, OrsSnapshotFence, RestoreContext,
    RestoreHistoricalAuthority, RestorePlan, RestoredSealedBlob, WrappedKeyManifest,
    issue_restoration_receipts, suspended_recovery_entries, verify_key_coverage,
};
use eliot_contracts::{OperationId, RequestMetadata, StateFence, canonical_json_bytes, sha256_hex};
use eliot_ors::{
    CapabilityIntroductionProjection, SessionBindingReceipt, SessionDetach, UserBrokerFence,
    UserBrokerRegistrationReceipt,
};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, TransitionClass,
    WriteReceipt, WriteReceiptStatus,
};
use serde_json::Value;

use super::{
    KernelComposition, KernelStoreGateway, KernelSupervisionLeaseAuthority,
    SupervisionLeaseAuthorityError,
};
use super::backup_coordination::{
    COORD_PARAM_ADMISSION_DIGEST, COORD_PARAM_DECISION_DIGEST, COORD_PARAM_DESTINATION,
    COORD_PARAM_FENCE_DIGEST, COORD_PARAM_OPERATION_ID, COORD_PARAM_PAYLOAD_DIGEST,
    CoordinationDecision,
};
use super::backup_restore::KernelBackupRestore;
use super::backup_restore_admission::{
    KernelRestoreAdmission, RestoreProvisioningProof, require_restore_transition_class,
};
use super::backup_restore_driver::{
    CoordinationCommit, ProductionRestoreCall, ProductionRestoreOutcome, RestoreImport,
    drive_production,
};
use super::backup_restore_ports::{
    KernelIsolatedDestination, KernelRestoreJournal, RestorePorts,
};
use eliot_ors::{SupervisionLeaseCommitTicket, SupervisionLeaseSnapshot};

/// Wire identity of the Host-issued restore destination authorization.
pub const DESTINATION_AUTHORIZATION_WIRE: &str =
    "eliot.host.restore-destination-authorization.v1";
/// Issuer identity every accepted destination authorization must carry.
/// Non-authoritative hint: authority comes from the authenticated delivery
/// channel plus the ORS-journaled binding, never from this literal.
pub const DESTINATION_AUTHORIZATION_ISSUER: &str = "host-restore-destination-owner";
/// Missing live canonical-store import channel: writing the live store is
/// never staged locally; the effect crosses the retained gateway.
pub const STORE_IMPORT_CHANNEL: &str = "canonical-store-gateway-import";
/// Missing per-member purge suppression API: no in-tree contract maps a
/// ledger `subject_ref` to archive member identities.
pub const PURGE_MEMBER_SUPPRESSION: &str = "purge-member-suppression";

/// Live-authority invalidation kinds. Each names the exact owner that must
/// execute it; only the lease kind has an in-tree execution API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationKind {
    Runtime,
    Session,
    Lease,
    Route,
    UserBroker,
}

impl InvalidationKind {
    /// Obligation owner id for this invalidation.
    #[must_use]
    pub const fn owner_id(self) -> &'static str {
        match self {
            Self::Runtime => "runtime-owner",
            Self::Session => "session-owner",
            Self::Lease => "lease-owner",
            Self::Route => "route-owner",
            Self::UserBroker => "user-broker-owner",
        }
    }
}

/// Channel-level failure: either the backup-domain owner refusal or the
/// supervision-lease owner's typed refusal. Gateway transport refusals map
/// into the backup domain as target failures; unknown outcomes never become
/// errors here — they surface as [`ImportReconciliation::Unknown`].
#[derive(Debug)]
pub enum OwnerChannelError {
    Backup(BackupError),
    Lease(SupervisionLeaseAuthorityError),
}

impl From<BackupError> for OwnerChannelError {
    fn from(error: BackupError) -> Self {
        Self::Backup(error)
    }
}

impl std::fmt::Display for OwnerChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backup(error) => write!(f, "owner channel backup failure: {error}"),
            Self::Lease(error) => write!(f, "owner channel lease failure: {error}"),
        }
    }
}

/// Caller-supplied binding expectation for one destination authorization.
pub struct AuthorizationExpectation<'a> {
    /// Isolated restore target the authorization must bind.
    pub target_id: &'a str,
    /// Restore transaction the authorization must bind.
    pub transaction_id: &'a str,
    /// Archive `config` artifact digest when the archive carries one; the
    /// admitted manifest digest must equal it.
    pub expected_manifest_digest: Option<&'a str>,
    /// Kernel work root the destination must live under (never caller text
    /// on the authoritative side; the coordinator supplies its own root).
    pub kernel_work_root: &'a Path,
}

/// Host-issued destination authorization after successful Kernel
/// verification: the exact target/transaction binding plus the owner digests,
/// registry revision, source installation, and approved generation every
/// effect client retains. This is the verified projection — never a second
/// issuance. `source_installation_id` and `approved_generation` are bound
/// here (never discarded): continuity against the first-journaled binding
/// is enforced at resume and cutover, so a swapped authorization binding a
/// different installation or generation refuses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDestinationBinding {
    manifest_digest: String,
    roots_digest: String,
    registry_revision: u64,
    source_installation_id: String,
    approved_generation: String,
    fence_generation: String,
    fence_config_digest: String,
    fence_authority_generation: u64,
}

impl VerifiedDestinationBinding {
    /// Canonical binding digest identifying this exact verified destination
    /// for effect receipts and journal comparisons.
    pub fn binding_digest(&self) -> String {
        let bytes = canonical_json_bytes(&(
            DESTINATION_AUTHORIZATION_WIRE,
            self.manifest_digest.as_str(),
            self.roots_digest.as_str(),
            self.registry_revision,
            self.source_installation_id.as_str(),
            self.approved_generation.as_str(),
            self.fence_generation.as_str(),
            self.fence_config_digest.as_str(),
            self.fence_authority_generation,
        ))
        .unwrap_or_default();
        sha256_hex(&bytes)
    }

    /// Owner config digest of the active manifest bound by this verification.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Digest of the manifest-bound runtime roots bound by this verification.
    pub fn roots_digest(&self) -> &str {
        &self.roots_digest
    }

    /// Registry CAS revision observed at Host inspection time.
    pub fn registry_revision(&self) -> u64 {
        self.registry_revision
    }

    /// Owner-observed source installation identity bound by this verification.
    pub fn source_installation_id(&self) -> &str {
        &self.source_installation_id
    }

    /// Active approved generation identity bound by this verification.
    pub fn approved_generation(&self) -> &str {
        &self.approved_generation
    }

    /// Committed fence generation bound by this verification.
    pub fn fence_generation(&self) -> &str {
        &self.fence_generation
    }

    /// Committed fence config digest bound by this verification.
    pub fn fence_config_digest(&self) -> &str {
        &self.fence_config_digest
    }

    /// Committed fence authority generation bound by this verification.
    pub fn fence_authority_generation(&self) -> u64 {
        self.fence_authority_generation
    }
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn auth_text<'a>(auth: &'a serde_json::Value, field: &'static str) -> Result<&'a str, BackupError> {
    auth.get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or(BackupError::PlanMismatch)
}

fn auth_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

/// Verifies Host-issued destination authorization bytes before any effect.
///
/// Checks wire/issuer identity, exact target/transaction binding against
/// `expectation`, digest shapes, work-root containment (the bound root must
/// canonicalize-equal the Kernel's own root), manifest agreement with
/// the archive, and the owner-observed source installation and approved
/// generation identities (bound into the verification, never discarded).
/// Any refusal fails closed with the exact binding error — never a default
/// success, never a self-authorized write. The wire/issuer literals are
/// non-authoritative hints only: authority comes from the ORS-journaled
/// binding plus agreement with independently observed evidence, established
/// by the caller after this shape/binding filter passes.
pub fn verify_destination_authorization(
    auth_json: &[u8],
    expectation: &AuthorizationExpectation<'_>,
) -> Result<VerifiedDestinationBinding, BackupError> {
    if auth_json.is_empty() || auth_json.len() > 16_384 {
        return Err(BackupError::PlanMismatch);
    }
    let auth: serde_json::Value =
        serde_json::from_slice(auth_json).map_err(|error| BackupError::Serialization(error.to_string()))?;
    if auth.get("wire").and_then(serde_json::Value::as_str) != Some(DESTINATION_AUTHORIZATION_WIRE)
        || auth.get("issuer").and_then(serde_json::Value::as_str)
            != Some(DESTINATION_AUTHORIZATION_ISSUER)
    {
        return Err(BackupError::PlanMismatch);
    }
    if auth_text(&auth, "target_id")? != expectation.target_id
        || auth_text(&auth, "transaction_id")? != expectation.transaction_id
    {
        return Err(BackupError::PlanMismatch);
    }
    let source_installation_id = auth_text(&auth, "source_installation_id")?;
    if !auth_identity(source_installation_id) {
        return Err(BackupError::PlanMismatch);
    }
    let manifest_digest = auth_text(&auth, "manifest_digest")?;
    let roots_digest = auth_text(&auth, "roots_digest")?;
    if !is_hex64(manifest_digest) || !is_hex64(roots_digest) {
        return Err(BackupError::PlanMismatch);
    }
    let registry_revision = auth
        .get("registry_revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or(BackupError::PlanMismatch)?;
    let approved_generation = auth_text(&auth, "approved_generation")?;
    if !auth_identity(approved_generation) {
        return Err(BackupError::PlanMismatch);
    }
    let fence_generation = auth_text(&auth, "fence_generation")?;
    if !auth_identity(fence_generation) {
        return Err(BackupError::PlanMismatch);
    }
    let fence_config_digest = auth_text(&auth, "fence_config_digest")?;
    if !is_hex64(fence_config_digest) {
        return Err(BackupError::PlanMismatch);
    }
    let fence_authority_generation = auth
        .get("fence_authority_generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or(BackupError::PlanMismatch)?;
    // Fence↔manifest agreement re-proven from the delivered fields: a
    // splice of manifest facts from different inspections refuses here.
    if fence_generation != approved_generation
        || fence_config_digest != manifest_digest
    {
        return Err(BackupError::PlanMismatch);
    }
    let bound_root = auth_text(&auth, "kernel_work_root")?;
    let own_root = std::fs::canonicalize(expectation.kernel_work_root)
        .map_err(|error| BackupError::Target(error.to_string()))?;
    let admitted_root = std::fs::canonicalize(Path::new(bound_root))
        .map_err(|error| BackupError::Target(error.to_string()))?;
    if own_root != admitted_root {
        return Err(BackupError::FenceMismatch {
            subject: "destination authorization work root".to_owned(),
        });
    }
    if let Some(expected) = expectation.expected_manifest_digest
        && manifest_digest != expected
    {
        return Err(BackupError::FenceMismatch {
            subject: "destination manifest".to_owned(),
        });
    }
    Ok(VerifiedDestinationBinding {
        manifest_digest: manifest_digest.to_owned(),
        roots_digest: roots_digest.to_owned(),
        registry_revision,
        source_installation_id: source_installation_id.to_owned(),
        approved_generation: approved_generation.to_owned(),
        fence_generation: fence_generation.to_owned(),
        fence_config_digest: fence_config_digest.to_owned(),
        fence_authority_generation,
    })
}

/// Purge owner client: validates the purge ledger through the owner's
/// accepted validation before any import.
///
/// Per-entry `validate` is the owner check the archive already passed at
/// bundle validation and each purge phase re-proves; the staged ledger is
/// the tombstone preservation itself. `validate_restore` (refusing
/// `Purged`-state resurrection) is deliberately NOT called here: ledger
/// entries legitimately sit at `Purged`, and it guards resurrection into
/// live authority — isolated import preserves tombstones instead.
pub struct PurgeOwnerClient<'a> {
    entries: &'a [PurgeLedgerEntry],
    destination_binding_digest: String,
}

impl<'a> PurgeOwnerClient<'a> {
    /// Binds the client's view to the archive's purge ledger. Construction
    /// requires the verified destination binding: no verification, no
    /// client, no effect.
    pub fn bind(
        entries: &'a [PurgeLedgerEntry],
        verified: &VerifiedDestinationBinding,
    ) -> Self {
        Self {
            entries,
            destination_binding_digest: verified.binding_digest(),
        }
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Runs the owner's accepted per-entry validation.
    pub fn validate_entries(&self) -> Result<(), BackupError> {
        for entry in self.entries {
            entry
                .validate()
                .map_err(|error| BackupError::Security(error.to_string()))?;
        }
        Ok(())
    }

    /// Suppression of one purged member. Unavailable: no accepted contract
    /// maps a ledger `subject_ref` to archive member identities. Fails
    /// closed as backlog rather than guessing.
    pub fn suppress_purged_member(&self, _subject_ref: &str) -> Result<(), BackupError> {
        Err(BackupError::RestoreCapabilityUnsupported {
            capability: PURGE_MEMBER_SUPPRESSION,
        })
    }
}

/// Canonical owner client: runs the owner's accepted validation and
/// verification over staged members.
///
/// Record/receipt validation and receipt/event-chain coverage are the
/// owner's checks, invoked here with the exact members the phase touches.
/// Live-store effects belong to [`CanonicalStoreImportClient`]: this client
/// never presents a staged byte as an executed owner transition.
pub struct CanonicalOwnerClient {
    destination_binding_digest: String,
}

impl CanonicalOwnerClient {
    /// Binds the client under the verified destination. No verification, no
    /// client, no effect.
    pub fn bind(verified: &VerifiedDestinationBinding) -> Self {
        Self {
            destination_binding_digest: verified.binding_digest(),
        }
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Runs the owner's accepted canonical-record validation.
    pub fn validate_event(record: &CanonicalRecord) -> Result<(), BackupError> {
        record.validate()
    }

    /// Runs the owner's accepted write-receipt validation.
    pub fn validate_receipt(receipt: &WriteReceipt) -> Result<(), BackupError> {
        receipt.validate().map_err(BackupError::Store)
    }

    /// Runs receipt/event-chain coverage over the exact staged members using
    /// only owner primitives: every receipt validates through the owner and
    /// every emitted event id must be carried by the staged events.
    pub fn verify_chain(
        receipts: &[WriteReceipt],
        events: &[CanonicalRecord],
    ) -> Result<(), BackupError> {
        let event_ids: std::collections::BTreeSet<&str> = events
            .iter()
            .map(|event| event.record_id.as_str())
            .collect();
        for receipt in receipts {
            Self::validate_receipt(receipt)?;
            for event_id in &receipt.emitted_event_ids {
                if !event_ids.contains(event_id.as_str()) {
                    return Err(BackupError::ReceiptChainGap {
                        event_id: event_id.to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Reconciliation outcome for one live store import: exact applied receipt,
/// proven non-application, or undecidable bytes. Undecidable never becomes
/// success — the coordinator takes the explicit rollback-required
/// disposition (I14.21) with no new identity and no blind retry.
#[derive(Clone, Debug)]
pub enum ImportReconciliation {
    Applied(Box<WriteReceipt>),
    NotApplied,
    Unknown,
}

/// Live canonical-store import client: executes Governor-built restore
/// transitions through the retained canonical-store gateway — the accepted
/// A12.3 write path — and reconciles them by exact operation identity.
///
/// The client never builds semantics: `transition` is supplied by its owner
/// (the Governor path that admitted it) with the exact operation identity
/// the coordinator journaled as intent before the effect. The gateway runs
/// fixed Kernel admission plus `recover_commit` unknown-commit recovery, so
/// intent-before-effect and reconcile-unknown hold end to end.
pub struct CanonicalStoreImportClient {
    gateway: Arc<KernelStoreGateway>,
    destination_binding_digest: String,
}

impl CanonicalStoreImportClient {
    /// Binds the client to the retained gateway under the verified
    /// destination. No verification, no client, no effect.
    pub fn bind(gateway: Arc<KernelStoreGateway>, verified: &VerifiedDestinationBinding) -> Self {
        Self {
            gateway,
            destination_binding_digest: verified.binding_digest(),
        }
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Requires the per-effect verified binding to match this client's
    /// construction binding. Any drift refuses the effect instead of
    /// continuing under changed authority.
    fn gate(&self, verified: &VerifiedDestinationBinding) -> Result<(), BackupError> {
        if verified.binding_digest() != self.destination_binding_digest {
            return Err(BackupError::FenceMismatch {
                subject: "destination authorization".to_owned(),
            });
        }
        Ok(())
    }

    /// Executes one Governor-built restore transition through the gateway.
    ///
    /// Pre-send, the transition validates through the owner and its
    /// operation identity must equal the journaled `operation_id`;
    /// post-send, possible execution follows the gateway's unknown-commit
    /// recovery. A transport refusal before send is distinct from a
    /// possible effect after send — the latter reconciles by identity.
    pub async fn import_transition(
        &self,
        verified: &VerifiedDestinationBinding,
        context: &RequestMetadata,
        transition: PreparedTransition,
        operation_id: &OperationId,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, OwnerChannelError> {
        self.gate(verified)?;
        transition
            .validate()
            .map_err(BackupError::Store)
            .map_err(OwnerChannelError::Backup)?;
        if transition.identity.operation_id != *operation_id {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        self.gateway
            .apply(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
            .map_err(BackupError::Target)
            .map_err(OwnerChannelError::Backup)
    }

    /// Re-fetches the independent journal anchor live and requires it to
    /// anchor the presented admission.
    ///
    /// The stream key comes from the owner-held journal handle (never
    /// caller spelling) and the binding is the owner's durably held value
    /// read back now, not a presented copy: stream key, binding digest,
    /// transaction, destination, and source archive must all match the
    /// admission, and the writer fence digest must match the fence
    /// presented at import (a rotated authority refuses instead of
    /// importing under stale bindings). Self-consistency was already
    /// proven by `admission.validate()`; this proves anchoring.
    fn require_journal_anchor(
        journal: &KernelRestoreJournal,
        admission: &KernelRestoreAdmission,
        live_fence: &StateFence,
    ) -> Result<(), BackupError> {
        let live_stream = journal
            .bound_stream()
            .ok_or(BackupError::RestoreJournalMismatch)?;
        if live_stream != admission.journal_stream() {
            return Err(BackupError::RestoreJournalMismatch);
        }
        let live = journal
            .read_durable_binding(live_stream)
            .map_err(|error| BackupError::Target(error.to_string()))?
            .ok_or(BackupError::RestoreJournalMismatch)?;
        if live.transaction_id != admission.transaction_id() {
            return Err(BackupError::RestoreJournalMismatch);
        }
        if live.destination_ref != admission.target_id() {
            return Err(BackupError::RestoreJournalMismatch);
        }
        if live.source_archive_id != admission.source_archive_id() {
            return Err(BackupError::RestoreJournalMismatch);
        }
        let live_bytes = canonical_json_bytes(&live)
            .map_err(|error| BackupError::Target(error.to_string()))?;
        if sha256_hex(&live_bytes) != admission.journal_binding_digest() {
            return Err(BackupError::RestoreJournalMismatch);
        }
        let fence_bytes = canonical_json_bytes(live_fence)
            .map_err(|error| BackupError::Target(error.to_string()))?;
        if sha256_hex(&fence_bytes) != live.writer_fence_digest {
            return Err(BackupError::RestoreJournalMismatch);
        }
        Ok(())
    }

    /// Enforces one Governor-minted restore admission against the
    /// destination and fence it is presented for, shared by the restore
    /// import and coordination commit wires. Identity binding is enforced
    /// by each wire separately: imports link by decision-digest reference
    /// (per-import identities stay distinct), while the coordination
    /// commit requires full triple equality (single-anchor rule).
    /// Divergence conflicts here, never at the store.
    fn check_restore_admission(
        &self,
        transition: &PreparedTransition,
        admission: &KernelRestoreAdmission,
    ) -> Result<(), BackupError> {
        if admission.destination_binding_digest() != self.destination_binding_digest {
            return Err(BackupError::FenceMismatch {
                subject: "destination authorization".to_owned(),
            });
        }
        if admission.fence() != &transition.state_fence {
            return Err(BackupError::FenceMismatch {
                subject: "restore admission fence is not current".to_owned(),
            });
        }
        admission.validate()
    }

    /// Requires one closed coordination parameter to equal its decision
    /// field. Divergence between parameters and decision refuses: the
    /// bridge persists parameters verbatim, so a mismatch would admit a
    /// row the decision never made.
    fn check_coordination_parameter(
        parameters: &BTreeMap<String, Value>,
        key: &'static str,
        expected: &str,
    ) -> Result<(), BackupError> {
        if parameters.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(BackupError::PlanMismatch);
        }
        Ok(())
    }

    /// Executes one Governor-admitted restore transition through the gateway.
    ///
    /// The admitted-restore wire: restore imports run only under a
    /// Governor-minted [`KernelRestoreAdmission`] covering this import.
    /// Each import carries the admission's decision digest in its proof
    /// handles (set by the Governor builder); an import that does not
    /// reference the enforced admission refuses here. The admission
    /// itself is enforced for destination, fence, and decision before
    /// any store effect — a fence-diverged admission or a diverged
    /// decision digest refuses (conflict, never retry-as-same). The
    /// journal anchor is re-fetched live below: the importer reads the
    /// owner-held stream binding from the journal handle at import time
    /// and requires it to anchor the presented admission, so a
    /// self-consistent admission the journal does not anchor refuses
    /// with `RestoreJournalMismatch`. Per-import transition identities
    /// stay distinct (idempotency per import); the single restore
    /// identity lives in the admission and the coordination row, never
    /// duplicated. Ordinary canonical imports keep using
    /// [`Self::import_transition`]; this wire never admits them.
    pub async fn import_restore_transition(
        &self,
        verified: &VerifiedDestinationBinding,
        context: &RequestMetadata,
        transition: PreparedTransition,
        operation_id: &OperationId,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        admission: &KernelRestoreAdmission,
        journal: &KernelRestoreJournal,
    ) -> Result<WriteReceipt, OwnerChannelError> {
        self.gate(verified)?;
        transition
            .validate()
            .map_err(BackupError::Store)
            .map_err(OwnerChannelError::Backup)?;
        require_restore_transition_class(&transition).map_err(OwnerChannelError::Backup)?;
        if transition.identity.operation_id != *operation_id {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        // Admission reference: the import must carry this admission's
        // decision digest in its proof handles (bound by the Governor
        // builder). Per-import identities stay distinct for idempotent
        // replay; the admission is linked by digest reference, never by
        // identity equality — there is deliberately one restore identity,
        // carried by the admission and the coordination row, not one per
        // import.
        if !transition
            .required_proof_and_approval_refs
            .iter()
            .any(|proof| proof == admission.decision_digest())
        {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        self.check_restore_admission(&transition, admission)
            .map_err(OwnerChannelError::Backup)?;
        Self::require_journal_anchor(journal, admission, &context.state_fence)
            .map_err(OwnerChannelError::Backup)?;
        self.gateway
            .apply(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
            .map_err(BackupError::Target)
            .map_err(OwnerChannelError::Backup)
    }

    /// Commits one Governor restore coordination decision as a canonical
    /// transition and proves it re-fetchable by operation identity.
    ///
    /// The coordination-row writer (H1): the Governor-built transition
    /// carrying the closed coordination parameters commits through the
    /// single canonical write path (gateway apply with unknown-commit
    /// recovery — never reimplemented here). The committed receipt must
    /// bind the operation identity, and an identity readback must return
    /// the same receipt: that readback is the mechanism the bridge uses
    /// to fetch the anchor independently, exercised here before the row
    /// key is handed out. Returns the committed receipt plus the row key
    /// (operation identity string) for bridge readback. Unknown outcomes
    /// propagate as target failures for identity reconciliation by the
    /// caller — never a fabricated receipt, never a blind retry.
    pub async fn commit_coordination_row(
        &self,
        verified: &VerifiedDestinationBinding,
        context: &RequestMetadata,
        transition: PreparedTransition,
        operation_id: &OperationId,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        admission: &KernelRestoreAdmission,
        decision: &CoordinationDecision,
    ) -> Result<(WriteReceipt, String), OwnerChannelError> {
        self.gate(verified)?;
        transition
            .validate()
            .map_err(BackupError::Store)
            .map_err(OwnerChannelError::Backup)?;
        require_restore_transition_class(&transition).map_err(OwnerChannelError::Backup)?;
        if transition.identity.operation_id != *operation_id {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        self.check_restore_admission(&transition, admission)
            .map_err(OwnerChannelError::Backup)?;
        // Single-anchor rule: the coordination transition commits UNDER
        // the restore identity — full triple equality, no second
        // identity. The bridge fetches the coordination receipt by this
        // exact identity.
        if admission.identity() != &transition.identity {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        // Decision binding: the decision links this exact admission and
        // transition — operation, payload, destination, and fence must all
        // agree across decision, admission, and transition, or the commit
        // would admit a row the decision never made.
        if decision.admission_decision_digest() != admission.decision_digest() {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        if decision.operation_id() != &transition.identity.operation_id {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        if decision.payload_digest() != transition.identity.canonical_request_hash.as_str() {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        if decision.destination() != admission.target_id() {
            return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
        }
        if decision.fence() != &transition.state_fence {
            return Err(OwnerChannelError::Backup(BackupError::FenceMismatch {
                subject: "restore admission fence is not current".to_owned(),
            }));
        }
        decision
            .validate()
            .map_err(OwnerChannelError::Backup)?;
        // Closed single-operation structure: a coordination commit carries
        // exactly one named operation whose parameters equal the decision
        // fields. The operation variant itself stays Store-owned (M1B);
        // until its catalogue row activates, validation below fail-closes.
        if transition.named_operations.len() != 1 {
            return Err(OwnerChannelError::Backup(BackupError::InvalidField {
                field: "restore.coordination_operations",
                reason: "coordination commit carries exactly one named operation",
            }));
        }
        let parameters = &transition.named_operations[0].parameters;
        let fence_bytes = canonical_json_bytes(decision.fence())
            .map_err(|error| OwnerChannelError::Backup(BackupError::Target(error.to_string())))?;
        Self::check_coordination_parameter(
            parameters,
            COORD_PARAM_OPERATION_ID,
            decision.operation_id().to_string().as_str(),
        )
        .map_err(OwnerChannelError::Backup)?;
        Self::check_coordination_parameter(
            parameters,
            COORD_PARAM_DESTINATION,
            decision.destination(),
        )
        .map_err(OwnerChannelError::Backup)?;
        Self::check_coordination_parameter(
            parameters,
            COORD_PARAM_PAYLOAD_DIGEST,
            decision.payload_digest(),
        )
        .map_err(OwnerChannelError::Backup)?;
        Self::check_coordination_parameter(
            parameters,
            COORD_PARAM_FENCE_DIGEST,
            sha256_hex(&fence_bytes).as_str(),
        )
        .map_err(OwnerChannelError::Backup)?;
        Self::check_coordination_parameter(
            parameters,
            COORD_PARAM_DECISION_DIGEST,
            decision.decision_digest(),
        )
        .map_err(OwnerChannelError::Backup)?;
        Self::check_coordination_parameter(
            parameters,
            COORD_PARAM_ADMISSION_DIGEST,
            decision.admission_decision_digest(),
        )
        .map_err(OwnerChannelError::Backup)?;
        let receipt = self
            .gateway
            .apply(
                context,
                transition.clone(),
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
            .map_err(BackupError::Target)
            .map_err(OwnerChannelError::Backup)?;
        CanonicalOwnerClient::validate_receipt(&receipt)
            .map_err(OwnerChannelError::Backup)?;
        if receipt.operation_id != transition.identity.operation_id
            || receipt.idempotency_key != transition.identity.idempotency_key
            || receipt.canonical_request_hash != transition.identity.canonical_request_hash
            || receipt.transition_class != TransitionClass::RecoverySchema
            || receipt.status != WriteReceiptStatus::Committed
        {
            return Err(OwnerChannelError::Backup(BackupError::Target(
                "coordination commit did not commit the admitted operation".to_owned(),
            )));
        }
        if receipt.state_fence != transition.state_fence {
            return Err(OwnerChannelError::Backup(BackupError::FenceMismatch {
                subject: "coordination receipt fence diverged".to_owned(),
            }));
        }
        // Readback proof: the committed row must be re-fetchable by exact
        // operation identity through the same receipt mechanism the bridge
        // uses. A successful commit the store cannot return stays
        // unclaimed here instead of becoming an unattested row key.
        let row_key = decision.row_key();
        let readback = self
            .gateway
            .receipt(
                &transition.state_fence,
                transition.identity.operation_id.clone(),
            )
            .await
            .map_err(|error| OwnerChannelError::Backup(BackupError::Target(error)))?;
        match readback {
            Some(confirmed)
                if confirmed.operation_id == receipt.operation_id
                    && confirmed.canonical_request_hash == receipt.canonical_request_hash
                    && confirmed.status == WriteReceiptStatus::Committed =>
            {
                Ok((receipt, row_key))
            }
            _ => Err(OwnerChannelError::Backup(BackupError::Target(
                "coordination receipt not re-fetchable by identity".to_owned(),
            ))),
        }
    }

    /// Reconciles one import by exact operation identity through owner
    /// readback: a present receipt bound to this operation is `Applied`;
    /// its absence is `NotApplied` and the coordinator re-applies
    /// idempotently under the same identity; an owner/transport refusal to
    /// answer is `Unknown` and never a fabricated outcome.
    pub async fn reconcile_import(
        &self,
        state_fence: &StateFence,
        operation_id: OperationId,
    ) -> ImportReconciliation {
        match self.gateway.receipt(state_fence, operation_id).await {
            Ok(Some(receipt)) => ImportReconciliation::Applied(Box::new(receipt)),
            Ok(None) => ImportReconciliation::NotApplied,
            Err(_) => ImportReconciliation::Unknown,
        }
    }
}

/// Blob owner client: restores sealed blobs under destination ownership
/// through the accepted destination adapter.
///
/// Binds the backup-bound restoration receipts (issued through
/// `issue_restoration_receipts` from the validated bundle and admitted key
/// manifest under exact `verify_key_coverage`), the admitted key manifest,
/// and the destination scope. Invocation opens the sealed envelope through
/// the installation secret owner, digest-verifies the plaintext, and
/// re-seals under the destination lineage: key material and plaintext stay
/// memory-only inside the adapter and never cross back.
pub struct BlobOwnerClient<'a> {
    receipts: Vec<BlobRestorationReceipt>,
    manifest: &'a WrappedKeyManifest,
    scope: &'a DestinationScope,
    destination_binding_digest: String,
}

impl<'a> BlobOwnerClient<'a> {
    /// Binds restoration receipts, key manifest, destination scope, and the
    /// verified destination. All bindings must be present: a blob without
    /// any binding refuses.
    pub fn bind(
        receipts: Vec<BlobRestorationReceipt>,
        manifest: Option<&'a WrappedKeyManifest>,
        scope: Option<&'a DestinationScope>,
        verified: &VerifiedDestinationBinding,
    ) -> Result<Self, BackupError> {
        let manifest = manifest.ok_or(BackupError::MissingRecoveryComponent("blob_key_material"))?;
        let scope = scope.ok_or(BackupError::RestoreCapabilityUnsupported {
            capability: "blob-destination-scope",
        })?;
        Ok(Self {
            receipts,
            manifest,
            scope,
            destination_binding_digest: verified.binding_digest(),
        })
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Issues backup-bound restoration receipts through the owner function
    /// (which re-proves exact key coverage first).
    pub fn issue_receipts(
        backup_id: &str,
        manifest: &WrappedKeyManifest,
        blobs: &[BackupBlob],
    ) -> Result<Vec<BlobRestorationReceipt>, BackupError> {
        issue_restoration_receipts(backup_id, manifest, blobs)
    }

    /// Re-proves exact key coverage before effects.
    pub fn ensure_key_coverage(
        blobs: &[BackupBlob],
        manifest: &WrappedKeyManifest,
    ) -> Result<(), BackupError> {
        verify_key_coverage(blobs, manifest)
    }

    /// Restores one sealed blob: receipt binding, envelope open, plaintext
    /// digest verification, destination re-seal. The per-effect verified
    /// binding must match construction; any refusal fails the phase closed
    /// — never write-through.
    pub fn restore_blob(
        &self,
        verified: &VerifiedDestinationBinding,
        adapter: &DestinationRestoreAdapter,
        blob: &BackupBlob,
    ) -> Result<RestoredSealedBlob, BackupError> {
        if verified.binding_digest() != self.destination_binding_digest {
            return Err(BackupError::FenceMismatch {
                subject: "destination authorization".to_owned(),
            });
        }
        let receipt = self
            .receipts
            .iter()
            .find(|receipt| receipt.blob_hash == blob.locator.hash.as_str())
            .ok_or(BackupError::PlanMismatch)?;
        adapter.restore_blob_sealed(blob, receipt, self.manifest, self.scope)
    }
}

/// ORS owner client: derives suspended-recovery evidence through the
/// accepted pure function.
///
/// Suspended entries are evidence only: restored ORS operations return as
/// `suspended_recovery`, never runnable, and this client performs no live
/// ORS mutation.
pub struct OrsOwnerClient {
    destination_binding_digest: String,
}

impl OrsOwnerClient {
    /// Binds the client under the verified destination. No verification, no
    /// client.
    pub fn bind(verified: &VerifiedDestinationBinding) -> Self {
        Self {
            destination_binding_digest: verified.binding_digest(),
        }
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Derives suspended-recovery entries from a validated ORS snapshot.
    pub fn suspend(
        snapshot: &OrsSnapshotFence,
    ) -> Result<Vec<RestoreHistoricalAuthority>, BackupError> {
        suspended_recovery_entries(snapshot)
    }
}

/// Live-authority invalidation owner client (cutover-gated).
///
/// Old sessions, leases, routes, broker registrations, and epochs must not
/// survive alongside a cutover. Lease revocation executes for real through
/// the supervision-lease authority when the caller supplies the terminal
/// ticket (with predecessor proof, trust anchor, and signer held by the
/// authority); session detach, broker fence, and route retirement execute
/// through their dedicated owner clients (see `SessionOwnerClient`,
/// `BrokerOwnerClient`, and the router-owner executor in `backup_restore`),
/// while only the runtime kind has no execution API in-tree and refuses
/// with its exact owner — prior-generation retirement belongs to the #961
/// installation-cutover owner. Without a
/// validated cutover receipt every kind refuses with `CutoverNotAuthorized`:
/// invalidating live authority during isolated rehearsal would be
/// destructive.
pub struct InvalidationOwnerClient {
    kind: InvalidationKind,
    destination_binding_digest: String,
}

impl InvalidationOwnerClient {
    /// Binds the client to one invalidation kind under the verified
    /// destination.
    pub fn bind(kind: InvalidationKind, verified: &VerifiedDestinationBinding) -> Self {
        Self {
            kind,
            destination_binding_digest: verified.binding_digest(),
        }
    }

    /// Invalidation kind this client was constructed for.
    pub fn kind(&self) -> InvalidationKind {
        self.kind
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Revokes one supervision lease through the lease owner after
    /// cutover-gating: the cutover receipt validates through the accepted
    /// function, the per-effect verified binding must match construction,
    /// then the authority commits the caller-supplied terminal ticket.
    pub fn revoke_lease(
        &self,
        verified: &VerifiedDestinationBinding,
        authority: &KernelSupervisionLeaseAuthority,
        ticket: &SupervisionLeaseCommitTicket,
        cutover: &CutoverReceipt,
    ) -> Result<SupervisionLeaseSnapshot, OwnerChannelError> {
        if self.kind != InvalidationKind::Lease {
            return Err(OwnerChannelError::Backup(
                BackupError::RestoreCapabilityUnsupported {
                    capability: self.kind.owner_id(),
                },
            ));
        }
        cutover
            .validate()
            .map_err(OwnerChannelError::Backup)?;
        if verified.binding_digest() != self.destination_binding_digest {
            return Err(OwnerChannelError::Backup(BackupError::FenceMismatch {
                subject: "destination authorization".to_owned(),
            }));
        }
        authority
            .commit_terminal(ticket)
            .map_err(OwnerChannelError::Lease)
    }

    /// Requests a non-lease invalidation. Cutover-gated and channel-absent:
    /// always refuses here, naming either the missing cutover authority or
    /// the missing owner execution API. No live state is touched.
    pub fn request(&self, cutover: Option<&CutoverReceipt>) -> Result<(), BackupError> {
        if self.kind == InvalidationKind::Lease {
            return Err(BackupError::RestoreCapabilityUnsupported {
                capability: "lease-terminal-ticket",
            });
        }
        match cutover {
            None => Err(BackupError::CutoverNotAuthorized),
            Some(receipt) => {
                receipt.validate()?;
                Err(BackupError::RestoreCapabilityUnsupported {
                    capability: self.kind.owner_id(),
                })
            }
        }
    }
}

/// Retained live-owner handles for restore effect execution, injected from
/// the composition (never test fakes: construction fails closed when the
/// canonical-store gateway is absent or fenced for rebind).
pub struct BackupOwnerChannels {
    store_gateway: Arc<KernelStoreGateway>,
}

impl BackupOwnerChannels {
    /// Canonical-store gateway this bundle executes live imports through.
    pub fn store_gateway(&self) -> &Arc<KernelStoreGateway> {
        &self.store_gateway
    }

    /// Builds the live canonical-store import client under the verified
    /// destination.
    pub fn store_import_client(
        &self,
        verified: &VerifiedDestinationBinding,
    ) -> CanonicalStoreImportClient {
        CanonicalStoreImportClient::bind(Arc::clone(&self.store_gateway), verified)
    }
}

impl KernelComposition {
    /// Injects the live restore owner channels from composition-retained
    /// state.
    ///
    /// Clones the retained canonical-store gateway; an absent gateway, a
    /// poisoned lock, or a gateway fenced for rebind fails closed before
    /// any owner channel exists — production constructors bind actual
    /// clients, never test fakes.
    pub fn backup_owner_channels(
        self: &Arc<Self>,
        _destination_root: &PathBuf,
    ) -> Result<BackupOwnerChannels, OwnerChannelError> {
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| {
                OwnerChannelError::Backup(BackupError::Target(
                    "canonical-store gateway lock poisoned".to_owned(),
                ))
            })?
            .clone()
            .ok_or(OwnerChannelError::Backup(
                BackupError::RestoreCapabilityUnsupported {
                    capability: STORE_IMPORT_CHANNEL,
                },
            ))?;
        if gateway.is_fenced() {
            return Err(OwnerChannelError::Backup(BackupError::Target(
                "canonical-store gateway is fenced for rebind".to_owned(),
            )));
        }
        Ok(BackupOwnerChannels {
            store_gateway: gateway,
        })
    }

    /// Dispatches one production restore from composition-held owners plus
    /// operator-supplied archive/target/authorization (H5 operator dispatch,
    /// issues #960/#962/#963).
    ///
    /// Assembly order with real owner calls only: bind the journal against
    /// the retained operational store (no reopen, no second writer);
    /// inject owner channels from retained composition state; validate and
    /// compile the operator archive; verify destination authorization;
    /// open the constructed destination under the adapter work root bound
    /// to the plan target; then delegate to [`drive_production`], which
    /// mints, live-verifies introductions, decides, commits, imports, and
    /// reconciles. The Governor-built coordination commit, restore-class
    /// imports, provisioning attestations, live fence, and admitted ports
    /// arrive as params from their owning lanes — this dispatch never
    /// synthesizes, defaults, or re-spells them. Any refusal fails closed
    /// with the exact owner cause before any effect.
    pub async fn dispatch_production_restore(
        self: &Arc<Self>,
        bundle: &BackupBundle,
        target: RestoreContext,
        ports: &RestorePorts<'_>,
        destination_authorization: &[u8],
        authorization: AuthorizationExpectation<'_>,
        live_fence: &StateFence,
        provisioning: RestoreProvisioningProof,
        coordination: CoordinationCommit,
        imports: Vec<RestoreImport>,
        introductions: Vec<CapabilityIntroductionProjection>,
    ) -> Result<ProductionRestoreOutcome, OwnerChannelError> {
        ports.validate().map_err(|error| {
            OwnerChannelError::Backup(BackupError::Target(error.to_string()))
        })?;
        let journal =
            KernelRestoreJournal::bind_owner(Arc::clone(self.ors_store())).map_err(|error| {
                OwnerChannelError::Backup(BackupError::Target(error.to_string()))
            })?;
        let channels = self.backup_owner_channels(&self.backup_restore().work_root().to_path_buf())?;
        let plan = KernelBackupRestore::compile_plan(bundle, target).map_err(|error| {
            OwnerChannelError::Backup(BackupError::Target(error.to_string()))
        })?;
        let destination =
            KernelIsolatedDestination::open(self.backup_restore().work_root(), &plan.target.target_id)
                .map_err(|error| {
                    OwnerChannelError::Backup(BackupError::Target(error.to_string()))
                })?;
        drive_production(ProductionRestoreCall {
            journal: &journal,
            channels: &channels,
            destination_authorization,
            authorization,
            plan: &plan,
            bundle,
            destination: &destination,
            live_fence,
            provisioning,
            coordination,
            imports,
            introductions,
        })
        .await
    }
}

/// Session owner client: detaches live sessions through the session
/// owner (Active → Suspended) under the verified destination.
///
/// Each detach executes against the owner's accepted mutation with the
/// exact bindings the coordinator supplies and returns the owner-issued
/// receipt. The client performs no enumeration itself: callers
/// enumerate-then-act on live Active subjects per attempt, so retries skip
/// already-detached sessions instead of erroring.
pub struct SessionOwnerClient {
    destination_binding_digest: String,
}

impl SessionOwnerClient {
    /// Binds the client under the verified destination. No verification,
    /// no client, no effect.
    pub fn bind(verified: &VerifiedDestinationBinding) -> Self {
        Self {
            destination_binding_digest: verified.binding_digest(),
        }
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Detaches one session: binding check, then the genuine owner
    /// operation. Any refusal fails the invalidation closed — never
    /// write-through, never a fabricated receipt.
    pub fn detach(
        &self,
        verified: &VerifiedDestinationBinding,
        journal: &KernelRestoreJournal,
        detach: SessionDetach,
    ) -> Result<SessionBindingReceipt, OwnerChannelError> {
        if verified.binding_digest() != self.destination_binding_digest {
            return Err(OwnerChannelError::Backup(BackupError::FenceMismatch {
                subject: "destination authorization".to_owned(),
            }));
        }
        journal
            .detach_restore_session(detach)
            .map_err(OwnerChannelError::Backup)
    }
}

/// User-broker owner client: fences live broker registrations through the
/// broker owner (Active → Fenced) under the verified destination.
///
/// Same enumerate-then-act retry discipline as sessions: each fence
/// executes against the owner's accepted mutation with the exact bindings
/// the coordinator supplies and returns the owner-issued receipt.
pub struct BrokerOwnerClient {
    destination_binding_digest: String,
}

impl BrokerOwnerClient {
    /// Binds the client under the verified destination. No verification,
    /// no client, no effect.
    pub fn bind(verified: &VerifiedDestinationBinding) -> Self {
        Self {
            destination_binding_digest: verified.binding_digest(),
        }
    }

    /// Destination binding digest this client was constructed under.
    pub fn destination_binding_digest(&self) -> &str {
        &self.destination_binding_digest
    }

    /// Fences one broker registration: binding check, then the genuine
    /// owner operation. Any refusal fails the invalidation closed.
    pub fn fence(
        &self,
        verified: &VerifiedDestinationBinding,
        journal: &KernelRestoreJournal,
        fence: UserBrokerFence,
    ) -> Result<UserBrokerRegistrationReceipt, OwnerChannelError> {
        if verified.binding_digest() != self.destination_binding_digest {
            return Err(OwnerChannelError::Backup(BackupError::FenceMismatch {
                subject: "destination authorization".to_owned(),
            }));
        }
        journal
            .fence_restore_broker(fence)
            .map_err(OwnerChannelError::Backup)
    }
}
