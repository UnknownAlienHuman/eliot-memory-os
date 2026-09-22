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
//!                    proof, trust anchor, and signer); runtime, session,
//!                    route, and user-broker invalidations have no execution
//!                    API in-tree and refuse with their exact owner.
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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_backup::{
    BackupBlob, BackupError, BlobRestorationReceipt, CanonicalRecord, CutoverReceipt,
    DestinationRestoreAdapter, DestinationScope, OrsSnapshotFence, RestoreHistoricalAuthority,
    RestoredSealedBlob, WrappedKeyManifest, issue_restoration_receipts, suspended_recovery_entries,
    verify_key_coverage,
};
use eliot_contracts::{OperationId, RequestMetadata, StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, WriteReceipt,
};

use super::{
    KernelComposition, KernelStoreGateway, KernelSupervisionLeaseAuthority,
    SupervisionLeaseAuthorityError,
};
use eliot_ors::{SupervisionLeaseCommitTicket, SupervisionLeaseSnapshot};

/// Wire identity of the Host-issued restore destination authorization.
pub const DESTINATION_AUTHORIZATION_WIRE: &str =
    "eliot.host.restore-destination-authorization.v1";
/// Issuer identity every accepted destination authorization must carry.
pub const DESTINATION_AUTHORIZATION_ISSUER: &str = "host-restore-destination-owner";
/// Pinned transport filename inside the isolated destination: the
/// Host-authorized preparation flow writes the issued authorization here and
/// the Kernel verifier reads it back before effects. No new pipe family or
/// transport is introduced; the file is the cross-process handoff both owner
/// halves document.
pub const DESTINATION_AUTHORIZATION_FILE: &str = "destination-authorization.json";
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
/// verification: the exact target/transaction binding plus the owner digests
/// and registry revision every effect client retains. This is the verified
/// projection — never a second issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDestinationBinding {
    manifest_digest: String,
    roots_digest: String,
    registry_revision: u64,
}

impl VerifiedDestinationBinding {
    /// Canonical binding digest identifying this exact verified destination
    /// for effect receipts.
    pub fn binding_digest(&self) -> String {
        let bytes = canonical_json_bytes(&(
            DESTINATION_AUTHORIZATION_WIRE,
            self.manifest_digest.as_str(),
            self.roots_digest.as_str(),
            self.registry_revision,
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

/// Verifies Host-issued destination authorization bytes before any effect.
///
/// Checks wire/issuer identity, exact target/transaction binding against
/// `expectation`, digest shapes, work-root containment (the bound root must
/// canonicalize-equal the Kernel's own root), and manifest agreement with
/// the archive. Any refusal fails closed with the exact binding error —
/// never a default success, never a self-authorized write.
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
    let _source = auth_text(&auth, "source_installation_id")?;
    let manifest_digest = auth_text(&auth, "manifest_digest")?;
    let roots_digest = auth_text(&auth, "roots_digest")?;
    if !is_hex64(manifest_digest) || !is_hex64(roots_digest) {
        return Err(BackupError::PlanMismatch);
    }
    let registry_revision = auth
        .get("registry_revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or(BackupError::PlanMismatch)?;
    let _generation = auth_text(&auth, "approved_generation")?;
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
/// authority); the runtime, session, route, and user-broker kinds have no
/// execution API in-tree and refuse with their exact owner. Without a
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
}
