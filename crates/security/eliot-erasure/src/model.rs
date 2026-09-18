use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_evidence::EvidenceEnvelope;
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::erasure_scope::ErasureScopeSnapshot;

/// A request contains references and policy evidence, never the private value
/// being erased.  `approval_digest` binds the operator approval to this exact
/// request and is deliberately not reversible into the erased content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErasureRequest {
    pub request_id: String,
    pub subject_ref: String,
    pub scope: String,
    pub locations: Vec<PurgeLocation>,
    pub expected_revision: u64,
    pub approval_digest: String,
    pub evidence: Vec<EvidenceEnvelope>,
    pub state_fence: StateFence,
}

impl ErasureRequest {
    pub fn validate(&self) -> Result<(), ErasureError> {
        text(&self.request_id, "request_id")?;
        text(&self.subject_ref, "subject_ref")?;
        text(&self.scope, "scope")?;
        self.state_fence
            .validate()
            .map_err(|_| ErasureError::InvalidField("state_fence"))?;
        if self.locations.is_empty() {
            return Err(ErasureError::EmptyLocations);
        }
        let mut locations = BTreeSet::new();
        for location in &self.locations {
            if !locations.insert(location_code(*location)) {
                return Err(ErasureError::DuplicateLocation);
            }
        }
        digest(&self.approval_digest, "approval_digest")?;
        for evidence in &self.evidence {
            evidence
                .validate()
                .map_err(|_| ErasureError::InvalidEvidence)?;
            if evidence.state_fence != self.state_fence {
                return Err(ErasureError::FenceMismatch);
            }
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, ErasureError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ErasureError::Canonicalization)?;
        Ok(sha256_hex(&bytes))
    }

    /// Binds this request to a frozen [`ErasureScopeSnapshot`] (contract shape
    /// only; performs no I/O and no destructive effect).
    ///
    /// Real cross-checks, all fail-closed: the snapshot validates; subject
    /// refs match; the frozen `subject_revision` equals `expected_revision`
    /// (I05-19: revalidate required revisions); every requested location is
    /// covered by the frozen denominator (a request outside the denominator is
    /// a scope gap, never silent coverage); fences are compatible; and the
    /// same `approval_digest` binds both (the packet shape itself remains an
    /// explicit gap per `ApprovalBinding`, so no new crypto is invented).
    /// Returns the binding digest over both canonical digests.
    pub fn bind_scope_snapshot(
        &self,
        snapshot: &ErasureScopeSnapshot,
    ) -> Result<String, ErasureError> {
        self.validate()?;
        snapshot
            .validate()
            .map_err(|_| ErasureError::InvalidScope)?;
        if snapshot.subject_ref != self.subject_ref {
            return Err(ErasureError::ScopeMismatch);
        }
        if snapshot.subject_revision != self.expected_revision {
            return Err(ErasureError::ScopeMismatch);
        }
        let frozen: BTreeSet<u8> = snapshot
            .targets
            .iter()
            .map(|target| location_code(target.location))
            .collect();
        if !self
            .locations
            .iter()
            .all(|location| frozen.contains(&location_code(*location)))
        {
            return Err(ErasureError::ScopeMismatch);
        }
        if !self.state_fence.is_compatible_with(&snapshot.state_fence) {
            return Err(ErasureError::FenceMismatch);
        }
        if snapshot.approval.approval_digest != self.approval_digest {
            return Err(ErasureError::ScopeMismatch);
        }
        let material = format!(
            "{}\0{}",
            self.request_digest()?,
            snapshot
                .scope_digest()
                .map_err(|_| ErasureError::InvalidScope)?
        );
        Ok(sha256_hex(material.as_bytes()))
    }
}

/// Durable erasure intent recorded BEFORE any destructive dispatch.
///
/// The `operation_id` is the caller-supplied `request_id`, never regenerated
/// on retry, so replaying the same intent id names the same operation.
/// `request_digest` binds the exact admitted request bytes: the same id with
/// a different digest is an [`ErasureError::IntentConflict`], never a silent
/// overwrite. `locations` is the exact admitted surface denominator for this
/// operation; `expected_revision` and `state_fence` pin the revision and
/// fence the destructive calls must execute under.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErasureIntent {
    pub operation_id: String,
    pub request_id: String,
    pub request_digest: String,
    pub subject_ref: String,
    pub scope: String,
    pub locations: Vec<PurgeLocation>,
    pub expected_revision: u64,
    pub state_fence: StateFence,
}

impl ErasureIntent {
    /// Builds the durable intent for one admitted request.
    ///
    /// Recomputes the canonical request digest and refuses a supplied digest
    /// that does not match: supplied strings cannot prove authorization or
    /// durable commit. The operation id is the caller-supplied request id so
    /// retries name the same operation without minting a new one.
    pub fn new(request: &ErasureRequest, request_digest: &str) -> Result<Self, ErasureError> {
        request.validate()?;
        digest(request_digest, "request_digest")?;
        let recomputed = request.request_digest()?;
        if recomputed != request_digest {
            return Err(ErasureError::InvalidField("request_digest"));
        }
        let intent = Self {
            operation_id: request.request_id.clone(),
            request_id: request.request_id.clone(),
            request_digest: request_digest.to_string(),
            subject_ref: request.subject_ref.clone(),
            scope: request.scope.clone(),
            locations: request.locations.clone(),
            expected_revision: request.expected_revision,
            state_fence: request.state_fence.clone(),
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Fail-closed validation of the frozen intent.
    pub fn validate(&self) -> Result<(), ErasureError> {
        text(&self.operation_id, "operation_id")?;
        text(&self.request_id, "request_id")?;
        if self.operation_id != self.request_id {
            return Err(ErasureError::InvalidField("operation_id"));
        }
        digest(&self.request_digest, "request_digest")?;
        text(&self.subject_ref, "subject_ref")?;
        text(&self.scope, "scope")?;
        self.state_fence
            .validate()
            .map_err(|_| ErasureError::InvalidField("state_fence"))?;
        if self.locations.is_empty() {
            return Err(ErasureError::EmptyLocations);
        }
        let mut seen = BTreeSet::new();
        for location in &self.locations {
            if !seen.insert(location_code(*location)) {
                return Err(ErasureError::DuplicateLocation);
            }
        }
        Ok(())
    }
}

/// Durable proof that an intent was recorded before dispatch.
///
/// Returned by [`ErasureBackend::record_intent`]; the orchestration keeps it
/// only as ordering evidence and never treats it as erasure proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntentReceipt {
    pub operation_id: String,
    pub request_digest: String,
}

/// Durable non-revivable tombstone committed BEFORE any destructive dispatch.
///
/// The tombstone carries no erased content: only the operation/request
/// digests, subject/scope refs, revision and fence. The orchestration commits
/// it after [`ErasureIntent`] and before [`ErasureBackend::erase`]; a missing
/// or mismatched tombstone fails closed with
/// [`ErasureError::MissingTombstone`] and zero destructive calls.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    pub operation_id: String,
    pub request_digest: String,
    pub tombstone_digest: String,
    pub subject_ref: String,
    pub scope: String,
    pub revision: u64,
    pub state_fence: StateFence,
}

impl Tombstone {
    /// Fail-closed validation of the durable tombstone.
    pub fn validate(&self) -> Result<(), ErasureError> {
        text(&self.operation_id, "tombstone.operation_id")?;
        digest(&self.request_digest, "tombstone.request_digest")?;
        digest(&self.tombstone_digest, "tombstone.tombstone_digest")?;
        text(&self.subject_ref, "tombstone.subject_ref")?;
        text(&self.scope, "tombstone.scope")?;
        self.state_fence
            .validate()
            .map_err(|_| ErasureError::InvalidField("tombstone.state_fence"))?;
        Ok(())
    }
}

/// Per-surface erasure outcome, supplied as a typed value.
///
/// Live Store/provider owners will produce these per surface in their own
/// integration slices; this crate never invents store-surface writes and only
/// aggregates outcomes passed in. `Purged` carries the location whose removal
/// the owning surface proved; `Incomplete` and `Unknown` preserve the
/// location that must block a complete result. An `Unknown` surface keeps its
/// possible effect explicit so the same operation is reconciled before retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SurfaceOutcome {
    Purged { location: PurgeLocation },
    Incomplete { location: PurgeLocation },
    Unknown { location: PurgeLocation },
}

impl SurfaceOutcome {
    /// The location this outcome reports on.
    #[must_use]
    pub const fn location(&self) -> PurgeLocation {
        match *self {
            Self::Purged { location }
            | Self::Incomplete { location }
            | Self::Unknown { location } => location,
        }
    }
}

/// Fail-closed aggregation over per-surface outcomes.
///
/// Returns the exact committed locations (in canonical order) only when every
/// requested location reports [`SurfaceOutcome::Purged`] with no extras and
/// no duplicates. One `Incomplete` surface — including a missing, extra, or
/// duplicated outcome entry — yields [`ErasureError::IncompleteErasure`];
/// one `Unknown` surface yields [`ErasureError::UnknownSurface`]. Unknown
/// takes precedence when both are present because it requires reconciling
/// the same operation before retry. Either refusal must prevent a
/// `PurgeState::Purged` result; callers never map these errors to `Ok`.
pub fn aggregate_surface_outcomes(
    requested: &[PurgeLocation],
    outcomes: &[SurfaceOutcome],
) -> Result<Vec<PurgeLocation>, ErasureError> {
    if requested.is_empty() {
        return Err(ErasureError::EmptyLocations);
    }
    let mut requested_codes = BTreeSet::new();
    for location in requested {
        if !requested_codes.insert(location_code(*location)) {
            return Err(ErasureError::DuplicateLocation);
        }
    }
    let mut by_location: BTreeMap<u8, SurfaceOutcome> = BTreeMap::new();
    for outcome in outcomes {
        let code = location_code(outcome.location());
        if by_location.insert(code, *outcome).is_some() {
            return Err(ErasureError::IncompleteErasure);
        }
    }
    if by_location.len() != requested_codes.len() {
        return Err(ErasureError::IncompleteErasure);
    }
    for code in &requested_codes {
        if !by_location.contains_key(code) {
            return Err(ErasureError::IncompleteErasure);
        }
    }
    let mut unknown_seen = false;
    let mut incomplete_seen = false;
    for outcome in by_location.values() {
        match outcome {
            SurfaceOutcome::Purged { .. } => {}
            SurfaceOutcome::Incomplete { .. } => incomplete_seen = true,
            SurfaceOutcome::Unknown { .. } => unknown_seen = true,
        }
    }
    if unknown_seen {
        return Err(ErasureError::UnknownSurface);
    }
    if incomplete_seen {
        return Err(ErasureError::IncompleteErasure);
    }
    let mut committed: Vec<PurgeLocation> = by_location
        .values()
        .map(SurfaceOutcome::location)
        .collect();
    committed.sort_by_key(|location| location_code(*location));
    Ok(committed)
}

/// The backend is the existing storage/evidence owner.  Implementations must
/// make intent recording, erasure, and ledger appends durable in their own
/// transaction boundary; this orchestration layer never caches or duplicates
/// that state.
///
/// Protocol order, enforced by [`execute`]: `current_revision`, then
/// `completed_receipt` (replay check, tombstone-verified), then
/// `record_intent` (durable intent), then `commit_tombstone` (durable
/// non-revivable tombstone), then `load_tombstone` verification, then `erase`
/// (destructive dispatch under the recorded intent and verified tombstone),
/// then the fail-closed outcome aggregation, then `append_purge_ledger` (only
/// on aggregate success), then `note_completed` (seals the replayable result).
/// No destructive call happens before both `record_intent` and
/// `commit_tombstone` succeed, and a missing tombstone fails closed with
/// [`ErasureError::MissingTombstone`].
pub trait ErasureBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    fn current_revision(&self, subject_ref: &str, scope: &str) -> Result<u64, Self::Error>;

    /// Records the durable intent before any destructive call.
    ///
    /// The default refuses with [`ErasureError::UnsupportedIntent`] so a
    /// backend without intent durability fails closed with zero destructive
    /// calls instead of erasing first. Implementations must persist the
    /// intent under its stable `operation_id`; recording the same intent
    /// twice with identical content is idempotent, while the same id with
    /// different content must yield [`ErasureError::IntentConflict`].
    fn record_intent(&mut self, _intent: ErasureIntent) -> Result<IntentReceipt, ErasureError> {
        Err(ErasureError::UnsupportedIntent)
    }

    /// Commits the durable tombstone before any destructive call.
    ///
    /// The default refuses with [`ErasureError::UnsupportedIntent`] so a
    /// backend without tombstone durability fails closed with zero
    /// destructive calls. Implementations must persist the tombstone under
    /// its stable `operation_id`; committing the same tombstone twice with
    /// identical content is idempotent, while the same id with different
    /// content must yield [`ErasureError::IntentConflict`].
    fn commit_tombstone(&mut self, _tombstone: Tombstone) -> Result<Tombstone, ErasureError> {
        Err(ErasureError::UnsupportedIntent)
    }

    /// Loads the durable tombstone for fail-closed verification.
    ///
    /// The default refuses with [`ErasureError::UnsupportedIntent`]; a
    /// backend that cannot prove the tombstone must not erase.
    fn load_tombstone(&self, _operation_id: &str) -> Result<Option<Tombstone>, ErasureError> {
        Err(ErasureError::UnsupportedIntent)
    }

    /// Loads a previously sealed completion for replay identity.
    ///
    /// The default refuses with [`ErasureError::UnsupportedIntent`]; a
    /// backend that cannot prove prior completion must not claim replay.
    fn completed_receipt(
        &self,
        _operation_id: &str,
    ) -> Result<Option<ErasureReceipt>, ErasureError> {
        Err(ErasureError::UnsupportedIntent)
    }

    /// Seals a completed receipt for future exact replays.
    ///
    /// Called once per operation after the purge ledger append, before
    /// returning success. The default refuses so an unsealed completion
    /// cannot be misreported as replayable.
    fn note_completed(&mut self, _receipt: ErasureReceipt) -> Result<(), ErasureError> {
        Err(ErasureError::UnsupportedIntent)
    }

    /// Removes every requested location under the recorded intent and
    /// returns the per-surface outcomes.
    ///
    /// Takes the durable [`ErasureIntent`] so no destructive path exists
    /// without a recorded intent. A successful result carries one outcome
    /// per requested location; transport failures are `Err`, while
    /// per-surface `Incomplete`/`Unknown` states are `Ok` outcomes that the
    /// fail-closed aggregation refuses.
    fn erase(
        &mut self,
        intent: &ErasureIntent,
    ) -> Result<Vec<SurfaceOutcome>, Self::Error>;

    fn append_purge_ledger(&mut self, entry: PurgeLedgerEntry) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErasureReceipt {
    pub request_id: String,
    pub request_digest: String,
    pub purge: PurgeLedgerEntry,
}

/// Executes one exact-fence erasure against the already-authoritative backend.
///
/// Tombstone-first lifecycle: the intent is built and recorded, then the
/// durable tombstone is committed and load-verified, and only then does
/// erasure fan out under the recorded intent and verified tombstone. An exact
/// replay of a completed intent returns the original receipt with no second
/// destructive dispatch after verifying the tombstone still binds the same
/// digest. Tombstone commit failure or a missing/mismatched tombstone yields
/// [`ErasureError::MissingTombstone`] (or the backend refusal) with zero
/// destructive calls. Per-surface outcomes aggregate fail-closed — one
/// incomplete or unknown surface prevents a `Purged` result and no ledger
/// entry is appended on refusal.
pub fn execute<B: ErasureBackend>(
    backend: &mut B,
    request: &ErasureRequest,
) -> Result<ErasureReceipt, ErasureError> {
    request.validate()?;
    let request_digest = request.request_digest()?;
    let revision = backend
        .current_revision(&request.subject_ref, &request.scope)
        .map_err(|error| ErasureError::Backend(Box::new(error)))?;
    if revision != request.expected_revision {
        return Err(ErasureError::RevisionMismatch {
            expected: request.expected_revision,
            observed: revision,
        });
    }

    let intent = ErasureIntent::new(request, &request_digest)?;
    let computed_tombstone_digest = tombstone_digest(request, &request_digest);

    if let Some(prior) = backend.completed_receipt(&intent.operation_id)? {
        if prior.request_digest != request_digest {
            return Err(ErasureError::IntentConflict);
        }
        let stored = backend.load_tombstone(&intent.operation_id)?;
        let Some(stored) = stored else {
            return Err(ErasureError::MissingTombstone);
        };
        if stored.tombstone_digest != computed_tombstone_digest
            || stored.tombstone_digest != prior.purge.tombstone_digest
        {
            return Err(ErasureError::MissingTombstone);
        }
        return Ok(prior);
    }

    backend.record_intent(intent.clone())?;

    let candidate = Tombstone {
        operation_id: intent.operation_id.clone(),
        request_digest: request_digest.clone(),
        tombstone_digest: computed_tombstone_digest.clone(),
        subject_ref: request.subject_ref.clone(),
        scope: request.scope.clone(),
        revision,
        state_fence: request.state_fence.clone(),
    };
    candidate.validate()?;
    let committed = backend.commit_tombstone(candidate)?;
    if committed.tombstone_digest != computed_tombstone_digest
        || committed.operation_id != intent.operation_id
        || committed.request_digest != request_digest
    {
        return Err(ErasureError::MissingTombstone);
    }
    let stored = backend.load_tombstone(&intent.operation_id)?;
    let Some(stored) = stored else {
        return Err(ErasureError::MissingTombstone);
    };
    if stored != committed {
        return Err(ErasureError::MissingTombstone);
    }

    let outcomes = backend
        .erase(&intent)
        .map_err(|error| ErasureError::Backend(Box::new(error)))?;
    let purged_locations = aggregate_surface_outcomes(&intent.locations, &outcomes)?;
    let purge = PurgeLedgerEntry {
        purge_id: format!("purge-{request_digest}"),
        subject_ref: request.subject_ref.clone(),
        scope: request.scope.clone(),
        purged_locations,
        tombstone_digest: committed.tombstone_digest.clone(),
        state: PurgeState::Purged,
        state_fence: request.state_fence.clone(),
        revision,
    };
    purge.validate().map_err(|_| ErasureError::InvalidLedger)?;
    backend
        .append_purge_ledger(purge.clone())
        .map_err(|error| ErasureError::Backend(Box::new(error)))?;
    let receipt = ErasureReceipt {
        request_id: request.request_id.clone(),
        request_digest,
        purge,
    };
    backend.note_completed(receipt.clone())?;
    Ok(receipt)
}

fn tombstone_digest(request: &ErasureRequest, request_digest: &str) -> String {
    let material = format!(
        "{}\0{}\0{}\0{}\0{}",
        request_digest,
        request.subject_ref,
        request.scope,
        request.expected_revision,
        request
            .locations
            .iter()
            .map(|location| location_code(*location).to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    sha256_hex(material.as_bytes())
}

fn location_code(location: PurgeLocation) -> u8 {
    match location {
        PurgeLocation::CanonicalPayload => 0,
        PurgeLocation::Projection => 1,
        PurgeLocation::Index => 2,
        PurgeLocation::Blob => 3,
        PurgeLocation::OperationalRecovery => 4,
        PurgeLocation::ProviderCopy => 5,
        PurgeLocation::BackupRestorePath => 6,
        PurgeLocation::RouteContinuation => 7,
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ErasureError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ErasureError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn digest(value: &str, field: &'static str) -> Result<(), ErasureError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ErasureError::InvalidField(field))
    }
}

#[derive(Debug, Error)]
pub enum ErasureError {
    #[error("invalid erasure field: {0}")]
    InvalidField(&'static str),
    #[error("erasure request has no locations")]
    EmptyLocations,
    #[error("erasure request contains a duplicate location")]
    DuplicateLocation,
    #[error("erasure evidence is invalid")]
    InvalidEvidence,
    #[error("erasure evidence and request use different state fences")]
    FenceMismatch,
    #[error("erasure request cannot be canonically serialized")]
    Canonicalization,
    #[error("erasure revision mismatch: expected {expected}, observed {observed}")]
    RevisionMismatch { expected: u64, observed: u64 },
    #[error("backend did not erase the exact requested locations")]
    IncompleteErasure,
    #[error("one or more erasure surfaces report unknown outcome; reconcile the same operation")]
    UnknownSurface,
    #[error("erasure backend does not implement durable intent")]
    UnsupportedIntent,
    #[error("erasure tombstone is missing or does not bind this operation")]
    MissingTombstone,
    #[error("erasure intent conflicts with the already-recorded operation")]
    IntentConflict,
    #[error("generated purge ledger entry is invalid")]
    InvalidLedger,
    #[error("erasure scope snapshot is invalid")]
    InvalidScope,
    #[error("erasure scope snapshot does not bind to this request")]
    ScopeMismatch,
    #[error("erasure backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
