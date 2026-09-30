//! Governor-owned coordination owner commit path.
//!
//! Before this module the coordination owner had no post-genesis write route:
//! its ORS record was written exactly once by
//! [`GovernorGenesisRequest`](crate::GovernorGenesisRequest) and never again, so
//! every coordination mutation was erased by the next
//! [`GovernorComposition::refresh_from_kernel`](crate::GovernorComposition::refresh_from_kernel).
//! This module is the missing route, and it deliberately mirrors the shape the
//! three existing post-genesis owner writes already use
//! (`owner/canonical` via `RecordFinishEvidence`, `owner/finish` via
//! `RecordFinishDecision`, and `owner/module_registry` via
//! `RecordModuleCatalogSnapshot`):
//!
//! 1. the Governor mutates a *scratch clone* of its own coordination owner
//!    through the existing owner API, so every lease/epoch/fence check inside
//!    [`CoordinationOwner`] still runs and still refuses;
//! 2. the resulting complete image is serialized once and bound into a
//!    [`CanonicalWriteEnvelope`] carrying
//!    [`NamedMutationOperation::RecordCoordinationOwner`], with the
//!    compare-and-set predecessor supplied by the caller from the *Kernel named
//!    read* of `owner/coordination` — never from the in-memory owner, which is
//!    exactly the value a refresh is about to overwrite;
//! 3. the daemon commits that envelope through the one retained Kernel port and
//!    then refreshes, so the committed image is what rehydration reads.
//!
//! The image is NOT pre-validated here. The existing recovery guard already
//! runs it: `refresh_from_kernel` calls
//! [`CoordinationOwner::from_snapshot_at`] on the read-back image, and a
//! mutated image its own owner would refuse therefore fails closed at the same
//! boundary that guards every other owner — adding a second, differently
//! parameterized copy of that check here would invent a guard rather than
//! reuse one.
//!
//! Nothing here mints coordination identity. Every `session_id`,
//! `work_item_id`, `lease_id`, and `result_id` arrives in the caller-supplied
//! requests, and the owner validates them against the image it already holds.
//! This module also grants no admission: the persisted coordination image caps
//! every admitted result at `CandidateArtifact`, which is stamped by the owner
//! itself, not by this path.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{ClockReading, OperationId, canonical_json_bytes, sha256_hex};
use eliot_coordination::{
    AgentResultDraft, AgentResultReceipt, CoordinationOwner, RegisterSession, WorkItem,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationManifestDigest, SecurityContext, ScopeId, TransitionClass, WriteReceipt,
    generated_operation_manifests, operation_manifest_set_digest,
};
use thiserror::Error;

use crate::composition::KernelGenerationPort;
use crate::finish_attempt::GOVERNOR_SCOPE_ID;
use crate::{CompositionError, CompositionReadiness, GovernorComposition, RecoveryOwner};

/// Typed failure at the coordination owner commit boundary.
#[derive(Debug, Error)]
pub enum CoordinationCommitError {
    /// The coordination owner refused the lifecycle mutation. Every arm here
    /// is the owner's own typed refusal (unknown work item, expired lease,
    /// fence mismatch, duplicate session, ...), carried unchanged across the
    /// layer rather than flattened into a string.
    #[error("coordination owner refused the mutation: {0}")]
    Owner(#[from] eliot_coordination::CoordinationError),
    /// The composition is not ready, its canonical owner rejected the derived
    /// transition, or the commit was refused by the store's own arbitration.
    #[error("coordination commit composition rejected the mutation: {0}")]
    Composition(#[from] CompositionError),
    /// The coordination image could not be serialized or canonicalized.
    #[error("coordination owner image could not be encoded: {0}")]
    Serialization(String),
}

/// The committed receipt plus the coordination owner's own admission receipt.
///
/// The coordination receipt is the owner's own output: this path persists the
/// image that contains it and never interprets it.
#[derive(Clone, Debug)]
pub struct CommittedCoordinationResult {
    /// SHA-256 over the exact canonical `owner/coordination` image bytes this
    /// commit published, bound into the envelope as the readback reference.
    pub image_digest: String,
    /// The Kernel/store `WriteReceipt`, returned unmodified.
    pub receipt: WriteReceipt,
    /// The owner-stamped candidate admission receipt, when this commit admitted
    /// a result. `None` for a leg that only registered a session or work item.
    pub result: Option<AgentResultReceipt>,
}

/// Assembles the closed `RecordCoordinationOwner` parameter map for one image.
///
/// `expected_coordination_revision` is the outer owner revision the store must
/// observe, and the store issues `expected + 1`. A zero predecessor is refused
/// here: a `RecoverySchema` coordination image is never created outside genesis,
/// so a zero would mean the caller lost the Kernel named read rather than
/// legitimately starting from nothing.
fn coordination_owner_parameters(
    image: &CoordinationOwner,
    expected_coordination_revision: u64,
) -> Result<(BTreeMap<String, serde_json::Value>, String), CoordinationCommitError> {
    if expected_coordination_revision == 0 {
        return Err(CoordinationCommitError::Composition(
            CompositionError::Recovery(
                "coordination owner commit has no genesis predecessor revision".to_owned(),
            ),
        ));
    }
    let bytes = canonical_json_bytes(image)
        .map_err(|error| CoordinationCommitError::Serialization(error.to_string()))?;
    let snapshot_json = String::from_utf8(bytes.clone())
        .map_err(|error| CoordinationCommitError::Serialization(error.to_string()))?;
    let digest = sha256_hex(&bytes);
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "expected_coordination_revision".to_owned(),
        serde_json::Value::String(expected_coordination_revision.to_string()),
    );
    parameters.insert(
        "snapshot_json".to_owned(),
        serde_json::Value::String(snapshot_json),
    );
    Ok((parameters, digest))
}

fn production_manifest_digest() -> Result<OperationManifestDigest, CoordinationCommitError> {
    let entries = generated_operation_manifests().map_err(|error| {
        CoordinationCommitError::Composition(CompositionError::Owner(error.to_string()))
    })?;
    operation_manifest_set_digest(&entries).map_err(|error| {
        CoordinationCommitError::Composition(CompositionError::Owner(error.to_string()))
    })
}

/// Builds the one immutable transition that publishes a coordination image.
///
/// Mirrors `canonical_owner_snapshot_envelope` in `finish_attempt`: the
/// envelope is bound to the admitted request metadata and idempotency key, so a
/// substituted identity cannot ride this route. The required approval reference
/// is the image digest itself — a reference to the content the store persists,
/// not a derived proof of any coordination meaning, because the store still
/// arbitrates only the address, the fence, and the outer revision.
fn coordination_owner_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    image: &CoordinationOwner,
    expected_coordination_revision: u64,
) -> Result<(CanonicalWriteEnvelope, String), CoordinationCommitError> {
    let (parameters, digest) =
        coordination_owner_parameters(image, expected_coordination_revision)?;
    let scope_id = ScopeId::new(GOVERNOR_SCOPE_ID)
        .map_err(|error| CoordinationCommitError::Serialization(error.to_string()))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        // The coordination image is not itself task-scoped: it names tasks
        // inside the persisted work items, and the owner validated every one of
        // them against the image it already held before this image was built.
        task_id: None,
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: digest.clone(),
        operation_manifest_digest: production_manifest_digest()?,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordCoordinationOwner,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![format!("coordination-owner-image:{digest}")],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    Ok((envelope, digest))
}

// The bound must match the composition's own inherent impl at `composition.rs`
// exactly. `readiness()`, `owners()`, `recovery_snapshot()`, and
// `commit_canonical()` are all defined inside `impl<P: KernelGenerationPort +
// ?Sized> GovernorComposition<P>`, so from a bare `P: ?Sized` this block the
// bound is unsatisfied, rustc falls back to the same-named private field, and
// the call silently resolves as a field access instead of a method.
impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Returns the live coordination owner image together with the outer owner
    /// revision the next coordination commit must compare against.
    ///
    /// The revision is read from the refresh-consistent Kernel named read of
    /// `owner/coordination` — the same value the store arbitrates on the write
    /// and the same value rehydration will read back. The in-memory image is
    /// returned alongside it so a caller can see exactly what it is about to
    /// replace, and it is deliberately NOT usable as the predecessor: deriving
    /// the compare-and-set from it is the bug this route exists to fix.
    pub fn coordination_owner_readback(
        &self,
    ) -> Result<(CoordinationOwner, u64), CoordinationCommitError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady.into());
        }
        let revision = self
            .recovery_snapshot()
            .owner_read(RecoveryOwner::Coordination)?
            .revision;
        Ok((self.owners().coordination.clone(), revision))
    }

    /// Registers one coordination session and durably publishes the resulting
    /// owner image.
    ///
    /// `session` carries the caller-admitted identity; the owner validates it
    /// against the image it already holds and refuses a blank identity, a stale
    /// fence, a foreign authority epoch, or a conflicting duplicate through its
    /// own typed errors. An identical retry is the owner's own idempotent
    /// `Ok(old)` return, not a second session.
    pub async fn commit_coordination_session(
        &mut self,
        identity: &RequestIdentity,
        operation_id: OperationId,
        expected_coordination_revision: u64,
        session: RegisterSession,
    ) -> Result<CommittedCoordinationResult, CoordinationCommitError> {
        let mut image = self.owners().coordination.clone();
        image.register_session(session)?;
        self.publish_coordination_image(
            identity,
            operation_id,
            expected_coordination_revision,
            image,
            None,
        )
        .await
    }

    /// Registers one ready work item and durably publishes the resulting owner
    /// image.
    ///
    /// The item's `work_item_id` and `task_id` arrive from the caller; the
    /// owner refuses a blank identity, a duplicate id, or any item that is not
    /// in `WorkState::Ready` through its own typed errors.
    pub async fn commit_coordination_work(
        &mut self,
        identity: &RequestIdentity,
        operation_id: OperationId,
        expected_coordination_revision: u64,
        item: WorkItem,
        request_id: &str,
        actor_id: &str,
        observed_at: ClockReading,
    ) -> Result<CommittedCoordinationResult, CoordinationCommitError> {
        let mut image = self.owners().coordination.clone();
        image.register_work(item, request_id, actor_id, observed_at)?;
        self.publish_coordination_image(
            identity,
            operation_id,
            expected_coordination_revision,
            image,
            None,
        )
        .await
    }

    /// Admits one candidate result reference against a live coordination lease
    /// and durably publishes the resulting owner image.
    ///
    /// This is the durable production caller of
    /// [`CoordinationOwner::admit_candidate_result`]. The draft's `session_id`,
    /// `work_item_id`, `lease_id`, and `result_id` all arrive from admitted
    /// ingress; the owner re-checks the lease holder, the lease window, the
    /// authority epoch, and the fence, and additionally refuses a work item that
    /// is not in a submittable state. The admitted receipt stays capped at
    /// `CandidateArtifact`: this path persists the image and grants no task
    /// finish, acceptance, or closure authority of any kind.
    pub async fn commit_coordination_candidate_result(
        &mut self,
        identity: &RequestIdentity,
        operation_id: OperationId,
        expected_coordination_revision: u64,
        draft: AgentResultDraft,
    ) -> Result<CommittedCoordinationResult, CoordinationCommitError> {
        let mut image = self.owners().coordination.clone();
        let admitted = image.admit_candidate_result(draft)?;
        self.publish_coordination_image(
            identity,
            operation_id,
            expected_coordination_revision,
            image,
            Some(admitted),
        )
        .await
    }

    /// Commits one coordination image through the sole retained Kernel port.
    ///
    /// Every mutating entry above funnels here, so there is exactly one place
    /// that can publish a coordination image and exactly one envelope shape it
    /// can take. The live `self.owners.coordination` is deliberately NOT updated
    /// on success: publication of the mutated owner happens only via
    /// `refresh_from_kernel` reading the committed image back, which is what
    /// makes the mutation durable rather than merely in-process.
    async fn publish_coordination_image(
        &self,
        identity: &RequestIdentity,
        operation_id: OperationId,
        expected_coordination_revision: u64,
        image: CoordinationOwner,
        result: Option<AgentResultReceipt>,
    ) -> Result<CommittedCoordinationResult, CoordinationCommitError> {
        if self.readiness() != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady.into());
        }
        let (envelope, image_digest) = coordination_owner_envelope(
            identity,
            operation_id,
            &image,
            expected_coordination_revision,
        )?;
        let receipt = self.commit_canonical(identity, envelope).await?;
        Ok(CommittedCoordinationResult {
            image_digest,
            receipt,
            result,
        })
    }
}
