//! Audit-bridge experience provider: V1 journal projections over durable reads
//! (#223 owner-consumer lane).
//!
//! This cell is the producer-to-provider link the experience lane was
//! missing: it reads Governor-admitted journal envelopes through the
//! existing canonical store bridge (the scoped `GetAuditRange` named read
//! over any store-neutral [`CanonicalReadClient`]), shapes the admitted V1
//! envelopes into the frozen [`JournalProjection`] owner envelope, assembles
//! the journal-family [`ExperienceView`] Smart read aid over the carried
//! records, and revalidates the view against caller-supplied live journal
//! presence. The composed entrypoint [`produce_journal_read`] performs the
//! full producer-to-provider-to-consumer call in production types:
//! bridge fetch, V1 shaping, Smart view assembly, owner-envelope
//! revalidation.
//!
//! Everything bound here derives from bytes actually returned by the bridge
//! plus handles actually read from the live journal at call time:
//!
//! - coverage binds the owner-issued `revision_heads` of the bridge
//!   response (canonical key order, denominator ref plus digest), never an
//!   invented denominator; every head fence must equal the read fence and
//!   every caller-required revision minimum must hold, mirroring the read
//!   facade owner checks, or the read fails closed (`StaleRevision`). The
//!   coverage digest proves this read's shape only: durable authority stays
//!   with the bound heads plus fence equality, and the output carries the
//!   canonical heads so a later read can re-prove durability and
//!   monotonicity. `Complete` posture is taken only on exact
//!   carried-to-observed count with empty omissions and empty blind
//!   intervals, exactly as the envelope contract requires;
//! - carried records presence-check against the live admitted-handle set and
//!   the read fails closed on drift (`PresenceDrift`);
//! - view revision cursors are owner-issued or absent, never rebuilt:
//!   bank and feedback view refs resolve through the shared
//!   `bank_record_ref` / `feedback_record_ref` constructors over admitted
//!   records (owner counters plus record digests); journal views carry no
//!   ref handles because V1 envelopes carry no owner revision cursor by
//!   contract. The journal view echoes coverage with `Partial` posture;
//!   substance travels in the owner projection;
//! - the view echoes coverage with `Partial` posture and never establishes
//!   completeness, exactly as the Smart read-aid contract requires.
//!
//! ## Retention posture (I05-14)
//!
//! Unknown, stale, or unreachable refs use the existing retention posture,
//! never an invented schedule: a bridge outage surfaces as
//! [`ProviderError::BridgeUnavailable`] with no hold claimed (the caller
//! emits a coverage gap and treats the material as unavailable), and
//! per-record retention resolves through [`resolve_retention_read`] with
//! caller-carried schedule attestation and holds only, per the `RETENTION_BLOCKED`
//! availability axis
//! (`docs/architecture/I05-14-retention-and-erasure.md`). Unknown or stale
//! policy refs yield the explicit gap posture with the ref echoed for gap
//! reporting; known holds carry only schedule-issued refs. No expiry,
//! permission, or erasure schedule is fabricated here; binds to a
//! configured owner-issued schedule arrive with the bridge response (fence
//! plus revision heads) and are echoed, not minted. Malformed bridge bytes
//! fail closed as integrity errors: required bytes/digest lineage that
//! cannot be proven never masquerades as a partial projection.
//!
//! ## V1 freeze discipline
//!
//! This cell carries the freeze-r5 V1 envelope as declared. Only V1
//! [`ObservationRecordEnvelope`] members project; an additive V2 record
//! twin (`record_v2`) is never collapsed into V1. The consumed
//! [`AuditRangeV1Payload`] shape rejects unknown fields, so a store-side
//! V2 payload fails closed here instead of silently degrading: the precise
//! incompatible surface is the payload version, and any V2 carriage needs
//! an explicit versioned compatibility and freeze delta before this cell
//! changes. Out-of-scope event records are counted in the observed volume
//! but not carried (no closed omission class names that loss); the
//! resulting `Partial` posture keeps the loss visible.
//!
//! ## Coordination (canonical bank/feedback owners)
//!
//! Bank and feedback owner supply arrives paired from the canonical owner
//! lane: admitted `ExperienceBankRecord` / `AgentFeedbackRecord` values,
//! the shared `bank_record_ref` / `feedback_record_ref` constructors, the
//! `resolve_retention_read` posture resolver, and live
//! `BankProjection` / `FeedbackProjection` envelopes from the Governor
//! suppliers. This cell consumes those outputs without rebuilding
//! cursors, holds, or envelopes: no new named reads (bridge reads use
//! only the existing `GetAuditRange` catalogue entry; bank/feedback reads
//! stay with the #19 registration), no contract edits (V1 envelope types
//! are reused unchanged), and journal-only assessment stays valid
//! (`assess_self_quality` requires at least one family, not all three).
//! Durable bank/feedback bridge execution remains the #19 join.
//!
//! ## Seam: dreamer-memory-revision consumer (sibling lane, not duplicated)
//!
//! The `propose` consumer (`Result<NegativeMemoryExtinctionCandidate,
//! RevisionError>`) lives ONLY on sibling branch
//! `work/223-dreamer-memory-revision-scope @
//! cdd6305ff0ab838e9e2855d5f6f0ac8b940012a79fe0`:
//! `crates/smart/eliot-dreamer-memory-revision/src/lib.rs` (`propose` at
//! line 290 over `RevisionIntake` at line 253). Its `RevisionIntake`
//! input shapes `FailureObservation` (observation-contracts role) and
//! `MemoryRevisionEvidence` exist nowhere on main (main carries only
//! that crate's `module.toml`): similarly-named main types do not
//! satisfy the intake — `FailureObservationState` (dreamer-contracts
//! failure-curation state enum) is a different type and role, and the
//! MCP surface `FailureObservation` DTO is explicitly rejected as
//! owner-neutral contract material by the freeze readback rule. The
//! sibling crate is not a workspace member, so no path dependency may
//! target it and vendoring its core would fork sibling-owned source. A caller here
//! becomes compilable when the sibling crate lands on main as a member:
//! `RevisionIntake` over owner-held observation, evidence,
//! `TaskProjection`/`SafetyProjection` (context contracts, on main),
//! `SelfQueryInput` (dreamer contracts, on main), `AcceptedSourceProjection`
//! (dreamer contracts, on main), pose digest, and candidate id — then a
//! `produce_dreamer_revision` caller mirrors the understanding legs
//! above. Until then this seam is recorded, not fabricated.
//!
//! ## Seam: durable commit transition (canonical transition owner)
//!
//! Persisting admitted bank/feedback records requires a canonical
//! transition the Governor canonical owner admits: an envelope carrying
//! `CommitExperienceBank` / `CommitAgentFeedback` (built from
//! `ExperienceCommitParameters`, already produced owner-side by
//! `produce_bank_commit` / `produce_feedback_commit`) admitted through
//! `CanonicalTransitionOwner::commit(envelope: CanonicalWriteEnvelope)`
//! (`crates/governor/eliot-canonical/src/lib.rs:723`, type
//! `PreparedTransition` at `crates/storage/eliot-store-api/src/lib.rs:1442`)
//! to a `WriteReceipt`. The named commit legs belong to the store bridge
//! (#19 registration); the Governor-side commit-leg driver belongs to
//! the canonical-transition owner lane (brief names lane Pascal —
//! confirm via the M1/root live map; code ownership is unambiguous
//! above). This cell performs no writes and mints no transitions: the
//! read legs here consume the same rows that path persists, bound by
//! digest re-proof on readback.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub use eliot_experience_projection::ExperienceView;

use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_cognitive_quality::{
    ExperienceProjections, OwnerSnapshot, QualityAssessmentCandidate, QualityError,
    assess_self_quality, recheck_candidate,
};
use eliot_epistemic_contracts::CurrentEpistemicPosition;
use eliot_experience_projection::{revalidate_bank_refs, revalidate_feedback_refs};
use eliot_learning_contracts::HarnessActivationReceiptCandidate;
use eliot_memory_quality::{MemoryEcologyAssessment, QualityRequest, assess_quality};
use eliot_memory_quality::QualityError as MemoryQualityError;
use eliot_understanding_assessment::{
    CommonGroundAssessment, CommonGroundInput, ScopedInput, ScopedUnderstandingAssessment,
    assess_common_ground, assess_scoped,
};
use eliot_understanding_assessment::AssessmentError as UnderstandingError;
use eliot_observation_contracts::{
    AgentFeedbackRecord, BankProjection, CoverageDisposition, CoverageEvidence, ExperienceBankRecord,
    ExperienceRetentionReadPosture, ExperienceSourceFamily, FeedbackProjection, JournalProjection,
    MAX_PROJECTION_MEMBERS, MAX_PROJECTION_OMISSIONS, ObservationError, ObservationRecordEnvelope,
    ObservationScope, ProjectionCoverage, ProjectionOmission, ProjectionOmissionClass,
    RetentionHold, RetentionSchedule, bank_record_ref, feedback_record_ref, resolve_retention_read,
};
use eliot_receipts::WorkScopeId;
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    RevisionHead, RevisionKey, StoreError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml` (r5).
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22-r5";

/// Coordination kind of the consumed audit payload.
///
/// The store side produces exactly [`AuditRangeV1Payload`] for `GetAuditRange`
/// responses this cell reads; anything else fails closed at the boundary.
pub const AUDIT_RANGE_PAYLOAD_KIND: &str = "audit_range_v1";

/// Typed consumer-boundary shape of one `GetAuditRange` response payload.
///
/// Unknown fields are rejected so store-side evolution fails closed here
/// instead of silently reshaping the projection.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditRangeV1Payload {
    /// Admitted V1 journal envelopes in deterministic supply order.
    pub records: Vec<ObservationRecordEnvelope>,
}

/// Typed failures of the audit-bridge provider.
#[derive(Clone, Debug, Error)]
pub enum ProviderError {
    /// The bridge call failed for a reason other than unavailability.
    #[error("bridge read failed: {0}")]
    Bridge(#[from] StoreError),
    /// The bridge answered with a response this cell must not project.
    #[error("response field {field}: {reason}")]
    Response {
        field: &'static str,
        reason: &'static str,
    },
    /// The bridge payload is not the coordinated `audit_range_v1` shape.
    #[error("audit payload is not audit_range_v1: {reason}")]
    Payload { reason: String },
    /// The bridge is unavailable: no records were read, so no retention
    /// posture is resolved and no hold is claimed. The caller emits a
    /// coverage gap and treats the material as unavailable; per-record
    /// retention resolves through [`resolve_retention_read`] wherever
    /// records exist, with caller-carried holds only.
    #[error("store bridge unavailable: no audit read, no hold claimed")]
    BridgeUnavailable,
    /// A required revision head is missing or regressed: the bridge read is
    /// stale relative to the caller-supplied minimums. Re-read at a current
    /// revision; never project a regressed enumeration.
    #[error("bridge revision heads are stale relative to required minimums")]
    StaleRevision,
    /// The live journal advanced past the bridge read: a carried record no
    /// longer presence-checks. Re-read; never project stale presence.
    #[error("live owner state advanced past the bridge read")]
    PresenceDrift,
    /// A Smart consumer assessment rejected the supplied owner inputs.
    #[error("quality consumer: {0}")]
    Quality(#[from] QualityError),
    /// A memory-quality consumer rejected the supplied owner inputs.
    #[error("memory quality consumer: {0}")]
    MemoryQuality(#[from] MemoryQualityError),
    /// An understanding-assessment consumer rejected the supplied inputs.
    #[error("understanding consumer: {0}")]
    Understanding(#[from] UnderstandingError),
    /// A projection or view contract rejected the shaped read.
    #[error("projection contract: {0}")]
    Contract(#[from] ObservationError),
    /// A foundation handle or encoding contract rejected the shaped read.
    #[error("foundation contract: {0}")]
    Foundation(#[from] eliot_contracts::ContractError),
}

/// Scaffold literals shadowing the canonical audit-paging contract
/// (`codex/b223-canonical-owner-20260922` b86fc66d,
/// `crates/storage/eliot-store-api/src/experience_store.rs`:
/// `audit_cursor_issue`, `AUDIT_PARAM_CURSOR`,
/// `MAX_AUDIT_RANGE_RECORDS`).
///
/// Values verified read-only against that commit; the store re-verifies
/// every cursor on receipt (fence digest plus bound), so drift fails
/// closed, never silent. Swap these literals for the canonical imports
/// when that surface lands on main. Never hand-roll the cursor format
/// elsewhere: all paging flows through [`page_cursor_for_ordinal`].
const AUDIT_CURSOR_PARAM: &str = "cursor";
/// Page bound every audit read carries: must equal the canonical bound
/// the store enforces, or cursors are rejected there.
const AUDIT_PAGE_BOUND: u32 = 32;
/// Maximum pages one journal enumeration walks before failing closed.
/// Bounds bridge work: a hotter store surfaces as an error, never a hang.
const MAX_AUDIT_READ_PAGES: u32 = 64;
/// Maximum restarts after fence/head advance before failing closed with
/// [`ProviderError::PresenceDrift`]: the live owner state advanced past
/// any coherent read this cell could finish.
const MAX_AUDIT_READ_RESTARTS: u32 = 3;

/// Plan one closed audit-range read (pure, no I/O).
///
/// Builds the existing `GetAuditRange` catalogue read with an optional
/// continuation cursor and no scope (scope-free row: scope filtering
/// stays consumer-owned) and validates it. `None` reads from the start
/// with legacy fail-closed overflow; `Some` resumes paging past that
/// candidate ordinal. This is the single request-shape implementation
/// the bridge fetch below and the daemon registration planner both
/// resolve: the O1 planner region delegates here so only one shape
/// exists. The store catalogue remains the authority; activation and
/// adapter handlers stay with the store lane.
pub fn plan_audit_range_request(
    fence: &StateFence,
    consistency: ReadConsistency,
    cursor: Option<String>,
) -> Result<NamedReadRequest, ProviderError> {
    let mut parameters = BTreeMap::new();
    if let Some(cursor) = cursor {
        parameters.insert(AUDIT_CURSOR_PARAM.to_owned(), serde_json::Value::String(cursor));
    }
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetAuditRange,
        scope_id: None,
        consistency,
        state_fence: fence.clone(),
        parameters,
    };
    request.validate().map_err(ProviderError::Bridge)?;
    Ok(request)
}

/// Mint one page cursor for an ordinal under a fence.
///
/// Scaffold twin of the canonical `audit_cursor_issue`: binds the exact
/// query-fence digest, the next candidate ordinal, and the page bound.
/// Every input here is owner-issued or observed (fence under read,
/// ordinal counted from responses, catalogue bound); the store
/// re-verifies all three on receipt, so a wrong cursor fails closed
/// there, never silently.
fn page_cursor_for_ordinal(fence: &StateFence, ordinal: u64) -> Result<String, ProviderError> {
    let digest = canonical_json_bytes(fence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ProviderError::Response {
            field: "read.fence",
            reason: "read fence is not canonically encodable",
        })?;
    Ok(format!("audit:{digest}:{ordinal:010}:{AUDIT_PAGE_BOUND}"))
}

/// Producer: fetch one audit-range page through the canonical bridge.
///
/// Issues the planned read and validates transport shape, operation
/// echo, and response shape. Semantic gates (fence agreement, head
/// equality, revision minimums) run in [`gate_audit_response`], not
/// here, so the page loop can distinguish transport failure from a
/// vintage advance. A bridge that reports `Unavailable` becomes
/// [`ProviderError::BridgeUnavailable`]; every other store failure
/// travels as [`ProviderError::Bridge`].
pub async fn fetch_audit_range<C: CanonicalReadClient + ?Sized>(
    client: &C,
    fence: &StateFence,
    consistency: ReadConsistency,
    cursor: Option<String>,
) -> Result<NamedReadResponse, ProviderError> {
    let request = plan_audit_range_request(fence, consistency, cursor)?;
    let response = match client.execute_named(request).await {
        Err(StoreError::Unavailable) => {
            return Err(ProviderError::BridgeUnavailable);
        }
        result => result.map_err(ProviderError::Bridge)?,
    };
    response.validate().map_err(ProviderError::Bridge)?;
    if response.operation != NamedReadOperation::GetAuditRange {
        return Err(ProviderError::Response {
            field: "response.operation",
            reason: "bridge did not answer the audit-range read",
        });
    }
    Ok(response)
}

/// Enforce the owner head gates on one head set.
///
/// Exact per-head fence equality (a compatible-but-unequal head means
/// the enumeration was not read under the claimed fence) plus revision
/// minimums (a missing key or regressed revision means stale). Shared
/// by response gating and fence-advance re-discovery so both enforce
/// the identical rule.
fn gate_audit_response_heads(
    heads: &[RevisionHead],
    fence: &StateFence,
    minimums: &BTreeMap<RevisionKey, u64>,
) -> Result<(), ProviderError> {
    if heads
        .iter()
        .any(|head| head.state_fence != *fence)
    {
        return Err(ProviderError::Response {
            field: "response.revision_heads",
            reason: "owner head fence does not equal the read fence",
        });
    }
    for (key, minimum) in minimums {
        let current = heads
            .iter()
            .find(|head| head.key == *key)
            .map(|head| head.revision);
        if current.is_none_or(|revision| revision < *minimum) {
            return Err(ProviderError::StaleRevision);
        }
    }
    Ok(())
}

/// Enforce the owner read gates on one audit response.
///
/// Mirrors the read facade: response fence compatibility, then the
/// shared head gates. Any violation fails the page closed; vintage
/// advance is detected by the caller comparing fences and head digests
/// across pages, not here.
fn gate_audit_response(
    response: &NamedReadResponse,
    fence: &StateFence,
    minimums: &BTreeMap<RevisionKey, u64>,
) -> Result<(), ProviderError> {
    if !response.state_fence.is_compatible_with(fence) {
        return Err(ProviderError::Response {
            field: "response.state_fence",
            reason: "bridge fence is not compatible with the read fence",
        });
    }
    gate_audit_response_heads(&response.revision_heads, fence, minimums)
}

/// Assembled shaping inputs: validated records plus read evidence.
///
/// Private assembly boundary shared by the single-read and multi-page
/// paths: `records` arrive validated, scope-filtered, and presence-bound
/// with `observed_total` counting every payload record read;
/// `gap_ids` names carried-overflow record ids for omission accounting
/// (capped); `canonical_heads` are the key-ordered owner heads of the
/// single vintage being assembled.
struct AssembledShapedInputs {
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    records: Vec<ObservationRecordEnvelope>,
    observed_total: u64,
    gap_ids: Vec<String>,
    canonical_heads: Vec<RevisionHead>,
}

/// Shaped owner projections plus the revalidated Smart view.
pub struct JournalShapeOutput {
    /// Frozen V1 owner envelope over the carried admitted records.
    pub projection: JournalProjection,
    /// Smart read-aid view over the carried event records, revalidated.
    pub view: ExperienceView,
    /// Owner-issued revision heads bound into coverage, in canonical key
    /// order, carried so a later read can re-prove durability and
    /// monotonicity against this read.
    pub revision_heads: Vec<RevisionHead>,
}

/// Assemble one shaped journal read from validated page records.
///
/// Private assembly boundary shared by every enumeration path: coverage
/// binds the canonical owner heads with honest posture (exact carried
/// count with empty omissions, or partial), carried overflow beyond the
/// envelope bound becomes closed `TruncatedAtBound` omissions (never
/// silent truncation, never failure), and the frozen envelope plus the
/// ref-less echo view assemble exactly as the single-read path always
/// did. Records arrive validated, scope-filtered, and presence-bound;
/// `observed_total` counts every payload record read.
fn assemble_shaped_journal(
    inputs: AssembledShapedInputs,
) -> Result<JournalShapeOutput, ProviderError> {
    let mut omissions: Vec<ProjectionOmission> = Vec::new();
    for id in &inputs.gap_ids {
        let omission = ProjectionOmission {
            handle: ArtifactId::new(id.clone()).map_err(ProviderError::Foundation)?,
            class: ProjectionOmissionClass::TruncatedAtBound,
            detail: format!(
                "audit-range carry bound {} exceeded",
                MAX_PROJECTION_MEMBERS
            ),
        };
        omission
            .validate()
            .map_err(ProviderError::Contract)?;
        omissions.push(omission);
    }
    let carried = inputs.records;
    let mut canonical_heads = inputs.canonical_heads;
    canonical_heads.sort_by(|left, right| left.key.cmp(&right.key));
    let heads_digest = canonical_json_bytes(&canonical_heads)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ProviderError::Response {
            field: "response.revision_heads",
            reason: "revision heads are not canonically encodable",
        })?;
    let observed_count = inputs.observed_total;
    let carried_count = u64::try_from(carried.len()).unwrap_or(u64::MAX);
    let disposition = if carried_count == observed_count && omissions.is_empty() {
        CoverageDisposition::Complete
    } else {
        CoverageDisposition::Partial
    };
    let denominator_source_ref =
        format!("store-audit:GetAuditRange:{heads_digest}");
    let evidence = CoverageEvidence {
        disposition,
        denominator_source_ref: denominator_source_ref.clone(),
        interval: None,
        blind_intervals: Vec::new(),
        observed_count,
    };
    let coverage_digest = canonical_json_bytes(&evidence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ProviderError::Response {
            field: "projection.coverage",
            reason: "coverage evidence is not canonically encodable",
        })?;
    let coverage = ProjectionCoverage {
        evidence,
        coverage_digest,
    };
    let source_revision = format!(
        "audit-range:{}:{carried_count}/{observed_count}",
        heads_digest.get(..16).unwrap_or(&heads_digest)
    );
    let projection = JournalProjection::assemble(
        inputs.projection_id.clone(),
        inputs.scope.clone(),
        inputs.fence.clone(),
        source_revision,
        carried,
        coverage,
        omissions,
    )?;
    // Journal views carry no ref handles: V1 envelopes carry no owner
    // revision cursor by contract, and this cell never rebuilds cursors
    // from parts. The view echoes the owner coverage with Partial posture
    // over the carried volume; presence already bound every carried
    // record above, and substance travels in the owner projection.
    let view_observed = carried_count;
    let view_evidence = CoverageEvidence {
        disposition: CoverageDisposition::Partial,
        denominator_source_ref,
        interval: None,
        blind_intervals: Vec::new(),
        observed_count: view_observed,
    };
    let view_digest = canonical_json_bytes(&view_evidence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ProviderError::Response {
            field: "view.coverage",
            reason: "view coverage evidence is not canonically encodable",
        })?;
    let view = ExperienceView::assemble(
        ExperienceSourceFamily::SystemObservationJournal,
        inputs.scope.clone(),
        inputs.fence.clone(),
        Vec::new(),
        ProjectionCoverage {
            evidence: view_evidence,
            coverage_digest: view_digest,
        },
        Vec::new(),
    )?;
    Ok(JournalShapeOutput {
        projection,
        view,
        revision_heads: canonical_heads,
    })
}

/// Composed production inputs: one bridge fetch plus shaping context.
pub struct ProduceJournalInputs<'a> {
    /// Stable identity minted by the caller for the projection envelope.
    pub projection_id: ArtifactId,
    /// Read scope governing the projection and the bridge read.
    pub scope: ObservationScope,
    /// Fence the bridge read runs under, carried for edge gating.
    pub fence: StateFence,
    /// Read consistency for the bridge fetch.
    pub consistency: ReadConsistency,
    /// Record ids read from the live journal at call time for binding.
    pub admitted_record_ids: &'a BTreeSet<String>,
    /// Required revision minimums per head key (revision monotonicity).
    pub minimum_revisions: &'a BTreeMap<RevisionKey, u64>,
}

/// Composed producer-to-provider-to-consumer call in production types.
///
/// Enumerates the scope-free audit range through the caller-supplied
/// bridge client across bounded pages, shapes the admitted V1 envelopes
/// into the frozen owner projection, assembles the Smart view, and
/// revalidates both. Every page carries a fence-bound cursor (ordinal
/// zero starts the enumeration, so the legacy fail-closed overflow
/// path is never taken); a full page continues past the counted
/// ordinal and a short page ends the enumeration. A fence or head
/// advance mid-loop restarts from the head under the adopted vintage
/// (bounded retries, then fail-closed); total volume past the envelope
/// bound carries with an explicit coverage gap, never silent
/// truncation. The caller supplies the bridge client and the live
/// admitted-handle set; the only durable-touching operations are
/// read-only `GetAuditRange` catalogue reads. Terminal invocation
/// belongs to the runtime flow that owns both (Governor/daemon
/// observation edge); this function is the typed join that invocation
/// performs.
#[allow(
    clippy::too_many_lines,
    reason = "page loop sequences fetch, vintage, accumulate, and assemble in explicit order"
)]
pub async fn produce_journal_read<C: CanonicalReadClient + ?Sized>(
    client: &C,
    inputs: &ProduceJournalInputs<'_>,
) -> Result<JournalShapeOutput, ProviderError> {
    let mut fence = inputs.fence.clone();
    let mut canonical_heads: Vec<RevisionHead> = Vec::new();
    let mut have_vintage = false;
    let mut ordinal: u64 = 0;
    let mut pages: u32 = 0;
    let mut restarts: u32 = 0;
    let mut carried: Vec<ObservationRecordEnvelope> = Vec::new();
    let mut gap_ids: Vec<String> = Vec::new();
    let mut observed_total: u64 = 0;
    loop {
        if pages >= MAX_AUDIT_READ_PAGES {
            return Err(ProviderError::Response {
                field: "audit_range.pages",
                reason: "enumeration exceeds the bounded page budget",
            });
        }
        let cursor = page_cursor_for_ordinal(&fence, ordinal)?;
        let response = match fetch_audit_range(
            client,
            &fence,
            inputs.consistency.clone(),
            Some(cursor),
        )
        .await
        {
            Err(ProviderError::Bridge(StoreError::FenceMismatch)) => {
                // Fence advanced mid-enumeration: re-discover current
                // heads for the observed keys and restart under the
                // adopted vintage. No keys observed yet means the read
                // fence itself is stale: propagate for the caller to
                // refresh rather than guessing a fence here.
                let known_keys: Vec<RevisionKey> = canonical_heads
                    .iter()
                    .map(|head| head.key.clone())
                    .collect();
                if known_keys.is_empty() {
                    return Err(ProviderError::Bridge(StoreError::FenceMismatch));
                }
                let mut fresh = client
                    .revision_heads(known_keys)
                    .await
                    .map_err(ProviderError::Bridge)?;
                fresh.sort_by(|left, right| left.key.cmp(&right.key));
                let adopted = fresh
                    .first()
                    .map(|head| head.state_fence.clone())
                    .ok_or(ProviderError::Bridge(StoreError::FenceMismatch))?;
                if fresh.iter().any(|head| head.state_fence != adopted)
                    || !adopted.is_compatible_with(&inputs.fence)
                {
                    return Err(ProviderError::Response {
                        field: "response.revision_heads",
                        reason: "re-discovered heads carry no single compatible fence",
                    });
                }
                gate_audit_response_heads(&fresh, &adopted, inputs.minimum_revisions)?;
                fence = adopted;
                canonical_heads = fresh;
                have_vintage = true;
                ordinal = 0;
                carried.clear();
                gap_ids.clear();
                observed_total = 0;
                restarts = restarts.saturating_add(1);
                if restarts > MAX_AUDIT_READ_RESTARTS {
                    return Err(ProviderError::PresenceDrift);
                }
                continue;
            }
            result => result?,
        };
        pages = pages.saturating_add(1);
        gate_audit_response(&response, &fence, inputs.minimum_revisions)?;
        let mut page_heads = response.revision_heads.clone();
        page_heads.sort_by(|left, right| left.key.cmp(&right.key));
        let page_digest = canonical_json_bytes(&page_heads)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| ProviderError::Response {
                field: "response.revision_heads",
                reason: "revision heads are not canonically encodable",
            })?;
        let vintage_digest = canonical_json_bytes(&canonical_heads)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| ProviderError::Response {
                field: "response.revision_heads",
                reason: "revision heads are not canonically encodable",
            })?;
        if have_vintage
            && (response.state_fence != fence || page_digest != vintage_digest)
        {
            // Mid-enumeration advance: adopt the observed vintage only
            // when its fence stays combinable with the read fence the
            // caller isolated. An incompatible fence means the store
            // moved to a generation this read must not observe: fail
            // closed instead of projecting across the boundary.
            if !response.state_fence.is_compatible_with(&inputs.fence) {
                return Err(ProviderError::Response {
                    field: "response.state_fence",
                    reason: "advanced fence is not compatible with the read fence",
                });
            }
            fence = response.state_fence.clone();
            canonical_heads = page_heads;
            ordinal = 0;
            carried.clear();
            gap_ids.clear();
            observed_total = 0;
            restarts = restarts.saturating_add(1);
            if restarts > MAX_AUDIT_READ_RESTARTS {
                return Err(ProviderError::PresenceDrift);
            }
            have_vintage = true;
        } else {
            canonical_heads = page_heads;
            have_vintage = true;
        }
        gate_audit_response(&response, &fence, inputs.minimum_revisions)?;
        let payload: AuditRangeV1Payload =
            serde_json::from_value(response.payload.clone()).map_err(|error| {
                ProviderError::Payload {
                    reason: error.to_string(),
                }
            })?;
        for record in &payload.records {
            record.validate()?;
            let in_scope = match &record.event {
                Some(event) if event.affected_scope != inputs.scope => false,
                _ => true,
            };
            observed_total = observed_total.saturating_add(1);
            if !in_scope {
                continue;
            }
            if !inputs
                .admitted_record_ids
                .contains(record.record_id.as_str())
            {
                return Err(ProviderError::PresenceDrift);
            }
            if carried.len() < MAX_PROJECTION_MEMBERS {
                carried.push(record.clone());
            } else if gap_ids.len() < MAX_PROJECTION_OMISSIONS {
                gap_ids.push(record.record_id.clone());
            }
        }
        let page_bound = usize::try_from(AUDIT_PAGE_BOUND).unwrap_or(usize::MAX);
        if payload.records.len() > page_bound {
            return Err(ProviderError::Response {
                field: "response.payload",
                reason: "page exceeds the bounded page size",
            });
        }
        if payload.records.len() < page_bound {
            break;
        }
        // Ordinals count candidates, not carried refs: the store numbers
        // every envelope candidate in commit order, so the next page
        // resumes past the full payload length regardless of scope
        // filtering or carry bounds. Advancing by the filtered count
        // would re-read (duplicating handles) or skip records.
        ordinal = ordinal.saturating_add(u64::try_from(payload.records.len()).unwrap_or(u64::MAX));
    }
    assemble_shaped_journal(AssembledShapedInputs {
        projection_id: inputs.projection_id.clone(),
        scope: inputs.scope.clone(),
        fence,
        records: carried,
        observed_total,
        gap_ids,
        canonical_heads,
    })
}

/// Retention schedule attestation for one shaping call.
///
/// The owner-issued [`RetentionSchedule`] carries the schedule identity,
/// revision, fence, and exact closed policy set; knowledge is owner
/// attestation, never caller assertion. `holds` carries schedule-issued
/// hold terms keyed by record-handle text; absent entries mean no hold
/// applies. Unknown or stale refs resolve to the explicit gap posture via
/// [`resolve_retention_read`], which also verifies the schedule was in
/// force at each record's fence; no default is invented.
pub struct RetentionContext<'a> {
    /// Owner-issued retention schedule in force for this shaping call.
    pub schedule: &'a RetentionSchedule,
    /// Schedule-issued hold terms by record-handle text.
    pub holds: &'a BTreeMap<String, RetentionHold>,
}

/// One record withheld from a shaped view with its honest posture.
///
/// Withheld handles let the caller emit coverage gaps for material the
/// view does not carry; nothing withheld is silently dropped.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WithheldMember {
    /// Handle of the withheld record.
    pub handle: ArtifactId,
    /// Closed read posture for the withheld record.
    pub posture: ExperienceRetentionReadPosture,
}

/// Provider inputs for shaping one bank view over admitted bank records.
pub struct BankShapeInputs<'a> {
    /// Read scope governing the view; records must name it.
    pub scope: ObservationScope,
    /// Fence the view is read under, carried for edge gating.
    pub fence: StateFence,
    /// Admitted bank records shaping starts from (durable/edge-supplied).
    pub records: &'a [ExperienceBankRecord],
    /// Owner-supplied live bank envelope at call time for binding.
    pub live: &'a BankProjection,
    /// Owner source identity cursors are minted under (edge passes the
    /// Governor bank source identity); never invented here.
    pub source_id: &'a str,
    /// Retention schedule attestation for these records.
    pub retention: &'a RetentionContext<'a>,
}

/// Bank view plus withheld members with their gap postures.
pub struct BankShapeOutput {
    /// Smart read-aid view over owner-resolved bank refs.
    pub view: ExperienceView,
    /// Withheld records with honest postures for caller gap emission.
    pub withheld: Vec<WithheldMember>,
}

/// Resolve one admitted bank record to its view ref or its gap posture.
///
/// Validation, retention resolution, and envelope agreement run in owner
/// order: malformed records fail closed, non-readable records withhold
/// with [`WithheldMember`] gaps, and scope/fence drift fails closed
/// exactly as the owner supplier requires. Refs resolve through the
/// shared [`bank_record_ref`] constructor only; cursors are never rebuilt
/// from parts here.
fn resolve_bank_member(
    record: &ExperienceBankRecord,
    scope: &ObservationScope,
    fence: &StateFence,
    source_id: &str,
    retention: &RetentionContext<'_>,
) -> Result<Result<eliot_observation_contracts::ExperienceRecordRef, WithheldMember>, ProviderError>
{
    let posture = resolve_retention_read(
        &record.retention,
        retention.schedule,
        &record.fence,
        retention.holds.get(record.handle.as_str()),
    )?;
    if !matches!(
        posture,
        ExperienceRetentionReadPosture::Readable { .. }
    ) {
        return Ok(Err(WithheldMember {
            handle: record.handle.clone(),
            posture,
        }));
    }
    if record.scope != *scope {
        return Err(ProviderError::Response {
            field: "bank_record.scope",
            reason: "record scope does not match view scope",
        });
    }
    if !record.fence.is_compatible_with(fence) {
        return Err(ProviderError::Response {
            field: "bank_record.fence",
            reason: "record fence is not compatible with view fence",
        });
    }
    bank_record_ref(record, source_id)
        .map(Ok)
        .map_err(ProviderError::Contract)
}

/// Provider plus Smart-consumer call: shape one bank view and revalidate.
///
/// Resolves admitted bank records to owner-issued refs, assembles the
/// bank-family [`ExperienceView`] with Partial echo coverage over the
/// live owner-observed volume, and invokes the Smart consumer edge
/// [`revalidate_bank_refs`] against the live owner envelope: every
/// carried ref must still resolve with identical revision cursor, scope,
/// and fence, or live advancement fails the read closed.
pub fn shape_bank_view(
    inputs: &BankShapeInputs<'_>,
) -> Result<BankShapeOutput, ProviderError> {
    let mut refs = Vec::new();
    let mut withheld = Vec::new();
    for record in inputs.records {
        match resolve_bank_member(
            record,
            &inputs.scope,
            &inputs.fence,
            inputs.source_id,
            inputs.retention,
        )? {
            Ok(reference) => refs.push(reference),
            Err(gap) => withheld.push(gap),
        }
    }
    for reference in &refs {
        let present = inputs
            .live
            .refs
            .iter()
            .any(|live| live.handle == reference.handle);
        if !present {
            return Err(ProviderError::PresenceDrift);
        }
    }
    let observed_count = u64::try_from(inputs.live.refs.len()).unwrap_or(u64::MAX);
    let carried_count = u64::try_from(refs.len()).unwrap_or(u64::MAX);
    if carried_count > observed_count {
        return Err(ProviderError::PresenceDrift);
    }
    let evidence = CoverageEvidence {
        disposition: CoverageDisposition::Partial,
        denominator_source_ref: format!("bank-projection:{}", inputs.live.digest),
        interval: None,
        blind_intervals: Vec::new(),
        observed_count,
    };
    let coverage_digest = canonical_json_bytes(&evidence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ProviderError::Response {
            field: "view.coverage",
            reason: "view coverage evidence is not canonically encodable",
        })?;
    let view = ExperienceView::assemble(
        ExperienceSourceFamily::SystemExperienceBank,
        inputs.scope.clone(),
        inputs.fence.clone(),
        refs,
        ProjectionCoverage {
            evidence,
            coverage_digest,
        },
        Vec::new(),
    )?;
    revalidate_bank_refs(&view, inputs.live)?;
    Ok(BankShapeOutput { view, withheld })
}

/// Provider inputs for shaping one feedback view over admitted records.
pub struct FeedbackShapeInputs<'a> {
    /// Read scope governing the view; records must name it.
    pub scope: ObservationScope,
    /// Fence the view is read under, carried for edge gating.
    pub fence: StateFence,
    /// Admitted feedback records shaping starts from (durable/edge-supplied).
    pub records: &'a [AgentFeedbackRecord],
    /// Owner-supplied live feedback envelope at call time for binding.
    pub live: &'a FeedbackProjection,
    /// Owner source identity cursors are minted under (edge passes the
    /// Governor feedback source identity); never invented here.
    pub source_id: &'a str,
    /// Retention schedule attestation for these records.
    pub retention: &'a RetentionContext<'a>,
}

/// Feedback view plus withheld members with their gap postures.
pub struct FeedbackShapeOutput {
    /// Smart read-aid view over owner-resolved feedback refs.
    pub view: ExperienceView,
    /// Withheld records with honest postures for caller gap emission.
    pub withheld: Vec<WithheldMember>,
}

/// Resolve one admitted feedback record to its view ref or gap posture.
/// Same owner order as [`resolve_bank_member`]: validate, retention
/// posture, envelope agreement, then the shared [`feedback_record_ref`]
/// constructor only.
fn resolve_feedback_member(
    record: &AgentFeedbackRecord,
    scope: &ObservationScope,
    fence: &StateFence,
    source_id: &str,
    retention: &RetentionContext<'_>,
) -> Result<Result<eliot_observation_contracts::ExperienceRecordRef, WithheldMember>, ProviderError>
{
    let posture = resolve_retention_read(
        &record.retention,
        retention.schedule,
        &record.fence,
        retention.holds.get(record.handle.as_str()),
    )?;
    if !matches!(
        posture,
        ExperienceRetentionReadPosture::Readable { .. }
    ) {
        return Ok(Err(WithheldMember {
            handle: record.handle.clone(),
            posture,
        }));
    }
    if record.scope != *scope {
        return Err(ProviderError::Response {
            field: "feedback_record.scope",
            reason: "record scope does not match view scope",
        });
    }
    if !record.fence.is_compatible_with(fence) {
        return Err(ProviderError::Response {
            field: "feedback_record.fence",
            reason: "record fence is not compatible with view fence",
        });
    }
    feedback_record_ref(record, source_id)
        .map(Ok)
        .map_err(ProviderError::Contract)
}

/// Provider plus Smart-consumer call: shape one feedback view and revalidate.
///
/// Same binding as [`shape_bank_view`]: owner-resolved refs, Partial echo
/// coverage over the live owner-observed volume named by the live
/// envelope digest, then the Smart consumer edge
/// [`revalidate_feedback_refs`] against the live owner envelope.
pub fn shape_feedback_view(
    inputs: &FeedbackShapeInputs<'_>,
) -> Result<FeedbackShapeOutput, ProviderError> {
    let mut refs = Vec::new();
    let mut withheld = Vec::new();
    for record in inputs.records {
        match resolve_feedback_member(
            record,
            &inputs.scope,
            &inputs.fence,
            inputs.source_id,
            inputs.retention,
        )? {
            Ok(reference) => refs.push(reference),
            Err(gap) => withheld.push(gap),
        }
    }
    for reference in &refs {
        let present = inputs
            .live
            .refs
            .iter()
            .any(|live| live.handle == reference.handle);
        if !present {
            return Err(ProviderError::PresenceDrift);
        }
    }
    let observed_count = u64::try_from(inputs.live.refs.len()).unwrap_or(u64::MAX);
    let carried_count = u64::try_from(refs.len()).unwrap_or(u64::MAX);
    if carried_count > observed_count {
        return Err(ProviderError::PresenceDrift);
    }
    let evidence = CoverageEvidence {
        disposition: CoverageDisposition::Partial,
        denominator_source_ref: format!("feedback-projection:{}", inputs.live.digest),
        interval: None,
        blind_intervals: Vec::new(),
        observed_count,
    };
    let coverage_digest = canonical_json_bytes(&evidence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ProviderError::Response {
            field: "view.coverage",
            reason: "view coverage evidence is not canonically encodable",
        })?;
    let view = ExperienceView::assemble(
        ExperienceSourceFamily::AgentFeedback,
        inputs.scope.clone(),
        inputs.fence.clone(),
        refs,
        ProjectionCoverage {
            evidence,
            coverage_digest,
        },
        Vec::new(),
    )?;
    revalidate_feedback_refs(&view, inputs.live)?;
    Ok(FeedbackShapeOutput { view, withheld })
}

/// Smart consumer invocation inputs: owner envelopes plus edge inputs.
pub struct SelfQualityInputs<'a> {
    /// Assessment identity minted by the caller.
    pub assessment_id: ArtifactId,
    /// Work scope governing the assessment.
    pub scope: WorkScopeId,
    /// Fence the assessment runs under, carried for edge gating.
    pub fence: StateFence,
    /// Owner journal envelope, when journal evidence is cited.
    pub journal: Option<&'a JournalProjection>,
    /// Owner bank envelope, when bank evidence is cited.
    pub bank: Option<&'a BankProjection>,
    /// Owner feedback envelope, when feedback is cited.
    pub feedback: Option<&'a FeedbackProjection>,
    /// Admitted epistemic position (must be current).
    pub position: &'a CurrentEpistemicPosition,
    /// Per-attempt receipt candidates (at least one).
    pub receipts: &'a [HarnessActivationReceiptCandidate],
    /// Obligation-profile handles cited by handle only.
    pub obligation_handles: &'a [ArtifactId],
}

/// Smart consumer invocation: assess self-quality over owner envelopes.
///
/// Calls the released [`assess_self_quality`] consumer with true owner
/// inputs: Governor-supplied journal/bank/feedback envelopes (journal
/// from the bridge-shaped projection, bank/feedback from the canonical
/// owner suppliers) plus edge-supplied position, receipts, and
/// obligation handles. At least one family must be present; journal-only
/// assessment stays valid while bank/feedback supply pends. No findings,
/// verdicts, scores, or completeness posture are emitted here: the
/// candidate freezes the assessed closure for Governor/Human review.
pub fn produce_self_quality(
    inputs: &SelfQualityInputs<'_>,
) -> Result<QualityAssessmentCandidate, ProviderError> {
    let projections = ExperienceProjections {
        journal: inputs.journal,
        bank: inputs.bank,
        feedback: inputs.feedback,
    };
    assess_self_quality(
        inputs.assessment_id.clone(),
        inputs.scope.clone(),
        inputs.fence.clone(),
        &projections,
        inputs.position,
        inputs.receipts,
        inputs.obligation_handles,
    )
    .map_err(ProviderError::Quality)
}

/// Self-quality assess-plus-recheck inputs: the assess closure plus the
/// edge attestation the recheck resolves handles against.
pub struct SelfQualityRecheckInputs<'a> {
    /// Assess inputs: owner envelopes plus edge position/receipts/handles.
    pub assess: SelfQualityInputs<'a>,
    /// Edge-attested handles for owner-held bodies cited by handle only
    /// (including every omission handle the assess closure names that no
    /// supplied envelope carries as a member).
    pub attested_handles: Vec<ArtifactId>,
}

/// Consuming call: assess self-quality, then re-resolve the candidate.
///
/// Runs [`produce_self_quality`] and immediately re-resolves the frozen
/// closure through [`recheck_candidate`] against the same owner inputs:
/// every echoed digest, denominator, and cited handle must resolve
/// against the supplied envelopes, receipts, position, and edge
/// attestation, or drift fails the read closed. A passing recheck states
/// that the frozen closure still resolves against current owner inputs,
/// nothing more: no score, verdict, or completeness is adjudicated.
pub fn assess_and_recheck(
    inputs: SelfQualityRecheckInputs<'_>,
) -> Result<QualityAssessmentCandidate, ProviderError> {
    let candidate = produce_self_quality(&inputs.assess)?;
    let journals = inputs.assess.journal.into_iter().collect::<Vec<_>>();
    let banks = inputs.assess.bank.into_iter().collect::<Vec<_>>();
    let feedbacks = inputs.assess.feedback.into_iter().collect::<Vec<_>>();
    let snapshot = OwnerSnapshot {
        statuses: Vec::new(),
        receipts: inputs.assess.receipts.iter().collect::<Vec<_>>(),
        journals,
        banks,
        feedbacks,
        positions: vec![inputs.assess.position],
        attested_handles: inputs.attested_handles,
    };
    recheck_candidate(&candidate, &snapshot).map_err(ProviderError::Quality)?;
    Ok(candidate)
}

/// Memory-quality consumer invocation: assess one owner batch.
///
/// Calls the released [`assess_quality`](eliot_memory_quality::assess_quality)
/// consumer with the edge-supplied owner request (bounded batch, owner
/// applicability verdict, admitted projections, advisory receipts). The
/// memory family has no provider read path in this lane: every member
/// arrives as an owner value through the request, validated there. The
/// returned assessment carries gravity, maintenance, and counter-metric
/// sections with explicit coverage; no score, rank, or lifecycle
/// transition is emitted.
pub fn produce_memory_quality(
    request: &QualityRequest,
) -> Result<MemoryEcologyAssessment, ProviderError> {
    assess_quality(request).map_err(ProviderError::MemoryQuality)
}

/// Understanding consumer invocation: assess one subject scope.
///
/// Calls the released [`assess_scoped`](eliot_understanding_assessment::assess_scoped)
/// consumer with the edge-supplied scoped input (owner context with
/// experience envelopes, scope, cites, closure). The caller binds
/// outcome-side experience evidence; this function performs no binding
/// of its own. The returned assessment is finding-free candidate
/// material for Governor/Human review, never a verdict.
pub fn produce_understanding_assessment(
    input: ScopedInput<'_>,
) -> Result<ScopedUnderstandingAssessment, ProviderError> {
    assess_scoped(input).map_err(ProviderError::Understanding)
}

/// Understanding consumer invocation: assess common ground.
///
/// Calls the released [`assess_common_ground`](eliot_understanding_assessment::assess_common_ground)
/// consumer with the edge-supplied common-ground input (owner context
/// with experience envelopes, scope, per-slot compatibility cites,
/// requalification scope, closure). Same binding rule as
/// [`produce_understanding_assessment`]: outcome-side experience
/// evidence arrives bound by the caller. Terminology, reference,
/// commitment, action-consequence, survival, and transfer cites stay
/// caller-supplied; nothing is inferred here.
pub fn produce_common_ground_assessment(
    input: CommonGroundInput<'_>,
) -> Result<CommonGroundAssessment, ProviderError> {
    assess_common_ground(input).map_err(ProviderError::Understanding)
}
