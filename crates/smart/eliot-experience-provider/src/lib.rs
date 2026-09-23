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
//! - view revision cursors digest the envelope bytes actually read; the
//!   `revision` cursor carries the read marker (the response revision-heads
//!   digest), because the durable audit read issues no per-record owner
//!   revision cursor. Per-record owner revision cursors remain an explicit
//!   follow-up for the canonical owner (see the coordination note below);
//! - the view echoes coverage with `Partial` posture and never establishes
//!   completeness, exactly as the Smart read-aid contract requires.
//!
//! ## Retention posture (I05-14)
//!
//! Unknown, stale, or unreachable refs use the existing retention posture,
//! never an invented schedule: a bridge that reports `Unavailable` becomes
//! [`ProviderError::RetentionBlocked`], recording the hold
//! (`store-bridge-unavailable`) with ordinary use unavailable while the
//! bridge stays down, per the `RETENTION_BLOCKED` availability axis
//! (`docs/architecture/I05-14-retention-and-erasure.md`). No expiry,
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
//! Bank and feedback owner supply (live `BankProjection`/`FeedbackProjection`
//! values plus per-record owner revision cursors for the audit payload) is
//! built by the canonical owner lane in a separate worktree against these
//! exact shared signatures: no new named reads (this cell consumes only the
//! existing `GetAuditRange` catalogue entry), no contract edits (V1 envelope
//! types are reused unchanged), and journal-only assessment stays valid
//! (`assess_self_quality` requires at least one family, not all three).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_experience_projection::{ExperienceView, revalidate_journal_presence};
use eliot_observation_contracts::{
    CoverageDisposition, CoverageEvidence, ExperienceRecordRef, ExperienceSourceFamily,
    JournalProjection, ObservationError, ObservationRecordEnvelope, ObservationScope,
    ProjectionCoverage, SourceRevisionHandle,
};
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    RevisionHead, RevisionKey, ScopeId, StoreError,
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
    /// The bridge is unavailable: ordinary use stays unavailable under the
    /// named hold (I05-14 `RETENTION_BLOCKED` posture). No schedule is
    /// invented; the hold cites the bridge condition for owner review.
    #[error("retention blocked ({hold}): ordinary use unavailable, no invented schedule")]
    RetentionBlocked { hold: &'static str },
    /// A required revision head is missing or regressed: the bridge read is
    /// stale relative to the caller-supplied minimums. Re-read at a current
    /// revision; never project a regressed enumeration.
    #[error("bridge revision heads are stale relative to required minimums")]
    StaleRevision,
    /// The live journal advanced past the bridge read: a carried record no
    /// longer presence-checks. Re-read; never project stale presence.
    #[error("live owner state advanced past the bridge read")]
    PresenceDrift,
    /// A projection or view contract rejected the shaped read.
    #[error("projection contract: {0}")]
    Contract(#[from] ObservationError),
    /// A foundation handle or encoding contract rejected the shaped read.
    #[error("foundation contract: {0}")]
    Foundation(#[from] eliot_contracts::ContractError),
}

/// Producer: fetch one scoped audit range through the canonical bridge.
///
/// Issues the existing `GetAuditRange` catalogue read with no parameters
/// and validates the response shape, operation echo, and fence
/// compatibility. A bridge that reports `Unavailable` becomes
/// [`ProviderError::RetentionBlocked`]; every other store failure travels
/// as [`ProviderError::Bridge`].
pub async fn fetch_audit_range<C: CanonicalReadClient + ?Sized>(
    client: &C,
    scope_id: ScopeId,
    fence: &StateFence,
    consistency: ReadConsistency,
) -> Result<NamedReadResponse, ProviderError> {
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetAuditRange,
        scope_id: Some(scope_id),
        consistency,
        state_fence: fence.clone(),
        parameters: BTreeMap::new(),
    };
    request.validate().map_err(ProviderError::Bridge)?;
    let response = match client.execute_named(request).await {
        Err(StoreError::Unavailable) => {
            return Err(ProviderError::RetentionBlocked {
                hold: "store-bridge-unavailable",
            });
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
    if !response.state_fence.is_compatible_with(fence) {
        return Err(ProviderError::Response {
            field: "response.state_fence",
            reason: "bridge fence is not compatible with the read fence",
        });
    }
    Ok(response)
}

/// Provider inputs for shaping one bridge read into owner projections.
pub struct JournalShapeInputs<'a> {
    /// Stable identity minted by the caller for the projection envelope.
    pub projection_id: ArtifactId,
    /// Read scope governing the projection; carried event records must name it.
    pub scope: ObservationScope,
    /// Fence the bridge read ran under, carried for edge gating.
    pub fence: StateFence,
    /// Validated `GetAuditRange` bridge response shaping starts from.
    pub response: &'a NamedReadResponse,
    /// Record ids read from the live journal at call time for binding.
    pub admitted_record_ids: &'a BTreeSet<String>,
    /// Required revision minimums per head key (revision monotonicity):
    /// every named key must be present with at least the named revision.
    /// Empty imposes no constraint.
    pub minimum_revisions: &'a BTreeMap<RevisionKey, u64>,
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

/// Provider plus Smart-consumer call: shape one bridge read and revalidate.
///
/// Parses the coordinated `audit_range_v1` payload, carries admitted V1
/// envelopes (event records in the read scope plus scope-free gap/control
/// records), binds every carried record against the live admitted-handle
/// set, assembles the frozen [`JournalProjection`] with honest coverage,
/// assembles the journal-family [`ExperienceView`], and revalidates the
/// view against the owner projection. Any drift, malformation, or fence
/// mismatch fails closed; nothing partial is ever emitted as complete.
pub fn shape_journal_read(
    inputs: &JournalShapeInputs<'_>,
) -> Result<JournalShapeOutput, ProviderError> {
    if inputs.response.operation != NamedReadOperation::GetAuditRange {
        return Err(ProviderError::Response {
            field: "response.operation",
            reason: "shaping starts from an audit-range read only",
        });
    }
    inputs
        .response
        .validate()
        .map_err(ProviderError::Bridge)?;
    if !inputs.response.state_fence.is_compatible_with(&inputs.fence) {
        return Err(ProviderError::Response {
            field: "response.state_fence",
            reason: "bridge fence is not compatible with the read fence",
        });
    }
    // Schedule-fence owner check (mirrors the read facade): every
    // owner-issued revision head must carry exactly the read fence. A
    // compatible-but-unequal head means the enumeration was not read under
    // the fence this projection claims, so the read fails closed.
    if inputs
        .response
        .revision_heads
        .iter()
        .any(|head| head.state_fence != inputs.fence)
    {
        return Err(ProviderError::Response {
            field: "response.revision_heads",
            reason: "owner head fence does not equal the read fence",
        });
    }
    // Revision monotonicity (mirrors the read facade): every required key
    // must be present with at least the required revision. A missing key
    // or a regressed revision means the read is stale for this caller.
    for (key, minimum) in inputs.minimum_revisions {
        let current = inputs
            .response
            .revision_heads
            .iter()
            .find(|head| head.key == *key)
            .map(|head| head.revision);
        if current.is_none_or(|revision| revision < *minimum) {
            return Err(ProviderError::StaleRevision);
        }
    }
    // Canonical refs: revision heads sort by key so the coverage digest
    // and denominator ref are order-independent. The digest below proves
    // this read's shape only; durable authority stays with the bound
    // heads plus the fence-equality check above, both carried in the
    // output for later re-proof.
    let mut canonical_heads = inputs.response.revision_heads.clone();
    canonical_heads.sort_by(|left, right| left.key.cmp(&right.key));
    let payload: AuditRangeV1Payload =
        serde_json::from_value(inputs.response.payload.clone())
            .map_err(|error| ProviderError::Payload {
                reason: error.to_string(),
            })?;
    let mut carried: Vec<ObservationRecordEnvelope> = Vec::new();
    for record in &payload.records {
        record.validate()?;
        match &record.event {
            Some(event) if event.affected_scope != inputs.scope => continue,
            _ => carried.push(record.clone()),
        }
    }
    for record in &carried {
        if !inputs.admitted_record_ids.contains(record.record_id.as_str()) {
            return Err(ProviderError::PresenceDrift);
        }
    }
    let heads_digest = canonical_json_bytes(&canonical_heads)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ProviderError::Response {
            field: "response.revision_heads",
            reason: "revision heads are not canonically encodable",
        })?;
    let observed_count = u64::try_from(payload.records.len()).unwrap_or(u64::MAX);
    let carried_count = u64::try_from(carried.len()).unwrap_or(u64::MAX);
    let disposition = if carried_count == observed_count {
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
        Vec::new(),
    )?;
    let mut refs = Vec::new();
    for record in projection.records.iter().filter(|item| item.event.is_some()) {
        let bytes = canonical_json_bytes(record).map_err(|_| ProviderError::Response {
            field: "projection.records",
            reason: "carried record is not canonically encodable",
        })?;
        let Some(event) = record.event.as_ref() else {
            return Err(ProviderError::Response {
                field: "projection.records",
                reason: "validated record lost its event scope",
            });
        };
        refs.push(ExperienceRecordRef {
            handle: ArtifactId::new(record.record_id.clone())?,
            revision: SourceRevisionHandle {
                source_id: record.record_id.clone(),
                revision: projection.source_revision.clone(),
                content_sha256: sha256_hex(&bytes),
                byte_length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            },
            scope: event.affected_scope.clone(),
            fence: inputs.fence.clone(),
        });
    }
    let view_observed = u64::try_from(refs.len()).unwrap_or(u64::MAX);
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
        refs,
        ProjectionCoverage {
            evidence: view_evidence,
            coverage_digest: view_digest,
        },
        Vec::new(),
    )?;
    revalidate_journal_presence(&view, &projection)?;
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
    /// Store scope the audit range is read in.
    pub scope_id: ScopeId,
    /// Read consistency for the bridge fetch.
    pub consistency: ReadConsistency,
    /// Record ids read from the live journal at call time for binding.
    pub admitted_record_ids: &'a BTreeSet<String>,
    /// Required revision minimums per head key (revision monotonicity).
    pub minimum_revisions: &'a BTreeMap<RevisionKey, u64>,
}

/// Composed producer-to-provider-to-consumer call in production types.
///
/// Fetches the scoped audit range through the caller-supplied bridge
/// client, shapes the admitted V1 envelopes into the frozen owner
/// projection, assembles the Smart view, and revalidates both. The caller
/// supplies the bridge client and the live admitted-handle set; the only
/// durable-touching operation is the read-only `GetAuditRange` catalogue
/// read. Terminal invocation belongs to the runtime flow that owns both
/// (Governor/daemon observation edge); this function is the typed join
/// that invocation performs.
pub async fn produce_journal_read<C: CanonicalReadClient + ?Sized>(
    client: &C,
    inputs: &ProduceJournalInputs<'_>,
) -> Result<JournalShapeOutput, ProviderError> {
    let response = fetch_audit_range(
        client,
        inputs.scope_id.clone(),
        &inputs.fence,
        inputs.consistency.clone(),
    )
    .await?;
    shape_journal_read(&JournalShapeInputs {
        projection_id: inputs.projection_id.clone(),
        scope: inputs.scope.clone(),
        fence: inputs.fence.clone(),
        response: &response,
        admitted_record_ids: inputs.admitted_record_ids,
        minimum_revisions: inputs.minimum_revisions,
    })
}
