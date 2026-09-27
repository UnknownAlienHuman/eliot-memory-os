//! Skill pair dispatch for the daemon local-read poller (issue #1882).
//!
//! Serves claimed pairs whose tool name routes to a Skill kind (see
//! [`skill_tool_kind`](eliot_agent_bridge_core::skill_transport::skill_tool_kind))
//! locally through the composition-held Skill driver instead of forwarding
//! them on the Kernel `local_read` leg (which serves store reads only).
//! Intake pairs decode to the wire intake, resolve canonical procedure
//! acceptance over the authenticated Kernel route, and drive install→receipt
//! only for owner-accepted material (issue #1191); display pairs decode to
//! the wire display request and drive ack→display; activation pairs decode to
//! the wire harness receipt and fold it into the per-attempt stage summary
//! (issue #1191); execution pairs decode to the wire evidence ingest, retain
//! the bounded page through the existing evidence owner, and publish an
//! explicit bounded reconciliation assessment over the OWNER-retained
//! attempt-wide execution set (issue #2664) — a partial page can no longer
//! clear a retained unresolved execution.
//! Every claimed pair settles through a result body — including refusals,
//! which persist as typed refusal outcomes — so no skill pair can poison the
//! poller into a crash loop. `WorkScope` guard withholding retains typed identity
//! evidence. Only transport and submit-leg failures fail the daemon closed.
//!
//! The pair arrives Kernel-admitted (capability linkage proven at intake);
//! the tool/capability coherence is re-checked here defensively, and the
//! admitted fence comes from the composition's live snapshot through the
//! existing injector and carry entries — never from a re-stated claim.

#![forbid(unsafe_code)]

use eliot_agent_bridge_core::{SkillResultEnvelope, SkillToolKind, skill_tool_kind};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt,
};
use serde_json::Value;
use thiserror::Error;

use super::DaemonComposition;
use super::daemon_kernel_client::DaemonKernelClient;
use super::skill_acceptance_read::{AcceptanceRecord, AcceptanceResolution, AcceptanceVerdict};
///
/// Driver refusals (stale, drift, unavailable, fence) are NOT errors here —
/// they persist as typed refusal outcomes through [`SkillResultEnvelope`],
/// so every claimed pair settles through the submit leg.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SkillDispatchError {
    /// Tool bytes are not a Skill request object.
    #[error("skill pair tool is not a well-formed skill request")]
    MalformedTool,
    /// Presented tool name does not match the admitted capability.
    #[error("skill pair capability does not match its tool name")]
    CapabilityMismatch,
    /// Result body fails its closed shape.
    #[error("skill pair result body fails its shape: {0}")]
    Body(String),
}

/// Routes one claimed pair tool to Skill handling, if it names one.
///
/// Thin predicate over the shared routing table for the poller: returns
/// `true` exactly when the tool JSON carries a Skill capability name. The
/// poller serves such pairs locally through [`plan_skill_pair`] and
/// [`commit_skill_pair`]; anything
/// else keeps the existing forward path byte-identical.
#[must_use]
pub fn is_skill_tool(tool: &Value) -> bool {
    tool.as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .is_some_and(|name| skill_tool_kind(name).is_some())
}

/// Owned work planned for one claimed Skill pair. Its binding fields are
/// private so only the planner can authorize a canonical acceptance result.
pub struct SkillPairPlan {
    envelope_sha256: String,
    attempt: LocalReadAttempt,
    admitted_fence: StateFence,
    action: PlannedSkillPair,
}

enum PlannedSkillPair {
    /// The request is fully resolved without further composition state.
    Resolved(SkillResultEnvelope),
    /// Display consumes the live composition owner synchronously.
    Display(eliot_agent_bridge_core::SkillDisplayPayload),
    /// Material-use evidence is admitted against the live catalogue and
    /// Governor standing only after the plan's fence is rechecked.
    ///
    /// The candidate carries the owner binding the plan resolved without the
    /// composition lock: the subject's Skill revision/package, the
    /// load-bearing owner revisions read, the outcome records that actually
    /// resolved, and the coverage those reads achieved. `useful` is already
    /// owner-qualified here — the bare wire receipt is not.
    Activation(ActivationCandidate),
    /// Execution evidence is reconciled and published through the lifecycle
    /// owner, then committed against a fresh fence recheck. The decoded
    /// payload and its reconciliation verdict travel together so the commit
    /// publishes the SAME evidence the plan reconciled.
    Execution(Box<ExecutionCandidate>),
    /// The acceptance read returned an owner-backed record at this fence.
    AcceptedIntake {
        /// Decoded candidate the Skill owner will validate and ingest.
        payload: Box<eliot_agent_bridge_core::SkillIntakePayload>,
        /// Exact accepted canonical lifecycle row used by the read plan.
        record: AcceptanceRecord,
        /// The exact canonical read the verdict was resolved from, retained so
        /// the commit step hydrates the daemon-held capability admission view
        /// from the same read (issue #1957, I3.4) without a second round trip.
        resolution: Box<AcceptanceResolution>,
    },
}

/// Activation ingest plan: the presented harness receipt kept DISTINCT from
/// the authenticated ingest that carried it, plus the owner binding resolved
/// for it without the composition lock.
///
/// The two identities are separate fields on purpose. `ingest_attempt_id` is
/// this daemon's own authenticated `LocalReadAttempt` — what the daemon may do
/// now. `receipt.attempt_ref` is the historical agent attempt the receipt
/// observes — what happened then. Neither is derived from the other, and a
/// receipt field never stands in for the ingest identity (I15.2: principal
/// identity is issued by Kernel, never self-declared).
pub struct ActivationCandidate {
    /// The presented per-attempt receipt, unverified on its own.
    receipt: Box<eliot_skill::SkillHarnessActivationReceipt>,
    /// This ingest's own authenticated attempt id, from the Kernel route.
    ingest_attempt_id: String,
    /// Owner-revision binding the Skill owner resolved for the subject.
    source_revisions: Vec<eliot_skill::SourceRevision>,
    /// Owner records that resolved the receipt's presented outcome refs.
    resolved_outcomes: Vec<eliot_skill::ResolvedOutcome>,
    /// How completely the backing reads were served.
    coverage: eliot_skill::EvidenceCoverage,
}

impl ActivationCandidate {
    /// Owner-qualified summary for this attempt: the presented receipt's stage
    /// claims, with usefulness resolved only from `resolved_outcomes`.
    fn qualified_summary(&self) -> eliot_skill::AttemptLifecycleSummary {
        eliot_skill::qualify_useful_outcomes(&self.receipt, &self.resolved_outcomes)
    }
}

/// Execution ingest plan: the decoded evidence window plus the owner-retained
/// attempt-wide position the plan read WITHOUT the composition lock
/// (issue #2664).
///
/// The window and the position are two different claims and stay two fields.
/// The window is what the harness submitted; the position is what the Skill
/// lifecycle owner actually holds for this Skill at the owner revision the
/// plan read. The disposition is computed from the position, so a page can
/// never clear a retained execution it simply did not mention.
pub struct ExecutionCandidate {
    /// The presented evidence window, bound to its Skill identity.
    payload: Box<eliot_agent_bridge_core::SkillExecutionPayload>,
    /// Owner-retained attempt-wide execution set as it stood at the plan's
    /// read, plus the owner revisions that read depended on. `None` when the
    /// owner held no lifecycle view for this Skill: that is absence of a row,
    /// never an empty-but-complete set.
    read_position: Option<Box<eliot_skill::SkillExecutionOwnerPosition>>,
    /// The Skill-owner lifecycle revision the read resolved, when it resolved
    /// one. `None` is the honest unresolved case.
    lifecycle_source_revision: Option<eliot_skill::SourceRevision>,
    /// This ingest's own authenticated attempt id, from the Kernel route.
    ingest_attempt_id: String,
}

/// Result of one read-only owner-position probe on the Skill lifecycle owner.
pub enum OwnerPositionRead {
    /// The owner holds a lifecycle view for this Skill. The read is a plain
    /// in-process owner lookup, so it cannot be held open across any canonical
    /// call.
    Read(Box<eliot_skill::SkillExecutionOwnerPosition>),
    /// The owner holds no lifecycle view for this Skill: absence of a row, not
    /// an empty set.
    Absent,
    /// The read failed or the profile is not wired; the assessment must be
    /// unavailable rather than a self-comparison of the submitted page.
    Unavailable(String),
}

/// Reads the owner-retained execution position for one subject Skill without
/// holding the daemon composition mutex across the read (issue #2664, AUD7).
///
/// Borrowed directly from the composition for the duration of the single
/// non-awaiting lookup, so no guard, lock handle or async context can be kept
/// open across a canonical read.
fn read_execution_owner_position(
    composition: &DaemonComposition,
    skill_id: &str,
) -> OwnerPositionRead {
    let governor = composition.skill_lifecycle_owner();
    let Some(view) = governor.view(skill_id) else {
        return OwnerPositionRead::Absent;
    };
    let position = eliot_skill::SkillExecutionOwnerPosition::from_lifecycle_view(view);
    match position.validate() {
        Ok(()) => OwnerPositionRead::Read(Box::new(position)),
        Err(error) => OwnerPositionRead::Unavailable(error.to_string()),
    }
}

/// Reads the owner-retained execution position for a claimed `skill.execute`
/// pair, under a composition borrow the caller releases immediately
/// (issue #2664).
///
/// `None` for every non-execute tool: the read is only meaningful for the
/// execute leg, and no other leg may observe the Skill owner's retained
/// execution set. This is the single production entry to the owner read, and
/// it performs no await, so the caller can take it under a short guard and
/// drop the guard before any canonical I/O.
#[must_use]
pub fn execution_owner_read(
    composition: &DaemonComposition,
    tool: &Value,
) -> Option<OwnerPositionRead> {
    let name = tool
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if skill_tool_kind(name) != Some(SkillToolKind::Execute) {
        return None;
    }
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);
    let Ok(payload) = canonical_json_bytes(&arguments)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            eliot_agent_bridge_core::SkillExecutionPayload::decode(&bytes)
                .map_err(|error| error.to_string())
        })
    else {
        // A payload that does not decode names no Skill, so there is no owner
        // to read. The decode failure itself is reported by the plan.
        return Some(OwnerPositionRead::Absent);
    };
    Some(read_execution_owner_position(
        composition,
        &payload.skill_id,
    ))
}

/// Plans one execution-evidence ingest into a bounded assessment over the
/// owner-retained attempt-wide set (issue #2664).
///
/// Every presented record is validated and deduplicated by exact evidence
/// identity, and the reconciliation reads the OWNER-retained set the caller
/// passed in — never the page — so a bounded window without an `Uncertain` row
/// is no longer read as proof that nothing is unresolved. The owner read
/// happens under the caller's short composition borrow; nothing here holds
/// composition state or accumulates the attempt.
fn plan_execution(
    owner_read: Option<OwnerPositionRead>,
    arguments: &Value,
    ingest_attempt_id: String,
) -> Result<ExecutionCandidate, Box<eliot_skill::SkillError>> {
    let payload = match canonical_json_bytes(&arguments)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            eliot_agent_bridge_core::SkillExecutionPayload::decode(&bytes)
                .map_err(|error| error.to_string())
        }) {
        Ok(payload) => payload,
        Err(detail) => {
            return Err(Box::new(eliot_skill::SkillError::Surface(format!(
                "execution arguments fail their shape: {detail}"
            ))));
        }
    };
    // The ingest's own identity is the Kernel-admitted `LocalReadAttempt`,
    // which the caller supplies; it is not the Skill's historical attempt and
    // is never taken from a payload field.
    let (read_position, lifecycle_source_revision) = match owner_read {
        Some(OwnerPositionRead::Read(position)) => (Some(position), None),
        Some(OwnerPositionRead::Absent | OwnerPositionRead::Unavailable(_)) | None => (None, None),
    };
    Ok(ExecutionCandidate {
        payload: Box::new(payload),
        read_position,
        lifecycle_source_revision,
        ingest_attempt_id,
    })
}

/// Publishes one execution evidence ingest and returns the explicit bounded
/// assessment over the owner's retained set (issue #2664, I7.25 / I14.21).
///
/// Audit step 6 runs here: the owner is re-read AFTER the publish, and any
/// execution that appeared between the plan's read and the commit is reported
/// in `appeared_after_read_refs`, which forces
/// [`AssessmentDisposition::ResolvedNotAuthorized`] and withholds any stale
/// clearance. Audit step 2 rides the same call: the bounded page is retained
/// by the existing evidence owner under the exact execution identity, where
/// same identity and same bytes replay and changed bytes are a conflict.
///
/// When the owner held no lifecycle view for this Skill at plan time, there
/// is no owner position to reconcile against and no denominator: the
/// assessment is unavailable and is reported as a typed refusal rather than a
/// self-comparison of the submitted page, which could never fail.
fn commit_execution_candidate(
    composition: &DaemonComposition,
    candidate: &ExecutionCandidate,
) -> SkillResultEnvelope {
    let payload = &candidate.payload;
    // The Skill revision/package read position must agree with what the
    // lifecycle owner actually holds, or the page is filed under a substituted
    // identity. `record_execution_evidence` enforces the same binding on the
    // write path; this rejects it before the read.
    if payload.skill_id.trim().is_empty()
        || payload.skill_revision.trim().is_empty()
        || payload.package_digest.len() != 64
    {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::InvalidField {
            field: "execute.skill_revision",
            reason: "execution evidence must name the exact Skill revision and package digest",
        });
    }
    match composition.skill_publish_execution_evidence(payload) {
        // The owner accepted the evidence: the assessment is only reported
        // after the owner took it, so a claim never outruns persistence.
        Ok(_published) => {
            let committed = match read_execution_owner_position(composition, &payload.skill_id) {
                OwnerPositionRead::Read(position) => position,
                OwnerPositionRead::Absent => {
                    return SkillResultEnvelope::refused(&eliot_skill::SkillError::NotFound);
                }
                OwnerPositionRead::Unavailable(detail) => {
                    return SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(
                        format!("execution evidence owner position unavailable: {detail}"),
                    ));
                }
            };
            match build_execution_assessment(candidate, &committed) {
                Ok(assessment) => SkillResultEnvelope::assessment(assessment),
                Err(error) => SkillResultEnvelope::refused(error.as_ref()),
            }
        }
        Err(error) => SkillResultEnvelope::refused(&error),
    }
}

/// Assembles the bounded assessment from the plan's read position and the
/// owner's committed position (issue #2664, AUD4/AUD5/AUD6).
///
/// The result is `None` exactly when the plan had no owner position to read,
/// which is the one case where no honest assessment exists: with no owner
/// record the only "comparison" left would be the page against itself.
fn build_execution_assessment(
    candidate: &ExecutionCandidate,
    committed: &eliot_skill::SkillExecutionOwnerPosition,
) -> Result<eliot_skill::ExecutionReconciliationAssessment, Box<eliot_skill::SkillError>> {
    let Some(read_position) = candidate.read_position.as_deref() else {
        return Err(Box::new(eliot_skill::SkillError::NotFound));
    };
    let mut source_revisions = vec![eliot_skill::SourceRevision {
        source: eliot_skill::SOURCE_EXECUTION_OWNER_SET.to_owned(),
        revision: Some(committed.revision),
    }];
    if let Some(lifecycle) = &candidate.lifecycle_source_revision {
        source_revisions.push(lifecycle.clone());
    }
    let context = eliot_skill::ExecutionAssessmentContext {
        skill_id: candidate.payload.skill_id.clone(),
        skill_revision: candidate.payload.skill_revision.clone(),
        package_digest: candidate.payload.package_digest.clone(),
        ingest_attempt_id: candidate.ingest_attempt_id.clone(),
        source_revisions,
    };
    eliot_skill::assess_execution_reconciliation(
        context,
        &candidate.payload.executions,
        read_position,
        committed,
    )
    .map_err(Box::new)
}

/// Plans one claimed Skill pair, completing canonical acceptance reads without
/// borrowing the daemon composition.
///
/// The caller snapshots `admitted_fence` under a short composition lock and
/// commits the owned plan under a fresh lock after this async function ends.
pub async fn plan_skill_pair(
    kernel: &DaemonKernelClient,
    admitted_fence: StateFence,
    execution_owner_read: Option<OwnerPositionRead>,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> SkillPairPlan {
    let plan = |action| SkillPairPlan {
        envelope_sha256: envelope.envelope_sha256.clone(),
        attempt: attempt.clone(),
        admitted_fence: admitted_fence.clone(),
        action,
    };
    if attempt.validate().is_err()
        || attempt.operation_id != eliot_protocol::host_request_operation_id(envelope)
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || admitted_fence != envelope.state_fence
    {
        return plan(PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::FenceMismatch,
        )));
    }
    let name = tool
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(kind) = skill_tool_kind(name) else {
        return plan(PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::Surface("not a Skill tool request".to_owned()),
        )));
    };
    if name != envelope.identity.capability {
        return plan(PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::Surface(
                "presented tool does not match the admitted capability".to_owned(),
            ),
        )));
    }
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);
    match kind {
        SkillToolKind::Inject => {
            let action = plan_accepted_inject(kernel, admitted_fence.clone(), &arguments).await;
            plan(action)
        }
        SkillToolKind::Display => match decode_display(&arguments) {
            Ok(payload) => plan(PlannedSkillPair::Display(payload)),
            Err(error) => plan(PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
                error.as_ref(),
            ))),
        },
        SkillToolKind::Activate => {
            // Both arms yield a PlannedSkillPair; `plan` binds the claim
            // legs onto whichever one the branch produced.
            let action = match decode_activation(&arguments) {
                Ok(receipt) => {
                    plan_qualified_activation(
                        kernel,
                        admitted_fence.clone(),
                        receipt,
                        attempt.attempt_id.clone(),
                    )
                    .await
                }
                Err(error) => {
                    PlannedSkillPair::Resolved(SkillResultEnvelope::refused(error.as_ref()))
                }
            };
            plan(action)
        }
        SkillToolKind::Execute => {
            // The execute plan consumes the owner read the caller already took
            // under a short composition borrow, so no composition state is
            // borrowed here and the whole attempt is not accumulated.
            match plan_execution(execution_owner_read, &arguments, attempt.attempt_id.clone()) {
                Ok(candidate) => plan(PlannedSkillPair::Execution(Box::new(candidate))),
                Err(error) => plan(PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
                    error.as_ref(),
                ))),
            }
        }
    }
}

/// Resolves one decoded intake through the canonical acceptance verdict without
/// holding the composition lock. An accepted result stays an owned plan until
/// the runtime revalidates its fence and commits it.
///
/// The wire intake entry decodes once here, the presented package digest
/// resolves against the canonical committed lifecycle-policy rows, and the
/// canonical verdict — never the wire procedure stamp — decides the drive. Accepted intakes bind their
/// presented procedure to the committed row and drive the decoded payload
/// plus that owner provenance into the composition; Unknown digests (absent
/// rows, or rows superseded by a newer committed package) refuse: absence
/// of a row proves nothing, so a wire-claimed Accepted stamp with no owner
/// backing cannot bind material, provisional or otherwise — the intake
/// remains a reversible candidate until governed promotion commits a row
/// for it (I7.25).
async fn plan_accepted_inject(
    kernel: &DaemonKernelClient,
    admitted_fence: StateFence,
    arguments: &Value,
) -> PlannedSkillPair {
    let bytes = match canonical_json_bytes(&arguments).map_err(|error| error.to_string()) {
        Ok(bytes) => bytes,
        Err(detail) => {
            return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
                &eliot_skill::SkillError::Surface(format!(
                    "intake arguments fail their shape: {detail}"
                )),
            ));
        }
    };
    let payload = match eliot_agent_bridge_core::SkillIntakePayload::decode(&bytes)
        .map_err(|error| error.to_string())
    {
        Ok(payload) => payload,
        Err(detail) => {
            return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
                &eliot_skill::SkillError::Surface(format!(
                    "intake arguments fail their shape: {detail}"
                )),
            ));
        }
    };
    match super::skill_acceptance_read::resolve_intake_acceptance(
        kernel,
        &admitted_fence,
        &payload.package.registration.skill_id,
        &payload.package.digests.source_digest,
    )
    .await
    {
        Ok(AcceptanceResolution {
            verdict: AcceptanceVerdict::Accepted(record),
            request,
            response,
        }) => {
            if let Err(error) = bind_accepted_intake(&payload, &record) {
                return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(&error));
            }
            let resolution = AcceptanceResolution {
                verdict: AcceptanceVerdict::Accepted(record.clone()),
                request,
                response,
            };
            PlannedSkillPair::AcceptedIntake {
                payload: Box::new(payload),
                record,
                resolution: Box::new(resolution),
            }
        }
        Ok(AcceptanceResolution {
            verdict: AcceptanceVerdict::Unknown,
            ..
        }) => PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::InvalidField {
                field: "procedure.acceptance",
                reason: "no committed lifecycle row backs this package digest at the current revision; the intake remains a reversible candidate until governed promotion",
            },
        )),
        Ok(AcceptanceResolution {
            verdict: AcceptanceVerdict::Revoked(_),
            ..
        }) => PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::InvalidField {
                field: "procedure.acceptance",
                reason: "canonical lifecycle revoked this package revision",
            },
        )),
        Err(error) => PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::Surface(error.to_string()),
        )),
    }
}

/// Publishes one owner-qualified activation candidate under a fresh
/// composition borrow (issue #2663, I7.25 / I12.24).
///
/// Revalidates every load-bearing owner binding before publishing: the plan's
/// reads ran WITHOUT the composition lock, so a Skill row or lifecycle
/// position that moved in between is caught here rather than published from a
/// stale observation. The admission re-validates the receipt against its
/// ORIGINAL recorded value and binds it to the stored view's exact revision
/// and package.
///
/// A candidate whose backing reads were partial, truncated or blocked never
/// publishes a settled claim: it reports the unresolved coverage instead, so
/// absence of evidence is never read as a finding. A candidate that cannot
/// name the ingest it arrived on, or that carries a broken owner revision
/// binding, is refused outright.
fn commit_activation_candidate(
    composition: &mut DaemonComposition,
    candidate: &ActivationCandidate,
) -> SkillResultEnvelope {
    let unpublished = if candidate.ingest_attempt_id.trim().is_empty() {
        Some(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::InvalidField {
                field: "ingest_attempt_id",
                reason: "activation evidence must name the authenticated ingest attempt",
            },
        ))
    } else if candidate
        .source_revisions
        .iter()
        .any(|revision| revision.validate().is_err())
    {
        Some(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::InvalidField {
                field: "source_revisions",
                reason: "activation evidence must bind every load-bearing owner revision to a named source",
            },
        ))
    } else if !candidate.coverage.is_settled() {
        Some(SkillResultEnvelope::attempt(
            eliot_skill::derive_attempt_summary(&candidate.receipt),
        ))
    } else {
        None
    };
    match unpublished {
        Some(outcome) => outcome,
        None => match composition.skill_admit_material_attempt(&candidate.receipt) {
            Ok(_) => {
                // The stage claims come from the admitted summary; usefulness
                // is re-decided here from the owner records the plan actually
                // resolved, never from the admission result and never from the
                // presented string set. The resolved records stay in the
                // private candidate, so a receiver sees the qualified verdict
                // rather than a raw flag.
                SkillResultEnvelope::attempt(candidate.qualified_summary())
            }
            Err(error) => SkillResultEnvelope::refused(&error),
        },
    }
}

pub fn commit_skill_pair(
    composition: &mut DaemonComposition,
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    plan: SkillPairPlan,
) -> HostRequestResultBody {
    let bound_to_current_claim = plan.envelope_sha256 == envelope.envelope_sha256
        && plan.attempt == *attempt
        && plan.admitted_fence == envelope.state_fence
        && attempt.operation_id == eliot_protocol::host_request_operation_id(envelope)
        && attempt.authority_epoch == envelope.state_fence.authority_epoch
        && attempt.expires_at_unix_ms == envelope.identity.deadline_unix_ms;
    let outcome = if bound_to_current_claim {
        match plan.action {
            PlannedSkillPair::Resolved(outcome) => outcome,
            PlannedSkillPair::Display(payload) => {
                if composition.kernel_snapshot().state_fence() == plan.admitted_fence {
                    match composition.skill_carry_receipt_to_display(
                        &payload.skill_id,
                        payload.receipt,
                        payload.ack,
                    ) {
                        Ok(display) => SkillResultEnvelope::display(display),
                        Err(error) => SkillResultEnvelope::refused(&error),
                    }
                } else {
                    SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch)
                }
            }
            PlannedSkillPair::Activation(candidate) => {
                if composition.kernel_snapshot().state_fence() == plan.admitted_fence {
                    commit_activation_candidate(composition, &candidate)
                } else {
                    SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch)
                }
            }
            PlannedSkillPair::Execution(candidate) => {
                // Execute gets the fence recheck it previously lacked: the
                // plan's owner read ran without the composition lock, so the
                // assessment may only be published while the admitted fence
                // still holds.
                if composition.kernel_snapshot().state_fence() == plan.admitted_fence {
                    // This ingest's own attempt identity is a separate leg from
                    // the historical executions being observed; evidence that
                    // cannot name the ingest it arrived on is not a claim about
                    // anything.
                    if candidate.ingest_attempt_id.trim().is_empty() {
                        SkillResultEnvelope::refused(&eliot_skill::SkillError::InvalidField {
                            field: "ingest_attempt_id",
                            reason: "execution evidence must name the authenticated ingest attempt",
                        })
                    } else {
                        commit_execution_candidate(composition, &candidate)
                    }
                } else {
                    SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch)
                }
            }
            PlannedSkillPair::AcceptedIntake {
                payload,
                record,
                resolution,
            } => {
                // The commit step is also where the daemon-held Governor
                // capability admission view is hydrated (issue #1957, I3.4):
                // the same canonical `GetCapabilityEvidenceState` response that
                // decided this intake is applied to the held registry, so the
                // admission view stops being permanently empty. A hydration
                // failure is a `warn` diagnostic naming the exact reason, never
                // a silent pass and never a rewritten verdict — the held view
                // keeps its previous contents, and a production route that
                // view cannot evidence stays refused, because `declared` /
                // `imported_legacy` records never admit.
                if composition.kernel_snapshot().state_fence() == plan.admitted_fence {
                    let hydration = composition
                        .capability_admission_mut()
                        .map_err(|error| error.to_string())
                        .and_then(|view| {
                            view.hydrate_from_evidence_response(
                                &resolution.request,
                                &resolution.response,
                            )
                            .map_err(|error| error.to_string())
                        });
                    match hydration {
                        Ok(hydrated) => {
                            tracing::info!(
                                target: "eliotd::capability_evidence",
                                event = "eliotd.capability_evidence_hydrated",
                                skill_id = %hydrated.summary.skill_id,
                                matched_lifecycle_rows = hydrated.summary.matched_total,
                                declared_records = hydrated.declared_records,
                                retained_records = hydrated.retained,
                            );
                        }
                        Err(reason) => {
                            tracing::warn!(
                                target: "eliotd::capability_evidence",
                                event = "eliotd.capability_evidence_hydration_unavailable",
                                skill_id = %record.skill_id,
                                reason = %reason,
                                "canonical capability evidence did not refresh the admission view; the held view keeps its previous contents and any production route it cannot evidence stays refused"
                            );
                        }
                    }
                    match composition.skill_ingest_accepted_intake(&payload, &record) {
                        Ok((_, receipt)) => SkillResultEnvelope::receipt(receipt),
                        Err(error) => SkillResultEnvelope::refused(&error),
                    }
                } else {
                    SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch)
                }
            }
        }
    } else {
        SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch)
    };
    skill_result_body(envelope, attempt, &outcome)
        .unwrap_or_else(|error| skill_refusal_body(envelope, attempt, &error.to_string()))
}

/// Binds one presented wire intake to its canonical committed acceptance row.
///
/// Payload-level consistency for the Accepted drive: the presented skill and
/// package must be exactly the row's skill and accepted package digest, the
/// presented procedure verifier must name the row's accepting verifier, and
/// the presented procedure stamp must agree with the row's acceptance. Every
/// check is consistency with owner state, never authority from the wire —
/// the row decides acceptance, and the candidate-level binding (stamped
/// material, receipt verifier, fence, scope, task) runs inside the
/// composition rehydration against the same row.
///
/// The crate error travels by value here like the Governor lifecycle API it
/// feeds, so the size lint is allowed for this boundary function.
#[allow(clippy::result_large_err)]
fn bind_accepted_intake(
    payload: &eliot_agent_bridge_core::SkillIntakePayload,
    record: &super::skill_acceptance_read::AcceptanceRecord,
) -> Result<(), eliot_skill::SkillError> {
    if payload.package.registration.skill_id != record.skill_id {
        return Err(eliot_skill::SkillError::IdentityMismatch);
    }
    if payload.package.digests.source_digest != record.package_digest {
        return Err(eliot_skill::SkillError::IdentityMismatch);
    }
    if payload.candidate.procedure.verifier.verifier_ref != record.verifier_ref {
        return Err(eliot_skill::SkillError::InvalidField {
            field: "candidate.procedure.verifier",
            reason: "procedure verifier is not the canonically accepting verifier",
        });
    }
    if !matches!(
        payload.candidate.procedure.state,
        eliot_skill::ProcedureState::Accepted
    ) {
        return Err(eliot_skill::SkillError::InvalidField {
            field: "candidate.procedure.state",
            reason: "committed row accepts this package but the presented procedure disagrees",
        });
    }
    Ok(())
}

/// Decodes one harness activation receipt for admission at the live owner.
///
/// The wire receipt is validated on decode (eligibility↔retrieval,
/// delivery↔retrieval, activation↔delivery, adherence↔activation bindings);
/// the fold keeps delivered, retrieved, activated and adhered distinct, so a
/// packet-included but never activated Skill is never marked successful.
/// Decoding alone cannot admit Material use: the commit leg checks the live
/// catalogue and Governor standing before returning an attempt summary, and
/// usefulness is resolved separately against owner records
/// ([`plan_qualified_activation`]).
fn decode_activation(
    arguments: &Value,
) -> Result<eliot_skill::SkillHarnessActivationReceipt, Box<eliot_skill::SkillError>> {
    let payload = match canonical_json_bytes(&arguments)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            eliot_agent_bridge_core::SkillActivationPayload::decode(&bytes)
                .map_err(|error| error.to_string())
        }) {
        Ok(payload) => payload,
        Err(detail) => {
            return Err(Box::new(eliot_skill::SkillError::Surface(format!(
                "activation arguments fail their shape: {detail}"
            ))));
        }
    };
    Ok(payload.receipt)
}

/// Qualifies one decoded activation receipt against real owner records
/// without holding the composition lock (issue #2663, I7.25 / I12.24).
///
/// Three identities stay distinct here and are never interchanged: this
/// ingest's authenticated `LocalReadAttempt`, the receipt's historical
/// `attempt_ref`, and the Kernel `operation_id`. The receipt is a *candidate*
/// until the owner reads below bind it:
///
/// 1. the Skill owner (`GetCapabilityEvidenceState`, exact `skill_id`,
///    `ExactFence`) resolves whether the subject Skill identity currently has
///    a committed lifecycle row — the Skill revision/package binding. An
///    unresolved Skill leaves the candidate unqualified, never positively
///    useful and never negatively so;
/// 2. the evidence owner (`GetLearningRecordRange`, closed
///    `activation_receipt` kind, `ExactFence`) is read for the durable
///    activation-receipt rows, and the receipt's presented
///    `verified_outcome_refs` are resolved by CONTENT against those rows.
///
/// The result is a private plan: nothing is published here, and no
/// composition state is borrowed. A refused or failed read is an error the
/// caller turns into a typed refusal — never a silent pass.
async fn plan_qualified_activation(
    kernel: &DaemonKernelClient,
    admitted_fence: StateFence,
    receipt: eliot_skill::SkillHarnessActivationReceipt,
    ingest_attempt_id: String,
) -> PlannedSkillPair {
    // 1. Skill-owner read: does a committed lifecycle row back this Skill at
    //    the current revision? This binds the Skill revision/package, nothing
    //    more — it is not a substitute for historical execution evidence.
    let acceptance = match super::skill_acceptance_read::resolve_intake_acceptance(
        kernel,
        &admitted_fence,
        &receipt.skill_id,
        &receipt.package_digest,
    )
    .await
    {
        Ok(resolution) => resolution,
        Err(error) => {
            return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
                &eliot_skill::SkillError::Surface(error.to_string()),
            ));
        }
    };
    let subject =
        super::skill_evidence_read::subject_binding_from_acceptance(&acceptance, &receipt.skill_id);
    let super::skill_evidence_read::SubjectBinding::Resolved { revisions, .. } = subject else {
        // No committed row binds this Skill. Absence of a row proves nothing:
        // the candidate stays unqualified and is reported as such, never as a
        // positive usefulness claim and never as a revocation.
        return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::InvalidField {
                field: "receipt.skill_id",
                reason: "no committed lifecycle row backs this Skill at the current revision; the activation candidate remains unqualified",
            },
        ));
    };

    // 2. Evidence-owner read: resolve the presented outcome references against
    //    durable owner records. There is no activated verifier-run producer
    //    today, so this legitimately resolves nothing and usefulness stays
    //    unestablished — the honest state, not a success port.
    let (rows, coverage) = match super::skill_evidence_read::read_evidence_owner_records(
        kernel,
        &admitted_fence,
        eliot_store_api::LearningRecordKind::ActivationReceipt,
    )
    .await
    {
        Ok(records) => records,
        Err(error) => {
            return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
                &eliot_skill::SkillError::Surface(error.to_string()),
            ));
        }
    };
    let resolved_outcomes =
        match super::skill_evidence_read::resolve_outcome_records(&receipt, &rows) {
            super::skill_evidence_read::OutcomeResolution::Resolved { records } => records,
            super::skill_evidence_read::OutcomeResolution::NoOwnerRecord => Vec::new(),
        };
    let mut source_revisions = revisions;
    source_revisions.push(super::skill_evidence_read::activation_receipt_revision());
    PlannedSkillPair::Activation(ActivationCandidate {
        receipt: Box::new(receipt),
        ingest_attempt_id,
        source_revisions,
        resolved_outcomes,
        coverage,
    })
}

fn decode_display(
    arguments: &Value,
) -> Result<eliot_agent_bridge_core::SkillDisplayPayload, Box<eliot_skill::SkillError>> {
    let payload = match canonical_json_bytes(&arguments)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            eliot_agent_bridge_core::SkillDisplayPayload::decode(&bytes)
                .map_err(|error| error.to_string())
        }) {
        Ok(payload) => payload,
        Err(detail) => {
            return Err(Box::new(eliot_skill::SkillError::Surface(format!(
                "display arguments fail their shape: {detail}"
            ))));
        }
    };
    Ok(payload)
}

/// Binds one skill outcome into the submit-leg result body.
pub fn skill_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    outcome: &SkillResultEnvelope,
) -> Result<HostRequestResultBody, SkillDispatchError> {
    let response = serde_json::to_value(outcome)
        .map_err(|error| SkillDispatchError::Body(error.to_string()))?;
    if !response.is_object() {
        return Err(SkillDispatchError::Body(
            "skill outcome must encode as a JSON object".to_owned(),
        ));
    }
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| SkillDispatchError::Body(error.to_string()))?;
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(&bytes),
        response,
        attempt: Some(attempt.clone()),
        lineage: None,
    };
    body.validate()
        .map_err(|error| SkillDispatchError::Body(error.to_string()))?;
    Ok(body)
}

fn skill_refusal_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    detail: &str,
) -> HostRequestResultBody {
    // Last-resort body for local construction failures: fixed shape, bounded
    // detail, same digest binding. Infallible by construction for validated
    // inputs; a failure here would already have failed closed above.
    let response = serde_json::json!({
        "contract_version": eliot_agent_bridge_core::SKILL_TRANSPORT_VERSION,
        "outcome": {
            "Refused": {
                "code": "SURFACE",
                "detail": detail.chars().take(512).collect::<String>(),
            }
        }
    });
    let outcome = SkillResultEnvelope {
        contract_version: eliot_agent_bridge_core::SKILL_TRANSPORT_VERSION,
        outcome: eliot_agent_bridge_core::SkillResultOutcome::Refused {
            code: "SURFACE".to_owned(),
            detail: detail.chars().take(512).collect::<String>(),
        },
    };
    skill_result_body(envelope, attempt, &outcome).unwrap_or_else(|_| HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(response.to_string().as_bytes()),
        response,
        attempt: Some(attempt.clone()),
        lineage: None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};

    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestIdentity, HostRequestKind, host_request_operation_id,
    };

    fn fence() -> eliot_contracts::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        StateFence::new(
            EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("valid test epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn envelope() -> HostRequestEnvelope {
        HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-1").expect("request id"),
                correlation_projection: None,
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: "skill.inject".to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: eliot_agent_bridge_core::SKILL_TRANSPORT_CONTRACT_ID.to_owned(),
                payload_sha256: "d".repeat(64),
            },
            state_fence: fence(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("envelope digest")
    }

    fn attempt(envelope: &HostRequestEnvelope) -> LocalReadAttempt {
        let operation_id = host_request_operation_id(envelope);
        LocalReadAttempt {
            wire_id: eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            operation_id: operation_id.clone(),
            attempt_id: format!("{operation_id}:attempt:test-boot:7:1"),
            fencing_generation: 1,
            session_id: "kernel-session-1".to_owned(),
            authority_epoch: envelope.state_fence.authority_epoch.clone(),
            scope_id: "kernel-session-1".to_owned(),
            facet_method: "skill.inject".to_owned(),
            expires_at_unix_ms: envelope.identity.deadline_unix_ms,
            use_budget: 1,
        }
    }

    #[test]
    fn result_body_binds_operation_request_response_and_attempt() {
        let envelope = envelope();
        let attempt = attempt(&envelope);
        let outcome = SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch);
        let body = skill_result_body(&envelope, &attempt, &outcome).expect("result body builds");
        body.validate().expect("result body validates");
        assert_eq!(body.operation_id, attempt.operation_id);
        assert_eq!(body.request_sha256, envelope.envelope_sha256);
        let echoed = body.attempt.expect("attempt echoed");
        assert_eq!(echoed.attempt_id, attempt.attempt_id);
        assert_eq!(echoed.fencing_generation, attempt.fencing_generation);
    }
}
