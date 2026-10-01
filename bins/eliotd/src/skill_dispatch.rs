//! Skill pair dispatch for the daemon local-read poller (issue #1882).
//!
//! Serves claimed pairs whose tool name routes to a Skill kind (see
//! [`skill_tool_kind`](eliot_agent_bridge_core::skill_transport::skill_tool_kind))
//! locally through the composition-held Skill driver instead of forwarding
//! them on the Kernel `local_read` leg (which serves store reads only).
//! Intake pairs decode to the wire intake, resolve canonical procedure
//! acceptance over the authenticated Kernel route, and drive install→receipt
//! only for owner-accepted material (issue #1191); display pairs decode to
//! the wire display request and drive sweep→ack→display; activation pairs decode to
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
use eliot_store_api::{NamedReadRequest, NamedReadResponse, ScopeId};
use serde_json::Value;
use thiserror::Error;

use super::DaemonComposition;
use super::capability_evidence_wiring::GovernorCapabilityAdmission;
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
        /// The durable capability-evidence RECORD read for the same Skill at
        /// the same fence, retained for the same reason
        /// ([`CapabilityRecordRead`]).
        capability_records: CapabilityRecordRead,
    },
}

/// Outcome of the plan's durable capability-evidence RECORD read for one
/// Skill (issue #1957, I3.4, acceptance A2/A3).
///
/// This leg is distinct from the intake's own `AcceptanceResolution` and both
/// travel through the same plan. The distinction is load-bearing and is the
/// reason the daemon can act on A2 at all:
///
/// * `GetCapabilityEvidenceState` answers committed `ApplyLifecyclePolicy`
///   governance rows. The measured payload carries exactly the six declared
///   lifecycle parameters (`action`, `base_view_digest`, `candidate_digest`,
///   `candidate_package_digest`, `skill_id`, `verifier_ref`) plus
///   `capture_index`, so it exposes NO capability status, NO evidence source
///   and NO route-scope fingerprint. It can only ever mint a non-admitting
///   `declared` / `imported_legacy_declaration` record.
/// * `GetCapabilityEvidenceRecordRange` answers the durable evidence rows
///   themselves, with their owner-issued `record_digest` and the store-issued
///   `revision` the fenced compare-and-set assigned. That is the only leg that
///   can mint a real `probe_passed` / `observed` / `broken` record, and
///   therefore the only leg on which A2's admitting half and A3's staleness
///   can be observed at all.
///
/// `Unavailable` is the honest unresolved case: the reason is named at the
/// commit step and the held view keeps its previous contents, so a production
/// route the view cannot evidence stays refused rather than being read as
/// "nothing to check".
pub enum CapabilityRecordRead {
    /// The store served this page of real evidence rows for the Skill.
    Served(Box<NamedReadRequest>, Box<NamedReadResponse>),
    /// The read did not answer, or the store served a page this bridge cannot
    /// decode. The exact reason is reported; nothing is inferred.
    Unavailable(String),
}

/// What the bounded evidence-owner activation-receipt read established about
/// one presented receipt's subject identity AND the stage content that read
/// binds (issue #2663, audit 5856960648).
///
/// The rows come from the existing finite named read
/// (`GetLearningRecordRange`, closed `activation_receipt` kind); the verdict
/// below only compares the presented subject legs against those served owner
/// documents by content. It never invents a record and never treats the
/// receipt's own shape as provenance. On an owner-bound subject the bound
/// owner row travels with the verdict, so the commit publishes the OWNER's
/// stage content rather than the receipt's self-declared stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationSubject {
    /// An owner row binds this exact subject: same Skill identity, same
    /// subject attempt, same route, same packet digest/position, same fence.
    OwnerBound,
    /// An owner row names this Skill and subject attempt but contradicts at
    /// least one presented subject leg: a foreign or substituted record under
    /// a real identity, never a silent pass.
    Contradicted,
    /// No owner row names this subject. Unresolved absence of evidence: never
    /// a negative fact, and on its own never a positive claim either.
    Unresolved,
}

/// Resolves one presented receipt's subject identity against the served
/// evidence-owner activation-receipt rows by content, carrying the bound row.
///
/// A row can name a subject only when it carries the owner projection shape
/// (`record_kind`, `handle`, `record_json`, `record_digest`) and its document
/// decodes to a self-validating harness receipt. A row naming this Skill and
/// subject attempt must then agree on every subject leg (Skill
/// revision/package, route, packet digest/position, fence); anything else is a
/// contradiction under a real identity. Rows of any other record shape —
/// including execution-evidence documents sharing the same closed kind — are
/// skipped, never half-parsed.
///
/// The bound row's own stage content is what the commit may publish: the six
/// matched legs authenticate the subject, and the row's eligibility,
/// retrieval, delivery, activation and adherence stages corroborate (or refuse)
/// the presented claim. A subject no row names carries no bound row and stays
/// refused as unqualified.
struct SubjectResolution {
    subject: ActivationSubject,
    bound: Option<Box<eliot_skill::SkillHarnessActivationReceipt>>,
}

fn resolve_activation_subject(
    receipt: &eliot_skill::SkillHarnessActivationReceipt,
    rows: &[Value],
) -> SubjectResolution {
    let mut contradicted = false;
    for row in rows {
        if row
            .get("record_kind")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || row
                .get("record_digest")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || row
                .get("handle")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            continue;
        }
        let Some(document) = row.get("record_json") else {
            continue;
        };
        let Ok(record) =
            serde_json::from_value::<eliot_skill::SkillHarnessActivationReceipt>(document.clone())
        else {
            continue;
        };
        if record.validate().is_err() {
            continue;
        }
        if record.skill_id != receipt.skill_id || record.attempt_ref != receipt.attempt_ref {
            continue;
        }
        if record.skill_revision == receipt.skill_revision
            && record.package_digest == receipt.package_digest
            && record.route_ref == receipt.route_ref
            && record.packet_digest == receipt.packet_digest
            && record.packet_position == receipt.packet_position
            && record.state_fence == receipt.state_fence
        {
            return SubjectResolution {
                subject: ActivationSubject::OwnerBound,
                bound: Some(Box::new(record)),
            };
        }
        contradicted = true;
    }
    SubjectResolution {
        subject: if contradicted {
            ActivationSubject::Contradicted
        } else {
            ActivationSubject::Unresolved
        },
        bound: None,
    }
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
    /// What the evidence-owner activation-receipt rows said about the
    /// presented subject identity: owner-bound, contradicted, or unresolved.
    /// The commit leg rechecks the lifecycle-owner view before publishing, so
    /// a subject the rows contradict can never become a qualified claim — and
    /// a subject no row names is refused as unqualified rather than published
    /// from the receipt's own shape.
    subject: ActivationSubject,
    /// The owner row that bound the subject, when one did. The published
    /// stage claims are folded from THIS row's stages, never from the
    /// presented receipt's self-declared stages: a positive stage the bound
    /// row does not corroborate is refused as unqualified (issue #2663, C3).
    /// `None` unless `subject` is `OwnerBound`.
    bound_subject: Option<Box<eliot_skill::SkillHarnessActivationReceipt>>,
}

impl ActivationCandidate {
    /// Owner-qualified summary for this attempt: the BOUND owner row's stage
    /// claims, with usefulness resolved only from `resolved_outcomes`.
    ///
    /// Folding the bound row keeps every published stage corroborated by the
    /// owner record that named the subject. The `None` arm is fail-closed and
    /// unreachable past the commit's subject checks: with no bound row there
    /// is no corroborated stage to publish, so every stage stays negative and
    /// usefulness stays unknown.
    fn qualified_summary(&self) -> eliot_skill::AttemptLifecycleSummary {
        match &self.bound_subject {
            Some(bound) => eliot_skill::qualify_useful_outcomes(bound, &self.resolved_outcomes),
            None => eliot_skill::AttemptLifecycleSummary {
                delivered: false,
                retrieved: false,
                activated: false,
                adhered: eliot_skill::SkillAdherenceStatus::Unknown,
                useful: eliot_skill::SkillUsefulness::Unknown,
            },
        }
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
    /// Retained-history binding for the presented package digest, resolved by
    /// the plan from committed lifecycle-policy rows (issue #2663, AC2). `Some`
    /// exactly when a committed accept-row holds the presented digest — current
    /// or superseded. The commit files a superseded observation as history
    /// through this binding; without it a non-current revision stays refused.
    historical_binding: Option<super::skill_evidence_read::HistoricalPackageBinding>,
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

/// Reads the lifecycle owner's stored view for one subject Skill without
/// holding the daemon composition mutex across the read.
///
/// Borrowed directly from the composition for the duration of the single
/// non-awaiting lookup, exactly like [`read_execution_owner_position`]: the
/// caller takes it under a short borrow and drops the borrow before any
/// canonical I/O. `None` means the owner holds no view for this Skill —
/// absence of a row, never an empty-but-complete record.
fn read_activation_owner_view(
    composition: &DaemonComposition,
    skill_id: &str,
) -> Option<eliot_skill::SkillLifecycleView> {
    composition.skill_lifecycle_owner().view(skill_id).cloned()
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

/// Resolves the retained-history binding for one presented execution-evidence
/// digest, without the composition lock (issue #2663, AC2).
///
/// The read is the SAME closed acceptance read the activation leg uses
/// (`GetCapabilityEvidenceState`, exact `skill_id`, `ExactFence`); only the
/// question differs. Intake asks currency ("does the LATEST row bind this
/// digest?"); history asks admission ("does ANY committed accept-row hold this
/// digest?"). A superseded-but-committed row is exactly the explicit permitted
/// historical binding a current collector reports an older attempt through —
/// resolved from retained rows, never reconstructed from payload fields.
/// `None` means no retained row holds the digest (substituted package), the
/// payload failed its shape (reported by the plan), or the read itself
/// failed: the current path is unaffected either way, and the historical path
/// stays refused at the seam. The plan never decides from this binding; it
/// only carries it for the commit.
async fn plan_execution_historical_binding(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
    arguments: &Value,
) -> Option<super::skill_evidence_read::HistoricalPackageBinding> {
    let payload = canonical_json_bytes(arguments)
        .ok()
        .and_then(|bytes| eliot_agent_bridge_core::SkillExecutionPayload::decode(&bytes).ok())?;
    let resolution = super::skill_acceptance_read::resolve_intake_acceptance(
        kernel,
        admitted_fence,
        &payload.skill_id,
        &payload.package_digest,
    )
    .await
    .ok()?;
    super::skill_evidence_read::historical_binding_from_acceptance(
        &resolution,
        &payload.skill_id,
        &payload.package_digest,
    )
}

/// Plans one execution-evidence ingest into a bounded assessment over the
/// owner-retained attempt-wide set (issue #2664).
///
/// Every presented record is validated and deduplicated by exact evidence
/// identity, and the reconciliation reads the OWNER-retained set the caller
/// passed in — never the page — so a bounded window without an `Uncertain` row
/// is no longer read as proof that nothing is unresolved. The owner read
/// happens under the caller's short composition borrow; nothing here holds
/// composition state or accumulates the attempt. The retained-history binding
/// travels untouched for the commit: a superseded observation is filed as
/// history only through that binding, never by revision-string comparison.
fn plan_execution(
    owner_read: Option<OwnerPositionRead>,
    arguments: &Value,
    ingest_attempt_id: String,
    historical_binding: Option<super::skill_evidence_read::HistoricalPackageBinding>,
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
        historical_binding,
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
    composition: &mut DaemonComposition,
    candidate: &ExecutionCandidate,
) -> SkillResultEnvelope {
    let payload = &candidate.payload;
    // The Skill revision/package read position must agree with what the
    // lifecycle owner actually holds, or the page is filed under a substituted
    // identity. `record_execution_evidence` enforces the same binding on the
    // write path; this rejects malformed identities before the read. A
    // superseded-but-committed observation is NOT rejected here: it travels
    // with the plan-resolved retained-history binding and the seam files it
    // as a linked historical revision that can never reactivate the Skill
    // (issue #2663, AC2).
    if payload.skill_id.trim().is_empty()
        || payload.skill_revision.trim().is_empty()
        || payload.package_digest.len() != 64
    {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::InvalidField {
            field: "execute.skill_revision",
            reason: "execution evidence must name the exact Skill revision and package digest",
        });
    }
    match composition.skill_publish_execution_evidence(
        payload,
        &candidate.ingest_attempt_id,
        candidate.historical_binding.as_ref(),
    ) {
        // The owner accepted the evidence: the assessment is only reported
        // after the owner took it, so a claim never outruns persistence. The
        // returned view IS the owner's result — the commit must observe it,
        // not discard it — and the owner is then re-read to prove the result
        // survived: a re-read that lost the published ingest refuses instead
        // of yielding a qualified positive summary.
        Ok(published) => {
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
            // The retention proof compares recorded content, not the whole
            // stored row: the owner stamps each retained record with the
            // filing binding (Skill, ingest attempt, fence) at record time,
            // which the presented wire window never carries. Content mismatch
            // under a retained identity already failed at publish with a
            // typed conflict, so a missing identity here means the owner lost
            // the ingest.
            if committed.revision < published.lifecycle_revision
                || payload.executions.iter().any(|presented| {
                    !committed
                        .retained
                        .iter()
                        .any(|held| held.same_recorded_content(presented))
                })
            {
                return SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(
                    "execution evidence owner did not retain the published ingest; the assessment stays unqualified"
                        .to_owned(),
                ));
            }
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
            // borrowed here and the whole attempt is not accumulated. The
            // retained-history binding resolves on the same terms: outside the
            // lock, from retained committed rows, so a superseded observation
            // can stay historical instead of being refused for not matching
            // the current revision (issue #2663, AC2).
            let historical =
                plan_execution_historical_binding(kernel, &admitted_fence, &arguments).await;
            match plan_execution(
                execution_owner_read,
                &arguments,
                attempt.attempt_id.clone(),
                historical,
            ) {
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
            // #1957 I3.4 (A2/A3): the durable capability-evidence RECORD read
            // for the SAME Skill at the SAME fence travels with the plan. The
            // acceptance response above can only mint a non-admitting
            // `declared` record; this one is the leg that can mint a real
            // `probe_passed` / `observed` / `broken` record, which is what makes
            // the admitting half of A2 and the staleness property of A3
            // observable in a running daemon instead of only after a restart.
            //
            // It is read HERE, without the composition lock, alongside the
            // acceptance read that already ran without it; the commit step
            // applies it under the fresh guard after rechecking the fence.
            let capability_records = read_capability_evidence_records(
                kernel,
                &admitted_fence,
                &payload.package.registration.skill_id,
            )
            .await;
            PlannedSkillPair::AcceptedIntake {
                payload: Box::new(payload),
                record,
                resolution: Box::new(resolution),
                capability_records,
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

/// Reads the durable capability-evidence records held for one Skill at the
/// admitted fence (issue #1957, I3.4, acceptance A2/A3).
///
/// This is the leg that makes A2 observable. The intake's own acceptance read
/// answers `ApplyLifecyclePolicy` governance rows, which expose no capability
/// status, source, or route-scope fingerprint, so hydration through it can only
/// ever add a non-admitting `declared` record. `GetCapabilityEvidenceRecordRange`
/// is the read that serves the durable evidence rows themselves — the verbatim
/// `CapabilityEvidenceRecord` document, the owner-issued `record_digest` of
/// those bytes, and the store-issued `revision` the fenced compare-and-set
/// assigned — so it is the only leg that can mint a real `probe_passed`,
/// `observed`, or `broken` record and make the admission decision in
/// [`CapabilityRegistry::admit_production_route`](eliot_governor::CapabilityRegistry::admit_production_route)
/// answer differently.
///
/// The read is planned and executed under the SAME admitted fence as the intake
/// it travels with, and the exact request/response pair is carried into the
/// plan so the commit step re-proves it against the response rather than
/// re-deriving a value over what it holds. A refusal is the honest
/// `Unavailable` case, never a silent pass: the held view keeps its previous
/// contents and a production route it cannot evidence stays refused.
///
/// The Governor scope is the same `governor` scope the durable rows are
/// committed under and the same scope the startup drain reads
/// ([`drain_capability_evidence_records`](super::capability_evidence_wiring::drain_capability_evidence_records)),
/// so a row committed by one leg is visible to the other.
async fn read_capability_evidence_records(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
    skill_id: &str,
) -> CapabilityRecordRead {
    let scope = match ScopeId::new(eliot_governor::GOVERNOR_SCOPE_ID) {
        Ok(scope) => scope,
        Err(error) => return CapabilityRecordRead::Unavailable(error.to_string()),
    };
    let request = match GovernorCapabilityAdmission::plan_evidence_record_read(
        Some(skill_id),
        eliot_store_api::MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS,
        None,
        scope,
        admitted_fence.clone(),
    ) {
        Ok(request) => request,
        Err(error) => return CapabilityRecordRead::Unavailable(error.to_string()),
    };
    match kernel.store_named_async(request.clone()).await {
        Ok(response) => CapabilityRecordRead::Served(Box::new(request), Box::new(response)),
        Err(error) => CapabilityRecordRead::Unavailable(error.to_string()),
    }
}

/// Publishes one owner-qualified activation candidate under a fresh
/// composition borrow (issue #2663, I7.25 / I12.24).
///
/// Revalidates every load-bearing owner binding before publishing: the plan's
/// reads ran WITHOUT the composition lock, so a Skill row or lifecycle
/// position that moved in between is caught here rather than published from a
/// stale observation. The subject legs are resolved against owner records,
/// never against the receipt's own shape: the evidence-owner rows the plan
/// read contradict a foreign or substituted subject outright, and the
/// lifecycle owner's stored view binds the fence and the route, and its own
/// staleness standing is enforced before either is read: a stale or
/// quarantined view refuses here (issue #1882 W2/A2, I7.13), so a Skill
/// whose declared dependencies changed cannot reach Material use through a
/// stored-status lag. A candidate
/// whose backing reads never settled, whose subject the owner rows
/// contradict, whose subject NO owner row names, or whose retained receipt
/// contradicts the presented bytes never publishes a settled claim: loss of a
/// required read, a contradicted subject, or an unbound subject refuses
/// instead of yielding a positive summary. A subject no owner row names stays
/// unresolved — never a negative fact — and is refused as unqualified rather
/// than published from the receipt's self-declared stages. The admission
/// re-validates the receipt's shape and binds it to the stored view's exact
/// revision and package; admission itself retains no activation receipt, so
/// cross-ingest activation replay awaits the lifecycle-owner write item 5
/// requires (the execution leg already enforces it through the owner).
///
/// A candidate that cannot name the ingest it arrived on, or that carries a
/// broken owner revision binding, is refused outright.
fn commit_activation_candidate(
    composition: &mut DaemonComposition,
    candidate: &ActivationCandidate,
) -> SkillResultEnvelope {
    let unpublished = if let Err(error) = candidate.receipt.validate() {
        // Bridge validation leg (issue #1882 W2, I7.13): the presented
        // receipt is shape-validated before any of its fields is compared
        // below or admitted for Material use, mirroring the owner
        // admission's own receipt check — an unvalidated receipt cannot
        // reach the fence/route/retained-row legs on a stored-status pass.
        Some(SkillResultEnvelope::refused(&error))
    } else if let Some(error) = candidate
        .bound_subject
        .as_deref()
        .and_then(|bound| bound.validate().err())
    {
        // Owner-row validation leg (issue #1882 W2, I7.13): the published
        // stages are folded from the BOUND owner row, never from the
        // presented receipt's self-declared stages, so the row is re-proved
        // here under the commit's fresh borrow like every other load-bearing
        // binding — an unvalidated owner row cannot reach Material use
        // through a plan-time pass.
        Some(SkillResultEnvelope::refused(&error))
    } else if candidate.ingest_attempt_id.trim().is_empty() {
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
        // Loss of a required read cannot yield a qualified positive summary:
        // an unsettled backing read refuses instead of publishing the
        // receipt's self-declared stages as a finding.
        Some(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::Surface(format!(
                "activation backing reads did not settle ({:?}); the candidate remains unqualified",
                candidate.coverage
            )),
        ))
    } else if candidate.subject == ActivationSubject::Contradicted {
        // The evidence owner names this Skill and subject attempt but
        // contradicts a presented subject leg: a foreign or substituted record
        // under a real identity can never become a qualified claim.
        Some(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::RevisionConflict,
        ))
    } else if candidate.subject == ActivationSubject::Unresolved {
        // No owner row binds this subject attempt, route, packet or fence:
        // the receipt's self-declared stages cannot become a qualified
        // positive claim. This is absence of backing, never a negative fact
        // about the Skill — a foreign attempt and a merely-unrecorded one
        // refuse identically until a durable owner record names the subject
        // (issue #2663, AC1/AUD1; audit 5856960648 repair 3).
        Some(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::Surface(
                "no owner row binds this activation subject attempt, route, packet or fence; the candidate remains unqualified"
                    .to_owned(),
            ),
        ))
    } else if candidate.subject == ActivationSubject::OwnerBound
        && candidate.bound_subject.is_none()
    {
        // The subject verdict claims an owner binding but carries no bound
        // row to corroborate the stages: with nothing owner-backed to fold,
        // no stage may publish. This arm is unreachable when the plan binds
        // both together, and it refuses rather than falling back to the
        // receipt's self-declared stages.
        Some(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::Surface(
                "owner-bound activation subject lost its bound owner row; the candidate remains unqualified"
                    .to_owned(),
            ),
        ))
    } else {
        None
    };
    if let Some(outcome) = unpublished {
        return outcome;
    }
    // Subject legs against the lifecycle owner's stored view, under this
    // fresh borrow: the view binds the Skill identity, the task scope, the
    // route and the fence the owner actually retains. A receipt naming a
    // foreign fence or a route the owner never bound the Skill to is refused
    // here even though its shape validates.
    let Some(view) = read_activation_owner_view(composition, &candidate.receipt.skill_id) else {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::NotFound);
    };
    // Bridge Material-use staleness leg (issue #1882 W2/A2, I7.13): the
    // commit binds the SAME stored view every leg below reads, so the view
    // is revalidated as observed before any of its fields is trusted, and a
    // stale or quarantined standing refuses here. A Skill whose declared
    // host/tool/contract dependencies changed stays blocked from Material
    // use through this commit plus the owner admission below: this leg
    // refuses stale/quarantined standing on the observed view, and the
    // admission re-checks live dep staleness even when the catalogue entry
    // itself has not been remarked yet; only revalidation or explicit
    // scoped/provisional admission through the governed lifecycle path
    // lifts the standing. STITCH (issue #1882 W2/A2): the full-world sweep
    // — live dependency-set feed, host/profile versions, admitted
    // definition version, tool-owner view
    // (`gate_material_use_against` over `LiveSkillWorld`) — has no producer
    // at this commit and is never synthesized here; the designated driver is
    // the owning crate's per-caller gate once a live-world feed reaches the
    // bridge. The owner admits the same
    // standing again at admission time; this leg keeps the commit's fence,
    // route and retained-receipt legs consistent on one observation instead
    // of trusting fields of an unvalidated or stale record.
    if let Err(error) = view.validate() {
        return SkillResultEnvelope::refused(&error);
    }
    if !eliot_skill::material_use_allowed(view.status) {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::InvalidField {
            field: "view.status",
            reason: "stale or quarantined Skills are blocked from Material use until governed review or restore",
        });
    }
    if candidate.receipt.state_fence != view.state_fence {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch);
    }
    if candidate.receipt.route_ref != view.scope.route {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::IdentityMismatch);
    }
    for held in &view.attempt_receipts {
        // A retained row under this receipt or attempt identity must agree
        // byte-for-byte with the candidate: a changed record under a retained
        // identity is a conflict, never a rewrite. Admission retains no
        // activation receipt itself, so this fires only where the owner
        // already holds rows; it never invents a conflict.
        if (held.receipt_id == candidate.receipt.receipt_id
            || held.attempt_ref == candidate.receipt.attempt_ref)
            && *held != *candidate.receipt
        {
            return SkillResultEnvelope::refused(&eliot_skill::SkillError::RevisionConflict);
        }
    }
    match composition.skill_admit_material_attempt(&candidate.receipt) {
        Ok(_) => {
            // The stage claims come from the BOUND owner row's admitted
            // summary; usefulness is re-decided here from the owner records
            // the plan actually resolved, never from the admission result and
            // never from the presented string set. The presented receipt's
            // self-declared stages never reach the published claim: a
            // positive stage the bound row does not corroborate stays
            // unqualified. The resolved records stay in the
            // private candidate, so a receiver sees the qualified verdict
            // rather than a raw flag.
            SkillResultEnvelope::attempt(candidate.qualified_summary())
        }
        Err(error) => SkillResultEnvelope::refused(&error),
    }
}

/// Refreshes the daemon-held Governor capability admission view from the two
/// canonical reads the accepted-intake plan carried (issue #1957, I3.4, A2/A3).
///
/// **This is a refresh, never a decision.** It runs after the caller has
/// rechecked the admitted fence and before the intake is published, and it never
/// refuses or rewrites the intake. That is the fail-closed direction: a
/// production route the view cannot evidence stays refused rather than being
/// read as "nothing to check".
///
/// Note the difference between the two legs on failure, because they are not
/// symmetric. The lifecycle leg replaces the view through the registry's own
/// import and leaves the held contents as they were when it refuses. The DURABLE
/// leg applies the served page ROW BY ROW into the live registry, so a refusal
/// part-way through a page leaves the rows before it applied. That is the
/// registry's own bounded-retain behaviour (a new key refused because the
/// registry is full means the requested coverage was NOT retained, which is
/// exactly what must be reported), and it is not a silent pass: the intake is
/// unaffected either way, and any route the partial page did not cover simply
/// stays refused. The startup drain is the leg that is atomic — it stages pages
/// and replaces the registry only after a complete drain.
///
/// The two legs carry different things and are reported separately:
///
/// * The intake's own `AcceptanceResolution` answers `GetCapabilityEvidenceState`,
///   which serves committed `ApplyLifecyclePolicy` governance rows carrying the
///   six declared lifecycle parameters and no capability status, source, or
///   route-scope fingerprint. It can therefore only ever contribute the
///   non-admitting `declared` / `imported_legacy_declaration` record.
/// * The plan's [`CapabilityRecordRead`] answers
///   `GetCapabilityEvidenceRecordRange`, which serves the durable evidence rows
///   themselves with their owner-issued `record_digest` and store-issued
///   `revision`. **This is the leg that can change an admission verdict:** a
///   fresh exact-fingerprint `probe_passed` / `observed` record mints real
///   admitting evidence, and an exact-fingerprint `broken` record for the same
///   `(skill_id, scope_fingerprint)` key supersedes it under the store-issued
///   revision and restricts the route. Both are the Governor registry's
///   decisions, reached through the one held view — this function defines no
///   admission rule of its own.
fn hydrate_capability_admission_view(
    composition: &mut DaemonComposition,
    record: &AcceptanceRecord,
    resolution: &AcceptanceResolution,
    capability_records: &CapabilityRecordRead,
) {
    let lifecycle = composition
        .capability_admission_mut()
        .map_err(|error| error.to_string())
        .and_then(|view| {
            view.hydrate_from_evidence_response(&resolution.request, &resolution.response)
                .map_err(|error| error.to_string())
        });
    match lifecycle {
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
    let durable = match capability_records {
        CapabilityRecordRead::Served(request, response) => composition
            .capability_admission_mut()
            .map_err(|error| error.to_string())
            .and_then(|view| {
                view.hydrate_from_evidence_record_page(request, response)
                    .map_err(|error| error.to_string())
            }),
        CapabilityRecordRead::Unavailable(reason) => Err(reason.clone()),
    };
    match durable {
        Ok(page) => {
            tracing::info!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_records_hydrated",
                skill_id = %record.skill_id,
                minted_records = page.minted,
                truncated = page.truncated,
                retained_records = page.retained,
            );
        }
        Err(reason) => {
            tracing::warn!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_records_unavailable",
                skill_id = %record.skill_id,
                reason = %reason,
                "durable capability evidence did not refresh the admission view; the held view keeps its previous contents and any production route it cannot evidence stays refused"
            );
        }
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
                    // Full-world tool/definition staleness sweep ahead of display
                    // (issue #1882 A4, I7.13): the versioned acknowledge entry
                    // below enforces the tool-basis and definition drift legs
                    // per call for the subject Skill, while this refresh sweep
                    // marks every OTHER drifted entry world-wide under the same
                    // live tool-owner source, so a Skill whose declared tool
                    // basis or admitted Tool Definition version changed is
                    // marked stale and not representable as generally
                    // delivered even when no display call ever reaches it. A
                    // mark rotates the catalogue digest, so Hotset receipts
                    // issued before the sweep fail closed at activation instead
                    // of displaying a drifted body. The dependency-set and
                    // host/profile legs still await their live producer (STITCH
                    // on `activation_display_against`): no live dependency
                    // registry or live host reporter feeds the bridge on main,
                    // and this drive never synthesizes those terms.
                    if let Err(error) = composition.skill_reconcile_tool_basis() {
                        SkillResultEnvelope::refused(&error)
                    } else {
                        match composition.skill_carry_receipt_to_display(
                            &payload.skill_id,
                            payload.receipt,
                            payload.ack,
                        ) {
                            Ok(display) => SkillResultEnvelope::display(display),
                            Err(error) => SkillResultEnvelope::refused(&error),
                        }
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
                capability_records,
            } => {
                if composition.kernel_snapshot().state_fence() == plan.admitted_fence {
                    hydrate_capability_admission_view(
                        composition,
                        &record,
                        &resolution,
                        &capability_records,
                    );
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
///    `verified_outcome_refs` are resolved by CONTENT against those rows --
///    each resolved record must name the deciding acceptance row's verifier
///    in its own `verifier_refs` (I12.24 verifier competence), so a
///    nonexistent verifier or a real-but-unrelated outcome cannot qualify;
/// 3. the same served rows resolve the presented SUBJECT identity by content:
///    a row naming this Skill and subject attempt must agree on Skill
///    revision/package, route, packet digest/position and fence, or the
///    subject travels as contradicted and the commit refuses it. The fence,
///    route and retained-receipt legs are then rechecked against the
///    lifecycle owner's stored view under the commit's fresh borrow, so no
///    caller-carried reference qualifies structurally.
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

    // The deciding row binds the competent verifier contract for this exact
    // skill/package (acceptance row `verifier_ref`, I12.24). The outcome
    // resolution below must see it: an unresolved subject already returned
    // above, so only a deciding row's verifier travels forward.
    let accepting_verifier = match &acceptance.verdict {
        super::skill_acceptance_read::AcceptanceVerdict::Accepted(record)
        | super::skill_acceptance_read::AcceptanceVerdict::Revoked(record) => {
            record.verifier_ref.as_str()
        }
        super::skill_acceptance_read::AcceptanceVerdict::Unknown => {
            return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
                &eliot_skill::SkillError::InvalidField {
                    field: "receipt.skill_id",
                    reason: "no committed lifecycle row backs this Skill at the current revision; the activation candidate remains unqualified",
                },
            ));
        }
    };

    // 2. Evidence-owner read: resolve the presented outcome references against
    //    durable owner records, each bound to the deciding row's verifier.
    //    There is still no activated verifier-run producer, so this
    //    legitimately resolves nothing until such rows exist -- and any row
    //    that does arrive must name the bound verifier, so a nonexistent
    //    verifier or a real-but-unrelated outcome can never qualify.
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
    let resolved_outcomes = match super::skill_evidence_read::resolve_outcome_records(
        &receipt,
        &rows,
        accepting_verifier,
    ) {
        super::skill_evidence_read::OutcomeResolution::Resolved { records } => records,
        super::skill_evidence_read::OutcomeResolution::NoOwnerRecord => Vec::new(),
    };
    // 3. Subject-identity read over the SAME served rows: the presented
    //    Skill/attempt/route/packet/fence legs are compared against the owner
    //    documents by content. A contradicted subject travels with the
    //    candidate so the commit refuses it; an unresolved subject travels as
    //    unresolved, never as a structural pass. An owner-bound subject
    //    carries the bound row itself, so the commit folds the owner's stage
    //    content rather than the receipt's self-declared stages.
    let resolution = resolve_activation_subject(&receipt, &rows);
    let mut source_revisions = revisions;
    source_revisions.push(super::skill_evidence_read::activation_receipt_revision());
    PlannedSkillPair::Activation(ActivationCandidate {
        receipt: Box::new(receipt),
        ingest_attempt_id,
        source_revisions,
        resolved_outcomes,
        coverage,
        subject: resolution.subject,
        bound_subject: resolution.bound,
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
        // Issue #1838 residual: the Skill owner wires execution evidence for
        // locally served pairs; until then the sealed manifest honestly lists
        // the absent evidence as missing parts.
        evidence: None,
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
        // Issue #1838 residual: no execution evidence on the last-resort
        // refusal body; the sealed manifest lists it as missing parts.
        evidence: None,
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
            authenticated_source: None,
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
