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
//! a private candidate, bind it to its committed lifecycle row outside the
//! composition mutex, and admit or report it at commit after the fence and
//! owner-revision recheck (issue #2663); execution pairs decode to a private
//! candidate, bind the header the same way, and reconcile unknown effects
//! before retry only after the recheck (issue #2663).
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
use super::skill_acceptance_read::{
    AcceptanceRecord, AcceptanceResolution, AcceptanceVerdict, HistoricalBinding,
};
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

/// Authenticated ingestion request versus observed historical subject
/// (issue #2663).
///
/// The collector that submits evidence over the present [`LocalReadAttempt`]
/// is not the agent execution being observed: a current authorized collector
/// may report an older attempt, so the ingest attempt id and the observed
/// subject refs are carried as separate identities and never equated. The
/// commit leg binds the plan to the live ingest attempt through the fence
/// check; the observed refs only ever resolve against owner records, never
/// against the ingest attempt.
struct IngestSubject {
    /// Authenticated collector attempt that submitted this ingest.
    ingest_attempt_id: String,
    /// Historical subject refs under observation (activation attempt ref, or
    /// the presented execution refs in first-presented order).
    observed_subject_refs: Vec<String>,
}

impl IngestSubject {
    /// Whether this candidate still binds the live ingest attempt and names
    /// its historical subject: the commit-leg candidate half of the
    /// plan/attempt binding. An empty observed set is a malformed candidate,
    /// never an anonymous one.
    fn binds_live_ingest(&self, attempt: &LocalReadAttempt) -> bool {
        self.ingest_attempt_id == attempt.attempt_id && !self.observed_subject_refs.is_empty()
    }
}

/// Currency of the committed lifecycle row behind one evidence candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingCurrency {
    /// The row still holds the current owner position: material admission
    /// may proceed after the commit-leg fence and revision recheck.
    Current,
    /// The row was superseded by a newer committed revision: the evidence
    /// stays usable at its historical identity and can never reactivate the
    /// superseded revision.
    Historical,
}

/// Owner qualification carried by one activation/execution candidate.
///
/// Binds the decoded caller payload to the exact committed lifecycle row for
/// its skill and package digest, resolved through the canonical acceptance
/// read outside the composition mutex. Stages without a production owner
/// read (subject-attempt, packet/delivery, route, task/scope, verifier run,
/// outcome/utility records) stay unqualified: they are reported as observed
/// structure, never as owner-backed positives, and `useful` stays false
/// without the owner-backed outcome relation.
struct EvidenceQualification {
    /// Exact committed lifecycle row binding the presented skill/package.
    record: AcceptanceRecord,
    /// Whether that row is still current or already superseded.
    currency: BindingCurrency,
}

impl EvidenceQualification {
    /// Whether the activation receipt still matches the plan's owner record:
    /// the commit-leg recheck of the load-bearing owner revision before
    /// publishing.
    fn matches_receipt(&self, receipt: &eliot_skill::SkillHarnessActivationReceipt) -> bool {
        receipt.skill_id == self.record.skill_id
            && receipt.package_digest == self.record.package_digest
    }

    /// Whether the execution header still matches the plan's owner record:
    /// the commit-leg recheck of the load-bearing owner revision before
    /// publishing.
    fn matches_execution_header(
        &self,
        payload: &eliot_agent_bridge_core::SkillExecutionPayload,
    ) -> bool {
        payload.skill_id == self.record.skill_id
            && payload.package_digest == self.record.package_digest
    }
}

enum PlannedSkillPair {
    /// The request is fully resolved without further composition state.
    Resolved(SkillResultEnvelope),
    /// Display consumes the live composition owner synchronously.
    Display(eliot_agent_bridge_core::SkillDisplayPayload),
    /// Activation evidence decoded to a private candidate and bound to its
    /// owner lifecycle row. Current bindings admit against the live catalogue
    /// and Governor standing only after the plan's fence is rechecked;
    /// historical bindings report at their historical identity without
    /// admission and can never reactivate the superseded revision.
    ActivationCandidate {
        /// Decoded caller receipt; qualified only through `qualification`.
        receipt: Box<eliot_skill::SkillHarnessActivationReceipt>,
        /// Authenticated ingest attempt kept distinct from the observed one.
        subject: IngestSubject,
        /// Committed-row binding plus its currency.
        qualification: EvidenceQualification,
    },
    /// Execution evidence decoded to a private candidate and bound to its
    /// owner lifecycle row. The unknown-effects fold runs at commit only
    /// after the plan's fence is rechecked; the report carries presented
    /// counts, never an admission or promotion claim.
    ExecutionCandidate {
        /// Decoded caller payload; qualified only through `qualification`.
        payload: Box<eliot_agent_bridge_core::SkillExecutionPayload>,
        /// Authenticated ingest attempt kept distinct from the observed refs.
        subject: IngestSubject,
        /// Committed-row binding plus its currency.
        qualification: EvidenceQualification,
    },
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

/// Plans one claimed Skill pair, completing canonical acceptance reads without
/// borrowing the daemon composition.
///
/// The caller snapshots `admitted_fence` under a short composition lock and
/// commits the owned plan under a fresh lock after this async function ends.
pub async fn plan_skill_pair(
    kernel: &DaemonKernelClient,
    admitted_fence: StateFence,
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
            let action =
                plan_activation_candidate(kernel, &admitted_fence, &arguments, attempt).await;
            plan(action)
        }
        SkillToolKind::Execute => {
            let action =
                plan_execution_candidate(kernel, &admitted_fence, &arguments, attempt).await;
            plan(action)
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

/// Resolves the owner qualification for one evidence header without holding
/// the composition lock (issue #2663).
///
/// Runs the canonical committed-lifecycle read over the authenticated Kernel
/// route and binds the presented skill/package to its row. Foreign digests
/// (never committed), revoked digests, contradictory bindings, and lost reads
/// return the refusal envelope: only a committed row qualifies the candidate,
/// current or historical.
async fn read_canonical_binding(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
    skill_id: &str,
    package_digest: &str,
) -> Result<HistoricalBinding, String> {
    let resolution = super::skill_acceptance_read::resolve_intake_acceptance(
        kernel,
        admitted_fence,
        skill_id,
        package_digest,
    )
    .await
    .map_err(|error| error.to_string())?;
    super::skill_acceptance_read::resolve_historical_binding(
        &resolution.request,
        &resolution.response,
        package_digest,
    )
    .map_err(|error| error.to_string())
}

async fn resolve_evidence_qualification(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
    skill_id: &str,
    package_digest: &str,
    digest_field: &'static str,
) -> Result<EvidenceQualification, SkillResultEnvelope> {
    let refused = |error: &eliot_skill::SkillError| SkillResultEnvelope::refused(error);
    let binding =
        match read_canonical_binding(kernel, admitted_fence, skill_id, package_digest).await {
            Ok(binding) => binding,
            Err(detail) => return Err(refused(&eliot_skill::SkillError::Surface(detail))),
        };
    let (record, currency) = match binding {
        HistoricalBinding::Current(record) => (record, BindingCurrency::Current),
        HistoricalBinding::Historical { record, .. } => (record, BindingCurrency::Historical),
        HistoricalBinding::Revoked(_) => {
            return Err(refused(&eliot_skill::SkillError::InvalidField {
                field: digest_field,
                reason: "canonical lifecycle revoked this package revision",
            }));
        }
        HistoricalBinding::NeverCommitted => {
            return Err(refused(&eliot_skill::SkillError::IdentityMismatch));
        }
    };
    if skill_id != record.skill_id || package_digest != record.package_digest {
        return Err(refused(&eliot_skill::SkillError::IdentityMismatch));
    }
    Ok(EvidenceQualification { record, currency })
}

/// Plans one activation receipt as an owner-qualified candidate without
/// holding the composition lock (issue #2663).
///
/// Decodes the private candidate, then qualifies its skill/package against
/// the canonical committed lifecycle rows. A current receipt must sit at the
/// admitted fence; a historical receipt keeps its own fence and is never
/// re-stamped with today's. The ingest attempt and the observed attempt are
/// carried as distinct identities — an observed ref that differs from the
/// ingest attempt is expected, never a mismatch.
async fn plan_activation_candidate(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
    arguments: &Value,
    attempt: &LocalReadAttempt,
) -> PlannedSkillPair {
    let receipt = match decode_activation(arguments) {
        Ok(receipt) => receipt,
        Err(error) => {
            return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(error.as_ref()));
        }
    };
    let qualification = match resolve_evidence_qualification(
        kernel,
        admitted_fence,
        &receipt.skill_id,
        &receipt.package_digest,
        "receipt.package_digest",
    )
    .await
    {
        Ok(qualification) => qualification,
        Err(outcome) => return PlannedSkillPair::Resolved(outcome),
    };
    if qualification.currency == BindingCurrency::Current && receipt.state_fence != *admitted_fence
    {
        return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(
            &eliot_skill::SkillError::FenceMismatch,
        ));
    }
    let subject = IngestSubject {
        ingest_attempt_id: attempt.attempt_id.clone(),
        observed_subject_refs: vec![receipt.attempt_ref.clone()],
    };
    PlannedSkillPair::ActivationCandidate {
        receipt: Box::new(receipt),
        subject,
        qualification,
    }
}

/// Plans one execution-evidence ingest as an owner-qualified candidate
/// without holding the composition lock (issue #2663).
///
/// The header skill/package binds to the canonical committed lifecycle rows
/// exactly like activation: foreign, revoked, contradictory, and unreadable
/// headers refuse before any record folds, and the unknown-effects fold runs
/// only at commit after the fence recheck. Per-record step/artifact/verifier
/// provenance has no production owner read, so records fold as presented
/// structure once the header binds; the reconciliation report carries counts,
/// never an admission or promotion claim.
/// STITCH (issue #2663): header-vs-record provenance is BLOCKED-BY
/// per-record skill/attempt linkage in the execution wire shape plus named
/// owner reads for step/artifact records and verifier contracts/runs; that
/// wire change shares one coherent revision with #2664 and is not made here.
async fn plan_execution_candidate(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
    arguments: &Value,
    attempt: &LocalReadAttempt,
) -> PlannedSkillPair {
    let payload = match decode_execution(arguments) {
        Ok(payload) => payload,
        Err(error) => {
            return PlannedSkillPair::Resolved(SkillResultEnvelope::refused(error.as_ref()));
        }
    };
    let qualification = match resolve_evidence_qualification(
        kernel,
        admitted_fence,
        &payload.skill_id,
        &payload.package_digest,
        "execute.package_digest",
    )
    .await
    {
        Ok(qualification) => qualification,
        Err(outcome) => return PlannedSkillPair::Resolved(outcome),
    };
    let mut observed_subject_refs = Vec::new();
    for execution in &payload.executions {
        if !observed_subject_refs.contains(&execution.execution_ref) {
            observed_subject_refs.push(execution.execution_ref.clone());
        }
    }
    let subject = IngestSubject {
        ingest_attempt_id: attempt.attempt_id.clone(),
        observed_subject_refs,
    };
    PlannedSkillPair::ExecutionCandidate {
        payload: Box::new(payload),
        subject,
        qualification,
    }
}

/// Commits one owner-qualified activation candidate under a fresh short
/// composition borrow (issue #2663).
///
/// Rechecks the admitted fence, the candidate's live-ingest binding, and the
/// load-bearing owner record before publishing. Current bindings admit
/// against the live catalogue and Governor standing (refusing on any drift
/// since the plan); historical bindings report at their historical identity
/// without admission and can never reactivate the superseded revision.
fn commit_activation_candidate(
    composition: &DaemonComposition,
    admitted_fence: &StateFence,
    attempt: &LocalReadAttempt,
    receipt: &eliot_skill::SkillHarnessActivationReceipt,
    subject: &IngestSubject,
    qualification: &EvidenceQualification,
) -> SkillResultEnvelope {
    if composition.kernel_snapshot().state_fence() != *admitted_fence
        || !subject.binds_live_ingest(attempt)
        || !qualification.matches_receipt(receipt)
    {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch);
    }
    match qualification.currency {
        // Current binding: the live catalogue revision, Governor standing,
        // and owner-backed outcome relation recheck inside admission, which
        // refuses on any drift since the plan.
        BindingCurrency::Current => match composition.skill_admit_material_attempt(receipt) {
            Ok(summary) => SkillResultEnvelope::attempt(summary),
            Err(error) => SkillResultEnvelope::refused(&error),
        },
        // Historical binding: report the observed structure at its
        // historical identity without material admission, so a superseded
        // revision can never reactivate. Usefulness stays unestablished: no
        // admission ran, so no owner-backed outcome relation qualified a
        // benefit claim.
        // STITCH (issue #2663): recording this qualified historical
        // observation through the lifecycle owner is BLOCKED-BY a governed
        // daemon→registry mutation port — `GovernorComposition` exposes
        // `owners(&self)` only, and minting a second write path needs owner
        // review, not a repair-lane edit.
        BindingCurrency::Historical => {
            let mut summary = eliot_skill::derive_attempt_summary(receipt);
            summary.useful = false;
            SkillResultEnvelope::attempt(summary)
        }
    }
}

/// Commits one owner-qualified execution candidate under a fresh short
/// composition borrow (issue #2663).
///
/// Rechecks the admitted fence, the candidate's live-ingest binding, and the
/// load-bearing owner record before the unknown-effects fold publishes its
/// reconciliation report.
fn commit_execution_candidate(
    composition: &DaemonComposition,
    admitted_fence: &StateFence,
    attempt: &LocalReadAttempt,
    payload: &eliot_agent_bridge_core::SkillExecutionPayload,
    subject: &IngestSubject,
    qualification: &EvidenceQualification,
) -> SkillResultEnvelope {
    if composition.kernel_snapshot().state_fence() != *admitted_fence
        || !subject.binds_live_ingest(attempt)
        || !qualification.matches_execution_header(payload)
    {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch);
    }
    drive_execution_evidence(payload)
}

/// Commits the accepted intake against the current composition owner, then
/// binds the final outcome to the exact local-read attempt.
///
/// The commit step is also where the daemon-held Governor capability admission
/// view is hydrated (issue #1957, I3.4): the same canonical
/// `GetCapabilityEvidenceState` response that decided this intake is applied to
/// the held registry, so the admission view stops being permanently empty.
/// A hydration failure is a `warn` diagnostic naming the exact reason, never a
/// silent pass and never a rewritten verdict — the held view keeps its
/// previous contents, and a production route that view cannot evidence stays
/// refused, because `declared` / `imported_legacy` records never admit.
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
            PlannedSkillPair::ActivationCandidate {
                receipt,
                subject,
                qualification,
            } => commit_activation_candidate(
                composition,
                &plan.admitted_fence,
                attempt,
                &receipt,
                &subject,
                &qualification,
            ),
            PlannedSkillPair::ExecutionCandidate {
                payload,
                subject,
                qualification,
            } => commit_execution_candidate(
                composition,
                &plan.admitted_fence,
                attempt,
                &payload,
                &subject,
                &qualification,
            ),
            PlannedSkillPair::AcceptedIntake {
                payload,
                record,
                resolution,
            } => {
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
/// the fold keeps delivered, retrieved, activated, adhered and useful
/// distinct, so a packet-included but never activated Skill is never marked
/// successful and usefulness still requires verifier-backed outcome refs.
/// Decoding alone cannot admit Material use: the commit leg checks the live
/// catalogue and Governor standing before returning an attempt summary.
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

/// Decodes one execution-evidence ingest for owner qualification at plan
/// time (issue #2663).
///
/// Decode verifies the header binding plus every record shape from the wire
/// bytes; the plan leg then binds the header to its committed lifecycle row
/// before the commit leg folds anything.
fn decode_execution(
    arguments: &Value,
) -> Result<eliot_agent_bridge_core::SkillExecutionPayload, Box<eliot_skill::SkillError>> {
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
    Ok(payload)
}

/// Drives one owner-qualified execution-evidence candidate through
/// unknown-effects reconciliation.
///
/// Every presented record is validated (observed executions require exact
/// step refs; causal credit stays denied) and folded by outcome. A clean
/// window carries its exact counts back; any still-uncertain execution
/// refuses retry with the pending refs named, so unknown effects are
/// reconciled by exact evidence before the next attempt. Absent records
/// prove nothing — only presented evidence folds, and uninstrumented
/// executions stay unknown instead of proving success.
fn drive_execution_evidence(
    payload: &eliot_agent_bridge_core::SkillExecutionPayload,
) -> SkillResultEnvelope {
    match eliot_skill::reconcile_unknown_effects(&payload.executions) {
        Ok(verdict) => {
            if verdict.retry_permitted() {
                SkillResultEnvelope::evidence(verdict.observed, verdict.failed, 0)
            } else {
                SkillResultEnvelope {
                    contract_version: eliot_agent_bridge_core::SKILL_TRANSPORT_VERSION,
                    outcome: eliot_agent_bridge_core::SkillResultOutcome::Refused {
                        code: "UNCERTAIN_EFFECTS".to_owned(),
                        detail: format!(
                            "{} execution(s) have unknown effects; reconcile with exact evidence before retry",
                            verdict.uncertain_pending_refs.len()
                        ),
                    },
                }
            }
        }
        Err(error) => SkillResultEnvelope::refused(&error),
    }
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
