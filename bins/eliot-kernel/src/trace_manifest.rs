//! Canonical replayable trace manifests for Material/Critical work (issue #1838).
//!
//! Architecture: I16.3 composite run trace context, I16.4 required
//! operational events, I16.12 trace completeness with explicit missing parts;
//! A10.8 honest finish vocabulary.
//!
//! A [`TraceManifest`] is the Kernel-owned replayable record for one bound
//! result, keyed by trace/operation ID. It binds the Task/Action contract and
//! State Fence; the presenting caller and its semantic Session; the lease
//! attempt; the policy snapshot when the fence is policy-bound; the requested
//! and actual route; the local-port call with immutable input/output handles;
//! observed side effects; canonical receipts; the finish decision; and an
//! explicit missing-parts list. The original principal comes from the retained
//! resolved activation; policy, packet and verifier handles come from their
//! retained owners. Absent required evidence is listed in `missing_parts` and
//! forces `DEGRADED_NO_PROOF` at this Material/Critical boundary.
//!
//! [`TraceEvidence::observed`] is the read model for the evidence classes this
//! bind path does not receive from its caller. It projects each one off the
//! durable ORS row that owns it: the authenticated producer principal the read
//! owner retained with the completion, the applicable policy snapshot together
//! with the exact fence that claim was made under, and the retained Active
//! View/packet manifest key. `None` means that owner held no such value, so an
//! absent class lands in [`TraceManifest::missing_parts`] and forces
//! [`TraceFinish::DegradedNoProof`]; it is never replaced by a derived,
//! recomputed, or defaulted value.
//!
//! The executor observation is not a second copy: it is projected from the
//! durable ORS row that retained it with the completion (issue #1853 W2), so
//! that row is the single owner and this manifest is only its replayable read
//! model.
//!
//! Persistence reuses the single #1837 audit chain: the manifest seals as one
//! [`AuditEventKind::TRACE_MANIFEST_SEALED`](crate::kernel_audit::AuditEventKind::TRACE_MANIFEST_SEALED)
//! record through the composition's one [`KernelAuditChain`](crate::kernel_audit::KernelAuditChain)
//! handle, covered by the same BLAKE3 linkage and anchor sink. There is no
//! second manifest store, no parallel chain, and no alternate receipt scheme.
//! Replay reads the sealed body back with [`TraceManifest::find_sealed`],
//! which serves the recorded body only when its recorded completion claim is
//! carried by the slots that body itself records.
//!
//! Posture matches the audit chain: sealing is observational and never
//! changes a submit disposition (the durable ORS record owns lifecycle
//! state). The seal runs only after the ORS persist, so `finish` classifies
//! the bound result: [`TraceFinish::VerifiedComplete`] when every required
//! slot is present, [`TraceFinish::DegradedNoProof`] when required evidence
//! is absent. The result boundary carries Critical assurance under the #1837
//! mapping, so required absence always forces the degraded classification.
//!
//! `finish` is a trace-completeness classification, not a Governor
//! FinishDecision (I7.9: a job result never sets that enum directly).

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_ipc::Session;
use eliot_ors::{HostRequestRecord, OpaqueLabel};
use eliot_protocol::{HostRequestEnvelope, HostRequestResultBody};
use eliot_store_api::CampaignLearningStateViewPublication;
use serde::{Deserialize, Serialize};

use crate::kernel_audit::{AuditEventKind, AuditRecord, authority_epoch_text};
use crate::sha256_json;

/// Canonical trace-manifest format version.
///
/// Version 2 enforces the full I16.12 evidence set. Original version-1 bodies
/// remain in the audit chain but are unsupported for replay; their earlier
/// completion claims are never rewritten to manufacture current proof.
pub const TRACE_MANIFEST_FORMAT_VERSION: u16 = 2;

/// Ceiling on one retained evidence reference, matching the bound ORS already
/// enforces on the same durable lineage reference fields
/// (`HostRequestRetainedLineage::validate`). Reused rather than re-invented so
/// a reference this module accepts is one the durable owner already validated.
const TRACE_EVIDENCE_REFERENCE_MAX_BYTES: usize = 1_024;

/// The I16.12 evidence classes a bound result observes outside the inputs its
/// binding caller supplies directly (`TraceManifest::seal`'s other arguments).
///
/// I16.12 requires "principal, Session, leases and policy snapshots", the
/// "Active View/packet manifest", and "verifier/artifact results" in a
/// replayable Material/Critical trace. This projection is where the classes the
/// caller does not hold are read from the owner that does, so none of them is a
/// literal at the seal site:
///
/// - `principal` is the authenticated producer principal/service reference the
///   read owner submitted and ORS retained with the completion
///   (`HostRequestRetainedLineage::producer_ref`). A12.2 makes the harness or
///   installation boundary — not the model and not Kernel — the establisher of
///   that identity, so Kernel only reads what that boundary retained.
/// - `policy_snapshot` is the retained applicable policy snapshot identity
///   (`PolicyFence::policy_snapshot_id`) together with the fence that claim was
///   made under, when the read owner submitted one and that fence is the same
///   fence observed with the authority decision; else the policy revision the
///   authority decision's own fence carries.
/// - `active_view_packet_manifest` is the immutable generated view envelope ORS
///   retained with the completion (`CampaignLearningStateViewPublication`), read
///   back off the row that owns it and re-proved against that row's own task,
///   scope and fence. It is the stored record's key, never a digest recomputed
///   here.
/// - `verifier_result` has no field on the admitted envelope, the durable ORS
///   row, or the submitted execution evidence, and no owner produces an
///   independent verifier result outside the completing actor's failure domain
///   (A5.5), so nothing at this seal site observes it. It is therefore
///   projected as absent and, being a required class, named in `missing_parts`
///   so the run classifies `DEGRADED_NO_PROOF`. Kernel never substitutes a
///   lane label, a recomputed digest, or any other stand-in for it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TraceEvidence {
    /// Authenticated producer principal/service reference, when retained.
    pub principal: Option<String>,
    /// Applicable policy snapshot identity, when retained or policy-bound.
    pub policy_snapshot: Option<String>,
    /// The exact fence the retained `policy_snapshot` claim was made under, so
    /// the seal can refuse a snapshot bound to a different fence than the one
    /// the authority decision was taken under.
    pub policy_snapshot_binding: Option<StateFence>,
    /// Active View/packet manifest reference, when the seal site observes one.
    pub active_view_packet_manifest: Option<String>,
    /// Independent verifier/artifact result, when the seal site observes one.
    pub verifier_result: Option<String>,
}

/// The three evidence inputs one seal site observes for itself.
///
/// These are bundled rather than passed as loose parameters so the precedence
/// between the caller's own observation and the durable projection is stated
/// once, here, instead of at every call site. `None` means *this site observed
/// nothing of its own* - it is never a placeholder and never a request to
/// invent a value; the durable projection in `evidence` supplies the class when
/// an owner exists for it, and the class is recorded as absent when none does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealEvidence<'a> {
    /// Authenticated caller principal observed at this site, if any.
    pub principal: Option<&'a str>,
    /// Active View/packet manifest observed at this site, if any. Honoured only
    /// on the `campaign-packet` lane, which is the lane whose replay readback
    /// re-derives the same value.
    pub active_view_packet_manifest: Option<&'a str>,
    /// The I16.12 classes read off the durable ORS row rather than handed over
    /// by the caller. See [`TraceEvidence::observed`].
    pub evidence: &'a TraceEvidence,
}

impl TraceEvidence {
    /// Projects the evidence classes from the durable result record.
    ///
    /// Read from `persisted`, the same single owner the executor evidence is
    /// read from (issue #1853 W2): a manifest can therefore never claim a
    /// principal or policy snapshot that recovery cannot also read back off
    /// the row, and the sealed body and the durable row can never disagree
    /// about what the read owner authenticated.
    #[must_use]
    pub fn observed(persisted: &HostRequestRecord, state_fence: Option<&StateFence>) -> Self {
        let lineage = persisted.result_lineage.as_ref();
        // A retained policy-snapshot claim is applicable only under the fence
        // it was made with; a claim bound to another fence is a substituted
        // snapshot and the fence's own policy revision is used instead.
        let retained_policy = lineage.and_then(|lineage| {
            let policy = lineage.policy_fence.as_ref()?;
            if state_fence != Some(&policy.state_fence) {
                return None;
            }
            Some(policy)
        });
        Self {
            principal: lineage.and_then(|lineage| valid_reference(lineage.producer_ref.as_deref())),
            policy_snapshot: retained_policy
                .and_then(|policy| valid_reference(Some(policy.policy_snapshot_id.as_str())))
                .or_else(|| {
                    state_fence.and_then(|fence| {
                        fence
                            .policy_revision
                            .map(|revision| revision.value().to_string())
                    })
                }),
            policy_snapshot_binding: retained_policy.map(|policy| policy.state_fence.clone()),
            // I16.12 "Active View/packet manifest": the immutable generated view
            // envelope ORS retained in the same transaction as this completion.
            active_view_packet_manifest: campaign_view_manifest(persisted),
            // No owner produces an independent verifier/artifact result for
            // this completion; see the type documentation. Absent stays absent.
            verifier_result: None,
        }
    }
}

/// Returns the reference only when it is a well-formed bounded value.
///
/// Refuses the blank, control-bearing, and over-long shapes that the durable
/// owner's own reference validation refuses, so a substituted or padded value
/// cannot satisfy a required slot.
fn valid_reference(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.len() > TRACE_EVIDENCE_REFERENCE_MAX_BYTES
    {
        return None;
    }
    Some(value.to_owned())
}

/// Returns true when the manifest records a well-formed reference for one of the
/// projected evidence classes.
///
/// A value the durable owner's own reference validation would reject is not
/// evidence here either, so an empty, padded, control-bearing, or over-long
/// substitute cannot satisfy a required slot.
fn carries_evidence_reference(value: Option<&str>) -> bool {
    valid_reference(value).is_some()
}

/// Reads the retained Active View/packet manifest reference off the durable row.
///
/// The owner is `eliot_store_api::CampaignLearningStateViewPublication`, which
/// ORS stored in `ors_campaign_learning_state_views_v1` under `view_id` in the
/// same write transaction that retained this row's result response. The value
/// recorded here is that stored record's own key — never a digest recomputed at
/// the seal site and never a handle the read owner supplied.
///
/// Bound by CONTENT, not by presence. `validate()` re-derives the view's
/// `content_digest` from the canonical view bytes and proves the publication
/// key matches the view's own identity and admitted binding, and the task,
/// scope and fence must equal this row's own exactly as
/// `validate_campaign_view_result` proved at the bind boundary. A view
/// published for another packet, task, scope or fence leaves the slot ABSENT —
/// and therefore named in `missing_parts` — rather than satisfying it. Only an
/// `eliot.packet` completion may carry one; every other lane, including the
/// query lane, still degrades honestly on this class.
fn campaign_view_manifest(persisted: &HostRequestRecord) -> Option<String> {
    if persisted.capability_ref.as_str() != "eliot.packet" {
        return None;
    }
    let publication: CampaignLearningStateViewPublication = serde_json::from_value(
        persisted
            .result_response
            .as_ref()?
            .get("campaign_learning_state_view")?
            .clone(),
    )
    .ok()?;
    publication.validate().ok()?;
    if persisted.task_ref.as_ref().map(OpaqueLabel::as_str) != Some(publication.task_id.as_str())
        || persisted.scope_ref.as_ref().map(OpaqueLabel::as_str)
            != Some(publication.scope_id.as_str())
        || crate::sha256_json(&publication.state_fence).ok()? != persisted.fence_digest
    {
        return None;
    }
    valid_reference(Some(publication.view_id.as_str()))
}

/// Required manifest slots, in stable enumeration order.
///
/// Every slot must resolve from the admitted envelope, the durable record,
/// the presenting session, or the submitted execution evidence. An absent
/// required slot lands in [`TraceManifest::missing_parts`] and forces
/// [`TraceFinish::DegradedNoProof`].
pub const TRACE_MANIFEST_REQUIRED_SLOTS: [&str; 17] = [
    "action_contract",
    "state_fence",
    "caller_session",
    "lease",
    "requested_route",
    "actual_route",
    "invoked_operation",
    "input_handle",
    "output_handle",
    "side_effects",
    "adapter_identity",
    "executor_identity",
    "result_receipt",
    "principal",
    "policy_snapshot",
    "active_view_packet_manifest",
    "verifier_result",
];

/// Honest finish vocabulary for one sealed manifest (A10.8).
///
/// Kernel-owned: the Kernel cannot depend on the native-worker composition
/// root that carries the sibling vocabulary, so the eight canonical states
/// are mirrored here. Only [`TraceFinish::VerifiedComplete`] claims a bound
/// result with complete required evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceFinish {
    /// Bound with complete required evidence.
    VerifiedComplete,
    /// Honestly preserved partial progress.
    Partial,
    /// Blocked on authority, scope, or input.
    Blocked,
    /// The verifier ran and did not accept the outcome.
    FailedVerification,
    /// Required evidence is absent; completion is not claimed.
    DegradedNoProof,
    /// Finishing would be unsafe.
    UnsafeToFinish,
    /// Cancelled before completion.
    Cancelled,
    /// Replaced by a newer unit of work.
    Superseded,
}

impl TraceFinish {
    /// Returns the canonical finish name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedComplete => "VERIFIED_COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Blocked => "BLOCKED",
            Self::FailedVerification => "FAILED_VERIFICATION",
            Self::DegradedNoProof => "DEGRADED_NO_PROOF",
            Self::UnsafeToFinish => "UNSAFE_TO_FINISH",
            Self::Cancelled => "CANCELLED",
            Self::Superseded => "SUPERSEDED",
        }
    }

    /// Returns true only for proof-bearing completion (ARCH-FIN-01).
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::VerifiedComplete)
    }
}

/// Canonical replayable trace manifest for one bound result (I16.12).
///
/// Keyed by `trace_id`/`operation_id`. `None` slots carry no value; required
/// slots without a value are named in `missing_parts`. Explicitly unavailable
/// evidence cannot bypass required completeness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceManifest {
    /// Canonical format version.
    pub format_version: u16,
    /// Request-scoped trace identity.
    pub trace_id: String,
    /// Kernel operation handle (`hostreq:<sha>`).
    pub operation_id: String,
    /// Daemon-claimable lane that served the read (`query`, `campaign-packet`).
    pub lane: Option<String>,
    /// Admitted capability name (Task/Action contract selector).
    pub capability: Option<String>,
    /// Digest over the exact admitted payload bytes.
    pub payload_digest: Option<String>,
    /// Exact fence observed with the authority decision.
    pub state_fence: Option<StateFence>,
    /// Presenting transport connection identity.
    pub connection_id: Option<String>,
    /// Durable semantic session identity claimed by the request, if any.
    pub session_id: Option<String>,
    /// Governor-owned task identity claimed by the request, if any.
    pub task_id: Option<String>,
    /// Governor-owned `WorkScope` identity claimed by the request, if any.
    pub work_scope_id: Option<String>,
    /// Fenced attempt identity of the completing lease.
    pub lease_attempt_id: Option<String>,
    /// Fencing generation of the completing attempt.
    pub fencing_generation: Option<u64>,
    /// Authority epoch `lineage_id:sequence` text.
    pub authority_epoch: Option<String>,
    /// Module/process generation text.
    pub module_generation: Option<String>,
    /// Requested route (capability selector).
    pub requested_route: Option<String>,
    /// Actual route taken (observed actual-route receipt digest).
    pub actual_route: Option<String>,
    /// Invoked local-port operation.
    pub invoked_operation: Option<String>,
    /// Executor-observed immutable input handle (envelope digest).
    pub input_handle: Option<String>,
    /// Executor-observed immutable output handle (result digest).
    pub output_handle: Option<String>,
    /// Executor-observed presenting adapter instance.
    pub adapter_identity: Option<String>,
    /// Executor-observed process identity (stable artifact digest).
    pub executor_identity: Option<String>,
    /// Observed side-effect declaration (`none` or an effect reference).
    pub side_effects: Option<String>,
    /// Original semantic principal from the retained resolved activation.
    pub principal: Option<String>,
    /// Original policy snapshot handle bound to the same State Fence.
    pub policy_snapshot: Option<String>,
    /// Fence the retained policy snapshot was claimed under, so read-back can
    /// refuse a snapshot bound to a foreign fence instead of trusting the
    /// snapshot text on its own.
    ///
    /// Added after the first version-2 seals, so a body sealed before this slot
    /// existed decodes with the truthful absent value rather than being refused
    /// outright: absence here means "no binding was recorded", and the required
    /// slot check already refuses a snapshot whose binding is absent only when
    /// the recorded fence is absent too. A version bump is a format decision
    /// for the issue owner; this default keeps those retained bodies replayable.
    #[serde(default)]
    pub policy_snapshot_binding: Option<StateFence>,
    /// Active View/packet manifest reference.
    pub active_view_packet_manifest: Option<String>,
    /// Independent verifier/artifact result.
    pub verifier_result: Option<String>,
    /// Canonical digest over the exact bounded response bytes.
    pub result_digest: Option<String>,
    /// Durable ORS state at bind time.
    pub durable_state: Option<String>,
    /// Finish decision for the bound result.
    pub finish: TraceFinish,
    /// Required slots with no value for this run.
    pub missing_parts: Vec<String>,
    /// I16.12 evidence slots this path cannot produce.
    pub unavailable: Vec<String>,
}

impl TraceManifest {
    /// Seals the manifest for one persisted result.
    ///
    /// Binds the admitted envelope (or, when queue memory already retired
    /// it, the durable record), the presenting session, the executor-observed
    /// evidence as it was RETAINED on the durable record, and the persisted
    /// receipt. Required slots without
    /// a value land in `missing_parts` and force
    /// [`TraceFinish::DegradedNoProof`]; anything else seals
    /// [`TraceFinish::VerifiedComplete`]. Call sites run only after the ORS
    /// persist, so the seal never precedes the binding it describes.
    ///
    /// The evidence is read from `persisted`, not from the submitted body
    /// (issue #1853 W2). The manifest is a projection of the durable record,
    /// and the ORS row is the single owner of the observation: a manifest can
    /// therefore never claim an executor observation that recovery cannot also
    /// read back from the row, and the sealed body and the durable row can never
    /// disagree about what was observed.
    ///
    /// `observed_evidence` carries the I16.12 classes that are read off the
    /// durable ORS row rather than handed over by the binding caller
    /// ([`TraceEvidence::observed`]). A class it reports absent arrives absent
    /// and is named in `missing_parts`; it is never given a placeholder, a
    /// recomputed digest, or a lane label here. Where an owner exists on both
    /// sides the precedence is fixed and stated, so the seal can never record
    /// one owner's claim while checking another's:
    ///
    /// - `principal` and `active_view_packet_manifest` are the caller's
    ///   authenticated observations and win; the projected row value is used
    ///   only where the caller observed none, so replay, which re-derives the
    ///   caller's values, still agrees with the sealed body.
    /// - `policy_snapshot` and its `policy_snapshot_binding` are the durable
    ///   evidence projection's alone. The retained `PolicyFence` claim is
    ///   applicable only under the exact fence the authority decision was taken
    ///   under, and a claim bound to another fence is a substituted snapshot:
    ///   the fence's own policy revision is recorded instead, and a projected
    ///   absence is never filled in from the caller's own re-derivation.
    /// - `verifier_result` is the one class the projection has no owner for, so
    ///   the projected value is used when a site observes one and the retained
    ///   verifier observation supplies it otherwise.
    #[must_use]
    pub fn seal(
        session: &Session,
        body: &HostRequestResultBody,
        persisted: &HostRequestRecord,
        envelope: Option<&HostRequestEnvelope>,
        lane: &'static str,
        observed_evidence: &SealEvidence<'_>,
    ) -> Self {
        let SealEvidence {
            principal,
            active_view_packet_manifest,
            evidence: projected_evidence,
        } = *observed_evidence;
        let capability = envelope
            .map(|envelope| envelope.identity.capability.clone())
            .or_else(|| Some(persisted.capability_ref.as_str().to_owned()));
        let payload_digest = envelope
            .map(|envelope| envelope.identity.payload_sha256.clone())
            .or_else(|| Some(persisted.payload_digest.clone()));
        let state_fence = Self::sealed_state_fence(session, persisted, envelope);
        let session_id = envelope
            .and_then(|envelope| envelope.identity.session_id.clone())
            .or_else(|| {
                persisted
                    .session_ref
                    .as_ref()
                    .map(|session| session.as_str().to_owned())
            });
        let evidence = persisted.result_evidence.as_ref();
        let verifier_result = Self::retained_verifier_result(persisted);
        let authority_epoch = state_fence
            .as_ref()
            .map(|fence| authority_epoch_text(&fence.authority_epoch));
        let module_generation = state_fence
            .as_ref()
            .map(|fence| fence.resource_generation.value().to_string());

        let mut manifest = Self {
            format_version: TRACE_MANIFEST_FORMAT_VERSION,
            trace_id: envelope.map_or_else(
                || persisted.request_id.as_str().to_owned(),
                |envelope| envelope.identity.request_id.as_str().to_owned(),
            ),
            operation_id: body.operation_id.clone(),
            lane: Some(lane.to_owned()),
            capability: capability.clone(),
            payload_digest,
            state_fence,
            connection_id: Some(persisted.connection_ref.as_str().to_owned()),
            session_id,
            task_id: envelope
                .and_then(|envelope| envelope.identity.task_id.clone())
                .or_else(|| {
                    persisted
                        .task_ref
                        .as_ref()
                        .map(|task| task.as_str().to_owned())
                }),
            work_scope_id: envelope
                .and_then(|envelope| envelope.identity.work_scope_id.clone())
                .or_else(|| {
                    persisted
                        .scope_ref
                        .as_ref()
                        .map(|scope| scope.as_str().to_owned())
                }),
            lease_attempt_id: body
                .attempt
                .as_ref()
                .map(|attempt| attempt.attempt_id.clone()),
            fencing_generation: body
                .attempt
                .as_ref()
                .map(|attempt| attempt.fencing_generation),
            authority_epoch,
            module_generation,
            requested_route: capability,
            actual_route: evidence.and_then(|evidence| evidence.actual_route.clone()),
            invoked_operation: evidence.and_then(|evidence| evidence.invoked_operation.clone()),
            input_handle: evidence.and_then(|evidence| evidence.input_handle.clone()),
            output_handle: evidence.and_then(|evidence| evidence.output_handle.clone()),
            adapter_identity: evidence.and_then(|evidence| evidence.adapter_identity.clone()),
            executor_identity: evidence.and_then(|evidence| evidence.executor_identity.clone()),
            side_effects: evidence.and_then(|evidence| evidence.side_effects.clone()),
            principal: principal
                .map(str::to_owned)
                .or_else(|| projected_evidence.principal.clone()),
            policy_snapshot: projected_evidence.policy_snapshot.clone(),
            policy_snapshot_binding: projected_evidence.policy_snapshot_binding.clone(),
            active_view_packet_manifest: Self::sealed_active_view_manifest(
                lane,
                active_view_packet_manifest,
                projected_evidence,
            ),
            verifier_result: projected_evidence
                .verifier_result
                .clone()
                .or(verifier_result),
            result_digest: Some(body.result_digest.clone()),
            durable_state: Some(format!("{:?}", persisted.state)),
            finish: TraceFinish::VerifiedComplete,
            missing_parts: Vec::new(),
            unavailable: Vec::new(),
        };
        let missing = manifest.missing_parts();
        manifest.finish = if missing.is_empty() {
            TraceFinish::VerifiedComplete
        } else {
            TraceFinish::DegradedNoProof
        };
        manifest.missing_parts = missing;
        manifest.unavailable = manifest.unavailable_parts();
        manifest
    }

    fn sealed_state_fence(
        session: &Session,
        persisted: &HostRequestRecord,
        envelope: Option<&HostRequestEnvelope>,
    ) -> Option<StateFence> {
        if let Some(envelope) = envelope {
            Some(envelope.state_fence.clone())
        } else {
            let fallback = &session.module_generation.state_fence;
            (fallback.validate().is_ok()
                && sha256_json(fallback).ok().as_deref() == Some(persisted.fence_digest.as_str()))
            .then(|| fallback.clone())
        }
    }

    /// Records the Active View/packet manifest the seal site observed.
    ///
    /// The caller's `campaign-packet` observation wins: it is the value the
    /// replay readback re-derives from the same stored publication, so the
    /// sealed body and the readback stay comparable. Only a site that observed
    /// no manifest of its own falls back to the durable evidence projection,
    /// which re-proves the stored publication's task, scope and fence against
    /// this row before naming its key.
    fn sealed_active_view_manifest(
        lane: &'static str,
        observed_at_call_site: Option<&str>,
        observed_evidence: &TraceEvidence,
    ) -> Option<String> {
        let lane_observed = if lane == "campaign-packet" {
            observed_at_call_site.map(str::to_owned)
        } else {
            None
        };
        lane_observed.or_else(|| observed_evidence.active_view_packet_manifest.clone())
    }

    fn retained_verifier_result(persisted: &HostRequestRecord) -> Option<String> {
        let lineage = persisted.result_lineage.as_ref()?;
        (matches!(
            &lineage.result_class,
            eliot_ors::HostRequestRetainedResultClass::VerifierObservation
        ) && persisted.result_digest.as_deref() == Some(lineage.output_digest.as_str()))
        .then(|| lineage.output_digest.clone())
    }

    /// Reads back the latest sealed manifest for one operation.
    ///
    /// Scans retained chain records for the newest
    /// `trace.manifest_sealed` entry bound to `operation_id` and decodes its
    /// sealed body. Returns `None` when no seal exists, when the sealed body
    /// does not decode, when it carries a foreign
    /// [`TRACE_MANIFEST_FORMAT_VERSION`], or when the recorded completion
    /// claim is not supported by the slots that very body records: replay is
    /// then limited, never invented.
    ///
    /// The check reads only the recorded body. It never re-derives the
    /// classification from live request state, so a readback either
    /// reproduces the sealed record or reports no manifest.
    #[must_use]
    pub fn find_sealed(records: &[AuditRecord], operation_id: &str) -> Option<Self> {
        let record = records.iter().rev().find(|record| {
            record.kind == AuditEventKind::TRACE_MANIFEST_SEALED
                && record.lineage.operation_id.as_deref() == Some(operation_id)
        })?;
        let manifest: Self = serde_json::from_value(record.event_body.clone()).ok()?;
        let trace_id = record.lineage.trace_id.as_deref()?;
        (has_text(trace_id)
            && has_text(operation_id)
            && manifest.trace_id == trace_id
            && manifest.operation_id == operation_id
            && Self::records_supported_completion(&manifest))
        .then_some(manifest)
    }

    /// Returns true when the recorded completion claim is carried by the
    /// recorded required slots.
    ///
    /// The original recorded lists and classification must agree with the
    /// required evidence carried by this body. A contradictory body is refused
    /// instead of receiving a newly computed completion claim.
    fn records_supported_completion(&self) -> bool {
        self.format_version == TRACE_MANIFEST_FORMAT_VERSION
            && has_text(&self.trace_id)
            && has_text(&self.operation_id)
            && self.missing_parts == self.missing_parts()
            && self.unavailable == self.unavailable_parts()
            && self.finish
                == if self.missing_parts.is_empty() {
                    TraceFinish::VerifiedComplete
                } else {
                    TraceFinish::DegradedNoProof
                }
    }

    /// Returns the required slots with no value, in stable order.
    ///
    /// Enumerated from [`TRACE_MANIFEST_REQUIRED_SLOTS`] itself, so the
    /// required set has exactly one declaration: a slot added there is
    /// enforced here without a second list to keep in step. An unrecognized
    /// required name resolves absent, which fails closed into
    /// [`TraceFinish::DegradedNoProof`] rather than into a completion claim.
    fn missing_parts(&self) -> Vec<String> {
        TRACE_MANIFEST_REQUIRED_SLOTS
            .iter()
            .filter(|slot| !self.required_slot_present(slot))
            .map(|slot| (*slot).to_owned())
            .collect()
    }

    /// Returns true when one required slot carries a value.
    fn required_slot_present(&self, slot: &str) -> bool {
        match slot {
            "action_contract" => {
                has_text_option(self.capability.as_deref())
                    && has_text_option(self.payload_digest.as_deref())
            }
            "state_fence" => self.state_fence.is_some(),
            // A1 names caller AND session: the presenting transport
            // connection alone does not identify the semantic caller, so
            // withholding the session leaves the slot absent.
            "caller_session" => {
                has_text_option(self.connection_id.as_deref())
                    && has_text_option(self.session_id.as_deref())
            }
            "lease" => {
                has_text_option(self.lease_attempt_id.as_deref())
                    && self.fencing_generation.is_some()
            }
            "requested_route" => has_text_option(self.requested_route.as_deref()),
            "actual_route" => has_text_option(self.actual_route.as_deref()),
            "invoked_operation" => has_text_option(self.invoked_operation.as_deref()),
            "input_handle" => has_text_option(self.input_handle.as_deref()),
            "output_handle" => has_text_option(self.output_handle.as_deref()),
            "side_effects" => has_text_option(self.side_effects.as_deref()),
            "adapter_identity" => has_text_option(self.adapter_identity.as_deref()),
            "executor_identity" => has_text_option(self.executor_identity.as_deref()),
            "result_receipt" => {
                has_text_option(self.result_digest.as_deref())
                    && has_text_option(self.durable_state.as_deref())
            }
            "principal" => has_text_option(self.principal.as_deref()),
            // I16.12 names the applicable policy snapshot as required trace
            // content. Presence alone is not enough: a snapshot bound to a
            // fence other than the recorded one is a substituted reference.
            "policy_snapshot" => self.policy_snapshot_is_applicable(),
            "active_view_packet_manifest" => {
                has_text_option(self.active_view_packet_manifest.as_deref())
            }
            "verifier_result" => has_text_option(self.verifier_result.as_deref()),
            _ => false,
        }
    }

    /// Returns true when the recorded policy snapshot is the applicable one for
    /// the exact fence this manifest records.
    ///
    /// The retained `PolicyFence` is the read owner's claim about which policy
    /// snapshot applied, and it carries the fence that claim was made under. A
    /// claim bound to a different fence than the authority decision was taken
    /// under is a substituted snapshot, so it is refused here rather than
    /// recorded as evidence. The fence's own policy revision is the recorded
    /// fallback: it is the policy identity the authority decision itself
    /// carries, and it corroborates no foreign binding.
    fn policy_snapshot_is_applicable(&self) -> bool {
        if !carries_evidence_reference(self.policy_snapshot.as_deref()) {
            return false;
        }
        let Some(fence) = self.state_fence.as_ref() else {
            return false;
        };
        self.policy_snapshot_binding
            .as_ref()
            .is_none_or(|bound| bound == fence)
    }

    /// Returns the I16.12 evidence slots this path cannot produce.
    fn unavailable_parts(&self) -> Vec<String> {
        let mut unavailable = Vec::new();
        for (slot, name) in [
            (has_text_option(self.principal.as_deref()), "principal"),
            (
                has_text_option(self.policy_snapshot.as_deref()),
                "policy_snapshot",
            ),
            (
                has_text_option(self.active_view_packet_manifest.as_deref()),
                "active_view_packet_manifest",
            ),
            (
                has_text_option(self.verifier_result.as_deref()),
                "verifier_result",
            ),
            (
                has_text_option(self.executor_identity.as_deref()),
                "executor_identity",
            ),
        ] {
            if !slot {
                unavailable.push(name.to_owned());
            }
        }
        unavailable
    }
}

fn has_text(value: &str) -> bool {
    !value.trim().is_empty()
}

fn has_text_option(value: Option<&str>) -> bool {
    value.is_some_and(has_text)
}
