//! Canonical replayable trace manifests for Material/Critical work (issue #1838).
//!
//! Architecture: I16.3 composite run trace context, I16.4 required
//! operational events, I16.12 trace completeness with explicit missing parts;
//! A10.8 honest finish vocabulary.
//!
//! A [`TraceManifest`] is the Kernel-owned replayable record for one bound
//! result, keyed by trace/operation ID. It binds the Task/Action contract and
//! State Fence; the Active View/packet manifest reference; the semantic
//! principal, the presenting caller and its semantic Session; the lease
//! attempt; the policy snapshot; the requested and actual route; the
//! local-port call with immutable input/output handles; observed side effects;
//! the verifier/artifact result; canonical receipts; the finish decision; and
//! an explicit missing-parts list.
//!
//! Every I16.12 class is a REQUIRED slot in
//! [`TRACE_MANIFEST_REQUIRED_SLOTS`], including the four this bind path can
//! only sometimes observe. [`TraceEvidence::observed`] reads each one from the
//! owner that holds it — the durable ORS row for the retained result lineage
//! (issue #1853 W2) and the exact fence observed with the authority decision —
//! and `None` means that owner held no such value. An absent class is
//! therefore reported by [`TraceManifest::missing_parts`] and forces
//! [`TraceFinish::DegradedNoProof`]; it is never replaced by a derived,
//! recomputed, or defaulted value. Only the executor identity, which I16.12
//! does not name as a required class, stays in `unavailable`: missing evidence
//! limits replay and is never silently treated as success.
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

/// Canonical trace-manifest format version.
pub const TRACE_MANIFEST_FORMAT_VERSION: u16 = 1;

/// Ceiling on one retained evidence reference, matching the bound ORS already
/// enforces on the same durable lineage reference fields
/// (`HostRequestRetainedLineage::validate`). Reused rather than re-invented so
/// a reference this module accepts is one the durable owner already validated.
const TRACE_EVIDENCE_REFERENCE_MAX_BYTES: usize = 1_024;

/// The four I16.12 evidence classes a bound result observes outside the durable
/// result evidence (`TraceManifest::seal`'s other inputs).
///
/// I16.12 requires "Active View/packet manifest", "principal, Session, leases
/// and policy snapshots", and "verifier/artifact results" in a replayable
/// Material/Critical trace. This projection is where each of those classes is
/// read from the owner that holds it, so none of them is a literal in the seal:
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

impl TraceEvidence {
    /// Projects the four evidence classes from the durable result record.
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

/// Returns true when the manifest records a well-formed reference for one of
/// the four evidence classes.
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
/// same write transaction that retained this row's result response
/// (`RedbRecoveryStore::persist_host_request_result`). The value recorded here
/// is that stored record's own key — never a digest recomputed at the seal site
/// and never a handle the read owner supplied.
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
/// the presenting session, the submitted execution evidence, or the durable
/// evidence projection in [`TraceEvidence`]. The set is the external
/// specification of I16.12's required trace content, so a class the
/// specification names is required whether or not this bind path can observe
/// it: an absent required slot lands in [`TraceManifest::missing_parts`] and
/// forces [`TraceFinish::DegradedNoProof`], and it is never diverted into the
/// parallel `unavailable` list the finish decision never consults.
pub const TRACE_MANIFEST_REQUIRED_SLOTS: [&str; 16] = [
    "action_contract",
    "state_fence",
    "active_view_packet_manifest",
    "caller_session",
    "principal",
    "lease",
    "policy_snapshot",
    "requested_route",
    "actual_route",
    "invoked_operation",
    "input_handle",
    "output_handle",
    "side_effects",
    "adapter_identity",
    "verifier_result",
    "result_receipt",
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
/// slots without a value are named in `missing_parts`, and I16.12 evidence
/// slots this path cannot produce are named in `unavailable`.
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
    /// Semantic principal: the authenticated producer principal/service
    /// reference the harness or installation boundary established
    /// (`TraceEvidence::observed`).
    pub principal: Option<String>,
    /// Applicable policy snapshot, retained with the completion or carried by
    /// the exact observed fence.
    pub policy_snapshot: Option<String>,
    /// Fence the retained policy snapshot was claimed under, so read-back can
    /// refuse a snapshot bound to a foreign fence instead of trusting the
    /// snapshot text on its own.
    pub policy_snapshot_binding: Option<StateFence>,
    /// Active View/packet manifest reference; absent is a required missing
    /// part on this bind path, never a stand-in value.
    pub active_view_packet_manifest: Option<String>,
    /// Independent verifier/artifact result; absent is a required missing part
    /// on this bind path, never a stand-in value.
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
    /// `observed_evidence` carries the four I16.12 classes that are not part
    /// of the durable result evidence (`TraceEvidence`), observed at this
    /// production seal site. A class the site does not observe arrives absent
    /// and is named in `missing_parts`; it is never given a placeholder, a
    /// recomputed digest, or a lane label here.
    #[must_use]
    pub fn seal(
        session: &Session,
        body: &HostRequestResultBody,
        persisted: &HostRequestRecord,
        envelope: Option<&HostRequestEnvelope>,
        lane: &'static str,
        observed_evidence: &TraceEvidence,
    ) -> Self {
        let capability = envelope
            .map(|envelope| envelope.identity.capability.clone())
            .or_else(|| Some(persisted.capability_ref.as_str().to_owned()));
        let payload_digest = envelope
            .map(|envelope| envelope.identity.payload_sha256.clone())
            .or_else(|| Some(persisted.payload_digest.clone()));
        let state_fence = envelope
            .map(|envelope| envelope.state_fence.clone())
            .or_else(|| Some(session.module_generation.state_fence.clone()));
        let session_id = envelope
            .and_then(|envelope| envelope.identity.session_id.clone())
            .or_else(|| {
                persisted
                    .session_ref
                    .as_ref()
                    .map(|session| session.as_str().to_owned())
            });
        let evidence = persisted.result_evidence.as_ref();
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
            connection_id: Some(session.connection_id.clone()),
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
            principal: observed_evidence.principal.clone(),
            policy_snapshot: observed_evidence.policy_snapshot.clone(),
            policy_snapshot_binding: observed_evidence.policy_snapshot_binding.clone(),
            active_view_packet_manifest: observed_evidence.active_view_packet_manifest.clone(),
            verifier_result: observed_evidence.verifier_result.clone(),
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
        records
            .iter()
            .rev()
            .find(|record| {
                record.kind == AuditEventKind::TRACE_MANIFEST_SEALED
                    && record.lineage.operation_id.as_deref() == Some(operation_id)
            })
            .and_then(|record| serde_json::from_value(record.event_body.clone()).ok())
            .filter(Self::records_supported_completion)
    }

    /// Returns true when the recorded completion claim is carried by the
    /// recorded required slots.
    ///
    /// The guarantee is one-directional on purpose: a recorded
    /// [`TraceFinish::VerifiedComplete`] whose own slots leave a required
    /// absence is a self-contradicting body and is refused, so replay never
    /// serves an unqualified success. A recorded degraded or partial
    /// classification over complete slots is conservative, never an
    /// over-claim, so it is served as recorded.
    fn records_supported_completion(&self) -> bool {
        self.format_version == TRACE_MANIFEST_FORMAT_VERSION
            && (!self.finish.is_complete() || self.missing_parts().is_empty())
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
            "action_contract" => self.capability.is_some() && self.payload_digest.is_some(),
            "state_fence" => self.state_fence.is_some(),
            // I16.12 names the Active View/packet manifest as required trace
            // content. No field on the envelope, the durable row, or the
            // submitted evidence carries one, so on this path the slot is
            // absent and named as a missing part rather than satisfied.
            "active_view_packet_manifest" => {
                carries_evidence_reference(self.active_view_packet_manifest.as_deref())
            }
            // A1 names caller AND session: the presenting transport
            // connection alone does not identify the semantic caller, so
            // withholding the session leaves the slot absent.
            "caller_session" => self.connection_id.is_some() && self.session_id.is_some(),
            // A12.2: identity is not self-declared. A principal that is not a
            // well-formed authenticated reference names no identity, so it
            // leaves the required slot absent.
            "principal" => carries_evidence_reference(self.principal.as_deref()),
            "lease" => self.lease_attempt_id.is_some(),
            "policy_snapshot" => self.policy_snapshot_is_applicable(),
            "requested_route" => self.requested_route.is_some(),
            "actual_route" => self.actual_route.is_some(),
            "invoked_operation" => self.invoked_operation.is_some(),
            "input_handle" => self.input_handle.is_some(),
            "output_handle" => self.output_handle.is_some(),
            "side_effects" => self.side_effects.is_some(),
            "adapter_identity" => self.adapter_identity.is_some(),
            // I16.12 names verifier/artifact results as required trace content
            // and A5.5 keeps finish honestly degraded when no observation route
            // outside the actor's failure domain ran. A well-formed reference is
            // the only thing that satisfies it; its absence leaves the slot
            // missing and the run degraded.
            "verifier_result" => carries_evidence_reference(self.verifier_result.as_deref()),
            "result_receipt" => self.result_digest.is_some() && self.durable_state.is_some(),
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
    /// recorded as evidence. The fence's own policy revision is the fallback:
    /// it is the policy identity the authority decision itself carries.
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
    ///
    /// Only slots I16.12 does NOT name as required trace content belong here,
    /// and only when this path cannot produce them. A required class is never
    /// listed here: an absent required class is a `missing_parts` entry, which
    /// is what the finish decision consults, so diverting one into this list
    /// would hide it from the classification.
    fn unavailable_parts(&self) -> Vec<String> {
        let mut unavailable = Vec::new();
        for (slot, name) in [
            // I16.3 names "adapter instance and process/job-object identity";
            // the adapter half is a required slot above, and the executor half
            // is what this path cannot name when the owner does not.
            (self.executor_identity.is_some(), "executor_identity"),
        ] {
            if !slot {
                unavailable.push(name.to_owned());
            }
        }
        unavailable
    }
}
