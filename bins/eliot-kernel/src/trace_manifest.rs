//! Canonical replayable trace manifests for Material/Critical work (issue #1838).
//!
//! Architecture: I16.3 composite run trace context, I16.4 required
//! operational events, I16.12 trace completeness with explicit missing parts;
//! A10.8 honest finish vocabulary.
//!
//! A [`TraceManifest`] is the Kernel-owned replayable record for one bound
//! result, keyed by trace/operation ID. It binds exactly the evidence classes
//! I16.12 names for a replayable Material/Critical trace: the Task/Action
//! contract and State Fence; the Active View/packet manifest; the principal,
//! the presenting caller with its semantic Session, the lease attempt, and the
//! policy snapshot; the requested and actual route with the invoked local-port
//! operation and its immutable input/output handles; the observed side effects;
//! the verifier/artifact result; the canonical receipt; and the finish
//! decision.
//!
//! Every one of those classes is a [`TRACE_MANIFEST_REQUIRED_SLOTS`] name, so
//! a class the run did not produce is named in `missing_parts` and forces
//! [`TraceFinish::DegradedNoProof`] instead of being reported as an
//! unqualified success (I16.12: missing trace "does not invent failure or
//! success"). The executor identity — the one I16.12 class this path cannot
//! produce when the owner does not name one, and which I16.12 does not name as
//! its own class — is enumerated in `unavailable`.
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
//! carried by the slots that body itself records. The production reader is the
//! problem-diagnostic projection
//! ([`crate::diagnostic_brief::compile_diagnostic_brief`]), which replays the
//! newest sealed manifest onto the brief an operator reads.
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
use eliot_ors::HostRequestRecord;
use eliot_protocol::{HostRequestEnvelope, HostRequestResultBody};
use serde::{Deserialize, Serialize};

use crate::kernel_audit::{AuditEventKind, AuditRecord, authority_epoch_text};

/// Canonical trace-manifest format version.
pub const TRACE_MANIFEST_FORMAT_VERSION: u16 = 1;

/// Required manifest slots, in stable enumeration order.
///
/// One name per I16.12 evidence class, including the four the earlier cut left
/// out of this set: `active_view_packet_manifest` (the Active View/packet
/// manifest), `principal` and `policy_snapshot` (principal and policy
/// snapshots), and `verifier_result` (verifier/artifact results). Every slot
/// must resolve from the admitted envelope, the durable record, the presenting
/// session, or the submitted execution evidence. An absent required slot lands
/// in [`TraceManifest::missing_parts`] and forces
/// [`TraceFinish::DegradedNoProof`].
pub const TRACE_MANIFEST_REQUIRED_SLOTS: [&str; 16] = [
    "action_contract",
    "state_fence",
    "active_view_packet_manifest",
    "principal",
    "caller_session",
    "lease",
    "policy_snapshot",
    "requested_route",
    "actual_route",
    "invoked_operation",
    "input_handle",
    "output_handle",
    "side_effects",
    "verifier_result",
    "adapter_identity",
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
    /// Semantic principal, from the durable result lineage's authenticated
    /// producer reference (resolved by eliotd, never by Kernel).
    pub principal: Option<String>,
    /// Policy revision snapshot, when the fence is policy-bound.
    pub policy_snapshot: Option<String>,
    /// Active View/packet manifest reference: the admitted campaign-view
    /// publication identity carried by a packet result.
    pub active_view_packet_manifest: Option<String>,
    /// Verifier/artifact result: the durable result lineage's immutable
    /// output artifact handle.
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
    /// evidence as it was RETAINED on the durable record, the durable result
    /// lineage, and the persisted receipt. Required slots without a value land
    /// in `missing_parts` and force [`TraceFinish::DegradedNoProof`]; anything
    /// else seals [`TraceFinish::VerifiedComplete`]. Call sites run only after
    /// the ORS persist, so the seal never precedes the binding it describes.
    ///
    /// The evidence is read from `persisted`, not from the submitted body
    /// (issue #1853 W2). The manifest is a projection of the durable record,
    /// and the ORS row is the single owner of the observation: a manifest can
    /// therefore never claim an executor observation that recovery cannot also
    /// read back from the row, and the sealed body and the durable row can never
    /// disagree about what was observed.
    ///
    /// The four classes the earlier cut wrote as literal `None` are bound from
    /// the same two production inputs. `principal` and `verifier_result` read
    /// the durable result lineage the completion retained — its authenticated
    /// producer reference and its immutable output artifact handle, which are
    /// the principal and the verifier/artifact result I16.12 names.
    /// `policy_snapshot` reads the bound State Fence's policy revision.
    /// `active_view_packet_manifest` reads the admitted campaign-view
    /// publication identity out of the exact result bytes. A run that retained
    /// none of them withholds the class, so the required set reports it in
    /// `missing_parts` and the run seals `DEGRADED_NO_PROOF`; the seal never
    /// substitutes a value it did not observe.
    #[must_use]
    pub fn seal(
        session: &Session,
        body: &HostRequestResultBody,
        persisted: &HostRequestRecord,
        envelope: Option<&HostRequestEnvelope>,
        lane: &'static str,
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
        // The durable result lineage is the owner's retained read of who
        // produced the bytes and which immutable artifact they are. Both are
        // the exact retained references; an absent one stays absent.
        let lineage = persisted.result_lineage.as_ref();
        let principal = lineage.and_then(|retained| retained.producer_ref.clone());
        let verifier_result =
            lineage.and_then(|retained| retained.output_artifact_ref.clone());
        // The Active View/packet manifest is the admitted campaign-view
        // publication the result carries; the result leg that admits it has
        // already proved it against the stored capability, task, scope, and
        // fence. The identity is read from the exact sealed response bytes.
        let active_view_packet_manifest = body
            .response
            .get("campaign_learning_state_view")
            .and_then(|publication| publication.get("view_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let policy_snapshot = state_fence.as_ref().and_then(|fence| {
            fence
                .policy_revision
                .map(|revision| revision.value().to_string())
        });
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
            principal,
            policy_snapshot,
            active_view_packet_manifest,
            verifier_result,
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
    /// The production reader is
    /// [`crate::diagnostic_brief::compile_diagnostic_brief`], which calls this
    /// for the newest sealed operation on the retained chain and carries the
    /// decoded body into the brief an operator reads.
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
    ///
    /// One arm per [`TRACE_MANIFEST_REQUIRED_SLOTS`] name, so the required set
    /// has exactly one declaration of what each class means. The four I16.12
    /// classes the earlier cut left outside that set resolve here like every
    /// other one: with no value the class is absent, it lands in
    /// [`TraceManifest::missing_parts`], and the run seals
    /// [`TraceFinish::DegradedNoProof`] instead of an unqualified success.
    fn required_slot_present(&self, slot: &str) -> bool {
        match slot {
            "action_contract" => self.capability.is_some() && self.payload_digest.is_some(),
            "state_fence" => self.state_fence.is_some(),
            "active_view_packet_manifest" => self.active_view_packet_manifest.is_some(),
            "principal" => self.principal.is_some(),
            // A1 names caller AND session: the presenting transport
            // connection alone does not identify the semantic caller, so
            // withholding the session leaves the slot absent.
            "caller_session" => self.connection_id.is_some() && self.session_id.is_some(),
            "lease" => self.lease_attempt_id.is_some(),
            "policy_snapshot" => self.policy_snapshot.is_some(),
            "requested_route" => self.requested_route.is_some(),
            "actual_route" => self.actual_route.is_some(),
            "invoked_operation" => self.invoked_operation.is_some(),
            "input_handle" => self.input_handle.is_some(),
            "output_handle" => self.output_handle.is_some(),
            "side_effects" => self.side_effects.is_some(),
            "verifier_result" => self.verifier_result.is_some(),
            "adapter_identity" => self.adapter_identity.is_some(),
            "result_receipt" => self.result_digest.is_some() && self.durable_state.is_some(),
            _ => false,
        }
    }

    /// Returns the I16.12 evidence slots this path cannot produce.
    ///
    /// The executor identity is the only remaining one: I16.12 names no such
    /// class of its own, so its absence limits replay without making the run
    /// incomplete. Every class I16.12 does name is a required slot, so a
    /// withheld one is reported by [`TraceManifest::missing_parts`] and is
    /// never diverted into this list instead.
    fn unavailable_parts(&self) -> Vec<String> {
        let mut unavailable = Vec::new();
        if self.executor_identity.is_none() {
            unavailable.push("executor_identity".to_owned());
        }
        unavailable
    }
}
