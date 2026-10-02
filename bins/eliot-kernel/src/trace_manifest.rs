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
use eliot_ors::HostRequestRecord;
use eliot_protocol::{HostRequestEnvelope, HostRequestResultBody};
use serde::{Deserialize, Serialize};

use crate::kernel_audit::{AuditEventKind, AuditRecord, authority_epoch_text};
use crate::sha256_json;

/// Canonical trace-manifest format version.
///
/// Version 2 enforces the full I16.12 evidence set. Original version-1 bodies
/// remain in the audit chain but are unsupported for replay; their earlier
/// completion claims are never rewritten to manufacture current proof.
pub const TRACE_MANIFEST_FORMAT_VERSION: u16 = 2;

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
    #[must_use]
    pub fn seal(
        session: &Session,
        body: &HostRequestResultBody,
        persisted: &HostRequestRecord,
        envelope: Option<&HostRequestEnvelope>,
        lane: &'static str,
        principal: Option<&str>,
        active_view_packet_manifest: Option<&str>,
    ) -> Self {
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
        let policy_snapshot = Self::retained_policy_snapshot(persisted, state_fence.as_ref());
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
            principal: principal.map(str::to_owned),
            policy_snapshot,
            active_view_packet_manifest: if lane == "campaign-packet" {
                active_view_packet_manifest.map(str::to_owned)
            } else {
                None
            },
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

    fn retained_policy_snapshot(
        persisted: &HostRequestRecord,
        state_fence: Option<&StateFence>,
    ) -> Option<String> {
        persisted
            .result_lineage
            .as_ref()
            .and_then(|lineage| lineage.policy_fence.as_ref())
            .filter(|policy_fence| state_fence == Some(&policy_fence.state_fence))
            .map(|policy_fence| policy_fence.policy_snapshot_id.clone())
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
            "policy_snapshot" => has_text_option(self.policy_snapshot.as_deref()),
            "active_view_packet_manifest" => {
                has_text_option(self.active_view_packet_manifest.as_deref())
            }
            "verifier_result" => has_text_option(self.verifier_result.as_deref()),
            _ => false,
        }
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
