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
//! and actual route; the local-port call with observed input/output digests
//! and an exact ORS owner-row reference for retrieving retained bytes; observed
//! side effects; canonical receipts; the finish decision; and an
//! explicit missing-parts list. I16.12 slots this path cannot produce (the
//! semantic principal, a policy snapshot without a policy-bound fence, the
//! Active View/packet manifest, the independent verifier result, and executor
//! identity when the owner does not name one) are enumerated in `unavailable`
//! and `missing_parts`:
//! missing evidence limits replay and is never silently treated as success.
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

/// Canonical trace-manifest format version.
pub const TRACE_MANIFEST_FORMAT_VERSION: u16 = 2;

/// Required manifest slots, in stable enumeration order.
///
/// Every slot must resolve from the admitted envelope, the durable record,
/// the presenting session, or retained execution evidence. An absent
/// required slot lands in [`TraceManifest::missing_parts`] and forces
/// [`TraceFinish::DegradedNoProof`].
pub const TRACE_MANIFEST_REQUIRED_SLOTS: [&str; 18] = [
    "retained_owner_row",
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
    "adapter_identity",
    "executor_identity",
    "result_receipt",
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
    /// Original request digest paired with `operation_id` for exact ORS row
    /// lookup. That row owns the admitted payload and retained result bytes.
    pub retained_request_digest: Option<String>,
    /// Daemon-claimable lane that served the read (`query`, `campaign-packet`).
    pub lane: Option<String>,
    /// Admitted capability name (Task/Action contract selector).
    pub capability: Option<String>,
    /// Exact admitted payload-schema identity for the action contract.
    pub action_contract_ref: Option<String>,
    /// Whether the referenced ORS owner row retains the exact admitted bytes.
    pub admitted_payload_retained: bool,
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
    /// Semantic principal (resolved by eliotd, never by Kernel).
    pub principal: Option<String>,
    /// Policy revision snapshot, when the fence is policy-bound.
    pub policy_snapshot: Option<String>,
    /// Active View/packet manifest reference.
    pub active_view_packet_manifest: Option<String>,
    /// Independent verifier/artifact result.
    pub verifier_result: Option<String>,
    /// Canonical digest over the exact bounded response bytes.
    pub result_digest: Option<String>,
    /// Whether the referenced ORS owner row retains the exact result bytes.
    pub result_bytes_retained: bool,
    /// Canonical semantic receipt retained with the exact result, if any.
    pub result_receipt: Option<String>,
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
    /// Binds durable identity and result evidence, the executor-observed
    /// evidence as it was RETAINED on the durable record, and the persisted
    /// receipt. Required slots without
    /// a value land in `missing_parts` and force
    /// [`TraceFinish::DegradedNoProof`]; only a manifest with every required
    /// evidence item seals [`TraceFinish::VerifiedComplete`]. Call sites run only after the ORS
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
        _session: &Session,
        _body: &HostRequestResultBody,
        persisted: &HostRequestRecord,
        _envelope: Option<&HostRequestEnvelope>,
        lane: &'static str,
    ) -> Self {
        let capability = Some(persisted.capability_ref.as_str().to_owned());
        let payload_digest = Some(persisted.payload_digest.clone());
        let state_fence = persisted.admitted_state_fence.clone();
        let session_id = persisted
            .session_ref
            .as_ref()
            .map(|session| session.as_str().to_owned());
        let evidence = persisted.result_evidence.as_ref();
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
            trace_id: persisted.request_id.as_str().to_owned(),
            operation_id: persisted.operation_id.as_str().to_owned(),
            retained_request_digest: Some(persisted.request_digest.clone()),
            lane: Some(lane.to_owned()),
            capability: capability.clone(),
            action_contract_ref: persisted
                .payload_schema_id
                .as_ref()
                .map(|schema| schema.as_str().to_owned()),
            admitted_payload_retained: persisted.payload_body.is_some(),
            payload_digest,
            state_fence,
            connection_id: Some(persisted.connection_ref.as_str().to_owned()),
            session_id,
            task_id: persisted
                .task_ref
                .as_ref()
                .map(|task| task.as_str().to_owned()),
            work_scope_id: persisted
                .scope_ref
                .as_ref()
                .map(|scope| scope.as_str().to_owned()),
            lease_attempt_id: persisted
                .attempt
                .as_ref()
                .map(|attempt| attempt.attempt_id.clone()),
            fencing_generation: persisted
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
            principal: None,
            policy_snapshot,
            active_view_packet_manifest: None,
            verifier_result: None,
            result_digest: persisted.result_digest.clone(),
            result_bytes_retained: persisted.result_response.is_some(),
            result_receipt: persisted
                .result_lineage
                .as_ref()
                .and_then(|lineage| lineage.semantic_receipt_ref.clone()),
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
            .filter(|manifest| manifest.records_supported_completion(operation_id))
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
    fn records_supported_completion(&self, operation_id: &str) -> bool {
        if self.format_version != TRACE_MANIFEST_FORMAT_VERSION
            || operation_id.trim().is_empty()
            || self.operation_id.trim().is_empty()
            || self.operation_id != operation_id
        {
            return false;
        }

        let missing = self.missing_parts();
        self.missing_parts == missing
            && self.unavailable == self.unavailable_parts()
            && (!self.finish.is_complete() || missing.is_empty())
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
            "retained_owner_row" => {
                nonblank(&self.operation_id)
                    && self
                        .retained_request_digest
                        .as_deref()
                        .is_some_and(nonblank)
            }
            "action_contract" => {
                self.capability.as_deref().is_some_and(nonblank)
                    && self.action_contract_ref.as_deref().is_some_and(nonblank)
                    && self.payload_digest.as_deref().is_some_and(nonblank)
                    && self.admitted_payload_retained
            }
            "state_fence" => self.state_fence.is_some(),
            "active_view_packet_manifest" => self
                .active_view_packet_manifest
                .as_deref()
                .is_some_and(nonblank),
            "principal" => self.principal.as_deref().is_some_and(nonblank),
            // A1 names caller AND session: the presenting transport
            // connection alone does not identify the semantic caller, so
            // withholding the session leaves the slot absent.
            "caller_session" => {
                self.connection_id.as_deref().is_some_and(nonblank)
                    && self.session_id.as_deref().is_some_and(nonblank)
            }
            "lease" => {
                self.lease_attempt_id.as_deref().is_some_and(nonblank)
                    && self.fencing_generation.is_some()
            }
            "policy_snapshot" => self.policy_snapshot.as_deref().is_some_and(nonblank),
            "requested_route" => self.requested_route.as_deref().is_some_and(nonblank),
            "actual_route" => self.actual_route.as_deref().is_some_and(nonblank),
            "invoked_operation" => self.invoked_operation.as_deref().is_some_and(nonblank),
            "input_handle" => self.input_handle.as_deref().is_some_and(nonblank),
            "output_handle" => self.output_handle.as_deref().is_some_and(nonblank),
            "side_effects" => self.side_effects.as_deref().is_some_and(nonblank),
            "adapter_identity" => self.adapter_identity.as_deref().is_some_and(nonblank),
            "executor_identity" => self.executor_identity.as_deref().is_some_and(nonblank),
            "result_receipt" => {
                self.result_digest.as_deref().is_some_and(nonblank)
                    && self.result_bytes_retained
                    && self.result_receipt.as_deref().is_some_and(nonblank)
                    && self.durable_state.as_deref().is_some_and(nonblank)
            }
            "verifier_result" => self.verifier_result.as_deref().is_some_and(nonblank),
            _ => false,
        }
    }

    /// Returns the I16.12 evidence slots this path cannot produce.
    fn unavailable_parts(&self) -> Vec<String> {
        let mut unavailable = Vec::new();
        for (slot, name) in [
            (self.principal.is_some(), "principal"),
            (self.policy_snapshot.is_some(), "policy_snapshot"),
            (
                self.active_view_packet_manifest.is_some(),
                "active_view_packet_manifest",
            ),
            (self.verifier_result.is_some(), "verifier_result"),
            (self.executor_identity.is_some(), "executor_identity"),
        ] {
            if !slot {
                unavailable.push(name.to_owned());
            }
        }
        unavailable
    }
}

fn nonblank(value: &str) -> bool {
    !value.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::{TRACE_MANIFEST_FORMAT_VERSION, TraceFinish, TraceManifest};
    use crate::kernel_audit::{
        AuditAssuranceClass, AuditCaptureMode, AuditEventKind, AuditLineage, AuditRecord,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use std::num::NonZeroU64;

    fn state_fence() -> StateFence {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("valid epoch lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(7).expect("nonzero epoch"))
            .expect("valid epoch");
        StateFence::new(epoch, ResourceGeneration::new(3).expect("nonzero generation"))
    }

    fn absent_evidence_manifest() -> TraceManifest {
        TraceManifest {
            format_version: TRACE_MANIFEST_FORMAT_VERSION,
            trace_id: "request:trace-test".to_owned(),
            operation_id: "hostreq:trace-test".to_owned(),
            retained_request_digest: Some("request-digest".to_owned()),
            lane: Some("query".to_owned()),
            capability: Some("eliot.query".to_owned()),
            action_contract_ref: Some("eliot.query.v1".to_owned()),
            admitted_payload_retained: true,
            payload_digest: Some("payload-digest".to_owned()),
            state_fence: Some(state_fence()),
            connection_id: Some("connection:trace-test".to_owned()),
            session_id: Some("session:trace-test".to_owned()),
            task_id: None,
            work_scope_id: None,
            lease_attempt_id: Some("attempt:trace-test".to_owned()),
            fencing_generation: Some(1),
            authority_epoch: Some("550e8400-e29b-41d4-a716-446655440000:7".to_owned()),
            module_generation: Some("3".to_owned()),
            requested_route: Some("eliot.query".to_owned()),
            actual_route: Some("route-receipt".to_owned()),
            invoked_operation: Some("local_read".to_owned()),
            input_handle: Some("request-digest".to_owned()),
            output_handle: Some("result-digest".to_owned()),
            adapter_identity: Some("adapter:trace-test".to_owned()),
            executor_identity: Some("executor:trace-test".to_owned()),
            side_effects: Some("none".to_owned()),
            principal: None,
            policy_snapshot: None,
            active_view_packet_manifest: None,
            verifier_result: None,
            result_digest: Some("result-digest".to_owned()),
            result_bytes_retained: true,
            result_receipt: None,
            durable_state: Some("ResultReceived".to_owned()),
            finish: TraceFinish::DegradedNoProof,
            missing_parts: Vec::new(),
            unavailable: Vec::new(),
        }
    }

    fn seal_record(manifest: &TraceManifest) -> AuditRecord {
        let mut lineage = AuditLineage::empty();
        lineage.operation_id = Some(manifest.operation_id.clone());
        AuditRecord {
            format_version: 1,
            chain_id: "chain:trace-test".to_owned(),
            seq: 1,
            prev_hash: "0".repeat(64),
            kind: AuditEventKind::TRACE_MANIFEST_SEALED.to_owned(),
            lineage,
            event_digest: "event-digest".to_owned(),
            event_body: serde_json::to_value(manifest).expect("manifest serializes"),
            assurance: AuditAssuranceClass::Critical,
            capture_mode: AuditCaptureMode::Full,
            emitted_at_ms: 1,
            current_hash: "record-hash".to_owned(),
        }
    }

    #[test]
    fn find_sealed_replays_degraded_manifest_with_exact_missing_evidence() {
        let mut manifest = absent_evidence_manifest();
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        let records = [seal_record(&manifest)];

        let replay = TraceManifest::find_sealed(&records, &manifest.operation_id)
            .expect("honest degraded trace remains replayable");

        assert_eq!(replay.finish, TraceFinish::DegradedNoProof);
        assert_eq!(replay, manifest);
        assert!(replay.state_fence.is_some());
        for required in ["principal", "active_view_packet_manifest", "verifier_result"] {
            assert!(replay.missing_parts.iter().any(|part| part == required));
        }
    }

    #[test]
    fn find_sealed_refuses_withheld_required_evidence_claimed_complete() {
        let mut manifest = absent_evidence_manifest();
        manifest.finish = TraceFinish::VerifiedComplete;
        manifest.missing_parts.clear();
        manifest.unavailable = manifest.unavailable_parts();
        let records = [seal_record(&manifest)];

        assert!(TraceManifest::find_sealed(&records, &manifest.operation_id).is_none());

        manifest.operation_id.clear();
        let records = [seal_record(&manifest)];
        assert!(TraceManifest::find_sealed(&records, "hostreq:trace-test").is_none());
    }
}
