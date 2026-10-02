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
//! explicit missing-parts list. I16.12 slots absent on this result (for
//! example, the Active View/packet manifest, the independent verifier result,
//! or executor identity when
//! the owner does not name one) are enumerated in `unavailable`
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
use eliot_ors::{HostRequestKind as OrsHostRequestKind, HostRequestRecord};
use eliot_protocol::{
    AgentActivationResolutionResult, HOST_REQUEST_INVOKE_READ_WIRE_ID, HostRequestEnvelope,
    HostRequestInvokeReadPayload, HostRequestResultBody, LocalReadAttempt,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::kernel_audit::{AuditEventKind, AuditLineage, AuditRecord, authority_epoch_text};

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
    /// Fencing generation of the ORS claim attempt.
    pub fencing_generation: Option<u64>,
    /// Exact fenced local-read attempt retained with the original completion.
    /// This remains a distinct identity from the ORS claim attempt above.
    pub local_read_attempt: Option<LocalReadAttempt>,
    /// Authority epoch `lineage_id:sequence` text.
    pub authority_epoch: Option<String>,
    /// Module/process generation text.
    pub module_generation: Option<String>,
    /// Requested route (capability selector).
    pub requested_route: Option<String>,
    /// Actual route receipt digest, bound to its retained original receipt body.
    pub actual_route: Option<String>,
    /// Exact original receipt body that carries the observed local-read route.
    pub actual_route_receipt: Option<Value>,
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
    /// Semantic principal from the original retained activation result.
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
    /// Original canonical Kernel audit record binding the persisted result.
    /// This is distinct from a semantic receipt and remains replayable only
    /// when the exact record precedes this manifest in the same audit chain.
    pub result_binding_receipt: Option<AuditRecord>,
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
        result_binding_receipt: Option<&AuditRecord>,
    ) -> Self {
        // This is a read model of the original ORS owner row. Validate its
        // retained bindings before projecting any of its claims; if the row
        // is contradictory, the seal records no owner evidence and cannot
        // make a proof-bearing completion claim.
        let owner_row_valid = persisted.validate().is_ok();
        let capability = owner_row_valid
            .then(|| persisted.capability_ref.as_str().to_owned());
        let payload_digest = owner_row_valid.then(|| persisted.payload_digest.clone());
        let admitted_envelope = owner_row_valid
            .then(|| original_admitted_envelope(persisted))
            .flatten();
        let state_fence = owner_row_valid
            .then(|| persisted.admitted_state_fence.clone())
            .flatten()
            .or_else(|| admitted_envelope.as_ref().map(|envelope| envelope.state_fence.clone()));
        let session_id = owner_row_valid
            .then(|| persisted.session_ref.as_ref())
            .flatten()
            .map(|session| session.as_str().to_owned());
        let evidence = owner_row_valid
            .then_some(persisted.result_evidence.as_ref())
            .flatten();
        let principal = evidence
            .and_then(|evidence| evidence.activation_resolution_result.clone())
            .and_then(|value| serde_json::from_value::<AgentActivationResolutionResult>(value).ok())
            .filter(|result| {
                result.validate().is_ok()
                    && admitted_envelope.as_ref().is_some_and(|envelope| {
                        activation_result_matches_envelope(result, envelope)
                    })
            })
            .and_then(|result| {
                result
                    .resolved_binding()
                    .map(|binding| binding.principal_id.clone())
            });
        let local_read_attempt = evidence
            .and_then(|evidence| evidence.local_read_attempt.clone())
            .and_then(|value| serde_json::from_value::<LocalReadAttempt>(value).ok())
            .filter(|attempt| {
                admitted_envelope.as_ref().is_some_and(|envelope| {
                    local_read_attempt_matches_row(attempt, envelope, persisted)
                })
            });
        let requested_route = admitted_envelope
            .as_ref()
            .map(|envelope| envelope.identity.capability.clone());
        let input_handle = evidence
            .and_then(|evidence| evidence.input_handle.as_deref())
            .filter(|handle| {
                admitted_envelope.is_some() && *handle == persisted.request_digest.as_str()
            })
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
            trace_id: persisted.request_id.as_str().to_owned(),
            operation_id: persisted.operation_id.as_str().to_owned(),
            retained_request_digest: owner_row_valid.then(|| persisted.request_digest.clone()),
            lane: Some(lane.to_owned()),
            capability: capability.clone(),
            action_contract_ref: owner_row_valid
                .then(|| persisted.payload_schema_id.as_ref())
                .flatten()
                .map(|schema| schema.as_str().to_owned()),
            admitted_payload_retained: exact_admitted_payload_retained(
                owner_row_valid,
                admitted_envelope.is_some(),
                persisted.payload_body.is_some(),
            ),
            payload_digest,
            state_fence,
            connection_id: owner_row_valid
                .then(|| persisted.connection_ref.as_str().to_owned()),
            session_id,
            task_id: owner_row_valid
                .then(|| persisted.task_ref.as_ref())
                .flatten()
                .map(|task| task.as_str().to_owned()),
            work_scope_id: owner_row_valid
                .then(|| persisted.scope_ref.as_ref())
                .flatten()
                .map(|scope| scope.as_str().to_owned()),
            // This slot names the original ORS claim lease. It remains distinct
            // from the LocalReadAttempt carried by a result submission.
            lease_attempt_id: owner_row_valid
                .then(|| persisted.attempt.as_ref())
                .flatten()
                .map(|attempt| attempt.attempt_id.clone()),
            fencing_generation: owner_row_valid
                .then(|| persisted.attempt.as_ref())
                .flatten()
                .map(|attempt| attempt.generation),
            local_read_attempt,
            authority_epoch,
            module_generation,
            // Requested route and input handle require the original retained
            // admitted envelope bytes. The ORS capability label and a bare
            // input digest do not stand in for that owner source.
            requested_route,
            actual_route: None,
            actual_route_receipt: None,
            invoked_operation: evidence.and_then(|evidence| evidence.invoked_operation.clone()),
            input_handle,
            output_handle: evidence.and_then(|evidence| evidence.output_handle.clone()),
            adapter_identity: evidence.and_then(|evidence| evidence.adapter_identity.clone()),
            executor_identity: evidence.and_then(|evidence| evidence.executor_identity.clone()),
            side_effects: evidence.and_then(|evidence| evidence.side_effects.clone()),
            principal,
            policy_snapshot,
            active_view_packet_manifest: None,
            verifier_result: None,
            result_digest: owner_row_valid
                .then(|| persisted.result_digest.clone())
                .flatten(),
            result_bytes_retained: owner_row_valid && persisted.result_response.is_some(),
            result_receipt: owner_row_valid
                .then(|| persisted.result_lineage.as_ref())
                .flatten()
                .and_then(|lineage| lineage.semantic_receipt_ref.clone()),
            result_binding_receipt: None,
            durable_state: owner_row_valid.then(|| format!("{:?}", persisted.state)),
            finish: TraceFinish::VerifiedComplete,
            missing_parts: Vec::new(),
            unavailable: Vec::new(),
        };
        if let Some(evidence) = evidence {
            // Retain the owner's original fields verbatim. The slot validates
            // the digest/body pair; a malformed present body stays visible and
            // is refused during replay instead of being rewritten as absence.
            manifest.actual_route.clone_from(&evidence.actual_route);
            manifest
                .actual_route_receipt
                .clone_from(&evidence.actual_route_receipt);
        }
        // Keep any supplied original record verbatim. A contradictory record
        // is a replay refusal, not an absent slot that can be downgraded into
        // an apparently ordinary degraded manifest.
        manifest.result_binding_receipt = result_binding_receipt.cloned();
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
    /// Scans verified retained chain records for the newest
    /// `trace.manifest_sealed` entry bound to `operation_id` and decodes its
    /// sealed body. Returns `None` when no seal exists, when the sealed body
    /// does not decode, when it carries a foreign
    /// [`TRACE_MANIFEST_FORMAT_VERSION`], or when the recorded completion
    /// claim is not supported by the slots that very body records: replay is
    /// then limited, never invented.
    ///
    /// A result-binding receipt must be the exact original record in the same
    /// chain prefix before the seal; it is never rebuilt from row digests.
    /// The check otherwise reads only the recorded body and never re-derives
    /// classification from live request state.
    #[must_use]
    pub fn find_sealed(records: &[AuditRecord], operation_id: &str) -> Option<Self> {
        records
            .iter()
            .enumerate()
            .rev()
            .find(|(_, record)| {
                record.kind == AuditEventKind::TRACE_MANIFEST_SEALED
                    && record.lineage.operation_id.as_deref() == Some(operation_id)
            })
            .and_then(|(seal_index, record)| {
                let manifest: Self = serde_json::from_value(record.event_body.clone()).ok()?;
                (manifest.records_supported_completion(operation_id)
                    && manifest.matches_sealed_lineage(&record.lineage)
                    && manifest.has_original_binding_receipt_before(&records[..seal_index], record))
                .then_some(manifest)
            })
    }

    /// Returns true when the recorded completion claim is carried by the
    /// recorded required slots.
    ///
    /// The finish must exactly reflect the required slots this format can
    /// produce: `VERIFIED_COMPLETE` when none are missing and
    /// `DEGRADED_NO_PROOF` when any are missing. Other finish states belong to
    /// lifecycle owners and are not produced by this result-binding path.
    fn records_supported_completion(&self, operation_id: &str) -> bool {
        if self.format_version != TRACE_MANIFEST_FORMAT_VERSION
            || operation_id.trim().is_empty()
            || self.operation_id.trim().is_empty()
            || self.operation_id != operation_id
            || !nonblank(&self.trace_id)
            || !self.projection_is_consistent()
        {
            return false;
        }

        let missing = self.missing_parts();
        let expected_finish = if missing.is_empty() {
            TraceFinish::VerifiedComplete
        } else {
            TraceFinish::DegradedNoProof
        };
        self.missing_parts == missing
            && self.unavailable == self.unavailable_parts()
            && self.finish == expected_finish
    }

    /// Checks that the audit envelope repeats the identity and authority
    /// values bound by the sealed manifest body.
    fn matches_sealed_lineage(&self, lineage: &AuditLineage) -> bool {
        lineage.trace_id.as_deref() == Some(self.trace_id.as_str())
            && lineage.operation_id.as_deref() == Some(self.operation_id.as_str())
            && lineage.work_item.as_deref() == Some(self.operation_id.as_str())
            && lineage.task_id.as_deref() == self.task_id.as_deref()
            && lineage.session_id.as_deref() == self.session_id.as_deref()
            && lineage.work_scope.as_deref() == self.work_scope_id.as_deref()
            && lineage.attempt_id.as_deref()
                == self
                    .lease_attempt_id
                    .as_deref()
                    .or_else(|| {
                        self.local_read_attempt
                            .as_ref()
                            .map(|attempt| attempt.attempt_id.as_str())
                    })
            && lineage.environment_lease.as_deref()
                == self
                    .lease_attempt_id
                    .as_deref()
                    .or_else(|| {
                        self.local_read_attempt
                            .as_ref()
                            .map(|attempt| attempt.attempt_id.as_str())
                    })
            && lineage.state_fence == self.state_fence
            && lineage.adapter_instance.as_deref() == self.adapter_identity.as_deref()
            && lineage.process_identity.as_deref() == self.executor_identity.as_deref()
            && lineage.principal.as_deref() == self.principal.as_deref()
            && lineage.route_receipt_requested.as_deref() == self.requested_route.as_deref()
            && lineage.route_receipt_actual.as_deref() == self.actual_route.as_deref()
            && lineage.module_generation.as_deref() == self.module_generation.as_deref()
            && lineage.authority_epoch.as_deref() == self.authority_epoch.as_deref()
            && lineage.controller.as_deref() == Some("kernel")
    }

    /// Rejects malformed claims before a missing-evidence classification is
    /// accepted. A well-formed absence remains replayable as degraded, while
    /// contradictory duplicates cannot be reclassified as mere absence.
    fn projection_is_consistent(&self) -> bool {
        [
            self.lane.as_deref(),
            self.capability.as_deref(),
            self.action_contract_ref.as_deref(),
            self.retained_request_digest.as_deref(),
            self.payload_digest.as_deref(),
            self.connection_id.as_deref(),
            self.session_id.as_deref(),
            self.task_id.as_deref(),
            self.work_scope_id.as_deref(),
            self.lease_attempt_id.as_deref(),
            self.authority_epoch.as_deref(),
            self.module_generation.as_deref(),
            self.requested_route.as_deref(),
            self.actual_route.as_deref(),
            self.invoked_operation.as_deref(),
            self.input_handle.as_deref(),
            self.output_handle.as_deref(),
            self.adapter_identity.as_deref(),
            self.executor_identity.as_deref(),
            self.side_effects.as_deref(),
            self.principal.as_deref(),
            self.policy_snapshot.as_deref(),
            self.active_view_packet_manifest.as_deref(),
            self.result_digest.as_deref(),
            self.result_receipt.as_deref(),
            self.durable_state.as_deref(),
            self.verifier_result.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(nonblank)
            && self
                .retained_request_digest
                .as_deref()
                .is_none_or(|digest| {
                    is_lowercase_sha256(digest)
                        && self.operation_id == format!("hostreq:{digest}")
                })
            && self
                .payload_digest
                .as_deref()
                .is_none_or(is_lowercase_sha256)
            && self.result_digest.as_deref().is_none_or(is_lowercase_sha256)
            && self
                .result_binding_receipt
                .as_ref()
                .is_none_or(|receipt| self.result_binding_receipt_matches(receipt))
            && self.local_read_attempt.as_ref().is_none_or(|attempt| {
                local_read_attempt_matches_manifest(attempt, self)
            })
            && self.input_handle.as_deref().is_none_or(|handle| {
                is_lowercase_sha256(handle)
                    && self.retained_request_digest.as_deref() == Some(handle)
            })
            && self.output_handle.as_deref().is_none_or(|handle| {
                is_lowercase_sha256(handle) && self.result_digest.as_deref() == Some(handle)
            })
            && match (
                self.lease_attempt_id.as_deref(),
                self.fencing_generation,
            ) {
                (None, None) => true,
                (Some(attempt), Some(generation)) => nonblank(attempt) && generation > 0,
                _ => false,
            }
            && match (
                self.capability.as_deref(),
                self.requested_route.as_deref(),
            ) {
                (Some(capability), Some(route)) => capability == route,
                _ => true,
            }
            && match (
                self.actual_route.as_deref(),
                self.actual_route_receipt.as_ref(),
            ) {
                (Some(digest), Some(receipt)) => self.route_receipt_matches(digest, receipt),
                (Some(digest), None) => is_lowercase_sha256(digest),
                (None, None) => true,
                (None, Some(_)) => false,
            }
            && self.fence_snapshot_is_consistent()
    }

    /// Checks that a retained State Fence and its denormalized identity fields
    /// describe the same original snapshot.
    fn fence_snapshot_is_consistent(&self) -> bool {
        let Some(fence) = self.state_fence.as_ref() else {
            return self.authority_epoch.is_none()
                && self.module_generation.is_none()
                && self.policy_snapshot.is_none();
        };
        if fence.validate().is_err() {
            return false;
        }
        let authority_epoch = authority_epoch_text(&fence.authority_epoch);
        let module_generation = fence.resource_generation.value().to_string();
        let policy_snapshot = fence
            .policy_revision
            .map(|revision| revision.value().to_string());
        self.authority_epoch.as_deref() == Some(authority_epoch.as_str())
            && self.module_generation.as_deref() == Some(module_generation.as_str())
            && self.policy_snapshot.as_deref() == policy_snapshot.as_deref()
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
                nonblank(&self.trace_id)
                    && self
                        .retained_request_digest
                        .as_deref()
                        .is_some_and(|digest| {
                            is_lowercase_sha256(digest)
                                && self.operation_id == format!("hostreq:{digest}")
                        })
            }
            "action_contract" => {
                self.capability.as_deref().is_some_and(nonblank)
                    && self.action_contract_ref.as_deref().is_some_and(nonblank)
                    && self
                        .payload_digest
                        .as_deref()
                        .is_some_and(is_lowercase_sha256)
                    && self.admitted_payload_retained
            }
            "state_fence" => self.state_fence.is_some() && self.fence_snapshot_is_consistent(),
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
                (self.lease_attempt_id.as_deref().is_some_and(nonblank)
                    && self.fencing_generation.is_some_and(|generation| generation > 0))
                    || self
                        .local_read_attempt
                        .as_ref()
                        .is_some_and(|attempt| local_read_attempt_matches_manifest(attempt, self))
            }
            "policy_snapshot" => {
                self.policy_snapshot.as_deref().is_some_and(nonblank)
                    && self.fence_snapshot_is_consistent()
            }
            "requested_route" => self
                .requested_route
                .as_deref()
                .is_some_and(|route| nonblank(route) && self.capability.as_deref() == Some(route)),
            "actual_route" => self
                .actual_route
                .as_deref()
                .zip(self.actual_route_receipt.as_ref())
                .is_some_and(|(digest, receipt)| self.route_receipt_matches(digest, receipt)),
            "invoked_operation" => self.invoked_operation.as_deref().is_some_and(nonblank),
            "input_handle" => self.input_handle.as_deref().is_some_and(|handle| {
                is_lowercase_sha256(handle)
                    && self.retained_request_digest.as_deref() == Some(handle)
            }),
            "output_handle" => self.output_handle.as_deref().is_some_and(|handle| {
                is_lowercase_sha256(handle) && self.result_digest.as_deref() == Some(handle)
            }),
            "side_effects" => self.side_effects.as_deref().is_some_and(nonblank),
            "adapter_identity" => self.adapter_identity.as_deref().is_some_and(nonblank),
            "executor_identity" => self.executor_identity.as_deref().is_some_and(nonblank),
            "result_receipt" => {
                self.result_digest
                    .as_deref()
                    .is_some_and(is_lowercase_sha256)
                    && self.result_bytes_retained
                    && (self.result_receipt.as_deref().is_some_and(nonblank)
                        || self
                            .result_binding_receipt
                            .as_ref()
                            .is_some_and(|receipt| self.result_binding_receipt_matches(receipt)))
                    && self.durable_state.as_deref().is_some_and(|state| {
                        matches!(state, "ResultReceived" | "Terminal")
                    })
            }
            "verifier_result" => self.verifier_result.as_deref().is_some_and(nonblank),
            _ => false,
        }
    }

    /// Validates the canonical result-binding record against the retained
    /// owner identity, result digests, and original fence.
    fn result_binding_receipt_matches(&self, receipt: &AuditRecord) -> bool {
        let Some(body) = receipt.event_body.as_object() else {
            return false;
        };
        let attempt_id = self
            .local_read_attempt
            .as_ref()
            .map(|attempt| attempt.attempt_id.as_str());
        receipt.kind == AuditEventKind::RESULT_KERNEL_BOUND
            && receipt.assurance
                == crate::kernel_audit::AuditAssuranceClass::Critical
            && receipt.capture_mode == crate::kernel_audit::AuditCaptureMode::Full
            && body.len() == 4
            && body.get("lane").and_then(Value::as_str) == self.lane.as_deref()
            && body.get("request_digest").and_then(Value::as_str)
                == self.retained_request_digest.as_deref()
            && body.get("result_digest").and_then(Value::as_str)
                == self.result_digest.as_deref()
            && body.get("durable_state").and_then(Value::as_str)
                == self.durable_state.as_deref()
            && receipt.lineage.trace_id.as_deref() == Some(self.trace_id.as_str())
            && receipt.lineage.operation_id.as_deref() == Some(self.operation_id.as_str())
            && receipt.lineage.work_item.as_deref() == Some(self.operation_id.as_str())
            && receipt.lineage.task_id.as_deref() == self.task_id.as_deref()
            && receipt.lineage.session_id.as_deref() == self.session_id.as_deref()
            && receipt.lineage.work_scope.as_deref() == self.work_scope_id.as_deref()
            && receipt.lineage.state_fence == self.state_fence
            && receipt.lineage.adapter_instance.as_deref() == self.connection_id.as_deref()
            && receipt.lineage.route_receipt_requested.as_deref()
                == self.requested_route.as_deref()
            && receipt.lineage.attempt_id.as_deref() == attempt_id
            && receipt.lineage.environment_lease.as_deref() == attempt_id
            && receipt.lineage.module_generation.as_deref() == self.module_generation.as_deref()
            && receipt.lineage.authority_epoch.as_deref() == self.authority_epoch.as_deref()
            && receipt.lineage.controller.as_deref() == Some("eliotd")
    }

    /// Requires the exact original binding receipt in the already-verified
    /// chain prefix before this manifest seal.
    fn has_original_binding_receipt_before(
        &self,
        preceding_records: &[AuditRecord],
        seal_record: &AuditRecord,
    ) -> bool {
        self.result_binding_receipt.as_ref().is_none_or(|receipt| {
            receipt.seq > 0
                && receipt.seq < seal_record.seq
                && receipt.chain_id == seal_record.chain_id
                && preceding_records.iter().any(|record| {
                    record == receipt
                        && record.kind == AuditEventKind::RESULT_KERNEL_BOUND
                        && record.seq < seal_record.seq
                        && record.chain_id == seal_record.chain_id
                })
        })
    }

    /// Validates the receipt digest and its original owner bindings.
    fn route_receipt_matches(&self, digest: &str, receipt: &Value) -> bool {
        if !is_lowercase_sha256(digest) {
            return false;
        }
        let Some(object) = receipt.as_object() else {
            return false;
        };
        let Some(response_fence_value) = object.get("state_fence") else {
            return false;
        };
        let Some(response_fence) =
            serde_json::from_value::<StateFence>(response_fence_value.clone()).ok()
        else {
            return false;
        };
        let Some(route_facts) = object.get("route_facts").and_then(Value::as_object) else {
            return false;
        };
        let expected_authority_epoch = serde_json::to_value(&response_fence.authority_epoch).ok();
        let expected_route_fact_keys = [
            "operation",
            "state_fence",
            "route_identity",
            "active_generation",
            "authority_epoch",
            "endpoint",
            "connection_id",
            "approved_artifact_hash",
            "approved_config_hash",
        ];
        if object.len() != 9
            || route_facts.len() != expected_route_fact_keys.len()
            || !expected_route_fact_keys.iter().all(|key| route_facts.contains_key(*key))
            || response_fence.validate().is_err()
            || self.state_fence.as_ref() != Some(&response_fence)
            || self
                .local_read_attempt
                .as_ref()
                .is_some_and(|attempt| attempt.authority_epoch != response_fence.authority_epoch)
            || route_facts.get("state_fence") != Some(response_fence_value)
            || route_facts.get("operation") != object.get("named_operation")
            || object.get("kind").and_then(Value::as_str) != Some("local_read_actual_route")
            || object.get("operation_id").and_then(Value::as_str)
                != Some(self.operation_id.as_str())
            || object.get("request_digest").and_then(Value::as_str)
                != self.retained_request_digest.as_deref()
            || object.get("result_digest").and_then(Value::as_str)
                != self.result_digest.as_deref()
            || self.invoked_operation.as_deref() != Some("local_read")
            || object.get("invoked_operation").and_then(Value::as_str) != Some("local_read")
            || object
                .get("named_operation")
                .and_then(Value::as_str)
                .is_none_or(|operation| !nonblank(operation))
            || route_facts
                .get("active_generation")
                .and_then(Value::as_u64)
                != Some(response_fence.resource_generation.value())
            || route_facts.get("authority_epoch") != expected_authority_epoch.as_ref()
            || route_facts
                .get("connection_id")
                .and_then(Value::as_str)
                != self.adapter_identity.as_deref()
            || route_facts
                .get("approved_artifact_hash")
                .and_then(Value::as_str)
                != self.executor_identity.as_deref()
            || route_facts
                .get("route_identity")
                .and_then(Value::as_str)
                .is_none_or(|identity| !nonblank(identity))
            || route_facts
                .get("endpoint")
                .and_then(Value::as_str)
                .is_none_or(|endpoint| !nonblank(endpoint))
            || route_facts
                .get("approved_artifact_hash")
                .and_then(Value::as_str)
                .is_none_or(|hash| !is_lowercase_sha256(hash))
            || route_facts
                .get("approved_config_hash")
                .and_then(Value::as_str)
                .is_none_or(|hash| !is_lowercase_sha256(hash))
            || object.get("receipt_digest").and_then(Value::as_str) != Some(digest)
        {
            return false;
        }
        let mut unsigned = receipt.clone();
        let Some(unsigned_object) = unsigned.as_object_mut() else {
            return false;
        };
        unsigned_object.remove("receipt_digest");
        crate::sha256_json(&unsigned).is_ok_and(|observed| observed == digest)
    }

    /// Returns every required slot that is unavailable in this run.
    fn unavailable_parts(&self) -> Vec<String> {
        self.missing_parts()
    }
}

fn original_admitted_envelope(persisted: &HostRequestRecord) -> Option<HostRequestEnvelope> {
    let bytes = persisted.admitted_input_bytes.as_deref()?;
    if crate::sha256_hex(bytes) != persisted.request_digest {
        return None;
    }
    let mut envelope: HostRequestEnvelope = serde_json::from_slice(bytes).ok()?;
    if envelope.canonical_unsigned_bytes().ok()?.as_slice() != bytes {
        return None;
    }
    // The owner row already carries the digest of these exact unsigned bytes.
    // Restore that original digest for typed validation instead of minting a
    // new one from a parsed/re-serialized request.
    envelope.envelope_sha256 = persisted.request_digest.clone();
    envelope.validate().ok()?;
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: persisted.payload_body.clone()?,
    }
    .validate()
    .ok()?;
    let identity = &envelope.identity;
    let same_optional = |observed: Option<&str>, expected: Option<&str>| observed == expected;
    if !request_kind_matches_row(envelope.kind, persisted.kind)
        || persisted.operation_id.as_str() != format!("hostreq:{}", persisted.request_digest)
        || identity.request_id.as_str() != persisted.request_id.as_str()
        || identity.idempotency_key != persisted.idempotency_key.as_str()
        || identity.cancellation_id != persisted.cancellation_id.as_str()
        || identity.correlation_projection != persisted.correlation_projection
        || !same_optional(
            identity.parent_operation_id.as_deref(),
            persisted.parent_operation_id.as_ref().map(|value| value.as_str()),
        )
        || identity.deadline_unix_ms != persisted.deadline_unix_ms
        || envelope.connection_id != persisted.connection_ref.as_str()
        || !same_optional(
            identity.session_id.as_deref(),
            persisted.session_ref.as_ref().map(|value| value.as_str()),
        )
        || !same_optional(
            identity.task_id.as_deref(),
            persisted.task_ref.as_ref().map(|value| value.as_str()),
        )
        || !same_optional(
            identity.work_scope_id.as_deref(),
            persisted.scope_ref.as_ref().map(|value| value.as_str()),
        )
        || identity.capability != persisted.capability_ref.as_str()
        || persisted
            .payload_schema_id
            .as_ref()
            .is_none_or(|schema| identity.payload_schema_id != schema.as_str())
        || identity.payload_sha256 != persisted.payload_digest
        || crate::sha256_json(&envelope.state_fence)
            .ok()
            .as_deref()
            != Some(persisted.fence_digest.as_str())
        || persisted
            .admitted_state_fence
            .as_ref()
            .is_some_and(|fence| fence != &envelope.state_fence)
        || envelope.state_fence.authority_epoch != persisted.authority_epoch
        || envelope.state_fence.resource_generation.value() != persisted.generation
    {
        return None;
    }
    Some(envelope)
}

fn request_kind_matches_row(
    request_kind: eliot_protocol::HostRequestKind,
    row_kind: OrsHostRequestKind,
) -> bool {
    match request_kind {
        eliot_protocol::HostRequestKind::Activation => {
            row_kind == OrsHostRequestKind::Activation
        }
        eliot_protocol::HostRequestKind::Invocation => {
            row_kind == OrsHostRequestKind::Invocation
        }
        eliot_protocol::HostRequestKind::Cancellation => {
            row_kind == OrsHostRequestKind::Cancellation
        }
        eliot_protocol::HostRequestKind::Status => row_kind == OrsHostRequestKind::Status,
        eliot_protocol::HostRequestKind::Reconciliation => {
            row_kind == OrsHostRequestKind::Reconciliation
        }
    }
}

fn exact_admitted_payload_retained(
    owner_row_valid: bool,
    original_envelope_valid: bool,
    payload_body_retained: bool,
) -> bool {
    owner_row_valid && original_envelope_valid && payload_body_retained
}

fn activation_result_matches_envelope(
    result: &AgentActivationResolutionResult,
    envelope: &HostRequestEnvelope,
) -> bool {
    let Some(binding) = result.resolved_binding() else {
        return false;
    };
    if envelope.kind != eliot_protocol::HostRequestKind::Invocation
        || envelope
            .identity
            .session_id
            .as_deref()
            .is_none_or(|session| session != binding.session_id.as_str())
        || envelope
            .identity
            .task_id
            .as_deref()
            .is_some_and(|task| task != binding.task_id.as_str())
        || envelope
            .identity
            .work_scope_id
            .as_deref()
            .is_some_and(|scope| scope != binding.work_scope_id.as_str())
        || !envelope
            .state_fence
            .authority_epoch
            .is_same_authority(&result.ticket_state_fence.authority_epoch)
        || envelope.state_fence.resource_generation
            != result.ticket_state_fence.resource_generation
        || envelope
            .state_fence
            .task_revision
            .is_some_and(|revision| binding.task_revision != revision.value().to_string())
        || binding.principal_id.trim().is_empty()
        || binding.principal_id.chars().any(char::is_control)
    {
        return false;
    }
    true
}

fn local_read_attempt_matches_row(
    attempt: &LocalReadAttempt,
    envelope: &HostRequestEnvelope,
    persisted: &HostRequestRecord,
) -> bool {
    if attempt.validate().is_err() {
        return false;
    }
    let Some(scope_id) = envelope
        .identity
        .work_scope_id
        .as_deref()
        .or(envelope.identity.session_id.as_deref())
    else {
        return false;
    };
    let session_id = envelope
        .identity
        .session_id
        .as_deref()
        .or(envelope.identity.work_scope_id.as_deref())
        .unwrap_or(envelope.connection_id.as_str());
    attempt.operation_id == persisted.operation_id.as_str()
        && attempt.session_id == session_id
        && attempt.scope_id == scope_id
        && attempt.facet_method == envelope.identity.capability
        && attempt.authority_epoch == envelope.state_fence.authority_epoch
        && attempt.expires_at_unix_ms == envelope.identity.deadline_unix_ms
        && attempt.expires_at_unix_ms == persisted.deadline_unix_ms
        && attempt.use_budget == 1
}

fn local_read_attempt_matches_manifest(
    attempt: &LocalReadAttempt,
    manifest: &TraceManifest,
) -> bool {
    if attempt.validate().is_err() {
        return false;
    }
    let Some(scope_id) = manifest
        .work_scope_id
        .as_deref()
        .or(manifest.session_id.as_deref())
    else {
        return false;
    };
    let session_id = manifest
        .session_id
        .as_deref()
        .or(manifest.work_scope_id.as_deref())
        .or(manifest.connection_id.as_deref());
    attempt.operation_id == manifest.operation_id
        && Some(attempt.session_id.as_str()) == session_id
        && attempt.scope_id == scope_id
        && Some(attempt.facet_method.as_str()) == manifest.capability.as_deref()
        && manifest
            .state_fence
            .as_ref()
            .is_some_and(|fence| attempt.authority_epoch == fence.authority_epoch)
        && attempt.use_budget == 1
}

fn nonblank(value: &str) -> bool {
    !value.trim().is_empty()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
            operation_id: format!("hostreq:{}", "a".repeat(64)),
            retained_request_digest: Some("a".repeat(64)),
            lane: Some("query".to_owned()),
            capability: Some("eliot.query".to_owned()),
            action_contract_ref: Some("eliot.query.v1".to_owned()),
            admitted_payload_retained: true,
            payload_digest: Some("c".repeat(64)),
            state_fence: Some(state_fence()),
            connection_id: Some("connection:trace-test".to_owned()),
            session_id: Some("session:trace-test".to_owned()),
            task_id: None,
            work_scope_id: None,
            lease_attempt_id: Some("attempt:trace-test".to_owned()),
            fencing_generation: Some(1),
            local_read_attempt: None,
            authority_epoch: Some("550e8400-e29b-41d4-a716-446655440000:7".to_owned()),
            module_generation: Some("3".to_owned()),
            requested_route: Some("eliot.query".to_owned()),
            actual_route: None,
            actual_route_receipt: None,
            invoked_operation: Some("local_read".to_owned()),
            input_handle: None,
            output_handle: Some("b".repeat(64)),
            adapter_identity: Some("adapter:trace-test".to_owned()),
            executor_identity: Some("f".repeat(64)),
            side_effects: Some("none".to_owned()),
            principal: None,
            policy_snapshot: None,
            active_view_packet_manifest: None,
            verifier_result: None,
            result_digest: Some("b".repeat(64)),
            result_bytes_retained: true,
            result_receipt: None,
            result_binding_receipt: None,
            durable_state: Some("ResultReceived".to_owned()),
            finish: TraceFinish::DegradedNoProof,
            missing_parts: Vec::new(),
            unavailable: Vec::new(),
        }
    }

    fn seal_record(manifest: &TraceManifest) -> AuditRecord {
        seal_record_after(manifest, 1, "0".repeat(64))
    }

    fn seal_record_after(
        manifest: &TraceManifest,
        seq: u64,
        previous_hash: String,
    ) -> AuditRecord {
        let mut lineage = AuditLineage::empty();
        lineage.fill_manifest(manifest);
        AuditRecord {
            format_version: 1,
            chain_id: "chain:trace-test".to_owned(),
            seq,
            prev_hash: previous_hash,
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

    fn actual_route_receipt(manifest: &TraceManifest) -> (String, serde_json::Value) {
        let fence = manifest.state_fence.as_ref().expect("manifest has fence");
        let fence_value = serde_json::to_value(fence).expect("fence serializes");
        let route_facts = serde_json::json!({
            "operation": "GetEvidencePack",
            "state_fence": fence_value.clone(),
            "route_identity": "route:evidence-pack",
            "active_generation": fence.resource_generation.value(),
            "authority_epoch": serde_json::to_value(&fence.authority_epoch)
                .expect("epoch serializes"),
            "endpoint": "endpoint:evidence-store",
            "connection_id": manifest.adapter_identity.as_deref(),
            "approved_artifact_hash": manifest.executor_identity.as_deref(),
            "approved_config_hash": "e".repeat(64),
        });
        let mut receipt = serde_json::json!({
            "kind": "local_read_actual_route",
            "operation_id": manifest.operation_id.as_str(),
            "request_digest": manifest.retained_request_digest.as_deref(),
            "result_digest": manifest.result_digest.as_deref(),
            "invoked_operation": "local_read",
            "named_operation": "GetEvidencePack",
            "state_fence": fence_value,
            "route_facts": route_facts,
        });
        let digest = crate::sha256_json(&receipt).expect("receipt digest");
        receipt["receipt_digest"] = serde_json::Value::String(digest.clone());
        (digest, receipt)
    }

    fn result_binding_record(manifest: &TraceManifest) -> AuditRecord {
        let mut lineage = AuditLineage::empty();
        lineage.trace_id = Some(manifest.trace_id.clone());
        lineage.operation_id = Some(manifest.operation_id.clone());
        lineage.work_item = Some(manifest.operation_id.clone());
        lineage.task_id.clone_from(&manifest.task_id);
        lineage.session_id.clone_from(&manifest.session_id);
        lineage.work_scope.clone_from(&manifest.work_scope_id);
        lineage.state_fence.clone_from(&manifest.state_fence);
        lineage.adapter_instance.clone_from(&manifest.connection_id);
        lineage.route_receipt_requested.clone_from(&manifest.requested_route);
        lineage.module_generation.clone_from(&manifest.module_generation);
        lineage.authority_epoch.clone_from(&manifest.authority_epoch);
        lineage.controller = Some("eliotd".to_owned());
        if let Some(attempt) = manifest.local_read_attempt.as_ref() {
            lineage.attempt_id = Some(attempt.attempt_id.clone());
            lineage.environment_lease = Some(attempt.attempt_id.clone());
        }
        AuditRecord {
            format_version: 1,
            chain_id: "chain:trace-test".to_owned(),
            seq: 1,
            prev_hash: "0".repeat(64),
            kind: AuditEventKind::RESULT_KERNEL_BOUND.to_owned(),
            lineage,
            event_digest: "result-bound-event".to_owned(),
            event_body: serde_json::json!({
                "lane": manifest.lane.as_deref(),
                "request_digest": manifest.retained_request_digest,
                "result_digest": manifest.result_digest,
                "durable_state": manifest.durable_state.as_deref(),
            }),
            assurance: AuditAssuranceClass::Critical,
            capture_mode: AuditCaptureMode::Full,
            emitted_at_ms: 1,
            current_hash: "original-result-bound-record".to_owned(),
        }
    }

    #[test]
    fn original_envelope_kind_must_match_the_durable_ors_kind() {
        assert!(super::request_kind_matches_row(
            eliot_protocol::HostRequestKind::Invocation,
            eliot_ors::HostRequestKind::Invocation,
        ));
        assert!(!super::request_kind_matches_row(
            eliot_protocol::HostRequestKind::Invocation,
            eliot_ors::HostRequestKind::Activation,
        ));
    }

    #[test]
    fn admitted_payload_slot_requires_both_original_sources() {
        assert!(super::exact_admitted_payload_retained(true, true, true));
        assert!(!super::exact_admitted_payload_retained(true, false, true));
        assert!(!super::exact_admitted_payload_retained(true, true, false));
        assert!(!super::exact_admitted_payload_retained(false, true, true));
    }

    #[test]
    fn find_sealed_replays_actual_route_only_with_exact_fence_and_route_facts() {
        let mut manifest = absent_evidence_manifest();
        let (digest, receipt) = actual_route_receipt(&manifest);
        assert_ne!(
            manifest.connection_id.as_deref(),
            manifest.adapter_identity.as_deref()
        );
        manifest.actual_route = Some(digest);
        manifest.actual_route_receipt = Some(receipt.clone());
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        manifest.finish = TraceFinish::DegradedNoProof;
        assert!(!manifest.missing_parts.iter().any(|part| part == "actual_route"));
        let seal = seal_record(&manifest);

        let replay = TraceManifest::find_sealed(&[seal], &manifest.operation_id)
            .expect("original route facts remain replayable");
        assert_eq!(replay.actual_route_receipt, manifest.actual_route_receipt);

        let mut substituted = receipt;
        let altered_fence = StateFence::new(
            manifest.state_fence.as_ref().expect("fence").authority_epoch.clone(),
            ResourceGeneration::new(4).expect("nonzero generation"),
        );
        let altered_fence_value =
            serde_json::to_value(altered_fence).expect("altered fence serializes");
        substituted["state_fence"] = altered_fence_value.clone();
        substituted["route_facts"]["state_fence"] = altered_fence_value;
        substituted["route_facts"]["active_generation"] = serde_json::json!(4);
        let mut unsigned = substituted.clone();
        unsigned
            .as_object_mut()
            .expect("receipt object")
            .remove("receipt_digest");
        let substituted_digest = crate::sha256_json(&unsigned).expect("new receipt digest");
        substituted["receipt_digest"] = serde_json::Value::String(substituted_digest.clone());
        assert!(!manifest.route_receipt_matches(&substituted_digest, &substituted));

        let (_, mut caller_connection_substitution) = actual_route_receipt(&manifest);
        caller_connection_substitution["route_facts"]["connection_id"] =
            serde_json::json!(manifest.connection_id);
        let mut unsigned = caller_connection_substitution.clone();
        unsigned
            .as_object_mut()
            .expect("receipt object")
            .remove("receipt_digest");
        let wrong_adapter_digest =
            crate::sha256_json(&unsigned).expect("wrong adapter receipt digest");
        caller_connection_substitution["receipt_digest"] =
            serde_json::Value::String(wrong_adapter_digest.clone());
        assert!(!manifest.route_receipt_matches(
            &wrong_adapter_digest,
            &caller_connection_substitution,
        ));

        let mut invalid_manifest = manifest.clone();
        invalid_manifest.actual_route = Some(wrong_adapter_digest);
        invalid_manifest.actual_route_receipt = Some(caller_connection_substitution);
        invalid_manifest.missing_parts = invalid_manifest.missing_parts();
        invalid_manifest.unavailable = invalid_manifest.unavailable_parts();
        invalid_manifest.finish = TraceFinish::DegradedNoProof;
        assert!(TraceManifest::find_sealed(
            &[seal_record(&invalid_manifest)],
            &invalid_manifest.operation_id,
        )
        .is_none());
    }

    #[test]
    fn find_sealed_accepts_original_kernel_bound_receipt_before_seal() {
        let mut manifest = absent_evidence_manifest();
        let receipt = result_binding_record(&manifest);
        manifest.result_binding_receipt = Some(receipt.clone());
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        manifest.finish = TraceFinish::DegradedNoProof;
        assert!(!manifest.missing_parts.iter().any(|part| part == "result_receipt"));
        let seal = seal_record_after(&manifest, 2, receipt.current_hash.clone());

        let replay = TraceManifest::find_sealed(
            &[receipt, seal],
            &manifest.operation_id,
        )
        .expect("the exact prior binding record satisfies result receipt");

        assert_eq!(replay.result_binding_receipt, manifest.result_binding_receipt);
        assert!(!replay.missing_parts.iter().any(|part| part == "result_receipt"));
        assert_eq!(replay.finish, TraceFinish::DegradedNoProof);
    }

    #[test]
    fn find_sealed_refuses_a_substituted_or_late_binding_receipt() {
        let mut manifest = absent_evidence_manifest();
        let receipt = result_binding_record(&manifest);
        manifest.result_binding_receipt = Some(receipt.clone());
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        manifest.finish = TraceFinish::DegradedNoProof;
        let seal = seal_record_after(&manifest, 2, receipt.current_hash.clone());

        let mut substituted = receipt.clone();
        substituted.current_hash = "substituted-record-hash".to_owned();
        assert!(TraceManifest::find_sealed(
            &[substituted.clone(), seal.clone()],
            &manifest.operation_id,
        ).is_none());
        assert!(TraceManifest::find_sealed(
            &[seal, receipt],
            &manifest.operation_id,
        ).is_none());
    }

    #[test]
    fn find_sealed_refuses_a_present_binding_receipt_for_another_result() {
        let mut manifest = absent_evidence_manifest();
        let mut receipt = result_binding_record(&manifest);
        receipt.event_body["result_digest"] = serde_json::json!("f".repeat(64));
        manifest.result_binding_receipt = Some(receipt.clone());
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        manifest.finish = TraceFinish::DegradedNoProof;
        let seal = seal_record_after(&manifest, 2, receipt.current_hash.clone());

        assert!(TraceManifest::find_sealed(
            &[receipt, seal],
            &manifest.operation_id,
        )
        .is_none());
    }

    #[test]
    fn find_sealed_replays_degraded_manifest_with_exact_missing_evidence() {
        let mut manifest = absent_evidence_manifest();
        // Without the validated original envelope bytes, the request selector
        // and immutable input proof cannot be projected from row labels alone.
        manifest.admitted_payload_retained = false;
        manifest.requested_route = None;
        // A digest without its original route body is explicitly unavailable.
        manifest.actual_route = Some("d".repeat(64));
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        assert_eq!(manifest.unavailable, manifest.missing_parts.clone());
        assert!(manifest.missing_parts.iter().any(|part| part == "actual_route"));
        let records = [seal_record(&manifest)];

        let replay = TraceManifest::find_sealed(&records, &manifest.operation_id)
            .expect("honest degraded trace remains replayable");

        assert_eq!(replay.finish, TraceFinish::DegradedNoProof);
        assert_eq!(replay, manifest);
        assert!(replay.state_fence.is_some());
        for required in [
            "action_contract",
            "requested_route",
            "actual_route",
            "input_handle",
            "principal",
            "active_view_packet_manifest",
            "verifier_result",
        ] {
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
        assert!(TraceManifest::find_sealed(&records, &manifest.operation_id).is_none());
    }

    #[test]
    fn find_sealed_refuses_a_finish_that_disagrees_with_missing_evidence() {
        let mut manifest = absent_evidence_manifest();
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        manifest.finish = TraceFinish::Partial;
        let records = [seal_record(&manifest)];

        assert!(TraceManifest::find_sealed(&records, &manifest.operation_id).is_none());

        manifest.finish = TraceFinish::DegradedNoProof;
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable.clear();
        let records = [seal_record(&manifest)];
        assert!(TraceManifest::find_sealed(&records, &manifest.operation_id).is_none());
    }

    #[test]
    fn find_sealed_replays_a_route_digest_without_its_original_receipt_as_degraded() {
        let mut manifest = absent_evidence_manifest();
        manifest.actual_route = Some("d".repeat(64));
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        manifest.finish = TraceFinish::DegradedNoProof;
        let records = [seal_record(&manifest)];

        let replay = TraceManifest::find_sealed(&records, &manifest.operation_id)
            .expect("digest-only route evidence remains honestly degraded");

        assert_eq!(replay.finish, TraceFinish::DegradedNoProof);
        assert!(replay.missing_parts.iter().any(|part| part == "actual_route"));
    }

    #[test]
    fn find_sealed_refuses_a_divergent_fence_projection_or_audit_identity() {
        let mut manifest = absent_evidence_manifest();
        manifest.missing_parts = manifest.missing_parts();
        manifest.unavailable = manifest.unavailable_parts();
        manifest.module_generation = Some("4".to_owned());
        let records = [seal_record(&manifest)];
        assert!(TraceManifest::find_sealed(&records, &manifest.operation_id).is_none());

        manifest.module_generation = Some("3".to_owned());
        let mut record = seal_record(&manifest);
        record.lineage.trace_id = Some("foreign-trace".to_owned());
        assert!(TraceManifest::find_sealed(&[record], &manifest.operation_id).is_none());
    }
}
