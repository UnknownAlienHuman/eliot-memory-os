//! Authenticated daemon operation dispatch.
//!
//! Architecture traceability: `A12.3`, `A13.2`, `A13.6`, `ARCH-AUTH-01`,
//! `ARCH-SEC-02`, and `ARCH-RES-01` require one fenced Kernel route and an
//! honest recovery boundary. Implementation anchors are `I1.8`, `I5`, `B.1`,
//! `B.2`, `P.3`, and `I14.21`: Store owns durable state, Kernel verifies the
//! authenticated route/fence, and Governor remains the semantic owner.
//!
//! This module does not decode Governor owner payloads, advertise capabilities,
//! choose retry/default/cache policy, or turn an uncertain genesis into
//! success. The existing wildcard import is retained as a parent-module
//! dispatch convention; the new Store carriers below are explicitly typed.

use super::*;
#[path = "store_receipt_dispatch.rs"]
mod store_receipt_dispatch;
use std::collections::BTreeMap;

use eliot_contracts::StateFence;
use eliot_kernel_service::AuthenticatedHostSession;
use eliot_ors::{OperationIdentity, OrsError};
use eliot_protocol::{HostRequestEnvelope, HostRequestResultBody, host_request_operation_id};
use eliot_store_api::{
    CanonicalRequestView, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    OrderingHeadExpectation, PreparedTransition, ReadConsistency, RequestMeta,
    RevisionHeadExpectation, StoreError, StoreGenesisRequest, StoreRecoveryRequest,
    StoreRecoverySnapshot, WriteReceipt, verify_canonical_request_hash,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreNamedOperation {
    request: NamedReadRequest,
}

/// Closed local-read envelope for one admitted `eliot.query` (Implements #18).
///
/// Carries the exact admitted envelope plus the exact canonical tool bytes it
/// admits — the same linkage-checked pair as the invoke-read frame payload —
/// so the read leg re-proves capability + payload-digest binding before any
/// Gateway IO. `eliot.packet` pairs decode here but are admitted, never read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalReadOperation {
    envelope: HostRequestEnvelope,
    tool: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreRecoveryOperation {
    request: StoreRecoveryRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreInitializeGenesisOperation {
    context: RequestMeta,
    request: StoreGenesisRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreApplyOperation {
    context: RequestMeta,
    transition: PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

impl KernelComposition {
    /// Executes one authenticated daemon lifecycle request.  Only the
    /// narrow handshake/health dispositions are handled here; semantic
    /// Governor mutations remain owned by `eliotd` and the existing Kernel
    /// transition gateway.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed daemon dispatcher keeps authenticated lifecycle operations and their exact response projection in one audited gateway"
    )]
    pub async fn execute_daemon_request(
        &self,
        session: &Session,
        request_id: RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.require_current_daemon_session(session)?;
        let result = match operation {
            "snapshot" => self.daemon_snapshot().map(|value| {
                serde_json::json!({
                    "status": "known",
                    "value": value,
                    "recovery": null,
                })
            }),
            "daemon_ready" => {
                let generation = payload
                    .get("generation")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(TransportError::SessionFenced)?;
                let authority_epoch: eliot_contracts::EpochId = serde_json::from_value(
                    payload
                        .get("authority_epoch")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                if generation != session.module_generation.generation.value()
                    || !authority_epoch.is_same_authority(&session.authority_epoch)
                {
                    return Err(TransportError::SessionFenced);
                }
                #[cfg(windows)]
                {
                    let (launch, process) = self
                        .validated_authenticated_daemon_ready_inputs()
                        .await
                        .map_err(|_| TransportError::SessionFenced)?;
                    let (contour, snapshot) = self
                        .establish_daemon_supervision(session, &process)
                        .map_err(|_| TransportError::SessionFenced)?;
                    if snapshot.record.lease_id.as_str() != contour.incarnation.supervision_lease_id
                    {
                        return Err(TransportError::SessionFenced);
                    }
                    let ready = Self::eliotd_live_ready_evidence(session, &request_id, &payload)
                        .map_err(|_| TransportError::SessionFenced)?;
                    {
                        let mut state = self
                            .daemon_runtime
                            .lock()
                            .map_err(|_| TransportError::SessionFenced)?;
                        if state
                            .supervision
                            .as_ref()
                            .is_some_and(|bound| bound != &contour)
                        {
                            return Err(TransportError::SessionFenced);
                        }
                        state
                            .bind_live_receipt_publication_operation(&ready)
                            .map_err(|_| TransportError::SessionFenced)?;
                        state.supervision = Some(contour.clone());
                    }
                    self.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, None)
                        .map_err(|_| TransportError::SessionFenced)?;
                }
                self.mark_daemon_ready()
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            "health" => self
                .daemon_health()
                .await
                .map_err(|_| TransportError::SessionFenced)
                .map(|health| Self::daemon_health_response(&health)),
            "store_recovery" => self.store_recovery_operation(session, payload).await,
            "store_initialize_genesis" => {
                self.store_initialize_genesis_operation(session, payload)
                    .await
            }
            "apply_prepared" => {
                self.store_apply_operation(session, request_id.clone(), payload)
                    .await
            }
            "receipt" => store_receipt_dispatch::dispatch(self, session, payload).await,
            "store_named" => self.store_named_operation(session, payload).await,
            "local_read" => self.local_read_operation(session, payload).await,
            "daemon_degraded" => {
                let reason = payload
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.len() <= 512
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or(TransportError::SessionFenced)?
                    .to_owned();
                self.mark_daemon_degraded(reason)
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            "daemon_fatal" => {
                let reason = payload
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.len() <= 512
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or(TransportError::SessionFenced)?
                    .to_owned();
                self.mark_daemon_failed(reason)
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            "agent_activation_claim" => {
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_agent_activation_ticket().map(|ticket| {
                        serde_json::json!({
                            "status": "known",
                            "value": { "ticket": ticket },
                            "recovery": null,
                        })
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "agent_activation_submit" => {
                #[cfg(windows)]
                {
                    // The closed submit operation carries exactly one resolver
                    // outcome in one of two result shapes: the production v2
                    // typed submit envelope carrying one
                    // AgentActivationResolutionResult (unknown envelope
                    // versions are rejected before adoption), or the
                    // unenveloped P-04 typed result shape covering the same
                    // seven closed dispositions, or the legacy success-only
                    // decision. The v2 envelope is trial-decoded first so
                    // production traffic keeps its typed acknowledgement and
                    // reconcile support; the two result shapes share the
                    // ticket ledger but keep independent
                    // exact-replay/conflict accounting. A payload carrying
                    // both keys or neither is fail-closed.
                    let has_decision = payload
                        .get("decision")
                        .is_some_and(|value| !value.is_null());
                    let has_result = payload.get("result").is_some_and(|value| !value.is_null());
                    match (has_decision, has_result) {
                        (true, false) => {
                            let decision_value = payload
                                .get("decision")
                                .cloned()
                                .ok_or(TransportError::SessionFenced)?;
                            let decision: AgentActivationResolutionDecision =
                                serde_json::from_value(decision_value)
                                    .map_err(|_| TransportError::SessionFenced)?;
                            match self.submit_agent_activation_decision(decision) {
                                Ok(()) => Ok(Self::accepted_daemon_response()),
                                // Deadline expiry is an expected race at this
                                // boundary, not a daemon-fatal transport failure.
                                // Return an explicit known outcome so the caller can
                                // retain liveness without parsing error strings.
                                Err(TransportError::Timeout) => {
                                    Ok(Self::expired_activation_daemon_response())
                                }
                                Err(error) => Err(error),
                            }
                        }
                        (false, true) => {
                            let result_value = payload
                                .get("result")
                                .cloned()
                                .ok_or(TransportError::SessionFenced)?;
                            if let Ok(submit) = serde_json::from_value::<AgentActivationResultSubmit>(
                                result_value.clone(),
                            ) {
                                match self.submit_agent_activation_result(submit) {
                                    Ok(ack) => Ok(Self::activation_result_daemon_response(&ack)),
                                    // Deadline expiry is an expected race at this
                                    // boundary, not a daemon-fatal transport failure.
                                    // Return an explicit known outcome so the caller can
                                    // retain liveness without parsing error strings.
                                    // A retained terminal result never takes this
                                    // path: exact replay stays idempotent across the
                                    // deadline.
                                    Err(TransportError::Timeout) => {
                                        Ok(Self::expired_activation_daemon_response())
                                    }
                                    Err(error) => Err(error),
                                }
                            } else {
                                let result: AgentActivationResolutionResult =
                                    serde_json::from_value(result_value)
                                        .map_err(|_| TransportError::SessionFenced)?;
                                match self.submit_agent_activation_resolution_result(result) {
                                    Ok(()) => Ok(Self::accepted_daemon_response()),
                                    // Same deadline-expiry race as the legacy path:
                                    // the ticket lapsed before the typed result
                                    // arrived, so the caller observes expiry without
                                    // losing daemon liveness.
                                    Err(TransportError::Timeout) => {
                                        Ok(Self::expired_activation_daemon_response())
                                    }
                                    Err(error) => Err(error),
                                }
                            }
                        }
                        _ => Err(TransportError::SessionFenced),
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "agent_activation_reconcile" => {
                #[cfg(windows)]
                {
                    // Lost-acknowledgement reconcile: answered purely from
                    // the retained per-ticket record, never by recomputing
                    // semantics or reading the Governor a second time. An
                    // unknown ticket yields a typed Unknown acknowledgement
                    // (the daemon then resubmits its retained result); a
                    // digest mismatch is an identity conflict.
                    let query_value = payload
                        .get("reconcile")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let query: AgentActivationResultReconcile = serde_json::from_value(query_value)
                        .map_err(|_| TransportError::SessionFenced)?;
                    self.reconcile_agent_activation_result(&query)
                        .map(|ack| Self::reconciled_activation_daemon_response(&ack))
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "local_read_claim" => {
                // Outbound-only eliotd poller for admitted `eliot.query` pairs
                // (Implements #18): mirrors `agent_activation_claim` exactly —
                // same session/auth/ready/fence gates via the dispatcher head
                // and `frame_dispatch` allowlist, same single-`operation`-key
                // payload shape, same null poll (not error) when empty.
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_local_read_pair().map(|pair| match pair {
                        Some((envelope, tool)) => serde_json::json!({
                            "status": "known",
                            "value": { "pair": { "envelope": envelope, "tool": tool } },
                            "recovery": null,
                        }),
                        None => serde_json::json!({
                            "status": "known",
                            "value": { "pair": null },
                            "recovery": null,
                        }),
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "local_read_result" => {
                // Daemon submit leg for the claimed pair (Implements #18):
                // validates plus fence-checks the submitted
                // `HostRequestResultBody` and binds it to the waiting host
                // request through the ORS result path. Exact replay stays
                // idempotent (even across deadline expiry); a changed body
                // under the same identity conflicts; an elapsed deadline is
                // the expected race and projects as a known expired outcome
                // so the caller retains liveness without parsing errors.
                #[cfg(windows)]
                {
                    let result_value = payload
                        .get("result")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let body: HostRequestResultBody = serde_json::from_value(result_value)
                        .map_err(|_| TransportError::SessionFenced)?;
                    match self.submit_local_read_result(session, &body) {
                        Ok(_) => Ok(Self::accepted_daemon_response()),
                        Err(TransportError::Timeout) => {
                            Ok(Self::expired_activation_daemon_response())
                        }
                        Err(error) => Err(error),
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            #[cfg(windows)]
            "agent_host_request_submit" => {
                // Typed P-04 host-request envelopes through the same closed
                // daemon dispatcher. The admit path owns every
                // connection/descriptor/fence/generation/durability join; a
                // changed binding under a known identity conflicts, an unknown
                // parent is unknown, and an elapsed deadline times out there.
                let envelope = host_request_route::host_request_envelope_from_payload(&payload)?;
                let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
                Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ))
            }
            #[cfg(windows)]
            "agent_host_request_cancel" => {
                let envelope = host_request_route::host_request_envelope_from_payload(&payload)?;
                let (receipt, record) = self.cancel_host_request(&envelope)?;
                Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ))
            }
            #[cfg(windows)]
            "agent_host_request_reconcile" => {
                let envelope = host_request_route::host_request_envelope_from_payload(&payload)?;
                let (receipt, record) = self.reconcile_host_request(&envelope)?;
                Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ))
            }
            #[cfg(windows)]
            "agent_host_request_rehydrate" => {
                let envelope = host_request_route::host_request_envelope_from_payload(&payload)?;
                let receipt = host_request_route::host_request_receipt_from_payload(&payload)?;
                let record = self.rehydrate_host_request(&envelope, &receipt)?;
                Ok(host_request_route::host_request_rehydrated_response(
                    &record,
                ))
            }
            _ => return Err(TransportError::SessionFenced),
        };
        let value = result.map_err(|_| TransportError::SessionFenced)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
        frame.request_id = Some(request_id);
        frame.validate()?;
        Ok(frame)
    }

    fn accepted_daemon_response() -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "accepted": true },
            "recovery": null,
        })
    }

    fn expired_activation_daemon_response() -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "accepted": false, "expired": true },
            "recovery": null,
        })
    }

    /// Typed acknowledgement for a v2 semantic-result submit: the exact
    /// retained result (with its full disposition) travels inside `ack`, so
    /// the daemon leg stays lossless without parsing error strings.
    fn activation_result_daemon_response(ack: &AgentActivationResultAck) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "accepted": true, "ack": ack },
            "recovery": null,
        })
    }

    /// Typed answer for a lost-acknowledgement reconcile query, served from
    /// retention only. `ack` carries outcome `Reconciled` with the retained
    /// result, or `Unknown` when nothing is retained for the ticket.
    fn reconciled_activation_daemon_response(ack: &AgentActivationResultAck) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "ack": ack },
            "recovery": null,
        })
    }

    #[cfg(windows)]
    async fn store_recovery_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreRecoveryOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.request.validate() {
            return Ok(Self::store_error_response_text(
                "store_recovery",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.request.state_fence)?;
        let gateway = self.retained_store_gateway()?;
        match gateway.recovery(operation.request).await {
            Ok(snapshot) => Ok(store_recovery_response(&snapshot)),
            Err(error) => Ok(Self::store_error_response_text("store_recovery", &error)),
        }
    }

    #[cfg(not(windows))]
    async fn store_recovery_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    async fn store_initialize_genesis_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreInitializeGenesisOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        operation
            .context
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.request.validate_for_context(&operation.context) {
            return Ok(Self::store_error_response_text(
                "store_initialize_genesis",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.context.state_fence)?;
        if operation.request.state_fence != operation.context.state_fence {
            return Err(TransportError::SessionFenced);
        }
        let gateway = self.retained_store_gateway()?;
        match gateway
            .initialize_genesis(&operation.context, operation.request)
            .await
        {
            Ok(receipt) => Ok(store_genesis_response(&receipt)),
            Err(error) => Ok(Self::store_error_response_text(
                "store_initialize_genesis",
                &error,
            )),
        }
    }

    #[cfg(not(windows))]
    async fn store_initialize_genesis_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    async fn store_apply_operation(
        &self,
        session: &Session,
        request_id: RequestId,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreApplyOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if operation.context.request_id != request_id {
            return Err(TransportError::SessionFenced);
        }
        operation
            .context
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.transition.validate() {
            return Ok(Self::store_error_response_text(
                "write_receipt",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.context.state_fence)?;
        if operation.transition.state_fence != operation.context.state_fence {
            return Err(TransportError::SessionFenced);
        }
        for head in &operation.expected_revision_heads {
            if let Err(error) = head.validate() {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    &error.to_string(),
                ));
            }
            if head.state_fence != operation.context.state_fence {
                return Err(TransportError::SessionFenced);
            }
        }
        for head in &operation.expected_ordering_heads {
            if let Err(error) = head.validate() {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    &error.to_string(),
                ));
            }
            if head.state_fence != operation.context.state_fence {
                return Err(TransportError::SessionFenced);
            }
        }
        // RECHECK-63 slice B: recompute the canonical request hash from the
        // exact values about to be executed (context + transition + expected
        // heads) and reject divergence before the gateway call. The view is
        // built from these references — not re-forwarded copies — so a
        // mutation after admission fails here with the typed mismatch,
        // rendered through the existing store-error response shape.
        {
            let view = CanonicalRequestView::from_apply(
                &operation.context,
                &operation.transition,
                &operation.expected_revision_heads,
                &operation.expected_ordering_heads,
            );
            if let Err(error) = verify_canonical_request_hash(
                &view,
                &operation.transition.identity.canonical_request_hash,
            ) {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    &error.to_string(),
                ));
            }
        }
        let gateway = self.retained_store_gateway()?;
        match gateway
            .apply(
                &operation.context,
                operation.transition,
                operation.expected_revision_heads,
                operation.expected_ordering_heads,
            )
            .await
        {
            Ok(receipt) => Ok(store_apply_response(&receipt)),
            Err(error) => Ok(Self::store_error_response_text("write_receipt", &error)),
        }
    }

    #[cfg(not(windows))]
    async fn store_apply_operation(
        &self,
        _session: &Session,
        _request_id: RequestId,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    async fn store_named_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreNamedOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.request.validate() {
            return Ok(Self::store_error_response_text(
                "store_named",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.request.state_fence)?;
        let gateway = self.retained_store_gateway()?;
        match gateway.execute_named(operation.request).await {
            Ok(response) => Ok(store_named_response(&response)),
            Err(error) => Ok(Self::store_error_response_text("store_named", &error)),
        }
    }

    #[cfg(not(windows))]
    async fn store_named_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    /// Executes one closed local read for an admitted `eliot.query`.
    ///
    /// The `local_read` kind is the GetEvidencePack-only sibling of
    /// `store_named` on the same authenticated daemon session: no new
    /// transport, pipe, or listener. Rejection happens before reading —
    /// linkage plus closed selectors are proven (pure, no IO), then the full
    /// admission gate runs, then an exact replay of a resulted operation
    /// serves its stored bounded body without re-dispatch and without Gateway
    /// IO. Only a fresh admitted query reaches the Gateway, over the admitted
    /// fence with the explicit scope, exact subject, and catalogue-bound
    /// `max_records`; the bounded answer is projected through the MCP
    /// evidence-pack projection and persisted through the ORS result path, so
    /// the bridge readback and later replays answer `Responded` with the exact
    /// record instead of a bare `Accepted` admission. `eliot.packet` pairs
    /// are admitted and returned honestly, never read on this leg.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed local-read leg keeps linkage, admission, replay, gateway, projection, and persistence joins in one audited order"
    )]
    async fn local_read_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        // Closed decode first: unknown fields never reach the read leg.
        let operation: LocalReadOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        let envelope = operation.envelope;
        let tool = operation.tool;
        // Rejection-before-reading: linkage plus closed selectors next. This
        // validation is pure, so a changed payload digest, a forged
        // descriptor, or a malformed selector never reaches Gateway IO.
        let selectors = host_request_route::check_local_read_admission(&envelope, &tool)?;
        let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
        if let Some(replayed) =
            host_request_route::local_read_replay_response(&receipt, &record, &envelope)?
        {
            return Ok(replayed);
        }
        let Some(selectors) = selectors else {
            return Ok(host_request_route::host_request_admitted_response(
                &receipt, &record,
            ));
        };
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "subject".to_owned(),
            serde_json::Value::String(selectors.subject.clone()),
        );
        parameters.insert(
            "max_records".to_owned(),
            serde_json::Value::String(selectors.max_records.to_string()),
        );
        let read = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(selectors.scope_id.clone()),
            consistency: ReadConsistency::Eventual,
            state_fence: envelope.state_fence.clone(),
            parameters,
        };
        if let Err(error) = check_local_read_request(&read) {
            return Ok(Self::store_error_response_text("local_read", &error));
        }
        validate_store_session_fence(session, &read.state_fence)?;
        let gateway = self.retained_store_gateway()?;
        let response = match gateway.execute_named(read).await {
            Ok(response) => response,
            Err(error) => return Ok(Self::store_error_response_text("local_read", &error)),
        };
        if response.operation != NamedReadOperation::GetEvidencePack {
            return Ok(Self::store_error_response_text(
                "local_read",
                "named-read operation does not match request",
            ));
        }
        let (digest, body) = AuthenticatedHostSession::build_local_read_result_body(
            &envelope,
            selectors.scope_id.as_str(),
            &selectors.subject,
            selectors.max_records,
            &selectors.intent_mode,
            response.payload,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = OperationIdentity::new(host_request_operation_id(&envelope))
            .map_err(|_| TransportError::SessionFenced)?;
        self.generation_gateway
            .ors
            .persist_host_request_result(&operation_id, &envelope.envelope_sha256, &digest, &body)
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?
            .ok_or(TransportError::SessionFenced)?;
        let resulted = self
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &envelope.envelope_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        if host_request_route::local_read_replay_response(&receipt, &resulted, &envelope)?.is_none()
        {
            return Err(TransportError::SessionFenced);
        }
        // The sync leg answered this operation: retire any queued async pair
        // for it so a later `local_read_claim` poll skips it without store IO.
        self.retire_local_read_pair(operation_id.as_str(), &envelope.envelope_sha256);
        Ok(host_request_route::host_request_admitted_response(
            &receipt, &resulted,
        ))
    }

    #[cfg(not(windows))]
    async fn local_read_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    fn retained_store_gateway(&self) -> Result<Arc<KernelStoreGateway>, TransportError> {
        self.canonical_store_gateway
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)
    }

    fn store_error_response_text(kind: &str, error: &str) -> serde_json::Value {
        let status = if error == StoreError::MissingReceiptEnvelope.to_string() {
            "unknown"
        } else {
            "error"
        };
        serde_json::json!({
            "status": status,
            "value": { "kind": kind, "value": null },
            "recovery": null,
        })
    }
}

fn validate_store_session_fence(
    session: &Session,
    state_fence: &StateFence,
) -> Result<(), TransportError> {
    state_fence
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if !session
        .authority_epoch
        .is_same_authority(&state_fence.authority_epoch)
        || session.module_generation.generation != state_fence.resource_generation
        || session.module_generation.state_fence != *state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn store_recovery_response(snapshot: &StoreRecoverySnapshot) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "store_recovery", "value": snapshot },
        "recovery": null,
    })
}

fn store_genesis_response(receipt: &WriteReceipt) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "store_initialize_genesis", "value": receipt },
        "recovery": null,
    })
}

fn store_apply_response(receipt: &WriteReceipt) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "write_receipt", "value": receipt },
        "recovery": null,
    })
}

/// Requires a local-read store request to be the closed evidence-pack read.
///
/// `local_read` is the `GetEvidencePack`-only sibling of `store_named`: any
/// other catalogue operation (including the packet projection-inputs read) is
/// refused here, so the packet path stays unavailable on this leg. Shape
/// validation is the Store-owned request check, unchanged and never weakened.
fn check_local_read_request(request: &NamedReadRequest) -> Result<(), String> {
    if request.operation != NamedReadOperation::GetEvidencePack {
        return Err(
            "local_read admits only GetEvidencePack; packet and position reads stay unavailable"
                .to_owned(),
        );
    }
    request.validate().map_err(|error| error.to_string())
}

fn store_named_response(response: &NamedReadResponse) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "store_named", "value": response },
        "recovery": null,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod store_named_dispatch_tests {
    use super::*;

    #[test]
    fn store_named_operation_rejects_unknown_fields_and_projects_typed_response() {
        let fence = StateFence::new(
            eliot_contracts::EpochId::new(
                eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("lineage"),
                std::num::NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            eliot_contracts::ResourceGeneration::genesis(),
        );
        let request = NamedReadRequest {
            operation: eliot_store_api::NamedReadOperation::GetEvidencePack,
            scope_id: None,
            consistency: eliot_store_api::ReadConsistency::ExactFence,
            state_fence: fence.clone(),
            parameters: std::collections::BTreeMap::new(),
        };
        let mut payload = serde_json::to_value(&request).expect("request encodes");
        if let serde_json::Value::Object(map) = &mut payload {
            map.insert("unknown_field".to_owned(), serde_json::Value::Null);
        }
        let rejected: Result<StoreNamedOperation, _> = serde_json::from_value(serde_json::json!({
            "request": payload,
        }));
        assert!(
            rejected.is_err(),
            "deny_unknown_fields must reject a widened named-read envelope"
        );

        let response = NamedReadResponse {
            operation: eliot_store_api::NamedReadOperation::GetEvidencePack,
            state_fence: fence,
            revision_heads: Vec::new(),
            payload: serde_json::json!({ "version": 1 }),
        };
        let projected = store_named_response(&response);
        assert_eq!(projected.get("status"), Some(&serde_json::json!("known")));
        assert_eq!(
            projected.get("value").and_then(|value| value.get("kind")),
            Some(&serde_json::json!("store_named"))
        );
        let expected = serde_json::to_value(&response).expect("response encodes");
        assert_eq!(
            projected.get("value").and_then(|value| value.get("value")),
            Some(&expected)
        );
        assert_eq!(projected.get("recovery"), Some(&serde_json::Value::Null));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod local_read_dispatch_tests {
    use super::*;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn tool_digest(tool: &serde_json::Value) -> String {
        let bytes = eliot_contracts::canonical_json_bytes(tool).expect("tool must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    }

    fn query_tool() -> serde_json::Value {
        serde_json::json!({"name":"eliot.query","arguments":{
            "intent":{
                "mode":"verification",
                "time_scope":"session-window",
                "branch_environment_scope":"branch",
                "freshness_policy":"exact-fence",
                "required_assurance":"evidence-provenance"
            },
            "query":"subject:evidence-alpha",
            "exact_resource_uri": null
        }})
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            eliot_contracts::EpochId::new(
                eliot_contracts::EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                std::num::NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            eliot_contracts::ResourceGeneration::genesis(),
        )
    }

    fn test_envelope(capability: &str, payload_sha256: &str) -> HostRequestEnvelope {
        eliot_protocol::HostRequestEnvelope {
            wire_id: eliot_protocol::HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::HostRequestEnvelope::CONTRACT_VERSION,
            kind: eliot_protocol::HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: eliot_protocol::HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-1")
                    .expect("valid request id"),
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: capability.to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: payload_sha256.to_owned(),
            },
            state_fence: test_fence(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("envelope must digest")
    }

    #[test]
    fn local_read_operation_rejects_unknown_fields() {
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &tool_digest(&tool));
        let valid = serde_json::json!({"envelope": envelope, "tool": tool});
        let decoded: LocalReadOperation =
            serde_json::from_value(valid).expect("closed envelope+tool pair must decode");
        assert_eq!(decoded.tool, tool);
        assert_eq!(
            decoded.envelope.envelope_sha256, envelope.envelope_sha256,
            "the admitted digest rides the closed carrier"
        );

        let widened = serde_json::json!({
            "envelope": envelope,
            "tool": tool,
            "unknown_field": null,
        });
        assert!(
            serde_json::from_value::<LocalReadOperation>(widened).is_err(),
            "deny_unknown_fields must reject a widened local-read envelope"
        );
    }

    #[test]
    fn local_read_gate_admits_only_evidence_pack() {
        let parameters = BTreeMap::from([
            (
                "subject".to_owned(),
                serde_json::Value::String("evidence-alpha".to_owned()),
            ),
            (
                "max_records".to_owned(),
                serde_json::Value::String("10".to_owned()),
            ),
        ]);
        let read = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(eliot_store_api::ScopeId::new("scope-1").expect("valid test scope")),
            consistency: ReadConsistency::Eventual,
            state_fence: test_fence(),
            parameters,
        };
        assert!(
            check_local_read_request(&read).is_ok(),
            "the closed evidence-pack read must pass the gate"
        );

        // Any other catalogue operation — including the packet
        // projection-inputs read — stays unavailable on this leg.
        for operation in [
            NamedReadOperation::GetCurrentEpistemicPosition,
            NamedReadOperation::GetRevisionHeads,
            NamedReadOperation::GetUnderstandingProjectionInputs,
        ] {
            let mut other = read.clone();
            other.operation = operation;
            assert!(
                check_local_read_request(&other).is_err(),
                "non-evidence operations must be refused before any store work"
            );
        }
    }
}
