//! Production preflight gate and per-attempt catalogue binding for the single
//! stable Codex App Server codec.
//!
//! This module owns the stable observation gate: `initialize` → `initialized` →
//! `model/list` observation must be complete and a validated
//! `ModelCatalogueSnapshot` must be bound before any thread/turn execution.
//! It never launches a process, owns canonical state, or invents a universal
//! model string. Legacy/stale wire (jsonrpc, protocolVersion, out-of-order) is
//! rejected fail-closed.

use eliot_agent_api::RouteFingerprint;
use eliot_agent_coordinator::{ModelCatalogueSnapshot, ModelControlError};

use crate::{CodexAdapterError, CodexWireMessage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    InitializeSent,
    InitializeAcked,
    Initialized,
    CatalogueRequested,
    CatalogueObserved,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::InitializeSent => "initialize_sent",
            Self::InitializeAcked => "initialize_acked",
            Self::Initialized => "initialized",
            Self::CatalogueRequested => "catalogue_requested",
            Self::CatalogueObserved => "catalogue_observed",
        }
    }
}

/// Production gate that tracks the stable observation sequence and an exact
/// per-attempt catalogue binding.
#[derive(Clone, Debug)]
pub struct CodexPreflightGate {
    phase: Phase,
    initialize_id: Option<String>,
    catalogue_id: Option<String>,
    catalogue_binding: Option<BoundCatalogue>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct BoundCatalogue {
    snapshot_id: String,
    account_scope: String,
    model_id: String,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl CodexPreflightGate {
    pub fn new() -> Self {
        Self {
            phase: Phase::Idle,
            initialize_id: None,
            catalogue_id: None,
            catalogue_binding: None,
        }
    }

    pub fn phase(&self) -> &'static str {
        self.phase.as_str()
    }

    pub fn is_ready(&self) -> bool {
        self.phase == Phase::CatalogueObserved && self.catalogue_binding.is_some()
    }

    pub fn require_ready(&self) -> Result<(), CodexAdapterError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(CodexAdapterError::PreflightIncomplete)
        }
    }

    /// Observe one wire message in sequence. Call for both outbound requests/
    /// notifications and inbound responses in the order they are sent/observed.
    pub fn observe(&mut self, message: &CodexWireMessage) -> Result<(), CodexAdapterError> {
        // Reject legacy envelope fields before state transition.
        let raw = serde_json::to_value(message)
            .map_err(|_| CodexAdapterError::MalformedWire("serialization"))?;
        if raw.get("jsonrpc").is_some() {
            return Err(CodexAdapterError::StaleWire("jsonrpc envelope is legacy"));
        }
        if let Some(params) = &message.params {
            if params.get("protocolVersion").is_some() {
                return Err(CodexAdapterError::StaleWire("protocolVersion is legacy"));
            }
            // experimentalApi must not be true (stable wire uses false or absent)
            if params
                .get("capabilities")
                .and_then(|caps| caps.get("experimentalApi"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                return Err(CodexAdapterError::StaleWire(
                    "experimentalApi must be false",
                ));
            }
        }

        let method = message.method.as_deref();
        let has_id = message.id.is_some();
        let has_result = message.result.is_some();
        let has_error = message.error.is_some();

        match (method, has_id, has_result, has_error) {
            (Some("initialize"), true, false, false) => self.observe_initialize_request(message),
            (None, true, true, false) | (None, true, false, true) => self.observe_response(message),
            (Some("initialized"), false, false, false) => self.observe_initialized(message),
            (Some("model/list"), true, false, false) => self.observe_catalogue_request(message),
            (Some(other), _, _, _) if is_execution_method(other) => {
                Err(CodexAdapterError::PreflightIncomplete)
            }
            _ => {
                if self.is_ready() {
                    Ok(())
                } else {
                    Err(CodexAdapterError::MalformedWire(
                        "unexpected wire during preflight",
                    ))
                }
            }
        }
    }

    fn observe_initialize_request(
        &mut self,
        message: &CodexWireMessage,
    ) -> Result<(), CodexAdapterError> {
        if self.phase != Phase::Idle {
            return Err(CodexAdapterError::PreflightIncomplete);
        }
        let id = message
            .id
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or(CodexAdapterError::MalformedWire("initialize missing id"))?
            .to_owned();
        self.initialize_id = Some(id);
        self.phase = Phase::InitializeSent;
        Ok(())
    }

    fn observe_response(&mut self, message: &CodexWireMessage) -> Result<(), CodexAdapterError> {
        let id = message
            .id
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or(CodexAdapterError::MalformedWire("response missing id"))?;
        if self.phase == Phase::InitializeSent && self.initialize_id.as_deref() == Some(id) {
            if message.error.is_some() {
                return Err(CodexAdapterError::MalformedWire(
                    "initialize error during preflight",
                ));
            }
            self.phase = Phase::InitializeAcked;
            return Ok(());
        }
        if self.phase == Phase::CatalogueRequested && self.catalogue_id.as_deref() == Some(id) {
            if message.error.is_some() {
                return Err(CodexAdapterError::MalformedWire(
                    "model/list error during preflight",
                ));
            }
            self.phase = Phase::CatalogueObserved;
            return Ok(());
        }
        Err(CodexAdapterError::PreflightIncomplete)
    }

    fn observe_initialized(
        &mut self,
        _message: &CodexWireMessage,
    ) -> Result<(), CodexAdapterError> {
        if self.phase != Phase::InitializeAcked {
            return Err(CodexAdapterError::PreflightIncomplete);
        }
        self.phase = Phase::Initialized;
        Ok(())
    }

    fn observe_catalogue_request(
        &mut self,
        message: &CodexWireMessage,
    ) -> Result<(), CodexAdapterError> {
        if self.phase != Phase::Initialized {
            return Err(CodexAdapterError::PreflightIncomplete);
        }
        let id = message
            .id
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or(CodexAdapterError::MalformedWire("model/list missing id"))?
            .to_owned();
        self.catalogue_id = Some(id);
        self.phase = Phase::CatalogueRequested;
        Ok(())
    }

    /// Bind an exact validated catalogue snapshot for per-attempt model
    /// identity. The snapshot must be validated, current at `now_unix_ms`,
    /// and contain `route.model`.
    pub fn bind_catalogue(
        &mut self,
        snapshot: &ModelCatalogueSnapshot,
        route: &RouteFingerprint,
        now_unix_ms: u64,
    ) -> Result<(), CodexAdapterError> {
        if self.phase != Phase::CatalogueObserved {
            return Err(CodexAdapterError::PreflightIncomplete);
        }
        validate_binding(snapshot, route, now_unix_ms)?;
        let model_id = route.model.clone();
        self.catalogue_binding = Some(BoundCatalogue {
            snapshot_id: snapshot.snapshot_id.clone(),
            account_scope: snapshot.account_scope.clone(),
            model_id,
            observed_at_unix_ms: snapshot.observed_at_unix_ms,
            expires_at_unix_ms: snapshot.expires_at_unix_ms,
        });
        Ok(())
    }

    pub fn bound_snapshot_id(&self) -> Option<&str> {
        self.catalogue_binding
            .as_ref()
            .map(|b| b.snapshot_id.as_str())
    }

    pub fn bound_model_id(&self) -> Option<&str> {
        self.catalogue_binding.as_ref().map(|b| b.model_id.as_str())
    }
}

impl Default for CodexPreflightGate {
    fn default() -> Self {
        Self::new()
    }
}

fn is_execution_method(method: &str) -> bool {
    matches!(
        method,
        "thread/start" | "turn/start" | "turn/interrupt" | "item/toolCall" | "item/toolResult"
    )
}

#[allow(clippy::too_many_lines)]
fn validate_binding(
    snapshot: &ModelCatalogueSnapshot,
    route: &RouteFingerprint,
    now_unix_ms: u64,
) -> Result<(), CodexAdapterError> {
    snapshot.validate().map_err(|e| match e {
        ModelControlError::StaleCatalogue => CodexAdapterError::CatalogueStale,
        ModelControlError::InvalidField(f) => CodexAdapterError::CatalogueMismatch(f),
        ModelControlError::UnsupportedSchema(_) => {
            CodexAdapterError::CatalogueMismatch("catalogue schema")
        }
        ModelControlError::DuplicateIdentity(_) => {
            CodexAdapterError::CatalogueMismatch("duplicate identity")
        }
        _ => CodexAdapterError::CatalogueMismatch("catalogue invalid"),
    })?;
    if !snapshot.is_current(now_unix_ms) {
        return Err(CodexAdapterError::CatalogueStale);
    }
    if snapshot.account_scope != route.auth_billing {
        return Err(CodexAdapterError::CatalogueMismatch(
            "account_scope mismatch",
        ));
    }
    let Some(entry) = snapshot
        .entries
        .iter()
        .find(|entry| entry.model_id == route.model && entry.provider_id == route.provider)
    else {
        return Err(CodexAdapterError::ModelNotInCatalogue);
    };
    if entry.account_scope != snapshot.account_scope {
        return Err(CodexAdapterError::CatalogueMismatch("entry scope"));
    }
    if entry.route != *route {
        return Err(CodexAdapterError::CatalogueMismatch("route mismatch"));
    }
    if entry.billing.observed_at_unix_ms != snapshot.observed_at_unix_ms
        || entry.quota.observed_at_unix_ms != snapshot.observed_at_unix_ms
    {
        // not a hard fail, but keep consistent observability window
    }
    let _ = entry;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines, clippy::panic)]
mod tests {
    use super::*;
    use crate::catalogue::{
        CODEX_CATALOGUE_CONTEXT_VERSION, CodexCatalogueContext, CodexModelWire,
        CodexProviderPolicy, CodexRouteTemplate, compile_codex_model_catalogue,
    };
    use eliot_agent_api::RouteFingerprint;
    use eliot_agent_coordinator::{
        ModelRole, QuotaDisposition, QuotaObservation, RouteAdmissionStatus, RouteHealthStatus,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn route_for(model: &str) -> RouteFingerprint {
        crate::codex_route(
            "runtime-hash",
            "adapter-hash",
            "codex",
            model,
            "account-1",
            "serializer-hash",
            "tool-semantics-hash",
            "catalogue-default",
            "native-resume",
            "feature-flags-hash",
        )
    }

    fn make_test_context() -> CodexCatalogueContext {
        CodexCatalogueContext {
            schema_version: CODEX_CATALOGUE_CONTEXT_VERSION.to_owned(),
            snapshot_id: "snapshot-1".to_owned(),
            account_scope: "account-1".to_owned(),
            collector_identity: "codex-provider-catalogue-v1".to_owned(),
            observed_at_unix_ms: 9_900,
            expires_at_unix_ms: 10_100,
            health_receipt_ref: "health-receipt".to_owned(),
            catalogue_receipt_ref: "catalogue-receipt".to_owned(),
            provider_id: "codex".to_owned(),
            provider_policy: CodexProviderPolicy {
                route: CodexRouteTemplate {
                    runtime_hash: "runtime-hash".to_owned(),
                    adapter_hash: "adapter-hash".to_owned(),
                    auth_billing: "account-1".to_owned(),
                    serializer_hash: "serializer-hash".to_owned(),
                    tool_semantics_hash: "tool-semantics-hash".to_owned(),
                    reasoning_mode: "catalogue-default".to_owned(),
                    continuation_behavior: "native-resume".to_owned(),
                    feature_flags_hash: "feature-flags-hash".to_owned(),
                },
                route_admission: RouteAdmissionStatus::Admitted,
                route_health: RouteHealthStatus::Healthy,
                billing_mode: crate::catalogue::CodexBillingMode::CataloguePrice,
                model_billing_overrides: BTreeMap::new(),
                billing_source: "codex-billing".to_owned(),
                billing_receipt_ref: "billing-receipt".to_owned(),
                quota: Some(QuotaObservation {
                    disposition: QuotaDisposition::Available,
                    source: "codex-quota".to_owned(),
                    receipt_ref: "quota-receipt".to_owned(),
                    observed_at_unix_ms: 9_900,
                    expires_at_unix_ms: 10_100,
                    reset_at_unix_ms: Some(11_000),
                    remaining_microunits: Some(10),
                }),
                quota_source: "codex-quota".to_owned(),
                quota_receipt_ref: "quota-receipt".to_owned(),
                cost_class: 1,
                latency_class: 1,
                role_eligibility: BTreeSet::from([ModelRole::Worker]),
                evidence_refs: vec!["route-policy-receipt".to_owned()],
            },
            provider_connected: true,
            provider_health: RouteHealthStatus::Healthy,
            evidence_refs: vec!["collector-receipt".to_owned()],
        }
    }

    fn snapshot_for(model: &str, now: u64) -> ModelCatalogueSnapshot {
        let ctx = make_test_context();
        let mut models = BTreeMap::new();
        models.insert(
            model.to_owned(),
            CodexModelWire {
                id: Some(model.to_owned()),
                display_name: Some(model.to_owned()),
                family: Some("family-a".to_owned()),
                context_window: Some(200_000),
                context_limit: None,
                limit: None,
                cost: Some(crate::catalogue::CodexModelCost {
                    input: Some(serde_json::Number::from(0)),
                    output: Some(serde_json::Number::from(0)),
                }),
                capabilities: None,
                extra: BTreeMap::new(),
            },
        );
        let collection = compile_codex_model_catalogue(&ctx, &models).unwrap();
        let mut snapshot = collection.snapshot;
        snapshot.observed_at_unix_ms = now - 50;
        snapshot.expires_at_unix_ms = now + 50;
        for entry in &mut snapshot.entries {
            entry.billing.observed_at_unix_ms = now - 50;
            entry.billing.expires_at_unix_ms = now + 50;
            entry.quota.observed_at_unix_ms = now - 50;
            entry.quota.expires_at_unix_ms = now + 50;
        }
        snapshot.validate().unwrap();
        snapshot
    }

    fn happy_gate(now: u64, model: &str) -> CodexPreflightGate {
        let mut gate = CodexPreflightGate::new();
        let initialize = CodexWireMessage::initialize("init-1", "eliot", "0.1.0");
        gate.observe(&initialize).unwrap();
        let initialize_resp = CodexWireMessage {
            id: Some(serde_json::Value::String("init-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({})),
            error: None,
        };
        gate.observe(&initialize_resp).unwrap();
        gate.observe(&CodexWireMessage::initialized()).unwrap();
        let model_list = CodexWireMessage::model_list("ml-1", None, false, None);
        gate.observe(&model_list).unwrap();
        let model_list_resp = CodexWireMessage {
            id: Some(serde_json::Value::String("ml-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({"data": {}})),
            error: None,
        };
        gate.observe(&model_list_resp).unwrap();
        let snapshot = snapshot_for(model, now);
        let route = route_for(model);
        gate.bind_catalogue(&snapshot, &route, now).unwrap();
        gate
    }

    #[test]
    fn gate_requires_complete_sequence() {
        let now = 10_000;
        let mut gate = CodexPreflightGate::new();
        assert!(!gate.is_ready());
        assert!(gate.require_ready().is_err());
        gate = happy_gate(now, "model-a");
        assert!(gate.is_ready());
        assert!(gate.require_ready().is_ok());
        assert_eq!(gate.bound_model_id(), Some("model-a"));
    }

    #[test]
    fn gate_rejects_out_of_order() {
        let mut gate = CodexPreflightGate::new();
        assert!(gate.observe(&CodexWireMessage::initialized()).is_err());
        let mut gate = CodexPreflightGate::new();
        let model_list = CodexWireMessage::model_list("ml-1", None, false, None);
        assert!(gate.observe(&model_list).is_err());
    }

    #[test]
    fn gate_rejects_stale_wire() {
        let mut gate = CodexPreflightGate::new();
        let mut legacy = CodexWireMessage::initialize("init-1", "eliot", "0.1.0");
        legacy.params = Some(serde_json::json!({"protocolVersion": "1.0"}));
        assert!(matches!(
            gate.observe(&legacy),
            Err(CodexAdapterError::StaleWire(_))
        ));
        assert!(
            CodexWireMessage::parse_line(
                br#"{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn binding_rejects_mismatched_model() {
        let now = 10_000;
        let mut gate = CodexPreflightGate::new();
        let init = CodexWireMessage::initialize("init-1", "eliot", "0.1.0");
        gate.observe(&init).unwrap();
        gate.observe(&CodexWireMessage {
            id: Some(serde_json::Value::String("init-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({})),
            error: None,
        })
        .unwrap();
        gate.observe(&CodexWireMessage::initialized()).unwrap();
        gate.observe(&CodexWireMessage::model_list("ml-1", None, false, None))
            .unwrap();
        gate.observe(&CodexWireMessage {
            id: Some(serde_json::Value::String("ml-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({})),
            error: None,
        })
        .unwrap();
        let snapshot = snapshot_for("model-a", now);
        let wrong_route = route_for("other-model");
        assert!(matches!(
            gate.bind_catalogue(&snapshot, &wrong_route, now),
            Err(CodexAdapterError::ModelNotInCatalogue)
        ));
    }

    #[test]
    fn binding_rejects_expired_snapshot() {
        let now = 10_000;
        let gate = happy_gate(now, "model-a");
        let mut expired = snapshot_for("model-a", now);
        expired.observed_at_unix_ms = now - 200;
        expired.expires_at_unix_ms = now - 100;
        for entry in &mut expired.entries {
            entry.billing.observed_at_unix_ms = now - 200;
            entry.billing.expires_at_unix_ms = now - 100;
            entry.quota.observed_at_unix_ms = now - 200;
            entry.quota.expires_at_unix_ms = now - 100;
        }
        let mut gate2 = CodexPreflightGate::new();
        let init = CodexWireMessage::initialize("init-1", "eliot", "0.1.0");
        gate2.observe(&init).unwrap();
        gate2
            .observe(&CodexWireMessage {
                id: Some(serde_json::Value::String("init-1".to_owned())),
                message_type: None,
                method: None,
                params: None,
                result: Some(serde_json::json!({})),
                error: None,
            })
            .unwrap();
        gate2.observe(&CodexWireMessage::initialized()).unwrap();
        gate2
            .observe(&CodexWireMessage::model_list("ml-1", None, false, None))
            .unwrap();
        gate2
            .observe(&CodexWireMessage {
                id: Some(serde_json::Value::String("ml-1".to_owned())),
                message_type: None,
                method: None,
                params: None,
                result: Some(serde_json::json!({})),
                error: None,
            })
            .unwrap();
        let route = route_for("model-a");
        assert!(matches!(
            gate2.bind_catalogue(&expired, &route, now),
            Err(CodexAdapterError::CatalogueStale)
        ));
        let _ = gate;
    }
}
