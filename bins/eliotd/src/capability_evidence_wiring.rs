//! Daemon-held Governor capability admission view (#1957).
//!
//! The canonical registry and evidence semantics live in `eliot-governor`;
//! legacy normalization lives in `eliot-config`. This module owns only the
//! daemon composition root's handle on that view. The single
//! [`GovernorCapabilityAdmission`] is constructed empty at
//! [`DaemonComposition::start`](super::DaemonComposition::start) and is
//! mutated in production at exactly ONE site:
//! [`GovernorCapabilityAdmission::hydrate_from_evidence_response`], reached
//! from the daemon's live Skill-intake commit step
//! ([`commit_skill_pair`](super::skill_dispatch::commit_skill_pair)), which
//! applies the canonical `GetCapabilityEvidenceState` response that same
//! intake already read.
//!
//! No semantic rule lives here; every admission decision is the Governor
//! registry's.
//!
//! Where the view is consulted, measured on this base: the production model
//! execution path is
//! [`GovernedDreamerModelAdapter::invoke`](super::dreamer_model_adapter::GovernedDreamerModelAdapter::invoke)
//! -> [`invoke_admitted_model`](super::dreamer_model_adapter::invoke_admitted_model)
//! -> the C1 join `gate_model_capability`, which requires
//! [`admit_production_route`](GovernorCapabilityAdmission::admit_production_route)
//! over this held view for every item of the canonical required set, on the
//! caller-observed route scope, at the caller's observation time, and returns
//! before the `DreamerModelExecution` port is touched. That adapter is
//! constructed in production by `daemon_runtime::attach_dreamer_model`
//! through [`DaemonComposition::dreamer_model`](super::DaemonComposition::dreamer_model).
//!
//! [`AgentFabric::require_model_route`](super::agent_fabric::AgentFabric::require_model_route)
//! is NOT that gate and this module does not claim it is. It has no in-crate
//! production caller on this base: its only would-be caller,
//! [`DaemonComposition::drive_verified_agent_fabric`](super::DaemonComposition::drive_verified_agent_fabric),
//! itself has none, and the production B-MOD model-registry port
//! (`ProductionModelRegistryPort`) reports `PortBindingState::Missing`, so a
//! production route resolution cannot succeed in this crate at all. The gate
//! is therefore reachable only once its per-operation executor binds that
//! driver; the driver seam lives outside `bins/eliotd`, and no composition
//! method here invents a caller for it.
//!
//! Evidence bridge: `GetCapabilityEvidenceState` is the existing canonical
//! read for capability evidence (selected by exact `skill_id` +
//! `max_records`; see `operation_catalogue` and the `Affordances` role in
//! `GovernorContextInputs`). [`GovernorCapabilityAdmission::plan_evidence_read`]
//! builds that closed request for one skill, and
//! [`GovernorCapabilityAdmission::ingest_evidence_response`] decodes the
//! versioned store payload.
//!
//! What the read actually carries, measured on current store source: the
//! store answers with committed `ApplyLifecyclePolicy` authority-receipt rows,
//! each carrying exactly the six declared lifecycle parameters (`action`,
//! `base_view_digest`, `candidate_digest`, `candidate_package_digest`,
//! `skill_id`, `verifier_ref`) plus its commit-order `capture_index`. A row
//! carries no probe status, no evidence source, and no route-scope
//! fingerprint, so `ingest_evidence_response` mints no verified record from it
//! and reports observation currency only.
//!
//! Hydration therefore admits exactly one shape, and it is deliberately
//! non-admitting: [`GovernorCapabilityAdmission::hydrate_from_evidence_response`]
//! imports the read's skill through the legacy importer
//! ([`GovernorCapabilityAdmission::import_legacy`]), the only construction path
//! the adopted `CapabilityEvidenceRecord` relation allows for `declared`, and
//! leaves every scope-fingerprint field `None` (unknown, never inferred)
//! because the read exposes none. Such a record places the skill in
//! [`GovernorCapabilityAdmission::required_set`] and evaluates as
//! [`SkillStanding::Unevaluated`]. It can never satisfy
//! [`GovernorCapabilityAdmission::admit_production_route`], which requires
//! `probe_passed` or `observed` evidence from an admissible source on a
//! matching scope. Absence of canonical evidence therefore REFUSES a
//! production route; it is never treated as a pass, and never as "nothing to
//! check".
//!
//! Staleness is DERIVED, never persisted, and this module applies no
//! invalidation pass of its own. A changed runtime hash, adapter hash,
//! provider/model/auth route, serializer, or feature-flag scope stops
//! admitting through exact-fingerprint comparison alone:
//! [`admit_production_route`](Self::admit_production_route) requires a retained
//! record whose `scope_fingerprint` equals the observed scope by exact value,
//! so a record taken against a different adapter hash or serializer can no
//! longer authorize the changed route, and the exact route must be re-probed
//! first. No production site in `bins/eliotd` observes a dependency change to
//! report, so none invents one.
//!
//! [`apply_scope_change`](Self::apply_scope_change) remains the registry's own
//! facility for a caller that can attribute a change to a narrowed
//! [`ScopeDependencySelector`], and it is not invoked from any production site
//! in this crate. It is deliberately not used as a general "narrow to the
//! current route" operation: the registry inserts every record whose fingerprint
//! differs from the supplied scope into a growing `invalidated_scopes` set that
//! a later matching record does not revive, so passing an observed route scope
//! as the "current" scope would permanently invalidate still-valid evidence for
//! every other account and route.

use std::collections::BTreeMap;

use eliot_config::legacy_capability_import::{
    LegacyCapabilityDeclaration, LegacyImportError, LegacyScopeFingerprint,
    import_legacy_declaration,
};
use eliot_governor::{
    CapabilityEvidenceRecord, CapabilityRegistry, RouteScopeFingerprint, ScopeDependencySelector,
    SkillStanding,
};
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    ReadConsistency, ScopeId,
};
use thiserror::Error;

/// Fail-closed errors for the daemon capability-evidence bridge.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EvidenceBridgeError {
    /// The skill identity is blank or carries control characters.
    #[error("capability evidence skill identity must be non-blank with no control characters")]
    BlankSkill,
    /// The record bound is outside `1..=EVIDENCE_PACK_MAX_RECORDS`.
    #[error("capability evidence max_records must be within 1..=32")]
    BadBound,
    /// The store request is structurally invalid.
    #[error("capability evidence read request is invalid: {0}")]
    Request(String),
    /// The store response answers a different operation, fence, scope, or
    /// skill than the planned read.
    #[error("capability evidence response does not answer the planned read: {0}")]
    ResponseMismatch(&'static str),
    /// The store payload is not the versioned capability-evidence shape.
    #[error("capability evidence payload is not the versioned shape: {0}")]
    Payload(&'static str),
}

/// Daemon-held Governor capability admission view.
///
/// Constructed empty by the daemon composition root and consulted before
/// route execution; hydrated from the canonical evidence read and the
/// legacy importer. Semantics stay in [`CapabilityRegistry`].
#[derive(Debug, Default)]
pub struct GovernorCapabilityAdmission {
    registry: CapabilityRegistry,
}

impl GovernorCapabilityAdmission {
    /// Creates an empty admission view.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: CapabilityRegistry::new(),
        }
    }

    /// Returns the underlying canonical registry.
    #[must_use]
    pub const fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    /// Returns the number of retained evidence records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Returns true when no evidence records are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// Inserts one canonical evidence record (probe/observation path).
    pub fn insert(&mut self, record: CapabilityEvidenceRecord) {
        self.registry.insert(record);
    }

    /// Imports one legacy declaration as `declared/imported_legacy`.
    ///
    /// # Errors
    ///
    /// Returns [`LegacyImportError`] when the legacy skill identity is
    /// blank or carries control characters.
    pub fn import_legacy(
        &mut self,
        declaration: &LegacyCapabilityDeclaration,
    ) -> Result<(), LegacyImportError> {
        let imported = import_legacy_declaration(declaration)?;
        self.registry
            .insert(CapabilityEvidenceRecord::from(&imported));
        Ok(())
    }

    /// Returns the canonical required capability set: distinct skill
    /// identities with retained evidence records, sorted. No semantic rule
    /// lives here; this is the Governor registry's observed model.
    #[must_use]
    pub fn required_set(&self) -> Vec<String> {
        self.registry.required_set()
    }

    /// Returns the standing of one skill at `now` across its retained
    /// scopes. No semantic rule lives here; this is the Governor
    /// registry's aggregation of its verified predicates.
    #[must_use]
    pub fn skill_standing(&self, skill_id: &str, now: u64) -> SkillStanding {
        self.registry.skill_standing(skill_id, now)
    }

    /// Production admission for one skill on one exact route scope at `now`.
    ///
    /// The observation time is the daemon's real clock reading
    /// (`unix_ms`): positive evidence expires and goes stale in a running
    /// daemon instead of admitting forever.
    #[must_use]
    pub fn admit_production_route(
        &self,
        skill_id: &str,
        scope: &RouteScopeFingerprint,
        now: u64,
    ) -> bool {
        self.registry.admit_production_route(skill_id, scope, now)
    }

    /// Stales dependent evidence after a narrowed dependency change.
    /// Returns the count of newly staled records.
    pub fn apply_scope_change(
        &mut self,
        current: &RouteScopeFingerprint,
        changed: ScopeDependencySelector,
    ) -> usize {
        self.registry.apply_scope_change(current, changed)
    }

    /// Hydrates the held view from one canonical evidence-read response.
    ///
    /// Runs the full [`ingest_evidence_response`](Self::ingest_evidence_response)
    /// identity/shape validation first — a response that answers another
    /// operation, fence, scope, skill, or payload version never reaches the
    /// registry — then imports the read's skill through
    /// [`import_legacy`](Self::import_legacy) when the store holds committed
    /// governance rows for it.
    ///
    /// The imported record is `declared` / `imported_legacy_declaration` on a
    /// fully unknown route-scope fingerprint, for the two measured reasons
    /// stated in the module documentation: the served lifecycle row exposes no
    /// status, no source, and no scope fingerprint, and `declared` is the only
    /// status the adopted `CapabilityEvidenceRecord` relation admits without
    /// verified evidence. The record therefore establishes the required
    /// capability key space and the visible-degradation report, and can never
    /// satisfy [`admit_production_route`](Self::admit_production_route).
    ///
    /// A read that matched no row imports nothing: the view keeps its previous
    /// contents and no absence is ever promoted into evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the response does not answer the
    /// planned read, the payload is not the versioned shape, or the read's
    /// skill identity is not importable.
    pub fn hydrate_from_evidence_response(
        &mut self,
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<CapabilityHydration, EvidenceBridgeError> {
        let summary = self.ingest_evidence_response(request, response)?;
        let mut declared_records = 0;
        if summary.returned > 0 {
            self.import_legacy(&LegacyCapabilityDeclaration {
                skill_id: summary.skill_id.clone(),
                scope: LegacyScopeFingerprint::default(),
            })
            // The importer's only rejection is a blank or control-bearing skill
            // identity, which is exactly the bridge's own identity failure.
            .map_err(|_| EvidenceBridgeError::BlankSkill)?;
            declared_records = 1;
        }
        Ok(CapabilityHydration {
            summary,
            declared_records,
            retained: self.len(),
        })
    }

    /// Plans the closed canonical evidence read for one skill.
    ///
    /// The request carries the exact `skill_id` + `max_records` selectors
    /// the store catalogue declares for `GetCapabilityEvidenceState`, under
    /// the caller-supplied scope and `ExactFence` fence. It executes through
    /// [`KernelContextReadClient`](super::kernel_context_read_client::KernelContextReadClient),
    /// which remains the downstream authority on the wire shape.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the skill identity or bound is
    /// not closed, or the built request is structurally invalid.
    pub fn plan_evidence_read(
        skill_id: &str,
        max_records: u32,
        scope: ScopeId,
        fence: eliot_contracts::StateFence,
    ) -> Result<NamedReadRequest, EvidenceBridgeError> {
        if skill_id.trim().is_empty() || skill_id.chars().any(char::is_control) {
            return Err(EvidenceBridgeError::BlankSkill);
        }
        if max_records == 0 || max_records > EVIDENCE_PACK_MAX_RECORDS {
            return Err(EvidenceBridgeError::BadBound);
        }
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "skill_id".to_owned(),
            serde_json::Value::String(skill_id.to_owned()),
        );
        parameters.insert(
            "max_records".to_owned(),
            serde_json::Value::String(max_records.to_string()),
        );
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetCapabilityEvidenceState,
            scope_id: Some(scope),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence,
            parameters,
        };
        request
            .validate()
            .map_err(|error| EvidenceBridgeError::Request(error.to_string()))?;
        Ok(request)
    }

    /// Decodes one evidence-read response planned by
    /// [`plan_evidence_read`](Self::plan_evidence_read).
    ///
    /// Validates operation, fence, scope, skill, and payload-version
    /// identity, then reports how many admitted lifecycle records the store
    /// holds for the skill. Lifecycle rows carry no probe status, source,
    /// or scope fingerprint, so ingest mints no evidence records: the
    /// count is observation currency for operators, never admission.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the response does not answer
    /// the planned read or the payload is not the versioned shape.
    pub fn ingest_evidence_response(
        &self,
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<ObservedLifecycleSummary, EvidenceBridgeError> {
        if response.operation != NamedReadOperation::GetCapabilityEvidenceState
            || response.operation != request.operation
        {
            return Err(EvidenceBridgeError::ResponseMismatch("operation"));
        }
        if response.state_fence != request.state_fence {
            return Err(EvidenceBridgeError::ResponseMismatch("fence"));
        }
        response
            .validate()
            .map_err(|_| EvidenceBridgeError::ResponseMismatch("shape"))?;
        let payload = &response.payload;
        let version = payload.get("version").and_then(serde_json::Value::as_u64);
        if version != Some(1) {
            return Err(EvidenceBridgeError::Payload("version"));
        }
        let planned_skill = request
            .parameters
            .get("skill_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(EvidenceBridgeError::Payload("skill"))?;
        let payload_skill = payload
            .get("skill_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(EvidenceBridgeError::Payload("skill"))?;
        if payload_skill != planned_skill {
            return Err(EvidenceBridgeError::Payload("skill"));
        }
        let planned_scope = request
            .scope_id
            .clone()
            .ok_or(EvidenceBridgeError::Payload("scope"))?;
        let payload_scope = payload
            .get("scope_id")
            .ok_or(EvidenceBridgeError::Payload("scope"))?;
        let planned_scope_value = serde_json::to_value(&planned_scope)
            .map_err(|_| EvidenceBridgeError::Payload("scope"))?;
        if payload_scope != &planned_scope_value {
            return Err(EvidenceBridgeError::Payload("scope"));
        }
        let provenance = payload
            .get("provenance")
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        let matched_total = provenance
            .get("matched_total")
            .and_then(serde_json::Value::as_u64)
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        let returned = provenance
            .get("returned")
            .and_then(serde_json::Value::as_u64)
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        let truncated = provenance
            .get("truncated")
            .and_then(serde_json::Value::as_bool)
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        Ok(ObservedLifecycleSummary {
            skill_id: planned_skill.to_owned(),
            matched_total,
            returned,
            truncated,
        })
    }
}

/// Observation currency decoded from one evidence-read response: how many
/// admitted lifecycle records the store holds for the skill. Never
/// admission by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedLifecycleSummary {
    /// Skill the read selected.
    pub skill_id: String,
    /// Total matching lifecycle records at the admitted fence.
    pub matched_total: u64,
    /// Records carried in this payload.
    pub returned: u64,
    /// Whether the store truncated to the requested bound.
    pub truncated: bool,
}

/// Result of hydrating the held view from one canonical evidence read.
///
/// `declared_records` is the count of `declared` / `imported_legacy`
/// contributions the read added; a read that matched no committed governance
/// row adds none and leaves the registry exactly as it was.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityHydration {
    /// Observation currency decoded from the served payload.
    pub summary: ObservedLifecycleSummary,
    /// Declared/imported records this read contributed (0 or 1).
    pub declared_records: usize,
    /// Records the held view retains after hydration.
    pub retained: usize,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_config::legacy_capability_import::LegacyScopeFingerprint;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_governor::{CapabilitySource, CapabilityStatus};
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn scope() -> RouteScopeFingerprint {
        RouteScopeFingerprint {
            runtime_hash: Some("runtime-hash-1".into()),
            adapter_hash: Some("adapter-hash-1".into()),
            os_architecture: Some("x86_64-windows".into()),
            auth_profile_class: Some("user-broker".into()),
            provider_model_route: Some("provider/model/auth".into()),
            feature_flags_and_serializer: Some("serializer-v1".into()),
        }
    }

    fn probe(skill: &str, observed_at: u64) -> CapabilityEvidenceRecord {
        CapabilityEvidenceRecord::verified(
            skill,
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            scope(),
            observed_at,
        )
        .expect("valid probe verifies")
    }

    fn scope_id() -> ScopeId {
        ScopeId::new("governor").expect("scope")
    }

    #[test]
    fn admission_is_held_and_consulted_with_real_time() {
        let mut admission = GovernorCapabilityAdmission::new();
        assert!(admission.is_empty());
        admission
            .import_legacy(&LegacyCapabilityDeclaration {
                skill_id: "skill-demo".into(),
                scope: LegacyScopeFingerprint::default(),
            })
            .expect("legacy imports");
        assert_eq!(admission.len(), 1);
        // Declared/imported evidence never admits, even with no other data.
        assert!(!admission.admit_production_route("skill-demo", &scope(), 10));
        admission.insert(probe("skill-demo", 1));
        assert!(admission.admit_production_route("skill-demo", &scope(), 10));
        // Positive evidence goes stale in the running daemon: expiry ends
        // admission without any other write.
        let mut expiring = GovernorCapabilityAdmission::new();
        expiring.insert(probe("skill-demo", 1).expires_at(10));
        assert!(expiring.admit_production_route("skill-demo", &scope(), 9));
        assert!(!expiring.admit_production_route("skill-demo", &scope(), 10));
    }

    #[test]
    fn scope_change_stales_through_the_held_view() {
        let mut admission = GovernorCapabilityAdmission::new();
        admission.insert(probe("skill-demo", 1));
        assert!(admission.admit_production_route("skill-demo", &scope(), 10));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        let selector = ScopeDependencySelector {
            adapter_hash: true,
            ..ScopeDependencySelector::none()
        };
        assert_eq!(admission.apply_scope_change(&changed, selector), 1);
        assert!(!admission.admit_production_route("skill-demo", &changed, 10));
    }

    #[test]
    fn required_set_and_standing_read_through_the_held_view() {
        let mut admission = GovernorCapabilityAdmission::new();
        assert!(admission.required_set().is_empty());
        admission.insert(probe("skill-demo", 1));
        assert_eq!(admission.required_set(), vec!["skill-demo".to_owned()]);
        assert_eq!(
            admission.skill_standing("skill-demo", 10),
            SkillStanding::Holding
        );
        assert_eq!(
            admission.skill_standing("skill-unknown", 10),
            SkillStanding::Unevaluated
        );
    }

    #[test]
    fn evidence_read_plan_carries_the_closed_selectors() {
        let request =
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 8, scope_id(), fence())
                .expect("closed plan builds");
        assert_eq!(
            request.operation,
            NamedReadOperation::GetCapabilityEvidenceState
        );
        assert_eq!(request.consistency, ReadConsistency::ExactFence);
        assert_eq!(
            request.parameters.get("skill_id"),
            Some(&serde_json::Value::String("skill-demo".to_owned()))
        );
        assert_eq!(
            request.parameters.get("max_records"),
            Some(&serde_json::Value::String("8".to_owned()))
        );
        assert_eq!(
            GovernorCapabilityAdmission::plan_evidence_read("  ", 8, scope_id(), fence()),
            Err(EvidenceBridgeError::BlankSkill)
        );
        assert_eq!(
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 0, scope_id(), fence()),
            Err(EvidenceBridgeError::BadBound)
        );
        assert_eq!(
            GovernorCapabilityAdmission::plan_evidence_read(
                "skill-demo",
                EVIDENCE_PACK_MAX_RECORDS + 1,
                scope_id(),
                fence()
            ),
            Err(EvidenceBridgeError::BadBound)
        );
    }

    #[test]
    fn ingest_reports_lifecycle_observations_without_minting_evidence() {
        let admission = GovernorCapabilityAdmission::new();
        let request =
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 8, scope_id(), fence())
                .expect("plan builds");
        let scope_value = serde_json::to_value(scope_id()).expect("scope serializes");
        let response = NamedReadResponse {
            operation: NamedReadOperation::GetCapabilityEvidenceState,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload: serde_json::json!({
                "version": 1,
                "skill_id": "skill-demo",
                "scope_id": scope_value,
                "records": [],
                "provenance": {
                    "state_fence": serde_json::to_value(fence()).expect("fence serializes"),
                    "matched_total": 3,
                    "returned": 3,
                    "max_records": 8,
                    "truncated": false,
                },
            }),
        };
        let summary = admission
            .ingest_evidence_response(&request, &response)
            .expect("versioned payload ingests");
        assert_eq!(summary.skill_id, "skill-demo");
        assert_eq!(summary.matched_total, 3);
        assert!(!summary.truncated);
        // Ingest mints nothing: the view still holds no evidence.
        assert!(admission.is_empty());
        assert!(!admission.admit_production_route("skill-demo", &scope(), 10));
    }

    #[test]
    fn ingest_rejects_identity_substitution() {
        let admission = GovernorCapabilityAdmission::new();
        let request =
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 8, scope_id(), fence())
                .expect("plan builds");
        let scope_value = serde_json::to_value(scope_id()).expect("scope serializes");
        let payload = serde_json::json!({
            "version": 1,
            "skill_id": "skill-other",
            "scope_id": scope_value,
            "records": [],
            "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
        });
        let response = NamedReadResponse {
            operation: NamedReadOperation::GetCapabilityEvidenceState,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload,
        };
        assert_eq!(
            admission.ingest_evidence_response(&request, &response),
            Err(EvidenceBridgeError::Payload("skill"))
        );
        let wrong_op = NamedReadResponse {
            operation: NamedReadOperation::GetTaskState,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload: serde_json::json!({}),
        };
        assert_eq!(
            admission.ingest_evidence_response(&request, &wrong_op),
            Err(EvidenceBridgeError::ResponseMismatch("operation"))
        );
    }
}
