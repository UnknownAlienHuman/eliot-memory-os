//! Task-relative tool-surface decision compiled under the semantic owner (I7.24).
//!
//! The [`SemanticRegistry`] remains the single operational semantics owner.
//! This module compiles one closed, versioned [`ToolSurfaceDecision`] for the
//! current task/role/route from the registry's complete considered set plus
//! task conditions supplied by the Governor/Kernel owners, then derives the
//! permitted subset from the owner-joined published surface
//! ([`published_mcp_tool_surface`])
//! and validated semantic-owner bindings. Unavailable and forbidden methods
//! are withheld from the permitted subset, never merely discouraged in prose.
//! Dispositions never grant authority: call admission resolves the invoked
//! method by name from the live owners whether it was advertised or hidden.

use std::collections::{BTreeMap, BTreeSet};

use eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES;
use eliot_receipts::surface::{
    MaterialGrantStanding, authorize_material_grant, resolve_material_grant,
};
use eliot_receipts::{
    BudgetCoverage, BudgetOverflow, GrantClosureReceipt, OverflowDisposition, RenderedToolCost,
    SurfaceBudgetInput, TOOL_SURFACE_CONTRACT_VERSION, TokenCountObservation,
    TokenCountUnavailableReason, ToolExposureError, ToolSurfaceBudget, compile_surface_budget,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CANONICAL_DEFINITION_VERSION, EffectClass, OperationClass, SemanticRegistry,
    ToolMethodIdentity, ToolSchema, known_tool_profile, published_mcp_tool_surface,
};

/// Maximum number of methods carried by one surface decision.
pub const MAX_SURFACE_METHODS: usize = 64;
/// Maximum UTF-8 bytes of one surface decision text field.
pub const MAX_SURFACE_TEXT_BYTES: usize = 4_096;
/// Maximum capability-evidence references per considered method.
pub const MAX_EVIDENCE_PER_METHOD: usize = 8;
/// Maximum policy references carried by one surface decision.
pub const MAX_POLICY_REFS: usize = 16;

/// Failure to compile, validate, or derive a task-relative tool surface.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SurfaceDecisionError {
    /// A required text field is blank, oversized, or carries control characters.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable public reason.
        reason: &'static str,
    },
    /// A method is not in the decision's considered set.
    #[error("surface method is not in the considered set: {method}")]
    UnknownMethod {
        /// Canonical method name.
        method: String,
    },
    /// A method appears twice or its reason disagrees with its set.
    #[error("surface method has conflicting or duplicate decision entries: {method}")]
    DispositionConflict {
        /// Canonical method name.
        method: String,
    },
    /// The decision does not completely cover its considered set.
    #[error("task-relative surface is incomplete: {detail}")]
    IncompleteSurface {
        /// Stable public detail.
        detail: &'static str,
    },
    /// The generated descriptor catalogue is unavailable.
    #[error("generated tool descriptors are unavailable")]
    DescriptorsUnavailable,
}

/// Advertisement disposition of one considered method.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SurfaceDisposition {
    /// Rendered inline on the advertised surface.
    Visible,
    /// Advertised by handle; detail loads lazily with a policy recheck.
    LazyVisible,
    /// Withheld from advertisement; invocation by name still needs authorization.
    Hidden,
    /// Withheld by task/role policy or effect ceiling.
    Forbidden,
}

/// Task, role, scope, route, and capability conditions supplied by the
/// Governor/Kernel owners for one surface compilation.
///
/// The surface compiler never mints task, role, grant, or capability facts:
/// every condition arrives from its owner and is validated for shape only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSurfaceConditions {
    /// Exact task identity from the Governor owner.
    pub task_ref: String,
    /// Role the surface is compiled for.
    pub role: String,
    /// Scope the surface is compiled for.
    pub scope_ref: String,
    /// Route fingerprint the surface is compiled for.
    pub route_fingerprint: String,
    /// State Fence reference the surface is compiled against.
    pub state_fence: String,
    /// Governance Profile revision from the Governor owner.
    pub governance_profile: String,
    /// Grant revision from the authority owner.
    pub grant_revision: String,
    /// Canonical methods admitted for this task/role.
    pub admitted: BTreeSet<String>,
    /// Canonical methods forbidden for this task/role.
    pub forbidden: BTreeSet<String>,
    /// Owner-resolved capability evidence per canonical method.
    pub capability_evidence: BTreeMap<String, Vec<String>>,
    /// Strongest effect class admitted for this task/role.
    pub effect_ceiling: EffectClass,
    /// Privacy boundary for this task/role.
    pub privacy_boundary: String,
    /// Expected evidence, decision, artifact, or proof delta.
    pub expected_delta: String,
    /// Cheaper or safer alternative to this surface.
    pub cheaper_alternative: String,
    /// Recheck policy for lazy expansion.
    pub expansion_recheck: String,
    /// Policy references this decision depends on.
    pub policy_refs: Vec<String>,
}

impl TaskSurfaceConditions {
    /// Validates condition shape without resolving any owner fact.
    pub fn validate(&self) -> Result<(), SurfaceDecisionError> {
        bounded_text(&self.task_ref, "conditions.task_ref")?;
        bounded_text(&self.role, "conditions.role")?;
        bounded_text(&self.scope_ref, "conditions.scope_ref")?;
        bounded_text(&self.route_fingerprint, "conditions.route_fingerprint")?;
        bounded_text(&self.state_fence, "conditions.state_fence")?;
        bounded_text(&self.governance_profile, "conditions.governance_profile")?;
        bounded_text(&self.grant_revision, "conditions.grant_revision")?;
        if self.admitted.len() > MAX_SURFACE_METHODS || self.forbidden.len() > MAX_SURFACE_METHODS {
            return Err(SurfaceDecisionError::InvalidField {
                field: "conditions.admitted",
                reason: "exceeds the bounded method count",
            });
        }
        for name in self.admitted.iter().chain(self.forbidden.iter()) {
            bounded_text(name, "conditions.method")?;
        }
        if self.admitted.intersection(&self.forbidden).next().is_some() {
            return Err(SurfaceDecisionError::InvalidField {
                field: "conditions.forbidden",
                reason: "must not admit and forbid the same method",
            });
        }
        if self.capability_evidence.len() > MAX_SURFACE_METHODS {
            return Err(SurfaceDecisionError::InvalidField {
                field: "conditions.capability_evidence",
                reason: "exceeds the bounded method count",
            });
        }
        for (name, evidence) in &self.capability_evidence {
            bounded_text(name, "conditions.capability_evidence.method")?;
            if evidence.len() > MAX_EVIDENCE_PER_METHOD {
                return Err(SurfaceDecisionError::InvalidField {
                    field: "conditions.capability_evidence",
                    reason: "exceeds the bounded evidence count",
                });
            }
            for reference in evidence {
                bounded_text(reference, "conditions.capability_evidence")?;
            }
        }
        bounded_text(&self.privacy_boundary, "conditions.privacy_boundary")?;
        bounded_text(&self.expected_delta, "conditions.expected_delta")?;
        bounded_text(&self.cheaper_alternative, "conditions.cheaper_alternative")?;
        bounded_text(&self.expansion_recheck, "conditions.expansion_recheck")?;
        if self.policy_refs.len() > MAX_POLICY_REFS {
            return Err(SurfaceDecisionError::InvalidField {
                field: "conditions.policy_refs",
                reason: "exceeds the bounded policy reference count",
            });
        }
        for reference in &self.policy_refs {
            bounded_text(reference, "conditions.policy_refs")?;
        }
        Ok(())
    }
}

/// One considered method/version with its capability evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsideredSurfaceMethod {
    /// Versioned method identity.
    pub method: ToolMethodIdentity,
    /// Exact semantic-profile version considered.
    pub profile_version: String,
    /// Operation class owned by the profile.
    pub operation_class: OperationClass,
    /// Effect class owned by the profile.
    pub effect_class: EffectClass,
    /// Owner-resolved capability evidence references.
    pub capability_evidence: Vec<String>,
}

/// Selection or suppression reason for one considered method.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceMethodReason {
    /// Canonical method name.
    pub method: String,
    /// Disposition assigned to the method.
    pub disposition: SurfaceDisposition,
    /// Closed selection/suppression reason.
    pub reason: String,
}

/// Expansion path for lazy-visible methods.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceExpansion {
    /// Canonical lazy-visible methods covered by this path.
    pub lazy_methods: Vec<String>,
    /// Recheck policy applied before lazy expansion.
    pub recheck_policy: String,
}

/// Invalidation dependencies of one surface decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceInvalidation {
    /// Tool Definition revisions this decision depends on.
    pub definition_revisions: Vec<String>,
    /// Semantic-profile revisions as `name@version` entries.
    pub profile_revisions: Vec<String>,
    /// Policy references this decision depends on.
    pub policy_refs: Vec<String>,
}

/// Closed versioned task-relative tool-surface decision (I7.24).
///
/// Compiled under the existing semantic owner from the registry's complete
/// method/version set. Every considered method carries capability evidence
/// and lands in exactly one disposition set with a recorded reason. The
/// decision governs advertisement only; it grants no execution authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceDecision {
    /// Wire contract revision. Must equal the shared surface contract version.
    pub schema_version: u16,
    /// Exact task identity this decision was compiled for.
    pub task_ref: String,
    /// Role this decision was compiled for.
    pub role: String,
    /// Scope this decision was compiled for.
    pub scope_ref: String,
    /// Route fingerprint this decision was compiled for.
    pub route_fingerprint: String,
    /// State Fence reference this decision was compiled against.
    pub state_fence: String,
    /// Governance Profile revision this decision was compiled against.
    pub governance_profile: String,
    /// Grant revision this decision was compiled against.
    pub grant_revision: String,
    /// Complete considered method/version set with capability evidence.
    pub considered: Vec<ConsideredSurfaceMethod>,
    /// Canonical methods rendered inline.
    pub visible: Vec<String>,
    /// Canonical methods advertised by handle.
    pub lazy_visible: Vec<String>,
    /// Canonical methods withheld from advertisement.
    pub hidden: Vec<String>,
    /// Canonical methods withheld by policy or effect ceiling.
    pub forbidden: Vec<String>,
    /// Exactly one selection/suppression reason per considered method.
    pub reasons: Vec<SurfaceMethodReason>,
    /// Admitted effect classes as `SCREAMING_SNAKE_CASE` names.
    pub effect_limits: Vec<String>,
    /// Privacy boundary for this task/role.
    pub privacy_boundary: String,
    /// Expected evidence, decision, artifact, or proof delta.
    pub expected_delta: String,
    /// Cheaper or safer alternative to this surface.
    pub cheaper_alternative: String,
    /// Expansion path for lazy-visible methods.
    pub expansion: SurfaceExpansion,
    /// Invalidation dependencies of this decision.
    pub invalidation: SurfaceInvalidation,
}

impl ToolSurfaceDecision {
    /// Returns the disposition assigned to one method, if considered.
    #[must_use]
    pub fn disposition_of(&self, method: &str) -> Option<SurfaceDisposition> {
        if self.visible.iter().any(|name| name == method) {
            Some(SurfaceDisposition::Visible)
        } else if self.lazy_visible.iter().any(|name| name == method) {
            Some(SurfaceDisposition::LazyVisible)
        } else if self.hidden.iter().any(|name| name == method) {
            Some(SurfaceDisposition::Hidden)
        } else if self.forbidden.iter().any(|name| name == method) {
            Some(SurfaceDisposition::Forbidden)
        } else {
            None
        }
    }

    /// Validates version, completeness, partition, reasons, limits,
    /// expansion, and invalidation without consulting any owner.
    pub fn validate(&self) -> Result<(), SurfaceDecisionError> {
        if self.schema_version != TOOL_SURFACE_CONTRACT_VERSION {
            return Err(SurfaceDecisionError::InvalidField {
                field: "decision.schema_version",
                reason: "unsupported tool surface contract version",
            });
        }
        bounded_text(&self.task_ref, "decision.task_ref")?;
        bounded_text(&self.role, "decision.role")?;
        bounded_text(&self.scope_ref, "decision.scope_ref")?;
        bounded_text(&self.route_fingerprint, "decision.route_fingerprint")?;
        bounded_text(&self.state_fence, "decision.state_fence")?;
        bounded_text(&self.governance_profile, "decision.governance_profile")?;
        bounded_text(&self.grant_revision, "decision.grant_revision")?;
        let considered = self.validate_considered()?;
        self.validate_partition(&considered)?;
        self.validate_reasons(&considered)?;
        self.validate_limits()?;
        self.validate_expansion()?;
        self.validate_invalidation(&considered)?;
        Ok(())
    }

    fn validate_considered(
        &self,
    ) -> Result<BTreeMap<&str, &ConsideredSurfaceMethod>, SurfaceDecisionError> {
        if self.considered.is_empty() {
            return Err(SurfaceDecisionError::IncompleteSurface {
                detail: "considered set must not be empty",
            });
        }
        if self.considered.len() > MAX_SURFACE_METHODS {
            return Err(SurfaceDecisionError::InvalidField {
                field: "decision.considered",
                reason: "exceeds the bounded method count",
            });
        }
        let mut considered = BTreeMap::new();
        for entry in &self.considered {
            bounded_text(
                &entry.method.canonical_name,
                "decision.considered.method.canonical_name",
            )?;
            bounded_text(
                &entry.method.definition_version,
                "decision.considered.method.definition_version",
            )?;
            bounded_text(
                &entry.profile_version,
                "decision.considered.profile_version",
            )?;
            if entry.capability_evidence.len() > MAX_EVIDENCE_PER_METHOD {
                return Err(SurfaceDecisionError::InvalidField {
                    field: "decision.considered.capability_evidence",
                    reason: "exceeds the bounded evidence count",
                });
            }
            for reference in &entry.capability_evidence {
                bounded_text(reference, "decision.considered.capability_evidence")?;
            }
            if considered
                .insert(entry.method.canonical_name.as_str(), entry)
                .is_some()
            {
                return Err(SurfaceDecisionError::DispositionConflict {
                    method: entry.method.canonical_name.clone(),
                });
            }
        }
        Ok(considered)
    }

    fn validate_partition(
        &self,
        considered: &BTreeMap<&str, &ConsideredSurfaceMethod>,
    ) -> Result<(), SurfaceDecisionError> {
        let mut assigned = BTreeSet::new();
        for name in self
            .visible
            .iter()
            .chain(self.lazy_visible.iter())
            .chain(self.hidden.iter())
            .chain(self.forbidden.iter())
        {
            bounded_text(name, "decision.disposition")?;
            if !considered.contains_key(name.as_str()) {
                return Err(SurfaceDecisionError::UnknownMethod {
                    method: name.clone(),
                });
            }
            if !assigned.insert(name.as_str()) {
                return Err(SurfaceDecisionError::DispositionConflict {
                    method: name.clone(),
                });
            }
        }
        for name in considered.keys() {
            if !assigned.contains(*name) {
                return Err(SurfaceDecisionError::IncompleteSurface {
                    detail: "every considered method needs exactly one disposition",
                });
            }
        }
        Ok(())
    }

    fn validate_reasons(
        &self,
        considered: &BTreeMap<&str, &ConsideredSurfaceMethod>,
    ) -> Result<(), SurfaceDecisionError> {
        let mut reasoned = BTreeSet::new();
        for entry in &self.reasons {
            bounded_text(&entry.method, "decision.reasons.method")?;
            bounded_text(&entry.reason, "decision.reasons.reason")?;
            if !considered.contains_key(entry.method.as_str()) {
                return Err(SurfaceDecisionError::UnknownMethod {
                    method: entry.method.clone(),
                });
            }
            if !reasoned.insert(entry.method.as_str()) {
                return Err(SurfaceDecisionError::DispositionConflict {
                    method: entry.method.clone(),
                });
            }
            if self.disposition_of(&entry.method) != Some(entry.disposition) {
                return Err(SurfaceDecisionError::DispositionConflict {
                    method: entry.method.clone(),
                });
            }
        }
        for name in considered.keys() {
            if !reasoned.contains(*name) {
                return Err(SurfaceDecisionError::IncompleteSurface {
                    detail: "every considered method needs exactly one reason",
                });
            }
        }
        Ok(())
    }

    fn validate_limits(&self) -> Result<(), SurfaceDecisionError> {
        if self.effect_limits.is_empty() || self.effect_limits.len() > MAX_EVIDENCE_PER_METHOD {
            return Err(SurfaceDecisionError::InvalidField {
                field: "decision.effect_limits",
                reason: "must name one or more admitted effect classes",
            });
        }
        let mut seen = BTreeSet::new();
        for limit in &self.effect_limits {
            bounded_text(limit, "decision.effect_limits")?;
            if !seen.insert(limit.as_str()) {
                return Err(SurfaceDecisionError::InvalidField {
                    field: "decision.effect_limits",
                    reason: "must not contain duplicate effect classes",
                });
            }
        }
        bounded_text(&self.privacy_boundary, "decision.privacy_boundary")?;
        bounded_text(&self.expected_delta, "decision.expected_delta")?;
        bounded_text(&self.cheaper_alternative, "decision.cheaper_alternative")?;
        Ok(())
    }

    fn validate_expansion(&self) -> Result<(), SurfaceDecisionError> {
        let mut lazy = BTreeSet::new();
        for name in &self.expansion.lazy_methods {
            bounded_text(name, "decision.expansion.lazy_methods")?;
            if !lazy.insert(name.as_str()) {
                return Err(SurfaceDecisionError::DispositionConflict {
                    method: name.clone(),
                });
            }
        }
        let visible_lazy: BTreeSet<&str> = self.lazy_visible.iter().map(String::as_str).collect();
        if lazy != visible_lazy {
            return Err(SurfaceDecisionError::IncompleteSurface {
                detail: "expansion lazy methods must equal the lazy-visible set",
            });
        }
        bounded_text(
            &self.expansion.recheck_policy,
            "decision.expansion.recheck_policy",
        )?;
        Ok(())
    }

    fn validate_invalidation(
        &self,
        considered: &BTreeMap<&str, &ConsideredSurfaceMethod>,
    ) -> Result<(), SurfaceDecisionError> {
        if self.invalidation.definition_revisions.len() > MAX_SURFACE_METHODS
            || self.invalidation.profile_revisions.len() > MAX_SURFACE_METHODS
            || self.invalidation.policy_refs.len() > MAX_POLICY_REFS
        {
            return Err(SurfaceDecisionError::InvalidField {
                field: "decision.invalidation",
                reason: "exceeds a bounded invalidation count",
            });
        }
        for reference in self
            .invalidation
            .definition_revisions
            .iter()
            .chain(self.invalidation.profile_revisions.iter())
            .chain(self.invalidation.policy_refs.iter())
        {
            bounded_text(reference, "decision.invalidation")?;
        }
        for entry in considered.values() {
            if !self
                .invalidation
                .definition_revisions
                .iter()
                .any(|revision| revision == &entry.method.definition_version)
            {
                return Err(SurfaceDecisionError::IncompleteSurface {
                    detail: "every considered definition version needs an invalidation entry",
                });
            }
            let profile_entry =
                format!("{}@{}", entry.method.canonical_name, entry.profile_version);
            if !self
                .invalidation
                .profile_revisions
                .iter()
                .any(|revision| revision == &profile_entry)
            {
                return Err(SurfaceDecisionError::IncompleteSurface {
                    detail: "every considered profile version needs an invalidation entry",
                });
            }
        }
        Ok(())
    }
}

/// Compiles one [`ToolSurfaceDecision`] from the registry's complete set.
///
/// Every registered profile is considered exactly once in stable registry
/// order, so two compilations over equal inputs produce equal decisions.
/// Dispositions derive deterministically from the owner conditions plus
/// profile-owned facts; no method is inferred from names or prose.
///
/// The live grant-closure verdict is the grant/revocation owner join: the
/// claimed `grant_revision` in `conditions` authorizes Material (non-read-only)
/// advertisement only when the verdict is `Active` and covers it. A missing
/// verdict, a revoked closure, or an uncovered revision withholds every
/// Material method to `Hidden` with a recorded reason — a missing or revoked
/// grant can never enable Material dispatch through advertisement, while
/// read-only methods keep the narrowest observable capability. A blank grant
/// revision still fails the whole compile through [`TaskSurfaceConditions::validate`].
///
/// # Errors
///
/// Returns an error when the conditions are malformed or the compiled
/// decision fails [`ToolSurfaceDecision::validate`].
pub fn compile_surface_decision(
    registry: &SemanticRegistry,
    conditions: &TaskSurfaceConditions,
    grant_closure: Option<&GrantClosureReceipt>,
) -> Result<ToolSurfaceDecision, SurfaceDecisionError> {
    conditions.validate()?;
    let grant = resolve_material_grant(grant_closure, &conditions.grant_revision).ok();
    let mut considered = Vec::new();
    let mut visible = Vec::new();
    let mut lazy_visible = Vec::new();
    let mut hidden = Vec::new();
    let mut forbidden = Vec::new();
    let mut reasons = Vec::new();
    for profile in registry.profiles() {
        let name = profile.method.canonical_name.clone();
        let evidence = conditions
            .capability_evidence
            .get(&name)
            .cloned()
            .unwrap_or_default();
        let (disposition, reason) =
            decide_disposition(profile, conditions, &evidence, grant.as_ref());
        considered.push(ConsideredSurfaceMethod {
            method: profile.method.clone(),
            profile_version: profile.profile_version.clone(),
            operation_class: profile.operation_class,
            effect_class: profile.effect_class,
            capability_evidence: evidence,
        });
        match disposition {
            SurfaceDisposition::Visible => visible.push(name.clone()),
            SurfaceDisposition::LazyVisible => lazy_visible.push(name.clone()),
            SurfaceDisposition::Hidden => hidden.push(name.clone()),
            SurfaceDisposition::Forbidden => forbidden.push(name.clone()),
        }
        reasons.push(SurfaceMethodReason {
            method: name,
            disposition,
            reason: reason.to_owned(),
        });
    }
    let mut definition_revisions = BTreeSet::new();
    let mut profile_revisions = Vec::new();
    for entry in &considered {
        definition_revisions.insert(entry.method.definition_version.clone());
        profile_revisions.push(format!(
            "{}@{}",
            entry.method.canonical_name, entry.profile_version
        ));
    }
    let decision = ToolSurfaceDecision {
        schema_version: TOOL_SURFACE_CONTRACT_VERSION,
        task_ref: conditions.task_ref.clone(),
        role: conditions.role.clone(),
        scope_ref: conditions.scope_ref.clone(),
        route_fingerprint: conditions.route_fingerprint.clone(),
        state_fence: conditions.state_fence.clone(),
        governance_profile: conditions.governance_profile.clone(),
        grant_revision: conditions.grant_revision.clone(),
        considered,
        visible,
        lazy_visible: lazy_visible.clone(),
        hidden,
        forbidden,
        reasons,
        effect_limits: admitted_effect_names(conditions.effect_ceiling),
        privacy_boundary: conditions.privacy_boundary.clone(),
        expected_delta: conditions.expected_delta.clone(),
        cheaper_alternative: conditions.cheaper_alternative.clone(),
        expansion: SurfaceExpansion {
            lazy_methods: lazy_visible,
            recheck_policy: conditions.expansion_recheck.clone(),
        },
        invalidation: SurfaceInvalidation {
            definition_revisions: definition_revisions.into_iter().collect(),
            profile_revisions,
            policy_refs: conditions.policy_refs.clone(),
        },
    };
    decision.validate()?;
    Ok(decision)
}

fn decide_disposition(
    profile: &crate::ToolSemanticProfile,
    conditions: &TaskSurfaceConditions,
    evidence: &[String],
    grant: Option<&MaterialGrantStanding>,
) -> (SurfaceDisposition, &'static str) {
    let name = profile.method.canonical_name.as_str();
    if conditions.forbidden.contains(name) {
        return (
            SurfaceDisposition::Forbidden,
            "withheld by task/role policy",
        );
    }
    if !conditions.admitted.contains(name) {
        return (
            SurfaceDisposition::Hidden,
            "not admitted for this task/role; withheld from advertisement",
        );
    }
    if effect_rank(profile.effect_class) > effect_rank(conditions.effect_ceiling) {
        return (
            SurfaceDisposition::Forbidden,
            "effect class exceeds the task effect ceiling",
        );
    }
    // A2: a missing or revoked grant cannot enable Material dispatch. Only
    // read-only methods keep the narrowest observable capability without a
    // live standing; every Material method is withheld from advertisement
    // with its reason recorded, never merely discouraged in prose. The typed
    // grant gate fails closed on every error: a missing standing
    // (GrantRequired) and a revoked standing (GrantRevoked) withhold with
    // distinct recorded reasons so the two acceptance cases stay
    // distinguishable in the decision evidence.
    if effect_rank(profile.effect_class) > effect_rank(EffectClass::ReadOnly) {
        match authorize_material_grant(grant) {
            Ok(()) => {}
            Err(ToolExposureError::GrantRevoked) => {
                return (
                    SurfaceDisposition::Hidden,
                    "grant revoked; Material use withheld from advertisement",
                );
            }
            Err(_) => {
                return (
                    SurfaceDisposition::Hidden,
                    "no live grant standing; Material use withheld from advertisement",
                );
            }
        }
    }
    if !profile.introduction_requirements.is_empty() && evidence.is_empty() {
        return (
            SurfaceDisposition::Hidden,
            "capability evidence unresolved; registration alone does not qualify the capability",
        );
    }
    if profile.repetition.pagination_admitted {
        return (
            SurfaceDisposition::LazyVisible,
            "admitted; detail loads lazily through pagination handles",
        );
    }
    (
        SurfaceDisposition::Visible,
        "admitted for this task/role with satisfied capability evidence",
    )
}

const fn effect_rank(effect: EffectClass) -> u8 {
    match effect {
        EffectClass::ReadOnly => 0,
        EffectClass::ScopedMutation => 1,
        EffectClass::ExternalEffect => 2,
    }
}

fn admitted_effect_names(ceiling: EffectClass) -> Vec<String> {
    let mut names = vec!["READ_ONLY".to_owned()];
    if effect_rank(ceiling) >= effect_rank(EffectClass::ScopedMutation) {
        names.push("SCOPED_MUTATION".to_owned());
    }
    if effect_rank(ceiling) >= effect_rank(EffectClass::ExternalEffect) {
        names.push("EXTERNAL_EFFECT".to_owned());
    }
    names
}

/// One method withheld from the permitted subset, with its decision reason.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithheldSurfaceMethod {
    /// Canonical method name.
    pub method: String,
    /// Disposition assigned by the decision.
    pub disposition: SurfaceDisposition,
    /// Why the method is withheld.
    pub reason: String,
}

/// Permitted descriptors plus explicitly withheld methods.
#[derive(Clone, Debug, PartialEq)]
pub struct PermittedTaskSurface {
    /// Generated descriptors admitted for advertisement, in decision order.
    pub permitted: Vec<ToolSchema>,
    /// Considered methods withheld from advertisement, in decision order.
    pub withheld: Vec<WithheldSurfaceMethod>,
}

/// Derives the permitted subset before publishing.
///
/// Only visible and lazy-visible methods are admitted, and only when the
/// generated descriptor still agrees with the live validated semantic-owner
/// binding. Hidden, forbidden, and unavailable methods are withheld —
/// omitted from the permitted subset, never warned about in prose.
///
/// # Errors
///
/// Returns an error when the decision itself is invalid.
pub fn derive_permitted_surface(
    registry: &SemanticRegistry,
    decision: &ToolSurfaceDecision,
    descriptors: &[ToolSchema],
) -> Result<PermittedTaskSurface, SurfaceDecisionError> {
    decision.validate()?;
    let mut reasons = BTreeMap::new();
    for entry in &decision.reasons {
        reasons.insert(entry.method.as_str(), entry.reason.as_str());
    }
    let mut permitted = Vec::new();
    let mut withheld = Vec::new();
    for entry in &decision.considered {
        let name = entry.method.canonical_name.as_str();
        let reason = reasons.get(name).copied().unwrap_or_default();
        match decision.disposition_of(name) {
            Some(disposition @ (SurfaceDisposition::Visible | SurfaceDisposition::LazyVisible)) => {
                match live_descriptor_for(descriptors, entry) {
                    Some(descriptor)
                        if registry
                            .resolve(name, &entry.method.definition_version)
                            .is_ok() =>
                    {
                        permitted.push(descriptor.clone());
                    }
                    _ => withheld.push(WithheldSurfaceMethod {
                        method: name.to_owned(),
                        disposition,
                        reason: "live owner binding no longer matches the decision".to_owned(),
                    }),
                }
            }
            Some(disposition) => withheld.push(WithheldSurfaceMethod {
                method: name.to_owned(),
                disposition,
                reason: reason.to_owned(),
            }),
            None => {
                return Err(SurfaceDecisionError::UnknownMethod {
                    method: name.to_owned(),
                });
            }
        }
    }
    Ok(PermittedTaskSurface {
        permitted,
        withheld,
    })
}

fn live_descriptor_for<'a>(
    descriptors: &'a [ToolSchema],
    entry: &ConsideredSurfaceMethod,
) -> Option<&'a ToolSchema> {
    descriptors.iter().find(|descriptor| {
        descriptor.name == entry.method.canonical_name
            && descriptor.definition_version == entry.method.definition_version
    })
}

/// Compiles the no-task discovery decision from the live owner catalogue.
///
/// Discovery carries no owner-supplied task conditions, so no task-relative
/// narrowing applies: every descriptor of the owner-joined published surface
/// ([`published_mcp_tool_surface`]) is considered exactly once, in catalogue
/// order, and advertised [`SurfaceDisposition::Visible`] with a recorded
/// no-task reason. Owner-shaped identity fields carry explicit no-task
/// markers rather than invented task, role, grant, or capability facts. A
/// catalogued method without a live registered owner fails closed instead of
/// being advertised without semantics; withholding still applies downstream
/// in [`derive_permitted_surface`] when a live descriptor no longer matches
/// its owner binding.
///
/// # Errors
///
/// Returns an error when the published catalogue is unavailable, a catalogued
/// method has no live registered owner, or the compiled decision fails
/// [`ToolSurfaceDecision::validate`].
pub fn compile_discovery_surface_decision(
    registry: &SemanticRegistry,
) -> Result<ToolSurfaceDecision, SurfaceDecisionError> {
    let catalogue =
        published_mcp_tool_surface().map_err(|_| SurfaceDecisionError::DescriptorsUnavailable)?;
    let mut considered = Vec::with_capacity(catalogue.len());
    let mut visible = Vec::with_capacity(catalogue.len());
    let mut reasons = Vec::with_capacity(catalogue.len());
    let mut definition_revisions = BTreeSet::new();
    let mut profile_revisions = Vec::with_capacity(catalogue.len());
    for descriptor in &catalogue {
        let profile = registry
            .resolve(&descriptor.name, &descriptor.definition_version)
            .map_err(|_| SurfaceDecisionError::UnknownMethod {
                method: descriptor.name.clone(),
            })?;
        considered.push(ConsideredSurfaceMethod {
            method: profile.method.clone(),
            profile_version: profile.profile_version.clone(),
            operation_class: profile.operation_class,
            effect_class: profile.effect_class,
            capability_evidence: Vec::new(),
        });
        visible.push(descriptor.name.clone());
        reasons.push(SurfaceMethodReason {
            method: descriptor.name.clone(),
            disposition: SurfaceDisposition::Visible,
            reason: "no-task discovery advertisement; no task-relative narrowing applies"
                .to_owned(),
        });
        definition_revisions.insert(descriptor.definition_version.clone());
        profile_revisions.push(format!("{}@{}", descriptor.name, profile.profile_version));
    }
    let decision = ToolSurfaceDecision {
        schema_version: TOOL_SURFACE_CONTRACT_VERSION,
        task_ref: "no-task-discovery".to_owned(),
        role: "no-role-discovery".to_owned(),
        scope_ref: "no-scope-discovery".to_owned(),
        route_fingerprint: "no-route-discovery".to_owned(),
        state_fence: "no-state-fence-discovery".to_owned(),
        governance_profile: "no-governance-profile-discovery".to_owned(),
        grant_revision: "no-grant-discovery".to_owned(),
        considered,
        visible,
        lazy_visible: Vec::new(),
        hidden: Vec::new(),
        forbidden: Vec::new(),
        reasons,
        effect_limits: admitted_effect_names(EffectClass::ExternalEffect),
        privacy_boundary: "no-task discovery advertisement".to_owned(),
        expected_delta: "advertised catalogue only; no work delta".to_owned(),
        cheaper_alternative: "no-task discovery advertisement".to_owned(),
        expansion: SurfaceExpansion {
            lazy_methods: Vec::new(),
            recheck_policy: "no lazy methods on the discovery surface".to_owned(),
        },
        invalidation: SurfaceInvalidation {
            definition_revisions: definition_revisions.into_iter().collect(),
            profile_revisions,
            policy_refs: Vec::new(),
        },
    };
    decision.validate()?;
    Ok(decision)
}

/// One compiled task-relative surface: decision plus derived subsets.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskRelativeSurface {
    /// The compiled task-relative decision.
    pub decision: ToolSurfaceDecision,
    /// Generated descriptors admitted for advertisement.
    pub permitted: Vec<ToolSchema>,
    /// Considered methods withheld from advertisement.
    pub withheld: Vec<WithheldSurfaceMethod>,
}

/// Compiles the decision and derives the permitted subset in one pass.
///
/// Starts from the owner-joined published surface
/// ([`published_mcp_tool_surface`]: generated descriptors with validated live
/// semantic-owner bindings, failing closed on version disagreement), applies
/// the owner-supplied task conditions deterministically, and withholds
/// unavailable or forbidden methods. The live grant-closure
/// verdict is the grant/revocation owner: Material methods are withheld
/// without a live standing covering the claimed grant revision, so a
/// missing or revoked grant can never enable Material advertisement.
///
/// # Errors
///
/// Returns an error when descriptors are unavailable, the conditions are
/// malformed, or the compiled decision is invalid.
pub fn compile_task_relative_surface(
    registry: &SemanticRegistry,
    conditions: &TaskSurfaceConditions,
    grant_closure: Option<&GrantClosureReceipt>,
) -> Result<TaskRelativeSurface, SurfaceDecisionError> {
    let descriptors =
        published_mcp_tool_surface().map_err(|_| SurfaceDecisionError::DescriptorsUnavailable)?;
    let decision = compile_surface_decision(registry, conditions, grant_closure)?;
    let derived = derive_permitted_surface(registry, &decision, &descriptors)?;
    Ok(TaskRelativeSurface {
        decision,
        permitted: derived.permitted,
        withheld: derived.withheld,
    })
}

/// Binds the actual rendered `tools/list` surface to a [`ToolSurfaceBudget`].
///
/// Measures the exact rendered tool entries — description and schema bytes
/// from the final host serialization — and compiles the budget over them.
/// ELIOT ownership resolves through the live semantic owner, never from
/// name text. Route, role, tokenizer, reserve, and expiry owners are not
/// joined at this pre-task seam, so those fields stay explicitly unresolved;
/// non-ELIOT coverage stays incomplete because host/provider additions
/// beyond this projection are not observable here.
///
/// # Errors
///
/// Returns an error when a rendered entry has no measurable name,
/// description, or schema, or when the compiled budget is invalid.
pub fn bind_list_surface_budget(
    rendered_tools: &[Value],
) -> Result<ToolSurfaceBudget, ToolExposureError> {
    let mut tools = Vec::with_capacity(rendered_tools.len());
    for entry in rendered_tools {
        tools.push(measure_rendered_tool(entry)?);
    }
    let rendered_surface_bytes =
        serde_json::to_vec(rendered_tools).map_err(|_| ToolExposureError::InvalidField {
            field: "budget_input.rendered_surface_bytes",
            reason: "rendered surface bytes are not serializable",
        })?;
    let disposition = if rendered_surface_bytes.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        OverflowDisposition::OverflowUnresolved
    } else {
        OverflowDisposition::WithinBudget
    };
    let input = SurfaceBudgetInput {
        role: None,
        route_fingerprint: None,
        profile_revision: CANONICAL_DEFINITION_VERSION.to_owned(),
        rendered_surface_bytes,
        tools,
        builtin_tool_count: 0,
        hidden_tool_count: 0,
        hidden_eliot_tool_count: 0,
        non_eliot_coverage: BudgetCoverage::Incomplete {
            reason: "host and provider tools beyond this projection are not observable".to_owned(),
        },
        first_prompt_tokens: TokenCountObservation::Unavailable {
            reason: TokenCountUnavailableReason::TokenizerUnavailable,
        },
        protected_reserves: None,
        first_line_task_shape: "no-task discovery listing".to_owned(),
        overflow: BudgetOverflow {
            disposition,
            justification: None,
            alternative: None,
        },
        change_owner: "eliot-mcp tools/list projection".to_owned(),
        validity_scope: Some("single tools/list rendering".to_owned()),
        expires_at: None,
    };
    compile_surface_budget(&input)
}

fn measure_rendered_tool(entry: &Value) -> Result<RenderedToolCost, ToolExposureError> {
    let missing = ToolExposureError::InvalidField {
        field: "budget_input.rendered_tools",
        reason: "rendered tool entry is not measurable",
    };
    let tool = entry
        .get("name")
        .and_then(Value::as_str)
        .ok_or(missing.clone())?
        .to_owned();
    let description_bytes = entry
        .get("description")
        .and_then(Value::as_str)
        .ok_or(missing.clone())
        .map(str::len)?;
    let input_bytes = entry.get("inputSchema").ok_or(missing.clone())?;
    let output_bytes = entry.get("outputSchema").ok_or(missing)?;
    let input_len = serde_json::to_vec(input_bytes)
        .map_err(|_| ToolExposureError::InvalidField {
            field: "budget_input.rendered_tools",
            reason: "rendered schema bytes are not serializable",
        })
        .map(|bytes| bytes.len())?;
    let output_len = serde_json::to_vec(output_bytes)
        .map_err(|_| ToolExposureError::InvalidField {
            field: "budget_input.rendered_tools",
            reason: "rendered schema bytes are not serializable",
        })
        .map(|bytes| bytes.len())?;
    let schema_bytes = input_len.saturating_add(output_len);
    // ELIOT ownership resolves through the live semantic owner: a rendered
    // tool without a registered profile is not ELIOT-owned.
    let is_eliot_owned = known_tool_profile(&tool).is_ok();
    Ok(RenderedToolCost {
        tool,
        is_eliot_owned,
        description_bytes: u64::try_from(description_bytes).unwrap_or(u64::MAX),
        schema_bytes: u64::try_from(schema_bytes).unwrap_or(u64::MAX),
        // This projection renders no examples or permission text; absence is
        // measured from the entries above, not estimated.
        example_bytes: 0,
        permission_bytes: 0,
        lazy_handle: None,
    })
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), SurfaceDecisionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SurfaceDecisionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    if value.len() > MAX_SURFACE_TEXT_BYTES {
        return Err(SurfaceDecisionError::InvalidField {
            field,
            reason: "exceeds the bounded text length",
        });
    }
    Ok(())
}
