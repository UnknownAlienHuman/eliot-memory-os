//! Governor-owned disclosure decisions for exact Agent Bridge host-event bytes.
//!
//! The owner snapshot is assembled only from the live `WorkScope` and `Policy`
//! owners plus an admitted `attach receipt`. Callers may submit event bytes and
//! a typed normalization class, but cannot submit an `Allow` decision.

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::{
    ClosureCompleteness, DisclosureDecision, DisclosureDecisionKind, DisclosureDependencyClosure,
    ObservationDomainRef, PolicyFence, PrivacyClass,
};
use eliot_workscope::{
    PrivacyBoundary, ScopeRelocationKind, ScopeRelocationOrAttachReceipt, WorkScopeBindingOwner,
    WorkScopeBindingSnapshot,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::composition::PolicyOwner;

pub const BRIDGE_EVENT_PRIVACY_OWNER_SCHEMA_VERSION: u16 = 1;

/// Classification emitted by the host-event normalizer.
///
/// This enum is intentionally independent of `WorkScope`'s `PrivacyClass`.
/// The owner retention rule supplies the explicit mapping used at the attach
/// boundary; no mapping is inferred from a scope-wide class.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeEventSourcePrivacyClass {
    PublicSummary,
    RedactedSummary,
    RestrictedHandleOnly,
}

/// Retention disposition explicitly assigned by the admitted attach owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeEventRetentionDisposition {
    RawAllowed,
    RedactedOnly,
    Denied,
}

/// Owner-declared mapping and retention rule for one normalized host class.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventRetentionRule {
    pub source_class: BridgeEventSourcePrivacyClass,
    pub workscope_privacy_class: PrivacyClass,
    pub disposition: BridgeEventRetentionDisposition,
}

/// Complete attach-time retention policy. All source classes are represented
/// exactly once so omission cannot be interpreted as permission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventRetentionPolicy {
    pub policy_ref: String,
    pub rules: Vec<BridgeEventRetentionRule>,
}

/// Domain lineage and the explicit recipient capabilities needed for it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventDisclosureDomainRule {
    pub domain: ObservationDomainRef,
    pub required_capabilities: Vec<String>,
}

/// Explicit closure lineage captured by the attach owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventDisclosureClosureOwner {
    pub completeness: ClosureCompleteness,
    pub inherited_closure_refs: Vec<String>,
    pub derivation_or_transformation_refs: Vec<String>,
    pub declassification_receipt_refs: Vec<String>,
}

/// Authenticated Bridge recipient identity, route, and capability set.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventPrivacyRecipient {
    pub principal_or_route: String,
    pub capabilities: Vec<String>,
}

/// Exact owner evidence used to decide whether one Bridge event may be kept.
///
/// `work_scope` and `attach_receipt` are the admitted binding and attach
/// evidence; policy identity, revision and digests are read from `PolicyOwner`.
/// All remaining fields are typed inputs of the authenticated attach operation
/// and are retained here so the Kernel can independently verify each event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventPrivacyOwnerSnapshot {
    pub schema_version: u16,
    pub work_scope: WorkScopeBindingSnapshot,
    pub attach_receipt: ScopeRelocationOrAttachReceipt,
    pub privacy_boundary: PrivacyBoundary,
    pub retention: BridgeEventRetentionPolicy,
    pub domain_rules: Vec<BridgeEventDisclosureDomainRule>,
    pub closure: BridgeEventDisclosureClosureOwner,
    pub recipient: BridgeEventPrivacyRecipient,
    pub policy_snapshot_id: String,
    pub policy_revision: u64,
    pub policy_state_fence: StateFence,
    pub policy_owner_canonical_digest: String,
    pub policy_snapshot_digest: String,
}

/// Result of Governor disclosure evaluation, bound to exact event bytes and
/// the complete owner snapshot. Kernel ingress must independently recompute
/// this result before persistence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventPrivacyDecision {
    pub source_bytes_sha256: String,
    pub owner_snapshot_sha256: String,
    pub scope_ref: String,
    pub work_scope_owner_revision: u64,
    pub policy_snapshot_id: String,
    pub policy_revision: u64,
    pub policy_state_fence: StateFence,
    pub source_class: BridgeEventSourcePrivacyClass,
    pub retention_disposition: BridgeEventRetentionDisposition,
    pub closure: DisclosureDependencyClosure,
    pub disclosure: DisclosureDecision,
}

/// Fail-closed owner and disclosure validation failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BridgeEventPrivacyError {
    #[error("Bridge event privacy owner data is invalid: {0}")]
    InvalidOwner(&'static str),
    #[error("WorkScope owner rejected the exact policy fence: {0}")]
    WorkScope(String),
    #[error("Policy owner rejected its retained snapshot: {0}")]
    Policy(String),
    #[error("disclosure contract rejected owner evidence: {0}")]
    Disclosure(String),
    #[error("owner snapshot could not be canonicalized")]
    Canonicalization,
    #[error("source bytes must be non-empty")]
    EmptySource,
}

impl BridgeEventPrivacyOwnerSnapshot {
    /// Builds an owner snapshot from live owners and the admitted attach
    /// receipt. `work_scope.owner_revision` is sourced from the retained
    /// snapshot at `policy_owner.state_fence()`; it is never caller supplied.
    #[allow(clippy::too_many_arguments)]
    pub fn from_owners(
        work_scope_owner: &WorkScopeBindingOwner,
        policy_owner: &PolicyOwner,
        attach_receipt: ScopeRelocationOrAttachReceipt,
        privacy_boundary: PrivacyBoundary,
        retention: BridgeEventRetentionPolicy,
        domain_rules: Vec<BridgeEventDisclosureDomainRule>,
        closure: BridgeEventDisclosureClosureOwner,
        recipient: BridgeEventPrivacyRecipient,
    ) -> Result<Self, BridgeEventPrivacyError> {
        let state_fence = policy_owner.state_fence();
        let work_scope = work_scope_owner
            .read_current(state_fence)
            .map_err(|error| BridgeEventPrivacyError::WorkScope(error.to_string()))?;
        policy_owner
            .snapshot()
            .validate()
            .map_err(|error| BridgeEventPrivacyError::Policy(error.to_string()))?;
        attach_receipt
            .validate()
            .map_err(|_| BridgeEventPrivacyError::InvalidOwner("attach receipt"))?;
        privacy_boundary
            .validate()
            .map_err(|_| BridgeEventPrivacyError::InvalidOwner("privacy boundary"))?;

        let policy_snapshot = policy_owner.snapshot();
        if policy_owner.revision() == 0
            || policy_snapshot.revision.value() != policy_owner.revision()
            || policy_snapshot.state_fence != *state_fence
            || policy_snapshot.policy_fence.state_fence != *state_fence
            || policy_snapshot.policy_fence.policy_snapshot_id != policy_snapshot.snapshot_id
        {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "policy owner fence or revision mismatch",
            ));
        }
        if work_scope.state_fence != *state_fence
            || work_scope.owner_revision == 0
            || attach_receipt.state_fence != *state_fence
            || attach_receipt.kind != ScopeRelocationKind::Attach
            || attach_receipt.scope_ref != work_scope.binding.scope.scope_ref
            || attach_receipt.lineage.lineage_ref
                != work_scope
                    .binding
                    .scope
                    .lineage_ref
                    .as_deref()
                    .unwrap_or_default()
            || attach_receipt.observed_instance.instance_ref
                != work_scope.binding.scope.instance_ref
            || attach_receipt.observed_instance.root_identity
                != work_scope.binding.scope.root_identity
            || attach_receipt.observed_instance.generation != work_scope.binding.scope.generation
            || !privacy_boundary.admits(work_scope.binding.privacy_class)
            || privacy_boundary
                .lineage
                .as_ref()
                .map(|lineage| lineage.lineage_ref.as_str())
                != work_scope.binding.scope.lineage_ref.as_deref()
        {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "WorkScope, attach receipt, boundary and Policy fence disagree",
            ));
        }
        let snapshot = Self {
            schema_version: BRIDGE_EVENT_PRIVACY_OWNER_SCHEMA_VERSION,
            work_scope,
            attach_receipt,
            privacy_boundary,
            retention,
            domain_rules,
            closure,
            recipient,
            policy_snapshot_id: policy_snapshot.snapshot_id.clone(),
            policy_revision: policy_owner.revision(),
            policy_state_fence: state_fence.clone(),
            policy_owner_canonical_digest: policy_owner.canonical_digest().to_owned(),
            policy_snapshot_digest: policy_owner.snapshot_digest().to_owned(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Revalidates a deserialized owner snapshot against the immutable typed
    /// evidence carried in it before it is published or consumed.
    pub fn validate(&self) -> Result<(), BridgeEventPrivacyError> {
        if self.schema_version != BRIDGE_EVENT_PRIVACY_OWNER_SCHEMA_VERSION
            || self.work_scope.owner_revision == 0
            || self.policy_revision == 0
            || self.policy_snapshot_id.trim().is_empty()
            || self.policy_snapshot_id.chars().any(char::is_control)
            || !is_sha256(&self.policy_owner_canonical_digest)
            || !is_sha256(&self.policy_snapshot_digest)
        {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "schema, revision or policy digest",
            ));
        }
        self.work_scope
            .validate()
            .map_err(|_| BridgeEventPrivacyError::InvalidOwner("WorkScope binding"))?;
        self.attach_receipt
            .validate()
            .map_err(|_| BridgeEventPrivacyError::InvalidOwner("attach receipt"))?;
        self.privacy_boundary
            .validate()
            .map_err(|_| BridgeEventPrivacyError::InvalidOwner("privacy boundary"))?;
        if self.work_scope.state_fence != self.policy_state_fence
            || self.attach_receipt.state_fence != self.policy_state_fence
            || self.attach_receipt.kind != ScopeRelocationKind::Attach
            || self.attach_receipt.scope_ref != self.work_scope.binding.scope.scope_ref
            || self.attach_receipt.lineage.lineage_ref
                != self
                    .work_scope
                    .binding
                    .scope
                    .lineage_ref
                    .as_deref()
                    .unwrap_or_default()
            || self.attach_receipt.observed_instance.instance_ref
                != self.work_scope.binding.scope.instance_ref
            || self.attach_receipt.observed_instance.root_identity
                != self.work_scope.binding.scope.root_identity
            || self.attach_receipt.observed_instance.generation
                != self.work_scope.binding.scope.generation
            || !self
                .privacy_boundary
                .admits(self.work_scope.binding.privacy_class)
            || self
                .privacy_boundary
                .lineage
                .as_ref()
                .map(|lineage| lineage.lineage_ref.as_str())
                != self.work_scope.binding.scope.lineage_ref.as_deref()
        {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "owner evidence fence or binding mismatch",
            ));
        }
        self.retention.validate()?;
        self.recipient.validate()?;
        if self.domain_rules.is_empty() {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "empty domain closure",
            ));
        }
        let mut seen_domains = Vec::with_capacity(self.domain_rules.len());
        for rule in &self.domain_rules {
            rule.domain
                .validate()
                .map_err(|error| BridgeEventPrivacyError::Disclosure(error.to_string()))?;
            if rule.domain.state_fence != self.policy_state_fence
                || rule.required_capabilities.is_empty()
                || !unique_nonblank(&rule.required_capabilities)
                || seen_domains.contains(&rule.domain.domain_id)
            {
                return Err(BridgeEventPrivacyError::InvalidOwner(
                    "domain fence, capability requirements or duplicate domain",
                ));
            }
            seen_domains.push(rule.domain.domain_id.clone());
        }
        if !unique_nonblank(&self.closure.inherited_closure_refs)
            || !unique_nonblank(&self.closure.derivation_or_transformation_refs)
            || !unique_nonblank(&self.closure.declassification_receipt_refs)
        {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "closure lineage references",
            ));
        }
        Ok(())
    }
}

impl BridgeEventRetentionPolicy {
    pub fn validate(&self) -> Result<(), BridgeEventPrivacyError> {
        if !valid_text(&self.policy_ref) || self.rules.len() != 3 {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "retention policy reference or class coverage",
            ));
        }
        let required = [
            BridgeEventSourcePrivacyClass::PublicSummary,
            BridgeEventSourcePrivacyClass::RedactedSummary,
            BridgeEventSourcePrivacyClass::RestrictedHandleOnly,
        ];
        if required.iter().any(|class| {
            self.rules
                .iter()
                .filter(|rule| rule.source_class == *class)
                .count()
                != 1
        }) {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "retention policy must define each source class exactly once",
            ));
        }
        Ok(())
    }

    fn rule_for(&self, class: BridgeEventSourcePrivacyClass) -> Option<&BridgeEventRetentionRule> {
        self.rules.iter().find(|rule| rule.source_class == class)
    }
}

impl BridgeEventPrivacyRecipient {
    fn validate(&self) -> Result<(), BridgeEventPrivacyError> {
        if !valid_text(&self.principal_or_route) || !unique_nonblank(&self.capabilities) {
            return Err(BridgeEventPrivacyError::InvalidOwner(
                "recipient identity or capabilities",
            ));
        }
        Ok(())
    }
}

/// Builds the validated dependency closure the owner decision is computed over.
fn closure_for_decision(
    owner: &BridgeEventPrivacyOwnerSnapshot,
    source_hash: &str,
) -> Result<DisclosureDependencyClosure, BridgeEventPrivacyError> {
    let closure_ref = format!("bridge-event-closure:{source_hash}");
    let closure = DisclosureDependencyClosure {
        closure_id: closure_ref,
        subject_ref: format!("sha256:{source_hash}"),
        direct_domain_refs: owner
            .domain_rules
            .iter()
            .map(|rule| rule.domain.clone())
            .collect(),
        inherited_closure_refs: owner.closure.inherited_closure_refs.clone(),
        derivation_or_transformation_refs: owner.closure.derivation_or_transformation_refs.clone(),
        completeness: owner.closure.completeness,
        declassification_receipt_refs: owner.closure.declassification_receipt_refs.clone(),
        policy_snapshot_id: owner.policy_snapshot_id.clone(),
        state_fence: owner.policy_state_fence.clone(),
        revision: owner.policy_revision,
    };
    closure
        .validate()
        .map_err(|error| BridgeEventPrivacyError::Disclosure(error.to_string()))?;
    Ok(closure)
}

/// Computes the owner decision against exact event bytes and the owner
/// snapshot's source classification, domain closure, retention and recipient.
/// The returned evidence is deterministic; a consumer must compare it against
/// its current retained owner snapshot rather than trusting caller JSON.
pub fn decide_bridge_event_disclosure(
    owner: &BridgeEventPrivacyOwnerSnapshot,
    exact_source_bytes: &[u8],
    source_class: BridgeEventSourcePrivacyClass,
) -> Result<BridgeEventPrivacyDecision, BridgeEventPrivacyError> {
    if exact_source_bytes.is_empty() {
        return Err(BridgeEventPrivacyError::EmptySource);
    }
    owner.validate()?;
    let source_hash = sha256_hex(exact_source_bytes);
    let owner_snapshot_sha256 = sha256_hex(
        &canonical_json_bytes(owner).map_err(|_| BridgeEventPrivacyError::Canonicalization)?,
    );
    let retention_rule =
        owner
            .retention
            .rule_for(source_class)
            .ok_or(BridgeEventPrivacyError::InvalidOwner(
                "missing source class rule",
            ))?;
    let closure = closure_for_decision(owner, &source_hash)?;
    let closure_ref = format!("bridge-event-closure:{source_hash}");

    let source_class_admitted = owner
        .privacy_boundary
        .admits(retention_rule.workscope_privacy_class)
        && owner.work_scope.binding.privacy_class == retention_rule.workscope_privacy_class;
    let mut covered_domains = Vec::new();
    let mut uncovered_domains = Vec::new();
    for rule in &owner.domain_rules {
        if rule
            .required_capabilities
            .iter()
            .all(|required| owner.recipient.capabilities.contains(required))
        {
            covered_domains.push(rule.domain.domain_id.clone());
        } else {
            uncovered_domains.push(rule.domain.domain_id.clone());
        }
    }
    let decision_kind = if !source_class_admitted
        || owner.closure.completeness != ClosureCompleteness::Complete
        || !uncovered_domains.is_empty()
    {
        DisclosureDecisionKind::Deny
    } else {
        match retention_rule.disposition {
            BridgeEventRetentionDisposition::RawAllowed => DisclosureDecisionKind::Allow,
            BridgeEventRetentionDisposition::RedactedOnly => DisclosureDecisionKind::AllowRedacted,
            BridgeEventRetentionDisposition::Denied => DisclosureDecisionKind::Deny,
        }
    };
    let receipt_ref = format!(
        "bridge-event-decision:{}:{}:{}:{}",
        owner.work_scope.binding.scope.scope_ref,
        owner.work_scope.owner_revision,
        owner.policy_revision,
        source_hash
    );
    let disclosure = DisclosureDecision {
        subject_and_closure_ref: closure_ref,
        recipient_principal_or_route: owner.recipient.principal_or_route.clone(),
        recipient_capability_set: owner.recipient.capabilities.clone(),
        covered_domains,
        uncovered_domains,
        decision: decision_kind,
        policy_snapshot_and_state_fence: PolicyFence {
            policy_snapshot_id: owner.policy_snapshot_id.clone(),
            state_fence: owner.policy_state_fence.clone(),
        },
        receipt_ref,
        closure_completeness: owner.closure.completeness,
    };
    disclosure
        .validate()
        .map_err(|error| BridgeEventPrivacyError::Disclosure(error.to_string()))?;
    Ok(BridgeEventPrivacyDecision {
        source_bytes_sha256: source_hash,
        owner_snapshot_sha256,
        scope_ref: owner.work_scope.binding.scope.scope_ref.clone(),
        work_scope_owner_revision: owner.work_scope.owner_revision,
        policy_snapshot_id: owner.policy_snapshot_id.clone(),
        policy_revision: owner.policy_revision,
        policy_state_fence: owner.policy_state_fence.clone(),
        source_class,
        retention_disposition: retention_rule.disposition,
        closure,
        disclosure,
    })
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn unique_nonblank(values: &[String]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    values
        .iter()
        .all(|value| valid_text(value) && seen.insert(value))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod issue_1935_tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_security_contracts::{
        DisclosureDecisionKind, ObservationDomainKind,
    };
    use eliot_workscope::{
        ScopeBinding, ScopeBindingDisposition, ScopeBindingGuardReceipt, ScopeIdentity,
        ScopeKind, WorkspaceInstanceIdentity,
    };
    use std::num::NonZeroU64;

    fn owner(disposition: BridgeEventRetentionDisposition) -> BridgeEventPrivacyOwnerSnapshot {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001")
                .expect("test lineage"),
            NonZeroU64::new(1).expect("nonzero test epoch"),
        )
        .expect("test epoch");
        let fence = StateFence::new(
            epoch,
            ResourceGeneration::new(1).expect("test generation"),
        );
        let scope = ScopeIdentity {
            scope_ref: "scope:test".to_owned(),
            kind: ScopeKind::GitRepo,
            lineage_ref: Some("lineage:test".to_owned()),
            instance_ref: "instance:test".to_owned(),
            root_identity: "root:test".to_owned(),
            generation: 1,
        };
        let instance = WorkspaceInstanceIdentity {
            instance_ref: scope.instance_ref.clone(),
            root_identity: scope.root_identity.clone(),
            vcs_identity_ref: None,
            generation: 1,
        };
        let work_scope = WorkScopeBindingSnapshot::new(
            fence.clone(),
            1,
            ScopeBinding {
                scope: scope.clone(),
                privacy_class: PrivacyClass::Internal,
                governing_source_generation: 1,
            },
            ScopeBindingGuardReceipt {
                expected_scope_ref: scope.scope_ref.clone(),
                observed_scope_ref: scope.scope_ref.clone(),
                expected_lineage_ref: scope.lineage_ref.clone(),
                observed_lineage_ref: scope.lineage_ref.clone(),
                expected_instance_ref: scope.instance_ref.clone(),
                observed_instance_ref: scope.instance_ref.clone(),
                disposition: ScopeBindingDisposition::Matched,
                source_generation: 1,
            },
        )
        .expect("valid WorkScope binding");
        BridgeEventPrivacyOwnerSnapshot {
            schema_version: BRIDGE_EVENT_PRIVACY_OWNER_SCHEMA_VERSION,
            work_scope,
            attach_receipt: ScopeRelocationOrAttachReceipt {
                receipt_ref: "attach:test".to_owned(),
                kind: ScopeRelocationKind::Attach,
                scope_ref: scope.scope_ref,
                scope_kind: scope.kind,
                lineage: eliot_workscope::RepositoryLineageIdentity {
                    lineage_ref: "lineage:test".to_owned(),
                    object_store_ref: "store:test".to_owned(),
                    initial_history_ref: "history:test".to_owned(),
                    normalized_remote_ref: None,
                    manifest_identity_ref: None,
                },
                prior_instance: instance.clone(),
                observed_instance: instance,
                authorizing_ref: "authority:test".to_owned(),
                state_fence: fence.clone(),
            },
            privacy_boundary: PrivacyBoundary {
                boundary_ref: "privacy:test".to_owned(),
                admitted_classes: vec![PrivacyClass::Internal],
                lineage: Some(eliot_workscope::RepositoryLineageIdentity {
                    lineage_ref: "lineage:test".to_owned(),
                    object_store_ref: "store:test".to_owned(),
                    initial_history_ref: "history:test".to_owned(),
                    normalized_remote_ref: None,
                    manifest_identity_ref: None,
                }),
            },
            retention: BridgeEventRetentionPolicy {
                policy_ref: "retention:test".to_owned(),
                rules: [
                    BridgeEventSourcePrivacyClass::PublicSummary,
                    BridgeEventSourcePrivacyClass::RedactedSummary,
                    BridgeEventSourcePrivacyClass::RestrictedHandleOnly,
                ]
                .into_iter()
                .map(|source_class| BridgeEventRetentionRule {
                    source_class,
                    workscope_privacy_class: PrivacyClass::Internal,
                    disposition: if source_class == BridgeEventSourcePrivacyClass::PublicSummary {
                        disposition
                    } else {
                        BridgeEventRetentionDisposition::RedactedOnly
                    },
                })
                .collect(),
            },
            domain_rules: vec![BridgeEventDisclosureDomainRule {
                domain: ObservationDomainRef {
                    domain_id: "domain:test".to_owned(),
                    kind: ObservationDomainKind::LocalRoot,
                    authority_root: "root:test".to_owned(),
                    resource_scope: "scope:test".to_owned(),
                    privacy_class: PrivacyClass::Internal,
                    visibility_and_export_rule: "local-only".to_owned(),
                    model_route_rule: "none".to_owned(),
                    state_fence: fence.clone(),
                },
                required_capabilities: vec!["host-event:retain".to_owned()],
            }],
            closure: BridgeEventDisclosureClosureOwner {
                completeness: ClosureCompleteness::Complete,
                inherited_closure_refs: Vec::new(),
                derivation_or_transformation_refs: Vec::new(),
                declassification_receipt_refs: Vec::new(),
            },
            recipient: BridgeEventPrivacyRecipient {
                principal_or_route: "route:test".to_owned(),
                capabilities: vec!["host-event:retain".to_owned()],
            },
            policy_snapshot_id: "policy:test".to_owned(),
            policy_revision: 1,
            policy_state_fence: fence,
            policy_owner_canonical_digest: "0".repeat(64),
            policy_snapshot_digest: "1".repeat(64),
        }
    }

    #[test]
    fn issue_1935_governor_owner_admits_exact_source_with_retention_rule() {
        let owner = owner(BridgeEventRetentionDisposition::RawAllowed);
        let decision = decide_bridge_event_disclosure(
            &owner,
            b"{\"event\":\"native source\"}",
            BridgeEventSourcePrivacyClass::PublicSummary,
        )
        .expect("owner decision");
        assert_eq!(decision.disclosure.decision, DisclosureDecisionKind::Allow);
        assert_eq!(decision.source_bytes_sha256, sha256_hex(b"{\"event\":\"native source\"}"));
    }

    #[test]
    fn issue_1935_governor_owner_refuses_denied_retention_rule() {
        let owner = owner(BridgeEventRetentionDisposition::Denied);
        let decision = decide_bridge_event_disclosure(
            &owner,
            b"{\"event\":\"native source\"}",
            BridgeEventSourcePrivacyClass::PublicSummary,
        )
        .expect("owner refusal");
        assert_eq!(decision.disclosure.decision, DisclosureDecisionKind::Deny);
    }
}
