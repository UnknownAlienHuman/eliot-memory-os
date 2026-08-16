//! The single policy owner for origin-bound influence.
//!
//! This crate evaluates immutable provenance and source-assurance records.  It
//! does not persist content or perform a purge.  Callers must persist the
//! returned receipt and use its explicit closure when updating derived state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::{
    InfluenceDependencyClosure, InfluenceState, RevocationReason, SourceAssurance,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.security.influence";
pub const CONTRACT_VERSION: &str = "eliot-influence-v1";

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceLevel {
    Stored,
    Available,
    Delivered,
    Acknowledged,
    Used,
    VerifiedUse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub subject_ref: String,
    pub origin_ref: String,
    pub source_assurance: SourceAssurance,
    pub parent_refs: Vec<String>,
    pub transformation_ref: Option<String>,
    pub state_fence: StateFence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluencePolicy {
    pub policy_id: String,
    pub revision: u64,
    pub state_fence: StateFence,
    pub require_verified_integrity: bool,
    pub require_current_freshness: bool,
    pub allow_unknown_independence: bool,
    pub allow_instruction_taint: bool,
    pub minimum_level: InfluenceLevel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceRequest {
    pub request_id: String,
    pub subject_ref: String,
    pub requested_level: InfluenceLevel,
    pub policy: InfluencePolicy,
    pub provenance: ProvenanceRecord,
    pub dependency_closure: InfluenceDependencyClosure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceDisposition {
    Allowed,
    Restricted,
    Quarantined,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceDecision {
    pub request_id: String,
    pub request_digest: String,
    pub subject_ref: String,
    pub disposition: InfluenceDisposition,
    pub allowed_level: InfluenceLevel,
    pub reasons: Vec<InfluenceReason>,
    pub origin_ref: String,
    pub policy_id: String,
    pub state_fence: StateFence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceReason {
    IntegrityNotVerified,
    SourceStale,
    SourceQuarantined,
    SourceUnknown,
    InstructionTainted,
    WrongScope,
    DependencyRevoked,
    DependencyQuarantined,
    IncompleteLineage,
    PolicyFenceMismatch,
    RequestedLevelCapped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub request_id: String,
    pub root_ref: String,
    pub reason: RevocationReason,
    pub state_fence: StateFence,
    pub graph: Vec<InfluenceEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceEdge {
    pub source_ref: String,
    pub dependent_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationReceipt {
    pub request_id: String,
    pub request_digest: String,
    pub root_ref: String,
    pub affected_refs: Vec<String>,
    pub closures: Vec<InfluenceDependencyClosure>,
    pub state_fence: StateFence,
}

impl InfluencePolicy {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.policy_id, "policy_id")?;
        self.state_fence
            .validate()
            .map_err(|_| InfluenceError::InvalidField("state_fence"))?;
        Ok(())
    }
}

impl InfluenceRequest {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.request_id, "request_id")?;
        text(&self.subject_ref, "subject_ref")?;
        self.policy.validate()?;
        self.provenance.validate()?;
        self.dependency_closure
            .validate()
            .map_err(|_| InfluenceError::InvalidClosure)?;
        if self.provenance.subject_ref != self.subject_ref
            || self.dependency_closure.root_ref != self.provenance.origin_ref
            || self.provenance.state_fence != self.policy.state_fence
            || self.dependency_closure.state_fence != self.policy.state_fence
        {
            return Err(InfluenceError::FenceOrLineageMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, InfluenceError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceError::Canonicalization)
    }
}

impl ProvenanceRecord {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.subject_ref, "provenance.subject_ref")?;
        text(&self.origin_ref, "provenance.origin_ref")?;
        self.source_assurance
            .validate()
            .map_err(|_| InfluenceError::InvalidSourceAssurance)?;
        self.state_fence
            .validate()
            .map_err(|_| InfluenceError::InvalidField("provenance.state_fence"))?;
        unique(&self.parent_refs, "parent_refs")?;
        if let Some(reference) = &self.transformation_ref {
            text(reference, "transformation_ref")?;
        }
        if self.source_assurance.state_fence != self.state_fence {
            return Err(InfluenceError::FenceOrLineageMismatch);
        }
        Ok(())
    }
}

pub fn decide(request: &InfluenceRequest) -> Result<InfluenceDecision, InfluenceError> {
    let digest = request.digest()?;
    let source = &request.provenance.source_assurance;
    let mut reasons = Vec::new();
    if request.dependency_closure.current_influence == InfluenceState::Revoked {
        reasons.push(InfluenceReason::DependencyRevoked);
    } else if request.dependency_closure.current_influence == InfluenceState::Quarantined {
        reasons.push(InfluenceReason::DependencyQuarantined);
    }
    if request.policy.require_verified_integrity
        && !matches!(
            source.integrity,
            eliot_security_contracts::IntegrityStatus::Verified
        )
    {
        reasons.push(InfluenceReason::IntegrityNotVerified);
    }
    if request.policy.require_current_freshness
        && !matches!(
            source.freshness,
            eliot_security_contracts::FreshnessStatus::Current
        )
    {
        reasons.push(InfluenceReason::SourceStale);
    }
    if !matches!(
        source.quarantine,
        eliot_security_contracts::QuarantineState::None
            | eliot_security_contracts::QuarantineState::Released
    ) {
        reasons.push(InfluenceReason::SourceQuarantined);
    }
    if !request.policy.allow_instruction_taint
        && source.instruction_taint != eliot_security_contracts::InstructionTaint::Cleared
    {
        reasons.push(InfluenceReason::InstructionTainted);
    }
    if !request.policy.allow_unknown_independence
        && matches!(
            source.independence,
            eliot_security_contracts::IndependenceLevel::Unknown
        )
    {
        reasons.push(InfluenceReason::SourceUnknown);
    }
    if request.provenance.parent_refs.is_empty() && request.provenance.transformation_ref.is_some()
    {
        reasons.push(InfluenceReason::IncompleteLineage);
    }
    let blocked = reasons.iter().any(|reason| {
        matches!(
            reason,
            InfluenceReason::DependencyRevoked
                | InfluenceReason::SourceQuarantined
                | InfluenceReason::WrongScope
        )
    });
    let restricted = !reasons.is_empty();
    let allowed_level = if blocked {
        InfluenceLevel::Stored
    } else if restricted {
        InfluenceLevel::Available.min(request.policy.minimum_level)
    } else {
        request.requested_level.min(request.policy.minimum_level)
    };
    if allowed_level != request.requested_level {
        reasons.push(InfluenceReason::RequestedLevelCapped);
    }
    let disposition = if reasons
        .iter()
        .any(|reason| matches!(reason, InfluenceReason::DependencyRevoked))
    {
        InfluenceDisposition::Revoked
    } else if blocked {
        InfluenceDisposition::Quarantined
    } else if restricted {
        InfluenceDisposition::Restricted
    } else {
        InfluenceDisposition::Allowed
    };
    Ok(InfluenceDecision {
        request_id: request.request_id.clone(),
        request_digest: digest,
        subject_ref: request.subject_ref.clone(),
        disposition,
        allowed_level,
        reasons,
        origin_ref: request.provenance.origin_ref.clone(),
        policy_id: request.policy.policy_id.clone(),
        state_fence: request.policy.state_fence.clone(),
    })
}

pub fn revoke(request: &RevocationRequest) -> Result<RevocationReceipt, InfluenceError> {
    text(&request.request_id, "request_id")?;
    text(&request.root_ref, "root_ref")?;
    request
        .state_fence
        .validate()
        .map_err(|_| InfluenceError::InvalidField("state_fence"))?;
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &request.graph {
        text(&edge.source_ref, "edge.source_ref")?;
        text(&edge.dependent_ref, "edge.dependent_ref")?;
        adjacency
            .entry(&edge.source_ref)
            .or_default()
            .push(&edge.dependent_ref);
    }
    let mut affected = BTreeSet::new();
    let mut queue = VecDeque::from([request.root_ref.as_str()]);
    while let Some(reference) = queue.pop_front() {
        if !affected.insert(reference.to_owned()) {
            continue;
        }
        if let Some(dependents) = adjacency.get(reference) {
            queue.extend(dependents.iter().copied());
        }
    }
    let affected_refs: Vec<String> = affected.into_iter().collect();
    let closures = affected_refs
        .iter()
        .map(|subject| InfluenceDependencyClosure {
            closure_id: format!("{}:{}", request.request_id, subject),
            root_ref: request.root_ref.clone(),
            dependent_refs: affected_refs.clone(),
            invalidation_reason: Some(request.reason),
            current_influence: InfluenceState::Revoked,
            state_fence: request.state_fence.clone(),
            revision: 0,
        })
        .collect::<Vec<_>>();
    for closure in &closures {
        closure
            .validate()
            .map_err(|_| InfluenceError::InvalidClosure)?;
    }
    let request_digest = canonical_json_bytes(request)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| InfluenceError::Canonicalization)?;
    Ok(RevocationReceipt {
        request_id: request.request_id.clone(),
        request_digest,
        root_ref: request.root_ref.clone(),
        affected_refs,
        closures,
        state_fence: request.state_fence.clone(),
    })
}

fn text(value: &str, field: &'static str) -> Result<(), InfluenceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(InfluenceError::InvalidField(field))
    } else {
        Ok(())
    }
}
fn unique(values: &[String], field: &'static str) -> Result<(), InfluenceError> {
    let mut set = BTreeSet::new();
    if values.iter().any(|value| !set.insert(value)) {
        Err(InfluenceError::DuplicateReference(field))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum InfluenceError {
    #[error("invalid influence field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate influence reference in {0}")]
    DuplicateReference(&'static str),
    #[error("source assurance is invalid")]
    InvalidSourceAssurance,
    #[error("influence dependency closure is invalid")]
    InvalidClosure,
    #[error("influence provenance or state fence does not match")]
    FenceOrLineageMismatch,
    #[error("influence request cannot be canonically serialized")]
    Canonicalization,
}
