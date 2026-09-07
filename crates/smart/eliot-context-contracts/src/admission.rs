//! Decision Safety Floor, explicit admission and economy conservation.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdmissionDisposition, AdmittedAtom, AtomAvailability, CapacityLimits, ContextBinding,
    ContextCandidate, ContextEconomyReceipt, ContextError, DecisionContextIncomplete,
    MeasurementRef, ProviderRoleDenominator,
};

/// One exact mandatory member of the Decision Safety Floor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SafetyFloorMember {
    pub atom_id: ArtifactId,
    pub role: crate::SemanticRole,
    pub availability: AtomAvailability,
    pub measurement: Option<MeasurementRef>,
    pub required_dependencies: Vec<ArtifactId>,
}

/// Recheckable exact denominator for a decision boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionSafetyFloor {
    pub binding: ContextBinding,
    pub mandatory_atoms: Vec<ArtifactId>,
    pub mandatory_roles: Vec<crate::SemanticRole>,
    pub providers: ProviderRoleDenominator,
    pub members: Vec<SafetyFloorMember>,
    pub interpretation_dependencies: Vec<ArtifactId>,
    pub rule_evidence: ArtifactId,
    pub capacity: CapacityLimits,
}

impl DecisionSafetyFloor {
    /// Validate exact membership and preserve every non-success state.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.providers.validate()?;
        if self.mandatory_atoms.is_empty() || self.members.is_empty() {
            return Err(ContextError::MissingFloor);
        }
        let expected: BTreeSet<_> = self.mandatory_atoms.iter().cloned().collect();
        if expected.len() != self.mandatory_atoms.len() {
            return Err(ContextError::Duplicate("floor.mandatory_atoms"));
        }
        let mut seen = BTreeSet::new();
        for member in &self.members {
            if !expected.contains(&member.atom_id) || !seen.insert(member.atom_id.clone()) {
                return Err(ContextError::DenominatorMismatch);
            }
            if matches!(member.availability, AtomAvailability::PresentCurrent) {
                let measurement = member
                    .measurement
                    .as_ref()
                    .ok_or(ContextError::MissingField("floor.member.measurement"))?;
                measurement.validate()?;
            }
        }
        if seen != expected {
            return Err(ContextError::MissingFloor);
        }
        let role_set: BTreeSet<_> = self.mandatory_roles.iter().collect();
        if role_set.len() != self.mandatory_roles.len() {
            return Err(ContextError::Duplicate("floor.mandatory_roles"));
        }
        let member_ids: BTreeSet<_> = self
            .members
            .iter()
            .map(|member| member.atom_id.clone())
            .collect();
        if !self
            .interpretation_dependencies
            .iter()
            .all(|id| member_ids.contains(id))
        {
            return Err(ContextError::MissingFloor);
        }
        for member in &self.members {
            if !member
                .required_dependencies
                .iter()
                .all(|id| member_ids.contains(id))
            {
                return Err(ContextError::MissingFloor);
            }
        }
        for role in &self.mandatory_roles {
            if !self.members.iter().any(|member| member.role == *role) {
                return Err(ContextError::MissingFloor);
            }
        }
        Ok(())
    }

    /// Build the first-class incomplete result when the floor cannot be proven.
    pub fn incomplete(&self) -> Result<Option<DecisionContextIncomplete>, ContextError> {
        self.validate()?;
        let mut result = DecisionContextIncomplete::new(self.rule_evidence.clone());
        let fixed = self
            .capacity
            .fixed_overhead
            .checked_add(self.capacity.output_reserve)
            .and_then(|v| v.checked_add(self.capacity.review_reserve));
        if fixed.is_none_or(|value| value > self.capacity.route_capacity) {
            result
                .oversized
                .extend(self.mandatory_atoms.iter().cloned());
        }
        for member in &self.members {
            match member.availability {
                AtomAvailability::Missing => result.missing.push(member.atom_id.clone()),
                AtomAvailability::Stale => result.stale.push(member.atom_id.clone()),
                AtomAvailability::Blocked => {
                    result.blocked.push(member.atom_id.clone());
                }
                AtomAvailability::Unavailable => result.unavailable.push(member.atom_id.clone()),
                AtomAvailability::Omitted => result.omitted.push(member.atom_id.clone()),
                AtomAvailability::Exhausted => result.exhausted.push(member.atom_id.clone()),
                AtomAvailability::Unknown
                | AtomAvailability::Partial
                | AtomAvailability::KnownEmpty => result.unknown.push(member.atom_id.clone()),
                AtomAvailability::PresentCurrent => {}
            }
        }
        for disposition in &self.providers.dispositions {
            let id = ArtifactId::new(format!("provider:{}", disposition.slot.provider.as_str()))
                .map_err(|_| ContextError::InvalidField("provider"))?;
            match disposition.state {
                AtomAvailability::Stale => result.stale.push(id),
                AtomAvailability::Blocked => {
                    result.blocked.push(id);
                }
                AtomAvailability::Unavailable => result.unavailable.push(id),
                AtomAvailability::Omitted => result.omitted.push(id),
                AtomAvailability::Exhausted => result.exhausted.push(id),
                AtomAvailability::Unknown
                | AtomAvailability::Partial
                | AtomAvailability::KnownEmpty => result.unknown.push(id),
                AtomAvailability::PresentCurrent => {}
                AtomAvailability::Missing => result.missing.push(id),
            }
        }
        for dependency in &self.interpretation_dependencies {
            if !self.members.iter().any(|member| {
                member.atom_id == *dependency
                    && member.availability == AtomAvailability::PresentCurrent
            }) {
                result.missing.push(dependency.clone());
            }
        }
        result.missing.sort();
        result.missing.dedup();
        result.stale.sort();
        result.stale.dedup();
        result.blocked.sort();
        result.blocked.dedup();
        if result.missing.is_empty()
            && result.stale.is_empty()
            && result.blocked.is_empty()
            && result.oversized.is_empty()
            && result.unavailable.is_empty()
            && result.omitted.is_empty()
            && result.exhausted.is_empty()
            && result.unknown.is_empty()
        {
            Ok(None)
        } else {
            result.validate()?;
            Ok(Some(result))
        }
    }
}

/// Explicit disposition for one candidate, preserving candidate identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    pub atom_id: ArtifactId,
    pub provider_role: crate::ProviderRole,
    pub disposition: AdmissionDisposition,
    pub rule_evidence: ArtifactId,
}

/// Exact candidate-to-admitted membership stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextCandidateSet {
    pub binding: ContextBinding,
    pub candidates: Vec<ContextCandidate>,
    pub denominator: ProviderRoleDenominator,
}

impl ContextCandidateSet {
    /// Validate candidate identities and exact provider coverage.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.denominator.validate()?;
        if self.candidates.is_empty() {
            return Err(ContextError::MissingField("candidates"));
        }
        let mut ids = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if candidate.binding != self.binding {
                return Err(ContextError::InvalidFence);
            }
            if !self
                .denominator
                .requested
                .iter()
                .any(|slot| slot == &candidate.provider_role)
            {
                return Err(ContextError::DenominatorMismatch);
            }
            if !ids.insert(candidate.atom_id.clone()) {
                return Err(ContextError::Duplicate("candidates.atom_id"));
            }
        }
        for candidate in &self.candidates {
            if !candidate
                .dependencies
                .iter()
                .all(|dependency| ids.contains(dependency))
            {
                return Err(ContextError::MissingField("candidate.dependencies"));
            }
        }
        Ok(())
    }
}

/// Exact admitted membership plus floor and economy evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedContextSet {
    pub binding: ContextBinding,
    pub records: Vec<AdmittedAtom>,
    pub admissions: Vec<AdmissionRecord>,
    pub floor: DecisionSafetyFloor,
    pub economy: ContextEconomyReceipt,
}

impl AdmittedContextSet {
    /// Validate candidate/admitted identity conservation and floor outcome.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.floor.validate()?;
        if self.floor.binding != self.binding || self.economy.binding != self.binding {
            return Err(ContextError::InvalidFence);
        }
        let mut ids = BTreeSet::new();
        for record in &self.records {
            record.candidate.validate()?;
            if record.candidate.binding != self.binding
                || !ids.insert(record.candidate.atom_id.clone())
            {
                return Err(ContextError::Duplicate("admitted.atom_id"));
            }
            if !matches!(
                record.disposition,
                AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
            ) {
                return Err(ContextError::DenominatorMismatch);
            }
        }
        let mut admitted_ids = BTreeSet::new();
        for admission in &self.admissions {
            if !ids.contains(&admission.atom_id) || !admitted_ids.insert(admission.atom_id.clone())
            {
                return Err(ContextError::DenominatorMismatch);
            }
            let record = self
                .records
                .iter()
                .find(|record| record.candidate.atom_id == admission.atom_id)
                .ok_or(ContextError::DenominatorMismatch)?;
            if record.candidate.provider_role != admission.provider_role
                || record.disposition != admission.disposition
                || record.rule_evidence != admission.rule_evidence
            {
                return Err(ContextError::IdentityConflict);
            }
        }
        if admitted_ids != ids {
            return Err(ContextError::DenominatorMismatch);
        }
        self.economy.validate()
    }

    /// Return a complete result only if the floor is complete.
    pub fn outcome(&self) -> Result<crate::ContextOutcome<Self>, ContextError> {
        self.validate()?;
        if let Some(incomplete) = self.floor.incomplete()? {
            Ok(crate::ContextOutcome::Incomplete(incomplete))
        } else {
            Ok(crate::ContextOutcome::Complete(self.clone()))
        }
    }
}
