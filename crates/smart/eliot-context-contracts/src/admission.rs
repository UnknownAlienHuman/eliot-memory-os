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
        if self.mandatory_atoms.len() > 256 || self.members.len() > 256 {
            return Err(ContextError::Bounds {
                field: "floor.members",
            });
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
        if self.interpretation_dependencies.len() > 256 {
            return Err(ContextError::Bounds {
                field: "floor.interpretation_dependencies",
            });
        }
        let mut interpretation_dependencies = BTreeSet::new();
        for dependency in &self.interpretation_dependencies {
            if !interpretation_dependencies.insert(dependency.clone()) {
                return Err(ContextError::Duplicate("floor.interpretation_dependencies"));
            }
        }
        if !self
            .interpretation_dependencies
            .iter()
            .all(|id| member_ids.contains(id))
        {
            return Err(ContextError::MissingFloor);
        }
        for member in &self.members {
            if member.required_dependencies.len() > 256 {
                return Err(ContextError::Bounds {
                    field: "floor.required_dependencies",
                });
            }
            let mut dependencies = BTreeSet::new();
            if member
                .required_dependencies
                .iter()
                .any(|id| !dependencies.insert(id.clone()) || *id == member.atom_id)
            {
                return Err(ContextError::Duplicate("floor.required_dependencies"));
            }
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
                AtomAvailability::Unknown => result.unknown.push(member.atom_id.clone()),
                AtomAvailability::Partial => result.partial.push(member.atom_id.clone()),
                AtomAvailability::KnownEmpty => result.known_empty.push(member.atom_id.clone()),
                AtomAvailability::PresentCurrent => {}
            }
        }
        for disposition in &self.providers.dispositions {
            if disposition.state != AtomAvailability::PresentCurrent {
                result.provider_gaps.push(crate::ProviderRoleGap {
                    slot: disposition.slot.clone(),
                    state: disposition.state,
                });
            }
        }
        result.missing.sort();
        result.missing.dedup();
        result.stale.sort();
        result.stale.dedup();
        result.blocked.sort();
        result.blocked.dedup();
        result.unavailable.sort();
        result.unavailable.dedup();
        result.omitted.sort();
        result.omitted.dedup();
        result.exhausted.sort();
        result.exhausted.dedup();
        result.unknown.sort();
        result.unknown.dedup();
        result.known_empty.sort();
        result.known_empty.dedup();
        result.partial.sort();
        result.partial.dedup();
        if result.missing.is_empty()
            && result.stale.is_empty()
            && result.blocked.is_empty()
            && result.oversized.is_empty()
            && result.unavailable.is_empty()
            && result.omitted.is_empty()
            && result.exhausted.is_empty()
            && result.unknown.is_empty()
            && result.known_empty.is_empty()
            && result.partial.is_empty()
            && result.provider_gaps.is_empty()
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
            let provider_state = self
                .denominator
                .dispositions
                .iter()
                .find(|disposition| disposition.slot == candidate.provider_role)
                .ok_or(ContextError::DenominatorMismatch)?
                .state;
            if candidate.availability != provider_state {
                return Err(ContextError::IdentityConflict);
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
            let floor_member = self
                .floor
                .members
                .iter()
                .find(|member| member.atom_id == record.candidate.atom_id)
                .ok_or(ContextError::DenominatorMismatch)?;
            if record.candidate.provider_role.role != floor_member.role
                || record.candidate.availability != floor_member.availability
            {
                return Err(ContextError::IdentityConflict);
            }
            if let Some(measurement) = &floor_member.measurement
                && record.candidate.measurement != *measurement
            {
                return Err(ContextError::IdentityConflict);
            }
            let provider = self
                .floor
                .providers
                .dispositions
                .iter()
                .find(|disposition| disposition.slot == record.candidate.provider_role)
                .ok_or(ContextError::DenominatorMismatch)?;
            if record.candidate.availability != provider.state {
                return Err(ContextError::IdentityConflict);
            }
            let candidate_dependencies: BTreeSet<_> =
                record.candidate.dependencies.iter().cloned().collect();
            let floor_dependencies: BTreeSet<_> =
                floor_member.required_dependencies.iter().cloned().collect();
            if candidate_dependencies != floor_dependencies {
                return Err(ContextError::IdentityConflict);
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
        for member in &self.floor.members {
            if member.availability == crate::AtomAvailability::PresentCurrent
                && !ids.contains(&member.atom_id)
            {
                return Err(ContextError::MissingFloor);
            }
        }
        if admitted_ids != ids {
            return Err(ContextError::DenominatorMismatch);
        }
        self.economy.validate()?;
        let economy_admitted: BTreeSet<_> = self.economy.admitted.iter().cloned().collect();
        if economy_admitted != ids {
            return Err(ContextError::EconomyMismatch);
        }
        Ok(())
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
