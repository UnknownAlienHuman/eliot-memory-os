//! Claim map: per-claim verdicts inside one admitted manifest.
//!
//! A [`ClaimMap`] holds exactly one [`ClaimEntry`] per admitted claim. Each entry carries verdict, audit outcome,
//! counterevidence, conflict reference, authority, grade, dependencies, bounds, component coverage, ceiling,
//! assumptions, and discriminators. Component coverage is validated, never inferred: an accepted entry carries
//! a supporting handle or an explicit unresolved marker; outside-manifest claims and duplicates fail.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::ArtifactId;
use eliot_evidence::EvidenceAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::grade::{EvidenceGrade, GradeAssignment};
use crate::identity::{ClaimId, ManifestId};
use crate::support::ValidityBounds;
use crate::temporal::TemporalRecord;

/// Per-claim verdict of the position author.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimVerdict {
    /// The claim is accepted within its bounds.
    Accepted,
    /// The claim is rejected within its bounds.
    Rejected,
    /// The claim is met by preserved counterevidence and held open.
    Countered,
}

/// Independent claim-audit outcome per I21.8: reference, value, specification, and method-artifact checks
/// stay independent; uncertainty and scope limits are preserved, never smoothed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimAuditOutcome {
    /// Every material statement resolves to admitted evidence.
    Supported,
    /// Material statements resolve in part; the rest stays explicit.
    PartiallySupported,
    /// Evaluated and not supported.
    Unsupported,
    /// Preserved counterevidence contradicts the claim.
    Contradicted,
    /// Cannot be verified inside the declared scope.
    NotVerifiableInScope,
}

/// One governed claim inside the map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimEntry {
    /// Stable claim identity.
    pub claim: ClaimId,
    /// Digest of the exact statement text this entry audited.
    pub statement_digest: String,
    /// Author verdict for the claim.
    pub verdict: ClaimVerdict,
    /// Independent audit outcome for the claim.
    pub audit: ClaimAuditOutcome,
    /// Preserved counterevidence handles, even when the claim is accepted.
    pub counterevidence: BTreeSet<ArtifactId>,
    /// Conflict digest, when the claim participates in one: it must equal the exact frozen digest of the
    /// referenced set; any unrelated nonempty set fails the reference.
    pub conflict: Option<String>,
    /// Authority class of the evidence behind the claim.
    pub authority: EvidenceAuthority,
    /// Grade assignment the claim was produced under; unknown stays unknown.
    pub grade: GradeAssignment,
    /// Explicit claim dependencies; order carries no meaning.
    pub dependencies: BTreeSet<ClaimId>,
    /// Temporal, scope, and precision bounds of the claim.
    pub bounds: ValidityBounds,
    /// Applicable temporal record, when the claim carries its own capture times; the five roles stay separate.
    pub temporal: Option<TemporalRecord>,
    /// Canonical digest of the component coverage behind the claim.
    pub coverage_digest: String,
    /// Accepted supporting handles behind the component coverage; order
    /// carries no meaning. An accepted claim carries at least one handle here
    /// or an explicit marker in `unresolved_support`.
    pub support: BTreeSet<ArtifactId>,
    /// Per-component accepted-handle mapping: each named proposition component maps to the accepted handle
    /// covering it. Every mapped handle must be a member of `support`; a digest plus assumption and
    /// discriminator names never counts as coverage on its own.
    pub components: BTreeMap<String, ArtifactId>,
    /// Explicit unresolved component markers; order carries no meaning. A
    /// marker keeps the component open instead of silently uncovered.
    pub unresolved_support: BTreeSet<String>,
    /// Grade ceiling the claim must not exceed.
    pub ceiling: EvidenceGrade,
    /// Named assumption sets the claim depends on; order carries no meaning.
    pub assumptions: BTreeSet<String>,
    /// Discriminators separating this claim from its rivals.
    pub discriminators: BTreeSet<String>,
}

impl ClaimEntry {
    /// Constructs a claim entry after validation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claim: ClaimId,
        statement_digest: impl Into<String>,
        verdict: ClaimVerdict,
        audit: ClaimAuditOutcome,
        counterevidence: BTreeSet<ArtifactId>,
        conflict: Option<String>,
        authority: EvidenceAuthority,
        grade: GradeAssignment,
        dependencies: BTreeSet<ClaimId>,
        bounds: ValidityBounds,
        temporal: Option<TemporalRecord>,
        coverage_digest: impl Into<String>,
        support: BTreeSet<ArtifactId>,
        components: BTreeMap<String, ArtifactId>,
        unresolved_support: BTreeSet<String>,
        ceiling: EvidenceGrade,
        assumptions: BTreeSet<String>,
        discriminators: BTreeSet<String>,
    ) -> Result<Self, ContractError> {
        let entry = Self {
            claim,
            statement_digest: statement_digest.into(),
            verdict,
            audit,
            counterevidence,
            conflict,
            authority,
            grade,
            dependencies,
            bounds,
            temporal,
            coverage_digest: coverage_digest.into(),
            support,
            components,
            unresolved_support,
            ceiling,
            assumptions,
            discriminators,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Validates verdict/audit coherence, ceilings, bounds, and component coverage
    /// (accepted entries carry support or an unresolved marker).
    pub fn validate(&self) -> Result<(), ContractError> {
        self.check_entry_fields()?;
        self.check_entry_coherence()?;
        Ok(())
    }

    fn check_entry_fields(&self) -> Result<(), ContractError> {
        validate_digest(&self.statement_digest, "claim.statement_digest")?;
        validate_digest(&self.coverage_digest, "claim.coverage_digest")?;
        self.bounds.validate()?;
        self.grade.validate()?;
        if let Some(known) = self.grade.known_grade() {
            EvidenceGrade::check_ceiling(known, self.ceiling)?;
        }
        if let Some(conflict) = &self.conflict {
            validate_digest(conflict.as_str(), "claim.conflict")?;
        }
        if let Some(temporal) = &self.temporal {
            temporal.validate()?;
        }
        if self.counterevidence.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.counterevidence",
            });
        }
        if self.support.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.support",
            });
        }
        if self.components.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.components",
            });
        }
        for (component, handle) in &self.components {
            validate_bounded_text(component.as_str(), "claim.components", MAX_SHORT_TEXT)?;
            if !self.support.contains(handle) {
                return Err(ContractError::MissingReference {
                    field: "claim.components",
                });
            }
        }
        if self.unresolved_support.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.unresolved_support",
            });
        }
        for marker in &self.unresolved_support {
            validate_bounded_text(marker.as_str(), "claim.unresolved_support", MAX_SHORT_TEXT)?;
        }
        if self.dependencies.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.dependencies",
            });
        }
        if self.assumptions.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.assumptions",
            });
        }
        if self.discriminators.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.discriminators",
            });
        }
        for assumption in &self.assumptions {
            validate_bounded_text(assumption.as_str(), "claim.assumptions", MAX_SHORT_TEXT)?;
        }
        for discriminator in &self.discriminators {
            validate_bounded_text(
                discriminator.as_str(),
                "claim.discriminators",
                MAX_SHORT_TEXT,
            )?;
        }
        Ok(())
    }

    fn check_entry_coherence(&self) -> Result<(), ContractError> {
        if self.dependencies.contains(&self.claim) {
            return Err(ContractError::SelfReference {
                field: "claim.dependencies",
            });
        }
        if matches!(self.verdict, ClaimVerdict::Accepted)
            && self.support.is_empty()
            && self.unresolved_support.is_empty()
        {
            return Err(ContractError::EmptyCollection {
                field: "claim.support",
            });
        }
        match (self.verdict, self.audit) {
            (
                ClaimVerdict::Accepted,
                ClaimAuditOutcome::Supported | ClaimAuditOutcome::PartiallySupported,
            )
            | (
                ClaimVerdict::Rejected,
                ClaimAuditOutcome::Unsupported | ClaimAuditOutcome::Contradicted,
            ) => Ok(()),
            (ClaimVerdict::Countered, _) => {
                if self.counterevidence.is_empty() {
                    return Err(ContractError::EmptyCollection {
                        field: "claim.counterevidence",
                    });
                }
                Ok(())
            }
            _ => Err(ContractError::ImpossibleCombination {
                field: "claim.verdict",
            }),
        }
    }
}

/// One explicit dependence group: members that stand or fall together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependenceGroup {
    /// Stable group identity.
    pub group_id: String,
    /// Member claims of the group; order carries no meaning.
    pub members: BTreeSet<ClaimId>,
    /// Bounded rationale for grouping these members.
    pub rationale: String,
}

impl DependenceGroup {
    /// Constructs a dependence group after validation.
    pub fn new(
        group_id: impl Into<String>,
        members: BTreeSet<ClaimId>,
        rationale: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let group = Self {
            group_id: group_id.into(),
            members,
            rationale: rationale.into(),
        };
        group.validate()?;
        Ok(group)
    }

    /// Validates group identity, non-empty membership, and rationale.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.group_id, "claim.group_id", MAX_SHORT_TEXT)?;
        if self.members.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "claim.group_members",
            });
        }
        if self.members.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.group_members",
            });
        }
        validate_bounded_text(&self.rationale, "claim.group_rationale", MAX_SHORT_TEXT)?;
        Ok(())
    }
}

/// The governed map of per-claim verdicts inside one manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimMap {
    /// Allowed-reference manifest admitting every entry.
    pub manifest: ManifestId,
    /// Claims admitted by the manifest; order carries no meaning. The entry
    /// set coincides with this set exactly: an admitted claim without an entry
    /// is unrepresented, and an entry without admission is outside the
    /// manifest.
    pub admitted: BTreeSet<ClaimId>,
    /// Per-claim entries in declaration order.
    pub entries: Vec<ClaimEntry>,
    /// Explicit dependence groups in declaration order.
    pub groups: Vec<DependenceGroup>,
    /// Admitted claims held open for further inquiry; order carries no
    /// meaning. Held-open claims keep their provisional entries: `unresolved`
    /// is a subset of the entered claims, never unentered claims.
    pub unresolved: BTreeSet<ClaimId>,
    /// Canonical digest of the map shape, excluding this field.
    pub digest: String,
}

impl ClaimMap {
    /// Constructs a claim map and freezes its canonical digest.
    pub fn new(
        manifest: ManifestId,
        admitted: BTreeSet<ClaimId>,
        entries: Vec<ClaimEntry>,
        groups: Vec<DependenceGroup>,
        unresolved: BTreeSet<ClaimId>,
    ) -> Result<Self, ContractError> {
        let mut map = Self {
            manifest,
            admitted,
            entries,
            groups,
            unresolved,
            digest: String::new(),
        };
        map.validate_shape()?;
        map.digest = map.compute_digest()?;
        Ok(map)
    }

    /// Recomputes the canonical digest of the map shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.manifest,
            &self.admitted,
            &self.entries,
            &self.groups,
            &self.unresolved,
        ))
    }

    /// Returns whether every accepted entry carries component coverage: at
    /// least one supporting accepted handle or an explicit unresolved marker.
    pub fn has_component_coverage(&self) -> bool {
        self.entries.iter().all(|entry| {
            !matches!(entry.verdict, ClaimVerdict::Accepted)
                || !entry.support.is_empty()
                || !entry.unresolved_support.is_empty()
        })
    }

    /// Returns the admitted claims accepted by verdict.
    pub fn accepted_ids(&self) -> BTreeSet<ClaimId> {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.verdict, ClaimVerdict::Accepted))
            .map(|entry| entry.claim.clone())
            .collect()
    }

    /// Returns the admitted claims rejected by verdict.
    pub fn rejected_ids(&self) -> BTreeSet<ClaimId> {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.verdict, ClaimVerdict::Rejected))
            .map(|entry| entry.claim.clone())
            .collect()
    }

    /// Returns the admitted claims held open by preserved counterevidence.
    pub fn countered_ids(&self) -> BTreeSet<ClaimId> {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.verdict, ClaimVerdict::Countered))
            .map(|entry| entry.claim.clone())
            .collect()
    }

    /// Returns every named assumption set across all entries.
    pub fn assumption_names(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .flat_map(|entry| entry.assumptions.iter().cloned())
            .collect()
    }

    /// Returns the weakest known grade across all entries, or `None` when any
    /// entry is unknown: the floor no dependent may rise above, and the grade
    /// ceiling the map as a whole can claim. Unknown poisons the aggregate.
    pub fn weakest_grade(&self) -> Option<EvidenceGrade> {
        let mut weakest: Option<EvidenceGrade> = None;
        for entry in &self.entries {
            let known = entry.grade.known_grade()?;
            weakest = Some(match weakest {
                Some(current) if current.rank() < known.rank() => current,
                _ => known,
            });
        }
        weakest
    }

    /// Returns the weakest assignment across all entries: unknown when any
    /// entry is unknown, else the least rigorous known grade.
    pub fn weakest_assignment(&self) -> Result<GradeAssignment, ContractError> {
        GradeAssignment::weakest(
            &self
                .entries
                .iter()
                .map(|entry| entry.grade.clone())
                .collect::<Vec<_>>(),
        )
    }

    /// Validates entries against the manifest, returning entered claims and
    /// their grades for the closure checks below.
    fn check_entries(
        &self,
    ) -> Result<(BTreeSet<ClaimId>, BTreeMap<ClaimId, GradeAssignment>), ContractError> {
        let mut seen_claims = BTreeSet::new();
        let mut seen_digests = BTreeSet::new();
        let mut grades = BTreeMap::new();
        for entry in &self.entries {
            entry.validate()?;
            if !self.admitted.contains(&entry.claim) {
                return Err(ContractError::OutsideManifest {
                    field: "claim.entries",
                });
            }
            if !seen_claims.insert(entry.claim.clone()) {
                return Err(ContractError::Duplicate {
                    field: "claim.entries",
                });
            }
            if !seen_digests.insert((entry.claim.clone(), entry.statement_digest.clone())) {
                return Err(ContractError::Duplicate {
                    field: "claim.entries",
                });
            }
            for dependency in &entry.dependencies {
                if !self.admitted.contains(dependency) {
                    return Err(ContractError::MissingReference {
                        field: "claim.dependencies",
                    });
                }
            }
            grades.insert(entry.claim.clone(), entry.grade.clone());
        }
        Ok((seen_claims, grades))
    }

    /// Validates dependence groups against the manifest.
    fn check_groups(&self) -> Result<(), ContractError> {
        let mut seen_groups = BTreeSet::new();
        for group in &self.groups {
            group.validate()?;
            if !seen_groups.insert(group.group_id.clone()) {
                return Err(ContractError::Duplicate {
                    field: "claim.groups",
                });
            }
            for member in &group.members {
                if !self.admitted.contains(member) {
                    return Err(ContractError::OutsideManifest {
                        field: "claim.group_members",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.entries.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "claim.entries",
            });
        }
        if self.entries.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.entries",
            });
        }
        if self.groups.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.groups",
            });
        }
        if self.unresolved.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "claim.unresolved",
            });
        }
        let (seen_claims, grades) = self.check_entries()?;
        // Exact entries: the entry set coincides with the admitted set. An admitted claim without an entry is
        // unrepresented; an entry without admission is outside the manifest. Held-open claims keep their
        // provisional entries, so `unresolved` is a subset of the admitted claims, never unentered claims.
        for held in &self.unresolved {
            if !self.admitted.contains(held) {
                return Err(ContractError::OutsideManifest {
                    field: "claim.unresolved",
                });
            }
            if !seen_claims.contains(held) {
                return Err(ContractError::MissingReference {
                    field: "claim.unresolved",
                });
            }
        }
        for admitted in &self.admitted {
            if !seen_claims.contains(admitted) {
                return Err(ContractError::MissingReference {
                    field: "claim.entries",
                });
            }
        }
        // Dependent grades: quoting a claim never upgrades it. An unknown parent caps every dependent: a known
        // grade over an unknown parent is an upgrade and fails.
        for entry in &self.entries {
            for dependency in &entry.dependencies {
                if let Some(parent) = grades.get(dependency) {
                    match (parent.known_grade(), entry.grade.known_grade()) {
                        (Some(known_parent), Some(known_child)) => {
                            EvidenceGrade::check_dependent(known_parent, known_child)?;
                        }
                        (None, Some(_)) => {
                            return Err(ContractError::CeilingViolation {
                                field: "grade.dependent",
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        self.check_groups()?;
        // Dependence groups cover dependent claims: every dependency edge of
        // an entry resolves inside a group holding both ends together.
        for entry in &self.entries {
            for dependency in &entry.dependencies {
                let covered = self.groups.iter().any(|group| {
                    group.members.contains(&entry.claim) && group.members.contains(dependency)
                });
                if !covered {
                    return Err(ContractError::MissingReference {
                        field: "claim.groups",
                    });
                }
            }
        }
        if !self.has_component_coverage() {
            return Err(ContractError::EmptyCollection {
                field: "claim.support",
            });
        }
        Ok(())
    }

    /// Validates the map shape, manifest closure, and frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "claim.digest")
    }
}
