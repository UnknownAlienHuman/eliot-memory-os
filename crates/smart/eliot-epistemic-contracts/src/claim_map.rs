//! Claim map: per-claim verdicts inside one admitted manifest.
//!
//! A [`ClaimMap`] holds one [`ClaimEntry`] per admitted claim — exactly one:
//! every admitted claim ID has an entry and every entry names an admitted
//! claim, so the admitted set and the entry set coincide. Each entry carries
//! its verdict, independent claim-audit outcome, preserved counterevidence,
//! conflict reference, authority, grade, explicit dependencies, temporal/scope/
//! precision bounds, component coverage, ceiling, assumptions, and
//! discriminators. Entries form a meaningful sequence: declaration order is
//! preserved on the wire so reviewers read the map as written, while identity
//! semantics come from the claim IDs.
//!
//! Component coverage is an explicit per-component support mapping, validated
//! rather than inferred: an accepted entry carries at least one supporting
//! accepted handle or an explicit unresolved marker. A digest plus assumption
//! and discriminator names never counts as coverage on its own.
//!
//! The map rejects two failures closed: claims outside the admitted manifest,
//! and duplicate entries — including two entries sharing one claim ID with
//! different statement digests.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::ArtifactId;
use eliot_evidence::EvidenceAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::grade::EvidenceGrade;
use crate::identity::{ClaimId, ManifestId};
use crate::support::ValidityBounds;

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

impl ClaimVerdict {
    /// Returns the exact frozen wire name of this verdict.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::Rejected => "REJECTED",
            Self::Countered => "COUNTERED",
        }
    }
}

/// Independent claim-audit outcome per I21.8.
///
/// Reference verification, value verification, specification compliance, and
/// method-artifact alignment are checked independently; uncertainty and scope
/// limits are preserved rather than smoothed.
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

impl ClaimAuditOutcome {
    /// Returns the exact frozen wire name of this audit outcome.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::PartiallySupported => "PARTIALLY_SUPPORTED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Contradicted => "CONTRADICTED",
            Self::NotVerifiableInScope => "NOT_VERIFIABLE_IN_SCOPE",
        }
    }
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
    /// Conflict set reference, when the claim participates in one.
    pub conflict: Option<ArtifactId>,
    /// Authority class of the evidence behind the claim.
    pub authority: EvidenceAuthority,
    /// Grade the claim was produced under.
    pub grade: EvidenceGrade,
    /// Explicit claim dependencies; order carries no meaning.
    pub dependencies: BTreeSet<ClaimId>,
    /// Temporal, scope, and precision bounds of the claim.
    pub bounds: ValidityBounds,
    /// Canonical digest of the component coverage behind the claim.
    pub coverage_digest: String,
    /// Accepted supporting handles behind the component coverage; order
    /// carries no meaning. An accepted claim carries at least one handle here
    /// or an explicit marker in `unresolved_support`.
    pub support: BTreeSet<ArtifactId>,
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
        conflict: Option<ArtifactId>,
        authority: EvidenceAuthority,
        grade: EvidenceGrade,
        dependencies: BTreeSet<ClaimId>,
        bounds: ValidityBounds,
        coverage_digest: impl Into<String>,
        support: BTreeSet<ArtifactId>,
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
            coverage_digest: coverage_digest.into(),
            support,
            unresolved_support,
            ceiling,
            assumptions,
            discriminators,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Validates verdict/audit coherence, ceilings, bounds, and component
    /// coverage: an accepted entry carries at least one supporting accepted
    /// handle or an explicit unresolved marker.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_digest(&self.statement_digest, "claim.statement_digest")?;
        validate_digest(&self.coverage_digest, "claim.coverage_digest")?;
        self.bounds.validate()?;
        EvidenceGrade::check_ceiling(self.grade, self.ceiling)?;
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

    /// Returns the weakest grade across all entries: the floor no dependent
    /// may rise above, and the grade ceiling the map as a whole can claim.
    pub fn weakest_grade(&self) -> Option<EvidenceGrade> {
        self.entries
            .iter()
            .map(|entry| entry.grade)
            .min_by_key(|grade| grade.rank())
    }

    /// Validates entries against the manifest, returning entered claims and
    /// their grades for the closure checks below.
    fn check_entries(
        &self,
    ) -> Result<(BTreeSet<ClaimId>, BTreeMap<ClaimId, EvidenceGrade>), ContractError> {
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
            grades.insert(entry.claim.clone(), entry.grade);
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
        // Exact entries: the entry set coincides with the admitted set. An
        // admitted claim without an entry is unrepresented; an entry without
        // admission is outside the manifest. Held-open claims keep their
        // provisional entries, so `unresolved` is a subset of the admitted
        // claims, never unentered claims.
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
        // Dependent grades: quoting a claim never upgrades it.
        for entry in &self.entries {
            for dependency in &entry.dependencies {
                if let Some(parent) = grades.get(dependency) {
                    EvidenceGrade::check_dependent(*parent, entry.grade)?;
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
        validate_digest(&self.digest, "claim.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "claim.digest",
            });
        }
        Ok(())
    }
}
