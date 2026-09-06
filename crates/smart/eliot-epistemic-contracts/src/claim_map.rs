//! Claim map: per-claim verdicts inside one admitted manifest.
//!
//! A [`ClaimMap`] holds one [`ClaimEntry`] per admitted claim. Each entry
//! carries its verdict, independent claim-audit outcome, preserved
//! counterevidence, conflict reference, authority, grade, explicit
//! dependencies, temporal/scope/precision bounds, coverage digest, ceiling,
//! assumptions, and discriminators. Entries form a meaningful sequence:
//! declaration order is preserved on the wire so reviewers read the map as
//! written, while identity semantics come from the claim IDs.
//!
//! The map rejects two failures closed: claims outside the admitted manifest,
//! and duplicate entries — including two entries sharing one claim ID with
//! different statement digests.

use std::collections::BTreeSet;

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
            ceiling,
            assumptions,
            discriminators,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Validates verdict/audit coherence, ceilings, and bounds.
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
    /// Claims admitted by the manifest; order carries no meaning.
    pub admitted: BTreeSet<ClaimId>,
    /// Per-claim entries in declaration order.
    pub entries: Vec<ClaimEntry>,
    /// Explicit dependence groups in declaration order.
    pub groups: Vec<DependenceGroup>,
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
    ) -> Result<Self, ContractError> {
        let mut map = Self {
            manifest,
            admitted,
            entries,
            groups,
            digest: String::new(),
        };
        map.validate_shape()?;
        map.digest = map.compute_digest()?;
        Ok(map)
    }

    /// Recomputes the canonical digest of the map shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(&self.manifest, &self.admitted, &self.entries, &self.groups))
    }

    /// Returns whether every entry carries component coverage.
    pub fn has_component_coverage(&self) -> bool {
        self.entries.iter().all(|entry| {
            entry.coverage_digest.len() == 64
                && !entry.assumptions.is_empty()
                && !entry.discriminators.is_empty()
        })
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
        let mut seen_claims = BTreeSet::new();
        let mut seen_digests = BTreeSet::new();
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
        }
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
