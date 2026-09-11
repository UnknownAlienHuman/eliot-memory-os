//! A14's versioned numerical policy for bounded activation.
use eliot_cue_contracts::{
    ActivationBounds, ActivationStrength, CueContractError, CueKind, Digest, MatchMode,
    RelationKind,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ACTIVATION_PROFILE_REVISION: &str = "1.0.0";
const MAX_RULES: usize = 64;
const MAX_REGISTRY_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct MatchRule {
    pub kind: CueKind,
    pub mode: MatchMode,
    pub direct_strength: ActivationStrength,
}

impl MatchRule {
    #[must_use]
    pub const fn new(kind: CueKind, mode: MatchMode, direct_strength: ActivationStrength) -> Self {
        Self {
            kind,
            mode,
            direct_strength,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RelationRule {
    pub kind: RelationKind,
    pub weight_milli: u16,
}

impl RelationRule {
    #[must_use]
    pub const fn new(kind: RelationKind, weight_milli: u16) -> Self {
        Self { kind, weight_milli }
    }
}

#[derive(Serialize)]
struct ProfilePreimage<'a> {
    domain: &'static str,
    revision: &'a str,
    profile_id: &'a str,
    profile_revision: u32,
    bounds: &'a ActivationBounds,
    match_rules: &'a [MatchRule],
    relation_rules: &'a [RelationRule],
    registry_revision: &'a Option<String>,
}

/// Caller-supplied, versioned scoring and relation policy.
///
/// The profile is numerical retrieval policy only. Its digest is a local
/// integrity check over the supplied definition; it is not a benchmark,
/// authorization, registry admission, or semantic claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ActivationProfile {
    pub revision: String,
    pub profile_id: String,
    pub profile_revision: u32,
    pub bounds: ActivationBounds,
    pub match_rules: Vec<MatchRule>,
    pub relation_rules: Vec<RelationRule>,
    pub registry_revision: Option<String>,
    pub digest: Digest,
}

impl ActivationProfile {
    pub fn seal(
        profile_id: String,
        profile_revision: u32,
        bounds: ActivationBounds,
        mut match_rules: Vec<MatchRule>,
        mut relation_rules: Vec<RelationRule>,
        registry_revision: Option<String>,
    ) -> Result<Self, CueContractError> {
        match_rules.sort_by_key(|rule| (rule.kind, rule.mode));
        relation_rules.sort_by_key(|rule| relation_rank(rule.kind));
        let mut profile = Self {
            revision: ACTIVATION_PROFILE_REVISION.to_owned(),
            profile_id,
            profile_revision,
            bounds,
            match_rules,
            relation_rules,
            registry_revision,
            digest: Digest::new("0".repeat(64))?,
        };
        profile.validate_shape()?;
        profile.digest = profile.recompute_digest()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), CueContractError> {
        self.validate_shape()?;
        if self.digest != self.recompute_digest()? {
            return Err(CueContractError::Foundation {
                field: "activation.profile_digest",
            });
        }
        Ok(())
    }

    pub(crate) fn rule(&self, kind: CueKind, mode: MatchMode) -> Option<&MatchRule> {
        self.match_rules
            .iter()
            .find(|rule| rule.kind == kind && rule.mode == mode)
    }

    pub(crate) fn relation_weight(&self, kind: RelationKind) -> Option<u16> {
        self.relation_rules
            .iter()
            .find(|rule| rule.kind == kind)
            .map(|rule| rule.weight_milli)
    }

    fn validate_shape(&self) -> Result<(), CueContractError> {
        text(&self.revision, "activation.revision", 64)?;
        text(&self.profile_id, "activation.profile_id", 512)?;
        if self.revision != ACTIVATION_PROFILE_REVISION || self.profile_revision == 0 {
            return Err(CueContractError::InvalidText {
                field: "activation.profile",
            });
        }
        self.bounds.validate()?;
        self.validate_match_rules()?;
        self.validate_relation_rules()?;
        self.validate_registry()
    }

    fn validate_match_rules(&self) -> Result<(), CueContractError> {
        if self.match_rules.is_empty() || self.match_rules.len() > MAX_RULES {
            return Err(CueContractError::BoundExceeded {
                field: "activation.match_rules",
                limit: MAX_RULES,
            });
        }
        if self.relation_rules.len() > MAX_RULES {
            return Err(CueContractError::BoundExceeded {
                field: "activation.relation_rules",
                limit: MAX_RULES,
            });
        }
        let mut matches = BTreeSet::new();
        if self
            .match_rules
            .windows(2)
            .any(|pair| (pair[0].kind, pair[0].mode) >= (pair[1].kind, pair[1].mode))
        {
            return Err(CueContractError::Foundation {
                field: "activation.match_rules",
            });
        }
        for rule in &self.match_rules {
            if rule.direct_strength.0 == 0 || !matches.insert((rule.kind, rule.mode)) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "activation.match_rules",
                });
            }
            if rule.mode == MatchMode::Prefix
                && !matches!(rule.kind, CueKind::FilePath | CueKind::DirPath)
            {
                return Err(CueContractError::Foundation {
                    field: "activation.match_rules",
                });
            }
            if rule.mode == MatchMode::Signature && rule.kind != CueKind::ErrorSignature {
                return Err(CueContractError::Foundation {
                    field: "activation.match_rules",
                });
            }
        }
        for kind in [
            CueKind::FilePath,
            CueKind::DirPath,
            CueKind::Symbol,
            CueKind::ErrorSignature,
            CueKind::CommandPattern,
            CueKind::Dependency,
            CueKind::ApiSurface,
            CueKind::TaskClass,
            CueKind::Subsystem,
            CueKind::Concept,
        ] {
            let broad = self
                .match_rules
                .iter()
                .filter(|r| r.kind == kind && r.mode != MatchMode::Exact)
                .max_by_key(|r| r.direct_strength);
            if broad.is_some() && self.rule(kind, MatchMode::Exact).is_none() {
                return Err(CueContractError::Foundation {
                    field: "activation.exact_priority",
                });
            }
            if let (Some(exact), Some(broad)) = (self.rule(kind, MatchMode::Exact), broad)
                && exact.direct_strength < broad.direct_strength
            {
                return Err(CueContractError::Foundation {
                    field: "activation.exact_priority",
                });
            }
        }
        Ok(())
    }

    fn validate_relation_rules(&self) -> Result<(), CueContractError> {
        if self.relation_rules.len() > MAX_RULES {
            return Err(CueContractError::BoundExceeded {
                field: "activation.relation_rules",
                limit: MAX_RULES,
            });
        }
        let mut relations = BTreeSet::new();
        if self
            .relation_rules
            .windows(2)
            .any(|pair| relation_rank(pair[0].kind) >= relation_rank(pair[1].kind))
        {
            return Err(CueContractError::Foundation {
                field: "activation.relation_rules",
            });
        }
        for rule in &self.relation_rules {
            if !relations.insert(relation_rank(rule.kind)) || rule.weight_milli > 1000 {
                return Err(CueContractError::DuplicateIdentity {
                    field: "activation.relation_rules",
                });
            }
        }
        Ok(())
    }

    fn validate_registry(&self) -> Result<(), CueContractError> {
        if self.relation_rules.is_empty() {
            if self.registry_revision.is_some() {
                return Err(CueContractError::Foundation {
                    field: "activation.registry_revision",
                });
            }
        } else {
            let registry =
                self.registry_revision
                    .as_ref()
                    .ok_or(CueContractError::InvalidText {
                        field: "activation.registry_revision",
                    })?;
            text(registry, "activation.registry_revision", MAX_REGISTRY_BYTES)?;
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Result<Digest, CueContractError> {
        let preimage = ProfilePreimage {
            domain: "eliot.cue.activation.profile.v1",
            revision: &self.revision,
            profile_id: &self.profile_id,
            profile_revision: self.profile_revision,
            bounds: &self.bounds,
            match_rules: &self.match_rules,
            relation_rules: &self.relation_rules,
            registry_revision: &self.registry_revision,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&preimage).map_err(|_| {
            CueContractError::Foundation {
                field: "activation.profile_digest",
            }
        })?;
        Digest::new(eliot_contracts::sha256_hex(&bytes))
    }
}

fn text(value: &str, field: &'static str, limit: usize) -> Result<(), CueContractError> {
    if value.trim().is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return if value.len() > limit {
            Err(CueContractError::BoundExceeded { field, limit })
        } else {
            Err(CueContractError::InvalidText { field })
        };
    }
    Ok(())
}

const fn relation_rank(kind: RelationKind) -> u8 {
    match kind {
        RelationKind::Supports => 0,
        RelationKind::Counters => 1,
        RelationKind::Supersedes => 2,
        RelationKind::DerivedFrom => 3,
        RelationKind::AppliesTo => 4,
        RelationKind::ObservedIn => 5,
    }
}
