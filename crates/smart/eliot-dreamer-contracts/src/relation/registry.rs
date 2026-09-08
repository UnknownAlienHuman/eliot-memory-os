//! Immutable relation-registry snapshots and the closed I5.18 vocabulary.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::classification::ClassificationRecordFamily;
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};
use crate::relation::input::preflight_serialized;

/// The exact relation family vocabulary from I5.18.
pub const RELATION_FAMILIES: &[&str] = &[
    "supports",
    "contradicts",
    "verified_by",
    "supersedes",
    "belongs_to",
    "covers",
    "implements",
    "depends_on",
    "calls",
    "reads",
    "writes",
    "produces",
    "consumes",
    "causes",
    "fails_because",
    "resolved_by",
    "invalidated_by",
    "blocks",
    "unblocks",
    "satisfies",
    "reopens",
    "mentions",
    "derived_from",
    "included_in",
    "used_for",
    "suppressed_by",
    "authorized_by",
    "assigned_to",
    "influenced_by",
    "invalidates_influence",
    "derived_disclosure_from",
    "declassified_by",
    "grant_parent",
    "introduced_as",
    "bound_with_credential",
    "builds",
    "emits_artifact",
    "executes_test",
    "covers_code",
    "verifies_property",
    "co_change",
    "resembles",
    "diverges_from",
];

/// Closed relation family.  The spelling is the architecture authority.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationFamily {
    Supports,
    Contradicts,
    VerifiedBy,
    Supersedes,
    BelongsTo,
    Covers,
    Implements,
    DependsOn,
    Calls,
    Reads,
    Writes,
    Produces,
    Consumes,
    Causes,
    FailsBecause,
    ResolvedBy,
    InvalidatedBy,
    Blocks,
    Unblocks,
    Satisfies,
    Reopens,
    Mentions,
    DerivedFrom,
    IncludedIn,
    UsedFor,
    SuppressedBy,
    AuthorizedBy,
    AssignedTo,
    InfluencedBy,
    InvalidatesInfluence,
    DerivedDisclosureFrom,
    DeclassifiedBy,
    GrantParent,
    IntroducedAs,
    BoundWithCredential,
    Builds,
    EmitsArtifact,
    ExecutesTest,
    CoversCode,
    VerifiesProperty,
    CoChange,
    Resembles,
    DivergesFrom,
}

impl RelationFamily {
    /// Returns the canonical architecture spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
            Self::VerifiedBy => "verified_by",
            Self::Supersedes => "supersedes",
            Self::BelongsTo => "belongs_to",
            Self::Covers => "covers",
            Self::Implements => "implements",
            Self::DependsOn => "depends_on",
            Self::Calls => "calls",
            Self::Reads => "reads",
            Self::Writes => "writes",
            Self::Produces => "produces",
            Self::Consumes => "consumes",
            Self::Causes => "causes",
            Self::FailsBecause => "fails_because",
            Self::ResolvedBy => "resolved_by",
            Self::InvalidatedBy => "invalidated_by",
            Self::Blocks => "blocks",
            Self::Unblocks => "unblocks",
            Self::Satisfies => "satisfies",
            Self::Reopens => "reopens",
            Self::Mentions => "mentions",
            Self::DerivedFrom => "derived_from",
            Self::IncludedIn => "included_in",
            Self::UsedFor => "used_for",
            Self::SuppressedBy => "suppressed_by",
            Self::AuthorizedBy => "authorized_by",
            Self::AssignedTo => "assigned_to",
            Self::InfluencedBy => "influenced_by",
            Self::InvalidatesInfluence => "invalidates_influence",
            Self::DerivedDisclosureFrom => "derived_disclosure_from",
            Self::DeclassifiedBy => "declassified_by",
            Self::GrantParent => "grant_parent",
            Self::IntroducedAs => "introduced_as",
            Self::BoundWithCredential => "bound_with_credential",
            Self::Builds => "builds",
            Self::EmitsArtifact => "emits_artifact",
            Self::ExecutesTest => "executes_test",
            Self::CoversCode => "covers_code",
            Self::VerifiesProperty => "verifies_property",
            Self::CoChange => "co_change",
            Self::Resembles => "resembles",
            Self::DivergesFrom => "diverges_from",
        }
    }

    /// Parses only the current architecture vocabulary.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        let found = Self::all().iter().copied().find(|f| f.as_str() == value);
        found.ok_or_else(|| ContractViolation::UnknownVariant {
            field: "relation_family",
            value: value.to_owned(),
        })
    }

    /// Returns all current families in stable wire order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Supports,
            Self::Contradicts,
            Self::VerifiedBy,
            Self::Supersedes,
            Self::BelongsTo,
            Self::Covers,
            Self::Implements,
            Self::DependsOn,
            Self::Calls,
            Self::Reads,
            Self::Writes,
            Self::Produces,
            Self::Consumes,
            Self::Causes,
            Self::FailsBecause,
            Self::ResolvedBy,
            Self::InvalidatedBy,
            Self::Blocks,
            Self::Unblocks,
            Self::Satisfies,
            Self::Reopens,
            Self::Mentions,
            Self::DerivedFrom,
            Self::IncludedIn,
            Self::UsedFor,
            Self::SuppressedBy,
            Self::AuthorizedBy,
            Self::AssignedTo,
            Self::InfluencedBy,
            Self::InvalidatesInfluence,
            Self::DerivedDisclosureFrom,
            Self::DeclassifiedBy,
            Self::GrantParent,
            Self::IntroducedAs,
            Self::BoundWithCredential,
            Self::Builds,
            Self::EmitsArtifact,
            Self::ExecutesTest,
            Self::CoversCode,
            Self::VerifiesProperty,
            Self::CoChange,
            Self::Resembles,
            Self::DivergesFrom,
        ]
    }
}

/// Preserved orientation of the supplied source and target roles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationDirection {
    Forward,
    Reverse,
}

/// Per-family rule binding; registry flags are never ambient/global.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RelationFamilyRule {
    pub family: RelationFamily,
    pub direction: RelationDirection,
    pub source_roles: Vec<String>,
    pub target_roles: Vec<String>,
    pub source_record_families: Vec<ClassificationRecordFamily>,
    pub target_record_families: Vec<ClassificationRecordFamily>,
    pub permits_self_relation: bool,
    pub symmetric: bool,
    pub inverse_family: Option<RelationFamily>,
    pub permits_transitive: bool,
    pub requires_causal_mechanism: bool,
    pub rule_ref: String,
}

impl RelationDirection {
    /// Returns the canonical direction spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Reverse => "reverse",
        }
    }
}

/// Immutable, caller-supplied registry state used for structural validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationRegistrySnapshot {
    pub owner: String,
    pub schema: String,
    pub revision: String,
    pub digest: String,
    pub complete: bool,
    pub denominator: Vec<RelationFamily>,
    pub allowed_families: Vec<RelationFamily>,
    pub omitted_families: Vec<RelationFamily>,
    pub rules: Vec<RelationFamilyRule>,
    pub rule_refs: Vec<String>,
}

impl RelationRegistrySnapshot {
    /// Validates the finite registry snapshot without executing its rules.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_header()?;
        self.validate_family_partition()?;
        self.validate_rules()?;
        if self.computed_digest()? != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "registry.digest",
                reason: "registry digest does not cover full snapshot".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_header(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.owner, "registry.owner"),
            (&self.schema, "registry.schema"),
            (&self.revision, "registry.revision"),
        ] {
            check_text(value, field, 256)?;
        }
        if !is_hex64_lower(&self.digest) {
            return Err(ContractViolation::Malformed {
                field: "registry.digest",
                reason: "must be lowercase sha256".to_owned(),
            });
        }
        check_vec_bound(self.denominator.len(), 256, "registry.denominator")?;
        check_vec_bound(
            self.allowed_families.len(),
            256,
            "registry.allowed_families",
        )?;
        check_vec_bound(self.rule_refs.len(), 256, "registry.rule_refs")?;
        check_vec_bound(
            self.omitted_families.len(),
            256,
            "registry.omitted_families",
        )?;
        check_vec_bound(self.rules.len(), 256, "registry.rules")?;
        if self.denominator.is_empty() || self.allowed_families.is_empty() {
            return Err(ContractViolation::MissingField("registry.denominator"));
        }
        if self.complete && !self.omitted_families.is_empty() {
            return Err(ContractViolation::Registry(
                "complete registry cannot omit families".to_owned(),
            ));
        }
        if !self.complete && self.omitted_families.is_empty() {
            return Err(ContractViolation::Registry(
                "partial registry requires explicit omitted families".to_owned(),
            ));
        }
        for rule in &self.rule_refs {
            check_text(rule, "registry.rule_ref", 256)?;
        }
        Ok(())
    }

    fn validate_family_partition(&self) -> Result<(), ContractViolation> {
        let mut denominator = self.denominator.clone();
        denominator.sort_by_key(|family| family.as_str());
        denominator.dedup();
        if denominator.len() != self.denominator.len() {
            return Err(ContractViolation::Registry(
                "duplicate denominator family".to_owned(),
            ));
        }
        let mut allowed = self.allowed_families.clone();
        allowed.sort_by_key(|family| family.as_str());
        allowed.dedup();
        if allowed.len() != self.allowed_families.len() {
            return Err(ContractViolation::Registry(
                "duplicate allowed family".to_owned(),
            ));
        }
        let mut omitted = self.omitted_families.clone();
        omitted.sort_by_key(|family| family.as_str());
        omitted.dedup();
        if omitted.len() != self.omitted_families.len() {
            return Err(ContractViolation::Registry(
                "duplicate omitted family".to_owned(),
            ));
        }
        if self
            .allowed_families
            .iter()
            .any(|family| !self.denominator.contains(family))
        {
            return Err(ContractViolation::Registry(
                "allowed family is outside denominator".to_owned(),
            ));
        }
        if self
            .allowed_families
            .iter()
            .any(|family| self.omitted_families.contains(family))
        {
            return Err(ContractViolation::Registry(
                "allowed and omitted families must be disjoint".to_owned(),
            ));
        }
        let covered = self
            .allowed_families
            .iter()
            .chain(&self.omitted_families)
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let denominator = self
            .denominator
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if covered != denominator {
            return Err(ContractViolation::Registry(
                "registry must partition its denominator into allowed and omitted families"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_rules(&self) -> Result<(), ContractViolation> {
        let mut rule_families = Vec::with_capacity(self.rules.len());
        let mut row_refs = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if !self.allowed_families.contains(&rule.family) {
                return Err(ContractViolation::Registry(
                    "rule family outside allowed family set".to_owned(),
                ));
            }
            check_text(&rule.rule_ref, "registry.rule_ref", 256)?;
            check_vec_bound(rule.source_roles.len(), 32, "registry.source_roles")?;
            check_vec_bound(rule.target_roles.len(), 32, "registry.target_roles")?;
            check_vec_bound(
                rule.source_record_families.len(),
                32,
                "registry.source_record_families",
            )?;
            check_vec_bound(
                rule.target_record_families.len(),
                32,
                "registry.target_record_families",
            )?;
            for value in rule.source_roles.iter().chain(&rule.target_roles) {
                check_text(value, "registry.rule_member", 128)?;
            }
            if rule.source_roles.is_empty()
                || rule.target_roles.is_empty()
                || rule.source_record_families.is_empty()
                || rule.target_record_families.is_empty()
            {
                return Err(ContractViolation::Registry(
                    "per-family rule requires endpoint roles and record families".to_owned(),
                ));
            }
            if rule_families.contains(&rule.family) {
                return Err(ContractViolation::Registry(
                    "duplicate per-family rule".to_owned(),
                ));
            }
            if row_refs.contains(&rule.rule_ref) {
                return Err(ContractViolation::Registry(
                    "duplicate per-family rule reference".to_owned(),
                ));
            }
            if !self.rule_refs.contains(&rule.rule_ref) {
                return Err(ContractViolation::Registry(
                    "per-family rule reference is not retained by snapshot".to_owned(),
                ));
            }
            rule_families.push(rule.family);
            row_refs.push(rule.rule_ref.clone());
            if let Some(inverse) = rule.inverse_family
                && !self.denominator.contains(&inverse)
            {
                return Err(ContractViolation::Registry(
                    "inverse family is outside denominator".to_owned(),
                ));
            }
        }
        if self.rule_refs.len() != row_refs.len()
            || self
                .rule_refs
                .iter()
                .any(|reference| !row_refs.contains(reference))
        {
            return Err(ContractViolation::Registry(
                "snapshot rule references must exactly match per-family rows".to_owned(),
            ));
        }
        if rule_families.len() != self.allowed_families.len()
            || self
                .allowed_families
                .iter()
                .any(|family| !rule_families.contains(family))
        {
            return Err(ContractViolation::Registry(
                "registry requires one rule per allowed family".to_owned(),
            ));
        }
        Ok(())
    }
    /// Computes the SHA-256 over the full normalized registry preimage.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let preimage = self.normalized_for_digest()?;
        Ok(digest_hex(&canonical_bytes(&preimage)?))
    }

    /// Returns the bounded canonical form used for the registry digest.
    pub(crate) fn normalized_for_digest(&self) -> Result<Self, ContractViolation> {
        preflight_serialized(self, 4 * 1024 * 1024, "registry.bytes")?;
        let mut preimage = self.clone();
        preimage.digest.clear();
        preimage.denominator.sort_by_key(|f| f.as_str());
        preimage.allowed_families.sort_by_key(|f| f.as_str());
        preimage.omitted_families.sort_by_key(|f| f.as_str());
        preimage.rule_refs.sort();
        preimage.rules.sort_by_key(|rule| rule.family.as_str());
        for rule in &mut preimage.rules {
            rule.source_roles.sort();
            rule.target_roles.sort();
            rule.source_record_families
                .sort_by_key(|family| family.as_str());
            rule.target_record_families
                .sort_by_key(|family| family.as_str());
        }
        Ok(preimage)
    }
}
