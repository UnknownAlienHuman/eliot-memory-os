//! Pure, bounded negative-memory matcher for one pending action (I12.19).
//!
//! The matcher is the semantic owner's comparison step. It performs no I/O, no
//! Store read, no network access, no model call and no clock read of its own:
//! the caller supplies the bounded read, the subject and the explicit
//! clock/revision reading. Its output is a comparison, never a decision — it
//! cannot publish an action policy, block an effect or expire a rule.
//!
//! # Exactness
//!
//! Every compared dimension is exact:
//!
//! * recorded trigger dimensions are compared to the subject's owner-issued
//!   dimensions by typed [`FailureDimensionValue`] equality, and both sides must
//!   agree on the dimension source and field;
//! * the canonical action kind and parameters, the owner-issued
//!   scope/resource/environment identities and the do-not-repeat horizon are
//!   compared as exact identities inside their own declared domains.
//!
//! There is deliberately no substring, prefix, ordering, embedding or
//! display-name relation in this module, so none of them can satisfy a recorded
//! exact predicate. A near match is a different outcome value from an exact
//! match, carries no gate effect, and no public function converts one into the
//! other.
//!
//! # Incompleteness is a distinct outcome
//!
//! [`NegativeMemoryOutcome::Incomplete`] and [`NegativeMemoryOutcome::NoMatch`]
//! are different values. A no-match can only be produced from
//! [`EnumerationCoverage::Complete`], and its completeness token is not
//! constructible outside this module, so a bounded enumeration with a missing
//! page can never certify the absence of an applicable rule.

use eliot_dreamer_contracts::{
    ContractViolation, FailureAction, FailureApplicability, FailureCoverage, FailureDimension,
    FailureDimensionSource, FailureDimensionValue, FailureEnvironment, canonical_bytes, digest_hex,
    error::check_text, is_hex64_lower,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::negative_memory::{
    NEGATIVE_MEMORY_MAX_TEXT, NegativeMemoryFingerprint, NegativeMemoryHorizonDomain,
    NegativeMemoryHorizonRelation, NegativeMemoryRecordDefect, NegativeMemoryResource,
    NegativeMemoryResourceKind, NegativeMemoryUnresolvedReason, NegativeMemoryViolation,
    effect_class_text, negative_memory_record_defect,
};

/// Wire revision of a matcher result.
pub const NEGATIVE_MEMORY_MATCH_SCHEMA_VERSION: u32 = 1;

/// Domain label mixed into the matcher result content digest.
const MATCH_DIGEST_DOMAIN: &str = "eliot-dreamer-failure/negative-memory-match/v1";

/// Domain label mixed into the subject content digest.
const SUBJECT_DIGEST_DOMAIN: &str = "eliot-dreamer-failure/negative-memory-subject/v1";

/// The closed set of relations a compared identity can satisfy.
///
/// [`IdentityRelation::ExactIdentity`] is the only relation that can satisfy a
/// recorded exact predicate. The absence of any approximate, containment or
/// ordering variant is the load-bearing property: a display name, a substring
/// or an approximate embedding has no way to be reported as a relation between
/// two owner-issued identities.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum IdentityRelation {
    /// Both sides carry the same owner-issued identity.
    ExactIdentity,
    /// Both sides carry known, different owner-issued identities.
    DistinctIdentity,
    /// The subject retained no value for this field, so the relation cannot be
    /// decided from the retained record.
    Unresolved,
    /// The recorded side is advisory and unresolved, so no relation can be
    /// asserted at all.
    AdvisoryUnresolved,
}

impl IdentityRelation {
    /// Whether this relation is the exact one an admitted predicate requires.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::ExactIdentity)
    }
}

/// One recorded trigger-predicate dimension compared against the subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PredicateComparison {
    /// The owner-declared dimension name.
    pub dimension_name: String,
    /// The owner-declared dimension source.
    pub source: FailureDimensionSource,
    /// The owner-declared dimension field.
    pub field: String,
    /// The exact recorded value.
    pub recorded: FailureDimensionValue,
    /// The exact observed value, or `Missing` when the subject retained none.
    pub observed: FailureDimensionValue,
    /// The relation the two sides satisfy.
    pub relation: IdentityRelation,
}

/// The recorded domain a compared identity came from.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ComparedScopeSource {
    /// The canonical action kind or parameter from the failed action record.
    FailedAction,
    /// An owner-issued task, work-scope or target identity.
    AffectedScope,
    /// An owner-issued resource identity.
    AffectedResource,
    /// An owner-issued environment identity.
    AffectedEnvironment,
}

/// One owner-issued scope, resource, environment or canonical-action identity
/// compared against the record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeComparison {
    /// Where the recorded identity came from.
    pub source: ComparedScopeSource,
    /// The exact field spelling on both sides.
    pub field: String,
    /// The exact recorded value.
    pub recorded: FailureDimensionValue,
    /// The exact observed value, or `Missing` when the subject retained none.
    pub observed: FailureDimensionValue,
    /// The relation the two sides satisfy.
    pub relation: IdentityRelation,
}

/// The pending action a rule set is checked against.
///
/// It carries only owner-issued identities: the canonical action kind and
/// parameters, the scope, the resources, the environment, and the typed
/// dimensions the subject supplies. A display name is not one of its fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemorySubject {
    /// The exact pending action.
    pub action: FailureAction,
    /// The owner-issued task, scope and target identities of the pending action.
    pub applicability: FailureApplicability,
    /// The owner-issued environment identity of the pending action.
    pub environment: FailureEnvironment,
    /// The exact owner-issued resources the pending action affects.
    pub resources: Vec<NegativeMemoryResource>,
    /// The owner-issued typed dimensions of the pending action, in the same
    /// dimension vocabulary as the record's trigger profile.
    pub predicate_dimensions: Vec<FailureDimension>,
    /// Coverage of the subject's own retained facts.
    pub coverage: FailureCoverage,
}

#[derive(Serialize)]
struct SubjectPreimage<'a> {
    domain: &'static str,
    action: &'a FailureAction,
    applicability: &'a FailureApplicability,
    environment: &'a FailureEnvironment,
    resources: &'a [NegativeMemoryResource],
    predicate_dimensions: &'a [FailureDimension],
    coverage: FailureCoverage,
}

impl NegativeMemorySubject {
    /// Computes the order-invariant content digest of this subject.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::DigestMismatch`] when the subject
    /// cannot be canonicalized.
    pub fn computed_digest(&self) -> Result<String, NegativeMemoryViolation> {
        let mut resources = self.resources.clone();
        resources.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        let mut dimensions = self.predicate_dimensions.clone();
        dimensions.sort_by(|left, right| left.name.cmp(&right.name));
        let preimage = SubjectPreimage {
            domain: SUBJECT_DIGEST_DOMAIN,
            action: &self.action,
            applicability: &self.applicability,
            environment: &self.environment,
            resources: &resources,
            predicate_dimensions: &dimensions,
            coverage: self.coverage,
        };
        canonical_bytes(&preimage)
            .map(|bytes| digest_hex(&bytes))
            .map_err(|_| NegativeMemoryViolation::DigestMismatch {
                field: "matcher.subject_digest",
            })
    }

    /// Validates the subject's identities, its typed dimensions and its
    /// coverage.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for a malformed identity, a
    /// duplicated dimension or resource identity, a `Missing` dimension value
    /// (which is never a wildcard) or a completely covered subject that
    /// supplies no dimensions at all.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        self.action
            .validate()
            .map_err(|_| NegativeMemoryViolation::MissingRequiredField {
                field: "matcher.subject.action",
            })?;
        self.applicability.validate().map_err(|_| {
            NegativeMemoryViolation::MissingRequiredField {
                field: "matcher.subject.applicability",
            }
        })?;
        self.environment
            .validate()
            .map_err(|_| NegativeMemoryViolation::MissingRequiredField {
                field: "matcher.subject.environment",
            })?;
        if self.resources.is_empty() {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "matcher.subject.resources",
            });
        }
        let mut resource_ids: Vec<&str> = Vec::with_capacity(self.resources.len());
        for resource in &self.resources {
            resource
                .validate()
                .map_err(|_| NegativeMemoryViolation::MissingRequiredField {
                    field: "matcher.subject.resources",
                })?;
            if resource_ids.contains(&resource.resource_id.as_str()) {
                return Err(NegativeMemoryViolation::DuplicateMember {
                    field: "matcher.subject.resources",
                    member: resource.resource_id.clone(),
                });
            }
            resource_ids.push(&resource.resource_id);
        }
        let mut names: Vec<&str> = Vec::with_capacity(self.predicate_dimensions.len());
        for dimension in &self.predicate_dimensions {
            dimension
                .validate()
                .map_err(|_| NegativeMemoryViolation::MissingRequiredField {
                    field: "matcher.subject.predicate_dimensions",
                })?;
            if names.contains(&dimension.name.as_str()) {
                return Err(NegativeMemoryViolation::DuplicateMember {
                    field: "matcher.subject.predicate_dimensions",
                    member: dimension.name.clone(),
                });
            }
            names.push(&dimension.name);
        }
        if matches!(self.coverage, FailureCoverage::Complete)
            && self.predicate_dimensions.is_empty()
        {
            return Err(NegativeMemoryViolation::BindingInconsistent {
                field: "matcher.subject.coverage",
            });
        }
        Ok(())
    }
}

/// One delivered page of the bounded rule read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryCandidatePage {
    /// One-based ordinal of this page inside the read.
    pub page_ordinal: u32,
    /// Exact named page reference.
    pub page_ref: String,
    /// The candidate rules this page delivered.
    pub rules: Vec<NegativeMemoryFingerprint>,
}

/// Whether the bounded read could establish the rule scope's page total.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DeclaredPageTotal {
    /// The read established the exact page total of the rule scope.
    Known {
        /// The exact page total.
        page_total: u32,
    },
    /// The read could not establish the page total, so the absence of an
    /// applicable rule cannot be certified.
    Unknown,
}

/// One bounded, named read of the applicable rule set.
///
/// The caller supplies the pages the read actually delivered together with the
/// pages it could not deliver. A missing page is retained here as a named
/// reference; it is never silently dropped, and its presence is what makes the
/// enumeration incomplete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryCandidateRead {
    /// Exact named read handle (I1.8).
    pub read_handle: String,
    /// The rule-set revision head the read observed before reading (I12.16
    /// Fence A). The matcher records it; it does not revalidate it.
    pub rule_set_revision: String,
    /// Digest over the delivered pages.
    pub rule_set_digest: String,
    /// The page total, when the read established it.
    pub declared_page_total: DeclaredPageTotal,
    /// Pages the read actually delivered, in read order.
    pub delivered_pages: Vec<NegativeMemoryCandidatePage>,
    /// Named pages the rule scope requires but the read did not deliver.
    pub missing_page_refs: Vec<String>,
    /// The read's own coverage of the rule scope.
    pub coverage: FailureCoverage,
}

impl NegativeMemoryCandidateRead {
    /// Validates the read's identity, page set, missing pages and coverage.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for a blank handle, a malformed
    /// digest or revision, a duplicated page ordinal or reference, a page
    /// ordinal of zero, an unknown page total, or complete coverage that still
    /// omits a required page.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        read_text("matcher.read.read_handle", &self.read_handle)?;
        read_text("matcher.read.rule_set_revision", &self.rule_set_revision)?;
        if !is_hex64_lower(&self.rule_set_digest) {
            return Err(NegativeMemoryViolation::NotADigest {
                field: "matcher.read.rule_set_digest",
            });
        }
        let mut ordinals: Vec<u32> = Vec::with_capacity(self.delivered_pages.len());
        let mut refs: Vec<&str> = Vec::with_capacity(self.delivered_pages.len());
        for delivered in &self.delivered_pages {
            if delivered.page_ordinal == 0 {
                return Err(NegativeMemoryViolation::NotPositiveRevision {
                    field: "matcher.read.page_ordinal",
                    got: 0,
                });
            }
            read_text("matcher.read.page_ref", &delivered.page_ref)?;
            if ordinals.contains(&delivered.page_ordinal) {
                return Err(NegativeMemoryViolation::DuplicateMember {
                    field: "matcher.read.page_ordinal",
                    member: delivered.page_ordinal.to_string(),
                });
            }
            if refs.contains(&delivered.page_ref.as_str()) {
                return Err(NegativeMemoryViolation::DuplicateMember {
                    field: "matcher.read.page_ref",
                    member: delivered.page_ref.clone(),
                });
            }
            ordinals.push(delivered.page_ordinal);
            refs.push(&delivered.page_ref);
        }
        for absent in &self.missing_page_refs {
            read_text("matcher.read.missing_page_refs", absent)?;
            if refs.contains(&absent.as_str()) {
                return Err(NegativeMemoryViolation::DuplicateMember {
                    field: "matcher.read.missing_page_refs",
                    member: absent.clone(),
                });
            }
        }
        if matches!(self.coverage, FailureCoverage::Complete) && !self.missing_page_refs.is_empty()
        {
            return Err(NegativeMemoryViolation::BindingInconsistent {
                field: "matcher.read.coverage",
            });
        }
        if let DeclaredPageTotal::Known { page_total } = self.declared_page_total
            && page_total as usize != self.delivered_pages.len() + self.missing_page_refs.len()
        {
            return Err(NegativeMemoryViolation::BindingInconsistent {
                field: "matcher.read.declared_page_total",
            });
        }
        Ok(())
    }
}

/// The real, named bound on one candidate enumeration.
///
/// Every field must be positive. The caller supplies the bound, so no default
/// is invented here and no unbounded enumeration is reachable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryMatchBound {
    /// Maximum rule pages one call may enumerate.
    pub max_enumerated_pages: u32,
    /// Maximum candidate rules one call may compare.
    pub compared_rule_limit: u32,
    /// Maximum compared identity fields one rule may produce.
    pub per_rule_field_limit: u32,
}

impl NegativeMemoryMatchBound {
    /// Validates that every named bound is positive.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::NotPositiveRevision`] naming the
    /// first zero bound.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        for (field, value) in [
            (
                "matcher.bound.max_enumerated_pages",
                self.max_enumerated_pages,
            ),
            (
                "matcher.bound.compared_rule_limit",
                self.compared_rule_limit,
            ),
            (
                "matcher.bound.per_rule_field_limit",
                self.per_rule_field_limit,
            ),
        ] {
            if value == 0 {
                return Err(NegativeMemoryViolation::NotPositiveRevision {
                    field,
                    got: u64::from(value),
                });
            }
        }
        Ok(())
    }
}

/// Proof that a bounded enumeration covered the whole queried rule scope.
///
/// [`EnumerationCoverage::Incomplete`] is the reason a bounded read with a
/// missing page cannot certify the absence of an applicable rule. It is a
/// value, not a comment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum EnumerationCoverage {
    /// Every page the rule scope names was delivered within the bound.
    Complete {
        /// Pages actually enumerated.
        pages_enumerated: u32,
        /// Candidate rules actually compared.
        candidate_count: u32,
    },
    /// The enumeration did not cover the rule scope.
    Incomplete {
        /// Named pages that were not delivered.
        missing_page_refs: Vec<String>,
        /// Why the enumeration is not complete.
        reason: IncompleteReason,
    },
}

/// Why a bounded comparison is not decidable. Each cause keeps its own variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum IncompleteReason {
    /// The read declared a page total but did not deliver every page.
    PageTotalNotDelivered {
        /// Pages the rule scope names.
        declared_page_total: u32,
        /// Pages actually delivered.
        pages_enumerated: u32,
    },
    /// The read could not establish the rule scope's page total.
    DeclaredPageTotalUnknown,
    /// One or more named pages were retained as not delivered.
    MissingRulePage {
        /// The named pages that were not delivered.
        page_refs: Vec<String>,
    },
    /// The read's own coverage was not complete.
    ReadCoverage {
        /// The coverage the read reported.
        coverage: FailureCoverage,
    },
    /// One candidate record could not be validated, so the enumeration cannot
    /// certify that it assessed the whole set.
    UnvalidatedCandidateRecord {
        /// Identity of the record that could not be validated.
        record_id: String,
        /// The typed defect.
        defect: NegativeMemoryRecordDefect,
    },
    /// One recorded rule's trigger is advisory and unresolved, so it can never
    /// satisfy an exact predicate and cannot be treated as any-scope.
    AdvisoryTriggerUnresolved {
        /// Identity of the unresolved rule.
        record_id: String,
        /// Rule revision.
        rule_revision: u64,
        /// Why its trigger is unresolved.
        reason: NegativeMemoryUnresolvedReason,
    },
    /// One compared field had no observed value, so its relation cannot be
    /// decided and absence cannot be certified.
    UndecidableComparison {
        /// Identity of the rule whose comparison is undecidable.
        record_id: String,
        /// Rule revision.
        rule_revision: u64,
        /// The field with no observed value.
        field: String,
    },
    /// One recorded do-not-repeat horizon names a different clock/revision
    /// domain than the caller's reading, so it decides nothing.
    UnrelatedHorizonDomain {
        /// Identity of the rule whose horizon is unrelated.
        record_id: String,
        /// Domain identity named by the record.
        recorded_domain_id: String,
        /// Domain identity supplied by the caller.
        observed_domain_id: String,
    },
}

/// The exact compared fields and retained evidence behind one comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchEvidence {
    /// Exact named read handle the rules came from.
    pub read_handle: String,
    /// Rule-set revision head the read observed (I12.16 Fence A).
    pub rule_set_revision: String,
    /// Digest over the delivered pages.
    pub rule_set_digest: String,
    /// Digest over the sorted identities of every assessed candidate.
    pub assessed_record_ids_digest: String,
    /// Number of candidate rules actually compared.
    pub assessed_record_count: u32,
    /// Number of recorded trigger-predicate dimensions compared.
    pub compared_predicate_dimension_count: u32,
    /// Number of owner-issued scope/action identity fields compared.
    pub compared_scope_field_count: u32,
    /// Retained limitation references; this matcher never holds authority.
    pub limitation_refs: Vec<String>,
}

/// An exact match of one admitted recorded rule against the subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactMatch {
    /// Immutable record identity of the matched rule.
    pub record_id: String,
    /// Immutable rule revision of the matched rule.
    pub rule_revision: u64,
    /// Content digest of the matched rule revision.
    pub record_digest: String,
    /// Every recorded predicate dimension and its exact relation.
    pub predicate_comparisons: Vec<PredicateComparison>,
    /// Every compared scope, action, resource and environment identity.
    pub scope_comparisons: Vec<ScopeComparison>,
    /// The do-not-repeat horizon relation inside its own domain.
    pub horizon: NegativeMemoryHorizonRelation,
    /// The exact compared fields and retained evidence.
    pub evidence: MatchEvidence,
}

/// A near match of one recorded rule against the subject.
///
/// The type holds its own comparisons and never an [`ExactMatch`]; no public
/// function in this crate promotes a near match into an exact one, and a near
/// match carries no gate effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NearMatch {
    /// Immutable record identity of the near-matched rule.
    pub record_id: String,
    /// Immutable rule revision of the near-matched rule.
    pub rule_revision: u64,
    /// Content digest of the near-matched rule revision.
    pub record_digest: String,
    /// Every recorded predicate dimension and its exact relation.
    pub predicate_comparisons: Vec<PredicateComparison>,
    /// Every compared scope, action, resource and environment identity.
    pub scope_comparisons: Vec<ScopeComparison>,
    /// The do-not-repeat horizon relation inside its own domain.
    pub horizon: NegativeMemoryHorizonRelation,
    /// Compared fields whose two sides are known, different identities.
    pub differing_field_names: Vec<String>,
    /// The exact compared fields and retained evidence.
    pub evidence: MatchEvidence,
}

/// A complete bounded enumeration that found no applicable rule.
///
/// The completeness token has no public constructor, so a no-match cannot be
/// fabricated outside this module and cannot be produced from an incomplete
/// enumeration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoMatch {
    /// Number of candidate rules actually compared.
    pub assessed_record_count: u32,
    /// The exact compared fields and retained evidence.
    pub evidence: MatchEvidence,
    /// Private: only a complete bounded enumeration can produce a no-match.
    enumeration: CompleteEnumeration,
}

impl NoMatch {
    /// Pages the complete bounded enumeration actually walked.
    #[must_use]
    pub const fn pages_enumerated(&self) -> u32 {
        self.enumeration.pages_enumerated
    }

    /// Candidate rules the complete bounded enumeration actually compared.
    #[must_use]
    pub const fn candidate_count(&self) -> u32 {
        self.enumeration.candidate_count
    }
}

/// The private completeness proof carried by a no-match.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CompleteEnumeration {
    pages_enumerated: u32,
    candidate_count: u32,
}

impl CompleteEnumeration {
    const fn new(pages_enumerated: u32, candidate_count: u32) -> Self {
        Self {
            pages_enumerated,
            candidate_count,
        }
    }
}

/// The matcher could not decide whether an applicable rule exists, so the
/// result certifies nothing about absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncompleteMatch {
    /// Every named reason the comparison is not decidable.
    pub reasons: Vec<IncompleteReason>,
    /// Number of candidate rules that could not be decided.
    pub undecidable_record_count: u32,
    /// The exact compared fields and retained evidence.
    pub evidence: MatchEvidence,
}

/// The four outcomes of one bounded comparison.
///
/// `NoMatch` and `Incomplete` are different values. A `Near` payload cannot be
/// read as an `Exact` payload by any public function in this crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum NegativeMemoryOutcome {
    /// An admitted recorded rule's exact predicate and every owner-issued
    /// scope, action, resource, environment and horizon join are satisfied.
    Exact {
        /// The exact match.
        matched: ExactMatch,
    },
    /// A recorded rule is the same rule with the same action kind, but at least
    /// one owner-issued identity is known and different. Advisory only.
    Near {
        /// The near match.
        matched: NearMatch,
    },
    /// A complete bounded enumeration compared every candidate rule and none
    /// applied.
    NoMatch {
        /// The no-match.
        observed: NoMatch,
    },
    /// The lookup is incomplete or unsupported, so absence is not certified.
    Incomplete {
        /// The incompleteness and what could not be decided.
        observed: IncompleteMatch,
    },
}

impl NegativeMemoryOutcome {
    /// The closed outcome class of this result.
    #[must_use]
    pub const fn kind(&self) -> NegativeMemoryMatchKind {
        match self {
            Self::Exact { .. } => NegativeMemoryMatchKind::Exact,
            Self::Near { .. } => NegativeMemoryMatchKind::Near,
            Self::NoMatch { .. } => NegativeMemoryMatchKind::NoMatch,
            Self::Incomplete { .. } => NegativeMemoryMatchKind::Incomplete,
        }
    }
}

/// The closed outcome class of a matcher result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum NegativeMemoryMatchKind {
    /// An exact admitted match.
    Exact,
    /// A near, advisory-only match.
    Near,
    /// A complete enumeration with no applicable rule.
    NoMatch,
    /// An incomplete or unsupported lookup.
    Incomplete,
}

impl NegativeMemoryMatchKind {
    /// Whether this outcome is allowed to certify that no applicable rule
    /// exists. Only a complete enumeration is.
    #[must_use]
    pub const fn certifies_rule_absence(self) -> bool {
        matches!(self, Self::NoMatch)
    }
}

/// The result of one pure, bounded comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryMatchResult {
    /// Wire revision of this result.
    pub schema_version: u32,
    /// The decisive outcome and its payload.
    pub outcome: NegativeMemoryOutcome,
    /// Whether the bounded enumeration covered the whole queried rule scope.
    pub enumeration: EnumerationCoverage,
    /// Order-invariant content digest of the subject compared.
    pub subject_digest: String,
    /// Number of candidate rules that produced an exact match.
    pub exact_record_count: u32,
    /// The bound this call was made under.
    pub bound: NegativeMemoryMatchBound,
}

#[derive(Serialize)]
struct ResultPreimage<'a> {
    domain: &'static str,
    schema_version: u32,
    outcome: &'a NegativeMemoryOutcome,
    enumeration: &'a EnumerationCoverage,
    subject_digest: &'a str,
    exact_record_count: u32,
    bound: NegativeMemoryMatchBound,
}

impl NegativeMemoryMatchResult {
    /// Computes the content digest of this result.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::DigestMismatch`] when the result
    /// cannot be canonicalized.
    pub fn computed_digest(&self) -> Result<String, NegativeMemoryViolation> {
        let preimage = ResultPreimage {
            domain: MATCH_DIGEST_DOMAIN,
            schema_version: self.schema_version,
            outcome: &self.outcome,
            enumeration: &self.enumeration,
            subject_digest: &self.subject_digest,
            exact_record_count: self.exact_record_count,
            bound: self.bound,
        };
        canonical_bytes(&preimage)
            .map(|bytes| digest_hex(&bytes))
            .map_err(|_| NegativeMemoryViolation::DigestMismatch {
                field: "matcher.result_digest",
            })
    }
}

fn read_text(field: &'static str, value: &str) -> Result<(), NegativeMemoryViolation> {
    check_text(value, field, NEGATIVE_MEMORY_MAX_TEXT).map_err(|error| match error {
        ContractViolation::MissingField(_) => {
            NegativeMemoryViolation::MissingRequiredField { field }
        }
        ContractViolation::OutOfBounds { got, max, .. } => {
            NegativeMemoryViolation::TextOutOfBounds {
                field,
                got,
                admitted: max,
            }
        }
        _ => NegativeMemoryViolation::ControlCharacterInText { field },
    })
}

fn counted(len: usize) -> Result<u32, NegativeMemoryViolation> {
    u32::try_from(len).map_err(|_| NegativeMemoryViolation::OutOfBounds {
        field: "matcher.count",
        got: i64::MAX,
        admitted: i64::from(u32::MAX),
    })
}

fn sum_counts(
    field: &'static str,
    mut lengths: impl Iterator<Item = usize>,
) -> Result<u32, NegativeMemoryViolation> {
    lengths.try_fold(0_u32, |total, len| {
        total
            .checked_add(counted(len)?)
            .ok_or(NegativeMemoryViolation::OutOfBounds {
                field,
                got: i64::MAX,
                admitted: i64::from(u32::MAX),
            })
    })
}

fn text_value(value: &str) -> FailureDimensionValue {
    FailureDimensionValue::Text(value.to_owned())
}

fn digest_value(value: &str) -> FailureDimensionValue {
    FailureDimensionValue::Digest(value.to_owned())
}

fn optional_text(value: Option<&str>) -> FailureDimensionValue {
    value.map_or(FailureDimensionValue::Missing, |inner| {
        FailureDimensionValue::Text(inner.to_owned())
    })
}

fn horizon_relation(
    through: &NegativeMemoryHorizonDomain,
    observed: &NegativeMemoryHorizonDomain,
) -> NegativeMemoryHorizonRelation {
    if observed.domain_sequence < through.domain_sequence {
        NegativeMemoryHorizonRelation::WithinHorizon {
            remaining_sequence_gap: through.domain_sequence - observed.domain_sequence,
        }
    } else {
        NegativeMemoryHorizonRelation::HorizonReached {
            observed_sequence: observed.domain_sequence,
        }
    }
}

/// One rule's decidable applicability, with every compared field retained.
struct RuleAssessment {
    record_id: String,
    rule_revision: u64,
    record_digest: String,
    predicate_comparisons: Vec<PredicateComparison>,
    scope_comparisons: Vec<ScopeComparison>,
    horizon: NegativeMemoryHorizonRelation,
    unresolved_reasons: Vec<NegativeMemoryUnresolvedReason>,
    is_exact: bool,
}

impl RuleAssessment {
    fn differing_field_names(&self) -> Vec<String> {
        self.predicate_comparisons
            .iter()
            .filter(|comparison| comparison.relation == IdentityRelation::DistinctIdentity)
            .map(|comparison| comparison.dimension_name.clone())
            .chain(
                self.scope_comparisons
                    .iter()
                    .filter(|comparison| comparison.relation == IdentityRelation::DistinctIdentity)
                    .map(|comparison| comparison.field.clone()),
            )
            .collect()
    }

    fn undecidable_field_names(&self) -> Vec<String> {
        self.predicate_comparisons
            .iter()
            .filter(|comparison| comparison.relation == IdentityRelation::Unresolved)
            .map(|comparison| comparison.dimension_name.clone())
            .chain(
                self.scope_comparisons
                    .iter()
                    .filter(|comparison| comparison.relation == IdentityRelation::Unresolved)
                    .map(|comparison| comparison.field.clone()),
            )
            .collect()
    }
}

/// Compares one pending action against a bounded, named rule read.
///
/// This is a pure function: it performs no I/O, no Store access, no network
/// call and no model call, and it reads no clock. The caller supplies the
/// bounded read, the subject and the explicit clock/revision reading.
///
/// The result is a comparison, not a decision. It never returns a disposition:
/// blocking and probe policy live in the separate
/// [`NegativeMemoryActionPolicy`](crate::NegativeMemoryActionPolicy) value, and
/// a record's existence or its digest matching grants no power here.
///
/// # Errors
///
/// Returns [`NegativeMemoryViolation`] when the bound, subject, observed
/// horizon or read fails validation, or when the delivered pages exceed the
/// named bound. A malformed *candidate record* is not an error: it becomes an
/// explicit undecidable reason so the lookup can never certify absence.
pub fn match_negative_memory(
    subject: &NegativeMemorySubject,
    observed_horizon: &NegativeMemoryHorizonDomain,
    read: &NegativeMemoryCandidateRead,
    bound: &NegativeMemoryMatchBound,
) -> Result<NegativeMemoryMatchResult, NegativeMemoryViolation> {
    bound.validate()?;
    subject.validate()?;
    observed_horizon.validate()?;
    read.validate()?;
    let pages_enumerated = counted(read.delivered_pages.len())?;
    let candidate_count = sum_counts(
        "matcher.candidate_count",
        read.delivered_pages
            .iter()
            .map(|delivered| delivered.rules.len()),
    )?;
    if pages_enumerated > bound.max_enumerated_pages {
        return Err(NegativeMemoryViolation::OutOfBounds {
            field: "matcher.bound.max_enumerated_pages",
            got: i64::from(pages_enumerated),
            admitted: i64::from(bound.max_enumerated_pages),
        });
    }
    if candidate_count > bound.compared_rule_limit {
        return Err(NegativeMemoryViolation::OutOfBounds {
            field: "matcher.bound.compared_rule_limit",
            got: i64::from(candidate_count),
            admitted: i64::from(bound.compared_rule_limit),
        });
    }
    let (enumeration, mut reasons) = enumeration_coverage(read, pages_enumerated, candidate_count);
    let mut record_reasons: Vec<IncompleteReason> = Vec::new();
    let assessments = assess_all(subject, observed_horizon, read, bound, &mut record_reasons)?;
    reasons.extend(record_reasons);
    let evidence = build_evidence(read, &assessments)?;
    let (outcome, exact_record_count) = decide(
        &assessments,
        &reasons,
        &evidence,
        pages_enumerated,
        candidate_count,
    )?;
    Ok(NegativeMemoryMatchResult {
        schema_version: NEGATIVE_MEMORY_MATCH_SCHEMA_VERSION,
        outcome,
        enumeration,
        subject_digest: subject.computed_digest()?,
        exact_record_count,
        bound: *bound,
    })
}

fn enumeration_coverage(
    read: &NegativeMemoryCandidateRead,
    pages_enumerated: u32,
    candidate_count: u32,
) -> (EnumerationCoverage, Vec<IncompleteReason>) {
    let mut reasons: Vec<IncompleteReason> = Vec::new();
    if !read.missing_page_refs.is_empty() {
        reasons.push(IncompleteReason::MissingRulePage {
            page_refs: read.missing_page_refs.clone(),
        });
    }
    match read.declared_page_total {
        DeclaredPageTotal::Unknown => reasons.push(IncompleteReason::DeclaredPageTotalUnknown),
        DeclaredPageTotal::Known { page_total } => {
            if page_total != pages_enumerated {
                reasons.push(IncompleteReason::PageTotalNotDelivered {
                    declared_page_total: page_total,
                    pages_enumerated,
                });
            }
        }
    }
    if read.coverage != FailureCoverage::Complete {
        reasons.push(IncompleteReason::ReadCoverage {
            coverage: read.coverage,
        });
    }
    if reasons.is_empty() {
        return (
            EnumerationCoverage::Complete {
                pages_enumerated,
                candidate_count,
            },
            reasons,
        );
    }
    let reason = reasons
        .first()
        .cloned()
        .unwrap_or(IncompleteReason::DeclaredPageTotalUnknown);
    (
        EnumerationCoverage::Incomplete {
            missing_page_refs: read.missing_page_refs.clone(),
            reason,
        },
        reasons,
    )
}

fn assess_all(
    subject: &NegativeMemorySubject,
    observed_horizon: &NegativeMemoryHorizonDomain,
    read: &NegativeMemoryCandidateRead,
    bound: &NegativeMemoryMatchBound,
    reasons: &mut Vec<IncompleteReason>,
) -> Result<Vec<RuleAssessment>, NegativeMemoryViolation> {
    let mut assessments = Vec::new();
    for delivered in &read.delivered_pages {
        for rule in &delivered.rules {
            match rule.validate() {
                Ok(()) => assessments.push(assess_one(subject, observed_horizon, rule, bound)?),
                Err(violation) => reasons.push(IncompleteReason::UnvalidatedCandidateRecord {
                    record_id: rule.record_id.clone(),
                    defect: negative_memory_record_defect(&violation),
                }),
            }
        }
    }
    assessments.sort_by(|left, right| {
        left.record_id
            .cmp(&right.record_id)
            .then(left.rule_revision.cmp(&right.rule_revision))
    });
    Ok(assessments)
}

fn assess_one(
    subject: &NegativeMemorySubject,
    observed_horizon: &NegativeMemoryHorizonDomain,
    rule: &NegativeMemoryFingerprint,
    bound: &NegativeMemoryMatchBound,
) -> Result<RuleAssessment, NegativeMemoryViolation> {
    let mut unresolved_reasons: Vec<NegativeMemoryUnresolvedReason> =
        rule.trigger.resolution.unresolved_reasons().to_vec();
    let predicate_comparisons: Vec<PredicateComparison> = rule
        .trigger
        .resolution
        .exact_predicate()
        .iter()
        .map(|dimension| compare_predicate_dimension(subject, dimension))
        .collect();
    let scope_comparisons = compare_scope_identities(subject, rule);
    if !matches!(subject.coverage, FailureCoverage::Complete) {
        unresolved_reasons.push(NegativeMemoryUnresolvedReason::IncompleteEvidence);
    }
    let compared = counted(predicate_comparisons.len() + scope_comparisons.len())?;
    if compared > bound.per_rule_field_limit {
        return Err(NegativeMemoryViolation::OutOfBounds {
            field: "matcher.bound.per_rule_field_limit",
            got: i64::from(compared),
            admitted: i64::from(bound.per_rule_field_limit),
        });
    }
    let horizon = if rule
        .do_not_repeat
        .through
        .shares_domain_with(observed_horizon)
    {
        horizon_relation(&rule.do_not_repeat.through, observed_horizon)
    } else {
        NegativeMemoryHorizonRelation::UnrelatedDomain {
            recorded_domain_id: rule.do_not_repeat.through.domain_id.clone(),
            observed_domain_id: observed_horizon.domain_id.clone(),
        }
    };
    let is_exact = unresolved_reasons.is_empty()
        && predicate_comparisons
            .iter()
            .all(|comparison| comparison.relation.is_exact())
        && scope_comparisons
            .iter()
            .all(|comparison| comparison.relation.is_exact())
        && matches!(horizon, NegativeMemoryHorizonRelation::WithinHorizon { .. });
    Ok(RuleAssessment {
        record_id: rule.record_id.clone(),
        rule_revision: rule.rule_revision,
        record_digest: rule.record_digest.clone(),
        predicate_comparisons,
        scope_comparisons,
        horizon,
        unresolved_reasons,
        is_exact,
    })
}

fn compare_predicate_dimension(
    subject: &NegativeMemorySubject,
    recorded: &FailureDimension,
) -> PredicateComparison {
    let found = subject.predicate_dimensions.iter().find(|candidate| {
        candidate.name == recorded.name
            && candidate.source == recorded.source
            && candidate.field == recorded.field
    });
    let observed = found.map_or(FailureDimensionValue::Missing, |candidate| {
        candidate.value.clone()
    });
    let relation = match found {
        None => IdentityRelation::Unresolved,
        Some(_) if observed == recorded.value => IdentityRelation::ExactIdentity,
        Some(_) => IdentityRelation::DistinctIdentity,
    };
    PredicateComparison {
        dimension_name: recorded.name.clone(),
        source: recorded.source,
        field: recorded.field.clone(),
        recorded: recorded.value.clone(),
        observed,
        relation,
    }
}

fn compare_scope_identities(
    subject: &NegativeMemorySubject,
    rule: &NegativeMemoryFingerprint,
) -> Vec<ScopeComparison> {
    let mut comparisons = compare_action_identities(subject, rule);
    comparisons.extend(compare_affected_identities(subject, rule));
    comparisons.extend(compare_environment_identities(subject, rule));
    comparisons.extend(compare_resources(
        &subject.resources,
        &rule.affected.resources,
    ));
    comparisons
}

fn compare_action_identities(
    subject: &NegativeMemorySubject,
    rule: &NegativeMemoryFingerprint,
) -> Vec<ScopeComparison> {
    let recorded = &rule.failed_action;
    let observed = &subject.action;
    vec![
        scope(
            ComparedScopeSource::FailedAction,
            "effect_id",
            &text_value(&recorded.effect_id),
            &text_value(&observed.effect_id),
        ),
        scope(
            ComparedScopeSource::FailedAction,
            "input_schema",
            &text_value(&recorded.input_schema),
            &text_value(&observed.input_schema),
        ),
        scope(
            ComparedScopeSource::FailedAction,
            "input_digest",
            &digest_value(&recorded.input_digest),
            &digest_value(&observed.input_digest),
        ),
        scope(
            ComparedScopeSource::FailedAction,
            "effect_class",
            &text_value(effect_class_text(recorded.effect_class)),
            &text_value(effect_class_text(observed.effect_class)),
        ),
        scope(
            ComparedScopeSource::FailedAction,
            "owner",
            &text_value(&recorded.owner),
            &text_value(&observed.owner),
        ),
        scope(
            ComparedScopeSource::FailedAction,
            "contract_revision",
            &text_value(&recorded.contract_revision),
            &text_value(&observed.contract_revision),
        ),
        scope(
            ComparedScopeSource::FailedAction,
            "contract_digest",
            &digest_value(&recorded.contract_digest),
            &digest_value(&observed.contract_digest),
        ),
    ]
}

fn compare_affected_identities(
    subject: &NegativeMemorySubject,
    rule: &NegativeMemoryFingerprint,
) -> Vec<ScopeComparison> {
    let observed = &subject.applicability;
    vec![
        scope(
            ComparedScopeSource::AffectedScope,
            "task_id",
            &text_value(&rule.affected.task_id),
            &text_value(&observed.task_id),
        ),
        scope(
            ComparedScopeSource::AffectedScope,
            "scope_id",
            &text_value(&rule.affected.scope_id),
            &text_value(&observed.scope_id),
        ),
        scope(
            ComparedScopeSource::AffectedScope,
            "target_id",
            &text_value(&rule.failed_action.target_id),
            &text_value(&observed.target_id),
        ),
    ]
}

fn compare_environment_identities(
    subject: &NegativeMemorySubject,
    rule: &NegativeMemoryFingerprint,
) -> Vec<ScopeComparison> {
    let recorded = &rule.affected.environment;
    let observed = &subject.environment;
    vec![
        scope(
            ComparedScopeSource::AffectedEnvironment,
            "environment_id",
            &text_value(&recorded.environment_id),
            &text_value(&observed.environment_id),
        ),
        scope(
            ComparedScopeSource::AffectedEnvironment,
            "platform",
            &text_value(&recorded.platform),
            &text_value(&observed.platform),
        ),
        scope(
            ComparedScopeSource::AffectedEnvironment,
            "tool_revision",
            &text_value(&recorded.tool_revision),
            &text_value(&observed.tool_revision),
        ),
        scope(
            ComparedScopeSource::AffectedEnvironment,
            "model_revision",
            &optional_text(recorded.model_revision.as_deref()),
            &optional_text(observed.model_revision.as_deref()),
        ),
        scope(
            ComparedScopeSource::AffectedEnvironment,
            "config_revision",
            &text_value(&recorded.config_revision),
            &text_value(&observed.config_revision),
        ),
        scope(
            ComparedScopeSource::AffectedEnvironment,
            "capability_revision",
            &text_value(&recorded.capability_revision),
            &text_value(&observed.capability_revision),
        ),
        scope(
            ComparedScopeSource::AffectedEnvironment,
            "policy_revision",
            &text_value(&recorded.policy_revision),
            &text_value(&observed.policy_revision),
        ),
    ]
}

fn compare_resources(
    subject: &[NegativeMemoryResource],
    recorded: &[NegativeMemoryResource],
) -> Vec<ScopeComparison> {
    recorded
        .iter()
        .map(|resource| {
            let observed = subject.iter().find(|candidate| {
                candidate.kind == resource.kind && candidate.resource_id == resource.resource_id
            });
            let relation = match observed {
                None => IdentityRelation::Unresolved,
                Some(found) if found.resource_digest == resource.resource_digest => {
                    IdentityRelation::ExactIdentity
                }
                Some(_) => IdentityRelation::DistinctIdentity,
            };
            let observed_value = observed.map_or(FailureDimensionValue::Missing, |found| {
                FailureDimensionValue::Digest(found.resource_digest.clone())
            });
            ScopeComparison {
                source: ComparedScopeSource::AffectedResource,
                field: resource_field_name(resource),
                recorded: FailureDimensionValue::Digest(resource.resource_digest.clone()),
                observed: observed_value,
                relation,
            }
        })
        .collect()
}

fn resource_field_name(resource: &NegativeMemoryResource) -> String {
    let kind = match resource.kind {
        NegativeMemoryResourceKind::WorkScopeTarget => "work_scope_target",
        NegativeMemoryResourceKind::ExternalResource => "external_resource",
        NegativeMemoryResourceKind::Artifact => "artifact",
        NegativeMemoryResourceKind::EnvironmentResource => "environment_resource",
    };
    format!("{kind}:{}", resource.resource_id)
}

fn scope(
    source: ComparedScopeSource,
    field: &str,
    recorded: &FailureDimensionValue,
    observed: &FailureDimensionValue,
) -> ScopeComparison {
    let relation = if recorded == observed {
        IdentityRelation::ExactIdentity
    } else if matches!(observed, FailureDimensionValue::Missing) {
        IdentityRelation::Unresolved
    } else {
        IdentityRelation::DistinctIdentity
    };
    ScopeComparison {
        source,
        field: field.to_owned(),
        recorded: recorded.clone(),
        observed: observed.clone(),
        relation,
    }
}

fn build_evidence(
    read: &NegativeMemoryCandidateRead,
    assessments: &[RuleAssessment],
) -> Result<MatchEvidence, NegativeMemoryViolation> {
    let mut sorted_ids: Vec<String> = assessments
        .iter()
        .map(|assessment| format!("{}@{}", assessment.record_id, assessment.rule_revision))
        .collect();
    sorted_ids.sort();
    let ids_digest = canonical_bytes(&sorted_ids)
        .map(|bytes| digest_hex(&bytes))
        .map_err(|_| NegativeMemoryViolation::DigestMismatch {
            field: "matcher.assessed_record_ids_digest",
        })?;
    Ok(MatchEvidence {
        read_handle: read.read_handle.clone(),
        rule_set_revision: read.rule_set_revision.clone(),
        rule_set_digest: read.rule_set_digest.clone(),
        assessed_record_ids_digest: ids_digest,
        assessed_record_count: counted(assessments.len())?,
        compared_predicate_dimension_count: sum_counts(
            "matcher.compared_predicate_dimension_count",
            assessments
                .iter()
                .map(|assessment| assessment.predicate_comparisons.len()),
        )?,
        compared_scope_field_count: sum_counts(
            "matcher.compared_scope_field_count",
            assessments
                .iter()
                .map(|assessment| assessment.scope_comparisons.len()),
        )?,
        limitation_refs: vec![
            "dreamer_proposes_and_never_activates".to_owned(),
            "matcher_compares_and_never_grants_block_probe_or_extinction".to_owned(),
            "near_match_is_advisory_and_never_exact".to_owned(),
            "incomplete_lookup_cannot_certify_rule_absence".to_owned(),
            "display_names_substrings_and_approximate_embeddings_are_not_relations".to_owned(),
            "elapsed_time_alone_cannot_erase_history_or_establish_safety".to_owned(),
        ],
    })
}

fn decide(
    assessments: &[RuleAssessment],
    enumeration_reasons: &[IncompleteReason],
    evidence: &MatchEvidence,
    pages_enumerated: u32,
    candidate_count: u32,
) -> Result<(NegativeMemoryOutcome, u32), NegativeMemoryViolation> {
    let exact: Vec<&RuleAssessment> = assessments
        .iter()
        .filter(|assessment| assessment.is_exact)
        .collect();
    let exact_record_count = counted(exact.len())?;
    if let Some(decisive) = exact.first() {
        return Ok((
            NegativeMemoryOutcome::Exact {
                matched: exact_payload(decisive, evidence),
            },
            exact_record_count,
        ));
    }
    let mut reasons = enumeration_reasons.to_vec();
    for assessment in assessments {
        reasons.extend(undecidable_reasons(assessment));
    }
    if !reasons.is_empty() {
        return Ok((
            NegativeMemoryOutcome::Incomplete {
                observed: IncompleteMatch {
                    reasons,
                    undecidable_record_count: counted(assessments.len())?,
                    evidence: evidence.clone(),
                },
            },
            exact_record_count,
        ));
    }
    if let Some(decisive) = assessments
        .iter()
        .find(|assessment| !assessment.differing_field_names().is_empty())
    {
        return Ok((
            NegativeMemoryOutcome::Near {
                matched: near_payload(decisive, evidence),
            },
            exact_record_count,
        ));
    }
    Ok((
        NegativeMemoryOutcome::NoMatch {
            observed: NoMatch {
                assessed_record_count: counted(assessments.len())?,
                evidence: evidence.clone(),
                enumeration: CompleteEnumeration::new(pages_enumerated, candidate_count),
            },
        },
        exact_record_count,
    ))
}

fn undecidable_reasons(assessment: &RuleAssessment) -> Vec<IncompleteReason> {
    let mut reasons = Vec::new();
    for reason in &assessment.unresolved_reasons {
        reasons.push(IncompleteReason::AdvisoryTriggerUnresolved {
            record_id: assessment.record_id.clone(),
            rule_revision: assessment.rule_revision,
            reason: reason.clone(),
        });
    }
    for field in assessment.undecidable_field_names() {
        reasons.push(IncompleteReason::UndecidableComparison {
            record_id: assessment.record_id.clone(),
            rule_revision: assessment.rule_revision,
            field,
        });
    }
    if let NegativeMemoryHorizonRelation::UnrelatedDomain {
        recorded_domain_id,
        observed_domain_id,
    } = &assessment.horizon
    {
        reasons.push(IncompleteReason::UnrelatedHorizonDomain {
            record_id: assessment.record_id.clone(),
            recorded_domain_id: recorded_domain_id.clone(),
            observed_domain_id: observed_domain_id.clone(),
        });
    }
    reasons
}

fn exact_payload(assessment: &RuleAssessment, evidence: &MatchEvidence) -> ExactMatch {
    ExactMatch {
        record_id: assessment.record_id.clone(),
        rule_revision: assessment.rule_revision,
        record_digest: assessment.record_digest.clone(),
        predicate_comparisons: assessment.predicate_comparisons.clone(),
        scope_comparisons: assessment.scope_comparisons.clone(),
        horizon: assessment.horizon.clone(),
        evidence: evidence.clone(),
    }
}

fn near_payload(assessment: &RuleAssessment, evidence: &MatchEvidence) -> NearMatch {
    NearMatch {
        record_id: assessment.record_id.clone(),
        rule_revision: assessment.rule_revision,
        record_digest: assessment.record_digest.clone(),
        predicate_comparisons: assessment.predicate_comparisons.clone(),
        scope_comparisons: assessment.scope_comparisons.clone(),
        horizon: assessment.horizon.clone(),
        differing_field_names: assessment.differing_field_names(),
        evidence: evidence.clone(),
    }
}
