//! Current durable negative-memory fingerprint, its legacy migration and its
//! owner-admitted action policy (I12.19).
//!
//! This owner is the semantic owner of the negative-memory rule: it holds the
//! one current durable record shape, the explicit legacy/candidate migration,
//! and the action policy value. It is not the activation owner and not the
//! enforcement owner.
//!
//! # Authority ceiling
//!
//! Every type here is inert. A record existing, a record digest matching, a
//! migration completing and a policy digest matching are all *values*. None of
//! them is a decision, and none of them publishes, admits, blocks, expires or
//! proves a mechanism:
//!
//! * a [`NegativeMemoryFingerprint`] has no disposition field at all, so a
//!   content hash can never be read as a block decision;
//! * a [`NegativeMemoryActionPolicy`] is a separate value that must be
//!   published by the Governor (step 3 of #1731) before any effect owner may
//!   read it, and this crate exposes no conversion from a record to a policy;
//! * a [`NegativeMemoryLegacyMigration`] is structurally incapable of carrying
//!   an admitted exact predicate, so a legacy untyped payload can never be read
//!   as wildcard applicability;
//! * the causal ceiling mirrors [`CausalLimits`]: correlation may be described,
//!   causal mechanism may not be claimed.
//!
//! The pure matcher that compares this record against a pending action lives in
//! [`crate::negative_memory_match`].

use std::fmt;

use eliot_dreamer_contracts::{
    ContractViolation, FailureAction, FailureComparator, FailureComparisonProfile, FailureCoverage,
    FailureDimension, FailureEnvironment, canonical_bytes, digest_hex, error::check_text,
    is_hex64_lower,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assessment::CausalLimits;

use eliot_receipts::EffectClass;

/// Wire revision of the current durable negative-memory fingerprint record.
pub const NEGATIVE_MEMORY_SCHEMA_VERSION: u32 = 1;

/// Wire revision of the legacy migration and of the action policy value.
pub const NEGATIVE_MEMORY_POLICY_SCHEMA_VERSION: u32 = 1;

/// Bound for one text field of a negative-memory record.
pub const NEGATIVE_MEMORY_MAX_TEXT: usize = 1024;

/// Bound for one retained byte field of a negative-memory record.
pub const NEGATIVE_MEMORY_MAX_BYTES: usize = 1_048_576;

/// Domain label mixed into the fingerprint record content digest.
const FINGERPRINT_DIGEST_DOMAIN: &str = "eliot-dreamer-failure/negative-memory-record/v1";

/// Domain label mixed into the action policy content digest.
const POLICY_DIGEST_DOMAIN: &str = "eliot-dreamer-failure/negative-memory-action-policy/v1";

/// Domain label mixed into the legacy migration content digest.
const MIGRATION_DIGEST_DOMAIN: &str = "eliot-dreamer-failure/legacy-migration/v1";

/// Closed, typed failure set for the negative-memory record, migration and
/// policy. Every distinct failure keeps its own named variant; none collapses
/// into a string or a generic code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeMemoryViolation {
    /// The wire value carried a schema version this owner does not admit.
    UnsupportedSchemaVersion {
        /// Field that carried the version.
        field: &'static str,
        /// Observed version.
        got: u32,
        /// Only admitted version.
        admitted: u32,
    },
    /// A field that must be present for admission was blank or absent.
    MissingRequiredField {
        /// Field name.
        field: &'static str,
    },
    /// A text field was longer than its exact bound.
    TextOutOfBounds {
        /// Field name.
        field: &'static str,
        /// Observed length.
        got: i64,
        /// Admitted length.
        admitted: i64,
    },
    /// A text field contained a control character.
    ControlCharacterInText {
        /// Field name.
        field: &'static str,
    },
    /// A digest field was not lowercase 64-character SHA-256 hex.
    NotADigest {
        /// Field name.
        field: &'static str,
    },
    /// A stored digest did not cover the bytes or record it claims to cover.
    DigestMismatch {
        /// Field name.
        field: &'static str,
    },
    /// A closed reference set carried a duplicate member.
    DuplicateMember {
        /// Field name.
        field: &'static str,
        /// The repeated member.
        member: String,
    },
    /// A revision or sequence that must be at least one was zero.
    NotPositiveRevision {
        /// Field name.
        field: &'static str,
        /// Observed value.
        got: u64,
    },
    /// A count or bound fell outside its exact permitted range.
    OutOfBounds {
        /// Field name.
        field: &'static str,
        /// Observed value.
        got: i64,
        /// Admitted value.
        admitted: i64,
    },
    /// The record's trigger resolution is not an admitted exact predicate, so
    /// it can only ever be advisory.
    TriggerNotAdmitted {
        /// Field name.
        field: &'static str,
        /// Record identity.
        record_id: String,
        /// Rule revision.
        rule_revision: u64,
    },
    /// The owner-declared comparison profile itself is not an exact-equality
    /// profile, so it cannot carry an exact predicate.
    ProfileNotAdmissible {
        /// Field name.
        field: &'static str,
        /// The profile that was not admissible.
        profile_id: String,
    },
    /// A recorded predicate dimension is absent from the owner profile
    /// definition, or the exact resolution is not the profile's dimension set.
    UndeclaredPredicateDimension {
        /// Field name.
        field: &'static str,
        /// The offending dimension name.
        dimension_name: String,
    },
    /// A recorded predicate dimension carries a value the dimension vocabulary
    /// rejects, including the `Missing` value that would otherwise read as a
    /// wildcard.
    MalformedDimensionValue {
        /// Field name.
        field: &'static str,
        /// The offending dimension name.
        dimension_name: String,
    },
    /// The action policy does not bind this exact record identity and revision.
    PolicyBindingMismatch {
        /// Field name.
        field: &'static str,
        /// Record identity the policy was bound to.
        bound_record_id: String,
        /// Record identity presented for comparison.
        got_record_id: String,
    },
    /// A legacy untyped payload was presented where an admitted exact predicate
    /// is required. It stays advisory and unresolved.
    LegacyPayloadNotAdmissible {
        /// Field name.
        field: &'static str,
    },
    /// A record or policy attempted to claim an authority this owner does not hold.
    AuthorityNotHeld {
        /// Field name.
        field: &'static str,
        /// The specific claim that is refused.
        claim: &'static str,
    },
    /// Two fields of one record disagree about coverage, and the disagreement
    /// is not one of the resolvable per-field failures above.
    BindingInconsistent {
        /// Field name.
        field: &'static str,
    },
}

impl fmt::Display for NegativeMemoryViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion {
                field,
                got,
                admitted,
            } => write!(
                f,
                "unsupported schema version on {field}: got {got}, admitted {admitted}"
            ),
            Self::MissingRequiredField { field } => {
                write!(f, "missing required field: {field}")
            }
            Self::TextOutOfBounds {
                field,
                got,
                admitted,
            } => write!(
                f,
                "text out of bounds on {field}: got {got}, admitted {admitted}"
            ),
            Self::ControlCharacterInText { field } => {
                write!(f, "control character in text on {field}")
            }
            Self::NotADigest { field } => {
                write!(f, "not lowercase sha256 hex on {field}")
            }
            Self::DigestMismatch { field } => {
                write!(f, "digest does not cover its record on {field}")
            }
            Self::DuplicateMember { field, member } => {
                write!(f, "duplicate member {member} on {field}")
            }
            Self::NotPositiveRevision { field, got } => {
                write!(f, "revision must be positive on {field}: got {got}")
            }
            Self::OutOfBounds {
                field,
                got,
                admitted,
            } => write!(
                f,
                "out of bounds on {field}: got {got}, admitted {admitted}"
            ),
            Self::TriggerNotAdmitted {
                field,
                record_id,
                rule_revision,
            } => write!(
                f,
                "trigger is not an admitted exact predicate on {field}: {record_id}@{rule_revision}"
            ),
            Self::ProfileNotAdmissible { field, profile_id } => write!(
                f,
                "comparison profile is not an admissible exact profile on {field}: {profile_id}"
            ),
            Self::UndeclaredPredicateDimension {
                field,
                dimension_name,
            } => write!(
                f,
                "undeclared predicate dimension {dimension_name} on {field}"
            ),
            Self::MalformedDimensionValue {
                field,
                dimension_name,
            } => write!(
                f,
                "predicate dimension {dimension_name} carries a rejected value on {field}"
            ),
            Self::PolicyBindingMismatch {
                field,
                bound_record_id,
                got_record_id,
            } => write!(
                f,
                "action policy binding mismatch on {field}: bound {bound_record_id}, got {got_record_id}"
            ),
            Self::LegacyPayloadNotAdmissible { field } => write!(
                f,
                "legacy untyped payload is not an admissible predicate on {field}"
            ),
            Self::AuthorityNotHeld { field, claim } => {
                write!(f, "authority not held on {field}: {claim}")
            }
            Self::BindingInconsistent { field } => {
                write!(f, "inconsistent binding on {field}")
            }
        }
    }
}

impl std::error::Error for NegativeMemoryViolation {}

/// Maps one contract-layer failure into the closed set above, keeping the
/// field name and never dropping the distinction between failure kinds.
impl From<NegativeMemoryViolation> for ContractViolation {
    fn from(value: NegativeMemoryViolation) -> Self {
        Self::BindingMismatch {
            field: "negative_memory",
            reason: value.to_string(),
        }
    }
}

fn text(field: &'static str, value: &str) -> Result<(), NegativeMemoryViolation> {
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

fn digest(field: &'static str, value: &str) -> Result<(), NegativeMemoryViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(NegativeMemoryViolation::NotADigest { field })
    }
}

fn unique(field: &'static str, values: &[String]) -> Result<(), NegativeMemoryViolation> {
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(NegativeMemoryViolation::DuplicateMember {
                field,
                member: value.clone(),
            });
        }
    }
    Ok(())
}

fn positive(field: &'static str, value: u64) -> Result<(), NegativeMemoryViolation> {
    if value == 0 {
        return Err(NegativeMemoryViolation::NotPositiveRevision { field, got: value });
    }
    Ok(())
}

fn bounded(
    field: &'static str,
    got: usize,
    admitted: usize,
) -> Result<(), NegativeMemoryViolation> {
    if got > admitted {
        return Err(NegativeMemoryViolation::OutOfBounds {
            field,
            got: i64::try_from(got).unwrap_or(i64::MAX),
            admitted: i64::try_from(admitted).unwrap_or(i64::MAX),
        });
    }
    Ok(())
}

/// Why one candidate record could not be validated.
///
/// Every distinct failure keeps its own named variant, so a malformed record is
/// never reported as a generic code and never collapsed into a string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryRecordDefect {
    /// The record carried a schema version this owner does not admit.
    UnsupportedSchemaVersion {
        /// Observed version.
        got: u32,
        /// Only admitted version.
        admitted: u32,
    },
    /// A field required for admission was blank or absent.
    MissingRequiredField,
    /// A text field was out of bounds or carried a control character.
    MalformedText,
    /// A stored digest was malformed or did not cover its record.
    DigestFailure,
    /// A closed reference set carried a duplicate member.
    DuplicateMember,
    /// A revision, sequence or count fell outside its exact range.
    OutOfRange,
    /// The record's trigger is not an admitted exact predicate.
    TriggerNotAdmitted,
    /// A recorded predicate dimension is absent from the owner profile.
    UndeclaredPredicateDimension,
    /// A recorded predicate dimension carries a rejected value.
    MalformedDimensionValue,
    /// An action policy does not bind the record it was presented with.
    PolicyBindingMismatch,
    /// A legacy untyped payload was presented as an admitted predicate.
    LegacyPayloadNotAdmissible,
    /// The record claimed an authority this owner does not hold.
    AuthorityNotHeld,
    /// Two fields of the record disagree about coverage.
    BindingInconsistent,
}

/// Reduces one closed violation to the matching closed record defect, keeping
/// the cause distinct.
#[must_use]
pub fn negative_memory_record_defect(
    violation: &NegativeMemoryViolation,
) -> NegativeMemoryRecordDefect {
    match violation {
        NegativeMemoryViolation::UnsupportedSchemaVersion { got, admitted, .. } => {
            NegativeMemoryRecordDefect::UnsupportedSchemaVersion {
                got: *got,
                admitted: *admitted,
            }
        }
        NegativeMemoryViolation::MissingRequiredField { .. } => {
            NegativeMemoryRecordDefect::MissingRequiredField
        }
        NegativeMemoryViolation::TextOutOfBounds { .. }
        | NegativeMemoryViolation::ControlCharacterInText { .. } => {
            NegativeMemoryRecordDefect::MalformedText
        }
        NegativeMemoryViolation::NotADigest { .. }
        | NegativeMemoryViolation::DigestMismatch { .. } => {
            NegativeMemoryRecordDefect::DigestFailure
        }
        NegativeMemoryViolation::DuplicateMember { .. } => {
            NegativeMemoryRecordDefect::DuplicateMember
        }
        NegativeMemoryViolation::NotPositiveRevision { .. }
        | NegativeMemoryViolation::OutOfBounds { .. } => NegativeMemoryRecordDefect::OutOfRange,
        NegativeMemoryViolation::TriggerNotAdmitted { .. }
        | NegativeMemoryViolation::ProfileNotAdmissible { .. } => {
            NegativeMemoryRecordDefect::TriggerNotAdmitted
        }
        NegativeMemoryViolation::UndeclaredPredicateDimension { .. } => {
            NegativeMemoryRecordDefect::UndeclaredPredicateDimension
        }
        NegativeMemoryViolation::MalformedDimensionValue { .. } => {
            NegativeMemoryRecordDefect::MalformedDimensionValue
        }
        NegativeMemoryViolation::PolicyBindingMismatch { .. } => {
            NegativeMemoryRecordDefect::PolicyBindingMismatch
        }
        NegativeMemoryViolation::LegacyPayloadNotAdmissible { .. } => {
            NegativeMemoryRecordDefect::LegacyPayloadNotAdmissible
        }
        NegativeMemoryViolation::AuthorityNotHeld { .. } => {
            NegativeMemoryRecordDefect::AuthorityNotHeld
        }
        NegativeMemoryViolation::BindingInconsistent { .. } => {
            NegativeMemoryRecordDefect::BindingInconsistent
        }
    }
}

/// Why a trigger is not (yet) an admitted exact predicate. Each cause keeps its
/// own variant; none of them can be silently upgraded to applicability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryUnresolvedReason {
    /// The record was migrated from a legacy uninterpreted payload, so no
    /// typed trigger parameter is available.
    LegacyUntypedPayload,
    /// A dimension named by the owner profile was never supplied.
    MissingTriggerParameter {
        /// The dimension the owner profile names but the record omits.
        dimension_name: String,
    },
    /// The record's comparator is not exact equality.
    UnsupportedComparator,
    /// Retained source or verification evidence does not cover the record.
    IncompleteEvidence,
}

/// The trigger predicate a record carries, or the explicit reason it is still
/// advisory.
///
/// There is deliberately no wildcard, any-scope or default-applicable variant:
/// a record that cannot state its exact predicate is unresolved, and an
/// unresolved record can never satisfy an exact match.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryTriggerResolution {
    /// Every owner-declared dimension carries an exact typed value.
    ExactPredicate {
        /// The exact typed predicate, equal to the profile's dimensions.
        dimensions: Vec<FailureDimension>,
    },
    /// The trigger stays advisory and unresolved until an owner explicitly
    /// admits the missing parameters.
    AdvisoryUnresolved {
        /// Owner-declared dimensions that carry no value.
        unresolved_dimension_names: Vec<String>,
        /// Why the trigger is unresolved.
        unresolved_reasons: Vec<NegativeMemoryUnresolvedReason>,
    },
}

impl NegativeMemoryTriggerResolution {
    /// Whether this resolution is an admitted exact predicate.
    #[must_use]
    pub const fn is_exact_predicate(&self) -> bool {
        matches!(self, Self::ExactPredicate { .. })
    }

    /// The exact predicate dimensions, or an empty slice while unresolved.
    #[must_use]
    pub fn exact_predicate(&self) -> &[FailureDimension] {
        match self {
            Self::ExactPredicate { dimensions } => dimensions,
            Self::AdvisoryUnresolved { .. } => &[],
        }
    }

    /// The retained unresolved causes, or an empty slice while exact.
    #[must_use]
    pub fn unresolved_reasons(&self) -> &[NegativeMemoryUnresolvedReason] {
        match self {
            Self::ExactPredicate { .. } => &[],
            Self::AdvisoryUnresolved {
                unresolved_reasons, ..
            } => unresolved_reasons,
        }
    }
}

/// The typed trigger, its owner profile and its comparator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryTrigger {
    /// The owner-declared comparison profile, including its comparator and the
    /// retained owner definition bytes.
    pub profile: FailureComparisonProfile,
    /// The exact predicate, or the explicit unresolved state.
    pub resolution: NegativeMemoryTriggerResolution,
}

impl NegativeMemoryTrigger {
    /// Validates the profile, the resolution and their agreement.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::ProfileNotAdmissible`] when the
    /// profile is not an exact-equality profile with no missing dimension,
    /// [`NegativeMemoryViolation::UndeclaredPredicateDimension`] when an exact
    /// resolution is not the profile's exact dimension set, and
    /// [`NegativeMemoryViolation::MissingRequiredField`] when an unresolved
    /// resolution does not name its causes.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        self.profile
            .validate()
            .map_err(|_| NegativeMemoryViolation::ProfileNotAdmissible {
                field: "negative_memory.trigger.profile",
                profile_id: self.profile.profile_id.clone(),
            })?;
        if self.profile.comparator != FailureComparator::ExactEquality
            || !self.profile.missing_dimensions.is_empty()
        {
            return Err(NegativeMemoryViolation::ProfileNotAdmissible {
                field: "negative_memory.trigger.profile",
                profile_id: self.profile.profile_id.clone(),
            });
        }
        match &self.resolution {
            NegativeMemoryTriggerResolution::ExactPredicate { dimensions } => {
                for dimension in dimensions {
                    dimension.validate().map_err(|_| {
                        NegativeMemoryViolation::MalformedDimensionValue {
                            field: "negative_memory.trigger.resolution",
                            dimension_name: dimension.name.clone(),
                        }
                    })?;
                }
                if dimensions != &self.profile.dimensions {
                    return Err(NegativeMemoryViolation::UndeclaredPredicateDimension {
                        field: "negative_memory.trigger.resolution",
                        dimension_name: first_divergent_dimension_name(
                            &self.profile.dimensions,
                            dimensions,
                        ),
                    });
                }
            }
            NegativeMemoryTriggerResolution::AdvisoryUnresolved {
                unresolved_dimension_names,
                unresolved_reasons,
            } => {
                if unresolved_dimension_names.is_empty() || unresolved_reasons.is_empty() {
                    return Err(NegativeMemoryViolation::MissingRequiredField {
                        field: "negative_memory.trigger.resolution",
                    });
                }
                unique(
                    "negative_memory.trigger.unresolved_dimension_names",
                    unresolved_dimension_names,
                )
                .and_then(|()| {
                    unique(
                        "negative_memory.trigger.unresolved_reasons",
                        &reason_tokens(unresolved_reasons),
                    )
                })?;
            }
        }
        Ok(())
    }
}

fn reason_tokens(reasons: &[NegativeMemoryUnresolvedReason]) -> Vec<String> {
    reasons
        .iter()
        .map(|reason| match reason {
            NegativeMemoryUnresolvedReason::LegacyUntypedPayload => {
                "legacy_untyped_payload".to_owned()
            }
            NegativeMemoryUnresolvedReason::MissingTriggerParameter { dimension_name } => {
                format!("missing_trigger_parameter:{dimension_name}")
            }
            NegativeMemoryUnresolvedReason::UnsupportedComparator => {
                "unsupported_comparator".to_owned()
            }
            NegativeMemoryUnresolvedReason::IncompleteEvidence => "incomplete_evidence".to_owned(),
        })
        .collect()
}

fn first_divergent_dimension_name(
    profile_dimensions: &[FailureDimension],
    resolved: &[FailureDimension],
) -> String {
    profile_dimensions
        .iter()
        .find(|dimension| !resolved.contains(dimension))
        .or_else(|| {
            resolved
                .iter()
                .find(|dimension| !profile_dimensions.contains(dimension))
        })
        .map_or_else(
            || {
                profile_dimensions
                    .first()
                    .map_or_else(String::new, |first| first.name.clone())
            },
            |dimension| dimension.name.clone(),
        )
}

/// Owner-issued resource identity kinds. Only exact identities are admitted;
/// there is no display-name or fuzzy resource kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryResourceKind {
    /// An owner-issued task or work-scope target.
    WorkScopeTarget,
    /// An owner-issued external system resource.
    ExternalResource,
    /// An owner-issued artifact or output handle.
    Artifact,
    /// An owner-issued environment or configuration resource.
    EnvironmentResource,
}

/// One exact owner-issued affected resource identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryResource {
    /// Owner-issued kind of the resource.
    pub kind: NegativeMemoryResourceKind,
    /// Owner-issued resource identity.
    pub resource_id: String,
    /// Digest over the exact resource content the owner retained.
    pub resource_digest: String,
}

impl NegativeMemoryResource {
    /// Validates the identity and its content digest.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for blank, oversize, control
    /// character or non-digest values.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.resource.resource_id", &self.resource_id)?;
        digest(
            "negative_memory.resource.resource_digest",
            &self.resource_digest,
        )
    }
}

/// The owner-issued scope, resources and environment a record is confined to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryAffectedScope {
    /// Owner-issued task identity.
    pub task_id: String,
    /// Owner-issued work-scope identity.
    pub scope_id: String,
    /// Owner-issued environment identity and its revisions.
    pub environment: FailureEnvironment,
    /// Exact owner-issued affected resources; at least one is required, so a
    /// record can never be read as an any-resource rule.
    pub resources: Vec<NegativeMemoryResource>,
}

impl NegativeMemoryAffectedScope {
    /// Validates every scope, environment and resource identity.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for an empty resource set, an
    /// invalid environment, a duplicate resource or a malformed identity.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.affected.task_id", &self.task_id)?;
        text("negative_memory.affected.scope_id", &self.scope_id)?;
        self.environment
            .validate()
            .map_err(|_| NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.affected.environment",
            })?;
        if self.resources.is_empty() {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.affected.resources",
            });
        }
        let mut seen: Vec<String> = Vec::with_capacity(self.resources.len());
        for resource in &self.resources {
            resource.validate()?;
            if seen.contains(&resource.resource_id) {
                return Err(NegativeMemoryViolation::DuplicateMember {
                    field: "negative_memory.affected.resources",
                    member: resource.resource_id.clone(),
                });
            }
            seen.push(resource.resource_id.clone());
        }
        Ok(())
    }
}

/// Retained source and verification evidence for the violated invariant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryInvariantVerification {
    /// Whether retained verifier evidence covers the violation claim.
    pub coverage: FailureCoverage,
    /// Owner-issued verifier identity.
    pub verifier_id: String,
    /// Verifier revision.
    pub verifier_revision: String,
    /// Digest over the exact canonical verifier binding.
    pub verifier_digest: String,
    /// Retained receipt that carries the verifier result.
    pub verifier_receipt_ref: String,
    /// Exact evidence references backing the violation.
    pub evidence_refs: Vec<String>,
}

impl NegativeMemoryInvariantVerification {
    /// Validates the verifier bindings, coverage and evidence references.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for malformed bindings, empty
    /// evidence or duplicate references.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.invariant.verifier_id", &self.verifier_id)?;
        text(
            "negative_memory.invariant.verifier_revision",
            &self.verifier_revision,
        )?;
        digest(
            "negative_memory.invariant.verifier_digest",
            &self.verifier_digest,
        )?;
        text(
            "negative_memory.invariant.verifier_receipt_ref",
            &self.verifier_receipt_ref,
        )?;
        if self.evidence_refs.is_empty() {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.invariant.evidence_refs",
            });
        }
        unique(
            "negative_memory.invariant.evidence_refs",
            &self.evidence_refs,
        )
    }
}

/// The violated invariant together with its source and verification evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryInvariant {
    /// Owner-issued invariant identity.
    pub invariant_id: String,
    /// Invariant revision the failure was assessed against.
    pub invariant_revision: String,
    /// The declared violated invariant text, retained verbatim.
    pub violated_invariant: String,
    /// Exact retained source references for the invariant.
    pub source_refs: Vec<String>,
    /// Retained source and verification evidence.
    pub verification: NegativeMemoryInvariantVerification,
}

impl NegativeMemoryInvariant {
    /// Validates the invariant identity, sources and verification evidence.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for blank identities, an empty
    /// source set, duplicates or malformed verification bindings.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.invariant.invariant_id", &self.invariant_id)?;
        text(
            "negative_memory.invariant.invariant_revision",
            &self.invariant_revision,
        )?;
        text(
            "negative_memory.invariant.violated_invariant",
            &self.violated_invariant,
        )?;
        if self.source_refs.is_empty() {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.invariant.source_refs",
            });
        }
        unique("negative_memory.invariant.source_refs", &self.source_refs)?;
        self.verification.validate()
    }
}

/// The kind of owner-issued clock/revision domain a do-not-repeat horizon is
/// expressed in. Two horizons are comparable only inside one domain kind and
/// one domain identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryHorizonDomainKind {
    /// A Governor-assigned causal transaction sequence.
    TransactionSequence,
    /// An owner-issued resource generation.
    ResourceGeneration,
    /// An owner-issued rule revision.
    RuleRevision,
}

/// An explicit clock/revision domain reading. A wall-clock timestamp is not a
/// member of this type, so a horizon can never be compared against an
/// unrelated clock: the domain owner, kind, identity and sequence are all
/// explicit and must agree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryHorizonDomain {
    /// Owner that issued this domain.
    pub owner: String,
    /// Kind of owner-issued domain.
    pub domain_kind: NegativeMemoryHorizonDomainKind,
    /// Exact identity of the domain instance.
    pub domain_id: String,
    /// The domain's own revision or sequence value; never elapsed time.
    pub domain_sequence: u64,
}

impl NegativeMemoryHorizonDomain {
    /// Validates the domain identity and requires a positive sequence.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for blank identities or a zero
    /// sequence.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.horizon.owner", &self.owner)?;
        text("negative_memory.horizon.domain_id", &self.domain_id)?;
        positive(
            "negative_memory.horizon.domain_sequence",
            self.domain_sequence,
        )
    }

    /// Whether both readings belong to the same owner-issued domain instance.
    #[must_use]
    pub fn shares_domain_with(&self, other: &Self) -> bool {
        self.domain_kind == other.domain_kind && self.domain_id == other.domain_id
    }
}

/// The do-not-repeat horizon bound, expressed only inside its own domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryHorizon {
    /// The bound the rule claims inside its own clock/revision domain.
    pub through: NegativeMemoryHorizonDomain,
}

impl NegativeMemoryHorizon {
    /// Validates the bound's domain.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] when the bound's domain is invalid.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        self.through.validate()
    }
}

/// How a recorded horizon relates to a caller-supplied reading of the same
/// domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryHorizonRelation {
    /// Same domain, and the reading is strictly before the bound.
    WithinHorizon {
        /// Remaining owner-issued sequence distance to the bound.
        remaining_sequence_gap: u64,
    },
    /// Same domain, and the bound has been reached.
    HorizonReached {
        /// The observed owner-issued sequence.
        observed_sequence: u64,
    },
    /// The reading belongs to a different domain, so the bound decides nothing
    /// and elapse cannot expire the rule.
    UnrelatedDomain {
        /// Domain identity named by the record.
        recorded_domain_id: String,
        /// Domain identity supplied by the caller.
        observed_domain_id: String,
    },
}

/// The condition under which the negative memory may be reconsidered. It is a
/// recorded condition only: this owner never evaluates it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryReopenCondition {
    /// The declared reopen condition, retained verbatim.
    pub condition: String,
    /// Digest over the exact condition bytes.
    pub condition_digest: String,
    /// Owner-issued verifier that must produce the reopening evidence.
    pub required_verifier: String,
    /// Exact evidence references the reopen requires.
    pub required_evidence_refs: Vec<String>,
}

impl NegativeMemoryReopenCondition {
    /// Validates the condition, its digest and its verifier bindings.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] when the stored digest does not
    /// cover the condition text, or when the verifier/evidence sets are
    /// malformed, empty or duplicated.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.reopen.condition", &self.condition)?;
        digest(
            "negative_memory.reopen.condition_digest",
            &self.condition_digest,
        )?;
        if digest_hex(self.condition.as_bytes()) != self.condition_digest {
            return Err(NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.reopen.condition_digest",
            });
        }
        text(
            "negative_memory.reopen.required_verifier",
            &self.required_verifier,
        )?;
        if self.required_evidence_refs.is_empty() {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.reopen.required_evidence_refs",
            });
        }
        unique(
            "negative_memory.reopen.required_evidence_refs",
            &self.required_evidence_refs,
        )
    }
}

/// A retained discriminating-check result. It is evidence, never a decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryCheckOutcome {
    /// The owner verifier reports the check passed.
    Passed,
    /// The owner verifier reports the check failed.
    Failed,
    /// The check result could not be established.
    Unknown,
}

/// Whether the declared discriminating check has been executed, and its result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryCheckExecution {
    /// The check is specified but not executed; this owner runs nothing.
    NotExecuted,
    /// The check was executed and its result is retained.
    Result {
        /// The retained verifier outcome.
        outcome: NegativeMemoryCheckOutcome,
    },
}

/// The specification of the one check that discriminates the recorded trigger
/// from a safe re-attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryDiscriminatingCheck {
    /// Owner-issued check identity.
    pub check_id: String,
    /// The recorded trigger dimensions this check discriminates. For an admitted
    /// exact predicate this must be a subset of the predicate's dimension names.
    pub discriminates_dimension_names: Vec<String>,
    /// Owner-issued verifier that must produce the check result.
    pub required_verifier: String,
    /// Verifier revision.
    pub verifier_revision: String,
    /// Digest over the exact canonical verifier binding.
    pub verifier_digest: String,
    /// Execution state; this owner only records it.
    pub execution: NegativeMemoryCheckExecution,
}

impl NegativeMemoryDiscriminatingCheck {
    /// Validates the check identity, verifier bindings and dimension names.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for an empty discrimination set,
    /// malformed verifier bindings or duplicated dimension names.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.check.check_id", &self.check_id)?;
        text(
            "negative_memory.check.required_verifier",
            &self.required_verifier,
        )?;
        text(
            "negative_memory.check.verifier_revision",
            &self.verifier_revision,
        )?;
        digest(
            "negative_memory.check.verifier_digest",
            &self.verifier_digest,
        )?;
        if self.discriminates_dimension_names.is_empty() {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.check.discriminates_dimension_names",
            });
        }
        unique(
            "negative_memory.check.discriminates_dimension_names",
            &self.discriminates_dimension_names,
        )
    }
}

/// References to the rule's activation and false-activation history. The
/// history is retained; extinction may narrow influence but never erase it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryFalseActivationHistory {
    /// Coverage of the retained history denominator.
    pub coverage: FailureCoverage,
    /// The exact history denominator the read established.
    pub expected_total: u32,
    /// References to each matched action, rule revision and outcome.
    pub activation_refs: Vec<String>,
    /// References to later confirmed false activations.
    pub false_activation_refs: Vec<String>,
    /// References to history members deliberately omitted under partial coverage.
    pub omitted_refs: Vec<String>,
}

impl NegativeMemoryFalseActivationHistory {
    /// Validates the denominator, coverage and reference sets.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] when the denominator does not
    /// reconcile with the retained references, when complete coverage still
    /// omits members, or when a reference set is duplicated.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        for (value, field) in [
            (
                &self.activation_refs,
                "negative_memory.history.activation_refs",
            ),
            (
                &self.false_activation_refs,
                "negative_memory.history.false_activation_refs",
            ),
            (&self.omitted_refs, "negative_memory.history.omitted_refs"),
        ] {
            for reference in value {
                text(field, reference)?;
            }
            unique(field, value)?;
        }
        if self.false_activation_refs.len() > self.activation_refs.len() {
            return Err(NegativeMemoryViolation::OutOfBounds {
                field: "negative_memory.history.false_activation_refs",
                got: i64::try_from(self.false_activation_refs.len()).unwrap_or(i64::MAX),
                admitted: i64::try_from(self.activation_refs.len()).unwrap_or(i64::MAX),
            });
        }
        let represented = self
            .activation_refs
            .len()
            .checked_add(self.omitted_refs.len())
            .ok_or(NegativeMemoryViolation::OutOfBounds {
                field: "negative_memory.history.denominator",
                got: i64::MAX,
                admitted: i64::MAX,
            })?;
        if represented != self.expected_total as usize {
            return Err(NegativeMemoryViolation::OutOfBounds {
                field: "negative_memory.history.denominator",
                got: i64::try_from(represented).unwrap_or(i64::MAX),
                admitted: i64::from(self.expected_total),
            });
        }
        if matches!(self.coverage, FailureCoverage::Complete) && !self.omitted_refs.is_empty() {
            return Err(NegativeMemoryViolation::BindingInconsistent {
                field: "negative_memory.history.coverage",
            });
        }
        Ok(())
    }
}

/// The one current durable negative-memory fingerprint record (I12.19).
///
/// Every field is required on the wire: there is no `serde` default anywhere in
/// this record, so a legacy or partial value cannot decode into a current one.
/// The record carries no disposition, so neither its existence nor its
/// [`Self::record_digest`] can be read as a block decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryFingerprint {
    /// Wire revision of this record.
    pub schema_version: u32,
    /// Immutable record identity.
    pub record_id: String,
    /// Immutable rule revision inside one record identity.
    pub rule_revision: u64,
    /// Digest over every other field of this record. Content identity only.
    pub record_digest: String,
    /// Owner that holds semantic admission of the rule and its action policy.
    pub semantic_owner: String,
    /// Typed trigger, owner profile and comparator.
    pub trigger: NegativeMemoryTrigger,
    /// The exact action that failed.
    pub failed_action: FailureAction,
    /// The owner-issued scope, resources and environment it is confined to.
    pub affected: NegativeMemoryAffectedScope,
    /// The violated invariant and its source/verification evidence.
    pub invariant: NegativeMemoryInvariant,
    /// Causal status and its explicit limits.
    pub causal: CausalLimits,
    /// Do-not-repeat horizon in an explicit clock/revision domain.
    pub do_not_repeat: NegativeMemoryHorizon,
    /// Recorded reopen condition.
    pub reopen: NegativeMemoryReopenCondition,
    /// Discriminating-check specification.
    pub discriminating_check: NegativeMemoryDiscriminatingCheck,
    /// False-activation history references.
    pub false_activation_history: NegativeMemoryFalseActivationHistory,
}

#[derive(Serialize)]
struct FingerprintPreimage<'a> {
    domain: &'static str,
    schema_version: u32,
    record_id: &'a str,
    rule_revision: u64,
    semantic_owner: &'a str,
    trigger: &'a NegativeMemoryTrigger,
    failed_action: &'a FailureAction,
    affected: &'a NegativeMemoryAffectedScope,
    invariant: &'a NegativeMemoryInvariant,
    causal: &'a CausalLimits,
    do_not_repeat: &'a NegativeMemoryHorizon,
    reopen: &'a NegativeMemoryReopenCondition,
    discriminating_check: &'a NegativeMemoryDiscriminatingCheck,
    false_activation_history: &'a NegativeMemoryFalseActivationHistory,
}

impl NegativeMemoryFingerprint {
    /// Computes the record content digest over every field except
    /// [`Self::record_digest`].
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::DigestMismatch`] when the record
    /// cannot be canonicalized.
    pub fn computed_digest(&self) -> Result<String, NegativeMemoryViolation> {
        let preimage = FingerprintPreimage {
            domain: FINGERPRINT_DIGEST_DOMAIN,
            schema_version: self.schema_version,
            record_id: &self.record_id,
            rule_revision: self.rule_revision,
            semantic_owner: &self.semantic_owner,
            trigger: &self.trigger,
            failed_action: &self.failed_action,
            affected: &self.affected,
            invariant: &self.invariant,
            causal: &self.causal,
            do_not_repeat: &self.do_not_repeat,
            reopen: &self.reopen,
            discriminating_check: &self.discriminating_check,
            false_activation_history: &self.false_activation_history,
        };
        canonical_bytes(&preimage)
            .map(|bytes| digest_hex(&bytes))
            .map_err(|_| NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.record_digest",
            })
    }

    /// Whether the record states an admitted exact trigger predicate.
    #[must_use]
    pub const fn has_admitted_trigger(&self) -> bool {
        self.trigger.resolution.is_exact_predicate()
    }

    /// Validates the complete record, its content digest and the cross-field
    /// agreement the admission requires.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for any malformed field, a
    /// non-recomputing record digest, a causal claim this owner does not hold,
    /// or an admitted predicate that is not covered by retained evidence.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        if self.schema_version != NEGATIVE_MEMORY_SCHEMA_VERSION {
            return Err(NegativeMemoryViolation::UnsupportedSchemaVersion {
                field: "negative_memory.schema_version",
                got: self.schema_version,
                admitted: NEGATIVE_MEMORY_SCHEMA_VERSION,
            });
        }
        text("negative_memory.record_id", &self.record_id)?;
        positive("negative_memory.rule_revision", self.rule_revision)?;
        text("negative_memory.semantic_owner", &self.semantic_owner)?;
        digest("negative_memory.record_digest", &self.record_digest)?;
        if self.computed_digest()? != self.record_digest {
            return Err(NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.record_digest",
            });
        }
        self.validate_fields()
    }

    fn validate_fields(&self) -> Result<(), NegativeMemoryViolation> {
        self.trigger.validate()?;
        self.failed_action.validate().map_err(|_| {
            NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.failed_action",
            }
        })?;
        self.affected.validate()?;
        self.invariant.validate()?;
        self.validate_causal_ceiling()?;
        self.do_not_repeat.validate()?;
        self.reopen.validate()?;
        self.discriminating_check.validate()?;
        self.false_activation_history.validate()?;
        self.validate_admission_joins()
    }

    fn validate_causal_ceiling(&self) -> Result<(), NegativeMemoryViolation> {
        if self.causal.causal_claim_permitted {
            return Err(NegativeMemoryViolation::AuthorityNotHeld {
                field: "negative_memory.causal",
                claim: "causal_claim_permitted",
            });
        }
        if matches!(
            self.causal.status,
            eliot_dreamer_contracts::FailureCausalStatus::InterventionSupported
        ) {
            return Err(NegativeMemoryViolation::AuthorityNotHeld {
                field: "negative_memory.causal.status",
                claim: "intervention_supported",
            });
        }
        if self.causal.limitation_refs.is_empty() {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.causal.limitation_refs",
            });
        }
        unique(
            "negative_memory.causal.limitation_refs",
            &self.causal.limitation_refs,
        )
    }

    fn validate_admission_joins(&self) -> Result<(), NegativeMemoryViolation> {
        if !self.has_admitted_trigger() {
            return Ok(());
        }
        if !matches!(
            self.invariant.verification.coverage,
            FailureCoverage::Complete
        ) {
            return Err(NegativeMemoryViolation::TriggerNotAdmitted {
                field: "negative_memory.invariant.verification.coverage",
                record_id: self.record_id.clone(),
                rule_revision: self.rule_revision,
            });
        }
        let names: Vec<&str> = self
            .trigger
            .resolution
            .exact_predicate()
            .iter()
            .map(|dimension| dimension.name.as_str())
            .collect();
        for name in &self.discriminating_check.discriminates_dimension_names {
            if !names.contains(&name.as_str()) {
                return Err(NegativeMemoryViolation::UndeclaredPredicateDimension {
                    field: "negative_memory.check.discriminates_dimension_names",
                    dimension_name: name.clone(),
                });
            }
        }
        Ok(())
    }
}

/// The owner-admitted action policy for one exact record revision.
///
/// This is a separate value on purpose. It is bound to one record identity,
/// revision and content digest, it carries its own policy digest, and this
/// crate exposes no conversion from a [`NegativeMemoryFingerprint`] to a
/// policy. A record existing, or its digest matching, therefore yields no
/// disposition: only an owner may publish this value, and publishing is the
/// activation step that this owner does not perform.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryDisposition {
    /// Semantic similarity or an unresolved trigger warns only. It never
    /// acquires blocking power.
    Advisory,
    /// The mechanical gate must block the matched action.
    Block,
    /// The mechanical gate must return the named admitted discriminating check.
    RequireCheck,
}

/// The exact record identity, revision and content digest one action policy is
/// bound to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryPolicyBinding {
    /// Record identity the policy was admitted for.
    pub record_id: String,
    /// Rule revision the policy was admitted for.
    pub rule_revision: u64,
    /// Record content digest the policy was admitted for.
    pub record_digest: String,
}

impl NegativeMemoryPolicyBinding {
    /// Builds the binding for one exact record revision.
    #[must_use]
    pub const fn new(record_id: String, rule_revision: u64, record_digest: String) -> Self {
        Self {
            record_id,
            rule_revision,
            record_digest,
        }
    }
}

/// An owner-admitted action policy value. It is inert until its owner publishes
/// it; this crate proposes and validates, it never admits or applies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryActionPolicy {
    /// Wire revision of this policy value.
    pub schema_version: u32,
    /// Owner-issued policy identity.
    pub policy_id: String,
    /// Monotone policy revision.
    pub policy_revision: u64,
    /// Owner that holds admission of the policy.
    pub policy_owner: String,
    /// The exact record revision this policy is bound to.
    pub binding: NegativeMemoryPolicyBinding,
    /// The admitted disposition.
    pub disposition: NegativeMemoryDisposition,
    /// The named discriminating check required by `REQUIRE_CHECK`.
    pub named_check_id: String,
    /// Digest over every other field of this policy. Content identity only.
    pub policy_digest: String,
}

#[derive(Serialize)]
struct PolicyPreimage<'a> {
    domain: &'static str,
    schema_version: u32,
    policy_id: &'a str,
    policy_revision: u64,
    policy_owner: &'a str,
    binding: &'a NegativeMemoryPolicyBinding,
    disposition: NegativeMemoryDisposition,
    named_check_id: &'a str,
}

impl NegativeMemoryActionPolicy {
    /// Computes the policy content digest over every field except
    /// [`Self::policy_digest`].
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::DigestMismatch`] when the policy
    /// cannot be canonicalized.
    pub fn computed_digest(&self) -> Result<String, NegativeMemoryViolation> {
        let preimage = PolicyPreimage {
            domain: POLICY_DIGEST_DOMAIN,
            schema_version: self.schema_version,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            policy_owner: &self.policy_owner,
            binding: &self.binding,
            disposition: self.disposition,
            named_check_id: &self.named_check_id,
        };
        canonical_bytes(&preimage)
            .map(|bytes| digest_hex(&bytes))
            .map_err(|_| NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.policy_digest",
            })
    }

    /// Validates the policy shape, its self digest and its disposition payload.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for a malformed identity, a
    /// non-recomputing digest, or a `REQUIRE_CHECK` disposition that names no
    /// discriminating check.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        if self.schema_version != NEGATIVE_MEMORY_POLICY_SCHEMA_VERSION {
            return Err(NegativeMemoryViolation::UnsupportedSchemaVersion {
                field: "negative_memory.policy.schema_version",
                got: self.schema_version,
                admitted: NEGATIVE_MEMORY_POLICY_SCHEMA_VERSION,
            });
        }
        text("negative_memory.policy.policy_id", &self.policy_id)?;
        positive(
            "negative_memory.policy.policy_revision",
            self.policy_revision,
        )?;
        text("negative_memory.policy.policy_owner", &self.policy_owner)?;
        text(
            "negative_memory.policy.binding.record_id",
            &self.binding.record_id,
        )?;
        positive(
            "negative_memory.policy.binding.rule_revision",
            self.binding.rule_revision,
        )?;
        digest(
            "negative_memory.policy.binding.record_digest",
            &self.binding.record_digest,
        )?;
        text(
            "negative_memory.policy.named_check_id",
            &self.named_check_id,
        )?;
        if matches!(self.disposition, NegativeMemoryDisposition::RequireCheck)
            && self.named_check_id.is_empty()
        {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.policy.named_check_id",
            });
        }
        if self.computed_digest()? != self.policy_digest {
            return Err(NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.policy_digest",
            });
        }
        Ok(())
    }

    /// Checks that this policy is bound to exactly this record revision.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::PolicyBindingMismatch`] when the
    /// record identity, rule revision or content digest differs.
    pub fn validate_binding(
        &self,
        record: &NegativeMemoryFingerprint,
    ) -> Result<(), NegativeMemoryViolation> {
        let expected = NegativeMemoryPolicyBinding::new(
            record.record_id.clone(),
            record.rule_revision,
            record.record_digest.clone(),
        );
        if self.binding != expected {
            return Err(NegativeMemoryViolation::PolicyBindingMismatch {
                field: "negative_memory.policy.binding",
                bound_record_id: self.binding.record_id.clone(),
                got_record_id: record.record_id.clone(),
            });
        }
        Ok(())
    }
}

/// Typed refusal of wildcard applicability for a legacy record.
///
/// The type has exactly one value and exists so that the refusal of an
/// any-scope reading is machine-visible on the wire rather than only prose.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WildcardApplicability {
    /// A legacy untyped payload never grants wildcard applicability.
    Refused,
}

/// A legacy `FailureFingerprint`-shaped record as retained on the wire: one
/// fingerprint string, one summary string and one uninterpreted payload.
///
/// The payload is carried as retained canonical bytes plus their digest. This
/// owner never decodes it, never summarises it into a predicate and never
/// treats it as an any-scope rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacyFailureFingerprintRecord {
    /// The legacy fingerprint string.
    pub fingerprint: String,
    /// The legacy human summary.
    pub summary: String,
    /// Digest over the retained untyped payload bytes.
    pub payload_digest: String,
    /// The retained untyped payload bytes, exactly as stored.
    pub payload_bytes: Vec<u8>,
    /// Exact source reference the legacy record was read from.
    pub source_ref: String,
}

impl LegacyFailureFingerprintRecord {
    /// Validates the legacy record shape and its payload digest.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] for blank text, an oversize
    /// payload, or a payload digest that does not cover the retained bytes.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        text("negative_memory.legacy.fingerprint", &self.fingerprint)?;
        text("negative_memory.legacy.summary", &self.summary)?;
        text("negative_memory.legacy.source_ref", &self.source_ref)?;
        digest(
            "negative_memory.legacy.payload_digest",
            &self.payload_digest,
        )?;
        bounded(
            "negative_memory.legacy.payload_bytes",
            self.payload_bytes.len(),
            NEGATIVE_MEMORY_MAX_BYTES,
        )?;
        if digest_hex(&self.payload_bytes) != self.payload_digest {
            return Err(NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.legacy.payload_digest",
            });
        }
        Ok(())
    }
}

/// The advisory state a legacy record can only ever carry.
///
/// This type has no admitted and no wildcard variant, so
/// [`NegativeMemoryLegacyMigration`] is structurally incapable of holding an
/// exact predicate or an any-scope rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryLegacyAdvisory {
    /// The legacy trigger tokens retained verbatim. A legacy record names no
    /// owner-declared dimension set at all, so each token is retained as an
    /// unresolvable trigger and never expanded into typed parameters.
    pub unresolved_trigger_tokens: Vec<String>,
    /// Why the legacy trigger is unresolved.
    pub unresolved_reasons: Vec<NegativeMemoryUnresolvedReason>,
    /// The typed refusal of wildcard applicability.
    pub wildcard_applicability: WildcardApplicability,
}

/// The explicit migration of one legacy record onto the current vocabulary.
///
/// The result is advisory and unresolved by construction: unknown trigger
/// parameters and untyped payloads stay unresolved until an owner explicitly
/// admits them, and they are never defaulted to wildcard applicability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryLegacyMigration {
    /// Wire revision of this migration value.
    pub schema_version: u32,
    /// The legacy record exactly as retained.
    pub legacy: LegacyFailureFingerprintRecord,
    /// The only resolution a legacy record can carry.
    pub advisory: NegativeMemoryLegacyAdvisory,
    /// Digest over every other field of this migration. Content identity only.
    pub migration_digest: String,
}

#[derive(Serialize)]
struct MigrationPreimage<'a> {
    domain: &'static str,
    schema_version: u32,
    legacy: &'a LegacyFailureFingerprintRecord,
    advisory: &'a NegativeMemoryLegacyAdvisory,
}

impl NegativeMemoryLegacyMigration {
    /// Computes the migration content digest over every field except
    /// [`Self::migration_digest`].
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation::DigestMismatch`] when the migration
    /// cannot be canonicalized.
    pub fn computed_digest(&self) -> Result<String, NegativeMemoryViolation> {
        let preimage = MigrationPreimage {
            domain: MIGRATION_DIGEST_DOMAIN,
            schema_version: self.schema_version,
            legacy: &self.legacy,
            advisory: &self.advisory,
        };
        canonical_bytes(&preimage)
            .map(|bytes| digest_hex(&bytes))
            .map_err(|_| NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.migration_digest",
            })
    }

    /// Validates the legacy record, the advisory state and the self digest.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryViolation`] when the legacy record is
    /// malformed, when the advisory state names no unresolved trigger token or
    /// reason, when wildcard applicability was not refused, when the advisory
    /// state does not name the legacy untyped payload as its cause, or when the
    /// stored migration digest does not recompute.
    pub fn validate(&self) -> Result<(), NegativeMemoryViolation> {
        if self.schema_version != NEGATIVE_MEMORY_POLICY_SCHEMA_VERSION {
            return Err(NegativeMemoryViolation::UnsupportedSchemaVersion {
                field: "negative_memory.migration.schema_version",
                got: self.schema_version,
                admitted: NEGATIVE_MEMORY_POLICY_SCHEMA_VERSION,
            });
        }
        self.legacy.validate()?;
        if self.advisory.unresolved_trigger_tokens.is_empty()
            || self.advisory.unresolved_reasons.is_empty()
        {
            return Err(NegativeMemoryViolation::MissingRequiredField {
                field: "negative_memory.migration.advisory",
            });
        }
        unique(
            "negative_memory.migration.unresolved_trigger_tokens",
            &self.advisory.unresolved_trigger_tokens,
        )?;
        if !matches!(
            self.advisory.wildcard_applicability,
            WildcardApplicability::Refused
        ) {
            return Err(NegativeMemoryViolation::LegacyPayloadNotAdmissible {
                field: "negative_memory.migration.wildcard_applicability",
            });
        }
        if !self
            .advisory
            .unresolved_reasons
            .contains(&NegativeMemoryUnresolvedReason::LegacyUntypedPayload)
        {
            return Err(NegativeMemoryViolation::LegacyPayloadNotAdmissible {
                field: "negative_memory.migration.unresolved_reasons",
            });
        }
        if self.computed_digest()? != self.migration_digest {
            return Err(NegativeMemoryViolation::DigestMismatch {
                field: "negative_memory.migration_digest",
            });
        }
        Ok(())
    }
}

/// Migrates one legacy record onto the current vocabulary as advisory and
/// unresolved.
///
/// The returned type cannot carry an exact predicate, so a migrated legacy
/// record can never be used as an exact rule, and it can never be read as an
/// any-scope rule. Admitting the missing trigger parameters is an owner
/// decision that this function does not make.
pub fn migrate_legacy_fingerprint(
    legacy: &LegacyFailureFingerprintRecord,
) -> Result<NegativeMemoryLegacyMigration, NegativeMemoryViolation> {
    legacy.validate()?;
    let mut migration = NegativeMemoryLegacyMigration {
        schema_version: NEGATIVE_MEMORY_POLICY_SCHEMA_VERSION,
        legacy: legacy.clone(),
        advisory: NegativeMemoryLegacyAdvisory {
            unresolved_trigger_tokens: vec![legacy.fingerprint.clone()],
            unresolved_reasons: vec![NegativeMemoryUnresolvedReason::LegacyUntypedPayload],
            wildcard_applicability: WildcardApplicability::Refused,
        },
        migration_digest: String::new(),
    };
    migration.migration_digest = migration.computed_digest()?;
    migration.validate()?;
    Ok(migration)
}

/// The exact canonical spelling of an effect class, so a recorded effect class
/// is compared by the same spelling on both sides.
///
/// These four spellings are deliberately upper case while this crate's own
/// enums are `snake_case`: they are not this crate's vocabulary. They are the
/// wire spelling of the owning `eliot_receipts::EffectClass`, which carries
/// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`. Mirroring the owner is what
/// makes a recorded value comparable with one written by that owner, so these
/// four must not be folded to this crate's casing.
#[must_use]
pub const fn effect_class_text(class: EffectClass) -> &'static str {
    match class {
        EffectClass::Read => "READ",
        EffectClass::Candidate => "CANDIDATE",
        EffectClass::ReversibleMutation => "REVERSIBLE_MUTATION",
        EffectClass::ExternalEffect => "EXTERNAL_EFFECT",
    }
}
