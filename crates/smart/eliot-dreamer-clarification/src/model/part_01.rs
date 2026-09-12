use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{DreamJobInput, JobClass, ValidatedDreamDraft};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ClarificationError;

/// Current wire version of the clarification candidate surface.
pub const CLARIFICATION_SCHEMA_VERSION: u32 = 1;
/// Maximum number of ambiguity records accepted by the implementation.
pub const HARD_MAX_AMBIGUITIES: usize = 128;
/// Maximum number of options or reference values in one answer schema.
pub const HARD_MAX_OPTIONS: usize = 64;
/// Maximum UTF-8 bytes in one public text field.
pub const HARD_MAX_TEXT_BYTES: usize = 16_384;
/// Maximum serialized decision bytes.
pub const HARD_MAX_OUTPUT_BYTES: usize = 1_048_576;
/// Standalone package proof ceiling; no delivery, effect, admission, or Finish.
pub const CLARIFICATION_PROOF_CEILING: &str = "clarification_candidate_module_only";

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    limit: usize,
) -> Result<(), ClarificationError> {
    if value.trim().is_empty() {
        return Err(ClarificationError::invalid(field, "must be non-blank"));
    }
    if value != value.trim() {
        return Err(ClarificationError::invalid(
            field,
            "must not contain boundary whitespace",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(ClarificationError::invalid(
            field,
            "must not contain control characters",
        ));
    }
    if value.len() > limit {
        return Err(ClarificationError::limit(field, limit));
    }
    Ok(())
}

pub(crate) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), ClarificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClarificationError::invalid(
            field,
            "must be lowercase SHA-256 hexadecimal",
        ));
    }
    Ok(())
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ClarificationError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ClarificationError::Canonicalization)
}

fn ensure_unique_text(
    values: &[String],
    field: &'static str,
    item_limit: usize,
    count_limit: usize,
) -> Result<(), ClarificationError> {
    if values.len() > count_limit {
        return Err(ClarificationError::limit(field, count_limit));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field, item_limit)?;
        if !seen.insert(value) {
            return Err(ClarificationError::DuplicateIdentity { field });
        }
    }
    Ok(())
}

/// Closed content role of the proposed question material.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ClarificationContentClass {
    /// Ordinary bounded data that may appear in a neutral question.
    OrdinaryData,
    /// Credential or secret material; never rendered by this cell.
    Secret,
    /// Protected evidence that must remain behind its owning handle.
    ProtectedEvidence,
    /// Tool, command, or executable instruction text; never promoted to control.
    ExecutableInstruction,
}

/// Closed Human-owned decision categories used only for routing recommendation.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HumanDecisionKind {
    GoalOrValue,
    Approval,
    Consent,
    Privacy,
    Security,
    IrreversibleEffect,
    CostEnvelope,
    RemoteAccess,
    HighImpactAmbiguity,
    TaskLocalFallback,
}

/// Semantic owner of one clarification decision variable.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "owner", content = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DecisionOwner {
    /// The current admitted agent may answer inside the current task scope.
    TaskLocalAgent,
    /// The value is owned by the authenticated Human boundary.
    Human(HumanDecisionKind),
    /// No current owner is known; no candidate can be routed.
    Unknown,
}

/// Closed reference families admitted by a reference answer schema.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Entity,
    Owner,
    Resource,
}

/// One neutral finite answer option.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerOption {
    pub key: String,
    pub label: String,
    /// Variables semantically referenced by this option. Exactly one is allowed.
    pub referenced_variables: Vec<String>,
}

impl AnswerOption {
    fn validate(&self, max_text: usize) -> Result<(), ClarificationError> {
        validate_text(&self.key, "answer_option.key", 128)?;
        validate_text(&self.label, "answer_option.label", max_text)?;
        let folded = self.label.to_ascii_lowercase();
        if ["default", "recommended", "preferred"]
            .iter()
            .any(|needle| folded.contains(needle))
        {
            return Err(ClarificationError::invalid(
                "answer_option.label",
                "preferred or default framing is forbidden",
            ));
        }
        ensure_unique_text(
            &self.referenced_variables,
            "answer_option.referenced_variables",
            128,
            4,
        )
    }
}

/// Closed answer families. This surface validates a schema, never an answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnswerSchema {
    Choice { options: Vec<AnswerOption> },
    Boolean,
    Ternary,
    Scalar {
        unit: String,
        min_milli: i64,
        max_milli: i64,
        precision: u8,
    },
    Date,
    DateTime,
    Interval,
    Version,
    Reference {
        reference_kind: ReferenceKind,
        allowed: Vec<AnswerOption>,
    },
    BoundedText {
        max_bytes: u32,
        interpretation_owner: String,
    },
}

impl AnswerSchema {
    pub(crate) fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        match &mut normalized {
            Self::Choice { options } | Self::Reference { allowed: options, .. } => {
                options.sort_by(|left, right| left.key.cmp(&right.key));
            }
            Self::Boolean
            | Self::Ternary
            | Self::Scalar { .. }
            | Self::Date
            | Self::DateTime
            | Self::Interval
            | Self::Version
            | Self::BoundedText { .. } => {}
        }
        normalized
    }

    pub(crate) fn validate(
        &self,
        policy: &ClarificationPolicy,
    ) -> Result<(), ClarificationError> {
        match self {
            Self::Choice { options } => validate_options(options, policy),
            Self::Reference { allowed, .. } => validate_options(allowed, policy),
            Self::Boolean | Self::Ternary | Self::Date | Self::DateTime | Self::Interval
            | Self::Version => Ok(()),
            Self::Scalar {
                unit,
                min_milli,
                max_milli,
                precision,
            } => {
                validate_text(unit, "answer_schema.unit", 64)?;
                if !matches!(
                    unit.as_str(),
                    "ms" | "s" | "bytes" | "count" | "percent" | "usd" | "unitless"
                ) {
                    return Err(ClarificationError::UnsupportedAnswerSchema {
                        reason: "scalar unit is not in the closed unit registry".to_owned(),
                    });
                }
                if min_milli > max_milli {
                    return Err(ClarificationError::UnsupportedAnswerSchema {
                        reason: "scalar minimum exceeds maximum".to_owned(),
                    });
                }
                if *precision > 9 {
                    return Err(ClarificationError::UnsupportedAnswerSchema {
                        reason: "scalar precision exceeds nine decimal places".to_owned(),
                    });
                }
                Ok(())
            }
            Self::BoundedText {
                max_bytes: _,
                interpretation_owner,
            } => {
                if !policy.allow_bounded_text {
                    return Err(ClarificationError::UnsupportedAnswerSchema {
                        reason: "bounded text is disabled by policy".to_owned(),
                    });
                }
                validate_text(
                    interpretation_owner,
                    "answer_schema.interpretation_owner",
                    256,
                )
            }
        }
    }

    pub(crate) fn exact_keys(&self) -> Option<Vec<String>> {
        match self {
            Self::Choice { options } => {
                Some(options.iter().map(|option| option.key.clone()).collect())
            }
            Self::Boolean => Some(vec!["false".to_owned(), "true".to_owned()]),
            Self::Ternary => Some(vec!["no".to_owned(), "unknown".to_owned(), "yes".to_owned()]),
            Self::Reference { allowed, .. } => {
                Some(allowed.iter().map(|option| option.key.clone()).collect())
            }
            Self::Scalar { .. }
            | Self::Date
            | Self::DateTime
            | Self::Interval
            | Self::Version
            | Self::BoundedText { .. } => None,
        }
    }

    pub(crate) const fn admits_any_valid_matcher(&self) -> bool {
        matches!(
            self,
            Self::Date
                | Self::DateTime
                | Self::Interval
                | Self::Version
                | Self::BoundedText { .. }
        )
    }
}
