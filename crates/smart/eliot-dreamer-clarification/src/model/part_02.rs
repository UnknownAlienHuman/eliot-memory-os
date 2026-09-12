fn validate_options(
    options: &[AnswerOption],
    policy: &ClarificationPolicy,
) -> Result<(), ClarificationError> {
    if options.len() < 2 {
        return Err(ClarificationError::UnsupportedAnswerSchema {
            reason: "finite schemas require at least two values".to_owned(),
        });
    }
    let limit = usize::from(policy.max_options);
    if options.len() > limit {
        return Err(ClarificationError::limit("answer_schema.options", limit));
    }
    let mut keys = BTreeSet::new();
    for option in options {
        option.validate(policy.max_text_bytes)?;
        if !keys.insert(&option.key) {
            return Err(ClarificationError::DuplicateIdentity {
                field: "answer_schema.options.key",
            });
        }
    }
    Ok(())
}

/// Matcher for one valid-answer branch. It never validates a runtime answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "match", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnswerMatcher {
    Exact { key: String },
    ScalarRange { min_milli: i64, max_milli: i64 },
    AnyValid,
}

/// One inert downstream disposition selected by a valid answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBranch {
    pub branch_id: String,
    pub matcher: AnswerMatcher,
    pub outcome_id: String,
    pub summary: String,
    pub referenced_variables: Vec<String>,
}

impl AnswerBranch {
    fn validate(&self, max_text: usize) -> Result<(), ClarificationError> {
        validate_text(&self.branch_id, "answer_branch.branch_id", 128)?;
        validate_text(&self.outcome_id, "answer_branch.outcome_id", 128)?;
        validate_text(&self.summary, "answer_branch.summary", max_text)?;
        ensure_unique_text(
            &self.referenced_variables,
            "answer_branch.referenced_variables",
            128,
            4,
        )?;
        match &self.matcher {
            AnswerMatcher::Exact { key } => validate_text(key, "answer_branch.matcher.key", 128),
            AnswerMatcher::ScalarRange {
                min_milli,
                max_milli,
            } => {
                if min_milli > max_milli {
                    return Err(ClarificationError::IncompleteBranchMap {
                        reason: "scalar branch range is inverted".to_owned(),
                    });
                }
                Ok(())
            }
            AnswerMatcher::AnyValid => Ok(()),
        }
    }
}

/// Explicit non-answer dispositions. These are never trial-decoded as values.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonAnswerBranches {
    pub unknown: String,
    pub refusal: String,
    pub unanswered: String,
    pub expired: String,
    pub invalid_value: String,
}

impl NonAnswerBranches {
    fn validate(&self) -> Result<(), ClarificationError> {
        let values = [
            self.unknown.as_str(),
            self.refusal.as_str(),
            self.unanswered.as_str(),
            self.expired.as_str(),
            self.invalid_value.as_str(),
        ];
        let mut seen = BTreeSet::new();
        for value in values {
            validate_text(value, "non_answer_branches", 128)?;
            if !seen.insert(value) {
                return Err(ClarificationError::DuplicateIdentity {
                    field: "non_answer_branches",
                });
            }
        }
        Ok(())
    }
}

/// Safe action if no valid answer arrives. It carries no assumed answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "fallback", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnansweredFallback {
    PartialResult {
        result_code: String,
        referenced_variables: Vec<String>,
    },
    Abstain {
        reason_code: String,
        referenced_variables: Vec<String>,
    },
    PreserveCurrent {
        state_ref: String,
        referenced_variables: Vec<String>,
    },
    Defer {
        reopen_condition: String,
        referenced_variables: Vec<String>,
    },
    BlockedWithoutAnswer {
        reason_code: String,
        referenced_variables: Vec<String>,
    },
}

impl UnansweredFallback {
    pub(crate) fn referenced_variables(&self) -> &[String] {
        match self {
            Self::PartialResult {
                referenced_variables,
                ..
            }
            | Self::Abstain {
                referenced_variables,
                ..
            }
            | Self::PreserveCurrent {
                referenced_variables,
                ..
            }
            | Self::Defer {
                referenced_variables,
                ..
            }
            | Self::BlockedWithoutAnswer {
                referenced_variables,
                ..
            } => referenced_variables,
        }
    }

    fn code(&self) -> &str {
        match self {
            Self::PartialResult { result_code, .. } => result_code,
            Self::Abstain { reason_code, .. } | Self::BlockedWithoutAnswer { reason_code, .. } => {
                reason_code
            }
            Self::PreserveCurrent { state_ref, .. } => state_ref,
            Self::Defer {
                reopen_condition, ..
            } => reopen_condition,
        }
    }

    fn validate(&self, max_text: usize) -> Result<(), ClarificationError> {
        validate_text(self.code(), "unanswered_fallback.code", max_text)?;
        ensure_unique_text(
            self.referenced_variables(),
            "unanswered_fallback.referenced_variables",
            128,
            4,
        )
    }
}

/// Evidence that the missing value is material rather than merely interesting.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialityBasis {
    BranchDivergence,
    HardBoundary { contract_ref: String },
    NoSafeContinuation { blocking_code: String },
}

/// Structured materiality proof for one ambiguity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialityEvidence {
    pub basis: MaterialityBasis,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub referenced_variables: Vec<String>,
}

impl MaterialityEvidence {
    fn validate(&self, max_text: usize) -> Result<(), ClarificationError> {
        validate_text(&self.summary, "materiality.summary", max_text)?;
        ensure_unique_text(
            &self.evidence_refs,
            "materiality.evidence_refs",
            256,
            128,
        )?;
        if self.evidence_refs.is_empty() {
            return Err(ClarificationError::invalid(
                "materiality.evidence_refs",
                "at least one admitted evidence handle is required",
            ));
        }
        ensure_unique_text(
            &self.referenced_variables,
            "materiality.referenced_variables",
            128,
            4,
        )?;
        match &self.basis {
            MaterialityBasis::BranchDivergence => Ok(()),
            MaterialityBasis::HardBoundary { contract_ref } => {
                validate_text(contract_ref, "materiality.contract_ref", 512)
            }
            MaterialityBasis::NoSafeContinuation { blocking_code } => {
                validate_text(blocking_code, "materiality.blocking_code", 128)
            }
        }
    }
}

/// One logical value that a candidate may ask for.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionVariable {
    pub variable_id: String,
    pub label: String,
    /// Structural components proving semantic atomicity. Exactly one is required.
    pub component_ids: Vec<String>,
    pub content_class: ClarificationContentClass,
    pub owner: DecisionOwner,
    /// Required active-agent capability for a task-local decision.
    pub required_capability: Option<String>,
    pub answer_schema: AnswerSchema,
    pub branches: Vec<AnswerBranch>,
    pub non_answer_branches: NonAnswerBranches,
}

impl DecisionVariable {
    pub(crate) fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.answer_schema = normalized.answer_schema.normalized();
        normalized.branches.sort_by(|left, right| {
            matcher_sort_key(&left.matcher)
                .cmp(&matcher_sort_key(&right.matcher))
                .then_with(|| left.branch_id.cmp(&right.branch_id))
        });
        normalized
    }

    pub(crate) fn validate(
        &self,
        policy: &ClarificationPolicy,
    ) -> Result<(), ClarificationError> {
        validate_text(&self.variable_id, "decision_variable.variable_id", 128)?;
        validate_text(&self.label, "decision_variable.label", policy.max_text_bytes)?;
        if self.label.contains('?') {
            return Err(ClarificationError::invalid(
                "decision_variable.label",
                "question punctuation is owned by the renderer",
            ));
        }
        ensure_unique_text(
            &self.component_ids,
            "decision_variable.component_ids",
            128,
            8,
        )?;
        if let Some(capability) = &self.required_capability {
            validate_text(capability, "decision_variable.required_capability", 256)?;
        }
        match self.owner {
            DecisionOwner::TaskLocalAgent if self.required_capability.is_none() => {
                return Err(ClarificationError::invalid(
                    "decision_variable.required_capability",
                    "task-local ownership requires an exact current capability",
                ));
            }
            DecisionOwner::Human(_) | DecisionOwner::Unknown
                if self.required_capability.is_some() =>
            {
                return Err(ClarificationError::invalid(
                    "decision_variable.required_capability",
                    "non-agent ownership cannot carry an agent capability",
                ));
            }
            DecisionOwner::TaskLocalAgent
            | DecisionOwner::Human(_)
            | DecisionOwner::Unknown => {}
        }
        self.answer_schema.validate(policy)?;
        if self.branches.is_empty() {
            return Err(ClarificationError::IncompleteBranchMap {
                reason: "no valid-answer branches were supplied".to_owned(),
            });
        }
        if self.branches.len() > HARD_MAX_OPTIONS {
            return Err(ClarificationError::limit(
                "decision_variable.branches",
                HARD_MAX_OPTIONS,
            ));
        }
        let mut matcher_keys = BTreeSet::new();
        for branch in &self.branches {
            branch.validate(policy.max_text_bytes)?;
            let key = matcher_sort_key(&branch.matcher);
            if !matcher_keys.insert(key) {
                return Err(ClarificationError::DuplicateIdentity {
                    field: "decision_variable.branches.matcher",
                });
            }
        }
        self.non_answer_branches.validate()?;
        validate_branch_coverage(&self.answer_schema, &self.branches)
    }

    pub(crate) fn all_referenced_variables(
        &self,
        fallback: &UnansweredFallback,
    ) -> BTreeSet<String> {
        let mut values = BTreeSet::new();
        for component in &self.component_ids {
            values.insert(component.clone());
        }
        match &self.answer_schema {
            AnswerSchema::Choice { options } | AnswerSchema::Reference { allowed: options, .. } => {
                for option in options {
                    values.extend(option.referenced_variables.iter().cloned());
                }
            }
            AnswerSchema::Boolean
            | AnswerSchema::Ternary
            | AnswerSchema::Scalar { .. }
            | AnswerSchema::Date
            | AnswerSchema::DateTime
            | AnswerSchema::Interval
            | AnswerSchema::Version
            | AnswerSchema::BoundedText { .. } => {}
        }
        for branch in &self.branches {
            values.extend(branch.referenced_variables.iter().cloned());
        }
        values.extend(fallback.referenced_variables().iter().cloned());
        values
    }
}
