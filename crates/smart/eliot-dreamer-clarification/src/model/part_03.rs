fn matcher_sort_key(matcher: &AnswerMatcher) -> String {
    match matcher {
        AnswerMatcher::Exact { key } => format!("0:{key}"),
        AnswerMatcher::ScalarRange {
            min_milli,
            max_milli,
        } => format!("1:{min_milli:020}:{max_milli:020}"),
        AnswerMatcher::AnyValid => "2:any".to_owned(),
    }
}

fn validate_branch_coverage(
    schema: &AnswerSchema,
    branches: &[AnswerBranch],
) -> Result<(), ClarificationError> {
    if let Some(mut expected) = schema.exact_keys() {
        expected.sort();
        let mut actual = Vec::with_capacity(branches.len());
        for branch in branches {
            let AnswerMatcher::Exact { key } = &branch.matcher else {
                return Err(ClarificationError::IncompleteBranchMap {
                    reason: "finite answer schema requires exact matchers".to_owned(),
                });
            };
            actual.push(key.clone());
        }
        actual.sort();
        if actual != expected {
            return Err(ClarificationError::IncompleteBranchMap {
                reason: "finite valid-answer denominator is not covered exactly once".to_owned(),
            });
        }
        return Ok(());
    }
    if let AnswerSchema::Scalar {
        min_milli,
        max_milli,
        ..
    } = schema
    {
        let mut ranges = Vec::with_capacity(branches.len());
        for branch in branches {
            let AnswerMatcher::ScalarRange {
                min_milli: branch_min,
                max_milli: branch_max,
            } = &branch.matcher
            else {
                return Err(ClarificationError::IncompleteBranchMap {
                    reason: "scalar answer schema requires scalar ranges".to_owned(),
                });
            };
            ranges.push((*branch_min, *branch_max));
        }
        ranges.sort_unstable();
        let mut cursor = *min_milli;
        for (start, end) in ranges {
            if start != cursor || end > *max_milli {
                return Err(ClarificationError::IncompleteBranchMap {
                    reason: "scalar ranges have a gap, overlap, or exceed the schema".to_owned(),
                });
            }
            if end == i64::MAX {
                cursor = end;
            } else {
                cursor = end + 1;
            }
        }
        if cursor != *max_milli && cursor != (*max_milli).saturating_add(1) {
            return Err(ClarificationError::IncompleteBranchMap {
                reason: "scalar ranges do not cover the upper bound".to_owned(),
            });
        }
        return Ok(());
    }
    if schema.admits_any_valid_matcher()
        && branches.len() == 1
        && matches!(&branches[0].matcher, AnswerMatcher::AnyValid)
    {
        return Ok(());
    }
    Err(ClarificationError::IncompleteBranchMap {
        reason: "open bounded schema requires exactly one any-valid branch".to_owned(),
    })
}

/// Current state of one structured ambiguity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AmbiguityState {
    Unresolved,
    NonMaterial { reason_code: String },
    ResolvedByEvidence {
        resolution_ref: String,
        evidence_refs: Vec<String>,
    },
    SafeDefaultAvailable {
        authority_ref: String,
        evidence_refs: Vec<String>,
        outcome_id: String,
    },
    Stale { invalidation_ref: String },
    OutOfScope { reason_code: String },
}

impl AmbiguityState {
    fn validate(&self) -> Result<(), ClarificationError> {
        match self {
            Self::Unresolved => Ok(()),
            Self::NonMaterial { reason_code } | Self::OutOfScope { reason_code } => {
                validate_text(reason_code, "ambiguity_state.reason_code", 256)
            }
            Self::ResolvedByEvidence {
                resolution_ref,
                evidence_refs,
            } => {
                validate_text(resolution_ref, "ambiguity_state.resolution_ref", 256)?;
                ensure_unique_text(
                    evidence_refs,
                    "ambiguity_state.evidence_refs",
                    256,
                    128,
                )?;
                if evidence_refs.is_empty() {
                    return Err(ClarificationError::invalid(
                        "ambiguity_state.evidence_refs",
                        "resolved evidence cannot be empty",
                    ));
                }
                Ok(())
            }
            Self::SafeDefaultAvailable {
                authority_ref,
                evidence_refs,
                outcome_id,
            } => {
                validate_text(authority_ref, "ambiguity_state.authority_ref", 512)?;
                validate_text(outcome_id, "ambiguity_state.outcome_id", 128)?;
                ensure_unique_text(
                    evidence_refs,
                    "ambiguity_state.evidence_refs",
                    256,
                    128,
                )?;
                if evidence_refs.is_empty() {
                    return Err(ClarificationError::invalid(
                        "ambiguity_state.evidence_refs",
                        "safe default requires admitted evidence",
                    ));
                }
                Ok(())
            }
            Self::Stale { invalidation_ref } => {
                validate_text(invalidation_ref, "ambiguity_state.invalidation_ref", 256)
            }
        }
    }
}

/// One structured ambiguity supplied by the admitted clarification job.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationAmbiguity {
    pub ambiguity_id: String,
    pub objective_id: String,
    pub state: AmbiguityState,
    pub variables: Vec<DecisionVariable>,
    pub materiality: Option<MaterialityEvidence>,
    pub fallback: Option<UnansweredFallback>,
    pub source_refs: Vec<String>,
}

impl ClarificationAmbiguity {
    pub(crate) fn validate(
        &self,
        policy: &ClarificationPolicy,
        denominator: &SourceDenominator,
    ) -> Result<(), ClarificationError> {
        validate_text(&self.ambiguity_id, "ambiguity.ambiguity_id", 128)?;
        validate_text(&self.objective_id, "ambiguity.objective_id", 128)?;
        self.state.validate()?;
        ensure_unique_text(
            &self.source_refs,
            "ambiguity.source_refs",
            256,
            128,
        )?;
        for source in &self.source_refs {
            if !denominator.material_handles.contains(source) {
                return Err(ClarificationError::binding("ambiguity.source_refs"));
            }
        }
        if self.variables.len() > 8 {
            return Err(ClarificationError::limit("ambiguity.variables", 8));
        }
        let mut variable_ids = BTreeSet::new();
        for variable in &self.variables {
            variable.validate(policy)?;
            if !variable_ids.insert(&variable.variable_id) {
                return Err(ClarificationError::DuplicateIdentity {
                    field: "ambiguity.variables.variable_id",
                });
            }
        }
        match &self.state {
            AmbiguityState::Unresolved => {
                if self.variables.is_empty() {
                    return Err(ClarificationError::invalid(
                        "ambiguity.variables",
                        "unresolved ambiguity requires a decision variable",
                    ));
                }
                let materiality = self.materiality.as_ref().ok_or_else(|| {
                    ClarificationError::invalid(
                        "ambiguity.materiality",
                        "unresolved ambiguity requires materiality evidence",
                    )
                })?;
                materiality.validate(policy.max_text_bytes)?;
                if let Some(fallback) = &self.fallback {
                    fallback.validate(policy.max_text_bytes)?;
                } else if !matches!(
                    materiality.basis,
                    MaterialityBasis::NoSafeContinuation { .. }
                ) {
                    return Err(ClarificationError::invalid(
                        "ambiguity.fallback",
                        concat!(
                            "missing fallback is allowed only for a proved ",
                            "blocked-without-answer state",
                        ),
                    ));
                }
                for reference in &materiality.evidence_refs {
                    if !denominator.material_handles.contains(reference) {
                        return Err(ClarificationError::binding("materiality.evidence_refs"));
                    }
                }
                Ok(())
            }
            AmbiguityState::ResolvedByEvidence { evidence_refs, .. }
            | AmbiguityState::SafeDefaultAvailable { evidence_refs, .. } => {
                for reference in evidence_refs {
                    if !denominator.material_handles.contains(reference) {
                        return Err(ClarificationError::binding("ambiguity_state.evidence_refs"));
                    }
                }
                Ok(())
            }
            AmbiguityState::NonMaterial { .. }
            | AmbiguityState::Stale { .. }
            | AmbiguityState::OutOfScope { .. } => Ok(()),
        }
    }
}

/// Explicit frozen source denominator behind the admitted ambiguity set.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDenominator {
    pub snapshot_id: String,
    pub snapshot_digest: String,
    pub material_handles: Vec<String>,
    pub omission_handles: Vec<String>,
    pub complete: bool,
    pub denominator_digest: String,
}

impl SourceDenominator {
    pub fn identity_digest(&self) -> Result<String, ClarificationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            snapshot_id: &'a str,
            snapshot_digest: &'a str,
            material_handles: Vec<&'a str>,
            omission_handles: Vec<&'a str>,
            complete: bool,
        }
        let mut material_handles: Vec<_> = self
            .material_handles
            .iter()
            .map(String::as_str)
            .collect();
        material_handles.sort_unstable();
        let mut omission_handles: Vec<_> = self
            .omission_handles
            .iter()
            .map(String::as_str)
            .collect();
        omission_handles.sort_unstable();
        canonical_digest(&Preimage {
            snapshot_id: &self.snapshot_id,
            snapshot_digest: &self.snapshot_digest,
            material_handles,
            omission_handles,
            complete: self.complete,
        })
    }

    pub fn validate(&self) -> Result<(), ClarificationError> {
        validate_text(&self.snapshot_id, "source_denominator.snapshot_id", 256)?;
        validate_digest(&self.snapshot_digest, "source_denominator.snapshot_digest")?;
        validate_digest(
            &self.denominator_digest,
            "source_denominator.denominator_digest",
        )?;
        ensure_unique_text(
            &self.material_handles,
            "source_denominator.material_handles",
            256,
            1024,
        )?;
        ensure_unique_text(
            &self.omission_handles,
            "source_denominator.omission_handles",
            256,
            1024,
        )?;
        if self.material_handles.is_empty() {
            return Err(ClarificationError::invalid(
                "source_denominator.material_handles",
                "at least one material handle is required",
            ));
        }
        let material: BTreeSet<_> = self
            .material_handles
            .iter()
            .map(String::as_str)
            .collect();
        if self
            .omission_handles
            .iter()
            .any(|item| material.contains(item.as_str()))
        {
            return Err(ClarificationError::DuplicateIdentity {
                field: "source_denominator.material_or_omission",
            });
        }
        if self.identity_digest()? != self.denominator_digest {
            return Err(ClarificationError::binding(
                "source_denominator.denominator_digest",
            ));
        }
        Ok(())
    }
}
