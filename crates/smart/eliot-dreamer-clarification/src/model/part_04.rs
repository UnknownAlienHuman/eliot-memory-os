/// Immutable limits and injected observation state for one clarification decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub max_ambiguities: u16,
    pub max_options: u16,
    pub max_text_bytes: usize,
    pub max_output_bytes: usize,
    pub max_work_units: u64,
    pub candidate_ttl_ms: u64,
    pub observation_time_ms: u64,
    pub allow_bounded_text: bool,
    pub cancellation_requested: bool,
    pub policy_digest: String,
}

impl ClarificationPolicy {
    pub fn seal(&mut self) -> Result<(), ClarificationError> {
        self.validate_unsealed()?;
        self.policy_digest = self.identity_digest()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ClarificationError> {
        self.validate_unsealed()?;
        validate_digest(&self.policy_digest, "policy.policy_digest")?;
        if self.policy_digest != self.identity_digest()? {
            return Err(ClarificationError::binding("policy.policy_digest"));
        }
        Ok(())
    }

    pub fn identity_digest(&self) -> Result<String, ClarificationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            policy_id: &'a str,
            max_ambiguities: u16,
            max_options: u16,
            max_text_bytes: usize,
            max_output_bytes: usize,
            max_work_units: u64,
            candidate_ttl_ms: u64,
            observation_time_ms: u64,
            allow_bounded_text: bool,
            cancellation_requested: bool,
        }
        canonical_digest(&Preimage {
            schema_version: self.schema_version,
            policy_id: &self.policy_id,
            max_ambiguities: self.max_ambiguities,
            max_options: self.max_options,
            max_text_bytes: self.max_text_bytes,
            max_output_bytes: self.max_output_bytes,
            max_work_units: self.max_work_units,
            candidate_ttl_ms: self.candidate_ttl_ms,
            observation_time_ms: self.observation_time_ms,
            allow_bounded_text: self.allow_bounded_text,
            cancellation_requested: self.cancellation_requested,
        })
    }

    fn validate_unsealed(&self) -> Result<(), ClarificationError> {
        if self.schema_version != CLARIFICATION_SCHEMA_VERSION {
            return Err(ClarificationError::invalid(
                "policy.schema_version",
                "unsupported clarification policy schema",
            ));
        }
        validate_text(&self.policy_id, "policy.policy_id", 256)?;
        let max_ambiguities = usize::from(self.max_ambiguities);
        if max_ambiguities == 0 || max_ambiguities > HARD_MAX_AMBIGUITIES {
            return Err(ClarificationError::limit(
                "policy.max_ambiguities",
                HARD_MAX_AMBIGUITIES,
            ));
        }
        let max_options = usize::from(self.max_options);
        if max_options < 2 || max_options > HARD_MAX_OPTIONS {
            return Err(ClarificationError::limit(
                "policy.max_options",
                HARD_MAX_OPTIONS,
            ));
        }
        if self.max_text_bytes == 0 || self.max_text_bytes > HARD_MAX_TEXT_BYTES {
            return Err(ClarificationError::limit(
                "policy.max_text_bytes",
                HARD_MAX_TEXT_BYTES,
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > HARD_MAX_OUTPUT_BYTES {
            return Err(ClarificationError::limit(
                "policy.max_output_bytes",
                HARD_MAX_OUTPUT_BYTES,
            ));
        }
        if self.max_work_units == 0 || self.candidate_ttl_ms == 0 {
            return Err(ClarificationError::invalid(
                "policy.work_or_ttl",
                "work and candidate lifetime limits must be positive",
            ));
        }
        Ok(())
    }
}

impl Default for ClarificationPolicy {
    fn default() -> Self {
        let mut policy = Self {
            schema_version: CLARIFICATION_SCHEMA_VERSION,
            policy_id: "eliot.clarification.policy.v1".to_owned(),
            max_ambiguities: 32,
            max_options: 16,
            max_text_bytes: 4096,
            max_output_bytes: 262_144,
            max_work_units: 4096,
            candidate_ttl_ms: 300_000,
            observation_time_ms: 0,
            allow_bounded_text: false,
            cancellation_requested: false,
            policy_digest: String::new(),
        };
        if let Ok(digest) = policy.identity_digest() {
            policy.policy_digest = digest;
        }
        policy
    }
}

/// Frozen admitted Clarification job plus its complete ambiguity denominator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedClarificationJob {
    pub schema_version: u32,
    pub job: DreamJobInput,
    pub ambiguities: Vec<ClarificationAmbiguity>,
    pub source_denominator: SourceDenominator,
    pub admission_digest: String,
}

impl AdmittedClarificationJob {
    pub fn seal(&mut self, policy: &ClarificationPolicy) -> Result<(), ClarificationError> {
        self.validate_unsealed(policy)?;
        self.admission_digest = self.identity_digest()?;
        Ok(())
    }

    pub fn validate(&self, policy: &ClarificationPolicy) -> Result<(), ClarificationError> {
        self.validate_unsealed(policy)?;
        validate_digest(&self.admission_digest, "job.admission_digest")?;
        if self.admission_digest != self.identity_digest()? {
            return Err(ClarificationError::IdentityConflict);
        }
        Ok(())
    }

    pub fn validate_draft(
        &self,
        draft: &ValidatedDreamDraft,
    ) -> Result<(), ClarificationError> {
        draft
            .validate()
            .map_err(|_| ClarificationError::invalid("validated_draft", "invalid A-03 receipt"))?;
        let receipt = &draft.receipt;
        if receipt.job_id != self.job.canonical_id()
            || receipt.task_id != self.job.task_id
            || receipt.scope_id != self.job.scope_id
            || receipt.state_fence != self.job.state_fence
            || draft.task_id != self.job.task_id
            || draft.scope_id != self.job.scope_id
            || draft.state_fence != self.job.state_fence
        {
            return Err(ClarificationError::binding("validated_draft"));
        }
        Ok(())
    }

    pub fn identity_digest(&self) -> Result<String, ClarificationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            job: &'a DreamJobInput,
            ambiguities: Vec<ClarificationAmbiguity>,
            source_denominator: &'a SourceDenominator,
        }
        let mut ambiguities: Vec<_> = self
            .ambiguities
            .iter()
            .map(normalize_ambiguity)
            .collect();
        ambiguities.sort_by(|left, right| left.ambiguity_id.cmp(&right.ambiguity_id));
        canonical_digest(&Preimage {
            schema_version: self.schema_version,
            job: &self.job,
            ambiguities,
            source_denominator: &self.source_denominator,
        })
    }

    fn validate_unsealed(
        &self,
        policy: &ClarificationPolicy,
    ) -> Result<(), ClarificationError> {
        policy.validate()?;
        if self.schema_version != CLARIFICATION_SCHEMA_VERSION {
            return Err(ClarificationError::invalid(
                "job.schema_version",
                "unsupported clarification job schema",
            ));
        }
        self.job
            .validate()
            .map_err(|_| ClarificationError::invalid("job.job", "invalid DreamJobInput"))?;
        if self.job.job_class != JobClass::Clarification {
            return Err(ClarificationError::binding("job.job_class"));
        }
        self.source_denominator.validate()?;
        let max_ambiguities = usize::from(policy.max_ambiguities);
        if self.ambiguities.len() > max_ambiguities {
            return Err(ClarificationError::limit(
                "job.ambiguities",
                max_ambiguities,
            ));
        }
        let mut ambiguity_ids = BTreeSet::new();
        for ambiguity in &self.ambiguities {
            ambiguity.validate(policy, &self.source_denominator)?;
            if !ambiguity_ids.insert(&ambiguity.ambiguity_id) {
                return Err(ClarificationError::DuplicateIdentity {
                    field: "job.ambiguities.ambiguity_id",
                });
            }
        }
        Ok(())
    }
}

fn normalize_ambiguity(value: &ClarificationAmbiguity) -> ClarificationAmbiguity {
    let mut normalized = value.clone();
    normalized
        .variables
        .iter_mut()
        .for_each(|variable| *variable = variable.normalized());
    normalized
        .variables
        .sort_by(|left, right| left.variable_id.cmp(&right.variable_id));
    normalized.source_refs.sort();
    if let Some(materiality) = &mut normalized.materiality {
        materiality.evidence_refs.sort();
        materiality.referenced_variables.sort();
    }
    if let Some(fallback) = &mut normalized.fallback {
        match fallback {
            UnansweredFallback::PartialResult {
                referenced_variables,
                ..
            }
            | UnansweredFallback::Abstain {
                referenced_variables,
                ..
            }
            | UnansweredFallback::PreserveCurrent {
                referenced_variables,
                ..
            }
            | UnansweredFallback::Defer {
                referenced_variables,
                ..
            }
            | UnansweredFallback::BlockedWithoutAnswer {
                referenced_variables,
                ..
            } => referenced_variables.sort(),
        }
    }
    match &mut normalized.state {
        AmbiguityState::ResolvedByEvidence { evidence_refs, .. }
        | AmbiguityState::SafeDefaultAvailable { evidence_refs, .. } => evidence_refs.sort(),
        AmbiguityState::Unresolved
        | AmbiguityState::NonMaterial { .. }
        | AmbiguityState::Stale { .. }
        | AmbiguityState::OutOfScope { .. } => {}
    }
    normalized
}
