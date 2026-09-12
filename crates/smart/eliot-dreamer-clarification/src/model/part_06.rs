/// Stable reason why this pure owner emitted no question candidate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoQuestionReason {
    NoMaterialAmbiguity,
    AlreadyAnswerable,
    SafeFallbackAvailable,
    DecompositionRequired,
    UnauthorizedResponder,
    SecretOrProtected,
    StaleInput,
    OutOfScope,
    Cancelled,
    Expired,
    NoSafeAtomicCandidate,
}

/// Terminal candidate-only disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClarificationDisposition {
    Candidate,
    NoQuestion { reason: NoQuestionReason },
}

/// Per-ambiguity accounting status retained by every decision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityAccountingStatus {
    Selected,
    NonMaterial,
    ResolvedByEvidence,
    SafeDefaultAvailable,
    Stale,
    OutOfScope,
    DecompositionRequired,
    UnauthorizedResponder,
    SecretBlocked,
    NotSelected,
}

/// Exact disposition of one ambiguity in the admitted denominator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmbiguityAccounting {
    pub ambiguity_id: String,
    pub status: AmbiguityAccountingStatus,
    pub reason_code: String,
}

impl AmbiguityAccounting {
    fn validate(&self) -> Result<(), ClarificationError> {
        validate_text(&self.ambiguity_id, "accounting.ambiguity_id", 128)?;
        validate_text(&self.reason_code, "accounting.reason_code", 256)
    }
}

/// One inert atomic clarification candidate. It carries no answer or delivery state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationCandidate {
    pub schema_version: u32,
    pub candidate_id: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub objective_id: String,
    pub ambiguity_id: String,
    pub question: String,
    pub variable: DecisionVariable,
    pub materiality: MaterialityEvidence,
    pub routing: RoutingRecommendation,
    pub fallback: UnansweredFallback,
    pub source_refs: Vec<String>,
    pub expires_at_ms: u64,
    pub policy_id: String,
    pub invalidation: CandidateInvalidation,
    pub proof_ceiling: String,
    pub candidate_digest: String,
}

impl ClarificationCandidate {
    pub fn seal(&mut self, policy: &ClarificationPolicy) -> Result<(), ClarificationError> {
        self.validate_unsealed(policy)?;
        self.candidate_digest = self.identity_digest()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ClarificationError::Canonicalization)?;
        if bytes.len() > policy.max_output_bytes {
            return Err(ClarificationError::limit(
                "candidate.output_bytes",
                policy.max_output_bytes,
            ));
        }
        Ok(())
    }

    pub fn validate(&self, policy: &ClarificationPolicy) -> Result<(), ClarificationError> {
        self.validate_unsealed(policy)?;
        validate_digest(&self.candidate_digest, "candidate.candidate_digest")?;
        if self.candidate_digest != self.identity_digest()? {
            return Err(ClarificationError::IdentityConflict);
        }
        let bytes = canonical_json_bytes(self).map_err(|_| ClarificationError::Canonicalization)?;
        if bytes.len() > policy.max_output_bytes {
            return Err(ClarificationError::limit(
                "candidate.output_bytes",
                policy.max_output_bytes,
            ));
        }
        Ok(())
    }

    pub fn identity_digest(&self) -> Result<String, ClarificationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            candidate_id: &'a str,
            operation_id: &'a str,
            idempotency_key: &'a str,
            task_id: &'a str,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            objective_id: &'a str,
            ambiguity_id: &'a str,
            question: &'a str,
            variable: DecisionVariable,
            materiality: MaterialityEvidence,
            routing: &'a RoutingRecommendation,
            fallback: UnansweredFallback,
            source_refs: Vec<&'a str>,
            expires_at_ms: u64,
            policy_id: &'a str,
            invalidation: &'a CandidateInvalidation,
            proof_ceiling: &'a str,
        }
        let mut materiality = self.materiality.clone();
        materiality.evidence_refs.sort();
        materiality.referenced_variables.sort();
        let mut fallback = self.fallback.clone();
        match &mut fallback {
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
        let mut source_refs: Vec<_> = self.source_refs.iter().map(String::as_str).collect();
        source_refs.sort_unstable();
        canonical_digest(&Preimage {
            schema_version: self.schema_version,
            candidate_id: &self.candidate_id,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            objective_id: &self.objective_id,
            ambiguity_id: &self.ambiguity_id,
            question: &self.question,
            variable: self.variable.normalized(),
            materiality,
            routing: &self.routing,
            fallback,
            source_refs,
            expires_at_ms: self.expires_at_ms,
            policy_id: &self.policy_id,
            invalidation: &self.invalidation,
            proof_ceiling: &self.proof_ceiling,
        })
    }

    fn validate_unsealed(
        &self,
        policy: &ClarificationPolicy,
    ) -> Result<(), ClarificationError> {
        if self.schema_version != CLARIFICATION_SCHEMA_VERSION {
            return Err(ClarificationError::invalid(
                "candidate.schema_version",
                "unsupported candidate schema",
            ));
        }
        for (value, field, limit) in [
            (&self.candidate_id, "candidate.candidate_id", 128),
            (&self.operation_id, "candidate.operation_id", 128),
            (&self.idempotency_key, "candidate.idempotency_key", 128),
            (&self.task_id, "candidate.task_id", 256),
            (&self.scope_id, "candidate.scope_id", 256),
            (&self.objective_id, "candidate.objective_id", 128),
            (&self.ambiguity_id, "candidate.ambiguity_id", 128),
            (&self.question, "candidate.question", policy.max_text_bytes),
            (&self.policy_id, "candidate.policy_id", 256),
            (&self.proof_ceiling, "candidate.proof_ceiling", 256),
        ] {
            validate_text(value, field, limit)?;
        }
        if !self.question.ends_with('?') {
            return Err(ClarificationError::invalid(
                "candidate.question",
                "neutral clarification rendering must end in one question mark",
            ));
        }
        if self.question.matches('?').count() != 1 {
            return Err(ClarificationError::invalid(
                "candidate.question",
                "candidate must contain exactly one question",
            ));
        }
        if self.proof_ceiling != CLARIFICATION_PROOF_CEILING {
            return Err(ClarificationError::binding("candidate.proof_ceiling"));
        }
        if self.policy_id != policy.policy_id || self.invalidation.policy_digest != policy.policy_digest {
            return Err(ClarificationError::binding("candidate.policy"));
        }
        self.variable.validate(policy)?;
        if let AnswerSchema::BoundedText { max_bytes, .. } = &self.variable.answer_schema {
            let policy_limit = match u32::try_from(policy.max_text_bytes) {
                Ok(value) => value,
                Err(_) => u32::MAX,
            };
            if *max_bytes == 0 || *max_bytes > policy_limit {
                return Err(ClarificationError::UnsupportedAnswerSchema {
                    reason: "bounded text exceeds the policy byte limit".to_owned(),
                });
            }
        }
        self.materiality.validate(policy.max_text_bytes)?;
        self.fallback.validate(policy.max_text_bytes)?;
        self.routing.validate()?;
        self.invalidation.validate()?;
        ensure_unique_text(&self.source_refs, "candidate.source_refs", 256, 128)?;
        if self.source_refs.is_empty() {
            return Err(ClarificationError::invalid(
                "candidate.source_refs",
                "candidate requires admitted source lineage",
            ));
        }
        if self.expires_at_ms <= policy.observation_time_ms {
            return Err(ClarificationError::invalid(
                "candidate.expires_at_ms",
                "candidate must expire after the injected observation time",
            ));
        }
        let mut expected = BTreeSet::new();
        expected.insert(self.variable.variable_id.clone());
        let mut actual = self.variable.all_referenced_variables(&self.fallback);
        actual.extend(self.materiality.referenced_variables.iter().cloned());
        if self.variable.component_ids.len() != 1
            || self.variable.component_ids[0] != self.variable.variable_id
            || actual != expected
        {
            return Err(ClarificationError::invalid(
                "candidate.atomicity",
                "all candidate branches must depend on exactly one decision variable",
            ));
        }
        Ok(())
    }
}

/// Complete result of one pure clarification decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationDecision {
    pub schema_version: u32,
    pub disposition: ClarificationDisposition,
    pub candidate: Option<ClarificationCandidate>,
    pub accounting: Vec<AmbiguityAccounting>,
    pub input_digest: String,
    pub policy_digest: String,
    pub boundary_digest: String,
    pub work_units: u64,
    pub output_bytes: u64,
    pub proof_ceiling: String,
    pub decision_digest: String,
}

impl ClarificationDecision {
    pub fn seal(&mut self, policy: &ClarificationPolicy) -> Result<(), ClarificationError> {
        self.validate_unsealed(policy)?;
        let bytes = self.semantic_bytes()?;
        if bytes.len() > policy.max_output_bytes {
            return Err(ClarificationError::limit(
                "decision.output_bytes",
                policy.max_output_bytes,
            ));
        }
        self.output_bytes = u64::try_from(bytes.len())
            .map_err(|_| ClarificationError::limit("decision.output_bytes", policy.max_output_bytes))?;
        self.decision_digest = sha256_hex(&bytes);
        Ok(())
    }

    pub fn validate(&self, policy: &ClarificationPolicy) -> Result<(), ClarificationError> {
        self.validate_unsealed(policy)?;
        validate_digest(&self.decision_digest, "decision.decision_digest")?;
        let bytes = self.semantic_bytes()?;
        let expected_bytes = u64::try_from(bytes.len())
            .map_err(|_| ClarificationError::limit("decision.output_bytes", policy.max_output_bytes))?;
        if self.output_bytes != expected_bytes || self.decision_digest != sha256_hex(&bytes) {
            return Err(ClarificationError::IdentityConflict);
        }
        Ok(())
    }

    fn validate_unsealed(
        &self,
        policy: &ClarificationPolicy,
    ) -> Result<(), ClarificationError> {
        if self.schema_version != CLARIFICATION_SCHEMA_VERSION {
            return Err(ClarificationError::invalid(
                "decision.schema_version",
                "unsupported decision schema",
            ));
        }
        validate_digest(&self.input_digest, "decision.input_digest")?;
        validate_digest(&self.policy_digest, "decision.policy_digest")?;
        validate_digest(&self.boundary_digest, "decision.boundary_digest")?;
        if self.policy_digest != policy.policy_digest {
            return Err(ClarificationError::binding("decision.policy_digest"));
        }
        if self.proof_ceiling != CLARIFICATION_PROOF_CEILING {
            return Err(ClarificationError::binding("decision.proof_ceiling"));
        }
        if self.work_units > policy.max_work_units {
            return Err(ClarificationError::limit(
                "decision.work_units",
                usize::try_from(policy.max_work_units).unwrap_or(usize::MAX),
            ));
        }
        let mut ambiguity_ids = BTreeSet::new();
        let mut selected = 0usize;
        for item in &self.accounting {
            item.validate()?;
            if !ambiguity_ids.insert(&item.ambiguity_id) {
                return Err(ClarificationError::DuplicateIdentity {
                    field: "decision.accounting.ambiguity_id",
                });
            }
            if item.status == AmbiguityAccountingStatus::Selected {
                selected = selected.saturating_add(1);
            }
        }
        match (&self.disposition, &self.candidate) {
            (ClarificationDisposition::Candidate, Some(candidate)) => {
                if selected != 1 {
                    return Err(ClarificationError::invalid(
                        "decision.accounting",
                        "candidate decision requires exactly one selected ambiguity",
                    ));
                }
                candidate.validate(policy)?;
                if candidate.invalidation.boundary_digest != self.boundary_digest
                    || candidate.invalidation.policy_digest != self.policy_digest
                {
                    return Err(ClarificationError::binding("decision.candidate"));
                }
            }
            (ClarificationDisposition::NoQuestion { .. }, None) if selected == 0 => {}
            _ => {
                return Err(ClarificationError::invalid(
                    "decision.disposition",
                    "candidate and disposition disagree",
                ));
            }
        }
        Ok(())
    }

    fn semantic_bytes(&self) -> Result<Vec<u8>, ClarificationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            disposition: &'a ClarificationDisposition,
            candidate: &'a Option<ClarificationCandidate>,
            accounting: Vec<AmbiguityAccounting>,
            input_digest: &'a str,
            policy_digest: &'a str,
            boundary_digest: &'a str,
            work_units: u64,
            proof_ceiling: &'a str,
        }
        let mut accounting = self.accounting.clone();
        accounting.sort_by(|left, right| left.ambiguity_id.cmp(&right.ambiguity_id));
        canonical_json_bytes(&Preimage {
            schema_version: self.schema_version,
            disposition: &self.disposition,
            candidate: &self.candidate,
            accounting,
            input_digest: &self.input_digest,
            policy_digest: &self.policy_digest,
            boundary_digest: &self.boundary_digest,
            work_units: self.work_units,
            proof_ceiling: &self.proof_ceiling,
        })
        .map_err(|_| ClarificationError::Canonicalization)
    }
}
