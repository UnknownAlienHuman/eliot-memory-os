/// Current task-local agent boundary supplied by its external owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveAgentBoundary {
    pub principal: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub capability_ids: Vec<String>,
    pub boundary_ref: String,
    pub current: bool,
}

impl ActiveAgentBoundary {
    fn validate(&self) -> Result<(), ClarificationError> {
        validate_text(&self.principal, "active_agent.principal", 256)?;
        validate_text(&self.task_id, "active_agent.task_id", 256)?;
        validate_text(&self.scope_id, "active_agent.scope_id", 256)?;
        validate_text(&self.boundary_ref, "active_agent.boundary_ref", 512)?;
        ensure_unique_text(
            &self.capability_ids,
            "active_agent.capability_ids",
            256,
            128,
        )
    }
}

/// Explicit authenticated Human boundary. This crate only recommends routing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanBoundary {
    pub principal: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub decision_kinds: Vec<HumanDecisionKind>,
    pub authority_ref: String,
    pub current: bool,
}

impl HumanBoundary {
    fn validate(&self) -> Result<(), ClarificationError> {
        validate_text(&self.principal, "human.principal", 256)?;
        validate_text(&self.scope_id, "human.scope_id", 256)?;
        validate_text(&self.authority_ref, "human.authority_ref", 512)?;
        if self.decision_kinds.len() > 32 {
            return Err(ClarificationError::limit("human.decision_kinds", 32));
        }
        let mut kinds = BTreeSet::new();
        for kind in &self.decision_kinds {
            if !kinds.insert(*kind) {
                return Err(ClarificationError::DuplicateIdentity {
                    field: "human.decision_kinds",
                });
            }
        }
        Ok(())
    }
}

/// Immutable projection of the possible task-local and Human recipients.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveAgentOrHumanBoundary {
    pub schema_version: u32,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub active_agent: Option<ActiveAgentBoundary>,
    pub human: Option<HumanBoundary>,
    pub boundary_digest: String,
}

impl ActiveAgentOrHumanBoundary {
    pub fn seal(&mut self) -> Result<(), ClarificationError> {
        self.validate_unsealed()?;
        self.boundary_digest = self.identity_digest()?;
        Ok(())
    }

    pub fn validate_for(&self, job: &DreamJobInput) -> Result<(), ClarificationError> {
        self.validate_unsealed()?;
        validate_digest(&self.boundary_digest, "boundary.boundary_digest")?;
        if self.boundary_digest != self.identity_digest()? {
            return Err(ClarificationError::IdentityConflict);
        }
        if self.task_id != job.task_id
            || self.scope_id != job.scope_id
            || self.state_fence != job.state_fence
        {
            return Err(ClarificationError::binding("boundary.job"));
        }
        Ok(())
    }

    pub fn identity_digest(&self) -> Result<String, ClarificationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            task_id: &'a str,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            active_agent: Option<ActiveAgentBoundary>,
            human: Option<HumanBoundary>,
        }
        let mut active_agent = self.active_agent.clone();
        if let Some(agent) = &mut active_agent {
            agent.capability_ids.sort();
        }
        let mut human = self.human.clone();
        if let Some(boundary) = &mut human {
            boundary.decision_kinds.sort();
        }
        canonical_digest(&Preimage {
            schema_version: self.schema_version,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            active_agent,
            human,
        })
    }

    fn validate_unsealed(&self) -> Result<(), ClarificationError> {
        if self.schema_version != CLARIFICATION_SCHEMA_VERSION {
            return Err(ClarificationError::invalid(
                "boundary.schema_version",
                "unsupported recipient-boundary schema",
            ));
        }
        validate_text(&self.task_id, "boundary.task_id", 256)?;
        validate_text(&self.scope_id, "boundary.scope_id", 256)?;
        if let Some(agent) = &self.active_agent {
            agent.validate()?;
            if agent.task_id != self.task_id
                || agent.scope_id != self.scope_id
                || agent.state_fence != self.state_fence
            {
                return Err(ClarificationError::binding("boundary.active_agent"));
            }
        }
        if let Some(human) = &self.human {
            human.validate()?;
            if human.scope_id != self.scope_id || human.state_fence != self.state_fence {
                return Err(ClarificationError::binding("boundary.human"));
            }
        }
        Ok(())
    }
}

/// Inert recommendation for the external mailbox or Human-attention owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum RoutingRecommendation {
    TaskLocalAgent {
        principal: String,
        capability_id: String,
        boundary_ref: String,
    },
    Human {
        principal: String,
        decision_kind: HumanDecisionKind,
        authority_ref: String,
    },
}

impl RoutingRecommendation {
    fn validate(&self) -> Result<(), ClarificationError> {
        match self {
            Self::TaskLocalAgent {
                principal,
                capability_id,
                boundary_ref,
            } => {
                validate_text(principal, "routing.principal", 256)?;
                validate_text(capability_id, "routing.capability_id", 256)?;
                validate_text(boundary_ref, "routing.boundary_ref", 512)
            }
            Self::Human {
                principal,
                decision_kind: _,
                authority_ref,
            } => {
                validate_text(principal, "routing.principal", 256)?;
                validate_text(authority_ref, "routing.authority_ref", 512)
            }
        }
    }
}

/// Load-bearing identities that invalidate a previously emitted candidate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateInvalidation {
    pub source_denominator_digest: String,
    pub validated_draft_digest: String,
    pub boundary_digest: String,
    pub policy_digest: String,
    pub state_fence: StateFence,
}

impl CandidateInvalidation {
    fn validate(&self) -> Result<(), ClarificationError> {
        validate_digest(
            &self.source_denominator_digest,
            "invalidation.source_denominator_digest",
        )?;
        validate_digest(
            &self.validated_draft_digest,
            "invalidation.validated_draft_digest",
        )?;
        validate_digest(&self.boundary_digest, "invalidation.boundary_digest")?;
        validate_digest(&self.policy_digest, "invalidation.policy_digest")
    }
}
