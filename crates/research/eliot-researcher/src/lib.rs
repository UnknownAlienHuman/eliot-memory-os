//! Researcher composition root.
//!
//! Researcher owns acquisition requests and bridge composition only. It does
//! not interpret claims, promote memory, or bypass the exchange fence.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_research_exchange::{ExchangeError, ExchangeJob, GovernedExchange, ResearchBridge};
use eliot_research_exchange_api::{
    AllowedReferenceManifest, AnchorPrecision, DisclosureClass, ResearchQueryRequest, SourceClass,
};

pub struct Researcher<B> {
    exchange: GovernedExchange<B>,
}

impl<B> Researcher<B> {
    pub fn new(bridge: B) -> Self {
        Self {
            exchange: GovernedExchange::new(bridge),
        }
    }
    pub fn from_exchange(exchange: GovernedExchange<B>) -> Self {
        Self { exchange }
    }
    #[must_use]
    pub fn exchange(&self) -> &GovernedExchange<B> {
        &self.exchange
    }
    pub fn exchange_mut(&mut self) -> &mut GovernedExchange<B> {
        &mut self.exchange
    }
    pub fn into_exchange(self) -> GovernedExchange<B> {
        self.exchange
    }
}

impl<B: ResearchBridge> Researcher<B> {
    pub fn submit_query(
        &mut self,
        query: ResearchQueryRequest,
    ) -> Result<ExchangeJob, ExchangeError> {
        self.exchange.submit(query)
    }

    pub fn request(
        &mut self,
        exchange_id: impl Into<String>,
        bridge_generation: impl Into<String>,
        idempotency_key: impl Into<String>,
        requester_principal: impl Into<String>,
        fence: StateFence,
        question: impl Into<String>,
        scope: impl Into<String>,
        expected_decision: impl Into<String>,
        source_classes: Vec<SourceClass>,
        allowed_references: AllowedReferenceManifest,
        budget_units: u64,
        deadline_ms: i64,
    ) -> Result<ExchangeJob, ExchangeError> {
        self.submit_query(ResearchQueryRequest {
            exchange_id: exchange_id.into(),
            protocol_revision: eliot_research_exchange_api::CONTRACT_VERSION,
            bridge_generation: bridge_generation.into(),
            idempotency_key: idempotency_key.into(),
            requester_principal: requester_principal.into(),
            state_fence: fence,
            question: question.into(),
            question_scope: scope.into(),
            expected_decision: expected_decision.into(),
            source_classes,
            coverage_goal: "bounded exact sources with explicit unknowns".into(),
            allowed_references,
            disclosure: DisclosureClass::ProjectBound,
            retention: "governed-by-caller".into(),
            license_policy: "caller-policy".into(),
            budget_units,
            deadline_ms,
            required_schema: "research-evidence-bundle/v1".into(),
        })
    }
}

#[must_use]
pub fn manifest(
    run_id: impl Into<String>,
    fence: StateFence,
    sources: Vec<String>,
    digest: impl Into<String>,
) -> AllowedReferenceManifest {
    AllowedReferenceManifest {
        run_id: run_id.into(),
        state_fence: fence,
        source_handles: sources,
        evidence_handles: Vec::new(),
        artifact_handles: Vec::new(),
        allowed_anchor_precision: AnchorPrecision::Section,
        stale_or_revoked_handles: Vec::new(),
        digest: digest.into(),
    }
}
