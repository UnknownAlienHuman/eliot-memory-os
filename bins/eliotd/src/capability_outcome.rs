//! Governor-owned scoped capability-failure records (issue #1961).
//!
//! Architecture: I3.4 scopes every capability failure to the narrowest
//! observed lifecycle (`ITEM`, `CALL`, `ATTEMPT`, `SESSION`, `GENERATION`,
//! `INSTALLATION`). A call-scoped fallback stays visible in the attempt
//! receipt and never becomes a sticky installation-global flag; broader
//! invalidation requires evidence tied to the broader owner. This module is
//! the canonical `CapabilityOutcome` implementation for the `eliotd`
//! composition root: fallback selection emits an outcome here and attaches
//! it to the relevant [`AttemptReceipt`], while [`CapabilityRegistryView`]
//! admits only evidence-backed broad scopes into global blocking state.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Narrowest observed lifecycle a capability failure is scoped to (I3.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DegradationScope {
    /// One item within a call; never installation-global.
    Item,
    /// One call; visible on the attempt receipt, never installation-global.
    Call,
    /// One attempt; visible on the attempt receipt, never installation-global.
    Attempt,
    /// One session; global only with session-tied evidence.
    Session,
    /// One exact generation/fingerprint; global only with generation-tied evidence.
    Generation,
    /// Whole installation; global only with installation-tied evidence.
    Installation,
}

impl DegradationScope {
    /// Narrow scopes remain attempt-visible and must never become global flags.
    #[must_use]
    pub const fn is_narrow(self) -> bool {
        matches!(
            self,
            DegradationScope::Item | DegradationScope::Call | DegradationScope::Attempt
        )
    }
}

/// Governor-owned scoped degradation/requalification result (I3.4
/// `CapabilityOutcome` evidence variant).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityOutcome {
    /// Capability under test, e.g. `provider.dispatch`.
    pub capability: String,
    /// Mode the caller requested, e.g. `route-a`.
    pub requested_mode: String,
    /// Mode actually executed, e.g. `fallback-route-b`.
    pub effective_mode: String,
    /// Narrowest observed lifecycle this failure is scoped to.
    pub degradation_scope: DegradationScope,
    /// Bounded human-readable reason for the degradation.
    pub reason: String,
    /// Evidence references backing this outcome. Required for broad scopes.
    pub evidence_refs: Vec<String>,
    /// Outputs or operations affected by the degraded execution.
    pub affected_outputs_or_operations: Vec<String>,
    /// Highest proof this degraded execution may still satisfy.
    pub proof_ceiling: String,
    /// Recovery, requalification, or expiry condition, e.g.
    /// `requalify-on-pass gen-probe-7` or `expires 1700000000000`.
    pub recovery_requalification_or_expiry: String,
    /// Owner identity the scope is keyed to: call/attempt/session owner id,
    /// generation owner, or installation id for broad scopes.
    pub scope_owner: String,
    /// Exact generation/route fingerprint. Required for `GENERATION` scope so
    /// a generation failure blocks only matching routes.
    pub generation_fingerprint: String,
    /// Unix milliseconds after which this outcome no longer blocks.
    /// `None` means no time expiry; explicit requalification still applies.
    pub valid_until_unix_ms: Option<u64>,
}

/// Typed outcome errors. Every variant is load-bearing: collapsing narrow
/// rejection and broad evidence rejection would hide which scoping rule fired.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum OutcomeError {
    /// A field is blank, unbounded, or carries control characters.
    #[error("capability outcome contract: {0}")]
    Contract(String),
    /// A narrow (item/call/attempt) outcome was offered to global state.
    #[error("capability outcome must not become global: {0}")]
    NarrowScopeMustNotBecomeGlobal(String),
    /// A broad scope was recorded without evidence tied to that scope.
    #[error("broad capability scope requires evidence: {0}")]
    BroadScopeRequiresEvidence(String),
}

/// Disposition returned when an outcome is recorded against the registry view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeDisposition {
    /// Narrow outcome: stays visible on the attempt receipt only.
    AttemptVisible,
    /// Broad outcome: admitted into scoped global blocking state.
    GlobalApplied,
}

const MAX_TEXT_LEN: usize = 512;
const MAX_REFS: usize = 16;

fn check_text(value: &str, field: &'static str) -> Result<(), OutcomeError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_LEN || value.chars().any(char::is_control)
    {
        return Err(OutcomeError::Contract(format!(
            "{field} is blank, unbounded, or contains control characters"
        )));
    }
    Ok(())
}

impl CapabilityOutcome {
    /// Validates every bound field plus the scope/evidence scoping rules.
    ///
    /// # Errors
    ///
    /// Returns [`OutcomeError::Contract`] for malformed fields, or
    /// [`OutcomeError::BroadScopeRequiresEvidence`] when a session,
    /// generation, or installation scope lacks evidence tied to that scope.
    pub fn validate(&self) -> Result<(), OutcomeError> {
        check_text(&self.capability, "capability")?;
        check_text(&self.requested_mode, "requested_mode")?;
        check_text(&self.effective_mode, "effective_mode")?;
        check_text(&self.reason, "reason")?;
        check_text(&self.proof_ceiling, "proof_ceiling")?;
        check_text(
            &self.recovery_requalification_or_expiry,
            "recovery_requalification_or_expiry",
        )?;
        check_text(&self.scope_owner, "scope_owner")?;
        if self.evidence_refs.len() > MAX_REFS
            || self.affected_outputs_or_operations.len() > MAX_REFS
        {
            return Err(OutcomeError::Contract(
                "evidence or affected-output lists are unbounded".to_owned(),
            ));
        }
        for reference in &self.evidence_refs {
            check_text(reference, "evidence_ref")?;
        }
        for output in &self.affected_outputs_or_operations {
            check_text(output, "affected_output_or_operation")?;
        }
        if !self.generation_fingerprint.is_empty() {
            check_text(&self.generation_fingerprint, "generation_fingerprint")?;
        }
        match self.degradation_scope {
            DegradationScope::Item | DegradationScope::Call | DegradationScope::Attempt => Ok(()),
            DegradationScope::Session
            | DegradationScope::Generation
            | DegradationScope::Installation => {
                if self.evidence_refs.is_empty() {
                    return Err(OutcomeError::BroadScopeRequiresEvidence(
                        "broader degradation requires evidence tied to the broader owner"
                            .to_owned(),
                    ));
                }
                if self.degradation_scope == DegradationScope::Generation
                    && self.generation_fingerprint.is_empty()
                {
                    return Err(OutcomeError::BroadScopeRequiresEvidence(
                        "generation scope requires the exact generation fingerprint".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Returns false once `valid_until_unix_ms` has passed.
    #[must_use]
    pub const fn is_live(&self, now_unix_ms: u64) -> bool {
        match self.valid_until_unix_ms {
            Some(until) => now_unix_ms < until,
            None => true,
        }
    }
}

/// Inputs for one call-scoped fallback emission.
///
/// Grouped so the emission constructor keeps a reviewable arity instead of a
/// long positional parameter list. Every field is validated through
/// [`CapabilityOutcome::validate`] when the outcome is emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackOutcomeRequest {
    /// Capability under test, e.g. `provider.dispatch`.
    pub capability: String,
    /// Mode the caller requested, e.g. `route-a`.
    pub requested_mode: String,
    /// Mode actually executed, e.g. `fallback-route-b`.
    pub effective_mode: String,
    /// Bounded human-readable reason for the degradation.
    pub reason: String,
    /// Outputs or operations affected by the degraded execution.
    pub affected_outputs_or_operations: Vec<String>,
    /// Highest proof this degraded execution may still satisfy.
    pub proof_ceiling: String,
    /// Recovery, requalification, or expiry condition.
    pub recovery_requalification_or_expiry: String,
    /// Attempt the fallback ran under; becomes the outcome scope owner.
    pub attempt_id: String,
}

/// Emits the call-scoped outcome for one fallback selection.
///
/// The requested mode failed for this call and the effective fallback mode
/// ran instead. The outcome is `CALL`-scoped: it belongs on the attempt
/// receipt and can never become an installation-global flag.
///
/// # Errors
///
/// Returns [`OutcomeError::Contract`] when any bound field is malformed.
pub fn fallback_outcome(
    request: FallbackOutcomeRequest,
) -> Result<CapabilityOutcome, OutcomeError> {
    let outcome = CapabilityOutcome {
        capability: request.capability,
        requested_mode: request.requested_mode,
        effective_mode: request.effective_mode,
        degradation_scope: DegradationScope::Call,
        reason: request.reason,
        evidence_refs: Vec::new(),
        affected_outputs_or_operations: request.affected_outputs_or_operations,
        proof_ceiling: request.proof_ceiling,
        recovery_requalification_or_expiry: request.recovery_requalification_or_expiry,
        scope_owner: request.attempt_id,
        generation_fingerprint: String::new(),
        valid_until_unix_ms: None,
    };
    outcome.validate()?;
    Ok(outcome)
}

/// Attempt receipt carrying the visible degradation outcomes for one attempt.
///
/// Fallback selections and narrow failures attach here so degraded execution
/// stays visible exactly where it happened.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptReceipt {
    /// Attempt this receipt records.
    pub attempt_id: String,
    /// Scoped outcomes observed on this attempt, in attach order.
    pub capability_outcomes: Vec<CapabilityOutcome>,
}

impl AttemptReceipt {
    /// Opens a receipt for one attempt.
    ///
    /// # Errors
    ///
    /// Returns [`OutcomeError::Contract`] when the attempt id is malformed.
    pub fn new(attempt_id: &str) -> Result<Self, OutcomeError> {
        check_text(attempt_id, "attempt_id")?;
        Ok(Self {
            attempt_id: attempt_id.to_owned(),
            capability_outcomes: Vec::new(),
        })
    }

    /// Attaches one validated outcome so the degradation stays visible on
    /// this attempt. Attaching never writes global capability state.
    ///
    /// # Errors
    ///
    /// Returns the outcome validation rejection unchanged.
    pub fn attach(&mut self, outcome: CapabilityOutcome) -> Result<(), OutcomeError> {
        outcome.validate()?;
        if outcome.scope_owner != self.attempt_id
            && matches!(
                outcome.degradation_scope,
                DegradationScope::Item | DegradationScope::Call | DegradationScope::Attempt
            )
        {
            return Err(OutcomeError::Contract(
                "narrow outcome owner does not match this attempt receipt".to_owned(),
            ));
        }
        self.capability_outcomes.push(outcome);
        Ok(())
    }
}

/// Governor-owned capability registry view (I3.4).
///
/// Holds only evidence-backed broad scopes: installation blocks and
/// generation blocks keyed by exact fingerprint, plus session blocks keyed
/// by session owner. Narrow outcomes are never stored here; they remain
/// attempt-visible through [`AttemptReceipt`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityRegistryView {
    installation: Vec<CapabilityOutcome>,
    generation: Vec<CapabilityOutcome>,
    session: Vec<CapabilityOutcome>,
}

impl CapabilityRegistryView {
    /// Records one outcome. Narrow scopes return
    /// [`OutcomeDisposition::AttemptVisible`] and store nothing global;
    /// broad scopes validate their tied evidence and apply globally.
    ///
    /// # Errors
    ///
    /// Returns the outcome validation or broad-evidence rejection unchanged.
    pub fn record(
        &mut self,
        outcome: &CapabilityOutcome,
    ) -> Result<OutcomeDisposition, OutcomeError> {
        outcome.validate()?;
        if outcome.degradation_scope.is_narrow() {
            return Ok(OutcomeDisposition::AttemptVisible);
        }
        self.apply_validated_broad(outcome.clone());
        Ok(OutcomeDisposition::GlobalApplied)
    }

    /// Applies one outcome directly to global state, rejecting narrow scopes
    /// loudly instead of silently storing them.
    ///
    /// # Errors
    ///
    /// Returns [`OutcomeError::NarrowScopeMustNotBecomeGlobal`] for item,
    /// call, or attempt scopes, or the validation/evicence rejection.
    pub fn apply_global(&mut self, outcome: &CapabilityOutcome) -> Result<(), OutcomeError> {
        outcome.validate()?;
        if outcome.degradation_scope.is_narrow() {
            return Err(OutcomeError::NarrowScopeMustNotBecomeGlobal(
                "call-, item-, or attempt-scoped outcomes cannot enter installation-global state"
                    .to_owned(),
            ));
        }
        self.apply_validated_broad(outcome.clone());
        Ok(())
    }

    fn apply_validated_broad(&mut self, outcome: CapabilityOutcome) {
        match outcome.degradation_scope {
            DegradationScope::Installation => self.installation.push(outcome),
            DegradationScope::Generation => self.generation.push(outcome),
            DegradationScope::Session => self.session.push(outcome),
            DegradationScope::Item | DegradationScope::Call | DegradationScope::Attempt => {}
        }
    }

    /// Drops expired broad blocks. Expiry is one defined recovery path.
    pub fn clear_expired(&mut self, now_unix_ms: u64) {
        self.installation.retain(|item| item.is_live(now_unix_ms));
        self.generation.retain(|item| item.is_live(now_unix_ms));
        self.session.retain(|item| item.is_live(now_unix_ms));
    }

    /// Removes generation blocks for one exact fingerprint: explicit
    /// requalification/recovery for that generation.
    pub fn requalify_generation(&mut self, generation_fingerprint: &str) {
        self.generation
            .retain(|item| item.generation_fingerprint != generation_fingerprint);
    }

    /// Drops all installation blocks: explicit recovery for installation
    /// scope. Expiry alone cannot recover a block without a time bound, so
    /// installation scope needs this named recovery path like generation
    /// scope has.
    pub fn requalify_installation(&mut self) {
        self.installation.clear();
    }

    /// Drops session blocks for one exact session owner: explicit recovery
    /// for session scope.
    pub fn requalify_session(&mut self, session_id: &str) {
        self.session.retain(|item| item.scope_owner != session_id);
    }

    /// Reports whether a route remains eligible for admission.
    ///
    /// Live installation blocks stop every route. Live generation blocks stop
    /// only routes presenting the same exact generation fingerprint. Live
    /// session blocks stop only the owning session. Narrow outcomes never
    /// reach this view, so past call failures cannot block later attempts.
    #[must_use]
    pub fn is_route_eligible(
        &self,
        generation_fingerprint: &str,
        session_id: Option<&str>,
        now_unix_ms: u64,
    ) -> bool {
        if self
            .installation
            .iter()
            .any(|item| item.is_live(now_unix_ms))
        {
            return false;
        }
        if self.generation.iter().any(|item| {
            item.is_live(now_unix_ms) && item.generation_fingerprint == generation_fingerprint
        }) {
            return false;
        }
        if let Some(session) = session_id
            && self
                .session
                .iter()
                .any(|item| item.is_live(now_unix_ms) && item.scope_owner == session)
        {
            return false;
        }
        true
    }

    /// Counts live installation-global blocks (narrow outcomes never land here).
    #[must_use]
    pub fn live_installation_blocks(&self, now_unix_ms: u64) -> usize {
        self.installation
            .iter()
            .filter(|item| item.is_live(now_unix_ms))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_failure(attempt: &str) -> Result<CapabilityOutcome, OutcomeError> {
        fallback_outcome(FallbackOutcomeRequest {
            capability: "provider.dispatch".to_owned(),
            requested_mode: "route-a".to_owned(),
            effective_mode: "fallback-route-b".to_owned(),
            reason: "route-a timed out once".to_owned(),
            affected_outputs_or_operations: vec!["attempt-output-1".to_owned()],
            proof_ceiling: "candidate-only".to_owned(),
            recovery_requalification_or_expiry:
                "no sticky block; each attempt re-admits on its own evidence".to_owned(),
            attempt_id: attempt.to_owned(),
        })
    }

    fn session_failure(owner: &str) -> CapabilityOutcome {
        CapabilityOutcome {
            capability: "provider.dispatch".to_owned(),
            requested_mode: "route-a".to_owned(),
            effective_mode: "degraded".to_owned(),
            degradation_scope: DegradationScope::Session,
            reason: "session evidence shows repeated degraded execution".to_owned(),
            evidence_refs: vec!["session-evidence-7-1".to_owned()],
            affected_outputs_or_operations: vec!["dispatch".to_owned()],
            proof_ceiling: "candidate-only".to_owned(),
            recovery_requalification_or_expiry: "requalify-session session-7".to_owned(),
            scope_owner: owner.to_owned(),
            generation_fingerprint: String::new(),
            valid_until_unix_ms: None,
        }
    }

    fn installation_failure() -> CapabilityOutcome {
        CapabilityOutcome {
            capability: "provider.dispatch".to_owned(),
            requested_mode: "route-a".to_owned(),
            effective_mode: "blocked".to_owned(),
            degradation_scope: DegradationScope::Installation,
            reason: "installation evidence shows a broken provider contract".to_owned(),
            evidence_refs: vec!["installation-evidence-1".to_owned()],
            affected_outputs_or_operations: vec!["dispatch".to_owned()],
            proof_ceiling: "none".to_owned(),
            recovery_requalification_or_expiry: "requalify-installation".to_owned(),
            scope_owner: "installation-1".to_owned(),
            generation_fingerprint: String::new(),
            valid_until_unix_ms: None,
        }
    }

    fn generation_failure(fingerprint: &str) -> CapabilityOutcome {
        CapabilityOutcome {
            capability: "provider.dispatch".to_owned(),
            requested_mode: "route-a".to_owned(),
            effective_mode: "blocked".to_owned(),
            degradation_scope: DegradationScope::Generation,
            reason: "exact-generation challenge failed on every retry".to_owned(),
            evidence_refs: vec!["challenge-receipt-gen-a-1".to_owned()],
            affected_outputs_or_operations: vec!["dispatch".to_owned()],
            proof_ceiling: "none".to_owned(),
            recovery_requalification_or_expiry: "requalify-on-pass gen-probe-7".to_owned(),
            scope_owner: "generation-owner-a".to_owned(),
            generation_fingerprint: fingerprint.to_owned(),
            valid_until_unix_ms: None,
        }
    }

    #[test]
    fn single_failed_call_stays_visible_without_blocking_later_attempts() -> Result<(), OutcomeError>
    {
        let outcome = call_failure("attempt-1")?;
        let mut receipt = AttemptReceipt::new("attempt-1")?;
        receipt.attach(outcome.clone())?;
        if receipt.capability_outcomes != vec![outcome.clone()] {
            return Err(OutcomeError::Contract(
                "call outcome is not visible on its attempt receipt".to_owned(),
            ));
        }

        let mut view = CapabilityRegistryView::default();
        if view.record(&outcome)? != OutcomeDisposition::AttemptVisible {
            return Err(OutcomeError::Contract(
                "narrow record must stay attempt-visible".to_owned(),
            ));
        }
        if !matches!(
            view.apply_global(&outcome),
            Err(OutcomeError::NarrowScopeMustNotBecomeGlobal(_))
        ) {
            return Err(OutcomeError::Contract(
                "narrow outcome reached installation-global state".to_owned(),
            ));
        }
        if view.live_installation_blocks(1_000) != 0
            || !view.is_route_eligible("gen-a", None, 1_000)
            || !view.is_route_eligible("gen-b", None, 1_000)
        {
            return Err(OutcomeError::Contract(
                "single failed call blocked a later attempt".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn exact_generation_failure_blocks_only_matching_routes_until_recovery()
    -> Result<(), OutcomeError> {
        let outcome = generation_failure("gen-a");
        outcome.validate()?;
        let mut view = CapabilityRegistryView::default();
        if view.record(&outcome)? != OutcomeDisposition::GlobalApplied {
            return Err(OutcomeError::Contract(
                "evidenced generation record must apply globally".to_owned(),
            ));
        }
        if view.is_route_eligible("gen-a", None, 1_000)
            || !view.is_route_eligible("gen-b", None, 1_000)
        {
            return Err(OutcomeError::Contract(
                "generation block did not match only its fingerprint".to_owned(),
            ));
        }

        let mut unproven = generation_failure("gen-a");
        unproven.evidence_refs.clear();
        if !matches!(
            view.record(&unproven),
            Err(OutcomeError::BroadScopeRequiresEvidence(_))
        ) {
            return Err(OutcomeError::Contract(
                "unevidenced generation scope was admitted".to_owned(),
            ));
        }

        view.requalify_generation("gen-a");
        if !view.is_route_eligible("gen-a", None, 1_000) {
            return Err(OutcomeError::Contract(
                "requalified generation still blocks its routes".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn installation_and_session_scopes_recover_through_defined_paths() -> Result<(), OutcomeError> {
        let mut view = CapabilityRegistryView::default();
        let mut bare = installation_failure();
        bare.evidence_refs.clear();
        if !matches!(
            view.record(&bare),
            Err(OutcomeError::BroadScopeRequiresEvidence(_))
        ) {
            return Err(OutcomeError::Contract(
                "unevidenced installation scope was admitted".to_owned(),
            ));
        }

        let installation = installation_failure();
        if view.record(&installation)? != OutcomeDisposition::GlobalApplied {
            return Err(OutcomeError::Contract(
                "evidenced installation record must apply globally".to_owned(),
            ));
        }
        if view.is_route_eligible("gen-a", None, 1_000) || view.live_installation_blocks(1_000) != 1
        {
            return Err(OutcomeError::Contract(
                "installation block did not stop every route".to_owned(),
            ));
        }
        view.requalify_installation();
        if !view.is_route_eligible("gen-a", None, 1_000) {
            return Err(OutcomeError::Contract(
                "requalified installation still blocks routes".to_owned(),
            ));
        }

        let session = session_failure("session-7");
        if view.record(&session)? != OutcomeDisposition::GlobalApplied {
            return Err(OutcomeError::Contract(
                "evidenced session record must apply globally".to_owned(),
            ));
        }
        if view.is_route_eligible("gen-b", Some("session-7"), 1_000)
            || !view.is_route_eligible("gen-b", Some("session-9"), 1_000)
            || !view.is_route_eligible("gen-b", None, 1_000)
        {
            return Err(OutcomeError::Contract(
                "session block did not match only its session".to_owned(),
            ));
        }
        view.requalify_session("session-7");
        if !view.is_route_eligible("gen-b", Some("session-7"), 1_000) {
            return Err(OutcomeError::Contract(
                "requalified session still blocks its routes".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn degradation_outcomes_round_trip_in_contract_vocabulary() -> Result<(), OutcomeError> {
        let outcome = call_failure("attempt-9")?;
        let json =
            serde_json::to_string(&outcome).map_err(|e| OutcomeError::Contract(e.to_string()))?;
        if !json.contains("\"CALL\"") {
            return Err(OutcomeError::Contract(
                "degradation scope left the contract vocabulary".to_owned(),
            ));
        }
        let back: CapabilityOutcome =
            serde_json::from_str(&json).map_err(|e| OutcomeError::Contract(e.to_string()))?;
        if back != outcome {
            return Err(OutcomeError::Contract(
                "capability outcome did not survive its wire round trip".to_owned(),
            ));
        }
        let mut receipt = AttemptReceipt::new("attempt-9")?;
        receipt.attach(outcome)?;
        let receipt_json =
            serde_json::to_string(&receipt).map_err(|e| OutcomeError::Contract(e.to_string()))?;
        let receipt_back: AttemptReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| OutcomeError::Contract(e.to_string()))?;
        if receipt_back != receipt {
            return Err(OutcomeError::Contract(
                "attempt receipt did not survive its wire round trip".to_owned(),
            ));
        }
        Ok(())
    }
}
