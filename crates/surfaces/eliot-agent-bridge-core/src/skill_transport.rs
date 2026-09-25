//! Versioned Skill wire payload contract (issue #1882).
//!
//! Typed serde payloads for Skill intake, receiver-ack carriage, and display
//! requests crossing the authenticated bridge transport. This module owns the
//! PAYLOAD contract only: a version tag, field shapes, size caps honoring the
//! I7.2 frame profile, and admission checks re-verifiable from the bytes
//! (package↔inputs binding, install-context shape, ack↔receipt binding). It
//! mints no authority, fence, epoch, identity, or effect ceiling, and it
//! performs no delivery, promotion, or display itself — those stay with the
//! Governor and daemon owners that consume decoded payloads.
//!
//! Transport operation registration (which message types carry these payloads,
//! which pipe, which generation) belongs to the bridge and protocol owners;
//! this contract is deliberately transport-agnostic JSON (I7.1 `json-v1`
//! profile) so the operation binding can land without changing a single
//! payload byte. A new Tool Definition or payload shape gets a NEW contract
//! revision — v1 is frozen and rejected; v2 adds the accepted candidate to
//! the intake payload, so the daemon binds every install to the exact
//! accepted procedure projection instead of a bare package claim.

#![forbid(unsafe_code)]

use eliot_skill::{
    ActivatedSkillDisplay, CatalogueInstallContext, HotsetDeliveryAck, HotsetDeliveryReceipt,
    MaterializationInputs, MaterializationScope, PortableSkillPackageCandidate, ReadinessClaims,
    SkillExecutionEvidence, SkillHarnessActivationReceipt, SkillPackage,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Versioned Skill transport contract identity.
pub const SKILL_TRANSPORT_CONTRACT_ID: &str = "eliot.skill.transport/v2";
/// Payload contract revision. Decode rejects any other revision.
pub const SKILL_TRANSPORT_VERSION: u32 = 2;
/// Maximum encoded intake bytes (I7.2 default frame max). Larger material
/// must arrive by Blob or handle reference (future extension), never as
/// giant inline frames; oversize fails closed here.
pub const MAX_INTAKE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded ack/display bytes (I7.2 hot-response profile: receipts,
/// acks, and displays are small bounded projections).
pub const MAX_CARRY_BYTES: usize = 64 * 1024;

/// Host-request capability and tool name carrying Skill intake.
///
/// NOT an MCP hot tool: no semantic profile, never advertised on the MCP
/// surface, always rejected by profile-driven dispatch. It names the
/// session-admitted capability for Hotset intake on the host-request
/// invoke-read leg, where the Kernel linkage rule (tool name equals envelope
/// capability, digest-bound bytes) applies unchanged.
pub const SKILL_INJECT_TOOL: &str = "skill.inject";
/// Host-request capability and tool name carrying Skill display requests.
/// Same non-MCP status as [`SKILL_INJECT_TOOL`].
pub const SKILL_DISPLAY_TOOL: &str = "skill.display";
/// Host-request capability and tool name carrying Skill harness activation
/// receipts (issue #1191).
///
/// Same non-MCP status as [`SKILL_INJECT_TOOL`]: it names the
/// session-admitted capability for per-attempt activation evidence on the
/// host-request invoke-read leg, where the Kernel linkage rule (tool name
/// equals envelope capability, digest-bound bytes) applies unchanged. The
/// daemon folds the carried receipt into its attempt summary; the receipt
/// producer is the harness that observed the attempt.
pub const SKILL_ACTIVATE_TOOL: &str = "skill.activate";
/// Host-request capability and tool name carrying Skill execution evidence
/// (issue #1191).
///
/// Same non-MCP status as [`SKILL_INJECT_TOOL`]: it names the
/// session-admitted capability for step/artifact/verifier/outcome evidence on
/// the host-request invoke-read leg. The daemon reconciles unknown effects
/// before retry; the evidence producer is the harness that ran the steps.
pub const SKILL_EXECUTE_TOOL: &str = "skill.execute";

/// Skill tool kinds routable on the host-request channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillToolKind {
    /// Hotset intake (`skill.inject`).
    Inject,
    /// Display request (`skill.display`).
    Display,
    /// Harness activation receipt ingest (`skill.activate`).
    Activate,
    /// Execution evidence ingest (`skill.execute`).
    Execute,
}

/// Routes one tool name to its Skill kind, if any.
///
/// Pure name match owned here so every lane (bridge submit path, daemon
/// dispatch, Kernel admission) resolves the same four names from one
/// definition. Unknown names yield `None` and stay on their existing path.
#[must_use]
pub fn skill_tool_kind(name: &str) -> Option<SkillToolKind> {
    match name {
        SKILL_INJECT_TOOL => Some(SkillToolKind::Inject),
        SKILL_DISPLAY_TOOL => Some(SkillToolKind::Display),
        SKILL_ACTIVATE_TOOL => Some(SkillToolKind::Activate),
        SKILL_EXECUTE_TOOL => Some(SkillToolKind::Execute),
        _ => None,
    }
}

/// Injector-carried Hotset delivery request as wire bytes (issue #1882).
///
/// Mirrors the injector handoff field-for-field: the accepted candidate the
/// package materializes, the canonical package with its actual
/// materialization inputs, the Governor-owned install context (eligibility,
/// versions including the admitted definition version, budgets),
/// provider-signed readiness, scope identities, Hotset identity, and
/// injector approval. Decode re-verifies the candidate's own shape, the
/// package↔inputs binding, and the install-context shape from the bytes, so
/// malformed intake fails before any catalogue, readiness, or sealed gate
/// runs. Owner issuance and fence/scope currency are NOT decided here — the
/// driver rehydrates the candidate against the live fence and scope at drive
/// time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillIntakePayload {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// Accepted candidate the presented package materializes. The daemon
    /// rehydrates its procedure against owner issuance and the live
    /// scope/fence; a non-candidate wire claim never binds.
    pub candidate: PortableSkillPackageCandidate,
    /// Canonical package source under delivery.
    pub package: SkillPackage,
    /// Actual materialization inputs the digests bind.
    pub inputs: MaterializationInputs,
    /// Governor-owned install context (eligibility, versions, budgets).
    pub context: CatalogueInstallContext,
    /// Provider-signed readiness claims.
    pub readiness: ReadinessClaims,
    /// Scope identities for the delivery.
    pub scope: MaterializationScope,
    /// Hotset identity carried by the injector.
    pub hotset_id: String,
    /// Injector approval handle.
    pub approval_ref: String,
}

impl SkillIntakePayload {
    /// Produces the canonical authenticated v2 intake.
    ///
    /// The single production constructor for intake objects: stamps the
    /// exact materialized package digests onto the accepted candidate,
    /// binds candidate↔package↔inputs, and validates the full wire shape,
    /// so no constructed intake exists in an unbound state. Stamping accepts
    /// an unstamped candidate (binding it here) but refuses a candidate
    /// already bound to different digests — one candidate identity is never
    /// rebound to new material. Decode deliberately does NOT stamp: a wire
    /// claim without expected digests fails there instead of being bound
    /// by the receiver.
    //
    // The intake producer takes ownership of every intake part by design:
    // the candidate shell is bound by stamping and intentionally consumed,
    // so the lint allowances below hold the constructor's explicit arity
    // and ownership rather than splitting the single binding point.
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn produce(
        candidate: PortableSkillPackageCandidate,
        package: SkillPackage,
        inputs: MaterializationInputs,
        context: CatalogueInstallContext,
        readiness: ReadinessClaims,
        scope: MaterializationScope,
        hotset_id: String,
        approval_ref: String,
    ) -> Result<Self, SkillTransportError> {
        let candidate = eliot_skill::stamp_materialization_digests(&candidate, &package, &inputs)
            .map_err(|error| {
            SkillTransportError::Shape(format!("intake.candidate: {error}"))
        })?;
        let payload = Self {
            contract_version: SKILL_TRANSPORT_VERSION,
            candidate,
            package,
            inputs,
            context,
            readiness,
            scope,
            hotset_id,
            approval_ref,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Encodes a validated intake within the frame bound.
    pub fn encode(&self) -> Result<Vec<u8>, SkillTransportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        check_bound(bytes.len(), MAX_INTAKE_BYTES)?;
        Ok(bytes)
    }

    /// Decodes and validates one intake within the frame bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, SkillTransportError> {
        check_bound(bytes.len(), MAX_INTAKE_BYTES)?;
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SkillTransportError> {
        check_version(self.contract_version)?;
        bounded_text(&self.hotset_id, "intake.hotset_id")?;
        bounded_text(&self.approval_ref, "intake.approval_ref")?;
        self.candidate
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("intake.candidate: {error}")))?;
        self.package
            .validate(&self.inputs)
            .map_err(|error| SkillTransportError::Shape(format!("intake.package: {error}")))?;
        self.context
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("intake.context: {error}")))?;
        Ok(())
    }
}

/// Typed Skill wire failure.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SkillTransportError {
    /// Payload contract revision is not the frozen v2.
    #[error("skill transport version mismatch: expected v2")]
    BadVersion,
    /// Encoded payload exceeds its I7.2 bound.
    #[error("skill transport payload exceeds its bound")]
    TooLarge,
    /// Payload shape or admission check failed, with the offending detail.
    #[error("skill transport payload fails its shape: {0}")]
    Shape(String),
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), SkillTransportError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SkillTransportError::Shape(format!(
            "{field}: must be non-blank with no control characters"
        )));
    }
    Ok(())
}

fn check_version(version: u32) -> Result<(), SkillTransportError> {
    if version != SKILL_TRANSPORT_VERSION {
        return Err(SkillTransportError::BadVersion);
    }
    Ok(())
}

fn check_bound(len: usize, limit: usize) -> Result<(), SkillTransportError> {
    if len > limit {
        return Err(SkillTransportError::TooLarge);
    }
    Ok(())
}

/// Receiver-ack carriage as wire bytes (issue #1882).
///
/// Carries the issued receipt with the receiver ack bound to its exact
/// digest. Decode verifies both shapes plus the applied binding, so a
/// foreign or rejected ack fails before any display boundary runs. Display
/// needs the skill identity separately (see [`SkillDisplayPayload`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillAckPayload {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// Issued Hotset delivery receipt being carried.
    pub receipt: HotsetDeliveryReceipt,
    /// Receiver ack binding that exact receipt digest.
    pub ack: HotsetDeliveryAck,
}

impl SkillAckPayload {
    /// Encodes a validated ack carriage within the carry bound.
    pub fn encode(&self) -> Result<Vec<u8>, SkillTransportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        Ok(bytes)
    }

    /// Decodes and validates one ack carriage within the carry bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, SkillTransportError> {
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SkillTransportError> {
        check_version(self.contract_version)?;
        self.receipt
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("carry.receipt: {error}")))?;
        self.ack
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("carry.ack: {error}")))?;
        if !self.ack.confirms_applied(&self.receipt) {
            return Err(SkillTransportError::Shape(
                "carry.ack: ack does not confirm the carried receipt as applied".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Display request as wire bytes (issue #1882).
///
/// Names the delivered Skill plus its bound receipt/ack pair. Decode
/// verifies the identity text and the same applied binding as
/// [`SkillAckPayload`]; tool-authority checks (admitted version, tool basis,
/// provisional ceiling) run at the display boundary, never here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillDisplayPayload {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// Delivered Skill identity to display.
    pub skill_id: String,
    /// Issued Hotset delivery receipt being carried.
    pub receipt: HotsetDeliveryReceipt,
    /// Receiver ack binding that exact receipt digest.
    pub ack: HotsetDeliveryAck,
}

impl SkillDisplayPayload {
    /// Encodes a validated display request within the carry bound.
    pub fn encode(&self) -> Result<Vec<u8>, SkillTransportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        Ok(bytes)
    }

    /// Decodes and validates one display request within the carry bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, SkillTransportError> {
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SkillTransportError> {
        check_version(self.contract_version)?;
        bounded_text(&self.skill_id, "display.skill_id")?;
        self.receipt
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("display.receipt: {error}")))?;
        self.ack
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("display.ack: {error}")))?;
        if !self.ack.confirms_applied(&self.receipt) {
            return Err(SkillTransportError::Shape(
                "display.ack: ack does not confirm the carried receipt as applied".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed Skill result envelope carried back on the submit leg (issue #1882).
///
/// The daemon serves a claimed skill pair locally and persists exactly one
/// of these outcomes; the bridge polls it like any other result body. Every
/// claimed pair settles through this envelope — including refusals — so no
/// skill pair can poison the poller into a crash loop. Success carries the
/// digest-bound receipt or display verbatim; refusal carries a stable code
/// plus bounded detail and never fabricates delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillResultEnvelope {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// Settled outcome for the claimed pair.
    pub outcome: SkillResultOutcome,
}

/// Settled outcome for one claimed skill pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SkillResultOutcome {
    /// Hotset intake installed and issued: the injector's receipt.
    Receipt(HotsetDeliveryReceipt),
    /// Display request bound and rendered: the activated view. Boxed: the
    /// view carries the full validation/staleness/receipt-chain binding and
    /// would otherwise push the envelope over the large-variant size lint.
    /// `Box` is serde-transparent, so the wire shape is unchanged.
    Display(Box<ActivatedSkillDisplay>),
    /// Activation receipt folded: the per-attempt stage summary derived from
    /// the exact presented harness receipt. Delivered, retrieved, activated,
    /// adhered and useful stay distinct; a packet-included but never
    /// activated Skill is never marked successful.
    Attempt(eliot_skill::AttemptLifecycleSummary),
    /// Execution evidence reconciled: exact presented outcome counts with the
    /// still-uncertain remainder. Retry is permitted only when
    /// `uncertain_pending` is zero; uncertain effects block retry until
    /// reconciled by exact evidence.
    Evidence {
        /// Presented executions with a fully observed outcome.
        observed: u64,
        /// Presented executions with a known failed outcome.
        failed: u64,
        /// Presented executions whose effects are still unknown.
        uncertain_pending: u64,
    },
    /// The pair was understood but refused: stable code plus detail.
    Refused {
        /// Stable refusal code (`FENCE_MISMATCH`, `INVALID_FIELD:<field>`,
        /// `NOT_FOUND`, `IDENTITY_MISMATCH`, `SURFACE`, `STORE`).
        code: String,
        /// Bounded human detail naming the refusal.
        detail: String,
    },
}

impl SkillResultEnvelope {
    /// Builds a receipt outcome.
    pub fn receipt(receipt: HotsetDeliveryReceipt) -> Self {
        Self {
            contract_version: SKILL_TRANSPORT_VERSION,
            outcome: SkillResultOutcome::Receipt(receipt),
        }
    }

    /// Builds a display outcome.
    pub fn display(display: ActivatedSkillDisplay) -> Self {
        Self {
            contract_version: SKILL_TRANSPORT_VERSION,
            outcome: SkillResultOutcome::Display(Box::new(display)),
        }
    }

    /// Builds an attempt-summary outcome from one validated harness receipt.
    ///
    /// The summary keeps delivered, retrieved, activated, adhered and useful
    /// distinct; absent adherence evidence stays unassessed or unknown, never
    /// compliance, and usefulness additionally requires verifier-backed
    /// outcome refs — never installation, retrieval, repetition or agreement.
    pub fn attempt(summary: eliot_skill::AttemptLifecycleSummary) -> Self {
        Self {
            contract_version: SKILL_TRANSPORT_VERSION,
            outcome: SkillResultOutcome::Attempt(summary),
        }
    }

    /// Builds an evidence-reconciliation outcome from one validated ingest.
    ///
    /// Carries the exact presented outcome counts. A non-zero
    /// `uncertain_pending` means retry stays blocked until those executions
    /// are reconciled by exact evidence.
    pub fn evidence(observed: u64, failed: u64, uncertain_pending: u64) -> Self {
        Self {
            contract_version: SKILL_TRANSPORT_VERSION,
            outcome: SkillResultOutcome::Evidence {
                observed,
                failed,
                uncertain_pending,
            },
        }
    }

    /// Builds a refusal outcome from a driver error. Every [`SkillError`]
    /// maps to a stable code; the detail carries the owner's message.
    /// Nothing about delivery is claimed: a refusal proves only that the
    /// pair was understood and declined with a reason.
    pub fn refused(error: &eliot_skill::SkillError) -> Self {
        use eliot_skill::SkillError;
        let (code, detail) = match error {
            SkillError::FenceMismatch => (
                "FENCE_MISMATCH".to_owned(),
                "scope fence does not match the admitted fence".to_owned(),
            ),
            SkillError::InvalidField { field, reason } => {
                (format!("INVALID_FIELD:{field}"), (*reason).to_owned())
            }
            SkillError::RevisionConflict => (
                "REVISION_CONFLICT".to_owned(),
                "base revision changed under the act".to_owned(),
            ),
            SkillError::NotFound => (
                "NOT_FOUND".to_owned(),
                "named Skill has no catalogue entry".to_owned(),
            ),
            SkillError::IdentityMismatch => (
                "IDENTITY_MISMATCH".to_owned(),
                "receipt, ack, or digest binding does not match".to_owned(),
            ),
            SkillError::IndependentEvidenceRequired => (
                "EVIDENCE_REQUIRED".to_owned(),
                "promotion needs independent evidence".to_owned(),
            ),
            SkillError::NonReversiblePromotion => (
                "NON_REVERSIBLE".to_owned(),
                "promotion is not reversible".to_owned(),
            ),
            SkillError::Serialization(error) | SkillError::Surface(error) => {
                ("SURFACE".to_owned(), error.clone())
            }
            SkillError::Store(_) => (
                "STORE".to_owned(),
                "canonical store failure; see store receipt".to_owned(),
            ),
            SkillError::Duplicate { field } => (
                format!("INVALID_FIELD:{field}"),
                "duplicate field".to_owned(),
            ),
        };
        Self {
            contract_version: SKILL_TRANSPORT_VERSION,
            outcome: SkillResultOutcome::Refused { code, detail },
        }
    }
}

/// Maximum execution evidence records per ingest (issue #1191). Evidence
/// frames stay in the hot-response profile: larger windows arrive as
/// successive bounded ingests, never as giant inline frames.
///
/// The activated display projection itself is owned by
/// [`ActivatedSkillDisplay`](eliot_skill::ActivatedSkillDisplay); validation
/// stays with that owner and is re-checked by receivers.
pub const MAX_EXECUTION_RECORDS: usize = 256;

/// Harness activation receipt ingest as wire bytes (issue #1191).
///
/// Carries one per-attempt [`SkillHarnessActivationReceipt`](eliot_skill::SkillHarnessActivationReceipt)
/// binding eligibility, packet position, retrieval, delivery, observable
/// activation and adherence for one Skill revision. Decode verifies the exact
/// receipt shape from the bytes; the daemon folds the receipt into its
/// attempt summary (delivered/retrieved/activated/adhered/useful stay
/// distinct) and carries the summary back in the result envelope. The
/// producer is the harness that observed the attempt — this module mints no
/// activation claim, it only contracts the carriage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillActivationPayload {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// The observed per-attempt activation receipt.
    pub receipt: SkillHarnessActivationReceipt,
}

impl SkillActivationPayload {
    /// Encodes a validated activation ingest within the carry bound.
    pub fn encode(&self) -> Result<Vec<u8>, SkillTransportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        Ok(bytes)
    }

    /// Decodes and validates one activation ingest within the carry bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, SkillTransportError> {
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SkillTransportError> {
        check_version(self.contract_version)?;
        self.receipt
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("activate.receipt: {error}")))?;
        Ok(())
    }
}

/// Execution evidence ingest as wire bytes (issue #1191).
///
/// Carries step/artifact/verifier/outcome evidence bound to one Skill
/// revision and package digest. Decode verifies the skill binding plus every
/// record shape from the bytes; the daemon reconciles unknown effects before
/// retry (uncertain executions block retry until superseded by exact
/// evidence) and carries the reconciliation counts back in the result
/// envelope. Absent records prove nothing: only presented evidence folds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillExecutionPayload {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// Skill identity the evidence is bound to.
    pub skill_id: String,
    /// Skill revision the evidence was observed at.
    pub skill_revision: String,
    /// Package digest the evidence was observed at.
    pub package_digest: String,
    /// Presented step/artifact/verifier/outcome records.
    pub executions: Vec<SkillExecutionEvidence>,
}

impl SkillExecutionPayload {
    /// Encodes a validated evidence ingest within the carry bound.
    pub fn encode(&self) -> Result<Vec<u8>, SkillTransportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        Ok(bytes)
    }

    /// Decodes and validates one evidence ingest within the carry bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, SkillTransportError> {
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SkillTransportError> {
        check_version(self.contract_version)?;
        bounded_text(&self.skill_id, "execute.skill_id")?;
        bounded_text(&self.skill_revision, "execute.skill_revision")?;
        if self.package_digest.len() != 64
            || self
                .package_digest
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(SkillTransportError::Shape(
                "execute.package_digest: must be lowercase SHA-256 hex".to_owned(),
            ));
        }
        if self.executions.is_empty() {
            return Err(SkillTransportError::Shape(
                "execute.executions: at least one presented record is required".to_owned(),
            ));
        }
        if self.executions.len() > MAX_EXECUTION_RECORDS {
            return Err(SkillTransportError::Shape(
                "execute.executions: window exceeds the bounded ingest".to_owned(),
            ));
        }
        for execution in &self.executions {
            execution.validate().map_err(|error| {
                SkillTransportError::Shape(format!("execute.executions: {error}"))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_skill::{
        AdvisoryRuleClaim, CapabilityVersion, DependencyMaterial, LifecycleProposal, SkillBehavior,
        SkillCounters, SkillState, ToolDefinitionMaterial,
    };

    fn behavior() -> SkillBehavior {
        SkillBehavior {
            intent: "refresh the task view before a Material effect".to_owned(),
            trigger: "when demo work arrives load this skill".to_owned(),
            action: "Refresh the task view before a Material effect.".to_owned(),
            applies_when: vec!["the task view is stale".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            required_outputs: vec!["refreshed view".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            stop: "Stop and escalate on conflicting instructions.".to_owned(),
            escalation: "escalate to the task owner".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
        }
    }

    fn inputs() -> MaterializationInputs {
        MaterializationInputs {
            canonical_source_bytes: b"canonical demo source\n".to_vec(),
            contract_materialization: behavior(),
            dependencies: vec![DependencyMaterial {
                name: "tool-def-1".to_owned(),
                version: "1.2.0".to_owned(),
                contract_digest: "c".repeat(64),
            }],
            tool_definitions: vec![ToolDefinitionMaterial {
                name: "eliot.finish".to_owned(),
                version: "1.0.0".to_owned(),
                description: "typed finish attempt".to_owned(),
                capabilities: vec![CapabilityVersion {
                    name: "finish-cap".to_owned(),
                    version: "1".to_owned(),
                }],
                actions: vec!["Refresh the task view before a Material effect.".to_owned()],
            }],
        }
    }

    fn package() -> SkillPackage {
        use eliot_skill::{
            ConflictState, DistractorState, FreshnessState, QuarantineState,
            SkillInteractionProjection as InteractionProjection,
        };
        // Behavior and host are the accepted candidate's own, so the intake
        // producer binds by construction.
        let candidate = candidate();
        let inputs = inputs();
        let rule: AdvisoryRuleClaim = serde_json::from_value(serde_json::json!({
            "rule_ref": { "rule_id": "rule-demo-1", "revision": 1 }
        }))
        .expect("rule fixture");
        SkillPackage {
            registration: eliot_skill::RegistrationIdentity::new(
                "skill-demo",
                "1.0.0",
                "demo skill",
            )
            .expect("valid test registration"),
            digests: eliot_skill::PackageDigests::derive(&inputs).expect("valid test inputs"),
            host: candidate.host.clone(),
            behavior: candidate.behavior.clone(),
            counters: SkillCounters::default(),
            state: SkillState {
                freshness: FreshnessState::Current,
                conflict: ConflictState::None,
                distractor: DistractorState::None,
                quarantine: QuarantineState::Clear,
            },
            lifecycle_proposal: LifecycleProposal::Keep,
            delivery: eliot_skill::DeliveryProjection::default(),
            interaction: InteractionProjection::default(),
            rule,
        }
    }

    fn context() -> CatalogueInstallContext {
        CatalogueInstallContext {
            eligible_routes: vec!["route-1".to_owned()],
            eligible_profiles: vec!["profile-1".to_owned()],
            eligible_policies: vec!["policy-1".to_owned()],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            admitted_definition_version: "1.2.0".to_owned(),
            index_budget_tokens: 200,
            body_budget_tokens: 800,
            runtime_budget_tokens: 2000,
            index_tokens: 60,
            body_tokens: 400,
            runtime_tokens: 0,
            references: vec!["references/playbook.md".to_owned()],
            scripts: Vec::new(),
            assets: Vec::new(),
            admitted_scope: eliot_skill::SkillScope {
                task_scope: "task-scope-1".to_owned(),
                host: "host-1".to_owned(),
                route: "route-1".to_owned(),
                governance_scope: "governance-1".to_owned(),
            },
        }
    }

    fn readiness() -> ReadinessClaims {
        use eliot_skill::{Availability, AvailabilityField, VersionedObservation};
        let available = |name: &str, version: &str| VersionedObservation {
            name: name.to_owned(),
            version: version.to_owned(),
            availability: Availability::Available {
                field: AvailabilityField::HostCapability,
            },
        };
        ReadinessClaims {
            host: "codex".to_owned(),
            profile: "default".to_owned(),
            provider: Availability::Available {
                field: AvailabilityField::Provider,
            },
            g16: Availability::Available {
                field: AvailabilityField::G16,
            },
            a06: Availability::Available {
                field: AvailabilityField::A06,
            },
            evidence: Availability::Available {
                field: AvailabilityField::Evidence,
            },
            tools: vec![available("eliot.finish", "1.0.0")],
            capabilities: vec![available("finish-cap", "1")],
        }
    }

    fn scope() -> MaterializationScope {
        use eliot_contracts::{EpochId, EpochLineageId, ProductId, ResourceGeneration, StateFence};
        use eliot_receipts::{WorkScopeBinding, WorkScopeId};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        let epoch =
            EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("valid test epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"));
        MaterializationScope {
            work_scope: WorkScopeBinding {
                scope_id: WorkScopeId::new("workscope-1").expect("valid test scope"),
                product_id: ProductId::new("test-product").expect("test product"),
                resource_generation: ResourceGeneration::new(1).expect("test generation"),
                state_fence: fence,
            },
            task: None,
        }
    }

    /// Mirrors [`behavior`] as the accepted procedure definition the intake
    /// candidate binds: same trigger, action, obligations, stop, and exact
    /// tool/capability revisions.
    fn candidate_definition() -> eliot_skill::ProcedureDefinition {
        eliot_skill::ProcedureDefinition {
            name: "demo orientation".to_owned(),
            purpose: "refresh the task view before a Material effect".to_owned(),
            trigger: "when demo work arrives load this skill".to_owned(),
            action: "Refresh the task view before a Material effect.".to_owned(),
            applies_when: vec!["the task view is stale".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            required_inputs: vec!["the exact task".to_owned()],
            ordered_steps: vec!["refresh the task view".to_owned()],
            expected_outputs: vec!["refreshed view".to_owned()],
            stop_conditions: vec!["Stop and escalate on conflicting instructions.".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            escalation: "escalate to the task owner".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
            rollback_or_recovery: "restore the prior revision".to_owned(),
            required_tools: vec![eliot_skill::VersionedRequirement {
                name: "eliot.finish".to_owned(),
                version: "1.0.0".to_owned(),
            }],
            required_capabilities: vec![eliot_skill::VersionedRequirement {
                name: "finish-cap".to_owned(),
                version: "1".to_owned(),
            }],
        }
    }

    fn candidate_target() -> eliot_skill::TargetProfile {
        eliot_skill::TargetProfile {
            target_id: "candidate-target".to_owned(),
            host: "codex".to_owned(),
            profile: "default".to_owned(),
            fingerprint: "3".repeat(64),
            available_tools: vec![eliot_skill::VersionedRequirement {
                name: "eliot.finish".to_owned(),
                version: "1.0.0".to_owned(),
            }],
            available_capabilities: vec![eliot_skill::VersionedRequirement {
                name: "finish-cap".to_owned(),
                version: "1".to_owned(),
            }],
        }
    }

    fn candidate_fence() -> eliot_contracts::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        StateFence::new(
            EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("valid test epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn acceptance_receipt(state_fence: eliot_contracts::StateFence) -> eliot_skill::ReceiptClaim {
        use eliot_contracts::{
            ArtifactId, ClockReading, ContractId, OperationId, ProductId, RequestId, SessionId,
            SourceId, TaskId, TaskRevision, TransactionSequence,
        };
        use eliot_receipts::{
            ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding,
            ProofCeiling, ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind,
            RequestBinding, SessionBinding, TaskBinding, VerifierBinding, WorkScopeBinding,
            WorkScopeId,
        };

        let request_id = RequestId::new("request-1").expect("request id");
        let task_id = TaskId::new("task-1").expect("task id");
        let metadata = eliot_receipts::RequestMetadata {
            request_id: request_id.clone(),
            session_id: Some(SessionId::new("session-1").expect("session id")),
            task_id: Some(task_id),
            product_id: ProductId::new("test-product").expect("product id"),
            source_id: SourceId::new("source-1").expect("source id"),
            state_fence: state_fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(10),
                known_time_ms: Some(11),
                transaction_sequence: Some(TransactionSequence::genesis()),
                monotonic_ns: Some(12),
            },
        };
        let verifier_artifact_id = ArtifactId::new("verifier-artifact-1").expect("artifact id");
        let rollback_artifact_id = ArtifactId::new("rollback-artifact-1").expect("artifact id");
        let work_scope = WorkScopeBinding {
            scope_id: WorkScopeId::new("workscope-1").expect("valid test scope"),
            product_id: ProductId::new("test-product").expect("test product"),
            resource_generation: eliot_contracts::ResourceGeneration::new(1)
                .expect("test generation"),
            state_fence: state_fence.clone(),
        };
        let task = TaskBinding {
            task_id: TaskId::new("task-1").expect("task id"),
            task_revision: TaskRevision::genesis(),
            state_fence: state_fence.clone(),
        };
        let core = ReceiptCore {
            contract: eliot_receipts::contract_identity().expect("receipt contract"),
            kind: ReceiptKind::Verification,
            work_scope: work_scope.clone(),
            task: Some(task.clone()),
            session: Some(SessionBinding {
                session_id: SessionId::new("session-1").expect("session id"),
                authority_epoch: state_fence.authority_epoch.clone(),
                state_fence: state_fence.clone(),
            }),
            causal: CausalBinding {
                state_fence: state_fence.clone(),
                transaction_sequence: TransactionSequence::genesis(),
                parent_receipt_id: None,
                predecessor_receipt_ids: Vec::new(),
            },
            request: RequestBinding {
                metadata,
                state_fence: state_fence.clone(),
            },
            operation: OperationBinding {
                operation_id: OperationId::new("operation-1").expect("operation id"),
                request_id,
                idempotency_key: "accept-procedure".to_owned(),
                operation_kind: "procedure.accept".to_owned(),
                effect: EffectClass::Read,
                state_fence: state_fence.clone(),
            },
            authority: AuthorityBinding {
                authority_id: ContractId::new("authority-1").expect("authority id"),
                authority_owner: "governor.skill".to_owned(),
                authority_epoch: state_fence.authority_epoch.clone(),
                state_fence: state_fence.clone(),
                allowed_effect: EffectClass::Read,
                proof_ceiling: ProofCeiling::ScopedVerification,
            },
            artifacts: vec![
                ArtifactBinding {
                    artifact_id: verifier_artifact_id.clone(),
                    sha256: eliot_receipts::sha256_hex(b"accepted-procedure"),
                    role: ReceiptKind::Artifact,
                    source_revision: Some("revision-1".to_owned()),
                },
                ArtifactBinding {
                    artifact_id: rollback_artifact_id,
                    sha256: eliot_receipts::sha256_hex(b"rollback-procedure"),
                    role: ReceiptKind::Artifact,
                    source_revision: Some("revision-1".to_owned()),
                },
            ],
            verifier: Some(VerifierBinding {
                verifier_id: ContractId::new("procedure-verifier").expect("verifier id"),
                verifier_revision: eliot_contracts::ContractVersion::new(1, 0, 0),
                artifact_ids: vec![verifier_artifact_id],
                proof_ceiling: ProofCeiling::ScopedVerification,
                state_fence: state_fence.clone(),
            }),
            problem: None,
            coordination: None,
            disposition: ReceiptDisposition::Success {
                proof: ProofCeiling::ScopedVerification,
            },
        };
        let envelope = ReceiptEnvelope::issue(core).expect("accepted receipt");
        eliot_skill::ReceiptClaim {
            evidence_ref: "receipt-evidence-1".to_owned(),
            envelope,
        }
    }

    fn candidate_procedure() -> eliot_skill::GovernedProcedureProjection {
        let state_fence = candidate_fence();
        let receipt = acceptance_receipt(state_fence.clone());
        let mut projection = eliot_skill::GovernedProcedureProjection {
            schema_version: eliot_skill::GOVERNED_PROCEDURE_PROJECTION_SCHEMA_VERSION.to_owned(),
            procedure_id: "procedure-1".to_owned(),
            procedure_revision: "revision-1".to_owned(),
            procedure_digest: "0".repeat(64),
            state: eliot_skill::ProcedureState::Accepted,
            state_fence: state_fence.clone(),
            work_scope: receipt.envelope.core.work_scope.clone(),
            task: receipt.envelope.core.task.clone().expect("task binding"),
            acceptance_receipt: receipt,
            definition: candidate_definition(),
            evidence: eliot_skill::ProcedureEvidence {
                source_refs: vec!["source-1".to_owned()],
                receipt_refs: vec!["receipt-evidence-1".to_owned()],
                applicability_refs: vec!["applicability-1".to_owned()],
                counterexample_refs: vec!["counterexample-1".to_owned()],
                negative_trigger_refs: vec!["negative-trigger-1".to_owned()],
                verifier_artifact_refs: vec!["verifier-artifact-1".to_owned()],
                rollback_artifact_ref: "rollback-artifact-1".to_owned(),
            },
            verifier: eliot_skill::ProcedureVerifier {
                verifier_ref: "procedure-verifier".to_owned(),
                verifier_revision: "1.0.0".to_owned(),
                artifact_refs: vec!["verifier-artifact-1".to_owned()],
            },
            safety_privacy_disclosure: eliot_skill::SafetyPrivacyDisclosure {
                safety_owner_ref: "safety-owner".to_owned(),
                safety_evidence_refs: vec!["safety-1".to_owned()],
                privacy_owner_ref: "privacy-owner".to_owned(),
                privacy_evidence_refs: vec!["privacy-1".to_owned()],
                disclosure_owner_ref: "disclosure-owner".to_owned(),
                disclosure_evidence_refs: vec!["disclosure-1".to_owned()],
            },
            assets: vec![eliot_skill::InertAsset {
                asset_ref: "asset-1".to_owned(),
                sha256: eliot_receipts::sha256_hex(b"asset"),
                role: "reference".to_owned(),
                executable: false,
            }],
        };
        projection.procedure_digest = projection.expected_digest().expect("procedure digest");
        projection
    }

    fn candidate() -> eliot_skill::PortableSkillPackageCandidate {
        let projection = eliot_skill::project_governed_procedure_to_portable_skill_candidates(
            &candidate_procedure(),
            &[candidate_target()],
        )
        .expect("projection");
        assert_eq!(projection.candidates.len(), 1);
        projection.candidates[0].clone()
    }

    fn intake() -> SkillIntakePayload {
        // The intake producer is the only construction path: stamping,
        // binding, and shape validation run here, never hand-rolled.
        SkillIntakePayload::produce(
            candidate(),
            package(),
            inputs(),
            context(),
            readiness(),
            scope(),
            "hotset-wire-1".to_owned(),
            "approval-commit-1".to_owned(),
        )
        .expect("fixture produces bound intake")
    }

    #[test]
    fn intake_round_trip_preserves_the_admitted_claim() {
        let bytes = intake().encode().expect("valid intake encodes");
        assert!(bytes.len() <= MAX_INTAKE_BYTES);
        let decoded = SkillIntakePayload::decode(&bytes).expect("valid intake decodes");
        assert_eq!(decoded, intake());
    }

    #[test]
    fn intake_wire_rejects_bad_version_oversize_and_malformed() {
        let mut versioned = intake();
        versioned.contract_version = SKILL_TRANSPORT_VERSION + 1;
        assert!(matches!(
            versioned.encode(),
            Err(SkillTransportError::BadVersion)
        ));
        assert!(matches!(
            SkillIntakePayload::decode(&vec![0_u8; MAX_INTAKE_BYTES + 1]),
            Err(SkillTransportError::TooLarge)
        ));
        assert!(matches!(
            SkillIntakePayload::decode(b"{not json"),
            Err(SkillTransportError::Shape(_))
        ));
        let mut blanked = intake();
        blanked.approval_ref = "   ".to_owned();
        assert!(matches!(
            blanked.encode(),
            Err(SkillTransportError::Shape(_))
        ));
    }

    #[test]
    fn intake_wire_rejects_a_non_candidate_claim() {
        // An activated candidate is not a materialization request: decode
        // refuses the wire claim before any catalogue, readiness, or sealed
        // gate runs.
        let mut activated = intake();
        activated.candidate.activation_applied = true;
        assert!(matches!(
            activated.encode(),
            Err(SkillTransportError::Shape(_))
        ));
    }

    #[test]
    fn ack_carriage_binds_applied_ack_to_its_receipt() {
        let receipt = eliot_skill::HotsetDeliveryReceipt {
            hotset_id: "hotset-1".to_owned(),
            catalogue_digest: "c".repeat(64),
            delivered_skill_ids: vec!["skill-demo".to_owned()],
            body_digests: [("skill-demo".to_owned(), "d".repeat(64))]
                .into_iter()
                .collect(),
            approval_ref: "approval-1".to_owned(),
            provisional: true,
            receipt_digest: String::new(),
        };
        // A hand-minted digest cannot bind: the requester must carry the
        // catalogue-issued receipt, never synthesize one.
        let minted = SkillAckPayload {
            contract_version: SKILL_TRANSPORT_VERSION,
            receipt: receipt.clone(),
            ack: eliot_skill::HotsetDeliveryAck {
                hotset_id: receipt.hotset_id.clone(),
                receipt_digest: receipt.receipt_digest.clone(),
                receiver_id: "runtime-hotset-1".to_owned(),
                disposition: eliot_skill::HotsetAckDisposition::Applied,
            },
        };
        assert!(matches!(
            minted.encode(),
            Err(SkillTransportError::Shape(_))
        ));
        // A foreign ack for a bound receipt refuses on the binding.
        let mut foreign = receipt.clone();
        foreign.receipt_digest = "d".repeat(64);
        let ack = eliot_skill::HotsetDeliveryAck {
            hotset_id: foreign.hotset_id.clone(),
            receipt_digest: "e".repeat(64),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: eliot_skill::HotsetAckDisposition::Applied,
        };
        // The foreign receipt itself fails shape first (unbound digest).
        assert!(matches!(
            SkillAckPayload {
                contract_version: SKILL_TRANSPORT_VERSION,
                receipt: foreign,
                ack,
            }
            .encode(),
            Err(SkillTransportError::Shape(_))
        ));
    }

    #[test]
    fn skill_tool_names_route_exactly_two_kinds() {
        assert_eq!(skill_tool_kind("skill.inject"), Some(SkillToolKind::Inject));
        assert_eq!(
            skill_tool_kind("skill.display"),
            Some(SkillToolKind::Display)
        );
        assert_eq!(skill_tool_kind("eliot.query"), None);
        assert_eq!(skill_tool_kind(""), None);
        assert_eq!(skill_tool_kind("skill.inject "), None);
    }

    #[test]
    fn refusal_envelope_codes_driver_errors_without_claiming_delivery() {
        use eliot_skill::SkillError;
        let refused = SkillResultEnvelope::refused(&SkillError::FenceMismatch);
        assert!(matches!(
            &refused.outcome,
            SkillResultOutcome::Refused { code, .. } if code == "FENCE_MISMATCH"
        ));
        let bytes = serde_json::to_vec(&refused).expect("refusal encodes");
        let decoded: SkillResultEnvelope = serde_json::from_slice(&bytes).expect("refusal decodes");
        assert_eq!(decoded, refused);
    }

    struct CarryTools;

    impl eliot_skill::KnownTools for CarryTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish"
        }
    }

    fn issued_pair() -> (
        eliot_skill::HotsetDeliveryReceipt,
        eliot_skill::HotsetDeliveryAck,
    ) {
        use eliot_skill::{
            DependencyVersion, SkillBody, SkillCatalogue, SkillCatalogueEntry, SkillIndexEntry,
            SkillRuntimeMetadata, SkillStatus,
        };
        let mut body = SkillBody {
            skill_id: "skill-demo".to_owned(),
            body_version: "1.0.0".to_owned(),
            body_digest: String::new(),
            actions: vec!["Refresh the task view before a Material effect.".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            stop_escalation: "Stop and escalate on conflicting instructions.".to_owned(),
            tool_refs: vec!["eliot.finish".to_owned()],
        };
        body.body_digest = body.expected_digest().expect("body digest");
        let index = SkillIndexEntry {
            skill_id: "skill-demo".to_owned(),
            name: "demo skill".to_owned(),
            trigger: "when demo work arrives load this skill".to_owned(),
            eligible_routes: vec!["route-1".to_owned()],
            eligible_profiles: vec!["profile-1".to_owned()],
            eligible_policies: vec!["policy-1".to_owned()],
        };
        let runtime = SkillRuntimeMetadata {
            skill_id: "skill-demo".to_owned(),
            body_version: "1.0.0".to_owned(),
            references: vec!["references/playbook.md".to_owned()],
            scripts: Vec::new(),
            assets: Vec::new(),
            index_budget_tokens: 200,
            body_budget_tokens: 800,
            runtime_budget_tokens: 2000,
            index_tokens: 60,
            body_tokens: 400,
            runtime_tokens: 0,
        };
        let dependencies = vec![DependencyVersion {
            name: "tool-def-1".to_owned(),
            version: "1.2.0".to_owned(),
            contract_digest: "c".repeat(64),
        }];
        let host_version = "host-4.1.0".to_owned();
        let profile_version = "profile-2.0.0".to_owned();
        let admitted_definition_version = "1.2.0".to_owned();
        let validation = eliot_skill::StructuralValidationReport::record(
            &index,
            &body,
            &runtime,
            &dependencies,
            &host_version,
            &profile_version,
            &admitted_definition_version,
        )
        .expect("validation report");
        let entry = SkillCatalogueEntry {
            index,
            body,
            runtime,
            dependencies,
            host_version,
            profile_version,
            admitted_definition_version,
            status: SkillStatus::Provisional,
            stale_reason: None,
            scope: eliot_skill::SkillScope {
                task_scope: "task-scope-1".to_owned(),
                host: "host-1".to_owned(),
                route: "route-1".to_owned(),
                governance_scope: "governance-1".to_owned(),
            },
            validation,
            promotion_evidence: None,
        };
        let catalogue =
            SkillCatalogue::from_snapshot([entry], &CarryTools).expect("carry catalogue");
        let receipt = eliot_skill::HotsetDeliveryReceipt::issue(
            "hotset-1".to_owned(),
            &catalogue,
            vec!["skill-demo".to_owned()],
            &CarryTools,
            "approval-1".to_owned(),
        )
        .expect("carry receipt");
        let ack = eliot_skill::HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: eliot_skill::HotsetAckDisposition::Applied,
        };
        (receipt, ack)
    }

    #[test]
    fn ack_carriage_round_trip_preserves_a_bound_pair() {
        // A catalogue-issued receipt with its applied ack encodes, decodes,
        // and compares equal: the carriage is transparent for bound pairs.
        let (receipt, ack) = issued_pair();
        let carried = SkillAckPayload {
            contract_version: SKILL_TRANSPORT_VERSION,
            receipt,
            ack,
        };
        let bytes = carried.encode().expect("bound pair encodes");
        assert!(bytes.len() <= MAX_CARRY_BYTES);
        let decoded = SkillAckPayload::decode(&bytes).expect("bound pair decodes");
        assert_eq!(decoded, carried);
    }

    #[test]
    fn display_request_round_trip_names_its_delivered_skill() {
        let (receipt, ack) = issued_pair();
        let request = SkillDisplayPayload {
            contract_version: SKILL_TRANSPORT_VERSION,
            skill_id: "skill-demo".to_owned(),
            receipt,
            ack,
        };
        let bytes = request.encode().expect("display request encodes");
        let decoded = SkillDisplayPayload::decode(&bytes).expect("display request decodes");
        assert_eq!(decoded, request);
        let mut blanked = request;
        blanked.skill_id = "   ".to_owned();
        assert!(matches!(
            blanked.encode(),
            Err(SkillTransportError::Shape(_))
        ));
    }
}
