use std::collections::{BTreeMap, BTreeSet};

use eliot_evidence::evidence_shape_digest;
use eliot_receipts::{
    EffectClass, ProofCeiling, ReceiptDispositionKind, ReceiptEnvelope, ReceiptKind, TaskBinding,
    WorkScopeBinding,
};
use eliot_rules::{RuleCatalogueEntry, RuleClass, RuleRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DIGEST_LENGTH: usize = 64;

/// A failure in the generated Skill/host-package contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SkillContractError {
    /// A required value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A field is not a lowercase SHA-256 digest.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// A required list is empty.
    #[error("{field} must contain at least one entry")]
    MissingRequired { field: &'static str },
    /// A collection or short contract has contradictory structure.
    #[error("ambiguous Skill structure: {reason}")]
    AmbiguousStructure { reason: &'static str },
    /// A caller-provided digest does not match the actual canonical input.
    #[error("materialization digest mismatch: {field}")]
    MaterializationDigestMismatch { field: &'static str },
    /// A later lifecycle state was claimed without its exact evidence predecessor.
    #[error("invalid lifecycle projection: {field} requires {required}")]
    LifecycleOrder {
        field: &'static str,
        required: &'static str,
    },
    /// Lifecycle flags, counts, and evidence are not bijective.
    #[error("lifecycle count/evidence contradiction: {field}")]
    LifecycleContradiction { field: &'static str },
    /// A canonical receipt does not bind the exact package/task/scope event.
    #[error("receipt binding mismatch: {field}")]
    ReceiptBindingMismatch { field: &'static str },
    /// Registration identity was not derived from the exact registration.
    #[error("registration identity digest mismatch")]
    RegistrationDigestMismatch,
    /// A claimed causal effect is outside this surface's proof ceiling.
    #[error("causal credit is not owned by the Skill execution projection")]
    CausalCreditEscalation,
    /// Availability reason code and field disagree.
    #[error("availability code does not match field {field}")]
    AvailabilityCodeMismatch { field: &'static str },
    /// A host tool/capability is absent or at the wrong version.
    #[error("unsupported tool or capability: {field}")]
    UnsupportedCapability { field: &'static str },
    /// The rendered short contract exceeds its host limit.
    #[error("rendered short contract exceeds max_description_chars")]
    DescriptionTooLong,
    /// A reversible lifecycle proposal lacks its exact review/owner/rollback binding.
    #[error("invalid reversible lifecycle proposal: {field}")]
    InvalidLifecycleProposal { field: &'static str },
    /// A sealed verification/readiness provider is absent or rejected the request.
    #[error("PLAN_GAP {code:?}: {reason}")]
    PlanGap {
        code: UnavailableCode,
        reason: String,
    },
    /// A verified rule did not match the exact catalogue reference/provenance.
    #[error("G-16 rule verification mismatch")]
    RuleVerificationMismatch,
    /// A deterministic contract hash could not be produced.
    #[error("cannot compute canonical Skill digest: {0}")]
    Canonicalization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), SkillContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(SkillContractError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validate_list(values: &[String], field: &'static str) -> Result<(), SkillContractError> {
    if values.is_empty() {
        return Err(SkillContractError::MissingRequired { field });
    }
    for value in values {
        validate_text(value, field)?;
    }
    unique(values, field)
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), SkillContractError> {
    if value.len() != DIGEST_LENGTH
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(SkillContractError::InvalidDigest { field });
    }
    Ok(())
}

fn unique(values: &[String], field: &'static str) -> Result<(), SkillContractError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(SkillContractError::AmbiguousStructure { reason: field });
    }
    Ok(())
}

fn raw_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Registration identity for one generated Skill revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationIdentity {
    /// Stable Skill identity.
    pub skill_id: String,
    /// Source revision represented by this package.
    pub revision: String,
    /// Human-readable registration name.
    pub name: String,
    /// Digest derived from `skill_id`, `revision`, and `name`.
    pub registration_digest: String,
}

impl RegistrationIdentity {
    /// Builds a registration identity and derives its digest.
    pub fn new(
        skill_id: impl Into<String>,
        revision: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, SkillContractError> {
        let mut identity = Self {
            skill_id: skill_id.into(),
            revision: revision.into(),
            name: name.into(),
            registration_digest: String::new(),
        };
        identity.validate_text_fields()?;
        identity.registration_digest = identity.expected_digest()?;
        Ok(identity)
    }

    fn validate_text_fields(&self) -> Result<(), SkillContractError> {
        validate_text(&self.skill_id, "registration.skill_id")?;
        validate_text(&self.revision, "registration.revision")?;
        validate_text(&self.name, "registration.name")
    }

    /// Computes the deterministic identity digest for this registration.
    pub fn expected_digest(&self) -> Result<String, SkillContractError> {
        canonical_digest(&(&self.skill_id, &self.revision, &self.name))
    }

    fn validate(&self) -> Result<(), SkillContractError> {
        self.validate_text_fields()?;
        validate_digest(
            &self.registration_digest,
            "registration.registration_digest",
        )?;
        if self.expected_digest()? != self.registration_digest {
            return Err(SkillContractError::RegistrationDigestMismatch);
        }
        Ok(())
    }
}

/// One exact dependency used to materialize the host package.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyMaterial {
    /// Package or contract name.
    pub name: String,
    /// Exact version/revision.
    pub version: String,
    /// Exact public contract identity digest.
    pub contract_digest: String,
}

impl DependencyMaterial {
    fn validate(&self) -> Result<(), SkillContractError> {
        validate_text(&self.name, "inputs.dependencies.name")?;
        validate_text(&self.version, "inputs.dependencies.version")?;
        validate_digest(&self.contract_digest, "inputs.dependencies.contract_digest")
    }
}

/// One versioned capability exposed by an actual host tool definition.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityVersion {
    /// Stable capability name.
    pub name: String,
    /// Exact capability version.
    pub version: String,
}

impl CapabilityVersion {
    fn validate(&self, field: &'static str) -> Result<(), SkillContractError> {
        validate_text(&self.name, field)?;
        validate_text(&self.version, field)
    }
}

/// Canonical materialized definition of an actual host tool.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinitionMaterial {
    /// Exact tool name.
    pub name: String,
    /// Exact tool definition version.
    pub version: String,
    /// Description rendered by the host.
    pub description: String,
    /// Capabilities supplied by this tool revision.
    pub capabilities: Vec<CapabilityVersion>,
    /// Action text materialized from this definition.
    pub actions: Vec<String>,
}

impl ToolDefinitionMaterial {
    fn validate(&self) -> Result<(), SkillContractError> {
        validate_text(&self.name, "inputs.tool.name")?;
        validate_text(&self.version, "inputs.tool.version")?;
        validate_text(&self.description, "inputs.tool.description")?;
        for capability in &self.capabilities {
            capability.validate("inputs.tool.capability")?;
        }
        let capability_keys: Vec<_> = self
            .capabilities
            .iter()
            .map(|value| format!("{}@{}", value.name, value.version))
            .collect();
        unique(&capability_keys, "inputs.tool.capability")?;
        for action in &self.actions {
            validate_text(action, "inputs.tool.actions")?;
            if action.lines().count() != 1 {
                return Err(SkillContractError::AmbiguousStructure {
                    reason: "tool actions must be one line",
                });
            }
        }
        Ok(())
    }
}

/// Actual canonical bytes and definitions used for one materialization attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationInputs {
    /// Canonical source bytes, hashed directly rather than as a caller digest string.
    pub canonical_source_bytes: Vec<u8>,
    /// Actual contract shape materialized by A-15.
    pub contract_materialization: SkillBehavior,
    /// Actual exact dependencies used during materialization.
    pub dependencies: Vec<DependencyMaterial>,
    /// Actual host tool definitions used during materialization.
    pub tool_definitions: Vec<ToolDefinitionMaterial>,
}

impl MaterializationInputs {
    fn validate(&self) -> Result<(), SkillContractError> {
        if self.canonical_source_bytes.is_empty() {
            return Err(SkillContractError::MissingRequired {
                field: "inputs.canonical_source_bytes",
            });
        }
        self.contract_materialization.validate()?;
        if self.dependencies.is_empty() {
            return Err(SkillContractError::MissingRequired {
                field: "inputs.dependencies",
            });
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        if self.tool_definitions.is_empty() {
            return Err(SkillContractError::MissingRequired {
                field: "inputs.tool_definitions",
            });
        }
        let mut tool_keys = BTreeSet::new();
        for tool in &self.tool_definitions {
            tool.validate()?;
            if !tool_keys.insert((&tool.name, &tool.version)) {
                return Err(SkillContractError::AmbiguousStructure {
                    reason: "duplicate exact tool definition name/version",
                });
            }
        }
        Ok(())
    }
}

/// Derived canonical source and dependency identities carried by a host package.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDigests {
    /// SHA-256 over the exact canonical source bytes.
    pub source_digest: String,
    /// Canonical digest of the actual short-contract materialization.
    pub contract_digest: String,
    /// Canonical digest of sorted exact dependency material.
    pub dependency_digest: String,
    /// Canonical digest of sorted actual tool definitions.
    pub tool_definition_digest: String,
}

impl PackageDigests {
    /// Derives all identities from actual canonical materialization inputs.
    pub fn derive(inputs: &MaterializationInputs) -> Result<Self, SkillContractError> {
        inputs.validate()?;
        let mut dependencies = inputs.dependencies.clone();
        dependencies.sort();
        let mut tools = inputs.tool_definitions.clone();
        tools.sort();
        Ok(Self {
            source_digest: raw_sha256(&inputs.canonical_source_bytes),
            contract_digest: canonical_digest(&inputs.contract_materialization)?,
            dependency_digest: canonical_digest(&dependencies)?,
            tool_definition_digest: canonical_digest(&tools)?,
        })
    }

    fn validate_against(&self, inputs: &MaterializationInputs) -> Result<(), SkillContractError> {
        for (value, field) in [
            (&self.source_digest, "digests.source_digest"),
            (&self.contract_digest, "digests.contract_digest"),
            (&self.dependency_digest, "digests.dependency_digest"),
            (
                &self.tool_definition_digest,
                "digests.tool_definition_digest",
            ),
        ] {
            validate_digest(value, field)?;
        }
        let derived = Self::derive(inputs)?;
        for (actual, expected, field) in [
            (&self.source_digest, &derived.source_digest, "source_digest"),
            (
                &self.contract_digest,
                &derived.contract_digest,
                "contract_digest",
            ),
            (
                &self.dependency_digest,
                &derived.dependency_digest,
                "dependency_digest",
            ),
            (
                &self.tool_definition_digest,
                &derived.tool_definition_digest,
                "tool_definition_digest",
            ),
        ] {
            if actual != expected {
                return Err(SkillContractError::MaterializationDigestMismatch { field });
            }
        }
        Ok(())
    }
}

/// Exact requirement for a tool revision or host capability revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedRequirement {
    /// Stable tool/capability name.
    pub name: String,
    /// Exact required version.
    pub version: String,
}

impl VersionedRequirement {
    fn validate(&self, field: &'static str) -> Result<(), SkillContractError> {
        validate_text(&self.name, field)?;
        validate_text(&self.version, field)
    }
}

/// Exact host/profile and bounded tool/capability surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfile {
    /// Exact host adapter identity.
    pub host: String,
    /// Exact host profile identity.
    pub profile: String,
    /// Exact required tool revisions.
    pub required_tools: Vec<VersionedRequirement>,
    /// Exact required capability revisions.
    pub required_capabilities: Vec<VersionedRequirement>,
    /// Explicit package limits.
    pub limits: HostLimits,
}

impl HostProfile {
    pub(crate) fn validate(&self) -> Result<(), SkillContractError> {
        validate_text(&self.host, "host.host")?;
        validate_text(&self.profile, "host.profile")?;
        if self.required_tools.is_empty() {
            return Err(SkillContractError::MissingRequired {
                field: "host.required_tools",
            });
        }
        if self.required_capabilities.is_empty() {
            return Err(SkillContractError::MissingRequired {
                field: "host.required_capabilities",
            });
        }
        for requirement in &self.required_tools {
            requirement.validate("host.required_tools")?;
        }
        for requirement in &self.required_capabilities {
            requirement.validate("host.required_capabilities")?;
        }
        let tool_keys: Vec<_> = self
            .required_tools
            .iter()
            .map(|value| format!("{}@{}", value.name, value.version))
            .collect();
        unique(&tool_keys, "host.required_tools")?;
        let capability_keys: Vec<_> = self
            .required_capabilities
            .iter()
            .map(|value| format!("{}@{}", value.name, value.version))
            .collect();
        unique(&capability_keys, "host.required_capabilities")?;
        self.limits.validate()
    }
}

/// Hard limits for a generated host package.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimits {
    /// Maximum rendered instruction characters.
    pub max_description_chars: u32,
    /// Must be exactly one for a short Skill contract.
    pub max_actions: u16,
    /// Maximum number of expansion handles.
    pub max_expansion_handles: u16,
}

impl HostLimits {
    fn validate(&self) -> Result<(), SkillContractError> {
        if self.max_description_chars == 0 {
            return Err(SkillContractError::MissingRequired {
                field: "host.limits.max_description_chars",
            });
        }
        if self.max_actions != 1 {
            return Err(SkillContractError::AmbiguousStructure {
                reason: "host.limits.max_actions must equal one",
            });
        }
        Ok(())
    }
}

/// Explicit A7.10 short-contract behavior, outputs, and writeback obligations.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillBehavior {
    /// Concise reason this Skill exists for the current request.
    pub intent: String,
    /// One observable trigger.
    pub trigger: String,
    /// Exactly one primary action line.
    pub action: String,
    /// Situations in which this Skill applies.
    pub applies_when: Vec<String>,
    /// Situations in which it must not apply.
    pub where_not_apply: Vec<String>,
    /// Required observable outputs.
    pub required_outputs: Vec<String>,
    /// Required governed writebacks or explicit `NONE` declaration.
    pub required_writebacks: Vec<String>,
    /// Typed stop condition.
    pub stop: String,
    /// Escalation path when the stop condition is reached.
    pub escalation: String,
    /// Challenge behavior for a suspected false block or conflict.
    pub challenge: String,
}

impl SkillBehavior {
    pub(crate) fn validate(&self) -> Result<(), SkillContractError> {
        validate_text(&self.intent, "behavior.intent")?;
        validate_text(&self.trigger, "behavior.trigger")?;
        validate_text(&self.action, "behavior.action")?;
        if self.action.lines().count() != 1 {
            return Err(SkillContractError::AmbiguousStructure {
                reason: "behavior.action must contain exactly one action line",
            });
        }
        validate_list(&self.applies_when, "behavior.applies_when")?;
        validate_list(&self.where_not_apply, "behavior.where_not_apply")?;
        validate_list(&self.required_outputs, "behavior.required_outputs")?;
        validate_list(&self.required_writebacks, "behavior.required_writebacks")?;
        validate_text(&self.stop, "behavior.stop")?;
        validate_text(&self.escalation, "behavior.escalation")?;
        validate_text(&self.challenge, "behavior.challenge")
    }

    fn rendered_description(&self) -> String {
        [
            self.intent.as_str(),
            self.trigger.as_str(),
            self.action.as_str(),
            &self.applies_when.join(";"),
            &self.where_not_apply.join(";"),
            &self.required_outputs.join(";"),
            &self.required_writebacks.join(";"),
            self.stop.as_str(),
            self.escalation.as_str(),
            self.challenge.as_str(),
        ]
        .join("\n")
    }
}

/// Public receipt-shaped wire claim. It has no authority until a sealed port accepts it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptClaim {
    /// Canonical immutable receipt envelope.
    pub envelope: ReceiptEnvelope,
    /// Exact evidence locator bound by G-16/evidence verification.
    pub evidence_ref: String,
}

impl ReceiptClaim {
    fn validate(&self) -> Result<(), SkillContractError> {
        validate_text(&self.evidence_ref, "receipt.evidence_ref")?;
        self.envelope
            .validate()
            .map_err(|_| SkillContractError::ReceiptBindingMismatch {
                field: "receipt.envelope",
            })
    }
}

/// Proof ceiling for an execution observation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionOutcome {
    /// Procedure steps were observed, with no verifier success claim.
    Observed,
    /// A bounded operation failed.
    Failed,
    /// External state remains unknown.
    Uncertain,
}

/// Causal interpretation deliberately stops below causal credit.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalCredit {
    /// No causal claim is made.
    None,
    /// Causal contribution is unknown.
    Uncertain,
    /// A causal claim is rejected by this surface.
    Claimed,
}

/// One execution observation and its exact canonical receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidenceProjection {
    /// Exact observed procedure step references.
    pub step_refs: Vec<String>,
    /// Exact operation receipt claim.
    pub receipt: ReceiptClaim,
    /// Bounded outcome classification.
    pub outcome: ExecutionOutcome,
    /// Causal interpretation ceiling.
    pub causal_credit: CausalCredit,
}

impl ExecutionEvidenceProjection {
    fn validate(&self) -> Result<(), SkillContractError> {
        validate_list(&self.step_refs, "execution.step_refs")?;
        self.receipt.validate()?;
        if self.causal_credit == CausalCredit::Claimed {
            return Err(SkillContractError::CausalCreditEscalation);
        }
        let core = &self.receipt.envelope.core;
        if core.kind != ReceiptKind::Operation {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "execution.receipt.kind",
            });
        }
        let disposition = core.disposition.kind();
        match self.outcome {
            ExecutionOutcome::Observed
                if disposition == ReceiptDispositionKind::Success && core.verifier.is_none() =>
            {
                Ok(())
            }
            ExecutionOutcome::Failed if disposition == ReceiptDispositionKind::Failure => Ok(()),
            ExecutionOutcome::Uncertain if disposition == ReceiptDispositionKind::Unknown => Ok(()),
            ExecutionOutcome::Observed => Err(SkillContractError::LifecycleContradiction {
                field: "execution.observed_requires_unverified_success",
            }),
            ExecutionOutcome::Failed => Err(SkillContractError::LifecycleContradiction {
                field: "execution.failed_requires_failure_receipt",
            }),
            ExecutionOutcome::Uncertain => Err(SkillContractError::LifecycleContradiction {
                field: "execution.uncertain_requires_unknown_receipt",
            }),
        }
    }
}

/// Explicit lifecycle counters. Every value is bijective with exact evidence.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCounters {
    /// Canonical installation observations.
    pub installed_count: u64,
    /// Canonical delivery observations.
    pub delivery_count: u64,
    /// Explicit expansion observations.
    pub expansion_count: u64,
    /// Canonical execution observations.
    pub execution_count: u64,
    /// Verifier-backed outcomes.
    pub verified_count: u64,
    /// Failed outcomes.
    pub failed_count: u64,
    /// Uncertain outcomes, including non-verified observations.
    pub uncertain_count: u64,
    /// Canonical useful-outcome observations.
    pub useful_count: u64,
}

/// Installed, delivered, executed, verified, and useful remain distinct evidence sets.
// These flags are an explicit public wire projection and are checked bijectively
// against counters and receipt evidence below.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProjection {
    /// Package is physically installed/registered by an external owner.
    pub installed: bool,
    /// Package was delivered to the host route.
    pub delivered: bool,
    /// Package was expanded beyond its short form.
    pub expanded: bool,
    /// An execution was observed.
    pub executed: bool,
    /// A verifier accepted at least one execution result.
    pub verified: bool,
    /// A useful downstream outcome was accepted; never inferred from execution.
    pub useful: bool,
    /// Exact installation receipts.
    pub installation_receipts: Vec<ReceiptClaim>,
    /// Exact delivery receipts.
    pub delivery_receipts: Vec<ReceiptClaim>,
    /// Exact expansion receipts.
    pub expansion_receipts: Vec<ReceiptClaim>,
    /// Exact execution observations.
    pub execution_evidence: Vec<ExecutionEvidenceProjection>,
    /// Exact verifier receipts causally bound to successful execution receipts.
    pub verification_receipts: Vec<ReceiptClaim>,
    /// Exact useful-outcome verification receipts.
    pub useful_receipts: Vec<ReceiptClaim>,
}

impl DeliveryProjection {
    #[allow(clippy::too_many_lines)]
    fn validate(&self, counters: &SkillCounters) -> Result<(), SkillContractError> {
        validate_positive_receipts(
            &self.installation_receipts,
            ReceiptKind::Artifact,
            false,
            "delivery.installation_receipts",
        )?;
        validate_positive_receipts(
            &self.delivery_receipts,
            ReceiptKind::Coordination,
            false,
            "delivery.delivery_receipts",
        )?;
        validate_positive_receipts(
            &self.expansion_receipts,
            ReceiptKind::Coordination,
            false,
            "delivery.expansion_receipts",
        )?;
        validate_positive_receipts(
            &self.verification_receipts,
            ReceiptKind::Verification,
            true,
            "delivery.verification_receipts",
        )?;
        validate_positive_receipts(
            &self.useful_receipts,
            ReceiptKind::Verification,
            true,
            "delivery.useful_receipts",
        )?;
        for evidence in &self.execution_evidence {
            evidence.validate()?;
        }
        let installed_count = usize_to_u64(self.installation_receipts.len());
        let delivery_count = usize_to_u64(self.delivery_receipts.len());
        let expansion_count = usize_to_u64(self.expansion_receipts.len());
        let execution_count = count_outcome(&self.execution_evidence, ExecutionOutcome::Observed);
        let verified_count = usize_to_u64(self.verification_receipts.len());
        let useful_count = usize_to_u64(self.useful_receipts.len());
        let failed_count = count_outcome(&self.execution_evidence, ExecutionOutcome::Failed);
        let uncertain_count = count_outcome(&self.execution_evidence, ExecutionOutcome::Uncertain);
        for (actual, expected, field) in [
            (counters.installed_count, installed_count, "installed_count"),
            (counters.delivery_count, delivery_count, "delivery_count"),
            (counters.expansion_count, expansion_count, "expansion_count"),
            (counters.execution_count, execution_count, "execution_count"),
            (counters.verified_count, verified_count, "verified_count"),
            (counters.failed_count, failed_count, "failed_count"),
            (counters.uncertain_count, uncertain_count, "uncertain_count"),
            (counters.useful_count, useful_count, "useful_count"),
        ] {
            if actual != expected {
                return Err(SkillContractError::LifecycleContradiction { field });
            }
        }
        for (flag, count, field) in [
            (self.installed, installed_count, "installed"),
            (self.delivered, delivery_count, "delivered"),
            (self.expanded, expansion_count, "expanded"),
            (self.executed, execution_count, "executed"),
            (self.verified, verified_count, "verified"),
            (self.useful, useful_count, "useful"),
        ] {
            if flag != (count > 0) {
                return Err(SkillContractError::LifecycleContradiction { field });
            }
        }
        if self.delivered && !self.installed {
            return Err(SkillContractError::LifecycleOrder {
                field: "delivery.delivered",
                required: "delivery.installed",
            });
        }
        if self.executed && !self.delivered {
            return Err(SkillContractError::LifecycleOrder {
                field: "delivery.executed",
                required: "delivery.delivered",
            });
        }
        if !self.execution_evidence.is_empty() && !self.delivered {
            return Err(SkillContractError::LifecycleOrder {
                field: "delivery.execution_evidence",
                required: "delivery.delivered",
            });
        }
        if self.verified && !self.executed {
            return Err(SkillContractError::LifecycleOrder {
                field: "delivery.verified",
                required: "delivery.executed",
            });
        }
        if self.useful && !self.verified {
            return Err(SkillContractError::LifecycleOrder {
                field: "delivery.useful",
                required: "delivery.verified",
            });
        }
        if counters.expansion_count > counters.delivery_count {
            return Err(SkillContractError::LifecycleOrder {
                field: "counters.expansion_count",
                required: "counters.delivery_count",
            });
        }
        if counters.useful_count > counters.verified_count {
            return Err(SkillContractError::LifecycleOrder {
                field: "counters.useful_count",
                required: "counters.verified_count",
            });
        }
        let successful_execution_ids: BTreeSet<_> = self
            .execution_evidence
            .iter()
            .filter(|item| item.outcome == ExecutionOutcome::Observed)
            .map(|item| item.receipt.envelope.identity.receipt_id.as_str())
            .collect();
        for receipt in &self.verification_receipts {
            if !receipt
                .envelope
                .core
                .causal
                .predecessor_receipt_ids
                .iter()
                .any(|predecessor| successful_execution_ids.contains(predecessor.as_str()))
            {
                return Err(SkillContractError::LifecycleContradiction {
                    field: "verification_receipts.execution_predecessor",
                });
            }
        }
        let verification_ids: BTreeSet<_> = self
            .verification_receipts
            .iter()
            .map(|claim| claim.envelope.identity.receipt_id.as_str())
            .collect();
        for receipt in &self.useful_receipts {
            if !receipt
                .envelope
                .core
                .causal
                .predecessor_receipt_ids
                .iter()
                .any(|predecessor| verification_ids.contains(predecessor.as_str()))
            {
                return Err(SkillContractError::LifecycleContradiction {
                    field: "useful_receipts.verification_predecessor",
                });
            }
        }
        if self.useful && !self.verified {
            return Err(SkillContractError::LifecycleContradiction {
                field: "useful_receipts",
            });
        }
        Ok(())
    }
}

fn validate_positive_receipts(
    receipts: &[ReceiptClaim],
    expected_kind: ReceiptKind,
    verifier_required: bool,
    field: &'static str,
) -> Result<(), SkillContractError> {
    for receipt in receipts {
        receipt.validate()?;
        let core = &receipt.envelope.core;
        if core.kind != expected_kind
            || core.disposition.kind() != ReceiptDispositionKind::Success
            || (verifier_required && core.verifier.is_none())
        {
            return Err(SkillContractError::ReceiptBindingMismatch { field });
        }
    }
    Ok(())
}

fn count_outcome(evidence: &[ExecutionEvidenceProjection], outcome: ExecutionOutcome) -> u64 {
    usize_to_u64(
        evidence
            .iter()
            .filter(|item| item.outcome == outcome)
            .count(),
    )
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// G-16-owned lifecycle and conflict state projected into A-15.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FreshnessState {
    Current,
    Stale { reason: String },
}

/// Conflict never selects a Skill by prompt order.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictState {
    None,
    Conflicted { references: Vec<String> },
}

/// Distractor classification from semantic filtering.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DistractorState {
    None,
    Distractor { reason: String },
}

/// Quarantine state from the lifecycle owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineState {
    Clear,
    Quarantined { reason: String },
}

/// Combined lifecycle projection supplied by G-16.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillState {
    pub freshness: FreshnessState,
    pub conflict: ConflictState,
    pub distractor: DistractorState,
    pub quarantine: QuarantineState,
}

/// Observed or explicitly specified interactions with other Skills.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillInteractionProjection {
    /// Rival Skill references. Prompt order has no selection meaning.
    pub conflict_refs: Vec<String>,
    /// Required order records only; never used to resolve a conflict.
    pub ordering_refs: Vec<String>,
    /// Mutually exclusive Skill references.
    pub mutual_exclusion_refs: Vec<String>,
}

impl SkillState {
    fn validate(&self, interaction: &SkillInteractionProjection) -> Result<(), SkillContractError> {
        for refs in [
            &interaction.conflict_refs,
            &interaction.ordering_refs,
            &interaction.mutual_exclusion_refs,
        ] {
            for value in refs {
                validate_text(value, "interaction.reference")?;
            }
            unique(refs, "interaction.reference")?;
        }
        match &self.conflict {
            ConflictState::None if !interaction.conflict_refs.is_empty() => {
                return Err(SkillContractError::LifecycleContradiction {
                    field: "interaction.conflict_refs_without_conflict",
                });
            }
            ConflictState::Conflicted { references } => {
                validate_list(references, "state.conflict.references")?;
                let left: BTreeSet<_> = references.iter().collect();
                let right: BTreeSet<_> = interaction.conflict_refs.iter().collect();
                if left != right {
                    return Err(SkillContractError::LifecycleContradiction {
                        field: "interaction.conflict_refs",
                    });
                }
            }
            ConflictState::None => {}
        }
        for (reason, field) in [
            (
                match &self.freshness {
                    FreshnessState::Stale { reason } => Some(reason),
                    FreshnessState::Current => None,
                },
                "state.freshness.reason",
            ),
            (
                match &self.distractor {
                    DistractorState::Distractor { reason } => Some(reason),
                    DistractorState::None => None,
                },
                "state.distractor.reason",
            ),
            (
                match &self.quarantine {
                    QuarantineState::Quarantined { reason } => Some(reason),
                    QuarantineState::Clear => None,
                },
                "state.quarantine.reason",
            ),
        ] {
            if let Some(reason) = reason {
                validate_text(reason, field)?;
            }
        }
        Ok(())
    }
}

/// One reversible lifecycle action. This is never an authority or mutation grant.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReversibleLifecycleAction {
    Patch,
    Split,
    Merge,
    Suppress,
    Archive,
    Quarantine,
    Restore,
}

/// Exact rollback and ownership binding for a reversible proposal.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversibleLifecycleBinding {
    pub action: ReversibleLifecycleAction,
    pub evidence_refs: Vec<String>,
    pub review_ref: String,
    pub owner_ref: String,
    pub rollback_ref: String,
    pub rollback_artifact_digest: String,
    pub proposal_receipt: ReceiptClaim,
}

impl ReversibleLifecycleBinding {
    fn validate(&self) -> Result<(), SkillContractError> {
        validate_list(&self.evidence_refs, "lifecycle.evidence_refs")?;
        for (value, field) in [
            (&self.review_ref, "lifecycle.review_ref"),
            (&self.owner_ref, "lifecycle.owner_ref"),
            (&self.rollback_ref, "lifecycle.rollback_ref"),
        ] {
            validate_text(value, field)?;
        }
        validate_digest(
            &self.rollback_artifact_digest,
            "lifecycle.rollback_artifact_digest",
        )?;
        self.proposal_receipt.validate()?;
        let core = &self.proposal_receipt.envelope.core;
        if core.kind != ReceiptKind::Operation
            || core.disposition.kind() != ReceiptDispositionKind::Success
        {
            return Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.proposal_receipt.outcome",
            });
        }
        validate_reversible_authority(
            core.operation.effect,
            core.authority.allowed_effect,
            core.authority.proof_ceiling,
        )?;
        if self.owner_ref != core.authority.authority_owner {
            return Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.owner_ref",
            });
        }
        let verifier =
            core.verifier
                .as_ref()
                .ok_or(SkillContractError::InvalidLifecycleProposal {
                    field: "lifecycle.review_ref",
                })?;
        if self.review_ref != verifier.verifier_id.as_str() {
            return Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.review_ref",
            });
        }
        let mut artifact_ids = BTreeSet::new();
        if core
            .artifacts
            .iter()
            .any(|artifact| !artifact_ids.insert(artifact.artifact_id.as_str()))
        {
            return Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.proposal_receipt.artifact_ids",
            });
        }
        let rollback = core
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id.as_str() == self.rollback_ref)
            .ok_or(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.rollback_ref",
            })?;
        if rollback.sha256 != self.rollback_artifact_digest
            || rollback.role != ReceiptKind::Artifact
        {
            return Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.rollback_artifact_digest",
            });
        }
        let evidence_artifact_ids: BTreeSet<_> = core
            .artifacts
            .iter()
            .filter(|artifact| artifact.role == ReceiptKind::Verification)
            .map(|artifact| artifact.artifact_id.as_str())
            .collect();
        let evidence_refs: BTreeSet<_> = self.evidence_refs.iter().map(String::as_str).collect();
        if evidence_artifact_ids != evidence_refs {
            return Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.evidence_refs",
            });
        }
        let mut expected_verifier_artifacts = evidence_refs;
        expected_verifier_artifacts.insert(self.rollback_ref.as_str());
        let mut verifier_artifacts = BTreeSet::new();
        for artifact in &verifier.artifact_ids {
            verifier_artifacts.insert(artifact.as_str());
        }
        if verifier_artifacts != expected_verifier_artifacts {
            return Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.review_artifact_bindings",
            });
        }
        Ok(())
    }
}

fn validate_reversible_authority(
    operation_effect: EffectClass,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
) -> Result<(), SkillContractError> {
    if operation_effect != EffectClass::ReversibleMutation
        || allowed_effect != EffectClass::ReversibleMutation
        || !proof_ceiling.is_at_most(ProofCeiling::ScopedVerification)
    {
        return Err(SkillContractError::InvalidLifecycleProposal {
            field: "lifecycle.proposal_receipt.authority",
        });
    }
    Ok(())
}

/// Reversible proposal only; `Keep` is the absence of a lifecycle mutation proposal.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleProposal {
    Keep,
    Reversible(Box<ReversibleLifecycleBinding>),
}

/// Field to which an availability observation applies.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AvailabilityField {
    Provider,
    G16,
    A06,
    Evidence,
    HostCapability,
}

/// Stable unavailable reason code. Each code maps to exactly one field.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnavailableCode {
    ProviderUnavailable,
    G16Unavailable,
    A06Unavailable,
    EvidenceUnavailable,
    HostCapabilityUnavailable,
}

impl UnavailableCode {
    const fn field(self) -> AvailabilityField {
        match self {
            Self::ProviderUnavailable => AvailabilityField::Provider,
            Self::G16Unavailable => AvailabilityField::G16,
            Self::A06Unavailable => AvailabilityField::A06,
            Self::EvidenceUnavailable => AvailabilityField::Evidence,
            Self::HostCapabilityUnavailable => AvailabilityField::HostCapability,
        }
    }
}

/// Public inert availability claim. Only sealed readiness ports may accept it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Availability {
    Available {
        field: AvailabilityField,
    },
    Unavailable {
        field: AvailabilityField,
        code: UnavailableCode,
        reason: String,
    },
}

impl Availability {
    fn validate(&self, expected: AvailabilityField) -> Result<(), SkillContractError> {
        match self {
            Self::Available { field } if *field == expected => Ok(()),
            Self::Unavailable {
                field,
                code,
                reason,
            } if *field == expected && code.field() == expected => {
                validate_text(reason, "availability.reason")
            }
            _ => Err(SkillContractError::AvailabilityCodeMismatch {
                field: availability_field_name(expected),
            }),
        }
    }

    fn unavailable(&self) -> Option<(UnavailableCode, &str)> {
        match self {
            Self::Unavailable { code, reason, .. } => Some((*code, reason)),
            Self::Available { .. } => None,
        }
    }
}

const fn availability_field_name(field: AvailabilityField) -> &'static str {
    match field {
        AvailabilityField::Provider => "provider",
        AvailabilityField::G16 => "g16",
        AvailabilityField::A06 => "a06",
        AvailabilityField::Evidence => "evidence",
        AvailabilityField::HostCapability => "host_capability",
    }
}

/// One actual versioned host observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedObservation {
    pub name: String,
    pub version: String,
    pub availability: Availability,
}

/// Public inert readiness claims. A-06 stays acceptance-only and is not imported.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessClaims {
    pub host: String,
    pub profile: String,
    pub provider: Availability,
    pub g16: Availability,
    pub a06: Availability,
    pub evidence: Availability,
    pub tools: Vec<VersionedObservation>,
    pub capabilities: Vec<VersionedObservation>,
}

impl ReadinessClaims {
    fn validate(&self) -> Result<(), SkillContractError> {
        validate_text(&self.host, "readiness.host")?;
        validate_text(&self.profile, "readiness.profile")?;
        self.provider.validate(AvailabilityField::Provider)?;
        self.g16.validate(AvailabilityField::G16)?;
        self.a06.validate(AvailabilityField::A06)?;
        self.evidence.validate(AvailabilityField::Evidence)?;
        for (observations, field) in [
            (self.tools.as_slice(), "readiness.tools"),
            (self.capabilities.as_slice(), "readiness.capabilities"),
        ] {
            let mut keys = BTreeSet::new();
            for observation in observations {
                validate_text(&observation.name, "readiness.observation.name")?;
                validate_text(&observation.version, "readiness.observation.version")?;
                observation
                    .availability
                    .validate(AvailabilityField::HostCapability)?;
                if !keys.insert((&observation.name, &observation.version)) {
                    return Err(SkillContractError::AmbiguousStructure { reason: field });
                }
            }
        }
        Ok(())
    }
}

/// Exact scope identity against which canonical receipts are checked.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationScope {
    pub work_scope: WorkScopeBinding,
    pub task: Option<TaskBinding>,
}

/// Advisory rule claim. Enforcement class/provenance comes only from a sealed G-16 port.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryRuleClaim {
    pub rule_ref: RuleRef,
}

/// Complete public wire claim for one generated Skill package.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPackage {
    pub registration: RegistrationIdentity,
    pub digests: PackageDigests,
    pub host: HostProfile,
    pub behavior: SkillBehavior,
    pub counters: SkillCounters,
    pub state: SkillState,
    pub lifecycle_proposal: LifecycleProposal,
    pub delivery: DeliveryProjection,
    pub interaction: SkillInteractionProjection,
    pub rule: AdvisoryRuleClaim,
}

impl SkillPackage {
    /// Validates inert wire claims against actual canonical materialization inputs.
    pub fn validate(&self, inputs: &MaterializationInputs) -> Result<(), SkillContractError> {
        self.registration.validate()?;
        self.digests.validate_against(inputs)?;
        self.host.validate()?;
        self.behavior.validate()?;
        if self.behavior != inputs.contract_materialization {
            return Err(SkillContractError::MaterializationDigestMismatch {
                field: "contract_materialization",
            });
        }
        if self.behavior.rendered_description().chars().count()
            > usize::try_from(self.host.limits.max_description_chars).unwrap_or(usize::MAX)
        {
            return Err(SkillContractError::DescriptionTooLong);
        }
        self.validate_tool_materialization(inputs)?;
        self.state.validate(&self.interaction)?;
        self.delivery.validate(&self.counters)?;
        if let LifecycleProposal::Reversible(binding) = &self.lifecycle_proposal {
            binding.validate()?;
        }
        validate_unique_receipt_identities(self)?;
        Ok(())
    }

    fn validate_tool_materialization(
        &self,
        inputs: &MaterializationInputs,
    ) -> Result<(), SkillContractError> {
        for requirement in &self.host.required_tools {
            if !inputs
                .tool_definitions
                .iter()
                .any(|tool| tool.name == requirement.name && tool.version == requirement.version)
            {
                return Err(SkillContractError::UnsupportedCapability {
                    field: "host.required_tools",
                });
            }
        }
        for requirement in &self.host.required_capabilities {
            if !inputs.tool_definitions.iter().any(|tool| {
                tool.capabilities.iter().any(|capability| {
                    capability.name == requirement.name && capability.version == requirement.version
                })
            }) {
                return Err(SkillContractError::UnsupportedCapability {
                    field: "host.required_capabilities",
                });
            }
        }
        let actions: Vec<_> = inputs
            .tool_definitions
            .iter()
            .filter(|tool| {
                self.host.required_tools.iter().any(|requirement| {
                    requirement.name == tool.name && requirement.version == tool.version
                })
            })
            .flat_map(|tool| tool.actions.iter())
            .collect();
        if actions.len() != 1 || actions[0].as_str() != self.behavior.action {
            return Err(SkillContractError::AmbiguousStructure {
                reason: "actual required tool definitions must materialize exactly one matching action",
            });
        }
        Ok(())
    }

    /// Stable materialization identity for the generated package definition.
    pub fn materialization_identity_digest(
        &self,
        inputs: &MaterializationInputs,
    ) -> Result<String, SkillContractError> {
        self.validate(inputs)?;
        canonical_digest(&(
            &self.registration,
            &self.digests,
            &self.host,
            &self.behavior,
            &self.rule,
        ))
    }

    fn verification_binding_digest(
        &self,
        inputs: &MaterializationInputs,
        readiness: &ReadinessClaims,
        scope: &MaterializationScope,
    ) -> Result<String, SkillContractError> {
        canonical_digest(&(
            self.materialization_identity_digest(inputs)?,
            scope,
            readiness,
            &self.counters,
            &self.state,
            &self.lifecycle_proposal,
            &self.delivery,
            &self.interaction,
        ))
    }

    /// Pure materialization through sealed, non-caller-mintable verification ports.
    pub fn materialize(
        &self,
        inputs: &MaterializationInputs,
        readiness: &ReadinessClaims,
        scope: &MaterializationScope,
        ports: &MaterializationPorts<'_>,
    ) -> Result<MaterializationOutcome, SkillContractError> {
        self.validate(inputs)?;
        readiness.validate()?;
        if readiness.host != self.host.host || readiness.profile != self.host.profile {
            return Ok(omitted(
                OmissionReason::UnsupportedHostProfile {
                    host: readiness.host.clone(),
                    profile: readiness.profile.clone(),
                },
                "UNSUPPORTED_HOST_PROFILE",
                &self.behavior.challenge,
            ));
        }
        if let Some(outcome) = self.lifecycle_omission() {
            return Ok(outcome);
        }
        for availability in [
            &readiness.provider,
            &readiness.g16,
            &readiness.a06,
            &readiness.evidence,
        ] {
            if let Some((code, reason)) = availability.unavailable() {
                return Ok(omitted(
                    OmissionReason::PlanGap {
                        code,
                        reason: reason.to_owned(),
                    },
                    "PLAN_GAP",
                    &self.behavior.escalation,
                ));
            }
        }
        self.validate_observations(readiness)?;
        let materialization_identity_digest = self.materialization_identity_digest(inputs)?;
        let verification_binding_digest =
            self.verification_binding_digest(inputs, readiness, scope)?;
        let request = VerificationRequest {
            package: self,
            inputs,
            readiness,
            scope,
            materialization_identity_digest,
            verification_binding_digest,
        };
        let readiness_decision = ports.readiness.verify(&request)?;
        readiness_decision.matches(&request)?;
        let g16_decision = ports.g16.verify(&request)?;
        g16_decision.matches(&request)?;
        verify_receipt_bindings(&request)?;
        let verified_rule =
            VerifiedRuleProjection::from_catalogue_entry(&g16_decision.catalogue_entry)?;
        verified_rule.validate()?;
        Ok(MaterializationOutcome::materialized(MaterializedSkill {
            package: self.clone(),
            verified_rule,
            accepted_receipt_ids: g16_decision.accepted_receipt_ids,
            readiness_decision_ref: readiness_decision.decision_ref,
        }))
    }

    fn validate_observations(&self, readiness: &ReadinessClaims) -> Result<(), SkillContractError> {
        readiness.validate()?;
        let tools: BTreeMap<_, _> = readiness
            .tools
            .iter()
            .map(|observation| {
                (
                    (observation.name.as_str(), observation.version.as_str()),
                    observation,
                )
            })
            .collect();
        let capabilities: BTreeMap<_, _> = readiness
            .capabilities
            .iter()
            .map(|observation| {
                (
                    (observation.name.as_str(), observation.version.as_str()),
                    observation,
                )
            })
            .collect();
        for requirement in &self.host.required_tools {
            let key = (requirement.name.as_str(), requirement.version.as_str());
            let observation = tools.get(&key).copied();
            match observation {
                Some(observation) if observation.availability.unavailable().is_none() => {}
                _ => {
                    return Err(SkillContractError::UnsupportedCapability {
                        field: "readiness.tools",
                    });
                }
            }
        }
        for requirement in &self.host.required_capabilities {
            let key = (requirement.name.as_str(), requirement.version.as_str());
            let observation = capabilities.get(&key).copied();
            match observation {
                Some(observation) if observation.availability.unavailable().is_none() => {}
                _ => {
                    return Err(SkillContractError::UnsupportedCapability {
                        field: "readiness.capabilities",
                    });
                }
            }
        }
        Ok(())
    }

    fn lifecycle_omission(&self) -> Option<MaterializationOutcome> {
        match &self.state.freshness {
            FreshnessState::Stale { reason } => Some(omitted(
                OmissionReason::Stale {
                    reason: reason.clone(),
                },
                "STALE_SKILL",
                &self.behavior.challenge,
            )),
            FreshnessState::Current => match &self.state.conflict {
                ConflictState::Conflicted { references } => Some(omitted(
                    OmissionReason::Conflict {
                        references: references.clone(),
                    },
                    "SKILL_CONFLICT",
                    &self.behavior.challenge,
                )),
                ConflictState::None => match &self.state.distractor {
                    DistractorState::Distractor { reason } => Some(omitted(
                        OmissionReason::Distractor {
                            reason: reason.clone(),
                        },
                        "SKILL_DISTRACTOR",
                        &self.behavior.challenge,
                    )),
                    DistractorState::None => match &self.state.quarantine {
                        QuarantineState::Quarantined { reason } => Some(omitted(
                            OmissionReason::Quarantined {
                                reason: reason.clone(),
                            },
                            "SKILL_QUARANTINED",
                            &self.behavior.challenge,
                        )),
                        QuarantineState::Clear => None,
                    },
                },
            },
        }
    }
}

fn verify_receipt_bindings(request: &VerificationRequest<'_>) -> Result<(), SkillContractError> {
    let package = request.package;
    let mut claims: Vec<(&ReceiptClaim, ReceiptKind, &str)> = Vec::new();
    claims.extend(
        package
            .delivery
            .installation_receipts
            .iter()
            .map(|claim| (claim, ReceiptKind::Artifact, "installed")),
    );
    claims.extend(
        package
            .delivery
            .delivery_receipts
            .iter()
            .map(|claim| (claim, ReceiptKind::Coordination, "delivered")),
    );
    claims.extend(
        package
            .delivery
            .expansion_receipts
            .iter()
            .map(|claim| (claim, ReceiptKind::Coordination, "expanded")),
    );
    claims.extend(
        package
            .delivery
            .execution_evidence
            .iter()
            .map(|evidence| (&evidence.receipt, ReceiptKind::Operation, "executed")),
    );
    claims.extend(
        package
            .delivery
            .verification_receipts
            .iter()
            .map(|claim| (claim, ReceiptKind::Verification, "verified")),
    );
    claims.extend(
        package
            .delivery
            .useful_receipts
            .iter()
            .map(|claim| (claim, ReceiptKind::Verification, "useful")),
    );
    if let LifecycleProposal::Reversible(binding) = &package.lifecycle_proposal {
        claims.push((
            &binding.proposal_receipt,
            ReceiptKind::Operation,
            "proposal",
        ));
    }
    for (claim, kind, event) in claims {
        claim.validate()?;
        let core = &claim.envelope.core;
        let operation_kind = format!(
            "eliot.skills/{event}/{}/{}/{}",
            package.host.host, package.host.profile, package.registration.skill_id
        );
        if core.kind != kind {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "receipt.kind",
            });
        }
        if core.work_scope != request.scope.work_scope || core.task != request.scope.task {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "receipt.scope",
            });
        }
        if core.operation.operation_kind != operation_kind {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "receipt.operation_kind",
            });
        }
        if core.authority.authority_owner != "G-16" {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "receipt.authority_owner",
            });
        }
        if !core.artifacts.iter().any(|artifact| {
            artifact.sha256 == request.materialization_identity_digest
                && artifact.source_revision.as_deref()
                    == Some(package.registration.revision.as_str())
        }) {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "receipt.package_artifact",
            });
        }
        if matches!(event, "verified" | "useful")
            && (core.verifier.is_none()
                || core.disposition.kind() != ReceiptDispositionKind::Success)
        {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "receipt.useful_verifier",
            });
        }
    }
    Ok(())
}

/// Verified exact rule projection returned by G-16. Skill text remains advisory.
///
/// Accepted projections intentionally cannot be deserialized or publicly constructed.
///
/// ```compile_fail
/// let _: eliot_skills::VerifiedRuleProjection = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRuleProjection {
    catalogue_entry: RuleCatalogueEntry,
    catalogue_provenance_digest: String,
}

impl VerifiedRuleProjection {
    fn from_catalogue_entry(entry: &RuleCatalogueEntry) -> Result<Self, SkillContractError> {
        entry
            .validate()
            .map_err(|_| SkillContractError::RuleVerificationMismatch)?;
        let catalogue_provenance_digest = canonical_digest(entry)?;
        Ok(Self {
            catalogue_entry: entry.clone(),
            catalogue_provenance_digest,
        })
    }

    fn validate(&self) -> Result<(), SkillContractError> {
        self.catalogue_entry
            .validate()
            .map_err(|_| SkillContractError::RuleVerificationMismatch)?;
        if canonical_digest(&self.catalogue_entry)? != self.catalogue_provenance_digest {
            return Err(SkillContractError::RuleVerificationMismatch);
        }
        Ok(())
    }

    /// Returns the exact G-16 catalogue rule reference.
    #[must_use]
    pub const fn rule_ref(&self) -> &RuleRef {
        &self.catalogue_entry.rule_ref
    }

    /// Returns the catalogue-owned enforcement class.
    #[must_use]
    pub const fn class(&self) -> RuleClass {
        self.catalogue_entry.class
    }

    /// Returns the validated catalogue entry.
    #[must_use]
    pub const fn catalogue_entry(&self) -> &RuleCatalogueEntry {
        &self.catalogue_entry
    }

    /// Returns the canonical digest derived from the exact catalogue entry.
    #[must_use]
    pub fn catalogue_provenance_digest(&self) -> &str {
        &self.catalogue_provenance_digest
    }
}

/// Output of successful materialization. It is a projection, never an authority grant.
///
/// ```compile_fail
/// let _: eliot_skills::MaterializedSkill = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedSkill {
    package: SkillPackage,
    verified_rule: VerifiedRuleProjection,
    accepted_receipt_ids: Vec<String>,
    readiness_decision_ref: String,
}

impl MaterializedSkill {
    /// Returns the inert package claims accepted by the sealed path.
    #[must_use]
    pub const fn package(&self) -> &SkillPackage {
        &self.package
    }

    /// Returns the exact rule projection accepted by G-16.
    #[must_use]
    pub const fn verified_rule(&self) -> &VerifiedRuleProjection {
        &self.verified_rule
    }

    /// Returns the exact receipt identities accepted by G-16.
    #[must_use]
    pub fn accepted_receipt_ids(&self) -> &[String] {
        &self.accepted_receipt_ids
    }

    /// Returns the readiness decision reference produced by the sealed port.
    #[must_use]
    pub fn readiness_decision_ref(&self) -> &str {
        &self.readiness_decision_ref
    }
}

/// Why a package was omitted from a host package.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OmissionReason {
    Conflict {
        references: Vec<String>,
    },
    Stale {
        reason: String,
    },
    Distractor {
        reason: String,
    },
    Quarantined {
        reason: String,
    },
    PlanGap {
        code: UnavailableCode,
        reason: String,
    },
    UnsupportedHostProfile {
        host: String,
        profile: String,
    },
}

/// A challenge path retained when a Skill is omitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeProjection {
    pub instruction: String,
    pub reason_code: String,
}

/// Pure materialization result; no process, network, storage, or lifecycle effect occurs.
///
/// The wrapper has no public constructor and does not implement `Deserialize`, so callers
/// cannot mint an accepted `MATERIALIZED` result from wire data.
///
/// ```compile_fail
/// let _: eliot_skills::MaterializationOutcome = serde_json::from_str(
///     r#"{"status":"MATERIALIZED"}"#,
/// ).unwrap();
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct MaterializationOutcome(MaterializationOutcomeKind);

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum MaterializationOutcomeKind {
    Materialized {
        materialization: Box<MaterializedSkill>,
    },
    Omitted {
        reason: OmissionReason,
        challenge: ChallengeProjection,
    },
}

impl MaterializationOutcome {
    fn materialized(materialization: MaterializedSkill) -> Self {
        Self(MaterializationOutcomeKind::Materialized {
            materialization: Box::new(materialization),
        })
    }

    /// Returns the accepted materialization, if this is a sealed positive result.
    #[must_use]
    pub fn materialized_skill(&self) -> Option<&MaterializedSkill> {
        match &self.0 {
            MaterializationOutcomeKind::Materialized { materialization } => Some(materialization),
            MaterializationOutcomeKind::Omitted { .. } => None,
        }
    }

    /// Returns the omission reason, if materialization was rejected.
    #[must_use]
    pub const fn omission_reason(&self) -> Option<&OmissionReason> {
        match &self.0 {
            MaterializationOutcomeKind::Omitted { reason, .. } => Some(reason),
            MaterializationOutcomeKind::Materialized { .. } => None,
        }
    }

    /// Returns the omission challenge, if materialization was rejected.
    #[must_use]
    pub const fn challenge(&self) -> Option<&ChallengeProjection> {
        match &self.0 {
            MaterializationOutcomeKind::Omitted { challenge, .. } => Some(challenge),
            MaterializationOutcomeKind::Materialized { .. } => None,
        }
    }
}

fn omitted(reason: OmissionReason, code: &str, instruction: &str) -> MaterializationOutcome {
    MaterializationOutcome(MaterializationOutcomeKind::Omitted {
        reason,
        challenge: ChallengeProjection {
            instruction: instruction.to_owned(),
            reason_code: code.to_owned(),
        },
    })
}

/// Exact request passed to both sealed verification ports.
pub struct VerificationRequest<'a> {
    package: &'a SkillPackage,
    inputs: &'a MaterializationInputs,
    readiness: &'a ReadinessClaims,
    scope: &'a MaterializationScope,
    materialization_identity_digest: String,
    verification_binding_digest: String,
}

impl<'a> VerificationRequest<'a> {
    /// Returns the exact package claim being verified.
    pub const fn package(&self) -> &'a SkillPackage {
        self.package
    }

    /// Returns the actual canonical materialization inputs.
    pub const fn inputs(&self) -> &'a MaterializationInputs {
        self.inputs
    }

    /// Returns the exact readiness claims that require provider verification.
    pub const fn readiness(&self) -> &'a ReadinessClaims {
        self.readiness
    }

    /// Returns the exact receipt/task/work-scope binding.
    pub const fn scope(&self) -> &'a MaterializationScope {
        self.scope
    }

    /// Returns the digest binding package, scope, and readiness inputs together.
    pub fn verification_binding_digest(&self) -> &str {
        &self.verification_binding_digest
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed readiness port. External callers cannot implement it or mint success decisions.
pub trait ReadinessVerifierPort: sealed::Sealed {
    fn verify(
        &self,
        request: &VerificationRequest<'_>,
    ) -> Result<VerifiedReadinessDecision, SkillContractError>;
}

/// Sealed G-16 port. Rule enforcement and receipt acceptance are not caller-selected.
pub trait G16VerifierPort: sealed::Sealed {
    fn verify(
        &self,
        request: &VerificationRequest<'_>,
    ) -> Result<VerifiedG16Decision, SkillContractError>;
}

/// Injected sealed verification ports used for a single pure materialization.
pub struct MaterializationPorts<'a> {
    pub readiness: &'a dyn ReadinessVerifierPort,
    pub g16: &'a dyn G16VerifierPort,
}

/// Non-serializable readiness decision; construction is crate-private.
pub struct VerifiedReadinessDecision {
    binding_digest: String,
    decision_ref: String,
}

impl VerifiedReadinessDecision {
    fn matches(&self, request: &VerificationRequest<'_>) -> Result<(), SkillContractError> {
        validate_text(&self.decision_ref, "readiness.decision_ref")?;
        if self.binding_digest != request.verification_binding_digest {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "readiness.binding_digest",
            });
        }
        Ok(())
    }
}

/// Non-serializable G-16 decision; construction is crate-private.
pub struct VerifiedG16Decision {
    binding_digest: String,
    catalogue_entry: RuleCatalogueEntry,
    accepted_receipt_ids: Vec<String>,
}

impl VerifiedG16Decision {
    fn matches(&self, request: &VerificationRequest<'_>) -> Result<(), SkillContractError> {
        self.catalogue_entry
            .validate()
            .map_err(|_| SkillContractError::RuleVerificationMismatch)?;
        if self.binding_digest != request.verification_binding_digest
            || self.catalogue_entry.rule_ref != request.package.rule.rule_ref
        {
            return Err(SkillContractError::RuleVerificationMismatch);
        }
        unique(&self.accepted_receipt_ids, "g16.accepted_receipt_ids")?;
        let mut claimed: Vec<_> = all_receipt_claims(request.package)
            .map(|claim| claim.envelope.identity.receipt_id.as_str().to_owned())
            .collect();
        let mut accepted = self.accepted_receipt_ids.clone();
        claimed.sort();
        accepted.sort();
        if claimed != accepted {
            return Err(SkillContractError::ReceiptBindingMismatch {
                field: "g16.accepted_receipt_ids",
            });
        }
        Ok(())
    }
}

fn all_receipt_claims(package: &SkillPackage) -> impl Iterator<Item = &ReceiptClaim> {
    let proposal = match &package.lifecycle_proposal {
        LifecycleProposal::Reversible(binding) => Some(&binding.proposal_receipt),
        LifecycleProposal::Keep => None,
    };
    package
        .delivery
        .installation_receipts
        .iter()
        .chain(&package.delivery.delivery_receipts)
        .chain(&package.delivery.expansion_receipts)
        .chain(
            package
                .delivery
                .execution_evidence
                .iter()
                .map(|evidence| &evidence.receipt),
        )
        .chain(&package.delivery.verification_receipts)
        .chain(&package.delivery.useful_receipts)
        .chain(proposal)
}

fn validate_unique_receipt_identities(package: &SkillPackage) -> Result<(), SkillContractError> {
    let mut identities = BTreeSet::new();
    if all_receipt_claims(package)
        .any(|claim| !identities.insert(claim.envelope.identity.receipt_id.as_str().to_owned()))
    {
        return Err(SkillContractError::LifecycleContradiction {
            field: "delivery.duplicate_receipt_identity",
        });
    }
    Ok(())
}

/// Built-in sealed provider that explicitly reports missing integration as `PLAN_GAP`.
pub struct MissingVerificationProvider;

impl sealed::Sealed for MissingVerificationProvider {}

impl ReadinessVerifierPort for MissingVerificationProvider {
    fn verify(
        &self,
        _request: &VerificationRequest<'_>,
    ) -> Result<VerifiedReadinessDecision, SkillContractError> {
        Err(SkillContractError::PlanGap {
            code: UnavailableCode::ProviderUnavailable,
            reason: "sealed readiness verifier provider is not injected".to_owned(),
        })
    }
}

impl G16VerifierPort for MissingVerificationProvider {
    fn verify(
        &self,
        _request: &VerificationRequest<'_>,
    ) -> Result<VerifiedG16Decision, SkillContractError> {
        Err(SkillContractError::PlanGap {
            code: UnavailableCode::G16Unavailable,
            reason: "sealed G-16 verifier provider is not injected".to_owned(),
        })
    }
}

/// Computes deterministic lowercase SHA-256 over a canonical evidence shape.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, SkillContractError> {
    evidence_shape_digest(value)
        .map_err(|error| SkillContractError::Canonicalization(error.to_string()))
}

/// Returns the only ELIOT contract dependencies consumed by this surface.
#[must_use]
pub const fn foundation_contract_names() -> (&'static str, &'static str, &'static str) {
    (
        eliot_evidence::CONTRACT_NAME,
        eliot_receipts::CONTRACT_NAME,
        eliot_rules::CONTRACT_NAME,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn behavior() -> SkillBehavior {
        SkillBehavior {
            intent: "verify one bounded Rust change".to_owned(),
            trigger: "a bounded Rust verifier is required".to_owned(),
            action: "run cargo test".to_owned(),
            applies_when: vec!["the package is exact".to_owned()],
            where_not_apply: vec!["the host is unsupported".to_owned()],
            required_outputs: vec!["test result".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            stop: "stop on stale material".to_owned(),
            escalation: "report PLAN_GAP".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
        }
    }

    fn inputs() -> MaterializationInputs {
        MaterializationInputs {
            canonical_source_bytes: b"canonical source\n".to_vec(),
            contract_materialization: behavior(),
            dependencies: vec![DependencyMaterial {
                name: "eliot-evidence".to_owned(),
                version: "0.1.0".to_owned(),
                contract_digest: canonical_digest(&"evidence-v1").expect("fixture digest"),
            }],
            tool_definitions: vec![ToolDefinitionMaterial {
                name: "cargo".to_owned(),
                version: "1.89".to_owned(),
                description: "bounded Cargo verifier".to_owned(),
                capabilities: vec![CapabilityVersion {
                    name: "rust-test".to_owned(),
                    version: "1".to_owned(),
                }],
                actions: vec!["run cargo test".to_owned()],
            }],
        }
    }

    fn fixture_package() -> SkillPackage {
        let inputs = inputs();
        SkillPackage {
            registration: RegistrationIdentity::new("skill.test", "r1", "Test skill")
                .expect("valid registration"),
            digests: PackageDigests::derive(&inputs).expect("valid inputs"),
            host: HostProfile {
                host: "codex".to_owned(),
                profile: "default".to_owned(),
                required_tools: vec![VersionedRequirement {
                    name: "cargo".to_owned(),
                    version: "1.89".to_owned(),
                }],
                required_capabilities: vec![VersionedRequirement {
                    name: "rust-test".to_owned(),
                    version: "1".to_owned(),
                }],
                limits: HostLimits {
                    max_description_chars: 500,
                    max_actions: 1,
                    max_expansion_handles: 2,
                },
            },
            behavior: behavior(),
            counters: SkillCounters::default(),
            state: SkillState {
                freshness: FreshnessState::Current,
                conflict: ConflictState::None,
                distractor: DistractorState::None,
                quarantine: QuarantineState::Clear,
            },
            lifecycle_proposal: LifecycleProposal::Keep,
            delivery: DeliveryProjection::default(),
            interaction: SkillInteractionProjection::default(),
            rule: advisory_rule(),
        }
    }

    fn advisory_rule() -> AdvisoryRuleClaim {
        // Deserialization is only a fixture convenience; a wire RuleRef is advisory.
        serde_json::from_str(r#"{"rule_ref":{"rule_id":"G16-SKILL","revision":1}}"#)
            .expect("valid rule fixture")
    }

    fn available(field: AvailabilityField) -> Availability {
        Availability::Available { field }
    }

    fn readiness() -> ReadinessClaims {
        ReadinessClaims {
            host: "codex".to_owned(),
            profile: "default".to_owned(),
            provider: available(AvailabilityField::Provider),
            g16: available(AvailabilityField::G16),
            a06: available(AvailabilityField::A06),
            evidence: available(AvailabilityField::Evidence),
            tools: vec![VersionedObservation {
                name: "cargo".to_owned(),
                version: "1.89".to_owned(),
                availability: available(AvailabilityField::HostCapability),
            }],
            capabilities: vec![VersionedObservation {
                name: "rust-test".to_owned(),
                version: "1".to_owned(),
                availability: available(AvailabilityField::HostCapability),
            }],
        }
    }

    fn scope() -> MaterializationScope {
        serde_json::from_str(
            r#"{"work_scope":{"scope_id":"scope","product_id":"product","resource_generation":1,"state_fence":{"authority_epoch":1,"resource_generation":1}},"task":null}"#,
        )
        .expect("valid scope fixture")
    }

    fn catalogue_entry() -> RuleCatalogueEntry {
        serde_json::from_str(
            r#"{
                "rule_ref":{"rule_id":"G16-SKILL","revision":1},
                "class":"HARD_BOUNDARY",
                "architecture_anchor_or_policy_root":"Architecture A7.10",
                "owning_implementation_section_and_capability":"G-16",
                "scope_and_applicability":"A-15 skill materialization",
                "rationale_and_failure_class":"caller claims are advisory",
                "observable_property_or_decision_changed":"materialization is omitted",
                "enforcement_or_degraded_behavior":"PLAN_GAP",
                "challenge_deviation_or_change_path":"G-16 review",
                "invalidation_and_expiry":"superseded exact rule revision"
            }"#,
        )
        .expect("valid catalogue entry")
    }

    struct ReceiptFixtureSpec {
        kind: ReceiptKind,
        event: &'static str,
        disposition: ReceiptDispositionKind,
        verifier: bool,
        operation_id: &'static str,
        predecessor_ids: Vec<String>,
        effect: EffectClass,
        extra_artifacts: Vec<serde_json::Value>,
        verifier_artifact_ids: Vec<String>,
    }

    fn artifact(artifact_id: &str, sha256: &str, role: ReceiptKind) -> serde_json::Value {
        serde_json::json!({
            "artifact_id": artifact_id,
            "sha256": sha256,
            "role": role,
            "source_revision": null
        })
    }

    #[allow(clippy::too_many_lines)]
    fn receipt_claim(package: &SkillPackage, spec: ReceiptFixtureSpec) -> ReceiptClaim {
        let identity_digest = package
            .materialization_identity_digest(&inputs())
            .expect("materialization identity");
        let fence = serde_json::json!({"authority_epoch":1,"resource_generation":1});
        let request_id = format!("request-{}", spec.operation_id);
        let mut artifacts = vec![serde_json::json!({
            "artifact_id": "package-artifact",
            "sha256": identity_digest,
            "role": ReceiptKind::Artifact,
            "source_revision": package.registration.revision
        })];
        artifacts.extend(spec.extra_artifacts);
        let verifier_artifact_ids = if spec.verifier_artifact_ids.is_empty() {
            vec!["package-artifact".to_owned()]
        } else {
            spec.verifier_artifact_ids
        };
        let verifier = spec.verifier.then(|| {
            serde_json::json!({
                "verifier_id":"review-1",
                "verifier_revision":{"major":1,"minor":0,"patch":0},
                "artifact_ids":verifier_artifact_ids,
                "proof_ceiling":"SCOPED_VERIFICATION",
                "state_fence":fence
            })
        });
        let disposition = match spec.disposition {
            ReceiptDispositionKind::Success => {
                serde_json::json!({"kind":"SUCCESS","proof":"SCOPED_VERIFICATION"})
            }
            ReceiptDispositionKind::Failure => serde_json::json!({
                "kind":"FAILURE","code":"INTERNAL","proof":"OBSERVATION"
            }),
            ReceiptDispositionKind::Unknown => {
                serde_json::json!({"kind":"UNKNOWN","reason":"fixture unknown"})
            }
            ReceiptDispositionKind::Partial | ReceiptDispositionKind::Cancelled => {
                panic!("unsupported receipt fixture disposition")
            }
        };
        let transaction_sequence = if spec.predecessor_ids.is_empty() {
            1
        } else {
            2
        };
        let parent_receipt_id = spec.predecessor_ids.first().cloned();
        let core: eliot_receipts::ReceiptCore = serde_json::from_value(serde_json::json!({
            "contract":{
                "name":"eliot.foundation.receipts",
                "version":{"major":1,"minor":0,"patch":0},
                "shape_sha256":"0".repeat(DIGEST_LENGTH)
            },
            "kind":spec.kind,
            "work_scope":{
                "scope_id":"scope",
                "product_id":"product",
                "resource_generation":1,
                "state_fence":fence
            },
            "task":null,
            "session":null,
            "causal":{
                "state_fence":fence,
                "transaction_sequence":transaction_sequence,
                "parent_receipt_id":parent_receipt_id,
                "predecessor_receipt_ids":spec.predecessor_ids
            },
            "request":{
                "metadata":{
                    "request_id":request_id,
                    "session_id":null,
                    "task_id":null,
                    "product_id":"product",
                    "source_id":"source",
                    "state_fence":fence,
                    "clock":{}
                },
                "state_fence":fence
            },
            "operation":{
                "operation_id":spec.operation_id,
                "request_id":request_id,
                "idempotency_key":format!("idempotency-{}", spec.operation_id),
                "operation_kind":format!(
                    "eliot.skills/{}/{}/{}/{}",
                    spec.event, package.host.host, package.host.profile, package.registration.skill_id
                ),
                "effect":spec.effect,
                "state_fence":fence
            },
            "authority":{
                "authority_id":"g16-authority",
                "authority_owner":"G-16",
                "authority_epoch":1,
                "state_fence":fence,
                "allowed_effect":spec.effect,
                "proof_ceiling":"SCOPED_VERIFICATION"
            },
            "artifacts":artifacts,
            "verifier":verifier,
            "problem":null,
            "coordination":null,
            "disposition":disposition
        }))
        .expect("valid receipt core fixture");
        ReceiptClaim {
            envelope: ReceiptEnvelope::issue(core).expect("canonical receipt fixture"),
            evidence_ref: format!("evidence-{}", spec.operation_id),
        }
    }

    fn positive_receipt(
        package: &SkillPackage,
        kind: ReceiptKind,
        event: &'static str,
        operation_id: &'static str,
    ) -> ReceiptClaim {
        receipt_claim(
            package,
            ReceiptFixtureSpec {
                kind,
                event,
                disposition: ReceiptDispositionKind::Success,
                verifier: matches!(kind, ReceiptKind::Verification),
                operation_id,
                predecessor_ids: Vec::new(),
                effect: EffectClass::Read,
                extra_artifacts: Vec::new(),
                verifier_artifact_ids: Vec::new(),
            },
        )
    }

    struct FixturePorts;

    impl sealed::Sealed for FixturePorts {}

    impl ReadinessVerifierPort for FixturePorts {
        fn verify(
            &self,
            request: &VerificationRequest<'_>,
        ) -> Result<VerifiedReadinessDecision, SkillContractError> {
            Ok(VerifiedReadinessDecision {
                binding_digest: request.verification_binding_digest.clone(),
                decision_ref: "readiness-fixture".to_owned(),
            })
        }
    }

    impl G16VerifierPort for FixturePorts {
        fn verify(
            &self,
            request: &VerificationRequest<'_>,
        ) -> Result<VerifiedG16Decision, SkillContractError> {
            Ok(VerifiedG16Decision {
                binding_digest: request.verification_binding_digest.clone(),
                catalogue_entry: catalogue_entry(),
                accepted_receipt_ids: all_receipt_claims(request.package)
                    .map(|claim| claim.envelope.identity.receipt_id.as_str().to_owned())
                    .collect(),
            })
        }
    }

    #[test]
    fn raw_source_and_actual_materialization_inputs_are_recomputed() {
        let actual_inputs = inputs();
        let package = fixture_package();
        assert_eq!(package.validate(&actual_inputs), Ok(()));

        let mut changed = actual_inputs.clone();
        changed.canonical_source_bytes.push(b'!');
        assert!(matches!(
            package.validate(&changed),
            Err(SkillContractError::MaterializationDigestMismatch {
                field: "source_digest"
            })
        ));

        let mut changed = actual_inputs;
        changed.tool_definitions[0].version = "forged".to_owned();
        assert!(matches!(
            package.validate(&changed),
            Err(SkillContractError::MaterializationDigestMismatch {
                field: "tool_definition_digest"
            })
        ));
    }

    #[test]
    fn caller_strings_cannot_mint_readiness_or_g16_acceptance() {
        let package = fixture_package();
        let inputs = inputs();
        let missing = MissingVerificationProvider;
        let ports = MaterializationPorts {
            readiness: &missing,
            g16: &missing,
        };
        let scope: MaterializationScope = serde_json::from_str(
            r#"{"work_scope":{"scope_id":"scope","product_id":"product","resource_generation":1,"state_fence":{"authority_epoch":1,"resource_generation":1}},"task":null}"#,
        )
        .expect("valid scope fixture");
        assert!(matches!(
            package.materialize(&inputs, &readiness(), &scope, &ports),
            Err(SkillContractError::PlanGap {
                code: UnavailableCode::ProviderUnavailable,
                ..
            })
        ));
    }

    #[test]
    fn accepted_results_exist_only_through_the_sealed_materializer_path() {
        let package = fixture_package();
        let fixture_ports = FixturePorts;
        let ports = MaterializationPorts {
            readiness: &fixture_ports,
            g16: &fixture_ports,
        };
        let outcome = package
            .materialize(&inputs(), &readiness(), &scope(), &ports)
            .expect("sealed fixture materialization");
        let materialized = outcome
            .materialized_skill()
            .expect("sealed positive result");
        assert_eq!(materialized.package(), &package);
        assert_eq!(
            materialized.verified_rule().class(),
            RuleClass::HardBoundary
        );
        assert!(materialized.accepted_receipt_ids().is_empty());
        assert_eq!(materialized.readiness_decision_ref(), "readiness-fixture");
        assert!(outcome.omission_reason().is_none());
    }

    #[test]
    fn availability_code_must_match_its_field() {
        let mut readiness = readiness();
        readiness.provider = Availability::Unavailable {
            field: AvailabilityField::Provider,
            code: UnavailableCode::A06Unavailable,
            reason: "wrong typed code".to_owned(),
        };
        assert!(matches!(
            readiness.validate(),
            Err(SkillContractError::AvailabilityCodeMismatch { field: "provider" })
        ));
    }

    #[test]
    fn conflict_refs_are_bijective_and_conflict_always_omits() {
        let mut package = fixture_package();
        package.interaction.conflict_refs = vec!["skill.rival".to_owned()];
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::LifecycleContradiction {
                field: "interaction.conflict_refs_without_conflict"
            })
        ));

        package.state.conflict = ConflictState::Conflicted {
            references: vec!["skill.rival".to_owned()],
        };
        let missing = MissingVerificationProvider;
        let ports = MaterializationPorts {
            readiness: &missing,
            g16: &missing,
        };
        let scope: MaterializationScope = serde_json::from_str(
            r#"{"work_scope":{"scope_id":"scope","product_id":"product","resource_generation":1,"state_fence":{"authority_epoch":1,"resource_generation":1}},"task":null}"#,
        )
        .expect("valid scope fixture");
        let outcome = package
            .materialize(&inputs(), &readiness(), &scope, &ports)
            .expect("conflict omission");
        assert!(matches!(
            outcome.omission_reason(),
            Some(OmissionReason::Conflict { .. })
        ));
    }

    #[test]
    fn lifecycle_flags_and_counts_cannot_contradict_evidence() {
        let mut package = fixture_package();
        package.delivery.installed = true;
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::LifecycleContradiction { field: "installed" })
        ));

        let mut package = fixture_package();
        package.counters.verified_count = 1;
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::LifecycleContradiction {
                field: "verified_count"
            })
        ));
    }

    #[test]
    fn positive_lifecycle_receipts_require_exact_kind_and_success() {
        let mut package = fixture_package();
        let installation = positive_receipt(
            &package,
            ReceiptKind::Artifact,
            "installed",
            "install-success",
        );
        package.delivery.installed = true;
        package.delivery.installation_receipts = vec![installation];
        package.counters.installed_count = 1;
        assert_eq!(package.validate(&inputs()), Ok(()));

        let mut failure_package = fixture_package();
        let failure = receipt_claim(
            &failure_package,
            ReceiptFixtureSpec {
                kind: ReceiptKind::Artifact,
                event: "installed",
                disposition: ReceiptDispositionKind::Failure,
                verifier: false,
                operation_id: "install-failure",
                predecessor_ids: Vec::new(),
                effect: EffectClass::Read,
                extra_artifacts: Vec::new(),
                verifier_artifact_ids: Vec::new(),
            },
        );
        failure_package.delivery.installed = true;
        failure_package.delivery.installation_receipts = vec![failure];
        failure_package.counters.installed_count = 1;
        assert!(matches!(
            failure_package.validate(&inputs()),
            Err(SkillContractError::ReceiptBindingMismatch {
                field: "delivery.installation_receipts"
            })
        ));

        let mut wrong_kind_package = fixture_package();
        let wrong_kind = positive_receipt(
            &wrong_kind_package,
            ReceiptKind::Operation,
            "installed",
            "install-wrong-kind",
        );
        wrong_kind_package.delivery.installed = true;
        wrong_kind_package.delivery.installation_receipts = vec![wrong_kind];
        wrong_kind_package.counters.installed_count = 1;
        assert!(matches!(
            wrong_kind_package.validate(&inputs()),
            Err(SkillContractError::ReceiptBindingMismatch {
                field: "delivery.installation_receipts"
            })
        ));
    }

    #[test]
    fn expansion_is_receipt_bijective_and_duplicate_receipts_are_rejected() {
        let mut package = fixture_package();
        let installation = positive_receipt(
            &package,
            ReceiptKind::Artifact,
            "installed",
            "install-expand",
        );
        let delivery = positive_receipt(
            &package,
            ReceiptKind::Coordination,
            "delivered",
            "deliver-expand",
        );
        let expansion = positive_receipt(
            &package,
            ReceiptKind::Coordination,
            "expanded",
            "expand-success",
        );
        package.delivery.installed = true;
        package.delivery.delivered = true;
        package.delivery.expanded = true;
        package.delivery.installation_receipts = vec![installation];
        package.delivery.delivery_receipts = vec![delivery];
        package.delivery.expansion_receipts = vec![expansion];
        package.counters.installed_count = 1;
        package.counters.delivery_count = 1;
        package.counters.expansion_count = 1;
        assert_eq!(package.validate(&inputs()), Ok(()));

        let mut duplicate_package = fixture_package();
        let receipt = positive_receipt(
            &duplicate_package,
            ReceiptKind::Artifact,
            "installed",
            "duplicate-install",
        );
        duplicate_package.delivery.installed = true;
        duplicate_package.delivery.installation_receipts = vec![receipt.clone(), receipt];
        duplicate_package.counters.installed_count = 2;
        assert!(matches!(
            duplicate_package.validate(&inputs()),
            Err(SkillContractError::LifecycleContradiction {
                field: "delivery.duplicate_receipt_identity"
            })
        ));
    }

    #[test]
    fn failed_and_unknown_execution_evidence_never_sets_positive_execution() {
        let mut package = fixture_package();
        let installation = positive_receipt(
            &package,
            ReceiptKind::Artifact,
            "installed",
            "install-failed-exec",
        );
        let delivery = positive_receipt(
            &package,
            ReceiptKind::Coordination,
            "delivered",
            "deliver-failed-exec",
        );
        let failure = receipt_claim(
            &package,
            ReceiptFixtureSpec {
                kind: ReceiptKind::Operation,
                event: "executed",
                disposition: ReceiptDispositionKind::Failure,
                verifier: false,
                operation_id: "failed-exec",
                predecessor_ids: Vec::new(),
                effect: EffectClass::Read,
                extra_artifacts: Vec::new(),
                verifier_artifact_ids: Vec::new(),
            },
        );
        package.delivery.installed = true;
        package.delivery.delivered = true;
        package.delivery.installation_receipts = vec![installation];
        package.delivery.delivery_receipts = vec![delivery];
        package.delivery.execution_evidence = vec![ExecutionEvidenceProjection {
            step_refs: vec!["step-failed".to_owned()],
            receipt: failure,
            outcome: ExecutionOutcome::Failed,
            causal_credit: CausalCredit::None,
        }];
        package.counters.installed_count = 1;
        package.counters.delivery_count = 1;
        package.counters.failed_count = 1;
        assert_eq!(package.validate(&inputs()), Ok(()));

        package.delivery.executed = true;
        package.counters.execution_count = 1;
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::LifecycleContradiction {
                field: "execution_count"
            })
        ));

        let mut uncertain_package = fixture_package();
        let uncertain_installation = positive_receipt(
            &uncertain_package,
            ReceiptKind::Artifact,
            "installed",
            "install-uncertain-exec",
        );
        let uncertain_delivery = positive_receipt(
            &uncertain_package,
            ReceiptKind::Coordination,
            "delivered",
            "deliver-uncertain-exec",
        );
        let unknown = receipt_claim(
            &uncertain_package,
            ReceiptFixtureSpec {
                kind: ReceiptKind::Operation,
                event: "executed",
                disposition: ReceiptDispositionKind::Unknown,
                verifier: false,
                operation_id: "uncertain-exec",
                predecessor_ids: Vec::new(),
                effect: EffectClass::Read,
                extra_artifacts: Vec::new(),
                verifier_artifact_ids: Vec::new(),
            },
        );
        uncertain_package.delivery.installed = true;
        uncertain_package.delivery.delivered = true;
        uncertain_package.delivery.installation_receipts = vec![uncertain_installation];
        uncertain_package.delivery.delivery_receipts = vec![uncertain_delivery];
        uncertain_package.delivery.execution_evidence = vec![ExecutionEvidenceProjection {
            step_refs: vec!["step-uncertain".to_owned()],
            receipt: unknown,
            outcome: ExecutionOutcome::Uncertain,
            causal_credit: CausalCredit::Uncertain,
        }];
        uncertain_package.counters.installed_count = 1;
        uncertain_package.counters.delivery_count = 1;
        uncertain_package.counters.uncertain_count = 1;
        assert_eq!(uncertain_package.validate(&inputs()), Ok(()));
    }

    #[test]
    fn observed_execution_needs_separate_causal_verification_and_useful_receipts() {
        let mut package = fixture_package();
        let installation = positive_receipt(
            &package,
            ReceiptKind::Artifact,
            "installed",
            "install-observed",
        );
        let delivery = positive_receipt(
            &package,
            ReceiptKind::Coordination,
            "delivered",
            "deliver-observed",
        );
        let execution = positive_receipt(
            &package,
            ReceiptKind::Operation,
            "executed",
            "execute-observed",
        );
        let execution_receipt_id = execution.envelope.identity.receipt_id.as_str().to_owned();
        let verification = receipt_claim(
            &package,
            ReceiptFixtureSpec {
                kind: ReceiptKind::Verification,
                event: "verified",
                disposition: ReceiptDispositionKind::Success,
                verifier: true,
                operation_id: "verify-observed",
                predecessor_ids: vec![execution_receipt_id],
                effect: EffectClass::Read,
                extra_artifacts: Vec::new(),
                verifier_artifact_ids: Vec::new(),
            },
        );
        let verification_receipt_id = verification
            .envelope
            .identity
            .receipt_id
            .as_str()
            .to_owned();
        let useful = receipt_claim(
            &package,
            ReceiptFixtureSpec {
                kind: ReceiptKind::Verification,
                event: "useful",
                disposition: ReceiptDispositionKind::Success,
                verifier: true,
                operation_id: "useful-observed",
                predecessor_ids: vec![verification_receipt_id],
                effect: EffectClass::Read,
                extra_artifacts: Vec::new(),
                verifier_artifact_ids: Vec::new(),
            },
        );
        package.delivery.installed = true;
        package.delivery.delivered = true;
        package.delivery.executed = true;
        package.delivery.verified = true;
        package.delivery.useful = true;
        package.delivery.installation_receipts = vec![installation];
        package.delivery.delivery_receipts = vec![delivery];
        package.delivery.execution_evidence = vec![ExecutionEvidenceProjection {
            step_refs: vec!["step-observed".to_owned()],
            receipt: execution,
            outcome: ExecutionOutcome::Observed,
            causal_credit: CausalCredit::None,
        }];
        package.delivery.verification_receipts = vec![verification];
        package.delivery.useful_receipts = vec![useful];
        package.counters.installed_count = 1;
        package.counters.delivery_count = 1;
        package.counters.execution_count = 1;
        package.counters.verified_count = 1;
        package.counters.useful_count = 1;
        assert_eq!(package.validate(&inputs()), Ok(()));

        package.delivery.verification_receipts.clear();
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::LifecycleContradiction {
                field: "verified_count"
            })
        ));
    }

    #[test]
    fn short_contract_requires_intent_outputs_writeback_and_one_action() {
        let mut package = fixture_package();
        package.behavior.intent.clear();
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::InvalidText {
                field: "behavior.intent"
            })
        ));

        let mut package = fixture_package();
        package.host.limits.max_actions = 2;
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::AmbiguousStructure { .. })
        ));

        let mut package = fixture_package();
        package.host.limits.max_description_chars = 1;
        assert_eq!(
            package.validate(&inputs()),
            Err(SkillContractError::DescriptionTooLong)
        );
    }

    #[test]
    fn exact_tool_and_capability_versions_and_observations_are_required() {
        let mut package = fixture_package();
        package.host.required_tools[0].version = "wrong".to_owned();
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::UnsupportedCapability {
                field: "host.required_tools"
            })
        ));

        let package = fixture_package();
        let mut missing_capability = readiness();
        missing_capability.capabilities.clear();
        assert!(matches!(
            package.validate_observations(&missing_capability),
            Err(SkillContractError::UnsupportedCapability {
                field: "readiness.capabilities"
            })
        ));

        let package = fixture_package();
        let mut duplicate_observation = readiness();
        let mut conflicting = duplicate_observation.tools[0].clone();
        conflicting.availability = Availability::Unavailable {
            field: AvailabilityField::HostCapability,
            code: UnavailableCode::HostCapabilityUnavailable,
            reason: "conflicting duplicate".to_owned(),
        };
        duplicate_observation.tools.push(conflicting);
        assert!(matches!(
            package.validate_observations(&duplicate_observation),
            Err(SkillContractError::AmbiguousStructure {
                reason: "readiness.tools"
            })
        ));

        let mut ordered = readiness();
        ordered.tools.push(VersionedObservation {
            name: "other-tool".to_owned(),
            version: "2".to_owned(),
            availability: available(AvailabilityField::HostCapability),
        });
        ordered.capabilities.push(VersionedObservation {
            name: "other-capability".to_owned(),
            version: "2".to_owned(),
            availability: available(AvailabilityField::HostCapability),
        });
        let mut reversed = ordered.clone();
        reversed.tools.reverse();
        reversed.capabilities.reverse();
        assert_eq!(
            package.validate_observations(&reversed),
            package.validate_observations(&ordered)
        );
    }

    #[test]
    fn observed_execution_cannot_be_mislabeled_verified_or_useful() {
        let mut package = fixture_package();
        package.delivery.useful = true;
        package.counters.useful_count = 1;
        assert!(matches!(
            package.validate(&inputs()),
            Err(SkillContractError::LifecycleContradiction { .. })
        ));
    }

    #[test]
    fn lifecycle_proposals_cannot_promote_authority() {
        assert_eq!(
            validate_reversible_authority(
                EffectClass::ReversibleMutation,
                EffectClass::ReversibleMutation,
                ProofCeiling::ScopedVerification,
            ),
            Ok(())
        );
        assert!(matches!(
            validate_reversible_authority(
                EffectClass::ExternalEffect,
                EffectClass::ExternalEffect,
                ProofCeiling::ObservedExternalEffect,
            ),
            Err(SkillContractError::InvalidLifecycleProposal {
                field: "lifecycle.proposal_receipt.authority"
            })
        ));
    }

    #[test]
    fn lifecycle_proposal_fields_bind_receipt_artifacts_and_verification_digest() {
        let mut package = fixture_package();
        let evidence_digest = "1".repeat(DIGEST_LENGTH);
        let rollback_digest = "2".repeat(DIGEST_LENGTH);
        let proposal_receipt = receipt_claim(
            &package,
            ReceiptFixtureSpec {
                kind: ReceiptKind::Operation,
                event: "proposal",
                disposition: ReceiptDispositionKind::Success,
                verifier: true,
                operation_id: "proposal-operation",
                predecessor_ids: Vec::new(),
                effect: EffectClass::ReversibleMutation,
                extra_artifacts: vec![
                    artifact("evidence-1", &evidence_digest, ReceiptKind::Verification),
                    artifact("rollback-1", &rollback_digest, ReceiptKind::Artifact),
                ],
                verifier_artifact_ids: vec!["evidence-1".to_owned(), "rollback-1".to_owned()],
            },
        );
        let before = package
            .verification_binding_digest(&inputs(), &readiness(), &scope())
            .expect("keep binding digest");
        let binding = ReversibleLifecycleBinding {
            action: ReversibleLifecycleAction::Patch,
            evidence_refs: vec!["evidence-1".to_owned()],
            review_ref: "review-1".to_owned(),
            owner_ref: "G-16".to_owned(),
            rollback_ref: "rollback-1".to_owned(),
            rollback_artifact_digest: rollback_digest,
            proposal_receipt,
        };
        package.lifecycle_proposal = LifecycleProposal::Reversible(Box::new(binding.clone()));
        assert_eq!(package.validate(&inputs()), Ok(()));
        let after = package
            .verification_binding_digest(&inputs(), &readiness(), &scope())
            .expect("proposal binding digest");
        assert_ne!(before, after);

        let fixture_ports = FixturePorts;
        let ports = MaterializationPorts {
            readiness: &fixture_ports,
            g16: &fixture_ports,
        };
        let outcome = package
            .materialize(&inputs(), &readiness(), &scope(), &ports)
            .expect("sealed proposal verification");
        assert_eq!(
            outcome
                .materialized_skill()
                .expect("accepted proposal")
                .accepted_receipt_ids()
                .len(),
            1
        );

        for invalid in [
            ReversibleLifecycleBinding {
                owner_ref: "caller".to_owned(),
                ..binding.clone()
            },
            ReversibleLifecycleBinding {
                review_ref: "caller-review".to_owned(),
                ..binding.clone()
            },
            ReversibleLifecycleBinding {
                evidence_refs: vec!["caller-evidence".to_owned()],
                ..binding.clone()
            },
            ReversibleLifecycleBinding {
                rollback_artifact_digest: "3".repeat(DIGEST_LENGTH),
                ..binding
            },
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(SkillContractError::InvalidLifecycleProposal { .. })
            ));
        }
    }

    #[test]
    fn enforcement_class_and_provenance_come_from_exact_catalogue_entry() {
        let entry = catalogue_entry();
        let provenance = canonical_digest(&entry).expect("catalogue provenance");
        let verified =
            VerifiedRuleProjection::from_catalogue_entry(&entry).expect("exact entry projection");
        assert_eq!(verified.rule_ref(), &advisory_rule().rule_ref);
        assert_eq!(verified.class(), RuleClass::HardBoundary);
        assert_eq!(verified.catalogue_provenance_digest(), provenance);

        let mut forged = verified;
        forged.catalogue_provenance_digest = "0".repeat(DIGEST_LENGTH);
        assert_eq!(
            forged.validate(),
            Err(SkillContractError::RuleVerificationMismatch)
        );
    }

    #[test]
    fn dependency_order_does_not_change_canonical_digest() {
        let mut left = inputs();
        left.dependencies.push(DependencyMaterial {
            name: "eliot-rules".to_owned(),
            version: "0.1.0".to_owned(),
            contract_digest: canonical_digest(&"rules-v1").expect("fixture digest"),
        });
        let mut right = left.clone();
        right.dependencies.reverse();
        assert_eq!(
            PackageDigests::derive(&left).expect("left"),
            PackageDigests::derive(&right).expect("right")
        );
        assert_eq!(
            foundation_contract_names(),
            (
                "eliot.foundation.evidence",
                "eliot.foundation.receipts",
                "eliot.foundation.rules"
            )
        );
    }
}
