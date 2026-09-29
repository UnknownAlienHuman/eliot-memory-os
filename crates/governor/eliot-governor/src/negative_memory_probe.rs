//! Governor-owned, read-only admission for a negative-memory discriminating
//! probe (issue #1731 W5, I12.19, A14.3).
//!
//! A proposal is not an execution receipt and does not grant permission to
//! retry the protected action. It names only the record owner's registered
//! check and verifier, carries a closed read-only effect ceiling and a budget
//! scoped to that one check, and retains the identities of the action that
//! must not be replayed.
//! There is deliberately no command, callback, executable, or mutable effect
//! field that could relabel that action as a probe.

use eliot_contracts::{OperationId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_failure::{
    NegativeMemoryActionPolicy, NegativeMemoryCandidateRead, NegativeMemoryDisposition,
    NegativeMemoryFingerprint, NegativeMemorySubject,
};
use serde::Serialize;

const PROBE_IDENTITY_DOMAIN: &str = "eliot-negative-memory-probe-v1";
const PROBE_OPERATION_PREFIX: &str = "negative-memory-probe";

/// The strongest effect a negative-memory discriminating probe may request.
///
/// This closed enum has no conversion to a mutation or external-effect class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum NegativeMemoryProbeEffectCeiling {
    /// A named read-only check; this proposal executes no effect itself.
    ReadOnly,
}

/// Proposal budget: exactly one owner-named discriminating check.
///
/// This scopes the proposal; it does not set execution byte, time, attempt, or
/// call limits. Any runtime resource budget belongs to the admitted check's
/// executor contract, which this proposal does not implement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum NegativeMemoryProbeBudget {
    /// The one named check bound to this proposal.
    OneNamedDiscriminatingCheck,
}

impl NegativeMemoryProbeBudget {
    /// The only proposal budget admitted by this Governor contract.
    pub const ADMITTED: Self = Self::OneNamedDiscriminatingCheck;
}

/// Structural guard carried into the proposal so an executor can identify
/// the exact operation/effect identities it is forbidden to repeat.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NegativeMemoryProbeForbiddenEffectGuard {
    /// Action identity that caused this exact-match check.
    pub action_id: String,
    /// Operation identity that must not be replayed under the probe label.
    pub operation_id: String,
    /// Effect identity that must not be replayed under the probe label.
    pub effect_id: String,
    /// Digest of the protected action's input.
    pub input_digest: String,
}

/// Why a read-only probe cannot be admitted for the exact matched action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeMemoryProbeRefusal {
    /// A required bound identity was absent or malformed.
    BindingInvalid,
    /// A supplied operation/effect identity would replay the protected action.
    ProtectedEffectIdentityReused,
    /// The proposal digest or deterministic operation identity does not match.
    IdentityMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct NegativeMemoryProbeBody {
    schema_version: u8,
    probe_id: String,
    probe_operation_id: String,
    record_id: String,
    rule_revision: u64,
    record_digest: String,
    policy_id: String,
    policy_revision: u64,
    source_operation_id: String,
    source_action_id: String,
    source_effect_id: String,
    source_input_digest: String,
    canonical_request_digest: String,
    subject_digest: String,
    read_handle: String,
    rule_set_revision: String,
    rule_set_digest: String,
    state_fence: StateFence,
    check_id: String,
    required_verifier: String,
    verifier_revision: String,
    verifier_digest: String,
    discriminates_dimension_names: Vec<String>,
    effect_ceiling: NegativeMemoryProbeEffectCeiling,
    budget: NegativeMemoryProbeBudget,
    forbidden_effect_guard: NegativeMemoryProbeForbiddenEffectGuard,
}

/// Governor admission for one specific safe, discriminating check.
///
/// The fields are private and there is no deserializer. The value is produced
/// only by [`admit_negative_memory_probe`] after the negative-memory gate has
/// validated an exact match, owner policy, candidate read and request binding.
/// It authorizes proposal delivery only; an executor and verifier still need
/// their own admitted contracts and receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NegativeMemoryProbeAdmission {
    probe_id: String,
    proposal_digest: String,
    effect_ceiling: NegativeMemoryProbeEffectCeiling,
    budget: NegativeMemoryProbeBudget,
    state_fence: StateFence,
}

impl NegativeMemoryProbeAdmission {
    /// Stable identity of the admitted proposal.
    #[must_use]
    pub fn probe_id(&self) -> &str {
        &self.probe_id
    }

    /// Digest of all proposal terms, including the source identities and
    /// prohibition guard.
    #[must_use]
    pub fn proposal_digest(&self) -> &str {
        &self.proposal_digest
    }

    /// Closed effect ceiling granted to this proposal.
    #[must_use]
    pub const fn effect_ceiling(&self) -> NegativeMemoryProbeEffectCeiling {
        self.effect_ceiling
    }

    /// Exact budget granted to this proposal.
    #[must_use]
    pub const fn budget(&self) -> NegativeMemoryProbeBudget {
        self.budget
    }

    /// State Fence bound to the read and action that triggered the probe.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
}

/// Typed Governor proposal for one safe check named by an exact rule match.
///
/// All load-bearing fields are private and exposed read-only. The proposal
/// contains no executable payload; its only available effect class is
/// `ReadOnly`, and its source action identities are retained in the guard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NegativeMemoryProbeProposal {
    body: NegativeMemoryProbeBody,
    admission: NegativeMemoryProbeAdmission,
}

impl NegativeMemoryProbeProposal {
    /// Stable check identity registered by the negative-memory owner.
    #[must_use]
    pub fn check_id(&self) -> &str {
        &self.body.check_id
    }

    /// Exact verifier named by the matched fingerprint.
    #[must_use]
    pub fn required_verifier(&self) -> &str {
        &self.body.required_verifier
    }

    /// Dimensions the named check must discriminate. These are copied from
    /// the admitted fingerprint and cannot be replaced with unrelated checks.
    #[must_use]
    pub fn discriminates_dimension_names(&self) -> &[String] {
        &self.body.discriminates_dimension_names
    }

    /// Distinct stable operation identity for the proposed read-only check.
    #[must_use]
    pub fn probe_operation_id(&self) -> &str {
        &self.body.probe_operation_id
    }

    /// Original operation identity preserved as a forbidden replay target.
    #[must_use]
    pub fn source_operation_id(&self) -> &str {
        &self.body.source_operation_id
    }

    /// Original effect identity preserved as a forbidden replay target.
    #[must_use]
    pub fn source_effect_id(&self) -> &str {
        &self.body.source_effect_id
    }

    /// Exact action/input that matched the rule.
    #[must_use]
    pub fn source_action(&self) -> (&str, &str) {
        (
            &self.body.forbidden_effect_guard.action_id,
            &self.body.source_input_digest,
        )
    }

    /// Admitted proposal token. It does not authorize an action retry.
    #[must_use]
    pub const fn admission(&self) -> &NegativeMemoryProbeAdmission {
        &self.admission
    }

    /// Revalidates deterministic identity, no-replay bindings, and the
    /// read-only proposal ceiling. This does not enforce runtime limits.
    pub fn validate(&self) -> Result<(), NegativeMemoryProbeRefusal> {
        if self.body.schema_version != 1
            || self.body.effect_ceiling != NegativeMemoryProbeEffectCeiling::ReadOnly
            || self.body.source_operation_id.trim().is_empty()
            || self.body.source_action_id.trim().is_empty()
            || self.body.source_effect_id.trim().is_empty()
            || self.body.source_input_digest.len() != 64
            || self.body.canonical_request_digest.len() != 64
            || self.body.subject_digest.len() != 64
            || self.body.rule_set_digest.len() != 64
            || self.body.check_id.trim().is_empty()
            || self.body.required_verifier.trim().is_empty()
            || self.body.verifier_revision.trim().is_empty()
            || self.body.verifier_digest.len() != 64
            || self.body.discriminates_dimension_names.is_empty()
            || self.body.probe_id == self.body.source_action_id
            || self.body.probe_operation_id == self.body.source_operation_id
            || self.body.probe_operation_id == self.body.source_effect_id
            || self.body.probe_id == self.body.source_effect_id
        {
            return Err(NegativeMemoryProbeRefusal::BindingInvalid);
        }
        if self.body.probe_operation_id == self.body.forbidden_effect_guard.operation_id
            || self.body.probe_id == self.body.forbidden_effect_guard.effect_id
            || self.body.forbidden_effect_guard.operation_id != self.body.source_operation_id
            || self.body.forbidden_effect_guard.effect_id != self.body.source_effect_id
            || self.body.forbidden_effect_guard.action_id != self.body.source_action_id
            || self.body.forbidden_effect_guard.input_digest != self.body.source_input_digest
        {
            return Err(NegativeMemoryProbeRefusal::ProtectedEffectIdentityReused);
        }
        let computed_probe_id = canonical_digest(&ProbeIdentityPreimage {
            domain: PROBE_IDENTITY_DOMAIN,
            record_id: &self.body.record_id,
            rule_revision: self.body.rule_revision,
            record_digest: &self.body.record_digest,
            policy_id: &self.body.policy_id,
            policy_revision: self.body.policy_revision,
            source_operation_id: &self.body.source_operation_id,
            source_action_id: &self.body.source_action_id,
            source_effect_id: &self.body.source_effect_id,
            source_input_digest: &self.body.source_input_digest,
            canonical_request_digest: &self.body.canonical_request_digest,
            subject_digest: &self.body.subject_digest,
            read_handle: &self.body.read_handle,
            rule_set_revision: &self.body.rule_set_revision,
            rule_set_digest: &self.body.rule_set_digest,
            state_fence: &self.body.state_fence,
            check_id: &self.body.check_id,
            required_verifier: &self.body.required_verifier,
            verifier_revision: &self.body.verifier_revision,
            verifier_digest: &self.body.verifier_digest,
        })?;
        if self.body.probe_id != computed_probe_id
            || self.body.probe_operation_id != format!("{PROBE_OPERATION_PREFIX}:{computed_probe_id}")
        {
            return Err(NegativeMemoryProbeRefusal::IdentityMismatch);
        }
        let proposal_digest = canonical_digest(&self.body)?;
        if self.admission.probe_id != self.body.probe_id
            || self.admission.proposal_digest != proposal_digest
            || self.admission.effect_ceiling != self.body.effect_ceiling
            || self.admission.budget != self.body.budget
            || self.admission.state_fence != self.body.state_fence
        {
            return Err(NegativeMemoryProbeRefusal::IdentityMismatch);
        }
        OperationId::new(self.body.probe_operation_id.clone())
            .map_err(|_| NegativeMemoryProbeRefusal::IdentityMismatch)?;
        Ok(())
    }
}

#[derive(Serialize)]
struct ProbeIdentityPreimage<'a> {
    domain: &'static str,
    record_id: &'a str,
    rule_revision: u64,
    record_digest: &'a str,
    policy_id: &'a str,
    policy_revision: u64,
    source_operation_id: &'a str,
    source_action_id: &'a str,
    source_effect_id: &'a str,
    source_input_digest: &'a str,
    canonical_request_digest: &'a str,
    subject_digest: &'a str,
    read_handle: &'a str,
    rule_set_revision: &'a str,
    rule_set_digest: &'a str,
    state_fence: &'a StateFence,
    check_id: &'a str,
    required_verifier: &'a str,
    verifier_revision: &'a str,
    verifier_digest: &'a str,
}

fn canonical_digest(value: &impl Serialize) -> Result<String, NegativeMemoryProbeRefusal> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| NegativeMemoryProbeRefusal::BindingInvalid)
}

/// Admits the only probe shape the Governor can propose for an exact
/// `RequireCheck` match. This is called from the production gate decision
/// builder, not exposed as a caller-selected command constructor.
pub(crate) fn admit_negative_memory_probe(
    record: &NegativeMemoryFingerprint,
    policy: &NegativeMemoryActionPolicy,
    subject: &NegativeMemorySubject,
    read: &NegativeMemoryCandidateRead,
    request_fence: &StateFence,
) -> Result<NegativeMemoryProbeProposal, NegativeMemoryProbeRefusal> {
    if policy.disposition != NegativeMemoryDisposition::RequireCheck
        || policy.validate().is_err()
        || policy.validate_binding(record).is_err()
        || record.validate().is_err()
        || subject.validate().is_err()
        || read.validate().is_err()
        || subject.canonical_request_digest.len() != 64
        || read.state_fence != *request_fence
    {
        return Err(NegativeMemoryProbeRefusal::BindingInvalid);
    }
    let check = &record.discriminating_check;
    if check.discriminates_dimension_names.is_empty()
        || check.required_verifier.trim().is_empty()
        || check.verifier_revision.trim().is_empty()
        || check.verifier_digest.len() != 64
    {
        return Err(NegativeMemoryProbeRefusal::BindingInvalid);
    }
    let subject_digest = subject
        .computed_digest()
        .map_err(|_| NegativeMemoryProbeRefusal::BindingInvalid)?;
    let probe_id = canonical_digest(&ProbeIdentityPreimage {
        domain: PROBE_IDENTITY_DOMAIN,
        record_id: &record.record_id,
        rule_revision: record.rule_revision,
        record_digest: &record.record_digest,
        policy_id: &policy.policy_id,
        policy_revision: policy.policy_revision,
        source_operation_id: &subject.action.operation_id,
        source_action_id: &subject.action.action_id,
        source_effect_id: &subject.action.effect_id,
        source_input_digest: &subject.action.input_digest,
        canonical_request_digest: &subject.canonical_request_digest,
        subject_digest: &subject_digest,
        read_handle: &read.read_handle,
        rule_set_revision: &read.rule_set_revision,
        rule_set_digest: &read.rule_set_digest,
        state_fence: &read.state_fence,
        check_id: &check.check_id,
        required_verifier: &check.required_verifier,
        verifier_revision: &check.verifier_revision,
        verifier_digest: &check.verifier_digest,
    })?;
    let probe_operation_id = format!("{PROBE_OPERATION_PREFIX}:{probe_id}");
    if probe_operation_id == subject.action.operation_id
        || probe_operation_id == subject.action.effect_id
        || probe_id == subject.action.action_id
        || probe_id == subject.action.effect_id
    {
        return Err(NegativeMemoryProbeRefusal::ProtectedEffectIdentityReused);
    }
    let body = NegativeMemoryProbeBody {
        schema_version: 1,
        probe_id: probe_id.clone(),
        probe_operation_id,
        record_id: record.record_id.clone(),
        rule_revision: record.rule_revision,
        record_digest: record.record_digest.clone(),
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision,
        source_operation_id: subject.action.operation_id.clone(),
        source_action_id: subject.action.action_id.clone(),
        source_effect_id: subject.action.effect_id.clone(),
        source_input_digest: subject.action.input_digest.clone(),
        canonical_request_digest: subject.canonical_request_digest.clone(),
        subject_digest,
        read_handle: read.read_handle.clone(),
        rule_set_revision: read.rule_set_revision.clone(),
        rule_set_digest: read.rule_set_digest.clone(),
        state_fence: read.state_fence.clone(),
        check_id: check.check_id.clone(),
        required_verifier: check.required_verifier.clone(),
        verifier_revision: check.verifier_revision.clone(),
        verifier_digest: check.verifier_digest.clone(),
        discriminates_dimension_names: check.discriminates_dimension_names.clone(),
        effect_ceiling: NegativeMemoryProbeEffectCeiling::ReadOnly,
        budget: NegativeMemoryProbeBudget::ADMITTED,
        forbidden_effect_guard: NegativeMemoryProbeForbiddenEffectGuard {
            action_id: subject.action.action_id.clone(),
            operation_id: subject.action.operation_id.clone(),
            effect_id: subject.action.effect_id.clone(),
            input_digest: subject.action.input_digest.clone(),
        },
    };
    let admission = NegativeMemoryProbeAdmission {
        probe_id,
        proposal_digest: canonical_digest(&body)?,
        effect_ceiling: NegativeMemoryProbeEffectCeiling::ReadOnly,
        budget: NegativeMemoryProbeBudget::ADMITTED,
        state_fence: read.state_fence.clone(),
    };
    let proposal = NegativeMemoryProbeProposal { body, admission };
    proposal.validate()?;
    Ok(proposal)
}
