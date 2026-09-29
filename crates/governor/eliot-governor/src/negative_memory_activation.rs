//! Governor-owned governed activation of one negative-memory action policy
//! (issue #1731 W3, I12.19).
//!
//! # What this module is for
//!
//! `NegativeMemoryFingerprint` (W1) is a durable *record* and
//! `NegativeMemoryActionPolicy` (W1) is a durable *policy value*. Neither has
//! effect merely by existing: the record's own doc comment states that
//! "publishing is the activation step that this owner does not perform", and
//! `NegativeMemoryActionPolicy::validate` proves only shape plus a self
//! recomputing digest. This module is the missing step — the one place where an
//! owner-supplied request becomes a governed decision, or is refused.
//!
//! # Why activation is not "a model said block"
//!
//! [`NegativeMemoryActivationRequest`] carries an explicit
//! [`NegativeMemoryActivationEvidence`] and the caller must supply it. A
//! request whose evidence does not name the record, does not cover it
//! completely, or carries a disposition the record's own trigger cannot support
//! is refused. Specifically:
//!
//! * `Block` and `RequireCheck` are refused unless the record carries an
//!   admitted **exact** predicate. `NegativeMemoryFingerprint::validate`
//!   already enforces that an exact predicate requires `FailureCoverage::Complete`
//!   invariant verification and that the discriminating check's
//!   `discriminates_dimension_names` are a subset of the predicate's dimension
//!   names; this module re-uses that validator instead of inventing a second
//!   one, and adds the *admission* join that `validate` does not have: the
//!   action policy's `named_check_id` must equal the record's
//!   `discriminating_check.check_id`.
//! * The policy must bind the exact record revision **and** digest
//!   ([`NegativeMemoryActionPolicy::validate_binding`]), so a policy admitted
//!   against an older rule revision cannot be published against a newer one.
//! * The owner of the policy must equal the record's `semantic_owner`. A
//!   different owner string is refused rather than trusted.
//! * The request's evidence references must be a non-empty set, must each be
//!   named by the record's own retained evidence, and must include the
//!   verifier that the record's reopen condition and discriminating check
//!   require. This is what makes a frequency count, a model assertion, or a
//!   declared invariant name insufficient: none of those produce a verifier
//!   identity plus a complete evidence set that the record itself already
//!   names.
//! * Causal limits are preserved, never upgraded. This is deliberately *not*
//!   a second causal check: `NegativeMemoryFingerprint::validate` already
//!   refuses `causal_claim_permitted: true`, already refuses
//!   `InterventionSupported`, and already requires a non-empty
//!   `limitation_refs` set, and it is the sole existing validator for that
//!   ceiling. Re-asserting it here with a second spelling of the status enum
//!   would invent a parallel scheme, so the published
//!   [`NegativeMemoryActivationDocument`] carries no causal field at all:
//!   accepting a conservative guard can never be read as a claim of mechanism
//!   because no admitted activation asserts one.
//!
//! # Scope and privacy
//!
//! [`NegativeMemoryActivationRequest::affected_scope_digest`] is compared
//! **content-wise** against the retained `NegativeMemoryAffectedScope` on the
//! record. The canonical write is also required to use that same scope ID.
//! This binds the activation to the failed task, scope, environment and
//! resources. The current `NegativeMemoryFingerprint` has no observation-domain
//! or disclosure-decision binding, however. Since I5.26 requires a complete,
//! current disclosure closure before a governed policy decision, this owner
//! refuses `Block` and `RequireCheck` until that current closure can be joined;
//! it does not treat causal limitations as a privacy proof.
//!
//! # The write path
//!
//! Publication goes through the **existing** seam. This module builds one
//! [`CanonicalWriteEnvelope`] and calls
//! [`GovernorComposition::commit_canonical`], i.e. the one
//! `CanonicalWriteEnvelope::prepare` -> `KernelTransitionPort::apply_prepared`
//! route in the process. There is no parallel activation write path, no direct
//! store handle, and no way for a caller to hand in a `PreparedTransition`.
//!
//! The durable bytes use the **existing** named mutation `RecordLearningRecord`
//! with `LearningRecordKind::ActivationReceipt` — an owner-issued activation
//! receipt row keyed `(record_kind, handle, record_digest)`, which is exactly
//! the shape a published rule needs: an immutable identity (the record digest),
//! an owner-assigned handle, and a per-scope row. The store persists the
//! document verbatim and never derives semantics from it; the semantics are
//! admitted here. This is the same seam `learning_record_commit` and
//! `capability_evidence_commit` already use, so no new database, no new named
//! operation and no catalogue change are introduced.
//!
//! The **expected revision** is the `RevisionHeadExpectation` the caller passes
//! for the activation key; the store arbitrates it under a compare-and-set.
//! The **immutable receipt** is the `WriteReceipt` returned by the commit,
//! checked here for status, operation identity, idempotency key, fence
//! agreement, and — exactly as the sibling commit paths apply — revision-head
//! base agreement and ordering-head advance, so a stale projection can never
//! surface as a healthy activation. The receipt is then returned to the caller
//! as [`NegativeMemoryActivationReceipt`], which additionally names the exact
//! rule revision and content digest that are now live.

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, StateFence};
use eliot_dreamer_failure::{
    NegativeMemoryActionPolicy, NegativeMemoryDisposition,
    NegativeMemoryFingerprint, NegativeMemoryHorizon, NegativeMemoryRecordDefect,
    NegativeMemoryReopenCondition, effect_class_text, negative_memory_record_defect,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, LearningRecordKind,
    MAX_LEARNING_RECORD_JSON_BYTES, NamedMutationRequest, OrderingHeadExpectation,
    RevisionHeadExpectation, ScopeId, SecurityContext, TransitionClass, WriteReceipt,
    WriteReceiptStatus, canonical_json_bytes, decode_learning_mutation,
    generated_operation_manifests, learning_record_commit_params, learning_record_mutation_request,
    operation_manifest_set_digest, reject_direct_learning_write, sha256_hex,
};

use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};

/// The durable handle of one published rule activation. The store keys the row
/// by `(record_kind, handle, record_digest)`; the handle names the rule
/// revision so two revisions of one record identity are distinct rows and
/// history is never rewritten in place.
const ACTIVATION_HANDLE_PREFIX: &str = "negative-memory";

/// Wire revision of the activation document this owner writes.
const ACTIVATION_DOCUMENT_SCHEMA_VERSION: u32 = 2;

/// The owner-issued evidence an activation decision rests on.
///
/// This is the W3 "supporting evidence" input. It is deliberately *not* a
/// frequency count, a boolean, or a model-produced claim: it must reproduce the
/// exact verifier binding and complete reference set retained by the record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryActivationEvidence {
    /// Owner-issued verifier that produced the invariant evidence. Must equal
    /// the exact verifier identity retained on the record.
    pub verifier: String,
    /// Exact verifier revision retained by the record.
    pub verifier_revision: String,
    /// Exact verifier digest retained by the record.
    pub verifier_digest: String,
    /// Exact verifier receipt reference retained by the record.
    pub verifier_receipt_ref: String,
    /// Exact complete evidence-reference set retained by the record.
    pub evidence_refs: Vec<String>,
}

/// Why an activation request was refused.
///
/// Every cause keeps its own variant so a refusal is never reported as a
/// generic code, and so no refusal can be read as a softer admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeMemoryActivationRefusal {
    /// The durable record failed its own validator.
    RecordInvalid {
        /// Closed defect class of the record.
        defect: NegativeMemoryRecordDefect,
        /// Exact validator text.
        detail: String,
    },
    /// The policy value failed its own validator.
    PolicyInvalid {
        /// Exact validator text.
        detail: String,
    },
    /// The policy does not bind the presented record revision and digest.
    PolicyNotBoundToRecord {
        /// Policy's bound record identity.
        bound_record_id: String,
        /// Presented record identity.
        record_id: String,
    },
    /// A blocking or probe disposition was requested for a record whose
    /// trigger is not an admitted exact predicate.
    DispositionNotSupportedByTrigger {
        /// The refused disposition.
        disposition: NegativeMemoryDisposition,
        /// The record identity.
        record_id: String,
    },
    /// The policy names no discriminating check for `RequireCheck`, or names a
    /// different check than the record declares.
    NamedCheckDisagreesWithRecord {
        /// Policy's named check.
        policy_check_id: String,
        /// Record's declared check.
        record_check_id: String,
    },
    /// The policy owner is not the record's semantic owner.
    OwnerMismatch {
        /// Policy's declared owner.
        policy_owner: String,
        /// Record's declared semantic owner.
        semantic_owner: String,
    },
    /// The supplied evidence is empty, duplicated, or names references the
    /// record does not retain.
    EvidenceNotSupportedByRecord {
        /// Exact refusal detail.
        detail: String,
    },
    /// The record requires a verifier the supplied evidence does not name.
    RequiredVerifierNotSatisfied {
        /// The verifier the record requires.
        required_verifier: String,
    },
    /// The activation scope, privacy, horizon or reopen binding is unavailable
    /// or does not equal the recorded value.
    ScopeOrPrivacyMismatch {
        /// Exact scope, freshness or disclosure refusal detail.
        detail: String,
    },
    /// The durable document could not be canonicalized.
    DocumentNotCanonical {
        /// Exact refusal detail.
        detail: String,
    },
}

/// One owner-governed request to publish a negative-memory action policy.
#[derive(Clone, Debug)]
pub struct NegativeMemoryActivationRequest {
    /// The durable rule record the policy is admitted for.
    pub record: NegativeMemoryFingerprint,
    /// The owner-admitted action policy for exactly that record revision.
    pub policy: NegativeMemoryActionPolicy,
    /// Supporting evidence the owner proved before requesting activation.
    pub evidence: NegativeMemoryActivationEvidence,
    /// The validity horizon, in the record's own clock/revision domain.
    pub validity_horizon: NegativeMemoryHorizon,
    /// The reopen criteria, which must equal the record's own condition.
    pub reopen: NegativeMemoryReopenCondition,
    /// Digest over the recorded `affected` scope the request was admitted for.
    pub affected_scope_digest: String,
    /// Deterministic identity reference for the exact policy snapshot.
    pub admission_ref: String,
}

/// The immutable receipt of one published activation.
///
/// `rule_revision` and `record_digest` name the exact rule revision that is now
/// live; `expected_revision_head` is the compare-and-swap predecessor the store
/// arbitrated; `store_write_receipt` is the canonical immutable write receipt.
#[derive(Clone, Debug)]
pub struct NegativeMemoryActivationReceipt {
    /// The operation identity the activation was committed under.
    pub operation_id: OperationId,
    /// The record identity now live.
    pub record_id: String,
    /// The exact rule revision now live.
    pub rule_revision: u64,
    /// The exact record content digest now live.
    pub record_digest: String,
    /// The admitted disposition now live.
    pub disposition: NegativeMemoryDisposition,
    /// The exact admitted policy identity now live.
    pub policy_id: String,
    /// The exact admitted policy revision now live.
    pub policy_revision: u64,
    /// The exact admitted policy digest now live.
    pub policy_digest: String,
    /// The named discriminating check, non-empty exactly for `RequireCheck`.
    pub named_check_id: String,
    /// The compare-and-swap predecessor the store arbitrated.
    pub expected_revision_head: RevisionHeadExpectation,
    /// The canonical immutable write receipt.
    pub store_write_receipt: WriteReceipt,
}

fn refused<T>(detail: impl Into<String>) -> Result<T, NegativeMemoryActivationRefusal> {
    Err(NegativeMemoryActivationRefusal::PolicyInvalid {
        detail: detail.into(),
    })
}

fn owner_error(detail: impl std::fmt::Display) -> CompositionError {
    CompositionError::Owner(format!("negative-memory activation: {detail}"))
}

/// Validates one activation request completely, before any write is attempted.
///
/// This is the whole W3 admission. It performs no I/O, reads no clock, and
/// grants no authority: it only answers whether this request may be published
/// through the governed commit seam. The checks are, in order:
///
/// 1. the record's own `validate()` (shape, self digest, causal ceiling,
///    evidence coverage, discriminating-check dimension join);
/// 2. the policy's own `validate()` (shape, self digest, `REQUIRE_CHECK`
///    payload);
/// 3. `validate_binding()` — the policy binds this record identity, revision
///    and content digest exactly;
/// 4. the owner join — the policy owner is the record's semantic owner;
/// 5. the disposition join — `Block`/`RequireCheck` require an admitted exact
///    predicate, and `RequireCheck` must name the record's own check;
/// 6. the causal ceiling — the record's validated causal status remains
///    authoritative; activation neither upgrades that status nor infers a
///    causal mechanism;
/// 7. the evidence join — exact verifier identity/revision/digest/receipt and
///    exact complete reference coverage from the record;
/// 8. the scope/privacy join — the presented `affected` binding must equal the
///    recorded one;
/// 9. the horizon and reopen joins — the presented horizon domain and the
///    presented reopen condition must equal the recorded ones, so an activation
///    cannot silently widen or shorten either.
///
/// # Errors
///
/// Returns the first [`NegativeMemoryActivationRefusal`] that applies. No
/// refusal is ever downgraded into an advisory publication.
pub fn validate_negative_memory_activation(
    request: &NegativeMemoryActivationRequest,
) -> Result<(), NegativeMemoryActivationRefusal> {
    request.record.validate().map_err(|violation| {
        NegativeMemoryActivationRefusal::RecordInvalid {
            defect: negative_memory_record_defect(&violation),
            detail: violation.to_string(),
        }
    })?;
    request.policy.validate().map_err(|violation| {
        NegativeMemoryActivationRefusal::PolicyInvalid {
            detail: violation.to_string(),
        }
    })?;
    request
        .policy
        .validate_binding(&request.record)
        .map_err(
            |_| NegativeMemoryActivationRefusal::PolicyNotBoundToRecord {
                bound_record_id: request.policy.binding.record_id.clone(),
                record_id: request.record.record_id.clone(),
            },
        )?;
    if request.policy.policy_owner != request.record.semantic_owner {
        return Err(NegativeMemoryActivationRefusal::OwnerMismatch {
            policy_owner: request.policy.policy_owner.clone(),
            semantic_owner: request.record.semantic_owner.clone(),
        });
    }
    if matches!(
        request.policy.disposition,
        NegativeMemoryDisposition::Block | NegativeMemoryDisposition::RequireCheck
    ) && !request.record.has_admitted_trigger()
    {
        return Err(
            NegativeMemoryActivationRefusal::DispositionNotSupportedByTrigger {
                disposition: request.policy.disposition,
                record_id: request.record.record_id.clone(),
            },
        );
    }
    if matches!(
        request.policy.disposition,
        NegativeMemoryDisposition::RequireCheck
    ) && request.policy.named_check_id != request.record.discriminating_check.check_id
    {
        return Err(
            NegativeMemoryActivationRefusal::NamedCheckDisagreesWithRecord {
                policy_check_id: request.policy.named_check_id.clone(),
                record_check_id: request.record.discriminating_check.check_id.clone(),
            },
        );
    }
    validate_evidence(request)?;
    if request.affected_scope_digest
        != sha256_hex(
            &canonical_json_bytes(&request.record.affected).map_err(|error| {
                NegativeMemoryActivationRefusal::ScopeOrPrivacyMismatch {
                    detail: format!("recorded affected scope is not canonicalizable: {error}"),
                }
            })?,
        )
    {
        return Err(NegativeMemoryActivationRefusal::ScopeOrPrivacyMismatch {
            detail: "activation does not bind the record's exact affected scope".to_owned(),
        });
    }
    if matches!(
        request.policy.disposition,
        NegativeMemoryDisposition::Block | NegativeMemoryDisposition::RequireCheck
    ) {
        return Err(NegativeMemoryActivationRefusal::ScopeOrPrivacyMismatch {
            detail: "active blocking/probe publication requires a current observation-domain disclosure closure, which this fingerprint does not carry".to_owned(),
        });
    }
    if request.validity_horizon != request.record.do_not_repeat {
        return Err(NegativeMemoryActivationRefusal::ScopeOrPrivacyMismatch {
            detail: "activation horizon does not equal the record's do-not-repeat horizon"
                .to_owned(),
        });
    }
    if request.reopen != request.record.reopen {
        return Err(NegativeMemoryActivationRefusal::ScopeOrPrivacyMismatch {
            detail: "activation reopen criteria do not equal the record's reopen condition"
                .to_owned(),
        });
    }
    if request.admission_ref
        != crate::negative_memory_extinction::negative_memory_policy_admission_ref(
            &request.policy,
        )
    {
        return Err(NegativeMemoryActivationRefusal::DocumentNotCanonical {
            detail: "activation admission reference does not bind the exact admitted policy identity".to_owned(),
        });
    }
    Ok(())
}

fn validate_evidence(
    request: &NegativeMemoryActivationRequest,
) -> Result<(), NegativeMemoryActivationRefusal> {
    if request.evidence.evidence_refs.is_empty() {
        return refused("activation supplied no supporting evidence references");
    }
    let mut seen: Vec<&str> = Vec::with_capacity(request.evidence.evidence_refs.len());
    for reference in &request.evidence.evidence_refs {
        if seen.contains(&reference.as_str()) {
            return refused("activation evidence references carry a duplicate member");
        }
        seen.push(reference);
    }
    let verification = &request.record.invariant.verification;
    if request.evidence.verifier != verification.verifier_id
        || request.evidence.verifier_revision != verification.verifier_revision
        || request.evidence.verifier_digest != verification.verifier_digest
        || request.evidence.verifier_receipt_ref != verification.verifier_receipt_ref
    {
        return Err(NegativeMemoryActivationRefusal::RequiredVerifierNotSatisfied {
            required_verifier: verification.verifier_id.clone(),
        });
    }
    // The complete supporting set is derived from the invariant's retained
    // source material and verifier evidence/receipt. Future reopen requirements
    // are not evidence that already supports the failed action. A frequency
    // count, model assertion, or declared invariant name cannot replace a member.
    let retained_owned = retained_evidence_refs(&request.record);
    if request.evidence.evidence_refs != retained_owned {
        return refused(
            "activation evidence references must exactly match the canonical invariant sources and verifier evidence/receipt",
        );
    }
    Ok(())
}

/// The canonical supporting evidence references for the failed invariant.
///
/// This is the *independent* expected set the activation coverage check compares
/// against: it includes retained invariant sources plus the invariant
/// verifier's evidence and receipt, but excludes evidence required only for a
/// future reopen. It comes from the durable record, not the caller's list, so
/// two copies of the same caller-supplied list can never satisfy the check.
fn retained_evidence_refs(record: &NegativeMemoryFingerprint) -> Vec<String> {
    let mut refs: Vec<String> = Vec::new();
    refs.extend(record.invariant.source_refs.iter().cloned());
    refs.push(
        record
            .invariant
            .verification
            .verifier_receipt_ref
            .clone(),
    );
    refs.extend(record.invariant.verification.evidence_refs.iter().cloned());
    refs.sort();
    refs.dedup();
    refs
}

/// The exact parameters of the failed action, derived from its canonical
/// `FailureAction` identity rather than from activation-caller strings.
fn activation_action_parameters(record: &NegativeMemoryFingerprint) -> Vec<String> {
    let action = &record.failed_action;
    vec![
        action.action_id.clone(),
        action.operation_id.clone(),
        action.attempt_id.clone(),
        action.target_id.clone(),
        action.input_schema.clone(),
        action.input_digest.clone(),
        action.effect_id.clone(),
        action.owner.clone(),
        action.contract_revision.clone(),
        action.contract_digest.clone(),
    ]
}

/// The durable activation document written for one published rule.
///
/// The store treats this as opaque bytes. It retains the exact failed action
/// and complete admitted policy value, so the canonical receipt cannot report
/// a caller annotation or a different policy with the same disposition.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryActivationDocument {
    /// Wire revision of this document.
    pub schema_version: u32,
    /// The record identity that is live.
    pub record_id: String,
    /// The exact rule revision that is live.
    pub rule_revision: u64,
    /// The exact record content digest that is live.
    pub record_digest: String,
    /// The exact action class derived from `failed_action.effect_class`.
    pub action_class: String,
    /// Exact ordered action identity/parameters derived from the record.
    pub action_parameters: Vec<String>,
    /// The complete policy snapshot admitted for this rule revision.
    pub policy: NegativeMemoryActionPolicy,
    /// The validity horizon the activation was admitted for.
    pub validity_horizon: NegativeMemoryHorizon,
    /// The reopen criteria the activation was admitted for.
    pub reopen: NegativeMemoryReopenCondition,
    /// Deterministic identity reference for the exact policy snapshot.
    pub admission_ref: String,
    /// The owner-issued evidence verifier that supported the activation.
    pub evidence_verifier: String,
    /// Exact verifier revision that supported the activation.
    pub evidence_verifier_revision: String,
    /// Exact verifier digest that supported the activation.
    pub evidence_verifier_digest: String,
    /// Exact verifier receipt reference that supported the activation.
    pub evidence_verifier_receipt_ref: String,
    /// The evidence references the owner proved.
    pub evidence_refs: Vec<String>,
}

impl NegativeMemoryActivationDocument {
    /// Digest over the exact document bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] when the document cannot be
    /// canonicalized.
    pub fn document_digest(&self) -> Result<String, CompositionError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| owner_error(format!("document: {error}")))?;
        Ok(sha256_hex(&bytes))
    }

    /// Checks the document against the exact validated record and policy.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] when the action, record identity,
    /// rule revision, record digest, policy, horizon or reopen criteria differ.
    pub fn validate_against_policy(
        &self,
        record: &NegativeMemoryFingerprint,
        policy: &NegativeMemoryActionPolicy,
    ) -> Result<(), CompositionError> {
        if self.schema_version != ACTIVATION_DOCUMENT_SCHEMA_VERSION {
            return Err(owner_error(
                "activation document uses an unsupported schema version",
            ));
        }
        record
            .validate()
            .map_err(|error| owner_error(format!("activation record invalid: {error}")))?;
        policy
            .validate()
            .map_err(|error| owner_error(format!("activation policy invalid: {error}")))?;
        policy
            .validate_binding(record)
            .map_err(|error| owner_error(format!("activation policy binding: {error}")))?;
        if policy.policy_owner != record.semantic_owner {
            return Err(owner_error(
                "activation policy owner does not match the record semantic owner",
            ));
        }
        for (field, got, expected) in [
            (
                "record_id",
                self.record_id.as_str(),
                policy.binding.record_id.as_str(),
            ),
            (
                "record_digest",
                self.record_digest.as_str(),
                policy.binding.record_digest.as_str(),
            ),
        ] {
            if got != expected {
                return Err(owner_error(format!(
                    "activation document {field} does not match the admitted policy binding"
                )));
            }
        }
        if self.rule_revision != policy.binding.rule_revision {
            return Err(owner_error(
                "activation document rule revision does not match the admitted policy binding",
            ));
        }
        if self.action_class != effect_class_text(record.failed_action.effect_class)
            || self.action_parameters != activation_action_parameters(record)
        {
            return Err(owner_error(
                "activation document class/parameters do not match the exact failed action",
            ));
        }
        if self.policy != *policy {
            return Err(owner_error(
                "activation document does not preserve the complete admitted policy snapshot",
            ));
        }
        if self.admission_ref
            != crate::negative_memory_extinction::negative_memory_policy_admission_ref(policy)
        {
            return Err(owner_error(
                "activation document admission reference does not bind the exact policy identity",
            ));
        }
        let verification = &record.invariant.verification;
        if self.evidence_refs != retained_evidence_refs(record)
            || self.evidence_verifier != verification.verifier_id
            || self.evidence_verifier_revision != verification.verifier_revision
            || self.evidence_verifier_digest != verification.verifier_digest
            || self.evidence_verifier_receipt_ref != verification.verifier_receipt_ref
        {
            return Err(owner_error(
                "activation document does not preserve the exact verifier binding and complete retained evidence set",
            ));
        }
        if self.validity_horizon != record.do_not_repeat || self.reopen != record.reopen {
            return Err(owner_error(
                "activation document validity horizon or reopen criteria do not match the record",
            ));
        }
        Ok(())
    }
}

/// Builds the closed `RecordLearningRecord` activation request for one
/// validated activation request.
///
/// The presented `record_digest` is the digest over the exact activation
/// document bytes, so it is simultaneously the committed-bytes identity, the
/// durable row key, and the value the gate's read-back integrity check
/// validates. `LearningRecordKind::ActivationReceipt` is the closed kind that
/// means "an owner-admitted activation", and the handle names the rule revision
/// so history is appended, never rewritten.
///
/// # Errors
///
/// Returns [`NegativeMemoryActivationRefusal`] when the request fails
/// [`validate_negative_memory_activation`], when the document exceeds the
/// bounded store length, or when the built request fails the closed
/// named-operation guard.
pub fn negative_memory_activation_mutation_request(
    request: &NegativeMemoryActivationRequest,
    expected_record_digest: &str,
    scope_digest: &str,
    fence_digest: &str,
    idempotency_key: String,
) -> Result<(NamedMutationRequest, NegativeMemoryActivationDocument), NegativeMemoryActivationRefusal>
{
    validate_negative_memory_activation(request)?;
    let document = NegativeMemoryActivationDocument {
        schema_version: ACTIVATION_DOCUMENT_SCHEMA_VERSION,
        record_id: request.record.record_id.clone(),
        rule_revision: request.record.rule_revision,
        record_digest: request.record.record_digest.clone(),
        action_class: effect_class_text(request.record.failed_action.effect_class).to_owned(),
        action_parameters: activation_action_parameters(&request.record),
        policy: request.policy.clone(),
        validity_horizon: request.validity_horizon.clone(),
        reopen: request.reopen.clone(),
        admission_ref: request.admission_ref.clone(),
        evidence_verifier: request.evidence.verifier.clone(),
        evidence_verifier_revision: request.evidence.verifier_revision.clone(),
        evidence_verifier_digest: request.evidence.verifier_digest.clone(),
        evidence_verifier_receipt_ref: request.evidence.verifier_receipt_ref.clone(),
        evidence_refs: request.evidence.evidence_refs.clone(),
    };
    document
        .validate_against_policy(&request.record, &request.policy)
        .map_err(|error| NegativeMemoryActivationRefusal::DocumentNotCanonical {
            detail: error.to_string(),
        })?;
    let bytes = canonical_json_bytes(&document).map_err(|error| {
        NegativeMemoryActivationRefusal::DocumentNotCanonical {
            detail: error.to_string(),
        }
    })?;
    if bytes.len() > MAX_LEARNING_RECORD_JSON_BYTES {
        return Err(NegativeMemoryActivationRefusal::DocumentNotCanonical {
            detail: "activation document exceeds the bounded store length".to_owned(),
        });
    }
    let record_json = String::from_utf8(bytes).map_err(|_| {
        NegativeMemoryActivationRefusal::DocumentNotCanonical {
            detail: "activation document is not UTF-8".to_owned(),
        }
    })?;
    let record_digest = sha256_hex(record_json.as_bytes());
    if record_digest != expected_record_digest {
        return Err(NegativeMemoryActivationRefusal::DocumentNotCanonical {
            detail: format!(
                "presented activation digest {expected_record_digest} does not cover the built document"
            ),
        });
    }
    let handle = format!(
        "{ACTIVATION_HANDLE_PREFIX}:{}:{}",
        request.record.record_id, request.record.rule_revision
    );
    let mutation = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::ActivationReceipt,
        handle,
        record_json,
        record_digest,
        scope_digest.to_owned(),
        fence_digest.to_owned(),
        idempotency_key,
    ));
    reject_direct_learning_write(&mutation).map_err(|error| {
        NegativeMemoryActivationRefusal::PolicyInvalid {
            detail: format!("activation commit guard: {error}"),
        }
    })?;
    Ok((mutation, document))
}

/// Publishes one validated activation through the governed canonical commit
/// seam and returns its immutable receipt.
///
/// This is the only activation write path: it revalidates the complete request,
/// rebuilds the named mutation and activation document from that request, and
/// rejects any caller-supplied mutation/document mismatch before building the
/// real [`CanonicalWriteEnvelope`]. The envelope carries the caller identity,
/// exact scope, supporting evidence/admission refs and live head expectations,
/// and the live store manifest digest, then calls
/// [`GovernorComposition::commit_canonical`] — the one
/// `CanonicalWriteEnvelope::prepare` -> `KernelTransitionPort::apply_prepared`
/// route. It never accepts a caller-created `PreparedTransition`, never mints a
/// revision from a local clock, and never reinterprets the receipt.
///
/// `expected_revision_heads` **is** the expected revision: the store arbitrates
/// the activation key under compare-and-set, so an intervening activation
/// cannot be silently overwritten. The single expectation for the activation
/// key is carried into the returned receipt.
///
/// # Errors
///
/// Returns [`NegativeMemoryActivationRefusal`] when the request fails
/// activation admission, and [`CompositionError`] for the guard, envelope,
/// transport and receipt checks.
#[allow(
    clippy::too_many_arguments,
    reason = "the commit caller joins every handoff-required envelope input in one typed call"
)]
pub async fn commit_negative_memory_activation<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    request: &NegativeMemoryActivationRequest,
    mutation: NamedMutationRequest,
    document: &NegativeMemoryActivationDocument,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<NegativeMemoryActivationReceipt, CompositionError> {
    validate_negative_memory_activation(request)
        .map_err(|error| owner_error(format!("activation admission refused: {error:?}")))?;
    reject_direct_learning_write(&mutation)
        .map_err(|error| owner_error(format!("activation guard: {error}")))?;
    let decoded = decode_learning_mutation(mutation.operation, &mutation.parameters)
        .map_err(|error| owner_error(format!("activation parameters: {error}")))?;
    identity
        .validate()
        .map_err(|error| owner_error(format!("activation identity invalid: {error}")))?;
    if identity.idempotency_key != decoded.idempotency_key {
        return Err(owner_error(
            "activation idempotency key does not match the named request key",
        ));
    }
    if decoded.record_kind != LearningRecordKind::ActivationReceipt {
        return Err(owner_error(
            "activation command does not use the closed activation-receipt kind",
        ));
    }
    let expected_handle = format!(
        "{ACTIVATION_HANDLE_PREFIX}:{}:{}",
        request.record.record_id, request.record.rule_revision
    );
    if decoded.handle != expected_handle {
        return Err(owner_error(
            "activation command handle does not match the admitted record revision",
        ));
    }
    if scope_id.as_str() != request.record.affected.scope_id.as_str() {
        return Err(owner_error(
            "activation store scope does not match the record's exact affected scope",
        ));
    }
    if expected_revision_heads.len() != 1 {
        return Err(owner_error(
            "activation requires exactly one expected revision head",
        ));
    }
    let envelope_fence = identity.request.metadata.state_fence.clone();
    let expected_scope_revision_key = format!("scope:{}", scope_id.as_str());
    expected_revision_heads[0]
        .validate()
        .map_err(|error| owner_error(format!("activation revision head: {error}")))?;
    if expected_revision_heads[0].key.as_str() != expected_scope_revision_key {
        return Err(owner_error(
            "activation CAS must name exactly the canonical transition-scope revision head",
        ));
    }
    if expected_revision_heads
        .iter()
        .any(|head| head.state_fence != envelope_fence)
        || expected_ordering_heads
            .iter()
            .any(|head| head.state_fence != envelope_fence)
    {
        return Err(owner_error(
            "activation CAS expectations do not use the request state fence",
        ));
    }
    document.validate_against_policy(&request.record, &request.policy)?;
    let document_digest = document.document_digest()?;
    let (expected_mutation, expected_document) = negative_memory_activation_mutation_request(
        request,
        &document_digest,
        &decoded.scope_digest,
        &decoded.fence_digest,
        decoded.idempotency_key.clone(),
    )
    .map_err(|error| owner_error(format!("activation mutation rebuild refused: {error:?}")))?;
    if expected_document != *document
        || expected_mutation.operation != mutation.operation
        || expected_mutation.parameters != mutation.parameters
        || decoded.record_digest != document_digest
    {
        return Err(owner_error(
            "activation mutation bytes do not match the validated record, action, policy and evidence",
        ));
    }
    for required_ref in request
        .evidence
        .evidence_refs
        .iter()
        .chain(std::iter::once(&request.admission_ref))
    {
        if !proof_refs.iter().any(|proof_ref| proof_ref == required_ref) {
            return Err(owner_error(format!(
                "activation canonical proof refs omit required evidence/admission ref {required_ref}"
            )));
        }
    }
    let operation_id = OperationId::new(format!(
        "negative-memory-activation:{}:{}",
        request.record.record_id, request.record.rule_revision
    ))
    .map_err(|error| owner_error(format!("activation identity invalid: {error}")))?;
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            owner_error(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| owner_error(format!("operation manifest digest: {error}")))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: decoded.idempotency_key.clone(),
        scope_id,
        task_id: None,
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: document.document_digest()?,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![mutation],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: proof_refs,
        expected_revision_heads: expected_revision_heads.clone(),
        expected_ordering_heads: expected_ordering_heads.clone(),
    };
    let receipt = composition.commit_canonical(identity, envelope).await?;
    check_activation_commit_freshness(
        &receipt,
        &operation_id,
        &decoded.idempotency_key,
        &envelope_fence,
        &expected_revision_heads,
        &expected_ordering_heads,
    )?;
    let expected_revision_head = expected_revision_heads
        .into_iter()
        .next()
        .ok_or_else(|| owner_error("activation published without an expected revision head"))?;
    Ok(NegativeMemoryActivationReceipt {
        operation_id,
        record_id: document.record_id.clone(),
        rule_revision: document.rule_revision,
        record_digest: document.record_digest.clone(),
        disposition: document.policy.disposition,
        policy_id: document.policy.policy_id.clone(),
        policy_revision: document.policy.policy_revision,
        policy_digest: document.policy.policy_digest.clone(),
        named_check_id: document.policy.named_check_id.clone(),
        expected_revision_head,
        store_write_receipt: receipt,
    })
}

/// Reports whether one canonical receipt really committed the named activation
/// request, with no stale projection reported healthy.
///
/// Identity and fence agreement mirror the store's own receipt-identity rule;
/// head agreement follows the owner CAS contract exactly as
/// `learning_record_commit::check_learning_commit_freshness` applies it
/// (expectations are validated against current store state at execution; both
/// providers advance heads as `before = current`, `after = before + 1`): the
/// returned `revision_before_after` entry for every expected revision key must
/// report the arbitrated base revision, and the returned `ordering_sequences`
/// entry for every expected ordering scope must report a sequence advanced
/// strictly past the expectation. Every requested head must appear exactly
/// once; omission or duplication is insufficient commit evidence.
fn check_activation_commit_freshness(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    idempotency_key: &str,
    envelope_fence: &StateFence,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), CompositionError> {
    receipt
        .validate()
        .map_err(|error| owner_error(format!("activation receipt invalid: {error}")))?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(owner_error(
            "activation receipt is not committed; stale projection refused",
        ));
    }
    if receipt.operation_id != *operation_id || receipt.idempotency_key != idempotency_key {
        return Err(owner_error(
            "activation receipt identity does not match the committed envelope",
        ));
    }
    if receipt.state_fence != *envelope_fence {
        return Err(owner_error(
            "activation receipt fence does not match the committed envelope fence",
        ));
    }
    for expected in expected_revision_heads {
        if expected.state_fence != *envelope_fence {
            return Err(owner_error(format!(
                "activation revision expectation uses a different fence for {}",
                expected.key.as_str(),
            )));
        }
        let matching: Vec<_> = receipt
            .revision_before_after
            .iter()
            .filter(|delta| delta.key == expected.key)
            .collect();
        if matching.len() != 1 {
            return Err(owner_error(format!(
                "activation receipt must report exactly one revision delta for {} (reported {})",
                expected.key.as_str(),
                matching.len(),
            )));
        }
        let delta = matching[0];
        let expected_successor = expected
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| owner_error("activation expected revision overflow"))?;
        if delta.before != expected.expected_revision || delta.after != expected_successor {
            return Err(owner_error(format!(
                "activation receipt revision is stale for {}: expected {} -> {}, observed {} -> {}",
                expected.key.as_str(),
                expected.expected_revision,
                expected_successor,
                delta.before,
                delta.after,
            )));
        }
    }
    for expected in expected_ordering_heads {
        if expected.state_fence != *envelope_fence {
            return Err(owner_error(format!(
                "activation ordering expectation uses a different fence for {}",
                expected.scope.as_str(),
            )));
        }
        let matching: Vec<_> = receipt
            .ordering_sequences
            .iter()
            .filter(|head| head.scope == expected.scope)
            .collect();
        if matching.len() != 1 {
            return Err(owner_error(format!(
                "activation receipt must report exactly one ordering head for {} (reported {})",
                expected.scope.as_str(),
                matching.len(),
            )));
        }
        let head = matching[0];
        if head.state_fence != *envelope_fence || head.sequence <= expected.expected_sequence {
            return Err(owner_error(format!(
                "activation receipt ordering is stale for {}: expected advance past {}, observed {}",
                expected.scope.as_str(),
                expected.expected_sequence,
                head.sequence,
            )));
        }
    }
    Ok(())
}
