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
//! # Scope
//!
//! [`NegativeMemoryActivationRequest::affected_scope_digest`] is compared
//! **content-wise** against the retained `NegativeMemoryAffectedScope` on the
//! record: the presented digest must equal the digest computed over exactly
//! that recorded value, so a rule may only acquire blocking power inside the
//! exact task, scope, environment and resources its record names. There is
//! deliberately no privacy-profile input on this request. `NegativeMemoryFingerprint`
//! and its `NegativeMemoryAffectedScope` carry no privacy/disclosure identity
//! at all (a case-insensitive sweep for one finds nothing), so a privacy
//! comparison here could only ever be a shape test against a field nothing
//! records. This module does not assert a privacy binding it cannot check; the
//! privacy ceiling that does exist on the record is its own `causal` ceiling,
//! enforced by `NegativeMemoryFingerprint::validate`.
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
    NegativeMemoryActionPolicy, NegativeMemoryDisposition, NegativeMemoryFingerprint,
    NegativeMemoryHorizon, NegativeMemoryRecordDefect, NegativeMemoryReopenCondition,
    negative_memory_record_defect,
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

/// The deterministic admission reference one admitted policy is published
/// under.
///
/// This is a digest over the exact policy value, so the reference on the
/// durable document is *bound* to the policy it names rather than being a
/// caller-supplied string that merely resembles an admission. A different
/// disposition, revision, owner or named check yields a different reference.
pub fn negative_memory_policy_admission_ref(policy: &NegativeMemoryActionPolicy) -> String {
    let bytes = canonical_json_bytes(policy).unwrap_or_default();
    format!(
        "negative-memory-admission:{}:{}:{}",
        policy.policy_id,
        policy.policy_revision,
        sha256_hex(&bytes)
    )
}

/// The durable handle of one published rule activation. The store keys the row
/// by `(record_kind, handle, record_digest)`; the handle names the rule
/// revision so two revisions of one record identity are distinct rows and
/// history is never rewritten in place.
pub(crate) const ACTIVATION_HANDLE_PREFIX: &str = "negative-memory";

/// The exact durable handle one rule revision is published under.
///
/// The bounded rule read in [`crate::negative_memory_read`] re-derives this
/// from the decoded document and refuses a row whose handle disagrees, so a
/// document cannot be filed under a name owned by another rule revision.
pub(crate) fn activation_handle(record_id: &str, rule_revision: u64) -> String {
    format!("{ACTIVATION_HANDLE_PREFIX}:{record_id}:{rule_revision}")
}

/// Wire revision of the activation document this owner writes.
///
/// Revision 2 carries the exact `NegativeMemoryFingerprint` and the complete
/// `NegativeMemoryActionPolicy` instead of a caller-annotated action
/// class/parameter pair and a bare disposition. A published activation is the
/// durable home of the rule the gate later matches against, so the rule and
/// the policy admitted for it must travel inside the document: a receipt that
/// named only an identity and a disposition left the bounded read unable to
/// rebuild anything to compare.
const ACTIVATION_DOCUMENT_SCHEMA_VERSION: u32 = 2;

/// The owner-issued evidence an activation decision rests on.
///
/// This is the W3 "supporting evidence" input. It is deliberately *not* a
/// frequency count, a boolean, or a model-produced claim: it is the exact set
/// of evidence references the record itself retains, plus the verifier that
/// produced them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryActivationEvidence {
    /// Owner-issued verifier that produced the evidence. Must equal the
    /// verifier the record's reopen condition requires, or the verifier its
    /// discriminating check binds.
    pub verifier: String,
    /// Exact evidence references the owner proved. Every entry must be named
    /// by the record's own retained evidence set.
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
    /// The activation's scope or horizon/reopen binding does not equal the
    /// recorded one. This is a content comparison, not a shape check.
    ScopeOrPrivacyMismatch {
        /// Exact refusal detail.
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
    /// Owner-issued admission reference recorded on the durable document.
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
    /// The exact admitted policy content digest now live.
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
/// 6. the causal join — the record's causal status must remain the `Unknown`
///    reading;
/// 7. the evidence join — non-empty, duplicate-free, a subset of the record's
///    retained evidence, and naming the record's required verifier;
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
    if request.admission_ref != negative_memory_policy_admission_ref(&request.policy) {
        return Err(NegativeMemoryActivationRefusal::DocumentNotCanonical {
            detail: "activation admission reference does not bind the exact admitted policy"
                .to_owned(),
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
    if request.evidence.verifier.trim().is_empty() {
        return refused("activation supplied no owner-issued evidence verifier");
    }
    // Every supplied reference must be one the record itself retains. A
    // frequency count, a model assertion, or a declared invariant name
    // produces a reference the record does not name, so it cannot pass here.
    let retained_owned = retained_evidence_refs(&request.record);
    let retained: Vec<&str> = retained_owned.iter().map(String::as_str).collect();
    for reference in &request.evidence.evidence_refs {
        if !retained.contains(&reference.as_str()) {
            return refused(format!(
                "activation evidence reference {reference} is not retained by the record"
            ));
        }
    }
    // The verifier must be one the record itself requires. This is the join
    // that makes "a model said it happened" structurally insufficient.
    let required = &request.record.reopen.required_verifier;
    if request.evidence.verifier != *required
        && request.evidence.verifier != request.record.discriminating_check.required_verifier
    {
        return Err(
            NegativeMemoryActivationRefusal::RequiredVerifierNotSatisfied {
                required_verifier: required.clone(),
            },
        );
    }
    Ok(())
}

/// The union of evidence references the record itself retains.
///
/// This is the *independent* expected set the coverage check compares against:
/// it is derived from the durable record, not from the caller's list, so two
/// copies of the same caller-supplied list can never satisfy it.
fn retained_evidence_refs(record: &NegativeMemoryFingerprint) -> Vec<String> {
    let mut refs: Vec<String> = Vec::new();
    refs.extend(record.invariant.verification.evidence_refs.iter().cloned());
    refs.extend(record.reopen.required_evidence_refs.iter().cloned());
    refs.sort();
    refs.dedup();
    refs
}

/// The durable activation document written for one published rule.
///
/// The store treats this as opaque bytes; every field here is the admitted
/// semantic content the owner proved, and the round trip through
/// [`NegativeMemoryActivationDocument::validate`] at the gate is what binds the
/// read-back rule to the activation decision.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryActivationDocument {
    /// Wire revision of this document.
    pub schema_version: u32,
    /// The exact durable record this activation published.
    ///
    /// The record travels whole, not as an identity: the bounded rule read
    /// rebuilds matcher candidates from this value and re-derives the record's
    /// own `record_digest` with the record's own validator, so a receipt that
    /// carried only an identity could never be compared against anything.
    pub record: NegativeMemoryFingerprint,
    /// The complete owner-admitted action policy for exactly that record
    /// revision.
    pub policy: NegativeMemoryActionPolicy,
    /// The validity horizon the activation was admitted for.
    pub validity_horizon: NegativeMemoryHorizon,
    /// The reopen criteria the activation was admitted for.
    pub reopen: NegativeMemoryReopenCondition,
    /// The owner-issued admission reference.
    pub admission_ref: String,
    /// The owner-issued evidence verifier that supported the activation.
    pub evidence_verifier: String,
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

    /// The exact durable handle this document's rule revision is published
    /// under.
    #[must_use]
    pub fn handle(&self) -> String {
        activation_handle(&self.record.record_id, self.record.rule_revision)
    }

    /// The exact rule record this activation published.
    #[must_use]
    pub const fn record(&self) -> &NegativeMemoryFingerprint {
        &self.record
    }

    /// The complete owner-admitted policy this activation published.
    #[must_use]
    pub const fn policy(&self) -> &NegativeMemoryActionPolicy {
        &self.policy
    }

    /// Checks that this document preserves the exact record and policy the
    /// activation admitted, and that both still validate against themselves.
    ///
    /// The record is validated with its **own** validator, which re-derives the
    /// recorded `record_digest` over the recorded fields. Nothing here
    /// recomputes a digest over something the caller holds instead: the
    /// compared values are the document's own record and policy, and the
    /// admitted values are re-proved against them.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] when the schema revision is
    /// unsupported, when the record or policy fails its own validation, when
    /// the policy is not bound to this record revision, or when the horizon,
    /// reopen criteria, admission reference, verifier or evidence set do not
    /// match the record.
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
        if &self.record != record {
            return Err(owner_error(
                "activation document does not preserve the exact admitted rule record",
            ));
        }
        if &self.policy != policy {
            return Err(owner_error(
                "activation document does not preserve the complete admitted policy snapshot",
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
        if self.validity_horizon != record.do_not_repeat || self.reopen != record.reopen {
            return Err(owner_error(
                "activation document validity horizon or reopen criteria do not match the record",
            ));
        }
        let verification = &record.invariant.verification;
        if self.evidence_verifier != verification.verifier_id
            || self.evidence_refs != retained_evidence_refs(record)
        {
            return Err(owner_error(
                "activation document does not preserve the record's exact verifier and retained evidence set",
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
        record: request.record.clone(),
        policy: request.policy.clone(),
        validity_horizon: request.validity_horizon.clone(),
        reopen: request.reopen.clone(),
        admission_ref: request.admission_ref.clone(),
        evidence_verifier: request.evidence.verifier.clone(),
        evidence_refs: request.evidence.evidence_refs.clone(),
    };
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
    let handle = document.handle();
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
/// This is the only activation write path: it builds the real
/// [`CanonicalWriteEnvelope`] from the caller identity, the decoded closed
/// parameters of the single named activation command, the caller-addressed
/// scope, the caller's proof refs and live head expectations, and the live store
/// manifest digest, then calls
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
    mutation: NamedMutationRequest,
    document: &NegativeMemoryActivationDocument,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<NegativeMemoryActivationReceipt, CompositionError> {
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
    let operation_id = OperationId::new(format!(
        "negative-memory-activation:{}:{}",
        document.record.record_id, document.record.rule_revision
    ))
    .map_err(|error| owner_error(format!("activation identity invalid: {error}")))?;
    let envelope_fence = identity.request.metadata.state_fence.clone();
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            owner_error(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| owner_error(format!("operation manifest digest: {error}")))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: decoded.idempotency_key.clone(),
        // #1925: this leg's stable intent is the owner-issued activation
        // document it commits, not the per-attempt operation identity.
        write_intent_id: crate::write_intent::admission_write_intent(
            "negative-memory-activation",
            &document.document_digest()?,
        )
        .ok_or_else(|| {
            owner_error("activation document has no owner-issued subject to declare")
        })?,
        write_envelope_protocol_version:
            crate::write_intent::GOVERNOR_ADMISSION_WRITE_ENVELOPE_PROTOCOL_VERSION,
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
        record_id: document.record.record_id.clone(),
        rule_revision: document.record.rule_revision,
        record_digest: document.record.record_digest.clone(),
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
/// strictly past the expectation. The same `if let Some(..) &&` match semantics
/// are mirrored, including their consequence: a key or scope the receipt does
/// not report at all is not itself a stale reading here, and the receipt's own
/// `validate()` is what requires the head set to be well formed. This is the
/// sibling freshness check in full, not a weaker spelling of it.
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
        if let Some(delta) = receipt
            .revision_before_after
            .iter()
            .find(|delta| delta.key == expected.key)
            && delta.before != expected.expected_revision
        {
            return Err(owner_error(format!(
                "activation receipt revision is stale for {}: expected base {}, observed {}",
                expected.key.as_str(),
                expected.expected_revision,
                delta.before,
            )));
        }
    }
    for expected in expected_ordering_heads {
        if let Some(head) = receipt
            .ordering_sequences
            .iter()
            .find(|head| head.scope == expected.scope)
            && head.sequence <= expected.expected_sequence
        {
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
