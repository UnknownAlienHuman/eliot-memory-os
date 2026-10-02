//! Typed pre-stage contract rejection for issue #1796 (I6.8).
//!
//! Architecture traceability: `I6.8` requires one typed `ContractError`
//! response carrying every defect plus `AdmissionRejection` as a typed
//! pre-stage result with `stage_state: none`, no ordering sequence, a
//! `not_accepted` or `conflict` decision, all contract errors, safe capture
//! fallback, retry identity rule, and next action. A schema-invalid request
//! with `NOT_ATTEMPTED` never consumes the stable `write_intent_id`; a
//! corrected payload receives a new operation identity (normally a new
//! idempotency key) with `corrected_from_operation_id` lineage; exact
//! same-hash retry returns the same rejection; reusing one idempotency key
//! with different canonical bytes is `IDENTITY_CONFLICT`.
//!
//! Owner: this crate (`eliot-canonical`) is the existing Governor semantic
//! admission owner. Kernel mechanically rechecks through its own pre-stage
//! gate (`eliot-kernel-service::contract_rejection_gate`) and never rebuilds
//! this semantic decision. Semantic ambiguity defaults to safe capture as an
//! Observation Candidate pointer, never data loss; the full candidate owner
//! remains `eliot-observation`.
//!
//! This module performs no database write, allocates no ordering sequence,
//! mints no `write_intent_id`, and records no effect. The journal below is an
//! in-memory, rebuildable pre-stage projection used for retry-identity
//! fixtures only.
//!
//! The corrected operation identity is an owner-issued fact, not advisory
//! prose: [`derive_corrected_operation_id`] derives it from the inputs the
//! refusal is already fixed by, [`RetainedRejections`] keeps every refusal it
//! issued, and [`RetainedRejections::verify_correction_lineage`] believes a
//! lineage claim only when that own record proves it. The derivation itself
//! is the one shared primitive the Kernel pre-stage gate
//! (`eliot-kernel-service::contract_rejection_gate`) also calls, so the
//! identity stamped on the live path is exactly the identity issued here and
//! there is no second issuer. The gate mechanically mirrors what it can see
//! on the wire - refusing a resubmission still wearing a refused operation
//! identity and verifying a presented correction against its own retained
//! refusals - but the semantic admission decision stays here.
//!
//! Retention policy is every refusal on both layers: this owner retains the
//! correction each refusal issued, and the Kernel gate retains every refusal
//! the same way, so the two layers never hold divergent policies.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{OperationId, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{CanonicalWriteEnvelope, contract_identity};

/// Closed mutation state for a pre-stage contract error.
///
/// Only `NotAttempted` ever appears on a pre-stage rejection. The remaining
/// arms exist so the wire shape stays closed and decodable when a later stage
/// reports its own outcome; they are never constructed here.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WriteMutationStatus {
    /// No mutation was attempted; no effect record exists.
    NotAttempted,
    /// A later stage holds the write; never emitted pre-stage.
    Staged,
    /// A later stage committed the write; never emitted pre-stage.
    Committed,
    /// Outcome is unknown; never emitted pre-stage.
    Unknown,
}

/// One typed contract defect in the I6.8 `ContractError` response shape.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractError {
    /// Stable defect code (e.g. `INVALID_FIELD`, `IDENTITY_CONFLICT`).
    pub code: String,
    /// Digest of the admitted semantic contract set under test.
    pub schema_digest: String,
    /// Invalid field paths collected for this defect.
    pub invalid_fields_and_paths: Vec<String>,
    /// Missing required fields collected for this defect.
    pub missing_fields: Vec<String>,
    /// Allowed enum values when the defect is an enum violation.
    pub allowed_enum_values: Vec<String>,
    /// `schema` for shape defects, `semantic` for fence/binding/ceiling ones.
    pub semantic_vs_schema_error: String,
    /// Bounded redacted evidence handles; never payload prose.
    pub evidence_refs: Vec<String>,
    /// Safe fallback disposition (`ObservationCandidate` for ambiguity).
    pub safe_fallback: String,
    /// Minimal valid example pointer for the caller.
    pub minimal_valid_example: String,
    /// Next allowed caller action.
    pub next_allowed_action: String,
    /// Retry rule for this defect.
    pub retry_policy: String,
    /// Always `NOT_ATTEMPTED` on a pre-stage rejection.
    pub write_mutation_status: WriteMutationStatus,
    /// Never consumed pre-stage; always `None` on a rejection.
    pub write_intent_id: Option<String>,
    /// Proposed operation under test.
    pub proposed_operation_id: String,
    /// Owner-issued operation identity a corrected resubmission must use.
    ///
    /// Issued by this owner through
    /// [`derive_corrected_operation_id`] on every refusal it produces, so the
    /// corrected request receives a new operation identity instead of a caller
    /// inventing one.
    pub corrected_operation_id: Option<String>,
    /// Lineage to the rejected operation for a corrected resubmission.
    ///
    /// Present only when this owner verified the claim against a rejection it
    /// itself retained; never defaulted from caller input alone.
    pub corrected_from_operation_id: Option<String>,
}

impl ContractError {
    /// Validates the pre-stage invariants of one defect.
    pub fn validate(&self) -> Result<(), ContractRejectionError> {
        if self.code.trim().is_empty()
            || self.code.chars().any(char::is_control)
            || self.code.len() > 128
        {
            return Err(ContractRejectionError::InvalidField {
                field: "contract_error.code",
                reason: "must be non-blank bounded text",
            });
        }
        if self.write_mutation_status != WriteMutationStatus::NotAttempted {
            return Err(ContractRejectionError::InvalidField {
                field: "contract_error.write_mutation_status",
                reason: "pre-stage rejection must report NOT_ATTEMPTED",
            });
        }
        if self.write_intent_id.is_some() {
            return Err(ContractRejectionError::InvalidField {
                field: "contract_error.write_intent_id",
                reason: "pre-stage rejection must not consume a write intent",
            });
        }
        if self.proposed_operation_id.trim().is_empty() {
            return Err(ContractRejectionError::InvalidField {
                field: "contract_error.proposed_operation_id",
                reason: "must be non-blank",
            });
        }
        Ok(())
    }
}

/// Pre-stage stage state. The only representable value is `none`.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum StageState {
    /// No stage was entered; no ordering sequence was assigned.
    #[serde(rename = "none")]
    None,
}

/// Typed pre-stage decision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    /// The request was refused before staging.
    NotAccepted,
    /// The idempotency identity conflicts with a different request hash.
    Conflict,
}

/// Safe capture pointer for semantic ambiguity.
///
/// This is a pointer, not a second candidate owner: the full
/// `ObservationCandidate` lifecycle stays in `eliot-observation`. The pointer
/// preserves content that would otherwise be dropped, under the existing
/// capture/candidate ceiling.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeCaptureFallback {
    /// Always `ObservationCandidate`.
    pub kind: String,
    /// Stable candidate pointer derived from the rejected operation.
    pub candidate_id: String,
    /// Bounded reason for the fallback.
    pub reason: String,
    /// Capture ceiling (`Cold` for unbound capture).
    pub disposition: String,
}

impl SafeCaptureFallback {
    /// Validates the fallback pointer shape.
    pub fn validate(&self) -> Result<(), ContractRejectionError> {
        if self.kind != "ObservationCandidate" {
            return Err(ContractRejectionError::InvalidField {
                field: "safe_capture_fallback.kind",
                reason: "must be ObservationCandidate",
            });
        }
        for (value, field) in [
            (&self.candidate_id, "safe_capture_fallback.candidate_id"),
            (&self.reason, "safe_capture_fallback.reason"),
            (&self.disposition, "safe_capture_fallback.disposition"),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > 512 {
                return Err(ContractRejectionError::InvalidField {
                    field,
                    reason: "must be non-blank bounded text",
                });
            }
        }
        Ok(())
    }
}

/// Typed pre-stage result for issue #1796 (I6.8 `AdmissionRejection`).
///
/// This is a typed pre-stage result, not a canonical receipt: it carries no
/// ordering sequence, no `write_intent_id`, and no effect record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRejection {
    /// Request identity from the rejected envelope.
    pub request_id: String,
    /// Proposed operation under test.
    pub proposed_operation_id: String,
    /// Stable logical retry identity.
    pub idempotency_key: String,
    /// Canonical request hash of the exact rejected bytes.
    pub canonical_request_hash: String,
    /// Stable rejection identity for exact same-hash retry.
    pub rejection_id: String,
    /// Always `none` pre-stage.
    pub stage_state: StageState,
    /// Always `false` pre-stage; no ordering sequence is assigned.
    pub ordering_sequence_assigned: bool,
    /// `not_accepted` for defects, `conflict` for identity reuse.
    pub decision: AdmissionDecision,
    /// Every detected defect in one response.
    pub all_contract_errors: Vec<ContractError>,
    /// Durable audit/problem reference, only when policy requires one.
    pub durable_audit_or_problem_ref: Option<String>,
    /// Safe capture pointer for semantic ambiguity, when applicable.
    pub safe_capture_fallback: Option<SafeCaptureFallback>,
    /// Retry identity rule for corrected payloads.
    pub corrected_retry_identity_rule: String,
    /// Next allowed caller action.
    pub next_allowed_action: String,
}

impl AdmissionRejection {
    /// Validates the typed pre-stage invariants.
    pub fn validate(&self) -> Result<(), ContractRejectionError> {
        if self.request_id.trim().is_empty() || self.request_id.len() > 1024 {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.request_id",
                reason: "must be non-blank bounded text",
            });
        }
        if self.proposed_operation_id.trim().is_empty() {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.proposed_operation_id",
                reason: "must be non-blank",
            });
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.idempotency_key",
                reason: "must be non-blank",
            });
        }
        if self.canonical_request_hash.len() != 64
            || self
                .canonical_request_hash
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.canonical_request_hash",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.rejection_id
            != derive_rejection_id(&self.idempotency_key, &self.canonical_request_hash)
        {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.rejection_id",
                reason: "must derive from the idempotency key and canonical hash",
            });
        }
        if !matches!(self.stage_state, StageState::None) {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.stage_state",
                reason: "pre-stage rejection must report none",
            });
        }
        if self.ordering_sequence_assigned {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.ordering_sequence_assigned",
                reason: "pre-stage rejection must not assign an ordering sequence",
            });
        }
        if self.all_contract_errors.is_empty() {
            return Err(ContractRejectionError::Empty {
                field: "rejection.all_contract_errors",
            });
        }
        let corrected_operation_id =
            derive_corrected_operation_id(&self.proposed_operation_id, &self.rejection_id);
        for error in &self.all_contract_errors {
            error.validate()?;
            if error.proposed_operation_id != self.proposed_operation_id
                || error.write_intent_id.is_some()
                || error.write_mutation_status != WriteMutationStatus::NotAttempted
            {
                return Err(ContractRejectionError::InvalidField {
                    field: "rejection.all_contract_errors",
                    reason: "every defect must share the proposed operation with NOT_ATTEMPTED and no write intent",
                });
            }
            if error.corrected_operation_id.as_deref() != Some(corrected_operation_id.as_str())
                || error.corrected_operation_id.as_deref()
                    == Some(self.proposed_operation_id.as_str())
            {
                return Err(ContractRejectionError::InvalidField {
                    field: "rejection.all_contract_errors",
                    reason: "every defect must carry the owner-issued corrected operation identity, which differs from the rejected one",
                });
            }
        }
        if let Some(fallback) = &self.safe_capture_fallback {
            fallback.validate()?;
        }
        if self.corrected_retry_identity_rule.trim().is_empty()
            || self.next_allowed_action.trim().is_empty()
        {
            return Err(ContractRejectionError::InvalidField {
                field: "rejection.retry_rule",
                reason: "must carry the corrected retry identity rule and next action",
            });
        }
        Ok(())
    }
}

/// Fail-closed errors for the rejection projection itself.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractRejectionError {
    /// A rejection field violates its pre-stage invariant.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A required collection was empty.
    #[error("empty field {field}")]
    Empty {
        /// Field path of the empty collection.
        field: &'static str,
    },
}

/// Stable retry-identity rule carried on every rejection.
pub const CORRECTED_RETRY_IDENTITY_RULE: &str = "corrected payload requires a new operation identity and normally a new idempotency key with corrected_from_operation_id lineage; exact same-hash retry returns the same rejection; changed bytes under one idempotency key is IDENTITY_CONFLICT";

/// Derives the stable rejection identity from the retry identity and the
/// canonical request hash.
#[must_use]
pub fn derive_rejection_id(idempotency_key: &str, canonical_request_hash: &str) -> String {
    sha256_hex(format!("{idempotency_key}:{canonical_request_hash}").as_bytes())
}

/// Defect code for a caller-asserted correction lineage the owner never
/// rejected.
pub const UNPROVEN_CORRECTION_LINEAGE: &str = "UNPROVEN_CORRECTION_LINEAGE";

/// Derives the owner-issued corrected operation identity for one refusal.
///
/// `I6.8` requires the corrected request to receive a new operation ID while
/// `corrected_from_operation_id` preserves lineage, and requires an exact
/// retry of the same request hash to return the same rejection. Both inputs
/// here are already fixed by the refusal being returned: the rejected
/// operation identity, and the rejection identity, which is itself derived
/// only from the idempotency key and the canonical request hash. The same
/// rejection therefore always issues the same corrected identity, and a
/// different rejection always issues a different one. No nonce, clock,
/// counter, or new input participates.
///
/// The derivation itself is the one shared primitive also used by the Kernel
/// mechanical gate, so the identity the live path stamps is exactly the
/// identity issued here: there is no second issuer to diverge from it.
#[must_use]
pub fn derive_corrected_operation_id(rejected_operation_id: &str, rejection_id: &str) -> String {
    eliot_store_api::derive_corrected_operation_id(rejected_operation_id, rejection_id)
}

/// One refusal this owner kept, bound to the operation identity it refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRejection {
    /// Operation identity this owner refused.
    pub rejected_operation_id: String,
    /// Stable rejection identity returned for it.
    pub rejection_id: String,
    /// Canonical request hash of the exact refused bytes.
    pub canonical_request_hash: String,
    /// Idempotency key the refused bytes arrived under.
    pub idempotency_key: String,
    /// Owner-issued identity a corrected resubmission must use.
    pub corrected_operation_id: String,
}

/// Fail-closed refusals for a correction lineage claim.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CorrectionLineageError {
    /// The caller asserted lineage from an operation this owner never
    /// refused, so the claim is unproven and is never recorded.
    #[error("corrected_from_operation_id {asserted} names no retained rejection")]
    UnprovenLineage {
        /// Asserted lineage operation identity.
        asserted: OperationId,
    },
    /// The presented operation identity is one this owner already refused,
    /// so corrected bytes may not still wear it.
    #[error("operation_id {presented} already carries a retained rejection")]
    RejectedOperationIdentityReuse {
        /// Presented operation identity.
        presented: OperationId,
    },
}

/// Owner-retained refusals, keyed by the corrected operation identity each
/// refusal issued.
///
/// This is the owner's own record, not a caller assertion: a lineage claim is
/// believed only when this record proves it. Every refusal retains its own
/// correction, not only the first per operation identity: each corrected
/// identity is derived from the rejected operation identity together with
/// that refusal's own rejection identity, so a second refusal of the same
/// operation identity issues a distinct corrected identity, and retaining
/// only the first would leave every later corrected identity unprovable.
/// This is the same every-refusal policy the Kernel pre-stage gate
/// (`eliot-kernel-service::contract_rejection_gate`) keeps, so the two
/// layers never hold divergent retention policies.
#[derive(Clone, Debug, Default)]
pub struct RetainedRejections {
    refused_operations: BTreeSet<String>,
    issued_corrections: BTreeMap<String, RetainedRejection>,
}

impl RetainedRejections {
    /// Retains one refusal under the operation identity it refused and under
    /// the corrected identity it issued.
    ///
    /// The refused-identity set is the owner's own record that this operation
    /// identity never admitted a write, so corrected bytes still wearing it
    /// are refused. The correction map keeps every refusal's own record
    /// keyed by the corrected identity it issued, so any of them verifies.
    /// Re-retaining the identical refusal is idempotent: the corrected
    /// identity is a pure function of the same pair, so the record written
    /// is byte-identical.
    pub fn retain(&mut self, rejected_operation_id: &OperationId, rejection: &AdmissionRejection) {
        self.refused_operations
            .insert(rejected_operation_id.as_str().to_owned());
        let corrected_operation_id =
            derive_corrected_operation_id(rejected_operation_id.as_str(), &rejection.rejection_id);
        self.issued_corrections.insert(
            corrected_operation_id.clone(),
            RetainedRejection {
                rejected_operation_id: rejected_operation_id.as_str().to_owned(),
                rejection_id: rejection.rejection_id.clone(),
                canonical_request_hash: rejection.canonical_request_hash.clone(),
                idempotency_key: rejection.idempotency_key.clone(),
                corrected_operation_id,
            },
        );
    }

    /// Verifies a correction lineage claim against this owner's own record.
    ///
    /// A presented operation identity this owner already refused is refused
    /// outright: corrected bytes must not still wear the rejected identity. An
    /// asserted `corrected_from_operation_id` is believed only when a
    /// rejection for exactly that operation is retained here. With no asserted
    /// lineage, the owner-issued [`RetainedRejection::corrected_operation_id`]
    /// is itself the proof, because a caller cannot present it without having
    /// read a refusal this owner issued.
    pub fn verify_correction_lineage(
        &self,
        presented_operation_id: &OperationId,
        asserted_corrected_from: Option<&OperationId>,
    ) -> Result<Option<&RetainedRejection>, CorrectionLineageError> {
        if self
            .refused_operations
            .contains(presented_operation_id.as_str())
        {
            return Err(CorrectionLineageError::RejectedOperationIdentityReuse {
                presented: presented_operation_id.clone(),
            });
        }
        if let Some(asserted) = asserted_corrected_from {
            return self
                .issued_corrections
                .values()
                .find(|record| record.rejected_operation_id == asserted.as_str())
                .map_or_else(
                    || {
                        Err(CorrectionLineageError::UnprovenLineage {
                            asserted: asserted.clone(),
                        })
                    },
                    |record| Ok(Some(record)),
                );
        }
        Ok(self.issued_corrections.get(presented_operation_id.as_str()))
    }
}

/// In-memory pre-stage admission journal preserving retry identity.
///
/// Maps one idempotency key to the exact canonical hash and rejection first
/// returned for it. Exact same-hash retry replays the stored rejection with
/// the same `rejection_id`; changed bytes under the same key yield a fresh
/// `IDENTITY_CONFLICT` rejection without overwriting the stored one. Valid
/// envelopes are never stored and never consume a `write_intent_id`.
///
/// Every refusal is also retained under the operation identity it refused, so
/// a corrected payload's lineage is checked against this journal's own record
/// instead of a caller assertion, and so a rejected operation identity can
/// never come back wearing corrected bytes.
#[derive(Clone, Debug, Default)]
pub struct ContractAdmissionJournal {
    entries: BTreeMap<String, StoredRejection>,
    retained: RetainedRejections,
}

#[derive(Clone, Debug)]
struct StoredRejection {
    canonical_request_hash: String,
    rejection: AdmissionRejection,
}

impl ContractAdmissionJournal {
    /// Admits one envelope at the pre-stage boundary.
    ///
    /// Returns the immutable prepared plan without writing, staging, or
    /// allocating an ordering sequence. On refusal returns the typed
    /// `AdmissionRejection` with every detected defect, each carrying the
    /// owner-issued corrected operation identity. This method never mints a
    /// `write_intent_id` and never records an effect.
    ///
    /// `corrected_from_operation_id` is a claim, not a fact: it is believed
    /// only when this journal itself retains a rejection for exactly that
    /// operation identity. An unproven claim is refused, never recorded, and
    /// never defaulted. Corrected bytes are additionally refused while still
    /// carrying an operation identity this journal already rejected.
    #[allow(
        clippy::result_large_err,
        reason = "the typed pre-stage rejection travels by value so one invalid request carries every defect"
    )]
    pub fn admit(
        &mut self,
        envelope: &CanonicalWriteEnvelope,
        corrected_from_operation_id: Option<&OperationId>,
    ) -> Result<eliot_store_api::PreparedTransition, AdmissionRejection> {
        let canonical_hash = envelope
            .canonical_request_hash()
            .unwrap_or_else(|_| "0".repeat(64));
        if let Some(stored) = self.entries.get(&envelope.idempotency_key) {
            if stored.canonical_request_hash == canonical_hash {
                return Err(stored.rejection.clone());
            }
            let rejection =
                identity_conflict_rejection(envelope, &canonical_hash, corrected_from_operation_id);
            self.retain_rejected_operation(envelope, &rejection);
            return Err(rejection);
        }
        if let Err(lineage) = self
            .retained
            .verify_correction_lineage(&envelope.operation_id, corrected_from_operation_id)
        {
            let rejection =
                unproven_correction_lineage_rejection(envelope, &canonical_hash, &lineage);
            self.retain_refusal(envelope, &canonical_hash, &rejection);
            return Err(rejection);
        }
        let defects = collect_contract_errors(envelope, corrected_from_operation_id);
        if defects.is_empty() {
            match envelope.prepare() {
                Ok(transition) => Ok(transition),
                Err(error) => {
                    let rejection = rejection_for_defects(
                        envelope,
                        &canonical_hash,
                        vec![unmapped_defect(
                            envelope,
                            &error.to_string(),
                            corrected_from_operation_id,
                        )],
                        corrected_from_operation_id,
                    );
                    self.retain_refusal(envelope, &canonical_hash, &rejection);
                    Err(rejection)
                }
            }
        } else {
            let has_semantic = defects
                .iter()
                .any(|defect| defect.semantic_vs_schema_error == "semantic");
            let mut rejection = rejection_for_defects(
                envelope,
                &canonical_hash,
                defects,
                corrected_from_operation_id,
            );
            if has_semantic {
                rejection.safe_capture_fallback = Some(SafeCaptureFallback {
                    kind: "ObservationCandidate".to_owned(),
                    candidate_id: format!("candidate:{}", envelope.operation_id.as_str()),
                    reason: "semantic ambiguity preserved as cold capture".to_owned(),
                    disposition: "Cold".to_owned(),
                });
            }
            self.retain_refusal(envelope, &canonical_hash, &rejection);
            Err(rejection)
        }
    }

    /// Looks up the stored rejection for one idempotency key, if any.
    #[must_use]
    pub fn get(&self, idempotency_key: &str) -> Option<&AdmissionRejection> {
        self.entries
            .get(idempotency_key)
            .map(|stored| &stored.rejection)
    }

    /// Retains one refusal under its idempotency key and under the operation
    /// identity it refused.
    ///
    /// The keyed entry keeps exact same-hash retry on the identical rejection;
    /// the retained operation identity keeps the corrected operation identity
    /// issued with that rejection and lets a later lineage claim be checked
    /// against this journal's own record.
    fn retain_refusal(
        &mut self,
        envelope: &CanonicalWriteEnvelope,
        canonical_hash: &str,
        rejection: &AdmissionRejection,
    ) {
        self.retain_rejected_operation(envelope, rejection);
        self.entries.insert(
            envelope.idempotency_key.clone(),
            StoredRejection {
                canonical_request_hash: canonical_hash.to_owned(),
                rejection: rejection.clone(),
            },
        );
    }

    /// Retains the refused operation identity without touching the keyed retry
    /// entry: a changed-bytes `IDENTITY_CONFLICT` refusal must never overwrite
    /// the stored rejection for that key.
    fn retain_rejected_operation(
        &mut self,
        envelope: &CanonicalWriteEnvelope,
        rejection: &AdmissionRejection,
    ) {
        self.retained.retain(&envelope.operation_id, rejection);
    }
}

/// Accumulates every detected defect in one response.
///
/// Each check pushes its own `ContractError` instead of returning early, so a
/// single invalid request reports schema and semantic defects together.
#[allow(
    clippy::too_many_lines,
    reason = "each admission check pushes its own defect so one request reports every defect"
)]
#[must_use]
pub fn collect_contract_errors(
    envelope: &CanonicalWriteEnvelope,
    corrected_from_operation_id: Option<&OperationId>,
) -> Vec<ContractError> {
    let mut defects: Vec<ContractError> = Vec::new();
    let mut push = |code: &str,
                    invalid: Vec<String>,
                    missing: Vec<String>,
                    allowed: Vec<String>,
                    kind: &str,
                    fallback: &str| {
        defects.push(mk_defect(
            envelope,
            code,
            invalid,
            missing,
            allowed,
            kind,
            fallback,
            corrected_from_operation_id,
        ));
    };

    if envelope.idempotency_key.trim().is_empty()
        || envelope.idempotency_key.chars().any(char::is_control)
    {
        push(
            "INVALID_FIELD",
            vec!["idempotency_key".to_owned()],
            Vec::new(),
            Vec::new(),
            "schema",
            "none",
        );
    }
    if envelope.admission_contract_set_digest.len() != 64
        || envelope
            .admission_contract_set_digest
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        push(
            "INVALID_FIELD",
            vec!["admission_contract_set_digest".to_owned()],
            Vec::new(),
            Vec::new(),
            "schema",
            "none",
        );
    }
    if envelope.semantic_commands.is_empty() {
        push(
            "EMPTY_FIELD",
            Vec::new(),
            vec!["semantic_commands".to_owned()],
            Vec::new(),
            "schema",
            "none",
        );
    }
    {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        let mut duplicate = false;
        for command in &envelope.semantic_commands {
            if !seen.insert(command.operation) {
                duplicate = true;
            }
        }
        if duplicate {
            push(
                "DUPLICATE_IDENTITY",
                vec!["semantic_commands".to_owned()],
                Vec::new(),
                Vec::new(),
                "schema",
                "none",
            );
        }
    }
    for (index, command) in envelope.semantic_commands.iter().enumerate() {
        if command.validate().is_err() {
            push(
                "INVALID_FIELD",
                vec![format!("semantic_commands[{index}]")],
                Vec::new(),
                Vec::new(),
                "schema",
                "none",
            );
        } else if command.operation.transition_class() != envelope.transition_class {
            push(
                "COMMAND_CLASS_MISMATCH",
                vec![format!("semantic_commands[{index}].operation")],
                Vec::new(),
                Vec::new(),
                "semantic",
                "ObservationCandidate",
            );
        }
    }
    if !eliot_store_api::effect_is_at_most(
        envelope.requested_effect_ceiling,
        envelope.transition_class.maximum_effect(),
    ) {
        push(
            "EFFECT_CEILING_EXCEEDED",
            vec!["requested_effect_ceiling".to_owned()],
            Vec::new(),
            Vec::new(),
            "semantic",
            "ObservationCandidate",
        );
    }
    if envelope
        .event_projection_relation_intents
        .validate()
        .is_err()
    {
        push(
            "INVALID_FIELD",
            vec!["event_projection_relation_intents".to_owned()],
            Vec::new(),
            Vec::new(),
            "schema",
            "none",
        );
    }
    {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        if envelope
            .required_proof_and_approval_refs
            .iter()
            .any(|value| !seen.insert(value.clone()))
        {
            push(
                "DUPLICATE_IDENTITY",
                vec!["required_proof_and_approval_refs".to_owned()],
                Vec::new(),
                Vec::new(),
                "schema",
                "none",
            );
        }
    }
    for reference in &envelope.required_proof_and_approval_refs {
        if reference.trim().is_empty() || reference.chars().any(char::is_control) {
            push(
                "INVALID_FIELD",
                vec!["required_proof_and_approval_ref".to_owned()],
                Vec::new(),
                Vec::new(),
                "schema",
                "none",
            );
            break;
        }
    }
    if envelope.request.validate().is_err() {
        push(
            "INVALID_FIELD",
            vec!["request".to_owned()],
            Vec::new(),
            Vec::new(),
            "schema",
            "none",
        );
    }
    if let (Some(request_task), Some(envelope_task)) =
        (envelope.request.task_id.as_ref(), envelope.task_id.as_ref())
        && request_task.as_str() != envelope_task
    {
        push(
            "TASK_BINDING_MISMATCH",
            vec!["task_id".to_owned()],
            Vec::new(),
            Vec::new(),
            "semantic",
            "ObservationCandidate",
        );
    }
    for head in &envelope.expected_revision_heads {
        if head.validate().is_err() || head.state_fence != envelope.request.state_fence {
            push(
                "STALE_REVISION",
                vec!["expected_revision_heads".to_owned()],
                Vec::new(),
                Vec::new(),
                "semantic",
                "ObservationCandidate",
            );
            break;
        }
    }
    for head in &envelope.expected_ordering_heads {
        if head.validate().is_err() || head.state_fence != envelope.request.state_fence {
            push(
                "ORDERING_CONFLICT",
                vec!["expected_ordering_heads".to_owned()],
                Vec::new(),
                Vec::new(),
                "semantic",
                "none",
            );
            break;
        }
    }
    if envelope
        .security
        .validate(&envelope.request.state_fence)
        .is_err()
    {
        push(
            "SECURITY_CONTRACT_REJECTED",
            vec!["security".to_owned()],
            Vec::new(),
            Vec::new(),
            "semantic",
            "ObservationCandidate",
        );
    }
    if let Some(corrected_from) = corrected_from_operation_id
        && corrected_from.as_str() == envelope.operation_id.as_str()
    {
        push(
            "IDENTITY_CONFLICT",
            vec!["operation_id".to_owned()],
            Vec::new(),
            Vec::new(),
            "semantic",
            "none",
        );
    }
    defects
}

fn schema_digest_or_unknown() -> String {
    contract_identity().map_or_else(|_| "unknown".to_owned(), |identity| identity.shape_sha256)
}

#[allow(
    clippy::too_many_arguments,
    reason = "one constructor keeps every ContractError field assignment in a single audited place"
)]
fn mk_defect(
    envelope: &CanonicalWriteEnvelope,
    code: &str,
    invalid_fields_and_paths: Vec<String>,
    missing_fields: Vec<String>,
    allowed_enum_values: Vec<String>,
    semantic_vs_schema_error: &str,
    safe_fallback: &str,
    corrected_from_operation_id: Option<&OperationId>,
) -> ContractError {
    ContractError {
        code: code.to_owned(),
        schema_digest: schema_digest_or_unknown(),
        invalid_fields_and_paths,
        missing_fields,
        allowed_enum_values,
        semantic_vs_schema_error: semantic_vs_schema_error.to_owned(),
        evidence_refs: Vec::new(),
        safe_fallback: safe_fallback.to_owned(),
        minimal_valid_example: "see eliot-canonical CanonicalWriteEnvelope schema".to_owned(),
        next_allowed_action:
            "correct the bounded contract errors and resubmit with a new operation identity"
                .to_owned(),
        retry_policy: CORRECTED_RETRY_IDENTITY_RULE.to_owned(),
        write_mutation_status: WriteMutationStatus::NotAttempted,
        write_intent_id: None,
        proposed_operation_id: envelope.operation_id.as_str().to_owned(),
        corrected_operation_id: None,
        corrected_from_operation_id: corrected_from_operation_id.map(|id| id.as_str().to_owned()),
    }
}

fn unmapped_defect(
    envelope: &CanonicalWriteEnvelope,
    detail: &str,
    corrected_from_operation_id: Option<&OperationId>,
) -> ContractError {
    let mut defect = mk_defect(
        envelope,
        "INVALID_FIELD",
        vec!["envelope".to_owned()],
        Vec::new(),
        Vec::new(),
        "schema",
        "none",
        corrected_from_operation_id,
    );
    defect.evidence_refs = vec![detail.chars().take(128).collect()];
    defect
}

fn rejection_for_defects(
    envelope: &CanonicalWriteEnvelope,
    canonical_hash: &str,
    defects: Vec<ContractError>,
    corrected_from_operation_id: Option<&OperationId>,
) -> AdmissionRejection {
    let mut errors = defects;
    let rejection_id = derive_rejection_id(&envelope.idempotency_key, canonical_hash);
    // The owner issues the corrected operation identity here, once, from the
    // inputs the refusal is already fixed by. Every defect in the one response
    // carries the same identity, so a caller never has to invent one and the
    // advisory retry rule stops being the only statement of the rule.
    let corrected_operation_id =
        derive_corrected_operation_id(envelope.operation_id.as_str(), &rejection_id);
    for error in &mut errors {
        error.corrected_from_operation_id =
            corrected_from_operation_id.map(|id| id.as_str().to_owned());
        error.corrected_operation_id = Some(corrected_operation_id.clone());
    }
    AdmissionRejection {
        request_id: envelope.request.request_id.as_str().to_owned(),
        proposed_operation_id: envelope.operation_id.as_str().to_owned(),
        idempotency_key: envelope.idempotency_key.clone(),
        canonical_request_hash: canonical_hash.to_owned(),
        rejection_id,
        stage_state: StageState::None,
        ordering_sequence_assigned: false,
        decision: if errors.iter().any(|error| error.code == "IDENTITY_CONFLICT") {
            AdmissionDecision::Conflict
        } else {
            AdmissionDecision::NotAccepted
        },
        all_contract_errors: errors,
        durable_audit_or_problem_ref: None,
        safe_capture_fallback: None,
        corrected_retry_identity_rule: CORRECTED_RETRY_IDENTITY_RULE.to_owned(),
        next_allowed_action:
            "correct the bounded contract errors and resubmit with a new operation identity"
                .to_owned(),
    }
}

fn identity_conflict_rejection(
    envelope: &CanonicalWriteEnvelope,
    canonical_hash: &str,
    corrected_from_operation_id: Option<&OperationId>,
) -> AdmissionRejection {
    let mut rejection = rejection_for_defects(
        envelope,
        canonical_hash,
        vec![mk_defect(
            envelope,
            "IDENTITY_CONFLICT",
            vec!["idempotency_key".to_owned()],
            Vec::new(),
            Vec::new(),
            "semantic",
            "none",
            corrected_from_operation_id,
        )],
        corrected_from_operation_id,
    );
    rejection.decision = AdmissionDecision::Conflict;
    "resubmit the changed bytes under a new idempotency key with corrected_from_operation_id lineage"
        .clone_into(&mut rejection.next_allowed_action);
    rejection
}

/// Refuses a correction whose lineage this owner cannot prove, or whose
/// corrected bytes still carry an operation identity it already rejected.
///
/// The refusal records no `corrected_from_operation_id`: an unproven claim is
/// never stamped as lineage, so a downstream layer cannot read the field and
/// believe it. The owner-issued corrected operation identity is still carried,
/// so the caller has exactly one identity to resubmit under.
fn unproven_correction_lineage_rejection(
    envelope: &CanonicalWriteEnvelope,
    canonical_hash: &str,
    lineage: &CorrectionLineageError,
) -> AdmissionRejection {
    let (code, invalid_field, next_action) = match lineage {
        CorrectionLineageError::UnprovenLineage { .. } => (
            UNPROVEN_CORRECTION_LINEAGE,
            "corrected_from_operation_id",
            "resubmit under the owner-issued corrected operation identity and a corrected_from_operation_id naming an operation this owner rejected",
        ),
        CorrectionLineageError::RejectedOperationIdentityReuse { .. } => (
            "IDENTITY_CONFLICT",
            "operation_id",
            "resubmit the corrected bytes under the owner-issued corrected operation identity and a new idempotency key",
        ),
    };
    let mut rejection = rejection_for_defects(
        envelope,
        canonical_hash,
        vec![mk_defect(
            envelope,
            code,
            vec![invalid_field.to_owned()],
            Vec::new(),
            Vec::new(),
            "semantic",
            "none",
            None,
        )],
        None,
    );
    if matches!(
        lineage,
        CorrectionLineageError::RejectedOperationIdentityReuse { .. }
    ) {
        rejection.decision = AdmissionDecision::Conflict;
    }
    next_action.clone_into(&mut rejection.next_allowed_action);
    rejection
}

/// Returns the canonical bytes hash input for identity decisions.
///
/// Thin helper so the Kernel pre-stage gate and this owner hash identical
/// bytes through the one shared [`eliot_store_api::canonical_request_hash`]
/// path.
#[must_use]
pub fn canonical_bytes_hash(view: &eliot_store_api::CanonicalRequestView) -> Option<String> {
    eliot_store_api::canonical_request_hash(view).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration, SourceId,
        StateFence, canonical_json_bytes,
    };
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId, ScopeId,
        SecurityContext, TransitionClass,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let lineage = EpochLineageId::new(LINEAGE).expect("lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nz")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn envelope(op: &str, idem: &str) -> CanonicalWriteEnvelope {
        let fence = fence();
        CanonicalWriteEnvelope {
            operation_id: OperationId::new(op).expect("op"),
            request: eliot_contracts::RequestMetadata {
                request_id: RequestId::new("req-1796").expect("req"),
                session_id: None,
                task_id: None,
                product_id: ProductId::new("product-1796").expect("product"),
                source_id: SourceId::new("source-1796").expect("source"),
                state_fence: fence.clone(),
                clock: eliot_contracts::ClockReading::default(),
            },
            idempotency_key: idem.to_owned(),
            scope_id: ScopeId::new("scope-1796").expect("scope"),
            task_id: None,
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: crate::supported_admission_contract_set_digest()
                .expect("admission contract set digest"),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1796")
                .expect("manifest"),
            semantic_commands: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-1796"),
                )]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
            expected_revision_heads: Vec::new(),
            expected_ordering_heads: vec![OrderingHeadExpectation {
                scope: OrderingScopeId::new("scope-1796").expect("ordering scope"),
                expected_sequence: 1,
                state_fence: fence,
            }],
        }
    }

    #[test]
    fn invalid_multi_defect_rejection_is_typed_pre_stage_with_stable_retry_identity() {
        let mut invalid = envelope("op-1796-bad", "idem-1796-a");
        invalid.admission_contract_set_digest = "not-a-digest".to_owned();
        invalid.semantic_commands.clear();
        invalid.requested_effect_ceiling = EffectClass::ExternalEffect;
        let mut journal = ContractAdmissionJournal::default();
        let Err(first) = journal.admit(&invalid, None) else {
            panic!("invalid envelope must be rejected pre-stage");
        };
        assert!(first.all_contract_errors.len() >= 3);
        assert!(matches!(first.stage_state, StageState::None));
        assert!(!first.ordering_sequence_assigned);
        assert!(matches!(first.decision, AdmissionDecision::NotAccepted));
        for defect in &first.all_contract_errors {
            assert_eq!(
                defect.write_mutation_status,
                WriteMutationStatus::NotAttempted
            );
            assert!(defect.write_intent_id.is_none());
        }
        first.validate().expect("rejection validates");
        assert!(journal.get("idem-1796-a").is_some());

        let Err(second) = journal.admit(&invalid, None) else {
            panic!("identical canonical-bytes retry must be rejected");
        };
        assert_eq!(second.rejection_id, first.rejection_id);
        assert_eq!(second.canonical_request_hash, first.canonical_request_hash);

        let mut changed = invalid.clone();
        changed.admission_contract_set_digest = "d".repeat(64);
        let Err(conflict) = journal.admit(&changed, None) else {
            panic!("changed bytes under one key must conflict");
        };
        assert!(matches!(conflict.decision, AdmissionDecision::Conflict));
        assert!(
            conflict
                .all_contract_errors
                .iter()
                .any(|defect| defect.code == "IDENTITY_CONFLICT")
        );

        let corrected_from = OperationId::new("op-1796-bad").expect("corrected-from lineage");
        let corrected = envelope("op-1796-fixed", "idem-1796-b");
        let transition = journal
            .admit(&corrected, Some(&corrected_from))
            .expect("corrected bytes admit");
        assert_eq!(transition.identity.operation_id.as_str(), "op-1796-fixed");
        let bytes = canonical_json_bytes(&transition).expect("transition encodes");
        assert!(!bytes.is_empty());
    }
}
