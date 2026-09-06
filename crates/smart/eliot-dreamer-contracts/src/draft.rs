//! Closed staged-draft schemas for provider-neutral Dreamer jobs.
//!
//! Cell `smart.dreamer.contracts`. Stages are separated by distinct types with
//! no cross-decode: raw provider bytes ([`RawProviderOutput`]), structured
//! model text ([`ModelDraft`]), evidence-grounded claims
//! ([`GroundedDreamDraft`]), validator-bound results
//! ([`ValidatedDreamDraft`]) and validator-bound curation
//! ([`ValidatedCurationItem`]). Resolved evidence lives only in the grounded
//! stage; model text can never populate it.

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::curation::{kind_family, parse_kind};
use crate::error::ContractViolation;

/// Exact schema version accepted by the versioned draft stages.
const DRAFT_SCHEMA_VERSION: u32 = 1;
/// Maximum provider-route length, measured in Unicode scalar values.
const MAX_ROUTE_CHARS: usize = 128;
/// Maximum raw provider payload accepted in one output.
const MAX_RAW_BYTES: usize = 1_048_576;
/// Maximum model statement length, measured in Unicode scalar values.
const MAX_STATEMENT_CHARS: usize = 16384;

/// Returns true when `value` is exactly 64 hex digits.
fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Returns true when `value` is empty or consists only of whitespace.
fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

/// Maps a fence validation failure onto the closed contract error.
fn fence_error(err: &eliot_contracts::ContractError) -> ContractViolation {
    ContractViolation::BindingMismatch {
        field: "state_fence",
        reason: err.to_string(),
    }
}

/// Rejects a blank identity field shared by the draft stages.
fn check_identity(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_blank(value) {
        return Err(ContractViolation::MissingField(field));
    }
    Ok(())
}

/// Rejects a digest that is not exactly 64 hex characters.
fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if !is_hex64(value) {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "digest must be 64 hex characters".to_string(),
        });
    }
    Ok(())
}

/// Rejects a schema version other than the exact accepted one.
fn check_schema_version(schema_version: u32) -> Result<(), ContractViolation> {
    if schema_version != DRAFT_SCHEMA_VERSION {
        return Err(ContractViolation::OutOfBounds {
            field: "schema_version",
            min: 1,
            max: 1,
            got: i64::from(schema_version),
        });
    }
    Ok(())
}

/// Opaque provider bytes exactly as returned, before any structuring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawProviderOutput {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Owning job identity.
    pub job_id: String,
    /// Provider route that produced these bytes, non-blank, at most 128 chars.
    pub provider_route: String,
    /// Untouched provider payload, at most 1 MiB.
    pub raw_bytes: Vec<u8>,
    /// SHA-256 of `raw_bytes` (64 hex); must match the payload exactly.
    pub output_digest: String,
}

impl RawProviderOutput {
    /// Validates intrinsic bounds plus digest isolation of the raw payload.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version)?;
        check_identity(&self.job_id, "job_id")?;
        check_identity(&self.provider_route, "provider_route")?;
        if self.provider_route.chars().count() > MAX_ROUTE_CHARS {
            return Err(ContractViolation::OutOfBounds {
                field: "provider_route",
                min: 1,
                max: crate::error::len_i64(MAX_ROUTE_CHARS),
                got: crate::error::len_i64(self.provider_route.chars().count()),
            });
        }
        if self.raw_bytes.len() > MAX_RAW_BYTES {
            return Err(ContractViolation::OutOfBounds {
                field: "raw_bytes",
                min: 0,
                max: crate::error::len_i64(MAX_RAW_BYTES),
                got: crate::error::len_i64(self.raw_bytes.len()),
            });
        }
        if self.output_digest != sha256_hex(&self.raw_bytes) {
            return Err(ContractViolation::BindingMismatch {
                field: "output_digest",
                reason: "output digest must equal sha256(raw_bytes)".to_string(),
            });
        }
        Ok(())
    }
}

/// Structured model text: hypotheses only, never resolved evidence.
///
/// `declared_confirmed_handles` must stay empty: model text cannot populate
/// resolved evidence, which lives only in [`GroundedDreamDraft`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelDraft {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Owning job identity.
    pub job_id: String,
    /// Hypothesis statement, non-empty, at most 16384 characters.
    pub statement: String,
    /// Non-empty list of source handles the statement draws on.
    pub source_handles: Vec<String>,
    /// Counterevidence the model itself surfaced.
    pub counterevidence: Vec<String>,
    /// Model-declared uncertainty.
    pub uncertainty: String,
    /// Expected benefit in hypothesis wording, non-empty.
    pub expected_benefit: String,
    /// Probes the model recommends to test the hypothesis.
    pub recommended_probes: Vec<String>,
    /// Conditions that would invalidate the hypothesis.
    pub invalidation_conditions: Vec<String>,
    /// Must be empty: model text cannot declare confirmed evidence.
    pub declared_confirmed_handles: Vec<String>,
}

impl ModelDraft {
    /// Validates intrinsic bounds and the no-confirmed-evidence rule.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version)?;
        check_identity(&self.job_id, "job_id")?;
        if is_blank(&self.statement) {
            return Err(ContractViolation::MissingField("statement"));
        }
        if self.statement.chars().count() > MAX_STATEMENT_CHARS {
            return Err(ContractViolation::OutOfBounds {
                field: "statement",
                min: 1,
                max: crate::error::len_i64(MAX_STATEMENT_CHARS),
                got: crate::error::len_i64(self.statement.chars().count()),
            });
        }
        if self.source_handles.is_empty() {
            return Err(ContractViolation::MissingField("source_handles"));
        }
        for handle in &self.source_handles {
            if is_blank(handle) {
                return Err(ContractViolation::MissingField("source_handles"));
            }
        }
        if is_blank(&self.expected_benefit) {
            return Err(ContractViolation::MissingField("expected_benefit"));
        }
        if !self.declared_confirmed_handles.is_empty() {
            return Err(ContractViolation::ForbiddenCarry(
                "model draft must not declare confirmed evidence handles".to_string(),
            ));
        }
        Ok(())
    }
}

/// Per-claim support outcome against the input manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SupportState {
    /// The claim is fully supported by manifest evidence.
    Supported,
    /// The claim is partially supported by manifest evidence.
    Partial,
    /// Manifest evidence contradicts the claim.
    Contradicted,
    /// The claim reaches beyond the manifest scope.
    OutsideManifest,
    /// The claim demands more precision than the evidence admits.
    UnsupportedPrecision,
}

/// One claim with its grounding outcome and preserved detail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimResidue {
    /// The claim text, non-blank.
    pub claim: String,
    /// Grounding outcome for the claim.
    pub state: SupportState,
    /// Preserved grounding detail, non-blank.
    pub detail: String,
}

impl ClaimResidue {
    /// Validates that claim and detail are both present.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if is_blank(&self.claim) {
            return Err(ContractViolation::MissingField("claim"));
        }
        if is_blank(&self.detail) {
            return Err(ContractViolation::MissingField("detail"));
        }
        Ok(())
    }
}

/// Evidence-grounded draft binding one [`ModelDraft`] digest to residues.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroundedDreamDraft {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Owning job identity.
    pub job_id: String,
    /// Digest of the model draft this grounding accounts for (64 hex).
    pub draft_digest: String,
    /// Non-empty residue list: every claim is accounted.
    pub residues: Vec<ClaimResidue>,
    /// Coverage note for the residue set.
    pub coverage_note: String,
}

impl GroundedDreamDraft {
    /// Validates the draft binding plus full residue accounting.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version)?;
        check_identity(&self.job_id, "job_id")?;
        check_digest(&self.draft_digest, "draft_digest")?;
        if self.residues.is_empty() {
            return Err(ContractViolation::MissingField("residues"));
        }
        for residue in &self.residues {
            residue.validate()?;
        }
        Ok(())
    }
}

/// A-05 validator binding receipt over one draft and one bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidationReceipt {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Validator contract identity, non-blank.
    pub validator_contract: String,
    /// Validator policy identity, non-blank.
    pub validator_policy: String,
    /// Job the validated draft belongs to.
    pub job_id: String,
    /// Digest of the validated draft (64 hex).
    pub draft_digest: String,
    /// Digest of the input bundle (64 hex).
    pub bundle_digest: String,
    /// Digest of the source manifest (64 hex).
    pub manifest_digest: String,
    /// Task the validated draft is bound to.
    pub task_id: String,
    /// Scope the validated draft is bound to.
    pub scope_id: String,
    /// Digest of the validator input (64 hex).
    pub input_digest: String,
    /// Digest of the validator output (64 hex).
    pub output_digest: String,
    /// Terminal disposition: exactly `accepted`, `rejected` or `partial`.
    pub terminal_disposition: String,
    /// Proof ceiling the validator attests, non-blank.
    pub proof_ceiling: String,
    pub state_fence: StateFence,
    pub preservation_digest: String,
    pub budget_digest: String,
}

impl ValidationReceipt {
    /// Validates intrinsic bounds, digest shapes and the closed disposition.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version)?;
        check_identity(&self.validator_contract, "validator_contract")?;
        check_identity(&self.validator_policy, "validator_policy")?;
        check_identity(&self.job_id, "job_id")?;
        check_identity(&self.task_id, "task_id")?;
        check_identity(&self.scope_id, "scope_id")?;
        check_identity(&self.proof_ceiling, "proof_ceiling")?;
        check_digest(&self.draft_digest, "draft_digest")?;
        check_digest(&self.bundle_digest, "bundle_digest")?;
        check_digest(&self.manifest_digest, "manifest_digest")?;
        check_digest(&self.input_digest, "input_digest")?;
        check_digest(&self.output_digest, "output_digest")?;
        check_digest(&self.preservation_digest, "preservation_digest")?;
        check_digest(&self.budget_digest, "budget_digest")?;
        self.state_fence
            .validate()
            .map_err(|err| fence_error(&err))?;
        match self.terminal_disposition.as_str() {
            "accepted" | "rejected" | "partial" => Ok(()),
            _ => Err(ContractViolation::UnknownVariant {
                field: "terminal_disposition",
                value: self.terminal_disposition.clone(),
            }),
        }
    }

    /// Validates both receipts, then binds self to the recorded receipt.
    ///
    /// Any mismatch of job, digests, contract, ceiling or fence fails with
    /// [`ContractViolation::BindingMismatch`].
    pub fn validate_binding(&self, expected: &ValidationReceipt) -> Result<(), ContractViolation> {
        self.validate()?;
        expected.validate()?;
        for (field, got, want) in [
            ("job_id", &self.job_id, &expected.job_id),
            ("draft_digest", &self.draft_digest, &expected.draft_digest),
            (
                "bundle_digest",
                &self.bundle_digest,
                &expected.bundle_digest,
            ),
            (
                "manifest_digest",
                &self.manifest_digest,
                &expected.manifest_digest,
            ),
            (
                "validator_contract",
                &self.validator_contract,
                &expected.validator_contract,
            ),
            (
                "preservation_digest",
                &self.preservation_digest,
                &expected.preservation_digest,
            ),
            (
                "budget_digest",
                &self.budget_digest,
                &expected.budget_digest,
            ),
            (
                "proof_ceiling",
                &self.proof_ceiling,
                &expected.proof_ceiling,
            ),
        ] {
            if got != want {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: std::format!("receipt {field} binding mismatch"),
                });
            }
        }
        if self.state_fence != expected.state_fence {
            return Err(ContractViolation::BindingMismatch {
                field: "state_fence",
                reason: "receipt state_fence binding mismatch".to_string(),
            });
        }
        Ok(())
    }
}

/// Draft accepted through a [`ValidationReceipt`] binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidatedDreamDraft {
    /// Validator receipt backing this draft.
    pub receipt: ValidationReceipt,
    /// Digest of the validated draft; must equal the receipt draft digest.
    pub draft_digest: String,
    /// Scope the draft is presented for; must equal the receipt scope.
    pub scope_id: String,
    /// Task the draft is presented for; must equal the receipt task.
    pub task_id: String,
    /// State fence the validation is presented under.
    pub state_fence: StateFence,
}

impl ValidatedDreamDraft {
    /// Validates the receipt plus the draft/scope/task/fence binding.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.receipt.validate()?;
        for (field, got, want) in [
            (
                "draft_digest",
                &self.draft_digest,
                &self.receipt.draft_digest,
            ),
            ("scope_id", &self.scope_id, &self.receipt.scope_id),
            ("task_id", &self.task_id, &self.receipt.task_id),
        ] {
            if got != want {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: std::format!("validated draft {field} binding mismatch"),
                });
            }
        }
        self.state_fence
            .validate()
            .map_err(|err| fence_error(&err))?;
        Ok(())
    }
}

/// Validator-bound typed curation item proposed for handling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidatedCurationItem {
    /// Validator receipt backing this item.
    pub receipt: ValidationReceipt,
    /// Curation kind wire spelling (e.g. `merge`), non-blank.
    pub kind_spelling: String,
    /// Curation family wire spelling, non-blank.
    pub family_spelling: String,
    /// Digest of the curation source.
    pub source_digest: String,
    /// Target denominator the curation applies to.
    pub target_denominator: String,
    /// Task the item is proposed for.
    pub task_id: String,
    /// Scope the item is proposed for.
    pub scope_id: String,
    /// State fence the item is presented under.
    pub state_fence: StateFence,
    /// Budget note recorded by the validator.
    pub budget_note: String,
}

impl ValidatedCurationItem {
    /// Validates receipt, kind/family agreement and task/scope/fence binding.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.receipt.validate()?;
        let kind = parse_kind(&self.kind_spelling)?;
        if kind_family(kind) != self.family_spelling.as_str() {
            return Err(ContractViolation::KindPayload(
                "curation item kind/family mismatch".to_owned(),
            ));
        }
        if (&self.task_id, &self.scope_id, &self.state_fence)
            != (
                &self.receipt.task_id,
                &self.receipt.scope_id,
                &self.receipt.state_fence,
            )
        {
            return Err(ContractViolation::BindingMismatch {
                field: "task_scope_fence",
                reason: "curation item task/scope/fence binding mismatch".to_string(),
            });
        }
        check_digest(&self.source_digest, "source_digest")?;
        check_identity(&self.target_denominator, "target_denominator")?;
        check_identity(&self.budget_note, "budget_note")?;
        Ok(())
    }
}

/// Samples a valid receipt bound to `draft_digest` for tests.
#[cfg(test)]
pub(crate) fn valid_receipt(draft_digest: &str, fence: StateFence) -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".to_string(),
        validator_policy: "policy-7".to_string(),
        job_id: "job-1".to_string(),
        draft_digest: draft_digest.to_string(),
        bundle_digest: sha256_hex(b"bundle"),
        manifest_digest: sha256_hex(b"manifest"),
        task_id: "task-1".to_string(),
        scope_id: "scope-1".to_string(),
        input_digest: sha256_hex(b"validator-input"),
        output_digest: sha256_hex(b"validator-output"),
        terminal_disposition: "accepted".to_string(),
        proof_ceiling: "candidate-only".to_string(),
        state_fence: fence,
        preservation_digest: sha256_hex(b"preservation"),
        budget_digest: sha256_hex(b"budget"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};

    fn valid_fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn valid_raw() -> RawProviderOutput {
        let raw_bytes = br#"{"hypothesis":"cache helps"}"#.to_vec();
        let output_digest = sha256_hex(&raw_bytes);
        RawProviderOutput {
            schema_version: 1,
            job_id: "job-1".to_string(),
            provider_route: "provider-a/v1".to_string(),
            raw_bytes,
            output_digest,
        }
    }

    fn valid_model() -> ModelDraft {
        ModelDraft {
            schema_version: 1,
            job_id: "job-1".to_string(),
            statement: "Caching cuts tail latency.".to_string(),
            source_handles: vec!["source-a".to_string()],
            counterevidence: vec!["cold start unaffected".to_string()],
            uncertainty: "medium".to_string(),
            expected_benefit: "Lower p99 if hit rate holds.".to_string(),
            recommended_probes: vec!["measure hit rate".to_string()],
            invalidation_conditions: vec!["hit rate below 50%".to_string()],
            declared_confirmed_handles: Vec::new(),
        }
    }

    fn model_wire_digest(model: &ModelDraft) -> String {
        let wire = serde_json::to_string(model).expect("model serializes");
        sha256_hex(wire.as_bytes())
    }

    fn valid_grounded(draft_digest: &str) -> GroundedDreamDraft {
        GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_string(),
            draft_digest: draft_digest.to_string(),
            residues: vec![ClaimResidue {
                claim: "Caching cuts tail latency.".to_string(),
                state: SupportState::Partial,
                detail: "supported for warm keys only".to_string(),
            }],
            coverage_note: "covers the single model claim".to_string(),
        }
    }

    // WORK_UNIT_CASE: 578/17
    #[test]
    fn stages_cannot_cross_decode() {
        let raw = valid_raw();
        assert!(raw.validate().is_ok());
        let raw_json = serde_json::to_string(&raw).expect("raw serializes");
        assert!(serde_json::from_str::<GroundedDreamDraft>(&raw_json).is_err());
        assert!(serde_json::from_str::<ValidatedDreamDraft>(&raw_json).is_err());

        let model = valid_model();
        assert!(model.validate().is_ok());
        let model_json = serde_json::to_string(&model).expect("model serializes");
        assert!(serde_json::from_str::<RawProviderOutput>(&model_json).is_err());
        assert!(serde_json::from_str::<ValidatedDreamDraft>(&model_json).is_err());

        let digest = model_wire_digest(&model);
        let grounded = valid_grounded(&digest);
        assert!(grounded.validate().is_ok());
        let grounded_json = serde_json::to_string(&grounded).expect("grounded serializes");
        assert!(serde_json::from_str::<RawProviderOutput>(&grounded_json).is_err());
        assert!(serde_json::from_str::<ModelDraft>(&grounded_json).is_err());

        // Digest isolation: a well-shaped payload with a foreign digest fails.
        let mut tampered = valid_raw();
        tampered.output_digest = sha256_hex(b"something-else");
        assert!(tampered.validate().is_err());

        // Closed world: an injected unknown field fails even on valid bytes.
        let with_extra = raw_json.trim_end_matches('}').to_string() + r#","injected":1}"#;
        assert!(serde_json::from_str::<RawProviderOutput>(&with_extra).is_err());

        // Model text can never carry confirmed evidence handles.
        let mut carrying = valid_model();
        carrying.declared_confirmed_handles = vec!["source-a".to_string()];
        assert!(matches!(
            carrying.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
    }

    // WORK_UNIT_CASE: 578/18
    #[test]
    fn all_support_states_roundtrip_with_detail() {
        let states = [
            SupportState::Supported,
            SupportState::Partial,
            SupportState::Contradicted,
            SupportState::OutsideManifest,
            SupportState::UnsupportedPrecision,
        ];
        let residues: Vec<ClaimResidue> = states
            .iter()
            .enumerate()
            .map(|(index, state)| ClaimResidue {
                claim: format!("claim-{index}"),
                state: *state,
                detail: format!("residue detail for claim-{index}"),
            })
            .collect();
        let draft = GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_string(),
            draft_digest: sha256_hex(b"model"),
            residues,
            coverage_note: "covers claims 0-4".to_string(),
        };
        assert!(draft.validate().is_ok());
        let wire = serde_json::to_string(&draft).expect("grounded serializes");
        let back: GroundedDreamDraft = serde_json::from_str(&wire).expect("grounded deserializes");
        assert_eq!(back, draft);
        for state in states {
            assert!(
                back.residues
                    .iter()
                    .any(|residue| residue.state == state && !residue.detail.trim().is_empty()),
                "state {state:?} must roundtrip with detail preserved"
            );
        }
        let mut wires: Vec<String> = states
            .iter()
            .map(|state| serde_json::to_string(state).expect("state serializes"))
            .collect();
        wires.sort();
        wires.dedup();
        assert_eq!(wires.len(), states.len());
    }

    // WORK_UNIT_CASE: 578/19
    #[test]
    fn valid_a05_receipt_binding_passes() {
        let model = valid_model();
        let digest = model_wire_digest(&model);
        let receipt = valid_receipt(&digest, valid_fence());
        assert!(receipt.validate().is_ok());
        let recorded = receipt.clone();
        assert!(receipt.validate_binding(&recorded).is_ok());

        let validated = ValidatedDreamDraft {
            receipt: receipt.clone(),
            draft_digest: digest,
            scope_id: "scope-1".to_string(),
            task_id: "task-1".to_string(),
            state_fence: valid_fence(),
        };
        assert!(validated.validate().is_ok());

        let item = ValidatedCurationItem {
            receipt,
            kind_spelling: "merge".to_string(),
            family_spelling: "structure_repair".to_string(),
            source_digest: sha256_hex(b"curation-source"),
            target_denominator: "scope-1:2-of-2".to_string(),
            task_id: "task-1".to_string(),
            scope_id: "scope-1".to_string(),
            state_fence: valid_fence(),
            budget_note: "within dimension".to_string(),
        };
        assert!(item.validate().is_ok());
    }

    // WORK_UNIT_CASE: 578/20
    #[test]
    fn any_binding_mutation_invalidates_receipt() {
        let model = valid_model();
        let digest = model_wire_digest(&model);
        let base = valid_receipt(&digest, valid_fence());
        let recorded = base.clone();
        assert!(base.validate_binding(&recorded).is_ok());
        let wire = serde_json::to_string(&base).expect("receipt serializes");
        for field in ["job-1", "a05-validator", "candidate-only"] {
            let mutated_wire = wire.replacen(field, "other", 1);
            let mutated: ValidationReceipt =
                serde_json::from_str(&mutated_wire).expect("mutated wire decodes");
            assert!(mutated.validate_binding(&recorded).is_err());
        }
        let mut changed_draft = base.clone();
        changed_draft.draft_digest = sha256_hex(b"other-draft");
        assert!(changed_draft.validate_binding(&recorded).is_err());
        let mut changed_bundle = base.clone();
        changed_bundle.bundle_digest = sha256_hex(b"other-bundle");
        assert!(changed_bundle.validate_binding(&recorded).is_err());
        let mut changed_manifest = base.clone();
        changed_manifest.manifest_digest = sha256_hex(b"other-manifest");
        assert!(changed_manifest.validate_binding(&recorded).is_err());
        let mut changed_preservation = base.clone();
        changed_preservation.preservation_digest = sha256_hex(b"other-preservation");
        assert!(changed_preservation.validate_binding(&recorded).is_err());
        let mut changed_budget = base.clone();
        changed_budget.budget_digest = sha256_hex(b"other-budget");
        assert!(changed_budget.validate_binding(&recorded).is_err());
        let mut changed_fence = base.clone();
        changed_fence.state_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).expect("non-genesis generation"),
        );
        assert!(changed_fence.validate_binding(&recorded).is_err());
        let mut changed_validator = base.clone();
        changed_validator.validator_contract = "   ".to_string();
        assert!(changed_validator.validate().is_err());
        let mut changed_digest = base.clone();
        changed_digest.output_digest = "not-a-digest".to_string();
        assert!(changed_digest.validate().is_err());
    }
}
