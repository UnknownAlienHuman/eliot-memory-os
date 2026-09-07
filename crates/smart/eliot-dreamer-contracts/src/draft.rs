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

use crate::curation::{CurationPayload, kind_family, parse_kind};
use crate::error::ContractViolation;
use crate::error::{check_fence, check_text, check_vec_bound, is_hex64_lower, sorted_set_eq};
use crate::{
    budget::BudgetUsage,
    bundle::DreamInputBundle,
    encoding,
    job::{DreamJobInput, Requester},
};
use crate::{
    registry::{AtomicityMode, TargetDenominator, TypedCurationHandlerRequest, parse_family},
    screen::ScreenBinding,
};

/// Exact schema version accepted by the versioned draft stages.
const DRAFT_SCHEMA_VERSION: u32 = 1;
/// Maximum provider-route/handle length, measured in bytes (`check_text` bound).
const MAX_ROUTE_CHARS: usize = 128;
/// Maximum raw provider payload accepted in one output.
const MAX_RAW_BYTES: usize = 1_048_576;
/// Maximum model statement length, measured in bytes (`check_text` bound).
const MAX_STATEMENT_CHARS: usize = 16384;

/// Rejects a receipt-owned value that drifts from the recorded receipt.
fn bind_eq(field: &'static str, got: &str, want: &str) -> Result<(), ContractViolation> {
    if got != want {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: std::format!("receipt {field} binding mismatch"),
        });
    }
    Ok(())
}
/// Rejects a digest that is not exactly 64 lowercase hex characters.
fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if !is_hex64_lower(value) {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "digest must be 64 hex characters".to_string(),
        });
    }
    Ok(())
}

/// Rejects over-count/over-bytes vectors plus bad elements via shared bounds.
fn check_str_vec(v: &[String], field: &'static str, max: usize) -> Result<(), ContractViolation> {
    check_vec_bound(v.len(), 1024, field)?;
    let total = v
        .iter()
        .map(String::len)
        .fold(0usize, usize::saturating_add);
    check_vec_bound(total, 1_048_576, field)?;
    for item in v {
        check_text(item, field, max)?;
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
        crate::error::check_schema_version(self.schema_version, DRAFT_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id", 256)?;
        check_text(&self.provider_route, "provider_route", MAX_ROUTE_CHARS)?;
        check_vec_bound(self.raw_bytes.len(), MAX_RAW_BYTES, "raw_bytes")?;
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
        crate::error::check_schema_version(self.schema_version, DRAFT_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id", 256)?;
        check_text(&self.statement, "statement", MAX_STATEMENT_CHARS)?;
        if self.source_handles.is_empty() {
            return Err(ContractViolation::MissingField("source_handles"));
        }
        check_str_vec(&self.source_handles, "source_handles", MAX_ROUTE_CHARS)?;
        check_str_vec(&self.counterevidence, "counterevidence", 1024)?;
        check_text(&self.uncertainty, "uncertainty", 1024)?;
        check_text(&self.expected_benefit, "expected_benefit", 1024)?;
        check_str_vec(&self.recommended_probes, "recommended_probes", 1024)?;
        let conds = &self.invalidation_conditions;
        check_str_vec(conds, "invalidation_conditions", 1024)?;
        let no_confirmed = "model draft must not declare confirmed evidence handles".to_string();
        if !self.declared_confirmed_handles.is_empty() {
            return Err(ContractViolation::ForbiddenCarry(no_confirmed));
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
    /// Validates claim/detail bounds (1024-byte `check_text` each).
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.claim, "claim", 1024)?;
        check_text(&self.detail, "detail", 1024)?;
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
        crate::error::check_schema_version(self.schema_version, DRAFT_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id", 256)?;
        check_digest(&self.draft_digest, "draft_digest")?;
        check_vec_bound(self.residues.len(), 1024, "residues")?;
        let bytes: usize = self
            .residues
            .iter()
            .map(|r| r.claim.len().saturating_add(r.detail.len()))
            .fold(0usize, usize::saturating_add);
        check_vec_bound(bytes, 1_048_576, "residues")?;
        if self.residues.is_empty() {
            return Err(ContractViolation::MissingField("residues"));
        }
        self.residues.iter().try_for_each(ClaimResidue::validate)?;
        check_text(&self.coverage_note, "coverage_note", 1024)?;
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
        crate::error::check_schema_version(self.schema_version, DRAFT_SCHEMA_VERSION)?;
        check_text(&self.validator_contract, "validator_contract", 256)?;
        check_text(&self.validator_policy, "validator_policy", 256)?;
        check_text(&self.job_id, "job_id", 256)?;
        check_text(&self.task_id, "task_id", 256)?;
        check_text(&self.scope_id, "scope_id", 256)?;
        check_text(&self.proof_ceiling, "proof_ceiling", 256)?;
        check_digest(&self.draft_digest, "draft_digest")?;
        check_digest(&self.bundle_digest, "bundle_digest")?;
        check_digest(&self.manifest_digest, "manifest_digest")?;
        check_digest(&self.input_digest, "input_digest")?;
        check_digest(&self.output_digest, "output_digest")?;
        check_digest(&self.preservation_digest, "preservation_digest")?;
        check_digest(&self.budget_digest, "budget_digest")?;
        check_fence(&self.state_fence)?;
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
    /// Binds job/draft/bundle/manifest/input/output/preservation/budget digests plus
    /// contract/policy/disposition/ceiling/task/scope/fence; any mismatch fails.
    pub fn validate_binding(&self, expected: &ValidationReceipt) -> Result<(), ContractViolation> {
        self.validate()?;
        expected.validate()?;
        let (a, b) = (self, expected);
        bind_eq("job_id", &a.job_id, &b.job_id)?;
        bind_eq("task_id", &a.task_id, &b.task_id)?;
        bind_eq("scope_id", &a.scope_id, &b.scope_id)?;
        bind_eq("draft_digest", &a.draft_digest, &b.draft_digest)?;
        bind_eq("bundle_digest", &a.bundle_digest, &b.bundle_digest)?;
        bind_eq("manifest_digest", &a.manifest_digest, &b.manifest_digest)?;
        bind_eq("input_digest", &a.input_digest, &b.input_digest)?;
        bind_eq("output_digest", &a.output_digest, &b.output_digest)?;
        bind_eq("proof_ceiling", &a.proof_ceiling, &b.proof_ceiling)?;
        bind_eq("budget_digest", &a.budget_digest, &b.budget_digest)?;
        let vc = (&a.validator_contract, &b.validator_contract);
        let vp = (&a.validator_policy, &b.validator_policy);
        let td = (&a.terminal_disposition, &b.terminal_disposition);
        let pd = (&a.preservation_digest, &b.preservation_digest);
        bind_eq("validator_contract", vc.0, vc.1)?;
        bind_eq("validator_policy", vp.0, vp.1)?;
        bind_eq("terminal_disposition", td.0, td.1)?;
        bind_eq("preservation_digest", pd.0, pd.1)?;
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
        let r = &self.receipt;
        for (field, got, want) in [
            ("draft_digest", &self.draft_digest, &r.draft_digest),
            ("scope_id", &self.scope_id, &r.scope_id),
            ("task_id", &self.task_id, &r.task_id),
        ] {
            if got != want {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: std::format!("validated draft {field} binding mismatch"),
                });
            }
        }
        check_fence(&self.state_fence)?;
        Ok(())
    }
}

/// Acceptance context for [`ValidatedCurationItem::accept`]; all refs required.
pub struct CurationAcceptanceCtx<'a> {
    pub job: &'a DreamJobInput,
    pub bundle: &'a DreamInputBundle,
    pub receipt: &'a ValidationReceipt,
    pub screen: &'a ScreenBinding,
    /// Grounded draft the item accounts for; job/draft digests bound in accept.
    pub grounded: &'a GroundedDreamDraft,
    /// Typed handler request the screen must stay compatible with.
    pub request: &'a TypedCurationHandlerRequest,
    /// Observed budget use, authorized against the job limits in accept.
    pub usage: &'a BudgetUsage,
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
    /// Typed curation payload carrying its own kind.
    pub payload: CurationPayload,
    /// Declared/frozen denominator carried by the item.
    pub denominator: TargetDenominator,
    /// Digest of the curation source.
    pub source_digest: String,
    /// Task the item is proposed for.
    pub task_id: String,
    /// Scope the item is proposed for.
    pub scope_id: String,
    /// State fence the item is presented under.
    pub state_fence: StateFence,
    /// Digest of the canonical job bytes; binds the whole job wholesale.
    pub job_digest: String,
    /// Requester the item is proposed for; must equal the job requester.
    pub requester: Requester,
    /// Budget note recorded by the validator.
    pub budget_note: String,
}

fn require_bind(ok: bool, field: &'static str) -> Result<(), ContractViolation> {
    if ok {
        return Ok(());
    }
    Err(ContractViolation::BindingMismatch {
        field,
        reason: "binding mismatch".to_string(),
    })
}

fn check_targets(targets: &[String], denom: &TargetDenominator) -> Result<(), ContractViolation> {
    require_bind(targets.iter().all(|t| denom.members.contains(t)), "targets")?;
    let lax = denom.mode != AtomicityMode::AllOrNothing;
    require_bind(lax || sorted_set_eq(targets, &denom.members), "targets")?;
    Ok(())
}

/// Receipt slice hashed into the item digest: the bound fields plus fence.
///
/// `schema_version` stays out: it is a constant admission gate, not identity.
#[derive(Serialize)]
struct ItemDigestReceipt<'a> {
    validator_contract: &'a str,
    validator_policy: &'a str,
    job_id: &'a str,
    draft_digest: &'a str,
    bundle_digest: &'a str,
    manifest_digest: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
    input_digest: &'a str,
    output_digest: &'a str,
    terminal_disposition: &'a str,
    proof_ceiling: &'a str,
    state_fence: &'a StateFence,
    preservation_digest: &'a str,
    budget_digest: &'a str,
}

/// Full item-identity preimage hashed by [`ValidatedCurationItem::item_digest`].
#[derive(Serialize)]
struct ItemDigestPreimage<'a> {
    kind_spelling: &'a str,
    family_spelling: &'a str,
    payload: &'a CurationPayload,
    denominator: &'a TargetDenominator,
    source_digest: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
    state_fence: &'a StateFence,
    job_digest: &'a str,
    grounded_draft_digest: &'a str,
    receipt: ItemDigestReceipt<'a>,
}

impl ValidatedCurationItem {
    /// Validates intrinsic bounds only; call `accept` with context to accept.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.receipt.validate()?;
        self.payload.validate()?;
        self.denominator.validate()?;
        let kind = parse_kind(&self.kind_spelling)?;
        let drift = "curation item payload kind drift".to_owned();
        let mismatch = "curation item kind/family mismatch".to_owned();
        if kind != self.payload.kind() {
            return Err(ContractViolation::KindPayload(drift));
        }
        if kind_family(kind) != self.family_spelling.as_str() {
            return Err(ContractViolation::KindPayload(mismatch));
        }
        check_targets(&self.payload.facets().targets, &self.denominator)?;
        let r = &self.receipt;
        let (t, s, f) = (&self.task_id, &self.scope_id, &self.state_fence);
        let (et, es, ef) = (&r.task_id, &r.scope_id, &r.state_fence);
        if (t, s, f) != (et, es, ef) {
            return Err(ContractViolation::BindingMismatch {
                field: "task_scope_fence",
                reason: "curation item task/scope/fence binding mismatch".to_string(),
            });
        }
        check_digest(&self.source_digest, "source_digest")?;
        check_digest(&self.job_digest, "job_digest")?;
        self.requester.validate()?;
        check_text(&self.budget_note, "budget_note", 1024)?;
        Ok(())
    }
    /// Returns sha256 over canonical bytes of the full item envelope.
    ///
    /// The preimage covers kind/family spellings, payload, the full
    /// denominator shape, source digest, task/scope/fence, the wholesale job
    /// digest, the grounded draft digest, and the receipt-bound fields plus
    /// fence. `budget_note` stays out: it is a free-text annotation, so a
    /// reword must not break item identity. Screen digests stay out by the
    /// recursion lemma: the screen attests *to* this digest, so hashing one
    /// back would demand a fixed point. The payload is hashed in
    /// digest-normalized form: order-only target/evidence permutations share
    /// one digest, while scalar, sequence, or set drift stays visible.
    pub fn item_digest(&self, grounded: &GroundedDreamDraft) -> Result<String, ContractViolation> {
        // Preflight bounds every hashed input before clone/sort/serialize.
        // Intrinsic and binding-free checks only; no dedup or new tables.
        // Valid inputs are untouched, so output identity is preserved.
        self.receipt.validate()?;
        self.payload.validate()?;
        self.denominator.validate()?;
        parse_kind(&self.kind_spelling).map(|_| ())?;
        parse_family(&self.family_spelling).map(|_| ())?;
        check_text(&self.task_id, "task_id", 256)?;
        check_text(&self.scope_id, "scope_id", 256)?;
        check_fence(&self.state_fence)?;
        check_digest(&self.source_digest, "source_digest")?;
        check_digest(&self.job_digest, "job_digest")?;
        check_digest(&grounded.draft_digest, "draft_digest")?;
        check_text(&grounded.job_id, "job_id", 256)?;
        let normalized = self.payload.normalized_for_digest();
        let receipt = ItemDigestReceipt {
            validator_contract: &self.receipt.validator_contract,
            validator_policy: &self.receipt.validator_policy,
            job_id: &self.receipt.job_id,
            draft_digest: &self.receipt.draft_digest,
            bundle_digest: &self.receipt.bundle_digest,
            manifest_digest: &self.receipt.manifest_digest,
            task_id: &self.receipt.task_id,
            scope_id: &self.receipt.scope_id,
            input_digest: &self.receipt.input_digest,
            output_digest: &self.receipt.output_digest,
            terminal_disposition: &self.receipt.terminal_disposition,
            proof_ceiling: &self.receipt.proof_ceiling,
            state_fence: &self.receipt.state_fence,
            preservation_digest: &self.receipt.preservation_digest,
            budget_digest: &self.receipt.budget_digest,
        };
        let preimage = ItemDigestPreimage {
            kind_spelling: &self.kind_spelling,
            family_spelling: &self.family_spelling,
            payload: &normalized,
            denominator: &self.denominator,
            source_digest: &self.source_digest,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            job_digest: &self.job_digest,
            grounded_draft_digest: &grounded.draft_digest,
            receipt,
        };
        let bytes = encoding::canonical_bytes(&preimage)?;
        Ok(encoding::digest_hex(&bytes))
    }
    /// Accepts the item against job/bundle/receipt/screen bindings in order.
    ///
    /// Comparison-only issuance boundary: accept compares envelopes, never
    /// mints runtime effects; dispatch and composition stay outside this cell.
    pub fn accept(&self, ctx: &CurationAcceptanceCtx<'_>) -> Result<(), ContractViolation> {
        self.validate()?;
        self.receipt.validate_binding(ctx.receipt)?;
        ctx.job.validate()?;
        ctx.usage.fits(&ctx.job.budget)?;
        // Deadline/expiry compared: none. `deadline_ms` is attested inside
        // the wholesale job digest, never recomputed against a clock here.
        ctx.bundle.validate()?;
        ctx.grounded.validate()?;
        require_bind(self.requester == ctx.job.requester, "requester")?;
        let (j, b, s) = (ctx.job, ctx.bundle, ctx.screen);
        bind_eq("task_id", &self.task_id, &j.task_id)?;
        bind_eq("scope_id", &self.scope_id, &j.scope_id)?;
        require_bind(self.state_fence == j.state_fence, "state_fence")?;
        bind_eq("job_id", &self.receipt.job_id, &b.job_id)?;
        let frozen = (&j.frozen_manifest_digest, &b.manifest_digest);
        bind_eq("frozen_manifest_digest", frozen.0, frozen.1)?;
        let manifest = (&self.receipt.manifest_digest, &b.manifest_digest);
        bind_eq("manifest_digest", manifest.0, manifest.1)?;
        // Wholesale job bind: covers requester/op/idempotency/session/
        // budget-shape/deadline/frozen in one digest; the fine-grained
        // task/scope/fence/requester binds above stay for localization.
        let job_bytes = encoding::canonical_bytes(ctx.job)?;
        let computed = encoding::digest_hex(&job_bytes);
        bind_eq("job_digest", &self.job_digest, &computed)?;
        bind_eq("job_id", &ctx.grounded.job_id, &self.receipt.job_id)?;
        let grounded_digest = (&ctx.grounded.draft_digest, &self.receipt.draft_digest);
        bind_eq("draft_digest", grounded_digest.0, grounded_digest.1)?;
        let src_ok = b.materials.iter().any(|m| m.digest == self.source_digest);
        require_bind(src_ok, "source_digest")?;
        for h in &self.payload.facets().evidence_refs {
            let in_m = b.materials.iter().any(|m| &m.handle == h);
            let in_o = b.omissions.iter().any(|o| &o.handle == h);
            require_bind(in_m || in_o, "evidence_refs")?;
        }
        check_targets(&self.payload.facets().targets, &self.denominator)?;
        let tgts = &self.payload.facets().targets;
        let cov_ok = tgts
            .iter()
            .all(|t| b.materials.iter().any(|m| &m.handle == t));
        require_bind(cov_ok, "targets")?;
        let digest = self.item_digest(ctx.grounded)?;
        bind_eq("item_digest", &digest, &s.item_digest)?;
        crate::registry::check_screen_compat(ctx.request, ctx.screen)?;
        let scr_ok = s.task_id == self.task_id && s.scope_id == self.scope_id;
        require_bind(scr_ok, "screen_binding")?;
        require_bind(s.state_fence == self.state_fence, "screen_binding")?;
        ctx.request.validate()?;
        // Digest proves item-envelope integrity; these checks prove
        // cross-envelope agreement the preimage cannot see.
        crate::registry::check_curation_request_compat(
            parse_kind(&self.kind_spelling)?,
            &self.payload,
            &self.denominator,
            ctx.request,
        )?;
        let all_screened = tgts.iter().all(|t| s.screened_targets.contains(t));
        if !all_screened {
            return Err(ContractViolation::ScreenIneligible("unscreened".to_owned()));
        }
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

    fn model_with(f: impl FnOnce(&mut ModelDraft)) -> ModelDraft {
        let mut m = valid_model();
        f(&mut m);
        m
    }
    fn assert_oob(r: &Result<(), ContractViolation>) {
        assert!(matches!(r, Err(ContractViolation::OutOfBounds { .. })));
    }
    fn assert_malformed(r: &Result<(), ContractViolation>) {
        assert!(matches!(r, Err(ContractViolation::Malformed { .. })));
    }
    fn assert_binding(r: &Result<(), ContractViolation>) {
        assert!(matches!(r, Err(ContractViolation::BindingMismatch { .. })));
    }
    fn mat(h: &str) -> crate::bundle::BundleMaterial {
        crate::bundle::BundleMaterial {
            handle: h.to_string(),
            disposition: crate::bundle::SourceDisposition::Required,
            bytes: 12,
            digest: sha256_hex(h.as_bytes()),
        }
    }
    fn ctx_of<'a>(
        job: &'a crate::job::DreamJobInput,
        bundle: &'a crate::bundle::DreamInputBundle,
        receipt: &'a ValidationReceipt,
        screen: &'a crate::screen::ScreenBinding,
        grounded: &'a GroundedDreamDraft,
        request: &'a TypedCurationHandlerRequest,
        usage: &'a BudgetUsage,
    ) -> CurationAcceptanceCtx<'a> {
        CurationAcceptanceCtx {
            job,
            bundle,
            receipt,
            screen,
            grounded,
            request,
            usage,
        }
    }
    fn assert_field(r: &Result<(), ContractViolation>, want: &str) {
        assert!(
            matches!(r, Err(ContractViolation::BindingMismatch { field: g, .. }) if *g == want)
        );
    }
    fn assert_budget(r: &Result<(), ContractViolation>, dim: &str) {
        assert!(matches!(r, Err(ContractViolation::Budget { dimension: g, .. }) if *g == dim));
    }
    fn job_digest_of(job: &crate::job::DreamJobInput) -> String {
        let bytes = encoding::canonical_bytes(job).expect("job serializes");
        encoding::digest_hex(&bytes)
    }
    fn accept_request(
        item: &ValidatedCurationItem,
        screen: &ScreenBinding,
    ) -> TypedCurationHandlerRequest {
        TypedCurationHandlerRequest {
            request_id: "req-1".to_string(),
            receipt_id: "rcpt-1".to_string(),
            source_snapshot: screen.source_snapshot.clone(),
            source_revision: screen.source_revision.clone(),
            profile: screen.profile.clone(),
            kind: crate::curation::CurationKind::Merge,
            family: crate::registry::CurationFamily::StructureRepair,
            job_id: "job-1".to_string(),
            scope_id: item.scope_id.clone(),
            task_id: item.task_id.clone(),
            state_fence: item.state_fence.clone(),
            payload: item.payload.clone(),
            denominator: item.denominator.clone(),
            screen_binding: Some(screen.clone()),
        }
    }

    // WORK_UNIT_CASE: 578/17
    #[test]
    fn stages_cannot_cross_decode() {
        assert!(valid_raw().validate().is_ok());
        let raw_json = serde_json::to_string(&valid_raw()).expect("raw serializes");
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

        let mut tampered = valid_raw();
        tampered.output_digest = sha256_hex(b"something-else");
        assert!(tampered.validate().is_err());

        let with_extra = raw_json.trim_end_matches('}').to_string() + r#","injected":1}"#;
        assert!(serde_json::from_str::<RawProviderOutput>(&with_extra).is_err());

        let carrying = model_with(|m| m.declared_confirmed_handles = vec!["source-a".to_string()]);
        let r = carrying.validate();
        assert!(matches!(r, Err(ContractViolation::ForbiddenCarry(_))));
        let max_stmt = model_with(|m| m.statement = "s".repeat(16384));
        let max_vec = model_with(|m| m.source_handles = vec!["s".to_string(); 1024]);
        assert!(max_stmt.validate().is_ok() && max_vec.validate().is_ok());
        assert_oob(&model_with(|m| m.statement = "s".repeat(16385)).validate());
        assert_malformed(&model_with(|m| m.source_handles = vec!["a\0b".to_string()]).validate());
        assert_oob(&model_with(|m| m.source_handles = vec!["s".to_string(); 1025]).validate());
        assert_oob(&model_with(|m| m.counterevidence = vec!["c".repeat(1025); 1024]).validate());
        assert_eq!(usize::MAX.saturating_add(1), usize::MAX);
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
        let mut draft = valid_grounded(&sha256_hex(b"model"));
        draft.coverage_note = "covers claims 0-4".to_string();
        draft.residues = states
            .iter()
            .map(|state| ClaimResidue {
                claim: format!("{state:?}"),
                state: *state,
                detail: format!("{state:?} detail"),
            })
            .collect();
        assert!(draft.validate().is_ok());
        let wire = serde_json::to_string(&draft).expect("grounded serializes");
        let back: GroundedDreamDraft = serde_json::from_str(&wire).expect("grounded deserializes");
        assert_eq!(back, draft);
        for s in states {
            let hit = back
                .residues
                .iter()
                .any(|r| r.state == s && !r.detail.trim().is_empty());
            assert!(hit, "state {s:?} must roundtrip with detail preserved");
        }
        let mut wires: Vec<String> = states
            .iter()
            .map(|s| serde_json::to_string(s).expect("state serializes"))
            .collect();
        wires.sort();
        wires.dedup();
        assert_eq!(wires.len(), states.len());
        let mut flood = valid_grounded(&sha256_hex(b"model"));
        flood.residues = vec![
            ClaimResidue {
                claim: "c".repeat(1024),
                state: SupportState::Supported,
                detail: "d".repeat(1024),
            };
            600
        ];
        assert!(matches!(
            flood.validate(),
            Err(ContractViolation::OutOfBounds {
                field: "residues",
                ..
            })
        ));
    }

    // WORK_UNIT_CASE: 578/19
    #[test]
    fn valid_a05_receipt_binding_passes() {
        let receipt = valid_receipt(&model_wire_digest(&valid_model()), valid_fence());
        assert!(receipt.validate().is_ok() && receipt.validate_binding(&receipt.clone()).is_ok());
        let validated = ValidatedDreamDraft {
            receipt: receipt.clone(),
            draft_digest: model_wire_digest(&valid_model()),
            scope_id: "scope-1".to_string(),
            task_id: "task-1".to_string(),
            state_fence: valid_fence(),
        };
        assert!(validated.validate().is_ok());
        let mut job = crate::job::sample_job();
        job.frozen_manifest_digest = sha256_hex(b"manifest");
        let grounded = valid_grounded(&model_wire_digest(&valid_model()));
        let mut item = ValidatedCurationItem {
            receipt: receipt.clone(),
            kind_spelling: "merge".to_string(),
            family_spelling: "structure_repair".to_string(),
            payload: crate::curation::sample_payload(crate::curation::CurationKind::Merge),
            denominator: TargetDenominator {
                mode: crate::registry::AtomicityMode::AllOrNothing,
                members: vec!["a".to_string(), "b".to_string(), "ab".to_string()],
                expected_total: 3,
            },
            source_digest: sha256_hex(b"curation-source"),
            task_id: "task-1".to_string(),
            scope_id: "scope-1".to_string(),
            state_fence: valid_fence(),
            job_digest: job_digest_of(&job),
            requester: crate::job::Requester {
                origin: crate::job::RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
            budget_note: "within dimension".to_string(),
        };
        assert!(item.validate().is_ok());
        let mut drifted = item.clone();
        drifted.kind_spelling = "split".to_string();
        assert!(matches!(
            drifted.validate(),
            Err(ContractViolation::KindPayload(_))
        ));
        let mut swapped = item.clone();
        swapped.denominator.members = vec!["a".to_string(), "b".to_string(), "x".to_string()];
        assert_binding(&swapped.validate());
        item.budget_note = "other".into();
        assert!(item.validate().is_ok());
        let mut per = item.clone();
        per.denominator.mode = crate::registry::AtomicityMode::PerMember;
        per.denominator.members.push("extra".to_string());
        per.denominator.expected_total = 4;
        assert!(per.validate().is_ok());
        per.denominator.mode = crate::registry::AtomicityMode::AllOrNothing;
        assert_binding(&per.validate());
        let mut t9 = item.clone();
        t9.task_id = "task-9".to_string();
        assert!(t9.validate().is_err());
        let base = item.item_digest(&grounded).expect("digest");
        assert!(base.len() == 64 && base == item.item_digest(&grounded).expect("digest-2"));
        let mut probe = item.clone();
        probe.source_digest = sha256_hex(b"other-source");
        assert_ne!(probe.item_digest(&grounded).expect("digest"), base);
        probe = item.clone();
        probe.denominator.members[2] = "x".to_string();
        assert_ne!(probe.item_digest(&grounded).expect("digest"), base);
        probe = item.clone();
        probe.task_id = "task-9".to_string();
        assert_ne!(probe.item_digest(&grounded).expect("digest"), base);
        probe = item.clone();
        probe.receipt.proof_ceiling = "other-ceiling".to_string();
        assert_ne!(probe.item_digest(&grounded).expect("digest"), base);
        let mut other_grounded = grounded.clone();
        other_grounded.draft_digest = sha256_hex(b"other-draft");
        assert_ne!(item.item_digest(&other_grounded).expect("digest"), base);
        probe = item.clone();
        probe.budget_note = "reworded note".to_string();
        assert!(probe.validate().is_ok());
        assert_eq!(probe.item_digest(&grounded).expect("digest"), base);
        digest_permutation_probes(&item, &base, &grounded);
        item.source_digest = sha256_hex(b"source-a");
        if let crate::curation::CurationPayload::Merge(p) = &mut item.payload {
            p.target_evidence.evidence_refs = vec!["source-b".to_string()];
        }
        let mut bundle = crate::bundle::valid_bundle();
        bundle
            .materials
            .extend([mat("a"), mat("b"), mat("ab"), mat("e-1"), mat("e-2")]);
        let digest = item.item_digest(&grounded).expect("congruent digest");
        let mut screen = crate::registry::sample_binding();
        screen.item_digest = digest;
        let request = accept_request(&item, &screen);
        let usage = BudgetUsage::default();
        accept_probes(&item, &job, &bundle, &screen, &grounded, &request, &usage);
        accept_probes_request(&item, &job, &bundle, &screen, &grounded, &request, &usage);
        accept_probes_permuted_evidence(&item, &job, &bundle, &screen, &grounded, &usage);
    }
    fn digest_permutation_probes(
        item: &ValidatedCurationItem,
        base: &str,
        grounded: &GroundedDreamDraft,
    ) {
        let mut probe = item.clone();
        if let crate::curation::CurationPayload::Merge(q) = &mut probe.payload {
            q.target_evidence.targets = vec!["ab".to_owned(), "a".to_owned(), "b".to_owned()];
        }
        assert!(probe.validate().is_ok());
        assert_eq!(probe.item_digest(grounded).expect("digest"), base);
        probe = item.clone();
        if let crate::curation::CurationPayload::Merge(q) = &mut probe.payload {
            q.target_evidence.evidence_refs = vec!["source-b".to_owned(), "e-1".to_owned()];
        }
        assert!(probe.validate().is_ok());
        let permuted = probe.item_digest(grounded).expect("digest");
        assert_ne!(permuted, base);
        probe = item.clone();
        if let crate::curation::CurationPayload::Merge(q) = &mut probe.payload {
            q.target_evidence.evidence_refs = vec!["e-1".to_owned(), "source-b".to_owned()];
        }
        assert!(probe.validate().is_ok());
        assert_eq!(probe.item_digest(grounded).expect("digest"), permuted);
    }
    #[test]
    fn item_digest_preflight_rejects_unbounded_inputs() {
        let receipt = valid_receipt(&model_wire_digest(&valid_model()), valid_fence());
        let grounded = valid_grounded(&model_wire_digest(&valid_model()));
        let mut job = crate::job::sample_job();
        job.frozen_manifest_digest = sha256_hex(b"manifest");
        let base = ValidatedCurationItem {
            receipt: receipt.clone(),
            kind_spelling: "merge".to_string(),
            family_spelling: "structure_repair".to_string(),
            payload: crate::curation::sample_payload(crate::curation::CurationKind::Merge),
            denominator: TargetDenominator {
                mode: crate::registry::AtomicityMode::AllOrNothing,
                members: vec!["a".to_string(), "b".to_string(), "ab".to_string()],
                expected_total: 3,
            },
            source_digest: sha256_hex(b"curation-source"),
            task_id: "task-1".to_string(),
            scope_id: "scope-1".to_string(),
            state_fence: valid_fence(),
            job_digest: job_digest_of(&job),
            requester: crate::job::Requester {
                origin: crate::job::RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
            budget_note: "within dimension".to_string(),
        };
        let mut p1 = base.clone();
        if let crate::curation::CurationPayload::Merge(inner) = &mut p1.payload {
            let mut targets = vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()];
            targets.extend((0..1022).map(|i| format!("t-{i:04}")));
            inner.target_evidence.targets = targets;
        }
        let r1 = p1.item_digest(&grounded);
        assert!(matches!(
            r1,
            Err(ContractViolation::OutOfBounds {
                field: "targets",
                ..
            })
        ));
        let mut p2 = base.clone();
        if let crate::curation::CurationPayload::Merge(inner) = &mut p2.payload {
            let flood: Vec<String> = (0..1025).map(|i| format!("e-{i:04}")).collect();
            inner.target_evidence.evidence_refs = flood;
        }
        let r2 = p2.item_digest(&grounded);
        assert!(matches!(
            r2,
            Err(ContractViolation::OutOfBounds {
                field: "evidence_refs",
                ..
            })
        ));
        let mut p3 = base.clone();
        if let crate::curation::CurationPayload::Merge(inner) = &mut p3.payload {
            let left = "l".repeat(257);
            inner.left = left.clone();
            inner.target_evidence.targets = vec![left, "b".to_owned(), "ab".to_owned()];
        }
        let r3 = p3.item_digest(&grounded);
        assert!(matches!(
            r3,
            Err(ContractViolation::OutOfBounds { field: "left", .. })
        ));
        let mut g4 = grounded.clone();
        g4.draft_digest = "ZZ".to_owned();
        let r4 = base.item_digest(&g4);
        assert!(matches!(
            r4,
            Err(ContractViolation::BindingMismatch {
                field: "draft_digest",
                ..
            })
        ));
        let mut g5 = grounded.clone();
        g5.job_id = "j".repeat(257);
        let r5 = base.item_digest(&g5);
        assert!(matches!(
            r5,
            Err(ContractViolation::OutOfBounds {
                field: "job_id",
                ..
            })
        ));
    }
    fn accept_probes_permuted_evidence(
        item: &ValidatedCurationItem,
        job: &DreamJobInput,
        bundle: &DreamInputBundle,
        screen: &ScreenBinding,
        grounded: &GroundedDreamDraft,
        usage: &BudgetUsage,
    ) {
        let mut permuted = item.clone();
        if let crate::curation::CurationPayload::Merge(q) = &mut permuted.payload {
            q.target_evidence.evidence_refs = vec!["e-2".to_owned(), "e-1".to_owned()];
        }
        assert!(permuted.validate().is_ok());
        let digest = permuted.item_digest(grounded).expect("digest");
        let mut same_order = permuted.clone();
        if let crate::curation::CurationPayload::Merge(q) = &mut same_order.payload {
            q.target_evidence.evidence_refs = vec!["e-1".to_owned(), "e-2".to_owned()];
        }
        assert_eq!(same_order.item_digest(grounded).expect("digest"), digest);
        let mut permuted_screen = screen.clone();
        permuted_screen.item_digest = digest;
        let mut request = accept_request(&permuted, &permuted_screen);
        if let crate::curation::CurationPayload::Merge(inner) = &mut request.payload {
            inner.target_evidence.evidence_refs = vec!["e-1".to_owned(), "e-2".to_owned()];
        }
        request.validate().expect("permuted request stays valid");
        let ctx = ctx_of(
            job,
            bundle,
            &permuted.receipt,
            &permuted_screen,
            grounded,
            &request,
            usage,
        );
        assert!(permuted.accept(&ctx).is_ok());
    }
    fn accept_probes(
        item: &ValidatedCurationItem,
        job: &DreamJobInput,
        bundle: &DreamInputBundle,
        screen: &ScreenBinding,
        grounded: &GroundedDreamDraft,
        request: &TypedCurationHandlerRequest,
        usage: &BudgetUsage,
    ) {
        let (jb, rc, sc, gr, rq, us) = (job, &item.receipt, screen, grounded, request, usage);
        let run =
            |it: &ValidatedCurationItem,
             jb: &DreamJobInput,
             rc: &ValidationReceipt,
             sc: &ScreenBinding,
             gr: &GroundedDreamDraft,
             rq: &TypedCurationHandlerRequest,
             us: &BudgetUsage| { it.accept(&ctx_of(jb, bundle, rc, sc, gr, rq, us)) };
        assert!(run(item, jb, rc, sc, gr, rq, us).is_ok());
        let mut p = item.clone();
        p.receipt.bundle_digest = sha256_hex(b"1");
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "bundle_digest");
        p = item.clone();
        p.receipt.validator_contract = "other".into();
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "validator_contract");
        p = item.clone();
        p.receipt.terminal_disposition = "rejected".into();
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "terminal_disposition");
        p = item.clone();
        p.receipt.state_fence.resource_generation = ResourceGeneration::new(2).expect("g");
        p.state_fence = p.receipt.state_fence.clone();
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "state_fence");
        p = item.clone();
        p.receipt.draft_digest = sha256_hex(b"other-draft");
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "draft_digest");
        p = item.clone();
        p.receipt.budget_digest = sha256_hex(b"other-budget");
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "budget_digest");
        p = item.clone();
        p.job_digest = sha256_hex(b"other-job");
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "job_digest");
        p = item.clone();
        p.requester.principal = "mallory".to_owned();
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "requester");
        p = item.clone();
        p.requester.origin = crate::job::RequesterOrigin::SchedulePolicy;
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "requester");
        p = item.clone();
        p.requester.session = Some("sess-9".to_owned());
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "requester");
        let mut mal = job.clone();
        mal.task_id = "task-9".to_owned();
        assert_field(&run(item, &mal, rc, sc, gr, rq, us), "task_id");
        p = item.clone();
        p.source_digest = sha256_hex(b"other-source");
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "source_digest");
        p = item.clone();
        if let crate::curation::CurationPayload::Merge(q) = &mut p.payload {
            q.target_evidence.evidence_refs = vec!["e-9".to_string()];
        }
        assert_field(&run(&p, jb, rc, sc, gr, rq, us), "evidence_refs");
        let mut wsc = screen.clone();
        wsc.item_digest = "c".repeat(64);
        assert_field(&run(item, jb, rc, &wsc, gr, rq, us), "item_digest");
        let mut frz = job.clone();
        frz.frozen_manifest_digest = sha256_hex(b"other-manifest");
        assert_field(
            &run(item, &frz, rc, sc, gr, rq, us),
            "frozen_manifest_digest",
        );
        let mut ovr = job.clone();
        ovr.budget.input_bytes = Some(crate::budget::INPUT_BYTES_CEILING + 1);
        assert_budget(&run(item, &ovr, rc, sc, gr, rq, us), "input_bytes");
        let mut ceil = rc.clone();
        ceil.proof_ceiling = "other-ceiling".to_owned();
        assert_field(&run(item, jb, &ceil, sc, gr, rq, us), "proof_ceiling");
        let mut prs = rc.clone();
        prs.preservation_digest = sha256_hex(b"other-preservation");
        assert_field(&run(item, jb, &prs, sc, gr, rq, us), "preservation_digest");
    }

    fn accept_probes_request(
        item: &ValidatedCurationItem,
        job: &DreamJobInput,
        bundle: &DreamInputBundle,
        screen: &ScreenBinding,
        grounded: &GroundedDreamDraft,
        request: &TypedCurationHandlerRequest,
        usage: &BudgetUsage,
    ) {
        let (jb, rc, sc, gr, rq, us) = (job, &item.receipt, screen, grounded, request, usage);
        let run =
            |it: &ValidatedCurationItem,
             jb: &DreamJobInput,
             rc: &ValidationReceipt,
             sc: &ScreenBinding,
             gr: &GroundedDreamDraft,
             rq: &TypedCurationHandlerRequest,
             us: &BudgetUsage| { it.accept(&ctx_of(jb, bundle, rc, sc, gr, rq, us)) };
        let mut sub = item.clone();
        sub.denominator.mode = crate::registry::AtomicityMode::PerMember;
        sub.denominator.members.push("extra".to_string());
        sub.denominator.expected_total = 4;
        let mut sub_screen = screen.clone();
        sub_screen.item_digest = sub.item_digest(grounded).expect("digest");
        let mut rq_congruent = request.clone();
        rq_congruent.denominator = sub.denominator.clone();
        assert!(run(&sub, jb, rc, &sub_screen, gr, &rq_congruent, us).is_ok());
        sub.denominator.mode = crate::registry::AtomicityMode::AllOrNothing;
        sub_screen.item_digest = sub.item_digest(grounded).expect("digest");
        assert_field(&run(&sub, jb, rc, &sub_screen, gr, rq, us), "targets");
        let mut rq_kind = request.clone();
        rq_kind.kind = crate::curation::CurationKind::Split;
        rq_kind.payload = crate::curation::sample_payload(crate::curation::CurationKind::Split);
        let kind_mismatch = run(item, jb, rc, sc, gr, &rq_kind, us);
        assert!(matches!(
            kind_mismatch,
            Err(ContractViolation::KindPayload(_))
        ));
        let mut rq_mode = request.clone();
        rq_mode.denominator.mode = crate::registry::AtomicityMode::PerMember;
        assert_field(&run(item, jb, rc, sc, gr, &rq_mode, us), "denominator");
        let mut rq_members = request.clone();
        rq_members.denominator.mode = crate::registry::AtomicityMode::PerMember;
        rq_members.denominator.members.push("extra".to_string());
        rq_members.denominator.expected_total = 4;
        assert_field(&run(item, jb, rc, sc, gr, &rq_members, us), "denominator");
        let mut wide = item.clone();
        wide.denominator.mode = crate::registry::AtomicityMode::PerMember;
        let mut wide_screen = screen.clone();
        wide_screen.item_digest = wide.item_digest(grounded).expect("digest");
        let mut rq_narrow = request.clone();
        if let crate::curation::CurationPayload::Merge(inner) = &mut rq_narrow.payload {
            inner.left = "a".to_owned();
            inner.right = "b".to_owned();
            inner.merged = "b".to_owned();
            inner.target_evidence.targets = vec!["a".to_owned(), "b".to_owned()];
        }
        rq_narrow.denominator.mode = crate::registry::AtomicityMode::PerMember;
        rq_narrow.denominator.members = vec!["a".to_owned(), "b".to_owned()];
        rq_narrow.denominator.expected_total = 2;
        assert_field(
            &run(&wide, jb, rc, &wide_screen, gr, &rq_narrow, us),
            "targets",
        );
        let mut rq_aon = rq_narrow.clone();
        rq_aon.denominator.mode = crate::registry::AtomicityMode::AllOrNothing;
        assert_field(
            &run(&wide, jb, rc, &wide_screen, gr, &rq_aon, us),
            "targets",
        );
        let mut gd = grounded.clone();
        gd.draft_digest = sha256_hex(b"other-draft");
        assert_field(&run(item, jb, rc, sc, &gd, rq, us), "draft_digest");
        let mut gj = grounded.clone();
        gj.job_id = "job-9".to_owned();
        assert_field(&run(item, jb, rc, sc, &gj, rq, us), "job_id");
        let mut rq2 = request.clone();
        rq2.profile = "other".to_owned();
        assert_field(&run(item, jb, rc, sc, gr, &rq2, us), "profile");
        let mut heavy = *usage;
        heavy.input_bytes = 1025;
        assert_budget(&run(item, jb, rc, sc, gr, rq, &heavy), "input_bytes");
        let mut nolim = job.clone();
        nolim.budget.output_bytes = None;
        assert_budget(&run(item, &nolim, rc, sc, gr, rq, us), "output_bytes");
        let mut rq_swap = request.clone();
        if let crate::curation::CurationPayload::Merge(inner) = &mut rq_swap.payload {
            inner.left = "b".to_owned();
            inner.right = "a".to_owned();
        }
        rq_swap.validate().expect("swapped request stays valid");
        assert_field(&run(item, jb, rc, sc, gr, &rq_swap, us), "payload");
        let mut rq_evidence = request.clone();
        if let crate::curation::CurationPayload::Merge(inner) = &mut rq_evidence.payload {
            inner.target_evidence.evidence_refs = vec!["e-9".to_owned()];
        }
        rq_evidence.validate().expect("evidence drift stays valid");
        assert_field(&run(item, jb, rc, sc, gr, &rq_evidence, us), "payload");
        let mut rq_permuted = request.clone();
        if let crate::curation::CurationPayload::Merge(inner) = &mut rq_permuted.payload {
            inner.target_evidence.targets = vec!["ab".to_owned(), "a".to_owned(), "b".to_owned()];
        }
        rq_permuted
            .validate()
            .expect("permuted request stays valid");
        assert!(run(item, jb, rc, sc, gr, &rq_permuted, us).is_ok());
    }

    // WORK_UNIT_CASE: 578/20
    #[test]
    fn any_binding_mutation_invalidates_receipt() {
        let base = valid_receipt(&model_wire_digest(&valid_model()), valid_fence());
        let recorded = base.clone();
        assert!(base.validate_binding(&recorded).is_ok());
        let wire = serde_json::to_string(&base).expect("receipt serializes");
        for field in [
            "job-1",
            "a05-validator",
            "candidate-only",
            "policy-7",
            "task-1",
            "scope-1",
        ] {
            let w = wire.replacen(field, "other", 1);
            let m: ValidationReceipt = serde_json::from_str(&w).expect("mutated wire decodes");
            assert!(m.validate_binding(&recorded).is_err());
        }
        for (field, other) in [
            ("draft_digest", sha256_hex(b"other-draft")),
            ("bundle_digest", sha256_hex(b"other-bundle")),
            ("manifest_digest", sha256_hex(b"other-manifest")),
            ("preservation_digest", sha256_hex(b"other-preservation")),
            ("budget_digest", sha256_hex(b"other-budget")),
            ("input_digest", sha256_hex(b"other-input")),
            ("output_digest", sha256_hex(b"other-output")),
        ] {
            let mut changed = base.clone();
            match field {
                "draft_digest" => changed.draft_digest = other,
                "bundle_digest" => changed.bundle_digest = other,
                "manifest_digest" => changed.manifest_digest = other,
                "preservation_digest" => changed.preservation_digest = other,
                "budget_digest" => changed.budget_digest = other,
                "input_digest" => changed.input_digest = other,
                _ => changed.output_digest = other,
            }
            assert_binding(&changed.validate_binding(&recorded));
        }
        let mut changed_disp = base.clone();
        changed_disp.terminal_disposition = "rejected".to_string();
        assert_binding(&changed_disp.validate_binding(&recorded));
        let mut over_id = base.clone();
        over_id.job_id = "x".repeat(257);
        assert_oob(&over_id.validate());
        let mut ctrl_id = base.clone();
        ctrl_id.task_id = "a\tb".to_string();
        assert_malformed(&ctrl_id.validate());
        let next_gen = ResourceGeneration::new(2).expect("non-genesis generation");
        let mut changed_fence = base.clone();
        changed_fence.state_fence = StateFence::new(AuthorityEpoch::genesis(), next_gen);
        assert_binding(&changed_fence.validate_binding(&recorded));
        let mut bad_validator = base.clone();
        bad_validator.validator_contract = "   ".to_string();
        let r = bad_validator.validate();
        assert!(matches!(r, Err(ContractViolation::MissingField(_))));
        let mut bad_digest = base.clone();
        bad_digest.output_digest = "not-a-digest".to_string();
        assert_binding(&bad_digest.validate());
    }
}
