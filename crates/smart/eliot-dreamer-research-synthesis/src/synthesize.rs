//! The single deterministic pure operation of this owner.
//!
//! [`synthesize`] maps one [`SynthesisRequest`] — validated job binding,
//! governed [`ResearchPack`], exact [`GroundedDraft`], inherited
//! [`InputReceipt`], immutable [`SynthesisPolicy`], independent
//! [`SynthesisBounds`], and a caller-observed [`CancellationView`] — to one
//! candidate [`SynthesisOutcome`]. The pipeline is staged so each normative
//! rule fails closed at its own layer:
//!
//! 1. envelope: closed schema, job spelling, identity shapes, ceilings;
//! 2. bindings: task, scope, fence, question, and digest agreement;
//! 3. terminal: cancellation, deadline, and stale policy stop projection;
//! 4. projection: firewall, duplicates, precision, coverage, rivals, probes,
//!    Concilium, bounds, and preservation;
//! 5. output budget: optional sections elide before any silent truncation.
//!
//! The operation performs no I/O, reads no clock, draws no randomness, holds
//! no mutable state across calls, and calls no A-05 post-handler: the seven
//! I9.7 subtype checks run natively inside stage 4.

use std::collections::{BTreeMap, BTreeSet};

use crate::bounds::{
    MAX_CLAIMS, MAX_PROBE_OUTCOMES, MAX_PROBES, MAX_REFERENCES_PER_CLAIM, MAX_RIVALS, MAX_SOURCES,
    MAX_UNKNOWNS, SYNTHESIS_JOB_CLASS, SYNTHESIS_SCHEMA_REVISION,
};
use crate::digest::{CanonicalWriter, len_u64, sha256_hex};
use crate::model::{
    CancellationView, ClaimDisposition, ClaimVerdict, ConciliumRecommendation, Counterclaim,
    CoverageReport, DenominatorKind, DependenceGroup, DraftConcilium, EvidenceGrade, Freshness,
    GroundedDraft, InputReceipt, JobBinding, Omission, OmissionKind, Precision, PrecisionKind,
    PreservationDimension, PreservationVerdict, ProbeBasis, ProbeResidue, ProbeResidueReason,
    RecommendedProbe, ResearchBrief, ResearchPack, RivalPosition, RivalStance, SourceAuthority,
    SourceCard, StructuredClaim, StructuredProbe, SynthesisBounds, SynthesisDisposition,
    SynthesisError, SynthesisOutcome, SynthesisPolicy, SynthesisRequest, claim_canonical_bytes,
    claim_disposition_as_str, counterclaim_canonical_bytes, draft_canonical_bytes, is_digest,
    is_handle, is_text, omission_kind_rank, pack_canonical_bytes, preservation_dimension_as_str,
    preservation_dimensions, redact_value, source_authority_rank, synthesis_disposition_as_str,
};

// ---------- public digests ----------

/// Digest of the governed pack content (excludes the stated `pack_digest`).
#[must_use]
pub fn pack_content_digest(pack: &ResearchPack) -> String {
    sha256_hex(&pack_canonical_bytes(pack, true))
}

/// Digest of the grounded draft content (excludes the stated `draft_digest`).
#[must_use]
pub fn draft_content_digest(draft: &GroundedDraft) -> String {
    sha256_hex(&draft_canonical_bytes(draft, true))
}

/// Canonical request byte length for input-budget planning.
#[must_use]
pub fn request_canonical_len(request: &SynthesisRequest) -> u64 {
    len_u64(&request_canonical_bytes(request))
}

/// Canonical brief byte length for output-budget planning.
#[must_use]
pub fn brief_canonical_len(brief: &ResearchBrief) -> u64 {
    len_u64(&brief_canonical_bytes(brief, false))
}

/// Digest of the canonical request bytes (order-sensitive input identity).
#[must_use]
pub fn request_digest(request: &SynthesisRequest) -> String {
    sha256_hex(&request_canonical_bytes(request))
}

/// Digest of the semantic request bytes (order-insensitive content identity).
#[must_use]
pub fn request_semantic_digest(request: &SynthesisRequest) -> String {
    let binding = &request.binding;
    let mut writer = CanonicalWriter::new();
    writer.integer("request.schema", u64::from(request.schema_revision));
    write_binding(binding, &mut writer);
    writer.section("request.pack", &pack_canonical_bytes(&request.pack, true));
    writer.section(
        "request.draft",
        &draft_canonical_bytes(&request.draft, true),
    );
    write_receipt(&request.receipt, &mut writer);
    write_policy(&request.policy, &mut writer);
    write_bounds(&request.bounds, &mut writer);
    write_cancellation(&request.cancellation, &mut writer);
    sha256_hex(&writer.finish())
}

/// Digest of the canonical brief bytes (order-insensitive semantic identity).
#[must_use]
pub fn brief_semantic_digest(brief: &ResearchBrief) -> String {
    sha256_hex(&brief_canonical_bytes(brief, true))
}

/// Digest of the exact brief bytes (order-sensitive raw identity).
#[must_use]
pub fn brief_raw_digest(brief: &ResearchBrief) -> String {
    sha256_hex(&brief_canonical_bytes(brief, false))
}

/// Outcome digest when no brief exists: binds disposition to the input.
#[must_use]
pub fn terminal_digest(disposition: SynthesisDisposition, input_digest: &str) -> String {
    let mut writer = CanonicalWriter::new();
    writer.text(
        "terminal.disposition",
        synthesis_disposition_as_str(disposition),
    );
    writer.text("terminal.input", input_digest);
    sha256_hex(&writer.finish())
}

fn request_canonical_bytes(request: &SynthesisRequest) -> Vec<u8> {
    let binding = &request.binding;
    let mut writer = CanonicalWriter::new();
    writer.integer("request.schema", u64::from(request.schema_revision));
    write_binding(binding, &mut writer);
    writer.section("request.pack", &pack_canonical_bytes(&request.pack, false));
    writer.section(
        "request.draft",
        &draft_canonical_bytes(&request.draft, false),
    );
    write_receipt(&request.receipt, &mut writer);
    write_policy(&request.policy, &mut writer);
    write_bounds(&request.bounds, &mut writer);
    write_cancellation(&request.cancellation, &mut writer);
    writer.finish()
}

fn write_binding(binding: &JobBinding, writer: &mut CanonicalWriter) {
    writer.text("binding.operation", &binding.operation_id);
    writer.text("binding.job", &binding.job_class);
    writer.text("binding.idempotency", &binding.idempotency_key);
    writer.text("binding.principal", &binding.requester_principal);
    writer.text(
        "binding.origin",
        match binding.requester_origin {
            crate::model::RequesterOrigin::Human => "human",
            crate::model::RequesterOrigin::AdmittedAgent => "admitted-agent",
            crate::model::RequesterOrigin::SchedulePolicy => "schedule-policy",
        },
    );
    writer.text("binding.session", &binding.requester_session);
    writer.text("binding.task", &binding.task_id);
    writer.text("binding.attempt", &binding.attempt_id);
    writer.text("binding.scope", &binding.scope_id);
    writer.text("binding.fence_epoch", &binding.fence_epoch);
    writer.integer("binding.fence_generation", binding.fence_generation);
}

fn write_receipt(receipt: &InputReceipt, writer: &mut CanonicalWriter) {
    writer.text("receipt.digest", &receipt.receipt_digest);
    writer.text("receipt.task", &receipt.task_id);
    writer.text("receipt.scope", &receipt.scope_id);
    writer.text("receipt.fence_epoch", &receipt.fence_epoch);
    writer.integer("receipt.fence_generation", receipt.fence_generation);
    writer.text("receipt.bundle", &receipt.bundle_digest);
    writer.text("receipt.manifest", &receipt.manifest_digest);
    writer.text("receipt.grounding", &receipt.grounding_digest);
    writer.text("receipt.validator", &receipt.validator_revision);
}

fn write_policy(policy: &SynthesisPolicy, writer: &mut CanonicalWriter) {
    writer.text("policy.digest", &policy.policy_digest);
    writer.text("policy.revision", &policy.revision);
    writer.integer("policy.valid_through", policy.valid_through_generation);
    writer.flag("policy.allow_partial", policy.allow_partial);
    writer.flag(
        "policy.authorize_supplied",
        policy.authorize_supplied_discriminative,
    );
    let mut allowlist = policy.probe_allowlist.clone();
    allowlist.sort();
    for probe in &allowlist {
        writer.text("policy.allowlisted_probe", probe);
    }
    let mut transforms = policy.canonical_transforms.clone();
    transforms.sort();
    for transform in &transforms {
        writer.text("policy.transform", transform);
    }
    writer.flag("policy.concilium", policy.concilium_allowed);
    writer.text(
        "policy.freshness_floor",
        match policy.freshness_floor {
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
            Freshness::Unknown => "unknown",
        },
    );
}

fn write_bounds(bounds: &SynthesisBounds, writer: &mut CanonicalWriter) {
    writer.integer("bounds.input_bytes", bounds.max_input_bytes);
    writer.integer("bounds.output_bytes", bounds.max_output_bytes);
    writer.integer("bounds.claims", bounds.max_claims);
    writer.integer("bounds.rivals", bounds.max_rivals);
    writer.integer("bounds.references", bounds.max_references);
    writer.integer("bounds.probes", bounds.max_probes);
    writer.integer("bounds.work", bounds.max_work);
}

fn write_cancellation(view: &CancellationView, writer: &mut CanonicalWriter) {
    writer.flag("cancel.cancelled", view.cancelled);
    writer.integer("cancel.now", view.now_ms.unwrap_or(u64::MAX));
    writer.integer("cancel.deadline", view.deadline_ms.unwrap_or(u64::MAX));
}

// ---------- stage 1: envelope ----------

fn malformed(field: &str, detail: &str) -> SynthesisError {
    SynthesisError::Malformed {
        field: field.to_owned(),
        detail: redact_value(detail),
    }
}

fn check_handle(value: &str, field: &str) -> Result<(), SynthesisError> {
    if !is_handle(value) {
        return Err(malformed(field, "must be a non-empty handle"));
    }
    Ok(())
}

fn check_text(value: &str, field: &str) -> Result<(), SynthesisError> {
    if !is_text(value) {
        return Err(malformed(field, "must be non-empty prose"));
    }
    Ok(())
}

fn check_digest(value: &str, field: &str) -> Result<(), SynthesisError> {
    if !is_digest(value) {
        return Err(malformed(field, "must be 64 hex digest characters"));
    }
    Ok(())
}

fn check_card(card: &SourceCard, index: usize) -> Result<(), SynthesisError> {
    let field = format!("pack.sources[{index}]");
    check_handle(&card.handle, &format!("{field}.handle"))?;
    check_text(&card.competence, &format!("{field}.competence"))?;
    check_text(&card.privacy_class, &format!("{field}.privacy_class"))?;
    check_text(&card.allowed_use, &format!("{field}.allowed_use"))?;
    check_handle(&card.lineage_group, &format!("{field}.lineage_group"))?;
    Ok(())
}

fn check_probe_shape(probe: &StructuredProbe, index: usize) -> Result<(), SynthesisError> {
    let field = format!("draft.probes[{index}]");
    check_handle(&probe.probe_id, &format!("{field}.probe_id"))?;
    if len_u64(&probe.outcomes) > MAX_PROBE_OUTCOMES {
        return Err(malformed(
            &format!("{field}.outcomes"),
            "outcome alternatives exceed the probe ceiling",
        ));
    }
    for target in &probe.discriminates {
        check_handle(target, &format!("{field}.discriminates"))?;
    }
    for outcome in &probe.outcomes {
        check_text(outcome, &format!("{field}.outcomes"))?;
    }
    check_handle(&probe.verifier, &format!("{field}.verifier"))?;
    check_handle(&probe.owner, &format!("{field}.owner"))?;
    Ok(())
}

fn check_claim_shape(claim: &StructuredClaim, index: usize) -> Result<(), SynthesisError> {
    let field = format!("draft.claims[{index}]");
    check_handle(&claim.claim_id, &format!("{field}.claim_id"))?;
    check_text(&claim.statement, &format!("{field}.statement"))?;
    for counter in &claim.counterclaims {
        check_handle(
            &counter.counterclaim_id,
            &format!("{field}.counterclaim.counterclaim_id"),
        )?;
        check_handle(
            &counter.source_handle,
            &format!("{field}.counterclaim.source_handle"),
        )?;
        check_text(
            &counter.statement,
            &format!("{field}.counterclaim.statement"),
        )?;
    }
    Ok(())
}

fn check_envelope(request: &SynthesisRequest) -> Result<(), SynthesisError> {
    check_envelope_identity(request)?;
    check_envelope_content(request)?;
    check_envelope_bounds(request)
}

fn check_envelope_identity(request: &SynthesisRequest) -> Result<(), SynthesisError> {
    if request.schema_revision != SYNTHESIS_SCHEMA_REVISION {
        return Err(SynthesisError::UnsupportedSchema {
            want_revision: SYNTHESIS_SCHEMA_REVISION,
            got_revision: request.schema_revision,
            detail: "research synthesis envelope revision".to_owned(),
        });
    }
    if request.binding.job_class != SYNTHESIS_JOB_CLASS {
        return Err(SynthesisError::KindMismatch {
            want: SYNTHESIS_JOB_CLASS.to_owned(),
            got: redact_value(&request.binding.job_class),
            detail: "research synthesis job class".to_owned(),
        });
    }
    let binding = &request.binding;
    check_handle(&binding.operation_id, "binding.operation_id")?;
    check_handle(&binding.idempotency_key, "binding.idempotency_key")?;
    check_handle(&binding.requester_principal, "binding.requester_principal")?;
    check_handle(&binding.requester_session, "binding.requester_session")?;
    check_handle(&binding.task_id, "binding.task_id")?;
    check_handle(&binding.attempt_id, "binding.attempt_id")?;
    check_handle(&binding.scope_id, "binding.scope_id")?;
    check_handle(&binding.fence_epoch, "binding.fence_epoch")?;
    check_text(&request.pack.question, "pack.question")?;
    check_digest(&request.pack.bundle_digest, "pack.bundle_digest")?;
    check_digest(&request.pack.manifest_digest, "pack.manifest_digest")?;
    check_digest(&request.draft.grounding_digest, "draft.grounding_digest")?;
    check_text(&request.draft.question, "draft.question")?;
    check_digest(&request.receipt.receipt_digest, "receipt.receipt_digest")?;
    check_digest(&request.receipt.bundle_digest, "receipt.bundle_digest")?;
    check_digest(&request.receipt.manifest_digest, "receipt.manifest_digest")?;
    check_digest(
        &request.receipt.grounding_digest,
        "receipt.grounding_digest",
    )?;
    check_handle(
        &request.receipt.validator_revision,
        "receipt.validator_revision",
    )?;
    check_digest(&request.policy.policy_digest, "policy.policy_digest")?;
    check_handle(&request.policy.revision, "policy.revision")?;
    Ok(())
}

fn check_envelope_content(request: &SynthesisRequest) -> Result<(), SynthesisError> {
    if request.pack.sources.is_empty() {
        return Err(malformed(
            "pack.sources",
            "at least one authorized source is required",
        ));
    }
    if request.pack.sources.len() > MAX_SOURCES {
        return Err(malformed(
            "pack.sources",
            "source count exceeds the ceiling",
        ));
    }
    for (index, card) in request.pack.sources.iter().enumerate() {
        check_card(card, index)?;
    }
    if request.draft.claims.len() > MAX_CLAIMS {
        return Err(malformed("draft.claims", "claim count exceeds the ceiling"));
    }
    if request.draft.rivals.len() > MAX_RIVALS {
        return Err(malformed("draft.rivals", "rival count exceeds the ceiling"));
    }
    if request.draft.unknowns.len() > MAX_UNKNOWNS {
        return Err(malformed(
            "draft.unknowns",
            "unknown count exceeds the ceiling",
        ));
    }
    if request.draft.probes.len() > MAX_PROBES {
        return Err(malformed("draft.probes", "probe count exceeds the ceiling"));
    }
    for (index, probe) in request.draft.probes.iter().enumerate() {
        check_probe_shape(probe, index)?;
    }
    for (index, claim) in request.draft.claims.iter().enumerate() {
        check_claim_shape(claim, index)?;
    }
    for (index, rival) in request.draft.rivals.iter().enumerate() {
        let field = format!("draft.rivals[{index}]");
        check_handle(&rival.rival_id, &format!("{field}.rival_id"))?;
        check_text(&rival.position, &format!("{field}.position"))?;
        check_handle(&rival.target_claim, &format!("{field}.target_claim"))?;
    }
    for (index, unknown) in request.draft.unknowns.iter().enumerate() {
        let field = format!("draft.unknowns[{index}]");
        check_handle(&unknown.unknown_id, &format!("{field}.unknown_id"))?;
        check_text(&unknown.detail, &format!("{field}.detail"))?;
    }
    for handle in &request.pack.source_denominator {
        check_handle(handle, "pack.source_denominator")?;
    }
    for class in &request.pack.missing_source_classes {
        check_text(class, "pack.missing_source_classes")?;
    }
    for (index, omitted) in request.pack.omitted_sources.iter().enumerate() {
        let field = format!("pack.omitted_sources[{index}]");
        check_handle(&omitted.handle, &format!("{field}.handle"))?;
        check_text(&omitted.reason, &format!("{field}.reason"))?;
    }
    check_handle(&request.draft.concilium.owner, "draft.concilium.owner")?;
    check_text(
        &request.draft.concilium.review_objective,
        "draft.concilium.review_objective",
    )?;
    for reference in &request.draft.concilium.evidence_refs {
        check_handle(reference, "draft.concilium.evidence_refs")?;
    }
    for position in &request.draft.concilium.positions {
        check_text(position, "draft.concilium.positions")?;
    }
    Ok(())
}

fn check_envelope_bounds(request: &SynthesisRequest) -> Result<(), SynthesisError> {
    let bounds = &request.bounds;
    if bounds.max_input_bytes == 0
        || bounds.max_output_bytes == 0
        || bounds.max_claims == 0
        || bounds.max_rivals == 0
        || bounds.max_references == 0
        || bounds.max_probes == 0
        || bounds.max_work == 0
    {
        return Err(SynthesisError::BudgetExceeded {
            detail: "independent synthesis bounds must be non-zero".to_owned(),
        });
    }
    Ok(())
}

// ---------- stage 2: bindings ----------

fn mismatch(field: &str, want: &str, got: &str) -> SynthesisError {
    SynthesisError::ReferenceMismatch {
        field: field.to_owned(),
        want: redact_value(want),
        got: redact_value(got),
    }
}

fn check_bindings(request: &SynthesisRequest) -> Result<(), SynthesisError> {
    let binding = &request.binding;
    let pack = &request.pack;
    let draft = &request.draft;
    let receipt = &request.receipt;
    for (got, field) in [
        (&pack.task_id, "pack.task_id"),
        (&draft.task_id, "draft.task_id"),
        (&receipt.task_id, "receipt.task_id"),
    ] {
        if *got != binding.task_id {
            return Err(mismatch(field, &binding.task_id, got));
        }
    }
    for (got, field) in [
        (&pack.scope_id, "pack.scope_id"),
        (&draft.scope_id, "draft.scope_id"),
        (&receipt.scope_id, "receipt.scope_id"),
    ] {
        if *got != binding.scope_id {
            return Err(mismatch(field, &binding.scope_id, got));
        }
    }
    for (got, field) in [
        (&pack.fence_epoch, "pack.fence_epoch"),
        (&receipt.fence_epoch, "receipt.fence_epoch"),
    ] {
        if *got != binding.fence_epoch {
            return Err(mismatch(field, &binding.fence_epoch, got));
        }
    }
    for (got, field) in [
        (pack.fence_generation, "pack.fence_generation"),
        (receipt.fence_generation, "receipt.fence_generation"),
    ] {
        if got != binding.fence_generation {
            return Err(mismatch(
                field,
                &binding.fence_generation.to_string(),
                &got.to_string(),
            ));
        }
    }
    if draft.question != pack.question {
        return Err(mismatch("draft.question", &pack.question, &draft.question));
    }
    if pack_content_digest(pack) != pack.pack_digest {
        return Err(mismatch(
            "pack.pack_digest",
            &pack_content_digest(pack),
            &pack.pack_digest,
        ));
    }
    if draft_content_digest(draft) != draft.draft_digest {
        return Err(mismatch(
            "draft.draft_digest",
            &draft_content_digest(draft),
            &draft.draft_digest,
        ));
    }
    if receipt.bundle_digest != pack.bundle_digest {
        return Err(mismatch(
            "receipt.bundle_digest",
            &pack.bundle_digest,
            &receipt.bundle_digest,
        ));
    }
    if receipt.manifest_digest != pack.manifest_digest {
        return Err(mismatch(
            "receipt.manifest_digest",
            &pack.manifest_digest,
            &receipt.manifest_digest,
        ));
    }
    if receipt.grounding_digest != draft.grounding_digest {
        return Err(mismatch(
            "receipt.grounding_digest",
            &draft.grounding_digest,
            &receipt.grounding_digest,
        ));
    }
    Ok(())
}

// ---------- stage 3: terminal ----------

fn unknown_preservation(note: &str) -> Vec<PreservationVerdict> {
    preservation_dimensions()
        .iter()
        .map(|dimension| PreservationVerdict {
            dimension: *dimension,
            passed: false,
            known: false,
            note: note.to_owned(),
        })
        .collect()
}

fn blocked_outcome(request: &SynthesisRequest, note: &str, input_digest: &str) -> SynthesisOutcome {
    SynthesisOutcome {
        disposition: SynthesisDisposition::Blocked,
        brief: None,
        preservation: unknown_preservation(note),
        inherited_receipt: request.receipt.clone(),
        input_digest: input_digest.to_owned(),
        output_digest: terminal_digest(SynthesisDisposition::Blocked, input_digest),
        work_used: 0,
        omitted: Vec::new(),
    }
}

fn check_terminal(request: &SynthesisRequest, input_digest: &str) -> Option<SynthesisOutcome> {
    if request.cancellation.cancelled {
        return Some(blocked_outcome(
            request,
            "pre-handler cancellation stops projection",
            input_digest,
        ));
    }
    if let (Some(now), Some(deadline)) = (
        request.cancellation.now_ms,
        request.cancellation.deadline_ms,
    ) && now > deadline
    {
        return Some(blocked_outcome(
            request,
            "observed now passed the wall deadline",
            input_digest,
        ));
    }
    if request.binding.fence_generation > request.policy.valid_through_generation {
        return Some(blocked_outcome(
            request,
            "policy revision is stale for the bound fence generation",
            input_digest,
        ));
    }
    None
}

fn check_input_budget(request: &SynthesisRequest) -> Result<(), SynthesisError> {
    if len_u64(&request_canonical_bytes(request)) > request.bounds.max_input_bytes {
        return Err(SynthesisError::BudgetExceeded {
            detail: "canonical request exceeds the input byte budget".to_owned(),
        });
    }
    Ok(())
}

// ---------- stage 4: projection ----------

struct ProjectionState<'a> {
    authorized: BTreeMap<String, &'a SourceCard>,
    seen_claims: BTreeMap<String, Vec<u8>>,
    refs_used: u64,
    work_used: u64,
    omitted: Vec<Omission>,
    partial_needed: bool,
    work_exhausted: bool,
}

impl<'a> ProjectionState<'a> {
    fn build(request: &'a SynthesisRequest) -> Self {
        let mut authorized = BTreeMap::new();
        for card in &request.pack.sources {
            authorized.insert(card.handle.clone(), card);
        }
        Self {
            authorized,
            seen_claims: BTreeMap::new(),
            refs_used: 0,
            work_used: 0,
            omitted: Vec::new(),
            partial_needed: false,
            work_exhausted: false,
        }
    }

    fn spend(&mut self, max_work: u64, cost: u64) -> bool {
        if self.work_used.saturating_add(cost) > max_work {
            self.work_exhausted = true;
            return false;
        }
        self.work_used = self.work_used.saturating_add(cost);
        true
    }

    fn omit(&mut self, kind: OmissionKind, detail: &str, denominator: u64, omitted: u64) {
        self.partial_needed = true;
        self.omitted.push(Omission {
            kind,
            detail: detail.to_owned(),
            denominator,
            omitted,
        });
    }
}

fn firewall_handle(
    state: &ProjectionState<'_>,
    handle: &str,
    field: &str,
) -> Result<(), SynthesisError> {
    if !state.authorized.contains_key(handle) {
        return Err(SynthesisError::AcquisitionRejected {
            handle: redact_value(handle),
            detail: format!("{field} leaves the authorized source set"),
        });
    }
    Ok(())
}

fn meets_floor(freshness: Freshness, floor: Freshness) -> bool {
    match floor {
        Freshness::Fresh => freshness == Freshness::Fresh,
        Freshness::Unknown => freshness != Freshness::Stale,
        Freshness::Stale => true,
    }
}

fn cap_precision(
    precision: Precision,
    card: &SourceCard,
    notes: &mut Vec<String>,
    handle: &str,
) -> Precision {
    if precision == Precision::Unsupported {
        return Precision::Unsupported;
    }
    if card.transformed {
        notes.push(format!(
            "capped to qualified: {handle} evidence was transformed after admission"
        ));
        return Precision::Qualified;
    }
    if card.freshness != Freshness::Fresh {
        notes.push(format!(
            "capped to qualified: {handle} freshness is not fresh and cannot raise precision"
        ));
        return Precision::Qualified;
    }
    precision
}

struct AcceptedSupport {
    handles: Vec<String>,
    weakest_grade: EvidenceGrade,
    authority: SourceAuthority,
    lineage: BTreeSet<String>,
    capped: u64,
    matched: u64,
    withheld: u64,
    precisionless: u64,
}

fn accept_citations(
    state: &ProjectionState<'_>,
    citations: &[crate::model::Citation],
    floor: Freshness,
    required: Option<PrecisionKind>,
    notes: &mut Vec<String>,
    field: &str,
) -> Result<AcceptedSupport, SynthesisError> {
    let mut handles = Vec::new();
    let mut weakest_grade = EvidenceGrade::E3;
    let mut authority = SourceAuthority::Authoritative;
    let mut lineage = BTreeSet::new();
    let mut capped = 0_u64;
    let mut matched = 0_u64;
    let mut withheld = 0_u64;
    let mut precisionless = 0_u64;
    for citation in citations {
        firewall_handle(state, &citation.source_handle, field)?;
        let card = state
            .authorized
            .get(&citation.source_handle)
            .ok_or_else(|| SynthesisError::Internal {
                detail: "firewall passed an unauthorized handle".to_owned(),
            })?;
        if card.privacy_class == "deny-brief" {
            notes.push(format!(
                "withheld: {} is privacy-denied for brief use",
                citation.source_handle
            ));
            withheld = withheld.saturating_add(1);
            continue;
        }
        if !meets_floor(card.freshness, floor) {
            notes.push(format!(
                "withheld: {} freshness misses the policy floor",
                citation.source_handle
            ));
            withheld = withheld.saturating_add(1);
            continue;
        }
        let before = notes.len();
        let capped_precision =
            cap_precision(citation.precision, card, notes, &citation.source_handle);
        if notes.len() > before {
            capped = capped.saturating_add(1);
        }
        if capped_precision == Precision::Unsupported {
            notes.push(format!(
                "unsupported precision: {} carries no usable precision",
                citation.source_handle
            ));
            precisionless = precisionless.saturating_add(1);
            continue;
        }
        if required.is_none_or(|kind| kind == citation.kind) {
            matched = matched.saturating_add(1);
        }
        handles.push(citation.source_handle.clone());
        if card.grade < weakest_grade {
            weakest_grade = card.grade;
        }
        if source_authority_rank(card.authority) > source_authority_rank(authority) {
            authority = card.authority;
        }
        lineage.insert(card.lineage_group.clone());
    }
    Ok(AcceptedSupport {
        handles,
        weakest_grade,
        authority,
        lineage,
        capped,
        matched,
        withheld,
        precisionless,
    })
}

fn canonical_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn project_counterclaim(
    state: &mut ProjectionState<'_>,
    counter: &Counterclaim,
    floor: Freshness,
) -> Result<ClaimVerdict, SynthesisError> {
    let canonical = counterclaim_canonical_bytes(counter, true);
    if let Some(previous) = state.seen_claims.get(&counter.counterclaim_id) {
        if *previous == canonical {
            return Ok(ClaimVerdict {
                claim_id: counter.counterclaim_id.clone(),
                is_counterclaim: true,
                kind: counter.kind,
                disposition: ClaimDisposition::DuplicateCollapsed,
                support: Vec::new(),
                counter_evidence: Vec::new(),
                citations: Vec::new(),
                weakest_grade: EvidenceGrade::E0,
                authority: SourceAuthority::Unknown,
                lineage_groups: vec!["unknown".to_owned()],
                precision_notes: vec!["byte-identical repeat collapsed".to_owned()],
                absence_basis: String::new(),
            });
        }
        return Err(malformed(
            "draft.claims",
            &format!(
                "duplicate counterclaim id with changed content: {}",
                counter.counterclaim_id
            ),
        ));
    }
    state
        .seen_claims
        .insert(counter.counterclaim_id.clone(), canonical);
    firewall_handle(state, &counter.source_handle, "counterclaim.source_handle")?;
    let mut notes = Vec::new();
    let accepted = accept_citations(
        state,
        &counter.citations,
        floor,
        required_precision_kind(counter.kind),
        &mut notes,
        "counterclaim.citations",
    )?;
    let disposition = if accepted.handles.is_empty() {
        ClaimDisposition::Unsupported
    } else {
        ClaimDisposition::Supported
    };
    let mut lineage: Vec<String> = accepted.lineage.iter().cloned().collect();
    if lineage.is_empty() {
        lineage.push("unknown".to_owned());
    }
    Ok(ClaimVerdict {
        claim_id: counter.counterclaim_id.clone(),
        is_counterclaim: true,
        kind: counter.kind,
        disposition,
        support: canonical_strings(accepted.handles.clone()),
        counter_evidence: Vec::new(),
        citations: canonical_strings(accepted.handles),
        weakest_grade: accepted.weakest_grade,
        authority: accepted.authority,
        lineage_groups: lineage,
        precision_notes: notes,
        absence_basis: String::new(),
    })
}

/// Precision kind a claim shape requires its citations to carry.
///
/// Factual, general, and absence shapes accept any kind; numeric, time,
/// version, and causal shapes need their own kind (I21.7: a document-level
/// source does not back a symbol, line, causal, or population-wide
/// statement on its own).
fn required_precision_kind(kind: crate::model::ClaimKind) -> Option<PrecisionKind> {
    use crate::model::ClaimKind::{Absence, Causal, Factual, Numeric, Time, Version};
    match kind {
        Numeric => Some(PrecisionKind::Numeric),
        Time => Some(PrecisionKind::Time),
        Version => Some(PrecisionKind::Version),
        Causal => Some(PrecisionKind::Causal),
        Factual | Absence => None,
    }
}

fn absence_verdict(pack: &ResearchPack, counter_evidence: &[String]) -> (ClaimDisposition, String) {
    if !counter_evidence.is_empty() {
        return (
            ClaimDisposition::Contested,
            "absence meets undefeated counter-evidence".to_owned(),
        );
    }
    if pack.coverage_denominator == DenominatorKind::CompleteScope
        && pack.counter_search == crate::model::CounterSearchStatus::Complete
    {
        (
            ClaimDisposition::AbsentScopeComplete,
            "absence under complete suitable authoritative coverage".to_owned(),
        )
    } else {
        (
            ClaimDisposition::AbsentScopeIncomplete,
            "absence unprovable without complete coverage and counter-search".to_owned(),
        )
    }
}

fn project_claim(
    state: &mut ProjectionState<'_>,
    claim: &StructuredClaim,
    request: &SynthesisRequest,
) -> Result<Option<(ClaimVerdict, Vec<ClaimVerdict>)>, SynthesisError> {
    if let Some(duplicate) = check_claim_duplicate(state, claim)? {
        return Ok(Some(duplicate));
    }
    let refs = claim_reference_cost(claim);
    if refs > MAX_REFERENCES_PER_CLAIM {
        return Err(malformed(
            "draft.claims",
            &format!(
                "claim {} exceeds the per-claim reference ceiling",
                claim.claim_id
            ),
        ));
    }
    if state.refs_used.saturating_add(refs) > request.bounds.max_references {
        state.omit(
            OmissionKind::References,
            &format!(
                "reference budget cut claim {} with a reopening reference",
                claim.claim_id
            ),
            request.bounds.max_references,
            refs,
        );
        return Ok(None);
    }
    if !state.spend(request.bounds.max_work, 1_u64.saturating_add(refs)) {
        state.omit(
            OmissionKind::Work,
            &format!(
                "work budget exhausted at claim {} with a reopening reference",
                claim.claim_id
            ),
            request.bounds.max_work,
            1,
        );
        return Ok(None);
    }
    state.refs_used = state.refs_used.saturating_add(refs);

    let mut notes = Vec::new();
    let accepted = accept_citations(
        state,
        &claim.support,
        request.policy.freshness_floor,
        required_precision_kind(claim.kind),
        &mut notes,
        "claim.support",
    )?;
    let mut counter_evidence = Vec::new();
    let mut counter_verdicts = Vec::new();
    for counter in &claim.counterclaims {
        firewall_handle(state, &counter.source_handle, "counterclaim.source_handle")?;
        let verdict = project_counterclaim(state, counter, request.policy.freshness_floor)?;
        if verdict.disposition == ClaimDisposition::Supported {
            counter_evidence.push(counter.source_handle.clone());
        }
        counter_verdicts.push(verdict);
    }
    let verdict = finish_claim_verdict(claim, request, &accepted, counter_evidence, notes);
    Ok(Some((verdict, counter_verdicts)))
}

fn check_claim_duplicate(
    state: &mut ProjectionState<'_>,
    claim: &StructuredClaim,
) -> Result<Option<(ClaimVerdict, Vec<ClaimVerdict>)>, SynthesisError> {
    let canonical = claim_canonical_bytes(claim, true);
    if let Some(previous) = state.seen_claims.get(&claim.claim_id) {
        if *previous == canonical {
            return Ok(Some((
                ClaimVerdict {
                    claim_id: claim.claim_id.clone(),
                    is_counterclaim: false,
                    kind: claim.kind,
                    disposition: ClaimDisposition::DuplicateCollapsed,
                    support: Vec::new(),
                    counter_evidence: Vec::new(),
                    citations: Vec::new(),
                    weakest_grade: EvidenceGrade::E0,
                    authority: SourceAuthority::Unknown,
                    lineage_groups: vec!["unknown".to_owned()],
                    precision_notes: vec!["byte-identical repeat collapsed".to_owned()],
                    absence_basis: String::new(),
                },
                Vec::new(),
            )));
        }
        return Err(malformed(
            "draft.claims",
            &format!(
                "duplicate claim id with changed content: {}",
                claim.claim_id
            ),
        ));
    }
    state.seen_claims.insert(claim.claim_id.clone(), canonical);
    Ok(None)
}

fn claim_reference_cost(claim: &StructuredClaim) -> u64 {
    len_u64(&claim.support)
        .saturating_add(len_u64(&claim.counterclaims))
        .saturating_add(
            claim
                .counterclaims
                .iter()
                .map(|counter| len_u64(&counter.citations))
                .fold(0_u64, u64::saturating_add),
        )
}

fn finish_claim_verdict(
    claim: &StructuredClaim,
    request: &SynthesisRequest,
    accepted: &AcceptedSupport,
    counter_evidence: Vec<String>,
    mut notes: Vec<String>,
) -> ClaimVerdict {
    let disposition = if claim.kind == crate::model::ClaimKind::Absence {
        let (absence_disposition, basis) = absence_verdict(&request.pack, &counter_evidence);
        notes.push(basis);
        absence_disposition
    } else if accepted.handles.is_empty() {
        if accepted.withheld > 0 {
            notes.push(
                "withheld: every support handle is privacy- or policy-withheld; reopen via the pack digest"
                    .to_owned(),
            );
            ClaimDisposition::Withheld
        } else if accepted.precisionless > 0 && required_precision_kind(claim.kind).is_some() {
            notes.push(
                "required numeric/time/version/causal precision is unsupported across all citations"
                    .to_owned(),
            );
            ClaimDisposition::PrecisionLimited
        } else {
            ClaimDisposition::Unsupported
        }
    } else {
        precision_gate(claim, accepted, &mut notes)
    };
    let disposition = if disposition == ClaimDisposition::Supported && !counter_evidence.is_empty()
    {
        notes.push("contested: undefeated counter-evidence coexists".to_owned());
        ClaimDisposition::Contested
    } else {
        disposition
    };

    let mut lineage: Vec<String> = accepted.lineage.iter().cloned().collect();
    if disposition == ClaimDisposition::AbsentScopeComplete {
        lineage = canonical_strings(request.pack.source_denominator.clone());
        notes.push(format!(
            "absence basis: complete denominator over {} sources",
            lineage.len()
        ));
    }
    if lineage.is_empty() {
        lineage.push("unknown".to_owned());
    }
    let mut verdict = ClaimVerdict {
        claim_id: claim.claim_id.clone(),
        is_counterclaim: false,
        kind: claim.kind,
        disposition,
        support: canonical_strings(accepted.handles.clone()),
        counter_evidence: canonical_strings(counter_evidence),
        citations: canonical_strings(accepted.handles.clone()),
        weakest_grade: accepted.weakest_grade,
        authority: accepted.authority,
        lineage_groups: lineage,
        precision_notes: notes,
        absence_basis: if claim.kind == crate::model::ClaimKind::Absence {
            "see precision notes".to_owned()
        } else {
            String::new()
        },
    };
    if accepted.capped > 0 {
        verdict
            .precision_notes
            .push(format!("{} citations capped to qualified", accepted.capped));
    }
    verdict
}

fn precision_gate(
    claim: &StructuredClaim,
    accepted: &AcceptedSupport,
    notes: &mut Vec<String>,
) -> ClaimDisposition {
    use crate::model::ClaimKind::{Absence, Causal, Factual, Numeric, Time, Version};
    match claim.kind {
        Factual | Absence => ClaimDisposition::Supported,
        Numeric | Time | Version => {
            if accepted.matched == 0 {
                notes.push(
                    "required numeric/time/version precision is unsupported; qualifiers kept"
                        .to_owned(),
                );
                ClaimDisposition::PrecisionLimited
            } else {
                notes.push("precision holds at the cited level; no promotion".to_owned());
                ClaimDisposition::Supported
            }
        }
        Causal => {
            if !claim.grounded_relation {
                notes.push("causal claim without a grounded relation stays limited".to_owned());
                ClaimDisposition::PrecisionLimited
            } else if accepted.matched == 0 {
                notes.push(
                    "grounded causal relation lacks a causal-kind citation; stays limited"
                        .to_owned(),
                );
                ClaimDisposition::PrecisionLimited
            } else {
                notes.push("causal relation grounded; mechanism qualifiers kept".to_owned());
                ClaimDisposition::Supported
            }
        }
    }
}

// ---------- rivals, unknowns, probes, concilium ----------

fn project_rivals(
    state: &mut ProjectionState<'_>,
    request: &SynthesisRequest,
    live_claims: &BTreeSet<String>,
) -> Result<Vec<RivalPosition>, SynthesisError> {
    let mut positions = Vec::new();
    let denominator = len_u64(&request.draft.rivals);
    let mut remaining = denominator.min(request.bounds.max_rivals);
    for rival in &request.draft.rivals {
        if remaining == 0 {
            break;
        }
        remaining = remaining.saturating_sub(1);
        if !live_claims.contains(&rival.target_claim) {
            return Err(malformed(
                "draft.rivals",
                &format!("rival {} targets an unknown claim", rival.rival_id),
            ));
        }
        for citation in &rival.evidence {
            firewall_handle(state, &citation.source_handle, "rival.evidence")?;
        }
        if !state.spend(
            request.bounds.max_work,
            1_u64.saturating_add(len_u64(&rival.evidence)),
        ) {
            state.omit(
                OmissionKind::Work,
                &format!(
                    "work budget exhausted at rival {} with a reopening reference",
                    rival.rival_id
                ),
                request.bounds.max_work,
                1,
            );
            break;
        }
        let mut notes = Vec::new();
        let accepted = accept_citations(
            state,
            &rival.evidence,
            request.policy.freshness_floor,
            None,
            &mut notes,
            "rival.evidence",
        )?;
        let _ = notes;
        positions.push(RivalPosition {
            rival_id: rival.rival_id.clone(),
            position: rival.position.clone(),
            stance: rival.stance,
            target_claim: rival.target_claim.clone(),
            minority: rival.minority,
            evidence: canonical_strings(accepted.handles.clone()),
            weakest_grade: accepted.weakest_grade,
        });
    }
    if denominator > len_u64(&positions) && !state.work_exhausted {
        state.omit(
            OmissionKind::Rivals,
            "rival budget cut the portfolio with reopening references",
            denominator,
            denominator.saturating_sub(len_u64(&positions)),
        );
    }
    Ok(positions)
}

fn project_unknowns(
    state: &mut ProjectionState<'_>,
    request: &SynthesisRequest,
    unknown_texts: &mut BTreeSet<String>,
) {
    for unknown in &request.draft.unknowns {
        if unknown_texts.len() >= MAX_UNKNOWNS {
            state.omit(
                OmissionKind::Unknowns,
                "unknown ceiling cut the gap list with reopening references",
                len_u64(&request.draft.unknowns),
                1,
            );
            break;
        }
        if !state.spend(request.bounds.max_work, 1) {
            state.omit(
                OmissionKind::Work,
                "work budget exhausted in the gap list with a reopening reference",
                request.bounds.max_work,
                1,
            );
            break;
        }
        unknown_texts.insert(format!("{}: {}", unknown.unknown_id, unknown.detail));
    }
}

fn project_probes(
    state: &mut ProjectionState<'_>,
    request: &SynthesisRequest,
    live_targets: &BTreeSet<String>,
    recommended: &mut Vec<RecommendedProbe>,
    residue: &mut Vec<ProbeResidue>,
) {
    for probe in &request.draft.probes {
        let mut outcomes: Vec<String> = probe.outcomes.clone();
        outcomes.sort();
        outcomes.dedup();
        if outcomes.len() < 2
            || probe.discriminates.is_empty()
            || probe
                .discriminates
                .iter()
                .any(|target| !live_targets.contains(target))
        {
            residue.push(ProbeResidue {
                probe_id: probe.probe_id.clone(),
                reason: if probe
                    .discriminates
                    .iter()
                    .any(|target| !live_targets.contains(target))
                {
                    ProbeResidueReason::UnknownTarget
                } else {
                    ProbeResidueReason::Nondiscriminative
                },
                detail: "probe needs two distinct outcomes over live targets".to_owned(),
            });
            continue;
        }
        let transform_authorized = match &probe.basis {
            ProbeBasis::CanonicalTransform(name) => {
                request.policy.canonical_transforms.contains(name)
            }
            ProbeBasis::SuppliedDiscriminative => false,
        };
        let authorized = request.policy.probe_allowlist.contains(&probe.probe_id)
            || (request.policy.authorize_supplied_discriminative
                && probe.basis == ProbeBasis::SuppliedDiscriminative)
            || transform_authorized;
        if !authorized {
            residue.push(ProbeResidue {
                probe_id: probe.probe_id.clone(),
                reason: ProbeResidueReason::Unauthorized,
                detail: "probe is neither allowlisted nor policy-authorized".to_owned(),
            });
            continue;
        }
        if len_u64(recommended) >= request.bounds.max_probes {
            residue.push(ProbeResidue {
                probe_id: probe.probe_id.clone(),
                reason: ProbeResidueReason::Budget,
                detail: "probe budget cut the recommendation with a reopening reference".to_owned(),
            });
            state.omit(
                OmissionKind::Probes,
                "probe budget cut recommendations with reopening references",
                len_u64(&request.draft.probes),
                1,
            );
            continue;
        }
        if !state.spend(request.bounds.max_work, 1) {
            state.omit(
                OmissionKind::Work,
                "work budget exhausted in probe planning with a reopening reference",
                request.bounds.max_work,
                1,
            );
            break;
        }
        recommended.push(RecommendedProbe {
            probe_id: probe.probe_id.clone(),
            discriminates: probe.discriminates.clone(),
            outcomes,
            verifier: probe.verifier.clone(),
            owner: probe.owner.clone(),
            cost_class: probe.cost_class.clone(),
            applicability: probe.applicability.clone(),
        });
    }
}

fn project_concilium(
    state: &mut ProjectionState<'_>,
    concilium: &DraftConcilium,
    policy: &SynthesisPolicy,
) -> Result<ConciliumRecommendation, SynthesisError> {
    for reference in &concilium.evidence_refs {
        firewall_handle(state, reference, "draft.concilium.evidence_refs")?;
    }
    if !policy.concilium_allowed {
        state.omit(
            OmissionKind::Concilium,
            "policy suppressed the Concilium recommendation with a reopening reference",
            1,
            1,
        );
        return Ok(ConciliumRecommendation {
            owner: concilium.owner.clone(),
            evidence_refs: Vec::new(),
            positions: Vec::new(),
            review_objective: concilium.review_objective.clone(),
            effect_count: 0,
            suppressed: true,
        });
    }
    Ok(ConciliumRecommendation {
        owner: concilium.owner.clone(),
        evidence_refs: concilium.evidence_refs.clone(),
        positions: concilium.positions.clone(),
        review_objective: concilium.review_objective.clone(),
        effect_count: 0,
        suppressed: false,
    })
}

// ---------- coverage, dependence, preservation ----------

fn build_coverage(request: &SynthesisRequest, cited: &BTreeSet<String>) -> CoverageReport {
    let denominator: BTreeSet<String> = request.pack.source_denominator.iter().cloned().collect();
    let mut represented: Vec<String> = denominator.intersection(cited).cloned().collect();
    represented.sort();
    let mut cited_sources: Vec<String> = cited.iter().cloned().collect();
    cited_sources.sort();
    CoverageReport {
        denominator: request.pack.coverage_denominator,
        counter_search: request.pack.counter_search,
        missing_classes: request.pack.missing_source_classes.clone(),
        omitted_sources: request.pack.omitted_sources.clone(),
        represented_sources: represented,
        cited_sources,
    }
}

fn build_dependence(request: &SynthesisRequest, cited: &BTreeSet<String>) -> Vec<DependenceGroup> {
    let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for card in &request.pack.sources {
        if cited.contains(&card.handle) {
            groups
                .entry(card.lineage_group.clone())
                .or_default()
                .insert(card.handle.clone());
        }
    }
    groups
        .into_iter()
        .map(|(group, members)| {
            let members_list: Vec<String> = members.iter().cloned().collect();
            DependenceGroup {
                lineage_group: group.clone(),
                independent_roots: len_u64(&members_list),
                members: members_list,
                unknown: group == "unknown",
            }
        })
        .collect()
}

fn brief_handles_resolve(brief: &ResearchBrief, allowed: &BTreeSet<&str>) -> (bool, &'static str) {
    for verdict in &brief.claim_matrix {
        for handle in verdict
            .support
            .iter()
            .chain(verdict.counter_evidence.iter())
            .chain(verdict.citations.iter())
        {
            if !allowed.contains(handle.as_str()) {
                return (false, "brief invents a handle outside inputs");
            }
        }
    }
    (
        true,
        "every brief handle resolves to an authorized or input handle",
    )
}

fn authority_ceiling_holds(state: &ProjectionState<'_>, brief: &ResearchBrief) -> bool {
    for verdict in &brief.claim_matrix {
        if verdict.disposition == ClaimDisposition::DuplicateCollapsed {
            continue;
        }
        let mut weakest_grade = EvidenceGrade::E3;
        let mut authority = SourceAuthority::Authoritative;
        let mut seen = false;
        for handle in &verdict.citations {
            if let Some(card) = state.authorized.get(handle) {
                seen = true;
                if card.grade < weakest_grade {
                    weakest_grade = card.grade;
                }
                if source_authority_rank(card.authority) > source_authority_rank(authority) {
                    authority = card.authority;
                }
            }
        }
        if seen && (weakest_grade != verdict.weakest_grade || authority != verdict.authority) {
            return false;
        }
    }
    true
}

fn check_preservation(
    request: &SynthesisRequest,
    brief: &ResearchBrief,
    state: &ProjectionState<'_>,
) -> Vec<PreservationVerdict> {
    let coverage_ok = request.pack.coverage_denominator == DenominatorKind::CompleteScope
        && request.pack.missing_source_classes.is_empty()
        && request.pack.omitted_sources.is_empty()
        && !state.omitted.iter().any(|omission| {
            matches!(
                omission.kind,
                OmissionKind::Claims | OmissionKind::Rivals | OmissionKind::References
            )
        });
    let preservation_ok = !state
        .omitted
        .iter()
        .any(|omission| matches!(omission.kind, OmissionKind::Claims | OmissionKind::Rivals));
    let mut allowed: BTreeSet<&str> = BTreeSet::new();
    for card in &request.pack.sources {
        allowed.insert(card.handle.as_str());
    }
    for claim in &request.draft.claims {
        allowed.insert(claim.claim_id.as_str());
        for counter in &claim.counterclaims {
            allowed.insert(counter.counterclaim_id.as_str());
        }
    }
    for rival in &request.draft.rivals {
        allowed.insert(rival.rival_id.as_str());
    }
    for unknown in &request.draft.unknowns {
        allowed.insert(unknown.unknown_id.as_str());
    }
    for probe in &request.draft.probes {
        allowed.insert(probe.probe_id.as_str());
    }
    let (faithfulness_ok, faithfulness_detail) = brief_handles_resolve(brief, &allowed);
    let lineage_unknown = brief.claim_matrix.iter().any(|verdict| {
        verdict
            .lineage_groups
            .iter()
            .any(|group| group == "unknown")
    });
    let reversibility_ok = brief.pack_digest == request.pack.pack_digest;
    let authority_ok = authority_ceiling_holds(state, brief);
    let closure_ok = state.omitted.iter().all(|omission| {
        omission.omitted <= omission.denominator && !omission.detail.trim().is_empty()
    });
    vec![
        PreservationVerdict {
            dimension: PreservationDimension::Coverage,
            passed: coverage_ok,
            known: request.pack.coverage_denominator != DenominatorKind::Unknown,
            note: "coverage holds only on a complete denominator without gaps".to_owned(),
        },
        PreservationVerdict {
            dimension: PreservationDimension::Preservation,
            passed: preservation_ok,
            known: true,
            note: "rivals, minority, and counterclaims retained or explicitly omitted".to_owned(),
        },
        PreservationVerdict {
            dimension: PreservationDimension::Faithfulness,
            passed: faithfulness_ok,
            known: true,
            note: faithfulness_detail.to_owned(),
        },
        PreservationVerdict {
            dimension: PreservationDimension::Lineage,
            passed: !brief.claim_matrix.is_empty(),
            known: !lineage_unknown,
            note: "unknown independence stays explicit instead of resolving".to_owned(),
        },
        PreservationVerdict {
            dimension: PreservationDimension::Reversibility,
            passed: reversibility_ok,
            known: true,
            note: "pack digest plus inherited receipt reopen every source".to_owned(),
        },
        PreservationVerdict {
            dimension: PreservationDimension::SourceAuthority,
            passed: authority_ok,
            known: true,
            note: "weakest evidence governs each verdict; no ceiling raised".to_owned(),
        },
        PreservationVerdict {
            dimension: PreservationDimension::DependencyClosure,
            passed: closure_ok,
            known: true,
            note: "omissions reconcile against denominators with reopening references".to_owned(),
        },
    ]
}

// ---------- brief canonical bytes ----------

#[allow(clippy::too_many_lines)]
fn brief_canonical_bytes(brief: &ResearchBrief, semantic: bool) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.text("brief.id", &brief.brief_id);
    writer.text("brief.pack", &brief.pack_digest);
    writer.text("brief.question", &brief.question);
    writer.text(
        "brief.disposition",
        synthesis_disposition_as_str(brief.disposition),
    );
    let mut matrix: Vec<&ClaimVerdict> = brief.claim_matrix.iter().collect();
    if semantic {
        matrix.sort_by(|left, right| {
            left.claim_id
                .cmp(&right.claim_id)
                .then_with(|| left.is_counterclaim.cmp(&right.is_counterclaim))
        });
    }
    for verdict in matrix {
        let mut section = CanonicalWriter::new();
        section.text("verdict.id", &verdict.claim_id);
        section.flag("verdict.counterclaim", verdict.is_counterclaim);
        section.text(
            "verdict.disposition",
            claim_disposition_as_str(verdict.disposition),
        );
        let mut support = verdict.support.clone();
        let mut counter = verdict.counter_evidence.clone();
        let mut citations = verdict.citations.clone();
        if semantic {
            support.sort();
            counter.sort();
            citations.sort();
        }
        for handle in &support {
            section.text("verdict.support", handle);
        }
        for handle in &counter {
            section.text("verdict.counter", handle);
        }
        for handle in &citations {
            section.text("verdict.citation", handle);
        }
        section.text(
            "verdict.grade",
            crate::model::evidence_grade_as_str(verdict.weakest_grade),
        );
        section.integer(
            "verdict.authority",
            source_authority_rank(verdict.authority),
        );
        writer.section("brief.verdict", &section.finish());
    }
    let mut rivals: Vec<&RivalPosition> = brief.rivals.iter().collect();
    if semantic {
        rivals.sort_by(|left, right| left.rival_id.cmp(&right.rival_id));
    }
    for rival in rivals {
        let mut section = CanonicalWriter::new();
        section.text("rival.id", &rival.rival_id);
        section.text("rival.position", &rival.position);
        section.text("rival.target", &rival.target_claim);
        section.flag("rival.minority", rival.minority);
        writer.section("brief.rival", &section.finish());
    }
    let mut unknowns = brief.unknowns.clone();
    if semantic {
        unknowns.sort();
    }
    for unknown in &unknowns {
        writer.text("brief.unknown", unknown);
    }
    let mut probes: Vec<&RecommendedProbe> = brief.probes.iter().collect();
    if semantic {
        probes.sort_by(|left, right| left.probe_id.cmp(&right.probe_id));
    }
    for probe in probes {
        let mut section = CanonicalWriter::new();
        section.text("probe.id", &probe.probe_id);
        for target in &probe.discriminates {
            section.text("probe.target", target);
        }
        for outcome in &probe.outcomes {
            section.text("probe.outcome", outcome);
        }
        writer.section("brief.probe", &section.finish());
    }
    let mut residues: Vec<&ProbeResidue> = brief.probe_residue.iter().collect();
    if semantic {
        residues.sort_by(|left, right| left.probe_id.cmp(&right.probe_id));
    }
    for residue in residues {
        let mut section = CanonicalWriter::new();
        section.text("residue.id", &residue.probe_id);
        section.text(
            "residue.reason",
            match residue.reason {
                ProbeResidueReason::Nondiscriminative => "nondiscriminative",
                ProbeResidueReason::UnknownTarget => "unknown-target",
                ProbeResidueReason::Unauthorized => "unauthorized",
                ProbeResidueReason::Budget => "budget",
            },
        );
        writer.section("brief.residue", &section.finish());
    }
    let concilium = &brief.concilium;
    writer.text("concilium.owner", &concilium.owner);
    writer.text("concilium.objective", &concilium.review_objective);
    writer.flag("concilium.suppressed", concilium.suppressed);
    writer.integer("concilium.effects", concilium.effect_count);
    let coverage = &brief.coverage;
    writer.text(
        "coverage.denominator",
        match coverage.denominator {
            DenominatorKind::CompleteScope => "complete-scope",
            DenominatorKind::Sampled => "sampled",
            DenominatorKind::Unknown => "unknown",
        },
    );
    for class in &coverage.missing_classes {
        writer.text("coverage.missing", class);
    }
    for source in &coverage.represented_sources {
        writer.text("coverage.represented", source);
    }
    for group in &brief.dependence {
        let mut section = CanonicalWriter::new();
        section.text("dependence.group", &group.lineage_group);
        section.integer("dependence.roots", group.independent_roots);
        for member in &group.members {
            section.text("dependence.member", member);
        }
        writer.section("brief.dependence", &section.finish());
    }
    let mut omitted: Vec<&Omission> = brief.omitted.iter().collect();
    if semantic {
        omitted.sort_by(|left, right| {
            omission_kind_rank(left.kind)
                .cmp(&omission_kind_rank(right.kind))
                .then_with(|| left.detail.cmp(&right.detail))
        });
    }
    for omission in omitted {
        let mut section = CanonicalWriter::new();
        section.integer("omission.kind", omission_kind_rank(omission.kind));
        section.text("omission.detail", &omission.detail);
        section.integer("omission.denominator", omission.denominator);
        section.integer("omission.omitted", omission.omitted);
        writer.section("brief.omission", &section.finish());
    }
    for verdict in &brief.preservation {
        let mut section = CanonicalWriter::new();
        section.text(
            "preservation.dimension",
            preservation_dimension_as_str(verdict.dimension),
        );
        section.flag("preservation.passed", verdict.passed);
        section.flag("preservation.known", verdict.known);
        writer.section("brief.preservation", &section.finish());
    }
    writer.finish()
}

// ---------- entry point ----------

/// Runs the single pure ResearchPack-to-ResearchBrief projection.
///
/// The call is deterministic: equal semantic inputs yield equal semantic
/// digests, and replaying a request reproduces its outcome byte for byte.
/// Hard input failures return [`SynthesisError`]; evidence-backed limits
/// return an [`SynthesisOutcome`] whose disposition names the limit.
pub fn synthesize(request: &SynthesisRequest) -> Result<SynthesisOutcome, SynthesisError> {
    check_envelope(request)?;
    check_bindings(request)?;
    let input_digest = request_digest(request);
    if let Some(outcome) = check_terminal(request, &input_digest) {
        return Ok(outcome);
    }
    check_input_budget(request)?;

    let mut state = ProjectionState::build(request);
    let (matrix, cited) = project_matrix(&mut state, request)?;
    let projected = project_portfolio(&mut state, request, matrix, cited)?;
    assemble_outcome(request, &mut state, projected, &input_digest)
}

struct ProjectedParts {
    matrix: Vec<ClaimVerdict>,
    cited: BTreeSet<String>,
    rivals: Vec<RivalPosition>,
    unknowns: Vec<String>,
    recommended: Vec<RecommendedProbe>,
    residue: Vec<ProbeResidue>,
    concilium: ConciliumRecommendation,
}

fn project_matrix(
    state: &mut ProjectionState<'_>,
    request: &SynthesisRequest,
) -> Result<(Vec<ClaimVerdict>, BTreeSet<String>), SynthesisError> {
    let mut matrix: Vec<ClaimVerdict> = Vec::new();
    let mut cited: BTreeSet<String> = BTreeSet::new();
    let claim_denominator = len_u64(&request.draft.claims);
    let admitted_claims = claim_denominator.min(request.bounds.max_claims);
    let mut projected_claims = 0_u64;
    for claim in &request.draft.claims {
        if projected_claims >= admitted_claims {
            break;
        }
        match project_claim(state, claim, request)? {
            Some((verdict, counter_verdicts)) => {
                projected_claims = projected_claims.saturating_add(1);
                for handle in verdict
                    .support
                    .iter()
                    .chain(verdict.counter_evidence.iter())
                    .chain(verdict.citations.iter())
                {
                    cited.insert(handle.clone());
                }
                matrix.push(verdict);
                for counter_verdict in counter_verdicts {
                    for handle in counter_verdict
                        .support
                        .iter()
                        .chain(counter_verdict.citations.iter())
                    {
                        cited.insert(handle.clone());
                    }
                    matrix.push(counter_verdict);
                }
            }
            None => break,
        }
        if state.work_exhausted {
            break;
        }
    }
    if claim_denominator > admitted_claims {
        state.omit(
            OmissionKind::Claims,
            "claim budget cut the matrix with reopening references",
            claim_denominator,
            claim_denominator.saturating_sub(admitted_claims),
        );
    }
    Ok((matrix, cited))
}

fn project_portfolio(
    state: &mut ProjectionState<'_>,
    request: &SynthesisRequest,
    matrix: Vec<ClaimVerdict>,
    mut cited: BTreeSet<String>,
) -> Result<ProjectedParts, SynthesisError> {
    let mut live_claims: BTreeSet<String> = BTreeSet::new();
    for claim in &request.draft.claims {
        live_claims.insert(claim.claim_id.clone());
        for counter in &claim.counterclaims {
            live_claims.insert(counter.counterclaim_id.clone());
        }
    }
    let rivals = project_rivals(state, request, &live_claims)?;
    for rival in &rivals {
        for handle in &rival.evidence {
            cited.insert(handle.clone());
        }
    }

    let mut unknown_texts: BTreeSet<String> = BTreeSet::new();
    project_unknowns(state, request, &mut unknown_texts);

    let mut live_targets = live_claims;
    for rival in &request.draft.rivals {
        live_targets.insert(rival.rival_id.clone());
    }
    for unknown in &request.draft.unknowns {
        live_targets.insert(unknown.unknown_id.clone());
    }
    let mut recommended: Vec<RecommendedProbe> = Vec::new();
    let mut residue: Vec<ProbeResidue> = Vec::new();
    project_probes(
        state,
        request,
        &live_targets,
        &mut recommended,
        &mut residue,
    );

    let concilium = project_concilium(state, &request.draft.concilium, &request.policy)?;

    let unknown_lineage = matrix.iter().any(|verdict| {
        verdict
            .lineage_groups
            .iter()
            .any(|group| group == "unknown")
    });
    let supported_any = matrix.iter().any(|verdict| {
        matches!(
            verdict.disposition,
            ClaimDisposition::Supported
                | ClaimDisposition::Contested
                | ClaimDisposition::AbsentScopeComplete
                | ClaimDisposition::DuplicateCollapsed
        )
    });
    if unknown_lineage && supported_any {
        unknown_texts.insert(
            "lineage-unknown: at least one verdict rests on unknown independence".to_owned(),
        );
    }
    Ok(ProjectedParts {
        matrix,
        cited,
        rivals,
        unknowns: unknown_texts.iter().cloned().collect(),
        recommended,
        residue,
        concilium,
    })
}

fn assemble_outcome(
    request: &SynthesisRequest,
    state: &mut ProjectionState<'_>,
    projected: ProjectedParts,
    input_digest: &str,
) -> Result<SynthesisOutcome, SynthesisError> {
    let coverage = build_coverage(request, &projected.cited);
    let dependence = build_dependence(request, &projected.cited);
    let opposed = has_opposed_rivals(&projected.rivals);
    let disposition = decide_disposition(
        request,
        &projected.matrix,
        &projected.rivals,
        &projected.unknowns,
        state,
        opposed,
    );

    let semantic_input = request_semantic_digest(request);
    let brief_id = format!("brief-{}", &semantic_input[..16.min(semantic_input.len())]);
    let mut brief = ResearchBrief {
        brief_id,
        pack_digest: request.pack.pack_digest.clone(),
        question: request.pack.question.clone(),
        claim_matrix: projected.matrix,
        rivals: projected.rivals,
        unknowns: projected.unknowns,
        probes: projected.recommended,
        probe_residue: projected.residue,
        concilium: projected.concilium,
        coverage,
        dependence,
        disposition,
        preservation: Vec::new(),
        omitted: state.omitted.clone(),
        raw_digest: String::new(),
        semantic_digest: String::new(),
    };
    settle_brief(request, state, &mut brief);
    enforce_output_budget(request, &mut brief, state)?;
    settle_brief(request, state, &mut brief);

    let outcome_disposition = brief.disposition;
    let output_digest = brief.semantic_digest.clone();
    let preservation = brief.preservation.clone();
    Ok(SynthesisOutcome {
        disposition: outcome_disposition,
        brief: Some(brief),
        preservation,
        inherited_receipt: request.receipt.clone(),
        input_digest: input_digest.to_owned(),
        output_digest,
        work_used: state.work_used,
        omitted: state.omitted.clone(),
    })
}

fn settle_brief(
    request: &SynthesisRequest,
    state: &ProjectionState<'_>,
    brief: &mut ResearchBrief,
) {
    brief.preservation = check_preservation(request, brief, state);
    if brief.disposition == SynthesisDisposition::Complete
        && brief
            .preservation
            .iter()
            .any(|verdict| !verdict.passed || !verdict.known)
    {
        brief.disposition = SynthesisDisposition::Partial;
    }
    brief.raw_digest = brief_raw_digest(brief);
    brief.semantic_digest = brief_semantic_digest(brief);
}

fn has_opposed_rivals(rivals: &[RivalPosition]) -> bool {
    for left in rivals {
        for right in rivals {
            if left.target_claim == right.target_claim
                && ((left.stance == RivalStance::Supports && right.stance == RivalStance::Opposes)
                    || (left.stance == RivalStance::Opposes
                        && right.stance == RivalStance::Supports))
            {
                return true;
            }
        }
    }
    false
}

fn decide_disposition(
    request: &SynthesisRequest,
    matrix: &[ClaimVerdict],
    rivals: &[RivalPosition],
    unknowns: &[String],
    state: &ProjectionState<'_>,
    opposed: bool,
) -> SynthesisDisposition {
    if state.work_exhausted {
        return SynthesisDisposition::Exhausted;
    }
    if opposed {
        return SynthesisDisposition::Conflicted;
    }
    if matrix.is_empty() && rivals.is_empty() {
        return SynthesisDisposition::Abstained;
    }
    let imperfect = matrix.iter().any(|verdict| {
        matches!(
            verdict.disposition,
            ClaimDisposition::Unsupported
                | ClaimDisposition::PrecisionLimited
                | ClaimDisposition::AbsentScopeIncomplete
                | ClaimDisposition::Withheld
                | ClaimDisposition::OutsideManifest
        )
    }) || !state.omitted.is_empty()
        || request.pack.coverage_denominator != DenominatorKind::CompleteScope
        || !request.pack.missing_source_classes.is_empty()
        || !request.pack.omitted_sources.is_empty();
    if imperfect && !request.policy.allow_partial {
        return SynthesisDisposition::Abstained;
    }
    let supported = matrix.iter().any(|verdict| {
        matches!(
            verdict.disposition,
            ClaimDisposition::Supported
                | ClaimDisposition::Contested
                | ClaimDisposition::AbsentScopeComplete
                | ClaimDisposition::DuplicateCollapsed
        )
    });
    if request.pack.coverage_denominator == DenominatorKind::Unknown && !supported {
        return SynthesisDisposition::Unknown;
    }
    if !supported && unknowns.is_empty() {
        return SynthesisDisposition::Unsupported;
    }
    if imperfect {
        return SynthesisDisposition::Partial;
    }
    SynthesisDisposition::Complete
}

fn enforce_output_budget(
    request: &SynthesisRequest,
    brief: &mut ResearchBrief,
    state: &mut ProjectionState<'_>,
) -> Result<(), SynthesisError> {
    let mut elided_probes = 0_u64;
    let mut elided_unknowns = 0_u64;
    let mut elided_residue = 0_u64;
    while len_u64(&brief_canonical_bytes(brief, false)) > request.bounds.max_output_bytes {
        if !brief.probes.is_empty() {
            elided_probes = elided_probes.saturating_add(len_u64(&brief.probes));
            brief.probes.clear();
        } else if !brief.unknowns.is_empty() {
            elided_unknowns = elided_unknowns.saturating_add(len_u64(&brief.unknowns));
            brief.unknowns.clear();
        } else if !brief.probe_residue.is_empty() {
            elided_residue = elided_residue.saturating_add(len_u64(&brief.probe_residue));
            brief.probe_residue.clear();
        } else {
            return Err(SynthesisError::BudgetExceeded {
                detail: "canonical brief exceeds the output byte budget".to_owned(),
            });
        }
    }
    if elided_probes + elided_unknowns + elided_residue > 0 {
        state.omit(
            OmissionKind::OutputBytes,
            "output budget elided optional sections with reopening references",
            elided_probes
                .saturating_add(elided_unknowns)
                .saturating_add(elided_residue),
            elided_probes
                .saturating_add(elided_unknowns)
                .saturating_add(elided_residue),
        );
        brief.omitted.clone_from(&state.omitted);
        if brief.disposition == SynthesisDisposition::Complete {
            brief.disposition = SynthesisDisposition::Partial;
        }
        brief.raw_digest = brief_raw_digest(brief);
        brief.semantic_digest = brief_semantic_digest(brief);
    }
    Ok(())
}

/// Recomputes outcome preservation from the finished brief.
///
/// Outcomes carry the brief verdicts verbatim so reviewers read one surface.
pub fn mirror_preservation(brief: &ResearchBrief) -> Vec<PreservationVerdict> {
    brief.preservation.clone()
}
