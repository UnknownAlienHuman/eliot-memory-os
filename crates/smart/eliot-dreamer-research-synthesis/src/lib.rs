//! Pure native ResearchPack-to-ResearchBrief synthesis owner.
//!
//! Cell `smart.dreamer.research-synthesis`, order 6. This crate is the single
//! owner of the deterministic pure `ResearchSynthesis` projection required by
//! I9.3: one call maps a validated job binding, a governed immutable
//! [`ResearchPack`], the exact A-03 validated [`GroundedDraft`], and an
//! immutable [`SynthesisPolicy`] to a candidate [`ResearchBrief`] (or an
//! honest evidence-backed disposition) at candidate-only ceiling.
//!
//! The operation keeps claims, counterclaims, exact citations, source
//! dependence, rivals, unknowns, recommended probes, and the inert Concilium
//! plan separate. It performs no model call, acquisition, parsing, indexing,
//! new-evidence creation, or project-truth promotion, and it owns no clock,
//! randomness, I/O, threads, mutable state, authority, effect, or Finish.
//! The seven I9.7 preservation checks run natively inside [`synthesize()`];
//! no second A-05 pass is invoked.
//!
//! Downstream parity: the `#634` guest adapter transcribes this owner's
//! outcome through [`guest_parity_disposition`]; the spelling map is part of
//! the public contract and covered by the proof matrix.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:34bc895ef590df2f0d6185eeb0fb4294a599a55471854bafd3afce5615e94839`,
//! read receipt
//! `sha256:7dda4cd66453bf3105a7717b9761af4291c5dd2eade40f1d39189c46f80e5fb9`,
//! bundle
//! `sha256:20ee39fcf279f51b5cfe078f52ef755c67dd29fd38fad37387bd401c0eb0d425`
//! (23 required items read under normative pair
//! `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`),
//! plus direct reads of `docs/architecture/I09-03-job-classes.md`,
//! `I09-04-dreamer-input-bundle.md`, `I09-05-dream-packet.md`,
//! `I09-07-memory-transformation-validation.md`, `I21-02-evidence-grade.md`,
//! `I21-06-source-portfolio-coverage-denominator-and-coveragereceipt.md`,
//! `I21-07-reference-firewall-and-unsupported-precision.md`,
//! `I21-08-evidence-freeze-synthesis-and-claim-audit.md`,
//! `I13-02-conflict-set.md`, `I07-20-agent-facing-error-contract.md`, the
//! owning issue #995 body, and the reader report for item 995.

#![forbid(unsafe_code)]

pub mod bounds;
pub mod digest;
pub mod model;
pub mod synthesize;

pub use bounds::{
    DEFAULT_MAX_WORK, DIAGNOSTIC_VALUE_PREFIX, MAX_CLAIMS, MAX_HANDLE_BYTES, MAX_PROBE_OUTCOMES,
    MAX_PROBES, MAX_REFERENCES_PER_CLAIM, MAX_RIVALS, MAX_SOURCES, MAX_SYNTHESIS_INPUT_BYTES,
    MAX_SYNTHESIS_OUTPUT_BYTES, MAX_TEXT_BYTES, MAX_UNKNOWNS, REDACTED_SUFFIX, SYNTHESIS_JOB_CLASS,
    SYNTHESIS_SCHEMA_REVISION,
};
pub use digest::{CanonicalWriter, hex_bytes, is_digest_hex, len_u64, sha256, sha256_hex};
pub use model::{
    CancellationView, Citation, ClaimDisposition, ClaimKind, ClaimVerdict, ConciliumRecommendation,
    CounterSearchStatus, Counterclaim, CoverageReport, DenominatorKind, DependenceGroup,
    DraftConcilium, DraftUnknown, EvidenceGrade, Freshness, GroundedDraft, InputReceipt,
    JobBinding, Omission, OmissionKind, OmittedSource, Precision, PrecisionKind,
    PreservationDimension, PreservationVerdict, ProbeBasis, ProbeResidue, ProbeResidueReason,
    RecommendedProbe, RequesterOrigin, ResearchBrief, ResearchPack, RivalPosition, RivalStance,
    SourceAuthority, SourceCard, StructuredClaim, StructuredProbe, StructuredRival,
    SynthesisBounds, SynthesisDisposition, SynthesisError, SynthesisOutcome, SynthesisPolicy,
    SynthesisRequest, claim_canonical_bytes, claim_disposition_as_str,
    counterclaim_canonical_bytes, draft_canonical_bytes, evidence_grade_as_str,
    guest_parity_disposition, is_digest, is_handle, is_text, omission_kind_rank,
    pack_canonical_bytes, parse_evidence_grade, parse_requester_origin, precision_kind_rank,
    precision_rank, preservation_dimension_as_str, preservation_dimensions, redact_value,
    requester_origin_as_str, source_authority_rank, synthesis_disposition_as_str,
};
pub use synthesize::{
    brief_canonical_len, brief_raw_digest, brief_semantic_digest, draft_content_digest,
    mirror_preservation, pack_content_digest, request_canonical_len, request_digest,
    request_semantic_digest, synthesize, terminal_digest,
};
