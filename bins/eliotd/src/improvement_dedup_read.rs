//! Restoring the improvement deduplication registry from the durable candidate
//! records this daemon already commits (issue #1867 W3, I12.24:297).
//!
//! # The gap this module closes
//!
//! `daemon_runtime::improvement_intake_artifact` admits each real observation
//! into a [`BoundedBacklog`] it constructs on the spot and then drops. A
//! backlog that exists for one pass can never take its lineage-merge branch:
//! the registry is empty at every admission, so a repeat of the same evidence
//! lineage looks exactly like a first observation. The daemon's durable
//! convergence therefore rested entirely on the content-derived candidate id
//! converging the `improvement-candidate:<id>` commit key — the DURABLE half of
//! "deduplicated by target surface and evidence lineage", with the registry
//! half absent.
//!
//! This module supplies the missing half, and it supplies it through the
//! mechanism that already owns the durable artifact.
//!
//! # The read is the EXISTING one, and it is the same one the commit used
//!
//! `eliotd::improvement_intake_dispatch::commit_improvement_artifact` commits
//! every candidate through the closed `RecordLearningRecord` mutation at
//! `LearningRecordKind::Candidate`, scope `governor`, record key
//! `improvement-candidate:<candidate_id>`, with a canonical JSON document
//! `{candidate, brief, owner_decision, enforced_bound,
//! governed_admission_digest}`. The read-back is the production
//! `GetLearningRecordRange` route over
//! `DaemonKernelClient::store_named_async` -- the same authenticated
//! Kernel named-read path `skill_evidence_read` and
//! `negative_memory_action_gate` already use. No second store client,
//! no second read operation, no new record kind, and no new scope.
//!
//! `DaemonKernelClient::store_named_async` is `pub(super)`, declared in
//! `daemon_kernel_client`, whose parent is this crate root. This module is a
//! child of that same root, so it reaches the route without widening its
//! visibility — exactly as the two modules named above do.
//!
//! # Paging: the read is followed to EXHAUSTION, and never past a silent stop
//!
//! `GetLearningRecordRange` declares exactly three parameters — required
//! `max_records`, optional `record_kind`, optional `cursor`
//! (`operation_parameters.rs::GET_LEARNING_RANGE_PARAMETERS`). There is NO
//! handle selector, so the store CANNOT be asked for `improvement-candidate:*`
//! directly: the daemon filters scope, fence and kind and orders rows by
//! `(record_kind, handle, record_digest)`. A single page of
//! [`MAX_LEARNING_PAGE_RECORDS`] rows is therefore NOT the complete candidate
//! set.
//!
//! This module follows the store's own `next_cursor` until the page reports
//! `truncated == false`, which is the providers' authoritative end-of-
//! enumeration signal: both the memory provider
//! (`learning_range_payload`) and the Surreal provider
//! (`read_learning_for_read`) set `truncated` only when a further eligible
//! row was actually observed, and serve an empty page only after the eligible
//! set was traversed to its end. A truncated page is therefore never mistaken
//! for a complete one.
//!
//! The only way the loop stops without an authoritative end is a
//! non-advancing cursor, and that is a [`ImprovementDedupReadError`] — a
//! refusal, not a partial registry. There is no page cap and no timeout: a cap
//! would manufacture exactly the "looks empty" state this module exists to
//! prevent, and the store's keyset continuation advances monotonically, so the
//! loop terminates on the store's own end-of-enumeration signal.
//!
//! # Completeness is never inferred, and a partial read is never "empty"
//!
//! Every refusal here — a transport error, a response that answers a
//! different operation or fence, a page shape that is not the versioned
//! learning page, a non-advancing cursor, or a row that is not a decodable
//! prior candidate — propagates as a typed error and the caller does NOT
//! admit. It is never downgraded to "the registry is empty", because that is
//! precisely the state in which a repeat would be admitted as new.
//!
//! The comparison a caller would be tempted to make instead — "did the record
//! I already hold come back?" — is not performed anywhere. A row qualifies as
//! a prior candidate only on CONTENT:
//!
//! 1. its `record_kind` is the closed `candidate` spelling;
//! 2. its presented `record_digest` is the SHA-256 of the exact `record_json`
//!    bytes the store returned under it, which is the immutable revision
//!    identity the store keys rows by;
//! 3. its document decodes to the committed artifact shape AND binds itself:
//!    the brief and the owner decision must name the very candidate the
//!    document carries, the owner decision must name the very brief the
//!    document carries, and the recorded decision owner must be a non-empty
//!    principal — the principal that RECORDED the disposition, which is a
//!    different fact from the candidate's ADMISSION authority and is therefore
//!    not required to equal it;
//! 4. the candidate itself passes [`ImprovementCandidate::validate`];
//! 5. the owner-decided bound committed beside it must pass
//!    [`CandidateBoundPolicy::validate`].
//!
//! The registry is then rebuilt through
//! [`BoundedBacklog::restored`], which re-proves the candidate and COMPUTES
//! the entry's lineage digest from the candidate's own canonical evidence
//! lineage via the `eliot-improvement` crate's existing
//! `canonical_evidence_lineage` / `evidence_lineage_digest`. The merge
//! decision is therefore driven by the candidate's own content, and a record
//! that merely exists, is well-shaped, or carries a key that looks right is
//! not a prior candidate.
//!
//! # Archive receipts are honoured, not ignored
//!
//! The archive path commits its receipts under the SAME closed
//! `candidate` kind (`{archived_candidate, disposition}`), so they arrive in
//! this read too. A receipt is a recorded terminal disposition, and the
//! candidate row it names is its own earlier revision — the daemon never
//! rewrites the candidate row when it archives. A registry that restored such
//! a candidate as ACTIVE would resurrect an archived candidate into the
//! active set and let it re-merge. Every candidate id named by a receipt in
//! the same exhaustive read is therefore excluded from the restored set.
//!
//! # The MERGE RESULT is a row too, and it is what makes the merge durable
//!
//! The commit path records a lineage merge as `{merged_survivor,
//! absorbed_candidate_id}` under the same closed `candidate` kind: the
//! surviving [`TrackedCandidate`] exactly as the merge left it — the unioned
//! `evidence_refs` and `source_trace_refs`, the `merged_from` absorbed-id
//! list, the retained `value`/`owner`/`admitted_under_authority`, the
//! recomputed `lineage_digest`, and the advanced `candidate.revision`.
//!
//! Without that row the daemon commits only the INCOMING candidate, so the
//! surviving entry's pre-merge revision is the newest revision the store holds
//! for it and the unioned lineage is gone by the next pass. The row is read
//! for the same two reasons the archive receipt is:
//!
//! 1. its `merged_survivor` becomes the restored entry, carrying the entry's
//!    OWN accumulated lineage rather than a lineage re-derived from one
//!    candidate's evidence list, and
//! 2. the `absorbed_candidate_id` it names is excluded from the active set,
//!    because a merge absorbed that candidate — it is not a second active
//!    entry and restoring it as one would let the same lineage occupy two
//!    slots of the bound.
//!
//! Both rows then reach [`BoundedBacklog::restored`], which resolves two
//! records naming ONE candidate by taking the highest candidate REVISION —
//! and the merge advanced the survivor's revision, so the accumulated entry
//! is the one that survives the restore.
//!
//! # An unresolved external effect is the third receipt-shaped row
//!
//! `improvement_candidate_dispatch::commit_unknown_effect_obligation` commits a
//! named unresolved effect under the SAME closed `candidate` kind, as
//! `{unknown_effect_obligation, retry_permitted, completion_retained}`.
//! It is classified here for the same reason the merge receipt is: this read is
//! exhaustive and fail-closed, so a document shape it does not recognise
//! refuses the WHOLE enumeration. An effect owner could not settle a debt this
//! daemon was unable to record, and the debt itself would stop every later pass
//! from rebuilding its registry — which is the exact "looks empty" failure this
//! module exists to prevent, reached from the opposite direction.
//!
//! What it is NOT given is registry meaning. An obligation names a candidate
//! whose EXTERNAL effect outcome is unresolved; it carries no candidate, no
//! brief and no owner decision, so there is nothing in it to re-prove as a
//! registry entry, and it neither adds an active candidate nor removes one.
//! Whether that effect may be attempted again is the Governor owner's own
//! question, answered by the obligation's own retry gate — not by this read
//! deciding to withhold a candidate. It is recognised, re-proved as a
//! self-binding record whose commitment identity is checked by the OWNER's own
//! `ImprovementUnknownEffectIdentity::validate`, and dropped; see the
//! `Reconciliation` row of `Row`.
//!
//! # A terminal improvement decision is the next row of the same closed kind
//!
//! `improvement_candidate_dispatch::commit_improvement_terminal_decision`
//! commits the Governor owner's own `ImprovementTerminalDecision` as
//! `{improvement_terminal_decision, retry_permitted, completion_retained}`: the
//! pipeline's advisory-only disposition verbatim, bound to the candidate
//! identity AND the candidate revision it was made on, to the exact bounded
//! experiment, to the exact committed proposal bytes when the run reached the
//! admitted branch, and to the independent evaluation record the verdict was made
//! against.
//!
//! It arrives here for the same reason the obligation does — this read is
//! exhaustive and fail-closed, so an untaught shape would refuse the WHOLE
//! enumeration and stop every later pass from rebuilding its registry — and it is
//! re-proved differently. Where the obligation re-proves itself, this one is
//! checked through the OWNER's own
//! `ImprovementTerminalDecision::validate`: that is the contract that produced the
//! record, so it is the right place to decide whether a canary admission really
//! arrived with an executed, independent, passing evaluation, whether a refusal
//! really committed no proposal bytes, and whether an admitted handoff disagrees
//! with the decision about its candidate, experiment, operation or commitment.
//! A disposition that contradicts the evidence recorded beside it is refused, not
//! read.
//!
//! Registry meaning it is not given either. It neither adds an active candidate
//! nor removes one: withholding the candidate it names would let a refused
//! candidate look unobserved, and restoring it as an entry would invent one.
//! Whether that decision may be attempted again is the Governor owner's question
//! through its own retry gate.
//!
//! # What is NOT claimed
//!
//! Restoring the registry makes the merge decision real and durable-adjacent.
//! It does not re-populate [`TrackedCandidate::merged_from`] on a restored
//! entry: the entry the merge built carries that absorbed-id list, and the
//! record this module reads carries it durably, but the backlog's own restore
//! builds its entries through a constructor that accepts no absorbed-id input.
//! So the absorbed ids are durable and re-proved here, and the registry's own
//! `merged_from` bookkeeping is empty on a restored entry. What is NOT lost is
//! the thing the merge is FOR: the unioned lineage, which is inside the
//! restored entry's candidate and is what the next admission is matched on.
//!
//! # Scope
//!
//! The read is `ExactFence` on the fence this pass admitted under, and
//! `store_named_async` independently refuses any request whose fence is not
//! the daemon's own admitted snapshot fence. The caller therefore cannot read
//! the registry at a fence other than the one the admission will use; if the
//! Kernel or composition fence moves between the read and the admission, the
//! daemon re-checks that under a fresh borrow and refuses the pass, exactly
//! as its Skill and ControlBoard reads already do.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::StateFence;
use eliot_improvement::candidate_bounds::{
    ArchivedCandidate, BoundedBacklog, BoundsError, CandidateBoundPolicy, DurableCandidateRecord,
    TrackedCandidate, canonical_evidence_lineage, evidence_lineage_digest,
};
use eliot_improvement::{
    ImprovementBrief, ImprovementCandidate, ImprovementLifecycle, OwnerDecision,
};
use eliot_maintenance::ImprovementUnknownEffectIdentity;
use eliot_store_api::{
    EXPERIENCE_PAGE_NEXT_CURSOR, EXPERIENCE_PAGE_RECORDS, EXPERIENCE_PAGE_STATE_FENCE,
    EXPERIENCE_PAGE_TRUNCATED, LEARNING_PARAM_CURSOR, LearningRecordKind,
    MAX_LEARNING_PAGE_RECORDS, NamedReadOperation, NamedReadRequest, NamedReadResponse, ScopeId,
    learning_record_read_request, sha256_hex,
};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::daemon_kernel_client::DaemonKernelClient;

/// Store scope carrying this daemon's durable improvement-candidate records.
///
/// This is the Governor-owned scope, read from the Governor's own published
/// constant rather than spelled here, and it is the same scope
/// `skill_dispatch::read_capability_evidence_records` addresses when it reads
/// the same owner rows. It matches the `governor` scope
/// `improvement_intake_dispatch` commits candidates under, which is what makes
/// a row this daemon wrote visible to this read.
const DEDUP_SCOPE: &str = eliot_governor::GOVERNOR_SCOPE_ID;

/// Fail-closed refusals from the bounded dedup-registry read.
///
/// Every variant means NO registry was established. None of them is an empty
/// registry, and a caller that treats one as "nothing was there" reintroduces
/// exactly the gap this module closes.
// `Eq` is deliberately absent: the `Registry` variant carries the crate's own
// `BoundsError`, which holds an `f64` value and therefore derives `PartialEq`
// only. Claiming `Eq` here would be a stronger guarantee than the wrapped
// refusal can carry (E0277).
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ImprovementDedupReadError {
    /// The closed read could not be planned, or the scope is not a contract
    /// value.
    #[error("improvement dedup read request is invalid: {0}")]
    Request(String),
    /// The authenticated Kernel read did not resolve.
    #[error("improvement dedup read transport failed: {0}")]
    Transport(String),
    /// The response answers a different operation or fence than the planned
    /// read, or is not a well-formed response.
    #[error("improvement dedup read response does not answer the planned read: {0}")]
    ResponseMismatch(&'static str),
    /// The served payload is not the versioned learning-record page shape.
    #[error("improvement dedup read payload is not the versioned shape: {0}")]
    Payload(&'static str),
    /// The enumeration did not reach the store's own end-of-page signal.
    ///
    /// This is the incomplete-read direction stated as a refusal: a partial
    /// page cannot stand in for the candidate scope, because absence of a
    /// record in a partial page proves nothing about its absence from the
    /// owner.
    #[error("improvement dedup read did not enumerate the whole candidate scope: {0}")]
    IncompleteEnumeration(String),
    /// A served row is not a decodable, content-validated prior candidate.
    #[error("candidate record {handle} is not a prior candidate: {detail}")]
    RowNotPriorCandidate { handle: String, detail: String },
    /// The reconstructed registry was refused by the bounded backlog itself.
    #[error("restored dedup registry refused: {0}")]
    Registry(#[from] BoundsError),
}

/// The committed improvement-candidate artifact document.
///
/// Exactly the shape `commit_improvement_artifact` writes:
/// `{candidate, brief, owner_decision, enforced_bound, governed_admission_digest}`.
/// `governed_admission_digest` is read as a presence requirement rather than
/// decoded into a typed owner value: the Governor mints it, the daemon has no
/// `LearningAdmissionPermit` to re-verify it against, and the merge decision
/// below is made from the candidate's own lineage rather than from it.
///
/// Unknown fields are DENIED, so a document that has drifted from the committed
/// artifact shape cannot decode into a partial read of one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateArtifactDocument {
    candidate: ImprovementCandidate,
    brief: ImprovementBrief,
    owner_decision: OwnerDecision,
    enforced_bound: CandidateBoundPolicy,
    governed_admission_digest: String,
}

/// A committed archive receipt for a candidate.
///
/// Exactly the shape `commit_archive_receipt` writes:
/// `{archived_candidate, disposition}`. It is read here so the candidate ids
/// it names can be kept OUT of the restored active set, and the disposition it
/// records is re-checked as terminal — a receipt is by definition a recorded
/// decision, and a receipt claiming a still-open lifecycle is refused rather
/// than read as an archival.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveReceiptDocument {
    archived_candidate: ArchivedCandidate,
    disposition: ImprovementLifecycle,
}

/// A committed lineage-merge receipt.
///
/// Exactly the shape `commit_lineage_merge_receipt` writes:
/// `{merged_survivor, absorbed_candidate_id}`. `merged_survivor` is the
/// surviving [`TrackedCandidate`] verbatim — the registry entry as the merge
/// left it — and is read for the accumulated state it carries, not for the fact
/// that a merge was recorded. `absorbed_candidate_id` is the candidate the
/// merge consumed, which must not come back as a second active entry.
///
/// Unknown fields are DENIED, as on the other two document shapes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageMergeReceiptDocument {
    merged_survivor: TrackedCandidate,
    absorbed_candidate_id: String,
}

/// A committed unresolved external-effect obligation.
///
/// Exactly the shape `commit_unknown_effect_obligation` writes:
/// `{unknown_effect_obligation, retry_permitted, completion_retained}`.
///
/// It is a DEBT record, not a candidate: it names the candidate whose external
/// effect outcome is unresolved, but it carries no candidate, no brief, and no
/// owner decision, so there is nothing here to re-prove as a registry entry. It
/// is still classified rather than refused, because this read is exhaustive and
/// fail-closed: an unrecognised document under the closed `candidate` kind
/// refuses the WHOLE read, and a debt the effect owner owes would then stop
/// every later pass from rebuilding its deduplication registry. The obligation
/// must therefore be recognised, and recognised as what it is.
///
/// Unknown fields are DENIED, as on the other document shapes, so a spliced
/// document cannot be read as an obligation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationObligationDocument {
    unknown_effect_obligation: ImprovementUnknownEffectIdentity,
    retry_permitted: bool,
    completion_retained: bool,
}

// The owner-facing identity inside a committed reconciliation record.
//
// This is the Governor owner's OWN record,
// `eliot_maintenance::ImprovementUnknownEffectIdentity`, decoded with the
// owner's own `deny_unknown_fields` decoder rather than as a second
// daemon-local shape. That is the point: the durable debt is re-proved against
// the contract that produced it, and a record carrying an identity the pipeline
// never committed cannot decode as one.
// `ImprovementUnknownEffectIdentity::validate` then re-checks the ORIGINAL
// recorded domain, encoding revision and algorithm of the retained commitment
// against the owner's own constants, which is a content check of the committed
// proposal bytes rather than a presence check on an operation reference.
//
// It is re-proved here as the other three shapes are: an obligation naming no
// candidate, no owner or no experiment is a spliced document, and a debt nobody
// owns is not a debt this registry can treat as recorded.

/// One served page of the bounded candidate read.
pub struct CandidatePage {
    /// Projected rows, verbatim.
    pub rows: Vec<Value>,
    /// The store's own continuation cursor, present only when the page was
    /// truncated.
    pub next_cursor: Option<String>,
}

/// Plans one page of the closed bounded candidate read.
///
/// The request carries only the catalogue-declared selectors — the closed
/// `record_kind`, the `max_records` page bound, and the optional opaque
/// `cursor` continuation — plus the typed scope and `ExactFence`
/// consistency. The page bound is the store's own
/// [`MAX_LEARNING_PAGE_RECORDS`]; no free text ever becomes a selector, and no
/// handle selector exists to smuggle one in.
pub fn plan_candidate_page(
    admitted_fence: &StateFence,
    cursor: Option<&str>,
) -> Result<NamedReadRequest, ImprovementDedupReadError> {
    let scope = ScopeId::new(DEDUP_SCOPE)
        .map_err(|error| ImprovementDedupReadError::Request(error.to_string()))?;
    let mut request = learning_record_read_request(
        scope,
        Some(LearningRecordKind::Candidate),
        MAX_LEARNING_PAGE_RECORDS,
        admitted_fence.clone(),
    );
    if let Some(cursor) = cursor {
        request.parameters.insert(
            LEARNING_PARAM_CURSOR.to_owned(),
            Value::String(cursor.to_owned()),
        );
    }
    request
        .validate()
        .map_err(|error| ImprovementDedupReadError::Request(error.to_string()))?;
    Ok(request)
}

/// Resolves one served page, re-proving that it answers exactly the planned
/// read before any row is read.
///
/// Checked here, in the order the guarantees are stated: operation identity
/// against the planned read, fence equality against the request's exact fence,
/// response shape, and the payload's own fence echo. The page's truncation
/// flag and continuation cursor are then read as the STORE's statements about
/// its own enumeration — the caller never decides whether it has seen enough.
pub fn resolve_candidate_page(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> Result<CandidatePage, ImprovementDedupReadError> {
    if response.operation != NamedReadOperation::GetLearningRecordRange
        || response.operation != request.operation
    {
        return Err(ImprovementDedupReadError::ResponseMismatch("operation"));
    }
    if response.state_fence != request.state_fence {
        return Err(ImprovementDedupReadError::ResponseMismatch("fence"));
    }
    response
        .validate()
        .map_err(|_| ImprovementDedupReadError::ResponseMismatch("shape"))?;
    let payload_fence: StateFence = serde_json::from_value(
        response
            .payload
            .get(EXPERIENCE_PAGE_STATE_FENCE)
            .cloned()
            .ok_or(ImprovementDedupReadError::Payload("state_fence"))?,
    )
    .map_err(|_| ImprovementDedupReadError::Payload("state_fence"))?;
    if payload_fence != response.state_fence {
        return Err(ImprovementDedupReadError::ResponseMismatch("payload_fence"));
    }
    let truncated = response
        .payload
        .get(EXPERIENCE_PAGE_TRUNCATED)
        .and_then(Value::as_bool)
        .ok_or(ImprovementDedupReadError::Payload("truncated"))?;
    let rows = response
        .payload
        .get(EXPERIENCE_PAGE_RECORDS)
        .and_then(Value::as_array)
        .ok_or(ImprovementDedupReadError::Payload("records"))?
        .clone();
    // A truncated page with no usable continuation cursor is an incomplete
    // enumeration, not an end. Reading it as an end is exactly how a partial
    // page would look like an empty registry.
    let next_cursor = if truncated {
        let cursor = response
            .payload
            .get(EXPERIENCE_PAGE_NEXT_CURSOR)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|cursor| !cursor.is_empty())
            .ok_or_else(|| {
                ImprovementDedupReadError::IncompleteEnumeration(
                    "the store reported a further candidate page and issued no continuation cursor"
                        .to_owned(),
                )
            })?;
        Some(cursor.to_owned())
    } else {
        None
    };
    Ok(CandidatePage { rows, next_cursor })
}

/// Reads the whole candidate scope for this pass, at the admitted fence.
///
/// Follows the store's own `next_cursor` to its authoritative end. Executed
/// WITHOUT the composition lock, exactly like the acceptance and evidence
/// reads: the caller captures immutable input under a short borrow, awaits
/// this without any mutex, and re-checks the fence under a fresh borrow before
/// it admits.
///
/// A refused or unexhausted read is an error, never an empty registry.
pub async fn read_candidate_scope(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
) -> Result<Vec<Value>, ImprovementDedupReadError> {
    let mut rows: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let request = plan_candidate_page(admitted_fence, cursor.as_deref())?;
        let response = kernel
            .store_named_async(request.clone())
            .await
            .map_err(|error| ImprovementDedupReadError::Transport(error.to_string()))?;
        let page = resolve_candidate_page(&request, &response)?;
        rows.extend(page.rows);
        let Some(next) = page.next_cursor else {
            return Ok(rows);
        };
        // A cursor that does not advance cannot lead anywhere: following it
        // again would serve the same page forever. That is a store fault, and
        // the only honest outcome is a refusal.
        if cursor.as_deref() == Some(next.as_str()) {
            return Err(ImprovementDedupReadError::IncompleteEnumeration(format!(
                "the store reissued continuation cursor {next} without advancing the enumeration"
            )));
        }
        cursor = Some(next);
    }
}

/// Rebuilds the bounded deduplication registry from an EXHAUSTIVE page set.
///
/// This is the reconstruction. Every row is re-proved against the bytes and the
/// closed kind the store served (see the module docs for the exact checks), a
/// candidate id named by any archive receipt in the same read is kept out of
/// the active set, and the surviving records are handed to
/// [`BoundedBacklog::restored`], which re-proves each candidate and computes
/// its lineage digest from its own canonical evidence lineage.
///
/// Two row shapes are recognised, re-proved, and deliberately NOT turned into
/// registry entries: a committed unresolved external-effect obligation, and a
/// committed terminal improvement decision. Both are facts ABOUT a candidate
/// rather than observations OF one, so neither adds an active candidate nor
/// removes one — see the module documentation for why withholding the candidate
/// either names would be the worse error.
///
/// `bound` is the bound this pass will enforce, read from the maintenance
/// (`G-19`) owner's own decision record. It is passed in rather than invented
/// here for the same reason the records are: the daemon spells no bound number
/// of its own.
pub fn restored_registry(
    rows: &[Value],
    bound: CandidateBoundPolicy,
) -> Result<BoundedBacklog, ImprovementDedupReadError> {
    let mut records: Vec<DurableCandidateRecord> = Vec::new();
    // Candidate ids a committed archive receipt has already taken out of the
    // active set. Collected across the WHOLE read before any record is
    // admitted into the registry, so a receipt on a later page still governs a
    // candidate row from an earlier one.
    let mut archived: BTreeSet<String> = BTreeSet::new();
    // Candidate ids a committed lineage-merge receipt consumed. Same whole-read
    // rule, and the same direction: a merged candidate is not an active entry,
    // it is lineage the survivor carries.
    let mut absorbed: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        match classify_row(row)? {
            Row::Candidate(record) => records.push(*record),
            Row::Merged {
                survivor,
                absorbed_candidate_id,
            } => {
                absorbed.insert(absorbed_candidate_id);
                records.push(*survivor);
            }
            Row::Archived(candidate_id) => {
                archived.insert(candidate_id);
            }
            // A reconciliation obligation names a candidate whose EXTERNAL effect
            // is unresolved; a terminal DECISION names a candidate the pipeline
            // already disposed of. Both are facts ABOUT a candidate rather than
            // observations OF one, and both contribute no registry entry, which is
            // why they share one arm: excluding either here would be wrong for this
            // read's own question — whether the same evidence lineage was already
            // observed as a candidate — and the debt and the decision each record
            // are settled by their own owners (the effect owner's retry gate and the
            // Governor admission gate), not by the registry refusing to restore a
            // candidate. Both are recognised, re-proved, dropped, and the pass
            // continues. They are re-proved differently before they get here: the
            // obligation against `ImprovementUnknownEffectIdentity::validate`, the
            // decision against `ImprovementTerminalDecision::validate`, so a
            // decision whose disposition disagrees with the evidence it also
            // carries is refused rather than read.
            Row::Reconciliation | Row::Decision => {}
        }
    }
    records.retain(|record| {
        let candidate_id = &record.candidate.candidate_id;
        !archived.contains(candidate_id) && !absorbed.contains(candidate_id)
    });
    Ok(BoundedBacklog::restored(vec![bound], records)?)
}

/// One served row, classified by what its document actually is.
///
/// The candidate arm is boxed: `DurableCandidateRecord` carries a whole
/// `ImprovementCandidate`, so inlining it would make every `Archived` row pay
/// for a candidate it does not hold (`clippy::large_enum_variant`).
enum Row {
    /// A committed candidate artifact that qualifies as a prior candidate.
    Candidate(Box<DurableCandidateRecord>),
    /// A committed lineage-merge receipt: the surviving entry with the
    /// accumulated state the merge produced, plus the candidate id it consumed.
    Merged {
        survivor: Box<DurableCandidateRecord>,
        absorbed_candidate_id: String,
    },
    /// A committed archive receipt naming the candidate id it removed from the
    /// active set.
    Archived(String),
    /// A committed unresolved external-effect obligation: a recorded debt owed
    /// by a named external effect owner.
    ///
    /// It carries no candidate content, so it is neither a registry entry nor
    /// an archive or merge receipt: it neither adds an active candidate nor
    /// removes one. The arm exists so this exhaustive read can classify the
    /// record instead of refusing the whole enumeration over it, and so the
    /// shape is stated here rather than defaulted past.
    Reconciliation,
    /// A committed terminal improvement decision: the pipeline's own advisory-only
    /// disposition, bound to the candidate identity and revision it was made on,
    /// to the exact bounded experiment, and to the independent evaluation record
    /// the verdict was made against.
    ///
    /// It is a DECISION about a candidate, not a candidate: it carries no
    /// candidate, brief or owner decision, so there is nothing in it to re-prove
    /// as a registry entry, and it neither adds an active candidate nor removes
    /// one. The arm exists for the same reason the reconciliation arm does — this
    /// read is exhaustive and fail-closed, so an untaught shape would refuse the
    /// WHOLE enumeration and stop every later pass from rebuilding its registry —
    /// and additionally because the decision is re-proved here against the
    /// Governor OWNER's own contract rather than trusted. See
    /// [`classify_terminal_decision`].
    Decision,
}

/// A committed terminal improvement decision.
///
/// Exactly the shape `commit_improvement_terminal_decision` writes:
/// `{improvement_terminal_decision, retry_permitted, completion_retained}`.
///
/// The inner record is the Governor owner's OWN
/// [`eliot_maintenance::ImprovementTerminalDecision`], decoded with that crate's
/// own `deny_unknown_fields` decoder and then re-proved by that same owner's
/// `ImprovementTerminalDecision::validate`. The durable decision is therefore
/// checked against the contract that produced it rather than against a second
/// daemon-local shape that could drift away from it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalDecisionDocument {
    improvement_terminal_decision: eliot_maintenance::ImprovementTerminalDecision,
    retry_permitted: bool,
    completion_retained: bool,
}

/// Re-proves one committed terminal decision and accepts it as a decision record.
///
/// Split out of [`classify_row`] so each row shape's re-proof reads on its own.
///
/// Three checks, and the first is the OWNER's. Everything a later reader could
/// otherwise have to take on trust about a durable decision — that it names a
/// candidate, a proposal, a bounded experiment and an operation; that its
/// disposition is the one its own bound records support; that a canary
/// admission really arrived with an executed, independent, passing evaluation and
/// with committed proposal bytes; that a refusal really committed none — is
/// decided by `eliot_maintenance::ImprovementTerminalDecision::validate`, the
/// owner's own method, over the ORIGINAL recorded values. Nothing is recomputed
/// over what this process happens to hold, and no digest stands in for a record
/// this build cannot read.
///
/// The second check is the same cross-check the reconciliation record uses: a
/// record claiming both a permitted retry and a retained completion is mutually
/// exclusive by construction in the owner, so a document claiming both is a
/// spliced document and is refused.
///
/// The third check re-proves that an evaluation record, when the decision carries
/// one, actually names its evidence identity and the content revision it
/// observed. Those two are present on every evaluation record this path has ever
/// produced, including the never-ran one, so an evaluation record that names
/// neither is not a record of an evaluation and the decision is refused rather
/// than read as one that was judged against something. The run reference is
/// deliberately NOT required here: it is empty on exactly the decisions whose
/// evaluation never ran, and requiring it would refuse the honest refusals while
/// accepting nothing extra.
///
/// The decision is accepted for what it is and then DROPPED: it does not add or
/// remove a candidate, so restoring it as a registry entry would invent one, and
/// withholding the candidate it names would let a refused candidate look
/// unobserved. Whether that decision may be attempted again is the Governor
/// owner's own question through its own retry gate.
fn classify_terminal_decision(
    document: Value,
    refused: &impl Fn(String) -> ImprovementDedupReadError,
) -> Result<Row, ImprovementDedupReadError> {
    let receipt: TerminalDecisionDocument = serde_json::from_value(document)
        .map_err(|error| refused(format!("terminal decision does not decode: {error}")))?;
    let decision = &receipt.improvement_terminal_decision;
    decision.validate().map_err(|error| {
        refused(format!(
            "terminal decision is not a re-provable Governor-owned decision: {error}"
        ))
    })?;
    if receipt.retry_permitted && receipt.completion_retained {
        return Err(refused(
            "terminal decision claims both a permitted retry and a retained completion".to_owned(),
        ));
    }
    if let Some(evaluation) = decision.evaluation.as_ref() {
        for (name, value) in [
            ("evidence_id", evaluation.evidence_id.as_str()),
            (
                "content_revision_ref",
                evaluation.content_revision_ref.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(refused(format!(
                    "terminal decision's evaluation record names no {name}"
                )));
            }
        }
    }
    Ok(Row::Decision)
}

/// Re-proves one lineage-merge receipt and returns what it merged.
///
/// Split out of [`classify_row`] so each row shape's re-proof reads on its own.
/// Every check here is a content check against the surviving entry's own
/// recorded material: the accumulated lineage is recomputed from the surviving
/// candidate's canonical evidence refs rather than accepted from the receipt's
/// `lineage_digest` field, so a row cannot claim an accumulation its candidate
/// does not carry.
fn classify_merge_receipt(
    document: Value,
    refused: &impl Fn(String) -> ImprovementDedupReadError,
) -> Result<Row, ImprovementDedupReadError> {
    let receipt: LineageMergeReceiptDocument = serde_json::from_value(document)
        .map_err(|error| refused(format!("lineage merge receipt does not decode: {error}")))?;
    let survivor_id = receipt
        .merged_survivor
        .candidate
        .candidate_id
        .trim()
        .to_owned();
    let absorbed_candidate_id = receipt.absorbed_candidate_id.trim().to_owned();
    if survivor_id.is_empty() {
        return Err(refused(
            "lineage merge receipt names no surviving candidate".to_owned(),
        ));
    }
    if absorbed_candidate_id.is_empty() || absorbed_candidate_id == survivor_id {
        return Err(refused(
            "lineage merge receipt names no distinct absorbed candidate".to_owned(),
        ));
    }
    // The accumulated lineage is the merge's own result, so the receipt's
    // `lineage_digest` is recomputed here from the surviving candidate's OWN
    // canonical evidence lineage and compared. A digest that disagrees would
    // let a row claim an accumulation its candidate does not carry.
    let lineage = canonical_evidence_lineage(&receipt.merged_survivor.candidate.evidence_refs);
    if lineage.is_empty() {
        return Err(refused(
            "the surviving candidate carries no canonical evidence lineage".to_owned(),
        ));
    }
    if evidence_lineage_digest(&lineage) != receipt.merged_survivor.lineage_digest {
        return Err(refused(
            "the recorded lineage digest is not the digest of the surviving candidate's own evidence lineage"
                .to_owned(),
        ));
    }
    receipt
        .merged_survivor
        .candidate
        .validate()
        .map_err(|error| {
            refused(format!(
                "stored surviving candidate does not validate: {error}"
            ))
        })?;
    let survivor = receipt.merged_survivor;
    // `into_entry` re-computes the lineage digest from the candidate's own
    // evidence refs and re-proves the candidate, so the restored entry carries
    // the union rather than the receipt's assertion of it. The entry's retained
    // value, owner and admission authority are the ones the merge kept, not a
    // value re-invented here.
    Ok(Row::Merged {
        survivor: Box::new(DurableCandidateRecord {
            owner: survivor.owner.clone(),
            admitted_under_authority: survivor.admitted_under_authority.clone(),
            admitted_value_floor: survivor.value,
            candidate: survivor.candidate,
        }),
        absorbed_candidate_id,
    })
}

/// Re-proves one unresolved external-effect obligation and accepts it as a debt
/// record.
///
/// Split out of [`classify_row`] so this row shape's re-proof reads on its own,
/// exactly as the merge receipt's does.
///
/// Four checks, all content. The first is the OWNER's own content check:
/// `ImprovementUnknownEffectIdentity::validate` re-checks the ORIGINAL recorded
/// domain, encoding revision and algorithm of the retained commitment against
/// the Governor owner's own constants, so a debt whose commitment was written
/// under an identity this build does not read is refused here rather than
/// treated as a recorded debt. The second is self-binding: every identity the
/// Governor pipeline copied into the obligation must be present and non-empty,
/// because a record naming an effect nobody owns, over no experiment, under no
/// committed operation, is not a recorded debt. The third is a cross-check on
/// the two answers the Governor gate gave. They are mutually exclusive BY
/// CONSTRUCTION there, so a record claiming both a permitted retry and a
/// retained completion is a spliced document and is refused rather than read.
/// The fourth re-proves the quarantine scope the obligation carries.
///
/// The operation and idempotency identities are read out of the retained
/// commitment rather than from loose sibling fields, because a second spelling
/// of them in the document is a second claim about the same operation: the
/// commitment is what the pipeline committed and what the owner re-checks a
/// receipt against.
///
/// This read restores a candidate registry; it decides nothing about whether an
/// effect may be retried, and the cross-check exists only so the recorded
/// answers stay the owner's distinguishable ones.
fn classify_reconciliation_obligation(
    document: Value,
    refused: &impl Fn(String) -> ImprovementDedupReadError,
) -> Result<Row, ImprovementDedupReadError> {
    let receipt: ReconciliationObligationDocument =
        serde_json::from_value(document).map_err(|error| {
            refused(format!(
                "reconciliation obligation does not decode: {error}"
            ))
        })?;
    let obligation = &receipt.unknown_effect_obligation;
    // The OWNER's own content check over the ORIGINAL recorded commitment
    // identity. It reads the values the producer recorded and compares them
    // with the Governor owner's constants; nothing is recomputed over what
    // this process happens to hold, and no digest stands in for a record this
    // build cannot read.
    obligation.validate().map_err(|error| {
        refused(format!(
            "reconciliation obligation is not the checked commitment identity: {}",
            error.component
        ))
    })?;
    for (name, value) in [
        ("candidate_id", obligation.candidate_id.as_str()),
        ("owner_id", obligation.owner_id.as_str()),
        ("experiment_id", obligation.experiment_id.as_str()),
        (
            "operation_ref",
            obligation.commitment.operation_ref.as_str(),
        ),
        (
            "idempotency_key",
            obligation.commitment.idempotency_key.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(refused(format!(
                "reconciliation obligation names no {name}"
            )));
        }
    }
    if receipt.retry_permitted && receipt.completion_retained {
        return Err(refused(
            "reconciliation obligation claims both a permitted retry and a retained completion"
                .to_owned(),
        ));
    }
    // The quarantine scope the obligation carries is re-proved rather than
    // trusted, in the direction that can only narrow what a reader believes: a
    // repeated target names a weaker quarantine than the same set deduped, and
    // an obligation that names no target at all would carry no repair scope.
    // A repeated target is refused rather than silently deduped, because the
    // Governor owner committed this set in its own order and a record that
    // disagrees with it is a spliced document.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    if obligation.invalidation_set.is_empty() {
        return Err(refused(
            "reconciliation obligation names no invalidation target".to_owned(),
        ));
    }
    for target in &obligation.invalidation_set {
        let target = target.trim();
        if target.is_empty() {
            return Err(refused(
                "reconciliation obligation names an empty invalidation target".to_owned(),
            ));
        }
        if !seen.insert(target) {
            return Err(refused(format!(
                "reconciliation obligation repeats invalidation target {target}"
            )));
        }
    }
    // The forward-repair binding is read for consistency, not strengthened: an
    // ABSENT forward-repair reference is a real value this daemon's own records
    // carry, so it is not refused here, but a reference that is present and
    // blank names no repair path and is a spliced document.
    if !obligation.forward_repair_ref.is_empty() && obligation.forward_repair_ref.trim().is_empty()
    {
        return Err(refused(
            "reconciliation obligation carries a blank forward-repair reference".to_owned(),
        ));
    }
    Ok(Row::Reconciliation)
}

/// One projected field of a served row, read verbatim.
///
/// The learning owner projects each row as
/// `{record_kind, handle, record_json, record_digest}`. A row missing any of
/// them is refused by the caller rather than half-read.
fn row_text<'a>(row: &'a Value, name: &str) -> Option<&'a str> {
    row.get(name).and_then(Value::as_str)
}

/// Re-proves one served row and classifies it.
///
/// The digest check is over the exact bytes the store returned: the learning
/// owner keys rows by `(record_kind, handle, record_digest)` and publishes no
/// per-row commit order, so the presented digest IS the row's revision
/// identity. A row whose digest does not cover its own document is refused
/// rather than read.
fn classify_row(row: &Value) -> Result<Row, ImprovementDedupReadError> {
    let handle = row
        .get("handle")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let refused = |detail: String| ImprovementDedupReadError::RowNotPriorCandidate {
        handle: handle.clone(),
        detail,
    };
    let missing = |name: &str| refused(format!("row is missing {name}"));
    let record_kind = row_text(row, "record_kind").ok_or_else(|| missing("record_kind"))?;
    let record_json = row_text(row, "record_json").ok_or_else(|| missing("record_json"))?;
    let record_digest = row_text(row, "record_digest").ok_or_else(|| missing("record_digest"))?;
    if record_kind != LearningRecordKind::Candidate.as_str() {
        return Err(refused("row is not a closed candidate record".to_owned()));
    }
    if sha256_hex(record_json.as_bytes()) != record_digest {
        return Err(refused(
            "presented row digest does not cover the served record bytes".to_owned(),
        ));
    }
    let document: Value = serde_json::from_str(record_json)
        .map_err(|error| refused(format!("record document is not JSON: {error}")))?;

    // An archive receipt is a legitimate row of the same closed kind, and it is
    // a recorded TERMINAL disposition. It is read for the id it removes, not
    // skipped: skipping it would let the candidate it names come back as an
    // active entry.
    if document.get("archived_candidate").is_some() {
        let receipt: ArchiveReceiptDocument = serde_json::from_value(document)
            .map_err(|error| refused(format!("archive receipt does not decode: {error}")))?;
        if !receipt.disposition.is_terminal() {
            return Err(refused(
                "archive receipt records a lifecycle that is not a terminal disposition".to_owned(),
            ));
        }
        let candidate_id = receipt.archived_candidate.candidate_id.trim().to_owned();
        if candidate_id.is_empty() {
            return Err(refused("archive receipt names no candidate".to_owned()));
        }
        return Ok(Row::Archived(candidate_id));
    }

    // A lineage-merge receipt is the second legitimate row of the same closed
    // kind, and it is read for WHAT it merged, not for the fact that a merge
    // was recorded. A receipt whose surviving entry names no lineage, whose
    // recorded lineage digest is not the digest of that entry's OWN canonical
    // evidence lineage, or that names itself as the absorbed candidate is a
    // spliced document, and every one of those is refused rather than read.
    if document.get("merged_survivor").is_some() {
        return classify_merge_receipt(document, &refused);
    }

    // An unresolved external-effect obligation is the third legitimate row of the
    // same closed kind. It is recognised so the enumeration completes, and it
    // is re-proved rather than trusted: the document must bind itself, naming a
    // candidate, a distinct external owner, an experiment, and the committed
    // operation and idempotency namespace the Governor owner re-checks any
    // receipt against. A debt with an empty identity is a spliced document, and
    // a spliced document is refused here exactly as everywhere else in this
    // read.
    if document.get("unknown_effect_obligation").is_some() {
        return classify_reconciliation_obligation(document, &refused);
    }

    // A terminal improvement decision is the FOURTH legitimate row of the same
    // closed kind, and the only one this read re-proves through the OWNER's own
    // method rather than through local checks: `ImprovementTerminalDecision::
    // validate` is the contract that produced the record, so it is the right place
    // to decide whether a canary admission really arrived with an executed,
    // independent, passing evaluation and whether a refusal really committed no
    // proposal bytes. A disposition that disagrees with the evidence recorded
    // beside it is refused here exactly as a spliced obligation is.
    if document.get("improvement_terminal_decision").is_some() {
        return classify_terminal_decision(document, &refused);
    }

    let artifact: CandidateArtifactDocument =
        serde_json::from_value(document).map_err(|error| {
            refused(format!(
                "record is neither a committed candidate artifact, nor an archive receipt, nor a lineage merge receipt, nor a reconciliation obligation, nor a terminal improvement decision: {error}"
            ))
        })?;
    // The document must bind ITSELF. A brief or an owner decision that names a
    // different candidate, or a decision that names a different brief, is a
    // spliced document: reading its owner or its evidence refs as this
    // candidate's would be trusting a string.
    let candidate_id = artifact.candidate.candidate_id.trim();
    if artifact.brief.candidate_id.trim() != candidate_id
        || artifact.owner_decision.candidate_id.trim() != candidate_id
    {
        return Err(refused(
            "the committed brief or owner decision names a different candidate".to_owned(),
        ));
    }
    if artifact.owner_decision.brief_id.trim() != artifact.brief.brief_id.trim() {
        return Err(refused(
            "the committed owner decision names a different brief".to_owned(),
        ));
    }
    // The recorded decision owner is the principal that RECORDED this
    // disposition, which is a different fact from the candidate's
    // `owner_and_decision_authority` — the authority that ADMITTED the
    // candidate, which `brief.rs` itself calls a separate owner decision and
    // the thing that admits the candidate to the backlog. Requiring
    // the two strings to be EQUAL therefore tested an accident, not an
    // invariant: it held only because both were the same constant, and the
    // first record written by a principal that actually selected a disposition
    // would have been refused as spliced — and refused on every later pass too,
    // because the registry re-reads the same durable rows each time. That is
    // why the equality is not kept and only its property is.
    //
    // What this read still proves is that the owner is a real principal, and
    // it proves it with the authority owner's own `PrincipalRef` constructor
    // rather than a predicate written here: that constructor refuses a blank,
    // whitespace-only or control-character value, and it is applied to the
    // ORIGINAL recorded string, not to a trimmed copy of it. A caller-declared
    // string is still not authority — admission is proved by `enforced_bound`
    // against a Governor-minted permit, the restored entry's owner is the
    // CANDIDATE's own authority and never this field, and the record's own
    // digest already covers this string, so it cannot be altered inside the
    // record without changing the revision identity the store keys the row by.
    eliot_authority::PrincipalRef::new(artifact.owner_decision.owner.as_str()).map_err(
        |error| {
            refused(format!(
                "recorded decision owner is not a principal: {error}"
            ))
        },
    )?;
    if artifact.governed_admission_digest.trim().is_empty() {
        return Err(refused(
            "record carries no owner-issued governed admission digest".to_owned(),
        ));
    }
    artifact.enforced_bound.validate().map_err(|error| {
        refused(format!(
            "recorded bound is not an owner-decided bound: {error}"
        ))
    })?;
    artifact
        .candidate
        .validate()
        .map_err(|error| refused(format!("stored candidate does not validate: {error}")))?;
    Ok(Row::Candidate(Box::new(DurableCandidateRecord {
        // The candidate is the record's own decoded content, and the entry's
        // lineage digest is computed from IT by `BoundedBacklog::restored`.
        owner: Some(artifact.candidate.owner_and_decision_authority.clone()),
        admitted_under_authority: Some(artifact.enforced_bound.governor_authority_ref.clone()),
        admitted_value_floor: artifact.enforced_bound.min_value,
        candidate: artifact.candidate,
    })))
}
