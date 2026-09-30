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
//!    document carries, and the recorded decision owner must be a real
//!    non-empty principal — the principal that SELECTED the disposition
//!    (I12.24:65), which is deliberately not required to be the authority the
//!    candidate NOMINATES (I12.24:31); see the note at `classify_row`;
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

    let artifact: CandidateArtifactDocument =
        serde_json::from_value(document).map_err(|error| {
            refused(format!(
                "record is neither a committed candidate artifact, nor an archive receipt, nor a lineage merge receipt: {error}"
            ))
        })?;
    // The document must bind ITSELF. A brief or an owner decision that names
    // a different candidate is a spliced document: reading its owner or its
    // evidence refs as this candidate's would be trusting a string. This is
    // where the anti-splice work actually happens, and it holds regardless of
    // WHICH principal decided.
    let candidate_id = artifact.candidate.candidate_id.trim();
    if artifact.brief.candidate_id.trim() != candidate_id
        || artifact.owner_decision.candidate_id.trim() != candidate_id
    {
        return Err(refused(
            "the committed brief or owner decision names a different candidate".to_owned(),
        ));
    }
    // The recorded decision owner is the principal that SELECTED the
    // disposition (I12.24:65: "decision owner selects reject / investigate /
    // work item / experiment"). The candidate's `owner_and_decision_authority`
    // is a different role (I12.24:31): the authority the candidate NOMINATES,
    // read back below as the restored entry's owner. Demanding the two be
    // the same string was not an anti-splice property at all — it asserts an
    // identity, and it can only ever hold while the machine decides about
    // itself, because the one moment a real principal selects a disposition is
    // the one moment the two names differ. It passed only for that reason, and
    // it is what made this read refuse the owner's own decision as a splice.
    //
    // What actually binds the decision to this document is the check above:
    // `owner_decision.candidate_id` is the candidate the decision was taken
    // over, and `brief.candidate_id` is the candidate the brief was written
    // for, so a decision lifted off another candidate cannot be read as this
    // one's. String equality against a nominated authority adds no binding to
    // that and no binding the digest does not already cover.
    //
    // So the surviving requirement on the owner is what A12.02:3 makes
    // load-bearing: "Unknown identity means minimum privilege and no Material
    // authority." A decision attributed to nobody is not a decision, and this
    // read will not present it as one. Nothing stronger is defensible HERE:
    // this module reads a stored document, and the principal that wrote it was
    // bound to a Session and an Authority Epoch at the harness boundary, not at
    // the moment of the read. The closed set of principals that may decide is
    // not a fact this document carries, and spelling one out here would be a
    // second identity scheme invented at a read site — the thing A12.02:3
    // warns against ("Identity is not a model's self-declared string"). The
    // admission of the decision stays where the principal is real: the governed
    // path that recorded it, under the recorded
    // `governed_admission_digest` checked below.
    if artifact.owner_decision.owner.trim().is_empty() {
        return Err(refused(
            "the recorded decision names no principal".to_owned(),
        ));
    }
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
