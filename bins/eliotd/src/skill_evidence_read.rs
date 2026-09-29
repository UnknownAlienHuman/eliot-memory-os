//! Bounded named owner reads qualifying Skill activation and execution
//! ingests (issue #2663, I7.25 / I12.24 / I15.2).
//!
//! The `Activate` and `Execute` legs arrive over the authenticated
//! host-request route carrying a *historical* observation: a harness receipt
//! or an execution-evidence window describing an agent attempt that already
//! ran. Three identities are involved and are never interchangeable here:
//!
//! ```text
//! LocalReadAttempt   the authenticated ingest request admitted at the live
//!                    fence (what this daemon is allowed to do NOW);
//! attempt_ref        the HISTORICAL agent attempt the receipt observes
//!                    (what happened THEN);
//! operation_id       the Kernel admission identity of the ingest itself.
//! ```
//!
//! A receipt field never promotes itself into the first, and the first never
//! stands in for the second. Nothing here is decided by a presented string:
//! every load-bearing claim is a comparison against a canonical owner record
//! read through the same closed `NamedReadRequest` / `ExactFence` / response
//! re-verification discipline the acceptance read already uses
//! ([`crate::skill_acceptance_read`]).
//!
//! ## What the owner actually serves
//!
//! Two named reads are activated in the store catalogue and have proven
//! adapter handlers on both providers:
//!
//! * [`NamedReadOperation::GetCapabilityEvidenceState`] — the canonical
//!   `ApplyLifecyclePolicy` rows for one exact `skill_id`, which resolve the
//!   Skill revision/package the ingest is about, exactly as the intake leg
//!   already does. This is the Skill-owner read.
//! * [`NamedReadOperation::GetLearningRecordRange`] — durable same-scope
//!   learning rows keyed `(record_kind, handle, record_digest)`, with the
//!   closed `record_kind` filter (issue #1868, I12.24). The
//!   `activation_receipt` kind is the durable home of a harness activation
//!   receipt, and it is the ONLY activated read that returns a record
//!   document. This is the evidence-owner read.
//!
//! ## What is deliberately NOT claimed
//!
//! There is no activated read that returns a *verifier-run* record, and no
//! activated mutation that writes one. `SkillExecutionEvidence` is a wire
//! payload with no store-owned persistence path. Consequently a
//! `verified_outcome_ref` cannot be resolved to a verifier-run owner record
//! by any real producer today, and this module therefore reports usefulness
//! as **unestablished** rather than inventing a success port. The
//! qualification path is real and wired — it is simply fed by an owner that
//! has not yet published that record, which is exactly the honest state I7.25
//! asks for.
//!
//! What IS verified here is the verifier *contract*: every resolved outcome
//! record must name the canonically bound verifier for this exact
//! skill/package -- the deciding acceptance row's `verifier_ref` (I12.24
//! verifier competence) -- in its own `verifier_refs`. A real record naming
//! an unrelated verifier therefore cannot qualify, exactly as a real record
//! for an unrelated artifact cannot.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_skill::{
    EvidenceCoverage, SkillExecutionEvidence, SkillHarnessActivationReceipt, SourceRevision,
};
use eliot_store_api::{
    LearningRecordKind, MAX_LEARNING_PAGE_RECORDS, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, ReadConsistency, ScopeId,
};
use thiserror::Error;

use super::daemon_kernel_client::DaemonKernelClient;
use super::skill_acceptance_read::{AcceptanceResolution, AcceptanceVerdict};

/// Scope carrying the canonical Skill lifecycle-policy rows. Matches the
/// scope the Governor lifecycle owner stamps on its canonical envelopes; a
/// read under any other scope finds no rows and resolves Unknown.
const LIFECYCLE_SCOPE: &str = "governor";
/// Learning-record payload version served by the store adapter.
const LEARNING_PAYLOAD_VERSION: u64 = 1;

/// Closed source label for the Skill-owner lifecycle row revision.
pub const SOURCE_SKILL_LIFECYCLE: &str = "skill_lifecycle_row";
/// Closed source label for the evidence-owner activation-receipt revision.
pub const SOURCE_ACTIVATION_RECEIPT: &str = "activation_receipt";

/// Fail-closed errors for the bounded evidence owner reads.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EvidenceReadError {
    /// The store request is structurally invalid.
    #[error("evidence lookup read request is invalid: {0}")]
    Request(String),
    /// The store response answers a different operation, fence or scope than
    /// the planned read.
    #[error("evidence lookup response does not answer the planned read: {0}")]
    ResponseMismatch(&'static str),
    /// The store payload is not the versioned shape it claims to be.
    #[error("evidence lookup payload is not the versioned shape: {0}")]
    Payload(&'static str),
    /// The authenticated Kernel route failed before any record resolved.
    #[error("evidence lookup transport failed: {0}")]
    Transport(String),
}

/// What one bounded owner read established about the ingest subject.
///
/// A subject that could not be read is `Unavailable`, never "absent" and never
/// "clean": absence of a record is absence of evidence, so the qualification
/// it feeds stays unknown rather than becoming a negative fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectBinding {
    /// The Skill owner resolved this exact Skill identity at the current
    /// revision, with the load-bearing revisions listed.
    Resolved {
        /// Skill the rows selected.
        skill_id: String,
        /// Load-bearing owner revisions the resolution depended on.
        revisions: Vec<SourceRevision>,
    },
    /// The Skill owner resolved no row binding this Skill. The candidate stays
    /// unqualified: this is not a revocation, only absence of a row.
    Unresolved {
        /// Skill that was looked up.
        skill_id: String,
    },
}

/// Outcome of the bounded evidence-owner lookup for one receipt's presented
/// outcome references.
///
/// Today the activated learning-record read has no `verifier_run` kind and no
/// producer writes one, so this resolves to [`OutcomeResolution::NoOwnerRecord`]
/// — the honest, fail-closed state. The type exists so that when such a
/// producer lands, the qualification below is already wired to it rather than
/// needing a second, parallel scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeResolution {
    /// Owner records were resolved for some presented references.
    Resolved {
        /// Records matched, each with the owner revision it was read at.
        records: Vec<eliot_skill::ResolvedOutcome>,
    },
    /// No owner record backs any presented outcome reference. Usefulness
    /// stays unestablished; this is never a positive claim.
    NoOwnerRecord,
}

/// Plans the closed learning-record range read for one scope, filtered to the
/// closed `record_kind`.
///
/// The request carries only the catalogue-declared selectors
/// (`record_kind`, `max_records`, optional `cursor`) plus the typed
/// `scope_id` and `ExactFence` consistency the caller observed. Free text
/// never becomes a selector: the record kind is a closed enum and the page
/// bound is a decimal the catalogue checks.
pub fn plan_learning_read(
    kind: LearningRecordKind,
    fence: StateFence,
) -> Result<NamedReadRequest, EvidenceReadError> {
    let scope = ScopeId::new(LIFECYCLE_SCOPE)
        .map_err(|error| EvidenceReadError::Request(error.to_string()))?;
    let mut parameters = std::collections::BTreeMap::new();
    parameters.insert(
        "record_kind".to_owned(),
        serde_json::Value::String(kind.as_str().to_owned()),
    );
    parameters.insert(
        "max_records".to_owned(),
        serde_json::Value::String(MAX_LEARNING_PAGE_RECORDS.to_string()),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetLearningRecordRange,
        scope_id: Some(scope),
        consistency: ReadConsistency::ExactFence,
        state_fence: fence,
        parameters,
    };
    request
        .validate()
        .map_err(|error| EvidenceReadError::Request(error.to_string()))?;
    Ok(request)
}

/// Resolves one learning-record range response, re-verifying the response
/// binding and the coverage it actually achieved.
///
/// Re-verified here, in the same order the acceptance read uses: operation
/// identity against the planned read, fence equality, response shape, payload
/// version, the planned scope echoed by the payload, and the record-kind
/// filter. Truncation is reported as [`EvidenceCoverage::Truncated`] rather
/// than treated as a complete set: a partial page cannot prove that a
/// reference is absent from the owner, so it must not produce a negative
/// finding.
pub fn resolve_learning_records(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> Result<(Vec<serde_json::Value>, EvidenceCoverage), EvidenceReadError> {
    if response.operation != NamedReadOperation::GetLearningRecordRange
        || response.operation != request.operation
    {
        return Err(EvidenceReadError::ResponseMismatch("operation"));
    }
    if response.state_fence != request.state_fence {
        return Err(EvidenceReadError::ResponseMismatch("fence"));
    }
    response
        .validate()
        .map_err(|_| EvidenceReadError::ResponseMismatch("shape"))?;
    let payload = &response.payload;
    if payload.get("version").and_then(serde_json::Value::as_u64) != Some(LEARNING_PAYLOAD_VERSION)
    {
        return Err(EvidenceReadError::Payload("version"));
    }
    let planned_scope = request
        .scope_id
        .clone()
        .ok_or(EvidenceReadError::Payload("scope"))?;
    let planned_scope_value =
        serde_json::to_value(&planned_scope).map_err(|_| EvidenceReadError::Payload("scope"))?;
    if payload.get("scope_id") != Some(&planned_scope_value) {
        return Err(EvidenceReadError::Payload("scope"));
    }
    let planned_kind = request
        .parameters
        .get("record_kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(EvidenceReadError::Payload("record_kind"))?;
    if payload
        .get("record_kind")
        .and_then(serde_json::Value::as_str)
        != Some(planned_kind)
    {
        return Err(EvidenceReadError::Payload("record_kind"));
    }
    let truncated = payload
        .get("truncated")
        .and_then(serde_json::Value::as_bool)
        .ok_or(EvidenceReadError::Payload("truncated"))?;
    let records = payload
        .get("records")
        .and_then(serde_json::Value::as_array)
        .ok_or(EvidenceReadError::Payload("records"))?
        .clone();
    let coverage = if truncated {
        EvidenceCoverage::Truncated
    } else {
        EvidenceCoverage::Complete
    };
    Ok((records, coverage))
}

/// Extracts the owner record payload a served learning row carries.
///
/// Rows are projected verbatim by the store as
/// `{record_kind, handle, record_json, record_digest}`; `record_json` is the
/// canonical record document. A row that does not carry a decodable document
/// cannot support a claim, so it is skipped rather than half-parsed.
fn record_document(row: &serde_json::Value) -> Option<&serde_json::Value> {
    if row
        .get("record_kind")
        .and_then(serde_json::Value::as_str)
        .is_some()
        && row
            .get("record_digest")
            .and_then(serde_json::Value::as_str)
            .is_some()
        && row
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        row.get("record_json")
    } else {
        None
    }
}

/// Resolves the presented outcome references of one receipt against the
/// durable evidence-owner records a single bounded learning read returned,
/// bound to the competent verifier contract for this exact skill/package.
///
/// The comparison is against CONTENT, not existence: a reference qualifies
/// only when a served record document decodes to a
/// [`SkillExecutionEvidence`] whose own `execution_ref` equals the exact
/// string the receipt presented, that names the canonically bound verifier
/// (`accepting_verifier`, the deciding acceptance row's `verifier_ref`) in
/// its own `verifier_refs`, and that validates against itself. A record
/// that merely exists, is well-shaped, carries a handle that resembles the
/// reference, or names an unrelated verifier never qualifies: a real
/// verifier record for an unrelated artifact -- or an unrelated verifier --
/// is insufficient (issue #2663, I12.24). No recursive crawl, no free-text
/// search and no URL fetch happens here: the page is exactly what the one
/// bounded read returned, and a reference absent from it stays unresolved.
pub fn resolve_outcome_records(
    receipt: &SkillHarnessActivationReceipt,
    rows: &[serde_json::Value],
    accepting_verifier: &str,
) -> OutcomeResolution {
    let mut records: Vec<eliot_skill::ResolvedOutcome> = Vec::new();
    for reference in &receipt.verified_outcome_refs {
        let matched = rows.iter().find_map(|row| {
            let document = record_document(row)?;
            // The record's own identity decides: the document must name the
            // exact presented reference, and it must validate as recorded.
            if document
                .get("execution_ref")
                .and_then(serde_json::Value::as_str)
                != Some(reference)
            {
                return None;
            }
            let record: SkillExecutionEvidence = serde_json::from_value(document.clone()).ok()?;
            // Verifier competence: the record must name the verifier the
            // governance bound to this exact skill/package. A valid record
            // observed by any other verifier is a real-but-unrelated outcome
            // and cannot support this receipt's claim.
            if !record
                .verifier_refs
                .iter()
                .any(|name| name == accepting_verifier)
            {
                return None;
            }
            if record.validate().is_err() {
                return None;
            }
            // The owner revision is whatever the serving read actually
            // reported for this row. The learning-record owner keys rows by
            // `(record_kind, handle, record_digest)` and publishes no per-row
            // commit order, so there is no revision to report: `None` is the
            // honest value and none is ever synthesized.
            Some(eliot_skill::ResolvedOutcome {
                reference: reference.clone(),
                source_revision: None,
                record,
            })
        });
        if let Some(resolved) = matched {
            records.push(resolved);
        }
    }
    if records.is_empty() {
        OutcomeResolution::NoOwnerRecord
    } else {
        OutcomeResolution::Resolved { records }
    }
}

/// Reads the evidence-owner page for one closed record kind under the caller's
/// observed admitted fence.
///
/// Executed without the composition lock held, exactly like the acceptance
/// read: the caller captures immutable input under a short borrow, awaits this
/// without any mutex, and re-checks the fence under a fresh borrow before it
/// publishes. A refused or unavailable read is an error, never a positive
/// qualification.
pub async fn read_evidence_owner_records(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
    kind: LearningRecordKind,
) -> Result<(Vec<serde_json::Value>, EvidenceCoverage), EvidenceReadError> {
    let request = plan_learning_read(kind, admitted_fence.clone())?;
    let response = kernel
        .store_named_async(request.clone())
        .await
        .map_err(|error| EvidenceReadError::Transport(error.to_string()))?;
    resolve_learning_records(&request, &response)
}

/// Narrows one resolved acceptance resolution to the Skill identity it
/// actually decided.
///
/// The acceptance read resolves the LATEST committed row for the Skill; that
/// row is the owner position for the Skill identity. It is a Skill-owner
/// read, not a substitute for historical execution evidence, so it contributes
/// only the Skill-revision binding — never a usefulness claim.
#[must_use]
pub fn subject_binding_from_acceptance(
    resolution: &AcceptanceResolution,
    skill_id: &str,
) -> SubjectBinding {
    match &resolution.verdict {
        AcceptanceVerdict::Accepted(record) | AcceptanceVerdict::Revoked(record) => {
            debug_assert_eq!(
                record.skill_id, skill_id,
                "acceptance row names the planned skill"
            );
            SubjectBinding::Resolved {
                skill_id: skill_id.to_owned(),
                revisions: vec![SourceRevision {
                    source: SOURCE_SKILL_LIFECYCLE.to_owned(),
                    revision: Some(record.revision),
                }],
            }
        }
        AcceptanceVerdict::Unknown => SubjectBinding::Unresolved {
            skill_id: skill_id.to_owned(),
        },
    }
}

/// Records the evidence-owner revision a qualification depended on.
///
/// The learning-record owner publishes no per-row commit order, so this is
/// `None`: the row's own immutable `record_digest` is its revision identity
/// (issue #1868), and a synthetic counter would be a fabricated value.
#[must_use]
pub fn activation_receipt_revision() -> SourceRevision {
    SourceRevision {
        source: SOURCE_ACTIVATION_RECEIPT.to_owned(),
        revision: None,
    }
}

/// Accept-family lifecycle actions: the closed vocabulary the canonical
/// acceptance read decides intake currency by. Restated here — not
/// re-derived — because `skill_acceptance_read` owns that decision and is not
/// reopened: the question here differs (was THIS digest ever admitted, not is
/// it current?), so the same vocabulary is consulted for history, never as a
/// second currency scheme.
const HISTORICAL_ACCEPT_ACTIONS: [&str; 6] =
    ["keep", "patch", "split", "merge", "restore", "rollback"];

/// One presented package digest held by retained committed history
/// (issue #2663, AC2).
///
/// This is the explicit permitted historical binding a current collector
/// reports an older attempt through: the latest committed
/// `ApplyLifecyclePolicy` row holding the PRESENTED digest with an
/// accept-family action, resolved from the retained lifecycle-policy rows —
/// never reconstructed from payload fields. Currency is deliberately NOT
/// required: a superseded-but-committed row is exactly what makes the ingest
/// historical rather than current. Only constructed by
/// [`historical_binding_from_acceptance`]; the daemon seam re-checks
/// [`holds`](Self::holds) before filing, so a binding is never trusted on
/// shape alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalPackageBinding {
    /// Skill the committed row names.
    pub skill_id: String,
    /// Package digest the committed row holds.
    pub package_digest: String,
    /// Commit order (`capture_index`) of the latest row holding the digest.
    pub row_revision: u64,
    /// Accept-family action holding the digest.
    pub action: String,
    /// Competent verifier bound by that row.
    pub verifier_ref: String,
    /// Candidate digest bound by that row.
    pub candidate_digest: String,
}

impl HistoricalPackageBinding {
    /// Whether this binding still holds its digest: the latest committed row
    /// for the digest carries an accept-family action. A digest whose latest
    /// row revokes it — or that no row holds — never constructs, so this is
    /// the seam's re-verification, not a second decision.
    #[must_use]
    pub fn holds(&self) -> bool {
        HISTORICAL_ACCEPT_ACTIONS.contains(&self.action.as_str())
    }
}

/// Scans an already-resolved acceptance read for the retained-history binding
/// of one presented package digest.
///
/// The response binding was verified by `resolve_acceptance` before this scan
/// runs (operation, fence, scope, shape, payload version, planned skill, no
/// truncation), so only committed rows for the planned skill remain; this
/// function only selects among them by commit order (`capture_index`, served
/// order breaking ties, exactly as the acceptance read orders). The latest
/// row binding the presented digest with an accept-family action yields the
/// binding; a revoked digest, an unknown action, or no row at all yields
/// `None` — absence of a row, never a negative fact. No new read, no new
/// port, no free-text lookup: the page is exactly what the one bounded
/// acceptance read returned.
#[must_use]
pub fn historical_binding_from_acceptance(
    resolution: &AcceptanceResolution,
    skill_id: &str,
    package_digest: &str,
) -> Option<HistoricalPackageBinding> {
    let records = resolution.response.payload.get("records")?.as_array()?;
    // Latest committed row holding the presented digest, by commit order.
    let mut best: Option<(u64, String, String, String)> = None;
    for record in records {
        if record.get("operation").and_then(serde_json::Value::as_str)
            != Some("ApplyLifecyclePolicy")
        {
            continue;
        }
        let parameters = record.get("parameters")?.as_object()?;
        let text = |name: &str| parameters.get(name).and_then(serde_json::Value::as_str);
        if text("skill_id") != Some(skill_id) {
            continue;
        }
        // A row missing its base view cannot prove the admission it claims —
        // the same completeness the acceptance read requires.
        if text("base_view_digest").is_none() {
            continue;
        }
        if text("candidate_package_digest") != Some(package_digest) {
            continue;
        }
        let (Some(action), Some(verifier_ref), Some(candidate_digest)) = (
            text("action"),
            text("verifier_ref"),
            text("candidate_digest"),
        ) else {
            continue;
        };
        let Some(revision) = record
            .get("capture_index")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        if best.as_ref().is_none_or(|current| revision > current.0) {
            best = Some((
                revision,
                action.to_owned(),
                verifier_ref.to_owned(),
                candidate_digest.to_owned(),
            ));
        }
    }
    let (row_revision, action, verifier_ref, candidate_digest) = best?;
    if !HISTORICAL_ACCEPT_ACTIONS.contains(&action.as_str()) {
        return None;
    }
    Some(HistoricalPackageBinding {
        skill_id: skill_id.to_owned(),
        package_digest: package_digest.to_owned(),
        row_revision,
        action,
        verifier_ref,
        candidate_digest,
    })
}
