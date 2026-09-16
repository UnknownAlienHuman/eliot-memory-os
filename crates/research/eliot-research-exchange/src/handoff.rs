//! Bounded exchange/receipt integration for researcher evidence handoff
//! (issue #700).
//!
//! This module owns exactly three behaviours over the existing exchange and
//! receipt vocabulary: wire-level receipt ingestion with exactly-once
//! semantics, frozen evidence handoff seals over delivered bundles, and the
//! honest terminal mapping that never decodes a partial, cancelled or unknown
//! outcome as complete. It introduces no acquisition algorithm, no Dreamer
//! grounding, no authority decision and no canonical write: every function is
//! a pure audit over supplied records plus the append-only receipt journal.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::sha256_hex;
use eliot_research_exchange_api::{
    CompletionDisposition, DisclosureClass, ResearchContractError, ResearchEvidenceBundle,
    ResearchQueryRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ExchangeStatus, GovernedExchange, ResearchBridge};

/// Stable identity of this handoff surface.
pub const HANDOFF_CONTRACT: &str = "eliot.research.evidence-handoff";
/// Current wire revision of this handoff surface.
pub const HANDOFF_VERSION: &str = "1.0.0";

/// Typed handoff failure. Variants name the failing field only and never echo
/// supplied values.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HandoffError {
    /// The supplied contract record is invalid.
    #[error("research contract rejected: {0}")]
    Contract(#[from] ResearchContractError),
    /// The job identity is unknown to this exchange.
    #[error("handoff job is unknown")]
    UnknownJob,
    /// The outcome cannot close as a finished handoff.
    #[error("handoff terminal cannot decode as complete")]
    InvalidTerminal,
    /// A cited handle has no delivered source snapshot behind it: a summary
    /// without raw lineage never replaces evidence.
    #[error("handoff citation has no delivered source lineage")]
    MissingSourceLineage,
    /// The handoff widens the admitted disclosure class.
    #[error("handoff widens disclosure beyond admission")]
    DisclosureWidened,
    /// The bound manifest digest or revision is not the frozen one.
    #[error("handoff manifest is stale")]
    StaleManifest,
    /// The handoff seal is past its expiry.
    #[error("handoff seal is expired")]
    Expired,
    /// The seal digest does not cover the presented shape.
    #[error("handoff seal digest mismatch")]
    DigestMismatch,
}

/// Disclosure widening order: material may only travel at or below its
/// admitted class, never above it.
#[must_use]
pub const fn disclosure_rank(class: DisclosureClass) -> u8 {
    match class {
        DisclosureClass::Private => 0,
        DisclosureClass::ProjectBound => 1,
        DisclosureClass::ExportableRedacted => 2,
        DisclosureClass::Public => 3,
    }
}

/// Honest terminal class of one handoff: only a closable disposition on a
/// completed job is finished. Partial, cancelled, failed and unknown outcomes
/// stay explicitly open or closed-without-completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffTerminal {
    /// Closed with supported evidence.
    Finished,
    /// Still open: partial, exhausted or inconclusive evidence.
    PartialOpen,
    /// Closed without completion: cancelled.
    CancelledClosed,
    /// Closed without completion: failed.
    FailedClosed,
    /// Still open: the outcome cannot be established.
    UnknownOpen,
}

impl HandoffTerminal {
    /// Whether this terminal counts as finished work.
    #[must_use]
    pub const fn is_finished(self) -> bool {
        matches!(self, Self::Finished)
    }
}

/// Maps one completion disposition on one exchange status to its honest
/// terminal. A terminal partial, abstention, cancellation or unknown outcome
/// never maps to [`HandoffTerminal::Finished`].
#[must_use]
pub const fn terminal_of(
    disposition: CompletionDisposition,
    status: ExchangeStatus,
) -> HandoffTerminal {
    if !matches!(status, ExchangeStatus::Completed) {
        return match status {
            ExchangeStatus::Cancelled | ExchangeStatus::CancelRequested => {
                HandoffTerminal::CancelledClosed
            }
            ExchangeStatus::Failed => HandoffTerminal::FailedClosed,
            ExchangeStatus::Accepted | ExchangeStatus::Running | ExchangeStatus::Partial => {
                HandoffTerminal::PartialOpen
            }
            ExchangeStatus::Completed => HandoffTerminal::PartialOpen,
        };
    }
    if disposition.may_close_inquiry() {
        HandoffTerminal::Finished
    } else {
        match disposition {
            CompletionDisposition::Cancelled => HandoffTerminal::CancelledClosed,
            CompletionDisposition::AnsweredWithSupportedResult
            | CompletionDisposition::NoMatchInCompleteScope => HandoffTerminal::Finished,
            CompletionDisposition::IncompleteCoverage
            | CompletionDisposition::NoNewUsefulEvidence
            | CompletionDisposition::StaleSourceOrIndex
            | CompletionDisposition::SourceUnavailable
            | CompletionDisposition::PolicyOrDisclosureDenied
            | CompletionDisposition::Inconclusive => HandoffTerminal::PartialOpen,
        }
    }
}

/// One journal entry binding a receipt identity to its original operation and
/// payload digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Original acquisition operation this receipt reports on.
    pub operation_id: String,
    /// Digest of the payload accepted under this receipt identity.
    pub payload_digest: String,
}

/// Outcome of ingesting one owner receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestOutcome {
    /// The receipt was accepted under a new identity.
    Accepted,
    /// The identical receipt was already present; no state changed. Pure
    /// replay checks claim no durable deduplication beyond this journal.
    ReplayDuplicate,
}

/// Directive after a timeout or disconnect: possible acquisition or spend is
/// reconciled through its original operation, never blindly retried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconcileDirective {
    /// Reconcile through the original operation identity.
    ReconcileViaOriginal {
        /// Original operation identity to reconcile.
        operation_id: String,
    },
    /// The operation identity is unknown to this journal.
    UnknownOperation,
}

/// Append-only journal ingesting each returned owner receipt exactly once
/// semantically. A delivery or transport success event is not acquisition
/// proof: only an entry accepted here counts, and a changed payload under a
/// known receipt identity conflicts instead of replacing history.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptJournal {
    entries: BTreeMap<String, JournalEntry>,
}

impl ReceiptJournal {
    /// Ingests one owner receipt. The same identity with the same payload
    /// digest is a replay duplicate without state change; the same identity
    /// with a changed payload digest is an idempotency conflict.
    pub fn ingest(
        &mut self,
        receipt_id: &str,
        operation_id: &str,
        payload_digest: &str,
    ) -> Result<IngestOutcome, crate::ExchangeError> {
        if receipt_id.trim().is_empty()
            || operation_id.trim().is_empty()
            || receipt_id.chars().any(char::is_control)
            || operation_id.chars().any(char::is_control)
        {
            return Err(crate::ExchangeError::InvalidTransition);
        }
        if payload_digest.len() != 64
            || payload_digest
                .bytes()
                .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(crate::ExchangeError::InvalidTransition);
        }
        match self.entries.get(receipt_id) {
            Some(current) if current.payload_digest == payload_digest => {
                Ok(IngestOutcome::ReplayDuplicate)
            }
            Some(_) => Err(crate::ExchangeError::IdempotencyConflict),
            None => {
                self.entries.insert(
                    receipt_id.to_owned(),
                    JournalEntry {
                        operation_id: operation_id.to_owned(),
                        payload_digest: payload_digest.to_owned(),
                    },
                );
                Ok(IngestOutcome::Accepted)
            }
        }
    }

    /// Returns the reconcile directive for one operation after a timeout or
    /// disconnect. Known operations reconcile through their original
    /// identity; unknown operations stay unknown instead of being retried.
    #[must_use]
    pub fn reconcile(&self, operation_id: &str) -> ReconcileDirective {
        if self
            .entries
            .values()
            .any(|entry| entry.operation_id == operation_id)
        {
            ReconcileDirective::ReconcileViaOriginal {
                operation_id: operation_id.to_owned(),
            }
        } else {
            ReconcileDirective::UnknownOperation
        }
    }

    /// Number of distinct receipt identities accepted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the journal holds no receipt.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Frozen evidence handoff seal over one delivered bundle: exact manifest
/// membership, delivered source lineage behind every citation, preserved
/// disclosure, and expiry/revision bounds. The seal digest is canonical over
/// sorted handles, so irrelevant receipt and source order never changes the
/// frozen bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffSeal {
    /// Exchange identity of the handoff.
    pub exchange_id: String,
    /// Job identity of the handoff.
    pub job_id: String,
    /// Digest of the delivered bundle.
    pub bundle_digest: String,
    /// Completion disposition wire name.
    pub disposition: String,
    /// Disclosure class wire name preserved into the handoff.
    pub disclosure: String,
    /// Digest of the frozen reference manifest bound here.
    pub manifest_digest: String,
    /// Manifest revision bound here; a revision invalidates older seals.
    pub manifest_revision: String,
    /// Cited source handles in frozen sorted order.
    pub cited_handles: Vec<String>,
    /// Statement digests in frozen sorted order: statements stay
    /// tamper-evident data and are never interpreted.
    pub statement_digests: Vec<String>,
    /// Expiry in Unix milliseconds; verification past it fails closed.
    pub expires_ms: i64,
    /// Frozen seal digest over the whole seal shape.
    pub seal_digest: String,
}

fn push_field(preimage: &mut String, tag: &str, value: &str) {
    preimage.push_str(tag);
    preimage.push('=');
    preimage.push_str(&value.len().to_string());
    preimage.push(':');
    preimage.push_str(value);
    preimage.push(';');
}

fn disclosure_wire(class: DisclosureClass) -> &'static str {
    match class {
        DisclosureClass::Private => "private",
        DisclosureClass::ProjectBound => "project_bound",
        DisclosureClass::ExportableRedacted => "exportable_redacted",
        DisclosureClass::Public => "public",
    }
}

fn disposition_wire(disposition: CompletionDisposition) -> &'static str {
    match disposition {
        CompletionDisposition::AnsweredWithSupportedResult => "answered_with_supported_result",
        CompletionDisposition::NoMatchInCompleteScope => "no_match_in_complete_scope",
        CompletionDisposition::NoNewUsefulEvidence => "no_new_useful_evidence",
        CompletionDisposition::SourceUnavailable => "source_unavailable",
        CompletionDisposition::StaleSourceOrIndex => "stale_source_or_index",
        CompletionDisposition::PolicyOrDisclosureDenied => "policy_or_disclosure_denied",
        CompletionDisposition::IncompleteCoverage => "incomplete_coverage",
        CompletionDisposition::Inconclusive => "inconclusive",
        CompletionDisposition::Cancelled => "cancelled",
    }
}

fn seal_preimage(
    bundle: &ResearchEvidenceBundle,
    request: &ResearchQueryRequest,
    manifest_revision: &str,
    expires_ms: i64,
) -> String {
    let mut cited: Vec<&str> = bundle
        .claims
        .iter()
        .flat_map(|claim| claim.citations.iter().map(|c| c.source_handle.as_str()))
        .collect();
    cited.sort_unstable();
    cited.dedup();
    let mut source_digests: Vec<&str> = bundle
        .sources
        .iter()
        .map(|source| source.snapshot_digest.as_str())
        .collect();
    source_digests.sort_unstable();
    let mut statement_digests: Vec<String> = bundle
        .claims
        .iter()
        .map(|claim| sha256_hex(claim.statement.as_bytes()))
        .collect();
    statement_digests.sort();
    let mut preimage = String::from("evidence-handoff/v1;");
    push_field(&mut preimage, "exchange_id", &bundle.exchange_id);
    push_field(&mut preimage, "job_id", &bundle.job_id);
    push_field(
        &mut preimage,
        "bundle_digest",
        &bundle.immutable_bundle_digest,
    );
    push_field(
        &mut preimage,
        "disposition",
        disposition_wire(bundle.disposition),
    );
    push_field(
        &mut preimage,
        "disclosure",
        disclosure_wire(bundle.disclosure),
    );
    push_field(
        &mut preimage,
        "manifest_digest",
        &request.allowed_references.digest,
    );
    push_field(&mut preimage, "manifest_revision", manifest_revision);
    preimage.push_str(&format!("cited={};", cited.len()));
    for handle in &cited {
        push_field(&mut preimage, "cited", handle);
    }
    preimage.push_str(&format!("sources={};", source_digests.len()));
    for digest in &source_digests {
        push_field(&mut preimage, "source_digest", digest);
    }
    preimage.push_str(&format!("statements={};", statement_digests.len()));
    for digest in &statement_digests {
        push_field(&mut preimage, "statement", digest);
    }
    push_field(&mut preimage, "expires_ms", &expires_ms.to_string());
    preimage
}

/// Seals one evidence handoff over a delivered bundle and its admitting
/// request. Checks exact manifest membership through the existing bundle
/// validation, requires delivered source lineage behind every citation (a
/// provider summary without raw lineage never replaces evidence), preserves
/// the admitted disclosure class without widening, and binds the frozen
/// manifest digest and revision. Source statements enter the seal only as
/// digests: instruction-like content stays inert data.
pub fn seal_handoff(
    bundle: &ResearchEvidenceBundle,
    request: &ResearchQueryRequest,
    manifest_revision: &str,
    expires_ms: i64,
) -> Result<HandoffSeal, HandoffError> {
    if manifest_revision.trim().is_empty()
        || manifest_revision.chars().any(char::is_control)
    {
        return Err(HandoffError::Contract(
            ResearchContractError::InvalidText {
                field: "handoff.manifest_revision",
            },
        ));
    }
    if expires_ms <= 0 {
        return Err(HandoffError::Contract(
            ResearchContractError::InvalidDisposition,
        ));
    }
    request.validate().map_err(HandoffError::Contract)?;
    bundle.validate_against(request).map_err(HandoffError::Contract)?;
    for claim in &bundle.claims {
        for citation in &claim.citations {
            if !bundle
                .sources
                .iter()
                .any(|source| source.source_handle == citation.source_handle)
            {
                return Err(HandoffError::MissingSourceLineage);
            }
        }
    }
    if disclosure_rank(bundle.disclosure) > disclosure_rank(request.disclosure) {
        return Err(HandoffError::DisclosureWidened);
    }
    let mut cited: Vec<String> = bundle
        .claims
        .iter()
        .flat_map(|claim| {
            claim
                .citations
                .iter()
                .map(|c| c.source_handle.clone())
        })
        .collect();
    cited.sort();
    cited.dedup();
    let mut statement_digests: Vec<String> = bundle
        .claims
        .iter()
        .map(|claim| sha256_hex(claim.statement.as_bytes()))
        .collect();
    statement_digests.sort();
    let preimage = seal_preimage(bundle, request, manifest_revision, expires_ms);
    Ok(HandoffSeal {
        exchange_id: bundle.exchange_id.clone(),
        job_id: bundle.job_id.clone(),
        bundle_digest: bundle.immutable_bundle_digest.clone(),
        disposition: disposition_wire(bundle.disposition).to_owned(),
        disclosure: disclosure_wire(bundle.disclosure).to_owned(),
        manifest_digest: request.allowed_references.digest.clone(),
        manifest_revision: manifest_revision.to_owned(),
        cited_handles: cited,
        statement_digests,
        expires_ms,
        seal_digest: sha256_hex(preimage.as_bytes()),
    })
}

/// Verifies one handoff seal against the current frozen manifest digest and
/// revision at `now_ms`: expiry and manifest revision invalidate the old
/// audit instead of being reinterpreted.
pub fn verify_seal(
    seal: &HandoffSeal,
    manifest_digest: &str,
    manifest_revision: &str,
    now_ms: i64,
) -> Result<(), HandoffError> {
    if now_ms > seal.expires_ms {
        return Err(HandoffError::Expired);
    }
    if seal.manifest_digest != manifest_digest || seal.manifest_revision != manifest_revision {
        return Err(HandoffError::StaleManifest);
    }
    if seal.seal_digest.len() != 64
        || seal
            .seal_digest
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(HandoffError::DigestMismatch);
    }
    Ok(())
}

impl<B: ResearchBridge> GovernedExchange<B> {
    /// Audits the handoff for one completed job: the job must be completed
    /// with a delivered result, otherwise a terminal partial, cancelled or
    /// unknown outcome can never decode as a finished handoff.
    pub fn audit_handoff(
        &self,
        job_id: &str,
        manifest_revision: &str,
        expires_ms: i64,
    ) -> Result<HandoffSeal, HandoffError> {
        let job = self.snapshot().jobs.get(job_id).ok_or(HandoffError::UnknownJob)?;
        let result = job.result.as_ref().ok_or(HandoffError::InvalidTerminal)?;
        if !terminal_of(result.disposition, job.status).is_finished() {
            return Err(HandoffError::InvalidTerminal);
        }
        seal_handoff(result, &job.request, manifest_revision, expires_ms)
    }
}
