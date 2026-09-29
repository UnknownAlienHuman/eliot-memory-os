//! Production bounded-read resolution of the negative-memory rule snapshot
//! (issue #1731 W4, I1.8 canonical read path, I12.16 Fence A, I12.24).
//!
//! # What this owner resolves
//!
//! The gate in [`crate::negative_memory_gate`] is a pure function over a rule
//! snapshot. Before this module existed, nothing in production produced that
//! snapshot: every caller had to hand-assemble a
//! [`NegativeMemoryCandidateRead`](eliot_dreamer_failure::NegativeMemoryCandidateRead),
//! a list of admitted policies, and a [`StateFence`], and the gate compared
//! that caller-supplied fence only for equality. Equality between two
//! caller-supplied values is not authentication, so this module exists to make
//! the read fence an **owner-observed** value instead.
//!
//! # The read this module issues
//!
//! Exactly one closed, already-activated store read:
//! [`NamedReadOperation::GetLearningRecordRange`] filtered to
//! [`LearningRecordKind::ActivationReceipt`], addressed to one scope, at
//! `ReadConsistency::ExactFence` on the fence the caller was admitted at. The
//! request is built by
//! [`eliot_store_api::learning_record_read_request`] — the closed builder that
//! [`skill_evidence_read`](../../../../bins/eliotd/src/skill_evidence_read.rs)
//! and the learning-record commit owner already use — so no new store
//! operation, catalogue entry, database or second read path is introduced.
//!
//! # What "authenticated read fence" means here, precisely
//!
//! [`ResolvedNegativeMemoryRuleSet::store_observed_fence`] is copied from the
//! `state_fence` the **store echoed on the response**, after the resolver has
//! proved that the response answers exactly the planned request (operation
//! identity, scope echo, kind echo, and the payload's own `state_fence` echo
//! against the response fence). A caller cannot choose it: the store serves
//! the read at the live fence or refuses, and the resolver refuses a response
//! that answers a different fence. The gate then compares that owner-observed
//! value against the **canonical request's own** state fence at dispatch. That
//! comparison — an owner-issued read fence measured against this operation's
//! content — is what the previous caller-supplied equality could not do.
//!
//! # What the resolver re-proves, and what it never re-derives
//!
//! Each served row is re-proved against the values the **store committed**:
//!
//! * the row's presented `record_digest` must equal the SHA-256 of the exact
//!   `record_json` bytes the store returned under it (the store keys rows by
//!   `(record_kind, handle, record_digest)`, so this is the immutable revision
//!   identity, not a digest recomputed over anything the caller holds);
//! * the row's `handle` must be the exact `negative-memory:{record_id}:{rule_revision}`
//!   activation handle, so a document cannot be filed under a name that
//!   belongs to another rule revision;
//! * the decoded document's own `record` and `policy` must each pass their own
//!   `validate()`, the policy must pass `validate_binding()` against that
//!   record, and the document must pass `validate_against_policy()` against
//!   both. A rule is therefore only ever delivered to the matcher after its
//!   **own** recorded `record_digest` has been re-derived by its own validator.
//!
//! # Truncation is never absence
//!
//! The resolver resolves exactly one bounded page. A page the store reports as
//! `truncated` is not a prefix that may stand in for the rule scope: the
//! resolver records a named missing page, sets
//! [`DeclaredPageTotal::Unknown`] and coverage `FailureCoverage::Partial`, so
//! the matcher's own enumeration is incomplete and
//! `NegativeMemoryGateDecision::Unavailable` is the only reachable outcome for
//! it. A truncated read can never certify that no applicable rule exists.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_dreamer_failure::{
    DeclaredPageTotal, FailureCoverage, NegativeMemoryActionPolicy, NegativeMemoryCandidatePage,
    NegativeMemoryCandidateRead, NegativeMemoryFingerprint,
};
use eliot_store_api::{
    EXPERIENCE_PAGE_RECORDS, EXPERIENCE_PAGE_STATE_FENCE, EXPERIENCE_PAGE_TRUNCATED,
    LearningRecordKind, MAX_LEARNING_PAGE_RECORDS, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, RevisionKey, ScopeId, canonical_json_bytes, learning_record_read_request,
    sha256_hex,
};
use serde_json::Value;
use thiserror::Error;

use crate::negative_memory_activation::{
    ACTIVATION_HANDLE_PREFIX, NegativeMemoryActivationDocument,
};

/// Maximum pages one resolver call may consider when a page was truncated.
///
/// A single bounded page is the whole enumeration this owner performs; the
/// bound exists so a future multi-page resolver cannot walk an unbounded rule
/// scope without a new, explicit decision.
const MAX_RULE_PAGES: u32 = 1;

/// Fail-closed refusals from the bounded rule-read resolver.
///
/// Every variant means no rule snapshot was established. None is a no-match and
/// none is a fabricated absence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NegativeMemoryReadRefusal {
    /// The planned read request is not the closed read this owner issues.
    #[error("negative-memory rule read request is invalid: {0}")]
    Request(String),
    /// The response answers a different operation, fence, scope or kind than
    /// the planned read.
    #[error("negative-memory rule read response does not answer the planned read: {0}")]
    ResponseMismatch(&'static str),
    /// The served payload is not the versioned learning-record page shape.
    #[error("negative-memory rule read payload is not the versioned shape: {0}")]
    Payload(&'static str),
    /// The store did not report a revision head for the read's own scope, so
    /// the rule-set revision this read observed is not owner-issued.
    #[error("negative-memory rule read carries no revision head for scope {scope_id}")]
    RuleSetRevisionAbsent {
        /// The scope the read was addressed to.
        scope_id: String,
    },
    /// A served row is not an admissible activation receipt.
    #[error("negative-memory activation row {handle} is not admissible: {detail}")]
    RowNotAdmissible {
        /// The exact store row handle the refusal concerns.
        handle: String,
        /// Exact refusal detail.
        detail: String,
    },
}

/// One rule set resolved from a bounded, exact-fence named read.
///
/// Every field is private and the only constructor is
/// [`resolve_negative_memory_rule_read`], so a caller cannot assemble a
/// snapshot, attach policies to it, or name a read fence for it. The store
/// observed the fence; the resolver copied it.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedNegativeMemoryRuleSet {
    read: NegativeMemoryCandidateRead,
    policies: Vec<NegativeMemoryActionPolicy>,
    records: Vec<NegativeMemoryFingerprint>,
    store_observed_fence: StateFence,
    scope_id: ScopeId,
    rule_set_revision: u64,
    complete: bool,
}

impl ResolvedNegativeMemoryRuleSet {
    /// The bounded rule read the matcher consumes.
    #[must_use]
    pub const fn read(&self) -> &NegativeMemoryCandidateRead {
        &self.read
    }

    /// The owner-admitted action policies carried by the resolved rules.
    #[must_use]
    pub fn policies(&self) -> &[NegativeMemoryActionPolicy] {
        &self.policies
    }

    /// The validated rule records the read delivered.
    #[must_use]
    pub fn records(&self) -> &[NegativeMemoryFingerprint] {
        &self.records
    }

    /// The fence the **store** reported while serving this read.
    ///
    /// This is the authenticated read fence. It is never a caller-supplied
    /// value: the resolver copies it off a response it has already proved
    /// answers the planned exact-fence read.
    #[must_use]
    pub const fn store_observed_fence(&self) -> &StateFence {
        &self.store_observed_fence
    }

    /// The scope the read was addressed to.
    #[must_use]
    pub const fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    /// The scope revision head the store reported for this read (I12.16 Fence
    /// A reading).
    #[must_use]
    pub const fn rule_set_revision(&self) -> u64 {
        self.rule_set_revision
    }

    /// Whether the bounded enumeration covered the whole queried rule scope.
    ///
    /// `false` means the store truncated the page. Absence of an applicable
    /// rule is then uncertifiable and the gate refuses rather than proceeding.
    #[must_use]
    pub const fn enumeration_complete(&self) -> bool {
        self.complete
    }

    /// The store revision-head key this owner reads for one scope.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryReadRefusal::Request`] when the scope cannot
    /// form a revision key.
    pub fn revision_key(scope_id: &ScopeId) -> Result<RevisionKey, NegativeMemoryReadRefusal> {
        RevisionKey::new(format!("scope:{}", scope_id.as_str()))
            .map_err(|error| NegativeMemoryReadRefusal::Request(error.to_string()))
    }
}

/// Plans the one closed bounded read this owner issues.
///
/// The request carries only the catalogue-declared selectors
/// (`record_kind`, `max_records`), the typed `scope_id` and `ExactFence`
/// consistency on the fence the caller was admitted at. Free text never becomes
/// a selector.
///
/// # Errors
///
/// Returns [`NegativeMemoryReadRefusal::Request`] when the closed builder's
/// output fails the store's own request validation.
pub fn plan_negative_memory_rule_read(
    scope_id: ScopeId,
    admitted_fence: StateFence,
) -> Result<NamedReadRequest, NegativeMemoryReadRefusal> {
    let request = learning_record_read_request(
        scope_id,
        Some(LearningRecordKind::ActivationReceipt),
        MAX_LEARNING_PAGE_RECORDS,
        admitted_fence,
    );
    request
        .validate()
        .map_err(|error| NegativeMemoryReadRefusal::Request(error.to_string()))?;
    Ok(request)
}

/// Resolves one bounded learning-record page into a rule set.
///
/// The order of the checks is the order of the guarantees:
///
/// 1. the response answers the planned read (operation identity, and the
///    response fence equal to the request's exact fence);
/// 2. the served payload echoes that same fence, so the fence this owner will
///    publish is the store's own statement and not the request's;
/// 3. the scope's own revision head is present, so the rule-set revision this
///    read observed is owner-issued;
/// 4. every row is re-proved and decoded, and the resulting documents are
///    validated against their own records and policies.
///
/// # Errors
///
/// Returns the first [`NegativeMemoryReadRefusal`] that applies. A refusal
/// yields no rule set at all, so no caller can continue with a partial read.
pub fn resolve_negative_memory_rule_read(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> Result<ResolvedNegativeMemoryRuleSet, NegativeMemoryReadRefusal> {
    let scope_id = planned_scope(request)?;
    verify_response_binding(request, response)?;
    let truncated = payload_truncated(response)?;
    let rule_set_revision = observed_scope_revision(response, &scope_id)?;
    let records = decode_rows(response)?;
    let read = assemble_read(&scope_id, rule_set_revision, &records, truncated)?;
    Ok(ResolvedNegativeMemoryRuleSet {
        read,
        policies: records.iter().map(|entry| entry.policy.clone()).collect(),
        records: records.iter().map(|entry| entry.record.clone()).collect(),
        store_observed_fence: response.state_fence.clone(),
        scope_id,
        rule_set_revision,
        complete: !truncated,
    })
}

/// One decoded activation row: the validated record and the policy admitted
/// for exactly that record revision.
struct DecodedRule {
    record: NegativeMemoryFingerprint,
    policy: NegativeMemoryActionPolicy,
}

/// The typed scope the planned read was addressed to.
fn planned_scope(request: &NamedReadRequest) -> Result<ScopeId, NegativeMemoryReadRefusal> {
    if request.operation != NamedReadOperation::GetLearningRecordRange {
        return Err(NegativeMemoryReadRefusal::Request(
            "negative-memory rules are read only through GetLearningRecordRange".to_owned(),
        ));
    }
    request
        .scope_id
        .clone()
        .ok_or_else(|| NegativeMemoryReadRefusal::Request("rule read requires a scope".to_owned()))
}

/// Proves the response answers exactly the planned read and publishes the
/// store's own fence.
fn verify_response_binding(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> Result<(), NegativeMemoryReadRefusal> {
    if response.operation != NamedReadOperation::GetLearningRecordRange
        || response.operation != request.operation
    {
        return Err(NegativeMemoryReadRefusal::ResponseMismatch("operation"));
    }
    if response.state_fence != request.state_fence {
        return Err(NegativeMemoryReadRefusal::ResponseMismatch("fence"));
    }
    response
        .validate()
        .map_err(|_| NegativeMemoryReadRefusal::ResponseMismatch("shape"))?;
    if payload_fence(response)? != response.state_fence {
        return Err(NegativeMemoryReadRefusal::ResponseMismatch("payload_fence"));
    }
    Ok(())
}

/// Reads the store's own fence statement out of the served payload.
fn payload_fence(response: &NamedReadResponse) -> Result<StateFence, NegativeMemoryReadRefusal> {
    serde_json::from_value(
        response
            .payload
            .get(EXPERIENCE_PAGE_STATE_FENCE)
            .cloned()
            .ok_or(NegativeMemoryReadRefusal::Payload("state_fence"))?,
    )
    .map_err(|_| NegativeMemoryReadRefusal::Payload("state_fence"))
}

/// Reads the store's own truncation statement out of the served payload.
fn payload_truncated(response: &NamedReadResponse) -> Result<bool, NegativeMemoryReadRefusal> {
    response
        .payload
        .get(EXPERIENCE_PAGE_TRUNCATED)
        .and_then(Value::as_bool)
        .ok_or(NegativeMemoryReadRefusal::Payload("truncated"))
}

/// Resolves the scope's own revision head from the store's response.
///
/// This is the rule-set revision the read observed. It is read from the head
/// the **store** reported for this read's scope, never from a caller-supplied
/// string, so it cannot be chosen freely.
fn observed_scope_revision(
    response: &NamedReadResponse,
    scope_id: &ScopeId,
) -> Result<u64, NegativeMemoryReadRefusal> {
    let key = ResolvedNegativeMemoryRuleSet::revision_key(scope_id)?;
    response
        .revision_heads
        .iter()
        .find(|head| head.key == key && head.state_fence == response.state_fence)
        .map(|head| head.revision)
        .ok_or_else(|| NegativeMemoryReadRefusal::RuleSetRevisionAbsent {
            scope_id: scope_id.as_str().to_owned(),
        })
}

/// Decodes and re-proves every activation row the page delivered.
fn decode_rows(
    response: &NamedReadResponse,
) -> Result<Vec<DecodedRule>, NegativeMemoryReadRefusal> {
    let rows = response
        .payload
        .get(EXPERIENCE_PAGE_RECORDS)
        .and_then(Value::as_array)
        .ok_or(NegativeMemoryReadRefusal::Payload("records"))?;
    let mut decoded = Vec::with_capacity(rows.len());
    for row in rows {
        decoded.push(decode_row(row)?);
    }
    Ok(decoded)
}

/// Re-proves one served row against the bytes and digest the store committed.
fn decode_row(row: &Value) -> Result<DecodedRule, NegativeMemoryReadRefusal> {
    let refused = |handle: &str, detail: String| NegativeMemoryReadRefusal::RowNotAdmissible {
        handle: handle.to_owned(),
        detail,
    };
    let text = |name: &'static str| -> Result<String, NegativeMemoryReadRefusal> {
        row.get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| refused("", format!("row is missing {name}")))
    };
    let record_kind = text("record_kind")?;
    let handle = text("handle")?;
    let record_digest = text("record_digest")?;
    let record_json = text("record_json")?;
    if record_kind != LearningRecordKind::ActivationReceipt.as_str() {
        return Err(refused(
            &handle,
            "row is not a closed activation receipt".to_owned(),
        ));
    }
    if sha256_hex(record_json.as_bytes()) != record_digest {
        return Err(refused(
            &handle,
            "presented row digest does not cover the served record bytes".to_owned(),
        ));
    }
    let document: NegativeMemoryActivationDocument =
        serde_json::from_str(&record_json).map_err(|error| {
            refused(
                &handle,
                format!("activation document does not decode: {error}"),
            )
        })?;
    if document.handle() != handle {
        return Err(refused(
            &handle,
            "activation document does not name its own store row handle".to_owned(),
        ));
    }
    let record = document.record();
    let policy = document.policy();
    record
        .validate()
        .map_err(|error| refused(&handle, format!("rule record is invalid: {error}")))?;
    policy
        .validate()
        .map_err(|error| refused(&handle, format!("action policy is invalid: {error}")))?;
    policy
        .validate_binding(record)
        .map_err(|error| refused(&handle, format!("action policy is unbound: {error}")))?;
    document
        .validate_against_policy(record, policy)
        .map_err(|error| refused(&handle, error.to_string()))?;
    Ok(DecodedRule {
        record: record.clone(),
        policy: policy.clone(),
    })
}

/// Assembles the bounded read the matcher consumes.
fn assemble_read(
    scope_id: &ScopeId,
    rule_set_revision: u64,
    records: &[DecodedRule],
    truncated: bool,
) -> Result<NegativeMemoryCandidateRead, NegativeMemoryReadRefusal> {
    let read_handle = format!(
        "{ACTIVATION_HANDLE_PREFIX}-read:{}:{}",
        scope_id.as_str(),
        LearningRecordKind::ActivationReceipt.as_str()
    );
    let rules: Vec<NegativeMemoryFingerprint> =
        records.iter().map(|entry| entry.record.clone()).collect();
    let page_ref = format!("{read_handle}#1");
    let (declared_page_total, missing_page_refs, coverage) = if truncated {
        (
            DeclaredPageTotal::Unknown,
            vec![format!("{read_handle}#2")],
            FailureCoverage::Partial,
        )
    } else {
        (
            DeclaredPageTotal::Known { page_total: 1 },
            Vec::new(),
            FailureCoverage::Complete,
        )
    };
    let read = NegativeMemoryCandidateRead {
        read_handle,
        rule_set_revision: rule_set_revision.to_string(),
        rule_set_digest: rule_set_digest(&rules)?,
        declared_page_total,
        delivered_pages: vec![NegativeMemoryCandidatePage {
            page_ordinal: 1,
            page_ref,
            rules,
        }],
        missing_page_refs,
        coverage,
    };
    if u32::try_from(read.delivered_pages.len()).unwrap_or(u32::MAX) > MAX_RULE_PAGES {
        return Err(NegativeMemoryReadRefusal::Payload("delivered page count"));
    }
    read.validate()
        .map_err(|_| NegativeMemoryReadRefusal::Payload("read"))?;
    Ok(read)
}

/// Digest over the exact rule identities this read delivered.
///
/// The digest is order-invariant: the store's row order is a keyset artefact,
/// not a property of the rule set, so two reads of the same rows agree.
fn rule_set_digest(
    rules: &[NegativeMemoryFingerprint],
) -> Result<String, NegativeMemoryReadRefusal> {
    let mut identities: Vec<(&str, u64, &str)> = rules
        .iter()
        .map(|rule| {
            (
                rule.record_id.as_str(),
                rule.rule_revision,
                rule.record_digest.as_str(),
            )
        })
        .collect();
    identities.sort_unstable();
    let bytes = canonical_json_bytes(&identities)
        .map_err(|_| NegativeMemoryReadRefusal::Payload("rule_set_digest"))?;
    Ok(sha256_hex(&bytes))
}
