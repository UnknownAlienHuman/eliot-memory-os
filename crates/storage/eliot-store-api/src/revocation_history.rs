//! Durable Store-owned authority-revocation history contract (issue #1732).
//!
//! A named read is a projection of two durable facts: an append-only
//! `RecordedRevocation` ledger and one fenced `RevocationHistoryRoot` watermark.
//! The root is independent of the authority/graph revision carried by a
//! closure.  The root binds every root identity, per-root revision, record
//! count, and a hash chain over the exact record bytes.  Missing, malformed,
//! stale, or partially hydrated data is an error; it is never converted into
//! an empty "no revocations" result.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;
use eliot_security_contracts::RevocationReason;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{StoreError, canonical_json_bytes, sha256_hex};

/// Version of the revocation-history payload shape served by the named read.
pub const REVOCATION_HISTORY_PAYLOAD_VERSION: u32 = 2;
/// Maximum revocation closures one history read may return.
pub const REVOCATION_HISTORY_MAX_RECORDS: u32 = 32;
/// Stable namespace of the Store-owned history root record.
pub const REVOCATION_HISTORY_ROOT_NAMESPACE: &str = "authority-revocation-root";
/// Stable key of the single Store-owned history root record.
pub const REVOCATION_HISTORY_ROOT_KEY: &str = "history";
/// Reserved exact origin selector used by the durable root-index read.
///
/// It is a Store-owned selector, not a grant identity. The handler returns
/// the complete [`RevocationHistoryRoot`] and no origin projection; callers
/// must never use it as a semantic authority root.
pub const REVOCATION_HISTORY_ROOT_SELECTOR: &str = "__eliot_store_revocation_root_index__";
/// Schema carried by the Store-owned history root record.
pub const REVOCATION_HISTORY_ROOT_SCHEMA: &str = "eliot.store.authority-revocation-root.v1";
/// Hash-chain seed used by an explicitly empty, initialized history root.
pub const REVOCATION_HISTORY_GENESIS_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Returns the canonical digest of an exact affected-reference vector.
///
/// The vector is sorted before this function is called by all producers.  The
/// function itself does not sort: silently changing the caller's denominator
/// would make a digest/count mismatch look valid.
pub fn affected_reference_digest(affected_refs: &[String]) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(&affected_refs)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Returns the canonical digest of a state fence.
pub fn revocation_fence_digest(state_fence: &StateFence) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(state_fence)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Returns the canonical digest of one durable record.
pub fn recorded_revocation_digest(record: &RecordedRevocation) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(record)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Advances the history hash chain with one exact record digest.
pub fn advance_revocation_history_digest(
    previous: &str,
    record_digest: &str,
) -> Result<String, StoreError> {
    validate_digest(previous, "revocation_history.previous_digest")?;
    validate_digest(record_digest, "revocation_history.record_digest")?;
    let bytes = canonical_json_bytes(&(previous, record_digest))
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// One durably recorded revocation closure.
///
/// `dependent_refs` is the exact affected-reference denominator.  It includes
/// `root_ref` and every dependent, in strictly increasing lexical order.  The
/// digest and count are persisted beside that vector and are rechecked on every
/// read; a caller cannot replace the denominator with a similar-looking set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedRevocation {
    /// Stable closure identity from the recording mutation.
    pub closure_id: String,
    /// Revoked origin named by the closure.
    pub root_ref: String,
    /// Exact affected references: the origin plus every dependent.
    pub dependent_refs: Vec<String>,
    /// Canonical digest of `dependent_refs`.
    pub affected_digest: String,
    /// Exact number of entries in `dependent_refs`.
    pub affected_count: u64,
    /// Terminal reason the origin was invalidated.
    pub invalidation_reason: RevocationReason,
    /// Exact state fence at which this record was committed.
    pub state_fence: StateFence,
    /// Canonical digest of `state_fence`.
    pub fence_digest: String,
    /// Authority/graph revision carried by the originating closure.
    pub revision: u64,
    /// Independent Store history revision at which this record was appended.
    pub history_revision: u64,
    /// Independent per-origin root revision at which this record was appended.
    pub root_revision: u64,
}

impl RecordedRevocation {
    /// Validates the complete persisted record and all digest/count/fence
    /// couplings.  No provider-specific interpretation occurs here.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_reference(&self.closure_id, "closure_id")?;
        validate_reference(&self.root_ref, "root_ref")?;
        if self.root_ref == REVOCATION_HISTORY_ROOT_SELECTOR {
            return Err(StoreError::InvalidField {
                field: "root_ref",
                reason: "the Store history root selector is reserved",
            });
        }
        if self.dependent_refs.is_empty() {
            return Err(StoreError::InvalidField {
                field: "dependent_refs",
                reason: "recorded revocation must name its affected references",
            });
        }
        let mut previous: Option<&str> = None;
        for reference in &self.dependent_refs {
            validate_reference(reference, "dependent_ref")?;
            if let Some(previous) = previous
                && previous >= reference.as_str()
            {
                return Err(StoreError::InvalidField {
                    field: "dependent_refs",
                    reason: "affected references must be strictly sorted and unique",
                });
            }
            previous = Some(reference.as_str());
        }
        if !self.dependent_refs.iter().any(|r| r == &self.root_ref) {
            return Err(StoreError::InvalidField {
                field: "dependent_refs",
                reason: "affected references must include the revoked origin",
            });
        }
        if self.affected_count != self.dependent_refs.len() as u64 {
            return Err(StoreError::InvalidField {
                field: "affected_count",
                reason: "does not match the exact affected-reference count",
            });
        }
        validate_digest(&self.affected_digest, "affected_digest")?;
        if affected_reference_digest(&self.dependent_refs)? != self.affected_digest {
            return Err(StoreError::InvalidField {
                field: "affected_digest",
                reason: "does not match the exact affected-reference vector",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_digest(&self.fence_digest, "fence_digest")?;
        if revocation_fence_digest(&self.state_fence)? != self.fence_digest {
            return Err(StoreError::InvalidField {
                field: "fence_digest",
                reason: "does not match the persisted state fence",
            });
        }
        for (value, field) in [
            (self.revision, "revision"),
            (self.history_revision, "history_revision"),
            (self.root_revision, "root_revision"),
        ] {
            if value == 0 {
                return Err(StoreError::InvalidField {
                    field,
                    reason: "must be non-zero",
                });
            }
        }
        Ok(())
    }
}

/// The independent Store-owned root/watermark for the complete history.
///
/// This is deliberately separate from `RecordedRevocation::revision`, which
/// is the authority/graph revision.  `root_refs` is the all-root denominator;
/// an origin-specific read may return no closure while this root still proves
/// that history was hydrated and current.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationHistoryRoot {
    pub schema: String,
    pub history_revision: u64,
    pub state_fence: StateFence,
    pub record_count: u64,
    pub root_refs: Vec<String>,
    pub root_revisions: BTreeMap<String, u64>,
    pub ledger_digest: String,
}

impl RevocationHistoryRoot {
    /// Constructs the explicit empty root used by Store genesis.
    pub fn genesis(state_fence: StateFence) -> Result<Self, StoreError> {
        let root = Self {
            schema: REVOCATION_HISTORY_ROOT_SCHEMA.to_owned(),
            history_revision: 1,
            state_fence,
            record_count: 0,
            root_refs: Vec::new(),
            root_revisions: BTreeMap::new(),
            ledger_digest: REVOCATION_HISTORY_GENESIS_DIGEST.to_owned(),
        };
        root.validate()?;
        Ok(root)
    }

    /// Validates the root shape independently of a provider read.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema != REVOCATION_HISTORY_ROOT_SCHEMA {
            return Err(StoreError::InvalidProjection);
        }
        if self.history_revision == 0 {
            return Err(StoreError::InvalidProjection);
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.record_count > self.history_revision.saturating_sub(1) {
            return Err(StoreError::InvalidProjection);
        }
        let mut previous: Option<&str> = None;
        for root in &self.root_refs {
            validate_reference(root, "history_root.root_ref")?;
            if let Some(previous) = previous
                && previous >= root.as_str()
            {
                return Err(StoreError::InvalidProjection);
            }
            previous = Some(root.as_str());
        }
        if self.root_revisions.len() != self.root_refs.len()
            || self
                .root_refs
                .iter()
                .any(|root| !self.root_revisions.contains_key(root))
        {
            return Err(StoreError::InvalidProjection);
        }
        if self.root_revisions.values().any(|revision| *revision == 0) {
            return Err(StoreError::InvalidProjection);
        }
        validate_digest(&self.ledger_digest, "history_root.ledger_digest")?;
        if self.record_count == 0
            && (!self.root_refs.is_empty()
                || !self.root_revisions.is_empty()
                || self.ledger_digest != REVOCATION_HISTORY_GENESIS_DIGEST)
        {
            return Err(StoreError::InvalidProjection);
        }
        if self.record_count > 0 && self.root_refs.is_empty() {
            return Err(StoreError::InvalidProjection);
        }
        Ok(())
    }

    /// Rechecks the complete all-root ledger against this root.  Callers must
    /// pass every record, not only the origin selected by a named read.
    pub fn validate_against_records(
        &self,
        records: &[RecordedRevocation],
    ) -> Result<(), StoreError> {
        self.validate()?;
        if self.record_count != records.len() as u64 {
            return Err(StoreError::InvalidProjection);
        }
        let mut ordered = records.to_vec();
        ordered.sort_by(|left, right| {
            left.history_revision
                .cmp(&right.history_revision)
                .then_with(|| left.closure_id.cmp(&right.closure_id))
        });
        let mut previous_revision = 1_u64;
        let mut digest = REVOCATION_HISTORY_GENESIS_DIGEST.to_owned();
        let mut seen_closures = BTreeSet::new();
        let mut root_max_revisions: BTreeMap<&str, u64> = BTreeMap::new();
        for record in &ordered {
            record.validate()?;
            if !seen_closures.insert(record.closure_id.as_str()) {
                return Err(StoreError::InvalidProjection);
            }
            if record.state_fence != self.state_fence
                || record.history_revision != previous_revision + 1
                || record.history_revision > self.history_revision
                || self.root_revisions.get(&record.root_ref) != Some(&record.root_revision)
            {
                return Err(StoreError::InvalidProjection);
            }
            let observed_root_revision = root_max_revisions
                .entry(record.root_ref.as_str())
                .or_insert(0);
            if record.root_revision != observed_root_revision.saturating_add(1) {
                return Err(StoreError::InvalidProjection);
            }
            *observed_root_revision = record.root_revision;
            previous_revision = record.history_revision;
            digest =
                advance_revocation_history_digest(&digest, &recorded_revocation_digest(record)?)?;
        }
        if previous_revision != self.history_revision
            || root_max_revisions
                .iter()
                .any(|(root, revision)| self.root_revisions.get(*root) != Some(revision))
            || digest != self.ledger_digest
        {
            return Err(StoreError::InvalidProjection);
        }
        let observed_roots: BTreeSet<&str> = records
            .iter()
            .map(|record| record.root_ref.as_str())
            .collect();
        let declared_roots: BTreeSet<&str> = self.root_refs.iter().map(String::as_str).collect();
        if observed_roots != declared_roots {
            return Err(StoreError::InvalidProjection);
        }
        Ok(())
    }
}

/// Versioned exact revocation-history payload for one origin read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationHistoryPayload {
    /// Payload shape version.
    pub version: u32,
    /// Exact origin selector echoed from the request.
    pub origin_ref: String,
    /// Independent Store history-root revision represented by this view.
    /// The authority/graph revision on each closure is deliberately separate.
    pub source_revision: u64,
    /// Independent complete Store history root/watermark.
    pub history_root: RevocationHistoryRoot,
    /// Recorded closures for this origin, in closure-id order.
    pub closures: Vec<RecordedRevocation>,
}

impl RevocationHistoryPayload {
    /// Validates the complete origin projection without a response fence.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != REVOCATION_HISTORY_PAYLOAD_VERSION {
            return Err(StoreError::InvalidField {
                field: "version",
                reason: "unsupported revocation-history payload version",
            });
        }
        validate_reference(&self.origin_ref, "origin_ref")?;
        if self.source_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "source_revision",
                reason: "must be non-zero",
            });
        }
        self.history_root.validate()?;
        if self.source_revision != self.history_root.history_revision {
            return Err(StoreError::InvalidProjection);
        }
        if !self
            .history_root
            .root_refs
            .iter()
            .any(|root| root == &self.origin_ref)
            && !self.closures.is_empty()
        {
            return Err(StoreError::InvalidProjection);
        }
        let mut previous: Option<&str> = None;
        for closure in &self.closures {
            closure.validate()?;
            if closure.root_ref != self.origin_ref
                || closure.state_fence != self.history_root.state_fence
                || closure.history_revision > self.history_root.history_revision
                || self.history_root.root_revisions.get(&closure.root_ref)
                    != Some(&closure.root_revision)
            {
                return Err(StoreError::InvalidProjection);
            }
            if let Some(previous) = previous
                && previous >= closure.closure_id.as_str()
            {
                return Err(StoreError::InvalidField {
                    field: "closures",
                    reason: "must arrive in strictly increasing closure_id order",
                });
            }
            previous = Some(closure.closure_id.as_str());
        }
        Ok(())
    }

    /// Revalidates the payload against the exact response fence.
    pub fn validate_for_fence(&self, state_fence: &StateFence) -> Result<(), StoreError> {
        self.validate()?;
        if &self.history_root.state_fence != state_fence {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }
}

/// Parses and validates one revocation-history payload value.
pub fn parse_revocation_history_payload(
    payload: &Value,
) -> Result<RevocationHistoryPayload, StoreError> {
    let parsed: RevocationHistoryPayload =
        serde_json::from_value(payload.clone()).map_err(|_| StoreError::InvalidField {
            field: "payload",
            reason: "revocation-history payload is malformed",
        })?;
    parsed.validate()?;
    Ok(parsed)
}

fn validate_reference(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "revocation reference must be a non-blank string",
        });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}
