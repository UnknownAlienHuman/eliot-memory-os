//! Durable authority-revocation-history wire contract (issue #686).
//!
//! The Governor records committed influence revocations through the
//! `RecordAuthorityRevocation` named mutation and serves the CURRENT
//! revocation history through the `GetAuthorityRevocationHistory` named
//! read. Both operations are known-but-unsupported until a store-owned
//! slice activates their catalogue rows with proven handlers: the typed
//! parameter contracts and this payload shape are already closed so the
//! Governor decision edge (envelope construction, evidence decoding) is
//! exact before activation.
//!
//! The read payload carries only actually recorded revocations under the
//! exact response fence — never a synthesized default. An empty `closures`
//! array with a nonzero `source_revision` is the source explicitly
//! attesting zero revocations; a missing history is not representable here
//! and refuses upstream, never as an empty closure.
//!
//! Issue #2966, step 2: every recorded row declares the full versioned
//! evidence coordinates its producer vouches for — the owner namespace, the
//! traversal bounds the membership was proven under, the completeness
//! disposition, the omissions, the terminal influence state, the recorded
//! commit fence/epoch, and the affected-member count and digest plus the
//! canonical request hash. The decoding adapter carries these coordinates
//! verbatim into the authority-specific evidence, and recovery recomputes and
//! compares the content-addressed ones; nothing downstream mints them. A v1
//! payload carries no producer coordinates and is refused rather than
//! reinterpreted.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use eliot_contracts::StateFence;
use eliot_security_contracts::{InfluenceState, RevocationReason};

use crate::StoreError;

/// Version of the revocation-history payload shape served by the named read.
///
/// Consumers match on this version before interpreting `closures`; any
/// shape change bumps it on every side, mirroring
/// `EVIDENCE_PACK_PAYLOAD_VERSION`. Version 2 rows carry the full
/// producer-declared evidence coordinates (issue #2966, step 2); version 1
/// rows carry none and are refused, never upgraded with defaults.
pub const REVOCATION_HISTORY_PAYLOAD_VERSION: u32 = 2;

/// Maximum revocation closures one history read may return.
///
/// The bound is explicit per request (`max_records` decimal-string
/// selector) and every handler refuses an over-bound request with
/// [`StoreError::PayloadTooLarge`] instead of returning a successful
/// over-bound view. 32 keeps the worst case far below
/// [`READ_MAX_OUTPUT_BYTES`](crate::operation_catalogue::READ_MAX_OUTPUT_BYTES):
/// each closure carries short stable references plus fixed provenance.
pub const REVOCATION_HISTORY_MAX_RECORDS: u32 = 32;

/// Traversal bounds one recorded revocation declares its membership was proven under.
///
/// The wire shape of the bounded-engine limits, carried so recovery admits
/// under the bounds the evidence declared. The decoding adapter maps this
/// to the engine bounds verbatim; a zero limit refuses here, never widens.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedRevocationBounds {
    /// Maximum admitted nodes.
    pub max_nodes: u64,
    /// Maximum examined edges.
    pub max_edges: u64,
    /// Maximum traversal depth.
    pub max_depth: u64,
    /// Maximum admitted result members.
    pub max_result: u64,
    /// Maximum cumulative work units.
    pub max_work: u64,
    /// Maximum outstanding frontier width.
    pub max_frontier: u64,
    /// Maximum resume rounds.
    pub max_time: u64,
}

impl RecordedRevocationBounds {
    /// Rejects a bounds set with any zero limit.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.max_nodes == 0
            || self.max_edges == 0
            || self.max_depth == 0
            || self.max_result == 0
            || self.max_work == 0
            || self.max_frontier == 0
            || self.max_time == 0
        {
            return Err(StoreError::InvalidField {
                field: "bounds",
                reason: "recorded revocation bounds must be non-zero",
            });
        }
        Ok(())
    }
}

/// Declared completeness of one recorded revocation's own affected evidence.
///
/// The disposition is what the durable producer CLAIMS about the closure it
/// committed. The wire carries every variant; recovery admits only
/// `Complete` and refuses the rest as incomplete coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecordedRevocationDisposition {
    /// The committed membership is declared to be the whole affected
    /// denominator.
    Complete,
    /// The committed membership is declared to omit at least one dependent.
    Partial,
    /// The producer cannot state whether the membership is whole.
    Unknown,
}

/// One durably recorded revocation served by the history read.
///
/// This is the recorded form of one `eliot-influence` revocation closure:
/// the revoked origin, its exact affected set (origin plus dependents, in
/// affected order), the terminal invalidation reason, and the durable
/// history revision the record was committed at — plus every coordinate the
/// versioned authority evidence binds: the owner namespace the row was
/// served under, the recorded commit fence/epoch the closure was committed
/// under, the bounds the membership was proven under, the declared
/// completeness disposition and omissions, the terminal influence state,
/// and the affected-member count and digest plus the canonical request hash.
/// All of them are producer declarations the decoding adapter carries
/// verbatim; recovery recomputes and compares the content-addressed ones.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedRevocation {
    /// Stable closure identity from the recording mutation.
    pub closure_id: String,
    /// Revoked origin named by the closure.
    pub root_ref: String,
    /// Exact affected references: the origin plus every dependent.
    pub dependent_refs: Vec<String>,
    /// Terminal reason the origin was invalidated.
    pub invalidation_reason: RevocationReason,
    /// Durable history revision this record was committed at.
    pub revision: u64,
    /// Fence/epoch the durable commit that produced this closure was committed
    /// under, read out of that commit's own recorded authority binding.
    ///
    /// This is a RECORDED coordinate, not the serving read's fence: the durable
    /// owner projects it from the immutable commit receipt it already holds, and
    /// recovery compares it against its own live fence. A row that carried only
    /// the read-time fence would bind the closure to whichever read projected
    /// it and would compare a value with itself at restore.
    pub commit_state_fence: StateFence,
    /// Declared graph/snapshot owner namespace this row was served under:
    /// the authority root that owns the committed closure.
    pub owner_namespace: String,
    /// Declared traversal bounds the committed membership was proven under.
    pub bounds: RecordedRevocationBounds,
    /// Declared completeness of the committed membership itself.
    pub disposition: RecordedRevocationDisposition,
    /// References the committed membership declares it omitted.
    pub omissions: Vec<String>,
    /// Terminal influence state the producer observed for the closure.
    pub current_influence: InfluenceState,
    /// Declared count of the committed affected membership: the origin plus
    /// every dependent.
    pub affected_member_count: u64,
    /// Declared canonical digest of that exact committed affected membership.
    pub affected_member_digest: String,
    /// Declared canonical request hash of the exact presented closure bytes.
    pub canonical_request_digest: String,
}

impl RecordedRevocation {
    /// Validates the recorded closure shape without interpreting authority.
    ///
    /// Shape only: the disposition, influence state, count and digests are
    /// carried for the authority decision and are never pre-refused here,
    /// so a producer-declared incompleteness or a tampered coordinate
    /// reaches recovery and refuses there, under its exact cause.
    ///
    /// The one coordinate this stage does check is the recorded commit fence:
    /// it is re-derived from the ORIGINAL recorded value with the contract's own
    /// [`StateFence::validate`], never recomputed from the serving read, so a
    /// malformed commit coordinate refuses at the wire instead of reaching the
    /// authority decision as a usable epoch.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_reference(&self.closure_id, "closure_id")?;
        validate_reference(&self.root_ref, "root_ref")?;
        if self.dependent_refs.is_empty() {
            return Err(StoreError::InvalidField {
                field: "dependent_refs",
                reason: "recorded revocation must name its dependents",
            });
        }
        for dependent in &self.dependent_refs {
            validate_reference(dependent, "dependent_ref")?;
        }
        if self.revision == 0 {
            return Err(StoreError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        self.commit_state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_reference(&self.owner_namespace, "owner_namespace")?;
        self.bounds.validate()?;
        for omission in &self.omissions {
            validate_reference(omission, "omission")?;
        }
        validate_reference(&self.affected_member_digest, "affected_member_digest")?;
        validate_reference(&self.canonical_request_digest, "canonical_request_digest")?;
        Ok(())
    }
}

/// Versioned exact revocation-history payload for one read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationHistoryPayload {
    /// Payload shape version (see [`REVOCATION_HISTORY_PAYLOAD_VERSION`]).
    pub version: u32,
    /// Exact origin selector echoed from the request.
    pub origin_ref: String,
    /// Durable history revision this view is current at.
    pub source_revision: u64,
    /// Recorded revocation closures affecting the origin, in closure order.
    pub closures: Vec<RecordedRevocation>,
}

impl RevocationHistoryPayload {
    /// Validates the complete history view before it is consumed.
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
        let mut previous: Option<&str> = None;
        for closure in &self.closures {
            closure.validate()?;
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
}

/// Parses and validates one revocation-history payload value.
///
/// Rejects a wrong-version, malformed, unordered, or unknown-field payload
/// fail-closed instead of serving a lossy history view.
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
