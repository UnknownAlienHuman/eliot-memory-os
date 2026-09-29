//! The one cross-owner bridge-event recovery selector contract (issue #2798).
//!
//! Before this module the selector crossed three owners — Kernel
//! (`host_request_route`), ORS (`store`) and the agent bridge
//! (`eliot-agent-bridge`) — as raw [`serde_json::Value`], with three
//! hand-rolled parsers of the same shape. A field that one parser knew and
//! another ignored was a silent, owner-dependent difference in what a
//! continuation request meant.
//!
//! One type is now the sole owner of the selector's wire shape:
//! [`BridgeRecoverySelector`]. Kernel validates mechanically through
//! [`BridgeRecoverySelector::decode`]; ORS consumes the same decoded value
//! for window/page meaning; the bridge builds and re-verifies it. There is no
//! second parse anywhere on this path.
//!
//! Two properties are load-bearing and are enforced here rather than at each
//! call site:
//!
//! * `deny_unknown_fields` closes the object at every nesting level, so a
//!   field this contract does not know can never be silently ignored. A
//!   mixed legacy/new shape is rejected, not partially honoured.
//! * [`BridgeRecoverySelector::validate`] compares every field's *value*
//!   against its declared bound (the closed kind set, the digest shape, the
//!   exclusive [`BridgeRecoverySelector::after_sequence`] window, the cursor
//!   arithmetic, and the shared page/gap budgets). It never merely checks
//!   presence or shape.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContractError, canonical_json_bytes, sha256_hex};

/// Wire revision of the keyed selector contract. A decoder that does not know
/// this revision refuses the selector instead of guessing its meaning.
pub const BRIDGE_RECOVERY_SELECTOR_VERSION: u64 = 2;

/// Wire revision for the owner-scoped process-restart resume selector.
/// Resume remains revision 2 and does not carry a continuation proof.
pub const BRIDGE_RECOVERY_RESUME_SELECTOR_VERSION: u64 = 2;

/// Wire revision for a resume selector pinned to one previously issued window.
/// This is a pure row selector: it carries no continuation proof or authority.
pub const BRIDGE_RECOVERY_RESUME_WINDOW_SELECTOR_VERSION: u64 = 1;

/// Key separator that may not appear inside a selector text field, because
/// every persisted owner key is built as `<namespace>::<suffix>`.
const SELECTOR_KEY_SEPARATOR: &str = "::";

/// Bounded text length for a selector identity field (stream, connection,
/// scope, principal). Matches the long-standing reconcile text bound.
pub const BRIDGE_RECOVERY_SELECTOR_TEXT_BYTES: usize = 1024;

/// Outer stream-enumeration page bound.
pub const BRIDGE_RECOVERY_SELECTOR_STREAM_LIMIT: u64 = 4;

/// Event page bound within one stream.
pub const BRIDGE_RECOVERY_SELECTOR_EVENT_LIMIT: u64 = 128;

/// Per-stream and unscoped gap page bound.
pub const BRIDGE_RECOVERY_SELECTOR_GAP_LIMIT: u64 = 256;

/// One bounded, owner-issued continuation selector over exactly one recovery
/// window.
///
/// The four independently bounded dimensions — outer stream enumeration, the
/// event page within a stream, per-stream gaps, and unscoped gaps — each carry
/// their own cursor and limit here, so one continuation can never stand in
/// for a different dimension's completeness. A returned length shorter than a
/// limit is never owner-issued completeness: the owner declares completion
/// only through the matching continuation absence, and the bounds below are
/// what make a short page still require a check.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeRecoverySelector {
    /// Resume the unique active recovery window admitted for the current
    /// authenticated owner scope. The caller supplies neither owner identity
    /// nor a window key; the owner must fail closed if that scope does not
    /// resolve to exactly one unexpired persisted window.
    Resume {
        /// Exactly [`BRIDGE_RECOVERY_RESUME_SELECTOR_VERSION`].
        version: u64,
    },
    /// Resume or recover the terminal disposition for this exact previously
    /// issued window. The key narrows owner lookup only; ORS must still
    /// revalidate the authenticated caller's lineage, principal, and scope.
    /// This selector deliberately carries no stale continuation proof; it
    /// constrains lookup to this exact row while authorization is rechecked.
    ResumeWindow {
        /// Exactly [`BRIDGE_RECOVERY_RESUME_WINDOW_SELECTOR_VERSION`].
        version: u64,
        /// Exact previously issued recovery window to resolve.
        window_key: String,
    },
    /// One page of the outer stream enumeration, starting after the
    /// owner-issued `after_stream` position.
    Streams {
        /// Exactly this version.
        version: u64,
        /// The owner-issued recovery window this page belongs to.
        window_key: String,
        /// Owner-authenticated proof of this exact continuation cursor,
        /// encoded as 64 lowercase hexadecimal characters.
        continuation_proof: String,
        /// Owner list position the page must advance past (exclusive).
        after_stream: String,
        /// Declared outer page bound for this dimension.
        stream_limit: u64,
    },
    /// One event page and one per-stream gap page inside a single stream.
    Stream {
        /// Exactly this version.
        version: u64,
        /// The owner-issued recovery window this page belongs to.
        window_key: String,
        /// Owner-authenticated proof of this exact continuation cursor,
        /// encoded as 64 lowercase hexadecimal characters.
        continuation_proof: String,
        /// Stream identity inside the window's owner scope.
        stream_id: String,
        /// Stream incarnation bound when the window cut it; a successor
        /// stream under the same name is not the same walk.
        owner_incarnation: u64,
        /// Owner binding revision bound when the window cut it.
        owner_revision: u64,
        /// Recovery view revision of the namespace, the stream-level
        /// movement detector.
        expected_revision: u64,
        /// Predecessor sequence the next page must advance past
        /// (exclusive); the continuation carries the LAST RETURNED
        /// sequence, never `last + 1`.
        after_sequence: u64,
        /// Finite upper bound of the window's retained interval.
        upper_sequence: u64,
        /// Retention floor of the window's cut.
        retention_floor: u64,
        /// Declared event page bound for this dimension.
        event_limit: u64,
        /// Per-stream gap cursor (exclusive offset).
        gap_offset: u64,
        /// Declared per-stream gap page bound for this dimension.
        gap_limit: u64,
    },
    /// One unscoped-gap page starting after the owner-issued scope.
    UnscopedGaps {
        /// Exactly this version.
        version: u64,
        /// The owner-issued recovery window this page belongs to.
        window_key: String,
        /// Owner-authenticated proof of this exact continuation cursor,
        /// encoded as 64 lowercase hexadecimal characters.
        continuation_proof: String,
        /// Owner namespace this unscoped-gap page starts after.
        after_gap_scope: String,
        /// Unscoped-gap cursor (exclusive offset).
        gap_offset: u64,
        /// Declared unscoped gap page bound for this dimension.
        gap_limit: u64,
    },
}

impl BridgeRecoverySelector {
    /// Decodes one selector from the wire exactly once, everywhere.
    ///
    /// `deny_unknown_fields` rejects a legacy shape mixed with new fields, and
    /// a non-object, a null, or a missing `kind` is refused outright — an
    /// absent selector is [`Option::None`] at the call site, never a
    /// "default" object.
    pub fn decode(value: &serde_json::Value) -> Result<Self, ContractError> {
        let selector: Self =
            serde_json::from_value(value.clone()).map_err(|_| ContractError::Blank {
                field: "bridge_recovery_selector",
            })?;
        selector.validate()?;
        Ok(selector)
    }

    /// The owner-issued window this selector is bound to, when the selector
    /// already carries one. An owner-scoped [`Self::Resume`] intentionally
    /// has no caller-supplied window key; [`Self::ResumeWindow`] is pinned to
    /// its exact key without carrying continuation authority.
    pub fn window_key(&self) -> Option<&str> {
        match self {
            Self::Resume { .. } => None,
            Self::ResumeWindow { window_key, .. }
            | Self::Streams { window_key, .. }
            | Self::Stream { window_key, .. }
            | Self::UnscopedGaps { window_key, .. } => Some(window_key.as_str()),
        }
    }

    /// Canonical bytes of the whole selector, under a versioned domain
    /// separator. This is the preimage a page commitment binds, so two
    /// selectors that mean the same walk can never share a commitment with
    /// two selectors that do not.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let tagged = CanonicalBridgeRecoverySelector {
            domain: "eliot.bridge-event.recovery-selector.v2",
            selector: self,
        };
        canonical_json_bytes(&tagged).map_err(|_| ContractError::Blank {
            field: "bridge_recovery_selector",
        })
    }

    /// Returns canonical, domain-separated bytes for the unsigned keyed
    /// continuation selector used as an ORS MAC preimage.
    ///
    /// The keyed variants are validated first, then their required proof
    /// field is blanked before serialization. Neither resume selector carries
    /// a cursor proof, so neither can be used as a keyed continuation preimage.
    pub fn continuation_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut unsigned = self.clone();
        match &mut unsigned {
            Self::Resume { .. } | Self::ResumeWindow { .. } => {
                return Err(ContractError::Blank {
                    field: "bridge_recovery_selector.continuation_proof",
                });
            }
            Self::Streams {
                continuation_proof, ..
            }
            | Self::Stream {
                continuation_proof, ..
            }
            | Self::UnscopedGaps {
                continuation_proof, ..
            } => continuation_proof.clear(),
        }

        let tagged = CanonicalBridgeRecoverySelector {
            domain: "eliot.bridge-event.recovery-selector-continuation.v2",
            selector: &unsigned,
        };
        canonical_json_bytes(&tagged).map_err(|_| ContractError::Blank {
            field: "bridge_recovery_selector.continuation_proof",
        })
    }

    /// Binds every field's value against its declared bound.
    ///
    /// This is the mechanical check the Kernel runs before forwarding, and
    /// ORS re-runs it on the decoded value. It compares content, not
    /// existence: a selector that carries the right keys with the wrong
    /// cursor, the wrong incarnation, or an out-of-window bound fails here.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_version()?;
        match self {
            Self::Resume { .. } => {}
            Self::ResumeWindow { window_key, .. } => {
                validate_digest(window_key, "bridge_recovery_selector.window_key")?;
            }
            Self::Streams {
                window_key,
                continuation_proof,
                after_stream,
                stream_limit,
                ..
            } => {
                validate_digest(window_key, "bridge_recovery_selector.window_key")?;
                validate_digest(
                    continuation_proof,
                    "bridge_recovery_selector.continuation_proof",
                )?;
                validate_text(after_stream, "bridge_recovery_selector.after_stream")?;
                if *stream_limit == 0 || *stream_limit > BRIDGE_RECOVERY_SELECTOR_STREAM_LIMIT {
                    return Err(ContractError::Blank {
                        field: "bridge_recovery_selector.stream_limit",
                    });
                }
            }
            Self::Stream {
                window_key,
                continuation_proof,
                stream_id,
                owner_incarnation,
                owner_revision,
                expected_revision,
                after_sequence,
                upper_sequence,
                retention_floor,
                event_limit,
                gap_offset,
                gap_limit,
                ..
            } => {
                validate_digest(window_key, "bridge_recovery_selector.window_key")?;
                validate_digest(
                    continuation_proof,
                    "bridge_recovery_selector.continuation_proof",
                )?;
                validate_text(stream_id, "bridge_recovery_selector.stream_id")?;
                if stream_id.contains(SELECTOR_KEY_SEPARATOR) {
                    return Err(ContractError::Blank {
                        field: "bridge_recovery_selector.stream_id",
                    });
                }
                // A zero incarnation or revision cannot name a real owner
                // cut, so it could never be compared against one.
                if *owner_incarnation == 0 || *owner_revision == 0 || *expected_revision == 0 {
                    return Err(ContractError::Blank {
                        field: "bridge_recovery_selector.owner_revision",
                    });
                }
                if *after_sequence > *upper_sequence
                    || *retention_floor > *upper_sequence
                    || (*upper_sequence > 0 && after_sequence.saturating_add(1) < *retention_floor)
                {
                    return Err(ContractError::Blank {
                        field: "bridge_recovery_selector.after_sequence",
                    });
                }
                if *event_limit == 0 || *event_limit > BRIDGE_RECOVERY_SELECTOR_EVENT_LIMIT {
                    return Err(ContractError::Blank {
                        field: "bridge_recovery_selector.event_limit",
                    });
                }
                if *gap_limit == 0
                    || *gap_limit > BRIDGE_RECOVERY_SELECTOR_GAP_LIMIT
                    || gap_offset.checked_add(*gap_limit).is_none()
                {
                    return Err(ContractError::Blank {
                        field: "bridge_recovery_selector.gap_limit",
                    });
                }
            }
            Self::UnscopedGaps {
                window_key,
                continuation_proof,
                after_gap_scope,
                gap_offset,
                gap_limit,
                ..
            } => {
                validate_digest(window_key, "bridge_recovery_selector.window_key")?;
                validate_digest(
                    continuation_proof,
                    "bridge_recovery_selector.continuation_proof",
                )?;
                validate_digest(after_gap_scope, "bridge_recovery_selector.after_gap_scope")?;
                if *gap_limit == 0
                    || *gap_limit > BRIDGE_RECOVERY_SELECTOR_GAP_LIMIT
                    || gap_offset.checked_add(*gap_limit).is_none()
                {
                    return Err(ContractError::Blank {
                        field: "bridge_recovery_selector.gap_limit",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_version(&self) -> Result<(), ContractError> {
        let (version, expected_version) = match self {
            Self::Resume { version } => (*version, BRIDGE_RECOVERY_RESUME_SELECTOR_VERSION),
            Self::ResumeWindow { version, .. } => {
                (*version, BRIDGE_RECOVERY_RESUME_WINDOW_SELECTOR_VERSION)
            }
            Self::Streams { version, .. }
            | Self::Stream { version, .. }
            | Self::UnscopedGaps { version, .. } => (*version, BRIDGE_RECOVERY_SELECTOR_VERSION),
        };
        if version != expected_version {
            return Err(ContractError::Blank {
                field: "bridge_recovery_selector.version",
            });
        }
        Ok(())
    }
}

/// Canonical preimage wrapper: a domain separator plus the selector, so a
/// selector commitment can never collide with any other hashed object.
#[derive(Serialize)]
struct CanonicalBridgeRecoverySelector<'a> {
    domain: &'static str,
    selector: &'a BridgeRecoverySelector,
}

/// The closed set of ORS-side window dispositions a recovery page can carry.
///
/// These reuse the recovery reason vocabulary the bridge already owns
/// (`window-moved-refresh-required`, `window-expired-refresh-required`)
/// instead of introducing a parallel scheme. `Moved` is the refresh-required
/// case: compaction, a retention floor, an owner revision, or a stream
/// incarnation moved inside the window, so the walk cannot continue and the
/// current rows must NOT be stitched onto the old walk.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeRecoveryWindowDisposition {
    /// The page is the real answer for the requested selector.
    Active,
    /// Required material inside the window moved; a refresh is required and
    /// no partial page was stitched.
    Moved,
    /// The window's finite lifetime ended; a refresh is required.
    Expired,
}

impl BridgeRecoveryWindowDisposition {
    /// The existing bridge-side reason vocabulary for this disposition.
    ///
    /// These are the literal reason strings `eliot-agent-bridge-core` already
    /// publishes for the same two refresh-required cases, so the closed
    /// vocabulary gains no parallel scheme and no renamed member.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Moved => "window-moved-refresh-required",
            Self::Expired => "window-expired-refresh-required",
        }
    }
}

/// The unresolved frontier of one recovery page: the dimensions the owner
/// could NOT complete, each named explicitly so an incomplete enumeration
/// stays visibly incomplete instead of reading as a short but whole page.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// The four dimensions the owner must enumerate independently (I7.23): outer
// stream list, unscoped gaps, per-stream pages/gaps, and material outside the
// proven scope.  Each is a separate fact, so a struct of four booleans is the
// honest shape; a single `complete` flag would re-collapse them.
#[allow(clippy::struct_excessive_bools)]
pub struct BridgeRecoveryUnresolvedFrontier {
    /// Outer stream enumeration is not finished.
    pub stream_list_pending: bool,
    /// Unscoped-gap enumeration is not finished.
    pub unscoped_gaps_pending: bool,
    /// One or more stream pages or per-stream gap pages are not finished.
    pub stream_pages_pending: bool,
    /// Material exists outside the proven owner scope.
    pub unproven_scope_present: bool,
}

/// One owner-issued page commitment: a canonical digest binding the window,
/// the exact selector, the disposition, the unresolved frontier, and the
/// returned facts together.
///
/// It is computable and checkable entirely from the response itself, so a
/// consumer can verify the whole page BEFORE it swaps any live state. There
/// is no second journal and no second digest scheme: this is one
/// SHA-256 over canonical bytes, the same primitive the existing
/// `reconcile_key` preimage uses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeRecoveryPageCommitment {
    version: u64,
    window_key: String,
    disposition: BridgeRecoveryWindowDisposition,
    unresolved: BridgeRecoveryUnresolvedFrontier,
    digest: String,
}

/// Commitment revision of the page-commitment preimage contract.
pub const BRIDGE_RECOVERY_PAGE_COMMITMENT_VERSION: u64 = 1;

impl BridgeRecoveryPageCommitment {
    /// Computes the commitment over the exact selector, the owner's
    /// disposition, the unresolved frontier, and the returned page facts.
    ///
    /// `facts` is the page body exactly as it is returned to the consumer
    /// (page content, not its re-serialization): the commitment must bind
    /// the bytes the consumer will actually see.
    pub fn compute(
        selector: Option<&BridgeRecoverySelector>,
        window_key: &str,
        disposition: BridgeRecoveryWindowDisposition,
        unresolved: &BridgeRecoveryUnresolvedFrontier,
        facts: &serde_json::Value,
    ) -> Result<Self, ContractError> {
        validate_digest(window_key, "bridge_recovery_commitment.window_key")?;
        let body = serde_json::json!({
            "version": BRIDGE_RECOVERY_PAGE_COMMITMENT_VERSION,
            "domain": "eliot.bridge-event.recovery-page.v1",
            "window_key": window_key,
            "selector": selector.map_or(serde_json::Value::Null, |s| {
                serde_json::to_value(s).unwrap_or(serde_json::Value::Null)
            }),
            "disposition": disposition,
            "unresolved": unresolved,
            "facts": facts,
        });
        let bytes = canonical_json_bytes(&body).map_err(|_| ContractError::Blank {
            field: "bridge_recovery_commitment",
        })?;
        Ok(Self {
            version: BRIDGE_RECOVERY_PAGE_COMMITMENT_VERSION,
            window_key: window_key.to_owned(),
            disposition,
            unresolved: unresolved.clone(),
            digest: sha256_hex(&bytes),
        })
    }

    /// The commitment digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The owner-issued window this commitment belongs to.
    pub fn window_key(&self) -> &str {
        &self.window_key
    }

    /// The owner's disposition for this page.
    pub const fn disposition(&self) -> BridgeRecoveryWindowDisposition {
        self.disposition
    }

    /// The explicit unresolved frontier recorded with the commitment.
    pub const fn unresolved(&self) -> &BridgeRecoveryUnresolvedFrontier {
        &self.unresolved
    }

    /// The commitment revision this value was computed under.
    pub const fn version(&self) -> u64 {
        self.version
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty()
        || value.len() > BRIDGE_RECOVERY_SELECTOR_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ContractError::Blank { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractError::Blank { field });
    }
    Ok(())
}
