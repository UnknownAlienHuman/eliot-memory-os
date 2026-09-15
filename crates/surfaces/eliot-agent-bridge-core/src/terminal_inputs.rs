//! Issue #9 Slice A transport evidence for terminal reconciliation.
//!
//! This module carries the MGR01 half of Antigravity terminal
//! reconciliation: fingerprint passthrough, raw/normalized host-event
//! history with sequences and cursors, attempt state transitions, typed
//! recovery directives, candidate canonical-write references, and the
//! timeout/cancel/parse/late-success/duplicate/unknown/disconnect edges.
//!
//! Everything here is transport evidence. The stale UI/CLI display, an
//! earlier error event, and the canonical operation references are kept as
//! independent fields until reduction. This crate computes no terminal
//! attempt/session disposition: the reducer lives outside the bridge
//! (MGR02 governor/canonical land) and consumes
//! [`TerminalReductionInputs`] read-only.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};

use super::{BridgeError, OutstandingDeliveryView, validate_text};

use eliot_agent_api::{AttemptState, HostEventEnvelope, RouteFingerprint};

/// Bounded transport journal capacity for observed host events.
///
/// When the cap is reached the oldest observation rotates out and the
/// incomplete-coverage flag is raised explicitly, so missing coverage can
/// never be mistaken for a clean history downstream.
pub const TERMINAL_JOURNAL_CAPACITY: usize = 1024;

/// Typed recovery rule for one invalid/recoverable host call.
///
/// The corrected call always carries a new identity: the retry/new-identity
/// rule is enforced by [`RecoveryDirective::prescribe`], never by convention.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryDirectiveKind {
    RetryWithNewIdentity,
    CorrectAndResubmit,
}

/// Typed recovery directive chaining one observed recoverable failure to its
/// corrected call. Both identities reference host-event identities carried by
/// the transport journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDirective {
    for_event: String,
    corrected_event: String,
    kind: RecoveryDirectiveKind,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecoveryDirective {
    for_event: String,
    corrected_event: String,
    kind: RecoveryDirectiveKind,
    reason: String,
}

impl<'de> Deserialize<'de> for RecoveryDirective {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRecoveryDirective::deserialize(deserializer)?;
        Self::prescribe(raw.for_event, raw.corrected_event, raw.kind, raw.reason)
            .map_err(de::Error::custom)
    }
}

impl RecoveryDirective {
    /// Prescribes the typed recovery for one observed recoverable failure.
    ///
    /// Fails closed when any reference is blank or when the corrected call
    /// reuses the failed identity instead of minting a new one.
    pub fn prescribe(
        for_event: impl Into<String>,
        corrected_event: impl Into<String>,
        kind: RecoveryDirectiveKind,
        reason: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let for_event = for_event.into();
        let corrected_event = corrected_event.into();
        let reason = reason.into();
        validate_text(&for_event, "recovery_directive.for_event")?;
        validate_text(&corrected_event, "recovery_directive.corrected_event")?;
        validate_text(&reason, "recovery_directive.reason")?;
        if for_event == corrected_event {
            return Err(BridgeError::InvalidContract {
                field: "recovery_directive.corrected_event",
                reason: "corrected call must use a new identity under the retry/new-identity rule",
            });
        }
        Ok(Self {
            for_event,
            corrected_event,
            kind,
            reason,
        })
    }

    pub fn for_event(&self) -> &str {
        &self.for_event
    }

    pub fn corrected_event(&self) -> &str {
        &self.corrected_event
    }

    pub const fn kind(&self) -> RecoveryDirectiveKind {
        self.kind
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Opaque candidate canonical-write references carried by the transport.
///
/// The bridge never mints, validates, or applies a write envelope: these
/// are correlation references only. Submission, receipt, and readback stay
/// independent optional fields so an unresolved effect or a missing exact
/// readback remains visible to the reducer as missing input, never as an
/// implied success.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWriteRefs {
    #[serde(default)]
    submission: Option<String>,
    #[serde(default)]
    receipt: Option<String>,
    #[serde(default)]
    readback: Option<String>,
}

impl CanonicalWriteRefs {
    pub fn record_submission(&mut self, reference: impl Into<String>) -> Result<(), BridgeError> {
        Self::record_slot(
            &mut self.submission,
            reference.into(),
            "canonical_write_refs.submission_ref",
        )
    }

    pub fn record_receipt(&mut self, reference: impl Into<String>) -> Result<(), BridgeError> {
        Self::record_slot(
            &mut self.receipt,
            reference.into(),
            "canonical_write_refs.receipt_ref",
        )
    }

    pub fn record_readback(&mut self, reference: impl Into<String>) -> Result<(), BridgeError> {
        Self::record_slot(
            &mut self.readback,
            reference.into(),
            "canonical_write_refs.readback_ref",
        )
    }

    fn record_slot(
        slot: &mut Option<String>,
        reference: String,
        field: &'static str,
    ) -> Result<(), BridgeError> {
        validate_text(&reference, field)?;
        if let Some(current) = slot
            && *current != reference
        {
            return Err(BridgeError::InvalidTransition(
                "canonical write reference already recorded under a different identity",
            ));
        }
        *slot = Some(reference);
        Ok(())
    }

    pub fn submission_ref(&self) -> Option<&str> {
        self.submission.as_deref()
    }

    pub fn receipt_ref(&self) -> Option<&str> {
        self.receipt.as_deref()
    }

    pub fn readback_ref(&self) -> Option<&str> {
        self.readback.as_deref()
    }

    /// Reports whether submission, receipt, and exact readback references
    /// are all present. This is a completeness fact about carried inputs,
    /// not a disposition: only the reducer may decide what it means.
    #[must_use]
    pub const fn has_complete_canonical_chain(&self) -> bool {
        self.submission.is_some() && self.receipt.is_some() && self.readback.is_some()
    }
}

/// Transport edge kept independent until reduction.
///
/// Each edge records one terminal-relevant observation (timeout,
/// cancellation, parse failure, late success, duplicate corrected call,
/// unknown commit/effect, or process disconnect) without resolving it. A
/// later-looking success never clears an edge recorded here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportEdgeKind {
    Timeout,
    CancelRequested,
    ParseFailure,
    LateSuccess,
    DuplicateCorrectedCall,
    UnknownCommit,
    Disconnect,
}

impl fmt::Display for TransportEdgeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Timeout => "TIMEOUT",
            Self::CancelRequested => "CANCEL_REQUESTED",
            Self::ParseFailure => "PARSE_FAILURE",
            Self::LateSuccess => "LATE_SUCCESS",
            Self::DuplicateCorrectedCall => "DUPLICATE_CORRECTED_CALL",
            Self::UnknownCommit => "UNKNOWN_COMMIT",
            Self::Disconnect => "DISCONNECT",
        };
        formatter.write_str(name)
    }
}

/// One independently recorded transport edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportEdge {
    kind: TransportEdgeKind,
    event_ref: String,
    sequence: u64,
    detail: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTransportEdge {
    kind: TransportEdgeKind,
    event_ref: String,
    sequence: u64,
    detail: String,
}

impl<'de> Deserialize<'de> for TransportEdge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawTransportEdge::deserialize(deserializer)?;
        Self::record(raw.kind, raw.event_ref, raw.sequence, raw.detail).map_err(de::Error::custom)
    }
}

impl TransportEdge {
    /// Records one transport edge. The sequence is the host observation
    /// order; zero is rejected because it cannot be ordered.
    pub fn record(
        kind: TransportEdgeKind,
        event_ref: impl Into<String>,
        sequence: u64,
        detail: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let event_ref = event_ref.into();
        let detail = detail.into();
        validate_text(&event_ref, "transport_edge.event_ref")?;
        validate_text(&detail, "transport_edge.detail")?;
        if sequence == 0 {
            return Err(BridgeError::InvalidContract {
                field: "transport_edge.sequence",
                reason: "edge sequence must be non-zero to preserve observation order",
            });
        }
        Ok(Self {
            kind,
            event_ref,
            sequence,
            detail,
        })
    }

    pub const fn kind(&self) -> TransportEdgeKind {
        self.kind
    }

    pub fn event_ref(&self) -> &str {
        &self.event_ref
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// One observed attempt state transition, recorded verbatim.
///
/// Whether the transition is legal is decided by the reducer, not the
/// transport: this log preserves the observed order for that decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptTransition {
    from: AttemptState,
    to: AttemptState,
    sequence: u64,
}

impl AttemptTransition {
    /// Records one observed attempt transition. Zero carries no order and
    /// is rejected.
    pub fn observe(
        from: AttemptState,
        to: AttemptState,
        sequence: u64,
    ) -> Result<Self, BridgeError> {
        if sequence == 0 {
            return Err(BridgeError::InvalidContract {
                field: "attempt_transition.sequence",
                reason: "transition sequence must be non-zero to preserve observation order",
            });
        }
        Ok(Self { from, to, sequence })
    }

    pub const fn from(&self) -> AttemptState {
        self.from
    }

    pub const fn to(&self) -> AttemptState {
        self.to
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Explicit coverage facts that forbid silent reduction to success.
///
/// Every flag defaults to false for a fresh attach and is raised only by an
/// observed edge or by journal rotation. The reducer must treat any raised
/// flag as blocking success; the transport itself reduces nothing.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageFlags {
    #[serde(default)]
    unknown_commit: bool,
    #[serde(default)]
    cancel_unconfirmed: bool,
    #[serde(default)]
    incomplete_coverage: bool,
}

impl CoverageFlags {
    pub const fn unknown_commit(&self) -> bool {
        self.unknown_commit
    }

    pub const fn cancel_unconfirmed(&self) -> bool {
        self.cancel_unconfirmed
    }

    pub const fn incomplete_coverage(&self) -> bool {
        self.incomplete_coverage
    }

    #[must_use]
    pub const fn mark_unknown_commit(mut self) -> Self {
        self.unknown_commit = true;
        self
    }

    #[must_use]
    pub const fn mark_cancel_unconfirmed(mut self) -> Self {
        self.cancel_unconfirmed = true;
        self
    }

    #[must_use]
    pub const fn mark_incomplete_coverage(mut self) -> Self {
        self.incomplete_coverage = true;
        self
    }
}

/// Terminal reduction inputs projected by the bridge transport.
///
/// This is the MGR01 half of issue #9: every field the reducer needs, with
/// history and terminal evidence carried independently:
/// - `history` keeps every observed host event, including earlier
///   recoverable errors, in observation order;
/// - `stale_ui_disposition` preserves the stale UI/CLI display verbatim;
/// - `error_event_refs` cites the earlier error events as history;
/// - `canonical` carries the candidate submission/receipt/readback
///   references independently of both fields above.
///
/// No method here derives a terminal disposition. Unknown commit/effect,
/// unconfirmed cancellation, or incomplete coverage is carried as explicit
/// flags for the reducer to honor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalReductionInputs {
    fingerprint: Option<RouteFingerprint>,
    history: Vec<HostEventEnvelope>,
    attempt_transitions: Vec<AttemptTransition>,
    recovery_directives: Vec<RecoveryDirective>,
    stale_ui_disposition: Option<String>,
    error_event_refs: Vec<String>,
    canonical: CanonicalWriteRefs,
    edges: Vec<TransportEdge>,
    coverage: CoverageFlags,
    cursors: BTreeMap<String, u64>,
    outstanding: Vec<OutstandingDeliveryView>,
}

impl TerminalReductionInputs {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fingerprint: Option<RouteFingerprint>,
        history: Vec<HostEventEnvelope>,
        attempt_transitions: Vec<AttemptTransition>,
        recovery_directives: Vec<RecoveryDirective>,
        stale_ui_disposition: Option<String>,
        error_event_refs: Vec<String>,
        canonical: CanonicalWriteRefs,
        edges: Vec<TransportEdge>,
        coverage: CoverageFlags,
        cursors: BTreeMap<String, u64>,
        outstanding: Vec<OutstandingDeliveryView>,
    ) -> Self {
        Self {
            fingerprint,
            history,
            attempt_transitions,
            recovery_directives,
            stale_ui_disposition,
            error_event_refs,
            canonical,
            edges,
            coverage,
            cursors,
            outstanding,
        }
    }

    /// Route fingerprint passed through from the most recent observed host
    /// event, if any. The transport never invents or rewrites it.
    pub const fn fingerprint(&self) -> Option<&RouteFingerprint> {
        self.fingerprint.as_ref()
    }

    /// Immutable host-event history in observation order, including earlier
    /// recoverable errors. A later success never removes entries here.
    pub fn history(&self) -> &[HostEventEnvelope] {
        &self.history
    }

    pub fn attempt_transitions(&self) -> &[AttemptTransition] {
        &self.attempt_transitions
    }

    pub fn recovery_directives(&self) -> &[RecoveryDirective] {
        &self.recovery_directives
    }

    /// Stale UI/CLI terminal display preserved verbatim. It is independent
    /// of [`Self::canonical`] until the reducer compares them.
    pub fn stale_ui_disposition(&self) -> Option<&str> {
        self.stale_ui_disposition.as_deref()
    }

    /// Earlier error events kept queryable as non-terminal history.
    pub fn error_event_refs(&self) -> &[String] {
        &self.error_event_refs
    }

    pub const fn canonical(&self) -> &CanonicalWriteRefs {
        &self.canonical
    }

    pub fn edges(&self) -> &[TransportEdge] {
        &self.edges
    }

    pub const fn coverage(&self) -> CoverageFlags {
        self.coverage
    }

    pub fn cursors(&self) -> &BTreeMap<String, u64> {
        &self.cursors
    }

    pub fn outstanding(&self) -> &[OutstandingDeliveryView] {
        &self.outstanding
    }
}
