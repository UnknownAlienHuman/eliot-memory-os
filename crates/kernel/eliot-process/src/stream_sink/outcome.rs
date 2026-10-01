//! The one derived decision table from a declared coverage-gap set to the
//! durable outcome of a process-stream sink session.
//!
//! A provider adapter must not re-derive "which terminal does this gap set
//! mean" from its own gap comparisons: two tables would eventually disagree,
//! and one of them would be the one nobody reviews. This module is the single
//! owner of that mapping. It is derived from the declared
//! [`StreamEvidenceGap`] values themselves, so a new gap member fails to
//! compile here instead of silently inheriting the complete disposition.

use super::types::ProcessStreamSinkState;
use super::{ProcessStreamSinkError, StreamEvidenceGap};

/// Declared persistence-pressure disposition of one session.
///
/// The value is derived from the gaps the caller declared on the one
/// finalize/abort command; it never inspects provider I/O results, and it
/// grants no storage, semantic or verifier authority.
///
/// It is a derived decision, not a durable field, so it carries no wire
/// representation: nothing can round-trip a disposition in place of the gap
/// set it was derived from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessStreamPersistenceDisposition {
    /// No coverage gap: the admitted admissible prefix is the whole source.
    Complete,
    /// The provider never admitted the stream, so no durable source exists.
    ProviderUnavailable,
    /// The provider returned a known failure.
    ProviderFailed,
    /// The bounded staging window overflowed and shed the remainder while the
    /// pipe kept draining.
    BackpressureShed,
    /// The provider may or may not have committed the source.
    OutcomeUnknown,
    /// Current policy forbids durable retention or inline disclosure.
    PolicyWithheld,
    /// The declared redaction/transformation could not produce an exact
    /// admissible source.
    RedactionFailed,
}

impl ProcessStreamPersistenceDisposition {
    /// Derives the disposition from one declared coverage-gap set.
    ///
    /// Transport-axis gaps (`TRANSPORT_READ_FAILED`, `CANCELLED_BEFORE_EOF`,
    /// `CAPTURE_UNAVAILABLE`, `UNKNOWN_OUTCOME`) describe the physical read,
    /// not persistence pressure, so they contribute no disposition here; the
    /// transport status itself carries them.
    ///
    /// Several persistence gaps may legitimately travel together (a shed tail
    /// is both `PERSISTENCE_UNAVAILABLE` and `PERSISTENCE_BACKPRESSURE`), so
    /// the strongest declared reason wins by a fixed precedence instead of
    /// being rejected. Withholding always dominates: a prohibited or
    /// failed-redaction stream is never staged, whatever else was declared.
    #[must_use]
    pub fn from_gaps(gaps: &[StreamEvidenceGap]) -> Self {
        let mut disposition = Self::Complete;
        for gap in gaps {
            let candidate = match *gap {
                StreamEvidenceGap::PolicyProhibited => Self::PolicyWithheld,
                StreamEvidenceGap::RedactionFailed => Self::RedactionFailed,
                StreamEvidenceGap::PersistenceBackpressure => Self::BackpressureShed,
                StreamEvidenceGap::PersistenceFailed => Self::ProviderFailed,
                StreamEvidenceGap::PersistenceUnavailable => Self::ProviderUnavailable,
                StreamEvidenceGap::PersistenceUnknownOutcome => Self::OutcomeUnknown,
                StreamEvidenceGap::TransportReadFailed
                | StreamEvidenceGap::CancelledBeforeEof
                | StreamEvidenceGap::CaptureUnavailable
                | StreamEvidenceGap::UnknownOutcome => continue,
            };
            if candidate.precedence() > disposition.precedence() {
                disposition = candidate;
            }
        }
        disposition
    }

    /// Fixed precedence: a stronger reason never degrades into a weaker one.
    const fn precedence(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::ProviderUnavailable => 1,
            Self::ProviderFailed => 2,
            Self::BackpressureShed => 3,
            Self::OutcomeUnknown => 4,
            Self::PolicyWithheld => 5,
            Self::RedactionFailed => 6,
        }
    }

    /// The terminal state this disposition names for one exact coverage.
    ///
    /// `coverage_complete` is true only when the admissible bytes this
    /// provider admitted are provably the whole physical transport stream the
    /// command declared. A disposition that does not name a durable source
    /// (`COMPLETE_SOURCE` / `PARTIAL_SOURCE`) is never paired with staged
    /// bytes, and a coverage gap can never be paired with a whole-stream
    /// claim: both contradictions fail closed instead of minting a terminal.
    pub fn terminal_state(
        self,
        coverage_complete: bool,
    ) -> Result<ProcessStreamSinkState, ProcessStreamSinkError> {
        match (self, coverage_complete) {
            (Self::Complete, true) => Ok(ProcessStreamSinkState::CompleteSource),
            (Self::Complete, false) => Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "a gap-free command must cover the whole declared transport stream"
                    .to_owned(),
            }),
            (Self::BackpressureShed | Self::ProviderUnavailable, true) => {
                Ok(ProcessStreamSinkState::SourceUnavailable)
            }
            (Self::BackpressureShed | Self::ProviderUnavailable, false) => {
                Ok(ProcessStreamSinkState::PartialSource)
            }
            (Self::ProviderFailed, true) => Ok(ProcessStreamSinkState::SourceUnavailable),
            (Self::ProviderFailed, false) => Ok(ProcessStreamSinkState::PersistenceFailed),
            // An unknown provider effect cannot become a terminal in either
            // direction: only the retained reservation and its readback
            // reconcile may settle it.
            (Self::OutcomeUnknown, _) => Err(ProcessStreamSinkError::ProviderUnavailable),
            (Self::PolicyWithheld, _) => Ok(ProcessStreamSinkState::PolicyProhibited),
            (Self::RedactionFailed, _) => Ok(ProcessStreamSinkState::RedactionFailed),
        }
    }

    /// Whether the admitted admissible prefix may be staged for this
    /// disposition and coverage.
    ///
    /// This is exactly the set of dispositions whose terminal state names a
    /// durable source, so the staging decision and the minted terminal can
    /// never disagree.
    pub fn stages_admissible_bytes(self, coverage_complete: bool) -> bool {
        matches!(
            self.terminal_state(coverage_complete),
            Ok(ProcessStreamSinkState::CompleteSource | ProcessStreamSinkState::PartialSource)
        )
    }
}
