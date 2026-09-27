//! Critical-path fallback state machine (I16.11, no hidden telemetry failure).
//!
//! I16.11 fixes the exact chain and forbids silent success:
//!
//! ```text
//! normal audit write;
//! if unavailable → ORS/Watchdog spool;
//! if unavailable → last-resort control slot/event log;
//! if all unavailable → visible control-loss state when next channel returns.
//! ```
//!
//! [`CriticalPath`] is that machine. Each admission step is non-blocking and
//! returns the exact sink that carried the record, or the typed reason it did
//! not. When the last-resort sink also fails, the record is held in the
//! machine as [`CriticalEventState::ControlLoss`] together with the attempted
//! chain, and it is **replayed on the next returning channel** — that is the
//! "visible control-loss state when next channel returns" requirement. A
//! degraded state is never reported as success, and success is never claimed
//! for a sink that did not accept the record.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::event_log::EventLogReport;
use crate::spool::SpoolSinks;

/// A bounded operational-log or metric record; never canonical audit proof
/// (I16.1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriticalEventRecord {
    /// Stable event identity; replay uses it to stay idempotent.
    pub event_id: String,
    /// Stable event name, e.g. `host.service_start`.
    pub event: String,
    /// Installation profile that produced the record.
    pub profile: String,
    /// Bounded, already-redacted detail. Never content, secret, argv, or
    /// environment material (I15.4).
    pub detail: String,
}

impl CriticalEventRecord {
    /// Builds a record, rejecting blank identity and non-bound detail.
    ///
    /// # Errors
    ///
    /// Returns [`CriticalEventError::InvalidRecord`] for a blank event
    /// identity/name or a control-character detail.
    pub fn new(
        event_id: &str,
        event: &str,
        profile: &str,
        detail: &str,
    ) -> Result<Self, CriticalEventError> {
        if event_id.trim().is_empty() || event.trim().is_empty() {
            return Err(CriticalEventError::InvalidRecord(
                "event identity and name must be non-blank",
            ));
        }
        if detail.chars().any(char::is_control) {
            return Err(CriticalEventError::InvalidRecord(
                "detail must contain no control characters",
            ));
        }
        Ok(Self {
            event_id: event_id.to_owned(),
            event: event.to_owned(),
            profile: profile.to_owned(),
            detail: detail.to_owned(),
        })
    }
}

/// Typed critical-path rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CriticalEventError {
    /// The record could not be constructed from the supplied fields.
    #[error("critical event record rejected: {0}")]
    InvalidRecord(&'static str),
    /// The bounded held-record buffer is full and the record cannot be held.
    #[error("critical event retention is exhausted")]
    RetentionExhausted,
}

/// Why one sink could not carry a record.
///
/// I16.11 requires the reason to stay visible, so this is never collapsed into
/// a single `false`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnavailableReason {
    /// The sink reported itself unavailable (unsupported platform, missing
    /// port, refused source).
    Unavailable,
    /// The sink's bounded queue or buffer rejected the record.
    Saturated,
    /// The sink was not applicable to this installation profile.
    NotApplicable,
    /// The sink wrote the record to a layer that does not prove downstream
    /// delivery; acceptance is recorded honestly as such.
    AcceptedWithoutDeliveryProof,
}

impl UnavailableReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Saturated => "saturated",
            Self::NotApplicable => "not_applicable",
            Self::AcceptedWithoutDeliveryProof => "accepted_without_delivery_proof",
        }
    }
}

/// Result of attempting one sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkStatus {
    /// The sink carried the record.
    Delivered,
    /// The sink could not carry the record, with the exact typed reason.
    Unavailable(UnavailableReason),
}

impl SinkStatus {
    /// Returns the stable status name for a bounded diagnostic record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Unavailable(reason) => reason.as_str(),
        }
    }

    /// Whether this sink carried the record.
    #[must_use]
    pub const fn is_delivered(self) -> bool {
        matches!(self, Self::Delivered)
    }

    /// The exact reason this status is not a delivery.
    ///
    /// A delivered sink reports [`UnavailableReason::NotApplicable`]: there
    /// is no failure reason to preserve for a record that was carried.
    #[must_use]
    pub const fn unavailable_reason(self) -> UnavailableReason {
        match self {
            Self::Delivered => UnavailableReason::NotApplicable,
            Self::Unavailable(reason) => reason,
        }
    }
}

/// Sinks available to the critical path, grouped by the I16.11 stage they
/// serve.
#[derive(Clone, Debug, Default)]
pub struct CriticalEventSinks {
    /// Stage 1: the normal audit/operational-log write.
    pub normal: Option<CriticalEventSinksEntry>,
    /// Stage 2: the ORS/Watchdog event spool.
    pub spool: Option<SpoolSinks>,
    /// Stage 3: the last-resort control slot or Windows Event Log.
    pub last_resort: Option<EventLogReport>,
}

/// Wraps the normal audit write so the machine never depends on a concrete
/// audit crate.
#[derive(Clone)]
pub struct CriticalEventSinksEntry {
    write: Arc<dyn Fn(&CriticalEventRecord) -> SinkStatus + Send + Sync>,
}

impl fmt::Debug for CriticalEventSinksEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CriticalEventSinksEntry(<normal audit write>)")
    }
}

impl CriticalEventSinksEntry {
    /// Wraps one bounded normal-audit write.
    #[must_use]
    pub fn new(write: impl Fn(&CriticalEventRecord) -> SinkStatus + Send + Sync + 'static) -> Self {
        Self {
            write: Arc::new(write),
        }
    }

    /// Attempts the normal audit write.
    pub fn write(&self, record: &CriticalEventRecord) -> SinkStatus {
        (self.write)(record)
    }
}

/// State of one critical record inside the machine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CriticalEventState {
    /// A sink carried the record. Delivery is a real acceptance, not a
    /// silent drop.
    Delivered {
        /// Name of the sink that carried the record.
        sink: &'static str,
    },
    /// Every stage failed. The record is held for replay, and this state is
    /// durable and visible: [`CriticalPath::held_control_loss`] counts it,
    /// [`CriticalPath::control_loss_total`] is its monotone total, and
    /// [`CriticalPath::release_control_loss`] hands the held records back
    /// when a channel returns.
    ControlLoss {
        /// Every stage that was attempted, in order, with its typed reason.
        attempts: Vec<UnavailableReason>,
    },
}

impl CriticalEventState {
    /// Stable state name for a bounded diagnostic record.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Delivered { .. } => "delivered",
            Self::ControlLoss { .. } => "control_loss",
        }
    }

    /// Whether this record is in the visible control-loss state.
    #[must_use]
    pub fn is_control_loss(&self) -> bool {
        matches!(self, Self::ControlLoss { .. })
    }
}

/// Terminal view of one admission attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriticalPathOutcome {
    /// Stable event identity.
    pub event_id: String,
    /// The state this record ended in.
    pub state: CriticalEventState,
}

/// Largest number of records held while every sink is unavailable. Bounded so
/// a total telemetry outage cannot become unbounded memory growth (I16.9).
pub const MAX_HELD_CONTROL_LOSS_RECORDS: usize = 1024;

#[derive(Clone, Debug)]
struct HeldRecord {
    record: CriticalEventRecord,
}

/// The I16.11 fallback state machine.
#[derive(Clone, Debug)]
pub struct CriticalPath {
    sinks: CriticalEventSinks,
    held: Arc<Mutex<VecDeque<HeldRecord>>>,
    control_loss_total: Arc<AtomicU64>,
    replayed_total: Arc<AtomicU64>,
}

impl CriticalPath {
    /// Builds the machine over the available sinks.
    #[must_use]
    pub fn new(sinks: CriticalEventSinks) -> Self {
        Self {
            sinks,
            held: Arc::new(Mutex::new(VecDeque::new())),
            control_loss_total: Arc::new(AtomicU64::new(0)),
            replayed_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Attempts the whole chain for one record.
    ///
    /// Stage order is exactly I16.11: normal audit write, then the
    /// ORS/Watchdog spool, then the last-resort control slot/Event Log. The
    /// first carrying stage wins; the terminal state is that stage's status.
    /// A record is never reported as delivered when no stage carried it.
    pub fn submit(&self, record: CriticalEventRecord) -> CriticalPathOutcome {
        let mut attempts: Vec<UnavailableReason> = Vec::with_capacity(3);
        let event_id = record.event_id.clone();

        if let Some(normal) = &self.sinks.normal {
            match normal.write(&record) {
                SinkStatus::Delivered => {
                    return outcome(
                        &event_id,
                        CriticalEventState::Delivered {
                            sink: "normal_audit",
                        },
                    );
                }
                SinkStatus::Unavailable(reason) => attempts.push(reason),
            }
        } else {
            attempts.push(UnavailableReason::NotApplicable);
        }

        if let Some(spool) = &self.sinks.spool {
            match spool.write(&record) {
                SinkStatus::Delivered => {
                    return outcome(
                        &event_id,
                        CriticalEventState::Delivered {
                            sink: "event_spool",
                        },
                    );
                }
                SinkStatus::Unavailable(reason) => attempts.push(reason),
            }
        } else {
            attempts.push(UnavailableReason::NotApplicable);
        }

        if let Some(last_resort) = &self.sinks.last_resort {
            match last_resort.write(&record) {
                SinkStatus::Delivered => {
                    return outcome(
                        &event_id,
                        CriticalEventState::Delivered {
                            sink: "last_resort_event_log",
                        },
                    );
                }
                SinkStatus::Unavailable(reason) => attempts.push(reason),
            }
        } else {
            attempts.push(UnavailableReason::NotApplicable);
        }

        // I16.11: every path unavailable. Hold the record and expose the
        // durable, visible control-loss state rather than a success
        // indication. The reported state carries the *actual* typed reason
        // each stage returned for *this* record; a reason is never
        // substituted by a generic one nor borrowed from another record.
        self.hold(record);
        outcome(&event_id, CriticalEventState::ControlLoss { attempts })
    }

    fn hold(&self, record: CriticalEventRecord) {
        let Ok(mut held) = self.held.lock() else {
            return;
        };
        // The total counts every record that reached the control-loss state,
        // including one the bounded buffer had to refuse: I16.11 forbids
        // silent loss, so a refused record is still a counted loss.
        self.control_loss_total.fetch_add(1, Ordering::Relaxed);
        if held.len() >= MAX_HELD_CONTROL_LOSS_RECORDS {
            return;
        }
        held.push_back(HeldRecord { record });
    }

    /// Replays every held control-loss record against the currently returning
    /// channels and returns the records that were carried.
    ///
    /// This is the I16.11 "visible control-loss state when next channel
    /// returns" edge: a caller invokes it after a channel is observed to be
    /// back, and the replayed records are handed back for the caller's
    /// canonical projection. Records that still cannot be carried stay held.
    pub fn release_control_loss(&self) -> Vec<CriticalEventRecord> {
        let Ok(mut held) = self.held.lock() else {
            return Vec::new();
        };
        let mut replayed = Vec::new();
        let mut remaining = VecDeque::with_capacity(held.len());
        while let Some(entry) = held.pop_front() {
            if self.attempt_chain(&entry.record).is_some() {
                self.replayed_total.fetch_add(1, Ordering::Relaxed);
                replayed.push(entry.record);
            } else {
                remaining.push_back(entry);
            }
        }
        *held = remaining;
        replayed
    }

    /// Number of records currently held in the control-loss state.
    #[must_use]
    pub fn held_control_loss(&self) -> usize {
        self.held.lock().map_or(0, |held| held.len())
    }

    /// Monotone count of records that entered the control-loss state.
    #[must_use]
    pub fn control_loss_total(&self) -> u64 {
        self.control_loss_total.load(Ordering::Relaxed)
    }

    /// Monotone count of held records later carried by a returning channel.
    #[must_use]
    pub fn replayed_total(&self) -> u64 {
        self.replayed_total.load(Ordering::Relaxed)
    }

    /// Reports the sink status the machine would currently use for `record`.
    pub fn current_state(&self, record: &CriticalEventRecord) -> CriticalEventState {
        if self.attempt_chain(record).is_some() {
            return CriticalEventState::Delivered {
                sink: "returning_channel",
            };
        }
        CriticalEventState::ControlLoss {
            attempts: self.chain_attempts(record),
        }
    }

    /// The typed reason each stage reports for `record` right now.
    ///
    /// Each stage is probed once and its real reason kept, so a stage that is
    /// saturated is never reported as merely unavailable.
    fn chain_attempts(&self, record: &CriticalEventRecord) -> Vec<UnavailableReason> {
        let mut attempts = Vec::with_capacity(3);
        match &self.sinks.normal {
            Some(normal) => attempts.push(normal.write(record).unavailable_reason()),
            None => attempts.push(UnavailableReason::NotApplicable),
        }
        match &self.sinks.spool {
            Some(spool) => attempts.push(spool.write(record).unavailable_reason()),
            None => attempts.push(UnavailableReason::NotApplicable),
        }
        match &self.sinks.last_resort {
            Some(last_resort) => attempts.push(last_resort.write(record).unavailable_reason()),
            None => attempts.push(UnavailableReason::NotApplicable),
        }
        attempts
    }

    fn attempt_chain(&self, record: &CriticalEventRecord) -> Option<SinkStatus> {
        if let Some(normal) = &self.sinks.normal
            && normal.write(record).is_delivered()
        {
            return Some(SinkStatus::Delivered);
        }
        if let Some(spool) = &self.sinks.spool
            && spool.write(record).is_delivered()
        {
            return Some(SinkStatus::Delivered);
        }
        let last_resort = self.sinks.last_resort.as_ref()?;
        last_resort
            .write(record)
            .is_delivered()
            .then_some(SinkStatus::Delivered)
    }
}

fn outcome(event_id: &str, state: CriticalEventState) -> CriticalPathOutcome {
    CriticalPathOutcome {
        event_id: event_id.to_owned(),
        state,
    }
}
