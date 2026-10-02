//! Synthetic Host Event Log sink owner (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: the bounded admission queue of the synthetic
//! tree. Delivery stays an honest incomplete: the sink seam is not reachable
//! from this fixture, so the boundary records mapping evidence only.

use std::collections::VecDeque;

/// Bounded admission capacity of the synthetic sink queue.
pub const EVENT_LOG_QUEUE_CAPACITY: usize = 4;

/// Fixed Event Log source identity of the synthetic tree.
pub const EVENT_LOG_SOURCE: &str = "EliotHost";

/// One synthetic admitted Event Log record.
pub struct EventLogRecord {
    pub source: &'static str,
    pub event_id: u32,
}

impl EventLogRecord {
    /// Map one consumer event onto its fixed Event Log identity.
    pub fn mapping() -> Self {
        Self {
            source: EVENT_LOG_SOURCE,
            event_id: 102,
        }
    }
}

/// Bounded admission queue of the synthetic sink.
pub struct EventLogQueue {
    records: VecDeque<EventLogRecord>,
}

impl EventLogQueue {
    /// Open the queue at the frozen capacity.
    pub fn with_default_capacity() -> Self {
        Self {
            records: VecDeque::new(),
        }
    }

    /// Admit one record, dropping it when the bound is reached.
    pub fn try_admit(&mut self, record: EventLogRecord) -> Result<(), String> {
        if self.records.len() >= EVENT_LOG_QUEUE_CAPACITY {
            return Err("event_log.queue_full".to_owned());
        }
        self.records.push_back(record);
        Ok(())
    }

    /// Records currently admitted.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Frozen bound of the queue.
    pub fn capacity(&self) -> usize {
        EVENT_LOG_QUEUE_CAPACITY
    }
}
