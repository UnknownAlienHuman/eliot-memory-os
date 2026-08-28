//! Readiness projection — read-only Kernel readiness identity/freshness projection.
//!
//! Source-backed handles (current source is authoritative):
//! - Architecture A13.2 (Kernel/failure-domain health/unavailable guarantees, module lifecycle):
//!   readiness health is unavailable by default; proof requires Active Consumed Kernel,
//!   exact `HostState` readiness observation bound to the active Kernel checksum/process/Job/authority,
//!   and explicit freshness evidence. Absent freshness lease the projection stays Unknown.
//! - Implementation I16.1 (reports/projections are not truth):
//!   this module is a read-only projection of durable Host journal state; it never asserts
//!   liveness or freshness beyond what the durable wire proves. `observed_at` is an opaque
//!   `PlatformHandle` without wall-clock binding, so freshness cannot be proven from the record
//!   schema alone.
//! - Truth-boundary: no readiness, lifecycle, SCM, canonical, or supervision authority is added
//!   or changed here. Mechanical split only — exact behavior, signatures, public facade
//!   (`ReadinessContour`), tests, and imports preserved; `observed_at` remains opaque.
//!
//! Crate-level note: `readiness_projection` owns only `ReadinessContour`, `readiness_gap`,
//! and `inspect_readiness_from_host_state` plus direct helpers. Host-journal inspection,
//! transaction-stage, live observers, service registration, kernel/store/eliotd/watchdog cells,
//! supervision verifier/projection, provider process, and frozen/retried/Luna/Dreamer scopes are
//! explicitly excluded.

#![forbid(unsafe_code)]

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::ComponentState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReadinessContour {
    pub proof_status: ComponentState,
    pub age_gap: String,
}

fn readiness_gap() -> String {
    "readiness identity is durable, but KernelReadinessObservationRecord.observed_at is an opaque PlatformHandle; a typed Host-authored timestamp or bounded readiness lease is required before freshness can be proven".to_owned()
}

// Readiness projection deliberately keeps every identity comparison adjacent;
// freshness remains Unknown until the durable wire carries a typed time lease.
#[allow(clippy::too_many_lines)]
pub(super) fn inspect_readiness_from_host_state(
    host_state: Option<&eliot_host_state::HostState>,
    deadline: Instant,
) -> ReadinessContour {
    if Instant::now() >= deadline {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "deadline exceeded before readiness inspection".to_owned(),
                gap: "bounded deadline".to_owned(),
            },
            age_gap: "bounded deadline".to_owned(),
        };
    }
    let Some(host_state) = host_state else {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no HostState for readiness; Host journal is not validated".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    };
    let Some(kernel) = host_state.kernel.as_ref() else {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no active Kernel record for readiness".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    };
    if kernel.state != eliot_runtime_contracts::KernelActivationState::Active
        || kernel.one_time_nonce.state() != eliot_host_state::NonceState::Consumed
        || host_state.prior_kernel_unknown
    {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: format!(
                    "Kernel not Active Consumed for readiness: state {:?} nonce {:?} prior_unknown {}",
                    kernel.state,
                    kernel.one_time_nonce.state(),
                    host_state.prior_kernel_unknown
                ),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    }
    if host_state.readiness_observations.is_empty() {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no KernelReadinessObservationRecord is present".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    }
    let mut seen_requests = std::collections::HashSet::new();
    let mut seen_receipts = std::collections::HashSet::new();
    let mut duplicate = false;
    for observation in &host_state.readiness_observations {
        let request = observation.probe_request_digest.as_str().to_owned();
        let receipt = observation.ready_receipt_digest.as_str().to_owned();
        if !seen_requests.insert(request) || !seen_receipts.insert(receipt) {
            duplicate = true;
        }
    }
    if duplicate {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason:
                    "readiness observation digests are duplicated; freshness requires fresh digests"
                        .to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    }
    let Some(observed) = host_state.readiness_observations.last() else {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no KernelReadinessObservationRecord is present".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    };
    let active_checksum = match eliot_host_state::record_checksum(
        &eliot_host_state::HostStateRecord::Kernel(kernel.clone()),
    ) {
        Ok(checksum) => checksum,
        Err(error) => {
            return ReadinessContour {
                proof_status: ComponentState::Unknown {
                    reason: format!("active Kernel checksum failed: {error}"),
                    gap: readiness_gap(),
                },
                age_gap: readiness_gap(),
            };
        }
    };
    if observed.validate_against(kernel, &active_checksum).is_err() {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "readiness observation is not bound to the exact active Kernel checksum/process/Job/authority"
                    .to_owned(),
                gap: "substituted readiness observation".to_owned(),
            },
            age_gap: "substituted readiness observation".to_owned(),
        };
    }
    let gap = readiness_gap();
    ReadinessContour {
        proof_status: ComponentState::Unknown {
            reason: "exact readiness identity is present, but observed_at is opaque and cannot prove freshness"
                .to_owned(),
            gap: gap.clone(),
        },
        age_gap: gap,
    }
}
