//! Frozen one-snapshot sample with explicit denominator and omissions.
//!
//! A [`CycleSample`] selects a bounded deterministic identity scope over the
//! already-frozen [`DreamerCycleState`](crate::contract::DreamerCycleState)
//! consumed by the pure one-snapshot controller. It performs no storage read,
//! Researcher/model/tool call, agent launch, or scheduler operation: every
//! identity it carries is copied from the supplied frozen snapshot in state
//! order, and every identity it does not carry remains explicitly listed as
//! omitted against the complete denominator. It introduces no second
//! lifecycle: the single [`CyclePhase`](crate::contract::CyclePhase) chain
//! remains the only phase vocabulary.

use eliot_contracts::{ArtifactId, ReceiptId, RequestId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contract::{
    CYCLE_SCHEMA_VERSION, CyclePhase, CyclePolicy, DreamerCycleState, MAX_RECORDS, MAX_REQUESTS,
    check_frozen_binding, is_digest, job_digest,
};
use crate::error::CycleError;

/// Caller-supplied bound for one frozen sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleLimits {
    /// Maximum identities sampled per category (pending, proposed, outcomes).
    pub max_sampled: u32,
}

impl SampleLimits {
    /// Validates that the bound is positive and fits the controller ceiling.
    pub fn validate(&self) -> Result<(), CycleError> {
        if self.max_sampled == 0 || self.max_sampled as usize > MAX_REQUESTS {
            return Err(CycleError::Bound {
                field: "sample.max_sampled",
                maximum: MAX_REQUESTS,
            });
        }
        Ok(())
    }
}

/// Complete denominator over the frozen snapshot at sample time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleDenominator {
    /// Pending requests in the frozen state.
    pub pending_total: u64,
    /// Caller-supplied proposed requests in the frozen state.
    pub proposed_total: u64,
    /// Previously accepted owner outcomes in the frozen state.
    pub outcomes_total: u64,
    /// Unresolved material/frontier entries in the frozen state.
    pub frontier_total: u64,
}

/// Bounded deterministic identity scope over one frozen snapshot.
///
/// Identities beyond [`SampleLimits::max_sampled`] in any category are
/// retained in the matching `omitted_*` list in state order; they stay bound
/// to the frozen snapshot and are never silently dropped.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CycleSample {
    /// Exact cycle schema revision.
    pub schema_version: u32,
    /// Cycle identity sampled from the frozen state.
    pub cycle_id: ArtifactId,
    /// Controller phase sampled from the frozen state.
    pub phase: CyclePhase,
    /// Digest of the complete frozen job.
    pub job_digest: String,
    /// Digest of the frozen input bundle.
    pub bundle_digest: String,
    /// Canonical digest of the frozen policy.
    pub policy_digest: String,
    /// Canonical digest of the frozen state.
    pub state_digest: String,
    /// Complete denominator at sample time.
    pub denominator: SampleDenominator,
    /// Sampled pending request identities in state order.
    pub sampled_pending: Vec<RequestId>,
    /// Sampled proposed request identities in state order.
    pub sampled_proposed: Vec<RequestId>,
    /// Sampled outcome receipt identities in state order.
    pub sampled_outcomes: Vec<ReceiptId>,
    /// Pending identities beyond the sample bound, in state order.
    pub omitted_pending: Vec<RequestId>,
    /// Proposed identities beyond the sample bound, in state order.
    pub omitted_proposed: Vec<RequestId>,
    /// Outcome identities beyond the sample bound, in state order.
    pub omitted_outcomes: Vec<ReceiptId>,
    /// Unresolved material carried whole from the frozen state.
    pub frontier: Vec<String>,
    /// Whether every denominator identity was sampled.
    pub complete: bool,
    /// Digest of this sample payload excluding this field.
    pub coverage_digest: String,
}

impl CycleSample {
    /// Computes the sample digest while excluding the digest field itself.
    pub fn computed_digest(&self) -> Result<String, CycleError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: u32,
            cycle_id: &'a ArtifactId,
            phase: CyclePhase,
            job_digest: &'a str,
            bundle_digest: &'a str,
            policy_digest: &'a str,
            state_digest: &'a str,
            denominator: SampleDenominator,
            sampled_pending: &'a [RequestId],
            sampled_proposed: &'a [RequestId],
            sampled_outcomes: &'a [ReceiptId],
            omitted_pending: &'a [RequestId],
            omitted_proposed: &'a [RequestId],
            omitted_outcomes: &'a [ReceiptId],
            frontier: &'a [String],
            complete: bool,
        }
        let bytes = eliot_contracts::canonical_json_bytes(&Payload {
            schema_version: self.schema_version,
            cycle_id: &self.cycle_id,
            phase: self.phase,
            job_digest: &self.job_digest,
            bundle_digest: &self.bundle_digest,
            policy_digest: &self.policy_digest,
            state_digest: &self.state_digest,
            denominator: self.denominator,
            sampled_pending: &self.sampled_pending,
            sampled_proposed: &self.sampled_proposed,
            sampled_outcomes: &self.sampled_outcomes,
            omitted_pending: &self.omitted_pending,
            omitted_proposed: &self.omitted_proposed,
            omitted_outcomes: &self.omitted_outcomes,
            frontier: &self.frontier,
            complete: self.complete,
        })
        .map_err(|error| CycleError::Encoding(error.to_string()))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validates the sample against the exact frozen snapshot and policy.
    pub fn validate(
        &self,
        state: &DreamerCycleState,
        policy: &CyclePolicy,
    ) -> Result<(), CycleError> {
        state.validate()?;
        policy.validate()?;
        check_frozen_binding(state, policy)?;
        if self.schema_version != CYCLE_SCHEMA_VERSION {
            return Err(CycleError::BindingMismatch {
                field: "sample.schema_version",
                reason: "unsupported schema version",
            });
        }
        if self.cycle_id != state.cycle_id || self.phase != state.phase {
            return Err(CycleError::BindingMismatch {
                field: "sample.cycle_identity",
                reason: "sample cycle identity differs from frozen state",
            });
        }
        if self.job_digest != job_digest(&state.job)?
            || self.bundle_digest != state.bundle_digest
            || self.policy_digest != policy.canonical_digest
            || self.policy_digest != state.policy_digest
            || self.state_digest != state.canonical_digest
        {
            return Err(CycleError::BindingMismatch {
                field: "sample.snapshot_binding",
                reason: "sample digests differ from the frozen snapshot",
            });
        }
        for digest in [&self.job_digest, &self.bundle_digest, &self.policy_digest] {
            if !is_digest(digest) {
                return Err(CycleError::BindingMismatch {
                    field: "sample.snapshot_binding",
                    reason: "snapshot digest must be lowercase sha256",
                });
            }
        }
        let state_pending: Vec<RequestId> = state
            .pending
            .iter()
            .map(|pending| pending.request_id.clone())
            .collect();
        let state_proposed: Vec<RequestId> = state
            .proposed_requests
            .iter()
            .map(|pending| pending.request_id.clone())
            .collect();
        let state_outcomes: Vec<ReceiptId> = state
            .outcomes
            .iter()
            .map(|outcome| outcome.receipt.identity.receipt_id.clone())
            .collect();
        check_partition(
            &state_pending,
            &self.sampled_pending,
            &self.omitted_pending,
            "sample.pending",
            self.denominator.pending_total,
        )?;
        check_partition(
            &state_proposed,
            &self.sampled_proposed,
            &self.omitted_proposed,
            "sample.proposed",
            self.denominator.proposed_total,
        )?;
        check_partition(
            &state_outcomes,
            &self.sampled_outcomes,
            &self.omitted_outcomes,
            "sample.outcomes",
            self.denominator.outcomes_total,
        )?;
        let frontier_total =
            u64::try_from(state.frontier.len()).map_err(|_| CycleError::Bound {
                field: "sample.frontier",
                maximum: MAX_RECORDS,
            })?;
        if self.denominator.frontier_total != frontier_total || self.frontier != state.frontier {
            return Err(CycleError::BindingMismatch {
                field: "sample.frontier",
                reason: "sample frontier differs from the frozen state",
            });
        }
        let omitted_empty = self.omitted_pending.is_empty()
            && self.omitted_proposed.is_empty()
            && self.omitted_outcomes.is_empty();
        if self.complete != omitted_empty {
            return Err(CycleError::BindingMismatch {
                field: "sample.complete",
                reason: "sample completeness disagrees with explicit omissions",
            });
        }
        if self.coverage_digest != self.computed_digest()? {
            return Err(CycleError::IdentityConflict {
                identity: "sample.coverage_digest".to_owned(),
            });
        }
        Ok(())
    }
}

fn check_partition<T: Clone + PartialEq>(
    state_order: &[T],
    sampled: &[T],
    omitted: &[T],
    field: &'static str,
    total: u64,
) -> Result<(), CycleError> {
    let expected_total = u64::try_from(state_order.len()).map_err(|_| CycleError::Bound {
        field,
        maximum: MAX_RECORDS,
    })?;
    if total != expected_total
        || sampled.len() + omitted.len() != state_order.len()
        || sampled.iter().chain(omitted.iter()).ne(state_order.iter())
    {
        return Err(CycleError::BindingMismatch {
            field,
            reason: "sample partition is not the frozen state order prefix",
        });
    }
    if sampled.len() > MAX_REQUESTS || omitted.len() > MAX_RECORDS {
        return Err(CycleError::Bound {
            field,
            maximum: MAX_RECORDS,
        });
    }
    Ok(())
}

fn partition<T: Clone>(items: &[T], bound: usize) -> (Vec<T>, Vec<T>) {
    let split = bound.min(items.len());
    (items[..split].to_vec(), items[split..].to_vec())
}

/// Selects a bounded deterministic sample over one frozen snapshot.
///
/// The bound applies independently per identity category; every identity
/// beyond the bound is listed explicitly as omitted. The frozen snapshot,
/// policy, and their binding are validated before anything is selected.
pub fn sample_cycle(
    state: &DreamerCycleState,
    policy: &CyclePolicy,
    limits: &SampleLimits,
) -> Result<CycleSample, CycleError> {
    limits.validate()?;
    state.validate()?;
    policy.validate()?;
    check_frozen_binding(state, policy)?;
    let bound = limits.max_sampled as usize;
    let (sampled_pending, omitted_pending) = partition(
        &state
            .pending
            .iter()
            .map(|pending| pending.request_id.clone())
            .collect::<Vec<_>>(),
        bound,
    );
    let (sampled_proposed, omitted_proposed) = partition(
        &state
            .proposed_requests
            .iter()
            .map(|pending| pending.request_id.clone())
            .collect::<Vec<_>>(),
        bound,
    );
    let (sampled_outcomes, omitted_outcomes) = partition(
        &state
            .outcomes
            .iter()
            .map(|outcome| outcome.receipt.identity.receipt_id.clone())
            .collect::<Vec<_>>(),
        bound,
    );
    let denominator = SampleDenominator {
        pending_total: u64::try_from(state.pending.len()).map_err(|_| CycleError::Bound {
            field: "sample.pending",
            maximum: MAX_RECORDS,
        })?,
        proposed_total: u64::try_from(state.proposed_requests.len()).map_err(|_| {
            CycleError::Bound {
                field: "sample.proposed",
                maximum: MAX_REQUESTS,
            }
        })?,
        outcomes_total: u64::try_from(state.outcomes.len()).map_err(|_| CycleError::Bound {
            field: "sample.outcomes",
            maximum: MAX_RECORDS,
        })?,
        frontier_total: u64::try_from(state.frontier.len()).map_err(|_| CycleError::Bound {
            field: "sample.frontier",
            maximum: MAX_RECORDS,
        })?,
    };
    let mut sample = CycleSample {
        schema_version: CYCLE_SCHEMA_VERSION,
        cycle_id: state.cycle_id.clone(),
        phase: state.phase,
        job_digest: job_digest(&state.job)?,
        bundle_digest: state.bundle_digest.clone(),
        policy_digest: policy.canonical_digest.clone(),
        state_digest: state.canonical_digest.clone(),
        denominator,
        sampled_pending,
        sampled_proposed,
        sampled_outcomes,
        omitted_pending,
        omitted_proposed,
        omitted_outcomes,
        frontier: state.frontier.clone(),
        complete: false,
        coverage_digest: String::new(),
    };
    sample.complete = sample.omitted_pending.is_empty()
        && sample.omitted_proposed.is_empty()
        && sample.omitted_outcomes.is_empty();
    sample.coverage_digest = sample.computed_digest()?;
    sample.validate(state, policy)?;
    Ok(sample)
}
