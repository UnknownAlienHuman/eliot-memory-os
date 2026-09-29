#![forbid(unsafe_code)]

//! The smallest controlled pilot harness for the six mandated `RGF-AGENT-ROUTES`
//! probes of I10.11 (issue #1835).
//!
//! ## What this harness is, and what it is not
//!
//! It is a **measurement** step: it reads one real bounded
//! [`NoAuthorityRunResult`](crate::NoAuthorityRunResult) and derives the
//! [`OpenCodePilotObservation`](crate::OpenCodePilotObservation) the six
//! mandated probes are evaluated from. It executes nothing on its own and
//! selects no route.
//!
//! Every field it derives comes from that one observed result, and a probe
//! whose required reading the run did not produce stays
//! [`OpenCodeProbeReading::NotObserved`], which
//! [`opencode_pilot_probe_evidence`](crate::opencode_pilot_probe_evidence)
//! records as `Failed`. The harness therefore cannot mint a passing probe: a
//! route the live stack did not demonstrate stays non-admitted under
//! `RGF-AGENT-ROUTES`, which is the correct outcome for the empirical
//! DeepSeek/OpenCode profile.
//!
//! Two probes in particular are never inferred here. Context/output limits and
//! compaction are **measured**, never read from the provider catalogue's
//! advertised capacity, so they remain unobserved until a pilot that can
//! actually observe them runs. The equal-stack comparison needs a second
//! route's own retained run, supplied by the operator alongside the candidate
//! run ([`opencode_pilot_observation_with_fallback`]); from the candidate run
//! alone it is never claimed.

use crate::{
    AvailabilityState, NoAuthorityRunResult, OpenCodePilotObservation, OpenCodeProbeReading,
    RunStatus,
};

/// The runtime facts whose absence the pilot must report honestly rather than
/// fill from the requested route: the wire receipt reports each as absent
/// rather than echoing what was asked for.
const OBSERVED_ROUTE_FACTS: [&str; 5] = [
    "provider",
    "observed_model",
    "endpoint",
    "server_version",
    "route_fingerprint",
];

/// Derives the six mandated probe readings from one real bounded run result.
///
/// A run that did not succeed yields an all-unobserved observation: a failed or
/// non-successful attempt produced no evidence for any probe, and reporting it
/// as a measurement would be a claim the run never made.
#[must_use]
pub fn opencode_pilot_observation(result: &NoAuthorityRunResult) -> OpenCodePilotObservation {
    if result.status != RunStatus::Succeeded {
        return unmeasured_observation();
    }
    let route = &result.actual_route;
    OpenCodePilotObservation {
        // Turn-level continuation needs a multi-turn transcript; one bounded
        // read-only attempt observes no completed second turn, so the harness
        // does not claim one.
        continuation_turns_observed: 0,
        // The read-only attempt is dispatched in the text format, which carries
        // no reasoning part, so preservation is not demonstrated here.
        reasoning_continuation_preserved: OpenCodeProbeReading::NotObserved,
        observed_provider: route.provider.clone(),
        observed_model: route.observed.as_ref().map(|model| model.model_id.clone()),
        missing_fields_observed: missing_observed_facts(result),
        // Advertised catalogue capacity is not a measurement; the pilot leaves
        // both absent until a run that actually fills the context observes them.
        measured_context_limit: None,
        measured_output_limit: None,
        compaction_observed: OpenCodeProbeReading::NotObserved,
        quota_usage_sourced: reading(usage_is_sourced(result)),
        // An equal-stack comparison needs a second route's own run and is never
        // claimed from this one.
        equal_stack_comparison_retained: OpenCodeProbeReading::NotObserved,
    }
}

/// Derives the six mandated probe readings from one real bounded candidate run
/// plus the retained bounded run of the equal-stack fallback route.
///
/// The first five readings are exactly what [`opencode_pilot_observation`]
/// derives from the candidate run alone; the sixth —
/// [`OpenCodePilotObservation::equal_stack_comparison_retained`] — is derived
/// from the pair by [`opencode_equal_stack_comparison`]. The fallback run is
/// operator-supplied retained evidence of the same controlled task run against
/// the fallback route, never an automatic second attempt: this harness runs
/// nothing on its own. Task sameness is not taken on trust: the comparison
/// requires both runs to carry the same controlled-task session identity
/// before it reads `Observed`.
///
/// [`opencode_equal_stack_comparison`]: crate::opencode_equal_stack_comparison
#[must_use]
pub fn opencode_pilot_observation_with_fallback(
    candidate: &NoAuthorityRunResult,
    fallback: &NoAuthorityRunResult,
) -> OpenCodePilotObservation {
    let mut observation = opencode_pilot_observation(candidate);
    observation.equal_stack_comparison_retained =
        opencode_equal_stack_comparison(candidate, fallback);
    observation
}

/// Whether the candidate run and the retained fallback run form the
/// equal-stack comparison I10.11 mandates for its sixth probe ("controlled
/// implementation tasks are compared with an equal-stack fallback route").
///
/// `Observed` requires all of: both runs succeeded, because a failed attempt
/// produced no evidence for any probe; both runs executed the same controlled
/// task — both retained the same session identity, present on both sides and
/// equal, so an unrelated successful fallback run on the same stack never
/// reads as the comparison; both retained their actual-route receipts on the
/// same observed stack — the same endpoint and the same installed server
/// version (I10.6 keeps the route provisional until the exact installed
/// server passes the gate); and both retained an identified route with the
/// two route fingerprints differing, so a run compared with itself can never
/// read as a fallback comparison. Any absence reads
/// [`OpenCodeProbeReading::NotObserved`]: absence is never a pass.
///
/// The session identity is the existing [`NoAuthorityRunResult::session_id`]
/// each run already carries: the production minter records the `OpenCode`
/// server session the controlled task ran in, the actual-route receipt
/// mirrors it (deserialization rejects an `Observed` receipt whose session
/// identity differs from its run result), and a continued task reuses its
/// session. Compared for equality only, never parsed.
#[must_use]
pub fn opencode_equal_stack_comparison(
    candidate: &NoAuthorityRunResult,
    fallback: &NoAuthorityRunResult,
) -> OpenCodeProbeReading {
    if candidate.status != RunStatus::Succeeded || fallback.status != RunStatus::Succeeded {
        return OpenCodeProbeReading::NotObserved;
    }
    let candidate_route = &candidate.actual_route;
    let fallback_route = &fallback.actual_route;
    let same_controlled_task =
        same_observed(candidate.session_id.as_ref(), fallback.session_id.as_ref());
    let equal_stack = same_observed(
        candidate_route.endpoint.as_ref(),
        fallback_route.endpoint.as_ref(),
    ) && same_observed(
        candidate_route.server_version.as_ref(),
        fallback_route.server_version.as_ref(),
    );
    let distinct_routes = distinct_observed(
        candidate_route.route_fingerprint.as_ref(),
        fallback_route.route_fingerprint.as_ref(),
    );
    reading(same_controlled_task && equal_stack && distinct_routes)
}

/// Whether both runs retained the same observed value: present on both sides
/// and equal. Compared for equality only, never parsed.
fn same_observed(first: Option<&String>, second: Option<&String>) -> bool {
    matches!((first, second), (Some(a), Some(b)) if a == b)
}

/// Whether both runs retained an identified route and the two identities
/// differ. Compared for equality only, never parsed.
fn distinct_observed(first: Option<&String>, second: Option<&String>) -> bool {
    matches!((first, second), (Some(a), Some(b)) if a != b)
}

fn reading(observed: bool) -> OpenCodeProbeReading {
    if observed {
        OpenCodeProbeReading::Observed
    } else {
        OpenCodeProbeReading::NotObserved
    }
}

fn unmeasured_observation() -> OpenCodePilotObservation {
    OpenCodePilotObservation {
        continuation_turns_observed: 0,
        reasoning_continuation_preserved: OpenCodeProbeReading::NotObserved,
        observed_provider: None,
        observed_model: None,
        missing_fields_observed: missing_fact_count(),
        measured_context_limit: None,
        measured_output_limit: None,
        compaction_observed: OpenCodeProbeReading::NotObserved,
        quota_usage_sourced: OpenCodeProbeReading::NotObserved,
        equal_stack_comparison_retained: OpenCodeProbeReading::NotObserved,
    }
}

/// The count of runtime route facts, as the honest upper bound a bounded run
/// can leave unexposed. The literal count is derived from the fact list so the
/// two cannot drift apart.
fn missing_fact_count() -> u32 {
    u32::try_from(OBSERVED_ROUTE_FACTS.len()).unwrap_or(u32::MAX)
}

/// Counts the runtime route facts the wire receipt left unexposed. Each missing
/// fact is reported as missing; none is filled from the requested route.
fn missing_observed_facts(result: &NoAuthorityRunResult) -> u32 {
    let route = &result.actual_route;
    let mut missing = 0_u32;
    for fact in OBSERVED_ROUTE_FACTS {
        let exposed = match fact {
            "provider" => route.provider.is_some(),
            "observed_model" => route.observed.is_some(),
            "endpoint" => route.endpoint.is_some(),
            "server_version" => route.server_version.is_some(),
            "route_fingerprint" => route.route_fingerprint.is_some(),
            _ => false,
        };
        if !exposed {
            missing += 1;
        }
    }
    missing
}

/// Whether usage and quota are **sourced**: usage carries a measured telemetry
/// value, and quota is either a reported remaining value or an explicit
/// unavailable state with its reason. An unavailable quota is honest sourcing;
/// a fabricated `0` remaining is not, and nothing here produces one.
fn usage_is_sourced(result: &NoAuthorityRunResult) -> bool {
    let usage_sourced =
        result.usage.state == AvailabilityState::Available && result.usage.value.is_some();
    let quota_sourced = match result.quota.state {
        AvailabilityState::Available => result.quota.remaining.is_some(),
        AvailabilityState::Unavailable => result
            .quota
            .unavailable_reason
            .as_ref()
            .is_some_and(|reason| !reason.trim().is_empty()),
    };
    usage_sourced && quota_sourced
}
