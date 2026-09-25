//! `eliotd` supervision-progress producer (Implements #88, wave 3).
//!
//! Architecture: ARCH-WDG-01 (independent supervision from observed progress,
//! never self-report alone), ARCH-AUTH-01 (authority stays explicit, scoped,
//! and fenced), ARCH-RES-04 (degradation is visible and local).
//! Implementation: I1.5 (lease renewal requires fresh observed evidence;
//! process survival alone never renews), I8.4 (interaction heartbeat carries
//! observable progress), I14.15 (daemon generations never revive old authority).
//!
//! This module owns only the daemon half of the renewal evidence: it builds
//! one [`DaemonProgressObservation`] per progress channel per 5-second tick
//! from live daemon facts (claimed/dispatched/applied activation cursors,
//! validated transport session, boot identity, monotonic and wall clocks, and
//! independent health dimensions). It decides nothing: the Kernel joins each
//! observation against its exact durable predecessor through the single
//! timing owner and either renews, replays, defers, degrades, or refuses with
//! a typed code. The producer converges by adopting the exact predecessor the
//! Kernel answers, and halts progress submits once the Kernel reports the
//! lease expired (only a new admitted generation can supervise again).
//!
//! The lineage half of every observation (installation, activation,
//! generation binding, epoch, fence) is echoed verbatim from the
//! Kernel-authored `daemon_ready` bundle and re-verified by the Kernel on
//! every submit: the daemon can cite lineage but never invent it. `StoreHealth`
//! is reused as the `store_dependency` evidence dimension only; it is never
//! the renewal signal (a `NoProgress` observation cannot renew by contract).

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eliot_contracts::{EpochId, ResourceGeneration, StateFence, sha256_hex};
use eliot_runtime_contracts::{
    DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_NAME, DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_VERSION,
    DAEMON_SUPERVISION_HEARTBEAT_SCHEMA, DaemonChannelCursor, DaemonHeartbeatHealth,
    DaemonProgressChannel, DaemonProgressDisposition, DaemonProgressObservation,
    DaemonSupervisionRenewalDecision, DaemonSupervisionRenewalOutcome,
    DaemonSupervisionRenewalReceipt, DaemonSupervisionRenewalRequest, HealthDimension,
    SupervisionGenerationBinding, SupervisionLeasePredecessorProof,
};
use serde::Deserialize;

/// Stable wire identity of the daemon progress submit operation.
pub const DAEMON_SUPERVISION_PROGRESS_OPERATION: &str = "daemon_supervision_progress";

/// Named dependency cited when governed activation work is outstanding while
/// the Store bridge is not Ready. The daemon observes the coincidence of
/// in-flight work and Store unavailability; the Kernel decides whether the
/// wait state permits renewal.
pub const STORE_DEPENDENCY_WAIT_NAME: &str = "store-bridge:not-ready";

/// Kernel-authored lineage half of an observation, handed to the daemon once
/// per generation in the `daemon_ready` answer and echoed verbatim on every
/// submit. The Kernel re-verifies every field against its supervision contour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionProgressLineage {
    pub installation_id: String,
    pub activation_id: String,
    pub activation_generation: ResourceGeneration,
    pub generation_binding: SupervisionGenerationBinding,
    pub kernel_epoch: EpochId,
    pub state_fence: StateFence,
}

/// Last learned lease head: the exact cited predecessor plus the informational
/// lease window. The window never authorizes anything locally; the Kernel
/// computes expiry from its own durable binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionProgressHead {
    pub predecessor: SupervisionLeasePredecessorProof,
    pub lease_issued_at_ms: u64,
    pub lease_expires_at_ms: u64,
}

/// Typed `daemon_ready` supervision bundle parsed from the Kernel answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonReadySupervision {
    pub lineage: SupervisionProgressLineage,
    pub head: SupervisionProgressHead,
}

/// Kernel answer to one progress submit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionProgressAnswer {
    /// Decided outcome, when the join decided instead of refusing.
    pub outcome: Option<DaemonSupervisionRenewalOutcome>,
    /// Stable refusal code, when the join refused.
    pub refusal_code: Option<String>,
    /// Full decision, when decided.
    pub decision: Option<DaemonSupervisionRenewalDecision>,
    /// Full receipt, when decided.
    pub receipt: Option<DaemonSupervisionRenewalReceipt>,
    /// Exact durable predecessor, always present on a shape-valid request so
    /// the producer converges after renewals on other paths.
    pub predecessor: SupervisionLeasePredecessorProof,
    /// Kernel-accepted cursors, always present so the next observation cites
    /// the accepted cursor instead of its own last-submitted cursor.
    pub accepted_cursors: Vec<DaemonChannelCursor>,
    /// True when the refusal is the terminal lease-expiry code.
    pub expired: bool,
}

/// Per-tick producer inputs that the run loop observes locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupervisionTickInputs {
    /// Whether the Store bridge reported Ready on this tick's health poll.
    pub store_ready: bool,
    /// Whether governed activation work is outstanding on this tick.
    pub activation_in_flight: bool,
}

fn channel_index(channel: DaemonProgressChannel) -> usize {
    match channel {
        DaemonProgressChannel::Claim => 0,
        DaemonProgressChannel::Dispatch => 1,
        DaemonProgressChannel::Apply => 2,
    }
}

fn channel_name(channel: DaemonProgressChannel) -> &'static str {
    match channel {
        DaemonProgressChannel::Claim => "CLAIM",
        DaemonProgressChannel::Dispatch => "DISPATCH",
        DaemonProgressChannel::Apply => "APPLY",
    }
}

fn progress_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!(
            "{field}: must be non-blank and free of control characters"
        ));
    }
    Ok(())
}

fn progress_digest(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(format!("{field}: must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn unix_ms_now() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("daemon wall clock is before the Unix epoch: {error}"))?
        .as_millis();
    let wall_ms = u64::try_from(millis.min(u128::from(u64::MAX)))
        .map_err(|_| "daemon wall clock overflowed".to_owned())?;
    if wall_ms == 0 {
        return Err("daemon wall clock produced zero".to_owned());
    }
    Ok(wall_ms)
}

/// Fixed wire shape of the Kernel-authored `daemon_ready` supervision bundle.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadySupervisionWire {
    lineage: ReadyLineageWire,
    head: ReadyHeadWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyLineageWire {
    installation_id: String,
    activation_id: String,
    activation_generation: u64,
    generation_binding: SupervisionGenerationBinding,
    kernel_epoch: EpochId,
    state_fence: StateFence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyHeadWire {
    predecessor: SupervisionLeasePredecessorProof,
    lease_issued_at_ms: u64,
    lease_expires_at_ms: u64,
}

/// Parses the Kernel-authored supervision bundle from a `daemon_ready` answer
/// value. Every echoed field is shape-checked here; authority is re-proved by
/// the Kernel on every submit, never trusted from this parse.
pub fn parse_daemon_ready_supervision(
    value: &serde_json::Value,
) -> Result<DaemonReadySupervision, String> {
    let supervision = value
        .get("supervision")
        .ok_or_else(|| "Kernel daemon_ready answer omits the supervision bundle".to_owned())?;
    let wire: ReadySupervisionWire = serde_json::from_value(supervision.clone())
        .map_err(|error| format!("Kernel supervision bundle does not decode: {error}"))?;
    progress_text(&wire.lineage.installation_id, "lineage.installation_id")?;
    progress_text(&wire.lineage.activation_id, "lineage.activation_id")?;
    let activation_generation = ResourceGeneration::new(wire.lineage.activation_generation)
        .map_err(|_| "lineage.activation_generation: must be greater than zero".to_owned())?;
    // The generation binding is echoed verbatim and re-proved by the Kernel
    // join on every submit; the parse checks only bound text and nonzero
    // generations (exact lineage equality is authority business, never
    // decided from this parse, and the contract validator is crate-private).
    let binding = &wire.lineage.generation_binding;
    progress_text(&binding.target_id, "lineage.generation_binding.target_id")?;
    progress_text(&binding.module_id, "lineage.generation_binding.module_id")?;
    progress_text(&binding.process_id, "lineage.generation_binding.process_id")?;
    if binding.target_generation.value() == 0
        || binding.module_generation.value() == 0
        || binding.process_generation.value() == 0
    {
        return Err("lineage.generation_binding: generations must be greater than zero".to_owned());
    }
    wire.lineage
        .state_fence
        .validate()
        .map_err(|error| format!("lineage.state_fence: {error}"))?;
    if !wire
        .lineage
        .state_fence
        .authority_epoch
        .is_same_authority(&wire.lineage.kernel_epoch)
    {
        return Err("lineage.state_fence.authority_epoch: must equal kernel_epoch".to_owned());
    }
    if wire.lineage.state_fence.resource_generation != activation_generation {
        return Err(
            "lineage.state_fence.resource_generation: must equal activation_generation".to_owned(),
        );
    }
    wire.head
        .predecessor
        .validate()
        .map_err(|error| format!("head.predecessor: {error}"))?;
    if wire.head.lease_issued_at_ms == 0
        || wire.head.lease_expires_at_ms <= wire.head.lease_issued_at_ms
    {
        return Err("head.lease window: must be a positive ordered interval".to_owned());
    }
    Ok(DaemonReadySupervision {
        lineage: SupervisionProgressLineage {
            installation_id: wire.lineage.installation_id,
            activation_id: wire.lineage.activation_id,
            activation_generation,
            generation_binding: wire.lineage.generation_binding,
            kernel_epoch: wire.lineage.kernel_epoch,
            state_fence: wire.lineage.state_fence,
        },
        head: SupervisionProgressHead {
            predecessor: wire.head.predecessor,
            lease_issued_at_ms: wire.head.lease_issued_at_ms,
            lease_expires_at_ms: wire.head.lease_expires_at_ms,
        },
    })
}

/// Fixed wire shape of the Kernel progress-submit answer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressAnswerWire {
    outcome: Option<DaemonSupervisionRenewalOutcome>,
    refusal_code: Option<String>,
    decision: Option<DaemonSupervisionRenewalDecision>,
    receipt: Option<DaemonSupervisionRenewalReceipt>,
    predecessor: SupervisionLeasePredecessorProof,
    accepted_cursors: Vec<DaemonChannelCursor>,
}

/// Parses and shape-checks one Kernel progress-submit answer. A decision and
/// a refusal never co-occur; the durable predecessor is always present so the
/// producer converges even after refusals.
pub fn parse_progress_answer(
    value: &serde_json::Value,
) -> Result<SupervisionProgressAnswer, String> {
    let wire: ProgressAnswerWire = serde_json::from_value(value.clone())
        .map_err(|error| format!("Kernel progress answer does not decode: {error}"))?;
    match (&wire.outcome, &wire.refusal_code) {
        (Some(_), None) => {}
        (None, Some(code)) => {
            progress_text(code, "answer.refusal_code")?;
        }
        _ => {
            return Err(
                "Kernel progress answer carries neither a decision outcome nor a refusal code"
                    .to_owned(),
            );
        }
    }
    if let Some(decision) = &wire.decision {
        decision
            .validate()
            .map_err(|error| format!("answer.decision: {error}"))?;
    }
    if let Some(receipt) = &wire.receipt {
        receipt
            .validate()
            .map_err(|error| format!("answer.receipt: {error}"))?;
    }
    match (&wire.outcome, &wire.decision, &wire.receipt) {
        (Some(_), Some(_), Some(_)) | (None, None, None) => {}
        _ => {
            return Err(
                "Kernel progress answer mixes a decision outcome with a partial decision"
                    .to_owned(),
            );
        }
    }
    wire.predecessor
        .validate()
        .map_err(|error| format!("answer.predecessor: {error}"))?;
    if wire.accepted_cursors.len() > 3 {
        return Err("answer.accepted_cursors: at most one entry per progress channel".to_owned());
    }
    let expired = wire.refusal_code.as_deref() == Some("SUPERVISION_LEASE_EXPIRED");
    Ok(SupervisionProgressAnswer {
        outcome: wire.outcome,
        refusal_code: wire.refusal_code,
        decision: wire.decision,
        receipt: wire.receipt,
        predecessor: wire.predecessor,
        accepted_cursors: wire.accepted_cursors,
        expired,
    })
}

/// Per-tick supervision-progress producer for one daemon generation.
///
/// The producer retains the Kernel-authored lineage, the last learned lease
/// head, per-channel observed cursors, last-submitted cursors, the
/// Kernel-accepted cursors, and a terminal halt once the Kernel reports lease
/// expiry. cursors only advance on locally observed, Kernel-acknowledged
/// activation flow: a claimed ticket advances Claim; a completed dispatch
/// whose result the Kernel accepted advances Dispatch and Apply together.
pub struct SupervisionProgressProducer {
    daemon_artifact_id: String,
    daemon_config_digest: String,
    boot_id: String,
    transport_session_evidence: String,
    transport_connection_evidence: String,
    process_pid: u32,
    lineage: SupervisionProgressLineage,
    head: SupervisionProgressHead,
    observed: [u64; 3],
    submitted: [u64; 3],
    accepted: [u64; 3],
    sequence: u64,
    monotonic_base: Instant,
    pending_request_id: Option<String>,
    halted_expired: bool,
}

/// Constructor inputs for one daemon generation. Every identity is either
/// locally observed (artifact/config digests, process id, launch nonce) or
/// Kernel-authored (session binding, lineage, head); nothing is invented.
pub struct SupervisionProducerDeps {
    pub daemon_artifact_id: String,
    pub daemon_config_digest: String,
    pub launch_nonce: String,
    pub process_pid: u32,
    pub transport_session_evidence: String,
    pub transport_connection_evidence: String,
    pub ready: DaemonReadySupervision,
}

impl SupervisionProgressProducer {
    /// Builds the producer for one daemon generation. The boot identity binds
    /// the launch nonce and process id through a one-way digest: it is stable
    /// for this process and unpredictable across restarts, so a restarted
    /// process can never continue the old monotonic series.
    pub fn new(deps: SupervisionProducerDeps) -> Result<Self, String> {
        progress_text(&deps.daemon_artifact_id, "producer.daemon_artifact_id")?;
        progress_digest(&deps.daemon_config_digest, "producer.daemon_config_digest")?;
        progress_text(&deps.launch_nonce, "producer.launch_nonce")?;
        progress_text(
            &deps.transport_session_evidence,
            "producer.transport_session_evidence",
        )?;
        progress_text(
            &deps.transport_connection_evidence,
            "producer.transport_connection_evidence",
        )?;
        if deps.process_pid == 0 {
            return Err("producer.process_pid: must be greater than zero".to_owned());
        }
        let boot_id = sha256_hex(
            format!("eliotd-boot:{}:{}", deps.launch_nonce, deps.process_pid).as_bytes(),
        );
        Ok(Self {
            daemon_artifact_id: deps.daemon_artifact_id,
            daemon_config_digest: deps.daemon_config_digest,
            boot_id,
            transport_session_evidence: deps.transport_session_evidence,
            transport_connection_evidence: deps.transport_connection_evidence,
            process_pid: deps.process_pid,
            lineage: deps.ready.lineage,
            head: deps.ready.head,
            observed: [0, 0, 0],
            submitted: [0, 0, 0],
            accepted: [0, 0, 0],
            sequence: 0,
            monotonic_base: Instant::now(),
            pending_request_id: None,
            halted_expired: false,
        })
    }

    /// Records one claimed activation ticket on the Claim channel.
    pub fn note_claim(&mut self) {
        self.observed[channel_index(DaemonProgressChannel::Claim)] =
            self.observed[channel_index(DaemonProgressChannel::Claim)].saturating_add(1);
    }

    /// Records one completed dispatch whose result the Kernel accepted. The
    /// accepted acknowledgement proves both dispatch and apply, so both
    /// channels advance together from this single event.
    pub fn note_kernel_applied(&mut self) {
        for channel in [
            DaemonProgressChannel::Dispatch,
            DaemonProgressChannel::Apply,
        ] {
            let slot = &mut self.observed[channel_index(channel)];
            *slot = slot.saturating_add(1);
        }
    }

    /// Returns true while progress submits may continue. Once the Kernel
    /// reports lease expiry the producer halts: an expired lease never
    /// revives from further heartbeats; only a new admitted generation
    /// supervises again.
    #[must_use]
    pub fn halted(&self) -> bool {
        self.halted_expired
    }

    /// Returns the last learned lease head for diagnostics only.
    #[must_use]
    pub fn head(&self) -> &SupervisionProgressHead {
        &self.head
    }

    /// Returns whether a submit is due on a channel this tick. A channel with
    /// newly observed work always reports; the Claim channel additionally
    /// reports liveness every tick so monotonic continuity and session
    /// binding stay fresh even when no work flows.
    #[must_use]
    pub fn submit_due(&self, channel: DaemonProgressChannel) -> bool {
        if self.halted_expired {
            return false;
        }
        let index = channel_index(channel);
        self.observed[index] > self.submitted[index] || channel == DaemonProgressChannel::Claim
    }

    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.monotonic_base.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1)
    }

    /// Builds one renewal request for a channel. The disposition is selected
    /// from locally observed facts only: newly observed work is
    /// `FORWARD_PROGRESS`; outstanding activation work while the Store bridge
    /// is not Ready waits on the named Store dependency; anything else is an
    /// explicit `NO_PROGRESS` liveness statement that can never renew by
    /// contract. The cited predecessor is the last head the Kernel answered.
    pub fn build_observation(
        &mut self,
        channel: DaemonProgressChannel,
        inputs: &SupervisionTickInputs,
        store_dependency: HealthDimension,
    ) -> Result<DaemonSupervisionRenewalRequest, String> {
        if self.halted_expired {
            return Err("supervision producer halted after lease expiry".to_owned());
        }
        let index = channel_index(channel);
        let advanced = self.observed[index] > self.submitted[index];
        let (disposition, cursor) = if advanced {
            (
                DaemonProgressDisposition::ForwardProgress,
                self.observed[index],
            )
        } else if inputs.activation_in_flight && !inputs.store_ready {
            (
                DaemonProgressDisposition::WaitingOnNamedDependency,
                self.observed[index].max(self.accepted[index]),
            )
        } else {
            (
                DaemonProgressDisposition::NoProgress,
                self.observed[index].max(self.accepted[index]),
            )
        };
        let waiting_on_dependency =
            if disposition == DaemonProgressDisposition::WaitingOnNamedDependency {
                Some(STORE_DEPENDENCY_WAIT_NAME.to_owned())
            } else {
                None
            };
        self.sequence = self.sequence.saturating_add(1);
        let observation_id = format!(
            "hb-{}-{}-{}",
            &self.boot_id[..12],
            channel_name(channel),
            self.sequence
        );
        let health = DaemonHeartbeatHealth {
            daemon: HealthDimension::Healthy,
            transport: HealthDimension::Healthy,
            store_dependency,
            app_readiness: HealthDimension::Healthy,
        };
        let observation = DaemonProgressObservation {
            schema: DAEMON_SUPERVISION_HEARTBEAT_SCHEMA.to_owned(),
            contract_name: DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_NAME.to_owned(),
            contract_version: DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_VERSION,
            observation_id: observation_id.clone(),
            installation_id: self.lineage.installation_id.clone(),
            activation_id: self.lineage.activation_id.clone(),
            activation_generation: self.lineage.activation_generation,
            generation_binding: self.lineage.generation_binding.clone(),
            daemon_artifact_id: self.daemon_artifact_id.clone(),
            daemon_config_digest: self.daemon_config_digest.clone(),
            kernel_epoch: self.lineage.kernel_epoch.clone(),
            state_fence: self.lineage.state_fence.clone(),
            boot_id: self.boot_id.clone(),
            transport_session_evidence: self.transport_session_evidence.clone(),
            transport_connection_evidence: self.transport_connection_evidence.clone(),
            lease_id: self.head.predecessor.lease_id.clone(),
            lease_revision: self.head.predecessor.lease_revision,
            predecessor_receipt_sha256: self.head.predecessor.receipt_sha256.clone(),
            progress_channel: channel,
            progress_cursor: cursor,
            previous_progress_cursor: self.accepted[index],
            observed_monotonic_ms: self.monotonic_ms(),
            observed_wall_ms: unix_ms_now()?,
            disposition,
            idle_contract_id: None,
            waiting_on_dependency,
            evidence_refs: vec![
                format!("daemon-process:pid:{}", self.process_pid),
                format!("daemon-connection:{}", self.transport_connection_evidence),
                format!("daemon-tick:{}", self.sequence),
            ],
            health,
            watchdog_covered: false,
        };
        let request = DaemonSupervisionRenewalRequest {
            request_id: observation_id.clone(),
            observation,
            predecessor: self.head.predecessor.clone(),
        };
        request
            .validate()
            .map_err(|error| format!("producer built an invalid renewal request: {error}"))?;
        self.submitted[index] = cursor;
        self.pending_request_id = Some(observation_id);
        Ok(request)
    }

    /// Adopts one Kernel answer: validates the decision and receipt when the
    /// join decided, always adopts the exact durable predecessor and the
    /// accepted cursors, and halts on terminal lease expiry. An answer for an
    /// unknown request identity is rejected without touching continuity.
    pub fn adopt_answer(&mut self, answer: &SupervisionProgressAnswer) -> Result<(), String> {
        if let Some(decision) = &answer.decision {
            match &self.pending_request_id {
                Some(pending) if pending == &decision.request_id => {}
                _ => {
                    return Err(
                        "Kernel progress answer names an unknown request identity".to_owned()
                    );
                }
            }
        }
        for entry in &answer.accepted_cursors {
            self.accepted[channel_index(entry.channel)] = entry.cursor;
        }
        self.head.predecessor = answer.predecessor.clone();
        self.pending_request_id = None;
        if answer.expired {
            self.halted_expired = true;
        }
        Ok(())
    }
}

/// Maps one Store bridge health status to the evidence-only Store-dependency
/// dimension. The mapping never touches the disposition: an unavailable Store
/// with live daemon progress still renews, while an idle daemon still cannot.
#[must_use]
pub fn store_dependency_dimension(status: eliot_store_api::StoreHealthStatus) -> HealthDimension {
    match status {
        eliot_store_api::StoreHealthStatus::Ready => HealthDimension::Healthy,
        eliot_store_api::StoreHealthStatus::Degraded => HealthDimension::Degraded,
        eliot_store_api::StoreHealthStatus::Unavailable => HealthDimension::Failed,
    }
}

/// Serializes one renewal request to the daemon progress submit payload.
pub fn progress_submit_payload(request: &DaemonSupervisionRenewalRequest) -> serde_json::Value {
    serde_json::json!({ "request": request })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod supervision_progress_tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochLineageId, ResourceGeneration};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(sequence).expect("non-zero sequence"),
        )
        .expect("test epoch")
    }

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn test_ready() -> DaemonReadySupervision {
        let kernel_epoch = test_epoch(4);
        let activation_generation = ResourceGeneration::new(3).expect("test generation");
        DaemonReadySupervision {
            lineage: SupervisionProgressLineage {
                installation_id: "installation-1".to_owned(),
                activation_id: "activation-1".to_owned(),
                activation_generation,
                generation_binding: SupervisionGenerationBinding {
                    target_id: "eliotd".to_owned(),
                    target_generation: ResourceGeneration::new(1).expect("test generation"),
                    module_id: "eliotd".to_owned(),
                    module_generation: ResourceGeneration::new(2).expect("test generation"),
                    process_id: "process-1".to_owned(),
                    process_generation: ResourceGeneration::new(5).expect("test generation"),
                },
                kernel_epoch: kernel_epoch.clone(),
                state_fence: StateFence::new(kernel_epoch, activation_generation),
            },
            head: SupervisionProgressHead {
                predecessor: SupervisionLeasePredecessorProof {
                    lease_id: "lease-1".to_owned(),
                    record_id: "record-1".to_owned(),
                    lease_revision: 7,
                    receipt_sha256: digest('d'),
                    envelope_sha256: digest('e'),
                },
                lease_issued_at_ms: 1_000,
                lease_expires_at_ms: 61_000,
            },
        }
    }

    fn test_producer() -> SupervisionProgressProducer {
        SupervisionProgressProducer::new(SupervisionProducerDeps {
            daemon_artifact_id: "eliotd-artifact-1".to_owned(),
            daemon_config_digest: digest('c'),
            launch_nonce: "nonce-1".to_owned(),
            process_pid: 4242,
            transport_session_evidence: "sid=1;session=2".to_owned(),
            transport_connection_evidence: "eliotd:conn:1".to_owned(),
            ready: test_ready(),
        })
        .expect("test producer")
    }

    fn idle_inputs() -> SupervisionTickInputs {
        SupervisionTickInputs {
            store_ready: true,
            activation_in_flight: false,
        }
    }

    #[test]
    fn producer_binds_lineage_and_cites_learned_predecessor() {
        let mut producer = test_producer();
        producer.note_claim();
        let request = producer
            .build_observation(
                DaemonProgressChannel::Claim,
                &idle_inputs(),
                HealthDimension::Healthy,
            )
            .expect("claim observation builds");
        assert_eq!(request.request_id, request.observation.observation_id);
        assert_eq!(request.observation.installation_id, "installation-1");
        assert_eq!(request.observation.activation_id, "activation-1");
        assert_eq!(request.observation.lease_id, "lease-1");
        assert_eq!(request.observation.lease_revision, 7);
        assert_eq!(request.observation.predecessor_receipt_sha256, digest('d'));
        assert_eq!(request.predecessor, test_ready().head.predecessor);
        assert_eq!(
            request.observation.disposition,
            DaemonProgressDisposition::ForwardProgress
        );
        assert_eq!(request.observation.progress_cursor, 1);
        assert_eq!(request.observation.previous_progress_cursor, 0);
        assert!(request.observation.observed_monotonic_ms > 0);
        assert!(request.observation.observed_wall_ms > 0);
    }

    #[test]
    fn idle_daemon_reports_explicit_no_progress_that_cannot_renew() {
        let mut producer = test_producer();
        let request = producer
            .build_observation(
                DaemonProgressChannel::Claim,
                &idle_inputs(),
                HealthDimension::Healthy,
            )
            .expect("idle observation builds");
        assert_eq!(
            request.observation.disposition,
            DaemonProgressDisposition::NoProgress
        );
        assert!(!request.observation.disposition.is_renewal_eligible());
    }

    #[test]
    fn store_outage_keeps_forward_progress_disposition() {
        let mut producer = test_producer();
        producer.note_claim();
        let request = producer
            .build_observation(
                DaemonProgressChannel::Claim,
                &idle_inputs(),
                HealthDimension::Failed,
            )
            .expect("observation builds");
        // The Store dimension is evidence only: live daemon progress keeps its
        // renewal-eligible disposition while reporting the failed dependency.
        assert_eq!(
            request.observation.disposition,
            DaemonProgressDisposition::ForwardProgress
        );
        assert_eq!(
            request.observation.health.store_dependency,
            HealthDimension::Failed
        );
    }

    #[test]
    fn blocked_work_on_unready_store_waits_on_the_named_dependency() {
        let mut producer = test_producer();
        let inputs = SupervisionTickInputs {
            store_ready: false,
            activation_in_flight: true,
        };
        let request = producer
            .build_observation(
                DaemonProgressChannel::Claim,
                &inputs,
                HealthDimension::Failed,
            )
            .expect("waiting observation builds");
        assert_eq!(
            request.observation.disposition,
            DaemonProgressDisposition::WaitingOnNamedDependency
        );
        assert_eq!(
            request.observation.waiting_on_dependency.as_deref(),
            Some(STORE_DEPENDENCY_WAIT_NAME)
        );
    }

    #[test]
    fn kernel_applied_advances_dispatch_and_apply_together() {
        let mut producer = test_producer();
        producer.note_claim();
        producer.note_kernel_applied();
        let claim = producer
            .build_observation(
                DaemonProgressChannel::Claim,
                &idle_inputs(),
                HealthDimension::Healthy,
            )
            .expect("claim builds");
        let dispatch = producer
            .build_observation(
                DaemonProgressChannel::Dispatch,
                &idle_inputs(),
                HealthDimension::Healthy,
            )
            .expect("dispatch builds");
        let apply = producer
            .build_observation(
                DaemonProgressChannel::Apply,
                &idle_inputs(),
                HealthDimension::Healthy,
            )
            .expect("apply builds");
        assert_eq!(claim.observation.progress_cursor, 1);
        assert_eq!(dispatch.observation.progress_cursor, 1);
        assert_eq!(apply.observation.progress_cursor, 1);
        assert_ne!(claim.request_id, dispatch.request_id);
        assert_ne!(dispatch.request_id, apply.request_id);
    }

    #[test]
    fn answer_adoption_converges_predecessor_and_cursors_then_halts_on_expiry() {
        let mut producer = test_producer();
        producer.note_claim();
        let request = producer
            .build_observation(
                DaemonProgressChannel::Claim,
                &idle_inputs(),
                HealthDimension::Healthy,
            )
            .expect("claim builds");
        let renewed_head = SupervisionLeasePredecessorProof {
            lease_id: "lease-1".to_owned(),
            record_id: "record-2".to_owned(),
            lease_revision: 8,
            receipt_sha256: digest('f'),
            envelope_sha256: digest('a'),
        };
        let decision = DaemonSupervisionRenewalDecision {
            request_id: request.request_id.clone(),
            lease_id: "lease-1".to_owned(),
            outcome: DaemonSupervisionRenewalOutcome::Renewed,
            predecessor_revision: 7,
            successor_revision: Some(8),
            predecessor_receipt_sha256: digest('d'),
        };
        let answer = SupervisionProgressAnswer {
            outcome: Some(DaemonSupervisionRenewalOutcome::Renewed),
            refusal_code: None,
            decision: Some(decision),
            receipt: Some(DaemonSupervisionRenewalReceipt {
                request_id: request.request_id.clone(),
                lease_id: "lease-1".to_owned(),
                outcome: DaemonSupervisionRenewalOutcome::Renewed,
                predecessor_revision: 7,
                successor_revision: Some(8),
                predecessor_receipt_sha256: digest('d'),
                successor_receipt_sha256: Some(digest('b')),
                live_receipt_sha256: Some(digest('9')),
            }),
            predecessor: renewed_head.clone(),
            accepted_cursors: vec![DaemonChannelCursor {
                channel: DaemonProgressChannel::Claim,
                cursor: 1,
            }],
            expired: false,
        };
        producer.adopt_answer(&answer).expect("answer adopts");
        assert_eq!(producer.head.predecessor, renewed_head);
        // The next observation cites the renewed predecessor and the accepted
        // cursor, never its own last-submitted cursor.
        producer.note_claim();
        let next = producer
            .build_observation(
                DaemonProgressChannel::Claim,
                &idle_inputs(),
                HealthDimension::Healthy,
            )
            .expect("next builds");
        assert_eq!(next.observation.lease_revision, 8);
        assert_eq!(next.observation.predecessor_receipt_sha256, digest('f'));
        assert_eq!(next.observation.previous_progress_cursor, 1);
        assert_eq!(next.observation.progress_cursor, 2);
        // An answer for an unknown request identity is rejected.
        let mut foreign = answer.clone();
        if let Some(decision) = foreign.decision.as_mut() {
            decision.request_id = "hb-foreign".to_owned();
        }
        assert!(producer.adopt_answer(&foreign).is_err());
        // Terminal expiry halts further submits.
        let expired_answer = SupervisionProgressAnswer {
            outcome: None,
            refusal_code: Some("SUPERVISION_LEASE_EXPIRED".to_owned()),
            decision: None,
            receipt: None,
            predecessor: renewed_head,
            accepted_cursors: Vec::new(),
            expired: true,
        };
        producer
            .adopt_answer(&expired_answer)
            .expect("expiry adopts");
        assert!(producer.halted());
        assert!(!producer.submit_due(DaemonProgressChannel::Claim));
        assert!(
            producer
                .build_observation(
                    DaemonProgressChannel::Claim,
                    &idle_inputs(),
                    HealthDimension::Healthy
                )
                .is_err()
        );
    }

    #[test]
    fn ready_bundle_and_answer_wire_shapes_parse_strictly() {
        let ready = test_ready();
        let lineage_value = serde_json::json!({
            "installation_id": ready.lineage.installation_id,
            "activation_id": ready.lineage.activation_id,
            "activation_generation": ready.lineage.activation_generation.value(),
            "generation_binding": ready.lineage.generation_binding,
            "kernel_epoch": ready.lineage.kernel_epoch,
            "state_fence": ready.lineage.state_fence,
        });
        let value = serde_json::json!({
            "accepted": true,
            "supervision": {
                "lineage": lineage_value,
                "head": {
                    "predecessor": ready.head.predecessor,
                    "lease_issued_at_ms": ready.head.lease_issued_at_ms,
                    "lease_expires_at_ms": ready.head.lease_expires_at_ms,
                },
            },
        });
        let parsed = parse_daemon_ready_supervision(&value).expect("ready bundle parses");
        assert_eq!(parsed, ready);
        assert!(parse_daemon_ready_supervision(&serde_json::json!({"accepted": true})).is_err());

        let answer_value = serde_json::json!({
            "outcome": "NOT_DUE",
            "refusal_code": null,
            "decision": {
                "request_id": "hb-1",
                "lease_id": "lease-1",
                "outcome": "NOT_DUE",
                "predecessor_revision": 7,
                "successor_revision": null,
                "predecessor_receipt_sha256": digest('d'),
            },
            "receipt": {
                "request_id": "hb-1",
                "lease_id": "lease-1",
                "outcome": "NOT_DUE",
                "predecessor_revision": 7,
                "successor_revision": null,
                "predecessor_receipt_sha256": digest('d'),
                "successor_receipt_sha256": null,
                "live_receipt_sha256": null,
            },
            "predecessor": ready.head.predecessor,
            "accepted_cursors": [],
        });
        let answer = parse_progress_answer(&answer_value).expect("answer parses");
        assert_eq!(
            answer.outcome,
            Some(DaemonSupervisionRenewalOutcome::NotDue)
        );
        assert!(!answer.expired);
        assert!(parse_progress_answer(&serde_json::json!({})).is_err());
    }

    #[test]
    fn constructor_rejects_invented_identities() {
        let mut deps = SupervisionProducerDeps {
            daemon_artifact_id: "eliotd-artifact-1".to_owned(),
            daemon_config_digest: digest('c'),
            launch_nonce: "nonce-1".to_owned(),
            process_pid: 4242,
            transport_session_evidence: "sid=1;session=2".to_owned(),
            transport_connection_evidence: "eliotd:conn:1".to_owned(),
            ready: test_ready(),
        };
        deps.transport_session_evidence = "   ".to_owned();
        assert!(SupervisionProgressProducer::new(deps).is_err());
    }
}
