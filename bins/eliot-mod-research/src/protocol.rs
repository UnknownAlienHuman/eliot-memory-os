//! Typed versioned research-provider wire protocol.
//!
//! The bridge speaks one bounded JSONL wire to the provider child. The first
//! stdout line is the submit acknowledgement; the terminal result frame, when
//! present, carries the provider disposition plus the candidate content digest
//! (candidate bytes stay in raw evidence for Governor admission; they are
//! never parsed here as semantic results).
//!
//! A returned provider `job_id` is provider-local correlation state. It is
//! retained in bridge outcome evidence and never promoted to canonical
//! task/job identity: the exchange keys on the admitted operation identity.
//! Provider bodies never enter errors; every refusal carries a stable reason.
//!
//! ## Envelope delivery (issue #24, W4)
//!
//! The shared process contour has no stdin channel. This module therefore
//! does **not** pretend the full envelope bytes are delivered to the child.
//! Instead the submit is delivered in two exact, separately verifiable parts:
//!
//! 1. [`SubmitBinding`] — the envelope *minus* the process-request digest. It
//!    contains the operation identity, exchange and idempotency correlation,
//!    protocol revision, required schema, and the exact request digest. Its
//!    canonical SHA-256 is projected into the **admitted** `ProcessIntent`
//!    argv, which the dispatch permit seals through the intent's
//!    `effect_digest`. The provider therefore receives a Kernel-authorized,
//!    digest-bound description of exactly which request it must answer, and it
//!    cannot be substituted or retargeted without detection. No child pipe is
//!    opened, so no ambient caller-supplied input surface returns.
//!
//! 2. [`SubmitEnvelope`] — the full canonical envelope, which additionally
//!    binds the sealed process-request digest. Its bytes are the exact
//!    reconciliation/evidence record: they are retained in
//!    `ProviderExecution::wire_bytes` and in the terminal
//!    `ProviderExecutionReceipt`, so a replay or an unknown outcome can be
//!    reconciled byte-for-byte against the digest the provider was given.
//!
//! Splitting the binding from the invocation digest is what makes this
//! non-circular: the binding digest is computed before the process request
//! exists, and the process request's own digest is what the envelope then
//! records. A single self-referential digest would be uncomputable.
//!
//! ## Admitted identity coverage (issue #24, W2)
//!
//! [`SubmitBinding`] carries the eight identities the issue requires the
//! provider to be bound to — exact artifact/config/protocol digest, the
//! Module/Capability Registry evidence references, process generation, Authority
//! Epoch, State Fence, privacy/data class, budget/deadline and cancellation
//! identity — beside its correlation fields. They belong to the
//! [`crate::admission::ProviderAdmission`] alone; this module never derives
//! them, and [`ProviderAdmission::validate_submit_binding`](crate::admission::ProviderAdmission::validate_submit_binding)
//! is what compares them back by value at mint time. Carrying them here is
//! necessary but not sufficient: the canonical digest is what the provider is
//! actually given, and it is compared twice — once by the minting port and once
//! by the bridge before the executor is contacted.
//!
//! The wire version is deliberately **not** bumped for this. The provider never
//! receives these bytes: it receives only the canonical binding digest through
//! the admitted argv, and the envelope bytes stay in this process as the
//! reconciliation record. [`RESEARCH_PROVIDER_WIRE_VERSION`] governs the frames
//! the provider sends back, and those are unchanged.

use eliot_contracts::{ContractVersion, EpochId, StateFence};
use serde::{Deserialize, Serialize};

use crate::evidence::sha256_hex;

/// Current research-provider wire version. The bridge accepts exactly this
/// version; anything else is a stale/foreign wire, never a best-effort parse.
pub const RESEARCH_PROVIDER_WIRE_VERSION: u16 = 1;
/// Maximum accepted wire payload in bytes (one envelope or one frame).
pub const MAX_WIRE_BYTES: usize = 64 * 1024;
/// Maximum accepted stdout lines scanned for ack/result frames.
pub const MAX_WIRE_LINES: usize = 4096;

/// Stable refusal reasons for wire violations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolRefusal {
    /// Payload exceeds the wire bound.
    WireTooLarge,
    /// Payload is not well-formed JSON under the exact schema.
    MalformedWire,
    /// Wire version differs from the admitted version.
    StaleWire,
    /// A required correlation field is blank.
    BlankCorrelation,
    /// No terminal result frame is present in provider output.
    MissingResultFrame,
    /// Provider output exceeds the line scan bound.
    TooManyLines,
    /// The envelope and its binding disagree on a shared field.
    BindingMismatch,
}

impl ProtocolRefusal {
    /// Returns the stable machine-greppable reason string.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::WireTooLarge => "provider wire payload exceeds the wire bound",
            Self::MalformedWire => "provider wire payload is not well-formed typed JSON",
            Self::StaleWire => "provider wire version differs from the admitted version",
            Self::BlankCorrelation => "provider correlation field is blank",
            Self::MissingResultFrame => "provider output carries no terminal result frame",
            Self::TooManyLines => "provider output exceeds the wire line bound",
            Self::BindingMismatch => "submit envelope disagrees with its delivered submit binding",
        }
    }
}

/// Bounded submit projection delivered to the provider through the admitted
/// `ProcessIntent` argv.
///
/// This is the part of the submit the provider can actually verify: its
/// canonical digest is the value handed over, and the field values are the
/// exact correlation the answer must be attributed to. It deliberately omits
/// the process-request digest, which cannot exist before the argv is sealed.
///
/// The admitted-identity block below is what issue #24's "bind the provider to
/// exact artifact/config/protocol hash, Module/Capability Registry evidence,
/// process generation, Authority Epoch, State Fence, privacy/data class,
/// budget/deadline, and cancellation identity" requires. Every one of those
/// values is read from a [`ProviderAdmission`](crate::admission::ProviderAdmission)
/// accessor and re-proved against the same record at mint time by
/// [`ProviderAdmission::validate_submit_binding`](crate::admission::ProviderAdmission::validate_submit_binding);
/// nothing here is a second identity authority, and no value is derived,
/// defaulted or widened in this module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitBinding {
    /// Exact wire version (must equal `RESEARCH_PROVIDER_WIRE_VERSION`).
    pub wire_version: u16,
    /// Stable admitted operation identity.
    pub operation_id: String,
    /// Exchange correlation echoed from the request.
    pub exchange_id: String,
    /// Idempotency correlation echoed from the request.
    pub idempotency_key: String,
    /// Admitted protocol revision.
    pub protocol_revision: ContractVersion,
    /// Admitted required result schema.
    pub required_schema: String,
    /// SHA-256 of the canonical request JSON this binding was built from.
    pub request_sha256: String,
    /// Exact admitted executable content digest (the artifact identity).
    pub executable_sha256: String,
    /// Exact admitted provider configuration digest.
    pub config_digest: String,
    /// Exact admitted provider protocol digest.
    pub protocol_digest: String,
    /// Module/Capability Registry evidence reference for the provider.
    pub module_id: String,
    /// Module generation evidence reference for the provider.
    pub module_generation_id: String,
    /// Admitted process generation.
    pub process_generation: u64,
    /// Admitted Authority Epoch (exact lineage/sequence tuple).
    pub authority_epoch: EpochId,
    /// Admitted State Fence.
    pub state_fence: StateFence,
    /// Admitted privacy/data-class wire name.
    pub disclosure: String,
    /// Admitted budget ceiling in provider units.
    pub budget_units: u64,
    /// Admitted deadline ceiling in milliseconds.
    pub deadline_ms: i64,
    /// Cancellation identity for this operation's lifecycle.
    pub cancellation_id: String,
}

impl SubmitBinding {
    /// Returns the canonical bytes of this binding.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolRefusal::WireTooLarge`] when the encoded binding
    /// exceeds the wire bound.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolRefusal> {
        let bytes = serde_json::to_vec(self).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        Ok(bytes)
    }

    /// Returns the canonical SHA-256 digest projected into the admitted argv.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolRefusal::WireTooLarge`] when the encoded binding
    /// exceeds the wire bound.
    pub fn digest(&self) -> Result<String, ProtocolRefusal> {
        Ok(sha256_hex(&self.encode()?))
    }
}

/// Canonical submit envelope retained as the exact reconciliation record.
///
/// The envelope binds operation, route, exact request content, the full
/// admitted-identity block, and the sealed process-request digest the execution
/// ran under. Its bytes never reach the child as a stream (see the module
/// docs); they are retained so an unknown outcome or a replay can be reconciled
/// byte-for-byte against the binding digest the provider was actually given.
///
/// It is exactly its [`SubmitBinding`] plus `invocation_digest`, so
/// [`SubmitEnvelope::binding`] is total: every admitted identity the provider was
/// bound to is still readable from the retained reconciliation record after the
/// run, and a round-trip comparison of `binding().digest()` against the
/// delivered digest re-proves all of them at once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitEnvelope {
    /// Exact wire version (must equal `RESEARCH_PROVIDER_WIRE_VERSION`).
    pub wire_version: u16,
    /// Stable admitted operation identity.
    pub operation_id: String,
    /// Exchange correlation echoed from the request.
    pub exchange_id: String,
    /// Idempotency correlation echoed from the request.
    pub idempotency_key: String,
    /// Sealed process-request digest the envelope is bound to execute under.
    pub invocation_digest: String,
    /// Admitted protocol revision.
    pub protocol_revision: ContractVersion,
    /// Admitted required result schema.
    pub required_schema: String,
    /// SHA-256 of the canonical request JSON this envelope was built from.
    pub request_sha256: String,
    /// Exact admitted executable content digest (the artifact identity).
    pub executable_sha256: String,
    /// Exact admitted provider configuration digest.
    pub config_digest: String,
    /// Exact admitted provider protocol digest.
    pub protocol_digest: String,
    /// Module/Capability Registry evidence reference for the provider.
    pub module_id: String,
    /// Module generation evidence reference for the provider.
    pub module_generation_id: String,
    /// Admitted process generation.
    pub process_generation: u64,
    /// Admitted Authority Epoch (exact lineage/sequence tuple).
    pub authority_epoch: EpochId,
    /// Admitted State Fence.
    pub state_fence: StateFence,
    /// Admitted privacy/data-class wire name.
    pub disclosure: String,
    /// Admitted budget ceiling in provider units.
    pub budget_units: u64,
    /// Admitted deadline ceiling in milliseconds.
    pub deadline_ms: i64,
    /// Cancellation identity for this operation's lifecycle.
    pub cancellation_id: String,
}

impl SubmitEnvelope {
    /// Builds the retained reconciliation record from the delivered binding and
    /// the sealed process-request digest the execution ran under.
    ///
    /// The two records differ by exactly that one field, so this is the
    /// INVERSE of [`Self::binding`] and the pair is total in both directions:
    /// `SubmitEnvelope::from_binding(&b, d).binding() == b` for every binding
    /// `b`, and no admitted identity the provider was bound to can be dropped
    /// on the way into the retained record.
    ///
    /// The `invocation_digest` cannot exist while the binding is being built —
    /// the binding's own digest is projected into the argv that the process
    /// request seals, so the envelope is strictly later — which is why this is
    /// a separate constructor and not a field on [`SubmitBinding`].
    pub fn from_binding(binding: &SubmitBinding, invocation_digest: &str) -> Self {
        Self {
            wire_version: binding.wire_version,
            operation_id: binding.operation_id.clone(),
            exchange_id: binding.exchange_id.clone(),
            idempotency_key: binding.idempotency_key.clone(),
            invocation_digest: invocation_digest.to_owned(),
            protocol_revision: binding.protocol_revision,
            required_schema: binding.required_schema.clone(),
            request_sha256: binding.request_sha256.clone(),
            executable_sha256: binding.executable_sha256.clone(),
            config_digest: binding.config_digest.clone(),
            protocol_digest: binding.protocol_digest.clone(),
            module_id: binding.module_id.clone(),
            module_generation_id: binding.module_generation_id.clone(),
            process_generation: binding.process_generation,
            authority_epoch: binding.authority_epoch.clone(),
            state_fence: binding.state_fence.clone(),
            disclosure: binding.disclosure.clone(),
            budget_units: binding.budget_units,
            deadline_ms: binding.deadline_ms,
            cancellation_id: binding.cancellation_id.clone(),
        }
    }

    /// Returns the bounded submit projection of this envelope.
    ///
    /// # Errors
    ///
    /// Never fails for a well-formed envelope; the signature stays total so
    /// the call site cannot silently skip the projection.
    pub fn binding(&self) -> SubmitBinding {
        SubmitBinding {
            wire_version: self.wire_version,
            operation_id: self.operation_id.clone(),
            exchange_id: self.exchange_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            protocol_revision: self.protocol_revision,
            required_schema: self.required_schema.clone(),
            request_sha256: self.request_sha256.clone(),
            executable_sha256: self.executable_sha256.clone(),
            config_digest: self.config_digest.clone(),
            protocol_digest: self.protocol_digest.clone(),
            module_id: self.module_id.clone(),
            module_generation_id: self.module_generation_id.clone(),
            process_generation: self.process_generation,
            authority_epoch: self.authority_epoch.clone(),
            state_fence: self.state_fence.clone(),
            disclosure: self.disclosure.clone(),
            budget_units: self.budget_units,
            deadline_ms: self.deadline_ms,
            cancellation_id: self.cancellation_id.clone(),
        }
    }

    /// Encodes the envelope to canonical bounded bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolRefusal> {
        let bytes = serde_json::to_vec(self).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        Ok(bytes)
    }

    /// Decodes one envelope, enforcing version and correlation shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolRefusal> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if envelope.wire_version != RESEARCH_PROVIDER_WIRE_VERSION {
            return Err(ProtocolRefusal::StaleWire);
        }
        // Every admitted identity is shape-checked here as well as compared by
        // value in `admission`: `deny_unknown_fields` refuses an *extra* field,
        // and the checks below refuse a missing, blank or out-of-range one, so a
        // stripped envelope cannot decode into a record that looks admitted.
        // Blank text is `BlankCorrelation`; a zero generation or non-positive
        // ceiling is `MalformedWire`, because the Kernel never admits one and
        // naming it as blank correlation would misdescribe the refusal.
        if envelope.operation_id.trim().is_empty()
            || envelope.invocation_digest.trim().is_empty()
            || envelope.request_sha256.trim().is_empty()
            || envelope.exchange_id.trim().is_empty()
            || envelope.idempotency_key.trim().is_empty()
            || envelope.required_schema.trim().is_empty()
            || envelope.executable_sha256.trim().is_empty()
            || envelope.config_digest.trim().is_empty()
            || envelope.protocol_digest.trim().is_empty()
            || envelope.module_id.trim().is_empty()
            || envelope.module_generation_id.trim().is_empty()
            || envelope.disclosure.trim().is_empty()
            || envelope.cancellation_id.trim().is_empty()
        {
            return Err(ProtocolRefusal::BlankCorrelation);
        }
        if envelope.process_generation == 0
            || envelope.budget_units == 0
            || envelope.deadline_ms <= 0
        {
            return Err(ProtocolRefusal::MalformedWire);
        }
        Ok(envelope)
    }
}

/// Provider submit acknowledgement (first stdout line).
///
/// `provider_job_id` is provider-local correlation only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitAck {
    /// Exact wire version (must equal `RESEARCH_PROVIDER_WIRE_VERSION`).
    pub wire_version: u16,
    /// Provider-local job reference (never canonical identity).
    pub provider_job_id: String,
}

impl SubmitAck {
    /// Decodes the acknowledgement line, enforcing version and non-blank ref.
    pub fn decode(line: &[u8]) -> Result<Self, ProtocolRefusal> {
        if line.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        let ack: Self = serde_json::from_slice(line).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if ack.wire_version != RESEARCH_PROVIDER_WIRE_VERSION {
            return Err(ProtocolRefusal::StaleWire);
        }
        if ack.provider_job_id.trim().is_empty() {
            return Err(ProtocolRefusal::BlankCorrelation);
        }
        Ok(ack)
    }
}

/// Terminal provider result disposition (provider-local outcome, not a
/// semantic verdict and never task finish).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderResultDisposition {
    /// Provider completed and a candidate is available under its digest.
    CompletedCandidateAvailable,
    /// Provider reports it cancelled the acquisition.
    ProviderCancelled,
    /// Provider reports acquisition failure.
    ProviderFailed,
}

/// Terminal result frame decoded from provider stdout.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultFrame {
    /// Exact wire version (must equal `RESEARCH_PROVIDER_WIRE_VERSION`).
    pub wire_version: u16,
    /// Provider-local terminal disposition.
    pub disposition: ProviderResultDisposition,
    /// SHA-256 of the candidate bytes available in raw evidence.
    pub candidate_sha256: String,
}

impl ResultFrame {
    /// Decodes one terminal result frame.
    pub fn decode(line: &[u8]) -> Result<Self, ProtocolRefusal> {
        if line.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        let frame: Self =
            serde_json::from_slice(line).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if frame.wire_version != RESEARCH_PROVIDER_WIRE_VERSION {
            return Err(ProtocolRefusal::StaleWire);
        }
        if !crate::is_lowercase_sha256(&frame.candidate_sha256) {
            return Err(ProtocolRefusal::MalformedWire);
        }
        Ok(frame)
    }
}

/// Scans bounded stdout bytes for the terminal result frame.
///
/// Lines are scanned in order within the line bound; the last well-formed
/// result frame wins. Returns `None` when no line decodes as a result frame
/// (absence is explicit, never a fabricated empty result).
pub fn scan_result_frame(stdout: &[u8]) -> Result<Option<ResultFrame>, ProtocolRefusal> {
    if stdout.len() > MAX_WIRE_BYTES {
        return Err(ProtocolRefusal::WireTooLarge);
    }
    let mut found: Option<ResultFrame> = None;
    let mut lines = 0_usize;
    for line in stdout.split(|byte| *byte == b'\n') {
        lines += 1;
        if lines > MAX_WIRE_LINES {
            return Err(ProtocolRefusal::TooManyLines);
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if let Ok(frame) = ResultFrame::decode(line) {
            found = Some(frame);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use eliot_contracts::ContractVersion;

    use crate::support::{DIGEST_A, DIGEST_B, DIGEST_C, test_epoch, test_fence};

    use super::*;

    fn test_envelope() -> SubmitEnvelope {
        SubmitEnvelope {
            wire_version: RESEARCH_PROVIDER_WIRE_VERSION,
            operation_id: "op-24-slice-a".to_owned(),
            exchange_id: "ex-24-slice-a".to_owned(),
            idempotency_key: "idem-24-slice-a".to_owned(),
            invocation_digest: DIGEST_A.to_owned(),
            protocol_revision: ContractVersion::new(1, 0, 0),
            required_schema: "research-evidence-bundle/v1".to_owned(),
            request_sha256: DIGEST_A.to_owned(),
            executable_sha256: DIGEST_A.to_owned(),
            config_digest: DIGEST_B.to_owned(),
            protocol_digest: DIGEST_C.to_owned(),
            module_id: "mod-research-provider".to_owned(),
            module_generation_id: "gen-mod-24-a".to_owned(),
            process_generation: 3,
            authority_epoch: test_epoch(),
            state_fence: test_fence(),
            disclosure: "ProjectBound".to_owned(),
            budget_units: 10,
            deadline_ms: 1_800_000_000_000,
            cancellation_id: "cancel-24-slice-a".to_owned(),
        }
    }

    #[test]
    fn envelope_round_trips_exactly() {
        let envelope = test_envelope();
        let bytes = envelope.encode().expect("envelope must encode");
        let decoded = SubmitEnvelope::decode(&bytes).expect("envelope must decode");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn envelope_rejects_stale_wire_version() {
        let mut envelope = test_envelope();
        envelope.wire_version = RESEARCH_PROVIDER_WIRE_VERSION + 1;
        let bytes = envelope.encode().expect("encoding is version-agnostic");
        assert_eq!(
            SubmitEnvelope::decode(&bytes),
            Err(ProtocolRefusal::StaleWire)
        );
        let mut legacy = test_envelope();
        legacy.wire_version = RESEARCH_PROVIDER_WIRE_VERSION - 1;
        let legacy_bytes = legacy.encode().expect("encoding is version-agnostic");
        assert_eq!(
            SubmitEnvelope::decode(&legacy_bytes),
            Err(ProtocolRefusal::StaleWire)
        );
    }

    #[test]
    fn envelope_rejects_malformed_and_blank_payloads() {
        assert_eq!(
            SubmitEnvelope::decode(b"{not json"),
            Err(ProtocolRefusal::MalformedWire)
        );
        assert_eq!(
            SubmitEnvelope::decode(b"{\"wire_version\":1}"),
            Err(ProtocolRefusal::MalformedWire)
        );
        let mut blank = test_envelope();
        blank.operation_id = "   ".to_owned();
        let bytes = blank.encode().expect("encoding is shape-agnostic");
        assert_eq!(
            SubmitEnvelope::decode(&bytes),
            Err(ProtocolRefusal::BlankCorrelation)
        );
    }

    #[test]
    fn ack_decode_accepts_only_versioned_non_blank_refs() {
        let ack = SubmitAck::decode(b"{\"wire_version\":1,\"provider_job_id\":\"pv-991\"}")
            .expect("ack must decode");
        assert_eq!(ack.provider_job_id, "pv-991");
        assert_eq!(
            SubmitAck::decode(b"{\"wire_version\":1,\"provider_job_id\":\"  \"}"),
            Err(ProtocolRefusal::BlankCorrelation)
        );
        assert_eq!(
            SubmitAck::decode(b"{\"wire_version\":2,\"provider_job_id\":\"pv-991\"}"),
            Err(ProtocolRefusal::StaleWire)
        );
        assert_eq!(
            SubmitAck::decode(b"provider started job pv-991"),
            Err(ProtocolRefusal::MalformedWire)
        );
        // Unknown fields are refused: the provider must speak the exact schema.
        assert_eq!(
            SubmitAck::decode(
                b"{\"wire_version\":1,\"provider_job_id\":\"pv-991\",\"extra\":true}"
            ),
            Err(ProtocolRefusal::MalformedWire)
        );
    }

    #[test]
    fn result_scan_finds_the_terminal_frame_and_nothing_else() {
        let frame = format!(
            "{{\"wire_version\":1,\"disposition\":\"completed_candidate_available\",\"candidate_sha256\":\"{DIGEST_A}\"}}"
        );
        let stdout = format!("{{\"wire_version\":1,\"provider_job_id\":\"pv-991\"}}\n{frame}\n");
        let found = scan_result_frame(stdout.as_bytes())
            .expect("scan must succeed")
            .expect("terminal frame must be found");
        assert_eq!(
            found.disposition,
            ProviderResultDisposition::CompletedCandidateAvailable
        );
        assert_eq!(found.candidate_sha256, DIGEST_A);
    }

    #[test]
    fn all_provider_dispositions_decode() {
        for (wire, expected) in [
            (
                "completed_candidate_available",
                ProviderResultDisposition::CompletedCandidateAvailable,
            ),
            (
                "provider_cancelled",
                ProviderResultDisposition::ProviderCancelled,
            ),
            ("provider_failed", ProviderResultDisposition::ProviderFailed),
        ] {
            let line = format!(
                "{{\"wire_version\":1,\"disposition\":\"{wire}\",\"candidate_sha256\":\"{DIGEST_A}\"}}"
            );
            let frame = ResultFrame::decode(line.as_bytes()).expect("disposition must decode");
            assert_eq!(frame.disposition, expected);
        }
    }

    #[test]
    fn result_scan_absence_is_explicit() {
        let stdout = b"{\"wire_version\":1,\"provider_job_id\":\"pv-991\"}\nprogress: 3\n";
        assert!(
            scan_result_frame(stdout)
                .expect("scan must succeed")
                .is_none(),
            "absence of a result frame must decode as absence, never an empty result"
        );
    }

    #[test]
    fn result_scan_rejects_malformed_candidate_digest() {
        let stdout = b"{\"wire_version\":1,\"disposition\":\"completed_candidate_available\",\"candidate_sha256\":\"ZZZ\"}\n";
        // A malformed frame is skipped by the scan (provider-local noise), so
        // absence stays explicit here; strict decode still refuses it below.
        assert!(
            scan_result_frame(stdout)
                .expect("scan must succeed")
                .is_none()
        );
        assert_eq!(
            ResultFrame::decode(
                b"{\"wire_version\":1,\"disposition\":\"completed_candidate_available\",\"candidate_sha256\":\"ZZZ\"}"
            ),
            Err(ProtocolRefusal::MalformedWire)
        );
    }

    #[test]
    fn wire_bounds_are_enforced() {
        let oversized = vec![b'x'; MAX_WIRE_BYTES + 1];
        assert_eq!(
            SubmitEnvelope::decode(&oversized),
            Err(ProtocolRefusal::WireTooLarge)
        );
        assert_eq!(
            scan_result_frame(&oversized),
            Err(ProtocolRefusal::WireTooLarge)
        );
        let mut many_lines = Vec::new();
        for _ in 0..=MAX_WIRE_LINES {
            many_lines.extend_from_slice(b"\n");
        }
        assert_eq!(
            scan_result_frame(&many_lines),
            Err(ProtocolRefusal::TooManyLines)
        );
    }

    #[test]
    fn refusal_reasons_are_stable() {
        assert_eq!(
            ProtocolRefusal::StaleWire.reason(),
            "provider wire version differs from the admitted version"
        );
    }
}
