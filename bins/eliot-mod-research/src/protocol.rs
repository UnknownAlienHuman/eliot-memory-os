//! Typed versioned research-provider wire protocol.
//!
//! The request envelope is encoded before the Kernel-issued process request
//! is minted and is carried as an exact process argument. The executor's
//! argv is therefore the delivery channel: the child receives the bytes that
//! were hashed and admitted, rather than a locally reconstructed equivalent.
//! Provider-local job identifiers remain correlation evidence only.

use eliot_contracts::ContractVersion;
use eliot_research_exchange_api::DisclosureClass;
use serde::{Deserialize, Serialize};

use crate::admission::ProviderAdmission;
use crate::{is_lowercase_sha256, sha256_hex};

/// Current research-provider wire version.
pub const RESEARCH_PROVIDER_WIRE_VERSION: u16 = 2;
/// Maximum accepted wire payload in bytes (one envelope or one frame).
pub const MAX_WIRE_BYTES: usize = 64 * 1024;
/// Maximum accepted stdout lines scanned for ack/result frames.
pub const MAX_WIRE_LINES: usize = 4096;
/// Exact argv marker used to deliver the admitted request envelope.
pub const PROVIDER_WIRE_ARGUMENT: &str = "--eliot-research-wire";

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
    /// Provider output contains more than one terminal result claim.
    AmbiguousResultFrame,
    /// Provider output exceeds the line scan bound.
    TooManyLines,
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
            Self::AmbiguousResultFrame => "provider output carries multiple terminal result frames",
            Self::TooManyLines => "provider output exceeds the wire line bound",
        }
    }
}

/// Canonical submit envelope delivered to the provider child.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitEnvelope {
    /// Exact wire version.
    pub wire_version: u16,
    /// Stable admitted operation identity.
    pub operation_id: String,
    /// Exchange correlation echoed from the request.
    pub exchange_id: String,
    /// Idempotency correlation echoed from the request.
    pub idempotency_key: String,
    /// Sealed process-request digest is carried by the executor receipt; the
    /// wire itself carries the canonical request digest so the pre-launch
    /// envelope can be delivered before a permit-bound request exists.
    /// Admitted protocol revision.
    pub protocol_revision: ContractVersion,
    /// Admitted required result schema.
    pub required_schema: String,
    /// SHA-256 of the canonical request JSON.
    pub request_sha256: String,
    /// Exact registry-selected route.
    pub route_id: String,
    /// Exact provider implementation identity selected by the registry.
    pub provider_id: String,
    /// Exact bridge generation selected by the registry.
    pub bridge_generation: String,
    /// SHA-256 of the complete State Fence, including optional revisions.
    pub state_fence_sha256: String,
    /// Exact privacy ceiling.
    pub disclosure: DisclosureClass,
    /// Exact data class.
    pub data_class: String,
    /// Exact owner/credential binding identity.
    pub credential_binding_id: String,
    pub credential_owner_principal: String,
    pub credential_acting_principal: String,
    /// Budget ceiling admitted for this operation.
    pub budget_units: u64,
    /// Absolute deadline in Unix milliseconds.
    pub deadline_unix_ms: i64,
    /// Stable cancellation identity.
    pub cancellation_id: String,
    /// Registry evidence digest used to resolve the route.
    pub registry_evidence_sha256: String,
    /// Process generation admitted by Kernel.
    pub process_generation: u64,
}

impl SubmitEnvelope {
    /// Builds the exact envelope from the admitted contract and request.
    #[must_use]
    pub fn from_admission(
        request: &eliot_research_exchange_api::ResearchQueryRequest,
        admission: &ProviderAdmission,
        request_sha256: String,
    ) -> Self {
        let contract = admission.contract();
        Self {
            wire_version: RESEARCH_PROVIDER_WIRE_VERSION,
            operation_id: admission.operation_id().as_str().to_owned(),
            exchange_id: request.exchange_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            protocol_revision: contract.protocol_revision,
            required_schema: contract.required_schema.clone(),
            request_sha256,
            route_id: contract.route().route_id.clone(),
            provider_id: contract.route().provider_id.clone(),
            bridge_generation: contract.bridge_generation.clone(),
            state_fence_sha256: state_fence_sha256(&contract.fence),
            disclosure: contract.disclosure,
            data_class: contract.data_class.clone(),
            credential_binding_id: contract.credential_binding().binding_id.clone(),
            credential_owner_principal: contract.credential_binding().owner_principal.clone(),
            credential_acting_principal: contract.credential_binding().acting_principal.clone(),
            budget_units: contract.budget_units,
            deadline_unix_ms: contract.deadline_ms,
            cancellation_id: contract.cancellation().cancellation_id.clone(),
            registry_evidence_sha256: contract.registry_evidence_sha256().to_owned(),
            process_generation: contract.process_generation.get(),
        }
    }

    /// Encodes the envelope to bounded JSON bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolRefusal> {
        let bytes = serde_json::to_vec(self).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        Ok(bytes)
    }

    /// Decodes one envelope, enforcing version, correlation, and digest shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolRefusal> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if envelope.wire_version != RESEARCH_PROVIDER_WIRE_VERSION {
            return Err(ProtocolRefusal::StaleWire);
        }
        for value in [
            &envelope.operation_id,
            &envelope.exchange_id,
            &envelope.idempotency_key,
            &envelope.required_schema,
            &envelope.route_id,
            &envelope.provider_id,
            &envelope.bridge_generation,
            &envelope.state_fence_sha256,
            &envelope.data_class,
            &envelope.credential_binding_id,
            &envelope.credential_owner_principal,
            &envelope.credential_acting_principal,
            &envelope.cancellation_id,
            &envelope.registry_evidence_sha256,
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(ProtocolRefusal::BlankCorrelation);
            }
        }
        for digest in [
            &envelope.request_sha256,
            &envelope.state_fence_sha256,
            &envelope.registry_evidence_sha256,
        ] {
            if !is_lowercase_sha256(digest) {
                return Err(ProtocolRefusal::MalformedWire);
            }
        }
        if envelope.budget_units == 0 || envelope.deadline_unix_ms <= 0 {
            return Err(ProtocolRefusal::BlankCorrelation);
        }
        Ok(envelope)
    }
}

/// Computes a stable digest of the complete State Fence.
#[must_use]
pub fn state_fence_sha256(fence: &eliot_contracts::StateFence) -> String {
    serde_json::to_vec(fence).map_or_else(|_| sha256_hex(&[]), |bytes| sha256_hex(&bytes))
}

/// Provider submit acknowledgement. The provider job reference is local
/// correlation state; operation/request digests bind it to the admitted run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitAck {
    /// Exact wire version.
    pub wire_version: u16,
    /// Operation identity echoed by the provider.
    pub operation_id: String,
    /// Canonical request digest echoed by the provider.
    pub request_sha256: String,
    /// Provider-local job reference, never canonical identity.
    pub provider_job_id: String,
}

impl SubmitAck {
    /// Decodes and validates an acknowledgement line.
    pub fn decode(
        line: &[u8],
        expected_operation: &str,
        expected_request_sha256: &str,
    ) -> Result<Self, ProtocolRefusal> {
        if line.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        let ack: Self = serde_json::from_slice(line).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if ack.wire_version != RESEARCH_PROVIDER_WIRE_VERSION {
            return Err(ProtocolRefusal::StaleWire);
        }
        if ack.operation_id.trim().is_empty()
            || ack.provider_job_id.trim().is_empty()
            || ack.operation_id != expected_operation
            || ack.request_sha256 != expected_request_sha256
            || !is_lowercase_sha256(&ack.request_sha256)
        {
            return Err(ProtocolRefusal::BlankCorrelation);
        }
        Ok(ack)
    }
}

/// Provider result coverage denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageDenominator {
    /// The provider proves the requested frozen denominator.
    CompleteScope,
    /// The provider used a declared sample.
    Sampled,
    /// The denominator is not known.
    Unknown,
}

/// Terminal provider result disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderResultDisposition {
    /// Candidate bytes are available under the returned digest.
    CompletedCandidateAvailable,
    /// Provider reports cancellation.
    ProviderCancelled,
    /// Provider reports acquisition failure.
    ProviderFailed,
}

/// Terminal result frame decoded from provider stdout.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultFrame {
    /// Exact wire version.
    pub wire_version: u16,
    /// Operation identity echoed by the provider.
    pub operation_id: String,
    /// Canonical request digest echoed by the provider.
    pub request_sha256: String,
    /// Exact route echoed by the provider.
    pub route_id: String,
    /// Provider-local terminal disposition.
    pub disposition: ProviderResultDisposition,
    /// SHA-256 of candidate bytes held in raw evidence custody.
    pub candidate_sha256: String,
    /// Exact source handles represented by the candidate.
    pub source_handles: Vec<String>,
    /// Exact provenance/evidence handles represented by the candidate.
    pub provenance_handles: Vec<String>,
    /// Coverage denominator claimed by the provider.
    pub coverage_denominator: CoverageDenominator,
    /// Sanitized provider-reported coverage gaps.
    pub coverage_gaps: Vec<String>,
    /// Provider-reported usage in the admitted units.
    pub usage_units: u64,
}

impl ResultFrame {
    /// Decodes one terminal result frame.
    pub fn decode(
        line: &[u8],
        expected_operation: &str,
        expected_request_sha256: &str,
        expected_route: &str,
    ) -> Result<Self, ProtocolRefusal> {
        if line.len() > MAX_WIRE_BYTES {
            return Err(ProtocolRefusal::WireTooLarge);
        }
        let frame: Self =
            serde_json::from_slice(line).map_err(|_| ProtocolRefusal::MalformedWire)?;
        if frame.wire_version != RESEARCH_PROVIDER_WIRE_VERSION {
            return Err(ProtocolRefusal::StaleWire);
        }
        if frame.operation_id != expected_operation
            || frame.request_sha256 != expected_request_sha256
            || frame.route_id != expected_route
            || frame.operation_id.trim().is_empty()
            || frame.route_id.trim().is_empty()
            || !is_lowercase_sha256(&frame.request_sha256)
            || !is_lowercase_sha256(&frame.candidate_sha256)
        {
            return Err(ProtocolRefusal::BlankCorrelation);
        }
        for value in frame
            .source_handles
            .iter()
            .chain(frame.provenance_handles.iter())
            .chain(frame.coverage_gaps.iter())
        {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(ProtocolRefusal::MalformedWire);
            }
        }
        if frame.disposition == ProviderResultDisposition::CompletedCandidateAvailable
            && (frame.source_handles.is_empty() || frame.provenance_handles.is_empty())
        {
            return Err(ProtocolRefusal::MalformedWire);
        }
        Ok(frame)
    }
}

/// Scans bounded stdout for the terminal result frame. A line that claims to
/// be a result frame is strict; ordinary progress/noise lines are ignored.
pub fn scan_result_frame(
    stdout: &[u8],
    expected_operation: &str,
    expected_request_sha256: &str,
    expected_route: &str,
) -> Result<Option<ResultFrame>, ProtocolRefusal> {
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
        if line.starts_with(b"{") && line.windows(12).any(|window| window == b"\"disposition\"") {
            if found.is_some() {
                return Err(ProtocolRefusal::AmbiguousResultFrame);
            }
            found = Some(ResultFrame::decode(
                line,
                expected_operation,
                expected_request_sha256,
                expected_route,
            )?);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use eliot_contracts::ContractVersion;

    use crate::support::DIGEST_A;

    use super::*;

    fn test_envelope() -> SubmitEnvelope {
        SubmitEnvelope {
            wire_version: RESEARCH_PROVIDER_WIRE_VERSION,
            operation_id: "op-24-slice-a".to_owned(),
            exchange_id: "ex-24-slice-a".to_owned(),
            idempotency_key: "idem-24-slice-a".to_owned(),
            protocol_revision: ContractVersion::new(1, 0, 0),
            required_schema: "research-evidence-bundle/v1".to_owned(),
            request_sha256: DIGEST_A.to_owned(),
            route_id: "route-research-private".to_owned(),
            provider_id: "provider-research".to_owned(),
            bridge_generation: "gen-24-slice-a".to_owned(),
            state_fence_sha256: DIGEST_A.to_owned(),
            disclosure: DisclosureClass::ProjectBound,
            data_class: "project-bound".to_owned(),
            credential_binding_id: "credential-binding-24".to_owned(),
            credential_owner_principal: "researcher-owner".to_owned(),
            credential_acting_principal: "requester-24-slice-a".to_owned(),
            budget_units: 10,
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-op-24".to_owned(),
            registry_evidence_sha256: DIGEST_A.to_owned(),
            process_generation: 3,
        }
    }

    #[test]
    fn envelope_round_trips_exactly() {
        let envelope = test_envelope();
        let bytes = envelope.encode().expect("envelope must encode");
        assert_eq!(SubmitEnvelope::decode(&bytes).expect("decode"), envelope);
    }

    #[test]
    fn envelope_rejects_stale_wire_and_bad_correlation() {
        let mut envelope = test_envelope();
        envelope.wire_version = RESEARCH_PROVIDER_WIRE_VERSION + 1;
        assert_eq!(
            SubmitEnvelope::decode(&envelope.encode().expect("encode")),
            Err(ProtocolRefusal::StaleWire)
        );
        let mut envelope = test_envelope();
        envelope.request_sha256 = "not-a-digest".to_owned();
        assert_eq!(
            SubmitEnvelope::decode(&envelope.encode().expect("encode")),
            Err(ProtocolRefusal::MalformedWire)
        );
    }

    #[test]
    fn ack_and_result_are_bound_to_operation_request_and_route() {
        let ack = SubmitAck::decode(
            br#"{"wire_version":2,"operation_id":"op-24-slice-a","request_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider_job_id":"pv-991"}"#,
            "op-24-slice-a",
            DIGEST_A,
        )
        .expect("ack");
        assert_eq!(ack.provider_job_id, "pv-991");
        assert!(SubmitAck::decode(
            br#"{"wire_version":2,"operation_id":"foreign","request_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider_job_id":"pv-991"}"#,
            "op-24-slice-a",
            DIGEST_A,
        )
        .is_err());
        let frame = ResultFrame {
            wire_version: 2,
            operation_id: "op-24-slice-a".to_owned(),
            request_sha256: DIGEST_A.to_owned(),
            route_id: "route-research-private".to_owned(),
            disposition: ProviderResultDisposition::CompletedCandidateAvailable,
            candidate_sha256: DIGEST_A.to_owned(),
            source_handles: vec!["source-a".to_owned()],
            provenance_handles: vec!["evidence-a".to_owned()],
            coverage_denominator: CoverageDenominator::Sampled,
            coverage_gaps: vec!["provider sample is not a complete scope".to_owned()],
            usage_units: 2,
        };
        let line = serde_json::to_vec(&frame).expect("frame");
        assert_eq!(
            ResultFrame::decode(&line, "op-24-slice-a", DIGEST_A, "route-research-private")
                .expect("frame"),
            frame
        );
    }

    #[test]
    fn result_scan_does_not_ignore_a_malformed_result_claim() {
        let stdout = br#"{"wire_version":2,"disposition":"completed_candidate_available","candidate_sha256":"bad"}"#;
        assert!(
            scan_result_frame(stdout, "op-24-slice-a", DIGEST_A, "route-research-private").is_err()
        );
    }
}
