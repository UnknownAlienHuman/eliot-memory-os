//! Immutable raw provider evidence materializer.
//!
//! Provider stdout/stderr/exit/process lineage are preserved as content
//! digests plus bounded byte counts, or as explicit reversible omission
//! handles. `stderr` is never discarded: on provider failure the diagnostic
//! stream, its truncation/omission disposition, and the process lineage are
//! retained in the evidence record. Full bytes stay with the executor capture;
//! this record carries exact digests so the Governor-owned Blob path can bind
//! the raw artifacts without trusting a claim about them.

use eliot_contracts::{ContractVersion, EpochId, StateFence};
use eliot_process::{
    CancellationReceipt, ExitDisposition, ExitStatus, ProcessEvidence, ProcessStartReceipt,
};
use eliot_process_executor::CapturedStream;
use eliot_research_exchange_api::DisclosureClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::execution::ProviderOutcome;
use crate::protocol::{CoverageDenominator, ProviderResultDisposition};

/// Length of a lowercase SHA-256 hex digest.
pub const SHA256_HEX_LEN: usize = 64;

/// Computes the lowercase SHA-256 hex digest of exact bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Why a captured stream is absent or incomplete. Omission is typed and
/// reversible (the variant names what is missing); it never poses as data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamOmission {
    /// The executor supplied no stream handle.
    NoHandle,
    /// EOF was not observed; the retained prefix is partial.
    IncompleteCapture,
    /// Bytes beyond the capture ceiling were observed and dropped.
    TruncatedAtCeiling,
}

/// Immutable record of one captured provider stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRecord {
    /// SHA-256 of the retained prefix bytes.
    pub sha256: String,
    /// Total bytes drained, including bytes not retained.
    pub total_bytes: u64,
    /// Whether the retained prefix is the complete stream.
    pub complete: bool,
    /// Omission disposition when the stream is not complete evidence.
    pub omission: Option<StreamOmission>,
}

impl StreamRecord {
    /// Records one executor-captured stream without dropping information:
    /// a missing handle, an incomplete capture, or a truncation all surface
    /// as explicit omission, never as silent absence.
    #[must_use]
    pub fn capture(stream: &CapturedStream) -> Self {
        let omission = if !stream.captured {
            Some(StreamOmission::NoHandle)
        } else if !stream.complete {
            Some(StreamOmission::IncompleteCapture)
        } else if stream.truncated {
            Some(StreamOmission::TruncatedAtCeiling)
        } else {
            None
        };
        Self {
            sha256: sha256_hex(&stream.bytes),
            total_bytes: stream.total_bytes,
            complete: omission.is_none(),
            omission,
        }
    }
}

/// Immutable raw evidence for one bounded provider execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProviderEvidence {
    /// Stable admitted operation identity.
    pub operation_id: String,
    /// Sealed process-request digest the execution ran under.
    pub invocation_digest: String,
    /// Immutable stdout record (never discarded, even on failure).
    pub stdout: StreamRecord,
    /// Immutable stderr record (never discarded, even on failure).
    pub stderr: StreamRecord,
    /// Physical exit disposition (never a semantic verdict).
    pub exit_disposition: ExitDisposition,
    /// Whether an actual exit observation was received.
    pub exit_observed: bool,
    /// Exact numeric exit code for completed exits; `None` otherwise (a
    /// non-completed exit has no meaningful code and none is fabricated).
    pub exit_code: Option<i32>,
    /// Whether exact descendant/tree-termination evidence was observed.
    pub descendants_complete: bool,
    /// Durable stdout locator when the shared executor supplied one.
    pub stdout_evidence_ref: Option<String>,
    /// Durable stderr locator when the shared executor supplied one.
    pub stderr_evidence_ref: Option<String>,
    /// Durable process-lineage/cleanup handle when observed.
    pub lineage_evidence_ref: Option<String>,
}

impl RawProviderEvidence {
    /// Materializes the immutable evidence record from one terminal
    /// observation. The exit code is recovered only for completed exits,
    /// following the established executor-observation precedent; every other
    /// disposition keeps `exit_code` empty rather than inventing a number.
    #[must_use]
    pub fn materialize(
        operation_id: &str,
        invocation_digest: &str,
        exit: &ExitStatus,
        stdout: &CapturedStream,
        stderr: &CapturedStream,
        descendants_complete: bool,
    ) -> Self {
        let exit_code = match exit.disposition() {
            ExitDisposition::Completed => exit_code_of(exit),
            ExitDisposition::Signalled
            | ExitDisposition::ResourceLimit
            | ExitDisposition::Cancelled
            | ExitDisposition::Unknown => None,
        };
        Self {
            operation_id: operation_id.to_owned(),
            invocation_digest: invocation_digest.to_owned(),
            stdout: StreamRecord::capture(stdout),
            stderr: StreamRecord::capture(stderr),
            exit_disposition: exit.disposition(),
            exit_observed: true,
            exit_code,
            descendants_complete,
            stdout_evidence_ref: None,
            stderr_evidence_ref: None,
            lineage_evidence_ref: None,
        }
    }
}

impl RawProviderEvidence {
    /// Materializes an honest pre-exit/unknown observation. No exit code or
    /// completed exit is fabricated when the process outcome is unconfirmed.
    #[must_use]
    pub fn unknown(
        operation_id: &str,
        invocation_digest: &str,
        stdout: &CapturedStream,
        stderr: &CapturedStream,
    ) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            invocation_digest: invocation_digest.to_owned(),
            stdout: StreamRecord::capture(stdout),
            stderr: StreamRecord::capture(stderr),
            exit_disposition: ExitDisposition::Unknown,
            exit_observed: false,
            exit_code: None,
            descendants_complete: false,
            stdout_evidence_ref: None,
            stderr_evidence_ref: None,
            lineage_evidence_ref: None,
        }
    }

    /// Attaches durable executor handles/omission locators without changing
    /// the raw digests or omission classifications.
    #[must_use]
    pub fn with_evidence_handles(
        mut self,
        stdout: Option<String>,
        stderr: Option<String>,
        lineage: Option<String>,
    ) -> Self {
        if stdout.is_none() && self.stdout.omission.is_none() {
            self.stdout.complete = false;
            self.stdout.omission = Some(StreamOmission::NoHandle);
        }
        if stderr.is_none() && self.stderr.omission.is_none() {
            self.stderr.complete = false;
            self.stderr.omission = Some(StreamOmission::NoHandle);
        }
        self.stdout_evidence_ref = stdout;
        self.stderr_evidence_ref = stderr;
        self.lineage_evidence_ref = lineage;
        self
    }

    /// Attaches a lineage handle observed on a terminal view when no separate
    /// reconciliation record was available.
    #[must_use]
    pub fn with_lineage_handle(mut self, lineage: Option<String>) -> Self {
        if self.lineage_evidence_ref.is_none() {
            self.lineage_evidence_ref = lineage;
        }
        self
    }
}

/// Recovers the exact numeric exit code of a completed exit from the
/// serialized exit observation, following the established
/// `eliot-instrument-runner` precedent: the typed contract exposes only the
/// coarse disposition, so the code is read from the serialized form.
fn exit_code_of(exit: &ExitStatus) -> Option<i32> {
    serde_json::to_value(exit)
        .ok()
        .and_then(|value| value.get("code").and_then(serde_json::Value::as_i64))
        .and_then(|code| i32::try_from(code).ok())
}

/// Cleanup observation retained with every provider attempt receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCleanupReceipt {
    /// Whether the executor observed every descendant.
    pub descendants_complete: bool,
    /// Whether every Job member was terminated/reaped.
    pub tree_terminated: bool,
    /// Durable executor lineage/evidence handle when available.
    pub lineage_evidence_ref: Option<String>,
    /// Whether cleanup is fully proven rather than merely requested.
    pub cleanup_proven: bool,
}

/// Immutable pre-start intent record. It is written before a process request
/// can be issued, so a disconnect during launch still has a durable binding
/// for the later reconciliation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIntentRecord {
    /// Stable admitted operation identity.
    pub operation_id: String,
    /// SHA-256 of the exact provider wire envelope.
    pub wire_sha256: String,
    /// Exact registered artifact/config/protocol/registry identities.
    pub artifact_sha256: String,
    pub config_digest: String,
    pub protocol_digest: String,
    pub registry_evidence_sha256: String,
    pub module_id: String,
    pub module_generation_id: String,
    /// Exact route, privacy, credential and process identity.
    pub route_id: String,
    pub provider_id: String,
    pub bridge_generation: String,
    pub protocol_revision: ContractVersion,
    pub required_schema: String,
    pub disclosure: DisclosureClass,
    pub data_class: String,
    pub credential_binding_id: String,
    pub credential_owner_principal: String,
    pub credential_acting_principal: String,
    pub process_generation: u64,
    pub state_fence: StateFence,
    /// Budget/deadline/cancellation ceilings.
    pub budget_units: u64,
    pub deadline_unix_ms: i64,
    pub cancellation_id: String,
    /// Wall-clock recording time; it is evidence metadata, not authority.
    pub recorded_at_unix_ms: u64,
}

/// Immutable operation-scoped receipt for one provider process attempt.
///
/// This is an evidence/coordination record, not a semantic result or authority
/// grant. It keeps route, privacy, budget/usage, deadline, cancellation,
/// cleanup, and reconciliation dimensions together so a caller cannot report
/// a successful provider exit while losing the operation's effect identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttemptReceipt {
    /// Stable admitted operation identity.
    pub operation_id: String,
    /// Process request invocation digest.
    pub invocation_digest: String,
    /// Sanitized executor error retained when a start/terminal observation
    /// could not be completed; it is never replaced by a clean refusal.
    pub process_error: Option<String>,
    /// Terminal provider/process classification carried by this receipt.
    pub outcome: ProviderOutcome,
    /// Exact executor start receipt, retained when start was proven.
    pub start_receipt: Option<ProcessStartReceipt>,
    /// Exact artifact/config/protocol/registry identity.
    pub artifact_sha256: String,
    pub config_digest: String,
    pub protocol_digest: String,
    pub registry_evidence_sha256: String,
    pub module_id: String,
    pub module_generation_id: String,
    pub provider_id: String,
    pub bridge_generation: String,
    pub protocol_revision: ContractVersion,
    pub required_schema: String,
    pub process_generation: u64,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    /// Exact route and privacy/data binding.
    pub route_id: String,
    pub disclosure: DisclosureClass,
    pub data_class: String,
    pub credential_binding_id: String,
    pub credential_owner_principal: String,
    pub credential_acting_principal: String,
    /// Budget/usage receipt.
    pub budget_units: u64,
    pub usage_units: u64,
    /// Absolute operation deadline and cancellation identity.
    pub deadline_unix_ms: i64,
    pub cancellation_id: String,
    /// SHA-256 of the exact request bytes delivered to the child.
    pub wire_sha256: String,
    /// Raw stream/exit/lineage evidence.
    pub raw_evidence: RawProviderEvidence,
    /// Optional durable typed stream/process evidence returned by reconcile.
    pub reconciliation: Option<ProcessEvidence>,
    /// Cancellation receipt, retained rather than discarded.
    pub cancellation: Option<CancellationReceipt>,
    /// Cleanup/descendant receipt.
    pub cleanup: ProviderCleanupReceipt,
    /// Provider-local correlation reference.
    pub provider_job_ref: Option<String>,
    /// Provider result disposition, if a typed frame was received.
    pub result_disposition: Option<ProviderResultDisposition>,
    /// Exact source handles echoed by the provider.
    pub source_handles: Vec<String>,
    /// Exact provenance/evidence handles echoed by the provider.
    pub provenance_handles: Vec<String>,
    /// Sanitized provider coverage-gap details.
    pub coverage_gaps: Vec<String>,
    /// Coverage denominator reported by the provider, if any.
    pub coverage_denominator: Option<CoverageDenominator>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use eliot_process::{ExitDisposition, ExitStatus};

    use crate::support::DIGEST_A;

    use super::*;

    fn full_stream(bytes: &[u8]) -> CapturedStream {
        CapturedStream {
            bytes: bytes.to_vec(),
            total_bytes: bytes.len() as u64,
            truncated: false,
            complete: true,
            captured: true,
        }
    }

    fn completed(code: i32) -> ExitStatus {
        ExitStatus::new(ExitDisposition::Completed, Some(code), None, 1).expect("exit")
    }

    #[test]
    fn sha256_digest_is_stable_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let digest = sha256_hex(b"stderr diagnostic line");
        assert_eq!(digest.len(), SHA256_HEX_LEN);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn complete_streams_record_exact_digests_without_omission() {
        let record = StreamRecord::capture(&full_stream(b"raw stdout bytes"));
        assert_eq!(record.sha256, sha256_hex(b"raw stdout bytes"));
        assert_eq!(record.total_bytes, 16);
        assert!(record.complete);
        assert_eq!(record.omission, None);
    }

    #[test]
    fn stream_omissions_stay_explicit_and_typed() {
        let missing = StreamRecord::capture(&CapturedStream {
            bytes: Vec::new(),
            total_bytes: 0,
            truncated: false,
            complete: false,
            captured: false,
        });
        assert_eq!(missing.omission, Some(StreamOmission::NoHandle));
        assert!(!missing.complete);

        let partial = StreamRecord::capture(&CapturedStream {
            bytes: b"prefix".to_vec(),
            total_bytes: 6,
            truncated: false,
            complete: false,
            captured: true,
        });
        assert_eq!(partial.omission, Some(StreamOmission::IncompleteCapture));
        // The retained prefix digest is still exact custody of what exists.
        assert_eq!(partial.sha256, sha256_hex(b"prefix"));

        let truncated = StreamRecord::capture(&CapturedStream {
            bytes: b"prefix".to_vec(),
            total_bytes: 600_000,
            truncated: true,
            complete: true,
            captured: true,
        });
        assert_eq!(truncated.omission, Some(StreamOmission::TruncatedAtCeiling));
        assert_eq!(truncated.total_bytes, 600_000);
    }

    #[test]
    fn stderr_is_preserved_on_failure() {
        let crashed = ExitStatus::new(ExitDisposition::Signalled, None, Some(15), 1).expect("exit");
        let evidence = RawProviderEvidence::materialize(
            "op-24-slice-a",
            DIGEST_A,
            &crashed,
            &full_stream(b""),
            &full_stream(b"provider diagnostic: route denied"),
            false,
        );
        // The diagnostic stream survives the crash: digest plus byte count.
        assert_eq!(
            evidence.stderr.sha256,
            sha256_hex(b"provider diagnostic: route denied")
        );
        assert_eq!(evidence.stderr.total_bytes, 33);
        assert_eq!(evidence.stderr.omission, None);
        assert_eq!(evidence.exit_disposition, ExitDisposition::Signalled);
        // A signalled exit has no meaningful numeric code: none is fabricated.
        assert_eq!(evidence.exit_code, None);
        assert!(!evidence.descendants_complete);
    }

    #[test]
    fn completed_exits_recover_the_exact_code() {
        for code in [0, 1, 128] {
            let evidence = RawProviderEvidence::materialize(
                "op-24-slice-a",
                DIGEST_A,
                &completed(code),
                &full_stream(b"out"),
                &full_stream(b""),
                true,
            );
            assert_eq!(evidence.exit_code, Some(code));
            assert!(evidence.descendants_complete);
        }
    }

    #[test]
    fn non_completed_exits_carry_no_code() {
        let cancelled = ExitStatus::new(ExitDisposition::Cancelled, None, None, 1).expect("exit");
        let evidence = RawProviderEvidence::materialize(
            "op-24-slice-a",
            DIGEST_A,
            &cancelled,
            &full_stream(b"out"),
            &full_stream(b"err"),
            true,
        );
        assert_eq!(evidence.exit_disposition, ExitDisposition::Cancelled);
        assert_eq!(evidence.exit_code, None);
    }
}
