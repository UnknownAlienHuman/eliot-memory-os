//! Immutable raw provider evidence materializer.
//!
//! Provider stdout/stderr/exit/process lineage are preserved as content
//! digests plus bounded byte counts, or as explicit reversible omission
//! handles. `stderr` is never discarded: on provider failure the diagnostic
//! stream, its truncation/omission disposition, and the process lineage are
//! retained in the evidence record. Full bytes stay with the executor capture;
//! this record carries exact digests so the Governor-owned Blob path can bind
//! the raw artifacts without trusting a claim about them.

use eliot_process::{ExitDisposition, ExitStatus, ProcessEvidence, ProcessExecutionView};
use eliot_process_executor::CapturedStream;
use sha2::{Digest, Sha256};

use crate::execution::ProviderOutcome;

/// Length of a lowercase SHA-256 hex digest.
pub const SHA256_HEX_LEN: usize = 64;

/// Computes the lowercase SHA-256 hex digest of exact bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Why a captured stream is absent or incomplete. Omission is typed and
/// reversible (the variant names what is missing); it never poses as data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamOmission {
    /// The executor supplied no stream handle.
    NoHandle,
    /// EOF was not observed; the retained prefix is partial.
    IncompleteCapture,
    /// Bytes beyond the capture ceiling were observed and dropped.
    TruncatedAtCeiling,
}

/// Immutable record of one captured provider stream.
#[derive(Clone, Debug, Eq, PartialEq)]
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

    /// Builds the explicit no-handle record for a stream that was never
    /// captured. The digest is the digest of zero bytes, which is exact and
    /// distinguishable from a captured empty stream only by the omission
    /// disposition.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            sha256: sha256_hex(&[]),
            total_bytes: 0,
            complete: false,
            omission: Some(StreamOmission::NoHandle),
        }
    }
}

/// Immutable raw evidence for one bounded provider execution.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// Exact numeric exit code for completed exits; `None` otherwise (a
    /// non-completed exit has no meaningful code and none is fabricated).
    pub exit_code: Option<i32>,
    /// Whether exact descendant/tree-termination evidence was observed.
    pub descendants_complete: bool,
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
            exit_code,
            descendants_complete,
        }
    }

    /// Builds the explicit absence record for an attempt that never reached
    /// stream readback.
    ///
    /// Absence is never a fabricated empty result: both streams carry the
    /// [`StreamOmission::NoHandle`] disposition, the exit disposition is
    /// `Unknown`, and no numeric code is invented. The receipt therefore
    /// reports "no stream evidence was obtained" instead of "the provider
    /// produced nothing".
    #[must_use]
    pub fn absent(operation_id: &str, invocation_digest: &str) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            invocation_digest: invocation_digest.to_owned(),
            stdout: StreamRecord::absent(),
            stderr: StreamRecord::absent(),
            exit_disposition: ExitDisposition::Unknown,
            exit_code: None,
            descendants_complete: false,
        }
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

/// Deterministic redacted projection of one executor evidence record.
///
/// I7.23 keeps the allowed raw bytes *or* a deterministic redacted
/// representation, with a redaction receipt. This projection retains only
/// identities, digests, byte counts and typed dispositions: provider prose,
/// credentials and payload bodies are never copied into a record that leaves
/// this process, so the projection is deterministic and safe to report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedEvidence {
    /// Schema revision of the retained evidence record.
    pub schema_version: String,
    /// Stable operation identity.
    pub operation_id: String,
    /// Sealed process-request digest the execution ran under.
    pub request_digest: String,
    /// Terminal lifecycle classification.
    pub lifecycle: String,
    /// Physical exit disposition, never a semantic verdict.
    pub exit_disposition: ExitDisposition,
    /// Whether exact descendant/tree-termination evidence was observed.
    pub descendants_complete: bool,
    /// stdout digest retained by the executor.
    pub stdout_sha256: Option<String>,
    /// stderr digest retained by the executor (never discarded).
    pub stderr_sha256: Option<String>,
    /// stdout byte count observed by the executor.
    pub stdout_bytes: Option<u64>,
    /// stderr byte count observed by the executor.
    pub stderr_bytes: Option<u64>,
}

impl RedactedEvidence {
    /// Projects one executor evidence record deterministically.
    #[must_use]
    pub fn from_evidence(evidence: &ProcessEvidence) -> Self {
        let view = evidence.view();
        let stream = |stream: Option<&eliot_process::ProcessStreamEvidence>| {
            stream.map(|stream| (stream.observed_sha256().to_owned(), stream.observed_bytes()))
        };
        let (stdout_sha256, stdout_bytes) = stream(evidence.stdout()).unzip();
        let (stderr_sha256, stderr_bytes) = stream(evidence.stderr()).unzip();
        Self {
            schema_version: evidence.schema_version().to_owned(),
            operation_id: evidence.operation_id().as_str().to_owned(),
            request_digest: evidence.request_digest().to_owned(),
            lifecycle: format!("{:?}", view.lifecycle()),
            exit_disposition: view.exit().map_or(
                ExitDisposition::Unknown,
                eliot_process::ExitStatus::disposition,
            ),
            descendants_complete: view
                .descendants()
                .is_some_and(|descendants| descendants.complete() && descendants.tree_terminated()),
            stdout_sha256,
            stderr_sha256,
            stdout_bytes,
            stderr_bytes,
        }
    }
}

/// Receipt naming exactly what the redaction withheld and why.
///
/// A redaction without a receipt is indistinguishable from data loss, so this
/// record states the withheld class explicitly. It is deterministic: the same
/// evidence always produces the same receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactionReceipt {
    /// Transport hash of the exact evidence bytes this projection covers.
    pub transport_sha256: String,
    /// Classes deliberately withheld from the retained projection.
    pub withheld: Vec<String>,
    /// Retention contract the projection was written under.
    pub retention: String,
}

impl RedactionReceipt {
    /// Builds the receipt for one redacted projection.
    #[must_use]
    pub fn for_evidence(redacted: &RedactedEvidence, transport_sha256: &str) -> Self {
        let mut withheld = vec![
            "provider stdout body".to_owned(),
            "provider stderr body".to_owned(),
        ];
        if redacted.stdout_sha256.is_none() {
            withheld.push("stdout digest (stream absent)".to_owned());
        }
        if redacted.stderr_sha256.is_none() {
            withheld.push("stderr digest (stream absent)".to_owned());
        }
        Self {
            transport_sha256: transport_sha256.to_owned(),
            withheld,
            retention: "governed-by-caller".to_owned(),
        }
    }
}

/// One retained executor evidence record: exact transport hash, deterministic
/// redacted projection, redaction receipt, and the typed terminal view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEvidenceRecord {
    /// Stable operation identity this record settles.
    pub operation_id: String,
    /// Sealed process-request digest the execution ran under.
    pub request_digest: String,
    /// SHA-256 over the exact canonical evidence bytes.
    pub transport_sha256: String,
    /// Deterministic redacted projection of those bytes.
    pub redacted: RedactedEvidence,
    /// Receipt naming what the projection withheld.
    pub redaction: RedactionReceipt,
    /// Typed terminal view, retained verbatim for process-tree cleanup proof.
    pub view: ProcessExecutionView,
}

/// One immutable receipt of a whole bounded research-provider execution.
///
/// This is the terminal evidence object A3 requires: deadline, cancellation,
/// process-tree cleanup, raw evidence, route, usage, privacy and provider
/// outcome are all bound here, and every field is either an exact identity, a
/// digest, a typed disposition, or an explicit omission handle. The receipt
/// records custody; it never records a verdict, an admission, or a finish.
#[derive(Clone, Debug)]
pub struct ProviderExecutionReceipt {
    /// Stable admitted operation identity.
    pub operation_id: String,
    /// Cancellation identity bound to that operation.
    pub cancellation_id: String,
    /// Kernel-admitted exchange identity.
    pub exchange_id: String,
    /// Kernel-admitted idempotency key.
    pub idempotency_key: String,
    /// Canonical digest of the exact admitted dispatch the Kernel sealed.
    pub dispatch_sha256: String,
    /// Digest of that admission's sealed Kernel receipt.
    pub admission_receipt_sha256: String,
    /// Admitted provider executable content digest.
    pub executable_sha256: String,
    /// Admitted provider module generation reference.
    pub module_generation_id: String,
    /// Admitted process generation.
    pub process_generation: u64,
    /// Admitted privacy/data class wire name (no silent widening).
    pub disclosure: String,
    /// Admitted budget ceiling in provider units.
    pub budget_units: u64,
    /// Admitted deadline ceiling in milliseconds.
    pub deadline_ms: i64,
    /// Digest of the frozen Researcher inquiry.
    pub inquiry_digest: String,
    /// Digest of the admitted source portfolio / coverage denominator.
    pub denominator_digest: String,
    /// Canonical submit wire bytes retained as the exact reconciliation record.
    pub submit_envelope_sha256: String,
    /// Bounded submit-binding digest projected into the admitted argv.
    pub submit_binding_sha256: String,
    /// Typed terminal provider outcome, or the typed failure that ended the
    /// attempt when execution did not complete.
    pub outcome: ProviderOutcome,
    /// Exact I7.20 reason code for this terminal disposition.
    pub reason_code: &'static str,
    /// Immutable raw provider evidence (stdout/stderr/exit/lineage digests).
    pub raw: RawProviderEvidence,
    /// Cancellation receipt, retained when cancellation was actually issued.
    pub cancellation: Option<CancellationEvidence>,
    /// Retained executor evidence records (transport hash + redaction).
    pub evidence_records: Vec<ProviderEvidenceRecord>,
    /// Whether the provider `job_id` is provider-local correlation only.
    pub provider_job_ref: Option<String>,
    /// The candidate result digest the provider reported, when it reported one.
    pub candidate_sha256: Option<String>,
    /// Whether the result is candidate-only and awaits Governor admission.
    pub candidate_only: bool,
}

impl std::fmt::Display for ProviderExecutionReceipt {
    /// Renders the receipt as one bounded, secret-free key/value line.
    ///
    /// Only identities, digests, counts, dispositions and reason codes appear.
    /// No provider prose, no payload body and no credential ever reaches this
    /// projection, and `candidate_only=true` is printed explicitly so a reader
    /// cannot mistake the line for an admitted result.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "operation={} exchange={} cancellation={} dispatch={} admission_receipt={} \
             executable={} module_generation={} process_generation={} disclosure={} \
             budget_units={} deadline_ms={} inquiry={} denominator={} \
             submit_envelope={} submit_binding={} outcome={:?} reason={} \
             stdout_sha256={} stdout_bytes={} stdout_omission={} stderr_sha256={} \
             stderr_bytes={} stderr_omission={} exit={:?} exit_code={} \
             descendants_complete={} cancelled={} cancel_status={} \
             no_effect_proven={} evidence_records={} provider_job_ref={} \
             candidate_sha256={} candidate_only={}",
            self.operation_id,
            self.exchange_id,
            self.cancellation_id,
            self.dispatch_sha256,
            self.admission_receipt_sha256,
            self.executable_sha256,
            self.module_generation_id,
            self.process_generation,
            self.disclosure,
            self.budget_units,
            self.deadline_ms,
            self.inquiry_digest,
            self.denominator_digest,
            self.submit_envelope_sha256,
            self.submit_binding_sha256,
            self.outcome,
            self.reason_code,
            self.raw.stdout.sha256,
            self.raw.stdout.total_bytes,
            omission_name(self.raw.stdout.omission),
            self.raw.stderr.sha256,
            self.raw.stderr.total_bytes,
            omission_name(self.raw.stderr.omission),
            self.raw.exit_disposition,
            self.raw
                .exit_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.raw.descendants_complete,
            self.cancellation.is_some(),
            self.cancellation
                .as_ref()
                .map_or("none", |receipt| receipt.status.as_str()),
            self.cancellation
                .as_ref()
                .is_some_and(|receipt| receipt.no_effect_proven),
            self.evidence_records.len(),
            self.provider_job_ref.as_deref().unwrap_or("none"),
            self.candidate_sha256.as_deref().unwrap_or("none"),
            self.candidate_only,
        )
    }
}

/// Returns the stable wire name of one omission disposition.
fn omission_name(omission: Option<StreamOmission>) -> &'static str {
    match omission {
        None => "none",
        Some(StreamOmission::NoHandle) => "no_handle",
        Some(StreamOmission::IncompleteCapture) => "incomplete_capture",
        Some(StreamOmission::TruncatedAtCeiling) => "truncated_at_ceiling",
    }
}

/// Receipt fragment proving what a cancellation actually did.
///
/// The previous contour discarded the `CancellationReceipt` entirely
/// (`let _ = ...cancel(...)`), which destroyed the only proof that a
/// cancellation was even attempted after a deadline overrun. This fragment
/// retains the exact binding, the reported status, the lifecycle, whether no
/// effect was proven, and the descendant-cleanup evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationEvidence {
    /// Stable operation identity the cancellation targeted.
    pub operation_id: String,
    /// Sealed process-request digest preserved on the receipt.
    pub request_digest: String,
    /// Reported cancellation status.
    pub status: String,
    /// Lifecycle observed at cancellation time.
    pub lifecycle: String,
    /// Whether the executor proved no physical effect.
    pub no_effect_proven: bool,
    /// Whether exact descendant/tree-termination evidence was observed.
    pub descendants_complete: bool,
}

impl CancellationEvidence {
    /// Projects one executor cancellation receipt into the retained fragment.
    #[must_use]
    pub fn from_receipt(receipt: &eliot_process::CancellationReceipt) -> Self {
        Self {
            operation_id: receipt.binding().operation_id().as_str().to_owned(),
            request_digest: receipt.binding().request_digest().to_owned(),
            status: format!("{:?}", receipt.status()),
            lifecycle: format!("{:?}", receipt.lifecycle()),
            no_effect_proven: receipt.no_effect_proven(),
            descendants_complete: receipt
                .descendants()
                .is_some_and(|descendants| descendants.complete() && descendants.tree_terminated()),
        }
    }
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
