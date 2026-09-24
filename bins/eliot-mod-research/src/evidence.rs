//! Immutable raw provider evidence materializer.
//!
//! Provider stdout/stderr/exit/process lineage are preserved as content
//! digests plus bounded byte counts, or as explicit reversible omission
//! handles. `stderr` is never discarded: on provider failure the diagnostic
//! stream, its truncation/omission disposition, and the process lineage are
//! retained in the evidence record. Full bytes stay with the executor capture;
//! this record carries exact digests so the Governor-owned Blob path can bind
//! the raw artifacts without trusting a claim about them.

use eliot_process::{ExitDisposition, ExitStatus};
use eliot_process_executor::CapturedStream;
use sha2::{Digest, Sha256};

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
