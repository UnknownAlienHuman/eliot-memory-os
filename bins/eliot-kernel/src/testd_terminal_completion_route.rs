//! Closed `TestD` terminal-completion wire on the existing authenticated Kernel
//! session. The request carries only the durable job id and immutable finish
//! receipt digest; owner identity is rehydrated from the `TestD` store.
//!
//! The same owner also serves the productive owner-submit intake
//! (`OWNER_SUBMIT_OPERATION`, `TestD` worker session) and the four daemon
//! owner routes (pending verifier dispatches, verifier-dispatch bind,
//! pending terminal evidence, terminal receipt acknowledgement). The daemon
//! never opens the `TestD` database: every row is read, validated, and
//! committed here from the Kernel-selected owner store.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_store_api::WriteReceipt;
use eliot_testd_core::{
    RetryPolicy, TestdOwnerSubmitRequest, TestdPendingVerifierDispatch,
    TestdTerminalCompletionEvidence, TestdVerifierDispatchBinding,
};
use serde::{Deserialize, Serialize};

use super::dispatch_launch::testd_owner_store_path;
use super::{ACTIVE_DAEMON_CALLER, KernelComposition, Session, TransportError};

/// Authenticated operation name used by `TestD` terminal completion.
pub const OPERATION: &str = "eliot.kernel.testd-terminal-completion";
pub(crate) const WIRE_VERSION: u16 = 1;
/// Authenticated operation name used by the `TestD` productive owner-submit
/// intake (`TestD` worker session).
pub(crate) const OWNER_SUBMIT_OPERATION: &str = eliot_testd_core::TESTD_OWNER_SUBMIT_OPERATION;
/// Authenticated daemon operation: list queued productive jobs that still
/// need their canonical verifier binding.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
pub(crate) const OWNER_PENDING_DISPATCHES_OPERATION: &str =
    "eliot.kernel.testd-owner-pending-dispatches";
/// Authenticated daemon operation: persist one verifier-dispatch binding
/// against the exact admitted identity retained at job admission.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
pub(crate) const OWNER_BIND_DISPATCH_OPERATION: &str = "eliot.kernel.testd-owner-bind-dispatch";
/// Authenticated daemon operation: list terminal productive jobs that still
/// need their canonical verifier-execution `WriteReceipt`.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
pub(crate) const OWNER_PENDING_TERMINALS_OPERATION: &str =
    "eliot.kernel.testd-owner-pending-terminals";
/// Authenticated daemon operation: record one committed canonical
/// `WriteReceipt` against its terminal owner row.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
pub(crate) const OWNER_ACK_TERMINAL_OPERATION: &str = "eliot.kernel.testd-owner-ack-terminal";
/// Wire revision retained by terminal-completion and daemon-side owner routes.
/// Productive owner-submit uses its submit-specific v2 contract.
pub(crate) const OWNER_WIRE_VERSION: u16 = eliot_testd_core::TESTD_OWNER_WIRE_VERSION;

pub(crate) type OwnerSubmitRequest = TestdOwnerSubmitRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub receipt_sha256: String,
    pub request_digest: String,
}

impl Request {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.wire_id != OPERATION || self.wire_version != WIRE_VERSION {
            return Err("unsupported TestD terminal-completion wire".to_owned());
        }
        if self.job_id.trim().is_empty() || self.job_id.chars().any(char::is_control) {
            return Err("invalid TestD terminal job id".to_owned());
        }
        validate_digest(&self.receipt_sha256)?;
        validate_digest(&self.request_digest)?;
        let expected = self.compute_request_digest()?;
        if expected != self.request_digest {
            return Err("TestD terminal-completion request digest mismatch".to_owned());
        }
        Ok(())
    }

    fn compute_request_digest(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            receipt_sha256: &'a str,
        }
        let bytes = canonical_json_bytes(&Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            receipt_sha256: &self.receipt_sha256,
        })
        .map_err(|error| error.to_string())?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Response {
    Pending {
        job_id: String,
        receipt_sha256: String,
        request_digest: String,
    },
    Committed {
        job_id: String,
        receipt_sha256: String,
        request_digest: String,
        receipt: Box<WriteReceipt>,
    },
}

pub(crate) fn request_from_payload(payload: &serde_json::Value) -> Result<Request, String> {
    let value = payload
        .get("request")
        .cloned()
        .ok_or_else(|| "terminal request is absent".to_owned())?;
    let request: Request = serde_json::from_value(value).map_err(|error| error.to_string())?;
    request.validate()?;
    Ok(request)
}

/// Decodes and validates the typed productive owner-submit request carried
/// under the frame `request` field.
pub(crate) fn owner_submit_request_from_payload(
    payload: &serde_json::Value,
) -> Result<OwnerSubmitRequest, String> {
    let value = payload
        .get("request")
        .cloned()
        .ok_or_else(|| "TestD owner-submit request is absent".to_owned())?;
    let request: OwnerSubmitRequest =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    request.validate().map_err(|error| error.to_string())?;
    Ok(request)
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("terminal request digest must be lowercase SHA-256".to_owned());
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
fn validate_owner_wire(wire_id: &str, wire_version: u16, operation: &str) -> Result<(), String> {
    if wire_id != operation || wire_version != OWNER_WIRE_VERSION {
        return Err("unsupported TestD owner wire".to_owned());
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
fn validate_job_id(job_id: &str) -> Result<(), String> {
    if job_id.trim().is_empty() || job_id.chars().any(char::is_control) {
        return Err("invalid TestD owner job id".to_owned());
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
fn validate_limit(limit: u16, field: &'static str) -> Result<usize, String> {
    if limit == 0 || limit > 64 {
        return Err(format!("{field} must be between one and 64"));
    }
    Ok(usize::from(limit))
}

#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

/// Daemon request: bounded pending verifier-dispatch poll. The response
/// carries the full durable job plus the exact admitted frame identity; the
/// daemon computes the canonical plan binding from its Governor read.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingDispatchesRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub limit: u16,
}

impl OwnerPendingDispatchesRequest {
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn validate(&self) -> Result<usize, String> {
        validate_owner_wire(
            &self.wire_id,
            self.wire_version,
            OWNER_PENDING_DISPATCHES_OPERATION,
        )?;
        validate_limit(self.limit, "pending dispatches limit")
    }
}

/// Daemon request: persist one verifier-dispatch binding. The binding must
/// reuse the exact admitted identity the Kernel retained at job admission;
/// the digest binds the wire, job, and binding bytes.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerBindDispatchRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub binding: TestdVerifierDispatchBinding,
    pub request_digest: String,
}

impl OwnerBindDispatchRequest {
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_owner_wire(
            &self.wire_id,
            self.wire_version,
            OWNER_BIND_DISPATCH_OPERATION,
        )?;
        validate_job_id(&self.job_id)?;
        validate_digest(&self.request_digest)?;
        let expected = self.compute_request_digest()?;
        if expected != self.request_digest {
            return Err("TestD bind-dispatch request digest mismatch".to_owned());
        }
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn binding_sha256(&self) -> Result<String, String> {
        let bytes = canonical_json_bytes(&self.binding).map_err(|error| error.to_string())?;
        Ok(sha256_hex(&bytes))
    }

    fn compute_request_digest(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            binding_sha256: &'a str,
        }
        let binding_sha256 = self.binding_sha256()?;
        let bytes = canonical_json_bytes(&Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            binding_sha256: &binding_sha256,
        })
        .map_err(|error| error.to_string())?;
        Ok(sha256_hex(&bytes))
    }
}

/// Daemon request: bounded pending terminal-evidence poll. Each entry is a
/// complete identity-joined productive terminal row still missing its
/// canonical `WriteReceipt`; worker exit alone never appears here.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingTerminalsRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub limit: u16,
}

impl OwnerPendingTerminalsRequest {
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn validate(&self) -> Result<usize, String> {
        validate_owner_wire(
            &self.wire_id,
            self.wire_version,
            OWNER_PENDING_TERMINALS_OPERATION,
        )?;
        validate_limit(self.limit, "pending terminals limit")
    }
}

/// Daemon request: record one committed canonical `WriteReceipt` against its
/// terminal owner row. The receipt must be the exact canonical bytes whose
/// digest the terminal publication advertises; the digest binds the wire,
/// job, and receipt bytes.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerAcknowledgeTerminalRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub receipt: WriteReceipt,
    pub request_digest: String,
}

impl OwnerAcknowledgeTerminalRequest {
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_owner_wire(
            &self.wire_id,
            self.wire_version,
            OWNER_ACK_TERMINAL_OPERATION,
        )?;
        validate_job_id(&self.job_id)?;
        self.receipt.validate().map_err(|error| error.to_string())?;
        validate_digest(&self.request_digest)?;
        let expected = self.compute_request_digest()?;
        if expected != self.request_digest {
            return Err("TestD ack-terminal request digest mismatch".to_owned());
        }
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn receipt_sha256(&self) -> Result<String, String> {
        let bytes = canonical_json_bytes(&self.receipt).map_err(|error| error.to_string())?;
        Ok(sha256_hex(&bytes))
    }

    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn receipt_json(&self) -> Result<String, String> {
        let bytes = canonical_json_bytes(&self.receipt).map_err(|error| error.to_string())?;
        String::from_utf8(bytes).map_err(|error| error.to_string())
    }

    fn compute_request_digest(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            receipt_sha256: &'a str,
        }
        let receipt_sha256 = self.receipt_sha256()?;
        let bytes = canonical_json_bytes(&Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            receipt_sha256: &receipt_sha256,
        })
        .map_err(|error| error.to_string())?;
        Ok(sha256_hex(&bytes))
    }
}

/// Daemon response: bounded identity-joined pending verifier dispatches.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingDispatchesResponse {
    pub pending: Vec<TestdPendingVerifierDispatch>,
}

/// Daemon response: persisted verifier-dispatch binding receipt.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerBindDispatchResponse {
    pub job_id: String,
    pub binding_sha256: String,
}

/// Daemon response: bounded identity-joined terminal evidence rows.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingTerminalsResponse {
    pub evidence: Vec<TestdTerminalCompletionEvidence>,
}

/// Daemon response: recorded terminal receipt.
#[allow(
    dead_code,
    reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerAcknowledgeTerminalResponse {
    pub job_id: String,
    pub receipt: WriteReceipt,
}

impl KernelComposition {
    /// Opens the single Kernel-selected `TestD` owner store. Paths are never
    /// taken from the caller; the daemon cannot substitute its own database.
    fn testd_owner_store(&self) -> Result<eliot_testd_core::TestdStore, TransportError> {
        eliot_testd_core::TestdStore::open(
            testd_owner_store_path(&self.work_root),
            RetryPolicy::default(),
        )
        .map_err(|_| TransportError::SessionFenced)
    }

    fn require_daemon_session(session: &Session) -> Result<(), TransportError> {
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Serves one authenticated daemon pending-dispatch poll from the
    /// Kernel-owned `TestD` store.
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn testd_owner_pending_dispatches_operation(
        &self,
        session: &Session,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        Self::require_daemon_session(session)?;
        let request: OwnerPendingDispatchesRequest = serde_json::from_value(
            payload
                .get("request")
                .cloned()
                .ok_or(TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let limit = request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let store = self.testd_owner_store()?;
        let pending = store
            .pending_verifier_dispatches(limit)
            .map_err(|_| TransportError::SessionFenced)?;
        let value = serde_json::to_value(OwnerPendingDispatchesResponse { pending })
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({ "kind": "testd_owner_pending_dispatches", "value": value }))
    }

    /// Persists one daemon-computed verifier-dispatch binding against the
    /// exact admitted identity retained at job admission.
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn testd_owner_bind_dispatch_operation(
        &self,
        session: &Session,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        Self::require_daemon_session(session)?;
        let request: OwnerBindDispatchRequest = serde_json::from_value(
            payload
                .get("request")
                .cloned()
                .ok_or(TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = now_ms();
        if now == 0 {
            return Err(TransportError::SessionFenced);
        }
        let binding_sha256 = request
            .binding_sha256()
            .map_err(|_| TransportError::SessionFenced)?;
        let store = self.testd_owner_store()?;
        let job = store
            .bind_verifier_dispatch_for_admitted_identity(&request.job_id, request.binding, now)
            .map_err(|_| TransportError::SessionFenced)?;
        let value = serde_json::to_value(OwnerBindDispatchResponse {
            job_id: job.job_id,
            binding_sha256,
        })
        .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({ "kind": "testd_owner_bind_dispatch", "value": value }))
    }

    /// Serves one authenticated daemon pending-terminal poll from the
    /// Kernel-owned `TestD` store. Only complete identity-joined terminal
    /// rows are returned; worker exit alone never qualifies.
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn testd_owner_pending_terminals_operation(
        &self,
        session: &Session,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        Self::require_daemon_session(session)?;
        let request: OwnerPendingTerminalsRequest = serde_json::from_value(
            payload
                .get("request")
                .cloned()
                .ok_or(TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let limit = request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let store = self.testd_owner_store()?;
        let evidence = store
            .pending_terminal_completion_evidence(limit)
            .map_err(|_| TransportError::SessionFenced)?;
        let value = serde_json::to_value(OwnerPendingTerminalsResponse { evidence })
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({ "kind": "testd_owner_pending_terminals", "value": value }))
    }

    /// Records one committed canonical `WriteReceipt` against its terminal
    /// owner row. The receipt must be the exact canonical bytes advertised
    /// by the terminal publication; anything else fails closed.
    #[allow(
        dead_code,
        reason = "wired by the MGR-A daemon dispatch arms (REPORT-325)"
    )]
    pub(crate) fn testd_owner_ack_terminal_operation(
        &self,
        session: &Session,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        Self::require_daemon_session(session)?;
        let request: OwnerAcknowledgeTerminalRequest = serde_json::from_value(
            payload
                .get("request")
                .cloned()
                .ok_or(TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = now_ms();
        if now == 0 {
            return Err(TransportError::SessionFenced);
        }
        let receipt_sha256 = request
            .receipt_sha256()
            .map_err(|_| TransportError::SessionFenced)?;
        let receipt_json = request
            .receipt_json()
            .map_err(|_| TransportError::SessionFenced)?;
        let store = self.testd_owner_store()?;
        let job = store
            .record_terminal_publication_receipt(
                &request.job_id,
                &receipt_sha256,
                receipt_json,
                now,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        let committed = job
            .terminal_publication
            .as_ref()
            .and_then(|publication| publication.committed_receipt_json.as_ref())
            .ok_or(TransportError::SessionFenced)?;
        let receipt: WriteReceipt =
            serde_json::from_str(committed).map_err(|_| TransportError::SessionFenced)?;
        let value = serde_json::to_value(OwnerAcknowledgeTerminalResponse {
            job_id: job.job_id,
            receipt,
        })
        .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({ "kind": "testd_owner_ack_terminal", "value": value }))
    }
}
