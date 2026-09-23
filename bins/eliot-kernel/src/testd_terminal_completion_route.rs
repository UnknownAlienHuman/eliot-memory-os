//! Closed TestD terminal-completion wire on the existing authenticated Kernel
//! session. The request carries only the durable job id and immutable finish
//! receipt digest; owner identity is rehydrated from the TestD store.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_store_api::WriteReceipt;
use eliot_testd_core::{
    TestdOwnerSubmitRequest, TestdOwnerSubmitResponse, TestdPendingVerifierDispatch,
    TestdTerminalCompletionEvidence, TestdVerifierDispatchBinding,
};
use serde::{Deserialize, Serialize};

/// Authenticated operation name used by TestD terminal completion.
pub const OPERATION: &str = "eliot.kernel.testd-terminal-completion";
pub(crate) const WIRE_VERSION: u16 = 1;
pub const OWNER_SUBMIT_OPERATION: &str = eliot_testd_core::TESTD_OWNER_SUBMIT_OPERATION;
pub(crate) const OWNER_PENDING_DISPATCHES_OPERATION: &str =
    "eliot.kernel.testd-owner-pending-dispatches";
pub(crate) const OWNER_BIND_DISPATCH_OPERATION: &str = "eliot.kernel.testd-owner-bind-dispatch";
pub(crate) const OWNER_PENDING_TERMINALS_OPERATION: &str =
    "eliot.kernel.testd-owner-pending-terminals";
pub(crate) const OWNER_ACK_TERMINAL_OPERATION: &str = "eliot.kernel.testd-owner-ack-terminal";
pub(crate) const OWNER_WIRE_VERSION: u16 = eliot_testd_core::TESTD_OWNER_WIRE_VERSION;

pub(crate) type OwnerSubmitRequest = TestdOwnerSubmitRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingDispatchesRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub limit: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerBindDispatchRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub binding: TestdVerifierDispatchBinding,
    pub request_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingTerminalsRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub limit: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerTerminalNotice {
    pub job_id: String,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerAcknowledgeTerminalRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub receipt: WriteReceipt,
    pub request_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingDispatchesResponse {
    pub pending: Vec<TestdPendingVerifierDispatch>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerPendingTerminalsResponse {
    pub evidence: Vec<TestdTerminalCompletionEvidence>,
}

pub(crate) type OwnerSubmitResponse = TestdOwnerSubmitResponse;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerBindDispatchResponse {
    pub job_id: String,
    pub binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerAcknowledgeTerminalResponse {
    pub job_id: String,
    pub receipt: WriteReceipt,
}

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
        receipt: WriteReceipt,
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
