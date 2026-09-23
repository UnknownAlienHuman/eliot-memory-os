//! Closed TestD terminal-completion wire on the existing authenticated Kernel
//! session. The request carries only the durable job id and immutable finish
//! receipt digest; owner identity is rehydrated from the TestD store.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_store_api::WriteReceipt;
use serde::{Deserialize, Serialize};

pub(crate) const OPERATION: &str = "eliot.kernel.testd-terminal-completion";
pub(crate) const WIRE_VERSION: u16 = 1;

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
    let request: Request =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
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
