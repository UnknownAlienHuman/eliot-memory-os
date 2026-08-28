//! Opaque typed platform identities and nonce value contracts.
//!
//! These values remain inert: generation, lifecycle, and authority belong to
//! their owning platform or control-plane boundaries.
//!
//! Normative anchors (verified):
//! - `docs/normative/ELIOT_ARCHITECTURE.md:A12.2` binds identity at the
//!   harness/installation boundary to Session, `WorkScope`, capabilities,
//!   visibility, and Authority Epoch.
//! - `docs/normative/ELIOT_IMPLEMENTATION.md:I1.8` assigns Kernel verification
//!   of identity, authority, State Fence, idempotency, ordering, and runtime
//!   generation.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::{PortError, validate_text};

/// A validated opaque provider/resource handle.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct PlatformHandle(String);

impl PlatformHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        validate_text(&value, "handle")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque nonce that binds one live Host process to its installation epoch.
///
/// This type is deliberately distinct from [`KernelActivationNonce`]. Neither
/// nonce type implements a conversion into the other, and their formatting is
/// always redacted so process credentials cannot leak through diagnostics.
#[derive(Clone, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[schemars(with = "String")]
pub struct HostProcessNonce(PlatformHandle);

impl HostProcessNonce {
    pub const fn new(value: PlatformHandle) -> Self {
        Self(value)
    }

    pub fn as_handle(&self) -> &PlatformHandle {
        &self.0
    }

    pub fn into_handle(self) -> PlatformHandle {
        self.0
    }
}

impl fmt::Debug for HostProcessNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostProcessNonce(<redacted>)")
    }
}

impl fmt::Display for HostProcessNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// One-use 256-bit permit for an exact Kernel activation transition.
///
/// The value is represented as exactly 64 hexadecimal characters so malformed
/// or truncated permits cannot enter the durable Host journal through typed
/// APIs. Entropy and generation remain the responsibility of the OS adapter.
#[derive(Clone, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
#[schemars(with = "String")]
pub struct KernelActivationNonce(PlatformHandle);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NonceContractError {
    #[error(
        "Kernel activation nonce must be exactly 256 bits encoded as 64 hexadecimal characters"
    )]
    InvalidKernelActivationNonce,
}

impl KernelActivationNonce {
    pub fn new(value: PlatformHandle) -> Result<Self, NonceContractError> {
        let text = value.as_str();
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(NonceContractError::InvalidKernelActivationNonce);
        }
        Ok(Self(value))
    }

    pub fn as_handle(&self) -> &PlatformHandle {
        &self.0
    }

    pub fn into_handle(self) -> PlatformHandle {
        self.0
    }
}

impl fmt::Debug for KernelActivationNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KernelActivationNonce(<redacted>)")
    }
}

impl fmt::Display for KernelActivationNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for KernelActivationNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KernelActivationNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = PlatformHandle::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PlatformHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
