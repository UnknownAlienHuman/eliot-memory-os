//! C6 route-aware token measurement for I7.24 tool-result receipts.
//!
//! The bridge runs no tokenizer: no tokenizer implementation exists on the
//! delivery path, the invocation response carries correlation and disposition
//! only (no usage source), and I0.4 forbids assuming STU equivalence while
//! I10.15 states that missing usage is `unknown`, never zero. The only
//! admissible token evidence is therefore a route-owner observation — the
//! route's actual tokenizer reporting a count over the exact delivered bytes.
//!
//! [`measure_tool_result_tokens`] binds such an observation by digest equality
//! before the count may enter a [`crate::ToolResultReceipt`]. A missing
//! observation, a digest mismatch, or an invalid tokenizer identity withholds
//! projection via [`crate::BridgeError::UnmeasuredTokens`]; the bridge never
//! estimates, substitutes byte/STU heuristics, or defaults a count. Route
//! identity reuses the shared [`crate::RouteFingerprint`] contract; tokenizer
//! identity follows the documented `tokenizer_id` / `tokenizer_version` /
//! `tokenizer_hash` observation vocabulary without converting to or from any
//! other crate's measurement type.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BridgeError, RouteFingerprint, validate_text};

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), BridgeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BridgeError::InvalidContract {
            field,
            reason: "must be a lowercase SHA-256 hex digest",
        });
    }
    Ok(())
}

/// Identity of the actual tokenizer a route ran, bound to that route.
///
/// `tokenizer_id` / `tokenizer_version` name the exact tokenizer build the
/// route owner ran; `tokenizer_hash` is the lowercase SHA-256 hex of the
/// tokenizer artifact or version manifest the owner attests. A route name,
/// model label, or provider string alone never identifies a tokenizer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTokenizer {
    route: RouteFingerprint,
    tokenizer_id: String,
    tokenizer_version: String,
    tokenizer_hash: String,
}

impl RouteTokenizer {
    /// Validates the route fingerprint, tokenizer names, and artifact digest.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] when the route fingerprint is
    /// invalid, a name is blank or carries control characters, or the artifact
    /// digest is not lowercase SHA-256 hex.
    pub fn new(
        route: RouteFingerprint,
        tokenizer_id: String,
        tokenizer_version: String,
        tokenizer_hash: String,
    ) -> Result<Self, BridgeError> {
        let tokenizer = Self {
            route,
            tokenizer_id,
            tokenizer_version,
            tokenizer_hash,
        };
        tokenizer.validate()?;
        Ok(tokenizer)
    }

    /// Validates every identity field without running any tokenizer.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] on the first invalid field.
    pub fn validate(&self) -> Result<(), BridgeError> {
        self.route
            .validate()
            .map_err(|_| BridgeError::InvalidContract {
                field: "route_tokens.route",
                reason: "route fingerprint invalid",
            })?;
        validate_text(&self.tokenizer_id, "route_tokens.tokenizer_id")?;
        validate_text(&self.tokenizer_version, "route_tokens.tokenizer_version")?;
        validate_digest(&self.tokenizer_hash, "route_tokens.tokenizer_hash")?;
        Ok(())
    }

    /// The documented route this tokenizer ran on.
    #[must_use]
    pub const fn route(&self) -> &RouteFingerprint {
        &self.route
    }

    /// Exact tokenizer build identity stated by the route owner.
    #[must_use]
    pub fn tokenizer_id(&self) -> &str {
        &self.tokenizer_id
    }

    /// Exact tokenizer version stated by the route owner.
    #[must_use]
    pub fn tokenizer_version(&self) -> &str {
        &self.tokenizer_version
    }

    /// Lowercase SHA-256 hex of the attested tokenizer artifact or manifest.
    #[must_use]
    pub fn tokenizer_hash(&self) -> &str {
        &self.tokenizer_hash
    }
}

/// Route-owner token observation bound to one exact byte string.
///
/// `result_digest` is the lowercase SHA-256 hex over the exact delivered
/// bytes the count was reported for; `tokens` is the count the route's actual
/// tokenizer reported. The bridge never reinterprets the count: measurement
/// accepts it only when the digest names the bytes being receipted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTokenObservation {
    tokenizer: RouteTokenizer,
    result_digest: String,
    tokens: u64,
}

impl RouteTokenObservation {
    /// Validates the tokenizer identity and digest shape.
    ///
    /// Digest-to-bytes binding happens in [`measure_tool_result_tokens`],
    /// not here: an observation is only evidence for the bytes it names.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] on the first invalid field.
    pub fn new(
        tokenizer: RouteTokenizer,
        result_digest: String,
        tokens: u64,
    ) -> Result<Self, BridgeError> {
        let observation = Self {
            tokenizer,
            result_digest,
            tokens,
        };
        observation.validate()?;
        Ok(observation)
    }

    /// Validates the tokenizer identity and digest shape.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] on the first invalid field.
    pub fn validate(&self) -> Result<(), BridgeError> {
        self.tokenizer.validate()?;
        validate_digest(&self.result_digest, "route_tokens.result_digest")?;
        Ok(())
    }

    /// The tokenizer identity this count is attributed to.
    #[must_use]
    pub const fn tokenizer(&self) -> &RouteTokenizer {
        &self.tokenizer
    }

    /// Lowercase SHA-256 hex of the exact bytes the count was reported for.
    #[must_use]
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    /// Owner-reported token count. A measured zero is a measurement, not an
    /// unknown; unknowns never reach this type (see [`UnmeasuredReason`]).
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }
}

/// Why a tool result carries no measured token cost.
///
/// Every variant withholds receipt projection: missing evidence denies the
/// receipt instead of estimating a count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnmeasuredReason {
    /// The route owner supplied no token observation for the result.
    NoObservation,
    /// The observation names different bytes, so its count must not be
    /// attributed to this result.
    DigestMismatch,
}

impl fmt::Display for UnmeasuredReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::NoObservation => "no route-owner token observation supplied",
            Self::DigestMismatch => "token observation digest does not match delivered bytes",
        };
        formatter.write_str(reason)
    }
}

/// Digest-bound token cost measured under the route's actual tokenizer.
///
/// Values exist only when [`measure_tool_result_tokens`] verified the
/// observation against the exact delivered bytes, so a receipt citing them
/// repeats owner-observed evidence instead of a bridge estimate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredTokens {
    tokens: u64,
    tokenizer_id: String,
    tokenizer_version: String,
    tokenizer_hash: String,
    result_digest: String,
}

impl MeasuredTokens {
    /// Token count the route's actual tokenizer reported for the receipted bytes.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Tokenizer build the count is attributed to.
    #[must_use]
    pub fn tokenizer_id(&self) -> &str {
        &self.tokenizer_id
    }

    /// Tokenizer version the count is attributed to.
    #[must_use]
    pub fn tokenizer_version(&self) -> &str {
        &self.tokenizer_version
    }

    /// Lowercase SHA-256 hex of the attested tokenizer artifact or manifest.
    #[must_use]
    pub fn tokenizer_hash(&self) -> &str {
        &self.tokenizer_hash
    }

    /// Lowercase SHA-256 hex of the exact delivered bytes that were measured.
    #[must_use]
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }
}

/// Binds a route-owner token observation to the exact delivered bytes.
///
/// A `None` observation withholds with [`UnmeasuredReason::NoObservation`];
/// an observation whose digest does not equal the SHA-256 of `result_bytes`
/// withholds with [`UnmeasuredReason::DigestMismatch`]. Only a validated
/// observation naming exactly these bytes yields [`MeasuredTokens`].
///
/// # Errors
///
/// Returns [`BridgeError::UnmeasuredTokens`] when no usable observation
/// exists, or [`BridgeError::InvalidContract`] when the supplied observation
/// itself is malformed.
pub fn measure_tool_result_tokens(
    result_bytes: &[u8],
    observation: Option<&RouteTokenObservation>,
) -> Result<MeasuredTokens, BridgeError> {
    let observation = observation.ok_or(BridgeError::UnmeasuredTokens {
        reason: UnmeasuredReason::NoObservation,
    })?;
    observation.validate()?;
    let actual_digest = sha256_hex(result_bytes);
    if actual_digest != observation.result_digest {
        return Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::DigestMismatch,
        });
    }
    let tokenizer = observation.tokenizer();
    Ok(MeasuredTokens {
        tokens: observation.tokens(),
        tokenizer_id: tokenizer.tokenizer_id().to_owned(),
        tokenizer_version: tokenizer.tokenizer_version().to_owned(),
        tokenizer_hash: tokenizer.tokenizer_hash().to_owned(),
        result_digest: actual_digest,
    })
}
