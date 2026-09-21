//! C6 route-aware token measurement for I7.24 tool-result receipts.
//!
//! The bridge runs no tokenizer: no tokenizer implementation exists on the
//! delivery path, the invocation response carries correlation and disposition
//! only (no usage source), and I0.4 forbids assuming STU equivalence while
//! I10.15 states that missing usage is `unknown`, never zero. Token evidence
//! therefore arrives only through the documented route-observation channel:
//! a [`PhysicalRouteObservationReceipt`] built by the route adapter carrying
//! the route's own [`UsageReceipt`], admission-linked and self-digest-bound
//! by the canonical contract.
//!
//! [`produce_route_token_observation`] is the live route-owner observation
//! producer. It verifies the observation end to end — shape plus recomputed
//! self digest, linkage against the explicitly supplied current admission
//! and execution binding (never trusted from the receipt alone), a matched
//! observed route, digest-bound evidence bytes, and a reported output count
//! — and only then yields a digest-bound [`RouteTokenObservation`]. Anything
//! else withholds with [`UnmeasuredReason`]; the bridge never estimates,
//! substitutes byte/STU heuristics or input/cost/quota figures, sums usage
//! fields, or defaults a count.
//!
//! Route identity reuses the shared [`crate::RouteFingerprint`] contract.
//! Tokenizer provenance is the validated observed route itself: the tree
//! attests no standalone tokenizer builds or model-to-tokenizer registry,
//! so none are named here and no tokenizer name, version, or hash is ever
//! accepted, defaulted, or synthesized. Source/version attestation for
//! installed material stays with the Skill transport feed (B2 owner); this
//! module claims no versions. There are no conversions to or from any other
//! crate's measurement type.

use eliot_agent_api::{
    AdmittedRouteReceipt, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
    RouteObservationState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BridgeError, RouteFingerprint};

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

/// Identity of the actual tokenizer that ran a measured count: the validated
/// observed route itself.
///
/// `provider`, `model`, and the behavior-bearing hashes of the route
/// fingerprint name the route whose tokenizer ran. No standalone tokenizer
/// build, version string, or artifact hash is recorded because no documented
/// source attests one; inventing a tokenizer name would fabricate provenance
/// the tree cannot verify.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTokenizer {
    route: RouteFingerprint,
}

impl RouteTokenizer {
    /// Validates the observed route identity.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] when the route fingerprint
    /// is invalid.
    pub fn new(route: RouteFingerprint) -> Result<Self, BridgeError> {
        let tokenizer = Self { route };
        tokenizer.validate()?;
        Ok(tokenizer)
    }

    /// Validates the route identity without running any tokenizer.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] when the route fingerprint
    /// is invalid.
    pub fn validate(&self) -> Result<(), BridgeError> {
        self.route
            .validate()
            .map_err(|_| BridgeError::InvalidContract {
                field: "route_tokens.route",
                reason: "route fingerprint invalid",
            })?;
        Ok(())
    }

    /// The documented observed route whose actual tokenizer ran the count.
    #[must_use]
    pub const fn route(&self) -> &RouteFingerprint {
        &self.route
    }
}

/// Route-owner token observation bound to one exact byte string.
///
/// `result_digest` is the lowercase SHA-256 hex over the exact delivered
/// bytes the count was reported for; `tokens` is the count the route's
/// actual tokenizer reported. Values produced by
/// [`produce_route_token_observation`] carry a fully verified provenance
/// (admission-linked matched route plus digest-bound bytes); directly
/// constructed values carry their constructor's attestation and must only
/// enter the receipt path with the same verified evidence behind them.
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
/// Every variant withholds receipt projection: missing or inapplicable
/// evidence denies the receipt instead of estimating a count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnmeasuredReason {
    /// The route owner supplied no token observation for the result.
    NoObservation,
    /// The observation names different bytes, so its count must not be
    /// attributed to this result. A missing evidence binding withholds the
    /// same way: unattributed counts never enter a receipt.
    DigestMismatch,
    /// The observation is not linked to the supplied current admission and
    /// execution binding, so it is not evidence for this delivery.
    AdmissionMismatch,
    /// The observed route diverged from the admitted route, so the count
    /// cannot be attributed to the route that ran.
    RouteDiverged,
    /// The route was not observed (or no observed route is recorded), so
    /// there is no route to attribute a count to.
    RouteUnobserved,
    /// The route observation reports no output count: the route supports no
    /// measurement on this delivery. Unknown stays unknown — input, cost,
    /// and quota figures are never substituted.
    UsageUnknown,
}

impl std::fmt::Display for UnmeasuredReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::NoObservation => "no route-owner token observation supplied",
            Self::DigestMismatch => "token observation evidence does not match delivered bytes",
            Self::AdmissionMismatch => "token observation is not linked to the current admission",
            Self::RouteDiverged => "observed route diverged from the admitted route",
            Self::RouteUnobserved => "route was not observed",
            Self::UsageUnknown => "route observation reports no output count",
        };
        formatter.write_str(reason)
    }
}

/// Digest-bound token cost measured under the route's actual tokenizer.
///
/// Values exist only when [`measure_tool_result_tokens`] or
/// [`produce_route_token_observation`] verified the observation against the
/// exact delivered bytes, so a receipt citing them repeats owner-observed
/// evidence instead of a bridge estimate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredTokens {
    tokens: u64,
    route: RouteFingerprint,
    result_digest: String,
}

impl MeasuredTokens {
    /// Token count the route's actual tokenizer reported for the receipted bytes.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Validated observed route whose tokenizer ran the count.
    #[must_use]
    pub const fn route(&self) -> &RouteFingerprint {
        &self.route
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
    Ok(MeasuredTokens {
        tokens: observation.tokens(),
        route: observation.tokenizer().route().clone(),
        result_digest: actual_digest,
    })
}

/// Produces a digest-bound token observation from a live route observation.
///
/// The live route-owner observation producer: every field of the yielded
/// observation is sourced from verified route evidence, never from caller
/// counts or invented tokenizer names —
/// * the observation receipt must be well-formed with a recomputed self
///   digest, else [`BridgeError::InvalidContract`];
/// * the receipt must link against the explicitly supplied current
///   admission and execution binding via the canonical
///   `validate_against`, else [`UnmeasuredReason::AdmissionMismatch`]
///   (the receipt's embedded digest is never trusted alone);
/// * the route must be matched with a recorded observed route, else
///   [`UnmeasuredReason::RouteDiverged`] or
///   [`UnmeasuredReason::RouteUnobserved`];
/// * the receipt's digest-bound evidence must name exactly `result_bytes`,
///   else [`UnmeasuredReason::DigestMismatch`];
/// * the receipt must report an output count, else
///   [`UnmeasuredReason::UsageUnknown`]. The output count is the route's
///   rendered-output quantity under its own tokenizer (route-completion
///   semantics); input, cost, and quota figures are never substituted,
///   summed, or overridden.
///
/// # Errors
///
/// Returns [`BridgeError::InvalidContract`] for malformed observation,
/// admission, or binding inputs, or [`BridgeError::UnmeasuredTokens`] when
/// the evidence does not support a measurement.
pub fn produce_route_token_observation(
    result_bytes: &[u8],
    route_observation: &PhysicalRouteObservationReceipt,
    admission: &AdmittedRouteReceipt,
    binding: &ProviderExecutionBinding,
) -> Result<RouteTokenObservation, BridgeError> {
    route_observation
        .validate()
        .map_err(|_| BridgeError::InvalidContract {
            field: "route_tokens.route_observation",
            reason: "route observation invalid",
        })?;
    admission
        .validate()
        .map_err(|_| BridgeError::InvalidContract {
            field: "route_tokens.admission",
            reason: "admission invalid",
        })?;
    binding
        .validate_internal()
        .map_err(|_| BridgeError::InvalidContract {
            field: "route_tokens.binding",
            reason: "execution binding invalid",
        })?;
    route_observation
        .validate_against(binding, admission)
        .map_err(|_| BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::AdmissionMismatch,
        })?;
    match route_observation.route_state {
        RouteObservationState::Matched => {}
        RouteObservationState::Diverged => {
            return Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::RouteDiverged,
            });
        }
        RouteObservationState::Unobserved => {
            return Err(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::RouteUnobserved,
            });
        }
    }
    let observed =
        route_observation
            .observed_route
            .as_ref()
            .ok_or(BridgeError::UnmeasuredTokens {
                reason: UnmeasuredReason::RouteUnobserved,
            })?;
    let actual_digest = sha256_hex(result_bytes);
    let evidence_matches = route_observation
        .raw_evidence_digest
        .as_ref()
        .is_some_and(|digest| digest.as_str() == actual_digest);
    if !evidence_matches {
        return Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::DigestMismatch,
        });
    }
    let tokens = route_observation
        .usage
        .output_tokens
        .ok_or(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::UsageUnknown,
        })?;
    RouteTokenObservation::new(
        RouteTokenizer {
            route: observed.clone(),
        },
        actual_digest,
        tokens,
    )
}
