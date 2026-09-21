//! C6 admitted-route byte-bound token measurement for I7.24 tool-result
//! receipts (issue #1941).
//!
//! The bridge runs no tokenizer: no tokenizer implementation exists on the
//! delivery path, invocation responses carry correlation and disposition
//! only, provider turn-level usage never measures exact rendered bytes, and
//! I0.4 forbids assuming any equivalence while I10.15 states that missing
//! usage is `unknown`, never zero. A route-tokenizer count for exact bytes
//! can therefore only be attested by the route owner at render time.
//!
//! This module owns the versioned adapter-to-bridge measurement wire that
//! carries such an attestation, following the bridge-core wire discipline:
//! a contract identity plus frozen revision, I7.2 byte bounds, serde wire
//! traits on every carried field, and admission checks re-verifiable from
//! the bytes. [`TokenMeasurementPayload`] binds the counted bytes
//! (`result_digest`), the attested count (`tokens`), and the canonical
//! route observation that names the admitted route. [`decode`] verifies
//! version, bounds, shape, and the observation's recomputed self digest;
//! [`produce_route_token_observation`] additionally verifies the observation
//! against the explicitly supplied current admission and execution binding
//! (never trusted from the payload alone), a matched observed route, and
//! digest equality with the exact bytes being receipted. Only then does the
//! attested count pass through — unaltered, never estimated, summed, or
//! substituted — into a digest-bound [`RouteTokenObservation`].
//!
//! Anything else withholds with [`UnmeasuredReason`]: no payload (the route
//! supports no measurement), unlinked, diverged, unobserved, or misbound
//! evidence. In particular the observation's turn-level [`UsageReceipt`]
//! is never read as a result cost — relabelling provider usage as measured
//! bytes would fabricate measurement the tree cannot verify.
//!
//! ## Render-time support matrix
//!
//! Verified on current main: no tokenizer implementation exists anywhere
//! (no tokenizer dependency in `Cargo.lock`, no encode calls outside
//! framing/base64), and no route adapter counts exact rendered bytes.
//! Every route therefore withholds, each for its exact documented reason;
//! the wire stays ready for the first adapter that measures at render time
//! and emits v1 attestations bound to the exact counted bytes:
//!
//! ```text
//! codex     turn-level native usage only; translate_result leaves evidence
//!           unbound and the route Unobserved
//!           (crates/agent/eliot-agent-codex/src/lib.rs:1050,1671,1676)
//!           → withhold: no byte-bound count exists. Measurement capability
//!           exists separately (`CodexRouteTokenizer`: tiktoken `o200k_base`
//!           for registry-mapped IDs, proven with real encoder output) but
//!           has no live caller yet; the withhold stands pending evidence
//!           flow to a callsite holding exact bytes, model, and observation.
//! claude    usage None/None with no production source
//!           (crates/agent/eliot-agent-claude/src/execution.rs:1413-1416)
//!           → withhold: unknown preserved, never zero.
//! acp       usage None/None, asserted by its own tests
//!           (crates/agent/eliot-agent-acp/src/lib.rs:1343-1345,2161-2162)
//!           → withhold: explicit unknown.
//! opencode  assistant/step usage at turn/step level
//!           (crates/agent/eliot-agent-opencode/src/client.rs:1407,1414)
//!           → withhold: usage is not measurement.
//! smart     owner observations validated, never counted
//!           (measure_serialized_context); STU is a normative estimate,
//!           never token proof → withhold: nothing counted here either.
//! wasm      child fuel/memory metering, B2 scope
//!           (bins/eliot-wasm-host/src/child_engine.rs)
//!           → withhold: metering is not tokens; foreign scope.
//! ledger    aggregate run counters, daemon/app scope (Halley owner;
//!           crates/eliot-app/src/mcp_stdio/autonomy.rs:274)
//!           → withhold: aggregate, not per-byte; foreign scope.
//! bridge    Invoke path carries bytes plus disposition only, A3 BIN scope
//!           (bins/eliot-agent-bridge/src/main.rs handle_invocation and
//!           record_invocation_delivery) → withhold: no evidence to bind.
//! notify    no token-cost shape exists in DeliveryReceiptEvidence or
//!           ReceiptCore (notify lane owner) → withhold: shape absent here,
//!           never shadow-invented.
//! ```
//!
//! A route graduates from this matrix only by emitting versioned
//! attestations bound to the exact bytes it counted with its actual
//! tokenizer; the intake below verifies every axis before a count passes.
//!
//! Route identity reuses the shared [`crate::RouteFingerprint`] contract.
//! Tokenizer provenance is the validated observed route itself: the tree
//! attests no standalone tokenizer builds or model-to-tokenizer registry,
//! so none are named here and no tokenizer name, version, or hash is ever
//! accepted, defaulted, or synthesized. Source/version attestation for
//! installed material stays with the Skill transport feed (B2 owner); this
//! module claims no versions. There are no conversions to or from any other
//! crate's measurement type.
//!
//! [`UsageReceipt`]: eliot_agent_api::UsageReceipt

use eliot_agent_api::{
    AdmittedRouteReceipt, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
    RouteObservationState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BridgeError, RouteFingerprint};

/// Versioned C6 measurement wire contract identity.
pub const TOKEN_MEASUREMENT_CONTRACT_ID: &str = "eliot.route.token-measurement/v1";
/// Wire payload contract revision. Decode rejects any other revision; a new
/// shape gets a NEW revision, v1 is never silently changed.
pub const TOKEN_MEASUREMENT_VERSION: u32 = 1;
/// Maximum encoded wire bytes (I7.2 hot-response profile: measurement
/// attestations are small bounded projections carrying digests, never raw
/// result bytes).
pub const MAX_MEASUREMENT_WIRE_BYTES: usize = 64 * 1024;

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

fn check_version(version: u32) -> Result<(), BridgeError> {
    if version != TOKEN_MEASUREMENT_VERSION {
        return Err(BridgeError::InvalidContract {
            field: "route_tokens.contract_version",
            reason: "contract version mismatch",
        });
    }
    Ok(())
}

fn check_bound(len: usize) -> Result<(), BridgeError> {
    if len > MAX_MEASUREMENT_WIRE_BYTES {
        return Err(BridgeError::InvalidContract {
            field: "route_tokens.wire",
            reason: "wire payload exceeds bound",
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
/// actual tokenizer reported. Values exist only via
/// [`produce_route_token_observation`] over a verified measurement wire
/// payload, so a receipt citing them repeats wire-bound owner evidence
/// instead of a bridge estimate.
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

/// Adapter-to-bridge token measurement attestation as wire bytes.
///
/// Carries the route's canonical observation (which names the admitted
/// route and stays re-verifiable from these bytes), the digest of the exact
/// bytes the route counted, and the attested count for those bytes. The
/// attested count is scoped to the evidenced bytes by the measurer setting
/// `result_digest` when it counts; the bridge enforces the binding at
/// intake and performs no arithmetic on any usage figure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMeasurementPayload {
    /// Wire contract revision (must be [`TOKEN_MEASUREMENT_VERSION`]).
    pub contract_version: u32,
    /// Canonical route observation naming the admitted route.
    pub observation: PhysicalRouteObservationReceipt,
    /// Lowercase SHA-256 hex of the exact bytes the count was reported for.
    pub result_digest: String,
    /// Token count the route's actual tokenizer reported for those bytes.
    pub tokens: u64,
}

impl TokenMeasurementPayload {
    /// Validates version, observation shape plus recomputed self digest, and
    /// digest shape. Admission linkage needs the live admission and binding
    /// and runs at intake ([`produce_route_token_observation`]), not here.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] on the first invalid field.
    pub fn validate(&self) -> Result<(), BridgeError> {
        check_version(self.contract_version)?;
        self.observation
            .validate()
            .map_err(|_| BridgeError::InvalidContract {
                field: "route_tokens.observation",
                reason: "route observation invalid",
            })?;
        validate_digest(&self.result_digest, "route_tokens.result_digest")?;
        Ok(())
    }

    /// Encodes a validated attestation within the wire bound.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] when validation fails, the
    /// shape does not serialize, or the encoding exceeds the bound.
    pub fn encode(&self) -> Result<Vec<u8>, BridgeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| BridgeError::InvalidContract {
            field: "route_tokens.wire",
            reason: "wire payload shape invalid",
        })?;
        check_bound(bytes.len())?;
        Ok(bytes)
    }

    /// Decodes and validates one attestation within the wire bound.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] when the bound, shape,
    /// version, observation, or digest checks fail.
    pub fn decode(bytes: &[u8]) -> Result<Self, BridgeError> {
        check_bound(bytes.len())?;
        let payload: Self =
            serde_json::from_slice(bytes).map_err(|_| BridgeError::InvalidContract {
                field: "route_tokens.wire",
                reason: "wire payload shape invalid",
            })?;
        payload.validate()?;
        Ok(payload)
    }
}

/// Why a tool result carries no measured token cost.
///
/// Every variant withholds receipt projection: missing or inapplicable
/// evidence denies the receipt instead of estimating a count. A route that
/// emits no measurement payload reports nothing, and nothing is its honest
/// state — absence is never a zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnmeasuredReason {
    /// The route owner emitted no measurement payload: the route supports
    /// no measurement on this delivery.
    NoObservation,
    /// The attested evidence names different bytes, so its count must not
    /// be attributed to this result. Missing evidence binding withholds the
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
}

impl std::fmt::Display for UnmeasuredReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::NoObservation => "no route-owner measurement payload emitted",
            Self::DigestMismatch => "measurement evidence does not match delivered bytes",
            Self::AdmissionMismatch => "measurement is not linked to the current admission",
            Self::RouteDiverged => "observed route diverged from the admitted route",
            Self::RouteUnobserved => "route was not observed",
        };
        formatter.write_str(reason)
    }
}

/// Produces a digest-bound token observation from a measurement wire payload.
///
/// The live route-owner observation producer: the yielded count passes
/// through byte-bound verification unaltered —
/// * the payload must be well-formed (version, bounds, observation shape
///   plus recomputed self digest, digest shape), else
///   [`BridgeError::InvalidContract`];
/// * the embedded observation must link against the explicitly supplied
///   current admission and execution binding via the canonical
///   `validate_against`, else [`UnmeasuredReason::AdmissionMismatch`]
///   (the payload's embedded digest is never trusted alone);
/// * the route must be matched with a recorded observed route, else
///   [`UnmeasuredReason::RouteDiverged`] or
///   [`UnmeasuredReason::RouteUnobserved`];
/// * the attested evidence digest must equal the SHA-256 of `result_bytes`
///   — and the embedded observation's own evidence digest, when present,
///   must agree — else [`UnmeasuredReason::DigestMismatch`].
///
/// The observation's turn-level usage is never read: provider usage does not
/// measure exact rendered bytes, and relabelling it would fabricate
/// measurement.
///
/// # Errors
///
/// Returns [`BridgeError::InvalidContract`] for malformed payload,
/// admission, or binding inputs, or [`BridgeError::UnmeasuredTokens`] when
/// the evidence does not support a measurement.
pub fn produce_route_token_observation(
    result_bytes: &[u8],
    payload: &TokenMeasurementPayload,
    admission: &AdmittedRouteReceipt,
    binding: &ProviderExecutionBinding,
) -> Result<RouteTokenObservation, BridgeError> {
    payload.validate()?;
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
    let observation = &payload.observation;
    observation
        .validate_against(binding, admission)
        .map_err(|_| BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::AdmissionMismatch,
        })?;
    match observation.route_state {
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
    let observed = observation
        .observed_route
        .as_ref()
        .ok_or(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::RouteUnobserved,
        })?;
    let actual_digest = sha256_hex(result_bytes);
    if payload.result_digest != actual_digest {
        return Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::DigestMismatch,
        });
    }
    if let Some(bound) = observation.raw_evidence_digest.as_ref()
        && bound.as_str() != actual_digest
    {
        return Err(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::DigestMismatch,
        });
    }
    let produced = RouteTokenObservation {
        tokenizer: RouteTokenizer {
            route: observed.clone(),
        },
        result_digest: actual_digest,
        tokens: payload.tokens,
    };
    produced.validate()?;
    Ok(produced)
}
