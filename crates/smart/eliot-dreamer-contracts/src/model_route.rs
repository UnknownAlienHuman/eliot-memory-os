//! Owner-neutral model-route adapter boundary (CC-002).
//!
//! Cell `smart.dreamer.contracts`. This module owns the closed,
//! versioned request/outcome shapes between a [`DreamInputBundle`] and a
//! schema-valid [`ModelDraft`]. It exposes timeout, cancellation, privacy
//! class, a bounded cost/usage receipt, and malformed/partial output
//! disposition with no semantic or canonical authority.
//!
//! Provider SDKs, route selection, account/capacity reservation, and retry
//! scheduling stay outside Smart: the runtime chooses one of the admitted
//! `allowed_routes`, enforces `timeout_ms`/`cancelled`, and returns one
//! [`ModelRouteOutcome`]. Smart consumers program against this contract and
//! never import a provider.
//!
//! Bounds mirror `draft.rs`: provider routes are at most 128 bytes,
//! raw payloads at most 1 MiB, model statements at most 16384 bytes.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::budget::{
    INPUT_BYTES_CEILING, MODEL_CALLS_CEILING, OUTPUT_BYTES_CEILING, WALL_MS_CEILING,
};
use crate::bundle::DreamInputBundle;
use crate::draft::{ModelDraft, RawProviderOutput};
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{
    ContractViolation, check_fence, check_schema_version, check_text, check_vec_bound,
    is_hex64_lower,
};

/// Exact schema version accepted by the model-route shapes.
pub const MODEL_ROUTE_SCHEMA_VERSION: u32 = 1;
/// Maximum admitted provider routes carried by one request.
pub const MAX_ALLOWED_ROUTES: usize = 16;
/// Maximum provider-route length in bytes (mirrors `draft.rs`).
pub const MAX_ROUTE_CHARS: usize = 128;
/// Maximum human-readable note length in bytes.
pub const MAX_NOTE_CHARS: usize = 1024;

/// Closed privacy class for one routed call.
///
/// Spellings mirror the admitted `DreamJobInput` privacy profiles
/// (`local_only` / `governed_external`) without importing runtime policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ModelRoutePrivacy {
    /// Host-local handling only.
    #[serde(rename = "local_only")]
    LocalOnly,
    /// Governed external handling under an explicit route disclosure.
    #[serde(rename = "governed_external")]
    GovernedExternal,
}

impl ModelRoutePrivacy {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::GovernedExternal => "governed_external",
        }
    }

    /// Parses a wire spelling into its closed value.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::UnknownVariant`] for any unknown spelling.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        match value {
            "local_only" => Ok(Self::LocalOnly),
            "governed_external" => Ok(Self::GovernedExternal),
            other => Err(ContractViolation::UnknownVariant {
                field: "privacy",
                value: other.to_owned(),
            }),
        }
    }
}

/// Closed terminal disposition of one routed call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelRouteDisposition {
    /// A schema-valid draft was produced within budget and deadline.
    Completed,
    /// A schema-valid draft was produced with a preserved raw payload.
    Partial,
    /// The provider payload could not be structured; raw is preserved.
    Malformed,
    /// The call was cancelled before a draft could be produced.
    Cancelled,
    /// The call exceeded its admitted timeout.
    Timeout,
}

impl ModelRouteDisposition {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Malformed => "malformed",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
        }
    }

    /// Parses a wire spelling into its closed value.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::UnknownVariant`] for any unknown spelling.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        match value {
            "completed" => Ok(Self::Completed),
            "partial" => Ok(Self::Partial),
            "malformed" => Ok(Self::Malformed),
            "cancelled" => Ok(Self::Cancelled),
            "timeout" => Ok(Self::Timeout),
            other => Err(ContractViolation::UnknownVariant {
                field: "disposition",
                value: other.to_owned(),
            }),
        }
    }
}

/// Versioned request from a [`DreamInputBundle`] digest to one routed call.
///
/// `bundle_digest` is the SHA-256 over the canonical bytes of the exact
/// bundle the runtime will send; see [`bundle_digest_of`]. `allowed_routes`
/// is the closed denominator the runtime may choose from. `timeout_ms` is
/// the admitted wall budget; `cancelled` is a pre-call cancellation
/// observation. `privacy` travels unchanged for route disclosure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteRequest {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Owning job identity.
    pub job_id: String,
    /// Digest over the canonical bytes of the input bundle (64 hex).
    pub bundle_digest: String,
    /// Dependency-only fence captured before the call.
    pub state_fence: eliot_contracts::StateFence,
    /// Closed route denominator; the runtime must pick one member.
    pub allowed_routes: Vec<String>,
    /// Admitted wall budget in milliseconds (`1..=600_000`).
    pub timeout_ms: u64,
    /// True when the caller already observed cancellation.
    pub cancelled: bool,
    /// Privacy class the chosen route must satisfy.
    pub privacy: ModelRoutePrivacy,
}

impl ModelRouteRequest {
    /// Validates intrinsic bounds without I/O or provider lookup.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when any bound, digest shape, fence, or
    /// denominator rule fails.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version, MODEL_ROUTE_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id", 256)?;
        if !is_hex64_lower(&self.bundle_digest) {
            return Err(ContractViolation::BindingMismatch {
                field: "bundle_digest",
                reason: "digest must be 64 hex characters".to_string(),
            });
        }
        check_fence(&self.state_fence)?;
        check_vec_bound(
            self.allowed_routes.len(),
            MAX_ALLOWED_ROUTES,
            "allowed_routes",
        )?;
        if self.allowed_routes.is_empty() {
            return Err(ContractViolation::MissingField("allowed_routes"));
        }
        for route in &self.allowed_routes {
            check_text(route, "allowed_routes", MAX_ROUTE_CHARS)?;
        }
        let mut sorted = self.allowed_routes.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != self.allowed_routes.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "allowed_routes",
                reason: "duplicate route".to_string(),
            });
        }
        let ceiling = i64::try_from(WALL_MS_CEILING).unwrap_or(i64::MAX);
        let got = i64::try_from(self.timeout_ms).unwrap_or(i64::MAX);
        if self.timeout_ms == 0 || self.timeout_ms > WALL_MS_CEILING {
            return Err(ContractViolation::OutOfBounds {
                field: "timeout_ms",
                min: 1,
                max: ceiling,
                got,
            });
        }
        Ok(())
    }

    /// Returns the canonical digest over this request envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Malformed`] when canonicalization fails.
    pub fn request_digest(&self) -> Result<String, ContractViolation> {
        Ok(digest_hex(&canonical_bytes(self)?))
    }

    /// Validates this request against the exact bundle it claims to carry.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when either side is invalid or the
    /// recorded digest does not equal the computed bundle digest.
    pub fn validate_binds_bundle(
        &self,
        bundle: &DreamInputBundle,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        bundle.validate()?;
        let computed = bundle_digest_of(bundle)?;
        if self.bundle_digest != computed {
            return Err(ContractViolation::BindingMismatch {
                field: "bundle_digest",
                reason: "request bundle digest does not match bundle".to_string(),
            });
        }
        if self.job_id != bundle.job_id {
            return Err(ContractViolation::BindingMismatch {
                field: "job_id",
                reason: "request job does not match bundle job".to_string(),
            });
        }
        if self.state_fence != bundle.state_fence {
            return Err(ContractViolation::BindingMismatch {
                field: "state_fence",
                reason: "request fence does not match bundle fence".to_string(),
            });
        }
        Ok(())
    }
}

/// Computes the bundle digest bound by [`ModelRouteRequest::bundle_digest`].
///
/// This is the SHA-256 over the canonical bytes of the whole bundle.
///
/// # Errors
///
/// Returns [`ContractViolation::Malformed`] when canonicalization fails.
pub fn bundle_digest_of(bundle: &DreamInputBundle) -> Result<String, ContractViolation> {
    Ok(digest_hex(&canonical_bytes(bundle)?))
}

/// Bounded cost/usage receipt for one routed call.
///
/// Each field is checked independently against its class ceiling; under-use
/// in one field never covers over-use in another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CostUsageReceipt {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Owning job identity.
    pub job_id: String,
    /// Consumed input bytes (at most `1_048_576`).
    pub input_bytes: u64,
    /// Produced output bytes (at most `1_048_576`).
    pub output_bytes: u64,
    /// Performed provider calls (at most `64`).
    pub model_calls: u64,
    /// Elapsed wall milliseconds (at most `600_000`).
    pub wall_ms: u64,
}

impl CostUsageReceipt {
    /// Validates every field against its class ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when any bound fails.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version, MODEL_ROUTE_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id", 256)?;
        for (used, ceiling, dimension) in [
            (self.input_bytes, INPUT_BYTES_CEILING, "input_bytes"),
            (self.output_bytes, OUTPUT_BYTES_CEILING, "output_bytes"),
            (self.model_calls, MODEL_CALLS_CEILING, "model_calls"),
            (self.wall_ms, WALL_MS_CEILING, "wall_ms"),
        ] {
            if used > ceiling {
                return Err(ContractViolation::Budget {
                    dimension,
                    reason: std::format!("usage {used} exceeds class ceiling {ceiling}"),
                });
            }
        }
        Ok(())
    }
}

/// Versioned outcome of one routed call: raw bytes and/or a structured draft.
///
/// This carries no semantic or canonical authority: it never grounds claims,
/// validates against a manifest, screens, admits, or writes state. A
/// [`ModelDraft`] here is hypothesis text only; resolved evidence lives
/// elsewhere.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteOutcome {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Owning job identity; must equal the request job.
    pub job_id: String,
    /// Bundle digest this outcome accounts for; must equal the request digest.
    pub bundle_digest: String,
    /// Chosen provider route; `Some` exactly for completed/partial/malformed.
    pub provider_route: Option<String>,
    /// Terminal disposition of the call.
    pub disposition: ModelRouteDisposition,
    /// Untouched provider payload, present for partial/malformed.
    pub raw: Option<RawProviderOutput>,
    /// Structured hypothesis text, present for completed/partial.
    pub draft: Option<ModelDraft>,
    /// Bounded cost/usage observed by the runtime.
    pub receipt: CostUsageReceipt,
    /// Fence the call ran under; must equal the request fence.
    pub state_fence: eliot_contracts::StateFence,
    /// Human-readable note, non-blank, at most 1024 bytes.
    pub note: String,
}

impl ModelRouteOutcome {
    /// Validates intrinsic bounds plus the disposition shape.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when any bound, digest, fence, receipt,
    /// or disposition-carry rule fails.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version, MODEL_ROUTE_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id", 256)?;
        if !is_hex64_lower(&self.bundle_digest) {
            return Err(ContractViolation::BindingMismatch {
                field: "bundle_digest",
                reason: "digest must be 64 hex characters".to_string(),
            });
        }
        check_fence(&self.state_fence)?;
        self.receipt.validate()?;
        check_text(&self.note, "note", MAX_NOTE_CHARS)?;
        if let Some(route) = &self.provider_route {
            check_text(route, "provider_route", MAX_ROUTE_CHARS)?;
        }
        match self.disposition {
            ModelRouteDisposition::Completed => {
                if self.provider_route.is_none() {
                    return Err(ContractViolation::MissingField("provider_route"));
                }
                let draft = self
                    .draft
                    .as_ref()
                    .ok_or(ContractViolation::MissingField("draft"))?;
                draft.validate()?;
                if self.raw.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "raw",
                        reason: "completed outcome must not carry raw bytes".to_string(),
                    });
                }
                bind_job("draft.job_id", &draft.job_id, &self.job_id)?;
            }
            ModelRouteDisposition::Partial => {
                if self.provider_route.is_none() {
                    return Err(ContractViolation::MissingField("provider_route"));
                }
                let draft = self
                    .draft
                    .as_ref()
                    .ok_or(ContractViolation::MissingField("draft"))?;
                let raw = self
                    .raw
                    .as_ref()
                    .ok_or(ContractViolation::MissingField("raw"))?;
                draft.validate()?;
                raw.validate()?;
                bind_job("draft.job_id", &draft.job_id, &self.job_id)?;
                bind_job("raw.job_id", &raw.job_id, &self.job_id)?;
                bind_route(raw, self.provider_route.as_ref())?;
            }
            ModelRouteDisposition::Malformed => {
                if self.provider_route.is_none() {
                    return Err(ContractViolation::MissingField("provider_route"));
                }
                let raw = self
                    .raw
                    .as_ref()
                    .ok_or(ContractViolation::MissingField("raw"))?;
                raw.validate()?;
                if self.draft.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "draft",
                        reason: "malformed outcome must not carry a draft".to_string(),
                    });
                }
                bind_job("raw.job_id", &raw.job_id, &self.job_id)?;
                bind_route(raw, self.provider_route.as_ref())?;
            }
            ModelRouteDisposition::Cancelled | ModelRouteDisposition::Timeout => {
                if self.provider_route.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "provider_route",
                        reason: "cancelled/timeout outcome must not name a route".to_string(),
                    });
                }
                if self.raw.is_some() || self.draft.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "raw",
                        reason: "cancelled/timeout outcome must not carry payload".to_string(),
                    });
                }
            }
        }
        if self.receipt.job_id != self.job_id {
            return Err(ContractViolation::BindingMismatch {
                field: "job_id",
                reason: "receipt job does not match outcome job".to_string(),
            });
        }
        Ok(())
    }

    /// Validates this outcome against the admitted request.
    ///
    /// Binds job, bundle digest, fence, and the chosen route to the closed
    /// denominator; enforces pre-call cancellation and the wall budget:
    /// completed/partial outcomes must fit inside `timeout_ms`, timeout
    /// outcomes must meet or exceed it.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when either side is invalid or any
    /// binding, cancellation, route, or timeout rule fails.
    pub fn validate_binding(&self, request: &ModelRouteRequest) -> Result<(), ContractViolation> {
        self.validate()?;
        request.validate()?;
        bind_job("job_id", &self.job_id, &request.job_id)?;
        if self.bundle_digest != request.bundle_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "bundle_digest",
                reason: "outcome bundle does not match request bundle".to_string(),
            });
        }
        if self.state_fence != request.state_fence {
            return Err(ContractViolation::BindingMismatch {
                field: "state_fence",
                reason: "outcome fence does not match request fence".to_string(),
            });
        }
        if let Some(route) = &self.provider_route
            && !request
                .allowed_routes
                .iter()
                .any(|allowed| allowed == route)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "provider_route",
                reason: "chosen route is outside the admitted denominator".to_string(),
            });
        }
        if request.cancelled && self.disposition != ModelRouteDisposition::Cancelled {
            return Err(ContractViolation::BindingMismatch {
                field: "disposition",
                reason: "pre-cancelled request must end cancelled".to_string(),
            });
        }
        match self.disposition {
            ModelRouteDisposition::Completed | ModelRouteDisposition::Partial => {
                if self.receipt.wall_ms > request.timeout_ms {
                    return Err(ContractViolation::BindingMismatch {
                        field: "wall_ms",
                        reason: "completed outcome exceeds admitted timeout".to_string(),
                    });
                }
            }
            ModelRouteDisposition::Timeout => {
                if self.receipt.wall_ms < request.timeout_ms {
                    return Err(ContractViolation::BindingMismatch {
                        field: "wall_ms",
                        reason: "timeout outcome must meet the admitted timeout".to_string(),
                    });
                }
            }
            ModelRouteDisposition::Malformed | ModelRouteDisposition::Cancelled => {}
        }
        Ok(())
    }
}

fn bind_job(field: &'static str, got: &str, want: &str) -> Result<(), ContractViolation> {
    if got != want {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: std::format!("{field} binding mismatch"),
        });
    }
    Ok(())
}

fn bind_route(
    raw: &RawProviderOutput,
    provider_route: Option<&String>,
) -> Result<(), ContractViolation> {
    let Some(want) = provider_route else {
        return Err(ContractViolation::MissingField("provider_route"));
    };
    if raw.provider_route != *want {
        return Err(ContractViolation::BindingMismatch {
            field: "provider_route",
            reason: "raw route does not match outcome route".to_string(),
        });
    }
    Ok(())
}
