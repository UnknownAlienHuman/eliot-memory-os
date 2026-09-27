//! OTLP bridge module, disabled by default (I16.2).
//!
//! I16.2 specifies an "optional OTLP bridge module, disabled by default". The
//! `otlp` cargo feature is off in the default feature set, so a default
//! startup never links this module's bridge body and never opens a collector
//! connection. [`otlp_enabled`] is the single honest answer to "is the bridge
//! compiled in", and it is `false` in every default build.
//!
//! The bridge is a bridge, not an authority: it never becomes durable audit,
//! never claims downstream delivery, and never turns a metrics sample into proof
//! (I16.1). A configured endpoint with the feature disabled is reported as
//! [`OtlpDisposition::FeatureDisabled`], never as a silent no-op.
//!
//! # No transport, therefore no fabricated export
//!
//! This crate declares no OTLP or HTTP transport dependency, so with the
//! `otlp` feature built there is still nothing that can put a record on the
//! wire. A configured endpoint is therefore reported as
//! [`OtlpDisposition::NoTransport`], never as an active bridge, and
//! [`OtlpBridge::export`] refuses with
//! [`OtlpBridgeError::NoTransportConfigured`] instead of reporting an export
//! that never happened. I16.11 forbids silent success, and a recorded success
//! for an unsent record is exactly that. Supplying a real exporter needs a
//! transport dependency, which is a separate decision from this module.

/// Whether the OTLP bridge body is compiled into this build.
#[must_use]
pub const fn otlp_enabled() -> bool {
    cfg!(feature = "otlp")
}

/// Honest state of the OTLP bridge for one process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtlpDisposition {
    /// An endpoint is configured and this build has the `otlp` feature on, but
    /// no transport is present, so no record can leave the process. Reported
    /// instead of an active bridge: a bridge that cannot transmit is not a
    /// bridge, and I16.11 forbids reporting it as one.
    NoTransport,
    /// An endpoint is configured but this build has the `otlp` feature off.
    FeatureDisabled,
    /// No endpoint is configured; the bridge stays inert.
    NotConfigured,
}

impl OtlpDisposition {
    /// Stable disposition name for a bounded diagnostic record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoTransport => "no_transport",
            Self::FeatureDisabled => "feature_disabled",
            Self::NotConfigured => "not_configured",
        }
    }
}

/// One bounded operational record handed to the bridge.
///
/// The record carries only bounded, already-redacted material; the bridge
/// performs no additional field policy of its own because the emitting
/// surface already passed the shared policy gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpExport {
    /// Stable event name.
    pub event: &'static str,
    /// Bounded low-cardinality labels.
    pub labels: Vec<(String, String)>,
}

/// The OTLP bridge.
///
/// Constructed only when [`otlp_enabled`] is true. With the feature disabled
/// the type still exists so the bootstrap can report `FeatureDisabled`
/// honestly, but [`OtlpBridge::export`] is unreachable in a default build.
///
/// A constructed bridge records a configured endpoint; it does not imply a
/// working transport, because this crate declares none. See
/// [`OtlpDisposition::NoTransport`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpBridge {
    endpoint: String,
}

impl OtlpBridge {
    /// Builds the bridge over a configured collector endpoint.
    ///
    /// Success means the endpoint is configured and the feature is built. It
    /// does not mean a record can be exported: see [`Self::export`].
    ///
    /// # Errors
    ///
    /// Returns [`OtlpBridgeError::FeatureDisabled`] when this build has the
    /// `otlp` feature off, and [`OtlpBridgeError::EndpointNotConfigured`] for
    /// a blank endpoint.
    pub fn new(endpoint: &str) -> Result<Self, OtlpBridgeError> {
        if !otlp_enabled() {
            return Err(OtlpBridgeError::FeatureDisabled);
        }
        if endpoint.trim().is_empty() {
            return Err(OtlpBridgeError::EndpointNotConfigured);
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
        })
    }

    /// The configured collector endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Exports one bounded operational record through the bridge.
    ///
    /// # Errors
    ///
    /// Returns [`OtlpBridgeError::FeatureDisabled`] in a default build, and
    /// [`OtlpBridgeError::NoTransportConfigured`] in a build with the feature
    /// on, because this crate declares no transport and the record cannot
    /// reach the configured endpoint.
    ///
    /// No result is ever fabricated: a refused export stays an error, never a
    /// recorded success. The record is deliberately not consumed, so an
    /// unsent record is never mistaken for a sent one.
    pub fn export(&self, _record: &OtlpExport) -> Result<(), OtlpBridgeError> {
        if !otlp_enabled() {
            return Err(OtlpBridgeError::FeatureDisabled);
        }
        Err(OtlpBridgeError::NoTransportConfigured)
    }
}

/// Typed bridge refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OtlpBridgeError {
    /// This build has the `otlp` feature disabled.
    #[error("otlp bridge is disabled by default in this build")]
    FeatureDisabled,
    /// No collector endpoint is configured.
    #[error("otlp bridge has no configured endpoint")]
    EndpointNotConfigured,
    /// The bridge is built and an endpoint is configured, but this crate
    /// declares no transport, so the record was not exported.
    #[error("otlp bridge has no transport, so the record was not exported")]
    NoTransportConfigured,
}

/// Reports the honest bridge disposition for a configured endpoint.
#[must_use]
pub fn disposition(configured_endpoint: Option<&str>) -> OtlpDisposition {
    match configured_endpoint {
        None => OtlpDisposition::NotConfigured,
        Some(_) if !otlp_enabled() => OtlpDisposition::FeatureDisabled,
        Some(_) => OtlpDisposition::NoTransport,
    }
}
