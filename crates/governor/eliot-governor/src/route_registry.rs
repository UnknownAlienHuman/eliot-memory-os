//! Governor-owned evidence-backed capability and route registry (I3.4).
//!
//! This module owns the route layer of the I3.4 identity separation: a
//! [`RuntimeRoute`] is *configured intent and compatibility only*, never
//! mutable liveness state, and it never carries a vendor label or a boolean
//! capability. Current availability and admission are derived here from the
//! retained [`CapabilityRegistry`] evidence compared against the *current*
//! identity.
//!
//! Three properties carry the contract:
//!
//! - **Fingerprint.** [`RouteBehaviorFingerprint`] covers exactly the
//!   semantics I3.4 lists as behaviour-changing: host family and adapter,
//!   protocol/transport, runtime and adapter hashes, provider/model/auth/
//!   billing, the declared execution identity and the User Broker class it is
//!   delegated to, the message serializer, tool-call ID and role ordering, and
//!   reasoning continuation/compaction plus feature-flag and tool/context
//!   profile hashes. Task Policy/Config snapshots, privacy classes and budget
//!   envelopes are deliberately outside it, so an unrelated policy edit does
//!   not invalidate route capability evidence.
//! - **Requested versus observed.** [`ActualRouteReceipt`] stores the
//!   requested route and the observed route separately. Fields the runtime
//!   does not expose stay `None` (`unknown`); they are never filled from UI
//!   selection, prompt text, or the requested intent.
//! - **Staleness by comparison.** Admission is derived by comparing each
//!   evidence record's scope fingerprint against the scope the current route
//!   presents. There is no mutable "stale" flag: changing the adapter hash or
//!   the serializer fingerprint moves the derived scope, the exact-fingerprint
//!   match fails, and admission is refused until the route is requalified.
//! - **Complete effective key (issue #1958).** Routing evidence, capability
//!   lookup, and outcome-profile lookup all key on the complete behaviour
//!   fingerprint through [`effective_route_key`] and
//!   [`RouteScopeFingerprint`], never on provider/model labels. Two attempts
//!   that differ only by serializer or by tool-call ID / role ordering
//!   therefore resolve to different keys and cannot reuse each other's
//!   capability or outcome evidence.
//!
//! The registry holds no durable state and performs no effect: it is the
//! read/decision half of the I1.9 evidence view.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};

use eliot_contracts::{LowercaseSha256, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability_evidence::{
    CapabilityEvidenceRecord, CapabilityRegistry, CapabilitySource, CapabilityStatus,
    RouteScopeFingerprint,
};

/// Digest domain of the complete effective route key (issue #1958).
///
/// The key is versioned material, not a bare hash of a value: a change to the
/// material shape moves the domain instead of silently reinterpreting an
/// already-published key. This mirrors the shared epoch-identity recipe in
/// `eliot_contracts` (`canonical_json_bytes` over a struct carrying a
/// `domain_separator`, then `sha256_hex`).
///
/// Version `v2` is this constant because issue #1816 added the declared
/// execution identity and its User Broker class to
/// [`RouteBehaviorFingerprint`], so a `v1` key and a `v2` key over otherwise
/// identical route material are different keys, exactly as the rule above
/// requires.
pub const EFFECTIVE_ROUTE_KEY_DOMAIN: &str = "eliot.governor.effective-route-key.v2";

/// Execution identity a route is configured for (I3.4 `RuntimeRoute`).
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionIdentity {
    /// A background service identity.
    Service,
    /// The interactive logged-in user identity.
    InteractiveUser,
    /// A remote identity outside the local host boundary.
    Remote,
}

fn is_identity_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

/// Configured route intent and compatibility (I3.4 `RuntimeRoute`).
///
/// This is intent only. Liveness, readiness and capacity are joined from
/// capability evidence by [`CapabilityRouteRegistry::admit_route`]; they are
/// not mutable state inside the route definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRoute {
    /// Stable route identity within the registry.
    pub route_id: String,
    /// The exact ELIOT adapter implementation or bundle the route uses.
    pub adapter_id: String,
    /// Requested provider and model. A request, never an observation.
    pub provider_and_model_request: String,
    /// Requested authentication profile class.
    pub auth_profile_class: String,
    /// Requested billing mode.
    pub billing_mode: String,
    /// Identity the route is configured to execute under.
    pub execution_identity: ExecutionIdentity,
    /// User Broker class the route requires before it may run.
    pub required_user_broker_class: String,
    /// Reasoning/tool/context serializer fingerprint the route assumes.
    pub serializer_fingerprint: String,
    /// Privacy classes the route is allowed to observe.
    pub privacy_classes: Vec<String>,
    /// Quota sources the route may consume.
    pub quota_sources: Vec<String>,
    /// Capability profile the route requires to be admitted.
    pub required_capability_profile_ref: String,
}

impl RuntimeRoute {
    /// Returns whether the route definition is a usable intent record.
    ///
    /// A blank or control-bearing identity field is not a route: admitting it
    /// would key the registry on an unusable identity instead of failing.
    ///
    /// The declared [`ExecutionIdentity`] is mandatory by construction: it is
    /// a non-optional enum, so every route names exactly one of `service`,
    /// `interactive_user`, or `remote` and none can omit it. I10-04's pairing
    /// requirement — "`interactive_user` routes ... run through the authorized
    /// User Broker" — is already covered by `required_user_broker_class` being
    /// in the required-identity list above: an `interactive_user` route that
    /// names no User Broker class is blank there and is refused here, and
    /// `define_route` / `record_receipt` admit nothing that fails this.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        [
            &self.route_id,
            &self.adapter_id,
            &self.provider_and_model_request,
            &self.auth_profile_class,
            &self.billing_mode,
            &self.required_user_broker_class,
            &self.serializer_fingerprint,
            &self.required_capability_profile_ref,
        ]
        .iter()
        .all(|value| is_identity_text(value))
            && self
                .privacy_classes
                .iter()
                .chain(self.quota_sources.iter())
                .all(|value| is_identity_text(value))
    }
}

/// Installation-layer identity that completes the route fingerprint.
///
/// These are the four I3.4 identity layers outside the route itself: host
/// family, adapter, protocol/transport and runtime instance. They are
/// discovered build/runtime artifacts owned by the Governor, not values the
/// route may assume, so they are required rather than optional.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteInstallationIdentity {
    /// Host family the runtime belongs to.
    pub host_family: String,
    /// Content hash of the exact adapter implementation or bundle.
    pub adapter_hash: String,
    /// Protocol kind, such as App Server or ACP.
    pub protocol_kind: String,
    /// Transport kind, such as stdio, HTTP+SSE or NDJSON sidecar.
    pub transport_kind: String,
    /// Content hash of the exact runtime executable or package.
    pub runtime_hash: String,
    /// Operating-system architecture of the runtime instance.
    pub os_architecture: String,
    /// Tool-call ID and role ordering semantics of the adapter.
    pub tool_call_id_and_role_ordering: String,
    /// Reasoning continuation and compaction behavior of the runtime.
    pub reasoning_continuation_and_compaction: String,
    /// Feature flags and behaviour-affecting tool/context profile hashes.
    pub feature_flags_and_behavior_affecting_profiles: String,
}

impl RouteInstallationIdentity {
    /// Returns whether every installation identity is present and usable.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        [
            &self.host_family,
            &self.adapter_hash,
            &self.protocol_kind,
            &self.transport_kind,
            &self.runtime_hash,
            &self.os_architecture,
            &self.tool_call_id_and_role_ordering,
            &self.reasoning_continuation_and_compaction,
            &self.feature_flags_and_behavior_affecting_profiles,
        ]
        .iter()
        .all(|value| is_identity_text(value))
    }
}

/// One identity layer that can make dependent evidence stale (I3.4).
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RouteIdentityLayer {
    /// Host family.
    HostFamily,
    /// Adapter identity or implementation hash.
    Adapter,
    /// Protocol and transport kind.
    ProtocolTransport,
    /// Operating-system architecture of the runtime instance.
    OsArchitecture,
    /// Runtime instance hash.
    RuntimeInstance,
    /// Provider and model route.
    ProviderModelRoute,
    /// Authentication profile class.
    AuthProfileClass,
    /// Billing mode.
    BillingMode,
    /// Message serializer or chat template fingerprint.
    Serializer,
    /// Tool-call ID and role ordering semantics.
    ToolCallOrdering,
    /// Reasoning continuation and compaction behavior.
    ReasoningContinuation,
    /// Feature flags and behaviour-affecting profile hashes.
    FeatureFlags,
    /// Declared execution identity and the User Broker class it is delegated
    /// to.
    ///
    /// I10-04: "The two are separate `RuntimeRoute` fingerprints and
    /// continuity does not transfer silently between them." Without this layer
    /// a `service` and an `interactive_user` route over one adapter and
    /// provider would report no divergence at all.
    ExecutionIdentityBroker,
}

/// All route semantics that can change behaviour (I3.4 `RouteFingerprint`).
///
/// This is a comparable value, not a digest: I3.4 requires the fingerprint to
/// *include* these semantics, and exact equality over these fields is what
/// decides staleness. Task Policy/Config snapshots, privacy classes and budget
/// envelopes are referenced elsewhere and are deliberately not folded in, so
/// an unrelated policy edit does not invalidate route capability evidence.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBehaviorFingerprint {
    /// Host family.
    pub host_family: String,
    /// Adapter identity.
    pub adapter_id: String,
    /// Protocol kind.
    pub protocol_kind: String,
    /// Transport kind.
    pub transport_kind: String,
    /// Runtime instance hash.
    pub runtime_hash: String,
    /// Adapter implementation hash.
    pub adapter_hash: String,
    /// Requested provider and model.
    pub provider_and_model_request: String,
    /// Authentication profile class.
    pub auth_profile_class: String,
    /// Billing mode.
    pub billing_mode: String,
    /// Identity the route is configured to execute under.
    pub execution_identity: ExecutionIdentity,
    /// User Broker class this route is delegated to.
    ///
    /// Carried beside `execution_identity` rather than folded into it, so
    /// re-pointing an `interactive_user` route at a different broker class
    /// moves the fingerprint too: I10-04 makes "the two are separate
    /// `RuntimeRoute` fingerprints".
    pub required_user_broker_class: String,
    /// Message serializer or chat template fingerprint.
    pub serializer_fingerprint: String,
    /// Tool-call ID and role ordering semantics.
    pub tool_call_id_and_role_ordering: String,
    /// Reasoning continuation and compaction behavior.
    pub reasoning_continuation_and_compaction: String,
    /// Feature flags and behaviour-affecting tool/context profile hashes.
    pub feature_flags_and_behavior_affecting_profiles: String,
}

impl RouteBehaviorFingerprint {
    /// Derives the behaviour fingerprint of one route on one installation.
    #[must_use]
    pub fn of(route: &RuntimeRoute, installation: &RouteInstallationIdentity) -> Self {
        Self {
            host_family: installation.host_family.clone(),
            adapter_id: route.adapter_id.clone(),
            protocol_kind: installation.protocol_kind.clone(),
            transport_kind: installation.transport_kind.clone(),
            runtime_hash: installation.runtime_hash.clone(),
            adapter_hash: installation.adapter_hash.clone(),
            provider_and_model_request: route.provider_and_model_request.clone(),
            auth_profile_class: route.auth_profile_class.clone(),
            billing_mode: route.billing_mode.clone(),
            execution_identity: route.execution_identity,
            required_user_broker_class: route.required_user_broker_class.clone(),
            serializer_fingerprint: route.serializer_fingerprint.clone(),
            tool_call_id_and_role_ordering: installation.tool_call_id_and_role_ordering.clone(),
            reasoning_continuation_and_compaction: installation
                .reasoning_continuation_and_compaction
                .clone(),
            feature_flags_and_behavior_affecting_profiles: installation
                .feature_flags_and_behavior_affecting_profiles
                .clone(),
        }
    }

    /// Returns every behaviour-changing layer on which two route fingerprints
    /// differ.
    ///
    /// This is the route-identity half of the staleness comparison: it covers
    /// all semantics I3.4 lists as behaviour-changing, including the layers an
    /// evidence scope does not carry (host family, protocol/transport,
    /// tool-call ordering, reasoning continuation/compaction, declared
    /// execution identity and the User Broker class it is delegated to).
    #[must_use]
    pub fn diverging_layers(&self, other: &Self) -> Vec<RouteIdentityLayer> {
        let mut layers = Vec::new();
        let mut record = |layer: RouteIdentityLayer, differs: bool| {
            if differs {
                layers.push(layer);
            }
        };
        record(
            RouteIdentityLayer::HostFamily,
            self.host_family != other.host_family,
        );
        record(
            RouteIdentityLayer::Adapter,
            self.adapter_id != other.adapter_id || self.adapter_hash != other.adapter_hash,
        );
        record(
            RouteIdentityLayer::ProtocolTransport,
            self.protocol_kind != other.protocol_kind
                || self.transport_kind != other.transport_kind,
        );
        record(
            RouteIdentityLayer::RuntimeInstance,
            self.runtime_hash != other.runtime_hash,
        );
        record(
            RouteIdentityLayer::ProviderModelRoute,
            self.provider_and_model_request != other.provider_and_model_request,
        );
        record(
            RouteIdentityLayer::AuthProfileClass,
            self.auth_profile_class != other.auth_profile_class,
        );
        record(
            RouteIdentityLayer::BillingMode,
            self.billing_mode != other.billing_mode,
        );
        // Declared execution identity and the User Broker class it is delegated
        // to are one identity layer: a change to either names the same layer
        // once, so an interactive_user route and a service route over one
        // adapter and provider never share a fingerprint (I10-04).
        record(
            RouteIdentityLayer::ExecutionIdentityBroker,
            self.execution_identity != other.execution_identity
                || self.required_user_broker_class != other.required_user_broker_class,
        );
        record(
            RouteIdentityLayer::Serializer,
            self.serializer_fingerprint != other.serializer_fingerprint,
        );
        record(
            RouteIdentityLayer::ToolCallOrdering,
            self.tool_call_id_and_role_ordering != other.tool_call_id_and_role_ordering,
        );
        record(
            RouteIdentityLayer::ReasoningContinuation,
            self.reasoning_continuation_and_compaction
                != other.reasoning_continuation_and_compaction,
        );
        record(
            RouteIdentityLayer::FeatureFlags,
            self.feature_flags_and_behavior_affecting_profiles
                != other.feature_flags_and_behavior_affecting_profiles,
        );
        layers
    }
}

/// Versioned canonical material the effective route key is computed over.
///
/// It carries the whole [`RouteBehaviorFingerprint`] value, never a subset of
/// it, so the key cannot collapse two behaviour-different routes onto one.
#[derive(Serialize)]
struct EffectiveRouteKeyMaterial<'a> {
    domain_separator: &'static str,
    fingerprint: &'a RouteBehaviorFingerprint,
}

/// Computes the complete effective route key of one route fingerprint.
///
/// This is the single keying function for routing evidence, capability lookup,
/// and outcome-profile lookup: it hashes the canonical bytes of the complete
/// behaviour fingerprint, so any behaviour-affecting difference - serializer or
/// chat template, tool-call ID / role ordering, reasoning
/// continuation/compaction, feature-flag or tool/context profile hashes, or
/// any identity layer - yields a different key, and no evidence recorded under
/// one can be found under the other.
///
/// # Errors
///
/// Returns [`RouteRegistryError::DigestComputation`] when the canonical
/// material cannot be serialized or the resulting hex is not a canonical
/// lowercase SHA-256 digest.
pub fn effective_route_key(
    fingerprint: &RouteBehaviorFingerprint,
) -> Result<LowercaseSha256, RouteRegistryError> {
    let material = EffectiveRouteKeyMaterial {
        domain_separator: EFFECTIVE_ROUTE_KEY_DOMAIN,
        fingerprint,
    };
    let bytes =
        canonical_json_bytes(&material).map_err(|_| RouteRegistryError::DigestComputation)?;
    // `LowercaseSha256` exposes no public constructor: its own deserializer is
    // the validating boundary, and `sha256_hex` output always satisfies it, so
    // this cannot fail in practice. The failure is still propagated rather
    // than unwrapped or replaced by a sentinel digest.
    serde_json::from_value::<LowercaseSha256>(serde_json::Value::String(sha256_hex(&bytes)))
        .map_err(|_| RouteRegistryError::DigestComputation)
}

/// Returns the identity layers on which two evidence scopes differ.
///
/// This is the comparison I3.4 requires for staleness: it is evaluated against
/// the scope the current route presents, so a runtime, adapter, provider,
/// serializer, tool-call-ordering, or reasoning/compaction change names itself
/// here instead of being recorded as a flag somebody may forget to set.
///
/// Every behaviour-changing dimension of [`RouteBehaviorFingerprint`] is a
/// dimension of [`RouteScopeFingerprint`], so no behaviour-changing layer can
/// move outside this report: an evidence scope that is field-complete equal on
/// the current route is the only shape that keeps admitting (issue #1958).
#[must_use]
pub fn diverging_scope_layers(
    stored: &RouteScopeFingerprint,
    current: &RouteScopeFingerprint,
) -> Vec<RouteIdentityLayer> {
    let mut layers = Vec::new();
    if stored.host_family != current.host_family {
        layers.push(RouteIdentityLayer::HostFamily);
    }
    // Adapter identity and adapter implementation hash are one identity layer:
    // a change to either names the same layer once.
    if stored.adapter_id != current.adapter_id || stored.adapter_hash != current.adapter_hash {
        layers.push(RouteIdentityLayer::Adapter);
    }
    if stored.protocol_transport != current.protocol_transport {
        layers.push(RouteIdentityLayer::ProtocolTransport);
    }
    if stored.runtime_hash != current.runtime_hash {
        layers.push(RouteIdentityLayer::RuntimeInstance);
    }
    if stored.os_architecture != current.os_architecture {
        layers.push(RouteIdentityLayer::OsArchitecture);
    }
    if stored.auth_profile_class != current.auth_profile_class {
        layers.push(RouteIdentityLayer::AuthProfileClass);
    }
    if stored.provider_model_route != current.provider_model_route {
        layers.push(RouteIdentityLayer::ProviderModelRoute);
    }
    if stored.tool_call_id_and_role_ordering != current.tool_call_id_and_role_ordering {
        layers.push(RouteIdentityLayer::ToolCallOrdering);
    }
    if stored.reasoning_continuation_and_compaction != current.reasoning_continuation_and_compaction
    {
        layers.push(RouteIdentityLayer::ReasoningContinuation);
    }
    if stored.feature_flags_and_serializer != current.feature_flags_and_serializer {
        layers.push(RouteIdentityLayer::Serializer);
    }
    layers
}

/// Route facts the runtime actually exposed for one attempt.
///
/// `None` is the explicit `unknown` state, and it is explicit in the type: an
/// unexposed fact is an absent value, never an empty string, a sentinel id, or
/// a default that reads as a value. I3.4 is explicit that the observed route
/// must not be reconstructed from the UI selection, the prompt text, or the
/// requested intent, so this type offers no constructor that fills one field
/// from another route's values, and no accessor that substitutes a requested
/// value for an unexposed one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoute {
    /// Provider and model the runtime reported, when it reported them.
    pub provider_and_model: Option<String>,
    /// Authentication profile class the runtime reported.
    pub auth_profile_class: Option<String>,
    /// Billing mode the runtime reported.
    pub billing_mode: Option<String>,
    /// Serializer fingerprint the runtime reported.
    pub serializer_fingerprint: Option<String>,
}

impl ObservedRoute {
    /// Returns the layers the runtime did not expose.
    #[must_use]
    pub fn unknown_layers(&self) -> Vec<RouteIdentityLayer> {
        let mut layers = Vec::new();
        if self.provider_and_model.is_none() {
            layers.push(RouteIdentityLayer::ProviderModelRoute);
        }
        if self.auth_profile_class.is_none() {
            layers.push(RouteIdentityLayer::AuthProfileClass);
        }
        if self.billing_mode.is_none() {
            layers.push(RouteIdentityLayer::BillingMode);
        }
        if self.serializer_fingerprint.is_none() {
            layers.push(RouteIdentityLayer::Serializer);
        }
        layers
    }

    /// Returns the observed layers that contradict the requested route.
    ///
    /// Divergence is reported, never repaired: an observed route that differs
    /// from the request is a fact about the runtime, and the two stay separate.
    #[must_use]
    pub fn diverging_layers(&self, requested: &RuntimeRoute) -> Vec<RouteIdentityLayer> {
        let mut layers = Vec::new();
        if self
            .provider_and_model
            .as_deref()
            .is_some_and(|observed| observed != requested.provider_and_model_request)
        {
            layers.push(RouteIdentityLayer::ProviderModelRoute);
        }
        if self
            .auth_profile_class
            .as_deref()
            .is_some_and(|observed| observed != requested.auth_profile_class)
        {
            layers.push(RouteIdentityLayer::AuthProfileClass);
        }
        if self
            .billing_mode
            .as_deref()
            .is_some_and(|observed| observed != requested.billing_mode)
        {
            layers.push(RouteIdentityLayer::BillingMode);
        }
        if self
            .serializer_fingerprint
            .as_deref()
            .is_some_and(|observed| observed != requested.serializer_fingerprint)
        {
            layers.push(RouteIdentityLayer::Serializer);
        }
        layers
    }
}

/// One route attempt's requested and observed route, stored separately.
///
/// The receipt pairs the configured [`RuntimeRoute`] with what the runtime
/// exposed. Because the observed fields are stored independently, a runtime
/// that reports nothing leaves the receipt explicitly `unknown` instead of
/// carrying the request forward as if it were an observation.
///
/// `requested` is populated from planning/configuration and `observed` only
/// from an evidence-bearing observation, and
/// [`CapabilityRouteRegistry::record_receipt`] refuses a receipt whose
/// `evidence_refs` name none: there is no constructor path that fills an
/// observed field from the requested route, a UI selection, or prompt text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActualRouteReceipt {
    /// Route identity this receipt belongs to.
    pub route_id: String,
    /// The requested route intent, from planning/configuration.
    pub requested: RuntimeRoute,
    /// The observed route, with `unknown` preserved as `None`.
    pub observed: ObservedRoute,
    /// Behaviour fingerprint of the requested route on the current installation.
    pub requested_fingerprint: RouteBehaviorFingerprint,
    /// Installation identity the fingerprint was derived on.
    pub installation: RouteInstallationIdentity,
    /// Observation time of the observed route.
    pub observed_at: u64,
    /// Evidence-bearing observation references (runtime handshake, transport
    /// metadata, or equivalent) supporting the observed route facts. At
    /// least one is required before the receipt is retained.
    pub evidence_refs: Vec<String>,
}

impl ActualRouteReceipt {
    /// Builds one receipt from the requested route and the exposed facts.
    #[must_use]
    pub fn new(
        requested: RuntimeRoute,
        installation: RouteInstallationIdentity,
        observed: ObservedRoute,
        observed_at: u64,
        evidence_refs: Vec<String>,
    ) -> Self {
        let route_id = requested.route_id.clone();
        let requested_fingerprint = RouteBehaviorFingerprint::of(&requested, &installation);
        Self {
            route_id,
            requested,
            observed,
            requested_fingerprint,
            installation,
            observed_at,
            evidence_refs,
        }
    }

    /// Returns the evidence scope the current route actually presents.
    ///
    /// The scope is the *complete effective* route identity, not a
    /// provider/model label: it carries every behaviour-changing group of
    /// [`RouteBehaviorFingerprint`], so capability evidence recorded under one
    /// serializer or one tool-call/role ordering cannot admit the other
    /// (issue #1958). Installation-side groups come from
    /// [`RouteInstallationIdentity`], which is the Governor's own discovered
    /// build/runtime artifact, not a value the route may assume.
    ///
    /// The scope exists only when the runtime exposed every route-side
    /// dimension admission compares. When any of them is `unknown` the scope
    /// is `None`: a scope assembled from the request instead would be exactly
    /// the silent inference I3.4 forbids.
    #[must_use]
    pub fn current_scope(&self) -> Option<RouteScopeFingerprint> {
        self.observed
            .auth_profile_class
            .clone()
            .zip(self.observed.provider_and_model.clone())
            .zip(self.observed.billing_mode.clone())
            .zip(self.observed.serializer_fingerprint.clone())
            .map(
                // `_billing`: the evidence `scope_fingerprint` has no billing
                // field, because I3.4's mandatory stale set is
                // runtime/adapter/provider/serializer. Billing still takes part
                // in the requested-vs-observed comparison below and in the
                // complete effective route key; it is not part of the evidence
                // scope and must not silently become one.
                |(((auth, provider), _billing), serializer)| RouteScopeFingerprint {
                    host_family: Some(self.requested_fingerprint.host_family.clone()),
                    adapter_id: Some(self.requested_fingerprint.adapter_id.clone()),
                    protocol_transport: Some(format!(
                        "{}|{}",
                        self.requested_fingerprint.protocol_kind,
                        self.requested_fingerprint.transport_kind
                    )),
                    runtime_hash: Some(self.requested_fingerprint.runtime_hash.clone()),
                    adapter_hash: Some(self.requested_fingerprint.adapter_hash.clone()),
                    os_architecture: Some(self.installation.os_architecture.clone()),
                    auth_profile_class: Some(auth),
                    provider_model_route: Some(provider),
                    tool_call_id_and_role_ordering: Some(
                        self.requested_fingerprint
                            .tool_call_id_and_role_ordering
                            .clone(),
                    ),
                    reasoning_continuation_and_compaction: Some(
                        self.requested_fingerprint
                            .reasoning_continuation_and_compaction
                            .clone(),
                    ),
                    feature_flags_and_serializer: Some(format!(
                        "{serializer}|{}",
                        self.requested_fingerprint
                            .feature_flags_and_behavior_affecting_profiles
                    )),
                },
            )
    }
}

/// Rejected route registry inputs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteRegistryError {
    /// The route definition is not a usable intent record.
    #[error("route definition is not well formed")]
    RouteNotWellFormed,
    /// The installation identity is missing a required dimension.
    #[error("installation identity is not well formed")]
    InstallationNotWellFormed,
    /// The receipt's route identity contradicts its requested route.
    #[error("receipt route identity does not match the requested route")]
    ReceiptRouteMismatch,
    /// The canonical material of the complete effective route key could not be
    /// built. The failure is reported, never replaced by a sentinel key.
    #[error("effective route key digest could not be computed")]
    DigestComputation,
    /// The observed route carries no evidence-bearing observation reference.
    ///
    /// I3.4 admits only a runtime handshake, transport metadata, or an
    /// equivalent evidence-bearing observation as the source of an observed
    /// route, so a receipt naming none is refused whole rather than retained
    /// as an unsupported observation.
    #[error("observed route requires at least one evidence-bearing observation reference")]
    ObservationEvidenceUnproven,
}

/// Evidence status, source and expiry shown with a route admission decision.
///
/// Production admission is not a boolean, so the decision carries the exact
/// status, provenance and expiry of the evidence that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteEvidenceSummary {
    /// Capability the evidence is for.
    pub capability: String,
    /// Claim status of the record.
    pub status: CapabilityStatus,
    /// Provenance of the record.
    pub source: CapabilitySource,
    /// Observation time of the record.
    pub observed_at: u64,
    /// Reached expiry of the record, when it has one.
    pub expires_at: Option<u64>,
    /// Scope the record was captured on.
    pub scope_fingerprint: RouteScopeFingerprint,
}

impl From<&CapabilityEvidenceRecord> for RouteEvidenceSummary {
    fn from(record: &CapabilityEvidenceRecord) -> Self {
        Self {
            capability: record.skill_id.clone(),
            status: record.status,
            source: record.source,
            observed_at: record.observed_at,
            expires_at: record.expires_at,
            scope_fingerprint: record.scope_fingerprint.clone(),
        }
    }
}

/// Why the Governor refused to admit a route.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteRefusalReason {
    /// The runtime exposed no usable route identity, so no evidence scope
    /// exists to compare against.
    ObservedRouteUnknown,
    /// Evidence exists, but not for the current runtime/adapter/serializer
    /// identity: the route must be requalified on the new scope.
    EvidenceStale,
    /// Exact-fingerprint `broken`, `unsupported` or `degraded` evidence
    /// restricts the route.
    EvidenceRestrictive,
    /// No evidence record exists for the required capability.
    EvidenceAbsent,
}

/// Whether the current evidence admits the route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "decision", deny_unknown_fields)]
pub enum RouteAdmissionDecision {
    /// Fresh exact-fingerprint positive evidence admits the route.
    Admitted {
        /// The admitting evidence, with its status, source and expiry.
        evidence: RouteEvidenceSummary,
    },
    /// The route is not admitted for production work.
    Refused {
        /// The reason admission was refused.
        reason: RouteRefusalReason,
        /// Identity layers on which the retained evidence differs from the
        /// current route, when the refusal is a scope mismatch.
        diverging_layers: Vec<RouteIdentityLayer>,
        /// Observed route layers the runtime did not expose, when the refusal
        /// is an unknown observed route.
        unknown_layers: Vec<RouteIdentityLayer>,
        /// Observed route layers that contradict the request.
        observed_diverging_layers: Vec<RouteIdentityLayer>,
        /// Behaviour-changing route layers that moved since the previously
        /// retained receipt for this route, empty on the first observation.
        route_layers_changed: Vec<RouteIdentityLayer>,
        /// Evidence considered by the decision, including non-admitting claims.
        evidence: Vec<RouteEvidenceSummary>,
    },
}

/// One derived production-admission decision for a route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteAdmission {
    /// Route identity the decision is about.
    pub route_id: String,
    /// Behaviour fingerprint of the requested route on the current installation.
    pub requested_fingerprint: RouteBehaviorFingerprint,
    /// Complete effective route key this decision was made on. Routing
    /// evidence and downstream lookups join on this value, so a decision can
    /// only be attributed to the exact behaviour stack that produced it.
    pub effective_route_key: LowercaseSha256,
    /// The derived decision, with the evidence that produced it.
    pub decision: RouteAdmissionDecision,
}

/// Sample counts of one route's derived empirical outcome profile (I3.4).
///
/// `unknown` is a real count, not an absence: a sample whose outcome was never
/// reconciled must stay visible so aggregated success cannot hide it.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOutcomeCounts {
    /// Samples whose output was verified complete.
    pub verified_complete: u32,
    /// Samples that finished with a partial result.
    pub partial: u32,
    /// Samples that failed.
    pub failed: u32,
    /// Samples whose outcome was never established.
    pub unknown: u32,
}

/// One route's derived empirical outcome profile (I3.4
/// `RouteOutcomeProfile`).
///
/// This is a profile, never a capability or proof by itself. It is stored and
/// looked up under the complete effective route key
/// ([`RouteOutcomeProfileIndex`]), so a profile measured on one serializer or
/// one tool-call/role ordering is never returned for another. Every composite
/// measure is carried as named, evidence-linked text because this type owns no
/// measurement taxonomy: a number without its measure name, unit and source
/// would be an invented value.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOutcomeProfile {
    /// Task class and recipe the samples were taken for.
    pub task_class_and_recipe: String,
    /// Governance and environment profile the samples were taken under.
    pub governance_and_environment_profile: String,
    /// Sample window and the observed distribution over it.
    pub sample_window_and_distribution: String,
    /// Verified/complete, partial, failed and unknown sample counts.
    pub outcome_counts: RouteOutcomeCounts,
    /// Verifier coverage and quality measures, named and sourced.
    pub verifier_coverage_and_quality_measures: String,
    /// Latency, cost, quota and cleanup measures, named and sourced.
    pub latency_cost_quota_and_cleanup_measures: String,
    /// Continuation, context and route-mismatch failures observed.
    pub continuation_context_and_route_mismatch_failures: String,
    /// Independence and common-lineage notes for the sampled work.
    pub independence_and_common_lineage_notes: String,
    /// Confidence, coverage and known biases of the profile.
    pub confidence_coverage_and_known_biases: String,
    /// Evidence references backing the profile.
    pub evidence_refs: Vec<String>,
    /// Validity bound and the dependencies that make the profile stale.
    pub valid_until_and_stale_dependencies: String,
}

/// Governor-owned outcome profiles keyed by the complete effective route
/// fingerprint (I3.4, issue #1958).
///
/// The key is [`effective_route_key`] over the complete
/// [`RouteBehaviorFingerprint`], not a provider/model label, so two routes that
/// differ only in serializer or in tool-call ID / role ordering hold separate
/// profiles and a lookup never returns another route's samples.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteOutcomeProfileIndex {
    profiles: HashMap<LowercaseSha256, RouteOutcomeProfile>,
}

impl RouteOutcomeProfileIndex {
    /// Creates an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Records one route's profile under its complete effective route key.
    ///
    /// A later record for the same key replaces the retained profile: the key
    /// is the whole identity, so there is no sibling to reconcile against.
    ///
    /// # Errors
    ///
    /// Returns [`RouteRegistryError::DigestComputation`] when the effective
    /// route key cannot be built; the profile is then not stored at all rather
    /// than stored under a placeholder key.
    pub fn record(
        &mut self,
        fingerprint: &RouteBehaviorFingerprint,
        profile: RouteOutcomeProfile,
    ) -> Result<(), RouteRegistryError> {
        self.profiles
            .insert(effective_route_key(fingerprint)?, profile);
        Ok(())
    }

    /// Returns the profile recorded for the exact complete effective route.
    ///
    /// `None` means no profile was recorded for this fingerprint, even when a
    /// provider/model-identical sibling exists under a different key.
    ///
    /// # Errors
    ///
    /// Returns [`RouteRegistryError::DigestComputation`] when the effective
    /// route key cannot be built.
    pub fn lookup(
        &self,
        fingerprint: &RouteBehaviorFingerprint,
    ) -> Result<Option<&RouteOutcomeProfile>, RouteRegistryError> {
        Ok(self.profiles.get(&effective_route_key(fingerprint)?))
    }

    /// Returns the number of distinct effective route keys retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Returns true when no profile is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

/// Governor-owned registry of route intent, observed routes, and the evidence
/// admission derived from both.
///
/// The registry owns configured intent and the retained receipts. It owns no
/// capability truth of its own: every admission and every restriction is
/// derived from the retained [`CapabilityRegistry`] evidence compared against
/// the current identity.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRouteRegistry {
    routes: BTreeMap<String, RuntimeRoute>,
    receipts: BTreeMap<String, ActualRouteReceipt>,
}

impl CapabilityRouteRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }

    /// Defines or revises one route's configured intent.
    ///
    /// # Errors
    ///
    /// Returns [`RouteRegistryError`] when the definition is not a usable
    /// intent record; a malformed route never enters the registry.
    pub fn define_route(&mut self, route: RuntimeRoute) -> Result<(), RouteRegistryError> {
        if !route.is_well_formed() {
            return Err(RouteRegistryError::RouteNotWellFormed);
        }
        self.routes.insert(route.route_id.clone(), route);
        Ok(())
    }

    /// Returns the configured intent for one route.
    #[must_use]
    pub fn route(&self, route_id: &str) -> Option<&RuntimeRoute> {
        self.routes.get(route_id)
    }

    /// Returns every defined route, ordered by route identity.
    #[must_use]
    pub fn routes(&self) -> &BTreeMap<String, RuntimeRoute> {
        &self.routes
    }

    /// Returns the retained receipt for one route.
    #[must_use]
    pub fn receipt(&self, route_id: &str) -> Option<&ActualRouteReceipt> {
        self.receipts.get(route_id)
    }

    /// Records the requested and observed route for one attempt.
    ///
    /// # Errors
    ///
    /// Returns [`RouteRegistryError`] when the receipt's route identity
    /// contradicts its own requested route, when either identity is malformed,
    /// or when the observed route names no evidence-bearing observation
    /// reference. The receipt is rejected whole; a partial receipt is never
    /// stored.
    pub fn record_receipt(
        &mut self,
        receipt: ActualRouteReceipt,
    ) -> Result<(), RouteRegistryError> {
        if receipt.route_id != receipt.requested.route_id {
            return Err(RouteRegistryError::ReceiptRouteMismatch);
        }
        if !receipt.requested.is_well_formed() {
            return Err(RouteRegistryError::RouteNotWellFormed);
        }
        if !receipt.installation.is_well_formed() {
            return Err(RouteRegistryError::InstallationNotWellFormed);
        }
        // An observed route exists only where a runtime handshake, transport
        // metadata, or an equivalent evidence-bearing observation produced it.
        // A receipt that names none is refused instead of being retained with
        // an unsupported observation.
        if receipt.evidence_refs.is_empty()
            || !receipt
                .evidence_refs
                .iter()
                .all(|reference| is_identity_text(reference))
        {
            return Err(RouteRegistryError::ObservationEvidenceUnproven);
        }
        self.define_route(receipt.requested.clone())?;
        self.receipts.insert(receipt.route_id.clone(), receipt);
        Ok(())
    }

    /// Records one route attempt and derives its production admission.
    ///
    /// Admission is derived, never asserted. The receipt's requested route
    /// becomes configured intent, the observed route is retained separately,
    /// and the capability is admitted only when the retained evidence holds a
    /// fresh exact-fingerprint positive on the scope the *current* route
    /// presents. `declared` / `imported_legacy_declaration` evidence never
    /// admits and exact-fingerprint `broken`/`unsupported`/`degraded` evidence
    /// overrides a declared claim, because the decision reuses the verified
    /// predicates of [`CapabilityRegistry::admit_production_route`] instead of
    /// re-deriving admissibility here.
    ///
    /// Staleness needs no flag: an adapter-hash or serializer change moves the
    /// derived scope, the exact-fingerprint match fails, and the refusal names
    /// the diverging layers so the route can be requalified.
    ///
    /// An execution-identity move is reported the same way, as an explicit
    /// changed layer rather than silent continuity: `route_layers_changed`
    /// names [`RouteIdentityLayer::ExecutionIdentityBroker`] whenever the
    /// previously retained receipt for this `route_id` declared a different
    /// execution identity or User Broker class. That layer alone also refuses
    /// admission: the evidence scope carries no execution identity, so retained
    /// records still match the current scope exactly across the move, and
    /// without the refusal the route would be admitted under fresh evidence
    /// observed for a different identity. The route must requalify under the
    /// identity it now declares. This is the I10-04 "the two are separate
    /// `RuntimeRoute` fingerprints and continuity does not transfer silently
    /// between them" rule, derived rather than asserted.
    ///
    /// # Errors
    ///
    /// Returns [`RouteRegistryError`] when the receipt is not a consistent,
    /// well-formed route observation, or when the complete effective route key
    /// of the current fingerprint cannot be built.
    pub fn admit_route(
        &mut self,
        evidence: &CapabilityRegistry,
        receipt: ActualRouteReceipt,
        capability: &str,
        now: u64,
    ) -> Result<RouteAdmission, RouteRegistryError> {
        let route_id = receipt.route_id.clone();
        let prior = self
            .receipts
            .get(&route_id)
            .map(|prior| prior.requested_fingerprint.clone());
        self.record_receipt(receipt)?;
        let Some(retained) = self.receipts.get(&route_id) else {
            return Err(RouteRegistryError::ReceiptRouteMismatch);
        };
        Self::derive_admission(evidence, retained, prior.as_ref(), capability, now)
    }

    /// Derives admission for one already recorded route receipt.
    ///
    /// # Errors
    ///
    /// Returns [`RouteRegistryError::DigestComputation`] when the complete
    /// effective route key of the current fingerprint cannot be built; the
    /// decision is then not produced at all, rather than reported under a
    /// placeholder key.
    fn derive_admission(
        evidence: &CapabilityRegistry,
        receipt: &ActualRouteReceipt,
        prior_fingerprint: Option<&RouteBehaviorFingerprint>,
        capability: &str,
        now: u64,
    ) -> Result<RouteAdmission, RouteRegistryError> {
        let requested_fingerprint =
            RouteBehaviorFingerprint::of(&receipt.requested, &receipt.installation);
        let key = effective_route_key(&requested_fingerprint)?;
        let route_layers_changed = prior_fingerprint
            .map(|prior| prior.diverging_layers(&requested_fingerprint))
            .unwrap_or_default();
        let retained: Vec<&CapabilityEvidenceRecord> = evidence
            .records()
            .iter()
            .filter(|record| record.skill_id == capability)
            .collect();
        let summaries: Vec<RouteEvidenceSummary> =
            retained.iter().map(|record| (*record).into()).collect();
        let observed_diverging_layers = receipt.observed.diverging_layers(&receipt.requested);
        let unknown_layers = receipt.observed.unknown_layers();
        // I10-04: "The two are separate `RuntimeRoute` fingerprints and
        // continuity does not transfer silently between them." The evidence
        // scope carries no execution identity, so prior evidence still matches
        // the current scope exactly across an identity change. Admission must
        // therefore refuse on the identity layer itself rather than let the
        // unchanged scope carry the route over silently; the route requalifies
        // under evidence observed for the identity it now declares.
        let identity_changed =
            route_layers_changed.contains(&RouteIdentityLayer::ExecutionIdentityBroker);
        let Some(current) = receipt.current_scope() else {
            return Ok(RouteAdmission {
                route_id: receipt.route_id.clone(),
                requested_fingerprint,
                effective_route_key: key,
                decision: RouteAdmissionDecision::Refused {
                    reason: RouteRefusalReason::ObservedRouteUnknown,
                    diverging_layers: Vec::new(),
                    unknown_layers,
                    observed_diverging_layers,
                    route_layers_changed,
                    evidence: summaries,
                },
            });
        };
        let on_current: Vec<&CapabilityEvidenceRecord> = retained
            .iter()
            .copied()
            .filter(|record| record.scope_fingerprint.exact_match(&current))
            .collect();
        let admitting = on_current.iter().find(|record| {
            matches!(
                record.status,
                CapabilityStatus::ProbePassed | CapabilityStatus::Observed
            ) && record.source.is_admissible_evidence()
                && record.is_time_fresh(now)
                && evidence.admit_production_route(capability, &current, now)
        });
        if let Some(record) = admitting.filter(|_| !identity_changed) {
            return Ok(RouteAdmission {
                route_id: receipt.route_id.clone(),
                requested_fingerprint,
                effective_route_key: key,
                decision: RouteAdmissionDecision::Admitted {
                    evidence: (*record).into(),
                },
            });
        }
        let restrictive = on_current.iter().any(|record| {
            matches!(
                record.status,
                CapabilityStatus::Broken
                    | CapabilityStatus::Unsupported
                    | CapabilityStatus::Degraded
            ) && record.is_time_fresh(now)
        });
        let diverging_layers = retained
            .iter()
            .flat_map(|record| diverging_scope_layers(&record.scope_fingerprint, &current))
            .collect();
        let reason = if restrictive {
            RouteRefusalReason::EvidenceRestrictive
        } else if identity_changed {
            // Prior evidence was observed under a different declared execution
            // identity. The evidence scope carries no identity, so the retained
            // records still match it exactly; the route is stale for the
            // identity it now declares and must be requalified.
            RouteRefusalReason::EvidenceStale
        } else if retained.is_empty() {
            RouteRefusalReason::EvidenceAbsent
        } else {
            RouteRefusalReason::EvidenceStale
        };
        Ok(RouteAdmission {
            route_id: receipt.route_id.clone(),
            requested_fingerprint,
            effective_route_key: key,
            decision: RouteAdmissionDecision::Refused {
                reason,
                diverging_layers,
                unknown_layers,
                observed_diverging_layers,
                route_layers_changed,
                evidence: summaries,
            },
        })
    }
}
