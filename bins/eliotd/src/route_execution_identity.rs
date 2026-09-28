//! Execution identity and route-fingerprint enforcement for every bridge
//! adapter route (issue #1816).
//!
//! Architecture: I10.3 (execution identity boundary on Windows), I10.4 (Codex
//! subscription/desktop versus service-safe API routes), I10.5 (Claude local
//! sidecar versus Managed Agents), I10.6 (the local server profile),
//! I10.7 (ACP, Antigravity and the generic minimum). A2.3 layering; A0.3 hard
//! boundaries stay fail-closed.
//!
//! Doctrine this cell enforces (I10.3, verbatim): "Every route profile declares
//! `execution_identity = service | interactive_user | remote`. `interactive_user`
//! routes are launched only through the authorized User Broker of I1.3. A bridge
//! cannot silently switch execution identity to obtain subscriptions, desktop
//! state or credentials."
//!
//! ## What this cell owns, and what it does not
//!
//! Route identity stays owned by
//! [`RouteFingerprint`](eliot_agent_api::RouteFingerprint). This module adds
//! **no second route-fingerprint type**: [`DeclaredRoute`] embeds the canonical
//! fingerprint and declares the execution identity and the policy facets the
//! specification requires the persisted route fingerprint to carry. Mapping of
//! the required content onto the record:
//!
//! ```text
//! adapter / runtime version and hash  -> route.adapter, route.adapter_hash,
//!                                       route.runtime_hash
//! account / credential mode          -> route.auth_billing
//! session locator semantics          -> route.continuation_behavior
//! execution identity                 -> execution_identity
//! retention policy                   -> retention_policy
//! network policy                     -> network_policy
//! workspace / scope policy           -> workspace_scope_policy
//! ```
//!
//! The credential-use mode, retention/billing route, observation domains, and
//! effect ceilings keep their existing owners (I6.15 `CredentialUseBinding` and
//! `CapabilityIntroduction`, I5.26 `ObservationDomainRef`); this record names
//! the declared policy identity, it never mints or widens one of them.
//!
//! Continuity reuses the closed protocol-line owner
//! [`ContinuityKind`](eliot_protocol::ContinuityKind) (I7.15) instead of
//! introducing another continuity vocabulary.
//!
//! ## Registry binding
//!
//! The daemon's capability registry is keyed by the **complete declared route**
//! ([`declared_route_key`]): the canonical fingerprint plus the execution
//! identity plus the policy facets. A `service` route and an
//! `interactive_user` route over the same provider, model, and adapter hash to
//! different keys, so evidence observed under one execution identity is never
//! served to the other — which is exactly the "separate `RuntimeRoute`
//! fingerprints; continuity does not transfer silently between them" boundary
//! I10.4 states. Enforcement on the invoke path is
//! [`enforce_declared_route`](crate::dreamer_model_adapter).

use eliot_agent_api::RouteFingerprint;
use eliot_contracts::{LowercaseSha256, canonical_json_bytes, sha256_hex};
use eliot_protocol::ContinuityKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The execution identity every adapter route must declare (I10.3).
///
/// The closed set is exactly `service`, `interactive_user`, and `remote`; a
/// route declaration is therefore a required, single-valued field, and a route
/// cannot declare none or two of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionIdentity {
    /// Machine/service identity: no interactive desktop state, no inherited
    /// interactive credentials.
    Service,
    /// Bound to one authorized user session. Launches only through the
    /// authorized User Broker (I1.3, I10.3).
    InteractiveUser,
    /// Remote execution under its own explicit credential, billing, retention,
    /// and privacy profile.
    Remote,
}

impl ExecutionIdentity {
    /// The declared identity in this type's serialized (`SCREAMING_SNAKE_CASE`)
    /// spelling, as it appears in the recorded refusal text.
    ///
    /// This is NOT the `execution_identity` spelling the adapter route profiles
    /// carry: `integrations/*/route-profile.json` spells the same three values
    /// `service` / `interactive_user` / `remote` in lower snake case. Nothing
    /// here parses those files, so this accessor is the record's own serialized
    /// form and must not be read as a profile-file parser.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "SERVICE",
            Self::InteractiveUser => "INTERACTIVE_USER",
            Self::Remote => "REMOTE",
        }
    }
}

/// The surface through which one launch reached the daemon.
///
/// The distinction is load-bearing: an `INTERACTIVE_USER` route acquires desktop
/// state, subscriptions, and credentials from the User Broker that owns the
/// interactive session, so a launch that claims that identity without resolving
/// to that broker is refused instead of being treated as equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchAuthority {
    /// `eliotd` or the Kernel is spawning the route process itself.
    DirectDaemonOrKernel,
    /// The launch was delegated through the authorized User Broker that owns the
    /// interactive session.
    UserBrokerDelegated,
}

/// The persisted route fingerprint of one declared adapter route: the canonical
/// [`RouteFingerprint`] plus the declared execution identity and the policy
/// facets that identity governs (I10.3–I10.7).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredRoute {
    /// Canonical route identity: adapter/runtime version and hash,
    /// account/credential mode (`auth_billing`), and session locator semantics
    /// (`continuation_behavior`), plus the serializer/tool/reasoning/feature
    /// behavior-bearing identity.
    pub route: RouteFingerprint,
    /// Exactly one declared execution identity.
    pub execution_identity: ExecutionIdentity,
    /// Retention policy the route runs under (I10.5 records retention and
    /// deletion for a remote route separately from a local one).
    pub retention_policy: String,
    /// Network policy the route runs under.
    pub network_policy: String,
    /// Workspace/scope policy the route runs under.
    pub workspace_scope_policy: String,
}

impl DeclaredRoute {
    /// Validates that the declaration is a usable route record: the canonical
    /// fingerprint validates, and no policy facet is blank or control-bearing.
    ///
    /// # Errors
    ///
    /// Returns [`RouteIdentityError::InvalidDeclaration`] on the first invalid
    /// component.
    pub fn validate(&self) -> Result<(), RouteIdentityError> {
        self.route
            .validate()
            .map_err(|_| RouteIdentityError::InvalidDeclaration("route"))?;
        for (field, value) in [
            ("retention_policy", &self.retention_policy),
            ("network_policy", &self.network_policy),
            ("workspace_scope_policy", &self.workspace_scope_policy),
        ] {
            if value.trim().is_empty() {
                return Err(RouteIdentityError::InvalidDeclaration(field));
            }
            if value.chars().any(char::is_control) {
                return Err(RouteIdentityError::InvalidDeclaration(field));
            }
        }
        Ok(())
    }

    /// The declared account/credential mode, carried by the canonical
    /// fingerprint's `auth_billing` field.
    #[must_use]
    pub fn account_credential_mode(&self) -> &str {
        &self.route.auth_billing
    }

    /// The declared session locator semantics, carried by the canonical
    /// fingerprint's `continuation_behavior` field.
    #[must_use]
    pub fn session_locator_semantics(&self) -> &str {
        &self.route.continuation_behavior
    }
}

/// Typed execution-identity and route-declaration failures. Every arm fails
/// closed before any provider budget is spent.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteIdentityError {
    /// A component of the route declaration is missing or malformed.
    #[error("declared route {0} is not a usable execution-identity declaration")]
    InvalidDeclaration(&'static str),
    /// The invoke carries no route declaration at all.
    #[error(
        "the bound route declares no execution identity, retention/network policy, or workspace/scope policy"
    )]
    RouteNotDeclared,
    /// The declaration names a different route than the bound one.
    #[error("the declared route is not the bound route fingerprint")]
    DeclarationRouteMismatch,
    /// An `INTERACTIVE_USER` route was launched without the authorized User
    /// Broker.
    #[error(
        "an INTERACTIVE_USER route may launch only through the authorized User Broker; direct daemon or kernel launching under a user-desktop identity is rejected"
    )]
    InteractiveUserRequiresUserBroker,
    /// A session was carried across a declared execution-identity,
    /// local-versus-managed adapter, or account-mode change.
    #[error(
        "a session may not be carried across a declared execution identity, local-versus-managed adapter, or account-mode change: the attempt must start as an explicit REHYDRATED new attempt"
    )]
    SessionCarryRequiresRehydration,
}

/// The complete declared-route key: the canonical route fingerprint **and** the
/// declared execution identity and policy facets.
///
/// This is what the daemon's capability registry keys evidence by, so a
/// `service` route and an `interactive_user` route over the same provider/model
/// hash to different keys and can never share one evidence entry or one
/// admission (I10.4: the two are separate `RuntimeRoute` fingerprints).
///
/// # Errors
///
/// Returns [`RouteIdentityError::InvalidDeclaration`] when the declaration does
/// not validate or its canonical bytes cannot be hashed.
pub fn declared_route_key(declared: &DeclaredRoute) -> Result<LowercaseSha256, RouteIdentityError> {
    declared.validate()?;
    let bytes = canonical_json_bytes(declared)
        .map_err(|_| RouteIdentityError::InvalidDeclaration("declared_route"))?;
    serde_json::from_value(serde_json::Value::String(sha256_hex(&bytes)))
        .map_err(|_| RouteIdentityError::InvalidDeclaration("declared_route_key"))
}

/// Admits one launch of a declared route under the stated launch authority.
///
/// An `INTERACTIVE_USER` route is admitted only when the launch resolved to the
/// authorized User Broker. `service` and `remote` routes carry no such
/// requirement and are admitted under either authority; this function never
/// widens a declared identity and never infers one that was not declared.
///
/// # Errors
///
/// Returns [`RouteIdentityError::InvalidDeclaration`] when the declaration does
/// not validate, and [`RouteIdentityError::InteractiveUserRequiresUserBroker`]
/// when an `INTERACTIVE_USER` route is launched directly by the daemon or
/// Kernel.
pub fn admit_declared_launch(
    declared: &DeclaredRoute,
    authority: LaunchAuthority,
) -> Result<(), RouteIdentityError> {
    declared.validate()?;
    if declared.execution_identity == ExecutionIdentity::InteractiveUser
        && authority != LaunchAuthority::UserBrokerDelegated
    {
        return Err(RouteIdentityError::InteractiveUserRequiresUserBroker);
    }
    Ok(())
}

/// The continuity a session may be continued under when moving from one
/// declared route to another.
///
/// The exact same declared route — same canonical fingerprint, same execution
/// identity, same policies — keeps native session identity. Any change is an
/// explicit rehydrated new attempt, which covers the three transitions I10.4,
/// I10.5, and I10.7 name: local-versus-managed adapter, service-versus-
/// interactive identity, and a distinct account/credential mode. Nothing here
/// silently continues a session across such a boundary.
///
/// # Errors
///
/// Returns [`RouteIdentityError::InvalidDeclaration`] when either declaration
/// does not validate.
pub fn declared_continuity(
    from: &DeclaredRoute,
    to: &DeclaredRoute,
) -> Result<ContinuityKind, RouteIdentityError> {
    from.validate()?;
    to.validate()?;
    Ok(if from == to {
        ContinuityKind::NativeResume
    } else {
        ContinuityKind::cross_runtime_transfer_default()
    })
}
