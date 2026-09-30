//! Bridge-local retained route-launch owner (issue #1816, W4).
//!
//! The Governor owns the route registry types and validators; this module owns
//! the bridge contour's own sealed launch record. [`crate::BridgeRunner::attach`]
//! seals it from the genuine post-attach facts — the admitted contour route
//! and installation plus the owner-issued attach binding — and
//! [`crate::BridgeRunner::reconnect`] classifies the live presentation against it
//! through `route_identity_gate::classify_bridge_route_reconnect`. The sealed
//! record is therefore written by a different production step, from different
//! facts, than the live presentation it is compared with: it is an
//! independent retained receipt, never a re-read of the field being
//! fingerprinted.
//!
//! The seal binds continuity to the exact admitted launch: the complete W3
//! route fingerprint and the launch authority (session and activation
//! generation). The replacement connection is deliberately NOT sealed: a
//! reconnect replaces the connection by design, so sealing it would refuse
//! legitimate reconnects. Any route-material move (local/managed adapter,
//! service/interactive identity, distinct account mode, retention/network,
//! session-locator, workspace/scope, serializer) moves the live fingerprint
//! away from the sealed one; any authority move (a session or generation the
//! launch did not admit) moves the live binding away from the sealed one.
//! Either classifies as an explicit rehydrated new attempt — I10.5's "it
//! becomes a `Rehydrated` attempt" — never silent continuity under the
//! previous launch.
//!
//! Proven contour invariant (not an assumption): one contour process derives
//! every presentation from the same fixed declaration source the seal
//! recorded, so the material and authority arms agree on every legitimate
//! path and the guard passes without false refusals. The arms are still
//! genuine violation conditions over distinct independently-acquired objects
//! — the sealed record, the freshly derived declaration, the fresh binding
//! read, and the production-recorded registry receipt — so any presenter or
//! registry divergence refuses instead of continuing silently. A resume with
//! no sealed launch while the core holds a live attach is likewise refused by
//! the caller: continuity without admission is the silent continuation W4
//! forbids.

use eliot_agent_bridge_core::{AttachView, Generation};
use eliot_governor::{RouteBehaviorFingerprint, RouteInstallationIdentity, RuntimeRoute};

/// The sealed route launch one attach admitted (issue #1816, W4).
///
/// Sealed by [`crate::BridgeRunner::attach`] after the core attach succeeds, read by
/// [`crate::BridgeRunner::reconnect`]. The fingerprint is derived with the owner's
/// [`RouteBehaviorFingerprint::of`] over the original launch route and
/// installation; the authority half is the owner-issued attach binding. Only
/// the route identity, the fingerprint, and the launch authority are
/// retained: the replacement connection is excluded on purpose (see the
/// module docs).
#[derive(Clone, Debug)]
pub struct RetainedRouteLaunch {
    route_id: String,
    fingerprint: RouteBehaviorFingerprint,
    launch_session: String,
    launch_generation: Generation,
}

impl RetainedRouteLaunch {
    /// Seals the launch [`crate::BridgeRunner::attach`] just admitted.
    ///
    /// `route`/`installation` are the admitted launch material and `view` is
    /// the owner-issued attach view the core returned for it. Pure
    /// constructor: sealing cannot fail and invents nothing.
    #[must_use]
    pub fn seal(
        route: &RuntimeRoute,
        installation: &RouteInstallationIdentity,
        view: &AttachView,
    ) -> Self {
        let binding = view.binding();
        Self {
            route_id: route.route_id.clone(),
            fingerprint: RouteBehaviorFingerprint::of(route, installation),
            launch_session: binding.session_id().as_str().to_owned(),
            launch_generation: binding.activation_generation(),
        }
    }

    /// Returns the route identity this launch was sealed under.
    #[must_use]
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    /// Returns the sealed launch fingerprint (the W3 bound).
    #[must_use]
    pub const fn fingerprint(&self) -> &RouteBehaviorFingerprint {
        &self.fingerprint
    }

    /// Returns the session the launch admitted.
    #[must_use]
    pub fn launch_session(&self) -> &str {
        &self.launch_session
    }

    /// Returns the activation generation the launch admitted.
    #[must_use]
    pub const fn launch_generation(&self) -> Generation {
        self.launch_generation
    }
}
