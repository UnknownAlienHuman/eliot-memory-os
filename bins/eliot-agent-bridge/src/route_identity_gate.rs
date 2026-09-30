//! Bridge-contour route identity gate (issue #1816).
//!
//! This is the bridge's production caller over the Governor-owned bridge
//! capability registry: every bridge route launch is authorized and recorded
//! here before it runs, and every resume is classified here before it
//! continues. The registry owns the fingerprint and admission derivation;
//! this module owns the bridge's call into it, so the enforcement is
//! reachable from the bridge contour instead of living only inside the
//! registry module.
//!
//! - I10.3: "Every route profile declares `execution_identity = service |
//!   interactive_user | remote`. `interactive_user` routes are launched only
//!   through the authorized User Broker of I1.3. A bridge cannot silently
//!   switch execution identity to obtain subscriptions, desktop state or
//!   credentials."
//! - I10.4: "A ChatGPT-subscription or desktop-profile Codex route declares
//!   `execution_identity = interactive_user` and runs through the authorized
//!   User Broker. ... The two are separate `RuntimeRoute` fingerprints and
//!   continuity does not transfer silently between them."
//! - I10.5: "A local Claude session cannot be silently continued as a
//!   Managed Agent session; it becomes a `Rehydrated` attempt."
//! - I10.7 generic minimum: "working root/scope and route fingerprint".

use crate::route_registry::RetainedRouteLaunch;
use eliot_agent_bridge_core::AttachView;
use eliot_governor::{
    CapabilityRouteRegistry, RouteBehaviorFingerprint, RouteInstallationIdentity,
    RouteRegistryError, RuntimeRoute,
};
use eliot_protocol::ContinuityKind;

/// Authorizes and records one bridge route launch (W1, W3).
///
/// The launch is admitted only through the registry's own validators: the
/// installation identity must be well formed, the route must authorize under
/// the stated User Broker delegation — so an `interactive_user` route
/// submitted without its declared User Broker class is rejected with the
/// registry's typed
/// [`RouteRegistryError::InteractiveUserRequiresUserBroker`](eliot_governor::RouteRegistryError)
/// instead of launching under a daemon user-desktop identity — and the
/// declared route is then defined in the registry. The returned fingerprint
/// is the persisted W3 material: adapter/runtime version and hash,
/// account/credential mode, execution identity and User Broker class,
/// retention/network policy, session locator semantics, and workspace/scope
/// policy. A `service` route and an `interactive_user` route over one
/// adapter therefore persist distinct fingerprints and distinct effective
/// route keys.
///
/// # Errors
///
/// Returns the registry's typed failure when the installation or route is
/// not a usable record, or when an `interactive_user` route bypasses its
/// declared User Broker.
pub fn admit_bridge_route_launch(
    registry: &mut CapabilityRouteRegistry,
    route: &RuntimeRoute,
    installation: &RouteInstallationIdentity,
    delegated_user_broker_class: Option<&str>,
) -> Result<RouteBehaviorFingerprint, RouteRegistryError> {
    if !installation.is_well_formed() {
        return Err(RouteRegistryError::InstallationNotWellFormed);
    }
    route.authorize_launch(delegated_user_broker_class)?;
    registry.define_route(route.clone())?;
    Ok(RouteBehaviorFingerprint::of(route, installation))
}

/// Classifies resuming under `next` after a session ran under `prior` (W4).
///
/// The fingerprints are the complete W3 material, so any local/managed
/// adapter move, any service/interactive identity move, and any distinct
/// account-mode move presented here diverge them. An unchanged fingerprint
/// keeps native resume; any divergence is an explicit
/// [`ContinuityKind::Rehydrated`](eliot_protocol::ContinuityKind) new
/// attempt — I10.5's "it becomes a `Rehydrated` attempt" — never silent
/// continuity under the previous session identity. The bound is the
/// session's launch fingerprint compared with the material presented for this
/// operation: a move the caller never presents is the caller's join (see
/// [`classify_bridge_route_reconnect`]), never continuity granted here.
#[must_use]
pub fn classify_bridge_route_resume(
    prior: &RouteBehaviorFingerprint,
    next: &RouteBehaviorFingerprint,
) -> ContinuityKind {
    if prior == next {
        ContinuityKind::NativeResume
    } else {
        ContinuityKind::Rehydrated
    }
}

/// Classifies a reconnect against the sealed launch and the Governor-retained receipt (W4).
///
/// The bound is the sealed launch [`RetainedRouteLaunch`] that the attach
/// path sealed after the core attach succeeded: the W3 launch fingerprint in
/// `prior` is cross-checked against the seal, so two retained stores must
/// agree with each other. The live side is derived fresh for this operation:
/// `live_route`/`live_installation` are the contour declaration re-derived
/// from the live profile — fingerprinted through the owner's
/// [`RouteBehaviorFingerprint::of`] over the originals, never a digest of a
/// digest — and `live` is a fresh read of the current attach binding.
/// Completeness is judged against the registry's independent receipt set: the
/// retained receipt for the sealed route identity must agree with both the
/// bound and the live fingerprint. That is the owner's `derive_admission`
/// pattern — comparing against the earlier retained receipt rather than the
/// defined intent — with a real production producer: the attach path records
/// the receipt from the genuine attach observation.
///
/// Any local/managed adapter move, any service/interactive identity move, and
/// any distinct account-mode move presented here diverge the complete W3
/// material, and any session or activation-generation move diverges the launch
/// authority, so the resume classifies as an explicit
/// [`ContinuityKind::Rehydrated`](eliot_protocol::ContinuityKind) new
/// attempt — I10.5's "it becomes a `Rehydrated` attempt" — never silent
/// continuity under the previous launch. When the registry retains no receipt
/// for the route, the sealed/live comparison alone applies.
///
/// STITCH (proven contour invariant, not a gap): one contour process derives
/// every presentation from the same fixed declaration source the seal
/// recorded, so the material and authority arms agree on every legitimate
/// path and the guard passes without false refusals. The arms are still
/// genuine violation conditions over distinct independently-acquired objects
/// — the sealed record, the fresh derivation, the fresh binding read, and the
/// production-recorded receipt — so any presenter or registry divergence
/// refuses instead of continuing silently.
#[must_use]
pub fn classify_bridge_route_reconnect(
    sealed: &RetainedRouteLaunch,
    prior: &RouteBehaviorFingerprint,
    registry: &CapabilityRouteRegistry,
    live_route: &RuntimeRoute,
    live_installation: &RouteInstallationIdentity,
    live: &AttachView,
) -> ContinuityKind {
    let live_fingerprint = RouteBehaviorFingerprint::of(live_route, live_installation);
    let bound_intact = prior == sealed.fingerprint();
    let material_moved = classify_bridge_route_resume(sealed.fingerprint(), &live_fingerprint)
        == ContinuityKind::Rehydrated;
    let live_binding = live.binding();
    let authority_moved = sealed.launch_session() != live_binding.session_id().as_str()
        || sealed.launch_generation() != live_binding.activation_generation();
    let retained_diverged = registry.receipt(sealed.route_id()).is_some_and(|receipt| {
        receipt.requested_fingerprint != *prior || receipt.requested_fingerprint != live_fingerprint
    });
    if !bound_intact || material_moved || authority_moved || retained_diverged {
        ContinuityKind::Rehydrated
    } else {
        ContinuityKind::NativeResume
    }
}
