//! Broker-owned one-shot `OpenCode` bootstrap route (issue #2898, step 4).
//!
//! Architecture anchors: I11.8 (the broker authenticates a local peer from OS
//! evidence before it discloses anything), I6.15 (a grant introduces exactly
//! what it names), and issue #2898 step 4 — "Authenticate the server before
//! protected disclosure. Plain loopback location is not identity."
//!
//! This module is the broker half of that step, and it is deliberately **one**
//! accepted mechanism, not half of each:
//!
//! * **Mechanism (a), the protected named-pipe one-shot bootstrap.** The
//!   introduction selects
//!   [`OPENCODE_BOOTSTRAP_PIPE_NAME`](eliot_user_broker_core::OPENCODE_BOOTSTRAP_PIPE_NAME),
//!   this broker owns the pipe, and the connecting process is authenticated
//!   from a sealed OS observation ([`NamedPipePeerEvidence`]) *before* the
//!   generation-bound one-shot ticket is redeemed and the credential is resolved
//!   through this broker's own secret table. No protected byte leaves this
//!   process before the peer is proven to be the exact approved `OpenCode`
//!   child this broker launched, in the bound SID and logon session.
//!
//! Mechanism (b) — an exclusively pre-bound loopback listener plus an
//! installation-pinned challenge/response identity — is **not** built here,
//! because this stack cannot authenticate loopback HTTP before the first
//! protected request: the plugin sends `Authorization: Bearer` as the first
//! bytes it writes, and an admitted child cannot carry the credential at all
//! (`LocalProcessPort::request_from_grant` refuses to materialise a secret
//! environment reference, per I6.15). Step 4 names exactly that conclusion: "If
//! the existing stack cannot authenticate loopback HTTP before first protected
//! request, use the protected local transport directly rather than shipping a
//! reusable bearer to an arbitrary port."
//!
//! What this module deliberately does **not** do: it does not mint the
//! introduction's `endpoint` or `server_identity`. Both are facts of the bridge
//! incarnation this broker never observes, no owner record for either exists in
//! this tree, and nothing here fabricates one from a port, a path, a pid, or an
//! environment value.

use std::path::Path;

use eliot_platform_windows::{NamedPipePeerEvidence, ProcessIdentity};
use eliot_user_broker_core::{
    BrokerError, LaunchReceipt, LaunchRequest, OpenCodeApprovedProcess, OpenCodeBootstrapPeer,
    OpenCodeBootstrapRoute, OpenCodeBootstrapTicket, OpenCodeBridgeProcessProjection,
    OpenCodeBrokerProcessBinding, OpenCodeOneUseIntroduction,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{BrokerAdmissionRefusal, BrokerComposition, CompositionError, now_unix_ms};

/// Mints one fresh short-lived route credential.
///
/// The shape is the introduction's own documented one: a 64-character lowercase
/// hex token, well inside
/// [`MAX_OPENCODE_ROUTE_CREDENTIAL_BYTES`](eliot_user_broker_core::MAX_OPENCODE_ROUTE_CREDENTIAL_BYTES).
/// It lives only in this process's
/// [`OpenCodeRouteCredentials`](eliot_user_broker_core::OpenCodeRouteCredentials)
/// table, under the opaque handle the introduction already names, and is never
/// logged, persisted, or projected into an ordinary launch map.
fn mint_route_credential() -> Box<str> {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()).into()
}

/// Lowercase SHA-256 hex of the exact bytes this broker opens and hashes itself.
/// A presented digest is never compared; the bytes are re-read here.
fn observed_image_digest(image_path: &str) -> Result<String, CompositionError> {
    let bytes = std::fs::read(Path::new(image_path)).map_err(|error| {
        BrokerAdmissionRefusal::OperatorClientProcessForeign.with_platform(format!(
            "approved process image bytes are unreadable: {error}"
        ))
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Maps the owner contract's typed refusals onto this composition's existing
/// stable admission codes. No new refusal is invented and no verdict is flattened
/// into a boolean.
fn classify(error: BrokerError) -> CompositionError {
    match error {
        BrokerError::StaleRegistrationIdentity => {
            BrokerAdmissionRefusal::OperatorBindingCrossSession.with_platform(
                "bootstrap peer SID/session is not this broker's own admitted identity",
            )
        }
        BrokerError::ProcessBindingMismatch => BrokerAdmissionRefusal::OperatorClientProcessForeign
            .with_platform(
                "bootstrap peer is not the exact approved process generation this broker launched",
            ),
        BrokerError::RegistrationNotAdmitted
        | BrokerError::StaleLease
        | BrokerError::LeaseExpired => BrokerAdmissionRefusal::OperatorSessionTokenStale
            .with_platform("the bootstrap route is not presently introduced and live"),
        BrokerError::ReplayConflict => BrokerAdmissionRefusal::OperatorSessionTokenStale
            .with_platform("the one-shot bootstrap ticket was already redeemed"),
        other => BrokerAdmissionRefusal::OperatorHandoffNotAdmitted
            .with_platform(format!("bootstrap redemption refused: {other}")),
    }
}

/// Returns the `OpenCode` bootstrap projection one admitted launch carries, if
/// any. A launch that names no projection is not an `OpenCode` route and
/// installs nothing.
pub(crate) fn launch_names_opencode_projection(request: &LaunchRequest) -> Option<String> {
    request
        .approved
        .environment
        .non_secret()
        .get(eliot_user_broker_core::OPENCODE_BRIDGE_ENV_INTRODUCTION)
        .cloned()
}

impl BrokerComposition {
    /// Installs the one-shot bootstrap route for the `OpenCode` child this
    /// broker just launched, from this broker's own owner records.
    ///
    /// `projection_bytes` is the broker-minted
    /// [`OpenCodeBridgeProcessProjection`] the admitted launch carried as its own
    /// child projection. It is *verified*, never trusted: the introduction is
    /// revalidated against its own digest and window and joined with the session
    /// facts it was minted under, and then every identity value this broker owns
    /// is compared with this broker's own protected declaration and live
    /// registration — installation, Windows SID, interactive session, the live
    /// attach fence, the introducing broker process id, and the SHA-256 of the
    /// exact image bytes the OS reported for the launched child.
    ///
    /// Installation is best-effort by design and never fails an admitted launch:
    /// a projection that fails any check leaves no route, so every redemption is
    /// refused until a rotation installs a fresh one.
    pub(crate) fn install_opencode_bootstrap_route(
        &mut self,
        projection_bytes: &str,
        receipt: &LaunchReceipt,
    ) {
        if self
            .admit_opencode_bootstrap_route(projection_bytes, receipt)
            .is_err()
        {
            self.opencode_bootstrap = None;
        }
    }

    /// The fail-closed half of [`Self::install_opencode_bootstrap_route`]: every
    /// owner-record comparison, then the install itself.
    fn admit_opencode_bootstrap_route(
        &mut self,
        projection_bytes: &str,
        receipt: &LaunchReceipt,
    ) -> Result<(), CompositionError> {
        let projection: OpenCodeBridgeProcessProjection =
            serde_json::from_str(projection_bytes).map_err(CompositionError::Encoding)?;
        let now = now_unix_ms()?;
        let facts = projection.facts(now).map_err(|error| {
            BrokerAdmissionRefusal::OperatorHandoffNotAdmitted.with_platform(format!(
                "bootstrap projection is not a current introduction: {error}"
            ))
        })?;
        self.verify_launch_lease()?;
        let introduction = &projection.introduction;
        let binding = self.opencode_launch_binding()?;
        if introduction.installation_id != binding.registration.installation_id
            || introduction.windows_sid != binding.registration.windows_sid
            || introduction.interactive_session_id != binding.registration.interactive_session_id
            || facts.installation_id != binding.registration.installation_id
            || facts.windows_sid != binding.registration.windows_sid
            || facts.interactive_session_id != binding.registration.interactive_session_id
        {
            return Err(
                BrokerAdmissionRefusal::OperatorBindingCrossSession.with_platform(
                    "bootstrap introduction is not this broker's own installation/SID/session",
                ),
            );
        }
        if introduction.fence_id != self.live_registration()?.fence_id {
            return Err(
                BrokerAdmissionRefusal::OperatorSessionTokenStale.with_platform(
                    "bootstrap introduction is not bound to the live Kernel registration fence",
                ),
            );
        }
        let identity = receipt.process_receipt.identity();
        // `ProcessIdentity` exposes no public fields: the OS-observed binding
        // lives on the executor's `PhysicalProcessBinding` and the identity's
        // own accessors are the only supported way in. The image DIGEST is the
        // executor's own `executable_sha256()`, not a re-hash of a path this
        // broker reads - `crates/kernel/AGENTS.md`: "Process ownership
        // requires immutable artifact/config/protocol identity ... PID/name/
        // path/port alone are insufficient."
        let physical = identity.physical();
        let approved = OpenCodeApprovedProcess {
            process_id: physical.process_id(),
            process_start_100ns: physical.start_time_100ns(),
            image_path: physical.image_path().to_owned(),
            image_digest: identity.executable_sha256().to_owned(),
        };
        let route = OpenCodeBootstrapRoute::new(
            introduction.clone(),
            approved,
            Self::opencode_broker_process_binding()?,
            mint_route_credential(),
            now,
        )
        .map_err(classify)?;
        self.opencode_bootstrap = Some(route);
        Ok(())
    }

    /// Authenticates the connected pipe peer and redeems the one-shot bootstrap
    /// exactly once (issue #2898, step 4; acceptance A2).
    ///
    /// This is the production caller of
    /// [`OpenCodeBootstrapRoute::redeem_peer`]. Before anything else it re-proves
    /// that this generation is still the live, lease-verifying,
    /// live-registration composition. Then it re-observes the connected peer
    /// process — Windows reuses process ids, so the observation decides, not the
    /// presented number — compares the OS-observed image path with the approved
    /// one, and hashes that image's bytes itself. Only the resulting
    /// [`OpenCodeBootstrapPeer`] reaches the route, and the credential is
    /// resolved only after the route accepted it as the exact approved process
    /// in the bound SID and logon session.
    pub fn redeem_opencode_bootstrap(
        &mut self,
        ticket: &OpenCodeBootstrapTicket,
        peer: &NamedPipePeerEvidence,
    ) -> Result<OpenCodeOneUseIntroduction, CompositionError> {
        self.verify_launch_lease()?;
        self.live_registration()?;
        let broker_process = Self::opencode_broker_process_binding()?;
        let approved_image = self
            .opencode_bootstrap
            .as_ref()
            .map(|route| route.approved_image_path().to_owned())
            .ok_or_else(|| {
                BrokerAdmissionRefusal::OperatorHandoffNotAdmitted
                    .with_platform("no OpenCode bootstrap route is installed in this generation")
            })?;
        let observed = observe_peer_process(peer)?;
        if !eliot_platform_windows::ordinal_eq_str(&observed.image_path, &approved_image) {
            return Err(BrokerAdmissionRefusal::OperatorClientProcessForeign
                .with_platform("bootstrap peer image is not the approved OpenCode image"));
        }
        let peer_facts = OpenCodeBootstrapPeer {
            windows_sid: peer.sid().to_owned(),
            interactive_session_id: peer.session_id().to_string(),
            process_id: observed.process_id,
            process_start_100ns: observed.start_time_100ns,
            image_path: observed.image_path.clone(),
            image_digest: observed_image_digest(&observed.image_path)?,
        };
        let route = self.opencode_bootstrap.as_mut().ok_or_else(|| {
            BrokerAdmissionRefusal::OperatorHandoffNotAdmitted
                .with_platform("no OpenCode bootstrap route is installed in this generation")
        })?;
        route
            .redeem_peer(ticket, now_unix_ms()?, &peer_facts, &broker_process)
            .map_err(classify)
    }

    /// The installation/SID/session declaration this broker admitted itself
    /// against, re-read from the retained protected launch configuration.
    fn opencode_launch_binding(
        &self,
    ) -> Result<&super::protected_launch_config::BrokerLaunchBinding, CompositionError> {
        self.launch_binding.as_ref().ok_or_else(|| {
            BrokerAdmissionRefusal::OperatorHandoffUncomposed
                .with_platform("protected launch configuration is not composed")
        })
    }

    /// This broker generation's own re-observed live process identity, which the
    /// introduction's `parent_broker_process_id` must name.
    ///
    /// This observes the OS *now* rather than reading the value bound at
    /// admission, so a broker whose identity was replaced between admission and
    /// this redemption cannot present the old binding. A generation whose
    /// retained binding no longer verifies has already been refused by
    /// `BrokerComposition::verify_launch_lease` above.
    fn opencode_broker_process_binding() -> Result<OpenCodeBrokerProcessBinding, CompositionError> {
        let identity = super::protected_launch_config::current_process_identity()?;
        Ok(OpenCodeBrokerProcessBinding {
            process_id: identity.process_id,
            process_start_100ns: identity.process_start_100ns,
        })
    }
}

/// Re-observes the connected peer process live, exactly as the Operator handoff
/// redemption does. A pid alone is never identity, so the observation — not the
/// presented number — decides, and a generation that has already exited fails
/// closed instead of being trusted.
#[cfg(windows)]
fn observe_peer_process(peer: &NamedPipePeerEvidence) -> Result<ProcessIdentity, CompositionError> {
    let observed =
        eliot_platform_windows::observe_named_pipe_peer_process(peer.process().process_id)
            .map_err(|error| {
                BrokerAdmissionRefusal::OperatorClientProcessForeign.with_platform(format!(
                    "bootstrap peer process observation failed: {error}"
                ))
            })?;
    if observed.identity() != peer.process() {
        return Err(BrokerAdmissionRefusal::OperatorClientProcessForeign
            .with_platform("bootstrap peer is no longer the authenticated process generation"));
    }
    Ok(observed.identity().clone())
}

#[cfg(not(windows))]
fn observe_peer_process(
    _peer: &NamedPipePeerEvidence,
) -> Result<ProcessIdentity, CompositionError> {
    Err(BrokerAdmissionRefusal::OperatorClientProcessForeign
        .with_platform("bootstrap peer process observation requires Windows"))
}
