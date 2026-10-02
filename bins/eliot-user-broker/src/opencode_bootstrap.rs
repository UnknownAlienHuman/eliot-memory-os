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
//! introduction's `endpoint` or `server_identity` from a port, a path, a pid,
//! or an environment value. Both are now owner data:
//!
//! * the **authorized endpoint** is read from the Kernel's own
//!   [`OpenCodeBridgeOwnerGrant`], published on the admitted launch under
//!   [`OPENCODE_BRIDGE_ENV_OWNER_GRANT`]. That grant carries the endpoint
//!   together with the admitted bridge artifact digest, the installation, the
//!   activation generation and the activation fence nonce, because
//!   `crates/kernel/AGENTS.md` states "Process ownership requires immutable
//!   artifact/config/protocol identity, installation/generation lineage and OS
//!   evidence. PID/name/path/port alone are insufficient" and `bins/AGENTS.md`
//!   states "Do not infer process ownership from PID, name, path, port,
//!   current directory, environment variables, or a successful exit". A bare
//!   port is therefore never owner data.
//! * the **server identity** is minted by this broker inside its own secret
//!   boundary, so a foreign process that merely bound the pinned port can hold
//!   a challenge but never this value, and therefore can neither mint the
//!   first-contact identity proof nor receive the request credential.

use std::path::Path;

use eliot_platform_windows::{NamedPipePeerEvidence, ProcessIdentity};
use eliot_process::{EnvironmentProjection, Generation, SecretRef};
use eliot_user_broker_core::{
    BrokerError, LaunchReceipt, LaunchRequest, OPENCODE_BRIDGE_CAPABILITIES,
    OPENCODE_BRIDGE_ENV_INTRODUCTION, OPENCODE_BRIDGE_ENV_OWNER_GRANT, OpenCodeApprovedProcess,
    OpenCodeBootstrapPeer, OpenCodeBootstrapRoute, OpenCodeBootstrapTicket,
    OpenCodeBridgeOwnerGrant, OpenCodeBridgeProcessProjection, OpenCodeBrokerProcessBinding,
    OpenCodeOneUseIntroduction, OpenCodeProcessBinding, OpenCodeProcessProjectionParams,
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
        .get(OPENCODE_BRIDGE_ENV_INTRODUCTION)
        .cloned()
}

/// Returns the Kernel-owned `OpenCode` bridge owner grant the launch
/// composition seam published on this admitted launch, if any.
///
/// A launch that carries no owner grant is not an `OpenCode` bridge launch: the
/// broker then mints nothing, so no introduction can exist without the Kernel's
/// own authorization for the endpoint, the activation generation and the
/// activation fence nonce.
pub(crate) fn launch_opencode_owner_grant(
    request: &LaunchRequest,
) -> Result<Option<OpenCodeBridgeOwnerGrant>, CompositionError> {
    let Some(raw) = request
        .approved
        .environment
        .non_secret()
        .get(OPENCODE_BRIDGE_ENV_OWNER_GRANT)
    else {
        return Ok(None);
    };
    serde_json::from_str(raw).map(Some).map_err(|error| {
        BrokerAdmissionRefusal::OperatorHandoffNotAdmitted.with_platform(format!(
            "launch owner grant is not the owner's closed record: {error}"
        ))
    })
}

/// Mints the broker-owned server identity for one `OpenCode` bridge launch.
///
/// It is 64 lowercase hex characters, exactly the introduction's own
/// `server_identity` shape, and it is **minted** rather than derived from the
/// endpoint: a process that merely bound the pinned port therefore holds a
/// challenge, never this value, so it can neither recompute the first-contact
/// identity proof nor receive the request credential that follows it. The value
/// is disclosed only to the exact approved children, alongside the route
/// credential, through the same broker-owned secret boundary.
fn mint_server_identity() -> String {
    let material = format!(
        "eliot.opencode.bridge-server-identity.v1:{}",
        Uuid::new_v4().simple()
    );
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

/// Broker-minted per-launch nonce and the revocation id derived from it.
///
/// The launch nonce binds this introduction to exactly one admitted launch
/// identity, and the revocation id is the key a later rotation or revocation
/// retires, so a superseded introduction fails closed even while it is still
/// installed and inside its window.
fn mint_launch_binding(request: &LaunchRequest) -> (String, String) {
    let nonce = format!("opencode-bridge-launch-{}", Uuid::new_v4().simple());
    let revocation_id = format!("opencode-bridge-revoke-{}", request.approved.request_id);
    (nonce, revocation_id)
}

/// Replaces the Kernel's authorization entry on this admitted launch with the
/// broker-minted child projection of it.
///
/// The owner grant is the Kernel's authorization to *this broker*; the child
/// receives the broker-minted projection of that authorization instead, so
/// exactly one introduction identity is ever present in the child environment
/// and a stale authorization is not carried forward. The projection is
/// re-admitted through [`EnvironmentProjection::new`], so a value the
/// secret-safe environment contract refuses is never written.
fn project_introduction_onto_child(
    request: &mut LaunchRequest,
    projection_bytes: String,
) -> Result<(), CompositionError> {
    let mut environment = request.approved.environment.non_secret().clone();
    environment.remove(OPENCODE_BRIDGE_ENV_OWNER_GRANT);
    environment.insert(
        OPENCODE_BRIDGE_ENV_INTRODUCTION.to_owned(),
        projection_bytes,
    );
    request.approved.environment = EnvironmentProjection::new(
        environment,
        request.approved.environment.secret_refs().to_vec(),
        request.approved.environment.inheritance(),
    )
    .map_err(|error| {
        BrokerAdmissionRefusal::OperatorHandoffNotAdmitted.with_platform(format!(
            "the minted child projection is not admissible: {error}"
        ))
    })?;
    Ok(())
}

impl BrokerComposition {
    /// Materializes the `OpenCode` bridge introduction and its child projection
    /// onto one admitted launch, from the Kernel's own owner grant (issue
    /// #2898, steps 1 and 2).
    ///
    /// This is the **production caller** of
    /// [`OpenCodeBridgeProcessProjection::compose`], and therefore of
    /// [`eliot_user_broker_core::OpenCodeBridgeIntroduction::mint`]. It runs
    /// before the launch is dispatched, so the bytes the child receives are
    /// broker-minted on the launch the Kernel admitted rather than read back
    /// from whatever the caller supplied.
    ///
    /// Everything unownable is taken from owner records: the activation
    /// generation, the activation fence nonce and the authorized loopback
    /// endpoint come from the [`OpenCodeBridgeOwnerGrant`] the Kernel
    /// published, and the server identity is minted here inside this broker's
    /// own secret boundary. The grant is additionally joined against this
    /// broker's live registration and against the approved artifact digest of
    /// this very launch, so a grant minted for another installation, session or
    /// image is refused instead of minted from.
    ///
    /// Installation is fail-closed: a projection that fails any check is simply
    /// absent, the launch still runs without a route, and
    /// [`Self::install_opencode_bootstrap_route`] then refuses every redemption
    /// because no introduction was carried.
    pub(crate) fn materialize_opencode_bridge_projection(
        &mut self,
        request: &mut LaunchRequest,
    ) -> Result<(), CompositionError> {
        let Some(owner) = launch_opencode_owner_grant(request)? else {
            return Ok(());
        };
        self.verify_launch_lease()?;
        let live = self.live_registration()?;
        let now = now_unix_ms()?;
        owner.validate(now).map_err(classify)?;
        if !owner.authorizes_endpoint_for(
            live.installation_id.as_str(),
            request.approved.artifact_digest.as_str(),
        ) {
            return Err(
                BrokerAdmissionRefusal::OperatorClientProcessForeign.with_platform(
                    "the launch owner grant does not authorize this bridge artifact and endpoint",
                ),
            );
        }
        // A grant may never outlive the registration it was minted under, and an
        // introduction may never outlive its own authorization.
        let expires_at = live
            .expires_at
            .min(owner.expires_at)
            .min(request.lease_expires_at);
        if expires_at <= now {
            return Err(BrokerAdmissionRefusal::OperatorSessionTokenStale
                .with_platform("the OpenCode bridge owner grant is not presently live"));
        }
        let (launch_nonce, revocation_id) = mint_launch_binding(request);
        let broker_process = Self::opencode_broker_process_binding()?;
        let generation = Generation::new(live.user_broker_epoch).map_err(|_| {
            BrokerAdmissionRefusal::OperatorSessionTokenStale
                .with_platform("the live broker epoch is not an admitted generation")
        })?;
        let projection = OpenCodeBridgeProcessProjection::compose(
            &owner,
            OpenCodeProcessProjectionParams {
                installation_id: live.installation_id.clone(),
                windows_sid: live.windows_sid.clone(),
                interactive_session_id: live.interactive_session_id.clone(),
                authority_epoch: live.authority_epoch.clone(),
                registration_fence_id: live.fence_id.clone(),
                broker_generation: generation,
                server_identity: mint_server_identity(),
                bootstrap_channel: None,
                credential: SecretRef::new(
                    "opencode-route",
                    format!("opencode-route-{revocation_id}"),
                )
                .map_err(|error| {
                    BrokerAdmissionRefusal::OperatorHandoffNotAdmitted
                        .with_platform(format!("route credential handle refused: {error}"))
                })?,
                credential_expires_at: expires_at,
                allowed_capabilities: OPENCODE_BRIDGE_CAPABILITIES
                    .iter()
                    .map(|capability| (*capability).to_owned())
                    .collect(),
                issued_at: now,
                expires_at,
                revocation_id,
                process_binding: OpenCodeProcessBinding {
                    executable_digest: request.approved.artifact_digest.clone(),
                    launch_nonce,
                    parent_broker_process_id: broker_process.process_id.to_string(),
                },
            },
        )
        .map_err(classify)?;
        let bytes = serde_json::to_string(&projection).map_err(CompositionError::Encoding)?;
        project_introduction_onto_child(request, bytes)
    }

    /// Installs the one-shot bootstrap route for the `OpenCode` child this
    /// broker just launched, from this broker's own owner records.
    ///
    /// `projection_bytes` is the broker-minted
    /// [`OpenCodeBridgeProcessProjection`] that
    /// [`Self::materialize_opencode_bridge_projection`] wrote onto the admitted
    /// launch as its own child projection, and that
    /// [`launch_names_opencode_projection`] reads back out of it. It is
    /// *verified*, never trusted: the introduction is revalidated against its
    /// own digest and window and joined with the session facts it was minted
    /// under, and then every identity value this broker owns is compared with
    /// this broker's own protected declaration and live registration —
    /// installation, Windows SID, interactive session, the introducing broker
    /// process id, the Kernel owner grant's authorized endpoint, and the
    /// SHA-256 of the exact image bytes the OS reported for the launched child.
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
        // The introduction's `fence_id` is now the **activation** fence nonce
        // the Kernel minted for the bridge incarnation, not this broker's
        // registration fence: the serving bridge re-proves it against its own
        // live attach `FencingToken` nonce, so requiring the registration fence
        // here would refuse every correct introduction. What this broker can and
        // does re-prove is that the minted introduction was issued under the
        // **same live Kernel authority** it still holds, and that it names a
        // non-empty Kernel-granted activation fence and generation.
        let live = self.live_registration()?;
        if !introduction
            .authority_epoch
            .is_same_authority(&live.authority_epoch)
            || introduction.fence_id.is_empty()
            || introduction.bridge_generation.get() == 0
        {
            return Err(
                BrokerAdmissionRefusal::OperatorSessionTokenStale.with_platform(
                    "bootstrap introduction is not bound to the live Kernel authority fence",
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
