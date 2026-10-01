//! User Broker-owned `OpenCode` bridge introduction issuance (issue #2898,
//! steps 2 and 3).
//!
//! This module is the physical User Broker owner of the one admitted
//! client-identity path for `POST /v1/host-events`. It closes three measured
//! absences on `main` that previously left the whole route unreachable:
//!
//! * `OpenCodeIntroductionParams` had **zero** producers, so nothing ever
//!   minted an [`OpenCodeBridgeIntroduction`]. [`OpenCodeIntroductionIssuer::issue`]
//!   is that producer, and every field it supplies is observed owner state.
//! * `OpenCodeSecretBoundary` had **zero** implementors, so
//!   `resolve_current_credential` and `child_environment_projection` had no
//!   physical source. [`BrokerSecretBoundary`] is that implementor: it holds
//!   the minted short-lived bearer in this process's memory and resolves only
//!   the exact handle it minted.
//! * The introduction was never *installed*, so the serving side read an empty
//!   store and refused at its first typed path.
//!   [`crate::BrokerComposition::introduce_opencode_bridge`] is the production
//!   call site of the registry's `install`, so a minted introduction is
//!   installed rather than left dead.
//!
//! ## What is never taken from a caller
//!
//! Installation id, Windows SID, logon session, the broker generation, the
//! broker's own process identity, the credential bytes, the capability set, the
//! issue and expiry instants, and the revocation id are all **derived here**
//! from the broker's live registration, its live process binding, its own
//! clock, and its own closed constants. The only caller-supplied values are the
//! ones the User Broker cannot observe by itself because they describe the
//! *peer* route this introduction names: the loopback endpoint the bridge
//! process pinned, that bridge's generation and attach fence, the bridge server
//! identity the peer proved, the authority epoch the bridge admitted under, and
//! the exact `OpenCode` image being launched.
//!
//! Those peer values are re-proved twice, by two different owners, and neither
//! re-proof is this module's to relax:
//!
//! * Here, shape and binding are re-proved before the record exists:
//!   [`OpenCodeBridgeIntroduction::mint`] refuses a non-canonical endpoint, a
//!   non-hex server identity or executable digest, a capability outside the
//!   closed set, and an empty fence or revocation id, and
//!   [`OpenCodeBridgeIntroduction::validate`] then recomputes the digest over
//!   the ORIGINAL recorded tuple, so no field can be changed after the fact
//!   and still validate.
//! * On the serving side, [`OpenCodeBridgeIntroduction::fence_id`] and
//!   [`OpenCodeBridgeIntroduction::authority_epoch`] are compared by exact
//!   tuple against the bridge's own live attach fence, so a peer that presents
//!   an introduction naming someone else's fence is refused even though the
//!   bearer verified.
//!
//! The bearer itself is never an input: it is minted here from a fresh broker
//! nonce, so no caller can choose, replay, or predict a credential.
//!
//! The raw bearer never leaves this module in a durable record, a command
//! line, an environment map, a log, or a wire response: it stays in
//! [`BrokerSecretBoundary`] and is reachable only through
//! `resolve_current_credential`, exactly as I6.15 requires.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_process::{Generation, SecretRef};
use eliot_user_broker_core::{
    BrokerError, OPENCODE_BRIDGE_CAPABILITIES, OpenCodeBridgeIntroduction,
    OpenCodeIntroductionParams, OpenCodeProcessBinding, OpenCodeSecretBoundary,
    OpenCodeSessionFacts,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Closed schema version of the broker-side introduction issuance record.
///
/// It names the broker's own issuance envelope, not the introduction's
/// `eliot.opencode.bridge-introduction.v1` wire version, so a change to how
/// the broker composes an introduction is distinguishable from a change to the
/// introduction record the route verifies.
pub const OPENCODE_ISSUANCE_VERSION: &str = "eliot.user-broker.opencode-issuance.v1";

/// Absolute lifetime of one issued introduction, in milliseconds.
///
/// The introduction and its credential share one window: the credential
/// expires no later than the introduction that names it, so a live
/// introduction can never outlive its own credential.
const OPENCODE_INTRODUCTION_TTL_MS: u64 = 15 * 60 * 1000;

/// Absolute lifetime of the minted bearer, in milliseconds.
///
/// Strictly shorter than the introduction window, so the credential is
/// retired before the introduction that names it expires.
const OPENCODE_CREDENTIAL_TTL_MS: u64 = 5 * 60 * 1000;

/// Stable non-secret provider name of the broker-owned OpenCode credential
/// store. It names the *owner* of the secret, never the secret itself.
const OPENCODE_CREDENTIAL_PROVIDER: &str = "eliot-user-broker.opencode-bridge";

/// Owner-observed facts this broker contributes to one introduction.
///
/// Every field is read from this broker's own live registration, process
/// binding, or clock at issue time. Nothing here is caller-supplied, which is
/// what makes the introduction a broker observation rather than a request
/// echo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerIntroductionOwnerFacts {
    /// Installation identity this broker generation registered under.
    pub installation_id: String,
    /// Canonical Windows SID of the approved interactive user.
    pub windows_sid: String,
    /// Interactive logon session the broker is admitted in.
    pub interactive_session_id: String,
    /// Broker-local generation this introduction is issued under.
    pub broker_generation: Generation,
    /// Live process id of this broker process, observed from the OS.
    pub broker_process_id: String,
    /// Absolute issue instant, read from this broker's own clock.
    pub issued_at: u64,
}

impl BrokerIntroductionOwnerFacts {
    /// Projects the live session facts a serving composition observes for this
    /// introduction, so the two sides of the join are compared against the
    /// same owner tuple rather than against constants.
    #[must_use]
    pub fn session_facts(
        &self,
        bridge_generation: Generation,
        launch_nonce: &str,
        executable_digest: &str,
    ) -> OpenCodeSessionFacts {
        OpenCodeSessionFacts {
            installation_id: self.installation_id.clone(),
            windows_sid: self.windows_sid.clone(),
            interactive_session_id: self.interactive_session_id.clone(),
            broker_generation: self.broker_generation,
            bridge_generation,
            launch_nonce: launch_nonce.to_owned(),
            executable_digest: executable_digest.to_owned(),
        }
    }
}

/// The peer route one broker request asks this broker to introduce.
///
/// These are exactly the facts the User Broker cannot observe by itself: they
/// describe the bridge incarnation and the `OpenCode` image on the other side
/// of the route. They are shape-checked and digest-bound by
/// [`OpenCodeIntroductionIssuer::issue`] before the introduction exists, and
/// the two that a foreign peer must not be able to present — the attach fence
/// and the authority epoch — are re-proved on the serving side against the
/// bridge's own live attach fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeIntroductionRequest {
    /// Canonical pinned loopback endpoint the bridge process owns.
    pub endpoint: String,
    /// Bridge process generation this introduction names.
    pub bridge_generation: u64,
    /// Live attach fence nonce the bridge admitted under.
    pub fence_id: String,
    /// Lowercase SHA-256 hex of the pinned bridge server identity.
    pub server_identity: String,
    /// Lowercase SHA-256 hex of the exact approved `OpenCode` image.
    pub executable_digest: String,
    /// Authority epoch the bridge admitted under, in the exact spelling
    /// [`EpochId`]'s own `Serialize` produces.
    pub authority_epoch: String,
}

/// One minted introduction plus the session facts that must accompany it.
///
/// The two travel together deliberately: the receiving composition can prove
/// the live session only against these facts, and can name the route only with
/// the introduction. Installing the introduction without the matching facts
/// would leave the serving side unable to prove the live session; installing
/// facts without the introduction would leave it unable to name the route.
/// [`crate::BrokerComposition::introduce_opencode_bridge`] installs the introduction
/// on the broker side in the same step that mints it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedOpenCodeIntroduction {
    /// Envelope schema version of this issuance record.
    pub version: String,
    /// The minted, digest-bound introduction.
    pub introduction: OpenCodeBridgeIntroduction,
    /// Live session facts observed for the same introduction.
    pub facts: OpenCodeSessionFacts,
}

/// The physical User Broker secret boundary (issue #2898, step 3).
///
/// This is the one implementor of
/// [`OpenCodeSecretBoundary`](eliot_user_broker_core::OpenCodeSecretBoundary)
/// in the tree: the User Broker process that owns the physical launch holds the
/// minted short-lived bearer in memory and resolves only the exact handle it
/// minted for the current introduction. A handle from another generation, a
/// rotated credential, or any value this broker did not mint is refused rather
/// than resolved to bytes.
///
/// The bytes are never cloned into a durable record, a command line, an
/// environment map, a log line, or a wire response.
pub struct BrokerSecretBoundary {
    minted: Option<MintedBrokerCredential>,
}

/// One minted bearer and the exact opaque handle that names it.
struct MintedBrokerCredential {
    handle: SecretRef,
    secret: String,
}

impl BrokerSecretBoundary {
    /// Mints one short-lived bearer and retains it as this broker's current
    /// OpenCode credential.
    ///
    /// The bytes are derived from a fresh broker nonce over the installation
    /// identity, both generations, and the exact endpoint, so two issuances
    /// never share a bearer and a re-issuance under a moved generation or a
    /// changed endpoint cannot reproduce the previous one.
    fn mint(
        request: &OwnedIntroductionRequest,
        owner: &BrokerIntroductionOwnerFacts,
    ) -> Result<Self, BrokerError> {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let key = format!(
            "{OPENCODE_CREDENTIAL_PROVIDER}/{}",
            owner.interactive_session_id
        );
        let broker_generation = owner.broker_generation.get().to_string();
        let bridge_generation = request.bridge_generation.get().to_string();
        let mut material = Sha256::new();
        for part in [
            OPENCODE_ISSUANCE_VERSION,
            nonce.as_str(),
            owner.installation_id.as_str(),
            owner.windows_sid.as_str(),
            broker_generation.as_str(),
            bridge_generation.as_str(),
            request.endpoint.as_str(),
            request.executable_digest.as_str(),
        ] {
            material.update(part.as_bytes());
            material.update(b"\n");
        }
        let secret = format!("{:x}", material.finalize());
        // The handle is derived from the same nonce, so the retained key names
        // exactly this issuance and no other.
        let handle = SecretRef::new(key, nonce)
            .map_err(|_| BrokerError::InvalidField("introduction.credential"))?;
        Ok(Self {
            minted: Some(MintedBrokerCredential { handle, secret }),
        })
    }

    /// Builds the pre-issuance boundary, which resolves nothing.
    ///
    /// `None` is the pre-issuance state, so `resolve_secret` fails closed
    /// instead of matching a handle no request could name.
    fn unminted() -> Self {
        Self { minted: None }
    }

    /// Returns the opaque handle this broker minted for the current
    /// introduction, or `None` before the first issuance.
    fn handle(&self) -> Option<&SecretRef> {
        self.minted.as_ref().map(|minted| &minted.handle)
    }
}

impl OpenCodeSecretBoundary for BrokerSecretBoundary {
    type Error = BrokerError;

    fn resolve_secret(&self, handle: &SecretRef) -> Result<Box<str>, Self::Error> {
        // Only the exact handle this broker minted for the currently installed
        // introduction resolves. A rotated generation's handle, a foreign
        // handle, and the pre-issuance state all fail closed.
        let minted = self
            .minted
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?;
        if handle != &minted.handle {
            return Err(BrokerError::RegistrationNotAdmitted);
        }
        Ok(minted.secret.clone().into_boxed_str())
    }
}

/// The broker-side introduction issuer.
///
/// It holds the physical secret boundary for the introduction currently
/// installed, so a rotation replaces the bearer and the record together: the
/// previous introduction's handle stops resolving at the moment the new one is
/// minted, exactly as `OpenCodeBridgeIntroductionRegistry::install` retires
/// the replaced credential handle.
pub struct OpenCodeIntroductionIssuer {
    boundary: BrokerSecretBoundary,
}

impl OpenCodeIntroductionIssuer {
    /// Creates an issuer with no current introduction.
    ///
    /// The route stays unintroduced until [`Self::issue`] runs; nothing here
    /// derives an introduction from a constant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            boundary: BrokerSecretBoundary::unminted(),
        }
    }

    /// Issues the introduction for one admitted `OpenCode` launch.
    ///
    /// The owner facts come from this broker's live registration and clock;
    /// the request carries only the peer route the broker cannot observe. The
    /// minted introduction is validated with its own
    /// [`OpenCodeBridgeIntroduction::validate`] before it is returned, so a
    /// malformed window, capability set, or digest never reaches a serving
    /// composition.
    pub fn issue(
        &mut self,
        owner: &BrokerIntroductionOwnerFacts,
        wire_request: OpenCodeIntroductionRequest,
    ) -> Result<IssuedOpenCodeIntroduction, BrokerError> {
        // A broker that has not proved its own live process identity cannot
        // name which process the introduction's parent is, so it issues
        // nothing.
        if owner.broker_process_id.is_empty() || owner.installation_id.is_empty() {
            return Err(BrokerError::StaleRegistrationIdentity);
        }
        let request = wire_request.into_owned()?;
        let credential = BrokerSecretBoundary::mint(request, owner)?;
        let credential_handle = credential
            .handle()
            .ok_or(BrokerError::InvalidField("introduction.credential"))?
            .clone();
        let credential_expires_at = owner
            .issued_at
            .checked_add(OPENCODE_CREDENTIAL_TTL_MS)
            .ok_or(BrokerError::InvalidField("introduction.issued_at"))?;
        let expires_at = owner
            .issued_at
            .checked_add(OPENCODE_INTRODUCTION_TTL_MS)
            .ok_or(BrokerError::InvalidField("introduction.issued_at"))?;
        // The credential must expire no later than the introduction that
        // names it; the two windows are derived from one clock reading, so a
        // clock that cannot express both fails closed here rather than
        // producing an introduction that outlives its own credential.
        if credential_expires_at > expires_at {
            return Err(BrokerError::InvalidField(
                "introduction.credential_expires_at",
            ));
        }
        let launch_nonce = uuid::Uuid::new_v4().simple().to_string();
        let params = OpenCodeIntroductionParams {
            installation_id: owner.installation_id.clone(),
            windows_sid: owner.windows_sid.clone(),
            interactive_session_id: owner.interactive_session_id.clone(),
            broker_generation: owner.broker_generation,
            bridge_generation: request.bridge_generation,
            endpoint: request.endpoint.clone(),
            server_identity: request.server_identity.clone(),
            // The pre-bound listener is the selected first-contact mechanism:
            // an exclusive bind with bind-conflict refusal, plus the pinned
            // challenge/response identity. The protected named-pipe bootstrap
            // is the alternative first contact and is not selected here, so
            // this introduction names no pipe.
            bootstrap_channel: None,
            credential: credential_handle,
            credential_expires_at,
            allowed_capabilities: OPENCODE_BRIDGE_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
            authority_epoch: parse_authority_epoch(&request.authority_epoch)?,
            fence_id: request.fence_id.clone(),
            issued_at: owner.issued_at,
            expires_at,
            // A fresh revocation id per issuance is what makes rotation retire
            // the previous generation: installing this record retires its
            // predecessor's revocation id and its credential handle, so the
            // replaced generation can neither be admitted nor have its secret
            // resolved.
            revocation_id: uuid::Uuid::new_v4().simple().to_string(),
            process_binding: OpenCodeProcessBinding {
                executable_digest: request.executable_digest.clone(),
                launch_nonce: launch_nonce.clone(),
                parent_broker_process_id: owner.broker_process_id.clone(),
            },
        };
        let introduction = OpenCodeBridgeIntroduction::mint(params)?;
        introduction.validate(owner.issued_at)?;
        let facts = owner.session_facts(
            request.bridge_generation,
            &launch_nonce,
            &request.executable_digest,
        );
        self.boundary = credential;
        Ok(IssuedOpenCodeIntroduction {
            version: OPENCODE_ISSUANCE_VERSION.to_owned(),
            introduction,
            facts,
        })
    }

    /// Returns the physical secret boundary holding the current introduction's
    /// bearer.
    ///
    /// This is the boundary the broker composition hands to
    /// `OpenCodeBridgeIntroductionRegistry::resolve_current_credential`, so the
    /// installed introduction's handle has exactly one physical source in the
    /// tree and the bearer never reaches a durable record, a command line, an
    /// environment map, a log, or a wire response.
    #[must_use]
    pub fn boundary(&self) -> &BrokerSecretBoundary {
        &self.boundary
    }
}

impl OpenCodeIntroductionRequest {
    /// Exact operation key this issuance is admitted under.
    ///
    /// It is derived from the peer route the request names, never from caller
    /// text: the pinned endpoint, the bridge generation, and the attach fence
    /// are the facts that make one issuance distinct from another, so the
    /// Human state-change gate binds the same tuple the mint digest binds.
    #[must_use]
    pub fn revocation_scope(&self) -> String {
        format!(
            "opencode-bridge-introduction:{}:{}:{}",
            self.endpoint, self.bridge_generation, self.fence_id
        )
    }

    /// Converts the wire request into its owner-typed internal form.
    ///
    /// The generation crosses the wire as a scalar but is re-proved here as a
    /// non-zero owner `Generation`, so a zero or absent generation refuses
    /// instead of becoming a wrapped identity that no fence comparison could
    /// ever match.
    fn into_owned(self) -> Result<OwnedIntroductionRequest, BrokerError> {
        let bridge_generation = Generation::new(self.bridge_generation)
            .map_err(|_| BrokerError::InvalidField("introduction.bridge_generation"))?;
        Ok(OwnedIntroductionRequest {
            endpoint: self.endpoint,
            bridge_generation,
            fence_id: self.fence_id,
            server_identity: self.server_identity,
            executable_digest: self.executable_digest,
            authority_epoch: self.authority_epoch,
        })
    }
}

/// Owner-typed form of [`OpenCodeIntroductionRequest`].
///
/// It exists so the generation is a non-zero owner `Generation` on every path
/// inside the issuer, and so the wire form cannot be mistaken for the value
/// the mint digest binds.
struct OwnedIntroductionRequest {
    endpoint: String,
    bridge_generation: Generation,
    fence_id: String,
    server_identity: String,
    executable_digest: String,
    authority_epoch: String,
}

impl IssuedOpenCodeIntroduction {
    /// Projects this issuance onto its closed wire record.
    ///
    /// The introduction is re-serialized from the owner's own validated type and
    /// the session facts are projected field by field from the owner's own
    /// values, so there is exactly one spelling of these facts on the wire and
    /// it is this one. The record carries the opaque credential handle only: no
    /// bearer byte is ever projected.
    #[must_use]
    pub fn to_wire_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version,
            "introduction": self.introduction,
            "facts": {
                "installation_id": self.facts.installation_id,
                "windows_sid": self.facts.windows_sid,
                "interactive_session_id": self.facts.interactive_session_id,
                "broker_generation": self.facts.broker_generation.get(),
                "bridge_generation": self.facts.bridge_generation.get(),
                "launch_nonce": self.facts.launch_nonce,
                "executable_digest": self.facts.executable_digest,
            },
        })
    }
}

impl Default for OpenCodeIntroductionIssuer {
    fn default() -> Self {
        Self::new()
    }
}

/// Re-binds a bridge-reported authority epoch into its owner type.
///
/// The epoch is owner state, so it is parsed into its owner type and re-bound
/// by the mint digest rather than carried as a free string: the introduction's
/// `is_same_authority` check compares exact `(lineage_id, sequence)` tuples, so
/// a free string could never satisfy it. The accepted spelling is exactly what
/// [`EpochId`]'s own `Serialize` produces — `{"lineage_id":…,"sequence":…}` —
/// and `deny_unknown_fields` refuses anything else, so no second spelling of
/// an authority epoch can enter the digest.
fn parse_authority_epoch(value: &str) -> Result<EpochId, BrokerError> {
    let wire: EpochIdWire = serde_json::from_str(value)
        .map_err(|_| BrokerError::InvalidField("introduction.authority_epoch"))?;
    Ok(EpochId::new(wire.lineage_id, wire.sequence)
        .map_err(|_| BrokerError::InvalidField("introduction.authority_epoch"))?)
}

/// Wire shape of one owner `AuthorityEpoch`, used only to re-bind
/// bridge-reported epoch text into the owner type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochIdWire {
    lineage_id: EpochLineageId,
    sequence: std::num::NonZeroU64,
}

/// Reads this broker's own wall clock in Unix milliseconds.
///
/// A clock that cannot be read fails closed at the call site: an introduction
/// with an invented issue instant would carry a window nothing observed.
pub fn broker_now_ms() -> Result<u64, BrokerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerError::InvalidField("introduction.issued_at"))
        .and_then(|elapsed| {
            u64::try_from(elapsed.as_millis())
                .map_err(|_| BrokerError::InvalidField("introduction.issued_at"))
        })
}
