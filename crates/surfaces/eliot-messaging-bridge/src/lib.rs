//! Optional replay-safe `MessagingBridge` adapter (I10.23).
//!
//! This crate is a thin translation layer over existing owners. It owns no
//! task semantics, memory, schedule, approval authority, route policy,
//! completion, canonical store, or scheduler. Every durable fact it reads
//! arrives as an explicit owner-supplied value; every durable effect it
//! projects is returned as data for the owning caller to persist through the
//! canonical route.
//!
//! The adapter is optional by construction: callers hold
//! `Option<MessagingBridge>` and the canonical delivery path never requires
//! one. Replay safety is structural: the inbound event identity is the stable
//! digest of platform update identity plus adapter generation plus principal
//! binding, so an exact replay resolves to the same event and can never mint
//! a second task or approval. Delivery retry only ever claims an already
//! committed outbox item or marks a new attempt; this crate holds no
//! agent, model, tool, or task ports, so retry cannot re-execute work.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum length of an opaque identity text field.
const IDENTITY_TEXT_LIMIT: usize = 256;
/// Exact length of a lowercase hexadecimal SHA-256 digest field.
const DIGEST_HEX_LENGTH: usize = 64;
/// Domain separator for the replay-safe inbound event identity.
///
/// V1 (`ELIOT/I10.23/INBOUND-EVENT/V1`) was an unframed concatenation and is
/// historical: a V1 key must never be compared against a V2 key. Owners
/// re-derive identity through [`InboundPlatformUpdate::event_key`].
const INBOUND_EVENT_DOMAIN: &str = "ELIOT/I10.23/INBOUND-EVENT/V2";
/// Domain separator for the evidenced bridge profile digest.
///
/// V1 (`ELIOT/I10.23/BRIDGE-PROFILE/V1`) was an unframed concatenation and is
/// historical: a V1 digest must never be compared against a V2 digest. Owners
/// re-derive identity through [`MessagingBridgeProfile::profile_digest`].
const PROFILE_DOMAIN: &str = "ELIOT/I10.23/BRIDGE-PROFILE/V2";
/// Domain separator for the approval binding digest.
///
/// V1 (`ELIOT/I10.23/APPROVAL-BINDING/V1`) was an unframed concatenation and
/// is historical: a V1 key must never be compared against a V2 key. Owners
/// re-derive identity through [`ApprovalBinding::approval_key`].
const APPROVAL_DOMAIN: &str = "ELIOT/I10.23/APPROVAL-BINDING/V2";
/// Domain separator for the logical delivery message digest.
///
/// V1 (`ELIOT/I10.23/LOGICAL-MESSAGE/V1`) was an unframed concatenation and
/// is historical: a V1 key must never be compared against a V2 key. Owners
/// re-derive identity through [`LogicalMessage::message_key`].
const LOGICAL_MESSAGE_DOMAIN: &str = "ELIOT/I10.23/LOGICAL-MESSAGE/V2";
/// Version of the single framed content-identity encoding (I5.27).
const IDENTITY_ENCODING_VERSION: u32 = 2;

/// Validates one opaque identity text field.
fn validate_identity_text(value: &str, field: &'static str) -> Result<(), BridgeError> {
    if value.is_empty() || value.len() > IDENTITY_TEXT_LIMIT {
        return Err(BridgeError::InvalidField(field));
    }
    Ok(())
}

/// Validates one optional opaque identity text field.
fn validate_optional_identity_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), BridgeError> {
    match value {
        Some(text) => validate_identity_text(text, field),
        None => Ok(()),
    }
}

/// Validates one lowercase hexadecimal SHA-256 digest field.
fn validate_digest(value: &str, field: &'static str) -> Result<(), BridgeError> {
    let is_lower_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    if value.len() != DIGEST_HEX_LENGTH || !value.bytes().all(is_lower_hex) {
        return Err(BridgeError::InvalidField(field));
    }
    Ok(())
}

/// Returns the lowercase hexadecimal SHA-256 of the input bytes.
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// One bounded private framed encoder for versioned content identities.
///
/// This is the only preimage encoding behind
/// [`MessagingBridgeProfile::profile_digest`],
/// [`InboundPlatformUpdate::event_key`], [`ApprovalBinding::approval_key`],
/// and [`LogicalMessage::message_key`]. Every variable-length field is
/// written as its one-byte tag, a fixed-width big-endian byte length, then
/// the UTF-8 bytes, so `(session="ab", workscope="c")` and
/// `(session="a", workscope="bc")` commit different bytes. Integers are
/// fixed-width big-endian; `Option` is a presence byte followed by the framed
/// value only when present; the capability set is committed in `Ord` order
/// with an explicit per-variant discriminant, so insertion order never moves
/// the digest while any membership change does. Each domain opens with its
/// framed name and the [`IDENTITY_ENCODING_VERSION`], so identities from
/// different domains never collide. All inputs are already
/// constructor-validated (identity text is length-bounded, digests are
/// fixed-length hex, the capability universe is seven variants), so the
/// encoding is bounded by construction.
struct FramedIdentity {
    hasher: Sha256,
}

impl FramedIdentity {
    /// Opens one named identity domain at the current encoding version.
    fn open(domain: &str) -> Self {
        let mut encoder = Self {
            hasher: Sha256::new(),
        };
        encoder.bytes(0x00, domain.as_bytes());
        encoder.u32(0x01, IDENTITY_ENCODING_VERSION);
        encoder
    }

    /// Appends raw bytes as tag, fixed-width big-endian length, then bytes.
    fn bytes(&mut self, tag: u8, value: &[u8]) {
        let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.hasher.update([tag]);
        self.hasher.update(len.to_be_bytes());
        self.hasher.update(value);
    }

    /// Appends one UTF-8 text field with its tag and byte length.
    fn text(&mut self, tag: u8, value: &str) {
        self.bytes(tag, value.as_bytes());
    }

    /// Appends one optional UTF-8 text field: a presence byte, then the
    /// framed value only when present.
    fn opt_text(&mut self, tag: u8, value: Option<&str>) {
        match value {
            Some(text) => {
                self.hasher.update([tag, 1]);
                let len = u64::try_from(text.len()).unwrap_or(u64::MAX);
                self.hasher.update(len.to_be_bytes());
                self.hasher.update(text.as_bytes());
            }
            None => {
                self.hasher.update([tag, 0]);
            }
        }
    }

    /// Appends one fixed-width big-endian `u32` with its tag.
    fn u32(&mut self, tag: u8, value: u32) {
        self.hasher.update([tag]);
        self.hasher.update(value.to_be_bytes());
    }

    /// Appends one fixed-width big-endian `u64` with its tag.
    fn u64(&mut self, tag: u8, value: u64) {
        self.hasher.update([tag]);
        self.hasher.update(value.to_be_bytes());
    }

    /// Appends one enrollment flag with its tag.
    fn flag(&mut self, tag: u8, value: bool) {
        self.hasher.update([tag, u8::from(value)]);
    }

    /// Appends the negotiated capability set in deterministic `Ord` order.
    fn capability_set(&mut self, tag: u8, supported: &BTreeSet<Capability>) {
        self.hasher.update([tag]);
        let len = u64::try_from(supported.len()).unwrap_or(u64::MAX);
        self.hasher.update(len.to_be_bytes());
        for capability in supported {
            let discriminant = match capability {
                Capability::Threads => 1,
                Capability::Editing => 2,
                Capability::Reactions => 3,
                Capability::MediaInbound => 4,
                Capability::MediaOutbound => 5,
                Capability::IdempotencyKeys => 6,
                Capability::ReadbackAck => 7,
            };
            self.hasher.update([discriminant]);
        }
    }

    /// Finalizes the framed encoding as lowercase hexadecimal SHA-256.
    fn finish(self) -> String {
        sha256_hex(&self.hasher.finalize())
    }
}

/// Returns true when the requested outbound value is recognizably a local
/// filesystem path rather than an opaque artifact handle.
fn looks_like_local_path(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let starts_rooted = matches!(value.as_bytes().first(), Some(b'/' | b'\\'));
    let has_drive = value.as_bytes().get(1) == Some(&b':');
    starts_rooted || has_drive || value.contains("..")
}

/// Typed failure for the optional bridge adapter.
///
/// Every variant is fail-closed: a malformed profile, a revoked principal, a
/// replayed approval, a local path, or a missing capability is rejected, and
/// absence of the bridge is reported without touching canonical delivery.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BridgeError {
    /// One named input field is malformed.
    #[error("invalid bridge field: {0}")]
    InvalidField(&'static str),
    /// The update generation does not match the attached profile generation.
    #[error("bridge generation mismatch")]
    GenerationMismatch,
    /// The bound principal does not match, or the principal was revoked.
    #[error("principal is not enrolled or was revoked")]
    PrincipalNotAuthorized,
    /// The supplied ledger evidence conflicts with the derived event identity.
    #[error("inbound identity conflicts with the claimed event")]
    IdentityConflict,
    /// The bridge is not attached; canonical delivery is unaffected.
    #[error("messaging bridge is not attached; canonical delivery is unaffected")]
    BridgeDisabled,
    /// The approval expired or its revision moved; the replay is rejected.
    #[error("approval expired or revised; replay rejected")]
    ApprovalReplayRejected,
    /// The requested command is not one of the typed bridge operations.
    #[error("operation is not a typed bridge command")]
    ProhibitedCommand,
    /// A local filesystem path was offered where only an authorized immutable
    /// artifact handle may be sent.
    #[error("local filesystem path is not an authorized immutable artifact handle")]
    LocalPathNotDisclosed,
    /// Inbound media was not admitted by the owning admission policy.
    #[error("inbound media was not admitted by the owning policy")]
    MediaNotAdmitted,
    /// The named capability surface was not negotiated for this generation.
    #[error("capability is not negotiated for this generation: {0}")]
    UnsupportedCapability(&'static str),
    /// The freshness window elapsed before the retry was attempted.
    #[error("freshness window elapsed")]
    FreshnessElapsed,
    /// The prior attempt is not in a state that admits the requested step.
    #[error("prior delivery attempt does not admit this transition")]
    ResendNotAllowed,
}

/// One negotiable platform capability surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    /// Threaded conversation surface.
    Threads,
    /// Message editing surface.
    Editing,
    /// Reaction surface.
    Reactions,
    /// Inbound file and media surface.
    MediaInbound,
    /// Outbound file and media surface.
    MediaOutbound,
    /// Platform idempotency-key surface.
    IdempotencyKeys,
    /// Acknowledgement and readback surface.
    ReadbackAck,
}

/// Negotiated and evidenced capability profile for one adapter generation.
///
/// Capabilities are an explicit set, never assumed. Requesting a surface that
/// is absent yields [`BridgeError::UnsupportedCapability`]; it is never
/// silently emulated with weaker guarantees.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProfile {
    supported: BTreeSet<Capability>,
    max_text_chars: u32,
    max_file_bytes: u64,
}

impl CapabilityProfile {
    /// Creates the validated capability set for one adapter generation.
    pub fn new(
        supported: BTreeSet<Capability>,
        max_text_chars: u32,
        max_file_bytes: u64,
    ) -> Result<Self, BridgeError> {
        if max_text_chars == 0 || max_text_chars > 1_000_000 {
            return Err(BridgeError::InvalidField(
                "capability_profile.max_text_chars",
            ));
        }
        if max_file_bytes == 0 || max_file_bytes > 1_000_000_000 {
            return Err(BridgeError::InvalidField(
                "capability_profile.max_file_bytes",
            ));
        }
        Ok(Self {
            supported,
            max_text_chars,
            max_file_bytes,
        })
    }

    /// Returns true when the capability surface was negotiated.
    pub fn supports(&self, capability: Capability) -> bool {
        self.supported.contains(&capability)
    }

    /// Returns the negotiated text bound for this generation.
    pub fn max_text_chars(&self) -> u32 {
        self.max_text_chars
    }

    /// Returns the negotiated file bound for this generation.
    pub fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }

    /// Requires a negotiated capability surface for the named bridge surface.
    pub fn require(
        &self,
        capability: Capability,
        surface: &'static str,
    ) -> Result<(), BridgeError> {
        if self.supports(capability) {
            Ok(())
        } else {
            Err(BridgeError::UnsupportedCapability(surface))
        }
    }
}

/// Revocable binding of an exact platform identity fingerprint to an existing
/// principal.
///
/// A platform account is a transport locator, never a principal by itself.
/// Revocation stops future delivery where enforceable and never rewrites the
/// historical delivery receipt, which the canonical owner keeps.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalBinding {
    principal: String,
    platform_fingerprint: String,
    revoked: bool,
}

impl PrincipalBinding {
    /// Binds the exact platform fingerprint to an existing principal.
    pub fn new(
        principal: impl Into<String>,
        platform_fingerprint: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let binding = Self {
            principal: principal.into(),
            platform_fingerprint: platform_fingerprint.into(),
            revoked: false,
        };
        validate_identity_text(&binding.principal, "principal_binding.principal")?;
        validate_identity_text(
            &binding.platform_fingerprint,
            "principal_binding.platform_fingerprint",
        )?;
        Ok(binding)
    }

    /// Marks the binding revoked; future inbound turns are refused.
    pub fn set_revoked(&mut self, revoked: bool) {
        self.revoked = revoked;
    }

    /// Returns the bound principal.
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Returns the bound platform fingerprint.
    pub fn platform_fingerprint(&self) -> &str {
        &self.platform_fingerprint
    }

    /// Refuses revoked bindings before any inbound turn is resolved.
    pub fn authorize(&self) -> Result<(), BridgeError> {
        if self.revoked {
            Err(BridgeError::PrincipalNotAuthorized)
        } else {
            Ok(())
        }
    }
}

/// Explicit chat, thread, session, task, and `WorkScope` binding.
///
/// Continuity is never inferred from chat history alone: the session and
/// `WorkScope` are bound here per adapter generation, and a turn without a
/// bound task becomes a typed [`OperatorIntentCandidate`] instead of an
/// implicit task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatBinding {
    chat: String,
    thread: Option<String>,
    session: String,
    task: Option<String>,
    workscope: String,
}

impl ChatBinding {
    /// Binds the transport locator to explicit session and `WorkScope` owners.
    pub fn new(
        chat: impl Into<String>,
        thread: Option<String>,
        session: impl Into<String>,
        task: Option<String>,
        workscope: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let binding = Self {
            chat: chat.into(),
            thread,
            session: session.into(),
            task,
            workscope: workscope.into(),
        };
        validate_identity_text(&binding.chat, "chat_binding.chat")?;
        validate_optional_identity_text(binding.thread.as_deref(), "chat_binding.thread")?;
        validate_identity_text(&binding.session, "chat_binding.session")?;
        validate_optional_identity_text(binding.task.as_deref(), "chat_binding.task")?;
        validate_identity_text(&binding.workscope, "chat_binding.workscope")?;
        Ok(binding)
    }

    /// Returns the bound session identity.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Returns the bound `WorkScope` identity.
    pub fn workscope(&self) -> &str {
        &self.workscope
    }

    /// Returns the bound task identity, if one is bound.
    pub fn task(&self) -> Option<&str> {
        self.task.as_deref()
    }
}

/// Static bridge contracts that are evidenced per adapter generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileContracts {
    media_contract: String,
    command_surface_version: u32,
    approval_surface_version: u32,
    scheduled_delivery_target: String,
    outbox_projection_ref: String,
}

impl ProfileContracts {
    /// Evidences the media, command, approval, scheduling, and projection refs.
    pub fn new(
        media_contract: impl Into<String>,
        command_surface_version: u32,
        approval_surface_version: u32,
        scheduled_delivery_target: impl Into<String>,
        outbox_projection_ref: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let contracts = Self {
            media_contract: media_contract.into(),
            command_surface_version,
            approval_surface_version,
            scheduled_delivery_target: scheduled_delivery_target.into(),
            outbox_projection_ref: outbox_projection_ref.into(),
        };
        validate_identity_text(
            &contracts.media_contract,
            "profile_contracts.media_contract",
        )?;
        validate_identity_text(
            &contracts.scheduled_delivery_target,
            "profile_contracts.scheduled_delivery_target",
        )?;
        validate_identity_text(
            &contracts.outbox_projection_ref,
            "profile_contracts.outbox_projection_ref",
        )?;
        Ok(contracts)
    }
}

/// Reconnect, replay, duplicate, and freshness policy for one generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayPolicy {
    freshness_window_ms: u64,
    max_attempts: u32,
}

impl ReplayPolicy {
    /// Creates the validated replay policy for one adapter generation.
    pub fn new(freshness_window_ms: u64, max_attempts: u32) -> Result<Self, BridgeError> {
        if freshness_window_ms == 0 {
            return Err(BridgeError::InvalidField(
                "replay_policy.freshness_window_ms",
            ));
        }
        if max_attempts == 0 {
            return Err(BridgeError::InvalidField("replay_policy.max_attempts"));
        }
        Ok(Self {
            freshness_window_ms,
            max_attempts,
        })
    }

    /// Returns the freshness window in milliseconds.
    pub fn freshness_window_ms(&self) -> u64 {
        self.freshness_window_ms
    }

    /// Returns the maximum delivery attempts for one logical message.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

/// Evidenced `MessagingBridgeProfile` for one adapter generation.
///
/// The profile binds the platform and adapter fingerprint generation, the
/// enrolled principal, the explicit session bindings, the negotiated
/// capabilities, the media and command and approval surfaces, the scheduled
/// delivery target, the canonical outbox and sink receipt projection, and the
/// replay policy. [`MessagingBridgeProfile::profile_digest`] is the stable
/// evidence handle for the whole binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessagingBridgeProfile {
    generation: String,
    principal_binding: PrincipalBinding,
    chat_binding: ChatBinding,
    capabilities: CapabilityProfile,
    contracts: ProfileContracts,
    replay_policy: ReplayPolicy,
}

impl MessagingBridgeProfile {
    /// Evidences the full bridge profile for one adapter generation.
    pub fn new(
        generation: impl Into<String>,
        principal_binding: PrincipalBinding,
        chat_binding: ChatBinding,
        capabilities: CapabilityProfile,
        contracts: ProfileContracts,
        replay_policy: ReplayPolicy,
    ) -> Result<Self, BridgeError> {
        let profile = Self {
            generation: generation.into(),
            principal_binding,
            chat_binding,
            capabilities,
            contracts,
            replay_policy,
        };
        validate_identity_text(&profile.generation, "bridge_profile.generation")?;
        profile.principal_binding.authorize()?;
        Ok(profile)
    }

    /// Returns the adapter generation fingerprint.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Returns the enrolled principal binding.
    pub fn principal_binding(&self) -> &PrincipalBinding {
        &self.principal_binding
    }

    /// Returns the explicit session binding.
    pub fn chat_binding(&self) -> &ChatBinding {
        &self.chat_binding
    }

    /// Returns the negotiated capability profile.
    pub fn capabilities(&self) -> &CapabilityProfile {
        &self.capabilities
    }

    /// Returns the replay policy.
    pub fn replay_policy(&self) -> &ReplayPolicy {
        &self.replay_policy
    }

    /// Returns the stable evidence digest of the whole profile binding.
    ///
    /// The digest commits the complete profile through the single framed
    /// V2 encoding: generation, principal enrollment (including the
    /// deliberately encoded revocation flag; construction only evidences
    /// non-revoked bindings), the full chat binding (chat, optional thread,
    /// session, optional task, `WorkScope`), the negotiated capability set
    /// with its numeric text and file limits, the media contract, the
    /// command and approval surface versions, the scheduled delivery target,
    /// the canonical outbox projection ref, and the full replay policy. Any
    /// behavior-changing field change moves the digest. V1 digests are
    /// historical and are never compared against V2 values.
    #[must_use]
    pub fn profile_digest(&self) -> String {
        let mut encoder = FramedIdentity::open(PROFILE_DOMAIN);
        encoder.text(0x01, &self.generation);
        encoder.text(0x02, &self.principal_binding.principal);
        encoder.text(0x03, &self.principal_binding.platform_fingerprint);
        encoder.flag(0x04, self.principal_binding.revoked);
        encoder.text(0x05, &self.chat_binding.chat);
        encoder.opt_text(0x06, self.chat_binding.thread.as_deref());
        encoder.text(0x07, &self.chat_binding.session);
        encoder.opt_text(0x08, self.chat_binding.task.as_deref());
        encoder.text(0x09, &self.chat_binding.workscope);
        encoder.capability_set(0x0A, &self.capabilities.supported);
        encoder.u32(0x0B, self.capabilities.max_text_chars);
        encoder.u64(0x0C, self.capabilities.max_file_bytes);
        encoder.text(0x0D, &self.contracts.media_contract);
        encoder.u32(0x0E, self.contracts.command_surface_version);
        encoder.u32(0x0F, self.contracts.approval_surface_version);
        encoder.text(0x10, &self.contracts.scheduled_delivery_target);
        encoder.text(0x11, &self.contracts.outbox_projection_ref);
        encoder.u64(0x12, self.replay_policy.freshness_window_ms);
        encoder.u32(0x13, self.replay_policy.max_attempts);
        encoder.finish()
    }
}

/// One inbound platform turn with its transport identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundPlatformUpdate {
    platform_update_id: String,
    generation: String,
    principal: String,
    platform_fingerprint: String,
    payload_digest: String,
}

impl InboundPlatformUpdate {
    /// Creates one validated inbound platform turn.
    pub fn new(
        platform_update_id: impl Into<String>,
        generation: impl Into<String>,
        principal: impl Into<String>,
        platform_fingerprint: impl Into<String>,
        payload_digest: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let update = Self {
            platform_update_id: platform_update_id.into(),
            generation: generation.into(),
            principal: principal.into(),
            platform_fingerprint: platform_fingerprint.into(),
            payload_digest: payload_digest.into(),
        };
        validate_identity_text(
            &update.platform_update_id,
            "inbound_update.platform_update_id",
        )?;
        validate_identity_text(&update.generation, "inbound_update.generation")?;
        validate_identity_text(&update.principal, "inbound_update.principal")?;
        validate_identity_text(
            &update.platform_fingerprint,
            "inbound_update.platform_fingerprint",
        )?;
        validate_digest(&update.payload_digest, "inbound_update.payload_digest")?;
        Ok(update)
    }

    /// Returns the replay-safe identity: platform update identity plus adapter
    /// generation plus principal binding. An exact replay derives the exact
    /// same key, so webhook and polling duplicates cannot create a second
    /// task or approval.
    ///
    /// The key uses the single framed V2 encoding. The inbound event lookup
    /// identity (platform update identity, generation, principal binding)
    /// and the payload conflict commitment (payload digest) occupy distinct
    /// framed sections, so a payload change under a seen update identity
    /// conflicts instead of merging. V1 keys are historical and are never
    /// compared against V2 values.
    #[must_use]
    pub fn event_key(&self) -> String {
        let mut encoder = FramedIdentity::open(INBOUND_EVENT_DOMAIN);
        encoder.text(0x01, &self.platform_update_id);
        encoder.text(0x02, &self.generation);
        encoder.text(0x03, &self.principal);
        encoder.text(0x04, &self.platform_fingerprint);
        encoder.text(0x10, &self.payload_digest);
        encoder.finish()
    }
}

/// Owner-supplied durable lookup result for one inbound event identity.
///
/// The bridge owns no ledger; the owning caller passes the outcome of its own
/// durable claim check. A claimed identity with a conflicting key is rejected
/// instead of merged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundLedgerEvidence {
    already_claimed: bool,
    claimed_key: Option<String>,
}

impl InboundLedgerEvidence {
    /// Presents the owner ledger outcome for one inbound event identity.
    pub fn new(already_claimed: bool, claimed_key: Option<String>) -> Result<Self, BridgeError> {
        validate_optional_identity_text(claimed_key.as_deref(), "inbound_evidence.claimed_key")?;
        if already_claimed && claimed_key.is_none() {
            return Err(BridgeError::InvalidField("inbound_evidence.claimed_key"));
        }
        if !already_claimed && claimed_key.is_some() {
            return Err(BridgeError::InvalidField(
                "inbound_evidence.already_claimed",
            ));
        }
        Ok(Self {
            already_claimed,
            claimed_key,
        })
    }

    /// Reports an identity the owner has never claimed.
    pub fn fresh() -> Self {
        Self {
            already_claimed: false,
            claimed_key: None,
        }
    }
}

/// One admitted inbound event with its stable identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundEvent {
    /// Stable replay-safe identity for the turn.
    pub key: String,
    /// Transport update identity the key was derived from.
    pub update_id: String,
    /// Adapter generation the key was derived from.
    pub generation: String,
    /// Enrolled principal the key was derived from.
    pub principal: String,
}

/// Typed operator-intent candidate for a turn without a bound task.
///
/// The candidate carries only explicit routing references. It never infers
/// session continuity from chat history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentCandidate {
    /// Stable identity of the turn this candidate was raised for.
    pub event_key: String,
    /// Explicitly bound session the candidate belongs to.
    pub session: String,
    /// Explicitly bound `WorkScope` the candidate belongs to.
    pub workscope: String,
}

/// One newly admitted inbound turn with its explicit owner binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundNewTurn {
    /// The admitted event.
    pub event: InboundEvent,
    /// Explicitly bound session identity.
    pub session: String,
    /// Explicitly bound `WorkScope` identity.
    pub workscope: String,
    /// Bound task identity, when the profile binds one.
    pub task: Option<String>,
    /// Typed candidate, present exactly when no task is bound.
    pub intent_candidate: Option<OperatorIntentCandidate>,
}

/// One duplicate inbound turn that replays an already claimed event.
///
/// A replay carries the event identity only. It creates no task and no
/// approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundReplay {
    /// Stable identity of the already claimed event.
    pub event_key: String,
}

/// Resolution of one inbound turn: either a new admitted turn or a replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum InboundResolution {
    /// A first-seen turn with its explicit owner binding.
    New(Box<InboundNewTurn>),
    /// A duplicate turn that must not create task or approval effects.
    Replay(InboundReplay),
}

/// Resolves one inbound turn against the attached profile and the owner
/// ledger evidence.
///
/// The generation, principal, and fingerprint must match the enrolled profile
/// binding, and a revoked principal is refused. A claimed identity returns
/// [`InboundResolution::Replay`]; only a fresh identity returns
/// [`InboundResolution::New`], so replaying the same platform update for the
/// same generation and enrolled principal produces one inbound event and
/// cannot create a second task or approval.
pub fn resolve_inbound(
    profile: &MessagingBridgeProfile,
    update: &InboundPlatformUpdate,
    evidence: &InboundLedgerEvidence,
) -> Result<InboundResolution, BridgeError> {
    if update.generation != profile.generation {
        return Err(BridgeError::GenerationMismatch);
    }
    profile.principal_binding.authorize()?;
    if update.principal != profile.principal_binding.principal
        || update.platform_fingerprint != profile.principal_binding.platform_fingerprint
    {
        return Err(BridgeError::PrincipalNotAuthorized);
    }
    let key = update.event_key();
    if evidence.already_claimed {
        match &evidence.claimed_key {
            Some(claimed) if *claimed == key => {
                return Ok(InboundResolution::Replay(InboundReplay { event_key: key }));
            }
            _ => return Err(BridgeError::IdentityConflict),
        }
    }
    let event = InboundEvent {
        key: key.clone(),
        update_id: update.platform_update_id.clone(),
        generation: update.generation.clone(),
        principal: update.principal.clone(),
    };
    let chat = &profile.chat_binding;
    let intent_candidate = match &chat.task {
        Some(_) => None,
        None => Some(OperatorIntentCandidate {
            event_key: key,
            session: chat.session.clone(),
            workscope: chat.workscope.clone(),
        }),
    };
    Ok(InboundResolution::New(Box::new(InboundNewTurn {
        event,
        session: chat.session.clone(),
        workscope: chat.workscope.clone(),
        task: chat.task.clone(),
        intent_candidate,
    })))
}

/// One typed operation the bridge command surface may compile to.
///
/// The set is closed: session create, resume, status, and stop, approval and
/// denial, route selection, automation inspection, and skill invocation. A
/// generic shell or database path does not exist in this type, so it cannot
/// be compiled, addressed, or bypassed through the bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TypedCommand {
    /// Create a session through the owning session contract.
    SessionCreate,
    /// Resume a session through the owning session contract.
    SessionResume,
    /// Report session status through the owning session contract.
    SessionStatus,
    /// Stop a session through the owning session contract.
    SessionStop,
    /// Approve the bound action through the owning approval contract.
    Approval,
    /// Deny the bound action through the owning approval contract.
    Denial,
    /// Select a route through the owning route contract.
    RouteSelection,
    /// Inspect automation through the owning automation contract.
    AutomationInspection,
    /// Invoke a skill through the owning skill contract.
    SkillInvocation,
}

/// Compiles a chat command name to exactly one typed existing operation.
///
/// Unknown names, including any generic shell or database access spelling,
/// are rejected with [`BridgeError::ProhibitedCommand`].
pub fn compile_command(name: &str) -> Result<TypedCommand, BridgeError> {
    match name {
        "/session-create" => Ok(TypedCommand::SessionCreate),
        "/session-resume" => Ok(TypedCommand::SessionResume),
        "/session-status" => Ok(TypedCommand::SessionStatus),
        "/session-stop" => Ok(TypedCommand::SessionStop),
        "/approve" => Ok(TypedCommand::Approval),
        "/deny" => Ok(TypedCommand::Denial),
        "/route" => Ok(TypedCommand::RouteSelection),
        "/automation-inspect" => Ok(TypedCommand::AutomationInspection),
        "/skill" => Ok(TypedCommand::SkillInvocation),
        _ => Err(BridgeError::ProhibitedCommand),
    }
}

/// Validated identity half of an approval binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalIdentity {
    action_digest: String,
    effect_digest: String,
    scope: String,
    principal: String,
    revision: String,
}

impl ApprovalIdentity {
    /// Binds the exact action and effect digests, scope, principal, and revision.
    pub fn new(
        action_digest: impl Into<String>,
        effect_digest: impl Into<String>,
        scope: impl Into<String>,
        principal: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let identity = Self {
            action_digest: action_digest.into(),
            effect_digest: effect_digest.into(),
            scope: scope.into(),
            principal: principal.into(),
            revision: revision.into(),
        };
        validate_digest(&identity.action_digest, "approval_identity.action_digest")?;
        validate_digest(&identity.effect_digest, "approval_identity.effect_digest")?;
        validate_identity_text(&identity.scope, "approval_identity.scope")?;
        validate_identity_text(&identity.principal, "approval_identity.principal")?;
        validate_identity_text(&identity.revision, "approval_identity.revision")?;
        Ok(identity)
    }
}

/// Approval bound to one exact action and effect digest, scope, `State Fence`
/// sequence, authority epoch, principal, and expiry.
///
/// `/approve` is never session-wide authority: a replay after expiry or after
/// a revision change is rejected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    identity: ApprovalIdentity,
    state_fence_seq: u64,
    authority_epoch: u64,
    expires_at_ms: u64,
}

impl ApprovalBinding {
    /// Binds the approval identity to its fence, epoch, and expiry.
    pub fn new(
        identity: ApprovalIdentity,
        state_fence_seq: u64,
        authority_epoch: u64,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            identity,
            state_fence_seq,
            authority_epoch,
            expires_at_ms,
        }
    }

    /// Returns the stable digest of the whole approval binding.
    ///
    /// The key commits the exact action and effect digests, scope,
    /// principal, revision, `State Fence` sequence, authority epoch, and
    /// expiry through the single framed V2 encoding. V1 keys are historical
    /// and are never compared against V2 values.
    #[must_use]
    pub fn approval_key(&self) -> String {
        let mut encoder = FramedIdentity::open(APPROVAL_DOMAIN);
        encoder.text(0x01, &self.identity.action_digest);
        encoder.text(0x02, &self.identity.effect_digest);
        encoder.text(0x03, &self.identity.scope);
        encoder.text(0x04, &self.identity.principal);
        encoder.text(0x05, &self.identity.revision);
        encoder.u64(0x06, self.state_fence_seq);
        encoder.u64(0x07, self.authority_epoch);
        encoder.u64(0x08, self.expires_at_ms);
        encoder.finish()
    }

    /// Authorizes one approval presentation at the given time and revision.
    ///
    /// A revision change or an elapsed expiry rejects the replay, so a stale
    /// `/approve` can never authorize a revised or expired action.
    pub fn authorize(&self, now_ms: u64, current_revision: &str) -> Result<(), BridgeError> {
        if self.identity.revision != current_revision {
            return Err(BridgeError::ApprovalReplayRejected);
        }
        if now_ms > self.expires_at_ms {
            return Err(BridgeError::ApprovalReplayRejected);
        }
        Ok(())
    }
}

/// Immutable disclosed artifact handle for outbound media.
///
/// Only handles admitted through disclosure closure and recipient policy may
/// be sent. A local filesystem path is never a handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosedArtifactHandle {
    handle: String,
    disclosure_digest: String,
}

impl DisclosedArtifactHandle {
    /// Creates one validated disclosed handle.
    pub fn new(
        handle: impl Into<String>,
        disclosure_digest: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let artifact = Self {
            handle: handle.into(),
            disclosure_digest: disclosure_digest.into(),
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates the handle shape and its disclosure digest.
    pub fn validate(&self) -> Result<(), BridgeError> {
        validate_identity_text(&self.handle, "artifact_handle.handle")?;
        if looks_like_local_path(&self.handle) {
            return Err(BridgeError::InvalidField("artifact_handle.handle"));
        }
        validate_digest(&self.disclosure_digest, "artifact_handle.disclosure_digest")?;
        Ok(())
    }

    /// Returns the opaque handle.
    pub fn handle(&self) -> &str {
        &self.handle
    }
}

/// One outbound file request naming either a disclosed handle or a path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundFileRequest {
    requested: String,
    disclosure_digest: String,
}

impl OutboundFileRequest {
    /// Creates one outbound file request.
    pub fn new(
        requested: impl Into<String>,
        disclosure_digest: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let request = Self {
            requested: requested.into(),
            disclosure_digest: disclosure_digest.into(),
        };
        validate_identity_text(&request.requested, "outbound_request.requested")?;
        validate_digest(
            &request.disclosure_digest,
            "outbound_request.disclosure_digest",
        )?;
        Ok(request)
    }
}

/// Owner port that resolves a requested outbound value to an authorized
/// immutable handle.
///
/// The bridge never touches the filesystem or the blob store, and it never
/// authorizes a handle itself; the owning artifact contract applies the
/// disclosure closure and recipient policy before confirming any value.
pub trait ArtifactResolutionPort {
    /// Resolves the requested value to an authorized handle, or nothing.
    ///
    /// The owner returns a handle only when the requested value — a local
    /// path or an opaque handle text — with the claimed disclosure digest
    /// denotes an authorized immutable artifact under disclosure closure
    /// and recipient policy.
    fn resolve_outbound(
        &self,
        requested: &str,
        disclosure_digest: &str,
    ) -> Option<DisclosedArtifactHandle>;
}

/// Resolves one outbound file request to an authorized immutable handle.
///
/// Every requested value is resolved through the owning port: the bridge
/// cannot tell an opaque handle from a local path by shape, so a value the
/// owner does not confirm is rejected with
/// [`BridgeError::LocalPathNotDisclosed`] and never sent as if it were the
/// artifact.
pub fn resolve_outbound_file(
    request: &OutboundFileRequest,
    owner: &dyn ArtifactResolutionPort,
) -> Result<DisclosedArtifactHandle, BridgeError> {
    match owner.resolve_outbound(&request.requested, &request.disclosure_digest) {
        Some(handle) => {
            handle.validate()?;
            Ok(handle)
        }
        None => Err(BridgeError::LocalPathNotDisclosed),
    }
}

/// One inbound media object awaiting admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundMedia {
    digest: String,
    claimed_size_bytes: u64,
}

impl InboundMedia {
    /// Creates one validated inbound media descriptor.
    pub fn new(digest: impl Into<String>, claimed_size_bytes: u64) -> Result<Self, BridgeError> {
        let media = Self {
            digest: digest.into(),
            claimed_size_bytes,
        };
        validate_digest(&media.digest, "inbound_media.digest")?;
        if media.claimed_size_bytes == 0 {
            return Err(BridgeError::InvalidField(
                "inbound_media.claimed_size_bytes",
            ));
        }
        Ok(media)
    }

    /// Returns the media digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Owner port that admits inbound media through source admission, privacy
/// scanning, and the blob store before model or tool exposure.
pub trait MediaAdmissionPort {
    /// Admits the media digest to an immutable handle, or nothing.
    fn admit_inbound_media(&self, digest: &str) -> Option<DisclosedArtifactHandle>;
}

/// Admits one inbound media object through the owning admission policy.
///
/// The media-inbound capability must be negotiated for the generation, and
/// the owning port must admit the digest. Unadmitted media is rejected with
/// [`BridgeError::MediaNotAdmitted`] and never exposed.
pub fn admit_inbound_media(
    profile: &MessagingBridgeProfile,
    media: &InboundMedia,
    owner: &dyn MediaAdmissionPort,
) -> Result<DisclosedArtifactHandle, BridgeError> {
    profile
        .capabilities
        .require(Capability::MediaInbound, "media.inbound")?;
    if media.claimed_size_bytes > profile.capabilities.max_file_bytes {
        return Err(BridgeError::InvalidField(
            "inbound_media.claimed_size_bytes",
        ));
    }
    match owner.admit_inbound_media(&media.digest) {
        Some(handle) => {
            handle.validate()?;
            Ok(handle)
        }
        None => Err(BridgeError::MediaNotAdmitted),
    }
}

/// Canonical sink-owned phase of one delivery attempt.
///
/// The ledger is a read model over the canonical outbox row and these
/// sink-owned phases, never a second store or lifecycle owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SinkPhase {
    /// The result is committed to the canonical outbox; send not started.
    Committed,
    /// Send started; no acknowledgement or readback observed yet.
    SendStarted,
    /// Send started and acknowledgement or readback lost; not reconciled.
    Unknown,
    /// The sink receipt confirms delivery.
    Acknowledged,
    /// The sink receipt confirms delivery failure.
    Failed,
}

/// One logical delivery message binding principal, target, refs, generation,
/// disclosure, freshness, and stable sink operation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalMessage {
    id: String,
    principal: String,
    target: String,
    task_ref: Option<String>,
    artifact_ref: Option<String>,
    generation: String,
    disclosure_digest: String,
    freshness_window_ms: u64,
}

impl LogicalMessage {
    /// Creates one validated logical delivery message without task or
    /// artifact refs. Refs are attached with [`LogicalMessage::with_refs`].
    pub fn new(
        id: impl Into<String>,
        principal: impl Into<String>,
        target: impl Into<String>,
        generation: impl Into<String>,
        disclosure_digest: impl Into<String>,
        freshness_window_ms: u64,
    ) -> Result<Self, BridgeError> {
        let message = Self {
            id: id.into(),
            principal: principal.into(),
            target: target.into(),
            task_ref: None,
            artifact_ref: None,
            generation: generation.into(),
            disclosure_digest: disclosure_digest.into(),
            freshness_window_ms,
        };
        message.validate()?;
        Ok(message)
    }

    /// Attaches the task and artifact refs to the logical message.
    pub fn with_refs(
        mut self,
        task_ref: Option<String>,
        artifact_ref: Option<String>,
    ) -> Result<Self, BridgeError> {
        self.task_ref = task_ref;
        self.artifact_ref = artifact_ref;
        self.validate()?;
        Ok(self)
    }

    /// Validates every binding of the logical message.
    fn validate(&self) -> Result<(), BridgeError> {
        validate_identity_text(&self.id, "logical_message.id")?;
        validate_identity_text(&self.principal, "logical_message.principal")?;
        validate_identity_text(&self.target, "logical_message.target")?;
        validate_optional_identity_text(self.task_ref.as_deref(), "logical_message.task_ref")?;
        validate_optional_identity_text(
            self.artifact_ref.as_deref(),
            "logical_message.artifact_ref",
        )?;
        validate_identity_text(&self.generation, "logical_message.generation")?;
        validate_digest(&self.disclosure_digest, "logical_message.disclosure_digest")?;
        if self.freshness_window_ms == 0 {
            return Err(BridgeError::InvalidField(
                "logical_message.freshness_window_ms",
            ));
        }
        Ok(())
    }

    /// Returns the logical message identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the stable digest of the whole logical message.
    ///
    /// The key commits the complete immutable logical-message content
    /// through the single framed V2 encoding: the stable outbox/logical
    /// identity stays distinct from the content commitment (principal,
    /// target, presence and value of the task and artifact refs, generation,
    /// disclosure decision, and the original freshness policy), so changed
    /// bytes under the same operation identity conflict rather than silently
    /// becoming another delivery. V1 keys are historical and are never
    /// compared against V2 values.
    #[must_use]
    pub fn message_key(&self) -> String {
        let mut encoder = FramedIdentity::open(LOGICAL_MESSAGE_DOMAIN);
        encoder.text(0x01, &self.id);
        encoder.text(0x02, &self.principal);
        encoder.text(0x03, &self.target);
        encoder.opt_text(0x04, self.task_ref.as_deref());
        encoder.opt_text(0x05, self.artifact_ref.as_deref());
        encoder.text(0x06, &self.generation);
        encoder.text(0x07, &self.disclosure_digest);
        encoder.u64(0x08, self.freshness_window_ms);
        encoder.finish()
    }
}

/// One delivery attempt in the projected ledger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryAttempt {
    attempt_id: String,
    logical_message_id: String,
    phase: SinkPhase,
    possible_duplicate: bool,
    freshness_deadline_ms: u64,
}

impl DeliveryAttempt {
    /// Creates one validated delivery attempt projection.
    pub fn new(
        attempt_id: impl Into<String>,
        logical_message_id: impl Into<String>,
        phase: SinkPhase,
        possible_duplicate: bool,
        freshness_deadline_ms: u64,
    ) -> Result<Self, BridgeError> {
        let attempt = Self {
            attempt_id: attempt_id.into(),
            logical_message_id: logical_message_id.into(),
            phase,
            possible_duplicate,
            freshness_deadline_ms,
        };
        validate_identity_text(&attempt.attempt_id, "delivery_attempt.attempt_id")?;
        validate_identity_text(
            &attempt.logical_message_id,
            "delivery_attempt.logical_message_id",
        )?;
        Ok(attempt)
    }

    /// Returns the sink-owned phase of the attempt.
    pub fn phase(&self) -> SinkPhase {
        self.phase
    }

    /// Returns true when the attempt is a marked possible duplicate.
    pub fn possible_duplicate(&self) -> bool {
        self.possible_duplicate
    }
}

/// One committed task result from the canonical outbox owner.
///
/// The bridge receives the committed row; it never executes the agent turn,
/// model call, tool call, or task effect that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedResult {
    outbox_item_id: String,
    logical_message: LogicalMessage,
    result_digest: String,
}

impl CommittedResult {
    /// Presents one committed outbox row for delivery claiming.
    pub fn new(
        outbox_item_id: impl Into<String>,
        logical_message: LogicalMessage,
        result_digest: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let committed = Self {
            outbox_item_id: outbox_item_id.into(),
            logical_message,
            result_digest: result_digest.into(),
        };
        validate_identity_text(&committed.outbox_item_id, "committed_result.outbox_item_id")?;
        validate_digest(&committed.result_digest, "committed_result.result_digest")?;
        Ok(committed)
    }
}

/// Claim of an existing outbox item for delivery after restart.
///
/// A committed result with send not started is delivered by claiming this
/// existing item. `re_executed_effects` is structurally always `false`: the
/// claim carries only the committed row identity, and this crate holds no
/// agent, model, tool, or task ports that could re-execute anything.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryClaim {
    /// The existing canonical outbox item to deliver.
    pub outbox_item_id: String,
    /// The logical message the item carries.
    pub logical_message_id: String,
    /// Always `false`; claiming never re-executes work.
    pub re_executed_effects: bool,
}

/// Claims the existing outbox item for a committed result with send not
/// started, without invoking any agent turn, model call, tool call, or task
/// effect again.
#[must_use]
pub fn claim_committed_item(committed: &CommittedResult) -> DeliveryClaim {
    DeliveryClaim {
        outbox_item_id: committed.outbox_item_id.clone(),
        logical_message_id: committed.logical_message.id.clone(),
        re_executed_effects: false,
    }
}

/// Records a started send with a lost acknowledgement as `UNKNOWN`.
///
/// Only a [`SinkPhase::SendStarted`] attempt becomes
/// [`SinkPhase::Unknown`]; any other phase rejects the transition with
/// [`BridgeError::ResendNotAllowed`], so a reconciled attempt is never
/// rewritten to unknown.
pub fn record_lost_ack(prior: &DeliveryAttempt) -> Result<DeliveryAttempt, BridgeError> {
    if prior.phase != SinkPhase::SendStarted {
        return Err(BridgeError::ResendNotAllowed);
    }
    Ok(DeliveryAttempt {
        phase: SinkPhase::Unknown,
        ..prior.clone()
    })
}

/// One policy-driven resend: the preserved unknown attempt plus the new
/// marked attempt for the same logical message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResendPair {
    /// The original unknown attempt, preserved untouched.
    pub preserved_unknown: DeliveryAttempt,
    /// The new attempt, marked as a possible duplicate.
    pub produced: DeliveryAttempt,
}

/// Creates a new marked delivery attempt for the same logical message while
/// preserving the original unknown attempt.
///
/// The prior attempt must still be [`SinkPhase::Unknown`], it must belong to
/// the same logical message, and the retry must land inside its freshness
/// deadline. The new attempt keeps the prior attempt's absolute freshness
/// deadline: the retry time never extends it, so a resend remains unavailable
/// after the original boundary. The new attempt is marked
/// `possible_duplicate`; the old attempt is preserved, never rewritten.
pub fn resend_as_marked_attempt(
    logical: &LogicalMessage,
    prior: &DeliveryAttempt,
    now_ms: u64,
) -> Result<ResendPair, BridgeError> {
    if prior.phase != SinkPhase::Unknown {
        return Err(BridgeError::ResendNotAllowed);
    }
    if prior.logical_message_id != logical.id {
        return Err(BridgeError::IdentityConflict);
    }
    check_freshness(now_ms, prior.freshness_deadline_ms)?;
    let attempt_id = format!("{}-retry-{now_ms}", prior.attempt_id);
    validate_identity_text(&attempt_id, "delivery_attempt.attempt_id")?;
    let produced = DeliveryAttempt {
        attempt_id,
        logical_message_id: logical.id.clone(),
        phase: SinkPhase::Committed,
        possible_duplicate: true,
        freshness_deadline_ms: prior.freshness_deadline_ms,
    };
    Ok(ResendPair {
        preserved_unknown: prior.clone(),
        produced,
    })
}

/// Checks that the current time still lands inside the freshness deadline.
pub fn check_freshness(now_ms: u64, deadline_ms: u64) -> Result<(), BridgeError> {
    if now_ms > deadline_ms {
        Err(BridgeError::FreshnessElapsed)
    } else {
        Ok(())
    }
}

/// The optional `MessagingBridge` adapter over existing owners.
///
/// The bridge holds only its evidenced profile. Inbound turns resolve through
/// [`resolve_inbound`], outbound files through [`resolve_outbound_file`],
/// inbound media through [`admit_inbound_media`], and delivery through
/// [`claim_committed_item`]. It keeps no store, no scheduler, and no
/// authority; callers hold `Option<MessagingBridge>` and the canonical path
/// never requires one.
#[derive(Clone, Debug)]
pub struct MessagingBridge {
    profile: MessagingBridgeProfile,
}

impl MessagingBridge {
    /// Attaches the bridge for one evidenced profile generation.
    pub fn new(profile: MessagingBridgeProfile) -> Self {
        Self { profile }
    }

    /// Returns the evidenced profile this bridge generation was attached for.
    pub fn profile(&self) -> &MessagingBridgeProfile {
        &self.profile
    }

    /// Resolves one inbound turn with the owner ledger evidence.
    pub fn resolve_inbound(
        &self,
        update: &InboundPlatformUpdate,
        evidence: &InboundLedgerEvidence,
    ) -> Result<InboundResolution, BridgeError> {
        resolve_inbound(&self.profile, update, evidence)
    }

    /// Claims the existing outbox item for a committed result of this
    /// generation, without re-executing any work.
    pub fn claim_committed(
        &self,
        committed: &CommittedResult,
    ) -> Result<DeliveryClaim, BridgeError> {
        if committed.logical_message.generation != self.profile.generation {
            return Err(BridgeError::GenerationMismatch);
        }
        Ok(claim_committed_item(committed))
    }

    /// Resolves one outbound file request to an authorized immutable handle.
    pub fn resolve_outbound(
        &self,
        request: &OutboundFileRequest,
        owner: &dyn ArtifactResolutionPort,
    ) -> Result<DisclosedArtifactHandle, BridgeError> {
        self.profile
            .capabilities
            .require(Capability::MediaOutbound, "media.outbound")?;
        resolve_outbound_file(request, owner)
    }

    /// Admits one inbound media object through the owning admission policy.
    pub fn admit_media(
        &self,
        media: &InboundMedia,
        owner: &dyn MediaAdmissionPort,
    ) -> Result<DisclosedArtifactHandle, BridgeError> {
        admit_inbound_media(&self.profile, media, owner)
    }
}
