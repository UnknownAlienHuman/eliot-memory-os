//! Canonical Watchdog fallback declaration renderer (issue #1780, I11.6).
//!
//! The per-user `eliot-notify.exe` image is staged and receipted by the
//! Phase-A source-bundle producer; its installed path and artifact digest
//! must additionally be recorded in the installer-owned fallback
//! verification declaration (`Eliot/notify/watchdog-verification.json`)
//! that the fallback route reads. This module renders those exact canonical
//! bytes from explicit installer inputs — it performs no machine writes,
//! generates no keys, and reads no ambient state. The caller (Host Phase-B
//! per-user setup) writes the returned bytes to the protected declaration
//! path and registers the Task Scheduler fallback against them; B3's daemon
//! caller later reads the same two fields back through
//! [`notify_binding_from_declaration`](crate::installed_binary::notify_binding_from_declaration).
//!
//! The rendered bytes are canonical JSON over [`FallbackVerificationDeclaration`],
//! so they satisfy the reader's canonical-bytes equality and
//! [`validate_fallback_declaration`](super::fallback_verification::validate_fallback_declaration)
//! gates by construction. The returned declaration digest is the
//! `verifier_sha256` pin consumed by `WatchdogTaskRegistration::new`.

use eliot_platform::PlatformHandle;
use eliot_receipts::canonical_json_bytes;

use super::fallback_verification::{
    FallbackVerificationDeclaration, sha256_hex, validate_fallback_declaration,
};
use crate::FALLBACK_VERIFIER_RELATIVE;

/// Explicit installer inputs for one fallback declaration publication.
///
/// Every value arrives from the installer lane: installation identity and
/// authority epoch from the installation record, the Watchdog signing key
/// material from the installer key ceremony (public half only — the private
/// key never enters this module), the interactive SID/session for the
/// authorizing user, and the staged notify path/digest from the Phase-A
/// publication receipt. Nothing is defaulted, probed, or inferred.
#[derive(Clone, Debug)]
pub struct NotifyDeclarationInputs {
    /// Installation identity bound to the declaration.
    pub installation_identity: PlatformHandle,
    /// Declared audience for the fallback route.
    pub audience: PlatformHandle,
    /// Non-zero authority epoch.
    pub authority_epoch: u64,
    /// Watchdog signing key identifier.
    pub key_id: PlatformHandle,
    /// Lowercase hex Watchdog verifying key (64 characters).
    pub public_key: String,
    /// Absolute installed path of the `eliot-notify` image.
    pub notify_executable: String,
    /// Lowercase SHA-256 of the installed image bytes.
    pub notify_artifact_sha256: String,
    /// Interactive user SID (`S-1-…`).
    pub interactive_user_sid: String,
    /// Interactive session id (non-zero).
    pub interactive_session_id: u32,
}

/// Rendered declaration publication: destination plus exact bytes.
///
/// The caller writes `canonical_bytes` to the protected resolution of
/// `relative_path` and pins `declaration_digest` as the verifier digest.
/// Bytes are canonical JSON; re-parsing and re-encoding them yields the
/// identical bytes, which is exactly what the fallback loader requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedNotifyDeclaration {
    /// Protected relative declaration path (`Eliot/notify/…`).
    pub relative_path: &'static str,
    /// Canonical JSON declaration bytes to publish.
    pub canonical_bytes: Vec<u8>,
    /// SHA-256 of the canonical bytes (verifier pin).
    pub declaration_digest: String,
}

/// Fail-closed declaration render errors. Field names only — no values,
/// paths, or key material are echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyDeclarationError {
    /// One named input field is malformed.
    InvalidField(&'static str),
    /// Canonical serialization failed.
    Unencodable,
}

impl NotifyDeclarationError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "NOTIFY_DECLARATION_INVALID_FIELD",
            Self::Unencodable => "NOTIFY_DECLARATION_UNENCODABLE",
        }
    }

    /// Name of the rejected input field, if any.
    #[must_use]
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::InvalidField(field) => Some(field),
            Self::Unencodable => None,
        }
    }
}

impl std::fmt::Display for NotifyDeclarationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField(field) => {
                write!(formatter, "NOTIFY_DECLARATION_INVALID_FIELD:{field}")
            }
            Self::Unencodable => formatter.write_str(Self::Unencodable.code()),
        }
    }
}

impl std::error::Error for NotifyDeclarationError {}

/// Renders one canonical fallback declaration from explicit installer inputs.
///
/// Builds the installer-owned declaration, enforces the reader's validation
/// gates before returning, and proves canonical-bytes stability by
/// re-parsing and re-encoding. The caller publishes the bytes; B3 consumes
/// the `notify_executable` / `notify_artifact_sha256` fields back through
/// the installed-binary binding.
///
/// # Errors
///
/// Returns [`NotifyDeclarationError::InvalidField`] naming the rejected
/// input, or [`NotifyDeclarationError::Unencodable`] when canonical
/// serialization fails.
pub fn render_notify_fallback_declaration(
    inputs: &NotifyDeclarationInputs,
) -> Result<RenderedNotifyDeclaration, NotifyDeclarationError> {
    let declaration = FallbackVerificationDeclaration {
        installation_identity: inputs.installation_identity.clone(),
        audience: inputs.audience.clone(),
        authority_epoch: inputs.authority_epoch,
        algorithm: crate::WATCHDOG_SIGNATURE_ALGORITHM.to_owned(),
        key_id: inputs.key_id.clone(),
        domain: crate::WATCHDOG_SIGNATURE_DOMAIN.to_owned(),
        public_key: inputs.public_key.clone(),
        notify_executable: inputs.notify_executable.clone(),
        notify_artifact_sha256: inputs.notify_artifact_sha256.clone(),
        interactive_user_sid: inputs.interactive_user_sid.clone(),
        interactive_session_id: inputs.interactive_session_id,
    };
    validate_fallback_declaration(&declaration)
        .map_err(|_| NotifyDeclarationError::InvalidField("declaration"))?;
    let canonical_bytes =
        canonical_json_bytes(&declaration).map_err(|_| NotifyDeclarationError::Unencodable)?;
    let reparsed: FallbackVerificationDeclaration = serde_json::from_slice(&canonical_bytes)
        .map_err(|_| NotifyDeclarationError::Unencodable)?;
    if reparsed != declaration {
        return Err(NotifyDeclarationError::Unencodable);
    }
    let canonical_again =
        canonical_json_bytes(&reparsed).map_err(|_| NotifyDeclarationError::Unencodable)?;
    if canonical_again != canonical_bytes {
        return Err(NotifyDeclarationError::Unencodable);
    }
    Ok(RenderedNotifyDeclaration {
        relative_path: FALLBACK_VERIFIER_RELATIVE,
        declaration_digest: sha256_hex(&canonical_bytes),
        canonical_bytes,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn valid_inputs() -> NotifyDeclarationInputs {
        use ed25519_dalek::SigningKey;
        let verifying = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let public_key = verifying
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        NotifyDeclarationInputs {
            installation_identity: PlatformHandle::new("installation:test").expect("identity"),
            audience: PlatformHandle::new("audience:test").expect("audience"),
            authority_epoch: 7,
            key_id: PlatformHandle::new("key:test").expect("key id"),
            public_key,
            notify_executable: "C:\\Eliot\\eliot-notify.exe".to_owned(),
            notify_artifact_sha256: "cd".repeat(32),
            interactive_user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            interactive_session_id: 1,
        }
    }

    #[test]
    fn valid_inputs_render_canonical_verifiable_bytes() {
        let rendered =
            render_notify_fallback_declaration(&valid_inputs()).expect("valid inputs render");
        assert_eq!(
            rendered.relative_path,
            "Eliot/notify/watchdog-verification.json"
        );
        assert_eq!(
            rendered.declaration_digest,
            sha256_hex(&rendered.canonical_bytes)
        );
        let declaration: FallbackVerificationDeclaration =
            serde_json::from_slice(&rendered.canonical_bytes).expect("bytes parse");
        validate_fallback_declaration(&declaration).expect("rendered declaration validates");
        assert_eq!(declaration.notify_executable, "C:\\Eliot\\eliot-notify.exe");
        assert_eq!(declaration.notify_artifact_sha256, "cd".repeat(32));
        let again = canonical_json_bytes(&declaration).expect("re-encode canonical");
        assert_eq!(again, rendered.canonical_bytes);
    }

    #[test]
    fn malformed_inputs_fail_closed_by_field() {
        let base = valid_inputs();
        let mut zero_epoch = base.clone();
        zero_epoch.authority_epoch = 0;
        assert_eq!(
            render_notify_fallback_declaration(&zero_epoch).map(|_| ()),
            Err(NotifyDeclarationError::InvalidField("declaration"))
        );
        let mut relative_exe = base.clone();
        relative_exe.notify_executable = "eliot-notify.exe".to_owned();
        assert_eq!(
            render_notify_fallback_declaration(&relative_exe).map(|_| ()),
            Err(NotifyDeclarationError::InvalidField("declaration"))
        );
        let mut bad_digest = base.clone();
        bad_digest.notify_artifact_sha256 = "NOT-HEX".to_owned();
        assert_eq!(
            render_notify_fallback_declaration(&bad_digest).map(|_| ()),
            Err(NotifyDeclarationError::InvalidField("declaration"))
        );
        let mut bad_sid = base.clone();
        bad_sid.interactive_user_sid = "not-a-sid".to_owned();
        assert_eq!(
            render_notify_fallback_declaration(&bad_sid).map(|_| ()),
            Err(NotifyDeclarationError::InvalidField("declaration"))
        );
        let mut zero_session = base.clone();
        zero_session.interactive_session_id = 0;
        assert_eq!(
            render_notify_fallback_declaration(&zero_session).map(|_| ()),
            Err(NotifyDeclarationError::InvalidField("declaration"))
        );
        let mut bad_key = base.clone();
        bad_key.public_key = "zz".to_owned();
        assert_eq!(
            render_notify_fallback_declaration(&bad_key).map(|_| ()),
            Err(NotifyDeclarationError::InvalidField("declaration"))
        );
        assert_eq!(
            NotifyDeclarationError::InvalidField("declaration").code(),
            "NOTIFY_DECLARATION_INVALID_FIELD"
        );
    }

    #[test]
    fn production_section_uses_no_ambient_authority_source() {
        // The renderer above the test module takes every value from explicit
        // installer inputs: it never probes the loader path, build output,
        // environment, registry, or filesystem. Tokens are assembled so this
        // scan cannot match itself.
        let source = include_str!("notify_declaration.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section precedes the test module");
        for token in [
            ["current", "_exe"].concat(),
            ["CARGO_BIN", "_EXE"].concat(),
            ["std::", "env"].concat(),
            ["option_", "env"].concat(),
            ["env", "!"].concat(),
            ["CARGO_TARGET", "_DIR"].concat(),
            ["CARGO_MANIFEST", "_DIR"].concat(),
            ["std::", "fs"].concat(),
            ["std::", "process"].concat(),
            ["Command", "::new"].concat(),
        ] {
            assert!(
                !production.contains(&token),
                "ambient authority source in production section: {token}"
            );
        }
    }
}
