//! Compatibility exports for the installer-owned Notify fallback declaration contract.

#[cfg(test)]
use crate::fallback_verification::sha256_hex;
#[cfg(test)]
use eliot_notify_core::{FallbackVerificationDeclaration, validate_fallback_declaration};
#[cfg(test)]
use eliot_platform::PlatformHandle;
#[cfg(test)]
use eliot_receipts::canonical_json_bytes;

pub use eliot_notify_core::{
    NotifyDeclarationError, NotifyDeclarationInputs, RenderedNotifyDeclaration,
    render_notify_fallback_declaration,
};
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
