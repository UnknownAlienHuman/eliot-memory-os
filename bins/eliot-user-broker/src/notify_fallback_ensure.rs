//! Broker-startup Notify fallback ensure (issue #1780, I11.6).
//!
//! The per-user bootstrap trigger: when the broker starts in the interactive
//! session, it ensures the signed Task Scheduler fallback is registered
//! against the installer-published declaration. The declaration itself is
//! installer-published (Host Phase-B per-user setup); this trigger never
//! fabricates one — absence skips explicitly. Registration replays the
//! existing notify route, which re-verifies the pinned artifact and the live
//! caller identity before touching the scheduler.
//!
//! The ensure is best-effort and infallible by design: fallback delivery is
//! optional next to normal User-Broker launch, so a deferred ensure must
//! never fail broker startup. Deferral retries on the next start. Effects
//! cross the [`NotifyFallbackEffects`] seam so tests inject fakes; only the
//! live impl touches the machine, and only through the existing
//! installer-owned record and registration route.

use crate::CompositionError;

/// Installer-observed fallback registration evidence carried by ensure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyFallbackRegistration {
    /// Scheduler task name.
    pub task_name: String,
    /// Verifier digest pinned at registration.
    pub verifier_sha256: String,
}

/// Injected platform effect seam for the ensure. Production uses
/// [`LiveNotifyFallbackEffects`]; tests inject fakes with scripted
/// presence/registration outcomes and zero machine effects.
pub trait NotifyFallbackEffects {
    /// Whether an installer-published declaration is present (read-only).
    fn declaration_present(&self) -> bool;
    /// Registers the signed fallback against the published declaration.
    fn register(&self) -> Result<NotifyFallbackRegistration, CompositionError>;
}

/// Live effect seam: protected declaration presence plus the existing
/// notify registration route.
pub struct LiveNotifyFallbackEffects;

impl NotifyFallbackEffects for LiveNotifyFallbackEffects {
    fn declaration_present(&self) -> bool {
        eliot_platform_windows::protected_program_data_path(
            "Eliot/notify/watchdog-verification.json",
        )
        .is_ok_and(|path| std::path::Path::new(&path).exists())
    }

    fn register(&self) -> Result<NotifyFallbackRegistration, CompositionError> {
        let receipt = eliot_notify::register_watchdog_fallback_task()
            .map_err(|error| CompositionError::Launch(error.to_string()))?;
        Ok(NotifyFallbackRegistration {
            task_name: receipt.task_name().to_owned(),
            verifier_sha256: receipt.verifier_sha256().to_owned(),
        })
    }
}

/// Best-effort ensure outcome. `Deferred` retries on the next broker start;
/// broker startup never fails for fallback setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyFallbackEnsure {
    /// Fallback registered against the published declaration.
    Registered {
        /// Scheduler task name.
        task_name: String,
        /// Verifier digest pinned at registration.
        verifier_sha256: String,
    },
    /// No installer-published declaration present; nothing fabricated.
    SkippedNoDeclaration,
    /// Registration failed; retry on the next start. Reason is a stable
    /// variant code, never a path or payload.
    Deferred {
        /// Stable deferral code.
        reason: &'static str,
    },
}

impl NotifyFallbackEnsure {
    /// Diagnostic projection of the outcome for the broker `Ready` channel
    /// (I11.7: failed delivery remains visible). Carries only the stable
    /// state and, when deferred, the stable reason code — never task names,
    /// digests, paths, or payloads.
    #[must_use]
    pub fn status_value(&self) -> serde_json::Value {
        match self {
            Self::Registered { .. } => {
                serde_json::json!({"state": "registered"})
            }
            Self::SkippedNoDeclaration => {
                serde_json::json!({"state": "skipped_no_declaration"})
            }
            Self::Deferred { reason } => {
                serde_json::json!({"state": "deferred", "reason": reason})
            }
        }
    }
}

/// Ensures fallback registration through the injected effect seam.
///
/// Absence skips explicitly; registration failure defers with a stable code.
/// This function cannot fail: fallback delivery is optional next to normal
/// launch, and broker startup must not depend on it.
pub fn ensure_notify_fallback_registered(
    effects: &impl NotifyFallbackEffects,
) -> NotifyFallbackEnsure {
    if !effects.declaration_present() {
        return NotifyFallbackEnsure::SkippedNoDeclaration;
    }
    match effects.register() {
        Ok(registration) => NotifyFallbackEnsure::Registered {
            task_name: registration.task_name,
            verifier_sha256: registration.verifier_sha256,
        },
        Err(error) => NotifyFallbackEnsure::Deferred {
            reason: ensure_deferral_code(&error),
        },
    }
}

fn ensure_deferral_code(error: &CompositionError) -> &'static str {
    match error {
        CompositionError::InvalidConfiguration(_) => "INVALID_CONFIGURATION",
        CompositionError::Durable(_) => "DURABLE",
        CompositionError::Encoding(_) => "ENCODING",
        CompositionError::Protected(_) => "PROTECTED",
        CompositionError::Launch(_) => "LAUNCH",
        CompositionError::Recovery(_) => "RECOVERY",
        CompositionError::Kernel(_) => "KERNEL",
        CompositionError::KernelLock => "KERNEL_LOCK",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    struct FakeEffects {
        present: bool,
        fail_register: bool,
    }

    impl NotifyFallbackEffects for FakeEffects {
        fn declaration_present(&self) -> bool {
            self.present
        }

        fn register(&self) -> Result<NotifyFallbackRegistration, CompositionError> {
            if self.fail_register {
                return Err(CompositionError::Launch("injected".to_owned()));
            }
            Ok(NotifyFallbackRegistration {
                task_name: "task".to_owned(),
                verifier_sha256: "v".repeat(64),
            })
        }
    }

    #[test]
    fn absent_declaration_skips_without_registering() {
        let effects = FakeEffects {
            present: false,
            fail_register: true,
        };
        assert_eq!(
            ensure_notify_fallback_registered(&effects),
            NotifyFallbackEnsure::SkippedNoDeclaration
        );
    }

    #[test]
    fn present_declaration_registers_task_evidence() {
        let effects = FakeEffects {
            present: true,
            fail_register: false,
        };
        assert_eq!(
            ensure_notify_fallback_registered(&effects),
            NotifyFallbackEnsure::Registered {
                task_name: "task".to_owned(),
                verifier_sha256: "v".repeat(64),
            }
        );
    }

    #[test]
    fn registration_failure_defers_with_stable_code() {
        let effects = FakeEffects {
            present: true,
            fail_register: true,
        };
        assert_eq!(
            ensure_notify_fallback_registered(&effects),
            NotifyFallbackEnsure::Deferred { reason: "LAUNCH" }
        );
        assert_eq!(
            ensure_deferral_code(&CompositionError::KernelLock),
            "KERNEL_LOCK"
        );
    }

    #[test]
    fn production_section_uses_no_ambient_authority_source() {
        // The ensure above the test module takes every input through the
        // injected effect seam or explicit caller values: it never probes
        // the loader path, build output, environment, or registry. Tokens
        // are assembled so this scan cannot match itself.
        let source = include_str!("notify_fallback_ensure.rs");
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
        ] {
            assert!(
                !production.contains(&token),
                "ambient authority source in production section: {token}"
            );
        }
    }
}
