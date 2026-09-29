//! Broker-startup Notify fallback ensure (issue #1780, I11.6).
//!
//! The per-user bootstrap trigger: when the broker starts in the interactive
//! session, it ensures the signed Task Scheduler fallback is registered
//! against the installer-published declaration. The declaration itself is
//! installer-published (Host Phase-B per-user setup); this trigger never
//! fabricates one — absence skips explicitly, and a declaration this broker
//! cannot read is *not* absence, so it defers instead. Registration replays
//! the existing notify route, which re-verifies the pinned artifact and the
//! live caller identity before touching the scheduler.
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

/// What the protected declaration path reports to the ensure.
///
/// The contour is per user, so a declaration published for one interactive
/// user is unreadable from another user's broker. A presence probe that
/// collapses every error into "absent" would report that as
/// `skipped_no_declaration` — a state that reads as "nothing was published"
/// and that never changes, hiding a real registration fault (I11.7: a
/// perpetually deferred fallback stays visible). Absence and unreadability are
/// therefore separate observations, never one boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyFallbackDeclaration {
    /// The declaration file is present at the protected path.
    Present,
    /// No declaration file exists at the protected path.
    Absent,
    /// The protected path could not be probed, so presence is unknown.
    Unreadable,
}

/// Injected platform effect seam for the ensure. Production uses
/// [`LiveNotifyFallbackEffects`]; tests inject fakes with scripted
/// presence/registration outcomes and zero machine effects.
pub trait NotifyFallbackEffects {
    /// Whether an installer-published declaration is present (read-only).
    fn declaration_present(&self) -> NotifyFallbackDeclaration;
    /// Registers the signed fallback against the published declaration.
    fn register(&self) -> Result<NotifyFallbackRegistration, CompositionError>;
}

/// Live effect seam: protected declaration presence plus the existing
/// notify registration route.
pub struct LiveNotifyFallbackEffects;

impl NotifyFallbackEffects for LiveNotifyFallbackEffects {
    /// Probes the protected declaration path and reads the error kind rather
    /// than collapsing it: `Path::exists` reports every failure — a denied
    /// traversal, a dangling reparse point, a reparse loop — as "absent",
    /// which would make a per-user contour this broker cannot traverse
    /// indistinguishable from a contour that was never published.
    fn declaration_present(&self) -> NotifyFallbackDeclaration {
        let Ok(path) = eliot_platform_windows::protected_program_data_path(
            "Eliot/notify/watchdog-verification.json",
        ) else {
            return NotifyFallbackDeclaration::Unreadable;
        };
        match std::fs::metadata(&path) {
            Ok(_) => NotifyFallbackDeclaration::Present,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                NotifyFallbackDeclaration::Absent
            }
            Err(_) => NotifyFallbackDeclaration::Unreadable,
        }
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

/// Stable deferral code for a declaration path this broker could not probe.
/// It is a distinct code rather than a reused one so the operator can tell
/// "the installer published nothing" from "the protected contour is not
/// readable as this user".
const DECLARATION_UNREADABLE: &str = "DECLARATION_UNREADABLE";

/// Ensures fallback registration through the injected effect seam.
///
/// Absence skips explicitly; an unprobeable declaration and a registration
/// failure both defer with a stable code, so a fault in the protected
/// contour stays visible instead of reading as "nothing was published".
/// This function cannot fail: fallback delivery is optional next to normal
/// launch, and broker startup must not depend on it.
pub fn ensure_notify_fallback_registered(
    effects: &impl NotifyFallbackEffects,
) -> NotifyFallbackEnsure {
    match effects.declaration_present() {
        NotifyFallbackDeclaration::Absent => return NotifyFallbackEnsure::SkippedNoDeclaration,
        // Presence is unknown, not disproven. `SkippedNoDeclaration` would
        // claim the installer published nothing and stop retrying for a
        // different reason; deferring keeps the outcome honest and retried.
        NotifyFallbackDeclaration::Unreadable => {
            return NotifyFallbackEnsure::Deferred {
                reason: DECLARATION_UNREADABLE,
            };
        }
        NotifyFallbackDeclaration::Present => {}
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
        CompositionError::OperationIdentityLedger(_) => "OPERATION_IDENTITY_LEDGER",
        CompositionError::LostOperation { .. } => "LOST_OPERATION",
        CompositionError::Admission { refusal, .. } => refusal.code(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    struct FakeEffects {
        declaration: NotifyFallbackDeclaration,
        fail_register: bool,
    }

    impl NotifyFallbackEffects for FakeEffects {
        fn declaration_present(&self) -> NotifyFallbackDeclaration {
            self.declaration
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
            declaration: NotifyFallbackDeclaration::Absent,
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
            declaration: NotifyFallbackDeclaration::Present,
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
            declaration: NotifyFallbackDeclaration::Present,
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
