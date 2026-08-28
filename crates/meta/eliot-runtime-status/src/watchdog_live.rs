//! Watchdog live observation — read-only Watchdog liveness.
//!
//! Architecture A13.2 (Kernel/failure-domain health/unavailable guarantees, module lifecycle):
//! Watchdog live is proven only via exact SCM registration, handle-bound supervision
//! lease and bounded heartbeat freshness; unavailable health is the default.
//! Implementation I16.1 (reports/projections are not truth):
//! this module projects the Watchdog heartbeat as a read-only projection, not truth.

use std::path::{Path, PathBuf};
use std::time::Instant;

use eliot_installation::CandidateManifest;

#[cfg(windows)]
use crate::supervision_verification::verify_host_supervision_bundle;

pub(super) fn watchdog_gap() -> String {
    "Watchdog live requires exact canonical SCM/process admission, current signed supervision lease and bounded heartbeat bound to that revision".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogLiveSnapshot {
    pub observed_at_unix_ms: u64,
    pub heartbeat_unix_ms: u64,
    pub lease_verified: bool,
}

pub trait WatchdogLiveObserver {
    fn observe_watchdog_live(
        &self,
        deadline: Instant,
    ) -> Result<Option<WatchdogLiveSnapshot>, String>;
}

#[allow(clippy::too_many_lines, clippy::needless_return)]
pub(super) fn inspect_watchdog_live(
    host_state: Option<&eliot_host_state::HostState>,
    manifest: Option<&eliot_installation::CandidateManifest>,
    ors: &crate::OrsContour,
    host_service: &crate::ServiceRegistrationState,
    watchdog_service: &crate::ServiceRegistrationState,
    observer: Option<&dyn WatchdogLiveObserver>,
    deadline: Instant,
) -> crate::ComponentState {
    if Instant::now() >= deadline {
        return crate::unknown_component(
            "Watchdog",
            "deadline exceeded before Watchdog inspection".to_owned(),
        );
    }
    if !matches!(ors.state, crate::ComponentState::Healthy) {
        return crate::unknown_component(
            "Watchdog",
            format!(
                "ORS supervision is not Healthy; Watchdog heartbeat cannot be proven: {:?}",
                ors.state
            ),
        );
    }
    let Some(_host_state) = host_state else {
        return crate::unknown_component(
            "Watchdog",
            "no HostState for Watchdog; Host journal is not validated".to_owned(),
        );
    };
    let Some(_manifest) = manifest else {
        return crate::unknown_component(
            "Watchdog",
            "active approved manifest is unavailable; Watchdog admission is not manifest-bound"
                .to_owned(),
        );
    };
    if host_service.registration != "Matching" || watchdog_service.registration != "Matching" {
        return crate::unknown_component(
            "Watchdog",
            format!(
                "SCM registration not Matching: host {} watchdog {}",
                host_service.registration, watchdog_service.registration
            ),
        );
    }
    if host_service.observed_runtime.is_none() || watchdog_service.observed_runtime.is_none() {
        return crate::unknown_component(
            "Watchdog",
            "SCM Running does not prove readiness; handle-bound process identity missing"
                .to_owned(),
        );
    }
    let Some(observer) = observer else {
        return crate::unknown_component(
            "Watchdog",
            "Watchdog live observer unavailable; no default observer is used; Watchdog heartbeat/lease requires independent observation".to_owned(),
        );
    };
    let snapshot = match observer.observe_watchdog_live(deadline) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return crate::unknown_component(
                "Watchdog",
                "Watchdog observer returned no live snapshot; Watchdog is not live".to_owned(),
            );
        }
        Err(e) => {
            return crate::unknown_component("Watchdog", format!("Watchdog observer failed: {e}"));
        }
    };
    if !snapshot.lease_verified {
        return crate::unknown_component(
            "Watchdog",
            "Watchdog lease not verified; Watchdog is not live".to_owned(),
        );
    }
    let now_ms = match crate::current_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            return crate::unknown_component("Watchdog", format!("current time unavailable: {e}"));
        }
    };
    if let Err(e) = crate::is_fresh_typed(snapshot.heartbeat_unix_ms, now_ms, 90_000) {
        return crate::unknown_component("Watchdog", format!("Watchdog heartbeat not fresh: {e}"));
    }
    if let Err(e) = crate::is_fresh_typed(snapshot.observed_at_unix_ms, now_ms, 90_000) {
        return crate::unknown_component(
            "Watchdog",
            format!("Watchdog observed_at not fresh: {e}"),
        );
    }
    crate::ComponentState::Healthy
}

pub struct ProductionWatchdogLiveObserver {
    host_state_root: PathBuf,
    manifest: Option<CandidateManifest>,
}

impl ProductionWatchdogLiveObserver {
    #[cfg(test)]
    pub(super) fn for_root(host_state_root: &Path) -> Self {
        Self {
            host_state_root: host_state_root.to_path_buf(),
            manifest: None,
        }
    }

    pub(super) fn for_manifest(host_state_root: &Path, manifest: &CandidateManifest) -> Self {
        Self {
            host_state_root: host_state_root.to_path_buf(),
            manifest: Some(manifest.clone()),
        }
    }
}

impl WatchdogLiveObserver for ProductionWatchdogLiveObserver {
    #[allow(clippy::needless_return)]
    fn observe_watchdog_live(
        &self,
        deadline: Instant,
    ) -> Result<Option<WatchdogLiveSnapshot>, String> {
        if Instant::now() >= deadline {
            return Err("deadline exceeded before Watchdog observation".to_owned());
        }
        #[cfg(not(windows))]
        {
            let _ = &self.host_state_root;
            return Ok(None);
        }
        #[cfg(windows)]
        {
            if Instant::now() >= deadline {
                return Err("deadline exceeded before Watchdog SCM observation".to_owned());
            }
            let now_ms = crate::current_unix_ms()?;
            let Some(manifest) = self.manifest.as_ref() else {
                return Ok(None);
            };
            let bundle = match verify_host_supervision_bundle(
                &self.host_state_root,
                manifest,
                now_ms,
                deadline,
            ) {
                Ok(envelope) => envelope,
                Err(_) => return Ok(None),
            };
            let heartbeat_ms = bundle.envelope.payload.issued_at_ms;
            Ok(Some(WatchdogLiveSnapshot {
                observed_at_unix_ms: now_ms,
                heartbeat_unix_ms: heartbeat_ms,
                lease_verified: true,
            }))
        }
    }
}
