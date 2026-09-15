//! Shared test-only bounded readiness retry for isolated Surreal provider harnesses.
//!
//! Mirrors `apply/read_boundary.rs:1274-1311` (PR #1488): retry `connect()`
//! until a ~30s shared deadline with 100ms backoff clamped to the deadline,
//! keeping the last error and reporting it on timeout. The failed adapter is
//! dropped before each retry because `SurrealStoreAdapter.client` caches its
//! first connection outcome; no migration or canonical operation has run yet.
//!
//! Test-only: this file is included once via `#[path]` from the
//! `payload_tests` harness (`pub(super)` to `client`) and reused from the
//! `ownership_tests` harness. It is never declared from production
//! code, adds no public API, no new dependency, no `#[ignore]`, and no
//! crate-wide serialization.
#![allow(clippy::expect_used, clippy::large_futures)]

use std::path::Path;
use std::time::Duration;
use tokio::time::{Instant, sleep};

use eliot_platform_windows::WindowsPlatform;

use crate::{SurrealAdapterConfig, SurrealStoreAdapter};

/// Retry authenticated provider connection until a shared 30s deadline.
///
/// `slot` holds the harness adapter (`None` between attempts). A fresh
/// process lease plus `SurrealStoreAdapter::new` is acquired per attempt,
/// then `connect()` is bounded by the shared deadline via `timeout_at`.
/// On success the live adapter is left in `slot`; on timeout the slot is
/// cleared and a panic reports the last observed error.
pub(crate) async fn connect_with_readiness_retry(
    root: &Path,
    config: &SurrealAdapterConfig,
    slot: &mut Option<SurrealStoreAdapter>,
) {
    let platform = WindowsPlatform::new(root.to_path_buf()).expect("platform");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_error = None;
    loop {
        let lease = platform
            .retain_process_path_lease(
                Path::new(&config.provider_executable_path),
                Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .expect("process lease");
        *slot = Some(SurrealStoreAdapter::new(config.clone(), lease).expect("adapter"));
        let adapter = slot.as_ref().expect("live adapter");
        match tokio::time::timeout_at(deadline, adapter.connect()).await {
            Ok(Ok(())) => return,
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                *slot = None;
                panic!(
                    "authenticated provider readiness timed out; last error: {last_error:?}"
                );
            }
        }
        // The adapter caches its first connection result. Drop the
        // failed attempt before retrying startup in this isolated root;
        // no migration or canonical operation has been submitted yet.
        *slot = None;
        assert!(
            Instant::now() < deadline,
            "authenticated provider readiness timed out; last error: {last_error:?}"
        );
        sleep(
            Duration::from_millis(100)
                .min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
    }
}
