//! Kernel-side automation notification delivery client (#1779/#1780).
//!
//! Production [`UserAutomationNotificationPort`] that carries an
//! already-recorded automation failure to the `eliot-notify` binary over its
//! existing stdin JSON route (`Request::DeliverUserAutomationFailure` in
//! `bins/eliot-notify/src/main.rs`) and maps the stdout response back to the
//! port vocabulary. This is the concrete cross-process transport: the
//! closure-based bin adapter cannot cross into Kernel in-process
//! composition, so this client owns the spawn/write/wait/parse sequence
//! instead of delegating to it.
//!
//! Trust rules (nothing invented, nothing guessed):
//!
//! - the binary path is an explicit constructor input validated as an
//!   absolute existing file. There is no installed-path resolver in-repo
//!   (installer fields are B2-owned); no default path, registry guess, or
//!   shadow binding is ever synthesized. When B2 lands a resolver, adopt it
//!   at the single construction site.
//! - working directory and environment are inherited unchanged: a one-shot
//!   stdin/stdout child with no file access needs no invented paths, and
//!   Windows children require their ambient environment.
//! - the child is reaped with `kill_on_drop` plus a bounded wait; output is
//!   length-capped. A timeout kills the child via drop and reports unknown
//!   outcome — never success, never silent retry.
//!
//! Outcome taxonomy (mirrors the unknown-outcome doctrine):
//!
//! - pre-transport validation or construction failures → `Rejected`
//!   (terminal, surfaces loudly; includes a `REQUEST_INVALID` answer,
//!   which means our own construction was wrong).
//! - spawn/setup failures where no effect could occur → `Unavailable`.
//! - anything after dispatch that is not a fully validated delivered
//!   observation (timeout, bad exit, unparseable or incomplete response) →
//!   `UnknownOutcome`: the notification may have been delivered, so the
//!   owner must reconcile rather than assume either way.

use std::path::{Path, PathBuf};
use std::time::Duration;

use eliot_kernel_service::{
    UserAutomationFailureRecord, UserAutomationNotificationDelivery,
    UserAutomationNotificationPort, UserAutomationRuntimeError,
};
use eliot_notify_core::{
    DeliveryObservation, UserAutomationFailureRequest, audience_for_envelope,
    failure_artifact_digest,
};
use eliot_platform::{NotificationRequest, PlatformHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bounded wait for one notify invocation (front-door 30s precedent).
pub const NOTIFY_SPAWN_TIMEOUT: Duration = Duration::from_secs(30);
/// Length cap on the notify stdout frame (1 MiB bound precedents).
pub const NOTIFY_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
/// Exact stdin op spelling owned by `bins/eliot-notify/src/main.rs`.
const DELIVER_OP: &str = "deliver_user_automation_failure";

/// Kernel-side delivery client invoking the notify binary.
///
/// Construct with the installer-owned binary path; see the module docs for
/// why no path is ever synthesized here.
pub struct KernelNotificationClient {
    notify_exe: PathBuf,
}

impl KernelNotificationClient {
    /// Binds an explicit installed binary path. Rejects relative, missing,
    /// or non-file paths instead of guessing.
    pub fn new(notify_exe: PathBuf) -> Result<Self, UserAutomationRuntimeError> {
        if !notify_exe.is_absolute() || !notify_exe.is_file() {
            return Err(UserAutomationRuntimeError::Rejected(
                "notify executable path must be an absolute existing file".to_owned(),
            ));
        }
        Ok(Self { notify_exe })
    }

    /// Returns the bound binary path.
    #[must_use]
    pub fn notify_exe(&self) -> &Path {
        &self.notify_exe
    }
}

/// Builds the exact stdin frame for the notify `DeliverUserAutomationFailure`
/// op. Field-for-field mirror of `Request::DeliverUserAutomationFailure` in
/// `bins/eliot-notify/src/main.rs`; any drift fails closed there as
/// `REQUEST_INVALID`, which maps back to `Rejected` below.
fn request_frame(
    failure: &UserAutomationFailureRequest,
    parent: &NotificationRequest,
) -> serde_json::Value {
    serde_json::json!({
        "op": DELIVER_OP,
        "failure": failure,
        "request": parent,
    })
}

/// Interprets one notify stdout frame.
///
/// A `delivered` status with a fully decodable observation is the only
/// success. A `REQUEST_INVALID` error answers our own construction bug and
/// rejects loudly; every other outcome (error status, unparseable bytes,
/// missing fields) is unknown — the notification may have been delivered.
fn interpret_response(stdout: &[u8]) -> Result<DeliveryObservation, UserAutomationRuntimeError> {
    let value: serde_json::Value = serde_json::from_slice(stdout).map_err(|_| {
        UserAutomationRuntimeError::UnknownOutcome("unparseable notify response".to_owned())
    })?;
    match value.get("status").and_then(serde_json::Value::as_str) {
        Some("delivered") => {
            let observation = value
                .get("observation")
                .cloned()
                .ok_or_else(|| {
                    UserAutomationRuntimeError::UnknownOutcome(
                        "delivered response carries no observation".to_owned(),
                    )
                })
                .and_then(|observation| {
                    serde_json::from_value(observation).map_err(|_| {
                        UserAutomationRuntimeError::UnknownOutcome(
                            "delivered observation undecodable".to_owned(),
                        )
                    })
                })?;
            Ok(observation)
        }
        Some("error") => {
            let code = value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let detail = value
                .get("detail")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("notify error")
                .to_owned();
            if code == "REQUEST_INVALID" {
                Err(UserAutomationRuntimeError::Rejected(detail))
            } else {
                Err(UserAutomationRuntimeError::UnknownOutcome(detail))
            }
        }
        _ => Err(UserAutomationRuntimeError::UnknownOutcome(
            "unknown notify status".to_owned(),
        )),
    }
}

#[allow(async_fn_in_trait)]
impl UserAutomationNotificationPort for KernelNotificationClient {
    async fn deliver_user_automation_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationNotificationDelivery, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let failure = UserAutomationFailureRequest::from_owner_failure(
            &request.failure,
            &request.preflight.source_receipt,
            &request.revision.automation_id,
            &request.revision.revision,
            &request.context.state_fence,
        )
        .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let envelope = failure
            .clone()
            .into_notification_envelope()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let body_digest = failure_artifact_digest(&envelope.source_receipt.core.artifacts)
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let parent = NotificationRequest {
            context: request.context.clone(),
            notification: envelope.notification_id.clone(),
            canonical_request_hash: PlatformHandle::new(envelope.source_receipt.canonical_sha256())
                .map_err(|_| {
                    UserAutomationRuntimeError::Rejected(
                        "automation canonical request hash invalid".to_owned(),
                    )
                })?,
            audience: audience_for_envelope(&envelope.recipients)
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?,
            body_digest: PlatformHandle::new(body_digest).map_err(|_| {
                UserAutomationRuntimeError::Rejected("automation body digest invalid".to_owned())
            })?,
        };
        let observation = self.invoke(&failure, &parent).await?;
        let delivery = UserAutomationNotificationDelivery {
            state_fence: request.context.state_fence.clone(),
            dedup_key: envelope.canonical.dedup_key.clone(),
            deduplicated: observation.deduplicated,
            notification_receipt_ref: None,
        };
        delivery
            .validate_for(&request)
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        Ok(delivery)
    }
}

impl KernelNotificationClient {
    async fn invoke(
        &self,
        failure: &UserAutomationFailureRequest,
        parent: &NotificationRequest,
    ) -> Result<DeliveryObservation, UserAutomationRuntimeError> {
        let mut frame = serde_json::to_vec(&request_frame(failure, parent)).map_err(|_| {
            UserAutomationRuntimeError::Rejected("automation request unserializable".to_owned())
        })?;
        frame.push(b'\n');
        let mut child = tokio::process::Command::new(&self.notify_exe)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                UserAutomationRuntimeError::Unavailable(format!(
                    "notify executable did not spawn: {error}"
                ))
            })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            UserAutomationRuntimeError::Unavailable("notify stdin unavailable".to_owned())
        })?;
        if stdin.write_all(&frame).await.is_err() {
            return Err(UserAutomationRuntimeError::UnknownOutcome(
                "notify stdin write failed".to_owned(),
            ));
        }
        drop(stdin);
        let outcome = tokio::time::timeout(NOTIFY_SPAWN_TIMEOUT, async {
            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| {
                    UserAutomationRuntimeError::Unavailable("notify stdout unavailable".to_owned())
                })?
                .take(NOTIFY_MAX_RESPONSE_BYTES);
            let mut bytes = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stdout, &mut bytes)
                .await
                .map_err(|_| {
                    UserAutomationRuntimeError::UnknownOutcome(
                        "notify stdout unreadable".to_owned(),
                    )
                })?;
            child.wait().await.map_err(|_| {
                UserAutomationRuntimeError::UnknownOutcome("notify wait failed".to_owned())
            })?;
            interpret_response(&bytes)
        })
        .await
        .map_err(|_| {
            UserAutomationRuntimeError::UnknownOutcome("notify invocation timed out".to_owned())
        })??;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(case: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "eliot-notify-client-test-{}-{}",
            std::process::id(),
            case
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn constructor_rejects_non_absolute_missing_and_directory_paths() {
        assert!(KernelNotificationClient::new(PathBuf::from("relative/eliot-notify.exe")).is_err());
        let missing = unique_temp_dir("missing").join("eliot-notify.exe");
        assert!(KernelNotificationClient::new(missing).is_err());
        let dir = unique_temp_dir("dir");
        assert!(KernelNotificationClient::new(dir).is_err());
        let file = unique_temp_dir("file").join("eliot-notify.exe");
        std::fs::write(&file, b"stub").expect("stub binary");
        let client = KernelNotificationClient::new(file.clone()).expect("valid path");
        assert_eq!(client.notify_exe(), file.as_path());
        let _ = std::fs::remove_dir_all(file.parent().expect("parent"));
    }

    #[test]
    fn error_and_garbage_responses_map_without_success() {
        assert!(matches!(
            interpret_response(b"\x00\x01 not json",),
            Err(UserAutomationRuntimeError::UnknownOutcome(_))
        ));
        assert!(matches!(
            interpret_response(br#"{"status":"mystery"}"#),
            Err(UserAutomationRuntimeError::UnknownOutcome(_))
        ));
        assert!(matches!(
            interpret_response(
                br#"{"status":"error","code":"NOTIFICATION_PROVIDER_REJECTED","detail":"boom"}"#
            ),
            Err(UserAutomationRuntimeError::UnknownOutcome(_))
        ));
        assert!(matches!(
            interpret_response(
                br#"{"status":"error","code":"REQUEST_INVALID","detail":"bad shape"}"#
            ),
            Err(UserAutomationRuntimeError::Rejected(_))
        ));
        assert!(matches!(
            interpret_response(br#"{"status":"delivered"}"#),
            Err(UserAutomationRuntimeError::UnknownOutcome(_))
        ));
    }
}
