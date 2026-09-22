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
//!   shadow binding is ever synthesized. The production construction is
//!   B2's exact entry point plus resolution (B-1780 tree,
//!   `bins/eliot-notify/src/installed_binary.rs`):
//!   `notify_binding_from_declaration(decl.notify_executable,
//!   decl.notify_artifact_sha256)` → `resolve_notify_binary(&binding)` →,
//!   `Self::new(installed.path().to_path_buf())`, with no path logic
//!   added here and no eliotd involvement (this client seats in the
//!   kernel bin beside the accepted deliver client; native launch stays
//!   with the Kernel/UserBroker owner per I11.6).
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
//!
//! Read taxonomy (side-effect-free reads differ by exactly one arm):
//!
//! - the `read_inbox` route (`Request::ReadInbox`) carries no canonical
//!   effect, so post-dispatch uncertainty (timeout, unparseable frame,
//!   undecodable read, fence/revision/page mismatch) is `Unavailable` —
//!   nothing to reconcile, safe to retry — never `UnknownOutcome`.
//!   Pre-transport shape failures and `REQUEST_INVALID` stay `Rejected`;
//!   spawn/setup failures stay `Unavailable`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use eliot_kernel_service::{
    UserAutomationFailureRecord, UserAutomationNotificationDelivery,
    UserAutomationNotificationPort, UserAutomationRuntimeError,
};
use eliot_notify_core::{
    DeliveryObservation, NotificationStateReadRequest, NotificationStateReadResponse,
    UserAutomationFailureRequest, audience_for_envelope, failure_artifact_digest,
};
use eliot_platform::{NotificationRequest, PlatformHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bounded wait for one notify invocation (front-door 30s precedent).
pub const NOTIFY_SPAWN_TIMEOUT: Duration = Duration::from_secs(30);
/// Length cap on the notify stdout frame (1 MiB bound precedents).
pub const NOTIFY_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
/// Exact stdin op spelling owned by `bins/eliot-notify/src/main.rs`.
const DELIVER_OP: &str = "deliver_user_automation_failure";
/// Exact stdin op spelling for inbox reads, derived by the same
/// `snake_case` tag rule (`Request::ReadInbox` in the same file).
const READ_OP: &str = "read_inbox";

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

/// Builds the exact stdin frame for the notify `ReadInbox` op.
///
/// Field-for-field mirror of `Request::ReadInbox` in
/// `bins/eliot-notify/src/main.rs` (`parent` plus `read`); any drift fails
/// closed there as `REQUEST_INVALID`, which maps back to `Rejected` below.
fn read_frame(
    parent: &NotificationRequest,
    read: &NotificationStateReadRequest,
) -> serde_json::Value {
    serde_json::json!({
        "op": READ_OP,
        "parent": parent,
        "read": read,
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

/// Interprets one notify inbox stdout frame.
///
/// An `inbox` status with a fully decodable read validated against the
/// admitted request (same fence, non-zero revision, page bound) is the
/// only success. A `REQUEST_INVALID` error answers our own construction
/// bug and rejects loudly. Every other outcome (error status,
/// unparseable bytes, missing or undecodable read, fence/revision/page
/// mismatch) is `Unavailable`: unlike delivery, a read performs no
/// canonical effect, so there is nothing to reconcile and retry is safe
/// — never `UnknownOutcome`.
fn interpret_inbox_response(
    stdout: &[u8],
    request: &NotificationStateReadRequest,
) -> Result<NotificationStateReadResponse, UserAutomationRuntimeError> {
    let value: serde_json::Value = serde_json::from_slice(stdout).map_err(|_| {
        UserAutomationRuntimeError::Unavailable("unparseable notify inbox response".to_owned())
    })?;
    match value.get("status").and_then(serde_json::Value::as_str) {
        Some("inbox") => {
            let read: NotificationStateReadResponse = value
                .get("read")
                .cloned()
                .ok_or_else(|| {
                    UserAutomationRuntimeError::Unavailable(
                        "inbox response carries no read".to_owned(),
                    )
                })
                .and_then(|read| {
                    serde_json::from_value(read).map_err(|_| {
                        UserAutomationRuntimeError::Unavailable("inbox read undecodable".to_owned())
                    })
                })?;
            if read.state_fence != request.state_fence {
                return Err(UserAutomationRuntimeError::Unavailable(
                    "inbox fence does not match the admitted read".to_owned(),
                ));
            }
            if read.revision == 0 {
                return Err(UserAutomationRuntimeError::Unavailable(
                    "inbox revision is not admitted".to_owned(),
                ));
            }
            if read.records.len() > usize::from(request.page_limit) {
                return Err(UserAutomationRuntimeError::Unavailable(
                    "inbox page exceeds the admitted bound".to_owned(),
                ));
            }
            Ok(read)
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
                Err(UserAutomationRuntimeError::Unavailable(detail))
            }
        }
        _ => Err(UserAutomationRuntimeError::Unavailable(
            "unknown notify inbox status".to_owned(),
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
    /// Reads one authenticated canonical notification page through the
    /// notify binary's existing stdin JSON route (`Request::ReadInbox` in
    /// `bins/eliot-notify/src/main.rs`) and maps the stdout response back
    /// to validated inbox rows.
    ///
    /// Same transport rules as delivery (explicit validated binary path,
    /// inherited working directory and environment, `kill_on_drop`,
    /// bounded wait, capped output). Read taxonomy differs by
    /// side-effect-freedom as documented above: pre-transport shape
    /// failures and `REQUEST_INVALID` reject; spawn/setup failures are
    /// unavailable; post-dispatch uncertainty is unavailable, never
    /// unknown outcome. The fence, revision, and page bound of the
    /// returned read are validated against the admitted request.
    pub async fn read_notification_state_via_notify(
        &self,
        parent: &NotificationRequest,
        read: &NotificationStateReadRequest,
    ) -> Result<NotificationStateReadResponse, UserAutomationRuntimeError> {
        parent
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        if read.context.state_fence != read.state_fence {
            return Err(UserAutomationRuntimeError::Rejected(
                "notification read fences must agree".to_owned(),
            ));
        }
        if !(1..=128).contains(&read.page_limit) {
            return Err(UserAutomationRuntimeError::Rejected(
                "notification page limit out of range".to_owned(),
            ));
        }
        let mut frame = serde_json::to_vec(&read_frame(parent, read)).map_err(|_| {
            UserAutomationRuntimeError::Rejected("notification read unserializable".to_owned())
        })?;
        frame.push(b'\n');
        let bytes = match self.invoke_raw(&frame).await {
            Ok(bytes) => bytes,
            Err(
                RawTransportFailure::SetupUnavailable(detail)
                | RawTransportFailure::CollectUncertain(detail),
            ) => {
                return Err(UserAutomationRuntimeError::Unavailable(detail));
            }
            Err(RawTransportFailure::WriteUncertain) => {
                return Err(UserAutomationRuntimeError::Unavailable(
                    "notify stdin write failed".to_owned(),
                ));
            }
        };
        interpret_inbox_response(&bytes, read)
    }

    async fn invoke(
        &self,
        failure: &UserAutomationFailureRequest,
        parent: &NotificationRequest,
    ) -> Result<DeliveryObservation, UserAutomationRuntimeError> {
        let mut frame = serde_json::to_vec(&request_frame(failure, parent)).map_err(|_| {
            UserAutomationRuntimeError::Rejected("automation request unserializable".to_owned())
        })?;
        frame.push(b'\n');
        let bytes = match self.invoke_raw(&frame).await {
            Ok(bytes) => bytes,
            Err(RawTransportFailure::SetupUnavailable(detail)) => {
                return Err(UserAutomationRuntimeError::Unavailable(detail));
            }
            Err(RawTransportFailure::WriteUncertain) => {
                return Err(UserAutomationRuntimeError::UnknownOutcome(
                    "notify stdin write failed".to_owned(),
                ));
            }
            Err(RawTransportFailure::CollectUncertain(detail)) => {
                return Err(UserAutomationRuntimeError::UnknownOutcome(detail));
            }
        };
        interpret_response(&bytes)
    }

    /// Runs one stdin/stdout child invocation and collects raw stdout bytes.
    ///
    /// Shared transport mechanics for delivery and inbox reads (explicit
    /// path spawn, piped stdio, inherited environment, `kill_on_drop`,
    /// bounded wait, capped output). Stages are reported raw; each caller
    /// maps them per its own side-effect semantics (delivery reconciles
    /// post-dispatch uncertainty as unknown outcome, reads report it as
    /// unavailable).
    async fn invoke_raw(&self, frame: &[u8]) -> Result<Vec<u8>, RawTransportFailure> {
        let mut child = tokio::process::Command::new(&self.notify_exe)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                RawTransportFailure::SetupUnavailable(format!(
                    "notify executable did not spawn: {error}"
                ))
            })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            RawTransportFailure::SetupUnavailable("notify stdin unavailable".to_owned())
        })?;
        if stdin.write_all(frame).await.is_err() {
            return Err(RawTransportFailure::WriteUncertain);
        }
        drop(stdin);
        let outcome = tokio::time::timeout(NOTIFY_SPAWN_TIMEOUT, async {
            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| {
                    RawTransportFailure::SetupUnavailable("notify stdout unavailable".to_owned())
                })?
                .take(NOTIFY_MAX_RESPONSE_BYTES);
            let mut bytes = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stdout, &mut bytes)
                .await
                .map_err(|_| {
                    RawTransportFailure::CollectUncertain("notify stdout unreadable".to_owned())
                })?;
            child.wait().await.map_err(|_| {
                RawTransportFailure::CollectUncertain("notify wait failed".to_owned())
            })?;
            Ok(bytes)
        })
        .await
        .map_err(|_| {
            RawTransportFailure::CollectUncertain("notify invocation timed out".to_owned())
        })??;
        Ok(outcome)
    }
}

/// Raw transport stages for one notify invocation. See [`KernelNotificationClient::invoke_raw`].
enum RawTransportFailure {
    /// Spawn or stdio setup failed where no effect could occur.
    SetupUnavailable(String),
    /// Stdin write failed after a successful spawn.
    WriteUncertain,
    /// Timeout, unreadable stdout, or failed wait after dispatch.
    CollectUncertain(String),
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

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    use eliot_contracts::StateFence;

    fn fence_at(generation: u64) -> StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(generation).expect("generation"),
        )
    }

    fn metadata() -> eliot_contracts::RequestMetadata {
        use eliot_contracts::{ClockReading, ProductId, RequestId, SourceId};
        eliot_contracts::RequestMetadata {
            request_id: RequestId::new("req-inbox-1").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product").expect("product id"),
            source_id: SourceId::new("source").expect("source id"),
            state_fence: fence_at(7),
            clock: ClockReading::default(),
        }
    }

    fn parent() -> NotificationRequest {
        NotificationRequest {
            context: metadata(),
            notification: PlatformHandle::new("notification-1").expect("notification id"),
            canonical_request_hash: PlatformHandle::new("c".repeat(64)).expect("request hash"),
            audience: PlatformHandle::new("owner-1").expect("audience"),
            body_digest: PlatformHandle::new("d".repeat(64)).expect("body digest"),
        }
    }

    fn read_request() -> NotificationStateReadRequest {
        NotificationStateReadRequest {
            context: metadata(),
            state_fence: fence_at(7),
            scope: None,
            include_resolved: true,
            page_limit: 128,
            cursor: None,
        }
    }

    /// Real notify-produced inbox bytes: verbatim wire shape from the
    /// `ReadInbox` server arm (`bins/eliot-notify/src/main.rs`), one
    /// acknowledged critical failed-delivery record plus owner metrics.
    fn inbox_stdout() -> Vec<u8> {
        serde_json::json!({
            "status": "inbox",
            "service": "eliot-notify",
            "protocol": "eliot.notify.v1",
            "read": {
                "records": [{
                    "notification_id": "notification-1",
                    "severity": "CRITICAL",
                    "subject": "subject",
                    "summary": "summary",
                    "evidence_handles": ["evidence-1"],
                    "affected_scope": "scope-1",
                    "owner": "owner-1",
                    "required_action": "review",
                    "deadline_or_review": null,
                    "dedup_key": "backup-failed",
                    "delivery_channels": ["CONTROL_BOARD"],
                    "occurrences": 2,
                    "delivery": {"kind": "FAILED", "reason": "toast provider failed"},
                    "acknowledgement": {"principal": "operator-1", "sequence": 1},
                    "resolution_ref": null,
                    "state_fence": serde_json::to_value(fence_at(7)).expect("fence encodes"),
                    "revision": 2
                }],
                "metrics": {
                    "unresolved_total": 1,
                    "critical_unresolved": 1,
                    "action_required_unresolved": 0,
                    "failed_delivery_unresolved": 1,
                    "acknowledged_unresolved": 1,
                    "resolved_total": 0
                },
                "state_fence": serde_json::to_value(fence_at(7)).expect("fence encodes"),
                "revision": 2
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn read_inbox_frame_is_field_exact_for_the_notify_route() {
        let frame = read_frame(&parent(), &read_request());
        // Exact `Request::ReadInbox` wire shape: snake_case op plus the
        // `parent`/`read` fields, nothing else.
        assert_eq!(frame["op"], "read_inbox");
        assert_eq!(frame["parent"]["notification"], "notification-1");
        assert_eq!(frame["parent"]["audience"], "owner-1");
        assert_eq!(frame["read"]["scope"], serde_json::Value::Null);
        assert_eq!(frame["read"]["include_resolved"], true);
        assert_eq!(frame["read"]["page_limit"].as_u64(), Some(128));
        assert_eq!(frame["read"]["cursor"], serde_json::Value::Null);
        assert_eq!(
            frame["read"]["state_fence"],
            serde_json::to_value(fence_at(7)).expect("fence encodes")
        );
    }

    #[test]
    fn inbox_response_bytes_map_to_rows_byte_equal() {
        let read =
            interpret_inbox_response(&inbox_stdout(), &read_request()).expect("inbox bytes map");
        assert_eq!(read.revision, 2);
        assert_eq!(read.state_fence, fence_at(7));
        assert_eq!(read.records.len(), 1);
        assert_eq!(read.records[0].dedup_key, "backup-failed");
        assert!(read.records[0].acknowledgement.is_some());
        assert_eq!(read.metrics.critical_unresolved, 1);
        assert_eq!(read.metrics.failed_delivery_unresolved, 1);
        assert_eq!(read.metrics.acknowledged_unresolved, 1);
        // Returned rows re-encode byte-equal to the wire records: the
        // mapping drops, reorders, or alters nothing.
        let wire_records = serde_json::from_slice::<serde_json::Value>(&inbox_stdout())
            .expect("wire decodes")["read"]["records"]
            .clone();
        let returned =
            eliot_contracts::canonical_json_bytes(&read.records).expect("returned encodes");
        let expected = eliot_contracts::canonical_json_bytes(&wire_records).expect("wire encodes");
        assert_eq!(returned, expected);
        assert!(!returned.is_empty());
    }

    #[test]
    fn inbox_taxonomy_is_unavailable_never_unknown() {
        let read = read_request();
        // Garbage, mystery status, and a delivery-shaped answer (wrong
        // shape for a read) are all unavailable.
        for bytes in [
            b"\x00\x01 not json".to_vec(),
            br#"{"status":"mystery"}"#.to_vec(),
            br#"{"status":"delivered"}"#.to_vec(),
            br#"{"status":"inbox"}"#.to_vec(),
            br#"{"status":"inbox","read":{"records":[]}}"#.to_vec(),
        ] {
            assert!(
                matches!(
                    interpret_inbox_response(&bytes, &read),
                    Err(UserAutomationRuntimeError::Unavailable(_))
                ),
                "must be unavailable, never unknown or success"
            );
        }
        // Provider errors stay unavailable; only our own construction bug
        // rejects loudly.
        assert!(matches!(
            interpret_inbox_response(
                br#"{"status":"error","code":"NOTIFICATION_PROVIDER_REJECTED","detail":"boom"}"#,
                &read
            ),
            Err(UserAutomationRuntimeError::Unavailable(_))
        ));
        assert!(matches!(
            interpret_inbox_response(
                br#"{"status":"error","code":"REQUEST_INVALID","detail":"bad shape"}"#,
                &read
            ),
            Err(UserAutomationRuntimeError::Rejected(_))
        ));
        // Fence drift, zero revision, and over-page reads fail closed.
        let mut drifted =
            serde_json::from_slice::<serde_json::Value>(&inbox_stdout()).expect("wire decodes");
        drifted["read"]["state_fence"] = serde_json::to_value(fence_at(6)).expect("fence encodes");
        assert!(matches!(
            interpret_inbox_response(&serde_json::to_vec(&drifted).expect("wire encodes"), &read),
            Err(UserAutomationRuntimeError::Unavailable(_))
        ));
        let mut unresolved =
            serde_json::from_slice::<serde_json::Value>(&inbox_stdout()).expect("wire decodes");
        unresolved["read"]["revision"] = serde_json::json!(0);
        assert!(matches!(
            interpret_inbox_response(
                &serde_json::to_vec(&unresolved).expect("wire encodes"),
                &read
            ),
            Err(UserAutomationRuntimeError::Unavailable(_))
        ));
        let mut overfull =
            serde_json::from_slice::<serde_json::Value>(&inbox_stdout()).expect("wire decodes");
        let record = overfull["read"]["records"][0].clone();
        overfull["read"]["records"] = serde_json::Value::Array(vec![record; 129]);
        assert!(matches!(
            interpret_inbox_response(&serde_json::to_vec(&overfull).expect("wire encodes"), &read),
            Err(UserAutomationRuntimeError::Unavailable(_))
        ));
    }

    /// Pre-transport shape failures reject WITHOUT spawning: the stub
    /// binary below is never executed (a spawn would surface as
    /// `Unavailable`, never `Rejected`).
    #[tokio::test]
    async fn read_pre_transport_failures_reject_before_any_spawn() {
        let file = unique_temp_dir("read-guard").join("eliot-notify.exe");
        std::fs::write(&file, b"stub").expect("stub binary");
        let client = KernelNotificationClient::new(file.clone()).expect("valid path");
        let mut drifted = read_request();
        drifted.state_fence = fence_at(6);
        assert!(matches!(
            client
                .read_notification_state_via_notify(&parent(), &drifted)
                .await,
            Err(UserAutomationRuntimeError::Rejected(_))
        ));
        for page_limit in [0, 129] {
            let mut bounded = read_request();
            bounded.page_limit = page_limit;
            assert!(matches!(
                client
                    .read_notification_state_via_notify(&parent(), &bounded)
                    .await,
                Err(UserAutomationRuntimeError::Rejected(_))
            ));
        }
        let _ = std::fs::remove_dir_all(file.parent().expect("parent"));
    }
}
