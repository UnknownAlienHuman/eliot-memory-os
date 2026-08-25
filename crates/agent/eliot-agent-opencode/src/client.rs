use crate::{
    ActualRouteReceipt, AuthorityCeiling, BasicAuth, HealthResponse, HttpMethod, HttpRequest,
    LoopbackEndpoint, LoopbackHttpClient, LoopbackHttpError, ModelSelection, NoAuthorityRunResult,
    OpenCodeEvent, ProviderCatalog, QuotaAvailability, ReadOnlyRunRequest, RunRequestError,
    RunStatus, Session, SessionDiff, SessionStatus, SessionStatusMap, SseConnection,
    SseDecodeError, SseDecoder, SseLimits, UnknownFields, UsageAvailability, UsageTelemetry,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::time::{Instant, sleep, timeout};

const CLIENT_PROTOCOL_REVISION: &str = "eliot-opencode-bootstrap-http-sse-v1";
const READ_ONLY_AGENT: &str = "plan";
const DEFAULT_SERVER_VERSION: &str = "1.4.3";
const RECONCILIATION_TIMEOUT: Duration = Duration::from_secs(20);
const RECONCILIATION_CALL_TIMEOUT: Duration = Duration::from_secs(5);
static MESSAGE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct OpenCodeRunPolicy {
    directory: PathBuf,
    workspace: Option<String>,
    session_title: String,
    expected_server_version: String,
    overall_timeout: Duration,
    event_idle_timeout: Duration,
    max_events: usize,
    max_sse_reconnects: usize,
    max_sse_chunk_bytes: usize,
    sse_limits: SseLimits,
}

impl OpenCodeRunPolicy {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, OpenCodeRunError> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(OpenCodeRunError::InvalidPolicy(
                "OpenCode directory must be absolute".to_owned(),
            ));
        }
        Ok(Self {
            directory,
            workspace: None,
            session_title: "ELIOT read-only bootstrap attempt".to_owned(),
            expected_server_version: DEFAULT_SERVER_VERSION.to_owned(),
            overall_timeout: Duration::from_mins(15),
            event_idle_timeout: Duration::from_mins(1),
            max_events: 20_000,
            max_sse_reconnects: 3,
            max_sse_chunk_bytes: 64 * 1024,
            sse_limits: SseLimits::default(),
        })
    }

    #[must_use]
    pub fn with_workspace(mut self, workspace: Option<String>) -> Self {
        self.workspace = workspace;
        self
    }

    #[must_use]
    pub fn with_expected_server_version(mut self, version: impl Into<String>) -> Self {
        self.expected_server_version = version.into();
        self
    }

    #[must_use]
    pub fn with_timeouts(
        mut self,
        overall_timeout: Duration,
        event_idle_timeout: Duration,
    ) -> Self {
        self.overall_timeout = overall_timeout;
        self.event_idle_timeout = event_idle_timeout;
        self
    }

    #[must_use]
    pub fn with_event_limits(
        mut self,
        max_events: usize,
        max_sse_chunk_bytes: usize,
        sse_limits: SseLimits,
    ) -> Self {
        self.max_events = max_events;
        self.max_sse_chunk_bytes = max_sse_chunk_bytes;
        self.sse_limits = sse_limits;
        self
    }

    #[must_use]
    pub const fn with_sse_reconnect_limit(mut self, max_sse_reconnects: usize) -> Self {
        self.max_sse_reconnects = max_sse_reconnects;
        self
    }

    fn validate(&self) -> Result<(), OpenCodeRunError> {
        if self.max_events == 0 || self.max_sse_reconnects == 0 || self.max_sse_chunk_bytes == 0 {
            return Err(OpenCodeRunError::InvalidPolicy(
                "OpenCode event and reconnect limits must be nonzero".to_owned(),
            ));
        }
        if self.overall_timeout.is_zero() || self.event_idle_timeout.is_zero() {
            return Err(OpenCodeRunError::InvalidPolicy(
                "OpenCode timeouts must be nonzero".to_owned(),
            ));
        }
        if self.session_title.trim().is_empty() {
            return Err(OpenCodeRunError::InvalidPolicy(
                "OpenCode session title must be nonblank".to_owned(),
            ));
        }
        if self.expected_server_version.trim().is_empty() {
            return Err(OpenCodeRunError::InvalidPolicy(
                "expected OpenCode server version must be nonblank".to_owned(),
            ));
        }
        if self
            .workspace
            .as_deref()
            .is_some_and(|workspace| workspace.trim().is_empty())
        {
            return Err(OpenCodeRunError::InvalidPolicy(
                "OpenCode workspace identity must be nonblank when supplied".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum OpenCodeRunError {
    #[error(transparent)]
    Http(#[from] LoopbackHttpError),
    #[error(transparent)]
    Sse(#[from] SseDecodeError),
    #[error(transparent)]
    Request(#[from] RunRequestError),
    #[error("invalid OpenCode run policy: {0}")]
    InvalidPolicy(String),
    #[error("OpenCode protocol violation: {0}")]
    Protocol(String),
    #[error("OpenCode route is unavailable: {0}")]
    RouteUnavailable(String),
    #[error(
        "OpenCode requested permission {permission_id}; read-only bootstrap attempt was aborted"
    )]
    PermissionRequested { permission_id: String },
    #[error("OpenCode read-only attempt timed out during {phase}")]
    Timeout { phase: &'static str },
    #[error("OpenCode read-only attempt produced {count} file diffs")]
    MutationObserved { count: usize },
    #[error("OpenCode message {message_id} completed after abort was requested")]
    CompletedAfterAbort { message_id: String },
    #[error("OpenCode provider returned {kind}: {message}")]
    Provider { kind: String, message: String },
    #[error(
        "OpenCode attempt outcome is unknown after {cause}; reconciliation failed: {reconciliation}"
    )]
    UnknownOutcome {
        cause: String,
        reconciliation: String,
    },
}

pub struct OpenCodeClient {
    endpoint: LoopbackEndpoint,
    http: LoopbackHttpClient,
    policy: OpenCodeRunPolicy,
}

impl std::fmt::Debug for OpenCodeClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenCodeClient")
            .field("endpoint", &self.endpoint)
            .field("http", &self.http)
            .field("policy", &self.policy)
            .finish()
    }
}

struct PreparedRun {
    health: HealthResponse,
    session: Session,
    baseline_diff: Vec<SessionDiff>,
    message_id: String,
}

struct EventCollection {
    events: Vec<OpenCodeEvent>,
    assistant_message_id: String,
}

struct EventCollectionFailure {
    error: OpenCodeRunError,
    events: Vec<OpenCodeEvent>,
    may_reconcile_success: bool,
}

impl EventCollectionFailure {
    fn reconcilable(error: OpenCodeRunError, events: Vec<OpenCodeEvent>) -> Self {
        Self {
            error,
            events,
            may_reconcile_success: true,
        }
    }

    fn terminal(error: OpenCodeRunError, events: Vec<OpenCodeEvent>) -> Self {
        Self {
            error,
            events,
            may_reconcile_success: false,
        }
    }
}

struct CorrelatedEventState {
    session_id: String,
    user_message_id: String,
    requested_model: ModelSelection,
    assistant_message_id: Option<String>,
    assistant_created_at: Option<u64>,
    terminal_part_message_ids: BTreeSet<String>,
    assistant_completed: bool,
    terminal_stop: bool,
    idle_observed: bool,
}

impl CorrelatedEventState {
    fn new(session_id: &str, user_message_id: &str, requested_model: &ModelSelection) -> Self {
        Self {
            session_id: session_id.to_owned(),
            user_message_id: user_message_id.to_owned(),
            requested_model: requested_model.clone(),
            assistant_message_id: None,
            assistant_created_at: None,
            terminal_part_message_ids: BTreeSet::new(),
            assistant_completed: false,
            terminal_stop: false,
            idle_observed: false,
        }
    }

    fn observe(&mut self, event: &OpenCodeEvent) -> Result<(), OpenCodeRunError> {
        if event.event_type == "session.error" {
            return self.observe_session_error(event);
        }
        if !event_belongs_to_session(event, &self.session_id) {
            return Ok(());
        }
        match event.event_type.as_str() {
            "permission.asked" => {
                let permission_id =
                    required_string(event.properties.get("id"), "permission request identity")?;
                Err(OpenCodeRunError::PermissionRequested { permission_id })
            }
            "session.idle" => {
                self.idle_observed = true;
                Ok(())
            }
            "session.status"
                if event
                    .properties
                    .pointer("/status/type")
                    .and_then(Value::as_str)
                    == Some("idle") =>
            {
                self.idle_observed = true;
                Ok(())
            }
            "message.updated" => self.observe_message(event),
            "message.part.updated" => self.observe_part(event),
            _ => Ok(()),
        }
    }

    fn observe_session_error(&self, event: &OpenCodeEvent) -> Result<(), OpenCodeRunError> {
        match event.properties.get("sessionID").and_then(Value::as_str) {
            Some(observed) if observed != self.session_id => Ok(()),
            None => Err(OpenCodeRunError::Protocol(
                "unbound OpenCode session.error made the attempt outcome ambiguous".to_owned(),
            )),
            Some(_) => Err(provider_error(
                event.properties.get("error"),
                "SessionError",
            )),
        }
    }

    fn observe_message(&mut self, event: &OpenCodeEvent) -> Result<(), OpenCodeRunError> {
        let Some(info) = event.properties.get("info").and_then(Value::as_object) else {
            return Err(OpenCodeRunError::Protocol(
                "message.updated info is not an object".to_owned(),
            ));
        };
        if info.get("role").and_then(Value::as_str) != Some("assistant")
            || info.get("parentID").and_then(Value::as_str) != Some(&self.user_message_id)
        {
            return Ok(());
        }
        let assistant_id = required_string(info.get("id"), "assistant message identity")?;
        attest_message_route(info, &self.requested_model)?;
        if info.get("error").is_some_and(|error| !error.is_null()) {
            return Err(provider_error(info.get("error"), "MessageError"));
        }
        let created_at = info
            .get("time")
            .and_then(Value::as_object)
            .and_then(|time| time.get("created"))
            .and_then(Value::as_u64);
        if let Some(known) = self.assistant_message_id.as_deref()
            && known != assistant_id
        {
            let strictly_later = self
                .assistant_created_at
                .zip(created_at)
                .is_some_and(|(known_created, observed_created)| observed_created > known_created);
            if !strictly_later || (self.assistant_completed && self.terminal_stop) {
                return Err(OpenCodeRunError::Protocol(
                    "assistant message succession is ambiguous for one prompt identity".to_owned(),
                ));
            }
            self.assistant_completed = false;
            self.terminal_stop = self.terminal_part_message_ids.contains(&assistant_id);
        }
        self.assistant_completed |= info
            .get("time")
            .and_then(Value::as_object)
            .and_then(|time| time.get("completed"))
            .and_then(Value::as_u64)
            .is_some();
        self.terminal_stop |= info.get("finish").and_then(Value::as_str) == Some("stop")
            || self.terminal_part_message_ids.contains(&assistant_id);
        self.assistant_created_at = created_at.or(self.assistant_created_at);
        self.assistant_message_id = Some(assistant_id);
        Ok(())
    }

    fn observe_part(&mut self, event: &OpenCodeEvent) -> Result<(), OpenCodeRunError> {
        let Some(part) = event.properties.get("part").and_then(Value::as_object) else {
            return Err(OpenCodeRunError::Protocol(
                "message.part.updated part is not an object".to_owned(),
            ));
        };
        if part.get("type").and_then(Value::as_str) != Some("step-finish")
            || part.get("reason").and_then(Value::as_str) != Some("stop")
        {
            return Ok(());
        }
        let message_id = required_string(part.get("messageID"), "terminal part message identity")?;
        self.terminal_part_message_ids.insert(message_id.clone());
        self.terminal_stop |= self.assistant_message_id.as_deref() == Some(message_id.as_str());
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.assistant_message_id.is_some()
            && self.assistant_completed
            && self.terminal_stop
            && self.idle_observed
    }
}

impl OpenCodeClient {
    pub fn new(
        endpoint: LoopbackEndpoint,
        auth: BasicAuth,
        policy: OpenCodeRunPolicy,
    ) -> Result<Self, OpenCodeRunError> {
        policy.validate()?;
        let http = LoopbackHttpClient::new(endpoint.clone(), auth)
            .with_absolute_timeout(policy.overall_timeout);
        Ok(Self {
            endpoint,
            http,
            policy,
        })
    }

    pub async fn health(&self) -> Result<HealthResponse, OpenCodeRunError> {
        Ok(self
            .http
            .execute(&HttpRequest::get("/global/health"))
            .await?
            .json()?)
    }

    pub async fn providers(&self) -> Result<ProviderCatalog, OpenCodeRunError> {
        let path = self.project_path("/provider", &[])?;
        Ok(self.http.execute(&HttpRequest::get(path)).await?.json()?)
    }

    pub async fn agents(&self) -> Result<Vec<Value>, OpenCodeRunError> {
        let path = self.project_path("/agent", &[])?;
        Ok(self.http.execute(&HttpRequest::get(path)).await?.json()?)
    }

    pub async fn create_session(&self) -> Result<Session, OpenCodeRunError> {
        let path = self.project_path("/session", &[])?;
        let request = HttpRequest::post_json(
            path,
            &json!({
                "title": self.policy.session_title,
                "permission": read_only_permission_rules(),
            }),
        )?;
        Ok(self.http.execute(&request).await?.json()?)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Session, OpenCodeRunError> {
        let path = self.project_path(&format!("/session/{}", encode_component(session_id)), &[])?;
        Ok(self.http.execute(&HttpRequest::get(path)).await?.json()?)
    }

    pub async fn session_statuses(&self) -> Result<SessionStatusMap, OpenCodeRunError> {
        let path = self.project_path("/session/status", &[])?;
        Ok(self.http.execute(&HttpRequest::get(path)).await?.json()?)
    }

    pub async fn prompt_async(
        &self,
        session_id: &str,
        message_id: &str,
        request: &ReadOnlyRunRequest,
    ) -> Result<(), OpenCodeRunError> {
        request.validate()?;
        let path = self.project_path(
            &format!("/session/{}/prompt_async", encode_component(session_id)),
            &[],
        )?;
        let wire = json!({
            "messageID": message_id,
            "model": request.model,
            "agent": READ_ONLY_AGENT,
            "format": {
                "type": "text",
            },
            "parts": [{"type": "text", "text": request.prompt}],
        });
        let response = self
            .http
            .execute(&HttpRequest::post_json(path, &wire)?)
            .await?;
        if response.status != 204 || !response.body.is_empty() {
            return Err(OpenCodeRunError::Protocol(format!(
                "prompt_async returned status {} with {} body bytes",
                response.status,
                response.body.len()
            )));
        }
        Ok(())
    }

    pub async fn abort(&self, session_id: &str) -> Result<(), OpenCodeRunError> {
        let path = self.project_path(
            &format!("/session/{}/abort", encode_component(session_id)),
            &[],
        )?;
        let request = HttpRequest {
            method: HttpMethod::Post,
            path_and_query: path,
            body: Vec::new(),
            accept_sse: false,
            last_event_id: None,
        };
        let response = self.http.execute(&request).await?;
        if !response.body.is_empty() {
            let acknowledged: bool = response.json()?;
            if !acknowledged {
                return Err(OpenCodeRunError::Protocol(
                    "OpenCode abort was not acknowledged".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub async fn messages(&self, session_id: &str) -> Result<Value, OpenCodeRunError> {
        let path = self.project_path(
            &format!("/session/{}/message", encode_component(session_id)),
            &[],
        )?;
        Ok(self.http.execute(&HttpRequest::get(path)).await?.json()?)
    }

    pub async fn diff(&self, session_id: &str) -> Result<Vec<SessionDiff>, OpenCodeRunError> {
        let path = self.project_path(
            &format!("/session/{}/diff", encode_component(session_id)),
            &[],
        )?;
        Ok(self.http.execute(&HttpRequest::get(path)).await?.json()?)
    }

    pub async fn run_read_only(
        &self,
        request: &ReadOnlyRunRequest,
    ) -> Result<NoAuthorityRunResult, OpenCodeRunError> {
        request.validate()?;
        self.policy.validate()?;
        let deadline = Instant::now() + self.policy.overall_timeout;
        let prepared = self.prepare_run(request).await?;
        let connection = self.open_event_stream(None).await?;

        if let Err(error) = self
            .prompt_async(&prepared.session.id, &prepared.message_id, request)
            .await
        {
            if dispatch_definitively_rejected(&error) {
                return Err(error);
            }
            return self
                .fail_after_dispatch(
                    &prepared.session.id,
                    &prepared.message_id,
                    &prepared.baseline_diff,
                    error,
                )
                .await;
        }

        let collection = match self
            .collect_events(
                connection,
                &prepared.session.id,
                &prepared.message_id,
                &request.model,
                deadline,
            )
            .await
        {
            Ok(collection) => collection,
            Err(failure) => {
                if failure.may_reconcile_success
                    && let Ok(projection) = self
                        .reconcile_success(
                            &prepared.session.id,
                            &prepared.message_id,
                            None,
                            &request.model,
                            &request.output_schema,
                            &prepared.baseline_diff,
                        )
                        .await
                {
                    return Ok(self.success_result(request, prepared, projection, failure.events));
                }
                return self
                    .fail_after_dispatch(
                        &prepared.session.id,
                        &prepared.message_id,
                        &prepared.baseline_diff,
                        failure.error,
                    )
                    .await;
            }
        };

        let projection = self
            .reconcile_success(
                &prepared.session.id,
                &prepared.message_id,
                Some(&collection.assistant_message_id),
                &request.model,
                &request.output_schema,
                &prepared.baseline_diff,
            )
            .await?;
        Ok(self.success_result(request, prepared, projection, collection.events))
    }

    async fn prepare_run(
        &self,
        request: &ReadOnlyRunRequest,
    ) -> Result<PreparedRun, OpenCodeRunError> {
        let health = self.health().await?;
        if !health.healthy || health.version != self.policy.expected_server_version {
            return Err(OpenCodeRunError::RouteUnavailable(format!(
                "expected healthy OpenCode {}, observed healthy={} version={:?}",
                self.policy.expected_server_version, health.healthy, health.version
            )));
        }
        attest_provider(&self.providers().await?, &request.model)?;
        attest_read_only_agent(&self.agents().await?)?;
        let session = if let Some(session_id) = &request.session_id {
            self.get_session(session_id).await?
        } else {
            self.create_session().await?
        };
        attest_session(
            &session,
            request.session_id.as_deref(),
            &self.policy,
            &health,
        )?;
        let baseline_diff = self.diff(&session.id).await?;
        let message_id = request
            .message_id
            .clone()
            .unwrap_or_else(|| generate_message_id(&session.id, request));
        Ok(PreparedRun {
            health,
            session,
            baseline_diff,
            message_id,
        })
    }

    async fn collect_events(
        &self,
        mut connection: SseConnection,
        session_id: &str,
        message_id: &str,
        requested_model: &ModelSelection,
        deadline: Instant,
    ) -> Result<EventCollection, EventCollectionFailure> {
        let mut decoder = SseDecoder::new(self.policy.sse_limits);
        let mut state = CorrelatedEventState::new(session_id, message_id, requested_model);
        let mut events = Vec::<OpenCodeEvent>::new();
        let mut reconnect_count = 0_usize;
        loop {
            let chunk_result = self.read_event_chunk(&mut connection, deadline).await;
            let chunk = match chunk_result {
                Ok(chunk) => chunk,
                Err(cause) => match self
                    .reconnect_event_stream(&decoder, reconnect_count, deadline)
                    .await
                {
                    Ok(Some((resumed_connection, resumed_decoder))) => {
                        connection = resumed_connection;
                        decoder = resumed_decoder;
                        reconnect_count += 1;
                        continue;
                    }
                    Ok(None) => {
                        return Err(EventCollectionFailure::reconcilable(cause, events));
                    }
                    Err(reconnect_error) => {
                        return Err(EventCollectionFailure::reconcilable(
                            OpenCodeRunError::Protocol(format!(
                                "{cause}; SSE reconnect failed: {reconnect_error}"
                            )),
                            events,
                        ));
                    }
                },
            };
            let frames = decoder.feed(&chunk).map_err(|error| {
                EventCollectionFailure::terminal(error.into(), std::mem::take(&mut events))
            })?;
            for frame in frames {
                if frame.data.trim().is_empty() {
                    continue;
                }
                let raw = frame.json_value().map_err(|error| {
                    EventCollectionFailure::terminal(error.into(), std::mem::take(&mut events))
                })?;
                let event = serde_json::from_value::<OpenCodeEvent>(raw).map_err(|error| {
                    EventCollectionFailure::terminal(
                        OpenCodeRunError::Protocol(format!("decode OpenCode event: {error}")),
                        std::mem::take(&mut events),
                    )
                })?;
                let observed = state.observe(&event);
                if event_belongs_to_session(&event, session_id)
                    || event.event_type == "server.connected"
                    || event.event_type == "session.error"
                {
                    events.push(event);
                }
                if let Err(error) = observed {
                    return Err(EventCollectionFailure::terminal(error, events));
                }
                if events.len() > self.policy.max_events {
                    return Err(EventCollectionFailure::terminal(
                        OpenCodeRunError::Protocol(format!(
                            "event count exceeded {}",
                            self.policy.max_events
                        )),
                        events,
                    ));
                }
                if state.is_complete() {
                    let Some(assistant_message_id) = state.assistant_message_id else {
                        return Err(EventCollectionFailure::terminal(
                            OpenCodeRunError::Protocol(
                                "correlated completion had no assistant identity".to_owned(),
                            ),
                            events,
                        ));
                    };
                    return Ok(EventCollection {
                        events,
                        assistant_message_id,
                    });
                }
            }
        }
    }

    async fn read_event_chunk(
        &self,
        connection: &mut SseConnection,
        deadline: Instant,
    ) -> Result<Vec<u8>, OpenCodeRunError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(OpenCodeRunError::Timeout {
                phase: "overall event wait",
            });
        }
        let wait = self
            .policy
            .event_idle_timeout
            .min(deadline.saturating_duration_since(now));
        match timeout(
            wait,
            connection.read_decoded_chunk(self.policy.max_sse_chunk_bytes),
        )
        .await
        {
            Ok(Ok(Some(chunk))) => Ok(chunk),
            Ok(Ok(None)) => Err(OpenCodeRunError::Protocol(
                "SSE stream ended before correlated completion".to_owned(),
            )),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(OpenCodeRunError::Timeout {
                phase: "SSE semantic idle",
            }),
        }
    }

    async fn open_event_stream(
        &self,
        last_event_id: Option<&str>,
    ) -> Result<SseConnection, OpenCodeRunError> {
        let event_path = self.project_path("/event", &[])?;
        let request = HttpRequest::sse(event_path).with_last_event_id(last_event_id)?;
        Ok(self.http.open_sse(&request).await?)
    }

    async fn reconnect_event_stream(
        &self,
        decoder: &SseDecoder,
        reconnect_count: usize,
        deadline: Instant,
    ) -> Result<Option<(SseConnection, SseDecoder)>, OpenCodeRunError> {
        let cursor = decoder.cursor().clone();
        let Some(last_event_id) = cursor.last_event_id.as_deref() else {
            return Ok(None);
        };
        if reconnect_count >= self.policy.max_sse_reconnects {
            return Ok(None);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(OpenCodeRunError::Timeout {
                phase: "SSE reconnect",
            });
        }
        let retry_delay = Duration::from_millis(cursor.retry_ms.unwrap_or(100).min(5_000));
        let remaining = deadline.saturating_duration_since(now);
        if !retry_delay.is_zero() {
            sleep(retry_delay.min(remaining)).await;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(OpenCodeRunError::Timeout {
                phase: "SSE reconnect",
            });
        }
        let connection = timeout(
            self.policy.event_idle_timeout.min(remaining),
            self.open_event_stream(Some(last_event_id)),
        )
        .await
        .map_err(|_| OpenCodeRunError::Timeout {
            phase: "SSE reconnect",
        })??;
        Ok(Some((
            connection,
            SseDecoder::resumed(self.policy.sse_limits, cursor),
        )))
    }

    async fn reconcile_success(
        &self,
        session_id: &str,
        user_message_id: &str,
        assistant_message_id: Option<&str>,
        requested_model: &ModelSelection,
        expected_output_schema: &Value,
        baseline_diff: &[SessionDiff],
    ) -> Result<MessageProjection, OpenCodeRunError> {
        self.wait_until_idle(session_id).await?;
        let messages = timeout(RECONCILIATION_CALL_TIMEOUT, self.messages(session_id))
            .await
            .map_err(|_| OpenCodeRunError::Timeout {
                phase: "message reconciliation",
            })??;
        let projection = inspect_messages(
            &messages,
            session_id,
            user_message_id,
            assistant_message_id,
            requested_model,
            expected_output_schema,
        )?;
        let diff = timeout(RECONCILIATION_CALL_TIMEOUT, self.diff(session_id))
            .await
            .map_err(|_| OpenCodeRunError::Timeout {
                phase: "diff reconciliation",
            })??;
        attest_unchanged_diff(baseline_diff, &diff)?;
        Ok(projection)
    }

    async fn wait_until_idle(&self, session_id: &str) -> Result<(), OpenCodeRunError> {
        let deadline = Instant::now() + RECONCILIATION_TIMEOUT;
        loop {
            let statuses = timeout(RECONCILIATION_CALL_TIMEOUT, self.session_statuses())
                .await
                .map_err(|_| OpenCodeRunError::Timeout {
                    phase: "status reconciliation",
                })??;
            match statuses.get(session_id) {
                Some(SessionStatus::Idle { .. }) => return Ok(()),
                None => {
                    let session =
                        timeout(RECONCILIATION_CALL_TIMEOUT, self.get_session(session_id))
                            .await
                            .map_err(|_| OpenCodeRunError::Timeout {
                                phase: "idle session identity reconciliation",
                            })??;
                    if session.id != session_id
                        || normalized_path(Path::new(&session.directory))
                            != normalized_path(&self.policy.directory)
                        || session.version != self.policy.expected_server_version
                        || session.extra.get("permission") != Some(&read_only_permission_rules())
                    {
                        return Err(OpenCodeRunError::Protocol(
                            "status-map omission did not reconcile to the bound idle session"
                                .to_owned(),
                        ));
                    }
                    return Ok(());
                }
                Some(SessionStatus::Unknown { kind, .. }) => {
                    return Err(OpenCodeRunError::Protocol(format!(
                        "session status became unknown kind {kind:?}"
                    )));
                }
                Some(SessionStatus::Busy { .. } | SessionStatus::Retry { .. }) => {}
            }
            if Instant::now() >= deadline {
                return Err(OpenCodeRunError::Timeout {
                    phase: "session idle reconciliation",
                });
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn fail_after_dispatch<T>(
        &self,
        session_id: &str,
        user_message_id: &str,
        baseline_diff: &[SessionDiff],
        cause: OpenCodeRunError,
    ) -> Result<T, OpenCodeRunError> {
        match self
            .abort_and_reconcile(session_id, user_message_id, baseline_diff)
            .await
        {
            Ok(()) => Err(cause),
            Err(
                error @ (OpenCodeRunError::MutationObserved { .. }
                | OpenCodeRunError::CompletedAfterAbort { .. }
                | OpenCodeRunError::Provider { .. }),
            ) => Err(error),
            Err(error) => Err(OpenCodeRunError::UnknownOutcome {
                cause: cause.to_string(),
                reconciliation: error.to_string(),
            }),
        }
    }

    async fn abort_and_reconcile(
        &self,
        session_id: &str,
        user_message_id: &str,
        baseline_diff: &[SessionDiff],
    ) -> Result<(), OpenCodeRunError> {
        timeout(RECONCILIATION_CALL_TIMEOUT, self.abort(session_id))
            .await
            .map_err(|_| OpenCodeRunError::Timeout {
                phase: "abort acknowledgement",
            })??;
        self.wait_until_idle(session_id).await?;
        let messages = timeout(RECONCILIATION_CALL_TIMEOUT, self.messages(session_id))
            .await
            .map_err(|_| OpenCodeRunError::Timeout {
                phase: "post-abort message reconciliation",
            })??;
        if !messages.is_array() {
            return Err(OpenCodeRunError::Protocol(
                "post-abort messages response is not an array".to_owned(),
            ));
        }
        let diff = timeout(RECONCILIATION_CALL_TIMEOUT, self.diff(session_id))
            .await
            .map_err(|_| OpenCodeRunError::Timeout {
                phase: "post-abort diff reconciliation",
            })??;
        attest_unchanged_diff(baseline_diff, &diff)?;
        attest_aborted_messages(&messages, session_id, user_message_id)
    }

    fn success_result(
        &self,
        request: &ReadOnlyRunRequest,
        prepared: PreparedRun,
        projection: MessageProjection,
        events: Vec<OpenCodeEvent>,
    ) -> NoAuthorityRunResult {
        let route_fingerprint = route_fingerprint(
            &self.endpoint,
            &prepared.health.version,
            &request.model,
            READ_ONLY_AGENT,
        );
        let mut actual_route =
            ActualRouteReceipt::observed(request.model.clone(), projection.observed_model.clone());
        actual_route.provider = Some(projection.observed_model.provider_id.clone());
        actual_route.endpoint = Some(self.endpoint.to_string());
        actual_route.route_fingerprint = Some(route_fingerprint);
        actual_route.session_id = Some(prepared.session.id.clone());
        actual_route.directory = Some(prepared.session.directory.clone());
        actual_route.server_version = Some(prepared.health.version.clone());
        actual_route
            .workspace_id
            .clone_from(&prepared.session.workspace_id);
        let usage = projection.usage.map_or_else(
            || UsageAvailability::unavailable("OpenCode message contained no complete usage"),
            UsageAvailability::available,
        );
        let mut extra = UnknownFields::new();
        extra.insert(
            "server_version".to_owned(),
            Value::String(prepared.health.version.clone()),
        );
        extra.insert(
            "protocol_revision".to_owned(),
            Value::String(CLIENT_PROTOCOL_REVISION.to_owned()),
        );
        extra.insert(
            "agent".to_owned(),
            Value::String(READ_ONLY_AGENT.to_owned()),
        );
        extra.insert("message_id".to_owned(), Value::String(prepared.message_id));
        extra.insert("session_status_reconciled".to_owned(), Value::Bool(true));
        extra.insert("file_diff_unchanged".to_owned(), Value::Bool(true));
        extra.insert(
            "structured_output_transport".to_owned(),
            Value::String("text_json_strict".to_owned()),
        );
        extra.insert(
            "baseline_diff_count".to_owned(),
            Value::from(prepared.baseline_diff.len()),
        );
        NoAuthorityRunResult {
            status: RunStatus::Succeeded,
            candidate_only: true,
            authority: AuthorityCeiling::CandidateOnly,
            actual_route,
            usage,
            quota: QuotaAvailability::unavailable(format!(
                "OpenCode {} public session API did not expose quota/reset telemetry",
                prepared.health.version
            )),
            session_id: Some(prepared.session.id),
            output: Some(projection.output),
            events,
            diff: Vec::new(),
            extra,
        }
    }

    fn project_path(&self, path: &str, extra: &[(&str, &str)]) -> Result<String, OpenCodeRunError> {
        if !path.starts_with('/') || path.contains('?') || path.contains('#') {
            return Err(OpenCodeRunError::Protocol(
                "internal OpenCode path is not canonical".to_owned(),
            ));
        }
        let directory = self.policy.directory.to_str().ok_or_else(|| {
            OpenCodeRunError::InvalidPolicy("OpenCode directory is not UTF-8".to_owned())
        })?;
        let mut query = vec![("directory", directory)];
        if let Some(workspace) = self.policy.workspace.as_deref() {
            query.push(("workspace", workspace));
        }
        query.extend_from_slice(extra);
        let encoded = query
            .into_iter()
            .map(|(name, value)| format!("{name}={}", encode_component(value)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(format!("{path}?{encoded}"))
    }
}

fn dispatch_definitively_rejected(error: &OpenCodeRunError) -> bool {
    matches!(
        error,
        OpenCodeRunError::Http(LoopbackHttpError::Status {
            status: 400..=499,
            ..
        })
    )
}

fn attest_session(
    session: &Session,
    requested_session_id: Option<&str>,
    policy: &OpenCodeRunPolicy,
    health: &HealthResponse,
) -> Result<(), OpenCodeRunError> {
    if session.id.trim().is_empty() || session.project_id.trim().is_empty() {
        return Err(OpenCodeRunError::Protocol(
            "OpenCode session identity/project identity is missing".to_owned(),
        ));
    }
    if requested_session_id.is_some_and(|requested| requested != session.id) {
        return Err(OpenCodeRunError::Protocol(
            "OpenCode returned a different session identity".to_owned(),
        ));
    }
    if normalized_path(Path::new(&session.directory)) != normalized_path(&policy.directory) {
        return Err(OpenCodeRunError::Protocol(format!(
            "OpenCode session directory {:?} does not match the requested directory",
            session.directory
        )));
    }
    if session.version != health.version {
        return Err(OpenCodeRunError::Protocol(format!(
            "OpenCode session version {:?} does not match server version {:?}",
            session.version, health.version
        )));
    }
    if session.extra.get("permission") != Some(&read_only_permission_rules()) {
        return Err(OpenCodeRunError::Protocol(
            "OpenCode session did not retain the exact no-authority permission profile".to_owned(),
        ));
    }
    if let Some(workspace) = policy.workspace.as_deref()
        && session.workspace_id.as_deref() != Some(workspace)
    {
        return Err(OpenCodeRunError::Protocol(
            "OpenCode session workspace identity does not match the route policy".to_owned(),
        ));
    }
    Ok(())
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn read_only_permission_rules() -> Value {
    json!([
        {"permission": "*", "pattern": "*", "action": "deny"},
        {"permission": "read", "pattern": "*", "action": "allow"},
        {"permission": "read", "pattern": "*.env", "action": "deny"},
        {"permission": "read", "pattern": "*.env.*", "action": "deny"},
        {"permission": "glob", "pattern": "*", "action": "allow"},
        {"permission": "grep", "pattern": "*", "action": "allow"},
        {"permission": "list", "pattern": "*", "action": "allow"}
    ])
}

fn generate_message_id(session_id: &str, request: &ReadOnlyRunRequest) -> String {
    let sequence = MESSAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut hasher = Sha256::new();
    for component in [
        session_id.as_bytes(),
        request.model.provider_id.as_bytes(),
        request.model.model_id.as_bytes(),
        request.prompt.as_bytes(),
        &std::process::id().to_le_bytes(),
        &sequence.to_le_bytes(),
        &timestamp.to_le_bytes(),
    ] {
        hasher.update(component);
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(48);
    for byte in &digest[..24] {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    format!("msg_{encoded}")
}

fn attest_unchanged_diff(
    baseline: &[SessionDiff],
    observed: &[SessionDiff],
) -> Result<(), OpenCodeRunError> {
    if baseline == observed {
        return Ok(());
    }
    Err(OpenCodeRunError::MutationObserved {
        count: baseline.len().max(observed.len()),
    })
}

fn attest_message_route(
    info: &serde_json::Map<String, Value>,
    requested: &ModelSelection,
) -> Result<ModelSelection, OpenCodeRunError> {
    let observed = ModelSelection::new(
        required_string(info.get("providerID"), "assistant providerID")?,
        required_string(info.get("modelID"), "assistant modelID")?,
    )
    .map_err(|error| OpenCodeRunError::Protocol(error.to_string()))?;
    if &observed != requested {
        return Err(OpenCodeRunError::Protocol(format!(
            "actual route {}/{} differs from requested {}/{}",
            observed.provider_id, observed.model_id, requested.provider_id, requested.model_id
        )));
    }
    Ok(observed)
}

fn provider_error(error: Option<&Value>, fallback_kind: &str) -> OpenCodeRunError {
    let kind = error
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(fallback_kind)
        .to_owned();
    let message = error
        .and_then(|value| value.pointer("/data/message"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("provider returned no public error message")
        .to_owned();
    OpenCodeRunError::Provider { kind, message }
}

fn attest_provider(
    providers: &ProviderCatalog,
    requested: &ModelSelection,
) -> Result<(), OpenCodeRunError> {
    if !providers
        .connected
        .iter()
        .any(|provider| provider == &requested.provider_id)
    {
        return Err(OpenCodeRunError::RouteUnavailable(format!(
            "provider {} is not connected",
            requested.provider_id
        )));
    }
    let provider = providers
        .all
        .iter()
        .find(|provider| provider.id == requested.provider_id)
        .ok_or_else(|| {
            OpenCodeRunError::RouteUnavailable(format!(
                "provider {} is absent from inventory",
                requested.provider_id
            ))
        })?;
    if !provider.models.contains_key(&requested.model_id) {
        return Err(OpenCodeRunError::RouteUnavailable(format!(
            "model {}/{} is absent from inventory",
            requested.provider_id, requested.model_id
        )));
    }
    Ok(())
}

fn attest_read_only_agent(agents: &[Value]) -> Result<(), OpenCodeRunError> {
    let plan = agents.iter().find(|agent| {
        agent.get("name").and_then(Value::as_str) == Some(READ_ONLY_AGENT)
            && matches!(
                agent.get("mode").and_then(Value::as_str),
                Some("primary" | "all")
            )
    });
    if plan.is_none() {
        return Err(OpenCodeRunError::RouteUnavailable(
            "OpenCode plan agent is unavailable as a top-level route".to_owned(),
        ));
    }
    Ok(())
}

fn event_belongs_to_session(event: &OpenCodeEvent, session_id: &str) -> bool {
    if event.event_type == "server.connected" {
        return true;
    }
    event
        .properties
        .get("sessionID")
        .and_then(Value::as_str)
        .is_some_and(|observed| observed == session_id)
}

fn attest_aborted_messages(
    messages: &Value,
    session_id: &str,
    user_message_id: &str,
) -> Result<(), OpenCodeRunError> {
    let messages = messages.as_array().ok_or_else(|| {
        OpenCodeRunError::Protocol("post-abort messages response is not an array".to_owned())
    })?;
    let Some(assistant) = messages.iter().rev().find(|message| {
        message.pointer("/info/role").and_then(Value::as_str) == Some("assistant")
            && message.pointer("/info/sessionID").and_then(Value::as_str) == Some(session_id)
            && message.pointer("/info/parentID").and_then(Value::as_str) == Some(user_message_id)
    }) else {
        return Ok(());
    };
    let info = assistant
        .get("info")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OpenCodeRunError::Protocol("post-abort assistant info is not an object".to_owned())
        })?;
    if let Some(error) = info.get("error").filter(|error| !error.is_null()) {
        if error.get("name").and_then(Value::as_str) == Some("MessageAbortedError") {
            return Ok(());
        }
        return Err(provider_error(Some(error), "MessageError"));
    }
    let message_id = required_string(info.get("id"), "post-abort assistant identity")?;
    let completed = info
        .get("time")
        .and_then(Value::as_object)
        .and_then(|time| time.get("completed"))
        .and_then(Value::as_u64)
        .is_some();
    let terminal_stop = info.get("finish").and_then(Value::as_str) == Some("stop")
        || assistant
            .get("parts")
            .and_then(Value::as_array)
            .is_some_and(|parts| {
                parts.iter().any(|part| {
                    part.get("type").and_then(Value::as_str) == Some("step-finish")
                        && part.get("reason").and_then(Value::as_str) == Some("stop")
                })
            });
    if completed && terminal_stop {
        return Err(OpenCodeRunError::CompletedAfterAbort { message_id });
    }
    Err(OpenCodeRunError::Protocol(
        "correlated assistant remained semantically unresolved after abort".to_owned(),
    ))
}

struct MessageProjection {
    observed_model: ModelSelection,
    output: Value,
    usage: Option<UsageTelemetry>,
}

fn inspect_messages(
    messages: &Value,
    session_id: &str,
    user_message_id: &str,
    expected_assistant_message_id: Option<&str>,
    requested: &ModelSelection,
    expected_output_schema: &Value,
) -> Result<MessageProjection, OpenCodeRunError> {
    let messages = messages.as_array().ok_or_else(|| {
        OpenCodeRunError::Protocol("session messages response is not an array".to_owned())
    })?;
    let user = messages
        .iter()
        .find(|message| {
            message.pointer("/info/role").and_then(Value::as_str) == Some("user")
                && message.pointer("/info/id").and_then(Value::as_str) == Some(user_message_id)
                && message.pointer("/info/sessionID").and_then(Value::as_str) == Some(session_id)
        })
        .ok_or_else(|| {
            OpenCodeRunError::Protocol("submitted user message was not reconciled".to_owned())
        })?;
    if user.pointer("/info/format/type").and_then(Value::as_str) != Some("text") {
        return Err(OpenCodeRunError::Protocol(
            "submitted user message did not retain text output format".to_owned(),
        ));
    }
    let assistant = messages
        .iter()
        .rev()
        .find(|message| {
            message.pointer("/info/role").and_then(Value::as_str) == Some("assistant")
                && message.pointer("/info/sessionID").and_then(Value::as_str) == Some(session_id)
                && message.pointer("/info/parentID").and_then(Value::as_str)
                    == Some(user_message_id)
                && expected_assistant_message_id.is_none_or(|expected| {
                    message.pointer("/info/id").and_then(Value::as_str) == Some(expected)
                })
        })
        .ok_or_else(|| {
            OpenCodeRunError::Protocol(
                "session has no assistant correlated to the submitted prompt".to_owned(),
            )
        })?;
    let info = assistant
        .get("info")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OpenCodeRunError::Protocol("assistant message info is not an object".to_owned())
        })?;
    if info.get("error").is_some_and(|error| !error.is_null()) {
        return Err(provider_error(info.get("error"), "MessageError"));
    }
    if info
        .get("time")
        .and_then(Value::as_object)
        .and_then(|time| time.get("completed"))
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(OpenCodeRunError::Protocol(
            "assistant message has no completion timestamp".to_owned(),
        ));
    }
    let observed_model = attest_message_route(info, requested)?;

    let parts = assistant
        .get("parts")
        .and_then(Value::as_array)
        .ok_or_else(|| OpenCodeRunError::Protocol("assistant parts are missing".to_owned()))?;
    let terminal_stop = parts.iter().any(|part| {
        part.get("type").and_then(Value::as_str) == Some("step-finish")
            && part.get("reason").and_then(Value::as_str) == Some("stop")
    }) || info.get("finish").and_then(Value::as_str) == Some("stop");
    if !terminal_stop {
        return Err(OpenCodeRunError::Protocol(
            "assistant message has no terminal stop attestation".to_owned(),
        ));
    }
    let output = parse_text_json_output(parts, expected_output_schema)?;

    let tokens = info.get("tokens").and_then(Value::as_object);
    let usage = tokens.map(|tokens| UsageTelemetry {
        input_tokens: tokens.get("input").and_then(Value::as_u64),
        output_tokens: tokens.get("output").and_then(Value::as_u64),
        total_tokens: tokens.get("total").and_then(Value::as_u64),
        cost_usd: info.get("cost").and_then(Value::as_f64),
        extra: UnknownFields::new(),
    });
    let usage = usage.filter(|usage| {
        usage.input_tokens.is_some() && usage.output_tokens.is_some() && usage.cost_usd.is_some()
    });
    Ok(MessageProjection {
        observed_model,
        output,
        usage,
    })
}

fn parse_text_json_output(
    parts: &[Value],
    expected_output_schema: &Value,
) -> Result<Value, OpenCodeRunError> {
    let text = parts
        .iter()
        .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect::<String>();
    if text.trim().is_empty() {
        return Err(OpenCodeRunError::Protocol(
            "assistant message contains no text JSON output".to_owned(),
        ));
    }
    let output = serde_json::from_str::<Value>(&text).map_err(|error| {
        OpenCodeRunError::Protocol(format!(
            "assistant text is not one strict JSON value: {error}"
        ))
    })?;
    attest_top_level_output_schema(&output, expected_output_schema)?;
    Ok(output)
}

fn required_string(value: Option<&Value>, field: &str) -> Result<String, OpenCodeRunError> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| OpenCodeRunError::Protocol(format!("{field} is missing")))
}

fn attest_top_level_output_schema(output: &Value, schema: &Value) -> Result<(), OpenCodeRunError> {
    let Some(schema) = schema.as_object() else {
        return Err(OpenCodeRunError::Protocol(
            "expected output schema is not an object".to_owned(),
        ));
    };
    if let Some(expected_type) = schema.get("type") {
        let matches = match expected_type.as_str() {
            Some("object") => output.is_object(),
            Some("array") => output.is_array(),
            Some("string") => output.is_string(),
            Some("number") => output.is_number(),
            Some("integer") => output.as_i64().is_some() || output.as_u64().is_some(),
            Some("boolean") => output.is_boolean(),
            Some("null") => output.is_null(),
            Some(_) | None => {
                return Err(OpenCodeRunError::Protocol(
                    "bootstrap output schema uses an unsupported top-level type".to_owned(),
                ));
            }
        };
        if !matches {
            return Err(OpenCodeRunError::Protocol(
                "assistant JSON output does not match the requested top-level type".to_owned(),
            ));
        }
    }
    if let Some(required) = schema.get("required") {
        let required = required.as_array().ok_or_else(|| {
            OpenCodeRunError::Protocol("output schema required must be an array".to_owned())
        })?;
        let output = output.as_object().ok_or_else(|| {
            OpenCodeRunError::Protocol(
                "output schema declares required fields for a non-object result".to_owned(),
            )
        })?;
        for field in required {
            let field = field.as_str().ok_or_else(|| {
                OpenCodeRunError::Protocol(
                    "output schema required fields must be strings".to_owned(),
                )
            })?;
            if !output.contains_key(field) {
                return Err(OpenCodeRunError::Protocol(format!(
                    "assistant JSON output is missing required field {field:?}"
                )));
            }
        }
    }
    Ok(())
}

fn route_fingerprint(
    endpoint: &LoopbackEndpoint,
    server_version: &str,
    model: &ModelSelection,
    agent: &str,
) -> String {
    let mut hasher = Sha256::new();
    for component in [
        CLIENT_PROTOCOL_REVISION,
        endpoint.as_str(),
        server_version,
        &model.provider_id,
        &model.model_id,
        agent,
    ] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    format!("sha256:{encoded}")
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{
        CorrelatedEventState, OpenCodeClient, OpenCodeRunError, OpenCodeRunPolicy,
        encode_component, generate_message_id,
    };
    use crate::{
        ActualRouteState, AuthorityCeiling, BasicAuth, LoopbackEndpoint, ModelSelection,
        OpenCodeEvent, ReadOnlyRunRequest, RunStatus,
    };
    use secrecy::SecretString;
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[test]
    fn percent_encodes_windows_directory_without_plus_semantics() {
        assert_eq!(
            encode_component(r"C:\Development\Rust\a b"),
            "C%3A%5CDevelopment%5CRust%5Ca%20b"
        );
    }

    #[test]
    fn stale_idle_cannot_complete_before_correlated_assistant_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let model = ModelSelection::new("opencode-go", "deepseek-v4-flash")?;
        let mut state = CorrelatedEventState::new("ses_1", "msg_user_1", &model);
        state.observe(&serde_json::from_value::<OpenCodeEvent>(
            serde_json::json!({
                "type": "session.status",
                "properties": {"sessionID": "ses_1", "status": {"type": "idle"}}
            }),
        )?)?;
        assert!(!state.is_complete());
        state.observe(&serde_json::from_value::<OpenCodeEvent>(
            serde_json::json!({
                "type": "message.updated",
                "properties": {"sessionID": "ses_1", "info": {
                    "id": "msg_assistant_1", "sessionID": "ses_1", "role": "assistant",
                    "parentID": "msg_user_1", "providerID": "opencode-go",
                    "modelID": "deepseek-v4-flash", "time": {"created": 1, "completed": 2}
                }}
            }),
        )?)?;
        assert!(!state.is_complete());
        state.observe(&serde_json::from_value::<OpenCodeEvent>(
            serde_json::json!({
                "type": "message.part.updated",
                "properties": {"sessionID": "ses_1", "part": {
                    "sessionID": "ses_1", "messageID": "msg_assistant_1",
                    "type": "step-finish", "reason": "stop"
                }}
            }),
        )?)?;
        assert!(state.is_complete());
        Ok(())
    }

    #[test]
    fn terminal_part_may_precede_correlated_message_update()
    -> Result<(), Box<dyn std::error::Error>> {
        let model = ModelSelection::new("opencode-go", "deepseek-v4-flash")?;
        let mut state = CorrelatedEventState::new("ses_1", "msg_user_1", &model);
        for event in [
            serde_json::json!({
                "type": "message.part.updated",
                "properties": {"sessionID": "ses_1", "part": {
                    "sessionID": "ses_1", "messageID": "msg_assistant_1",
                    "type": "step-finish", "reason": "stop"
                }}
            }),
            serde_json::json!({
                "type": "message.updated",
                "properties": {"sessionID": "ses_1", "info": {
                    "id": "msg_assistant_1", "sessionID": "ses_1", "role": "assistant",
                    "parentID": "msg_user_1", "providerID": "opencode-go",
                    "modelID": "deepseek-v4-flash", "time": {"completed": 2}
                }}
            }),
            serde_json::json!({
                "type": "session.idle", "properties": {"sessionID": "ses_1"}
            }),
        ] {
            state.observe(&serde_json::from_value::<OpenCodeEvent>(event)?)?;
        }
        assert!(state.is_complete());
        Ok(())
    }

    #[test]
    fn tool_rounds_may_advance_to_one_later_terminal_assistant()
    -> Result<(), Box<dyn std::error::Error>> {
        let model = ModelSelection::new("opencode-go", "deepseek-v4-flash")?;
        let mut state = CorrelatedEventState::new("ses_1", "msg_user_1", &model);
        for event in [
            serde_json::json!({
                "type": "message.updated",
                "properties": {"sessionID": "ses_1", "info": {
                    "id": "msg_assistant_tool", "sessionID": "ses_1", "role": "assistant",
                    "parentID": "msg_user_1", "providerID": "opencode-go",
                    "modelID": "deepseek-v4-flash", "time": {"created": 1, "completed": 2}
                }}
            }),
            serde_json::json!({
                "type": "message.updated",
                "properties": {"sessionID": "ses_1", "info": {
                    "id": "msg_assistant_final", "sessionID": "ses_1", "role": "assistant",
                    "parentID": "msg_user_1", "providerID": "opencode-go",
                    "modelID": "deepseek-v4-flash", "time": {"created": 3, "completed": 4}
                }}
            }),
            serde_json::json!({
                "type": "message.part.updated",
                "properties": {"sessionID": "ses_1", "part": {
                    "sessionID": "ses_1", "messageID": "msg_assistant_final",
                    "type": "step-finish", "reason": "stop"
                }}
            }),
            serde_json::json!({
                "type": "session.idle", "properties": {"sessionID": "ses_1"}
            }),
        ] {
            state.observe(&serde_json::from_value::<OpenCodeEvent>(event)?)?;
        }
        assert_eq!(
            state.assistant_message_id.as_deref(),
            Some("msg_assistant_final")
        );
        assert!(state.is_complete());
        Ok(())
    }

    #[test]
    fn correlated_wrong_route_and_unbound_session_error_are_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let model = ModelSelection::new("opencode-go", "deepseek-v4-flash")?;
        let mut state = CorrelatedEventState::new("ses_1", "msg_user_1", &model);
        let wrong_route = serde_json::from_value::<OpenCodeEvent>(serde_json::json!({
            "type": "message.updated",
            "properties": {"sessionID": "ses_1", "info": {
                "id": "msg_assistant_1", "sessionID": "ses_1", "role": "assistant",
                "parentID": "msg_user_1", "providerID": "opencode",
                "modelID": "deepseek-v4-flash-free", "time": {"completed": 2}
            }}
        }))?;
        assert!(matches!(
            state.observe(&wrong_route),
            Err(OpenCodeRunError::Protocol(_))
        ));

        let unbound_error = serde_json::from_value::<OpenCodeEvent>(serde_json::json!({
            "type": "session.error",
            "properties": {"error": {"name": "UnknownError", "data": {"message": "x"}}}
        }))?;
        assert!(matches!(
            state.observe(&unbound_error),
            Err(OpenCodeRunError::Protocol(_))
        ));
        Ok(())
    }

    #[test]
    fn generated_message_ids_are_canonical_and_distinct() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = ReadOnlyRunRequest::new(
            "Return structured JSON.",
            ModelSelection::new("opencode-go", "deepseek-v4-flash")?,
        )?;
        let first = generate_message_id("ses_1", &request);
        let second = generate_message_id("ses_1", &request);
        assert!(first.starts_with("msg_"));
        assert!(first[4..].bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
        Ok(())
    }

    #[tokio::test]
    async fn deterministic_fixture_runs_no_authority_http_sse_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = ReadOnlyRunRequest::new(
            "Return JSON status.",
            ModelSelection::new("opencode-go", "deepseek-v4-flash")?,
        )?
        .with_message_id("msg_fixture_1")?;
        let event_data = concat!(
            "data: {\"type\":\"server.connected\",\"properties\":{}}\n\n",
            "data: {\"type\":\"message.updated\",\"properties\":{\"sessionID\":\"ses_1\",\"info\":{\"id\":\"msg_assistant_1\",\"sessionID\":\"ses_1\",\"parentID\":\"msg_fixture_1\",\"role\":\"assistant\",\"time\":{\"created\":2,\"completed\":3},\"providerID\":\"opencode-go\",\"modelID\":\"deepseek-v4-flash\"}}}\n\n",
            "data: {\"type\":\"message.part.updated\",\"properties\":{\"sessionID\":\"ses_1\",\"part\":{\"sessionID\":\"ses_1\",\"messageID\":\"msg_assistant_1\",\"type\":\"step-finish\",\"reason\":\"stop\"},\"time\":3}}\n\n",
            "data: {\"type\":\"session.status\",\"properties\":{\"sessionID\":\"ses_1\",\"status\":{\"type\":\"idle\"}}}\n\n",
        );
        let sse_response = chunked_sse(event_data.as_bytes());
        let responses = vec![
            json_response(br#"{"healthy":true,"version":"1.4.3"}"#),
            json_response(br#"{"all":[{"id":"opencode-go","models":{"deepseek-v4-flash":{"id":"deepseek-v4-flash"}}}],"default":{},"connected":["opencode-go"]}"#),
            json_response(br#"[{"name":"plan","mode":"primary","permission":{},"options":{}}]"#),
            json_response(br#"{"id":"ses_1","slug":"s","projectID":"p","directory":"C:\\Scratch","title":"ELIOT","version":"1.4.3","time":{"created":1,"updated":1},"permission":[{"permission":"*","pattern":"*","action":"deny"},{"permission":"read","pattern":"*","action":"allow"},{"permission":"read","pattern":"*.env","action":"deny"},{"permission":"read","pattern":"*.env.*","action":"deny"},{"permission":"glob","pattern":"*","action":"allow"},{"permission":"grep","pattern":"*","action":"allow"},{"permission":"list","pattern":"*","action":"allow"}]}"#),
            json_response(br"[]"),
            sse_response,
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec(),
            json_response(br#"{"ses_1":{"type":"idle"}}"#),
            json_response(br#"[{"info":{"id":"msg_fixture_1","sessionID":"ses_1","role":"user","time":{"created":1},"format":{"type":"text"},"agent":"plan","model":{"providerID":"opencode-go","modelID":"deepseek-v4-flash"}},"parts":[{"id":"part_user","sessionID":"ses_1","messageID":"msg_fixture_1","type":"text","text":"Return JSON status."}]},{"info":{"id":"msg_assistant_1","sessionID":"ses_1","role":"assistant","time":{"created":2,"completed":3},"parentID":"msg_fixture_1","modelID":"deepseek-v4-flash","providerID":"opencode-go","mode":"plan","agent":"plan","path":{"cwd":"C:\\Scratch","root":"C:\\Scratch"},"cost":0.01,"tokens":{"total":12,"input":7,"output":5,"reasoning":0,"cache":{"read":0,"write":0}},"finish":"stop"},"parts":[{"id":"part_text","sessionID":"ses_1","messageID":"msg_assistant_1","type":"text","text":"{\"status\":\"ready\"}"},{"id":"part_1","sessionID":"ses_1","messageID":"msg_assistant_1","type":"step-finish","reason":"stop"}]}]"#),
            json_response(br"[]"),
        ];
        let (port, requests) = serve_sequence(responses).await?;
        let endpoint = format!("http://127.0.0.1:{port}").parse::<LoopbackEndpoint>()?;
        let policy = OpenCodeRunPolicy::new(Path::new(r"C:\Scratch"))?
            .with_timeouts(Duration::from_secs(5), Duration::from_secs(2));
        let client = OpenCodeClient::new(
            endpoint,
            BasicAuth::new("opencode", SecretString::from("secret".to_owned()))?,
            policy,
        )?;
        let result = client.run_read_only(&request).await?;
        assert_eq!(result.status, RunStatus::Succeeded);
        assert!(result.candidate_only);
        assert_eq!(result.authority, AuthorityCeiling::CandidateOnly);
        assert_eq!(result.actual_route.state, ActualRouteState::Observed);
        assert_eq!(result.output, Some(serde_json::json!({"status":"ready"})));
        assert!(result.diff.is_empty());

        let requests = requests.lock().await;
        assert_eq!(requests.len(), 10);
        assert!(requests.iter().any(|request| {
            request.starts_with("GET /event?directory=C%3A%5CScratch HTTP/1.1")
        }));
        assert!(requests.iter().any(|request| {
            request.starts_with("POST /session?directory=C%3A%5CScratch HTTP/1.1")
                && request.contains("\"permission\":\"*\"")
                && !request.contains("\"permission\":\"edit\"")
                && request.contains("\"action\":\"deny\"")
        }));
        assert!(requests.iter().any(|request| {
            request.contains("POST /session/ses_1/prompt_async?directory=C%3A%5CScratch HTTP/1.1")
                && request.contains("\"providerID\":\"opencode-go\"")
                && request.contains("\"modelID\":\"deepseek-v4-flash\"")
                && request.contains("\"agent\":\"plan\"")
                && request.contains("\"messageID\":\"msg_fixture_1\"")
                && request.contains("\"format\":{\"type\":\"text\"}")
        }));
        Ok(())
    }

    fn json_response(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn chunked_sse(body: &[u8]) -> Vec<u8> {
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(format!("{:X}\r\n", body.len()).as_bytes());
        response.extend_from_slice(body);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        response
    }

    async fn serve_sequence(
        responses: Vec<Vec<u8>>,
    ) -> Result<(u16, Arc<Mutex<Vec<String>>>), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let requests_task = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let response = responses.lock().await.pop_front();
                let Some(response) = response else {
                    break;
                };
                let accepted = listener.accept().await;
                let Ok((mut stream, _)) = accepted else {
                    break;
                };
                let requests = Arc::clone(&requests_task);
                let task = tokio::spawn(async move {
                    let mut raw = Vec::<u8>::new();
                    let mut buffer = [0_u8; 4096];
                    loop {
                        let read = stream.read(&mut buffer).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        raw.extend_from_slice(&buffer[..read]);
                        let Some(head_end) =
                            raw.windows(4).position(|window| window == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let content_length = String::from_utf8_lossy(&raw[..head_end])
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("Content-Length: ")
                                    .and_then(|value| value.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if raw.len() >= head_end + 4 + content_length {
                            break;
                        }
                    }
                    requests
                        .lock()
                        .await
                        .push(String::from_utf8_lossy(&raw).into_owned());
                    let _ = stream.write_all(&response).await;
                    let _ = stream.shutdown().await;
                });
                let _ = task.await;
            }
        });
        Ok((port, requests))
    }
}
