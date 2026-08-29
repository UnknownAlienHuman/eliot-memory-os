use crate::LoopbackEndpoint;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret as _, SecretString};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};

const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_ABSOLUTE_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_INFORMATIONAL_RESPONSES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

impl HttpMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

pub struct BasicAuth {
    username: String,
    password: SecretString,
}

impl BasicAuth {
    pub fn new(
        username: impl Into<String>,
        password: SecretString,
    ) -> Result<Self, LoopbackHttpError> {
        let username = username.into();
        if username.is_empty() || username.contains(':') || username.chars().any(char::is_control) {
            return Err(LoopbackHttpError::InvalidRequest(
                "basic-auth username is empty or contains a forbidden character".to_owned(),
            ));
        }
        if password.expose_secret().is_empty()
            || password
                .expose_secret()
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
        {
            return Err(LoopbackHttpError::InvalidRequest(
                "basic-auth password is empty or contains a line break".to_owned(),
            ));
        }
        Ok(Self { username, password })
    }

    fn header_value(&self) -> String {
        let cleartext = format!("{}:{}", self.username, self.password.expose_secret());
        format!("Basic {}", STANDARD.encode(cleartext.as_bytes()))
    }
}

impl fmt::Debug for BasicAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BasicAuth")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path_and_query: String,
    pub body: Vec<u8>,
    pub accept_sse: bool,
    pub last_event_id: Option<String>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path_and_query", &self.path_and_query)
            .field("body_len", &self.body.len())
            .field("accept_sse", &self.accept_sse)
            .field(
                "last_event_id",
                &self.last_event_id.as_deref().map(sanitize_text),
            )
            .finish()
    }
}

impl HttpRequest {
    #[must_use]
    pub fn get(path_and_query: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            path_and_query: path_and_query.into(),
            body: Vec::new(),
            accept_sse: false,
            last_event_id: None,
        }
    }

    pub fn post_json(
        path_and_query: impl Into<String>,
        body: &impl serde::Serialize,
    ) -> Result<Self, LoopbackHttpError> {
        let body = serde_json::to_vec(body).map_err(|error| {
            LoopbackHttpError::InvalidRequest(format!("serialize JSON request: {error}"))
        })?;
        Ok(Self {
            method: HttpMethod::Post,
            path_and_query: path_and_query.into(),
            body,
            accept_sse: false,
            last_event_id: None,
        })
    }

    #[must_use]
    pub fn sse(path_and_query: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            path_and_query: path_and_query.into(),
            body: Vec::new(),
            accept_sse: true,
            last_event_id: None,
        }
    }

    /// Adds the SSE reconnect cursor without exposing a generic caller-owned
    /// header surface that could shadow authentication or framing headers.
    pub fn with_last_event_id(
        mut self,
        last_event_id: Option<&str>,
    ) -> Result<Self, LoopbackHttpError> {
        if !self.accept_sse && last_event_id.is_some() {
            return Err(LoopbackHttpError::InvalidRequest(
                "Last-Event-ID is valid only for an SSE request".to_owned(),
            ));
        }
        self.last_event_id = last_event_id.map(str::to_owned);
        validate_last_event_id(self.last_event_id.as_deref())?;
        Ok(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| {
                let value = if sensitive_header(name) {
                    "[REDACTED]".to_owned()
                } else {
                    sanitize_text(value)
                };
                (name, value)
            })
            .collect::<BTreeMap<_, _>>();
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl HttpResponse {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, LoopbackHttpError> {
        serde_json::from_slice(&self.body)
            .map_err(|error| LoopbackHttpError::Protocol(format!("decode JSON response: {error}")))
    }
}

#[derive(Error)]
pub enum LoopbackHttpError {
    #[error("invalid loopback HTTP request: {0}")]
    InvalidRequest(String),
    #[error("loopback HTTP {phase} timed out")]
    Timeout { phase: &'static str },
    #[error("loopback HTTP {phase} failed: {source}")]
    Io {
        phase: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("invalid loopback HTTP response: {0}")]
    Protocol(String),
    #[error("loopback HTTP response exceeded {limit} bytes")]
    ResponseLimit { limit: usize },
    #[error("loopback HTTP status {status}")]
    Status { status: u16, body_preview: String },
}

impl fmt::Debug for LoopbackHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => formatter
                .debug_tuple("InvalidRequest")
                .field(&sanitize_text(message))
                .finish(),
            Self::Timeout { phase } => formatter
                .debug_struct("Timeout")
                .field("phase", phase)
                .finish(),
            Self::Io { phase, source } => formatter
                .debug_struct("Io")
                .field("phase", phase)
                .field("source", source)
                .finish(),
            Self::Protocol(message) => formatter
                .debug_tuple("Protocol")
                .field(&sanitize_text(message))
                .finish(),
            Self::ResponseLimit { limit } => formatter
                .debug_struct("ResponseLimit")
                .field("limit", limit)
                .finish(),
            Self::Status { status, .. } => formatter
                .debug_struct("Status")
                .field("status", status)
                .field("body_preview", &"[REDACTED]")
                .finish(),
        }
    }
}

pub struct LoopbackHttpClient {
    endpoint: LoopbackEndpoint,
    auth: BasicAuth,
    connect_timeout: Duration,
    io_timeout: Duration,
    max_header_bytes: usize,
    max_body_bytes: usize,
    absolute_timeout: Duration,
}

impl fmt::Debug for LoopbackHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackHttpClient")
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("max_header_bytes", &self.max_header_bytes)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("absolute_timeout", &self.absolute_timeout)
            .finish()
    }
}

impl LoopbackHttpClient {
    #[must_use]
    pub const fn new(endpoint: LoopbackEndpoint, auth: BasicAuth) -> Self {
        Self {
            endpoint,
            auth,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(30),
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            absolute_timeout: DEFAULT_ABSOLUTE_TIMEOUT,
        }
    }

    #[must_use]
    pub const fn with_limits(
        mut self,
        connect_timeout: Duration,
        io_timeout: Duration,
        max_header_bytes: usize,
        max_body_bytes: usize,
    ) -> Self {
        self.connect_timeout = connect_timeout;
        self.io_timeout = io_timeout;
        self.max_header_bytes = max_header_bytes;
        self.max_body_bytes = max_body_bytes;
        self
    }

    #[must_use]
    pub const fn with_absolute_timeout(mut self, absolute_timeout: Duration) -> Self {
        self.absolute_timeout = absolute_timeout;
        self
    }

    pub async fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, LoopbackHttpError> {
        let deadline = Instant::now() + self.absolute_timeout;
        timeout_at(deadline, self.execute_until(request))
            .await
            .map_err(|_| LoopbackHttpError::Timeout { phase: "request" })?
    }

    async fn execute_until(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, LoopbackHttpError> {
        let mut reader = self.send(request).await?;
        let head =
            read_final_response_head(&mut reader, self.io_timeout, self.max_header_bytes).await?;
        let body =
            read_response_body(&mut reader, &head, self.io_timeout, self.max_body_bytes).await?;
        let response = HttpResponse {
            status: head.status,
            headers: head.headers,
            body,
        };
        if !(200..300).contains(&response.status) {
            return Err(status_error(&response));
        }
        Ok(response)
    }

    pub async fn open_sse(
        &self,
        request: &HttpRequest,
    ) -> Result<SseConnection, LoopbackHttpError> {
        if !request.accept_sse {
            return Err(LoopbackHttpError::InvalidRequest(
                "SSE connection requires an SSE request".to_owned(),
            ));
        }
        let deadline = Instant::now() + self.absolute_timeout;
        timeout_at(deadline, self.open_sse_until(request, deadline))
            .await
            .map_err(|_| LoopbackHttpError::Timeout {
                phase: "SSE request",
            })?
    }

    async fn open_sse_until(
        &self,
        request: &HttpRequest,
        deadline: Instant,
    ) -> Result<SseConnection, LoopbackHttpError> {
        let mut reader = self.send(request).await?;
        let head =
            read_final_response_head(&mut reader, self.io_timeout, self.max_header_bytes).await?;
        if !(200..300).contains(&head.status) {
            let body = read_response_body(&mut reader, &head, self.io_timeout, self.max_body_bytes)
                .await?;
            return Err(status_error(&HttpResponse {
                status: head.status,
                headers: head.headers,
                body,
            }));
        }
        let content_type = head.headers.get("content-type").map_or("", String::as_str);
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(LoopbackHttpError::Protocol(format!(
                "SSE response has content type {content_type:?}"
            )));
        }
        let framing = response_framing(&head)?;
        Ok(SseConnection {
            reader,
            framing,
            io_timeout: self.io_timeout,
            decoded_bytes: 0,
            max_decoded_bytes: self.max_body_bytes,
            deadline,
        })
    }

    async fn send(&self, request: &HttpRequest) -> Result<BufReader<TcpStream>, LoopbackHttpError> {
        validate_request(request)?;
        let stream = timeout(
            self.connect_timeout,
            TcpStream::connect(self.endpoint.socket_addr()),
        )
        .await
        .map_err(|_| LoopbackHttpError::Timeout { phase: "connect" })?
        .map_err(|source| LoopbackHttpError::Io {
            phase: "connect",
            source,
        })?;
        let mut reader = BufReader::new(stream);
        let request_bytes = encode_request(
            request,
            self.endpoint.host_header(),
            &self.auth.header_value(),
        );
        timeout(self.io_timeout, reader.get_mut().write_all(&request_bytes))
            .await
            .map_err(|_| LoopbackHttpError::Timeout { phase: "write" })?
            .map_err(|source| LoopbackHttpError::Io {
                phase: "write",
                source,
            })?;
        timeout(self.io_timeout, reader.get_mut().flush())
            .await
            .map_err(|_| LoopbackHttpError::Timeout { phase: "flush" })?
            .map_err(|source| LoopbackHttpError::Io {
                phase: "flush",
                source,
            })?;
        Ok(reader)
    }
}

pub struct SseConnection {
    reader: BufReader<TcpStream>,
    framing: BodyFraming,
    io_timeout: Duration,
    decoded_bytes: usize,
    max_decoded_bytes: usize,
    deadline: Instant,
}

impl fmt::Debug for SseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SseConnection")
            .field("framing", &self.framing)
            .field("decoded_bytes", &self.decoded_bytes)
            .field("max_decoded_bytes", &self.max_decoded_bytes)
            .finish_non_exhaustive()
    }
}

impl SseConnection {
    pub async fn read_decoded_chunk(
        &mut self,
        requested_max: usize,
    ) -> Result<Option<Vec<u8>>, LoopbackHttpError> {
        if requested_max == 0 {
            return Err(LoopbackHttpError::InvalidRequest(
                "SSE chunk limit must be nonzero".to_owned(),
            ));
        }
        let remaining_budget = self.max_decoded_bytes.saturating_sub(self.decoded_bytes);
        let effective_max = requested_max.min(remaining_budget.max(1));
        let chunk = timeout_at(
            self.deadline,
            read_framed_chunk(
                &mut self.reader,
                &mut self.framing,
                self.io_timeout,
                effective_max,
            ),
        )
        .await
        .map_err(|_| LoopbackHttpError::Timeout {
            phase: "read SSE body",
        })??;
        if let Some(bytes) = &chunk {
            self.decoded_bytes = self.decoded_bytes.checked_add(bytes.len()).ok_or(
                LoopbackHttpError::ResponseLimit {
                    limit: self.max_decoded_bytes,
                },
            )?;
            if self.decoded_bytes > self.max_decoded_bytes {
                return Err(LoopbackHttpError::ResponseLimit {
                    limit: self.max_decoded_bytes,
                });
            }
        }
        Ok(chunk)
    }
}

#[derive(Debug)]
struct ResponseHead {
    status: u16,
    headers: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyFraming {
    Empty,
    ContentLength(usize),
    Chunked { remaining: usize, complete: bool },
    UntilEof,
}

fn validate_request(request: &HttpRequest) -> Result<(), LoopbackHttpError> {
    if !request.path_and_query.starts_with('/')
        || request.path_and_query.starts_with("//")
        || request.path_and_query.contains('#')
        || !request
            .path_and_query
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(LoopbackHttpError::InvalidRequest(
            "request target must be an origin-form path without whitespace, controls, or fragments"
                .to_owned(),
        ));
    }
    if request.method == HttpMethod::Get && !request.body.is_empty() {
        return Err(LoopbackHttpError::InvalidRequest(
            "GET request cannot carry a body".to_owned(),
        ));
    }
    if !request.accept_sse && request.last_event_id.is_some() {
        return Err(LoopbackHttpError::InvalidRequest(
            "Last-Event-ID is valid only for an SSE request".to_owned(),
        ));
    }
    validate_last_event_id(request.last_event_id.as_deref())?;
    Ok(())
}

fn validate_last_event_id(last_event_id: Option<&str>) -> Result<(), LoopbackHttpError> {
    let Some(last_event_id) = last_event_id else {
        return Ok(());
    };
    if last_event_id.is_empty()
        || last_event_id.len() > 8 * 1024
        || !last_event_id
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(LoopbackHttpError::InvalidRequest(
            "Last-Event-ID must be nonempty bounded printable ASCII".to_owned(),
        ));
    }
    Ok(())
}

fn encode_request(request: &HttpRequest, host: &str, authorization: &str) -> Vec<u8> {
    let accept = if request.accept_sse {
        "text/event-stream"
    } else {
        "application/json"
    };
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {authorization}\r\nAccept: {accept}\r\nConnection: close\r\nUser-Agent: eliot-agent-opencode/0.1\r\nContent-Length: {}\r\n",
        request.method.as_str(),
        request.path_and_query,
        request.body.len()
    );
    if !request.body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    if let Some(last_event_id) = &request.last_event_id {
        head.push_str("Last-Event-ID: ");
        head.push_str(last_event_id);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut encoded = head.into_bytes();
    encoded.extend_from_slice(&request.body);
    encoded
}

async fn read_response_head(
    reader: &mut BufReader<TcpStream>,
    io_timeout: Duration,
    max_header_bytes: usize,
) -> Result<ResponseHead, LoopbackHttpError> {
    let mut total = 0_usize;
    let status_line = read_limited_line(reader, io_timeout, &mut total, max_header_bytes).await?;
    require_crlf(&status_line, "HTTP status line")?;
    let status_line = status_line.strip_suffix("\r\n").unwrap_or_default();
    if !status_line.bytes().all(is_valid_header_value_byte) {
        return Err(LoopbackHttpError::Protocol(
            "HTTP status line contains a forbidden control byte".to_owned(),
        ));
    }
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            LoopbackHttpError::Protocol(format!("invalid status line {status_line:?}"))
        })?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || !(100..600).contains(&status) {
        return Err(LoopbackHttpError::Protocol(format!(
            "unsupported status line {status_line:?}"
        )));
    }
    let mut headers = BTreeMap::<String, String>::new();
    loop {
        let line = read_limited_line(reader, io_timeout, &mut total, max_header_bytes).await?;
        if line == "\r\n" {
            break;
        }
        if line.starts_with([' ', '\t']) {
            return Err(LoopbackHttpError::Protocol(
                "obsolete folded HTTP header is forbidden".to_owned(),
            ));
        }
        let (name, value) = parse_header_line(&line)?;
        headers
            .entry(name)
            .and_modify(|current| {
                current.push_str(", ");
                current.push_str(&value);
            })
            .or_insert(value);
    }
    Ok(ResponseHead { status, headers })
}

async fn read_final_response_head(
    reader: &mut BufReader<TcpStream>,
    io_timeout: Duration,
    max_header_bytes: usize,
) -> Result<ResponseHead, LoopbackHttpError> {
    for _ in 0..MAX_INFORMATIONAL_RESPONSES {
        let head = read_response_head(reader, io_timeout, max_header_bytes).await?;
        if !(100..200).contains(&head.status) {
            return Ok(head);
        }
        if head.status == 101 {
            return Err(LoopbackHttpError::Protocol(
                "HTTP 101 Switching Protocols is unsupported".to_owned(),
            ));
        }
        if head.headers.contains_key("content-length")
            || head.headers.contains_key("transfer-encoding")
        {
            return Err(LoopbackHttpError::Protocol(
                "informational HTTP response must not carry a body framing header".to_owned(),
            ));
        }
    }
    Err(LoopbackHttpError::Protocol(
        "too many informational HTTP responses".to_owned(),
    ))
}

async fn read_limited_line(
    reader: &mut BufReader<TcpStream>,
    io_timeout: Duration,
    total: &mut usize,
    max: usize,
) -> Result<String, LoopbackHttpError> {
    let remaining = max.saturating_sub(*total);
    let line = read_capped_line(reader, io_timeout, remaining, "read headers").await?;
    *total = total
        .checked_add(line.len())
        .ok_or(LoopbackHttpError::ResponseLimit { limit: max })?;
    String::from_utf8(line)
        .map_err(|_| LoopbackHttpError::Protocol("HTTP line is not valid UTF-8".to_owned()))
}

async fn read_capped_line(
    reader: &mut BufReader<TcpStream>,
    io_timeout: Duration,
    max_bytes: usize,
    phase: &'static str,
) -> Result<Vec<u8>, LoopbackHttpError> {
    let mut line = Vec::new();
    loop {
        let available = timeout(io_timeout, reader.fill_buf())
            .await
            .map_err(|_| LoopbackHttpError::Timeout { phase })?
            .map_err(|source| LoopbackHttpError::Io { phase, source })?;
        if available.is_empty() {
            return Err(LoopbackHttpError::Protocol(format!(
                "unexpected EOF while reading {phase}"
            )));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line
            .len()
            .checked_add(take)
            .is_none_or(|size| size > max_bytes)
        {
            return Err(LoopbackHttpError::ResponseLimit { limit: max_bytes });
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(line);
        }
        if line.len() == max_bytes {
            return Err(LoopbackHttpError::ResponseLimit { limit: max_bytes });
        }
    }
}

fn require_crlf(line: &str, kind: &str) -> Result<(), LoopbackHttpError> {
    if line.ends_with("\r\n") {
        Ok(())
    } else {
        Err(LoopbackHttpError::Protocol(format!("{kind} must use CRLF")))
    }
}

fn parse_header_line(line: &str) -> Result<(String, String), LoopbackHttpError> {
    require_crlf(line, "HTTP header")?;
    let line = line.strip_suffix("\r\n").unwrap_or_default();
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| LoopbackHttpError::Protocol(format!("malformed HTTP header {line:?}")))?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err(LoopbackHttpError::Protocol(format!(
            "invalid HTTP header name {name:?}"
        )));
    }
    if !value.bytes().all(is_valid_header_value_byte) {
        return Err(LoopbackHttpError::Protocol(format!(
            "HTTP header {name:?} contains a forbidden control byte"
        )));
    }
    Ok((name.to_ascii_lowercase(), value.trim().to_owned()))
}

const fn is_valid_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || byte >= 0x20 && byte != 0x7f
}

fn response_framing(head: &ResponseHead) -> Result<BodyFraming, LoopbackHttpError> {
    if head.headers.contains_key("transfer-encoding") && head.headers.contains_key("content-length")
    {
        return Err(LoopbackHttpError::Protocol(
            "Transfer-Encoding and Content-Length together are forbidden".to_owned(),
        ));
    }
    if (100..200).contains(&head.status) || matches!(head.status, 204 | 304) {
        return Ok(BodyFraming::Empty);
    }
    if let Some(encoding) = head.headers.get("transfer-encoding") {
        let tokens = encoding
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if tokens
            .last()
            .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
            && tokens[..tokens.len().saturating_sub(1)]
                .iter()
                .all(|value| value.eq_ignore_ascii_case("identity"))
        {
            return Ok(BodyFraming::Chunked {
                remaining: 0,
                complete: false,
            });
        }
        return Err(LoopbackHttpError::Protocol(format!(
            "unsupported transfer encoding {encoding:?}"
        )));
    }
    if let Some(length) = head.headers.get("content-length") {
        if length.contains(',') {
            return Err(LoopbackHttpError::Protocol(
                "duplicate Content-Length is forbidden".to_owned(),
            ));
        }
        let length = length.parse::<usize>().map_err(|_| {
            LoopbackHttpError::Protocol(format!("invalid Content-Length {length:?}"))
        })?;
        return Ok(BodyFraming::ContentLength(length));
    }
    Ok(BodyFraming::UntilEof)
}

async fn read_response_body(
    reader: &mut BufReader<TcpStream>,
    head: &ResponseHead,
    io_timeout: Duration,
    max_body_bytes: usize,
) -> Result<Vec<u8>, LoopbackHttpError> {
    let mut framing = response_framing(head)?;
    let mut body = Vec::new();
    loop {
        let remaining_capacity = max_body_bytes.saturating_sub(body.len());
        if remaining_capacity == 0 {
            if read_framed_chunk(reader, &mut framing, io_timeout, 1)
                .await?
                .is_some()
            {
                return Err(LoopbackHttpError::ResponseLimit {
                    limit: max_body_bytes,
                });
            }
            break;
        }
        match read_framed_chunk(reader, &mut framing, io_timeout, remaining_capacity).await? {
            Some(chunk) => body.extend_from_slice(&chunk),
            None => break,
        }
    }
    Ok(body)
}

async fn read_framed_chunk(
    reader: &mut BufReader<TcpStream>,
    framing: &mut BodyFraming,
    io_timeout: Duration,
    requested_max: usize,
) -> Result<Option<Vec<u8>>, LoopbackHttpError> {
    match framing {
        BodyFraming::Empty => Ok(None),
        BodyFraming::ContentLength(remaining) => {
            if *remaining == 0 {
                return Ok(None);
            }
            let to_read = (*remaining).min(requested_max);
            let bytes = read_exact_bytes(reader, io_timeout, to_read, "read body").await?;
            *remaining -= to_read;
            Ok(Some(bytes))
        }
        BodyFraming::UntilEof => {
            let mut bytes = vec![0_u8; requested_max];
            let read = timeout(io_timeout, reader.read(&mut bytes))
                .await
                .map_err(|_| LoopbackHttpError::Timeout { phase: "read body" })?
                .map_err(|source| LoopbackHttpError::Io {
                    phase: "read body",
                    source,
                })?;
            if read == 0 {
                return Ok(None);
            }
            bytes.truncate(read);
            Ok(Some(bytes))
        }
        BodyFraming::Chunked {
            remaining,
            complete,
        } => {
            if *complete {
                return Ok(None);
            }
            if *remaining == 0 {
                let size = read_chunk_size(reader, io_timeout).await?;
                if size == 0 {
                    read_chunk_trailers(reader, io_timeout).await?;
                    *complete = true;
                    return Ok(None);
                }
                *remaining = size;
            }
            let to_read = (*remaining).min(requested_max);
            let bytes = read_exact_bytes(reader, io_timeout, to_read, "read chunk").await?;
            *remaining -= to_read;
            if *remaining == 0 {
                let ending = read_exact_bytes(reader, io_timeout, 2, "read chunk ending").await?;
                if ending != b"\r\n" {
                    return Err(LoopbackHttpError::Protocol(
                        "HTTP chunk has no CRLF ending".to_owned(),
                    ));
                }
            }
            Ok(Some(bytes))
        }
    }
}

async fn read_chunk_size(
    reader: &mut BufReader<TcpStream>,
    io_timeout: Duration,
) -> Result<usize, LoopbackHttpError> {
    let line = read_capped_line(reader, io_timeout, 1024, "read chunk size").await?;
    let line = String::from_utf8(line)
        .map_err(|_| LoopbackHttpError::Protocol("invalid HTTP chunk-size line".to_owned()))?;
    require_crlf(&line, "HTTP chunk-size line")?;
    let token = line
        .trim_end_matches(['\r', '\n'])
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    usize::from_str_radix(token, 16)
        .map_err(|_| LoopbackHttpError::Protocol("invalid HTTP chunk size".to_owned()))
}

async fn read_chunk_trailers(
    reader: &mut BufReader<TcpStream>,
    io_timeout: Duration,
) -> Result<(), LoopbackHttpError> {
    let mut bytes = 0_usize;
    loop {
        let line = read_limited_line(reader, io_timeout, &mut bytes, 16 * 1024).await?;
        if line == "\r\n" {
            return Ok(());
        }
        parse_header_line(&line)?;
    }
}

async fn read_exact_bytes(
    reader: &mut BufReader<TcpStream>,
    io_timeout: Duration,
    count: usize,
    phase: &'static str,
) -> Result<Vec<u8>, LoopbackHttpError> {
    let mut bytes = vec![0_u8; count];
    timeout(io_timeout, reader.read_exact(&mut bytes))
        .await
        .map_err(|_| LoopbackHttpError::Timeout { phase })?
        .map_err(|source| LoopbackHttpError::Io { phase, source })?;
    Ok(bytes)
}

fn status_error(response: &HttpResponse) -> LoopbackHttpError {
    let preview = String::from_utf8_lossy(&response.body);
    let preview = preview
        .chars()
        .take(1024)
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    LoopbackHttpError::Status {
        status: response.status,
        body_preview: preview,
    }
}

fn sensitive_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" | "api-key"
    ) || name.contains("token")
        || name.contains("secret")
        || name.contains("password")
}

fn sanitize_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        BasicAuth, HttpRequest, HttpResponse, LoopbackHttpClient, LoopbackHttpError, ResponseHead,
        encode_request, response_framing, validate_request,
    };
    use crate::LoopbackEndpoint;
    use secrecy::SecretString;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    async fn serve_once(response: &'static [u8]) -> Result<u16, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let accepted = listener.accept().await;
            let Ok((mut stream, _)) = accepted else {
                return;
            };
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await;
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
        });
        Ok(port)
    }

    fn client(port: u16) -> Result<LoopbackHttpClient, LoopbackHttpError> {
        let endpoint = format!("http://127.0.0.1:{port}")
            .parse::<LoopbackEndpoint>()
            .map_err(|error| LoopbackHttpError::InvalidRequest(error.to_string()))?;
        let auth = BasicAuth::new("opencode", SecretString::from(["sec", "ret"].concat()))?;
        Ok(LoopbackHttpClient::new(endpoint, auth).with_limits(
            Duration::from_secs(1),
            Duration::from_secs(1),
            16 * 1024,
            16 * 1024,
        ))
    }

    #[tokio::test]
    async fn reads_content_length_json() -> Result<(), Box<dyn std::error::Error>> {
        let port = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"healthy\":true}",
        )
        .await?;
        let response = client(port)?
            .execute(&HttpRequest::get("/global/health"))
            .await?;
        assert_eq!(response.body, br#"{"healthy":true}"#);
        Ok(())
    }

    #[tokio::test]
    async fn decodes_chunked_body() -> Result<(), Box<dyn std::error::Error>> {
        let port = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        .await?;
        let response = client(port)?.execute(&HttpRequest::get("/test")).await?;
        assert_eq!(response.body, b"hello world");
        Ok(())
    }

    #[tokio::test]
    async fn streams_chunked_sse_without_buffering_to_eof() -> Result<(), Box<dyn std::error::Error>>
    {
        let port = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\nD\r\ndata: hello\n\n\r\n0\r\n\r\n",
        )
        .await?;
        let mut connection = client(port)?.open_sse(&HttpRequest::sse("/event")).await?;
        let chunk = connection.read_decoded_chunk(1024).await?;
        assert_eq!(chunk.as_deref(), Some(b"data: hello\n\n".as_slice()));
        assert!(connection.read_decoded_chunk(1024).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn consumes_informational_response_before_final_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let port = serve_once(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .await?;
        let response = client(port)?.execute(&HttpRequest::get("/test")).await?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_ambiguous_transfer_encoding_and_content_length()
    -> Result<(), Box<dyn std::error::Error>> {
        let port = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        )
        .await?;
        let error = match client(port)?.execute(&HttpRequest::get("/test")).await {
            Ok(response) => {
                return Err(
                    format!("ambiguous framing unexpectedly succeeded: {response:?}").into(),
                );
            }
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("Transfer-Encoding and Content-Length")
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_bare_lf_http_headers() -> Result<(), Box<dyn std::error::Error>> {
        let port = serve_once(b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok").await?;
        let error = match client(port)?.execute(&HttpRequest::get("/test")).await {
            Ok(response) => {
                return Err(
                    format!("bare-LF response unexpectedly succeeded: {response:?}").into(),
                );
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("must use CRLF"));
        Ok(())
    }

    #[test]
    fn rejects_request_target_controls_and_fragments() -> Result<(), Box<dyn std::error::Error>> {
        for target in ["/a b", "/a\tb", "/a\0b", "/a#fragment"] {
            match validate_request(&HttpRequest::get(target)) {
                Ok(()) => return Err(format!("invalid target was accepted: {target:?}").into()),
                Err(error) => {
                    assert!(error.to_string().contains("origin-form path"), "{target:?}");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn emits_one_bounded_last_event_id_header_and_rejects_injection()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = HttpRequest::sse("/event").with_last_event_id(Some("evt-42"))?;
        let encoded = String::from_utf8(encode_request(&request, "127.0.0.1", "Basic redacted"))?;
        assert_eq!(encoded.matches("Last-Event-ID: evt-42\r\n").count(), 1);
        assert!(
            HttpRequest::sse("/event")
                .with_last_event_id(Some("evt\r\ninjected: yes"))
                .is_err()
        );
        assert!(
            HttpRequest::get("/global/health")
                .with_last_event_id(Some("evt-42"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_conflicting_response_framing_without_network_io() {
        let head = ResponseHead {
            status: 200,
            headers: [
                ("transfer-encoding".to_owned(), "chunked".to_owned()),
                ("content-length".to_owned(), "2".to_owned()),
            ]
            .into_iter()
            .collect(),
        };
        assert!(matches!(
            response_framing(&head),
            Err(LoopbackHttpError::Protocol(message))
                if message.contains("Transfer-Encoding and Content-Length")
        ));
    }

    #[test]
    fn debug_and_status_errors_do_not_dump_payload_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = HttpRequest::post_json("/run", &json!({"token": "secret-token"}))?;
        assert!(!format!("{request:?}").contains("secret-token"));

        let response = HttpResponse {
            status: 200,
            headers: [("authorization".to_owned(), ["Basic ", "secret"].concat())]
                .into_iter()
                .collect(),
            body: b"secret-body".to_vec(),
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains(["Basic ", "secret"].concat().as_str()));
        assert!(!debug.contains("secret-body"));
        let error = super::status_error(&HttpResponse {
            status: 500,
            headers: BTreeMap::new(),
            body: b"secret-body".to_vec(),
        });
        assert!(!format!("{error:?}").contains("secret-body"));
        assert!(!error.to_string().contains("secret-body"));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_sse_read_request_is_clamped_to_response_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let port = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await?;
        let mut connection = client(port)?.open_sse(&HttpRequest::sse("/event")).await?;
        let bytes = connection.read_decoded_chunk(usize::MAX).await?;
        assert_eq!(bytes.as_deref(), Some(b"hello".as_slice()));
        Ok(())
    }

    #[tokio::test]
    async fn absolute_timeout_covers_sse_lifetime_and_redacts_timeout_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n5\r\n",
                )
                .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let endpoint = format!("http://127.0.0.1:{port}").parse::<LoopbackEndpoint>()?;
        let auth = BasicAuth::new("opencode", SecretString::from(["test-", "secret"].concat()))?;
        let client = LoopbackHttpClient::new(endpoint, auth)
            .with_limits(
                Duration::from_secs(1),
                Duration::from_secs(1),
                16 * 1024,
                16 * 1024,
            )
            .with_absolute_timeout(Duration::from_millis(300));
        let mut connection = client.open_sse(&HttpRequest::sse("/event")).await?;
        let error = match connection.read_decoded_chunk(1024).await {
            Ok(chunk) => return Err(format!("stalled SSE unexpectedly yielded {chunk:?}").into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            LoopbackHttpError::Timeout {
                phase: "read SSE body"
            }
        ));
        assert!(!format!("{error:?}").contains(["test-", "secret"].concat().as_str()));
        assert!(!error.to_string().contains("test-secret"));
        assert!(!format!("{error:?}").contains("prompt"));
        Ok(())
    }

    #[test]
    fn debug_output_redacts_password() -> Result<(), Box<dyn std::error::Error>> {
        let auth = BasicAuth::new("opencode", SecretString::from(["sec", "ret"].concat()))?;
        let debug = format!("{auth:?}");
        assert!(!debug.contains("secret"));
        assert!(debug.contains("[REDACTED]"));
        Ok(())
    }
}
