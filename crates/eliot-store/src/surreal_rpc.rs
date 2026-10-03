use crate::StoreError;
use eliot_types::SurrealServerConfig;
use futures_util::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Uri};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use uuid::Uuid;

type RpcSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
pub struct SurrealRpcTransport {
    socket: Mutex<RpcSocket>,
    request_timeout: Duration,
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    id: String,
    method: &'a str,
    params: Value,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    id: Option<Value>,
    result: Option<Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl SurrealRpcTransport {
    pub async fn connect(
        config: &SurrealServerConfig,
        connect_timeout_ms: u64,
    ) -> Result<Self, StoreError> {
        // #3980: the shared predicate owns the whole local-only grammar and runs
        // before any destination is constructed or contacted, so constructing the
        // public `SurrealServerConfig` directly cannot bypass the high-level
        // loader. The grammar's parse stays with its owner; only the port it
        // already validated is carried forward.
        config.validate_local_rpc_endpoint()?;
        let expected_port = config.local_rpc_port();

        let connect_timeout = millis(connect_timeout_ms);
        let mut request = config
            .endpoint
            .as_str()
            .into_client_request()
            .map_err(|error| StoreError::WebSocket(error.to_string()))?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("json"));
        if !agrees_with_validated_local_endpoint(request.uri(), expected_port) {
            return Err(StoreError::PolicyViolation(
                "surreal rpc transport destination must be exactly \
                 ws://127.0.0.1:<port>/rpc and must agree with the validated \
                 endpoint; the refused destination is never reported because it \
                 can carry secret material"
                    .to_owned(),
            ));
        }
        let connect = connect_async(request);
        let (socket, _response) = timeout(connect_timeout, connect)
            .await
            .map_err(|_| StoreError::Timeout {
                op: "surreal rpc connect".to_owned(),
                ms: connect_timeout_ms,
            })?
            .map_err(|error| StoreError::WebSocket(error.to_string()))?;

        Ok(Self {
            socket: Mutex::new(socket),
            request_timeout: millis(config.query_timeout_ms),
        })
    }

    pub async fn signin(&self, user: &str, password: &SecretString) -> Result<(), StoreError> {
        self.request(
            "signin",
            json!([{
                "user": user,
                "pass": password.expose_secret(),
            }]),
        )
        .await
        .map(|_| ())
        .map_err(|error| match error {
            StoreError::RpcError { .. } => StoreError::ServerAuthFailed(error.to_string()),
            other => other,
        })
    }

    pub async fn use_ns_db(&self, ns: &str, db: &str) -> Result<(), StoreError> {
        self.request("use", json!([ns, db])).await.map(|_| ())
    }

    pub async fn version(&self) -> Result<Value, StoreError> {
        self.request("version", Value::Array(Vec::new())).await
    }

    pub async fn query(&self, sql: &str, vars: Value) -> Result<Value, StoreError> {
        let bound_vars = if vars.is_null() {
            Value::Object(serde_json::Map::new())
        } else {
            vars
        };
        self.request("query", json!([sql, bound_vars])).await
    }

    pub async fn close(&self) -> Result<(), StoreError> {
        timeout(self.request_timeout, async {
            self.socket
                .lock()
                .await
                .send(Message::Close(None))
                .await
                .map_err(|error| StoreError::WebSocket(error.to_string()))
        })
        .await
        .map_err(|_| StoreError::Timeout {
            op: "surreal rpc close".to_owned(),
            ms: millis_u64(self.request_timeout),
        })?
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, StoreError> {
        let id = Uuid::new_v4().to_string();
        let expected_id = Value::String(id.clone());
        let payload = serde_json::to_string(&RpcRequest { id, method, params })
            .map_err(|error| StoreError::Decode(error.to_string()))?;

        timeout(self.request_timeout, async {
            let mut socket = self.socket.lock().await;
            socket
                .send(Message::text(payload))
                .await
                .map_err(|error| StoreError::WebSocket(error.to_string()))?;

            loop {
                let message = socket.next().await.ok_or(StoreError::ConnectionClosed)?;
                let message = message.map_err(|error| StoreError::WebSocket(error.to_string()))?;

                match message {
                    Message::Text(text) => {
                        let response = parse_response(text.as_str())?;
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(response);
                        }
                    }
                    Message::Binary(bytes) => {
                        let text = String::from_utf8(bytes.to_vec())
                            .map_err(|error| StoreError::Decode(error.to_string()))?;
                        let response = parse_response(&text)?;
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(response);
                        }
                    }
                    Message::Ping(payload) => socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|error| StoreError::WebSocket(error.to_string()))?,
                    Message::Pong(_) | Message::Frame(_) => {}
                    Message::Close(_) => return Err(StoreError::ConnectionClosed),
                }
            }
        })
        .await
        .map_err(|_| StoreError::Timeout {
            op: format!("surreal rpc {method}"),
            ms: millis_u64(self.request_timeout),
        })?
    }
}

/// #3980 stage 2: the observed destination must agree with the address stage 1
/// admitted. The scheme and the port are read from this parsed request URI and
/// compared against the validated endpoint -- `expected_port` is exactly the
/// port `validate_local_rpc_endpoint` already accepted, and `127.0.0.1` is the
/// single literal address the shared grammar admits, not a value read out of the
/// configuration here. `expected_port` stays an `Option` so a request URI
/// carrying no port is refused too, rather than vacuously satisfying the port
/// half of the comparison.
///
/// Defence in depth, not a second validator: with stage 1 in place this
/// disagreement is not reachable through `connect`, because stage 1 admits only
/// `ws://127.0.0.1:<digits>/rpc` and `http::Uri` then yields exactly that
/// scheme, host and port. The comparison stays because the checked address and
/// the transport's parsed destination must agree; it fails closed if a future
/// parser, case-folding rule or `http::Uri` behaviour ever makes the two layers
/// disagree.
///
/// The scheme is compared case-insensitively because `http::Uri` keeps a
/// non-standard scheme exactly as written (`ws` is not one of its two standard
/// protocols), while the predicate deliberately still admits the case variants
/// of `ws://` that the previous loader check admitted. An exact `== "ws"`
/// comparison here would refuse a configuration the types layer calls valid.
/// This matches the two layers; it does not broaden the grammar, which only
/// ever yields `ws`.
fn agrees_with_validated_local_endpoint(uri: &Uri, expected_port: Option<u16>) -> bool {
    uri.scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("ws"))
        && uri.host() == Some("127.0.0.1")
        && expected_port == uri.port_u16()
}

fn parse_response(text: &str) -> Result<RpcResponse, StoreError> {
    serde_json::from_str(text).map_err(|error| StoreError::Decode(error.to_string()))
}

fn rpc_result(response: RpcResponse) -> Result<Value, StoreError> {
    if let Some(error) = response.error {
        return Err(StoreError::RpcError {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }

    Ok(response.result.unwrap_or(Value::Null))
}

const fn millis(ms: u64) -> Duration {
    Duration::from_millis(if ms == 0 { 1 } else { ms })
}

fn millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod local_endpoint_admission_tests {
    use super::{SurrealRpcTransport, agrees_with_validated_local_endpoint};
    use crate::StoreError;
    use eliot_types::{CredentialProviderKind, SurrealCapabilities, SurrealServerConfig};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    /// The documented literal local form, the base every case varies.
    const BIND: &str = "127.0.0.1:18000";
    const ENDPOINT: &str = "ws://127.0.0.1:18000/rpc";

    /// #3980: the issue's own counterexample.
    const COUNTEREXAMPLE_ENDPOINT: &str = "ws://127.0.0.1:18000@192.0.2.1:18000/rpc";

    /// One private fixture builder shared by every case in this module. The
    /// uninteresting fields mirror the lifecycle fixture in `surreal_server`;
    /// only `bind` and `endpoint` vary. The library type has no `Default` impl
    /// and gained no constructor here.
    fn local_config(bind: &str, endpoint: &str) -> SurrealServerConfig {
        SurrealServerConfig {
            exe: "surreal".to_owned(),
            bind: bind.to_owned(),
            endpoint: endpoint.to_owned(),
            storage: "rocksdb:unused".to_owned(),
            ns: "eliot".to_owned(),
            db: "eliot".to_owned(),
            user: "root".to_owned(),
            credential_provider: CredentialProviderKind::WindowsCredentialManager,
            credential_id: "surreal-runtime/rpc-admission-test".to_owned(),
            password_file: "%LOCALAPPDATA%/Eliot/secrets/rpc-admission-test-unused.txt".to_owned(),
            log_level: "warn".to_owned(),
            query_timeout_ms: 2_000,
            transaction_timeout_ms: 2_000,
            startup_timeout_ms: 2_000,
            restart_backoff_ms: 50,
            max_restart_backoff_ms: 200,
            capabilities: SurrealCapabilities {
                deny_all: true,
                allow_funcs: Vec::new(),
                allow_net: Vec::new(),
                allow_scripting: false,
                allow_guests: false,
            },
        }
    }

    /// Address material a refused input could contain and that must never reach
    /// a diagnostic.
    const FORBIDDEN_FRAGMENTS: [&str; 5] =
        ["192.0.2.1", "user:pass", "localhost", "userinfo", "@192"];

    fn assert_diagnostic_withholds(error: &StoreError, case: &str) {
        let text = error.to_string();
        for fragment in FORBIDDEN_FRAGMENTS {
            assert!(
                !text.contains(fragment),
                "{case} diagnostic leaked rejected input {fragment}: {text}"
            );
        }
    }

    /// The stage-1 refusal of one configuration, already converted to the store
    /// layer's error type, with the no-rejected-value proof attached.
    fn stage_one_refusal(
        config: &SurrealServerConfig,
        case: &str,
    ) -> Result<StoreError, Box<dyn std::error::Error>> {
        let Err(error) = config.validate_local_rpc_endpoint() else {
            return Err(std::io::Error::other(format!("{case} must be refused by stage 1")).into());
        };
        let error: StoreError = error.into();
        assert_diagnostic_withholds(&error, case);
        Ok(error)
    }

    /// #3980: the documented literal local form is admitted by stage 1, and the
    /// port it exposes is the one the transport compares its parsed destination
    /// against. Asserted against the predicate directly, so no live listener and
    /// no socket work are involved.
    #[test]
    fn documented_literal_local_form_is_admitted_with_its_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = local_config(BIND, ENDPOINT);
        config.validate_local_rpc_endpoint()?;
        assert_eq!(config.local_rpc_port(), Some(18000));
        Ok(())
    }

    /// #3980: the issue's counterexample is refused, and the diagnostic states
    /// the accepted grammar without disclosing the rejected address, its
    /// userinfo, or the external host it names.
    #[test]
    fn userinfo_endpoint_counterexample_is_refused_without_disclosure()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = local_config(BIND, COUNTEREXAMPLE_ENDPOINT);
        let error = stage_one_refusal(&config, "userinfo endpoint counterexample")?;
        assert!(
            matches!(error, StoreError::Config(_)),
            "a stage-1 refusal must stay the typed configuration variant"
        );
        assert_eq!(config.local_rpc_port(), None);
        Ok(())
    }

    /// #3980: every other refused class the issue names, each carrying its own
    /// no-rejected-value proof.
    #[test]
    fn refused_endpoint_classes_never_echo_the_rejected_value()
    -> Result<(), Box<dyn std::error::Error>> {
        for endpoint in [
            "ws://user:pass@127.0.0.1:18000/rpc",
            "ws://192.0.2.1:18000/rpc",
            "ws://localhost:18000/rpc",
            "ws://127.0.0.1:18000/rpc/extra",
            "ws://127.0.0.1:18000/rpc?a=1",
            "ws://127.0.0.1:18000/rpc#f",
            "wss://127.0.0.1:18000/rpc",
            "ws://127.0.0.1:/rpc",
        ] {
            let config = local_config(BIND, endpoint);
            let error = stage_one_refusal(&config, endpoint)?;
            assert!(
                matches!(error, StoreError::Config(_)),
                "{endpoint} must surface the typed configuration variant"
            );
            assert_eq!(
                config.local_rpc_port(),
                None,
                "{endpoint} must name no port"
            );
        }
        Ok(())
    }

    /// #3980: the predicate covers `bind` as well as `endpoint`, so a valid
    /// endpoint cannot carry a foreign or userinfo-bearing bind past stage 1.
    #[test]
    fn refused_bind_variants_are_refused_despite_a_valid_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        for bind in ["127.0.0.1:18000@192.0.2.1", "192.0.2.1:18000"] {
            let error = stage_one_refusal(&local_config(bind, ENDPOINT), bind)?;
            assert!(
                matches!(error, StoreError::Config(_)),
                "{bind} must surface the typed configuration variant"
            );
        }
        Ok(())
    }

    /// #3980: the predicate deliberately still admits the case variants of
    /// `ws://` that the previous loader check admitted. `http::Uri` keeps a
    /// non-standard scheme exactly as written, so the transport's own agreement
    /// check must not refuse what the types layer calls valid -- otherwise a
    /// configuration that used to load and connect would stop working.
    ///
    /// The comparison is asserted through the production function itself, so
    /// deleting or narrowing `agrees_with_validated_local_endpoint` fails here.
    #[test]
    fn the_transport_agreement_check_admits_the_declared_case_compatibility()
    -> Result<(), Box<dyn std::error::Error>> {
        for endpoint in ["WS://127.0.0.1:18000/RPC", "Ws://127.0.0.1:18000/rpc"] {
            let config = local_config(BIND, endpoint);
            config.validate_local_rpc_endpoint()?;
            let expected_port = config.local_rpc_port();

            let request = endpoint.into_client_request()?;
            assert!(
                agrees_with_validated_local_endpoint(request.uri(), expected_port),
                "{endpoint} must keep its scheme comparable with the accepted grammar, \
                 and the transport must admit the destination it parses from it"
            );
            assert_eq!(request.uri().host(), Some("127.0.0.1"));
            assert_eq!(expected_port, request.uri().port_u16());
        }
        Ok(())
    }

    /// #3980: the other direction of the same stage-2 path. A destination that
    /// disagrees with what stage 1 admitted is refused: a foreign host, a port
    /// other than the validated one, and a request URI that carries no port at
    /// all, which must be refused rather than vacuously satisfying the port half
    /// of the comparison. `expected_port` is the port the predicate itself
    /// exposes, not a hardcoded list. No socket work is involved.
    #[test]
    fn the_transport_agreement_check_refuses_a_disagreeing_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = local_config(BIND, ENDPOINT);
        config.validate_local_rpc_endpoint()?;
        let expected_port = config.local_rpc_port();
        assert_eq!(expected_port, Some(18000));

        for uri in [
            "ws://192.0.2.1:18000/rpc",
            "ws://127.0.0.1:18001/rpc",
            "ws://127.0.0.1/rpc",
        ] {
            let request = uri.into_client_request()?;
            assert!(
                !agrees_with_validated_local_endpoint(request.uri(), expected_port),
                "{uri} must be refused: it disagrees with the endpoint stage 1 admitted"
            );
        }
        Ok(())
    }

    /// #3980: `connect` calls the shared predicate as its first statement, so
    /// directly constructing the public configuration cannot bypass the
    /// high-level loader. No listener is needed because the refusal precedes any
    /// destination construction or contact.
    #[tokio::test]
    async fn connect_refuses_a_bypassing_configuration_before_any_socket_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = local_config(BIND, COUNTEREXAMPLE_ENDPOINT);
        let Err(error) = SurrealRpcTransport::connect(&config, 250).await else {
            return Err(
                std::io::Error::other("connect must refuse a bypassing configuration").into(),
            );
        };
        assert!(
            matches!(error, StoreError::Config(_)),
            "connect must surface the typed stage-1 refusal, not a transport failure"
        );
        assert_diagnostic_withholds(&error, "connect stage-1 refusal");
        Ok(())
    }
}
