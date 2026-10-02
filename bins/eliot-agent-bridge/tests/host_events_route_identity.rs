//! Package-local wiring/negative proof for the supervised `POST /v1/host-events`
//! composition root (issue #2898, items W4, A1, A2).
//!
//! One positive case and one refusal case, both over the real
//! [`HostEventsListener`] socket this composition owns, the real
//! [`BridgeIntroductionStore`] the User Broker introduction is installed into,
//! and the real broker credential table behind [`FnCredentialResolver`]. No
//! stub introduction, no second store, no second credential source and no
//! invented identity format: the positive arm proves the listener discloses
//! exactly the installation-pinned `server_identity` of the introduction it
//! owns, and the refusal arm proves that a listener which no longer owns the
//! pinned endpoint discloses no identity proof at all.
//!
//! The admission port is the one collaborator this half does not own, so it is
//! held here as an explicit guard: an identity probe must reach no admission,
//! no gap and no effect decision, and the flag proves it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use eliot_agent_bridge::opencode_host_events::{
    BridgeIntroductionStore, FnCredentialResolver, GovernorActionGate, HostEventsStartup,
    host_events_startup,
};
use eliot_agent_opencode::{
    ActionGate, BootstrapIdentityFields, CredentialResolver, EffectDecisionRecord,
    HOST_EVENTS_CHALLENGE_HEADER, HOST_EVENTS_CHALLENGE_LENGTH, HOST_EVENTS_IDENTITY_VERSION,
    HOST_EVENTS_PATH, HostEventAdmission, HostEventAdmissionError, HostEventAdmissionFailure,
    HostEventAdmissionReceipt, HostEventGap, HostEventPorts, HostEventSubmission,
    HostEventsListener, HostEventsShutdown, IntroductionStore, REASON_ROUTE_UNAVAILABLE,
    verify_bootstrap_identity_proof,
};
use eliot_contracts::{EpochId, EpochLineageId};
use eliot_integration_coverage::GovernanceProfile;
use eliot_process::{Generation, SecretRef};
use eliot_user_broker_core::{
    MAX_OPENCODE_ROUTE_CREDENTIAL_BYTES, OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE,
    OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT, OpenCodeBridgeIntroduction,
    OpenCodeIntroductionParams, OpenCodeProcessBinding, OpenCodeRouteCredentials,
    OpenCodeSecretBoundary, OpenCodeSessionFacts,
};
use secrecy::SecretString;

/// Installation-pinned server identity of the introduced bridge incarnation.
/// It is the proof key and never appears on the wire before the proof.
const PINNED_SERVER_IDENTITY: &str = concat!(
    "0f0e0d0c0b0a0908",
    "1726354b3a291807",
    "0f0e0d0c0b0a0908",
    "1726354b3a291807"
);

/// A second installation-pinned identity of the same shape. A process that
/// merely holds the pinned loopback port knows neither value, so a proof built
/// under one must not verify under the other.
const FOREIGN_SERVER_IDENTITY: &str = concat!(
    "1111111111111111",
    "2222222222222222",
    "3333333333333333",
    "4444444444444444"
);

/// Broker-observed digest of the exact approved `OpenCode` executable.
const EXECUTABLE_DIGEST: &str = concat!(
    "abababababababab",
    "cdcdcdcdcdcdcdcd",
    "abababababababab",
    "cdcdcdcdcdcdcdcd"
);

const INSTALLATION_ID: &str = "installation-under-test";
const WINDOWS_SID: &str = "S-1-5-21-1004336348";
const INTERACTIVE_SESSION_ID: &str = "3";
const BROKER_GENERATION: u64 = 7;
const BRIDGE_GENERATION: u64 = 11;
const LAUNCH_NONCE: &str = "launch-nonce-11";
const CREDENTIAL: &str = "owner-minted-route-credential-generation-11";
/// Fixed far-future window: the composition clock is the real clock, and this
/// proof is about identity ownership, never about expiry.
const ISSUED_AT: u64 = 1;
const EXPIRES_AT: u64 = 4_000_000_000_000;
const CREDENTIAL_EXPIRES_AT: u64 = 3_000_000_000_000;

fn epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("00000000-0000-4000-8000-000000000001")
            .expect("canonical lineage identity"),
        NonZeroU64::new(1).expect("non-zero epoch sequence"),
    )
    .expect("typed epoch identity")
}

/// The one lawful producer: the User Broker's own mint over broker-observed
/// owner state. This proof never hand-builds an introduction.
fn minted_introduction(
    port: u16,
    server_identity: &str,
    revocation_id: &str,
) -> OpenCodeBridgeIntroduction {
    OpenCodeBridgeIntroduction::mint(OpenCodeIntroductionParams {
        installation_id: INSTALLATION_ID.to_owned(),
        windows_sid: WINDOWS_SID.to_owned(),
        interactive_session_id: INTERACTIVE_SESSION_ID.to_owned(),
        broker_generation: Generation::new(BROKER_GENERATION).expect("typed broker generation"),
        bridge_generation: Generation::new(BRIDGE_GENERATION).expect("typed bridge generation"),
        endpoint: format!("http://127.0.0.1:{port}"),
        server_identity: server_identity.to_owned(),
        // The exclusively pre-bound listener path with bind-conflict refusal.
        bootstrap_channel: None,
        credential: SecretRef::new("opencode-route", revocation_id)
            .expect("typed opaque credential handle"),
        credential_expires_at: CREDENTIAL_EXPIRES_AT,
        allowed_capabilities: vec![
            OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT.to_owned(),
            OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE.to_owned(),
        ],
        authority_epoch: epoch(),
        fence_id: format!("fence-{BRIDGE_GENERATION}"),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        revocation_id: revocation_id.to_owned(),
        process_binding: OpenCodeProcessBinding {
            executable_digest: EXECUTABLE_DIGEST.to_owned(),
            launch_nonce: LAUNCH_NONCE.to_owned(),
            parent_broker_process_id: "4242".to_owned(),
        },
    })
    .expect("the broker mints this introduction")
}

fn session_facts() -> OpenCodeSessionFacts {
    OpenCodeSessionFacts {
        installation_id: INSTALLATION_ID.to_owned(),
        windows_sid: WINDOWS_SID.to_owned(),
        interactive_session_id: INTERACTIVE_SESSION_ID.to_owned(),
        broker_generation: Generation::new(BROKER_GENERATION).expect("typed broker generation"),
        bridge_generation: Generation::new(BRIDGE_GENERATION).expect("typed bridge generation"),
        launch_nonce: LAUNCH_NONCE.to_owned(),
        executable_digest: EXECUTABLE_DIGEST.to_owned(),
    }
}

/// The physical owner's live credential table: the bytes are minted once per
/// generation against the introduction's own opaque handle, and the handle this
/// table resolves is the one the introduction already binds.
fn route_credentials(introduction: &OpenCodeBridgeIntroduction) -> OpenCodeRouteCredentials {
    assert!(
        CREDENTIAL.len() <= MAX_OPENCODE_ROUTE_CREDENTIAL_BYTES,
        "the owner mints the credential inside the owner's own bound"
    );
    let mut table = OpenCodeRouteCredentials::new();
    let issued = table
        .issue(
            introduction.credential.provider(),
            introduction.credential.key(),
            CREDENTIAL.to_owned().into_boxed_str(),
        )
        .expect("the owner issues the introduction's own handle");
    assert_eq!(
        issued, introduction.credential,
        "the resolved handle must be the introduction's own handle"
    );
    table
}

/// Resolver closure over the owner's live table, wired exactly as the shipped
/// front door wires it.
fn owner_resolver(
    table: OpenCodeRouteCredentials,
) -> impl Fn(&SecretRef) -> Option<SecretString> + Send {
    move |handle: &SecretRef| {
        table
            .resolve_secret(handle)
            .ok()
            .map(|secret| SecretString::from(secret.into_string()))
    }
}

/// The admission collaborator this half does not own, reduced to the one fact
/// it carries here: whether the identity probe reached it. It must not.
struct ProbeReachesNoAdmission {
    entered: Arc<AtomicBool>,
}

impl HostEventAdmission for ProbeReachesNoAdmission {
    fn admit(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        _submission: &HostEventSubmission,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError> {
        self.entered.store(true, Ordering::SeqCst);
        Err(HostEventAdmissionError::of(
            HostEventAdmissionFailure::Unavailable,
        ))
    }

    fn commit_decision(
        &mut self,
        _record: &EffectDecisionRecord,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError> {
        self.entered.store(true, Ordering::SeqCst);
        Err(HostEventAdmissionError::of(
            HostEventAdmissionFailure::Unavailable,
        ))
    }

    fn report_gap(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        _gap: &HostEventGap,
    ) -> Result<(), HostEventAdmissionError> {
        self.entered.store(true, Ordering::SeqCst);
        Err(HostEventAdmissionError::of(
            HostEventAdmissionFailure::Unavailable,
        ))
    }
}

type ProbePorts<F> = HostEventPorts<
    ProbeReachesNoAdmission,
    GovernorActionGate<GovernanceProfile>,
    BridgeIntroductionStore,
    FnCredentialResolver<F>,
>;

/// Builds the ingress composition over the real store, the real Governor
/// `ActionGate` adapter and the real broker credential boundary — the same four
/// ports [`assemble_ports`](eliot_agent_bridge::opencode_host_events::assemble_ports)
/// assembles for the shipped front door. No Governor profile is derived here,
/// so the gate refuses closed; an identity probe must never reach it anyway.
fn probe_ports<F>(resolve: F) -> ProbePorts<F>
where
    F: Fn(&SecretRef) -> Option<SecretString> + Send,
{
    HostEventPorts {
        admission: ProbeReachesNoAdmission {
            entered: Arc::new(AtomicBool::new(false)),
        },
        gate: GovernorActionGate::new(None),
        introductions: BridgeIntroductionStore::new(),
        credentials: FnCredentialResolver::new(resolve),
    }
}

/// One owner-created, exclusively pre-bound loopback socket: the mechanism step
/// 4 names as the alternative to pipe bootstrap. The socket is created and
/// bound by this composition, before any route exists.
fn owner_socket() -> (TcpListener, u16) {
    let socket = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("the composition creates its own loopback socket");
    let port = socket.local_addr().expect("socket address").port();
    assert_ne!(port, 0, "the owner reserves an explicit non-zero port");
    (socket, port)
}

/// A port this proof never binds, used to name another bridge incarnation.
fn other_port(port: u16) -> u16 {
    if port == u16::MAX { port - 1 } else { port + 1 }
}

struct ServingRoute {
    stop: tokio::sync::watch::Sender<bool>,
    generation: tokio::sync::watch::Sender<u64>,
    entered: Arc<AtomicBool>,
    outcome: mpsc::Receiver<HostEventsShutdown>,
}

/// Adopts the pre-bound socket and serves the composition on the shape the
/// shipped front door uses: one single-threaded runtime, one sequential serving
/// loop, both supervisor senders held for the whole serving life.
fn serve_route<F>(socket: TcpListener, ports: ProbePorts<F>, bound_generation: u64) -> ServingRoute
where
    // 'static is the bound the shipped front door already carries on this
    // resolver: the serving loop moves the ports onto its own thread, so the
    // resolver must outlive no borrowed data. Adding it here matches the
    // production signature instead of inventing a shorter-lived variant.
    F: Fn(&SecretRef) -> Option<SecretString> + Send + 'static,
{
    let (stop, stop_receiver) = tokio::sync::watch::channel(false);
    let (generation, generation_receiver) = tokio::sync::watch::channel(bound_generation);
    let entered = Arc::clone(&ports.admission.entered);
    let (outcome_tx, outcome) = mpsc::channel();
    thread::spawn(move || {
        let mut ports = ports;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the serving runtime is constructed");
        let listener = {
            let _serving = runtime.enter();
            HostEventsListener::from_pre_bound(socket).expect("adopt the pre-bound socket")
        };
        let shutdown = runtime.block_on(listener.serve_until(
            &mut ports,
            bound_generation,
            stop_receiver,
            generation_receiver,
        ));
        outcome_tx
            .send(shutdown)
            .expect("the proof receives the typed shutdown");
    });
    ServingRoute {
        stop,
        generation,
        entered,
        outcome,
    }
}

/// The closed first-contact identity probe: a fresh client challenge and
/// nothing else. No credential, no idempotency identity, no body.
fn identity_probe(port: u16, challenge: &str) -> (u16, serde_json::Value) {
    let request = format!(
        "POST {HOST_EVENTS_PATH} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 0\r\n\
         {HOST_EVENTS_CHALLENGE_HEADER}: {challenge}\r\n\
         \r\n"
    );
    let mut stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .expect("the composition owns this loopback port");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("bounded read timeout");
    stream
        .write_all(request.as_bytes())
        .expect("the probe sends no credential");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("the connection is closed by the listener");
    let text = String::from_utf8(raw).expect("a UTF-8 response");
    let (head, body) = text.split_once("\r\n\r\n").expect("a framed response");
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .expect("a status line")
        .parse()
        .expect("a numeric status");
    (
        status,
        serde_json::from_str(body).expect("a closed JSON body"),
    )
}

fn fresh_challenge(seed: char) -> String {
    std::iter::repeat(seed)
        .take(HOST_EVENTS_CHALLENGE_LENGTH)
        .collect()
}

fn field<'a>(body: &'a serde_json::Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the answer carries {key}"))
}

/// Positive case: the introduction this composition owns is the only identity
/// the listener proves, and the proof is computed from that introduction's own
/// `server_identity`.
#[test]
fn a_correct_introduction_is_served_under_its_pinned_identity() {
    let (socket, port) = owner_socket();
    let introduction =
        minted_introduction(port, PINNED_SERVER_IDENTITY, "revocation-generation-11");
    let mut ports = probe_ports(owner_resolver(route_credentials(&introduction)));
    ports.introductions.install(introduction.clone());
    ports.introductions.observe_session(session_facts());
    assert_eq!(
        host_events_startup(&ports.introductions).expect("an introduced store resolves"),
        HostEventsStartup::Introduced {
            port,
            bound_generation: BRIDGE_GENERATION,
        },
        "the composition binds the exact endpoint the introduction pins"
    );

    let route = serve_route(socket, ports, BRIDGE_GENERATION);
    let challenge = fresh_challenge('a');
    let (status, body) = identity_probe(port, &challenge);

    assert_eq!(status, 200, "a correct introduction is served");
    assert_eq!(
        field(&body, "identity_version"),
        HOST_EVENTS_IDENTITY_VERSION
    );
    assert_eq!(field(&body, "challenge"), challenge);
    assert_eq!(field(&body, "server_identity"), PINNED_SERVER_IDENTITY);
    assert_eq!(field(&body, "installation_id"), INSTALLATION_ID);
    assert_eq!(field(&body, "endpoint"), introduction.endpoint);
    assert_eq!(
        field(&body, "introduction_digest"),
        introduction.introduction_digest
    );

    let proof = field(&body, "identity_proof").to_owned();
    let fields = BootstrapIdentityFields {
        challenge,
        installation_id: INSTALLATION_ID.to_owned(),
        endpoint: introduction.endpoint.clone(),
        server_identity: PINNED_SERVER_IDENTITY.to_owned(),
        introduction_digest: introduction.introduction_digest.clone(),
        bridge_generation: BRIDGE_GENERATION,
    };
    assert!(
        verify_bootstrap_identity_proof(&fields, PINNED_SERVER_IDENTITY, &proof),
        "the client verifies the proof with the pinned identity it already holds"
    );
    assert!(
        !verify_bootstrap_identity_proof(&fields, FOREIGN_SERVER_IDENTITY, &proof),
        "a process that merely bound the pinned port holds no pinned identity, \
         so no proof of this listener can be replayed under another installation"
    );

    route.stop.send(true).expect("signal the supervised stop");
    assert_eq!(
        route.outcome.recv().expect("typed shutdown"),
        HostEventsShutdown::Stopped
    );
    assert!(
        !route.entered.load(Ordering::SeqCst),
        "an identity probe resolves no credential, admits no event and consults no gate"
    );
    // The generation sender stays held for the whole serving life: a closed
    // generation channel is a rotation, never a silent stop.
    assert_eq!(*route.generation.borrow(), BRIDGE_GENERATION);
}

/// Refusal case: a listener whose current introduction names another bridge
/// incarnation discloses nothing. Rotation has already retired the replaced
/// introduction, so the old generation cannot answer either.
#[test]
fn a_rotated_introduction_is_refused_and_discloses_no_identity() {
    let (socket, port) = owner_socket();
    let retired = minted_introduction(port, PINNED_SERVER_IDENTITY, "revocation-generation-11");
    let rotated = minted_introduction(
        other_port(port),
        PINNED_SERVER_IDENTITY,
        "revocation-generation-12",
    );
    let mut ports = probe_ports(owner_resolver(route_credentials(&rotated)));
    ports.introductions.install(retired.clone());
    ports.introductions.observe_session(session_facts());
    ports.introductions.install(rotated.clone());
    assert!(
        ports.introductions.is_revoked(&retired.revocation_id),
        "rotation retires the replaced introduction before another request"
    );
    assert!(!ports.introductions.is_revoked(&rotated.revocation_id));
    assert_eq!(
        host_events_startup(&ports.introductions).expect("an introduced store resolves"),
        HostEventsStartup::Introduced {
            port: other_port(port),
            bound_generation: BRIDGE_GENERATION,
        },
        "the rotated introduction names the new incarnation's endpoint"
    );

    let route = serve_route(socket, ports, BRIDGE_GENERATION);
    let (status, body) = identity_probe(port, &fresh_challenge('b'));

    assert_eq!(
        status, 404,
        "a listener that no longer owns the pinned endpoint refuses"
    );
    assert_eq!(field(&body, "reason_code"), REASON_ROUTE_UNAVAILABLE);
    assert!(
        body.get("identity_proof").is_none() && body.get("server_identity").is_none(),
        "a refused probe discloses neither a proof nor the pinned identity"
    );

    route.stop.send(true).expect("signal the supervised stop");
    assert_eq!(
        route.outcome.recv().expect("typed shutdown"),
        HostEventsShutdown::Stopped
    );
    assert!(
        !route.entered.load(Ordering::SeqCst),
        "a refused probe still admits nothing"
    );
}

/// Refusal case at the composition boundary: with no current introduction the
/// route resolves `Unintroduced`, which is what makes `serve_host_events`
/// return `HostEventsServiceError::Unintroduced` without opening a socket. A
/// cleared store — logout, listener death or bridge restart — closes it the
/// same way.
#[test]
fn a_composition_without_a_current_introduction_binds_nothing() {
    let mut store = BridgeIntroductionStore::new();
    assert_eq!(
        host_events_startup(&store).expect("no introduction is not an error"),
        HostEventsStartup::Unintroduced,
        "an unintroduced composition never binds a port"
    );

    let introduction = minted_introduction(1, PINNED_SERVER_IDENTITY, "revocation-generation-11");
    store.install(introduction.clone());
    store.observe_session(session_facts());
    assert_eq!(
        host_events_startup(&store).expect("an introduced store resolves"),
        HostEventsStartup::Introduced {
            port: 1,
            bound_generation: BRIDGE_GENERATION,
        },
        "the composition binds the exact endpoint the introduction pins"
    );

    store.clear();
    assert_eq!(
        host_events_startup(&store).expect("a cleared store is not an error"),
        HostEventsStartup::Unintroduced,
        "logout, listener death and bridge restart close the route again"
    );
    assert!(
        !store.is_revoked(&introduction.revocation_id),
        "clearing is not revocation: the introduction is retired, not blacklisted"
    );
    assert!(
        store.current_introduction().is_none(),
        "no introduction survives the clear"
    );
}
