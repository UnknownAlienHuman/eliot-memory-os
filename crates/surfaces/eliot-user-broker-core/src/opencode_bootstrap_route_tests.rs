//! Peer-authenticated one-shot `OpenCode` bootstrap redemption proof
//! (issue #2898, step 4 / acceptance A2).
//!
//! One positive case: the exact approved peer, in the exact bound SID and logon
//! session, running the exact image bytes this broker observed at launch, under
//! the broker generation that launched it, obtains the endpoint and the one-use
//! credential through [`OpenCodeBootstrapRoute::redeem_peer`].
//!
//! One refusal case: a foreign process image, a wrong SID, and a replayed
//! one-shot credential are each refused with the *existing* typed
//! [`BrokerError`] variants — [`BrokerError::ProcessBindingMismatch`],
//! [`BrokerError::StaleRegistrationIdentity`] and [`BrokerError::ReplayConflict`]
//! — and a wrong broker generation is refused the same way. Each refusal is
//! proven to happen *before* the secret boundary, by showing that the
//! introducing broker generation still holds its route (a refused foreign peer
//! never spends the one authenticator).

use std::num::NonZeroU64;

use super::{
    BrokerError, EpochId, EpochLineageId, Generation, MAX_OPENCODE_ROUTE_CREDENTIAL_BYTES,
    OPENCODE_BOOTSTRAP_PIPE_NAME, OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE,
    OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT, OpenCodeApprovedProcess, OpenCodeBootstrapPeer,
    OpenCodeBootstrapRoute, OpenCodeBridgeIntroduction, OpenCodeBrokerProcessBinding,
    OpenCodeIntroductionParams, OpenCodeProcessBinding, SecretRef,
};

const INSTALLATION_ID: &str = "installation-2898-bootstrap";
const WINDOWS_SID: &str = "S-1-5-21-100-200-300-1001";
const INTERACTIVE_SESSION_ID: &str = "7";
const BROKER_GENERATION: u64 = 11;
const BRIDGE_GENERATION: u64 = 12;
const REVOCATION_ID: &str = "opencode-bridge-revocation-1";
const EXECUTABLE_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FOREIGN_IMAGE_DIGEST: &str =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const LAUNCH_NONCE: &str = "opencode-launch-nonce-1";
const CREDENTIAL: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ISSUED_AT: u64 = 1_786_000_000_000;
const CREDENTIAL_EXPIRES_AT: u64 = 1_786_000_900_000;
const EXPIRES_AT: u64 = 1_786_000_950_000;
const REDEEMED_AT: u64 = 1_786_000_060_000;
const BROKER_PROCESS_ID: u32 = 4_242;
const BROKER_PROCESS_START_100NS: u64 = 133_000_000_000_000;
const OPENCODE_PROCESS_ID: u32 = 9_001;
const OPENCODE_PROCESS_START_100NS: u64 = 134_000_000_000_000;
const OPENCODE_IMAGE_PATH: &str = r"C:\Eliot\opencode\opencode.exe";

fn epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("00000000-0000-4000-8000-000000000289").expect("canonical lineage id"),
        NonZeroU64::new(1).expect("non-zero epoch sequence"),
    )
    .expect("typed epoch identity")
}

fn generation(value: u64) -> Generation {
    Generation::new(value).expect("non-zero typed generation")
}

/// The one lawful producer: the User Broker's own mint over broker-observed
/// owner state, on the protected named-pipe bootstrap channel.
fn minted_introduction() -> OpenCodeBridgeIntroduction {
    OpenCodeBridgeIntroduction::mint(OpenCodeIntroductionParams {
        installation_id: INSTALLATION_ID.to_owned(),
        windows_sid: WINDOWS_SID.to_owned(),
        interactive_session_id: INTERACTIVE_SESSION_ID.to_owned(),
        broker_generation: generation(BROKER_GENERATION),
        bridge_generation: generation(BRIDGE_GENERATION),
        endpoint: "http://127.0.0.1:39411".to_owned(),
        server_identity: EXECUTABLE_DIGEST.to_owned(),
        bootstrap_channel: Some(OPENCODE_BOOTSTRAP_PIPE_NAME.to_owned()),
        credential: SecretRef::new("opencode-route", REVOCATION_ID)
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
        revocation_id: REVOCATION_ID.to_owned(),
        process_binding: OpenCodeProcessBinding {
            executable_digest: EXECUTABLE_DIGEST.to_owned(),
            launch_nonce: LAUNCH_NONCE.to_owned(),
            parent_broker_process_id: BROKER_PROCESS_ID.to_string(),
        },
    })
    .expect("the broker mints this introduction")
}

fn approved_process() -> OpenCodeApprovedProcess {
    OpenCodeApprovedProcess {
        process_id: OPENCODE_PROCESS_ID,
        process_start_100ns: OPENCODE_PROCESS_START_100NS,
        image_path: OPENCODE_IMAGE_PATH.to_owned(),
        image_digest: EXECUTABLE_DIGEST.to_owned(),
    }
}

fn introducing_broker() -> OpenCodeBrokerProcessBinding {
    OpenCodeBrokerProcessBinding {
        process_id: BROKER_PROCESS_ID,
        process_start_100ns: BROKER_PROCESS_START_100NS,
    }
}

/// The connected pipe peer as the broker's sealed OS observation reports it:
/// the same token SID, the same logon session, and the exact approved process
/// image this broker observed and hashed at launch.
fn approved_peer() -> OpenCodeBootstrapPeer {
    OpenCodeBootstrapPeer {
        windows_sid: WINDOWS_SID.to_owned(),
        interactive_session_id: INTERACTIVE_SESSION_ID.to_owned(),
        process_id: OPENCODE_PROCESS_ID,
        process_start_100ns: OPENCODE_PROCESS_START_100NS,
        image_path: OPENCODE_IMAGE_PATH.to_owned(),
        image_digest: EXECUTABLE_DIGEST.to_owned(),
    }
}

fn installed_route() -> OpenCodeBootstrapRoute {
    assert!(
        CREDENTIAL.len() <= MAX_OPENCODE_ROUTE_CREDENTIAL_BYTES,
        "the owner mints the credential inside the owner's own bound"
    );
    OpenCodeBootstrapRoute::new(
        minted_introduction(),
        approved_process(),
        introducing_broker(),
        CREDENTIAL.into(),
        ISSUED_AT,
    )
    .expect("the broker installs one current one-shot route")
}

#[test]
fn the_authenticated_peer_obtains_the_introduction_exactly_once() {
    let mut route = installed_route();
    let digest = route.introduction_digest().to_owned();
    assert_eq!(digest.len(), 64, "an introduction digest is a hex digest");
    assert!(
        route.pending_ticket().is_some(),
        "one unredeemed ticket exists"
    );

    let presented = route.pending_ticket().expect("the one-shot ticket").clone();
    let granted = route
        .redeem_peer(
            &presented,
            REDEEMED_AT,
            &approved_peer(),
            &introducing_broker(),
        )
        .expect("the authenticated peer is admitted");

    assert_eq!(granted.endpoint, "http://127.0.0.1:39411");
    assert_eq!(granted.server_identity, EXECUTABLE_DIGEST);
    assert_eq!(
        granted.process_binding,
        minted_introduction().process_binding,
        "the grant binds the exact approved process"
    );
    assert_eq!(
        granted.credential.as_ref(),
        CREDENTIAL,
        "the one-use credential is resolved only after peer authentication"
    );
}

#[test]
fn a_foreign_peer_image_wrong_sid_and_replayed_ticket_are_refused() {
    let broker = introducing_broker();
    let mut other_broker_generation = introducing_broker();
    other_broker_generation.process_start_100ns += 1;
    let mut foreign_image = approved_peer();
    foreign_image.image_digest = FOREIGN_IMAGE_DIGEST.to_owned();
    let mut foreign_process = approved_peer();
    foreign_process.process_id = OPENCODE_PROCESS_ID + 1;
    let mut foreign_sid = approved_peer();
    foreign_sid.windows_sid = "S-1-5-21-100-200-300-1002".to_owned();
    let mut foreign_session = approved_peer();
    foreign_session.interactive_session_id = "9".to_owned();
    let exact = approved_peer();

    let refusals = [
        (
            "foreign process image",
            &foreign_image,
            &broker,
            BrokerError::ProcessBindingMismatch,
        ),
        (
            "foreign process id",
            &foreign_process,
            &broker,
            BrokerError::ProcessBindingMismatch,
        ),
        (
            "wrong SID",
            &foreign_sid,
            &broker,
            BrokerError::StaleRegistrationIdentity,
        ),
        (
            "wrong logon session",
            &foreign_session,
            &broker,
            BrokerError::StaleRegistrationIdentity,
        ),
        (
            "wrong broker generation",
            &exact,
            &other_broker_generation,
            BrokerError::ProcessBindingMismatch,
        ),
    ];

    for (label, peer, broker_process, expected) in refusals {
        let mut route = installed_route();
        let presented = route.pending_ticket().expect("the one-shot ticket").clone();
        assert_eq!(
            route.redeem_peer(&presented, REDEEMED_AT, peer, broker_process),
            Err(expected),
            "{label} must be refused with the existing typed error"
        );
        assert!(
            route.pending_ticket().is_some(),
            "{label} must not spend the one authenticator: the refusal happens \
             before the secret boundary"
        );
    }

    // The rejected peer presented the real ticket and learned nothing; the
    // correct peer can still redeem it exactly once, and a second presentation
    // of the now-spent ticket is a replay conflict.
    let mut route = installed_route();
    let presented = route.pending_ticket().expect("the one-shot ticket").clone();
    route
        .redeem_peer(&presented, REDEEMED_AT, &exact, &broker)
        .expect("the correct peer still redeems after refused peers");
    assert_eq!(
        route.redeem_peer(&presented, REDEEMED_AT, &exact, &broker),
        Err(BrokerError::ReplayConflict),
        "the one-use credential cannot be presented twice"
    );
    assert!(
        route.pending_ticket().is_none(),
        "a spent one-shot ticket leaves nothing to replay"
    );
}
