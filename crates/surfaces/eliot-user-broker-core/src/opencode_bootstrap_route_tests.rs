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
    OpenCodeBootstrapRoute, OpenCodeBridgeIntroduction, OpenCodeBridgeOwnerGrant,
    OpenCodeBridgeOwnerGrantParams, OpenCodeBridgeProcessProjection, OpenCodeBrokerProcessBinding,
    OpenCodeIntroductionParams, OpenCodeProcessBinding, OpenCodeProcessProjectionParams, SecretRef,
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

/// The Kernel-owned authorization record for this exact bridge launch. It is
/// the only source of the activation generation, the activation fence nonce
/// and the authorized endpoint, and it names the admitted bridge artifact that
/// authorizes that endpoint.
fn owner_grant() -> OpenCodeBridgeOwnerGrant {
    OpenCodeBridgeOwnerGrant::mint(OpenCodeBridgeOwnerGrantParams {
        installation_id: INSTALLATION_ID.to_owned(),
        windows_sid: WINDOWS_SID.to_owned(),
        interactive_session_id: INTERACTIVE_SESSION_ID.to_owned(),
        authority_epoch: epoch(),
        activation_generation: generation(BRIDGE_GENERATION),
        activation_fence_nonce: format!("fence-{BRIDGE_GENERATION}"),
        registration_fence_id: format!("user-broker-fence-{BROKER_GENERATION}"),
        authorized_endpoint: "http://127.0.0.1:39411".to_owned(),
        bridge_artifact_digest: EXECUTABLE_DIGEST.to_owned(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
    })
    .expect("the Kernel mints this owner grant")
}

/// The broker-observed half only. The activation generation, the activation
/// fence nonce and the endpoint are structurally absent: they are read from
/// [`owner_grant`], so no caller scalar can stand in for them.
fn broker_observed_params() -> OpenCodeProcessProjectionParams {
    OpenCodeProcessProjectionParams {
        installation_id: INSTALLATION_ID.to_owned(),
        windows_sid: WINDOWS_SID.to_owned(),
        interactive_session_id: INTERACTIVE_SESSION_ID.to_owned(),
        authority_epoch: epoch(),
        registration_fence_id: format!("user-broker-fence-{BROKER_GENERATION}"),
        broker_generation: generation(BROKER_GENERATION),
        server_identity: FOREIGN_IMAGE_DIGEST.to_owned(),
        bootstrap_channel: Some(OPENCODE_BOOTSTRAP_PIPE_NAME.to_owned()),
        credential: SecretRef::new("opencode-route", REVOCATION_ID)
            .expect("typed opaque credential handle"),
        credential_expires_at: CREDENTIAL_EXPIRES_AT,
        allowed_capabilities: vec![
            OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT.to_owned(),
            OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE.to_owned(),
        ],
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        revocation_id: REVOCATION_ID.to_owned(),
        process_binding: OpenCodeProcessBinding {
            executable_digest: EXECUTABLE_DIGEST.to_owned(),
            launch_nonce: LAUNCH_NONCE.to_owned(),
            parent_broker_process_id: BROKER_PROCESS_ID.to_string(),
        },
    }
}

/// Positive case for the launch-time producer: a projection composed from a
/// current Kernel owner grant carries exactly the grant's activation
/// generation, activation fence nonce and authorized endpoint, and re-reads
/// through its own closed validator. This is what makes
/// `ingress.rs:2689` reachable: the introduction's `bridge_generation` is the
/// generation the bridge's own live attach fence will carry, so the serving
/// loop no longer returns `Rotated` before the first byte.
#[test]
fn a_current_owner_grant_produces_the_serving_introduction() {
    let owner = owner_grant();
    owner
        .validate(ISSUED_AT)
        .expect("a freshly minted owner grant is current");
    let projection = OpenCodeBridgeProcessProjection::compose(&owner, broker_observed_params())
        .expect("the broker composes the child projection from its own owner grant");

    assert_eq!(
        projection.introduction.bridge_generation.get(),
        owner.activation_generation.get(),
        "the introduction's bridge generation IS the granted activation generation"
    );
    assert_eq!(
        projection.introduction.fence_id, owner.activation_fence_nonce,
        "the introduction's fence IS the nonce the activation exchange installs"
    );
    assert_eq!(
        projection.introduction.endpoint, owner.authorized_endpoint,
        "the endpoint is the owner-authorized one, never a bare port"
    );
    assert!(
        owner.authorizes_endpoint_for(INSTALLATION_ID, EXECUTABLE_DIGEST),
        "the endpoint is authorized by the admitted bridge artifact identity"
    );
    projection
        .facts(ISSUED_AT)
        .expect("the composed projection re-reads through its own validator");
}

/// Refusal cases for the same seam. Each is an owner-record mismatch or an
/// owner-record tamper, and each is answered with the *existing* typed
/// [`BrokerError`] set rather than a string verdict or a boolean:
///
/// * a grant issued under a superseded registration fence is
///   [`BrokerError::StaleRegistrationIdentity`];
/// * a grant whose activation generation no longer binds its own digest tuple
///   is [`BrokerError::GrantBindingMismatch`];
/// * a grant presented outside its own issue/expiry window is
///   [`BrokerError::LeaseExpired`];
/// * a grant that authorizes a *different* bridge artifact refuses to
///   authorize this launch's endpoint, which is what makes a port insufficient
///   owner data on its own.
#[test]
fn a_mismatched_owner_grant_is_refused_with_a_typed_error() {
    let owner = owner_grant();

    // A grant minted under another live registration fence never composes.
    let mut superseded = broker_observed_params();
    superseded.registration_fence_id = "user-broker-fence-99".to_owned();
    assert_eq!(
        OpenCodeBridgeProcessProjection::compose(&owner, superseded).err(),
        Some(BrokerError::StaleRegistrationIdentity),
        "a grant from another registration is refused, not minted from"
    );

    // A tampered activation generation no longer binds the grant digest.
    let mut rotated = owner.clone();
    rotated.activation_generation = generation(BROKER_GENERATION);
    assert_eq!(
        rotated.validate(ISSUED_AT).err(),
        Some(BrokerError::GrantBindingMismatch),
        "an activation generation that does not bind the grant is refused"
    );

    // A port is not owner data: the same grant authorizes no endpoint for a
    // foreign artifact, and no endpoint at all for another installation.
    assert!(
        !owner.authorizes_endpoint_for(INSTALLATION_ID, FOREIGN_IMAGE_DIGEST),
        "a foreign artifact never inherits an authorized endpoint"
    );
    assert!(
        !owner.authorizes_endpoint_for("installation-other", EXECUTABLE_DIGEST),
        "an endpoint is authorized inside one installation only"
    );

    // A grant outside its own window is refused as a stale lease.
    assert_eq!(
        owner.validate(EXPIRES_AT).err(),
        Some(BrokerError::LeaseExpired),
        "an expired owner grant composes nothing"
    );
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
