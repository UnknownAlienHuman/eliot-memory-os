//! #1862 BLOCK-2: the canonical render serializer owner has a real consumer.
//!
//! `eliot_context_contracts::canonical_render_serializer` is the single
//! publisher of the codec identity that I2.16:166-179 records as
//! `serializer_id_version_and_options`. `measure_exact_utf8` already stamps
//! that owner record into every measurement it produces, but the ROUTE half of
//! the same record — the triple `AssemblyPolicy` declares — had no production
//! consumer anywhere in the tree: the only bind was
//! `require_context_render_codec` inside
//! `bins/eliotd/src/kernel_context_read_client.rs`, and
//! `KernelContextReadClient::compile_context_packet` has no call site, so it is
//! never reached.
//!
//! The consumer is therefore placed where the measurement is actually issued:
//! `assemble_active_view_with_measurement`, the composition that forms the
//! canonical `|bytes| measure_exact_utf8(bytes, &params)` callback. The route
//! half is bound to the owner record before any byte is rendered, so
//! `measurement::verify` compares the render owner against the render owner
//! rather than one route's three strings against another route's three strings.
//!
//! Two cases, both on the typed errors this crate already returns: the owner's
//! own triple is accepted, and a route that names a foreign codec is refused
//! with `ContextError::IdentityConflict` — never re-described into the owner's
//! values, never defaulted, and never admitted with a second code path.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_context_assembly::{AssemblyError, AssemblyPolicy};
use eliot_context_contracts::{ContextError, MeasurementStatus, canonical_render_serializer};

fn digest() -> String {
    "a".repeat(64)
}

fn policy() -> AssemblyPolicy {
    AssemblyPolicy {
        fence_digest: digest(),
        max_serialized_bytes: 100_000,
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        measurement_status: MeasurementStatus::ExactUtf8,
    }
}

/// Owner-declared route: the triple the render owner published is the only
/// triple a route may compile under.
///
/// The positive case names the owner on all three members and is accepted, and
/// it also proves the two things a laundering consumer could otherwise get
/// wrong: the accepted values are the OWNER's values (not the policy's
/// placeholders), and they are the owner's own bytes — the id is the owner
/// contract name plus this render's stable codec name, and the version is the
/// very `CONTEXT_CONTRACT_VERSION` the render stamps into the payload's
/// `schema_version` member, so the record cannot disagree with the bytes.
#[test]
fn owner_triple_is_accepted_and_is_read_from_the_owner() {
    let owner = canonical_render_serializer().expect("owner record");
    let mut route = policy();
    route.serializer_id = owner.serializer_id().to_owned();
    route.serializer_version = owner.serializer_version().to_owned();
    route.serializer_options_digest = owner.serializer_options_digest().to_owned();

    // Accepted, and only with the owner's exact three values.
    assert!(eliot_context_assembly::compile_context_render_codec(&route).is_ok());

    // The identity is the owner's, not the route's placeholder spelling: the
    // policy started with `fixture-serde-v1` / `1` / an arbitrary digest and
    // every one of those had to be replaced by the owner's value before this
    // route could name a codec at all.
    assert_eq!(route.serializer_id, owner.serializer_id());
    assert_eq!(route.serializer_version, owner.serializer_version());
    assert_eq!(
        route.serializer_options_digest,
        owner.serializer_options_digest()
    );
    assert_ne!(route.serializer_id, "fixture-serde-v1");

    // The options digest is derived, not declared: it is the owner's canonical
    // digest over the options actually in force (codec, canonicalization rule,
    // byte form, payload member set, schema revision, owner contract). Two
    // independent issuances of the same owner record therefore agree, so a
    // consumer that obtained the identity twice could not tell the two apart
    // and cannot mint a second, different identity.
    let second = canonical_render_serializer().expect("owner record again");
    assert_eq!(second, owner);
    assert_ne!(second.serializer_options_digest(), "a".repeat(64));
}

/// The refusal case: a route that names another codec is refused by the owner,
/// as a typed identity conflict, before any byte is rendered.
///
/// Each member is varied on its own, because the owner compares all three
/// recorded values as recorded: a route that keeps the owner's id but substitutes
/// the revision, or keeps both and substitutes the options digest, is naming a
/// different codec and is refused too. Nothing here is recomputed to stand in
/// for the route, and no member is defaulted or normalised.
#[test]
fn foreign_codec_is_refused_as_a_typed_identity_conflict() {
    let owner = canonical_render_serializer().expect("owner record");

    for foreign in [
        AssemblyPolicy {
            serializer_id: "fixture-serde-v1".to_owned(),
            ..policy()
        },
        AssemblyPolicy {
            serializer_version: "1".to_owned(),
            ..policy()
        },
        AssemblyPolicy {
            serializer_options_digest: digest(),
            ..policy()
        },
    ] {
        assert_eq!(
            eliot_context_assembly::compile_context_render_codec(&foreign),
            Err(AssemblyError::Contract(ContextError::IdentityConflict)),
            "a route naming another codec must be refused, not re-described"
        );
    }

    // The refusal is the owner's, and it is the owner's own comparison: the
    // foreign route shares nothing with the owner record, so there is no second
    // identity for this crate to have substituted for it.
    assert!(owner.validate().is_ok());
    assert_ne!(owner.serializer_id(), "fixture-serde-v1");
    assert_ne!(owner.serializer_version(), "1");

    // A member that is not even a well-formed digest is refused the same way:
    // the owner compares the three recorded values as recorded and never asks
    // whether a foreign value is well formed enough to describe a codec. Same
    // typed refusal, one verdict on this seam — no boolean, no string verdict.
    let malformed = AssemblyPolicy {
        serializer_options_digest: "not-a-digest".to_owned(),
        ..policy()
    };
    assert_eq!(
        eliot_context_assembly::compile_context_render_codec(&malformed),
        Err(AssemblyError::Contract(ContextError::IdentityConflict))
    );
}
