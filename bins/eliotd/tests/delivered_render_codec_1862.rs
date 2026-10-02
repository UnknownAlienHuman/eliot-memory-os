//! #1862 BLOCK-2 delivered-lane render-codec binding.
//!
//! I2.16:163 — "Context admission and profile qualification use the exact bytes
//! that the selected route will receive, not an abstract source estimate." The
//! delivered lane is where those bytes already exist: the `ContextDelivery` row's
//! retained owner closures carry the exact delivered `ActiveUnderstandingView`,
//! whose `ContextExecutionIdentity` states the codec its bytes were produced
//! under.
//!
//! `ActiveUnderstandingView::validate` compares that identity against the same
//! delivery's own measurement, so a delivery rendered under a codec the Context
//! render owner does not publish satisfies every existing owner validator.
//! `require_delivered_context_render_codec` is the check that binds those three
//! recorded values to their issuer, and these two cases are its whole contract:
//! a delivery that names the owner-issued canonical codec passes, and one that
//! names any other codec is refused with the owner's typed `ContextError`.

use eliot_context_contracts::{
    CONTEXT_CONTRACT_VERSION, ContextError, ContextExecutionIdentity, MeasurementStatus,
    canonical_render_serializer,
};
use eliotd::require_delivered_context_render_codec;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn digest(byte: u8) -> String {
    std::iter::repeat_n(byte as char, 64).collect()
}

/// The execution identity a delivery recorded when it was rendered by the
/// Context render owner itself.
fn owner_issued_delivery() -> TestResult<ContextExecutionIdentity> {
    let owner = canonical_render_serializer()?;
    Ok(ContextExecutionIdentity {
        ordering_revision: "eliot-context-ordering/v1".to_owned(),
        serializer_id: owner.serializer_id().to_owned(),
        serializer_version: owner.serializer_version().to_owned(),
        serializer_options_digest: owner.serializer_options_digest().to_owned(),
        route_id: "eliot.packet".to_owned(),
        model_id: "eliot-context-model".to_owned(),
        measurement_status: MeasurementStatus::ExactUtf8,
    })
}

/// A delivery rendered under a route codec the Context render owner does not
/// publish. Every field is well-formed and the record passes its own
/// `validate()`, so the refusal can only come from the owner comparison.
fn foreign_codec_delivery() -> TestResult<ContextExecutionIdentity> {
    Ok(ContextExecutionIdentity {
        ordering_revision: "eliot-context-ordering/v1".to_owned(),
        serializer_id: "json-v1".to_owned(),
        serializer_version: CONTEXT_CONTRACT_VERSION.to_string(),
        serializer_options_digest: digest(b'f'),
        route_id: "eliot.packet".to_owned(),
        model_id: "eliot-context-model".to_owned(),
        measurement_status: MeasurementStatus::ExactUtf8,
    })
}

/// POSITIVE: a delivered execution identity that names the owner-issued
/// canonical render codec is admitted. The owner record is read here rather
/// than spelled out, so this asserts the binding against the live owner and not
/// against a copied triple.
#[test]
fn delivered_lane_bindings_the_owner_canonical_render_codec() -> TestResult {
    require_delivered_context_render_codec(&owner_issued_delivery()?)
        .map_err(|error| format!("owner-issued delivered codec must bind: {error}").into())
}

/// REFUSAL: a delivered execution identity naming another codec is refused with
/// the owner's typed `IdentityConflict`, not silently re-described. The identity
/// validates against its own closed contract first, so the refusal is
/// specifically the codec comparison.
#[test]
fn delivered_lane_refuses_a_codec_the_context_owner_does_not_publish() {
    let delivered = foreign_codec_delivery().expect("well-formed foreign-codec delivery");
    delivered
        .validate()
        .expect("the record is well formed; only its codec is foreign");
    assert_eq!(
        require_delivered_context_render_codec(&delivered),
        Err(ContextError::IdentityConflict),
        "a delivery under a non-owner codec must be refused by the codec binding"
    );
}