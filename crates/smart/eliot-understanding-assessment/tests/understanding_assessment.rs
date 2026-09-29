//! Package test entrypoint for the `smart.understanding.common_ground` cell (#238).
//!
//! This package shipped no `tests/` target, so its cell had no independently
//! invocable proof entrypoint: the generated
//! `docs/code-navigation/capsules/smart.understanding.common_ground/test_capsule.json`
//! reported `independent_proof_entrypoint.state = UNDECLARED` and
//! `expected_nonzero_test_count.nonzero = false`, and I2.20:117 holds that a
//! crate or cell without an executable `ModuleTestCapsule` "may be
//! investigated, but is not independently supported" (I2.20:135 adds that
//! without a test capsule there is no independently invocable proof, which
//! directly violates `ARCH-MOD-03`).
//!
//! THIS FILE IS THAT ENTRYPOINT. It is reached only through the package's
//! public surface and it adds no new behavioural claim:
//!
//! * the cell declares no test module (`module.toml|acceptance.required_tests`
//!   is empty and `required_exports` is empty), so there is no in-crate test
//!   module to move out of, and this file invents no fixture semantics, no
//!   handle, no digest, no fence and no owner envelope;
//! * the one outcome asserted is the closure-leg rule the package already
//!   states in its own public documentation on
//!   [`AssessmentClosure::missing`] — "held-out required only when
//!   `product_claims` is set" — and that the cell's own `module.toml`
//!   restates as the declared invariant "product claims additionally require
//!   held-out or leakage-controlled evaluation" and the `complete_rule`
//!   "NOT_ONBOARDED forbids LOCALLY_ADEQUATE until missing inputs resolve".
//!
//! The fixture is `AssessmentClosure::default()`, i.e. the crate's own
//! `#[derive(Default)]` empty closure; no value is fabricated.

#![forbid(unsafe_code)]

use eliot_understanding_assessment::AssessmentClosure;

/// The five closure legs the cell requires unconditionally, in the order
/// `AssessmentClosure::missing` names them.
const UNCONDITIONAL: [&str; 5] = [
    "closure.rival_model",
    "closure.pre_probe_prediction",
    "closure.discriminator",
    "closure.outcome_verifier",
    "closure.revision",
];

#[test]
fn held_out_closure_leg_is_required_only_for_product_claims() {
    let closure = AssessmentClosure::default();

    // No product claim: held-out evidence is not a required leg.
    assert_eq!(closure.missing(false), UNCONDITIONAL);
    // Product claim: the same five legs plus held-out, still in source order.
    let mut with_product_claim = UNCONDITIONAL.to_vec();
    with_product_claim.push("closure.held_out");
    assert_eq!(closure.missing(true), with_product_claim);

    // An empty closure is therefore never complete, with or without a claim.
    assert!(!closure.is_complete_for(false));
    assert!(!closure.is_complete_for(true));
}
