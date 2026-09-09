#![allow(clippy::expect_used)]

use eliot_dreamer_contracts::{ValidationPolicy, canonical_bytes, digest_hex};

#[test]
fn validation_policy_and_canonical_preimage_are_owned_by_a03() {
    let mut policy = ValidationPolicy::new("policy-1", 7, 1_048_576);
    policy.seal().expect("policy seals");
    let first = policy.canonical_digest.clone();
    policy.validate().expect("sealed policy validates");
    let wire = canonical_bytes(&policy).expect("policy has canonical bytes");
    assert_eq!(digest_hex(&wire).len(), 64);
    assert_eq!(policy.canonical_digest, first);
}
