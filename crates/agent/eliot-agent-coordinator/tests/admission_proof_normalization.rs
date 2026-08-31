#[test]
fn admission_is_normalized_before_exact_proof_bytes_are_derived() {
    let source = include_str!("../src/core.rs");
    let start = source
        .find("    pub fn admit(")
        .expect("AgentCoordinator::admit must remain present");
    let tail = &source[start..];
    let end = tail
        .find("    pub fn next_ready(")
        .expect("admit boundary must remain bounded");
    let admit = &tail[..end];

    let normalize = admit
        .find("receipt.admitted_lanes.sort_by")
        .expect("admitted lanes must be normalized");
    let canonical = admit
        .find("let canonical_receipt = canonical(&receipt)?;")
        .expect("normalized receipt must be serialized exactly once");
    let verify = admit
        .find("self.provider.verify(")
        .expect("normalized bytes must reach the sealed verifier");
    let identity = admit
        .find("self.validate_provider_identity(&receipt.provider_identity)?;")
        .expect("provider identity validation must remain in the admission path");

    assert!(normalize < canonical, "normalization must precede serialization");
    assert!(canonical < verify, "serialization must precede proof verification");
    assert!(verify < identity, "proof must precede provider-state admission");
    assert_eq!(
        admit.matches("receipt.admitted_lanes.sort_by").count(),
        1,
        "proof-bearing receipt must not be reordered again after verification"
    );
    assert!(
        admit.contains("&canonical_receipt,"),
        "verifier must receive the bytes derived from the normalized receipt"
    );
}
