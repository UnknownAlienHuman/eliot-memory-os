#[test]
fn bound_identity_ordering_does_not_depend_on_serde_or_fallback_bytes() {
    let source = include_str!("../src/lib.rs");
    let impl_start = source
        .find("impl Ord for BoundIdentity")
        .expect("BoundIdentity must keep an explicit total-order implementation");
    let remaining = &source[impl_start..];
    let impl_end = remaining
        .find("\n}\n")
        .map(|offset| offset + 3)
        .expect("BoundIdentity Ord implementation must have a bounded source body");
    let ordering_impl = &remaining[..impl_end];

    assert!(
        !ordering_impl.contains("serde_json::to_string"),
        "identity order must be structural and cannot depend on JSON spelling or serialization success"
    );
    assert!(
        !ordering_impl.contains("unwrap_or_default"),
        "serialization failure must never collapse an identity component to default bytes"
    );
}
