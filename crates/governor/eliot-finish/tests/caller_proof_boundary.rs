#[test]
fn public_finish_attempt_contains_only_candidate_input() {
    let source = include_str!("../src/lib.rs");
    let struct_start = source
        .find("pub struct FinishAttempt")
        .expect("the public FinishAttempt contract must remain explicit");
    let remaining = &source[struct_start..];
    let struct_end = remaining
        .find("\n}\n")
        .map(|offset| offset + 3)
        .expect("FinishAttempt must have a bounded source body");
    let finish_attempt = &remaining[..struct_end];

    assert!(
        !finish_attempt.contains("pub evidence:"),
        "caller input must not carry acceptance, verifier, effect, or completion evidence; Finish rehydrates it from current owners"
    );
}
