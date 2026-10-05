//! Verified-empty enumeration-state wire spelling (issue #1767, W1/A2).
//!
//! A verified empty eligible scope is its own enumeration state, distinct
//! from an enumeration that never ran. The wire spelling is the contract
//! every later W1 slice binds against, so the four states must render
//! distinct wire names.

use eliot_researcher::inquiry_governance::EnumerationState;

#[test]
fn verified_empty_wire_spelling_is_distinct() {
    let wire_names = [
        EnumerationState::Uninitialised.wire_name(),
        EnumerationState::Incomplete.wire_name(),
        EnumerationState::Complete.wire_name(),
        EnumerationState::VerifiedEmpty.wire_name(),
    ];
    for (index, wire_name) in wire_names.iter().enumerate() {
        for other in wire_names.iter().skip(index + 1) {
            assert_ne!(wire_name, other, "wire names must be distinct");
        }
    }
    assert_eq!(
        EnumerationState::VerifiedEmpty.wire_name(),
        "verified_empty"
    );
    assert_ne!(
        format!("{}", EnumerationState::VerifiedEmpty),
        format!("{}", EnumerationState::Uninitialised)
    );
}
