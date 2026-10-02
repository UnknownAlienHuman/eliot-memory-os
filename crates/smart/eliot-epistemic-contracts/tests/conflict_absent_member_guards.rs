//! Refusal coverage for the two absent-member integrity guards on
//! `ConflictSet::missing_positions` that the #673 delivery declared and left
//! unexercised: a record naming a member the set already carries (or naming the same
//! member twice) is refused as `Duplicate`, and a record whose owner the set's own
//! `unresolved_owners` residue never names is refused as `MissingReference`.
//!
//! Each negative enters the same production validator as the admitted qualified set —
//! `ConflictSet::validate_shape`, reached through `ConflictSet::new_with_missing_positions`
//! and again through `ConflictSet::validate` — so neither fixture is one no validator
//! ever sees. Every case first admits the identical two-member shape with a properly
//! referenced absent member, so the refusal is attributable to the named guard alone and
//! not to an unrelated defect in the fixture.

use std::collections::BTreeSet;

use eliot_contracts::{sha256_hex, SourceId};
use eliot_epistemic_contracts::{
    ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictPosition, ConflictSet,
    ConflictSetParams, ContractError, MemberDisposition, MissingConflictPosition,
};

type CaseResult = Result<(), ContractError>;

/// Owner of the one carried position every fixture below preserves.
const CARRIED: &str = "source-carried";
/// Owner of the declared-but-absent member; never carried as a position here.
const ABSENT: &str = "source-absent";

fn source(name: &str) -> Result<SourceId, ContractError> {
    SourceId::new(name).map_err(|_| ContractError::Blank {
        field: "case.source",
    })
}

/// The one carried position, held by [`CARRIED`].
fn carried() -> Result<ConflictPosition, ContractError> {
    ConflictPosition::new(
        source(CARRIED)?,
        "cache helps tail latency",
        BTreeSet::new(),
        BTreeSet::new(),
        false,
    )
}

/// One declared-but-absent member whose owner-issued outcome is still open, so the
/// member stays in the denominator and no other guard can refuse it.
fn absent(owner: &str) -> Result<MissingConflictPosition, ContractError> {
    MissingConflictPosition::new(
        source(owner)?,
        MemberDisposition::Unavailable,
        "the owner has not released its stance yet",
    )
}

/// One carried position plus the named `unresolved_owners` residue, with the
/// absent-member list supplied separately by the caller.
fn params(unresolved_owners: &[&str]) -> Result<ConflictSetParams, ContractError> {
    let owners = [CARRIED, ABSENT]
        .into_iter()
        .map(source)
        .collect::<Result<BTreeSet<SourceId>, ContractError>>()?;
    Ok(ConflictSetParams {
        conflict_id: "conflict-absent-member-guard".to_owned(),
        kind: ConflictKind::Epistemic,
        scope: "scope-673".to_owned(),
        task_id: None,
        positions: vec![carried()?],
        evidence_refs: BTreeSet::new(),
        owners,
        common_lineage: BTreeSet::new(),
        resolved_parts: BTreeSet::new(),
        unresolved: BTreeSet::from(["release timing is contested".to_owned()]),
        unresolved_owners: unresolved_owners
            .iter()
            .copied()
            .map(source)
            .collect::<Result<BTreeSet<SourceId>, ContractError>>()?,
        acceptability: ArgumentAcceptability::Contested,
        defeated_refs: BTreeSet::new(),
        probe: None,
        decision_owner: source(CARRIED)?,
        affected_actions: vec!["decide-cache".to_owned()],
        lifecycle: ConflictLifecycle::Open,
        receipt_digest: sha256_hex(b"receipt-conflict-absent-member-guard"),
    })
}

/// Proves one refused shape through both production entry points.
///
/// The control set is the admitted two-member denominator — one carried position plus
/// one properly referenced open absent member — so the guard under test is the only
/// difference between what is accepted and what is refused. The same shape is then
/// re-entered through `ConflictSet::validate` on a set whose recorded digest was
/// recomputed from its own fields, so a refusal there can only come from the shape guard
/// and never from the frozen digest.
fn expect_refused(
    label: &str,
    unresolved_owners: &[&str],
    records: Vec<MissingConflictPosition>,
    expected: ContractError,
) -> CaseResult {
    let mut control = ConflictSet::new_with_missing_positions(
        params(&[CARRIED, ABSENT])?,
        vec![absent(ABSENT)?],
    )?;
    control.validate()?;
    assert_eq!(control.position_denominator(), 2, "{label}: control denominator");
    let refused =
        ConflictSet::new_with_missing_positions(params(unresolved_owners)?, records.clone());
    assert_eq!(
        refused,
        Err(expected.clone()),
        "{label}: construction must refuse this shape"
    );
    control.missing_positions = records;
    control.unresolved_owners = unresolved_owners
        .iter()
        .copied()
        .map(source)
        .collect::<Result<BTreeSet<SourceId>, ContractError>>()?;
    control.digest = control.compute_digest()?;
    assert_eq!(
        control.validate(),
        Err(expected),
        "{label}: validate() must refuse the same shape"
    );
    Ok(())
}

// WORK_UNIT_CASE: 673/69
#[test]
fn absent_member_naming_a_carried_or_repeated_owner_is_a_duplicate() -> CaseResult {
    // Carried and absent at once: the set already holds this member's position, so the
    // record would count one owner twice in the same denominator. The residue names the
    // owner, so only the Duplicate guard can refuse this input.
    expect_refused(
        "carried and absent",
        &[CARRIED, ABSENT],
        vec![absent(CARRIED)?],
        ContractError::Duplicate {
            field: "conflict.missing_positions",
        },
    )?;
    // Named twice: the absent owner is not carried and is referenced, so the first record
    // is admissible and only the second one repeats it.
    expect_refused(
        "named twice",
        &[CARRIED, ABSENT],
        vec![absent(ABSENT)?, absent(ABSENT)?],
        ContractError::Duplicate {
            field: "conflict.missing_positions",
        },
    )
}

// WORK_UNIT_CASE: 673/70
#[test]
fn absent_member_owner_absent_from_unresolved_owners_is_a_missing_reference() -> CaseResult {
    // The owner is not carried, is named once, and its outcome is still open, so the
    // record is refused solely because the set's own residue never names it: without that
    // reference the record is an unowned assertion that a rival exists.
    expect_refused(
        "unreferenced owner",
        &[CARRIED],
        vec![absent(ABSENT)?],
        ContractError::MissingReference {
            field: "conflict.missing_positions",
        },
    )
}