//! Contract and wire regressions for the canonical ECXF event interval.

use std::error::Error;

use eliot_contracts::canonical_json_bytes;
use eliot_ecxf::{EcxfError, EventRange, FORMAT_VERSION};
use serde::Deserialize;

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    valid: bool,
    wire: String,
    canonical_wire: String,
}

fn fixtures() -> Result<Vec<Fixture>, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "data/event_range_cases.json"
    ))?)
}

fn fixture(id: &str) -> Result<Fixture, Box<dyn Error>> {
    fixtures()?
        .into_iter()
        .find(|case| case.id == id)
        .ok_or_else(|| format!("missing event-range fixture: {id}").into())
}

fn range(id: &str) -> Result<EventRange, Box<dyn Error>> {
    Ok(serde_json::from_str(&fixture(id)?.wire)?)
}

fn assert_invalid(value: &EventRange) {
    assert!(matches!(
        value.validate(),
        Err(EcxfError::InvalidField {
            field: "event_range",
            reason: "bounds and count do not describe one interval",
        })
    ));
}

// WORK_UNIT_CASE: 862/2
#[test]
fn empty_range_preserves_the_existing_sentinel() -> TestResult {
    let value = range("empty")?;
    assert_eq!(
        (value.first_sequence, value.last_sequence, value.count),
        (None, None, 0)
    );
    value.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 862/3
#[test]
fn single_event_accepts_zero_regular_and_maximum_sequence() -> TestResult {
    for (id, sequence) in [
        ("singleton_zero", 0),
        ("singleton", 47),
        ("singleton_max", u64::MAX),
    ] {
        let value = range(id)?;
        assert_eq!(
            (value.first_sequence, value.last_sequence, value.count),
            (Some(sequence), Some(sequence), 1)
        );
        value.validate()?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 862/4
#[test]
fn multi_event_interval_requires_its_exact_count() -> TestResult {
    for (id, first, last, count) in [("contiguous", 10, 13, 4), ("contiguous_from_zero", 0, 3, 4)] {
        let value = range(id)?;
        assert_eq!(
            (value.first_sequence, value.last_sequence, value.count),
            (Some(first), Some(last), count)
        );
        value.validate()?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 862/5
#[test]
fn count_above_interval_width_is_rejected() -> TestResult {
    for id in ["too_many", "singleton_too_many"] {
        let value = range(id)?;
        let first = value.first_sequence.ok_or("fixture requires first bound")?;
        let last = value.last_sequence.ok_or("fixture requires last bound")?;
        assert!(u128::from(value.count) > u128::from(last) + 1 - u128::from(first));
        assert_invalid(&value);
    }
    Ok(())
}

// WORK_UNIT_CASE: 862/6
#[test]
fn positive_sparse_count_is_not_a_contiguous_interval() -> TestResult {
    for id in ["sparse", "sparse_from_zero"] {
        let value = range(id)?;
        let first = value.first_sequence.ok_or("fixture requires first bound")?;
        let last = value.last_sequence.ok_or("fixture requires last bound")?;
        assert!(value.count > 0);
        assert!(u128::from(value.count) < u128::from(last) + 1 - u128::from(first));
        assert_invalid(&value);
    }
    Ok(())
}

// WORK_UNIT_CASE: 862/7
#[test]
fn bounded_zero_count_does_not_become_an_empty_sentinel() -> TestResult {
    let value = range("bounded_zero")?;
    assert_eq!(value.count, 0);
    assert!(value.first_sequence.is_some() && value.last_sequence.is_some());
    assert_invalid(&value);
    Ok(())
}

// WORK_UNIT_CASE: 862/8
#[test]
fn nonzero_count_requires_both_bounds() -> TestResult {
    let value = range("unbounded_nonzero")?;
    assert_eq!((value.first_sequence, value.last_sequence), (None, None));
    assert!(value.count > 0);
    assert_invalid(&value);
    Ok(())
}

// WORK_UNIT_CASE: 862/9
#[test]
fn first_bound_alone_is_rejected_for_zero_and_nonzero_counts() -> TestResult {
    for id in ["first_only", "first_only_zero"] {
        let value = range(id)?;
        assert!(value.first_sequence.is_some());
        assert!(value.last_sequence.is_none());
        assert_invalid(&value);
    }
    Ok(())
}

// WORK_UNIT_CASE: 862/10
#[test]
fn last_bound_alone_is_rejected_for_zero_and_nonzero_counts() -> TestResult {
    for id in ["last_only", "last_only_zero"] {
        let value = range(id)?;
        assert!(value.first_sequence.is_none());
        assert!(value.last_sequence.is_some());
        assert_invalid(&value);
    }
    Ok(())
}

// WORK_UNIT_CASE: 862/11
#[test]
fn reversed_bounds_are_rejected_without_underflow() -> TestResult {
    let value = range("reversed")?;
    assert!(
        value
            .first_sequence
            .zip(value.last_sequence)
            .is_some_and(|(first, last)| first > last)
    );
    assert_invalid(&value);
    Ok(())
}

// WORK_UNIT_CASE: 862/12
#[test]
fn maximum_width_is_checked_and_matches_a_wider_integer_oracle() -> TestResult {
    for id in ["largest_from_one", "largest_from_zero"] {
        let value = range(id)?;
        assert_eq!(value.count, u64::MAX);
        value.validate()?;
    }
    for id in ["full_width_zero", "full_width_one", "full_width_max_count"] {
        let value = range(id)?;
        assert_eq!(
            (value.first_sequence, value.last_sequence),
            (Some(0), Some(u64::MAX))
        );
        assert_invalid(&value);
    }

    // The wider oracle neither overflows nor repeats the owner's checked-u64
    // predicate. Include reversed, singleton, sparse and full-width pairs.
    let boundaries = [0, 1, 2, u64::MAX - 1, u64::MAX];
    for first in boundaries {
        for last in boundaries {
            for count in boundaries {
                let expected =
                    first <= last && u128::from(count) == u128::from(last) + 1 - u128::from(first);
                let value = EventRange {
                    first_sequence: Some(first),
                    last_sequence: Some(last),
                    count,
                };
                assert_eq!(
                    value.validate().is_ok(),
                    expected,
                    "first={first}, last={last}, count={count}"
                );
            }
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 862/14
#[test]
fn valid_old_bytes_survive_and_old_sparse_bytes_get_typed_rejection() -> TestResult {
    assert_eq!(FORMAT_VERSION, "ECXF/1");
    let cases = fixtures()?;
    assert!(!cases.is_empty());
    let mut valid_seen = 0;
    let mut invalid_seen = 0;
    for case in cases {
        let value: EventRange = serde_json::from_str(&case.wire)?;
        if case.valid {
            value.validate()?;
            assert_eq!(serde_json::to_string(&value)?, case.wire, "{}", case.id);
            assert_eq!(
                canonical_json_bytes(&value)?,
                case.canonical_wire.as_bytes(),
                "{}",
                case.id
            );
            valid_seen += 1;
        } else {
            assert_invalid(&value);
            invalid_seen += 1;
        }
    }
    assert!(valid_seen > 0 && invalid_seen > 0);

    // This raw historical shape was accepted by both old validators. It is
    // still decoded by the existing schema, but is invalid at its owner gate.
    let sparse = fixture("sparse")?;
    assert_eq!(
        sparse.wire,
        r#"{"first_sequence":10,"last_sequence":13,"count":2}"#
    );
    let value: EventRange = serde_json::from_str(&sparse.wire)?;
    assert_invalid(&value);
    Ok(())
}
