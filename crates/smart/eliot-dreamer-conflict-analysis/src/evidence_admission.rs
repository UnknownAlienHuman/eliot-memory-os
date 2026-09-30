//! Derived rival/confounder coverage over the frozen scope one `ConflictSet`
//! analysis already holds.
//!
//! I21.6 makes the coverage denominator a first-class obligation: a scoped
//! claim may only be called complete over a frozen scope, and an indexed or
//! self-selected set never narrows the denominator of a scoped absence. This
//! module is where that scope is DERIVED for the claims this cell reads without
//! an owner record, so the published cell names the rivals the frozen
//! `ConflictSet` actually records, how many of them this analysis can show, and
//! how many it omitted — instead of reporting a hardcoded unknown beside a
//! scope the analysis can measure.
//!
//! The derivation reads only what `analyze_conflict` already holds: the
//! `ConflictSet` position denominator and its counter handles. It performs no
//! I/O, admits no owner, executes no probe, and selects no winner.
//!
//! # What is deliberately NOT derived here
//!
//! The retained-evidence legs of the denominator — which expected members are
//! covered and which are omitted, and therefore the coverage itself — belong to
//! the owner-issued [`CausalEvidenceRecord`](crate::CausalEvidenceRecord) that
//! carries them, and are checked there by
//! [`RivalDenominator::validate`](crate::RivalDenominator::validate) against
//! the record's own retained envelopes. They are NOT re-derived from the
//! analysis-wide `SourceMemberRecord` set here: an analysis-wide member says
//! that some material exists for a source, which is not the same as evidence
//! this claim retains, and treating the two as interchangeable is exactly the
//! substitution the crate's envelope join refuses. A caller that declared such
//! a denominator is refused there, not repaired here.

use std::collections::BTreeSet;

use eliot_epistemic_contracts::ConflictSet;
use eliot_evidence::EvidenceCoverage;

use crate::{RivalDenominator, position_source_handles};

/// Canonicalizes one handle list into a sorted, deduplicated set.
///
/// The rival lists are compared and reported as SETS: declaration order carries
/// no meaning, so the same scope always derives the same denominator.
fn canonical_members(handles: &[String]) -> Vec<String> {
    let unique: BTreeSet<&str> = handles.iter().map(String::as_str).collect();
    unique.into_iter().map(str::to_owned).collect()
}

/// Derives one position's rival/confounder denominator over the frozen scope.
///
/// `expected` is the union of the two rival surfaces the `ConflictSet` itself
/// records against this position: every OTHER position's source handle, because
/// a conflict set is a set of competing claims, and every counter handle raised
/// against the position. Both are canonical `ConflictSet` members, so the
/// denominator is the scope's own and never a caller's selection.
///
/// A legacy declaration retains no evidence envelope of its own, so it observes
/// nothing here: `observed` is empty and every expected member lands in
/// `omitted`, which is the I21.6 obligation that a scoped absence be NAMED
/// rather than smoothed into a coverage claim. The published cell therefore
/// carries the frozen scope's size and its omission count, and its coverage is
/// [`EvidenceCoverage::Unknown`] — a real derivation, not a defaulted constant.
///
/// The coverage is set from [`RivalDenominator::derived_coverage`] rather than
/// asserted, so a denominator that carries an omission cannot report
/// [`EvidenceCoverage::CompleteForScope`]: the complete/omitted relation is a
/// property of this construction rather than a rule a caller must remember.
#[must_use]
pub fn derive_rival_denominator(
    position_source: &str,
    conflict_set: &ConflictSet,
) -> RivalDenominator {
    let mut expected: Vec<String> = position_source_handles(conflict_set)
        .into_iter()
        .filter(|handle| handle != position_source)
        .collect();
    for position in &conflict_set.positions {
        if position.source.as_str() != position_source {
            continue;
        }
        expected.extend(position.counters.iter().map(|counter| counter.as_str().to_owned()));
    }
    let expected = canonical_members(&expected);
    let omitted = expected.clone();
    let mut denominator = RivalDenominator {
        expected,
        observed: Vec::new(),
        omitted,
        coverage: EvidenceCoverage::Unknown,
    };
    denominator.coverage = denominator.derived_coverage();
    denominator
}
