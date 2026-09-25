//! Deterministic epistemic resolver: one question over one admitted set.
//!
//! [`resolve`] evaluates an admitted, fenced read set and returns a
//! forward-rebuildable position with rivals and inquiry preserved. It never
//! manufactures truth and never mutates a source record.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};

use crate::position::{
    CurrentEpistemicPosition, EpistemicError, EpistemicRecord, PositionRequest, PositionState,
    ProvenanceView,
};

const fn is_current_freshness(freshness: EvidenceFreshness) -> bool {
    matches!(
        freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    )
}

/// Resolve one question without ranking by prose, vote count, or model output.
#[allow(clippy::too_many_lines)]
pub fn resolve(request: &PositionRequest) -> Result<CurrentEpistemicPosition, EpistemicError> {
    request.validate()?;
    let mut direct = BTreeSet::new();
    let mut supporting = BTreeSet::new();
    let mut rivals = BTreeSet::new();
    let mut stale = BTreeSet::new();
    let mut unknowns = BTreeSet::new();
    let mut inquiries = BTreeSet::new();
    let mut current = Vec::new();
    let mut superseded = request
        .records
        .iter()
        .flat_map(|record| record.supersedes.iter().cloned())
        .collect::<BTreeSet<_>>();

    for record in &request.records {
        if let Some(note) = &record.note {
            inquiries.insert(note.clone());
        }
        if !is_current_freshness(record.evidence.freshness) {
            stale.insert(record.handle.clone());
            let inquiry = if record.evidence.freshness == EvidenceFreshness::Stale {
                format!("revalidate {}", record.handle)
            } else {
                format!("establish freshness for {}", record.handle)
            };
            inquiries.insert(inquiry);
            match record.evidence.status {
                EpistemicStatus::Unknown => {
                    unknowns.insert(record.subject.clone());
                    inquiries.insert(format!("obtain evidence for {}", record.subject));
                }
                EpistemicStatus::Superseded => {
                    superseded.insert(record.handle.clone());
                }
                _ => {}
            }
            continue;
        }
        if superseded.contains(&record.handle) {
            if record.evidence.status == EpistemicStatus::Unknown {
                unknowns.insert(record.subject.clone());
                inquiries.insert(format!("obtain evidence for {}", record.subject));
            }
            continue;
        }
        match record.evidence.status {
            EpistemicStatus::Observed => {
                direct.insert(record.handle.clone());
                current.push(record);
            }
            EpistemicStatus::Supported | EpistemicStatus::Verified => {
                supporting.insert(record.handle.clone());
                current.push(record);
            }
            EpistemicStatus::Contested => {
                rivals.insert(record.handle.clone());
                current.push(record);
            }
            EpistemicStatus::Stale => {
                stale.insert(record.handle.clone());
                inquiries.insert(format!("revalidate {}", record.handle));
            }
            EpistemicStatus::Superseded => {
                superseded.insert(record.handle.clone());
            }
            EpistemicStatus::Rejected => {
                rivals.insert(record.handle.clone());
                inquiries.insert(format!("reassess rejected {}", record.handle));
            }
            EpistemicStatus::Unknown => {
                unknowns.insert(record.subject.clone());
                inquiries.insert(format!("obtain evidence for {}", record.subject));
            }
        }
    }
    if current.is_empty() {
        unknowns.insert(request.question.clone());
    }
    let position_state = if !rivals.is_empty() {
        PositionState::Conflicted
    } else if !supporting.is_empty() {
        PositionState::Supported
    } else if !direct.is_empty() {
        PositionState::Observed
    } else if !stale.is_empty() {
        PositionState::Stale
    } else {
        PositionState::Unknown
    };
    if matches!(
        position_state,
        PositionState::Conflicted | PositionState::Stale | PositionState::Unknown
    ) {
        inquiries.insert("perform the cheapest discriminative inquiry".to_owned());
    }
    let provenance = provenance_for(&request.records);
    Ok(CurrentEpistemicPosition {
        question: request.question.clone(),
        scope: request.scope.clone(),
        state_fence: request.state_fence.clone(),
        state: position_state,
        direct_observations: direct.into_iter().collect(),
        supporting_records: supporting.into_iter().collect(),
        rival_records: rivals.into_iter().collect(),
        stale_records: stale.into_iter().collect(),
        superseded_records: superseded.into_iter().collect(),
        unknowns: unknowns.into_iter().collect(),
        required_inquiry: inquiries.into_iter().collect(),
        provenance,
    })
}

fn provenance_for(records: &[EpistemicRecord]) -> ProvenanceView {
    // Every admitted record remains addressable, including unknown and stale
    // evidence that cannot promote the current position.
    let selected: BTreeSet<_> = records.iter().map(|record| record.handle.clone()).collect();
    let mut sources = BTreeSet::new();
    let mut raw = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    let mut assertability = Assertability::Assertable;
    for record in records.iter().filter(|r| selected.contains(&r.handle)) {
        sources.insert(record.evidence.provenance.source_id.to_string());
        if let Some(value) = &record.evidence.provenance.raw_handle {
            raw.insert(value.clone());
        }
        if let Some(value) = &record.evidence.provenance.revision {
            revisions.insert(value.clone());
        }
        assertability = lowest_assertability(assertability, record.evidence.assertability);
    }
    let mixed_sources = sources.len() > 1;
    ProvenanceView {
        record_handles: selected.into_iter().collect(),
        source_ids: sources.into_iter().collect(),
        raw_handles: raw.into_iter().collect(),
        revisions: revisions.into_iter().collect(),
        mixed_sources,
        assertability,
    }
}

fn lowest_assertability(left: Assertability, right: Assertability) -> Assertability {
    match (left, right) {
        (Assertability::AbstainOrFence, _) | (_, Assertability::AbstainOrFence) => {
            Assertability::AbstainOrFence
        }
        (Assertability::NonAssertableUnverified, _)
        | (_, Assertability::NonAssertableUnverified) => Assertability::NonAssertableUnverified,
        _ => Assertability::Assertable,
    }
}
