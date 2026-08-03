use super::{ActivationEngine, ProjectSnapshot};
use crate::EngineError;
use eliot_types::{
    ActivationTrace, CueKind, ObservedCue, PendingInjectionItem, SessionId, TaskId,
    UlInjectionMode, WriteId, ul_token_estimate,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const MAX_LINE_BYTES: usize = 160;
const MAX_PAYLOAD_UNITS: u32 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InjectionSelectionPolicy {
    pub max_items: usize,
    pub max_token_units: u32,
    /// Compatibility seam only; B1 applies no record-kind-specific payload cap.
    pub max_negative_payloads: usize,
}

impl Default for InjectionSelectionPolicy {
    fn default() -> Self {
        Self {
            max_items: 3,
            max_token_units: 400,
            max_negative_payloads: 3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InjectionPlan {
    pub direct_firing: super::FiringResult,
    pub activation_trace: Option<ActivationTrace>,
    pub items: Vec<PendingInjectionItem>,
    pub overflow: usize,
}

#[derive(Clone, Debug, Default)]
pub struct InjectionSelection {
    pub items: Vec<PendingInjectionItem>,
    pub overflow: usize,
    pub token_units: u32,
}

/// Stateless, synchronous planner over immutable project snapshots.
pub struct InjectionPlanner;

impl InjectionPlanner {
    pub fn plan(
        snapshot: &ProjectSnapshot,
        activation: &ActivationEngine,
        session_id: SessionId,
        task_id: Option<TaskId>,
        observed_cues: &[ObservedCue],
    ) -> Result<InjectionPlan, EngineError> {
        let firing = snapshot.cue_projection().fire(observed_cues);
        let mut items = Vec::new();
        let mut seed_refs = BTreeSet::new();
        for fired in &firing.fired {
            let Some(record) = snapshot.record(&fired.record_ref) else {
                continue;
            };
            seed_refs.insert(fired.record_ref.clone());
            seed_refs.extend(fired.fired_cues.iter().filter_map(canonical_cue_ref));
            items.push(record.pending_item(fired.fired_cues.clone(), None, None));
        }
        let seed_refs = seed_refs.into_iter().collect::<Vec<_>>();
        let activation_trace = activation.plan(
            snapshot.project_id(),
            session_id,
            task_id,
            &seed_refs,
            snapshot.activation_projection(),
        )?;
        if let Some(trace) = activation_trace.as_ref() {
            for node in &trace.activated {
                for record_ref in snapshot.record_refs_for_activation_node(&node.node_ref) {
                    let Some(record) = snapshot.record(record_ref) else {
                        continue;
                    };
                    items.push(record.pending_item(
                        Vec::new(),
                        Some(format!("activation:{}", trace.trace_id)),
                        Some(node.score_milli),
                    ));
                }
            }
        }
        let mut deduped = BTreeMap::<(String, String), PendingInjectionItem>::new();
        for item in items {
            let key = (item.item_ref.clone(), item.source_fingerprint.clone());
            let replace = deduped.get(&key).is_none_or(|current| {
                current.activation_trace_ref.is_some() && item.activation_trace_ref.is_none()
            });
            if replace {
                deduped.insert(key, item);
            }
        }
        let mut items = deduped.into_values().collect::<Vec<_>>();
        items.sort_by(compare_pending);
        Ok(InjectionPlan {
            direct_firing: firing.clone(),
            activation_trace,
            overflow: firing.overflow,
            items,
        })
    }

    pub fn select(
        snapshot: &ProjectSnapshot,
        pending: &[PendingInjectionItem],
        delivered: &BTreeMap<String, String>,
        mode: UlInjectionMode,
        policy: InjectionSelectionPolicy,
    ) -> Result<InjectionSelection, EngineError> {
        let mut candidates = pending
            .iter()
            .filter(|item| {
                snapshot.record(&item.item_ref).is_some_and(|record| {
                    record.source_fingerprint == item.source_fingerprint
                        && delivered
                            .get(&item.item_ref)
                            .is_none_or(|fingerprint| fingerprint != &item.source_fingerprint)
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by(compare_pending);
        let mut selection = InjectionSelection::default();
        for mut item in candidates {
            if selection.items.len() >= policy.max_items {
                selection.overflow = selection.overflow.saturating_add(1);
                continue;
            }
            item.preview = truncate_utf8(item.preview.trim(), MAX_LINE_BYTES);
            item.payload = match mode {
                UlInjectionMode::Payload => item.payload,
                UlInjectionMode::HandlesOnly => None,
            };
            let mut payload_units = item
                .payload
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?
                .map_or(0, |payload| ul_token_estimate(&payload));
            if payload_units > MAX_PAYLOAD_UNITS {
                item.payload = None;
                payload_units = 0;
            }
            let token_units = ul_token_estimate(&item.preview).saturating_add(payload_units);
            if selection.token_units.saturating_add(token_units) > policy.max_token_units {
                selection.overflow = selection.overflow.saturating_add(1);
                continue;
            }
            item.token_estimate = token_units;
            selection.token_units = selection.token_units.saturating_add(token_units);
            selection.items.push(item);
        }
        Ok(selection)
    }
}

fn canonical_cue_ref(cue: &ObservedCue) -> Option<String> {
    match cue.kind {
        CueKind::FilePath => Some(format!("file:{}", cue.value)),
        CueKind::DirPath => Some(format!("dir:{}", cue.value)),
        CueKind::Symbol => Some(format!("symbol:{}", cue.value)),
        CueKind::Dependency => Some(format!("dependency:{}", cue.value)),
        CueKind::ApiSurface => Some(format!("api:{}", cue.value)),
        CueKind::Subsystem => Some(format!("subsystem:{}", cue.value)),
        CueKind::Concept => Some(format!("concept:{}", cue.value)),
        CueKind::CommandPattern | CueKind::ErrorSignature | CueKind::TaskClass => None,
    }
}

fn compare_pending(left: &PendingInjectionItem, right: &PendingInjectionItem) -> Ordering {
    pending_rank(left)
        .cmp(&pending_rank(right))
        .then_with(|| {
            left.activation_trace_ref
                .is_some()
                .cmp(&right.activation_trace_ref.is_some())
        })
        .then_with(|| {
            right
                .activation_score_milli
                .cmp(&left.activation_score_milli)
        })
        .then_with(|| left.item_ref.cmp(&right.item_ref))
        .then_with(|| left.source_fingerprint.cmp(&right.source_fingerprint))
}

fn pending_rank(item: &PendingInjectionItem) -> u8 {
    if item.negative_memory {
        return 0;
    }
    if item.invariant {
        return 1;
    }
    match item.record_kind.as_str() {
        "decision" => 2,
        "module_card" => 3,
        "claim" => 4,
        "experience_case" => 5,
        "skill" => 6,
        "subsystem_capsule" => 7,
        _ => 8,
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value[..boundary].to_owned()
}

#[must_use]
pub fn deterministic_write_id(key: &str) -> WriteId {
    let digest = blake3::hash(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(Uuid::from_bytes(bytes))
}
