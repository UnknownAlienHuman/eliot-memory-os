use crate::EngineError;
use eliot_types::{
    CoChangeEdge, CueBinding, CueKind, CueMatchMode, CueStrength, HotspotScore, ModuleCard,
    ProjectId, ul_token_estimate,
};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const MAX_CARDS_PER_SEGMENT: usize = 5;
const MAX_CO_CHANGE_PARTNERS: usize = 3;
const MAX_PURPOSE_BYTES: usize = 120;
const MAX_CARD_TOKEN_UNITS: u32 = 200;
const EXPECTED_REUSE_NOTE: &str = "when editing this module or investigating its failures";

#[derive(Clone, Debug, Default)]
pub struct ModuleCardService;

impl ModuleCardService {
    pub fn build(
        project_id: ProjectId,
        project_root: &Path,
        hotspots: &[HotspotScore],
        edges: &[CoChangeEdge],
        failure_refs_by_path: &BTreeMap<String, Vec<String>>,
        exact_verifiers: &BTreeMap<String, String>,
    ) -> Result<Vec<ModuleCard>, EngineError> {
        let mut groups = BTreeMap::<String, Vec<&HotspotScore>>::new();
        for hotspot in hotspots {
            groups
                .entry(first_path_segment(&hotspot.path))
                .or_default()
                .push(hotspot);
        }

        let mut selected = Vec::new();
        for group in groups.values_mut() {
            group.sort_by(|left, right| {
                right
                    .score
                    .cmp(&left.score)
                    .then_with(|| right.touches.cmp(&left.touches))
                    .then_with(|| left.path.cmp(&right.path))
            });
            selected.extend(group.iter().take(MAX_CARDS_PER_SEGMENT).copied());
        }
        selected.sort_by(|left, right| left.path.cmp(&right.path));

        let mut cards = selected
            .into_iter()
            .map(|hotspot| {
                Self::build_one(
                    project_id,
                    project_root,
                    hotspot,
                    edges,
                    failure_refs_by_path,
                    exact_verifiers,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        cards.sort_by(|left, right| left.card_id.cmp(&right.card_id));
        Ok(cards)
    }

    fn build_one(
        project_id: ProjectId,
        project_root: &Path,
        hotspot: &HotspotScore,
        edges: &[CoChangeEdge],
        failure_refs_by_path: &BTreeMap<String, Vec<String>>,
        exact_verifiers: &BTreeMap<String, String>,
    ) -> Result<ModuleCard, EngineError> {
        let path = hotspot.path.clone();
        let verifier = verifier_for_path(&path, exact_verifiers);
        let (purpose, source_ref) = source_purpose(project_root, &path);
        let source_refs = source_ref.into_iter().collect::<Vec<_>>();

        let mut couplings = edges
            .iter()
            .filter_map(|edge| coupling_for_path(edge, &path))
            .collect::<Vec<_>>();
        couplings.sort_by(compare_couplings);
        couplings.truncate(MAX_CO_CHANGE_PARTNERS);

        let mut failure_refs = failure_refs_by_path.get(&path).cloned().unwrap_or_default();
        failure_refs.sort();
        failure_refs.dedup();

        let body_md = bounded_body(&purpose, hotspot, &couplings, &failure_refs, &verifier)?;
        let co_change_refs = couplings
            .iter()
            .map(|coupling| coupling.edge_id.clone())
            .collect::<Vec<_>>();
        let mut cue_bindings = vec![file_binding(&path, CueStrength::Primary)];
        cue_bindings.extend(
            couplings
                .iter()
                .map(|coupling| file_binding(&coupling.partner, CueStrength::Secondary)),
        );

        let fingerprint_material = json!({
            "project_id": project_id,
            "path": path,
            "body_md": body_md,
            "verifier": verifier,
            "hotspot_ref": hotspot.hotspot_id,
            "co_change_refs": co_change_refs,
            "failure_refs": failure_refs,
            "source_refs": source_refs,
            "cue_bindings": cue_bindings,
        });
        let build_fingerprint = blake3::hash(&serde_json::to_vec(&fingerprint_material)?)
            .to_hex()
            .to_string();
        let card_id = format!("module-card-{build_fingerprint}");
        Ok(ModuleCard {
            card_id,
            project_id,
            path,
            body_md,
            verifier,
            hotspot_ref: Some(hotspot.hotspot_id.clone()),
            co_change_refs,
            failure_refs,
            source_refs,
            cue_bindings,
            build_fingerprint,
        })
    }
}

#[derive(Clone, Debug)]
struct Coupling {
    partner: String,
    confidence: f64,
    edge_id: String,
}

fn coupling_for_path(edge: &CoChangeEdge, path: &str) -> Option<Coupling> {
    if edge.path_a == path {
        Some(Coupling {
            partner: edge.path_b.clone(),
            confidence: edge.confidence_ab,
            edge_id: edge.edge_id.clone(),
        })
    } else if edge.path_b == path {
        Some(Coupling {
            partner: edge.path_a.clone(),
            confidence: edge.confidence_ba,
            edge_id: edge.edge_id.clone(),
        })
    } else {
        None
    }
}

fn compare_couplings(left: &Coupling, right: &Coupling) -> Ordering {
    right
        .confidence
        .total_cmp(&left.confidence)
        .then_with(|| left.partner.cmp(&right.partner))
        .then_with(|| left.edge_id.cmp(&right.edge_id))
}

fn bounded_body(
    purpose: &str,
    hotspot: &HotspotScore,
    couplings: &[Coupling],
    failure_refs: &[String],
    verifier: &str,
) -> Result<String, EngineError> {
    let mut visible_couplings = couplings.to_vec();
    let mut visible_failures = failure_refs.to_vec();
    loop {
        let body = render_body(
            purpose,
            hotspot,
            &visible_couplings,
            &visible_failures,
            verifier,
        );
        if ul_token_estimate(&body) <= MAX_CARD_TOKEN_UNITS {
            return Ok(body);
        }
        if visible_failures.pop().is_some() {
            continue;
        }
        if visible_couplings.pop().is_some() {
            continue;
        }
        return Err(EngineError::WriteRejected(format!(
            "module card for {} exceeds {MAX_CARD_TOKEN_UNITS} UL token units",
            hotspot.path
        )));
    }
}

fn render_body(
    purpose: &str,
    hotspot: &HotspotScore,
    couplings: &[Coupling],
    failure_refs: &[String],
    verifier: &str,
) -> String {
    let coupling_text = if couplings.is_empty() {
        "none observed".to_owned()
    } else {
        couplings
            .iter()
            .map(|coupling| format!("{}({:.2})", coupling.partner, coupling.confidence))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let failure_text = if failure_refs.is_empty() {
        "none recorded".to_owned()
    } else {
        failure_refs.join(", ")
    };
    format!(
        "PURPOSE: {purpose}\nHOTSPOT: {}/100; {} touches; {} fix-classified.\nHIDDEN COUPLING: {coupling_text}.\nKNOWN FAILURES: {failure_text}.\nVERIFY: {verifier}.",
        hotspot.score, hotspot.touches, hotspot.fix_touches
    )
}

fn verifier_for_path(path: &str, exact_verifiers: &BTreeMap<String, String>) -> String {
    let mut parts = path.split('/');
    if parts.next() == Some("crates")
        && let Some(name) = parts.next()
        && !name.is_empty()
    {
        return format!("cargo test -p {name}");
    }
    exact_verifiers
        .get(path)
        .cloned()
        .unwrap_or_else(|| "cargo test --workspace".to_owned())
}

fn source_purpose(project_root: &Path, path: &str) -> (String, Option<String>) {
    let fallback = format!("Owns behavior implemented at `{path}`.");
    let Ok(source) = fs::read_to_string(project_root.join(path)) else {
        return (fallback, None);
    };
    let mut text = String::new();
    let mut started = false;
    for line in source.lines() {
        let trimmed = line.trim_start().trim_start_matches('\u{feff}');
        let Some(comment) = trimmed
            .strip_prefix("//!")
            .or_else(|| trimmed.strip_prefix("///"))
        else {
            if started || !trimmed.is_empty() {
                break;
            }
            continue;
        };
        started = true;
        let comment = comment.trim();
        if !comment.is_empty() {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(comment);
        }
    }
    let sentence = first_sentence(&text);
    if sentence.is_empty() {
        (fallback, None)
    } else {
        (
            truncate_utf8(sentence, MAX_PURPOSE_BYTES),
            Some(format!("file:{path}:module-doc")),
        )
    }
}

fn first_sentence(value: &str) -> &str {
    let trimmed = value.trim();
    trimmed
        .char_indices()
        .find(|(_, character)| matches!(character, '.' | '!' | '?'))
        .map_or(trimmed, |(index, character)| {
            &trimmed[..index + character.len_utf8()]
        })
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value[..boundary].trim_end().to_owned()
}

fn first_path_segment(path: &str) -> String {
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.first() == Some(&"crates") && parts.len() >= 2 {
        format!("crates/{}", parts[1])
    } else {
        parts.first().copied().unwrap_or_default().to_owned()
    }
}

fn file_binding(path: &str, strength: CueStrength) -> CueBinding {
    CueBinding {
        cue_kind: CueKind::FilePath,
        cue_value: path.to_owned(),
        match_mode: CueMatchMode::Exact,
        strength,
        expected_reuse_note: EXPECTED_REUSE_NOTE.to_owned(),
    }
}

#[must_use]
pub fn failure_bindings_by_path(
    sources: &[eliot_types::CueRecordSource],
) -> BTreeMap<String, Vec<String>> {
    let mut failures = BTreeMap::<String, BTreeSet<String>>::new();
    for source in sources.iter().filter(|source| source.negative_memory) {
        for binding in &source.cue_bindings {
            if binding.cue_kind == CueKind::FilePath {
                failures
                    .entry(binding.cue_value.clone())
                    .or_default()
                    .insert(source.record_ref.clone());
            }
        }
    }
    failures
        .into_iter()
        .map(|(path, refs)| (path, refs.into_iter().collect()))
        .collect()
}
