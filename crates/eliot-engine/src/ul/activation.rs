use crate::EngineError;
use eliot_types::{
    ACTIVATION_SCALE, ACTIVATION_THRESHOLD, ActivationEdgeKind, ActivationNode, ActivationTrace,
    ProjectId, SessionId, SuppressedActivation, TaskId, UlActivationGraphRows,
};
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::Arc;
use uuid::Uuid;

const DEPTH_LIMIT: u8 = 2;
const FANOUT_CAP: usize = 20;
const MAX_ACTIVATED: usize = 128;
const MAX_SUPPRESSED: usize = 256;
pub const DEFAULT_ACTIVATION_ENABLE_MIN_EDGES: u32 = 500;

/// Immutable, store-free activation projection prepared by the background coordinator.
#[derive(Clone, Debug)]
pub struct ActivationProjection {
    enabled_edge_count: u32,
    adjacency: Arc<BTreeMap<String, Vec<WeightedEdge>>>,
    estimated_bytes: usize,
}

impl ActivationProjection {
    #[must_use]
    pub fn from_graph(graph: &UlActivationGraphRows) -> Self {
        let (adjacency, enabled_edge_count) = weighted_adjacency(graph);
        let estimated_bytes = adjacency
            .iter()
            .map(|(from, edges)| {
                ACTIVATION_MAP_ENTRY_OVERHEAD_BYTES
                    .saturating_add(size_of::<(String, Vec<WeightedEdge>)>())
                    .saturating_add(from.capacity())
                    .saturating_add(ACTIVATION_ALLOCATION_OVERHEAD_BYTES)
                    .saturating_add(
                        edges
                            .capacity()
                            .saturating_mul(size_of::<WeightedEdge>())
                            .saturating_add(ACTIVATION_ALLOCATION_OVERHEAD_BYTES),
                    )
                    .saturating_add(edges.iter().fold(0_usize, |total, edge| {
                        total
                            .saturating_add(edge.to_ref.capacity())
                            .saturating_add(ACTIVATION_ALLOCATION_OVERHEAD_BYTES)
                    }))
            })
            .fold(
                size_of::<ActivationProjection>()
                    .saturating_add(ACTIVATION_ALLOCATION_OVERHEAD_BYTES),
                usize::saturating_add,
            );
        Self {
            enabled_edge_count,
            adjacency: Arc::new(adjacency),
            estimated_bytes,
        }
    }

    #[must_use]
    pub const fn enabled_edge_count(&self) -> u32 {
        self.enabled_edge_count
    }

    #[must_use]
    pub const fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }
}

const ACTIVATION_ALLOCATION_OVERHEAD_BYTES: usize = 32;
const ACTIVATION_MAP_ENTRY_OVERHEAD_BYTES: usize = 256;

impl Default for ActivationProjection {
    fn default() -> Self {
        Self::from_graph(&UlActivationGraphRows::default())
    }
}

/// Pure activation planner. Persistence of the returned trace belongs to the coordinator.
#[derive(Clone, Copy, Debug)]
pub struct ActivationEngine {
    enable_min_edges: u32,
}

impl ActivationEngine {
    #[must_use]
    pub const fn new(enable_min_edges: u32) -> Self {
        Self { enable_min_edges }
    }

    #[must_use]
    pub const fn spread_enabled(&self, projection: &ActivationProjection) -> bool {
        projection.enabled_edge_count >= self.enable_min_edges
    }

    pub fn plan(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        task_id: Option<TaskId>,
        seed_refs: &[String],
        projection: &ActivationProjection,
    ) -> Result<Option<ActivationTrace>, EngineError> {
        if !self.spread_enabled(projection) {
            return Ok(None);
        }
        Self::compute_projection(project_id, session_id, task_id, seed_refs, projection).map(Some)
    }

    pub fn compute(
        project_id: ProjectId,
        session_id: SessionId,
        task_id: Option<TaskId>,
        seed_refs: &[String],
        graph: &UlActivationGraphRows,
    ) -> Result<ActivationTrace, EngineError> {
        let projection = ActivationProjection::from_graph(graph);
        Self::compute_projection(project_id, session_id, task_id, seed_refs, &projection)
    }

    pub fn compute_projection(
        project_id: ProjectId,
        session_id: SessionId,
        task_id: Option<TaskId>,
        seed_refs: &[String],
        projection: &ActivationProjection,
    ) -> Result<ActivationTrace, EngineError> {
        let mut seeds = seed_refs
            .iter()
            .map(|seed| seed.trim().to_owned())
            .filter(|seed| !seed.is_empty())
            .collect::<Vec<_>>();
        seeds.sort();
        seeds.dedup();
        let seed_set = seeds.iter().cloned().collect::<BTreeSet<_>>();
        let (activated, suppressed) =
            propagate_activation(&seeds, &seed_set, &projection.adjacency);

        let identity = serde_json::to_vec(&(
            project_id,
            session_id,
            task_id,
            &seeds,
            projection.enabled_edge_count,
            &activated,
            &suppressed,
        ))?;
        let trace_id = deterministic_uuid(&identity).to_string();
        Ok(ActivationTrace {
            trace_id,
            project_id,
            session_id,
            task_id,
            seed_refs: seeds,
            enabled_edge_count: projection.enabled_edge_count,
            depth_limit: DEPTH_LIMIT,
            fanout_cap: u8::try_from(FANOUT_CAP).unwrap_or(u8::MAX),
            threshold_milli: ACTIVATION_THRESHOLD,
            activated,
            suppressed,
        })
    }
}

impl Default for ActivationEngine {
    fn default() -> Self {
        Self::new(DEFAULT_ACTIVATION_ENABLE_MIN_EDGES)
    }
}

#[derive(Clone, Debug)]
struct WeightedEdge {
    to_ref: String,
    kind: ActivationEdgeKind,
    weight_milli: u16,
}

fn propagate_activation(
    seeds: &[String],
    seed_set: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<WeightedEdge>>,
) -> (Vec<ActivationNode>, Vec<SuppressedActivation>) {
    let mut activated = BTreeMap::<String, ActivationNode>::new();
    let mut suppressed = BTreeMap::<(String, String), SuppressedActivation>::new();
    let mut frontier = seeds
        .iter()
        .map(|seed| {
            (
                seed.clone(),
                ActivationNode {
                    node_ref: seed.clone(),
                    score_milli: ACTIVATION_SCALE,
                    depth: 0,
                    via: vec![seed.clone()],
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for depth in 1..=DEPTH_LIMIT {
        frontier = propagate_frontier(
            depth,
            &frontier,
            seed_set,
            adjacency,
            &mut activated,
            &mut suppressed,
        );
    }
    let mut activated = activated.into_values().collect::<Vec<_>>();
    activated.sort_by(|left, right| {
        right
            .score_milli
            .cmp(&left.score_milli)
            .then_with(|| left.depth.cmp(&right.depth))
            .then_with(|| left.node_ref.cmp(&right.node_ref))
    });
    if activated.len() > MAX_ACTIVATED {
        for node in activated.drain(MAX_ACTIVATED..) {
            record_suppressed(
                &mut suppressed,
                node.node_ref,
                node.score_milli,
                "activated_cap",
            );
        }
    }
    let mut suppressed = suppressed.into_values().collect::<Vec<_>>();
    suppressed.sort_by(|left, right| {
        right
            .score_milli
            .cmp(&left.score_milli)
            .then_with(|| left.node_ref.cmp(&right.node_ref))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    suppressed.truncate(MAX_SUPPRESSED);
    (activated, suppressed)
}

fn propagate_frontier(
    depth: u8,
    frontier: &BTreeMap<String, ActivationNode>,
    seed_set: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<WeightedEdge>>,
    activated: &mut BTreeMap<String, ActivationNode>,
    suppressed: &mut BTreeMap<(String, String), SuppressedActivation>,
) -> BTreeMap<String, ActivationNode> {
    let mut next = BTreeMap::<String, ActivationNode>::new();
    for parent in frontier.values() {
        let edges = adjacency
            .get(&parent.node_ref)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for edge in edges.iter().skip(FANOUT_CAP) {
            record_suppressed(
                suppressed,
                edge.to_ref.clone(),
                propagated_score(parent.score_milli, edge.weight_milli, depth),
                "fanout_cap",
            );
        }
        for edge in edges.iter().take(FANOUT_CAP) {
            let score = propagated_score(parent.score_milli, edge.weight_milli, depth);
            if seed_set.contains(&edge.to_ref) {
                continue;
            }
            if score < ACTIVATION_THRESHOLD {
                record_suppressed(suppressed, edge.to_ref.clone(), score, "below_threshold");
                continue;
            }
            let mut via = parent.via.clone();
            via.push(format!("{:?}:{}", edge.kind, edge.weight_milli));
            via.push(edge.to_ref.clone());
            let candidate = ActivationNode {
                node_ref: edge.to_ref.clone(),
                score_milli: score,
                depth,
                via,
            };
            upsert_max(&mut next, candidate.clone());
            upsert_max(activated, candidate);
        }
    }
    next
}

fn weighted_adjacency(graph: &UlActivationGraphRows) -> (BTreeMap<String, Vec<WeightedEdge>>, u32) {
    let mut adjacency = BTreeMap::<String, Vec<WeightedEdge>>::new();
    for relation in &graph.relations {
        add_bidirectional(
            &mut adjacency,
            &relation.from_ref,
            &relation.to_ref,
            relation.kind,
            relation_weight(relation.kind),
        );
    }
    for edge in &graph.co_change {
        add_directed(
            &mut adjacency,
            &format!("file:{}", edge.path_a),
            &format!("file:{}", edge.path_b),
            ActivationEdgeKind::CoChange,
            co_change_weight(edge.confidence_ab),
        );
        add_directed(
            &mut adjacency,
            &format!("file:{}", edge.path_b),
            &format!("file:{}", edge.path_a),
            ActivationEdgeKind::CoChange,
            co_change_weight(edge.confidence_ba),
        );
        if edge.static_edge_exists == Some(true) {
            add_bidirectional(
                &mut adjacency,
                &format!("file:{}", edge.path_a),
                &format!("file:{}", edge.path_b),
                ActivationEdgeKind::StaticDependency,
                500,
            );
        }
    }
    for edges in adjacency.values_mut() {
        edges.sort_by(|left, right| {
            right
                .weight_milli
                .cmp(&left.weight_milli)
                .then_with(|| left.to_ref.cmp(&right.to_ref))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        edges.dedup_by(|left, right| {
            left.to_ref == right.to_ref
                && left.kind == right.kind
                && left.weight_milli == right.weight_milli
        });
    }
    let enabled_edge_count =
        u32::try_from(graph.relations.len().saturating_add(graph.co_change.len()))
            .unwrap_or(u32::MAX);
    (adjacency, enabled_edge_count)
}

fn relation_weight(kind: ActivationEdgeKind) -> u16 {
    match kind {
        ActivationEdgeKind::CardCovers | ActivationEdgeKind::CapsuleCovers => 900,
        ActivationEdgeKind::ConceptImplementedBy => 800,
        ActivationEdgeKind::CoChange => 700,
        ActivationEdgeKind::StaticDependency => 500,
        ActivationEdgeKind::ConceptDependsOn => 600,
        ActivationEdgeKind::Supports | ActivationEdgeKind::VerifiedBy => 400,
    }
}

fn co_change_weight(confidence: f64) -> u16 {
    let bounded = if confidence.is_finite() {
        confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (700.0 * bounded).floor() as u16
    }
}

fn propagated_score(parent: u16, weight: u16, depth: u8) -> u16 {
    let numerator = u32::from(parent).saturating_mul(u32::from(weight));
    let score = if depth == 1 {
        numerator / u32::from(ACTIVATION_SCALE)
    } else {
        numerator.saturating_mul(500) / 1_000_000
    };
    u16::try_from(score).unwrap_or(u16::MAX)
}

fn add_bidirectional(
    adjacency: &mut BTreeMap<String, Vec<WeightedEdge>>,
    from: &str,
    to: &str,
    kind: ActivationEdgeKind,
    weight_milli: u16,
) {
    add_directed(adjacency, from, to, kind, weight_milli);
    add_directed(adjacency, to, from, kind, weight_milli);
}

fn add_directed(
    adjacency: &mut BTreeMap<String, Vec<WeightedEdge>>,
    from: &str,
    to: &str,
    kind: ActivationEdgeKind,
    weight_milli: u16,
) {
    adjacency
        .entry(from.to_owned())
        .or_default()
        .push(WeightedEdge {
            to_ref: to.to_owned(),
            kind,
            weight_milli,
        });
}

fn upsert_max(nodes: &mut BTreeMap<String, ActivationNode>, candidate: ActivationNode) {
    if nodes.get(&candidate.node_ref).is_none_or(|current| {
        candidate.score_milli > current.score_milli
            || (candidate.score_milli == current.score_milli
                && (candidate.depth, &candidate.via) < (current.depth, &current.via))
    }) {
        nodes.insert(candidate.node_ref.clone(), candidate);
    }
}

fn record_suppressed(
    suppressed: &mut BTreeMap<(String, String), SuppressedActivation>,
    node_ref: String,
    score_milli: u16,
    reason: &str,
) {
    let key = (node_ref.clone(), reason.to_owned());
    if suppressed
        .get(&key)
        .is_none_or(|current| score_milli > current.score_milli)
    {
        suppressed.insert(
            key,
            SuppressedActivation {
                node_ref,
                score_milli,
                reason: reason.to_owned(),
            },
        );
    }
}

fn deterministic_uuid(bytes: &[u8]) -> Uuid {
    let digest = blake3::hash(bytes);
    let mut value = [0_u8; 16];
    value.copy_from_slice(&digest.as_bytes()[..16]);
    value[6] = (value[6] & 0x0f) | 0x50;
    value[8] = (value[8] & 0x3f) | 0x80;
    Uuid::from_bytes(value)
}
