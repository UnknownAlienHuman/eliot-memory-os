//! Explicit, immutable limits and semantic requirements for relation handling.

use eliot_dreamer_contracts::{ExternalGradeRef, RelationFamily, RelationInput, RelationPredicate};
use eliot_dreamer_contracts::{canonical_bytes, digest_hex};
use eliot_epistemic_contracts::CausalClaim;
use eliot_epistemic_contracts::{EvidenceGrade, GradeAssignment};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;
const MAX_TEXT: usize = 256;

/// Semantic role of a typed evidence binding.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceBindingKind {
    Mechanism,
    Intervention,
    Outcome,
    Control,
    Rival,
    Confounder,
    Discriminator,
    TransitivePath,
}

/// A typed reference into the supplied relation evidence set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBinding {
    pub evidence_id: String,
    pub kind: EvidenceBindingKind,
    /// Human-readable factual assertion, bound to the evidence predicate
    /// expression and (where applicable) a canonical claim field.
    pub fact: String,
    /// Exact alternative identity for rival facts.  Primary facts leave this
    /// unset; an alternative id is never inferred from an artifact id.
    pub alternative_id: Option<String>,
    pub grade: GradeAssignment,
}

/// The exact C1 grade assignment retained by one named relation evidence item.
/// The external reference is data supplied by the caller; its digest is checked
/// against this complete binding before the assignment can qualify evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGradeBinding {
    pub evidence_id: String,
    pub reference: ExternalGradeRef,
    pub assignment: GradeAssignment,
}

/// Explicit source/proof handles used to qualify a canonical causal claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CausalMaterialBinding {
    pub source_handle: String,
    pub proof_handle: String,
}

/// Explicit proposition and predicate mapping for a canonical causal claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CausalPredicateBinding {
    pub subject: String,
    pub predicate: RelationPredicate,
}

/// One ordered, caller-supplied transitive edge reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathRef {
    pub edge_id: String,
    pub relation_digest: String,
}

/// Explicit relation policy; it carries no authority and performs no I/O.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_revision: u64,
    pub digest: String,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_evidence: u32,
    pub max_rivals: u32,
    pub max_neighborhood: u32,
    pub max_work: u64,
    pub max_stu: u64,
    pub required_grade: EvidenceGrade,
    pub maximum_grade: EvidenceGrade,
    pub grade_bindings: Vec<EvidenceGradeBinding>,
    pub causal_bindings: Vec<EvidenceBinding>,
    pub causal_claim: Option<CausalClaim>,
    pub causal_material: Option<CausalMaterialBinding>,
    pub causal_predicate: Option<CausalPredicateBinding>,
    pub proposed_snapshot: Option<eliot_dreamer_contracts::RelationSnapshot>,
    pub expected_alternative_refs: Vec<String>,
    pub omitted_alternative_refs: Vec<String>,
    pub transitive_path: Vec<PathRef>,
    pub temporal_required: bool,
    pub max_uncertainty_ms: u64,
    pub max_path_hops: u32,
    pub cancellation_requested: bool,
    pub clock_ref: Option<String>,
    pub now_ms: Option<i64>,
    pub deadline_ms: Option<i64>,
}

#[derive(Serialize)]
struct PolicyPreimage<'a> {
    schema_version: u32,
    policy_id: &'a str,
    policy_revision: u64,
    max_input_bytes: u64,
    max_output_bytes: u64,
    max_evidence: u32,
    max_rivals: u32,
    max_neighborhood: u32,
    max_work: u64,
    max_stu: u64,
    required_grade: EvidenceGrade,
    maximum_grade: EvidenceGrade,
    grade_bindings: &'a [EvidenceGradeBinding],
    causal_bindings: &'a [EvidenceBinding],
    causal_claim: &'a Option<CausalClaim>,
    causal_material: &'a Option<CausalMaterialBinding>,
    causal_predicate: &'a Option<CausalPredicateBinding>,
    proposed_snapshot: &'a Option<eliot_dreamer_contracts::RelationSnapshot>,
    expected_alternative_refs: &'a [String],
    omitted_alternative_refs: &'a [String],
    transitive_path: &'a [PathRef],
    temporal_required: bool,
    max_uncertainty_ms: u64,
    max_path_hops: u32,
    cancellation_requested: bool,
    clock_ref: &'a Option<String>,
    now_ms: Option<i64>,
    deadline_ms: Option<i64>,
}

impl RelationPolicy {
    /// Creates a bounded policy whose digest is set by [`Self::seal`].
    #[must_use]
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            schema_version: VERSION,
            policy_id: policy_id.into(),
            policy_revision: 1,
            digest: String::new(),
            max_input_bytes: 4 * 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
            max_evidence: 256,
            max_rivals: 256,
            max_neighborhood: 256,
            max_work: 32 * 1024,
            max_stu: 4096,
            required_grade: EvidenceGrade::Grounded,
            maximum_grade: EvidenceGrade::ScienceGrade,
            grade_bindings: Vec::new(),
            causal_bindings: Vec::new(),
            causal_claim: None,
            causal_material: None,
            causal_predicate: None,
            proposed_snapshot: None,
            expected_alternative_refs: Vec::new(),
            omitted_alternative_refs: Vec::new(),
            transitive_path: Vec::new(),
            temporal_required: false,
            max_uncertainty_ms: u64::MAX,
            max_path_hops: 8,
            cancellation_requested: false,
            clock_ref: None,
            now_ms: None,
            deadline_ms: None,
        }
    }

    fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized
            .grade_bindings
            .sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        normalized.causal_bindings.sort_by(|left, right| {
            left.evidence_id
                .cmp(&right.evidence_id)
                .then_with(|| left.kind.cmp(&right.kind))
                .then_with(|| left.fact.cmp(&right.fact))
                .then_with(|| left.alternative_id.cmp(&right.alternative_id))
        });
        normalized.expected_alternative_refs.sort();
        normalized.omitted_alternative_refs.sort();
        normalized
    }

    fn preimage(&self) -> PolicyPreimage<'_> {
        PolicyPreimage {
            schema_version: self.schema_version,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            max_input_bytes: self.max_input_bytes,
            max_output_bytes: self.max_output_bytes,
            max_evidence: self.max_evidence,
            max_rivals: self.max_rivals,
            max_neighborhood: self.max_neighborhood,
            max_work: self.max_work,
            max_stu: self.max_stu,
            required_grade: self.required_grade,
            maximum_grade: self.maximum_grade,
            grade_bindings: &self.grade_bindings,
            causal_bindings: &self.causal_bindings,
            causal_claim: &self.causal_claim,
            causal_material: &self.causal_material,
            causal_predicate: &self.causal_predicate,
            proposed_snapshot: &self.proposed_snapshot,
            expected_alternative_refs: &self.expected_alternative_refs,
            omitted_alternative_refs: &self.omitted_alternative_refs,
            transitive_path: &self.transitive_path,
            temporal_required: self.temporal_required,
            max_uncertainty_ms: self.max_uncertainty_ms,
            max_path_hops: self.max_path_hops,
            cancellation_requested: self.cancellation_requested,
            clock_ref: &self.clock_ref,
            now_ms: self.now_ms,
            deadline_ms: self.deadline_ms,
        }
    }

    /// Computes the digest over policy fields excluding the digest itself.
    pub fn computed_digest(&self) -> Result<String, eliot_dreamer_contracts::ContractViolation> {
        self.preflight()?;
        let normalized = self.normalized();
        Ok(digest_hex(&canonical_bytes(&normalized.preimage())?))
    }

    /// Seals this policy for use at a handler boundary.
    pub fn seal(&mut self) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        self.preflight()?;
        self.digest = self.computed_digest()?;
        Ok(())
    }

    /// Borrows the whole policy through a capped serializer before any
    /// normalization or digest allocation is performed.
    pub fn preflight(&self) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
        struct CappedWriter {
            bytes: Vec<u8>,
            limit: usize,
        }
        impl std::io::Write for CappedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let remaining = self.limit.saturating_sub(self.bytes.len());
                let take = remaining.min(bytes.len());
                self.bytes.extend_from_slice(&bytes[..take]);
                if take < bytes.len() {
                    return Err(std::io::Error::other("serialization bound exceeded"));
                }
                Ok(take)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut writer = CappedWriter {
            bytes: Vec::new(),
            limit: MAX_POLICY_BYTES,
        };
        serde_json::to_writer(&mut writer, self).map_err(|_| {
            eliot_dreamer_contracts::ContractViolation::Malformed {
                field: "relation.policy.bytes",
                reason: "policy serialization failed".to_owned(),
            }
        })?;
        Ok(())
    }

    /// Validates bounds, time observations, binding shape and the policy digest.
    pub fn validate(&self) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        self.preflight()?;
        validate_policy_scalars(self)?;
        validate_policy_bindings(self)?;
        validate_policy_references(self)?;
        validate_policy_semantics(self)?;
        if !eliot_dreamer_contracts::error::is_hex64_lower(&self.digest)
            || self.computed_digest()? != self.digest
        {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.policy.digest",
                    reason: "policy digest does not cover policy fields".to_owned(),
                },
            );
        }
        Ok(())
    }

    /// Validates policy-specific input budgets before handler work begins.
    pub fn check_input(
        &self,
        input: &RelationInput,
    ) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        input.preflight()?;
        if !serialized_within(
            input,
            usize::try_from(self.max_input_bytes).unwrap_or(usize::MAX),
        )? {
            return Err(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.input.bytes",
                reason: "input exceeds policy byte bound".to_owned(),
            });
        }
        let rivals = u64::try_from(input.rivals.len()).map_err(|_| {
            eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.policy.input",
                reason: "rival count overflow".to_owned(),
            }
        })?;
        let neighborhood = u64::try_from(input.neighborhood.relations.len()).map_err(|_| {
            eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.policy.input",
                reason: "neighborhood count overflow".to_owned(),
            }
        })?;
        let evidence = u64::try_from(input.evidence.len()).map_err(|_| {
            eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.policy.input",
                reason: "evidence count overflow".to_owned(),
            }
        })?;
        let counterevidence = u64::try_from(input.counterevidence.len()).map_err(|_| {
            eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.policy.input",
                reason: "counterevidence count overflow".to_owned(),
            }
        })?;
        if rivals > u64::from(self.max_rivals)
            || neighborhood > u64::from(self.max_neighborhood)
            || evidence.checked_add(counterevidence).ok_or_else(|| {
                eliot_dreamer_contracts::ContractViolation::Budget {
                    dimension: "relation.policy.input",
                    reason: "evidence count overflow".to_owned(),
                }
            })? > u64::from(self.max_evidence)
        {
            return Err(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.policy.input",
                reason: "independent relation bound exceeded".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns true for causal families governed by the registry rule.
    #[must_use]
    pub fn is_causal(
        &self,
        family: RelationFamily,
        registry: &eliot_dreamer_contracts::RelationRegistrySnapshot,
    ) -> bool {
        family == RelationFamily::Causes
            || registry
                .rules
                .iter()
                .any(|r| r.family == family && r.requires_causal_mechanism)
    }
}

fn validate_policy_scalars(
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    use eliot_dreamer_contracts::error::check_text;
    if policy.schema_version != VERSION {
        return Err(eliot_dreamer_contracts::ContractViolation::OutOfBounds {
            field: "relation.policy.schema_version",
            min: 1,
            max: 1,
            got: i64::from(policy.schema_version),
        });
    }
    check_text(&policy.policy_id, "relation.policy.id", MAX_TEXT)?;
    if [
        policy.policy_revision == 0,
        policy.max_input_bytes == 0,
        policy.max_output_bytes == 0,
        policy.max_evidence == 0,
        policy.max_rivals == 0,
        policy.max_neighborhood == 0,
        policy.max_work == 0,
        policy.max_stu == 0,
        policy.max_path_hops == 0,
    ]
    .into_iter()
    .any(|invalid| invalid)
    {
        return Err(eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.policy",
            reason: "all limits and revision must be positive".to_owned(),
        });
    }
    if policy.deadline_ms.is_some() != policy.now_ms.is_some() {
        return Err(eliot_dreamer_contracts::ContractViolation::ImplicitDefault(
            "relation.policy.now_deadline",
        ));
    }
    if let Some(now) = policy.now_ms {
        let Some(clock_ref) = policy.clock_ref.as_deref() else {
            return Err(eliot_dreamer_contracts::ContractViolation::ImplicitDefault(
                "relation.policy.clock_ref",
            ));
        };
        check_text(clock_ref, "relation.policy.clock_ref", MAX_TEXT)?;
        if now < 0 || policy.deadline_ms.is_some_and(|deadline| deadline < 0) {
            return Err(eliot_dreamer_contracts::ContractViolation::Malformed {
                field: "relation.policy.clock",
                reason: "time observations must be non-negative".to_owned(),
            });
        }
    } else if policy.clock_ref.is_some() {
        return Err(eliot_dreamer_contracts::ContractViolation::ImplicitDefault(
            "relation.policy.clock_ref_without_observation",
        ));
    }
    if policy.required_grade.rank() > policy.maximum_grade.rank() {
        return Err(
            eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                field: "relation.policy.grade",
                reason: "minimum grade exceeds maximum grade".to_owned(),
            },
        );
    }
    if policy.transitive_path.len() > usize::try_from(policy.max_path_hops).unwrap_or(usize::MAX)
        || policy.transitive_path.len() > 64
    {
        return Err(eliot_dreamer_contracts::ContractViolation::Budget {
            dimension: "relation.policy.path",
            reason: "ordered path exceeds its independent bound".to_owned(),
        });
    }
    Ok(())
}

fn validate_policy_bindings(
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    use eliot_dreamer_contracts::error::{check_text, check_vec_bound};
    check_vec_bound(
        policy.grade_bindings.len(),
        256,
        "relation.policy.grade_bindings",
    )?;
    for (index, binding) in policy.grade_bindings.iter().enumerate() {
        validate_grade_binding(binding)?;
        if policy.grade_bindings[..index]
            .iter()
            .any(|prior| prior.evidence_id == binding.evidence_id)
            || grade_binding_digest(binding)? != binding.reference.digest
        {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.policy.grade.digest",
                    reason: "grade binding is duplicate or digest mismatched".to_owned(),
                },
            );
        }
    }
    check_vec_bound(
        policy.causal_bindings.len(),
        256,
        "relation.policy.causal_bindings",
    )?;
    for (index, binding) in policy.causal_bindings.iter().enumerate() {
        check_text(
            &binding.evidence_id,
            "relation.policy.evidence_id",
            MAX_TEXT,
        )?;
        check_text(&binding.fact, "relation.policy.evidence_fact", MAX_TEXT)?;
        if let Some(alternative_id) = &binding.alternative_id {
            check_text(
                alternative_id,
                "relation.policy.evidence_alternative_id",
                MAX_TEXT,
            )?;
        }
        binding.grade.validate().map_err(|_| {
            eliot_dreamer_contracts::ContractViolation::Malformed {
                field: "relation.policy.grade",
                reason: "invalid canonical grade assignment".to_owned(),
            }
        })?;
        if policy.causal_bindings[..index]
            .iter()
            .any(|prior| prior.evidence_id == binding.evidence_id && prior.kind == binding.kind)
        {
            return Err(eliot_dreamer_contracts::ContractViolation::Registry(
                "duplicate semantic evidence binding".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_policy_references(
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    use eliot_dreamer_contracts::error::{check_text, check_vec_bound, is_hex64_lower};
    for value in policy
        .expected_alternative_refs
        .iter()
        .chain(&policy.omitted_alternative_refs)
    {
        check_text(value, "relation.policy.reference", MAX_TEXT)?;
    }
    check_vec_bound(
        policy.expected_alternative_refs.len(),
        256,
        "relation.policy.expected_alternatives",
    )?;
    check_vec_bound(
        policy.omitted_alternative_refs.len(),
        256,
        "relation.policy.omitted_alternatives",
    )?;
    for path in &policy.transitive_path {
        check_text(&path.edge_id, "relation.policy.path.edge_id", MAX_TEXT)?;
        if !is_hex64_lower(&path.relation_digest) {
            return Err(eliot_dreamer_contracts::ContractViolation::Malformed {
                field: "relation.policy.path.relation_digest",
                reason: "path relation digest must be lowercase sha256".to_owned(),
            });
        }
    }
    if has_duplicates(&policy.expected_alternative_refs)
        || has_duplicates(&policy.omitted_alternative_refs)
        || policy
            .transitive_path
            .iter()
            .enumerate()
            .any(|(index, path)| {
                policy.transitive_path[..index]
                    .iter()
                    .any(|prior| prior.edge_id == path.edge_id)
            })
    {
        return Err(eliot_dreamer_contracts::ContractViolation::Registry(
            "policy reference sets must not contain duplicates".to_owned(),
        ));
    }
    Ok(())
}

fn validate_policy_semantics(
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    use eliot_dreamer_contracts::error::check_text;
    if let Some(material) = &policy.causal_material {
        check_text(
            &material.source_handle,
            "relation.policy.causal_source_handle",
            MAX_TEXT,
        )?;
        check_text(
            &material.proof_handle,
            "relation.policy.causal_proof_handle",
            MAX_TEXT,
        )?;
    }
    if let Some(predicate) = &policy.causal_predicate {
        check_text(
            &predicate.subject,
            "relation.policy.causal_subject",
            MAX_TEXT,
        )?;
        check_text(
            &predicate.predicate.source_id,
            "relation.policy.causal_source",
            MAX_TEXT,
        )?;
        check_text(
            &predicate.predicate.target_id,
            "relation.policy.causal_target",
            MAX_TEXT,
        )?;
        check_text(
            &predicate.predicate.expression,
            "relation.policy.causal_expression",
            MAX_TEXT,
        )?;
        if predicate.predicate.family.is_none() || predicate.predicate.direction.is_none() {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.policy.causal_predicate",
                    reason: "causal predicate family and direction are required".to_owned(),
                },
            );
        }
    }
    if let Some(snapshot) = &policy.proposed_snapshot {
        validate_snapshot_shape(snapshot)?;
    }
    if let Some(claim) = &policy.causal_claim {
        claim.validate().map_err(|_| {
            eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                field: "relation.policy.causal_claim",
                reason: "canonical causal claim is invalid".to_owned(),
            }
        })?;
    }
    Ok(())
}

fn serialized_within<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<bool, eliot_dreamer_contracts::ContractViolation> {
    struct Probe {
        used: usize,
        limit: usize,
        overflowed: bool,
    }
    impl std::io::Write for Probe {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let Some(next) = self.used.checked_add(bytes.len()) else {
                self.overflowed = true;
                return Err(std::io::Error::other("serialization length overflow"));
            };
            self.used = next;
            if self.used > self.limit {
                self.overflowed = true;
                return Err(std::io::Error::other("serialization bound exceeded"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut probe = Probe {
        used: 0,
        limit,
        overflowed: false,
    };
    match serde_json::to_writer(&mut probe, value) {
        Ok(()) => Ok(true),
        Err(_) if probe.overflowed => Ok(false),
        Err(_) => Err(eliot_dreamer_contracts::ContractViolation::Malformed {
            field: "relation.input.bytes",
            reason: "input serialization failed".to_owned(),
        }),
    }
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn validate_grade_binding(
    binding: &EvidenceGradeBinding,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    use eliot_dreamer_contracts::error::{check_text, is_hex64_lower};
    check_text(
        &binding.evidence_id,
        "relation.policy.grade.evidence_id",
        MAX_TEXT,
    )?;
    check_text(
        &binding.reference.owner,
        "relation.policy.grade.owner",
        MAX_TEXT,
    )?;
    check_text(
        &binding.reference.schema,
        "relation.policy.grade.schema",
        MAX_TEXT,
    )?;
    check_text(
        &binding.reference.revision,
        "relation.policy.grade.revision",
        MAX_TEXT,
    )?;
    check_text(
        binding.reference.record_id.as_str(),
        "relation.policy.grade.record_id",
        MAX_TEXT,
    )?;
    if !is_hex64_lower(&binding.reference.digest) {
        return Err(eliot_dreamer_contracts::ContractViolation::Malformed {
            field: "relation.policy.grade.digest",
            reason: "grade reference digest must be lowercase sha256".to_owned(),
        });
    }
    binding.assignment.validate().map_err(|_| {
        eliot_dreamer_contracts::ContractViolation::Malformed {
            field: "relation.policy.grade.assignment",
            reason: "invalid canonical grade assignment".to_owned(),
        }
    })
}

fn validate_snapshot_shape(
    snapshot: &eliot_dreamer_contracts::RelationSnapshot,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    use eliot_dreamer_contracts::error::{check_fence, check_text, is_hex64_lower};
    for (value, field) in [
        (
            &snapshot.relation_id,
            "relation.policy.snapshot.relation_id",
        ),
        (&snapshot.source_id, "relation.policy.snapshot.source_id"),
        (&snapshot.target_id, "relation.policy.snapshot.target_id"),
        (&snapshot.scope_id, "relation.policy.snapshot.scope_id"),
        (
            &snapshot.adapter_revision,
            "relation.policy.snapshot.adapter_revision",
        ),
        (
            &snapshot.build_revision,
            "relation.policy.snapshot.build_revision",
        ),
    ] {
        check_text(value, field, MAX_TEXT)?;
    }
    for (value, field) in [
        (
            &snapshot.registry_digest,
            "relation.policy.snapshot.registry_digest",
        ),
        (
            &snapshot.relation_digest,
            "relation.policy.snapshot.relation_digest",
        ),
    ] {
        if !is_hex64_lower(value) {
            return Err(eliot_dreamer_contracts::ContractViolation::Malformed {
                field,
                reason: "snapshot digest must be lowercase sha256".to_owned(),
            });
        }
    }
    check_fence(&snapshot.state_fence)?;
    if snapshot.provenance_refs.is_empty() || snapshot.provenance_refs.len() > 256 {
        return Err(eliot_dreamer_contracts::ContractViolation::OutOfBounds {
            field: "relation.policy.snapshot.provenance_refs",
            min: 1,
            max: 256,
            got: i64::try_from(snapshot.provenance_refs.len()).unwrap_or(i64::MAX),
        });
    }
    if !matches!(
        snapshot.status,
        eliot_evidence::EpistemicStatus::Supported | eliot_evidence::EpistemicStatus::Verified
    ) || snapshot.lifecycle != eliot_evidence::LifecycleState::Active
    {
        return Err(
            eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                field: "relation.policy.snapshot.status",
                reason: "proposed snapshot must be current and supported".to_owned(),
            },
        );
    }
    Ok(())
}

/// Computes the exact grade reference digest, including evidence identity,
/// external owner identity and the complete canonical assignment.
pub fn grade_binding_digest(
    binding: &EvidenceGradeBinding,
) -> Result<String, eliot_dreamer_contracts::ContractViolation> {
    #[derive(Serialize)]
    struct GradePre<'a> {
        evidence_id: &'a str,
        owner: &'a str,
        schema: &'a str,
        revision: &'a str,
        record_id: &'a str,
        assignment: &'a GradeAssignment,
    }
    validate_grade_binding(binding)?;
    Ok(digest_hex(&canonical_bytes(&GradePre {
        evidence_id: &binding.evidence_id,
        owner: &binding.reference.owner,
        schema: &binding.reference.schema,
        revision: &binding.reference.revision,
        record_id: binding.reference.record_id.as_str(),
        assignment: &binding.assignment,
    })?))
}
