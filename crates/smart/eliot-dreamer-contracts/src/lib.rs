//! Provider-neutral Dreamer and typed Curation contract hub.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns closed schemas, canonical identities/encoding and intrinsic
//! wrapper/identity/bounds validation. Owns no bundle assembly, grounding,
//! validation, screening, handler, runtime, canonical-state, authority,
//! effect or finish behavior: those belong to A-04/A-05/A-14b, screens,
//! handlers, A-31 and runtime composition, which consume these contracts.

#![forbid(unsafe_code)]

pub mod budget;
pub mod bundle;
pub mod candidate;
pub mod classification;
pub mod curation;
pub mod draft;
pub mod encoding;
pub mod error;
pub mod job;
pub mod registry;
pub mod relation;
pub mod screen;

pub use budget::{
    BudgetDimension, BudgetLimits, BudgetUsage, DEX_BUDGET_DIMENSIONS, check_no_cross_subsidy,
};
pub use bundle::{
    BundleCompleteness, BundleMaterial, BundleStatus, DreamInputBundle, OmissionHandle,
    SourceDisposition, omit_handle,
};
pub use candidate::{
    CandidateDisposition, CandidateProposal, CandidateResult, PRESERVATION_DIMENSIONS,
    PreservationDimension, PreservationReport, propose_candidate,
};
pub use classification::{
    AdmittedTargetRef, ClassificationAssignmentSnapshot, ClassificationCandidate,
    ClassificationCandidateClosure, ClassificationCriterionRole, ClassificationInput,
    ClassificationPreservation, ClassificationPreservationDimension,
    ClassificationPreservationVerdict, ClassificationRecordFamily, ClassificationRollback,
    CriterionApplicability, CriterionStatus, ExternalGradeRef, FeatureObservation,
    GroundedCriterion, NamedEvidence, PriorAssignmentRef, TaxonomyAliasMapping,
    TaxonomyAlternative, TaxonomyCoverage, TaxonomyDenominator, classification_input_digest,
    preflight_classification_acceptance, seal_classification, validate_classification,
    validate_classification_acceptance,
};
pub use curation::{CURATION_WIRE_KINDS, CurationKind, CurationPayload, kind_family, parse_kind};
pub use draft::{
    ClaimResidue, CurationAcceptanceCtx, GroundedDreamDraft, ModelDraft, RawProviderOutput,
    SupportState, ValidatedCurationItem, ValidatedDreamDraft, ValidationReceipt,
};
pub use encoding::{canonical_bytes, digest_hex};
pub use error::{ContractViolation, check_fence, check_vec_bound, is_hex64_lower};
pub use job::{DreamJobInput, JobClass, Requester, RequesterOrigin, parse_job_class};
pub use registry::{
    AtomicityMode, CURATION_FAMILIES, CurationFamily, CurationHandlerDescriptor,
    CurationHandlerPort, CurationHandlerRegistry, TargetDenominator, TypedCurationHandlerRequest,
    TypedCurationHandlerResult, family_of, parse_family,
};
pub use relation::{
    RELATION_FAMILIES, RelationAlternative, RelationCandidate, RelationCandidateClosure,
    RelationDirection, RelationDisclosureEvidence, RelationDisposition, RelationEndpoint,
    RelationEvidence, RelationEvidencePolarity, RelationFamily, RelationFamilyRule, RelationInput,
    RelationNeighborhood, RelationPredicate, RelationPreservation, RelationPreservationDimension,
    RelationPreservationVerdict, RelationRegistrySnapshot, RelationRollback, RelationSnapshot,
    RelationTemporalEvidence, RelationTimePoint, RelationVerifier, relation_input_digest,
    seal_relation, validate_relation,
};
pub use screen::{ScreenBinding, ScreenEligibility, ScreenReference, ScreenState};

/// Contract hub identity (`name@version`).
pub const CONTRACT_NAME: &str = "eliot.smart.dreamer.contracts";
/// Contract hub version.
pub const CONTRACT_VERSION: &str = "1.0.0";
