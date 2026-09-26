//! Executable owner inventory and owner/Store read-model comparison (#1144).
//!
//! Issue items 1 and 2 ask this package for two things a crate-level
//! documentation block can only *assert*: an inventory of everything
//! `eliot-read` exposes and owns, and a comparison of that surface with the
//! Store read model it reads through. This module answers both with values
//! resolved at call time from the registries the read path already reads, so a
//! drift between the owner and the Store read model becomes a typed
//! [`ReadError`] instead of a sentence.
//!
//! # What is derived and what is declared
//!
//! Every row carries an [`InventoryProvenance`], and the inventory carries one
//! [`InventoryEvidenceClass`]:
//!
//! * the per-operation comparison, the Store declaration rows, the contract
//!   identity, the context-reconstruction membership and the port selector
//!   names are **derived**: they are read from the Store operation catalogue,
//!   the Store read-parameter declaration table, the projected parameter
//!   schema, its digest, the canonical operation names, the generated
//!   manifests, and this crate's own admission predicates;
//! * the public-API rows are **compile-time witnesses**: each row's body names
//!   the real type, so a rename or removal breaks the build, and the row's
//!   observed path is whatever the compiler reports;
//! * the mutable-state row, the port declarations and the test-target rows are
//!   **declared by this owner**, and each is checked against a derived source
//!   wherever a derived source exists for it.
//!
//! The language offers no reflection over enum variants, over the items of a
//! module, or over the test set of a package. Where a closed enumeration is
//! unavoidable it is declared here, and the declaration is the only hand-typed
//! part; every value computed from it comes from a real call.
//!
//! # Scope boundary, stated rather than hidden
//!
//! This inventory describes **this package**. It is not a measurement of which
//! other packages in the repository import it, of whether such an importer is
//! itself reachable from a process entry point, or of whether any read
//! currently executes. A package cannot observe its reverse consumers at
//! runtime, and this module never pretends to: `evidence_execution` is
//! [`InventoryEvidenceClass::NotExecuted`] for the whole inventory, and nothing
//! here may be read as evidence of liveness, freshness, support or authority.

use std::collections::BTreeSet;

use eliot_contracts::ContractVersion;
use eliot_store_api::{
    NamedOperationManifest, NamedReadOperation, ReadConsistency, activated_read_operations,
    declared_read_parameters, named_read_operation_name, parameter_schema_digest,
    project_parameter_schema,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    BranchEnvironmentScope, CONTRACT_NAME, CONTRACT_VERSION, DeclaredPageSelector,
    DeclaredResultSelector, FreshnessPolicy, NamedParameters, QueryIntent, QueryMode, ReadCoverage,
    ReadError, ReadOutcome, ReadSchemaIdentity, ReadSourceIdentity, RequiredAssurance,
    StoreReadFailure, TimeScope, contract_identity, context_reconstruction_operations,
    declares_store_coverage_statement, is_state_operation, operation_matches_intent, requires_scope,
};

/// How one inventory row was established.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryProvenance {
    /// Resolved at call time from a Store declaration table, a Store catalogue
    /// entry, or a real call into this crate's own admission predicates.
    DerivedAtCallTime,
    /// Proved while compiling: the row's body names the real item, so a rename
    /// or a removal is a build failure rather than a stale row.
    CompileTimeWitness,
    /// Declared by this owner, and checked against a derived source wherever a
    /// derived source exists for it.
    DeclaredByOwner,
}

/// Execution class of the evidence behind one inventory (I0.5).
///
/// The inventory is a statement about source shape. It is never runtime
/// evidence, and the single value below is the only one that exists, so a
/// consumer cannot read an inventory row as a proof of anything having run.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryEvidenceClass {
    /// No executed proof exists for this inventory. A compiler result, a row
    /// count, or a keyword match cannot promote it across an evidence class.
    NotExecuted,
}

/// Which kind of public item one inventory row describes.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicApiKind {
    /// A public trait a consumer implements or calls.
    Trait,
    /// The read service type over a caller-owned store client.
    Service,
    /// A JSON data object on the read wire.
    WireObject,
    /// A closed JSON enum on the read wire.
    WireEnum,
}

/// One declared public item of this owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicApiRow {
    /// Exported item name, exactly as a consumer imports it.
    pub name: String,
    /// Which kind of public item this is.
    pub kind: PublicApiKind,
    /// Path the compiler reports for this row's type, or absent for items with
    /// no single concrete type: a trait, or the generic service.
    pub observed_type_path: Option<String>,
    /// How this row was established.
    pub provenance: InventoryProvenance,
}

/// Mutable state this owner holds, as a closed vocabulary.
///
/// The vocabulary has exactly one value. Introducing a cache, a freshness memo
/// or a second consistency algorithm in this package requires adding a value
/// here, which is a visible contract change rather than a silent one.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerMutableState {
    /// No owned mutable state beyond the caller-owned store client:
    /// [`ReadService`](crate::ReadService) holds exactly that one field and
    /// every read re-dispatches to it under the caller fence.
    StatelessOverCallerOwnedStoreClient,
}

/// Closed owner role of one Store-declared read selector.
///
/// The role is read from the selector's own Store-declared name, so this owner
/// never re-declares a selector spelling. A selector outside the bound, page
/// and cursor vocabulary is carried verbatim as an exact caller discriminator
/// and is never interpreted here.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerParameterRole {
    /// The Store-declared result-set bound.
    ResultSetBound,
    /// The Store-declared page bound of a cursor-paged read.
    PageBound,
    /// The Store-declared opaque continuation cursor.
    ContinuationCursor,
    /// A declared selector outside the bound, page and cursor vocabulary,
    /// carried verbatim as an exact caller discriminator.
    ExactDiscriminator,
}

/// One Store read-model selector exactly as the Store declares it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredParameterRow {
    /// Exact selector name from the Store declaration table.
    pub name: String,
    /// Exact stable shape code from the Store declaration table.
    pub shape_code: String,
    /// Whether the Store requires this selector to be present.
    pub required: bool,
    /// Which closed role this owner gives the selector.
    pub owner_role: OwnerParameterRole,
}

/// How this owner admits one named read operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerAdmission {
    /// Admitted by the state facet and by at least one query mode.
    StateAndQuery,
    /// Admitted by the state facet only.
    StateOnly,
    /// Admitted by at least one query mode only.
    QueryOnly,
    /// Not admitted by any facet of this owner. Such an operation has no path
    /// through this package even when the Store activates it.
    NotAdmitted,
}

/// Whether this owner requires a caller scope for one operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerScopeDeclaration {
    /// The owner's request validation refuses an unscoped request.
    Required,
    /// The owner accepts an unscoped request.
    NotRequired,
}

/// Whether the Store catalogue requires a scope id for one operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreScopeDeclaration {
    /// The catalogue manifest declares a required scope id.
    Required,
    /// The catalogue manifest declares no scope requirement.
    NotRequired,
}

/// The resolved comparison between the owner's and the Store's scope
/// declaration for one operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDeclarationComparison {
    /// Owner and Store agree.
    Agree,
    /// The owner demands a scope the Store does not require. This is a
    /// deliberate narrowing of the accepted surface, never a wider read: the
    /// owner may refuse a read the Store would have answered.
    OwnerRequiresScopeStoreDoesNot,
    /// The Store requires a scope the owner does not demand. If this owner also
    /// admits the operation, the read would be dispatched unscoped against a
    /// scope-bound catalogue row, so the read path refuses it.
    StoreRequiresScopeOwnerDoesNot,
}

/// Whether the Store contract types a page coverage statement for one
/// operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreCoverageStatement {
    /// The Store exports a typed page statement for this operation, so the
    /// owner gates the payload on decoding and describing it.
    TypedByStoreContract,
    /// The Store exports no such statement for this operation, so the owner
    /// keeps the payload opaque.
    NotTypedByStoreContract,
}

/// Whether this owner's context-reconstruction table lists one operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextReconstructionMembership {
    /// Listed in the owner's declared reconstruction table.
    Listed,
    /// Not listed.
    NotListed,
}

/// One activated Store read operation compared against this owner.
///
/// Every field is resolved at call time from the Store catalogue and from this
/// crate's own admission predicates. The row is a comparison, not a verdict: it
/// states where the two surfaces agree and where they differ, and it grants no
/// support, freshness or authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReadModelComparison {
    /// The activated Store read operation.
    pub operation: NamedReadOperation,
    /// Exact canonical operation name bound by the Store.
    pub operation_name: String,
    /// Exact activated source identity resolved from the catalogue.
    pub source: ReadSourceIdentity,
    /// Exact projection schema identity resolved from the catalogue.
    pub schema: ReadSchemaIdentity,
    /// How this owner admits the operation.
    pub owner_admission: OwnerAdmission,
    /// Every query mode whose gate admits the operation, swept from the closed
    /// mode vocabulary.
    pub admitted_query_modes: Vec<QueryMode>,
    /// The owner's scope declaration.
    pub owner_scope: OwnerScopeDeclaration,
    /// The Store's scope declaration, read from the catalogue manifest.
    pub store_scope: StoreScopeDeclaration,
    /// Exact scope kind string the catalogue manifest carries.
    pub store_scope_kind: String,
    /// The resolved comparison of the two scope declarations.
    pub scope_declaration: ScopeDeclarationComparison,
    /// Whether the Store contract types a page coverage statement.
    pub store_coverage_statement: StoreCoverageStatement,
    /// Whether the owner's reconstruction table lists the operation.
    pub context_reconstruction_membership: ContextReconstructionMembership,
    /// Every selector the Store declares for the operation, in declaration
    /// order, with the role this owner gives it.
    pub declared_parameters: Vec<DeclaredParameterRow>,
}

impl OperationReadModelComparison {
    /// Resolves the coverage identity of one read bound to this operation.
    ///
    /// The result-set bound, the page bound and the continuation cursor are
    /// read from the Store declaration rows above, and the caller's declared
    /// bound is echoed exactly. No percentage, fraction or completeness
    /// estimate is produced: coverage states which bound was in force, never how
    /// much of a source a read happened to observe.
    pub fn coverage(&self, parameters: &NamedParameters) -> Result<ReadCoverage, ReadError> {
        if let Some(selector) = self.declared_role(OwnerParameterRole::ResultSetBound) {
            return Ok(match declared_bound(parameters, &selector.name)? {
                Some(bound) => ReadCoverage::BoundedByDeclaredSelector {
                    selector: DeclaredResultSelector::MaxRecords,
                    declared_bound: bound,
                },
                None => ReadCoverage::BoundByStore {
                    selector: DeclaredResultSelector::MaxRecords,
                },
            });
        }
        if self
            .declared_role(OwnerParameterRole::ContinuationCursor)
            .is_some()
        {
            return Ok(ReadCoverage::PagedByDeclaredCursor {
                selector: self
                    .declared_role(OwnerParameterRole::PageBound)
                    .map(|page| DeclaredPageSelector::PageLimit),
            });
        }
        Ok(ReadCoverage::NotApplicable)
    }

    /// Refuses a read this owner would dispatch against a scope-bound
    /// catalogue row without demanding a scope.
    ///
    /// The aggregate inventory only *reports* this divergence; the single read
    /// engine refuses it, so one divergent row cannot block unrelated reads.
    pub fn refuse_scope_divergence(&self) -> Result<(), ReadError> {
        if self.scope_declaration == ScopeDeclarationComparison::StoreRequiresScopeOwnerDoesNot
            && self.owner_admission != OwnerAdmission::NotAdmitted
        {
            return Err(ReadError::OperationNotAllowed {
                operation: self.operation,
                context: "owner scope declaration is narrower than the store catalogue row".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns the single declared selector carrying one owner role.
    fn declared_role(&self, role: OwnerParameterRole) -> Option<&DeclaredParameterRow> {
        let mut found = self
            .declared_parameters
            .iter()
            .filter(|row| row.owner_role == role);
        let first = found.next()?;
        found.next().is_none().then_some(first)
    }
}

/// One local read port method of this owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalReadPortMethod {
    /// The bounded evidence query served for an admitted `eliot.query` pair.
    EvidenceQuery,
    /// The projection-inputs read served for the same claim and result
    /// lifecycle.
    ProjectionInputs,
}

/// Closed selector roles one port method supplies to its Store request.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortSelectorRole {
    /// The exact caller subject, carried into the operation's single declared
    /// discriminator selector.
    Subject,
    /// The exact caller result-set bound, carried into the operation's declared
    /// result-set bound selector.
    ResultSetBound,
}

/// One validated binding of a local read port method.
///
/// The intent, the operation, the consistency mode and the supplied selector
/// roles are declared by this owner; the selector *names* are resolved from the
/// Store declaration table of the bound operation, so the port can never send a
/// selector the Store does not declare as required.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalReadPortBinding {
    /// Which port method this binding serves.
    pub method: LocalReadPortMethod,
    /// The closed named operation the method dispatches.
    pub operation: NamedReadOperation,
    /// Exact canonical operation name bound by the Store.
    pub operation_name: String,
    /// The exact closed semantic intent the method declares.
    pub intent: QueryIntent,
    /// The exact consistency the method requests.
    pub consistency: ReadConsistency,
    /// Exact Store-declared discriminator selector, when the method supplies
    /// one.
    pub subject_selector: Option<String>,
    /// Exact Store-declared result-set bound selector, when the method supplies
    /// one.
    pub result_set_bound_selector: Option<String>,
}

/// Exact contract identity of this owner, resolved from its own shape.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerContractIdentity {
    /// Stable wire name of the read contract.
    pub name: String,
    /// Current wire revision of the read contract.
    pub version: ContractVersion,
    /// Lowercase digest of the canonical contract shape this owner publishes.
    pub shape_sha256: String,
}

/// One `eliot_store_api` item this owner's read path depends on.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreDependencyRow {
    /// The depended-upon item, named as the Store exports it.
    pub symbol: String,
    /// Value observed by calling the item at inventory time.
    pub observed: usize,
    /// How this row was established.
    pub provenance: InventoryProvenance,
}

/// One declared test target of this package.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetRow {
    /// Exact target this package declares.
    pub target: String,
    /// Execution class of any evidence behind the target.
    pub evidence_execution: InventoryEvidenceClass,
    /// How this row was established.
    pub provenance: InventoryProvenance,
}

/// The resolved inventory of everything this package exposes and owns.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOwnerInventory {
    /// Exact contract identity of this owner.
    pub contract: OwnerContractIdentity,
    /// Mutable state this owner holds.
    pub mutable_state: OwnerMutableState,
    /// Every declared public item, with its compile-time witness result.
    pub public_api: Vec<PublicApiRow>,
    /// Every Store item the read path depends on, with the value observed.
    pub store_dependencies: Vec<StoreDependencyRow>,
    /// Every declared test target of this package.
    pub test_targets: Vec<TestTargetRow>,
    /// The owner and Store comparison for every activated Store read operation.
    pub read_model_comparisons: Vec<OperationReadModelComparison>,
    /// Every validated local read port binding.
    pub port_bindings: Vec<LocalReadPortBinding>,
    /// Execution class of the whole inventory.
    pub evidence_execution: InventoryEvidenceClass,
}

impl ReadOwnerInventory {
    /// Returns the validated binding of one local read port method.
    pub fn port_binding(
        &self,
        method: LocalReadPortMethod,
    ) -> Result<&LocalReadPortBinding, ReadError> {
        self.port_bindings
            .iter()
            .find(|binding| binding.method == method)
            .ok_or_else(|| ReadError::InvalidField {
                field: "local_read_port.declaration".to_owned(),
                reason: format!("no declared binding for port method {method:?}"),
            })
    }
}

/// Resolves the whole owner inventory from the registries the read path reads.
///
/// This is the single resolution path for this package's declared surface, and
/// it is a pure function of crate constants and the Store declaration tables:
/// it holds no state, is never cached, and creates no freshness. The two
/// [`LocalReadPort`](crate::LocalReadPort) methods resolve their binding
/// through it, so an owner that cannot describe its own surface does not
/// answer.
pub fn read_owner_inventory() -> Result<ReadOwnerInventory, ReadError> {
    let read_model_comparisons = compare_activated_read_model()?;
    verify_context_reconstruction_table(&read_model_comparisons)?;
    Ok(ReadOwnerInventory {
        contract: resolve_contract_identity()?,
        mutable_state: OwnerMutableState::StatelessOverCallerOwnedStoreClient,
        public_api: resolve_public_api_rows()?,
        store_dependencies: resolve_store_dependency_rows(),
        test_targets: resolve_test_target_rows(),
        port_bindings: resolve_port_bindings(&read_model_comparisons)?,
        read_model_comparisons,
        evidence_execution: InventoryEvidenceClass::NotExecuted,
    })
}

/// Compares one named read operation with the Store read model it reads
/// through.
///
/// This is the comparison the single read engine runs per read: it resolves the
/// activated source and the projection schema from the Store catalogue, sweeps
/// this owner's admission predicates, and reports where the two surfaces
/// differ. Nothing is re-declared here — the catalogue owns the source
/// identities, and this crate's own predicates own the admission.
pub fn compare_operation_with_store_read_model(
    operation: NamedReadOperation,
) -> Result<OperationReadModelComparison, ReadError> {
    let operation_name = named_read_operation_name(operation);
    if !activated_read_operations().contains(&operation) {
        return Err(ReadError::Outcome(ReadOutcome::NotRunning));
    }
    let entry = read_manifest(operation_name)?;
    let declared_parameters = resolve_declared_parameter_rows(operation);
    let admitted_query_modes = admitted_query_modes(operation);
    let owner_admission = owner_admission(operation, &admitted_query_modes);
    let owner_scope = owner_scope_declaration(operation);
    let store_scope = store_scope_declaration(entry.requires_scope_id);
    Ok(OperationReadModelComparison {
        operation,
        operation_name: operation_name.to_owned(),
        source: resolve_source_identity(operation, operation_name, &entry),
        schema: resolve_schema_identity(operation, &entry)?,
        owner_admission,
        admitted_query_modes,
        owner_scope,
        store_scope,
        store_scope_kind: entry.scope_kind.clone(),
        scope_declaration: compare_scope_declarations(owner_scope, store_scope),
        store_coverage_statement: store_coverage_statement(operation),
        context_reconstruction_membership: context_reconstruction_membership(operation),
        declared_parameters,
    })
}

/// Closed sweep of the query-mode vocabulary.
///
/// The language offers no reflection over enum variants, so the sweep is
/// declared. It only chooses which modes are *asked*; the admission answer for
/// every mode comes from the owner's own intent gate, which stays the single
/// admission owner. Adding a query mode is a wire-revision event: the exhaustive
/// match in that gate and `CONTRACT_VERSION` must both change, and this sweep is
/// where the new mode is added.
const QUERY_MODE_SWEEP: [QueryMode; 7] = [
    QueryMode::CurrentPosition,
    QueryMode::HistoricalReconstruction,
    QueryMode::Provenance,
    QueryMode::Navigation,
    QueryMode::Verification,
    QueryMode::ChangeImpact,
    QueryMode::ContextReconstruction,
];

/// One declared local read port binding row.
struct PortDeclaration {
    /// Which port method this row declares.
    method: LocalReadPortMethod,
    /// The closed named operation the method dispatches.
    operation: NamedReadOperation,
    /// The exact closed semantic intent the method declares.
    intent: QueryIntent,
    /// The exact consistency the method requests.
    consistency: ReadConsistency,
    /// Which closed selector roles the method supplies.
    selectors: &'static [PortSelectorRole],
}

/// Declared local read port surface of this owner.
///
/// This is the only hand-typed binding table in the package, and the read path
/// consults it: each port method builds its request from the row it resolves
/// rather than from a literal intent written at the call site. Every row is then
/// checked against the Store declaration table and against this owner's own
/// intent gate, so a declaration that stops matching its source is a typed
/// error rather than a silently wrong request.
const PORT_DECLARATIONS: [PortDeclaration; 2] = [
    PortDeclaration {
        method: LocalReadPortMethod::EvidenceQuery,
        operation: NamedReadOperation::GetEvidencePack,
        intent: QueryIntent {
            mode: QueryMode::Verification,
            time_scope: TimeScope::EvidenceWindow,
            branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
            freshness_policy: FreshnessPolicy::ExactCapturedRecords,
            required_assurance: RequiredAssurance::VerifierEvidence,
        },
        consistency: ReadConsistency::Eventual,
        selectors: &[PortSelectorRole::Subject, PortSelectorRole::ResultSetBound],
    },
    PortDeclaration {
        method: LocalReadPortMethod::ProjectionInputs,
        operation: NamedReadOperation::GetUnderstandingProjectionInputs,
        intent: QueryIntent {
            mode: QueryMode::ContextReconstruction,
            time_scope: TimeScope::ProjectionWindow,
            branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
            freshness_policy: FreshnessPolicy::ProjectionInputsOnly,
            required_assurance: RequiredAssurance::ReconstructionInputs,
        },
        consistency: ReadConsistency::Eventual,
        selectors: &[],
    },
];

/// One declared public item, with a compile-time witness of its type.
struct PublicTypeDeclaration {
    /// Exported item name.
    name: &'static str,
    /// Which kind of public item this is.
    kind: PublicApiKind,
    /// Body naming the real type, so a rename or a removal breaks the build.
    witness: Option<fn() -> &'static str>,
}

/// Declared public surface of this package.
///
/// Every concrete row below names its real public type in the witness body, so
/// this table cannot outlive the item it describes. The two trait rows and the
/// service row have no single concrete type path and are declared instead: their
/// presence is still a compile-time fact of this crate, because both traits and
/// the service are implemented and constructed here.
const PUBLIC_TYPE_DECLARATIONS: [PublicTypeDeclaration; 27] = [
    PublicTypeDeclaration {
        name: "ReadApi",
        kind: PublicApiKind::Trait,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "LocalReadPort",
        kind: PublicApiKind::Trait,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ReadService",
        kind: PublicApiKind::Service,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "QueryMode",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::QueryMode>()),
    },
    PublicTypeDeclaration {
        name: "TimeScope",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::TimeScope>()),
    },
    PublicTypeDeclaration {
        name: "BranchEnvironmentScope",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::BranchEnvironmentScope>()),
    },
    PublicTypeDeclaration {
        name: "FreshnessPolicy",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::FreshnessPolicy>()),
    },
    PublicTypeDeclaration {
        name: "RequiredAssurance",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::RequiredAssurance>()),
    },
    PublicTypeDeclaration {
        name: "QueryIntent",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::QueryIntent>()),
    },
    PublicTypeDeclaration {
        name: "EliotResourceUri",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::EliotResourceUri>()),
    },
    PublicTypeDeclaration {
        name: "ProvenanceHandle",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ProvenanceHandle>()),
    },
    PublicTypeDeclaration {
        name: "ProvenanceDisposition",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::ProvenanceDisposition>()),
    },
    PublicTypeDeclaration {
        name: "ReadProvenance",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ReadProvenance>()),
    },
    PublicTypeDeclaration {
        name: "NamedParameters",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::NamedParameters>()),
    },
    PublicTypeDeclaration {
        name: "ReadOutcome",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::ReadOutcome>()),
    },
    PublicTypeDeclaration {
        name: "ReadPrincipal",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ReadPrincipal>()),
    },
    PublicTypeDeclaration {
        name: "ReadSourceIdentity",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ReadSourceIdentity>()),
    },
    PublicTypeDeclaration {
        name: "ReadSchemaIdentity",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ReadSchemaIdentity>()),
    },
    PublicTypeDeclaration {
        name: "ReadCoverage",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::ReadCoverage>()),
    },
    PublicTypeDeclaration {
        name: "DeclaredResultSelector",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::DeclaredResultSelector>()),
    },
    PublicTypeDeclaration {
        name: "DeclaredPageSelector",
        kind: PublicApiKind::WireEnum,
        witness: Some(|| std::any::type_name::<super::DeclaredPageSelector>()),
    },
    PublicTypeDeclaration {
        name: "ReadOrderingBinding",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ReadOrderingBinding>()),
    },
    PublicTypeDeclaration {
        name: "ReadInvalidationSet",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ReadInvalidationSet>()),
    },
    PublicTypeDeclaration {
        name: "ReadIdentity",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::ReadIdentity>()),
    },
    PublicTypeDeclaration {
        name: "StateRequest",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::StateRequest>()),
    },
    PublicTypeDeclaration {
        name: "QueryRequest",
        kind: PublicApiKind::WireObject,
        witness: Some(|| std::any::type_name::<super::QueryRequest>()),
    },
];

/// Declared test targets of this package.
///
/// A package cannot observe its own test set at runtime: there is no reflection
/// over a target list and nothing is executed here, so these rows are declared
/// and carry [`InventoryEvidenceClass::NotExecuted`]. They state which targets
/// exist, never that any of them ran or passed.
const TEST_TARGETS: [&str; 3] = [
    "tests/read_owner_proof.rs",
    "tests/context_reconstruction.rs",
    "src/lib.rs::evidence_pack_read_tests",
];

/// One declared Store dependency with the real call that observes it.
struct StoreDependency {
    /// The depended-upon item, named as the Store exports it.
    symbol: &'static str,
    /// A real call into that item.
    witness: fn() -> usize,
}

/// Store items the read path depends on, each with a real call as its witness.
const STORE_DEPENDENCIES: [StoreDependency; 7] = [
    StoreDependency {
        symbol: "activated_read_operations",
        witness: activated_read_operation_count,
    },
    StoreDependency {
        symbol: "generated_operation_manifests",
        witness: manifest_count,
    },
    StoreDependency {
        symbol: "declared_read_parameters",
        witness: declared_selector_count,
    },
    StoreDependency {
        symbol: "project_parameter_schema",
        witness: projected_schema_field_count,
    },
    StoreDependency {
        symbol: "parameter_schema_digest",
        witness: distinct_parameter_schema_digest_count,
    },
    StoreDependency {
        symbol: "named_read_operation_name",
        witness: canonical_name_agreement_count,
    },
    StoreDependency {
        symbol: "ExperienceRangePage",
        witness: typed_coverage_statement_operation_count,
    },
];

/// Resolves the exact contract identity of this owner from its own shape.
fn resolve_contract_identity() -> Result<OwnerContractIdentity, ReadError> {
    let identity = contract_identity().map_err(|error| ReadError::InvalidField {
        field: "contract_identity".to_owned(),
        reason: error.to_string(),
    })?;
    Ok(OwnerContractIdentity {
        name: CONTRACT_NAME.to_owned(),
        version: CONTRACT_VERSION,
        shape_sha256: identity.shape_sha256,
    })
}

/// Resolves every declared public item, checking each witness against its
/// declared name.
fn resolve_public_api_rows() -> Result<Vec<PublicApiRow>, ReadError> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::with_capacity(PUBLIC_TYPE_DECLARATIONS.len());
    for declaration in &PUBLIC_TYPE_DECLARATIONS {
        if !seen.insert(declaration.name) {
            return Err(ReadError::DuplicateField("public_api".to_owned()));
        }
        rows.push(PublicApiRow {
            name: declaration.name.to_owned(),
            kind: declaration.kind,
            observed_type_path: observed_type_path(declaration)?,
            provenance: provenance_for(declaration.kind),
        });
    }
    Ok(rows)
}

/// Returns the compiler-reported type path of one declared row, refusing a row
/// whose witness no longer reports the declared name.
fn observed_type_path(
    declaration: &PublicTypeDeclaration,
) -> Result<Option<String>, ReadError> {
    let Some(witness) = declaration.witness else {
        return Ok(None);
    };
    let observed = witness();
    let reported = observed.rsplit("::").next().unwrap_or(observed);
    if reported != declaration.name {
        return Err(ReadError::InvalidField {
            field: format!("public_api.{}", declaration.name),
            reason: format!("witness reports {observed} instead of the declared type"),
        });
    }
    Ok(Some(observed.to_owned()))
}

/// Returns how one declared public row was established.
const fn provenance_for(kind: PublicApiKind) -> InventoryProvenance {
    match kind {
        PublicApiKind::Trait | PublicApiKind::Service => InventoryProvenance::DeclaredByOwner,
        PublicApiKind::WireObject | PublicApiKind::WireEnum => {
            InventoryProvenance::CompileTimeWitness
        }
    }
}

/// Resolves every declared test target row.
fn resolve_test_target_rows() -> Vec<TestTargetRow> {
    TEST_TARGETS
        .iter()
        .map(|target| TestTargetRow {
            target: (*target).to_owned(),
            evidence_execution: InventoryEvidenceClass::NotExecuted,
            provenance: InventoryProvenance::DeclaredByOwner,
        })
        .collect()
}

/// Resolves every Store dependency row by calling the depended-upon item.
fn resolve_store_dependency_rows() -> Vec<StoreDependencyRow> {
    STORE_DEPENDENCIES
        .iter()
        .map(|dependency| StoreDependencyRow {
            symbol: dependency.symbol.to_owned(),
            observed: (dependency.witness)(),
            provenance: InventoryProvenance::DerivedAtCallTime,
        })
        .collect()
}

/// Compares every activated Store read operation with this owner.
fn compare_activated_read_model() -> Result<Vec<OperationReadModelComparison>, ReadError> {
    activated_read_operations()
        .into_iter()
        .map(compare_operation_with_store_read_model)
        .collect()
}

/// Refuses a reconstruction table that no longer matches the intent gate it
/// claims to enumerate.
fn verify_context_reconstruction_table(
    comparisons: &[OperationReadModelComparison],
) -> Result<(), ReadError> {
    let mut declared: Vec<&str> = context_reconstruction_operations()
        .iter()
        .map(|operation| named_read_operation_name(*operation))
        .collect();
    declared.sort_unstable();
    let mut admitted: Vec<&str> = comparisons
        .iter()
        .filter(|comparison| {
            comparison
                .admitted_query_modes
                .contains(&QueryMode::ContextReconstruction)
        })
        .map(|comparison| comparison.operation_name.as_str())
        .collect();
    admitted.sort_unstable();
    if declared != admitted {
        return Err(ReadError::InvalidField {
            field: "context_reconstruction_operations".to_owned(),
            reason: "the declared table does not match the activated operations the reconstruction intent gate admits"
                .to_owned(),
        });
    }
    Ok(())
}

/// Resolves and validates every declared port binding against the Store read
/// model and this owner's own intent gate.
fn resolve_port_bindings(
    comparisons: &[OperationReadModelComparison],
) -> Result<Vec<LocalReadPortBinding>, ReadError> {
    PORT_DECLARATIONS
        .iter()
        .map(|declaration| resolve_port_binding(declaration, comparisons))
        .collect()
}

/// Resolves one declared port binding.
fn resolve_port_binding(
    declaration: &PortDeclaration,
    comparisons: &[OperationReadModelComparison],
) -> Result<LocalReadPortBinding, ReadError> {
    let comparison = comparisons
        .iter()
        .find(|comparison| comparison.operation == declaration.operation)
        .ok_or(ReadError::Outcome(ReadOutcome::NotRunning))?;
    if !operation_matches_intent(declaration.operation, declaration.intent.mode) {
        return Err(ReadError::InvalidIntentOperation {
            operation: declaration.operation,
            mode: declaration.intent.mode,
        });
    }
    if comparison.owner_admission == OwnerAdmission::NotAdmitted {
        return Err(ReadError::OperationNotAllowed {
            operation: declaration.operation,
            context: "declared local read port".to_owned(),
        });
    }
    Ok(LocalReadPortBinding {
        method: declaration.method,
        operation: declaration.operation,
        operation_name: comparison.operation_name.clone(),
        intent: declaration.intent,
        consistency: declaration.consistency,
        subject_selector: resolve_port_selector(declaration, comparison, PortSelectorRole::Subject)?,
        result_set_bound_selector: resolve_port_selector(
            declaration,
            comparison,
            PortSelectorRole::ResultSetBound,
        )?,
    })
}

/// Resolves the exact Store-declared selector name of one supplied port role.
///
/// A port may supply only a selector the Store declares as required, and exactly
/// one declaration may carry the role.
fn resolve_port_selector(
    declaration: &PortDeclaration,
    comparison: &OperationReadModelComparison,
    role: PortSelectorRole,
) -> Result<Option<String>, ReadError> {
    if !declaration.selectors.contains(&role) {
        return Ok(None);
    }
    let mut declared = comparison
        .declared_parameters
        .iter()
        .filter(|row| row.required && row.owner_role == port_owner_role(role));
    let Some(row) = declared.next() else {
        return Err(ReadError::InvalidField {
            field: format!("local_read_port.{:?}.{:?}", declaration.method, role),
            reason: "the store declares no required selector for this role".to_owned(),
        });
    };
    if declared.next().is_some() {
        return Err(ReadError::InvalidField {
            field: format!("local_read_port.{:?}.{:?}", declaration.method, role),
            reason: "the store declares more than one required selector for this role".to_owned(),
        });
    }
    Ok(Some(row.name.clone()))
}

/// Maps one supplied port role onto the owner role of a Store declaration.
const fn port_owner_role(role: PortSelectorRole) -> OwnerParameterRole {
    match role {
        PortSelectorRole::Subject => OwnerParameterRole::ExactDiscriminator,
        PortSelectorRole::ResultSetBound => OwnerParameterRole::ResultSetBound,
    }
}

/// Resolves the exact activated source identity of one named read.
fn resolve_source_identity(
    operation: NamedReadOperation,
    operation_name: &str,
    entry: &NamedOperationManifest,
) -> ReadSourceIdentity {
    ReadSourceIdentity {
        operation,
        operation_name: operation_name.to_owned(),
        manifest_name: entry.name.clone(),
        manifest_digest: entry.digest.as_str().to_owned(),
    }
}

/// Resolves the exact projection schema identity of one named read.
fn resolve_schema_identity(
    operation: NamedReadOperation,
    entry: &NamedOperationManifest,
) -> Result<ReadSchemaIdentity, ReadError> {
    Ok(ReadSchemaIdentity {
        manifest_name: entry.name.clone(),
        manifest_version: entry.version,
        manifest_schema_digest: entry.schema_digest.clone(),
        parameter_schema_digest: parameter_schema_digest(&project_parameter_schema(operation))?,
    })
}

/// Returns the catalogue manifest of one canonical read operation name.
fn read_manifest(operation_name: &str) -> Result<NamedOperationManifest, ReadError> {
    generated_manifests()?
        .into_iter()
        .find(|entry| entry.name == operation_name)
        .ok_or(ReadError::Outcome(ReadOutcome::NotRunning))
}

/// Returns the generated Store operation catalogue.
fn generated_manifests() -> Result<Vec<NamedOperationManifest>, ReadError> {
    eliot_store_api::generated_operation_manifests()
        .map_err(StoreReadFailure::from)
        .map_err(ReadError::Store)
}

/// Resolves every Store-declared selector of one operation with the closed
/// owner role this crate gives it.
fn resolve_declared_parameter_rows(operation: NamedReadOperation) -> Vec<DeclaredParameterRow> {
    declared_read_parameters(operation)
        .iter()
        .map(|declaration| DeclaredParameterRow {
            name: declaration.name.to_owned(),
            shape_code: declaration.shape.code().to_owned(),
            required: declaration.required,
            owner_role: owner_parameter_role(declaration.name),
        })
        .collect()
}

/// Returns the closed owner role of one Store-declared selector name.
const fn owner_parameter_role(name: &str) -> OwnerParameterRole {
    match name.as_bytes() {
        b"max_records" => OwnerParameterRole::ResultSetBound,
        b"page_limit" => OwnerParameterRole::PageBound,
        b"cursor" => OwnerParameterRole::ContinuationCursor,
        _ => OwnerParameterRole::ExactDiscriminator,
    }
}

/// Sweeps the closed query-mode vocabulary through this owner's intent gate.
fn admitted_query_modes(operation: NamedReadOperation) -> Vec<QueryMode> {
    QUERY_MODE_SWEEP
        .into_iter()
        .filter(|mode| operation_matches_intent(operation, *mode))
        .collect()
}

/// Resolves how this owner admits one operation.
fn owner_admission(operation: NamedReadOperation, modes: &[QueryMode]) -> OwnerAdmission {
    match (is_state_operation(operation), modes.is_empty()) {
        (true, true) => OwnerAdmission::StateOnly,
        (true, false) => OwnerAdmission::StateAndQuery,
        (false, false) => OwnerAdmission::QueryOnly,
        (false, true) => OwnerAdmission::NotAdmitted,
    }
}

/// Resolves the owner's scope declaration for one operation.
fn owner_scope_declaration(operation: NamedReadOperation) -> OwnerScopeDeclaration {
    if requires_scope(operation) {
        OwnerScopeDeclaration::Required
    } else {
        OwnerScopeDeclaration::NotRequired
    }
}

/// Resolves the Store's scope declaration from its catalogue manifest.
const fn store_scope_declaration(requires_scope_id: bool) -> StoreScopeDeclaration {
    if requires_scope_id {
        StoreScopeDeclaration::Required
    } else {
        StoreScopeDeclaration::NotRequired
    }
}

/// Compares the owner's and the Store's scope declarations.
const fn compare_scope_declarations(
    owner: OwnerScopeDeclaration,
    store: StoreScopeDeclaration,
) -> ScopeDeclarationComparison {
    match (owner, store) {
        (
            OwnerScopeDeclaration::Required,
            StoreScopeDeclaration::Required,
        )
        | (
            OwnerScopeDeclaration::NotRequired,
            StoreScopeDeclaration::NotRequired,
        ) => ScopeDeclarationComparison::Agree,
        (OwnerScopeDeclaration::Required, StoreScopeDeclaration::NotRequired) => {
            ScopeDeclarationComparison::OwnerRequiresScopeStoreDoesNot
        }
        (OwnerScopeDeclaration::NotRequired, StoreScopeDeclaration::Required) => {
            ScopeDeclarationComparison::StoreRequiresScopeOwnerDoesNot
        }
    }
}

/// Resolves whether the Store contract types a page coverage statement.
const fn store_coverage_statement(operation: NamedReadOperation) -> StoreCoverageStatement {
    if declares_store_coverage_statement(operation) {
        StoreCoverageStatement::TypedByStoreContract
    } else {
        StoreCoverageStatement::NotTypedByStoreContract
    }
}

/// Resolves whether this owner's reconstruction table lists one operation.
fn context_reconstruction_membership(
    operation: NamedReadOperation,
) -> ContextReconstructionMembership {
    if context_reconstruction_operations().contains(&operation) {
        ContextReconstructionMembership::Listed
    } else {
        ContextReconstructionMembership::NotListed
    }
}

/// Reads one caller-declared positive decimal bound out of the closed selectors.
fn declared_bound(parameters: &NamedParameters, selector: &str) -> Result<Option<u32>, ReadError> {
    let Some(raw) = parameters.as_map().get(selector) else {
        return Ok(None);
    };
    let text = raw.as_str().ok_or_else(|| ReadError::InvalidField {
        field: format!("coverage.{selector}"),
        reason: "declared bound must be a decimal string".to_owned(),
    })?;
    let bound: u32 = text.parse().map_err(|_| ReadError::InvalidField {
        field: format!("coverage.{selector}"),
        reason: "declared bound must be a positive decimal".to_owned(),
    })?;
    if bound == 0 {
        return Err(ReadError::InvalidField {
            field: format!("coverage.{selector}"),
            reason: "declared bound must be a positive decimal".to_owned(),
        });
    }
    Ok(Some(bound))
}

/// Observes how many named read operations the Store has activated.
fn activated_read_operation_count() -> usize {
    activated_read_operations().len()
}

/// Observes how many entries the generated Store operation catalogue holds.
fn manifest_count() -> usize {
    generated_manifests().map_or(0, |entries| entries.len())
}

/// Observes how many read selectors the Store declares across activated reads.
fn declared_selector_count() -> usize {
    activated_read_operations()
        .into_iter()
        .map(|operation| declared_read_parameters(operation).len())
        .sum()
}

/// Observes how many projected parameter-schema fields the activated reads
/// declare.
fn projected_schema_field_count() -> usize {
    activated_read_operations()
        .into_iter()
        .map(|operation| project_parameter_schema(operation).len())
        .sum()
}

/// Observes how many distinct parameter-schema digests the activated reads
/// produce.
fn distinct_parameter_schema_digest_count() -> usize {
    let mut digests = BTreeSet::new();
    for operation in activated_read_operations() {
        if let Ok(digest) = parameter_schema_digest(&project_parameter_schema(operation)) {
            digests.insert(digest);
        }
    }
    digests.len()
}

/// Observes how many activated reads carry a canonical operation name that the
/// generated catalogue also carries.
fn canonical_name_agreement_count() -> usize {
    let names: BTreeSet<String> = match generated_manifests() {
        Ok(entries) => entries.into_iter().map(|entry| entry.name).collect(),
        Err(_) => return 0,
    };
    activated_read_operations()
        .into_iter()
        .filter(|operation| names.contains(named_read_operation_name(*operation)))
        .count()
}

/// Observes how many activated reads the Store contract gates on its typed page
/// coverage statement.
fn typed_coverage_statement_operation_count() -> usize {
    activated_read_operations()
        .into_iter()
        .filter(|operation| declares_store_coverage_statement(*operation))
        .count()
}
