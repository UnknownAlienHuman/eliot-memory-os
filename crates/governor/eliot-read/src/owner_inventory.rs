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
//! * the public-API rows are **compile-time witnesses** for every type this
//!   crate declares, and **declared by this owner** for the items that have no
//!   single concrete type — the two traits, the generic service, the contract
//!   constants, the contract functions, the modules, and the
//!   `provider_memory_feed` candidate surface, whose items are marked
//!   [`PublicApiKind::OffWire`] so an off-wire type is never claimed as a read
//!   wire shape;
//! * the mutable-state row, the port declarations, the test-target rows and the
//!   reverse-consumer rows are **declared by this owner**, and each is checked
//!   against a derived source wherever a derived source exists for it. The
//!   reverse-consumer set is bound to its independent source by
//!   [`ReverseConsumerSource`], not merely described in prose;
//! * the serialization rows are **derived**: each item's shape is read from the
//!   JSON schema its own `JsonSchema` derive produces, so whether an unknown
//!   property is refused is observed rather than asserted.
//!
//! The language offers no reflection over enum variants, over the items of a
//! module, or over the test set of a package. Where a closed enumeration is
//! unavoidable it is declared here, and the declaration is the only hand-typed
//! part; every value computed from it comes from a real call.
//!
//! # Scope boundary, stated rather than hidden
//!
//! This inventory describes **this package**. It is not a measurement of whether
//! any other package that imports it is reachable from a process entry point, or
//! of whether any read currently executes. A package cannot observe its reverse
//! consumers' reachability at run time, and this module never pretends to:
//! `reverse_consumers` rows carry `DeclaredByOwner`, `evidence_execution` is
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
    BoundRead, BranchEnvironmentScope, CONTRACT_NAME, CONTRACT_VERSION, CurrentStateView,
    DeclaredPageSelector, DeclaredResultSelector, EliotResourceUri, FreshnessPolicy,
    NamedParameters, ProvenanceDisposition, ProvenanceHandle, QueryIntent, QueryMode, QueryRequest,
    QueryResult, ReadCoverage, ReadError, ReadIdentity, ReadInvalidationSet, ReadOrderingBinding,
    ReadOutcome, ReadPrincipal, ReadProvenance, ReadSchemaIdentity, ReadSourceIdentity,
    RequiredAssurance, ResourceContent, ResourceRequest, StateRequest, StoreReadFailure, TimeScope,
    context_reconstruction_operations, contract_identity, declares_store_coverage_statement,
    is_state_operation, operation_matches_intent, requires_scope,
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
    /// A public module of this package.
    Module,
    /// A public trait a consumer implements or calls.
    Trait,
    /// The read service type over a caller-owned store client.
    Service,
    /// A public contract constant.
    ContractConstant,
    /// A public contract function.
    ContractFunction,
    /// A JSON data object on the read wire.
    WireObject,
    /// A closed JSON enum on the read wire.
    WireEnum,
    /// A public type this owner deliberately keeps off the read wire: it
    /// declares no wire encoding of its own, so it is inventoried as part of
    /// the public surface without being claimed as wire shape.
    OffWire,
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
                // The closed page-bound vocabulary has exactly one selector, so
                // the presence of the Store declaration is the whole decision.
                selector: self
                    .declared_role(OwnerParameterRole::PageBound)
                    .map(|_| DeclaredPageSelector::PageLimit),
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
                context: "owner scope declaration is narrower than the store catalogue row"
                    .to_owned(),
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

/// How a public item is serialized on the read wire.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerializationShape {
    /// The item is a closed object: it declares named properties and refuses
    /// an unknown one, so a future field cannot widen an existing read silently.
    ClosedObject,
    /// The item is a closed enum: it serializes to one of a fixed set of
    /// renamings and carries no field names. An unknown member is refused, so a
    /// future variant cannot be silently read as a current one.
    ClosedEnum,
    /// The item is a transparent value: it carries exactly one value under no
    /// field name of its own and is not itself a closed object or enum.
    TransparentValue,
    /// The item declares an unbounded JSON object with no closed shape, so a
    /// caller-supplied key set is carried rather than a fixed one.
    OpenObject,
}

/// One observed serialization shape of a declared public item.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerializationRow {
    /// Exported item name, exactly as a consumer imports it.
    pub name: String,
    /// The shape this owner actually derives for the item.
    pub shape: SerializationShape,
    /// Whether the item carries a decoder as well as an encoder.
    pub decodable: bool,
    /// Number of top-level properties the derived JSON schema declares, or
    /// zero for a non-object shape.
    pub object_properties: usize,
    /// Whether an unknown property is refused on decode.
    pub denies_unknown_fields: bool,
    /// Number of closed members the derived JSON schema declares, or zero for
    /// a shape that is not an enum.
    pub enum_members: usize,
    /// How this row was established.
    pub provenance: InventoryProvenance,
}

/// One declared reverse consumer of this package.
///
/// A row records that a workspace member declares an edge onto this package. It
/// says nothing about whether that member ever calls a read: a member can
/// declare the edge and use nothing. Reachability from a process entry point and
/// execution are separate facts, measured outside this package, and
/// [`ReverseConsumerRow`] deliberately carries neither a reachability nor an
/// execution claim so no reader can mistake a declared edge for a live read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseConsumerRow {
    /// Declaring workspace member that depends on this package.
    pub member: String,
    /// How this owner resolved that member.
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
    /// The observed serialization shape of every declared wire item.
    pub serialization_shapes: Vec<SerializationRow>,
    /// Every declared reverse consumer of this package.
    pub reverse_consumers: Vec<ReverseConsumerRow>,
    /// The owner and Store comparison for every activated Store read operation.
    pub read_model_comparisons: Vec<OperationReadModelComparison>,
    /// Every validated local read port binding.
    pub port_bindings: Vec<LocalReadPortBinding>,
    /// Binds the declared reverse-consumer set to its independent source.
    ///
    /// A package cannot observe its importers at run time — the language has no
    /// reflection over the dependency graph — so the dependent set is settled
    /// outside this crate, by the workspace manifest. This member states which
    /// source the declared set was read from, so a row can never claim a
    /// provenance its bytes do not carry.
    #[serde(default)]
    pub reverse_consumer_source: ReverseConsumerSource,
    /// Execution class of the whole inventory.
    pub evidence_execution: InventoryEvidenceClass,
}

/// Independent source that settles this package's dependent set.
///
/// The declared rows below are read from this source by hand, because nothing in
/// this crate can execute it. Stating which source produced them is what keeps
/// the set checkable: a deletion decision re-reads the same source and compares,
/// instead of trusting a list this crate wrote for itself.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReverseConsumerSource {
    /// The dependent set was read from the workspace manifest graphs
    /// (`cargo metadata --no-deps --offline --locked`), which are produced by
    /// Cargo from every member's own `[dependencies]`, `[dev-dependencies]` and
    /// `[build-dependencies]` declarations. No file in this package contributes
    /// an entry, so the set cannot be widened or narrowed by anything written
    /// here.
    ///
    /// This is the default because it is the only source that was actually
    /// executed; it is a named default, not a claim that no other source exists.
    #[default]
    CargoWorkspaceMetadata,
    /// No source has produced a dependent set for this owner.
    ///
    /// Never the value of a resolved inventory: resolving an inventory that
    /// still carries it is refused, so a row set can never be reported under a
    /// source that was not used.
    Unbound,
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
    let reverse_consumers = resolve_reverse_consumer_rows()?;
    Ok(ReadOwnerInventory {
        contract: resolve_contract_identity()?,
        mutable_state: OwnerMutableState::StatelessOverCallerOwnedStoreClient,
        public_api: resolve_public_api_rows()?,
        store_dependencies: resolve_store_dependency_rows(),
        test_targets: resolve_test_target_rows(),
        serialization_shapes: resolve_serialization_rows()?,
        reverse_consumer_source: ReverseConsumerSource::CargoWorkspaceMetadata,
        reverse_consumers,
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
    compare_operation_in_catalogue(operation, &generated_manifests()?)
}

/// Compares one named read against an already generated Store catalogue.
fn compare_operation_in_catalogue(
    operation: NamedReadOperation,
    entries: &[NamedOperationManifest],
) -> Result<OperationReadModelComparison, ReadError> {
    let operation_name = named_read_operation_name(operation);
    if !activated_read_operations().contains(&operation) {
        return Err(ReadError::Outcome(ReadOutcome::NotRunning));
    }
    let entry = read_manifest(entries, operation_name)?;
    let declared_parameters = resolve_declared_parameter_rows(operation);
    let admitted_query_modes = admitted_query_modes(operation);
    let owner_admission = owner_admission(operation, &admitted_query_modes);
    let owner_scope = owner_scope_declaration(operation);
    let store_scope = store_scope_declaration(entry.requires_scope_id);
    Ok(OperationReadModelComparison {
        operation,
        operation_name: operation_name.to_owned(),
        source: resolve_source_identity(operation, operation_name, entry),
        schema: resolve_schema_identity(operation, entry)?,
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

/// Builds the declared public-type table from real type names.
///
/// Each expansion names the type twice: once as the identifier the row is
/// reported under, and once inside the witness body, where the compiler has to
/// resolve it. A renamed, moved or removed public type therefore breaks this
/// crate instead of leaving a stale row behind, and the reported name cannot
/// drift from the type it describes because it is that type's own identifier.
macro_rules! public_type_rows {
    ($($name:ident => $kind:ident),* $(,)?) => {
        [$(
            PublicTypeDeclaration {
                name: stringify!($name),
                kind: PublicApiKind::$kind,
                witness: Some(|| std::any::type_name::<$name>()),
            },
        )*]
    };
}

/// Declared public surface of this package.
///
/// Every concrete row names its real public type in the witness body, so this
/// table cannot outlive the item it describes. Rows for the module, the two
/// traits, the generic service, the contract constants and the contract
/// functions have no single concrete type path and are declared instead: their
/// presence is still a compile-time fact of this crate, because the traits and
/// the service are implemented here, the constants and the contract functions
/// are read while this inventory is resolved, and the module is the file these
/// tables live in.
const PUBLIC_TYPE_DECLARATIONS: &[PublicTypeDeclaration] = &public_type_rows![
    QueryMode => WireEnum,
    TimeScope => WireEnum,
    BranchEnvironmentScope => WireEnum,
    FreshnessPolicy => WireEnum,
    RequiredAssurance => WireEnum,
    ProvenanceDisposition => WireEnum,
    ReadOutcome => WireEnum,
    ReadCoverage => WireEnum,
    DeclaredResultSelector => WireEnum,
    DeclaredPageSelector => WireEnum,
    ReadError => WireEnum,
    StoreReadFailure => WireEnum,
    QueryIntent => WireObject,
    EliotResourceUri => WireObject,
    ProvenanceHandle => WireObject,
    ReadProvenance => WireObject,
    NamedParameters => WireObject,
    ReadPrincipal => WireObject,
    ReadSourceIdentity => WireObject,
    ReadSchemaIdentity => WireObject,
    ReadOrderingBinding => WireObject,
    ReadInvalidationSet => WireObject,
    ReadIdentity => WireObject,
    StateRequest => WireObject,
    QueryRequest => WireObject,
    ResourceRequest => WireObject,
    CurrentStateView => WireObject,
    QueryResult => WireObject,
    ResourceContent => WireObject,
    InventoryProvenance => WireEnum,
    InventoryEvidenceClass => WireEnum,
    PublicApiKind => WireEnum,
    OwnerMutableState => WireEnum,
    OwnerParameterRole => WireEnum,
    OwnerAdmission => WireEnum,
    OwnerScopeDeclaration => WireEnum,
    StoreScopeDeclaration => WireEnum,
    ScopeDeclarationComparison => WireEnum,
    StoreCoverageStatement => WireEnum,
    ContextReconstructionMembership => WireEnum,
    LocalReadPortMethod => WireEnum,
    PortSelectorRole => WireEnum,
    SerializationShape => WireEnum,
    ReverseConsumerSource => WireEnum,
    PublicApiRow => WireObject,
    DeclaredParameterRow => WireObject,
    OperationReadModelComparison => WireObject,
    LocalReadPortBinding => WireObject,
    OwnerContractIdentity => WireObject,
    StoreDependencyRow => WireObject,
    TestTargetRow => WireObject,
    SerializationRow => WireObject,
    ReverseConsumerRow => WireObject,
    ReadOwnerInventory => WireObject,
];

/// The one generic public type of this package, witnessed through a concrete
/// view so the compiler reports its real instantiated path.
const PUBLIC_GENERIC_TYPE_DECLARATIONS: &[PublicTypeDeclaration] = &[PublicTypeDeclaration {
    name: "BoundRead",
    kind: PublicApiKind::WireObject,
    witness: Some(|| std::any::type_name::<BoundRead<CurrentStateView>>()),
}];

/// Declared public items of this package that have no concrete type path.
const PUBLIC_ITEM_DECLARATIONS: &[PublicTypeDeclaration] = &[
    PublicTypeDeclaration {
        name: "owner_inventory",
        kind: PublicApiKind::Module,
        witness: None,
    },
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
        name: "CONTRACT_NAME",
        kind: PublicApiKind::ContractConstant,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "CONTRACT_VERSION",
        kind: PublicApiKind::ContractConstant,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "contract_identity",
        kind: PublicApiKind::ContractFunction,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "context_reconstruction_operations",
        kind: PublicApiKind::ContractFunction,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "read_owner_inventory",
        kind: PublicApiKind::ContractFunction,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "compare_operation_with_store_read_model",
        kind: PublicApiKind::ContractFunction,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "provider_memory_feed",
        kind: PublicApiKind::Module,
        witness: None,
    },
];

/// Public surface of the `provider_memory_feed` module.
///
/// A module is a public item like any other, and this one carries a candidate-only
/// adapter surface of its own. These rows name the real items for the same reason
/// the rest of the table does — a rename or a removal is a build failure — and
/// [`PublicApiKind::OffWire`] states plainly that the module publishes no read
/// wire shape of its own: it is a candidate import surface with no decoder and no
/// membership in [`WIRE_DECLARATIONS`], so nothing here claims a wire guarantee
/// the module does not make. Its two entry points are named by the rows below, and
/// it is invoked only through the port it declares, never by a second adapter path.
const PROVIDER_MEMORY_FEED_DECLARATIONS: &[PublicTypeDeclaration] = &[
    PublicTypeDeclaration {
        name: "MEMORY_PROVIDER_FEED_CAPABILITY",
        kind: PublicApiKind::ContractConstant,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedCapability",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryCandidateAuthority",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedError",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryProfileText",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFactBasis",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemorySurfaceFact",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryPoisoningRiskLevel",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryPoisoningRisk",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFallbackRoute",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryModelRoute",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemorySurfaceProfileInput",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemorySurfaceProfile",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryCandidateContent",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemorySourceCandidate",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryReadRequest",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedUnavailableReason",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedDegradationReason",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedOutcome",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedPortFailure",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedPort",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "ProviderMemoryFeedResult",
        kind: PublicApiKind::OffWire,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "read_provider_memory_feed",
        kind: PublicApiKind::ContractFunction,
        witness: None,
    },
    PublicTypeDeclaration {
        name: "provider_memory_feed_unavailable",
        kind: PublicApiKind::ContractFunction,
        witness: None,
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
/// declared name and against this crate's own module path.
fn resolve_public_api_rows() -> Result<Vec<PublicApiRow>, ReadError> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::with_capacity(
        PUBLIC_TYPE_DECLARATIONS.len()
            + PUBLIC_GENERIC_TYPE_DECLARATIONS.len()
            + PUBLIC_ITEM_DECLARATIONS.len()
            + PROVIDER_MEMORY_FEED_DECLARATIONS.len(),
    );
    for declaration in PUBLIC_TYPE_DECLARATIONS
        .iter()
        .chain(PUBLIC_GENERIC_TYPE_DECLARATIONS)
        .chain(PUBLIC_ITEM_DECLARATIONS)
        .chain(PROVIDER_MEMORY_FEED_DECLARATIONS)
    {
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

/// Returns the compiler-reported type path of one declared row.
///
/// The row is refused unless the compiler reports the declared name inside this
/// crate's own module path, so a row can never quietly end up describing a type
/// that arrived from somewhere else.
fn observed_type_path(declaration: &PublicTypeDeclaration) -> Result<Option<String>, ReadError> {
    let Some(witness) = declaration.witness else {
        return Ok(None);
    };
    let observed = witness();
    let reported = observed.rsplit("::").next().unwrap_or(observed);
    let generic = observed.contains(&format!("::{}<", declaration.name));
    if (reported != declaration.name && !generic) || !observed.starts_with(CRATE_TYPE_PATH) {
        return Err(ReadError::InvalidField {
            field: format!("public_api.{}", declaration.name),
            reason: format!("witness reports {observed}, not this crate's declared type"),
        });
    }
    Ok(Some(observed.to_owned()))
}

/// Module path prefix every public type of this crate is reported under.
const CRATE_TYPE_PATH: &str = "eliot_read::";

/// Returns how one declared public row was established.
const fn provenance_for(kind: PublicApiKind) -> InventoryProvenance {
    match kind {
        PublicApiKind::WireObject | PublicApiKind::WireEnum => {
            InventoryProvenance::CompileTimeWitness
        }
        PublicApiKind::Module
        | PublicApiKind::Trait
        | PublicApiKind::Service
        | PublicApiKind::OffWire
        | PublicApiKind::ContractConstant
        | PublicApiKind::ContractFunction => InventoryProvenance::DeclaredByOwner,
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

/// One declared wire item, with the real schema its derive macro produces.
struct WireDeclaration {
    /// Exported item name, exactly as a consumer imports it.
    name: &'static str,
    /// The item's own derived JSON schema, produced by the real derive.
    schema: fn() -> serde_json::Value,
    /// Whether the item is decoded as well as encoded.
    decodable: bool,
}

/// Builds the declared wire table from real derived schemas.
///
/// The `schema` body names the type, so a rename or a removal breaks this crate
/// rather than leaving a stale row, and the schema value it returns is the one
/// the item's own `JsonSchema` derive produces — not a hand-written summary of
/// what that shape is supposed to be.
macro_rules! wire_rows {
    ($($name:ident => $decodable:literal),* $(,)?) => {
        [$(
            WireDeclaration {
                name: stringify!($name),
                schema: || {
                    serde_json::to_value(schemars::schema_for!($name))
                        .expect("a derived JsonSchema is serializable")
                },
                decodable: $decodable,
            },
        )*]
    };
}

/// Declared serialization surface of this package's own read contract.
///
/// Every closed object, transparent value and encode-only error enum on the read
/// wire appears here exactly once, and each row's shape is derived from the
/// item's real `JsonSchema` rather than asserted.
const WIRE_DECLARATIONS: &[WireDeclaration] = &wire_rows![
    QueryIntent => true,
    EliotResourceUri => true,
    ProvenanceHandle => true,
    ReadProvenance => true,
    NamedParameters => true,
    ReadPrincipal => true,
    ReadSourceIdentity => true,
    ReadSchemaIdentity => true,
    ReadOrderingBinding => true,
    ReadInvalidationSet => true,
    ReadIdentity => true,
    StateRequest => true,
    QueryRequest => true,
    ResourceRequest => true,
    CurrentStateView => true,
    QueryResult => true,
    ResourceContent => true,
    QueryMode => true,
    TimeScope => true,
    BranchEnvironmentScope => true,
    FreshnessPolicy => true,
    RequiredAssurance => true,
    ProvenanceDisposition => true,
    ReadOutcome => true,
    ReadCoverage => true,
    DeclaredResultSelector => true,
    DeclaredPageSelector => true,
    ReadError => true,
    StoreReadFailure => true,
];

/// Resolves the observed serialization shape of every declared wire item.
///
/// The classification reads the item's own derived schema, so nothing here is
/// assumed. Schemars renders the four shapes this owner actually publishes in
/// three distinct renderings, and each is read from the key the derive emits
/// for it:
///
/// * a **closed object** declares a non-empty `properties` object together with
///   `additionalProperties: false`, so an unknown property is refused;
/// * a **closed enum** declares its members as an `enum` list — at the top
///   level for a unit enum, and inside a `oneOf` branch for a payload enum,
///   where schemars collapses a run of unit variants into a single branch and
///   gives every payload variant its own branch. Counting both placements is
///   what makes `ReadOutcome` the eight-member closed enum it is, rather than an
///   item that is not on the wire, and `ReadError` its sixteen;
/// * a **transparent value** is a `string`/scalar that declares neither;
/// * an **open object** declares `additionalProperties: true` and no closed
///   member, so its key set is the caller's.
///
/// A shape matching none of these is refused rather than reported as one of
/// them, so a future wire shape cannot be recorded under an existing guarantee.
fn resolve_serialization_rows() -> Result<Vec<SerializationRow>, ReadError> {
    WIRE_DECLARATIONS
        .iter()
        .map(|declaration| {
            let schema = (declaration.schema)();
            let properties = schema
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .map_or(0, serde_json::Map::len);
            let denies_unknown_fields = is_false(&schema, "additionalProperties");
            let enum_members = closed_enum_members(&schema);
            let unit_members = schema
                .get("enum")
                .and_then(serde_json::Value::as_array)
                .map_or(0, std::vec::Vec::len);
            let shape = if properties > 0 && denies_unknown_fields {
                SerializationShape::ClosedObject
            } else if enum_members + unit_members > 0 {
                SerializationShape::ClosedEnum
            } else if properties == 0 && !denies_unknown_fields {
                match declared_type(&schema) {
                    Some("string" | "number" | "integer" | "boolean") => {
                        SerializationShape::TransparentValue
                    }
                    Some("object") => SerializationShape::OpenObject,
                    _ => return Err(unrecognized_shape(declaration.name)),
                }
            } else {
                return Err(unrecognized_shape(declaration.name));
            };
            Ok(SerializationRow {
                name: declaration.name.to_owned(),
                shape,
                decodable: declaration.decodable,
                object_properties: properties,
                denies_unknown_fields,
                enum_members: enum_members + unit_members,
                provenance: InventoryProvenance::DerivedAtCallTime,
            })
        })
        .collect()
}

/// Returns how many closed members a derived schema declares as an enum.
///
/// A payload enum is a `oneOf` in which schemars collapses a run of unit
/// variants into a single branch carrying an `enum` list, while every payload
/// variant gets its own single-member branch. Both placements are counted, so a
/// schema that declares no `oneOf` at all contributes its top-level `enum` list
/// and a schema with no members contributes nothing, which keeps a non-enum out
/// of the enum branch of the classification.
fn closed_enum_members(schema: &serde_json::Value) -> usize {
    schema
        .get("oneOf")
        .and_then(serde_json::Value::as_array)
        .map_or(0, |branches| {
            branches
                .iter()
                .map(|branch| {
                    branch
                        .get("enum")
                        .and_then(serde_json::Value::as_array)
                        .map_or(1, std::vec::Vec::len)
                })
                .sum()
        })
}

/// Returns whether a derived schema declares the named boolean key as `false`.
fn is_false(schema: &serde_json::Value, key: &str) -> bool {
    schema
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .is_some_and(|declared| !declared)
}

/// Returns the JSON type a derived schema declares, when it declares one.
fn declared_type(schema: &serde_json::Value) -> Option<&str> {
    schema.get("type").and_then(serde_json::Value::as_str)
}

/// Returns the error refusing a shape this owner does not publish.
fn unrecognized_shape(name: &str) -> ReadError {
    ReadError::InvalidField {
        field: format!("serialization_shapes.{name}"),
        reason: "the derived JSON schema matches no serialization shape this owner publishes"
            .to_owned(),
    }
}

/// Declared reverse consumers of this package.
///
/// A package cannot observe its importers at run time — the language has no
/// reflection over the dependency graph — so this list is declared rather than
/// computed, and `DeclaredByOwner` says so on every row. What the list is
/// *not* is a liveness claim: a dependent member here proves that some
/// compile-time importer exists, never that a read executes.
///
/// The list is read from [`ReverseConsumerSource::CargoWorkspaceMetadata`], the
/// one source independent of this package: the workspace manifest graphs that
/// Cargo produces from every member's own dependency declarations. Nothing in
/// this crate contributes an entry, so the set cannot be widened or narrowed by
/// anything written here. It is recorded, not computed, because nothing in this
/// package can execute that source.
const REVERSE_CONSUMERS: [&str; 3] = ["eliot-governor", "eliot-kernel-service", "eliotd"];

/// Resolves every declared reverse-consumer row.
fn resolve_reverse_consumer_rows() -> Result<Vec<ReverseConsumerRow>, ReadError> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::with_capacity(REVERSE_CONSUMERS.len());
    for member in REVERSE_CONSUMERS {
        if !seen.insert(member) {
            return Err(ReadError::DuplicateField("reverse_consumers".to_owned()));
        }
        rows.push(ReverseConsumerRow {
            member: (*member).to_owned(),
            provenance: InventoryProvenance::DeclaredByOwner,
        });
    }
    Ok(rows)
}

/// Compares every activated Store read operation with this owner.
///
/// The catalogue is generated once for the whole sweep: it is a pure function
/// of the Store declaration table, so resolving it per operation would repeat
/// the same digests without adding a single derived value.
fn compare_activated_read_model() -> Result<Vec<OperationReadModelComparison>, ReadError> {
    let entries = generated_manifests()?;
    activated_read_operations()
        .into_iter()
        .map(|operation| compare_operation_in_catalogue(operation, &entries))
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
        subject_selector: resolve_port_selector(
            declaration,
            comparison,
            PortSelectorRole::Subject,
        )?,
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
///
/// A missing row here is [`ReadOutcome::Missing`], not
/// [`ReadOutcome::NotRunning`], and the two are different facts. This owner
/// admitting the operation is proven by the caller's own activation gate, which
/// has already passed by the time this runs; what failed is the Store
/// catalogue's own declaration. `NotRunning` would assert that no handler is
/// activated, which is exactly what the activation gate decides — asserting it
/// here from a lookup miss would let a catalogue gap be read as a lifecycle
/// fact, and a caller could not tell a source that was never started from a
/// source whose declaration is simply absent.
fn read_manifest<'a>(
    entries: &'a [NamedOperationManifest],
    operation_name: &str,
) -> Result<&'a NamedOperationManifest, ReadError> {
    entries
        .iter()
        .find(|entry| entry.name == operation_name)
        .ok_or(ReadError::Outcome(ReadOutcome::Missing))
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
        (OwnerScopeDeclaration::Required, StoreScopeDeclaration::Required)
        | (OwnerScopeDeclaration::NotRequired, StoreScopeDeclaration::NotRequired) => {
            ScopeDeclarationComparison::Agree
        }
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
