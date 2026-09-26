//! Production Governor closure-enumeration adapter for P-07.
//!
//! The canonical Governor owner admits delegations into its durable grant
//! graph; this adapter serves the exact admitted closure (plus the member
//! intents and opaque records the Governor service resolved from canonical
//! state) to the P-07 port through
//! [`RootGrantHydrationSource`](crate::grant_activation_port::RootGrantHydrationSource).
//! It replaces test doubles on the production path: enumeration reads the
//! restored durable graph at its revision, never caller material and never
//! process-local port memory.
//!
//! Ownership stays exact:
//!
//! - the graph is restored only from a durable
//!   [`GrantGraphRecoverySnapshot`](eliot_authority::GrantGraphRecoverySnapshot)
//!   under explicit current
//!   [`RevocationHistoryEvidence`](eliot_authority::RevocationHistoryEvidence)
//!   (absent history refuses; it is never read as absence of revocation);
//! - member intents and opaque records arrive inside the restore bundle from
//!   the Governor service's canonical state; the adapter indexes them but
//!   never invents, defaults, or re-derives them;
//! - alternate-path survivors arrive keyed by closure target from the same
//!   service decision; the adapter attaches them verbatim and never evaluates
//!   coverage itself;
//! - the port still validates everything (structure, owner equality,
//!   revision, fence, epoch, ceilings, opaque agreement) before any mutation.
//!
//! Refreshing the adapter (new snapshot, new revision, new admissions) is an
//! explicit [`GovernorClosureSource::refresh`] from newer durable state, not
//! an incremental mutation: the port's revision watermark and digest gates
//! keep serving the exact revision each operation committed under.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_authority::{GrantGraphRecoverySnapshot, RevocationHistoryEvidence};
use eliot_receipts::{GrantClosureDeclaration, ReceiptIdentity};

use crate::error::{KernelError, validate_id};
use crate::grant_activation_port::{
    GrantClosureEnumeration, GrantClosureMember, GrantClosureSurvivor, RootGrantHydration,
    RootGrantHydrationSource,
};
use crate::introduction_lifecycle::IntroductionHydration;

/// Governor-admitted closure material used to build (or refresh) a
/// [`GovernorClosureSource`].
///
/// Every field comes from durable canonical Governor state at one update:
///
/// - `graph_snapshot` is the durable grant-graph snapshot the closure is
///   enumerated from;
/// - `revocation_history` is the explicit current revocation-history
///   evidence observed at the snapshot; `None` refuses the restore because
///   unavailable history is not absence of revocation;
/// - `members` are the complete semantic intents plus opaque ORS records the
///   Governor service resolved for the admitted grants, keyed by grant
///   identity on restore;
/// - `roots` are the complete root hydrations for single-root requests the
///   service resolved, keyed by grant identity;
/// - `introductions` are the complete introduction hydrations the service
///   resolved, keyed by introduction identity on restore;
/// - `preserved` are the owner-declared alternate-path survivors keyed by
///   closure target grant identity;
/// - `canonical_receipts` are completed canonical second-phase receipt
///   identities keyed by the immutable ORS closure operation identity.
#[derive(Clone, Debug)]
pub struct GovernorClosureRestore {
    /// Durable grant-graph snapshot the closure is enumerated from.
    pub graph_snapshot: GrantGraphRecoverySnapshot,
    /// Explicit current revocation-history evidence observed at the
    /// snapshot. `None` refuses the restore: unavailable history is not
    /// absence of revocation.
    pub revocation_history: Option<RevocationHistoryEvidence>,
    /// Complete semantic intents plus opaque ORS records the Governor
    /// service resolved for the admitted grants.
    pub members: Vec<GrantClosureMember>,
    /// Complete root hydrations for single-root requests the service
    /// resolved.
    pub roots: Vec<RootGrantHydration>,
    /// Complete introduction hydrations the service resolved for admitted
    /// introductions. The introduction-hydration owner serves thin
    /// introduction activation from this material; absent material stays a
    /// typed refusal, never a fabricated introduction.
    pub introductions: Vec<IntroductionHydration>,
    /// Complete versioned owner declarations keyed by target identity. The
    /// Kernel indexes these declarations and never re-derives semantic graph
    /// membership from process-local state.
    pub declarations: Vec<GrantClosureDeclaration>,
    /// Owner-declared alternate-path survivors keyed by closure target
    /// grant identity.
    pub preserved: Vec<(String, Vec<GrantClosureSurvivor>)>,
    /// Exact canonical store receipt identities whose second phase has
    /// completed, keyed by ORS grant-closure operation identity.
    ///
    /// An absent entry leaves the committed first phase explicitly pending.
    /// The Kernel never derives either value from a closure request or
    /// fabricates a receipt when the owner has not completed canonical
    /// reconciliation.
    pub canonical_receipts: BTreeMap<String, ReceiptIdentity>,
}

/// Stable schema identity for the Governor-to-Kernel closure restore wire.
pub const GOVERNOR_CLOSURE_RESTORE_SCHEMA: &str = "eliot.kernel.governor-closure-restore";
/// Current Governor-to-Kernel closure restore wire version.
pub const GOVERNOR_CLOSURE_RESTORE_VERSION: u16 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernorClosureRestoreWire {
    schema: String,
    version: u16,
    graph_snapshot: GrantGraphRecoverySnapshot,
    revocation_history: Option<RevocationHistoryEvidence>,
    members: Vec<GrantClosureMember>,
    roots: Vec<RootGrantHydration>,
    introductions: Vec<IntroductionHydration>,
    declarations: Vec<GrantClosureDeclaration>,
    preserved: Vec<(String, Vec<GrantClosureSurvivor>)>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    canonical_receipts: BTreeMap<String, ReceiptIdentity>,
}

impl serde::Serialize for GovernorClosureRestore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        GovernorClosureRestoreWire {
            schema: GOVERNOR_CLOSURE_RESTORE_SCHEMA.to_owned(),
            version: GOVERNOR_CLOSURE_RESTORE_VERSION,
            graph_snapshot: self.graph_snapshot.clone(),
            revocation_history: self.revocation_history.clone(),
            members: self.members.clone(),
            roots: self.roots.clone(),
            introductions: self.introductions.clone(),
            declarations: self.declarations.clone(),
            preserved: self.preserved.clone(),
            canonical_receipts: self.canonical_receipts.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for GovernorClosureRestore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = GovernorClosureRestoreWire::deserialize(deserializer)?;
        if wire.schema != GOVERNOR_CLOSURE_RESTORE_SCHEMA
            || wire.version != GOVERNOR_CLOSURE_RESTORE_VERSION
        {
            return Err(serde::de::Error::custom(
                "governor closure restore has an unsupported schema or version",
            ));
        }
        Ok(Self {
            graph_snapshot: wire.graph_snapshot,
            revocation_history: wire.revocation_history,
            members: wire.members,
            roots: wire.roots,
            introductions: wire.introductions,
            declarations: wire.declarations,
            preserved: wire.preserved,
            canonical_receipts: wire.canonical_receipts,
        })
    }
}

/// Admitted material behind one [`GovernorClosureSource`].
#[derive(Debug)]
struct AdmittedClosureState {
    revision: u64,
    authority_roots: Vec<String>,
    revoked_grants: Vec<String>,
    non_admissible: BTreeSet<String>,
    declarations: BTreeMap<String, GrantClosureDeclaration>,
    members: BTreeMap<String, GrantClosureMember>,
    roots: BTreeMap<String, RootGrantHydration>,
    introductions: BTreeMap<String, IntroductionHydration>,
}

/// Production [`RootGrantHydrationSource`] reading the restored durable
/// Governor grant graph.
///
/// Constructed once from [`GovernorClosureRestore`] and refreshed only from
/// newer durable restores. Shared behind `Arc` with the P-07 port; interior
/// updates replace the whole admitted state so readers never observe a half
/// refreshed graph.
#[derive(Debug)]
pub struct GovernorClosureSource {
    state: Mutex<AdmittedClosureState>,
}

impl GovernorClosureSource {
    /// Builds the adapter from one durable Governor restore.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::RecoveryUnavailable`] when the revocation
    /// history is absent or not current, the snapshot is invalid, or the
    /// admitted material disagrees with the restored graph; returns
    /// [`KernelError::InvalidField`] for duplicate or blank admitted
    /// identities.
    pub fn restore(restore: GovernorClosureRestore) -> Result<Self, KernelError> {
        Ok(Self {
            state: Mutex::new(Self::admit(restore)?),
        })
    }

    /// Refreshes the adapter from a newer durable Governor restore.
    ///
    /// The whole admitted state is replaced atomically under the state lock;
    /// in-flight port operations keep serving the exact revision they
    /// validated under, and later operations observe the new revision
    /// through the port's watermark and digest gates.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::restore`], leaving the previous
    /// admitted state installed.
    pub fn refresh(&self, restore: GovernorClosureRestore) -> Result<(), KernelError> {
        let admitted = Self::admit(restore)?;
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = admitted;
        Ok(())
    }

    /// Returns the exact durable graph revision this adapter serves.
    ///
    /// The daemon/service bootstrap binds the port at this revision and
    /// refuses any expected revision that disagrees: the port never serves a
    /// closure from an unbound revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.lock_state().revision
    }

    /// Returns the distinct lineage roots admitted in the current restore, in
    /// sorted order.
    ///
    /// Roots are collected from the canonical graph snapshot plus admitted
    /// member, root, and introduction intents. The graph is never traversed or
    /// re-derived here; the snapshot only supplies closed lineage scope. The
    /// bootstrap advances the durable per-root revision watermark for exactly
    /// these roots.
    #[must_use]
    pub fn authority_roots(&self) -> Vec<String> {
        let state = self.lock_state();
        let mut roots = BTreeSet::new();
        for root in &state.authority_roots {
            roots.insert(root.clone());
        }
        for member in state.members.values() {
            roots.insert(member.intent.authority_root_ref.clone());
        }
        for root in state.roots.values() {
            roots.insert(root.intent.authority_root_ref.clone());
        }
        for hydration in state.introductions.values() {
            roots.insert(hydration.intent.authority_root_ref.clone());
        }
        roots.into_iter().collect()
    }

    /// Returns every grant suppressed by the exact restored graph revision
    /// and current revocation history in sorted order.
    ///
    /// The Kernel bootstrap uses this closed set to require a matching durable
    /// fence and closure receipt before it publishes the owner. A revoked
    /// identity missing from ORS therefore remains recovery-required instead
    /// of becoming admissible from process-local absence.
    #[must_use]
    pub fn revoked_grants(&self) -> Vec<String> {
        self.lock_state().revoked_grants.clone()
    }

    #[allow(
        clippy::too_many_lines,
        reason = "restore validation keeps history, declarations, hydrations, and alternate paths in one fail-closed sequence"
    )]
    fn admit(restore: GovernorClosureRestore) -> Result<AdmittedClosureState, KernelError> {
        validate_canonical_receipt_links(&restore.canonical_receipts)?;
        let history = restore.revocation_history.as_ref().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "closure owner revocation history is unavailable; unavailable history is not absence of revocation".to_owned(),
            )
        })?;
        let graph_snapshot = restore.graph_snapshot;
        graph_snapshot
            .validate()
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
        let validated_history = history
            .require_current()
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
        let revision = graph_snapshot.revision;
        let mut revoked_grants = validated_history
            .into_iter()
            .flat_map(|closure| closure.affected)
            .collect::<Vec<_>>();
        revoked_grants.extend(graph_snapshot.revoked.iter().cloned());
        revoked_grants.extend(
            graph_snapshot
                .grants
                .iter()
                .filter(|grant| grant.status == eliot_authority::GrantStatus::Revoked)
                .map(|grant| grant.grant_id.clone()),
        );
        revoked_grants.sort();
        revoked_grants.dedup();
        let mut non_admissible = revoked_grants.iter().cloned().collect::<BTreeSet<_>>();
        non_admissible.extend(
            graph_snapshot
                .grants
                .iter()
                .filter(|grant| {
                    matches!(
                        grant.status,
                        eliot_authority::GrantStatus::Revoked
                            | eliot_authority::GrantStatus::Stale
                            | eliot_authority::GrantStatus::Expired
                    )
                })
                .map(|grant| grant.grant_id.clone()),
        );

        let mut hydration_operations = BTreeSet::new();
        let mut members = BTreeMap::new();
        for member in restore.members {
            validate_id(&member.intent.grant_id, "restore.member.grant_id")?;
            verify_admitted_grant_seal(
                &member.intent.grant_id,
                &member.intent.operation_id,
                member.durable_record.record(),
            )?;
            if !hydration_operations.insert(member.intent.operation_id.clone()) {
                return Err(KernelError::InvalidField {
                    field: "restore.member.operation_id",
                    reason: "duplicate owner hydration operation identity",
                });
            }
            if members
                .insert(member.intent.grant_id.clone(), member)
                .is_some()
            {
                return Err(KernelError::InvalidField {
                    field: "restore.members",
                    reason: "duplicate admitted member identity",
                });
            }
        }
        let mut roots = BTreeMap::new();
        for root in restore.roots {
            validate_id(&root.intent.grant_id, "restore.root.grant_id")?;
            verify_admitted_grant_seal(
                &root.intent.grant_id,
                &root.intent.operation_id,
                root.durable_record.record(),
            )?;
            if !hydration_operations.insert(root.intent.operation_id.clone()) {
                return Err(KernelError::InvalidField {
                    field: "restore.root.operation_id",
                    reason: "duplicate owner hydration operation identity",
                });
            }
            if roots.insert(root.intent.grant_id.clone(), root).is_some() {
                return Err(KernelError::InvalidField {
                    field: "restore.roots",
                    reason: "duplicate admitted root identity",
                });
            }
        }
        if members.keys().any(|grant_id| roots.contains_key(grant_id)) {
            return Err(KernelError::InvalidField {
                field: "restore.hydration",
                reason: "a grant identity cannot be both a member and a root hydration",
            });
        }
        let mut introductions = BTreeMap::new();
        for hydration in restore.introductions {
            hydration.validate_complete().map_err(|_| {
                KernelError::RecoveryUnavailable(
                    "admitted introduction hydration failed validation".to_owned(),
                )
            })?;
            verify_admitted_introduction_seal(
                &hydration.intent.introduction_id,
                &hydration.intent.operation_id,
                hydration.durable_record.record(),
            )?;
            if !hydration_operations.insert(hydration.intent.operation_id.clone()) {
                return Err(KernelError::InvalidField {
                    field: "restore.introduction.operation_id",
                    reason: "duplicate owner hydration operation identity",
                });
            }
            if introductions
                .insert(hydration.intent.introduction_id.clone(), hydration)
                .is_some()
            {
                return Err(KernelError::InvalidField {
                    field: "restore.introductions",
                    reason: "duplicate admitted introduction identity",
                });
            }
        }
        if members
            .keys()
            .chain(roots.keys())
            .any(|identity| introductions.contains_key(identity))
        {
            return Err(KernelError::InvalidField {
                field: "restore.hydration",
                reason: "grant and introduction identities must be disjoint",
            });
        }
        let mut preserved = BTreeMap::new();
        for (target, survivors) in restore.preserved {
            validate_id(&target, "restore.preserved.target")?;
            for survivor in &survivors {
                check_preserved_membership(&graph_snapshot, &target, survivor)?;
            }
            if preserved.insert(target, survivors).is_some() {
                return Err(KernelError::InvalidField {
                    field: "restore.preserved",
                    reason: "duplicate preserved closure target",
                });
            }
        }

        let mut declarations = BTreeMap::new();
        for declaration in restore.declarations {
            if non_admissible.contains(declaration.target_grant_id.as_str()) {
                return Err(KernelError::RecoveryUnavailable(
                    "owner declaration names a non-admissible grant target".to_owned(),
                ));
            }
            declaration
                .validate()
                .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
            if declaration.grant_graph_revision != revision {
                return Err(KernelError::InvalidField {
                    field: "restore.declaration.grant_graph_revision",
                    reason: "declaration revision disagrees with the owner snapshot",
                });
            }
            let declared_survivors =
                preserved
                    .get(&declaration.target_grant_id)
                    .ok_or(KernelError::InvalidField {
                        field: "restore.declaration.preserved",
                        reason: "declaration requires an exact alternate-path projection",
                    })?;
            if &declaration.preserved != declared_survivors {
                return Err(KernelError::InvalidField {
                    field: "restore.declaration.preserved",
                    reason: "declaration and alternate-path projection disagree",
                });
            }
            for declared in &declaration.members {
                let graph_member = graph_snapshot
                    .grants
                    .iter()
                    .find(|grant| grant.grant_id == declared.grant_id)
                    .ok_or_else(|| {
                        KernelError::RecoveryUnavailable(
                            "closure declaration names an unknown graph member".to_owned(),
                        )
                    })?;
                if graph_member.parent_grant_id != declared.parent_grant_id
                    || graph_member.authority_root_ref != declaration.authority_root_ref
                {
                    return Err(KernelError::InvalidField {
                        field: "restore.declaration.members",
                        reason: "declaration disagrees with canonical parent/root identity",
                    });
                }
                let hydration = members
                    .get(&declared.grant_id)
                    .map(|member| &member.intent)
                    .or_else(|| roots.get(&declared.grant_id).map(|root| &root.intent))
                    .ok_or_else(|| {
                        KernelError::RecoveryUnavailable(
                            "closure declaration member has no admitted hydration".to_owned(),
                        )
                    })?;
                if hydration.parent_grant_id != declared.parent_grant_id
                    || hydration.authority_root_ref != declaration.authority_root_ref
                    || hydration.grant_graph_revision != revision
                    || declaration.proof_ceiling > hydration.proof_ceiling
                    || declaration.proof_ceiling > hydration.binding.proof_ceiling
                {
                    return Err(KernelError::InvalidField {
                        field: "restore.declaration.members",
                        reason: "member hydration disagrees with the owner declaration",
                    });
                }
            }
            if declarations
                .insert(declaration.target_grant_id.clone(), declaration)
                .is_some()
            {
                return Err(KernelError::InvalidField {
                    field: "restore.declarations",
                    reason: "duplicate owner closure declaration",
                });
            }
        }
        let declared_member_ids = declarations
            .values()
            .flat_map(|declaration| {
                declaration
                    .members
                    .iter()
                    .map(|member| member.grant_id.as_str())
            })
            .collect::<BTreeSet<_>>();
        for grant_id in members.keys().chain(roots.keys()) {
            if !declared_member_ids.contains(grant_id.as_str())
                && !non_admissible.contains(grant_id.as_str())
            {
                return Err(KernelError::RecoveryUnavailable(
                    "owner hydration exists outside a complete closure declaration".to_owned(),
                ));
            }
        }
        for target in preserved.keys() {
            if !declarations.contains_key(target) {
                return Err(KernelError::InvalidField {
                    field: "restore.preserved",
                    reason: "alternate-path target has no owner declaration",
                });
            }
        }
        for grant in &graph_snapshot.grants {
            if !non_admissible.contains(grant.grant_id.as_str())
                && !declarations.contains_key(&grant.grant_id)
            {
                return Err(KernelError::RecoveryUnavailable(
                    "current canonical grant has no complete owner closure declaration".to_owned(),
                ));
            }
        }

        let authority_roots = graph_snapshot
            .grants
            .iter()
            .map(|grant| grant.authority_root_ref.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(AdmittedClosureState {
            revision,
            authority_roots,
            revoked_grants,
            non_admissible,
            declarations,
            members,
            roots,
            introductions,
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, AdmittedClosureState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Validates owner-presented canonical second-phase identities before the
/// restore becomes a trust anchor. The owner supplies both the immutable ORS
/// closure operation identity and the exact canonical receipt identity; this
/// adapter validates their shape but never derives or synthesizes either.
fn validate_canonical_receipt_links(
    links: &BTreeMap<String, ReceiptIdentity>,
) -> Result<(), KernelError> {
    for (operation_id, receipt) in links {
        validate_id(operation_id, "restore.canonical_receipt.operation_id")?;
        validate_id(
            receipt.receipt_id.as_str(),
            "restore.canonical_receipt.receipt_id",
        )?;
        if receipt.canonical_sha256.len() != 64
            || !receipt
                .canonical_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(KernelError::InvalidField {
                field: "restore.canonical_receipt.canonical_sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
    }
    Ok(())
}

/// Proves the opaque↔intent seal for one admitted grant record at the
/// trust-anchor entry: exact identity contour plus shape/integrity
/// reconstruction exactly as ORS construction enforces. Epoch agreement
/// re-runs port-side at every use against the live epoch.
fn verify_admitted_grant_seal(
    grant_id: &str,
    operation_id: &str,
    record: &eliot_ors::OperationalRecordInput,
) -> Result<(), KernelError> {
    if record.record_id.as_str() != operation_id || record.subject_id.as_str() != grant_id {
        return Err(KernelError::InvalidField {
            field: "restore.durable_record",
            reason: "admitted opaque record identity disagrees with the admitted intent",
        });
    }
    eliot_ors::CapabilityGrantActivation::new(record.clone()).map_err(|_| {
        KernelError::InvalidField {
            field: "restore.durable_record",
            reason: "admitted opaque grant record failed seal validation",
        }
    })?;
    Ok(())
}

/// Proves the opaque↔intent seal for one admitted introduction record,
/// mirroring [`verify_admitted_grant_seal`].
fn verify_admitted_introduction_seal(
    introduction_id: &str,
    operation_id: &str,
    record: &eliot_ors::OperationalRecordInput,
) -> Result<(), KernelError> {
    if record.record_id.as_str() != operation_id || record.subject_id.as_str() != introduction_id {
        return Err(KernelError::InvalidField {
            field: "restore.durable_record",
            reason: "admitted opaque record identity disagrees with the admitted intent",
        });
    }
    eliot_ors::CapabilityIntroductionActivation::new(record.clone()).map_err(|_| {
        KernelError::InvalidField {
            field: "restore.durable_record",
            reason: "admitted opaque introduction record failed seal validation",
        }
    })?;
    Ok(())
}

/// Validates one preserved entry against the snapshot graph, mirroring
/// the provider-side admission check (`OwnerClosureProvider` proves the
/// same membership on its snapshot): the target, the survivor, and the
/// covering grant must all be known lineage. Unknown identities refuse
/// before any admitted state installs; coverage currency at the closure
/// revision is proven port-side, never here.
fn check_preserved_membership(
    snapshot: &GrantGraphRecoverySnapshot,
    target_grant_id: &str,
    survivor: &GrantClosureSurvivor,
) -> Result<(), KernelError> {
    for grant_id in [
        target_grant_id,
        survivor.grant_id.as_str(),
        survivor.covering_grant_id.as_str(),
    ] {
        if !snapshot
            .grants
            .iter()
            .any(|grant| grant.grant_id == grant_id)
        {
            return Err(KernelError::RecoveryUnavailable(
                "preserved admission names unknown grant lineage".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Thin-request root hydration handle shared by the production adapter.
///
/// `Arc<GovernorClosureSource>` implements [`RootGrantHydrationSource`]
/// directly; this alias only documents the production wiring shape for the
/// composition root.
pub type GovernorClosureSourceHandle = Arc<GovernorClosureSource>;

impl RootGrantHydrationSource for GovernorClosureSource {
    fn hydrate_root_grant(
        &self,
        request: &eliot_authority::GrantActivationRequest,
    ) -> Result<RootGrantHydration, KernelError> {
        let state = self.lock_state();
        if state.non_admissible.contains(request.grant_id.as_str()) {
            return Err(KernelError::RecoveryUnavailable(
                "non-admissible root hydration cannot be restored".to_owned(),
            ));
        }
        state
            .roots
            .get(request.grant_id.as_str())
            .cloned()
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "no canonical root hydration admitted for the requested grant".to_owned(),
                )
            })
    }

    fn rehydrate_root_grant(
        &self,
        projection: &eliot_ors::CapabilityGrantProjection,
    ) -> Result<RootGrantHydration, KernelError> {
        let state = self.lock_state();
        state
            .roots
            .get(projection.record().subject_id.as_str())
            .cloned()
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "no canonical root hydration admitted for the projected subject".to_owned(),
                )
            })
    }

    fn hydrate_introduction(
        &self,
        request: &eliot_authority::IntroductionActivationRequest,
    ) -> Result<IntroductionHydration, KernelError> {
        validate_id(
            request.introduction_id.as_str(),
            "introduction_activation.introduction_id",
        )?;
        let state = self.lock_state();
        let hydration = state
            .introductions
            .get(request.introduction_id.as_str())
            .cloned()
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "no canonical introduction hydration admitted for the requested introduction"
                        .to_owned(),
                )
            })?;
        if hydration
            .intent
            .supporting_grant_ids
            .iter()
            .any(|grant_id| state.non_admissible.contains(grant_id))
        {
            return Err(KernelError::RecoveryUnavailable(
                "introduction support includes a non-admissible grant".to_owned(),
            ));
        }
        // Exact-identity agreement, mirroring the root hydration gate: the
        // admitted hydration must name the requested introduction, snapshot,
        // and binding, or the request does not describe admitted authority.
        if hydration.intent.introduction_id != request.introduction_id.as_str()
            || hydration.intent.snapshot_id != request.snapshot_id.as_str()
            || hydration.intent.binding != request.binding
        {
            return Err(KernelError::InvalidField {
                field: "introduction_activation",
                reason: "admitted introduction hydration disagrees with the thin request",
            });
        }
        Ok(hydration)
    }

    fn hydrate_grant_member(&self, grant_id: &str) -> Result<GrantClosureMember, KernelError> {
        validate_id(grant_id, "grant_id")?;
        let state = self.lock_state();
        if state.non_admissible.contains(grant_id) {
            return Err(KernelError::RecoveryUnavailable(
                "non-admissible grant hydration cannot be restored".to_owned(),
            ));
        }
        if let Some(member) = state.members.get(grant_id) {
            return Ok(member.clone());
        }
        state
            .roots
            .get(grant_id)
            .map(|root| GrantClosureMember {
                intent: root.intent.clone(),
                durable_record: root.durable_record.clone(),
                observed_at_ms: root.observed_at_ms,
            })
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "canonical member hydration is absent for the requested grant".to_owned(),
                )
            })
    }

    fn historical_grant_hydration(
        &self,
        grant_id: &str,
    ) -> Result<Option<GrantClosureMember>, KernelError> {
        validate_id(grant_id, "grant_id")?;
        let state = self.lock_state();
        Ok(state.members.get(grant_id).cloned().or_else(|| {
            state.roots.get(grant_id).map(|root| GrantClosureMember {
                intent: root.intent.clone(),
                durable_record: root.durable_record.clone(),
                observed_at_ms: root.observed_at_ms,
            })
        }))
    }

    fn admitted_grant_hydrations(&self) -> Result<Vec<GrantClosureMember>, KernelError> {
        let state = self.lock_state();
        let mut hydrations = state
            .members
            .values()
            .cloned()
            .collect::<Vec<GrantClosureMember>>();
        hydrations.extend(state.roots.values().map(|root| GrantClosureMember {
            intent: root.intent.clone(),
            durable_record: root.durable_record.clone(),
            observed_at_ms: root.observed_at_ms,
        }));
        hydrations.sort_by(|left, right| left.intent.grant_id.cmp(&right.intent.grant_id));
        hydrations.dedup_by(|left, right| left.intent.grant_id == right.intent.grant_id);
        hydrations.retain(|hydration| !state.non_admissible.contains(&hydration.intent.grant_id));
        Ok(hydrations)
    }

    fn admitted_introductions(&self) -> Result<Vec<IntroductionHydration>, KernelError> {
        let state = self.lock_state();
        Ok(state
            .introductions
            .values()
            .filter(|hydration| {
                !hydration
                    .intent
                    .supporting_grant_ids
                    .iter()
                    .any(|grant_id| state.non_admissible.contains(grant_id))
            })
            .cloned()
            .collect())
    }

    fn enumerate_grant_closure(
        &self,
        grant_id: &str,
    ) -> Result<GrantClosureEnumeration, KernelError> {
        validate_id(grant_id, "grant_id")?;
        let state = self.lock_state();
        let declaration = state.declarations.get(grant_id).ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "no complete owner closure declaration is bound for the grant".to_owned(),
            )
        })?;
        let mut members = Vec::with_capacity(declaration.members.len());
        for declared in &declaration.members {
            let member = state
                .members
                .get(&declared.grant_id)
                .cloned()
                .or_else(|| {
                    state
                        .roots
                        .get(&declared.grant_id)
                        .map(|root| GrantClosureMember {
                            intent: root.intent.clone(),
                            durable_record: root.durable_record.clone(),
                            observed_at_ms: root.observed_at_ms,
                        })
                })
                .ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "canonical member hydration is absent for an owner-declared member"
                            .to_owned(),
                    )
                })?;
            members.push(member);
        }
        Ok(GrantClosureEnumeration {
            authority_root_ref: declaration.authority_root_ref.clone(),
            grant_graph_revision: declaration.grant_graph_revision,
            members,
            preserved: declaration.preserved.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_authority::{GrantGraphRecoverySnapshot, GrantRecoveryRecord, GrantStatus};
    use eliot_contracts::{ContractId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_receipts::{
        AuthorityBinding, EffectClass, GRANT_CLOSURE_SCHEMA, GRANT_CLOSURE_VERSION,
        GrantClosureMemberDeclaration, ProofCeiling,
    };
    use std::num::NonZeroU64;

    use crate::grant_activation_port::GrantActivationIntent;

    fn test_authority_epoch() -> Result<eliot_contracts::EpochId, KernelError> {
        let lineage_id =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").map_err(|_| {
                KernelError::InvalidField {
                    field: "lineage_id",
                    reason: "must be a canonical UUID lineage",
                }
            })?;
        let sequence = NonZeroU64::new(7).ok_or(KernelError::InvalidField {
            field: "sequence",
            reason: "must be greater than zero",
        })?;
        eliot_contracts::EpochId::new(lineage_id, sequence).map_err(|_| KernelError::InvalidField {
            field: "epoch_id",
            reason: "invalid canonical epoch",
        })
    }

    fn test_binding(epoch: &eliot_contracts::EpochId) -> Result<AuthorityBinding, KernelError> {
        let fence = StateFence::new(
            epoch.clone(),
            ResourceGeneration::new(1).map_err(|_| KernelError::InvalidField {
                field: "generation",
                reason: "test generation must validate",
            })?,
        );
        Ok(AuthorityBinding {
            authority_id: ContractId::new("authority:test").map_err(|_| {
                KernelError::InvalidField {
                    field: "authority_id",
                    reason: "test authority id must validate",
                }
            })?,
            authority_owner: "test-owner".to_owned(),
            authority_epoch: epoch.clone(),
            state_fence: fence,
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        })
    }

    fn recovery_snapshot(
        binding: &AuthorityBinding,
    ) -> Result<GrantGraphRecoverySnapshot, KernelError> {
        Ok(GrantGraphRecoverySnapshot {
            schema: eliot_authority::GRANT_GRAPH_RECOVERY_SCHEMA.to_owned(),
            version: eliot_authority::GRANT_GRAPH_RECOVERY_VERSION,
            revision: 5,
            grants: vec![GrantRecoveryRecord {
                grant_id: "grant-test-root".to_owned(),
                parent_grant_id: None,
                authority_root_ref: "root-test".to_owned(),
                issuer: "governor".to_owned(),
                holder: "holder-1".to_owned(),
                allowed_operations: vec!["op.read".to_owned()],
                allowed_resources: vec!["res:1".to_owned()],
                max_effect: EffectClass::Read,
                inherited_source_ceiling: None,
                binding: binding.clone(),
                issued_at: 1,
                expires_at: 10_000,
                max_uses: 1,
                status: GrantStatus::Active,
            }],
            revoked: Vec::new(),
            root_transitions: Vec::new(),
            quarantined_cross_root: Vec::new(),
        })
    }

    fn root_hydration(
        epoch: &eliot_contracts::EpochId,
        binding: &AuthorityBinding,
    ) -> Result<RootGrantHydration, KernelError> {
        let intent = GrantActivationIntent {
            operation_id: "op-test-root".to_owned(),
            grant_id: "grant-test-root".to_owned(),
            parent_grant_id: None,
            authority_root_ref: "root-test".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 5,
            holder_principal: "holder-1".to_owned(),
            session_id: "session-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            binding: binding.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
            issued_at_ms: 1_000,
            expires_at_ms: Some(10_000),
            receipt_obligations: vec!["obligation-1".to_owned()],
        };
        let authority_epoch = eliot_ors::EpochLineage {
            current: eliot_ors::EpochIdentity {
                lineage_id: eliot_ors::OpaqueLabel::new(epoch.lineage_id.as_str())
                    .map_err(KernelError::RecoveryState)?,
                epoch: epoch.sequence.get(),
            },
            predecessor: None,
        };
        let state_fence =
            eliot_ors::StateFenceSnapshot::capture(&binding.state_fence, epoch.sequence.get())
                .map_err(KernelError::RecoveryState)?;
        let input = eliot_ors::OperationalRecordInput::encrypted(
            eliot_ors::OperationalRecordContext {
                record_id: eliot_ors::OperationIdentity::new("op-test-root")
                    .map_err(KernelError::RecoveryState)?,
                subject_id: eliot_ors::OperationIdentity::new("grant-test-root")
                    .map_err(KernelError::RecoveryState)?,
                authority_epoch,
                state_fence,
                created_at_ms: 1_000,
                cleanup_after_ms: None,
            },
            eliot_platform::SecretReference::new("test-provider", "closure-test-key").map_err(
                |_error| KernelError::InvalidField {
                    field: "test_secret_reference",
                    reason: "fixture reference must validate",
                },
            )?,
            b"opaque-test-root-record".to_vec(),
        )
        .map_err(KernelError::RecoveryState)?;
        let durable_record =
            eliot_ors::CapabilityGrantActivation::new(input).map_err(KernelError::RecoveryState)?;
        Ok(RootGrantHydration {
            intent,
            durable_record,
            observed_at_ms: 1_000,
        })
    }

    fn restore_bundle() -> Result<GovernorClosureRestore, KernelError> {
        let epoch = test_authority_epoch()?;
        let binding = test_binding(&epoch)?;
        let hydration = root_hydration(&epoch, &binding)?;
        let member = GrantClosureMember {
            intent: hydration.intent.clone(),
            durable_record: hydration.durable_record.clone(),
            observed_at_ms: 1_000,
        };
        // The one canonical owner declaration for the single restored graph
        // grant. Every field is projected from the same durable material the
        // restore carries: the snapshot revision/root/parent identity, the
        // member intent's own ceiling, and the exact alternate-path set the
        // owner declared (empty here, so the declaration and the projection
        // agree byte for byte).
        let declaration = GrantClosureDeclaration {
            schema: GRANT_CLOSURE_SCHEMA.to_owned(),
            version: GRANT_CLOSURE_VERSION,
            target_grant_id: "grant-test-root".to_owned(),
            authority_root_ref: "root-test".to_owned(),
            grant_graph_revision: 5,
            members: vec![GrantClosureMemberDeclaration {
                grant_id: "grant-test-root".to_owned(),
                parent_grant_id: None,
            }],
            preserved: Vec::new(),
            proof_ceiling: ProofCeiling::ScopedVerification,
        };
        Ok(GovernorClosureRestore {
            graph_snapshot: recovery_snapshot(&binding)?,
            revocation_history: Some(eliot_authority::RevocationHistoryEvidence {
                state_fence: binding.state_fence.clone(),
                source_revision: 5,
                closures: Vec::new(),
            }),
            // One admitted grant identity cannot be both a closure member and a
            // single-root hydration, so this grant is admitted as the closure
            // member the enumeration test reads back.
            members: vec![member],
            roots: Vec::new(),
            introductions: Vec::new(),
            declarations: vec![declaration],
            preserved: vec![("grant-test-root".to_owned(), Vec::new())],
            // No canonical second phase has completed for this fixture, which
            // is the honest empty state: an absent entry leaves the committed
            // first phase explicitly pending rather than fabricating a receipt.
            canonical_receipts: BTreeMap::new(),
        })
    }

    #[test]
    fn restore_serves_owner_enumeration_from_durable_state() -> Result<(), KernelError> {
        let source = GovernorClosureSource::restore(restore_bundle()?)?;
        let enumeration = source.enumerate_grant_closure("grant-test-root")?;
        assert_eq!(enumeration.authority_root_ref, "root-test");
        assert_eq!(enumeration.grant_graph_revision, 5);
        assert_eq!(enumeration.members.len(), 1);
        assert_eq!(enumeration.members[0].intent.grant_id, "grant-test-root");
        assert!(enumeration.preserved.is_empty());
        Ok(())
    }

    #[test]
    fn restore_refuses_absent_revocation_history() {
        let mut bundle = restore_bundle().expect("fixture restore must build");
        bundle.revocation_history = None;
        assert!(matches!(
            GovernorClosureSource::restore(bundle),
            Err(KernelError::RecoveryUnavailable(_))
        ));
    }

    #[test]
    fn owner_reports_unknown_grant_without_fence() -> Result<(), KernelError> {
        let source = GovernorClosureSource::restore(restore_bundle()?)?;
        assert!(matches!(
            source.enumerate_grant_closure("grant-ghost"),
            Err(KernelError::RecoveryUnavailable(_))
        ));
        assert!(matches!(
            source.enumerate_grant_closure(""),
            Err(KernelError::InvalidField { .. })
        ));
        Ok(())
    }
}
