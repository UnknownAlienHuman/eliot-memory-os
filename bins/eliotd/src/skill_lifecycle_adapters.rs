//! Private Governor-backed Skill lifecycle port adapters.
//!
//! The forwarding adapter translates between the provider-neutral
//! [`SkillLifecycleApi`](eliot_skill::SkillLifecycleApi) and one Governor
//! [`GovernorSkillLifecycle`](eliot_governor::GovernorSkillLifecycle) borrowed
//! from the single [`DaemonComposition`](super::DaemonComposition) by its
//! `skill_lifecycle` accessor. It forwards authenticated input, translates
//! typed results, and enforces the catalogue usability gate on `promote`:
//!
//! - `promote` is blocked when the catalogue covers the candidate Skill and
//!   marks it stale or retired: drifted dependencies must be revalidated
//!   before Material promotion. Skills the catalogue does not cover forward
//!   untouched (open world: the registry stays authoritative until catalogue
//!   installation wiring lands).
//! - After a committed promotion, the candidate's observed dependency
//!   versions feed the catalogue, so the next promotion sees the drift. The
//!   feed runs after commit only: feeding before the usability gate would let
//!   an in-flight intentional update mark itself stale and deadlock every
//!   evolving Skill.
//! - `install_package` populates the shared catalogue from a canonical
//!   package source (production population caller): project, validate, and
//!   insert under the tool-owner existence check. It runs on whichever handle
//!   the adapter holds; the composition drives it on the shared handle
//!   ([`DaemonComposition::skill_install_package`](super::DaemonComposition::skill_install_package))
//!   so installs are visible to the promote gate.
//! - `install_package_versioned` is the same population caller behind the
//!   versioned canonical view: the tool source reports the definition version
//!   it binds, the composition states the version it admits, and drift fails
//!   closed before any entry is written. No version literal lives here.
//! - `run_install_to_receipt` composes the temporal delivery act the runtime
//!   injector drives: versioned install, then the sealed-observation mirror
//!   over the provider's [`ReadinessClaims`](eliot_skill::ReadinessClaims)
//!   (exact available `(name, version)` per required tool and capability),
//!   then the truthful sealed materialization check (sealed omissions refuse
//!   with the owner's voice; verifier absence proceeds provisional, never
//!   verified), then Hotset receipt issuance under the injector's approval
//!   handle. It returns the installed identity plus the receipt the injector
//!   carries to the receiver; the receiver's ack re-enters through
//!   `acknowledge_and_display`, never minted here. A provider-unavailable
//!   package stays installed but undelivered: installed is not delivered.
//! - `deliver_hotset` issues the Hotset delivery receipt the runtime injector
//!   carries, and `acknowledge_and_display` binds the runtime receiver's ack
//!   to that exact receipt before displaying. The ack is supplied by the real
//!   receiver (runtime Hotset injector caller), never minted here: the model
//!   validates the binding statelessly and keeps no second ledger.
//! - `view` and `propose` forward unchanged: reads and proposals neither
//!   consume the catalogue nor invent candidates.
//! - `activation_display` executes against the shared catalogue handle: entry
//!   usability, receipt self-consistency plus exact catalogue bind,
//!   applied-ack binding to that exact receipt, delivery coverage, and the
//!   tool-owner existence check all run inside the catalogue boundary. The
//!   display binds receipt, ack, and catalogue — not the state fence — so the
//!   guard is taken and dropped in a closed scope and never crosses an await.
//!   Tool-existence production wiring belongs to the tool owner: the caller
//!   supplies its `KnownTools` view, and this adapter never invents one.
//! - No other policy, admission, or semantic rules live here. Base digest/revision,
//!   exact evidence, fence, approval and reversibility stay with the Governor
//!   skill owner; this adapter never invents a candidate, gate, or promotion.
//! - `view` and `propose` are authenticated reads of the current owner at the
//!   admitted fence. A stale fence fails closed in the Governor owner, never
//!   as a local default.
//! - `promote` forwards the exact admitted identity, operation identity,
//!   candidate, gate and promoted view to the Governor canonical path. Only a
//!   `Committed` store receipt counts as promotion; rejected, cancelled and
//!   dead-letter outcomes stay pending as typed store failures, and a lost
//!   acknowledgement reconciles the same operation receipt.
//! - [`SkillPromotionReceipt`](eliot_skill::SkillPromotionReceipt) remains a
//!   domain payload/projection validated inside the Governor owner, never a
//!   second receipt ledger here.
//!
//! The adapter performs no I/O of its own beyond awaiting the inner Governor
//! owner, so it cannot block the single-thread async reactor beyond the
//! already-admitted canonical commit. Catalogue locks are never held across an
//! await: the pre-commit gate and the post-commit feed each take and drop the
//! guard in a closed scope. The current Kernel binding is observed
//! through the Governor composition, never through a second client.

#![forbid(unsafe_code)]
// The crate error carries the full store failure for typed recovery; every
// fallible function returns it by value like the Governor lifecycle API.
// Boxing it here would diverge from that contract, so the size lint is
// allowed for this module (same precedent as the Skill catalogue module).
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex, MutexGuard};

use eliot_contracts::StateFence;
use eliot_skill::{
    ActivatedSkillDisplay, CanonicalToolSource, CatalogueInstallContext, HotsetDeliveryAck,
    HotsetDeliveryReceipt, KnownTools, MaterializationInputs, MaterializationScope, PromotionGate,
    ReadinessClaims, SkillCandidate, SkillCatalogue, SkillError, SkillLifecycleApi,
    SkillLifecycleView, SkillPackage, ToolAliasTable, VersionBoundTools,
    activation::detect_dependency_staleness,
};

/// Shared handle to the composition-owned Governor Skill catalogue.
///
/// The catalogue lives in [`DaemonComposition`](super::DaemonComposition);
/// every `skill_lifecycle` accessor hands out an adapter borrowing this
/// shared handle, so all promotions observe one catalogue state.
pub(crate) type CatalogueHandle = Arc<Mutex<SkillCatalogue>>;

/// Forwards one [`SkillLifecycleApi`] to the single Governor owner behind
/// the catalogue usability gate described above.
pub(crate) struct ForwardingSkillLifecycle<T> {
    inner: T,
    catalogue: CatalogueHandle,
}

/// Refuses a delivery act whose claimed scope fence is not the live admitted
/// fence (issue #1882).
///
/// The injector builds the act under one Governor fence; the driver observes
/// the live admitted fence when driving it. Inequality means a Governor
/// refresh — or a foreign-fence act — crossed the drive: the install stands
/// unwritten and no receipt mints, so a refreshed Governor never inherits a
/// catalogue write plus receipt bound to a fence it already fenced. Pure over
/// its two inputs; the caller observes the live fence through the
/// composition's admitted snapshot.
fn check_delivery_fence(claimed: &StateFence, admitted: &StateFence) -> Result<(), SkillError> {
    if claimed != admitted {
        return Err(SkillError::FenceMismatch);
    }
    Ok(())
}

impl<T> ForwardingSkillLifecycle<T> {
    /// Wraps the single Governor lifecycle owner for forwarding.
    ///
    /// The adapter carries a fresh empty catalogue handle, so promotion
    /// forwards exactly as before (open world: uncovered Skills forward).
    /// Composition switches to [`with_catalogue`](Self::with_catalogue) with
    /// the shared handle once catalogue installation wiring lands.
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            catalogue: Arc::new(Mutex::new(SkillCatalogue::default())),
        }
    }

    /// Wraps the single Governor lifecycle owner plus the shared catalogue
    /// handle for guarded forwarding (see the module contract).
    pub(crate) fn with_catalogue(inner: T, catalogue: CatalogueHandle) -> Self {
        Self { inner, catalogue }
    }

    fn lock_catalogue(&self) -> MutexGuard<'_, SkillCatalogue> {
        // The reactor is single-threaded and guards never cross an await, so
        // a poisoned mutex means a previous holder panicked: fail open to the
        // held state rather than bricking the skill path on a stale poison
        // flag. Locking itself cannot fail otherwise.
        self.catalogue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Installs one canonical package source into the shared catalogue and
    /// returns the installed Skill identity.
    ///
    /// This is the production population caller the runtime composition
    /// drives: the Governor owner hands over a validated package claim, its
    /// actual materialization inputs, and the explicit install context, and
    /// the shared handle records the projected entry under the tool-owner
    /// existence check. Synchronous: the guard is taken and dropped in a
    /// closed scope and never crosses an await.
    ///
    /// No in-tree production flow drives the runtime population path yet:
    /// the composition seam
    /// ([`DaemonComposition::skill_install_package`](super::DaemonComposition::skill_install_package))
    /// carries the exact call for the Governor-owned driver. The allowance
    /// covers exactly that pending adoption; it expires when the driver
    /// lands. Tests drive all three runtime callers.
    #[allow(dead_code)]
    pub(crate) fn install_package(
        &self,
        package: &eliot_skill::SkillPackage,
        inputs: &eliot_skill::MaterializationInputs,
        context: &eliot_skill::CatalogueInstallContext,
        tools: &dyn KnownTools,
    ) -> Result<String, SkillError> {
        let mut catalogue = self.lock_catalogue();
        eliot_skill::install_package(&mut catalogue, package, inputs, context, tools)
    }

    /// Installs one canonical package source under the versioned canonical
    /// tool view and returns the installed Skill identity.
    ///
    /// Production population caller the runtime composition drives once the
    /// tool owner supplies its [`CanonicalToolSource`] registry view: the
    /// source reports the definition version it binds, `admitted_version`
    /// carries the version the Governor composition admits, and any drift
    /// fails closed before the shared handle is touched. The Skill-owned
    /// alias table resolves provider renames to canonical names first.
    /// Synchronous: the guard is taken and dropped in a closed scope.
    ///
    /// No in-tree Governor driver calls the versioned population path yet;
    /// the composition seam
    /// ([`DaemonComposition::skill_install_package_versioned`](super::DaemonComposition::skill_install_package_versioned))
    /// has landed for that driver. The allowance covers exactly that pending
    /// adoption; it expires when the driver lands.
    #[allow(dead_code)]
    pub(crate) fn install_package_versioned(
        &self,
        package: &eliot_skill::SkillPackage,
        inputs: &eliot_skill::MaterializationInputs,
        context: &eliot_skill::CatalogueInstallContext,
        source: &dyn CanonicalToolSource,
        aliases: &ToolAliasTable,
        admitted_definition_version: &str,
    ) -> Result<String, SkillError> {
        let mut catalogue = self.lock_catalogue();
        eliot_skill::install_package_versioned(
            &mut catalogue,
            package,
            inputs,
            context,
            source,
            aliases,
            admitted_definition_version,
        )
    }

    /// Runs versioned install, availability and sealed gates, and Hotset
    /// receipt issuance as one runtime delivery act.
    ///
    /// Driven by the runtime Hotset injector caller: after the versioned
    /// install, the exact sealed-observation rule runs over the provider's
    /// [`ReadinessClaims`](eliot_skill::ReadinessClaims) — a required tool or
    /// capability the provider did not mark available at its exact version
    /// refuses issuance while the install stands (installed is not
    /// delivered). The sealed materialization entry then runs truthfully with
    /// the public missing-ports provider: sealed omissions and binding
    /// failures refuse with the owner's own voice, while verifier absence
    /// proceeds WITHOUT sealed verification as `Provisional` (never
    /// `Current`). The injector's own approval handle authorizes the receipt.
    /// Returns the installed identity plus the receipt the injector carries
    /// to the receiver; the receiver's ack re-enters through
    /// [`acknowledge_and_display`](Self::acknowledge_and_display).
    /// Synchronous: each step takes and drops the guard in a closed scope.
    ///
    /// The act's scope fence is checked FIRST against the driver-observed
    /// live admitted fence: a Governor refresh (or a foreign-fence act)
    /// crossing the drive fails closed before the shared handle is touched,
    /// so a refreshed Governor never inherits a catalogue write plus receipt
    /// bound to a fence it already fenced.
    ///
    /// No in-tree Governor driver calls the composed delivery act yet; the
    /// composition seam
    /// ([`DaemonComposition::skill_run_install_to_receipt`](super::DaemonComposition::skill_run_install_to_receipt))
    /// has landed for that driver. The allowance covers exactly that pending
    /// adoption; it expires when the driver lands.
    #[allow(dead_code)]
    pub(crate) fn run_install_to_receipt(
        &self,
        act: VersionedDeliveryAct<'_>,
        admitted_fence: &StateFence,
    ) -> Result<(String, HotsetDeliveryReceipt), SkillError> {
        check_delivery_fence(&act.scope.work_scope.state_fence, admitted_fence)?;
        let skill_id = self.install_package_versioned(
            act.package,
            act.inputs,
            act.context,
            act.source,
            act.aliases,
            act.admitted_definition_version,
        )?;
        eliot_skill::readiness_available_for_package(act.package, act.readiness)?;
        eliot_skill::sealed_materialization_check(
            act.package,
            act.inputs,
            act.readiness,
            act.scope,
        )?;
        let tools = eliot_skill::VersionBoundTools::new(act.source, act.aliases);
        let receipt = self.deliver_hotset(
            act.hotset_id,
            vec![skill_id.clone()],
            act.approval_ref,
            &tools,
        )?;
        Ok((skill_id, receipt))
    }

    /// Runs the injector call end to end: assembles the delivery act from
    /// the injector request plus driver-observed terms, then drives it.
    ///
    /// Production injector entry the Hotset transport calls with one
    /// [`SkillHotsetRequest`]: the request carries ONLY injector-owned
    /// fields, while the live admitted fence, the Governor-built tool
    /// source, the Skill-owned alias table, and the admitted definition
    /// version arrive as separate driver-observed parameters — assembled
    /// here into the act, never taken from a transport copy. Every gate
    /// below runs in order (fence, admitted-version, readiness mirror,
    /// sealed check, approval); the first refusal stops the drive with the
    /// install standing or unwritten as each gate documents. Returns the
    /// installed identity plus the receipt the injector carries to the
    /// receiver. Synchronous: each step takes and drops the guard in a
    /// closed scope.
    ///
    /// No in-tree Hotset transport calls this yet; the composition seam
    /// ([`DaemonComposition::skill_inject_hotset`](super::DaemonComposition::skill_inject_hotset))
    /// has landed for that lane. The allowance covers exactly that pending
    /// adoption; it expires when the lane lands.
    #[allow(dead_code)]
    pub(crate) fn inject_hotset(
        &self,
        request: SkillHotsetRequest<'_>,
        source: &dyn CanonicalToolSource,
        aliases: &ToolAliasTable,
        admitted_definition_version: &str,
        admitted_fence: &StateFence,
    ) -> Result<(String, HotsetDeliveryReceipt), SkillError> {
        let act = VersionedDeliveryAct {
            package: request.package,
            inputs: request.inputs,
            context: request.context,
            readiness: request.readiness,
            scope: request.scope,
            source,
            aliases,
            admitted_definition_version,
            hotset_id: request.hotset_id,
            approval_ref: request.approval_ref,
        };
        self.run_install_to_receipt(act, admitted_fence)
    }

    /// Issues the Hotset delivery receipt the runtime injector carries.
    ///
    /// Driven by the runtime Hotset injector caller with its own approval
    /// handle: a non-blank approval never comes from a Hotset identity alone.
    /// Synchronous: the guard is taken and dropped in a closed scope.
    #[allow(dead_code)]
    pub(crate) fn deliver_hotset(
        &self,
        hotset_id: String,
        skill_ids: Vec<String>,
        approval_ref: String,
        tools: &dyn KnownTools,
    ) -> Result<HotsetDeliveryReceipt, SkillError> {
        let catalogue = self.lock_catalogue();
        HotsetDeliveryReceipt::issue(hotset_id, &catalogue, skill_ids, tools, approval_ref)
    }

    /// Refuses display when the entry's declared tool basis changed under
    /// it, marking the entry stale first (issue #1882, `I7.13`).
    ///
    /// Collects the entry's `body.tool_refs` unknown to the caller's
    /// tool-owner view; any missing tool means a declared host/tool
    /// dependency changed after install. The entry is marked stale naming
    /// every missing tool — so future issuance and promotion also fail
    /// closed — then display refuses with the stale status instead of
    /// rendering a removed tool as generally delivered. Unknown skills pass
    /// through untouched: the catalogue boundary below reports `NotFound`.
    /// Synchronous: each guard is taken and dropped in a closed scope and
    /// never crosses an await.
    fn invalidate_unknown_tool_basis(
        &self,
        skill_id: &str,
        tools: &dyn KnownTools,
    ) -> Result<(), SkillError> {
        let missing = {
            let catalogue = self.lock_catalogue();
            match catalogue.get(skill_id) {
                Some(entry) => entry
                    .body
                    .tool_refs
                    .iter()
                    .filter(|name| !tools.knows_tool(name))
                    .cloned()
                    .collect::<Vec<_>>(),
                None => return Ok(()),
            }
        };
        if missing.is_empty() {
            return Ok(());
        }
        {
            let mut catalogue = self.lock_catalogue();
            catalogue.mark_tool_basis_stale(skill_id, &missing)?;
        }
        Err(SkillError::InvalidField {
            field: "entry.status",
            reason: "declared tool basis changed; Skill marked stale until revalidated",
        })
    }

    /// Binds the runtime receiver's ack to its exact receipt, then displays.
    ///
    /// The ack arrives from the real receiver (runtime Hotset injector), which
    /// validated the receipt, applied or rejected the bodies, and returned the
    /// ack binding the exact receipt digest it acted on. Only an applied ack
    /// for this exact receipt reaches the catalogue boundary; anything else
    /// fails closed here without touching the catalogue. Before the boundary,
    /// a changed tool basis marks the entry stale and refuses: a removed tool
    /// is never displayed as generally delivered. Synchronous: the
    /// guard never crosses an await.
    ///
    /// Receipt and ack travel by value, mirroring the `SkillLifecycleApi`
    /// display boundary: the injector caller relinquishes the pair it acted
    /// on instead of retaining an alias into the guarded display.
    #[allow(dead_code, clippy::needless_pass_by_value)]
    pub(crate) fn acknowledge_and_display(
        &self,
        skill_id: &str,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
        tools: &dyn KnownTools,
    ) -> Result<ActivatedSkillDisplay, SkillError> {
        if !ack.confirms_applied(&receipt) {
            return Err(SkillError::IdentityMismatch);
        }
        ack.validate()?;
        self.invalidate_unknown_tool_basis(skill_id, tools)?;
        let catalogue = self.lock_catalogue();
        catalogue.activation_display(skill_id, &receipt, &ack, tools)
    }

    /// Binds the runtime receiver's ack to its exact receipt under the live
    /// canonical tool view, then displays.
    ///
    /// Receiver-side driver the injector caller runs once the receiver
    /// returns its ack for an issued receipt: the display-time
    /// definition-drift gate runs FIRST over the LIVE tool-owner source
    /// (`display_source`, normally the same registry value the Governor hook
    /// built, re-read at display time rather than reused from install), and
    /// requires the version it binds to equal the admitted version the
    /// install ran under. A Tool Definition change between install and
    /// display refuses the display instead of rendering installed bodies
    /// under drifted authority; a blank live version refuses the same way.
    /// On agreement the ack binds exactly as in
    /// [`acknowledge_and_display`](Self::acknowledge_and_display) through the
    /// versioned projection. The ack still arrives from the real receiver and
    /// is never synthesized here. Synchronous: the guard never crosses an
    /// await.
    ///
    /// No in-tree Governor driver calls the drift-gated display yet; the
    /// composition seam
    /// ([`DaemonComposition::skill_acknowledge_and_display_versioned`](super::DaemonComposition::skill_acknowledge_and_display_versioned))
    /// has landed for that driver. The allowance covers exactly that pending
    /// adoption; it expires when the driver lands.
    #[allow(dead_code, clippy::needless_pass_by_value)]
    pub(crate) fn acknowledge_and_display_versioned(
        &self,
        skill_id: &str,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
        display_source: &dyn CanonicalToolSource,
        aliases: &ToolAliasTable,
        admitted_definition_version: &str,
    ) -> Result<ActivatedSkillDisplay, SkillError> {
        let live = display_source.definition_version();
        if live.trim().is_empty() || live != admitted_definition_version {
            return Err(SkillError::InvalidField {
                field: "tools.definition_version",
                reason: "the live tool source no longer binds the admitted definition version",
            });
        }
        let tools = VersionBoundTools::new(display_source, aliases);
        self.acknowledge_and_display(skill_id, receipt, ack, &tools)
    }
}

/// Injector-carried Hotset delivery request (issue #1882).
///
/// Everything the Hotset injector transport delivers: the canonical package
/// source with its actual materialization inputs, the Governor-owned install
/// context (eligibility, versions, budgets, measured costs, inventories),
/// the provider-signed readiness claims, the scope identities, and the
/// Hotset identity plus injector approval handle. No defaults, no
/// test-only literals in production: every field arrives from the injector
/// lane (transport owned elsewhere; see the module contract). Owner-observed
/// terms — the live admitted fence, the Governor-built tool source plus
/// alias table and admitted version — are NEVER fields here; the driver
/// observes them at drive time so a stale transport copy cannot override
/// live admission. Assembled into a [`VersionedDeliveryAct`] by
/// [`ForwardingSkillLifecycle::inject_hotset`].
pub struct SkillHotsetRequest<'a> {
    pub package: &'a SkillPackage,
    pub inputs: &'a MaterializationInputs,
    pub context: &'a CatalogueInstallContext,
    pub readiness: &'a ReadinessClaims,
    pub scope: &'a MaterializationScope,
    pub hotset_id: String,
    pub approval_ref: String,
}

/// Inputs for one composed versioned delivery act
/// ([`ForwardingSkillLifecycle::run_install_to_receipt`]).
///
/// Bundles the install boundary (canonical package source, actual inputs,
/// Governor install context, versioned tool source plus alias table and the
/// admitted definition version) with the temporal delivery boundary
/// (provider readiness claims, materialization scope, Hotset identity,
/// injector approval handle) so the composition drives the whole act in one
/// call.
pub struct VersionedDeliveryAct<'a> {
    pub package: &'a eliot_skill::SkillPackage,
    pub inputs: &'a eliot_skill::MaterializationInputs,
    pub context: &'a eliot_skill::CatalogueInstallContext,
    pub readiness: &'a eliot_skill::ReadinessClaims,
    pub scope: &'a eliot_skill::MaterializationScope,
    pub source: &'a dyn CanonicalToolSource,
    pub aliases: &'a ToolAliasTable,
    pub admitted_definition_version: &'a str,
    pub hotset_id: String,
    pub approval_ref: String,
}

/// Records post-commit promotion observations in the catalogue: when the
/// catalogue covers the promoted Skill and the committed dependency versions
/// drift from the pinned set, the entry is marked stale for the next
/// promotion. Returns `true` when the entry became stale. Absent Skills are
/// uncovered (open world) and report `false`.
///
/// Called on the committed path only, with Governor-validated candidate
/// records, so the feed is infallible by construction once the pre-commit
/// usability gate has passed.
pub(crate) fn record_promotion_observation(
    catalogue: &mut SkillCatalogue,
    skill_id: &str,
    observed: Vec<eliot_skill::DependencyVersion>,
) -> Result<bool, SkillError> {
    if catalogue.get(skill_id).is_none() {
        return Ok(false);
    }
    let pinned = catalogue
        .get(skill_id)
        .map(|entry| entry.dependencies.clone())
        .unwrap_or_default();
    if let Some(reason) = detect_dependency_staleness(&pinned, &observed) {
        return catalogue.note_dependency_change(skill_id, observed, reason);
    }
    Ok(false)
}

impl<T: SkillLifecycleApi> SkillLifecycleApi for ForwardingSkillLifecycle<T> {
    async fn view(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
    ) -> Result<Option<SkillLifecycleView>, SkillError> {
        self.inner.view(ctx, skill_id).await
    }

    async fn propose(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
        candidate_package_digest: String,
        action: eliot_skill::LifecycleAction,
        evidence_refs: Vec<String>,
        dependencies: Vec<eliot_skill::DependencyVersion>,
        scope: eliot_skill::SkillScope,
    ) -> Result<SkillCandidate, SkillError> {
        self.inner
            .propose(
                ctx,
                skill_id,
                candidate_package_digest,
                action,
                evidence_refs,
                dependencies,
                scope,
            )
            .await
    }

    async fn promote(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        candidate: SkillCandidate,
        gate: PromotionGate,
        promoted_view: SkillLifecycleView,
    ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
        let skill_id = candidate.base_skill_ref.skill_id().to_owned();
        let observed = candidate.dependency_versions.clone();
        {
            let catalogue = self.lock_catalogue();
            if let Some(entry) = catalogue.get(&skill_id)
                && !entry.is_usable()
            {
                return Err(SkillError::InvalidField {
                    field: "entry.status",
                    reason: "catalogue marks this Skill stale or retired; revalidate before Material promotion",
                });
            }
        }
        let receipt = self
            .inner
            .promote(identity, operation_id, candidate, gate, promoted_view)
            .await?;
        {
            let mut catalogue = self.lock_catalogue();
            if catalogue.get(&skill_id).is_some()
                && record_promotion_observation(&mut catalogue, &skill_id, observed).is_err()
            {
                debug_assert!(false, "promotion feed carries Governor-validated records");
            }
        }
        Ok(receipt)
    }

    async fn activation_display(
        &self,
        _ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
        tools: &dyn KnownTools,
    ) -> Result<ActivatedSkillDisplay, SkillError> {
        // Same standing-display invalidation as the injector path: a changed
        // tool basis marks the entry stale before the catalogue boundary.
        self.invalidate_unknown_tool_basis(&skill_id, tools)?;
        let catalogue = self.lock_catalogue();
        catalogue.activation_display(&skill_id, &receipt, &ack, tools)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;
    use eliot_skill::{
        Availability, AvailabilityField, DependencyVersion, HotsetAckDisposition,
        HotsetDeliveryAck, HotsetDeliveryReceipt, KnownTools, LifecycleAction, LifecycleCounters,
        MaterializationScope, PromotionGate, ReadinessClaims, SkillBody, SkillCandidate,
        SkillCatalogue, SkillCatalogueEntry, SkillIndexEntry, SkillInteractionView,
        SkillLifecycleView, SkillRef, SkillRuntimeMetadata, SkillScope, SkillStatus,
        VersionedObservation,
    };
    use eliot_store_api::{
        CommitId, OperationManifestDigest, Resubmission, TransitionClass, WriteReceipt,
        WriteReceiptStatus,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    struct ClosedInner {
        fence_mismatch: bool,
        succeed_promote: bool,
        calls: Arc<Mutex<u64>>,
    }

    fn success_receipt(fence: &StateFence, operation_id: OperationId) -> WriteReceipt {
        WriteReceipt {
            operation_id,
            idempotency_key: "idem-skill-1".to_owned(),
            canonical_request_hash: "d".repeat(64),
            transition_class: TransitionClass::LifecyclePolicy,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new("commit-1").expect("commit id")),
            state_fence: fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["cmd-1".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: OperationManifestDigest::new("manifest-test-1")
                .expect("manifest digest"),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: None,
        }
    }

    impl SkillLifecycleApi for ClosedInner {
        async fn view(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
        ) -> Result<Option<SkillLifecycleView>, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            if self.fence_mismatch {
                return Err(SkillError::FenceMismatch);
            }
            Ok(None)
        }

        async fn propose(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
            _candidate_package_digest: String,
            _action: LifecycleAction,
            _evidence_refs: Vec<String>,
            _dependencies: Vec<DependencyVersion>,
            _scope: SkillScope,
        ) -> Result<SkillCandidate, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            Err(SkillError::NotFound)
        }

        async fn promote(
            &self,
            _identity: &eliot_protocol::RequestIdentity,
            operation_id: OperationId,
            _candidate: SkillCandidate,
            _gate: PromotionGate,
            _promoted_view: SkillLifecycleView,
        ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            if self.succeed_promote {
                // Test-only committed receipt: the adapter forwards receipts
                // without validating them, so only the Ok path matters here.
                let fence = StateFence::new(
                    test_epoch(1),
                    ResourceGeneration::new(1).expect("generation"),
                );
                return Ok(success_receipt(&fence, operation_id));
            }
            Err(SkillError::NotFound)
        }

        async fn activation_display(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
            _receipt: HotsetDeliveryReceipt,
            _ack: HotsetDeliveryAck,
            _tools: &dyn KnownTools,
        ) -> Result<ActivatedSkillDisplay, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            Err(SkillError::NotFound)
        }
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn metadata(fence: &StateFence) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("req-forward-1").expect("request"),
            session_id: Some(SessionId::new("session-forward-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn blocking_view<T>(future: impl std::future::Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn forwarding_preserves_typed_read_results_without_policy() {
        let fence = fence();
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let view = blocking_view(forwarding.view(&metadata(&fence), "skill-demo".to_owned()))
            .expect("forwarded view");
        assert!(view.is_none());
        assert_eq!(*calls.lock().expect("calls"), 1);
    }

    #[test]
    fn stale_catalogue_entry_blocks_promote_before_inner_call() {
        let fence = fence();
        let handle = installed_catalogue();
        {
            let mut catalogue = handle.lock().expect("catalogue lock");
            catalogue
                .note_dependency_change(
                    "skill-demo",
                    vec![DependencyVersion {
                        name: "tool-def-1".to_owned(),
                        version: "2.0.0".to_owned(),
                        contract_digest: "c".repeat(64),
                    }],
                    "tool-def-1 moved to 2.0.0".to_owned(),
                )
                .expect("mark stale");
        }
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: true,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let candidate = candidate_with_deps(&fence, vec![dependency("1.2.0")]);
        let gate = gate_for(&fence, &candidate);
        let blocked = blocking_view(forwarding.promote(
            &identity(&fence),
            OperationId::new("op-skill-1").expect("operation id"),
            candidate,
            gate,
            base_view(&fence),
        ));
        assert!(matches!(
            blocked,
            Err(SkillError::InvalidField { field, .. }) if field == "entry.status"
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn committed_promote_feeds_observed_dependencies_into_catalogue() {
        let fence = fence();
        let handle = installed_catalogue();
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: true,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, Arc::clone(&handle));
        let candidate = candidate_with_deps(&fence, vec![dependency("2.0.0")]);
        let gate = gate_for(&fence, &candidate);
        blocking_view(forwarding.promote(
            &identity(&fence),
            OperationId::new("op-skill-2").expect("operation id"),
            candidate,
            gate,
            base_view(&fence),
        ))
        .expect("committed promote forwards");
        assert_eq!(*calls.lock().expect("calls"), 1);
        let catalogue = handle.lock().expect("catalogue lock");
        let stored = catalogue.get("skill-demo").expect("stored entry");
        assert_eq!(stored.status, SkillStatus::Stale);
        assert_eq!(
            stored.dependencies,
            vec![DependencyVersion {
                name: "tool-def-1".to_owned(),
                version: "2.0.0".to_owned(),
                contract_digest: "c".repeat(64),
            }]
        );
    }

    #[test]
    fn promotion_observation_feed_covers_absent_steady_and_drift() {
        let mut catalogue = SkillCatalogue::default();
        assert!(
            !record_promotion_observation(
                &mut catalogue,
                "skill-missing",
                vec![dependency("1.2.0")]
            )
            .expect("absent skill reports no feed")
        );
        catalogue
            .insert(catalogue_entry(), &TestTools)
            .expect("install entry");
        assert!(
            !record_promotion_observation(&mut catalogue, "skill-demo", vec![dependency("1.2.0")])
                .expect("steady dependencies feed nothing")
        );
        assert!(
            record_promotion_observation(&mut catalogue, "skill-demo", vec![dependency("2.0.0")])
                .expect("drift feeds stale")
        );
        assert_eq!(
            catalogue.get("skill-demo").expect("entry").status,
            SkillStatus::Stale
        );
    }

    fn issued_display_inputs(
        handle: &CatalogueHandle,
    ) -> (HotsetDeliveryReceipt, HotsetDeliveryAck) {
        let catalogue = handle.lock().expect("catalogue lock");
        let receipt = HotsetDeliveryReceipt::issue(
            "hotset-display-1".to_owned(),
            &catalogue,
            vec!["skill-demo".to_owned()],
            &TestTools,
            "approval-commit-1".to_owned(),
        )
        .expect("delivery receipt");
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        (receipt, ack)
    }

    #[test]
    fn display_executes_real_boundary_without_touching_inner() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, ack) = issued_display_inputs(&handle);
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let display = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt.clone(),
            ack,
            &TestTools,
        ))
        .expect("applied display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn display_blocks_stale_entries_before_ack_checks() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, ack) = issued_display_inputs(&handle);
        {
            let mut catalogue = handle.lock().expect("catalogue lock");
            catalogue
                .note_dependency_change(
                    "skill-demo",
                    vec![dependency("9.9.9")],
                    "tool-def-1 moved to 9.9.9".to_owned(),
                )
                .expect("mark stale");
        }
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let blocked = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt,
            ack,
            &TestTools,
        ));
        assert!(matches!(
            blocked,
            Err(SkillError::InvalidField { field, .. }) if field == "entry.status"
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn display_rejects_ack_bound_to_another_receipt() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, _) = issued_display_inputs(&handle);
        let foreign_ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: "e".repeat(64),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let rejected = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt,
            foreign_ack,
            &TestTools,
        ));
        assert!(matches!(rejected, Err(SkillError::IdentityMismatch)));
    }

    #[test]
    fn display_rejects_unknown_skill_without_catalogue_entry() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, ack) = issued_display_inputs(&handle);
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let missing = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-missing".to_owned(),
            receipt,
            ack,
            &TestTools,
        ));
        assert!(matches!(missing, Err(SkillError::NotFound)));
    }

    #[test]
    fn install_populates_the_shared_handle_for_the_promote_gate() {
        let (forwarding, _calls, handle) = installing_forwarder();
        let catalogue = handle.lock().expect("catalogue lock");
        let stored = catalogue.get("skill-demo").expect("installed entry");
        assert_eq!(stored.index.name, "demo skill");
        assert!(catalogue.is_usable("skill-demo"));
        drop(catalogue);
        drop(forwarding);
    }

    #[test]
    fn runtime_delivery_round_trip_installs_delivers_acks_and_displays() {
        let (forwarding, calls, _handle) = installing_forwarder();
        let receipt = forwarding
            .deliver_hotset(
                "hotset-runtime-1".to_owned(),
                vec!["skill-demo".to_owned()],
                "approval-commit-1".to_owned(),
                &InstallTools,
            )
            .expect("runtime delivery");
        assert!(receipt.confirms_delivery("skill-demo"));
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let display = forwarding
            .acknowledge_and_display("skill-demo", receipt.clone(), ack, &InstallTools)
            .expect("acked display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
        assert!(
            display
                .render()
                .contains("when demo work arrives load this skill")
        );
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn acknowledge_rejects_unapplied_and_foreign_acks_before_display() {
        let (forwarding, calls, _handle) = installing_forwarder();
        let receipt = forwarding
            .deliver_hotset(
                "hotset-runtime-2".to_owned(),
                vec!["skill-demo".to_owned()],
                "approval-commit-1".to_owned(),
                &InstallTools,
            )
            .expect("runtime delivery");
        let rejected = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Rejected {
                reason: "receiver refused the bodies".to_owned(),
            },
        };
        assert!(matches!(
            forwarding.acknowledge_and_display(
                "skill-demo",
                receipt.clone(),
                rejected,
                &InstallTools
            ),
            Err(SkillError::IdentityMismatch)
        ));
        let foreign = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: "e".repeat(64),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        assert!(matches!(
            forwarding.acknowledge_and_display("skill-demo", receipt, foreign, &InstallTools),
            Err(SkillError::IdentityMismatch)
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    /// Boundary double missing one declared tool: "eliot.finish" left the
    /// canonical view after delivery while "finish-cap" remains. Test
    /// scaffolding only, proving the standing-display invalidation fires on
    /// a partial basis change.
    struct FinishCapOnly;

    impl KnownTools for FinishCapOnly {
        fn knows_tool(&self, name: &str) -> bool {
            name == "finish-cap"
        }
    }

    #[test]
    fn display_marks_removed_tool_basis_stale_and_blocks_redelivery() {
        // #1882 acceptance end to end: a declared tool removed from the
        // canonical view after delivery marks the delivered Skill stale at
        // display time, blocking both the display and any later delivery
        // until revalidated.
        let (forwarding, calls, handle) = installing_forwarder();
        let receipt = forwarding
            .deliver_hotset(
                "hotset-basis-1".to_owned(),
                vec!["skill-demo".to_owned()],
                "approval-commit-1".to_owned(),
                &InstallTools,
            )
            .expect("runtime delivery");
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let refused =
            forwarding.acknowledge_and_display("skill-demo", receipt, ack, &FinishCapOnly);
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "entry.status"
        ));
        {
            let catalogue = handle.lock().expect("catalogue lock");
            let stored = catalogue.get("skill-demo").expect("stored entry");
            assert_eq!(stored.status, SkillStatus::Stale);
            assert!(
                stored
                    .stale_reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("eliot.finish")
            );
        }
        // The stale mark persists: redelivery fails closed too.
        let redelivery = forwarding.deliver_hotset(
            "hotset-basis-2".to_owned(),
            vec!["skill-demo".to_owned()],
            "approval-commit-1".to_owned(),
            &InstallTools,
        );
        assert!(matches!(
            redelivery,
            Err(SkillError::InvalidField { field, .. }) if field == "delivery.delivered_skill_ids"
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
        drop(forwarding);
    }

    #[test]
    fn delivery_requires_a_blank_rejected_approval_handle() {
        let (forwarding, _calls, _handle) = installing_forwarder();
        let refused = forwarding.deliver_hotset(
            "hotset-runtime-3".to_owned(),
            vec!["skill-demo".to_owned()],
            "   ".to_owned(),
            &InstallTools,
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "delivery.approval_ref"
        ));
    }

    /// Boundary double implementing the OWNED versioned port. Test
    /// scaffolding only: the drift proof below shows the runtime callers
    /// refuse a double whose bound version the composition did not admit, so
    /// a compiled factory is never mistaken for provider availability.
    struct VersionedSource {
        version: String,
        known: Vec<String>,
    }

    impl CanonicalToolSource for VersionedSource {
        fn definition_version(&self) -> &str {
            &self.version
        }

        fn knows_canonical_tool(&self, canonical_name: &str) -> bool {
            self.known.iter().any(|name| name == canonical_name)
        }
    }

    fn canonical_source(version: &str) -> VersionedSource {
        VersionedSource {
            version: version.to_owned(),
            known: vec!["eliot.finish".to_owned(), "finish-cap".to_owned()],
        }
    }

    fn available_readiness() -> ReadinessClaims {
        let available = |name: &str, version: &str| VersionedObservation {
            name: name.to_owned(),
            version: version.to_owned(),
            availability: Availability::Available {
                field: AvailabilityField::HostCapability,
            },
        };
        ReadinessClaims {
            host: "codex".to_owned(),
            profile: "default".to_owned(),
            provider: Availability::Available {
                field: AvailabilityField::Provider,
            },
            g16: Availability::Available {
                field: AvailabilityField::G16,
            },
            a06: Availability::Available {
                field: AvailabilityField::A06,
            },
            evidence: Availability::Available {
                field: AvailabilityField::Evidence,
            },
            tools: vec![available("eliot.finish", "1.0.0")],
            capabilities: vec![available("finish-cap", "1")],
        }
    }

    fn versioned_forwarder() -> (ForwardingSkillLifecycle<ClosedInner>, Arc<Mutex<u64>>) {
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        (ForwardingSkillLifecycle::new(inner), calls)
    }

    fn delivery_scope(fence: &StateFence) -> MaterializationScope {
        MaterializationScope {
            work_scope: eliot_receipts::WorkScopeBinding {
                scope_id: eliot_receipts::WorkScopeId::new("workscope-1")
                    .expect("valid test scope"),
                product_id: ProductId::new("test-product").expect("test product"),
                resource_generation: ResourceGeneration::new(1).expect("test generation"),
                state_fence: fence.clone(),
            },
            task: None,
        }
    }

    #[test]
    fn versioned_delivery_path_installs_issues_acks_and_displays() {
        let (forwarding, calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let context = install_context();
        let readiness = available_readiness();
        let fence = fence();
        let scope = delivery_scope(&fence);
        let source = canonical_source("1.2.0");
        let aliases = ToolAliasTable::new();
        let (skill_id, receipt) = forwarding
            .run_install_to_receipt(
                VersionedDeliveryAct {
                    package: &package,
                    inputs: &inputs,
                    context: &context,
                    readiness: &readiness,
                    scope: &scope,
                    source: &source,
                    aliases: &aliases,
                    admitted_definition_version: "1.2.0",
                    hotset_id: "hotset-versioned-1".to_owned(),
                    approval_ref: "approval-commit-1".to_owned(),
                },
                &fence,
            )
            .expect("versioned delivery act");
        assert_eq!(skill_id, "skill-demo");
        assert!(receipt.confirms_delivery("skill-demo"));
        // No sealed verifier exists in-tree: the PlanGap path proceeds
        // provisional, and the artifacts say so — absence of verification
        // never mints current-grade delivery.
        assert!(receipt.provisional);
        {
            let catalogue = forwarding.catalogue.lock().expect("catalogue lock");
            assert!(catalogue.is_usable("skill-demo"));
        }
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let display = forwarding
            .acknowledge_and_display(
                "skill-demo",
                receipt.clone(),
                ack,
                &eliot_skill::VersionBoundTools::new(&canonical_source("1.2.0"), &aliases),
            )
            .expect("acked display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
        assert_eq!(display.status, eliot_skill::SkillStatus::Provisional);
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn versioned_display_driver_acks_under_the_live_source() {
        let (forwarding, calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let context = install_context();
        let readiness = available_readiness();
        let fence = fence();
        let scope = delivery_scope(&fence);
        let source = canonical_source("1.2.0");
        let aliases = ToolAliasTable::new();
        let (skill_id, receipt) = forwarding
            .run_install_to_receipt(
                VersionedDeliveryAct {
                    package: &package,
                    inputs: &inputs,
                    context: &context,
                    readiness: &readiness,
                    scope: &scope,
                    source: &source,
                    aliases: &aliases,
                    admitted_definition_version: "1.2.0",
                    hotset_id: "hotset-display-live-1".to_owned(),
                    approval_ref: "approval-commit-1".to_owned(),
                },
                &fence,
            )
            .expect("versioned delivery act");
        // The receiver returns its ack for the issued receipt; the driver
        // binds it under the live tool-owner source, which still binds the
        // admitted version — no drift, so the provisional display issues.
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let display = forwarding
            .acknowledge_and_display_versioned(
                &skill_id,
                receipt.clone(),
                ack,
                &source,
                &aliases,
                "1.2.0",
            )
            .expect("drift-gated display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
        assert_eq!(display.status, eliot_skill::SkillStatus::Provisional);
        assert!(display.render().contains("status provisional"));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn versioned_display_refuses_definition_drift_before_display() {
        let (forwarding, calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let context = install_context();
        let readiness = available_readiness();
        let fence = fence();
        let scope = delivery_scope(&fence);
        let source = canonical_source("1.2.0");
        let aliases = ToolAliasTable::new();
        let (skill_id, receipt) = forwarding
            .run_install_to_receipt(
                VersionedDeliveryAct {
                    package: &package,
                    inputs: &inputs,
                    context: &context,
                    readiness: &readiness,
                    scope: &scope,
                    source: &source,
                    aliases: &aliases,
                    admitted_definition_version: "1.2.0",
                    hotset_id: "hotset-display-live-2".to_owned(),
                    approval_ref: "approval-commit-1".to_owned(),
                },
                &fence,
            )
            .expect("versioned delivery act");
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        // The Tool Definition moved between install and display: the live
        // tool-owner source no longer binds the admitted version, so the
        // display refuses instead of rendering under drifted authority.
        let drifted = canonical_source("9.9.9");
        let refused = forwarding.acknowledge_and_display_versioned(
            &skill_id, receipt, ack, &drifted, &aliases, "1.2.0",
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "tools.definition_version"
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn versioned_install_refuses_drifted_source_before_touching_catalogue() {
        let (forwarding, calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let aliases = ToolAliasTable::new();
        let refused = forwarding.install_package_versioned(
            &package,
            &inputs,
            &install_context(),
            &canonical_source("9.9.9"),
            &aliases,
            "1.2.0",
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "tools.definition_version"
        ));
        let catalogue = forwarding.catalogue.lock().expect("catalogue lock");
        assert!(catalogue.is_empty());
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn versioned_install_refuses_tools_absent_from_the_source() {
        let (forwarding, _calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let aliases = ToolAliasTable::new();
        let unknown = VersionedSource {
            version: "1.2.0".to_owned(),
            known: Vec::new(),
        };
        let refused = forwarding.install_package_versioned(
            &package,
            &inputs,
            &install_context(),
            &unknown,
            &aliases,
            "1.2.0",
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "body.tool_refs"
        ));
        let catalogue = forwarding.catalogue.lock().expect("catalogue lock");
        assert!(catalogue.is_empty());
    }

    #[test]
    fn unavailable_readiness_blocks_receipt_but_keeps_the_install() {
        let (forwarding, _calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let aliases = ToolAliasTable::new();
        let mut readiness = available_readiness();
        readiness.tools[0].availability = Availability::Unavailable {
            field: AvailabilityField::HostCapability,
            code: eliot_skill::UnavailableCode::HostCapabilityUnavailable,
            reason: "provider revoked the tool".to_owned(),
        };
        let source = canonical_source("1.2.0");
        let scope_fence = fence();
        let refused = forwarding.run_install_to_receipt(
            VersionedDeliveryAct {
                package: &package,
                inputs: &inputs,
                context: &install_context(),
                readiness: &readiness,
                scope: &delivery_scope(&scope_fence),
                source: &source,
                aliases: &aliases,
                admitted_definition_version: "1.2.0",
                hotset_id: "hotset-versioned-2".to_owned(),
                approval_ref: "approval-commit-1".to_owned(),
            },
            &scope_fence,
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "readiness.tools"
        ));
        // Installed is not delivered: the entry stands, but no receipt exists.
        let catalogue = forwarding.catalogue.lock().expect("catalogue lock");
        assert!(catalogue.is_usable("skill-demo"));
    }

    #[test]
    fn sealed_omission_blocks_receipt_but_keeps_the_install() {
        let (forwarding, _calls) = versioned_forwarder();
        let (mut package, inputs) = package_source();
        package.state = eliot_skill::SkillState {
            freshness: eliot_skill::FreshnessState::Stale {
                reason: "tool-def-1 moved".to_owned(),
            },
            conflict: eliot_skill::ConflictState::None,
            distractor: eliot_skill::DistractorState::None,
            quarantine: eliot_skill::QuarantineState::Clear,
        };
        package
            .validate(&inputs)
            .expect("stale package still validates");
        let aliases = ToolAliasTable::new();
        let source = canonical_source("1.2.0");
        let scope_fence = fence();
        let refused = forwarding.run_install_to_receipt(
            VersionedDeliveryAct {
                package: &package,
                inputs: &inputs,
                context: &install_context(),
                readiness: &available_readiness(),
                scope: &delivery_scope(&scope_fence),
                source: &source,
                aliases: &aliases,
                admitted_definition_version: "1.2.0",
                hotset_id: "hotset-versioned-4".to_owned(),
                approval_ref: "approval-commit-1".to_owned(),
            },
            &scope_fence,
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "sealed.materialization"
        ));
        // The governed stale install stands; only the receipt is refused.
        let catalogue = forwarding.catalogue.lock().expect("catalogue lock");
        assert_eq!(
            catalogue.get("skill-demo").expect("entry").status,
            eliot_skill::SkillStatus::Stale
        );
    }

    #[test]
    fn composed_delivery_refuses_a_blank_approval_handle() {
        let (forwarding, _calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let aliases = ToolAliasTable::new();
        let readiness = available_readiness();
        let source = canonical_source("1.2.0");
        let scope_fence = fence();
        let refused = forwarding.run_install_to_receipt(
            VersionedDeliveryAct {
                package: &package,
                inputs: &inputs,
                context: &install_context(),
                readiness: &readiness,
                scope: &delivery_scope(&scope_fence),
                source: &source,
                aliases: &aliases,
                admitted_definition_version: "1.2.0",
                hotset_id: "hotset-versioned-3".to_owned(),
                approval_ref: "   ".to_owned(),
            },
            &scope_fence,
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "delivery.approval_ref"
        ));
    }

    #[test]
    fn stale_scope_fence_refuses_issuance_before_touching_the_catalogue() {
        let (forwarding, calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let context = install_context();
        let readiness = available_readiness();
        let claimed = fence();
        let scope = delivery_scope(&claimed);
        let source = canonical_source("1.2.0");
        let aliases = ToolAliasTable::new();
        // The Governor refreshed between the injector's build and the drive:
        // the live admitted fence no longer equals the act's scope fence, so
        // the install stands unwritten and no receipt mints.
        let admitted = StateFence::new(
            test_epoch(2),
            ResourceGeneration::new(2).expect("test generation"),
        );
        let refused = forwarding.run_install_to_receipt(
            VersionedDeliveryAct {
                package: &package,
                inputs: &inputs,
                context: &context,
                readiness: &readiness,
                scope: &scope,
                source: &source,
                aliases: &aliases,
                admitted_definition_version: "1.2.0",
                hotset_id: "hotset-versioned-5".to_owned(),
                approval_ref: "approval-commit-1".to_owned(),
            },
            &admitted,
        );
        assert!(matches!(refused, Err(SkillError::FenceMismatch)));
        let catalogue = forwarding.catalogue.lock().expect("catalogue lock");
        assert!(catalogue.is_empty());
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn injector_call_assembles_terms_and_drives_to_receipt() {
        // The injector-call assembly the transport lane drives: request
        // fields plus driver-observed terms (live source, aliases, admitted
        // version and fence) run the full gate order to a provisional
        // receipt, with the Governor owner untouched.
        let (forwarding, calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let context = install_context();
        let readiness = available_readiness();
        let fence = fence();
        let scope = delivery_scope(&fence);
        let source = canonical_source("1.2.0");
        let aliases = ToolAliasTable::new();
        let (skill_id, receipt) = forwarding
            .inject_hotset(
                SkillHotsetRequest {
                    package: &package,
                    inputs: &inputs,
                    context: &context,
                    readiness: &readiness,
                    scope: &scope,
                    hotset_id: "hotset-inject-1".to_owned(),
                    approval_ref: "approval-commit-1".to_owned(),
                },
                &source,
                &aliases,
                "1.2.0",
                &fence,
            )
            .expect("injector call drives to receipt");
        assert_eq!(skill_id, "skill-demo");
        assert!(receipt.confirms_delivery("skill-demo"));
        assert!(receipt.provisional);
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn injector_call_refuses_a_refreshed_fence_before_writing() {
        // Assembly order: the fence gate fires before version, readiness,
        // sealed, and approval gates, so a refreshed Governor inherits
        // nothing — not even a catalogue entry.
        let (forwarding, calls) = versioned_forwarder();
        let (package, inputs) = package_source();
        let context = install_context();
        let readiness = available_readiness();
        let claimed = fence();
        let scope = delivery_scope(&claimed);
        let source = canonical_source("1.2.0");
        let aliases = ToolAliasTable::new();
        let admitted = StateFence::new(
            test_epoch(2),
            ResourceGeneration::new(2).expect("test generation"),
        );
        let refused = forwarding.inject_hotset(
            SkillHotsetRequest {
                package: &package,
                inputs: &inputs,
                context: &context,
                readiness: &readiness,
                scope: &scope,
                hotset_id: "hotset-inject-2".to_owned(),
                approval_ref: "approval-commit-1".to_owned(),
            },
            &source,
            &aliases,
            "1.2.0",
            &admitted,
        );
        assert!(matches!(refused, Err(SkillError::FenceMismatch)));
        let catalogue = forwarding.catalogue.lock().expect("catalogue lock");
        assert!(catalogue.is_empty());
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn forwarding_preserves_typed_rejection_without_invention() {
        let fence = fence();
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: true,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let rejected = blocking_view(forwarding.view(&metadata(&fence), "skill-demo".to_owned()));
        assert!(matches!(rejected, Err(SkillError::FenceMismatch)));
        assert_eq!(*calls.lock().expect("calls"), 1);
    }

    struct TestTools;

    impl KnownTools for TestTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish"
        }
    }

    fn dependency(version: &str) -> DependencyVersion {
        DependencyVersion {
            name: "tool-def-1".to_owned(),
            version: version.to_owned(),
            contract_digest: "c".repeat(64),
        }
    }

    fn catalogue_entry() -> SkillCatalogueEntry {
        let mut body = SkillBody {
            skill_id: "skill-demo".to_owned(),
            body_version: "1.0.0".to_owned(),
            body_digest: String::new(),
            actions: vec!["Refresh the task view before a Material effect.".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            stop_escalation: "Stop and escalate on conflicting instructions.".to_owned(),
            tool_refs: vec!["eliot.finish".to_owned()],
        };
        body.body_digest = body.expected_digest().expect("body digest");
        SkillCatalogueEntry {
            index: SkillIndexEntry {
                skill_id: "skill-demo".to_owned(),
                name: "demo skill".to_owned(),
                trigger: "when demo work arrives load this skill".to_owned(),
                eligible_routes: vec!["route-1".to_owned()],
                eligible_profiles: vec!["profile-1".to_owned()],
            },
            body,
            runtime: SkillRuntimeMetadata {
                skill_id: "skill-demo".to_owned(),
                body_version: "1.0.0".to_owned(),
                references: vec!["references/playbook.md".to_owned()],
                scripts: Vec::new(),
                assets: Vec::new(),
                index_budget_tokens: 200,
                body_budget_tokens: 800,
                runtime_budget_tokens: 2000,
                index_tokens: 60,
                body_tokens: 400,
                runtime_tokens: 0,
            },
            dependencies: vec![dependency("1.2.0")],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            status: SkillStatus::Provisional,
            stale_reason: None,
        }
    }

    fn installed_catalogue() -> CatalogueHandle {
        let mut catalogue = SkillCatalogue::default();
        catalogue
            .insert(catalogue_entry(), &TestTools)
            .expect("install entry");
        Arc::new(Mutex::new(catalogue))
    }

    struct InstallTools;

    impl KnownTools for InstallTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish" || name == "finish-cap"
        }
    }

    fn package_behavior() -> eliot_skill::SkillBehavior {
        eliot_skill::SkillBehavior {
            intent: "refresh the task view before a Material effect".to_owned(),
            trigger: "when demo work arrives load this skill".to_owned(),
            action: "Refresh the task view before a Material effect.".to_owned(),
            applies_when: vec!["the task view is stale".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            required_outputs: vec!["refreshed view".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            stop: "Stop and escalate on conflicting instructions.".to_owned(),
            escalation: "escalate to the task owner".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
        }
    }

    fn package_inputs() -> eliot_skill::MaterializationInputs {
        eliot_skill::MaterializationInputs {
            canonical_source_bytes: b"canonical demo source\n".to_vec(),
            contract_materialization: package_behavior(),
            dependencies: vec![eliot_skill::DependencyMaterial {
                name: "tool-def-1".to_owned(),
                version: "1.2.0".to_owned(),
                contract_digest: "c".repeat(64),
            }],
            tool_definitions: vec![eliot_skill::ToolDefinitionMaterial {
                name: "eliot.finish".to_owned(),
                version: "1.0.0".to_owned(),
                description: "typed finish attempt".to_owned(),
                capabilities: vec![eliot_skill::CapabilityVersion {
                    name: "finish-cap".to_owned(),
                    version: "1".to_owned(),
                }],
                actions: vec!["Refresh the task view before a Material effect.".to_owned()],
            }],
        }
    }

    fn package_source() -> (
        eliot_skill::SkillPackage,
        eliot_skill::MaterializationInputs,
    ) {
        let inputs = package_inputs();
        let rule: eliot_skill::AdvisoryRuleClaim = serde_json::from_value(serde_json::json!({
            "rule_ref": { "rule_id": "rule-demo-1", "revision": 1 }
        }))
        .expect("rule fixture");
        let package = eliot_skill::SkillPackage {
            registration: eliot_skill::RegistrationIdentity::new(
                "skill-demo",
                "1.0.0",
                "demo skill",
            )
            .expect("valid test registration"),
            digests: eliot_skill::PackageDigests::derive(&inputs).expect("valid test inputs"),
            host: eliot_skill::HostProfile {
                host: "codex".to_owned(),
                profile: "default".to_owned(),
                required_tools: vec![eliot_skill::VersionedRequirement {
                    name: "eliot.finish".to_owned(),
                    version: "1.0.0".to_owned(),
                }],
                required_capabilities: vec![eliot_skill::VersionedRequirement {
                    name: "finish-cap".to_owned(),
                    version: "1".to_owned(),
                }],
                limits: eliot_skill::HostLimits {
                    max_description_chars: 500,
                    max_actions: 1,
                    max_expansion_handles: 2,
                },
            },
            behavior: package_behavior(),
            counters: eliot_skill::SkillCounters::default(),
            state: eliot_skill::SkillState {
                freshness: eliot_skill::FreshnessState::Current,
                conflict: eliot_skill::ConflictState::None,
                distractor: eliot_skill::DistractorState::None,
                quarantine: eliot_skill::QuarantineState::Clear,
            },
            lifecycle_proposal: eliot_skill::LifecycleProposal::Keep,
            delivery: eliot_skill::DeliveryProjection::default(),
            interaction: eliot_skill::SkillInteractionProjection::default(),
            rule,
        };
        package
            .validate(&inputs)
            .expect("fixture package validates");
        (package, inputs)
    }

    fn install_context() -> eliot_skill::CatalogueInstallContext {
        eliot_skill::CatalogueInstallContext {
            eligible_routes: vec!["route-1".to_owned()],
            eligible_profiles: vec!["profile-1".to_owned()],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            index_budget_tokens: 200,
            body_budget_tokens: 800,
            runtime_budget_tokens: 2000,
            index_tokens: 60,
            body_tokens: 400,
            runtime_tokens: 0,
            references: vec!["references/playbook.md".to_owned()],
            scripts: Vec::new(),
            assets: Vec::new(),
        }
    }

    fn installing_forwarder() -> (
        ForwardingSkillLifecycle<ClosedInner>,
        Arc<Mutex<u64>>,
        CatalogueHandle,
    ) {
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let (package, inputs) = package_source();
        let installed =
            forwarding.install_package(&package, &inputs, &install_context(), &InstallTools);
        assert_eq!(installed.expect("package install"), "skill-demo");
        let handle = forwarding.catalogue.clone();
        (forwarding, calls, handle)
    }

    fn base_view(fence: &StateFence) -> SkillLifecycleView {
        SkillLifecycleView {
            skill_ref: SkillRef::new("skill-demo", "rev-1", "Demo Skill", "a".repeat(64))
                .expect("skill ref"),
            scope: SkillScope {
                task_scope: "task-scope".to_owned(),
                host: "host-1".to_owned(),
                route: "route-1".to_owned(),
                governance_scope: "gov-1".to_owned(),
            },
            applies_when: vec!["when-a".to_owned()],
            does_not_apply_when: vec!["not-when-a".to_owned()],
            dependencies: Vec::new(),
            counters: LifecycleCounters::default(),
            execution_evidence: Vec::new(),
            observed_decision_or_verifier_delta: None,
            false_activation_refs: Vec::new(),
            interactions: SkillInteractionView::default(),
            status: SkillStatus::Current,
            stale_or_quarantine_reason: None,
            proposed_action: LifecycleAction::Keep,
            review: None,
            state_fence: fence.clone(),
            lifecycle_revision: 1,
        }
    }

    fn candidate_with_deps(
        fence: &StateFence,
        dependencies: Vec<DependencyVersion>,
    ) -> SkillCandidate {
        SkillCandidate::new(
            &base_view(fence),
            "b".repeat(64),
            LifecycleAction::Patch,
            vec!["evidence-1".to_owned()],
            dependencies,
            SkillScope {
                task_scope: "task-scope".to_owned(),
                host: "host-1".to_owned(),
                route: "route-1".to_owned(),
                governance_scope: "gov-1".to_owned(),
            },
            fence.clone(),
        )
        .expect("candidate")
    }

    fn gate_for(fence: &StateFence, candidate: &SkillCandidate) -> PromotionGate {
        PromotionGate {
            candidate_digest: candidate.candidate_digest.clone(),
            base_view_digest: candidate.base_view_digest.clone(),
            verifier_ref: "verifier-1".to_owned(),
            evidence_refs: vec!["evidence-1".to_owned()],
            independent_route_count: 1,
            human_approval_ref: None,
            reversible: true,
            state_fence: fence.clone(),
        }
    }

    fn identity(fence: &StateFence) -> RequestIdentity {
        RequestIdentity {
            request: RequestBinding {
                metadata: metadata(fence),
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-skill-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-skill-1".to_owned(),
        }
    }
}
