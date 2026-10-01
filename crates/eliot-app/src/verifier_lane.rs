//! The measured governed I2.22 lane the engine patch/verifier lane runs in
//! (issue #1897, audit #5910637761 defect 1).
//!
//! A Cargo verifier requirement is a mutating build, and I2.22 states that
//! governed instruments do not build in the repository `target/` directory.
//! `eliot_engine::VerifierHarness::with_governed_lane` therefore admits a
//! retained [`GovernedWorkEnvelope`], and this module is the producer that
//! builds that envelope from the real work item the product callers already
//! hold. Nothing here is a constant lane:
//!
//! * the workspace and worktree segments come from the SAME
//!   [`TargetLayoutBinding`] derivations the `TestD` lane uses, applied to this
//!   work item's real project identity and its real canonical checkout, so two
//!   checkouts never share a governed build root;
//! * the build fingerprint is MEASURED — the manifest digest is the SHA-256 of
//!   the checkout's real `Cargo.toml`, the source-closure digest is the SHA-256
//!   of the real admitted work item (project, work item, canonical checkout,
//!   and the exact verifier requirements), and the contract revision is the
//!   SHA-256 of the real [`VerifierPlan`] this lane executes;
//! * the exclusive runtime lease comes from the live
//!   [`ResourceLeaseAllocator`], which is the only owner that decides
//!   exclusivity against a holder set. The lease is bound to this work item, so
//!   a worktree alone still cannot reach a shared fixture root.
//!
//! The lane executes no process and allocates no port: it produces the tuple
//! the engine harness admits and launches. A checkout that cannot be measured
//! (no manifest, unresolvable application-data root) is refused here, before
//! any harness exists.
//!
//! Every field is read from real admitted material. Nothing here is a constant
//! standing in for an observation the caller does not hold: where the engine
//! lane genuinely has no admitted value, this returns an error rather than
//! minting a plausible-looking one, because a governed-looking fingerprint that
//! proves nothing is worse than an honest refusal.
//!
//! One such refusal is unconditional today. `BuildFingerprint.target` has no
//! admitted source on this lane (see [`unobtainable_target`]), and no route can
//! supply one, so [`governed_verifier_lane`] refuses on every call and the
//! engine harness fails closed through its own refusal. That is the intended
//! fail-closed state, not a gap: no Cargo verifier runs in the shared
//! repository `target/` directory while no admitted target names it. The
//! measurement below is complete and retained rather than deleted, so admitting
//! the target field activates this lane instead of requiring it to be rewritten.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use eliot_engine::VerifierHarness;
use eliot_testd_core::{
    BuildClass, BuildFingerprint, BuildMode, GovernedWorkEnvelope, LaneIdentity,
    ResourceLeaseAllocator, ResourceWeight, RuntimeEnvironmentLease, TargetLayoutBinding,
    TestResourceProfile,
};
use eliot_types::{VerifierCommandKind, VerifierPlan};
use sha2::{Digest, Sha256};

/// Environment class of the governed child this lane launches.
///
/// The engine verifier lane inherits the caller's process environment and adds
/// exactly the envelope's own bindings (the Cargo roots and the fixture pair),
/// so this class names that projection rather than a `TestD` product profile's
/// non-inheriting one.
const VERIFIER_ENVIRONMENT_CLASS: &str = "inheriting-governed-verifier-lane";

/// Cargo profile every admitted engine verifier requirement resolves to.
///
/// `eliot_engine::patch`'s fixed verifier command map never passes `--profile`
/// and never passes `--release`, so every requirement it launches resolves
/// Cargo's default `dev` profile. This is read off that real command map; it is
/// not a preference.
const VERIFIER_CARGO_PROFILE: &str = "dev";

/// Toolchain label for a checkout that declares no `rust-toolchain.toml`
/// channel.
///
/// Such a checkout resolves whatever Cargo's configured default is, so this
/// label states the measured outcome — no declared pin — instead of inventing a
/// version. A checkout that DOES pin one carries that channel instead, so the
/// two never share a fingerprint.
const UNPINNED_TOOLCHAIN: &str = "unpinned-cargo-default";

/// The one `BuildFingerprint` field this lane cannot measure, and why.
///
/// `BuildFingerprint.target` names the Cargo target triple the build resolves.
/// On this lane it is unobtainable, and every candidate source was measured
/// rather than assumed:
///
/// * `PatchRequest` (`eliot-types/src/memory.rs`), `ActionLease` and
///   `PatchToolInput` carry **no** target field, so nothing a caller holds names
///   one.
/// * `crates/eliot-app/build.rs` could read Cargo's own `TARGET` hermetically,
///   but that file belongs to `main` and already carries three `git` probes,
///   which makes it a `clippy::disallowed-methods` site (issue #748 / I10.8.2).
///   Editing it surfaces six violations owned by code this lane does not, in a
///   package this issue does not own.
/// * `std::env::consts` yields `ARCH` and `OS` only. Composing
///   `x86_64-pc-windows-msvc` from those would be inference, not observation.
/// * `DevFastCandidate::target_triple` (`eliot-instrument-runner/src/dev_fast.rs`)
///   is caller-supplied, and `git grep DevFastCandidate::bind` returns zero
///   callers, so no producer exists to read.
/// * Spawning `rustc --print` would be a fourth direct process launch, which is
///   the very thing `clippy::disallowed-methods` forbids.
/// * `cargo-nextest` does accept `--target <TRIPLE>`, but
///   `eliot_engine::patch`'s fixed verifier command map never passes it, so the
///   resolved target is Cargo's **host default** — exactly the value nobody in
///   this workspace can name without a probe or a build-script edit.
///
/// **The owner that must supply it:** the `ActionLease` admission path, which
/// already issues the scope and the `VerifierPlan` this lane admits. A `target`
/// field there, carried to `PatchRunnerInput` beside `VerifierPlan`, makes the
/// value admitted material — the same way the productive `TestD` lane reads
/// `InstrumentInvocation::target` in `admitted_lane_identity`. Wiring it requires
/// a change to `eliot-types`, which this issue does not own.
///
/// **Why an error and not `None`:** `build_script_digest` and `proc_macro_digest`
/// are `None` because *nothing observes them*. `target` is different in kind — a
/// real value exists and matters, this lane simply has no admitted source for
/// it — so `None` would understate it. Minting a plausible triple instead would
/// key every governed build root under this lane by a value no work item holds,
/// which is precisely the inert-fingerprint defect class this issue exists to
/// remove.
fn unobtainable_target() -> anyhow::Error {
    anyhow!(
        "BuildFingerprint.target is unobtainable on the engine verifier lane (issue #1897, \
         AUD7): the fixed verifier command map never passes --target, so the resolved target is \
         Cargo's host default, and no admitted input names it. PatchRequest, ActionLease and \
         PatchToolInput carry no target field; eliot-app/build.rs belongs to main and is a \
         clippy::disallowed-methods site (issue #748); std::env::consts yields only ARCH and OS; \
         DevFastCandidate::target_triple has zero callers. Owner: add a target field to the \
         ActionLease admission path and carry it to PatchRunnerInput beside VerifierPlan, so \
         this value arrives admitted rather than probed. Until then the governed lane is dormant \
         and every caller fails closed through VerifierHarness."
    )
}

/// Builds the retained governed lane for one engine verifier work item.
///
/// This lane is currently DORMANT, and that is the fail-closed path working, not
/// a gap: `target` is the one fingerprint field it cannot measure for itself
/// (see [`unobtainable_target`]), and no route can supply it yet, so every caller
/// passes `None` and receives that typed refusal. Each caller then takes
/// `VerifierHarness`'s own fail-closed refusal, so no Cargo verifier runs in the
/// shared repository `target/` directory and none pretends to be governed.
///
/// The measurement behind this refusal is complete and retained, not deleted, so
/// that whoever admits the `ActionLease` target field activates a working lane
/// rather than writing one: passing `Some(target)` is the whole change.
///
/// # Errors
///
/// [`unobtainable_target`] when `target` is `None`, which is every route today.
/// Otherwise an error when `target` is blank or control-bearing, when the
/// checkout cannot be canonicalized or has no readable `Cargo.toml`, when the
/// admitted project or checkout identity is not derivable, when the live lease
/// allocator refuses the fixture claim, or when the resulting tuple is not a
/// valid envelope. Every refusal happens before any Cargo process exists.
pub fn governed_verifier_lane(
    work_item_id: &str,
    project_id: &str,
    repo_root: &Path,
    plan: &VerifierPlan,
    target: Option<&str>,
) -> Result<GovernedWorkEnvelope> {
    // The one field this lane cannot measure for itself. `None` means the caller
    // holds no admitted target either, which is the case on every route today,
    // so this refuses before any filesystem work and no partial tuple is built
    // and then discarded.
    let Some(target) = target else {
        return Err(unobtainable_target());
    };
    if target.trim().is_empty() || target.chars().any(char::is_control) {
        return Err(anyhow!(
            "the admitted Cargo target triple must be a non-blank, control-free name \
             (issue #1897, BuildFingerprint.target)"
        ));
    }
    measure_verifier_lane(work_item_id, project_id, repo_root, plan, target)
}

/// Installs the governed lane on a harness when one was measurable, and fails
/// closed when it was not.
///
/// A harness with no lane admits no build: every Cargo requirement on it resolves
/// to `ungoverned_verifier_run`, so the requirement is recorded as a refusal and
/// no `cargo` process is launched. That is the state this repository must be in
/// whenever a lane cannot be measured, because the alternative is a governed
/// fingerprint that proves nothing while the build still runs in the shared
/// repository `target/` directory.
///
/// The refusal is reported rather than discarded, so an operator reading the logs
/// learns which field is missing instead of seeing an unexplained ungoverned run.
/// It is deliberately NOT propagated: propagating would abort the enclosing
/// `PatchRunner::apply` after `git apply` had already mutated the checkout, which
/// loses the rollback containment the harness's own refusal preserves.
#[must_use]
pub fn harness_with_measured_lane<'a>(
    harness: VerifierHarness<'a>,
    lane: Result<GovernedWorkEnvelope>,
    route: &'static str,
) -> VerifierHarness<'a> {
    match lane {
        Ok(lane) => harness.with_governed_lane(&lane),
        Err(refusal) => {
            tracing::warn!(
                route,
                error = %refusal,
                "no governed verifier lane was admitted, so every Cargo requirement on this \
                 route fails closed as an ungoverned verifier run"
            );
            harness
        }
    }
}

/// Measures every `BuildFingerprint` field this lane observes.
///
/// This is the complete, correct measurement for all but the `target` field it is
/// handed: workspace, candidate, toolchain, profile, features, environment class,
/// manifest digest, source-closure digest, build class and contract revision,
/// each read from real admitted material. It is reachable the moment a caller can
/// supply `target`, and it is a named function rather than inline code in the
/// refusing entry point so that whoever admits the `ActionLease` target field
/// activates this work instead of rewriting it.
///
/// # Errors
///
/// Returns an error when the checkout cannot be canonicalized or has no readable
/// `Cargo.toml`, when the admitted project or checkout identity is not derivable,
/// when the live lease allocator refuses the fixture claim, or when the
/// resulting tuple is not a valid envelope.
fn measure_verifier_lane(
    work_item_id: &str,
    project_id: &str,
    repo_root: &Path,
    plan: &VerifierPlan,
    target: &str,
) -> Result<GovernedWorkEnvelope> {
    let local_app_data =
        eliot_platform_windows::current_user_local_app_data_root().map_err(|error| {
            anyhow!(
                "resolve the current local application-data root for the governed lane: {error}"
            )
        })?;
    let canonical_checkout = std::fs::canonicalize(repo_root).with_context(|| {
        format!(
            "canonicalize the governed checkout {} (issue #1897, I2.22 target roots)",
            repo_root.display()
        )
    })?;
    let manifest_path = canonical_checkout.join("Cargo.toml");
    let manifest = std::fs::read(&manifest_path).with_context(|| {
        format!(
            "read the governed manifest {} (issue #1897, I2.22 target roots)",
            manifest_path.display()
        )
    })?;
    let checkout_text = canonical_checkout.to_string_lossy().into_owned();
    let plan_digest = sha256_hex(&canonical_json(plan)?);
    let workspace_id = TargetLayoutBinding::derive_workspace_component(project_id)
        .map_err(|error| anyhow!("derive the governed workspace component: {error}"))?;
    let worktree_id = TargetLayoutBinding::derive_checkout_component(&checkout_text)
        .map_err(|error| anyhow!("derive the governed checkout component: {error}"))?;
    let requirements: Vec<(&str, VerifierCommandKind, &str)> = plan
        .required
        .iter()
        .chain(plan.optional.iter())
        .map(|requirement| {
            (
                requirement.name.as_str(),
                requirement.command_kind,
                requirement.command_display.as_str(),
            )
        })
        .collect();
    let source_closure_digest = sha256_hex(&canonical_json(&(
        work_item_id,
        project_id,
        checkout_text.as_str(),
        requirements.as_slice(),
    ))?);
    // Every field of this fingerprint is measured from real admitted material;
    // `target` is the one value the caller had to admit, because no source on
    // this lane can observe it. See [`unobtainable_target`].
    let identity = LaneIdentity {
        work_item_id: work_item_id.to_owned(),
        workspace_id: workspace_id.clone(),
        worktree_id,
        fingerprint: BuildFingerprint {
            // The envelope refuses a fingerprint whose workspace disagrees with
            // the segment beside it, so both are this one derivation.
            workspace: workspace_id,
            // The work item IS the candidate revision under certification: one
            // patch request names exactly one candidate diff.
            candidate: work_item_id.to_owned(),
            toolchain: declared_toolchain(&canonical_checkout),
            // Admitted by the caller because nothing on this lane observes it.
            // No caller can supply one today, so this body is unreachable; see
            // [`unobtainable_target`] for why it is a parameter rather than a
            // constant or an `env!`.
            target: target.to_owned(),
            profile: VERIFIER_CARGO_PROFILE.to_owned(),
            // The fixed verifier command map admits no caller feature selection,
            // so the empty set is the observed declaration.
            features: Vec::new(),
            environment_class: VERIFIER_ENVIRONMENT_CLASS.to_owned(),
            source_closure_digest,
            manifest_digest: sha256_hex(&manifest),
            // This lane declares no build-script or proc-macro closure and
            // observes none, so neither digest is invented here.
            build_script_digest: None,
            proc_macro_digest: None,
            build_class: plan_build_class(plan).dir_name().to_owned(),
            contract_revision: format!("verifier-plan-{plan_digest}"),
        },
        // The fixed verifier argv sets no incremental flag (the
        // non-incremental half) and the governed root it derives ends in this
        // exact fingerprint (the exact-normalized half). I2.22's `+ sccache`
        // reuse mode is NOT claimed: this crate configures no compiler cache
        // daemon and owns no shared exact-fingerprint cache root.
        build_mode: BuildMode::SharedNonIncremental,
        local_app_data,
    };
    // The claim set is the lane's own derivation, not a copy: the envelope
    // re-derives the same namespace the claim is named from, so the leased
    // resource and the directory the child is handed are the same thing.
    let fixture_claims = identity
        .fixture_resource_claims()
        .map_err(|error| anyhow!("derive the governed fixture claim: {error}"))?;
    let mut allocator = ResourceLeaseAllocator::new();
    let granted = allocator
        .allocate(
            work_item_id,
            &TestResourceProfile {
                weight: ResourceWeight::Light,
                exclusive_resources: fixture_claims.clone(),
                serial_group: String::new(),
            },
        )
        .map_err(|error| anyhow!("allocate the governed runtime lease: {error}"))?;
    let runtime_leases = granted
        .into_iter()
        .map(|lease| RuntimeEnvironmentLease {
            kind: lease.kind,
            resource: lease.resource,
            holder: lease.holder,
        })
        .collect();
    GovernedWorkEnvelope::allocate(identity, fixture_claims, runtime_leases)
        .map_err(|error| anyhow!("allocate the governed work envelope: {error}"))
}

/// The declared Rust toolchain channel of a checkout, or the unpinned label.
///
/// Reading the checkout's own `rust-toolchain.toml` is the measurement: it is
/// the file Cargo itself resolves the toolchain from for that directory, so it
/// is the toolchain this lane's `cargo` invocation will use.
fn declared_toolchain(checkout: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(checkout.join("rust-toolchain.toml")) else {
        return UNPINNED_TOOLCHAIN.to_owned();
    };
    text.parse::<toml::Table>()
        .ok()
        .and_then(|table| {
            table
                .get("toolchain")
                .and_then(|toolchain| toolchain.get("channel"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| UNPINNED_TOOLCHAIN.to_owned())
}

/// The governed build class this lane's admitted plan performs.
///
/// One plan drives one lane, and a plan may mix lint and test requirements, so
/// the class is read off the plan rather than chosen: a governed lint
/// compilation when the plan declares one, otherwise governed test execution
/// when it declares one, otherwise the interactive class. The envelope derives
/// its governed root from `build_mode`, so this label classifies the work and
/// never places a directory.
fn plan_build_class(plan: &VerifierPlan) -> BuildClass {
    let mut class = BuildClass::Interactive;
    for requirement in plan.required.iter().chain(plan.optional.iter()) {
        match requirement.command_kind {
            VerifierCommandKind::CargoClippy | VerifierCommandKind::CargoCheck => {
                return BuildClass::Clippy;
            }
            VerifierCommandKind::CargoTest | VerifierCommandKind::CargoNextest => {
                class = BuildClass::Nextest;
            }
            VerifierCommandKind::CargoFmtCheck
            | VerifierCommandKind::CargoAudit
            | VerifierCommandKind::CargoDeny
            | VerifierCommandKind::DomainVerifier
            | VerifierCommandKind::ManualReview => {}
        }
    }
    class
}

/// Canonical JSON bytes, so a digest depends on content and not on field order.
fn canonical_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("serialize governed lane fingerprint material")
}

/// Lowercase SHA-256 of the exact bytes, matching the fingerprint digest shape.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
