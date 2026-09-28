//! Migration component/owner/path inventory, disposition ledger, repair impact
//! graph, and first Product Proof plan binding (issue #1860).
//!
//! This module is the production-code rendering of the `I19.2` required
//! outputs coordinated by `bins/eliotd`: every workspace package resolves to
//! its owner, migration disposition, and active-reference status; every
//! excluded-scope (standalone) package carries its verbatim `#1811`
//! disposition; the repair impact graph links the three hard-boundary
//! repairs, legacy-crate retirement, Kernel-Store v1 decode removal, the
//! release surface, Windows Product Proof, and the Store/Governor dependency
//! paths; and [`PRODUCT_PROOF_PLAN`] binds the first Product Proof plan with
//! its concrete installed-route receipt.
//!
//! # Source pin
//!
//! Rows are a deterministic projection of
//! `scripts/migration_inventory_1860.py v0.1.0` emit output at:
//!
//! ```text
//! git_head:       14cf4a6849fc13cb29a9dce4ba6dd6cacc29bbad (tree clean)
//! cargo_lock:     c82bc0d28eb9393c4fdb0957d83dcda031776d0ed7ba735ed65bc339eb4d6507
//! cargo/rustc:    1.97.1
//! aggregate:      f1c39e2cc53f4a1a3ead66320b1bede765d8c2bfcc930bfc05b0fd6c54fd3a0f
//! denominator:    188 members, 15 bins roots, 139 reachable, 49 unreachable,
//!                 9 standalone
//! ```
//!
//! # Refresh rule
//!
//! Per `I19.2` this evidence is valid only for the pinned source identity.
//! [`migration_inventory_guard`] pins the exact row counts, so any package
//! added, removed, admitted, or re-reached fails closed until a governed
//! refresh re-projects the tables. Reachability alone never retires anything:
//! unscanned or unknown rows resolve to [`ComponentDisposition::Unknown`].
//!
//! # Proof ceiling
//!
//! [`PROOF_CEILING`] (`MIGRATION_INVENTORY_EVIDENCE_ONLY`): source,
//! reachability, and ownership evidence only. Product status stays
//! `NOT_ACCEPTED / UNVERIFIED` until the exact Product Proof executes.
//!
//! # Reviewer lookup guide (acceptance #1860)
//!
//! ```text
//! any bins/* binary path or name .... `resolve` -> package row by manifest dir
//! any crates/* package path ......... `resolve` -> owner, disposition, rationale
//! any excluded/standalone path ...... `resolve` -> verbatim #1811 row
//! generated artifact / schema / Skill / `SURFACE_CLASSES` class row, then the
//!   prompt / config / CI / manifest ... referencing package rows via
//!                                `InventoryEntry::hit_classes`
//! installed integration / live state .. `resolve` -> `Unscanned` (UNKNOWN);
//!                                live store, installed artifacts, and runtime
//!                                integration state are never scanned here
//! repair impact ..................... `impact_node`, `impact_edges_from`,
//!                                `impact_edges_to`, `impact_entry_node`
//! first Product Proof plan .......... `PRODUCT_PROOF_PLAN`
//! ```
//!
//! # Premise reconciliation
//!
//! The issue's audit premise named 43 unreachable and 13 excluded packages.
//! At the pin, 49 packages are unreachable (every one dispositioned, covering
//! the audit-time 43) and 9 standalone packages carry `#1811` rows; two
//! former standalone crates were admitted to the workspace through governed
//! review, so the raw 13-wide count no longer holds and is intentionally not
//! asserted. The live `--check` predicate for that stale count fails on
//! current main; the guard below pins the refreshed denominator instead.

/// Inventory schema identity, shared with the projecting tool.
pub const INVENTORY_SCHEMA: &str = "eliot.migration-inventory-1860.v1";

/// Tool and revision the rows were projected from.
pub const INVENTORY_TOOL: &str = "scripts/migration_inventory_1860.py v0.1.0";

/// Pinned source commit the rows were measured at.
pub const INVENTORY_PIN_COMMIT: &str = "14cf4a6849fc13cb29a9dce4ba6dd6cacc29bbad";

/// Pinned root `Cargo.lock` SHA-256 at the source pin.
pub const INVENTORY_PIN_LOCK: &str =
    "c82bc0d28eb9393c4fdb0957d83dcda031776d0ed7ba735ed65bc339eb4d6507";

/// Aggregate SHA-256 of the emit document the rows project.
pub const INVENTORY_PIN_AGGREGATE: &str =
    "f1c39e2cc53f4a1a3ead66320b1bede765d8c2bfcc930bfc05b0fd6c54fd3a0f";

/// Migration coordination owner for this inventory (issue scope and owner).
pub const COORDINATOR: &str = "bins/eliotd migration coordination";

/// Proof ceiling: source/reachability/ownership evidence only.
pub const PROOF_CEILING: &str = "MIGRATION_INVENTORY_EVIDENCE_ONLY";

/// Workspace members at the pin.
pub const WORKSPACE_MEMBERS: usize = 188;
/// Composition roots under `bins/` at the pin.
pub const BINS_ROOTS: usize = 15;
/// Workspace packages reachable from a `bins/` root at the pin.
pub const BINS_REACHABLE: usize = 139;
/// Workspace packages reachable from no `bins/` root at the pin.
pub const BINS_UNREACHABLE: usize = 49;
/// Standalone (excluded-scope) packages at the pin.
pub const STANDALONE_PACKAGES: usize = 9;
/// Audit-time unreachable count from the issue body.
pub const AUDIT_UNREACHABLE_PREMISE: usize = 43;

/// Surfaces the repository scan never observes; always `UNKNOWN`.
pub const UNSCANNED_SURFACES: &[&str] = &[
    "live store/data",
    "installed artifacts/manifests",
    "active integrations runtime state",
];

/// Owner recorded for unscanned components.
const UNSCANNED_OWNER: &str = "unscanned surface owner TBD; coordinated by bins/eliotd (#1860)";

/// Rationale recorded for unscanned components (work order: unscanned is
/// `UNKNOWN`; reachability alone never retires anything).
const UNSCANNED_RATIONALE: &str = "Unscanned surface (live store, installed artifact, or active integration state). UNKNOWN (fail-closed): requires owner experiment before any other disposition; no retirement inferred (I19.2).";

/// Shared rationale for bins-reachable packages.
const RATIONALE_REACHABLE: &str =
    "Reachable from a bins/ binary; no migration disposition required.";

const OWNER_INSTRUMENT_KEEP: &str =
    "instrument plane support owner #20 (testd) via capability registry #13";
const RATIONALE_INSTRUMENT_KEEP: &str = "Instrument-plane support crate, not a production runtime dependency. KEEP as typed Instrument execution/evidence support; no promotion to runtime authority implied.";
const RATIONALE_ADMITTED_KEEP: &str = "Admitted capability cell awaiting production wiring. KEEP; no deletion. Reachability alone never implies retirement (I19.2 refresh rule).";
const RATIONALE_PROTOTYPE_REWORK: &str = "Prototype cell pending agent implementation and proof. REWORK before any admission-to-runtime claim.";

/// `I19.3` component disposition vocabulary: every dispositioned component
/// carries exactly one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentDisposition {
    /// Conforms and can remain.
    Keep,
    /// Useful component kept behind a new bridge.
    Wrap,
    /// Move from monolith to module with the same behavior.
    Extract,
    /// Concept valid, contract wrong.
    Rework,
    /// Incompatible or too costly.
    Replace,
    /// No value or duplicate; deletion stays gated on consumer migration.
    Retire,
    /// Requires experiment; blocks deletion of the affected scope only.
    Unknown,
}

impl ComponentDisposition {
    /// Recorded disposition word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "KEEP",
            Self::Wrap => "WRAP",
            Self::Extract => "EXTRACT",
            Self::Rework => "REWORK",
            Self::Replace => "REPLACE",
            Self::Retire => "RETIRE",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Parse a recorded disposition word; `None` rejects anything outside
    /// the closed `I19.3` vocabulary.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "KEEP" => Some(Self::Keep),
            "WRAP" => Some(Self::Wrap),
            "EXTRACT" => Some(Self::Extract),
            "REWORK" => Some(Self::Rework),
            "REPLACE" => Some(Self::Replace),
            "RETIRE" => Some(Self::Retire),
            "UNKNOWN" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Closed `I19.3` vocabulary. The guard rejects any row outside it, so
/// extending the enum without updating this table fails closed.
pub const ALL_COMPONENT_DISPOSITIONS: &[ComponentDisposition] = &[
    ComponentDisposition::Keep,
    ComponentDisposition::Wrap,
    ComponentDisposition::Extract,
    ComponentDisposition::Rework,
    ComponentDisposition::Replace,
    ComponentDisposition::Retire,
    ComponentDisposition::Unknown,
];

/// Active-reference scan outcome for one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveReferenceStatus {
    /// At least one repository hit outside the component's own directory;
    /// [`InventoryEntry::hit_classes`] names the surface classes.
    ActiveReference,
    /// No repository hit, but live store, installed artifacts, and runtime
    /// integration state were not scanned; never implies retirement.
    NoRepoReferenceLiveUnknown,
    /// Component itself was never scanned (installed integration, live
    /// state, or path absent from the inventory); the `#1860` work order
    /// renders every unscanned surface as `UNKNOWN`.
    UnscannedUnknown,
}

impl ActiveReferenceStatus {
    /// Recorded status word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveReference => "ACTIVE_REFERENCE",
            Self::NoRepoReferenceLiveUnknown => "NO_REPO_REFERENCE_LIVE_UNKNOWN",
            Self::UnscannedUnknown => "UNSCANNED_UNKNOWN",
        }
    }

    /// Parse a recorded status word; `None` rejects anything outside the
    /// closed vocabulary.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "ACTIVE_REFERENCE" => Some(Self::ActiveReference),
            "NO_REPO_REFERENCE_LIVE_UNKNOWN" => Some(Self::NoRepoReferenceLiveUnknown),
            "UNSCANNED_UNKNOWN" => Some(Self::UnscannedUnknown),
            _ => None,
        }
    }
}

/// Closed active-reference vocabulary; the guard rejects rows outside it.
pub const ALL_ACTIVE_REFERENCE_STATUSES: &[ActiveReferenceStatus] = &[
    ActiveReferenceStatus::ActiveReference,
    ActiveReferenceStatus::NoRepoReferenceLiveUnknown,
    ActiveReferenceStatus::UnscannedUnknown,
];

/// Which denominator one inventory row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    /// Root workspace member (including the `bins/` composition roots).
    WorkspacePackage,
    /// Standalone crate outside root members/exclude (the `#1811`
    /// excluded scope; verbatim `#1811` disposition and owner).
    StandalonePackage,
}

/// Closed component-kind vocabulary; the guard rejects rows outside it.
pub const ALL_COMPONENT_KINDS: &[ComponentKind] = &[
    ComponentKind::WorkspacePackage,
    ComponentKind::StandalonePackage,
];

/// One component/owner/path inventory row.
///
/// Reachable rows carry `disposition: None`: a package reachable from an
/// admitted composition root needs no migration disposition. Unreachable and
/// standalone rows always carry exactly one `I19.3` disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Repository-relative manifest directory, e.g. `crates/smart/eliot-cues`.
    pub path: &'static str,
    /// Cargo package name.
    pub package: &'static str,
    /// Which denominator this row belongs to.
    pub kind: ComponentKind,
    /// Whether a `bins/` root reaches this package through normal/build edges.
    pub bins_reachable: bool,
    /// Owning cell, issue, or coordination fallback.
    pub owner: &'static str,
    /// Migration disposition, or `None` for reachable packages.
    pub disposition: Option<ComponentDisposition>,
    /// Why this row carries its disposition.
    pub rationale: &'static str,
    /// Repository active-reference scan outcome.
    pub active_reference: ActiveReferenceStatus,
    /// Surface classes with at least one reference hit.
    pub hit_classes: &'static [&'static str],
}

/// Component/owner/path inventory: one row per workspace member at the pin,
/// ordered by manifest directory.
pub const INVENTORY: &[InventoryEntry] = &[
    InventoryEntry {
        path: "bins/eliot",
        package: "eliot",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "app",
            "binary",
            "ci",
            "config",
            "docs",
            "integration",
            "manifest",
            "other",
            "plugin",
            "script",
            "skill",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-agent-bridge",
        package: "eliot-agent-bridge",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-doctor",
        package: "eliot-doctor",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-dreamer",
        package: "eliot-dreamer",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-host",
        package: "eliot-host",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-kernel",
        package: "eliot-kernel",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-mod-research",
        package: "eliot-mod-research",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-native-worker",
        package: "eliot-native-worker",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-notify",
        package: "eliot-notify",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-store-surreal",
        package: "eliot-store-surreal",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-testd",
        package: "eliot-testd",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-user-broker",
        package: "eliot-user-broker",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-wasm-host",
        package: "eliot-wasm-host",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliot-watchdog",
        package: "eliot-watchdog",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "bins/eliotd",
        package: "eliotd",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via bins/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/agent/eliot-agent-acp",
        package: "eliot-agent-acp",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "agent plane via bins/eliot-native-worker (#22); provider-neutral execution allocation #361",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Provider-neutral ACP v1 stdio compatibility adapter referenced by the native-worker adapter registry. WRAP behind the admitted native owner; never a parallel agent runtime.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/agent/eliot-agent-api",
        package: "eliot-agent-api",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #18 via crates/agent/eliot-agent-api/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "integration",
            "manifest",
            "other",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/agent/eliot-agent-claude",
        package: "eliot-agent-claude",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/agent/eliot-agent-claude/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/agent/eliot-agent-codex",
        package: "eliot-agent-codex",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/agent area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/agent/eliot-agent-contracts",
        package: "eliot-agent-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/agent area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/agent/eliot-agent-coordinator",
        package: "eliot-agent-coordinator",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #187 via crates/agent/eliot-agent-coordinator/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "ci",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/agent/eliot-agent-opencode",
        package: "eliot-agent-opencode",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/agent area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/agent/eliot-swarm",
        package: "eliot-swarm",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "A-07 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/bridges/eliot-git-bridge",
        package: "eliot-git-bridge",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "crates/bridges/eliot-git-bridge owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: Some(ComponentDisposition::Rework),
        rationale: RATIONALE_PROTOTYPE_REWORK,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest"],
    },
    InventoryEntry {
        path: "crates/bridges/eliot-lsp-bridge",
        package: "eliot-lsp-bridge",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "crates/bridges/eliot-lsp-bridge owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: Some(ComponentDisposition::Unknown),
        rationale: "No rule matched this unreachable package. UNKNOWN (fail-closed): requires owner experiment before any other disposition; no retirement inferred (I19.2).",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest"],
    },
    InventoryEntry {
        path: "crates/eliot-app",
        package: "eliot-app",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189",
        disposition: Some(ComponentDisposition::Retire),
        rationale: "Legacy migration/regression facade. RETIRE only after every unique production consumer migrates to the documented current owner; removal gated on #1189.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "app",
            "binary",
            "ci",
            "config",
            "docs",
            "integration",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/eliot-engine",
        package: "eliot-engine",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189",
        disposition: Some(ComponentDisposition::Retire),
        rationale: "Legacy aggregate engine facade. RETIRE only after consumer migration; gated on #1189.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "ci",
            "config",
            "docs",
            "integration",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/eliot-sim-core",
        package: "eliot-sim-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "go39-1916 (admitted via #1916 root workspace membership as the pure deterministic simulation boundary owner; dependency-minimal pure state-transition crate with no runtime, store, model, or process authority)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest"],
    },
    InventoryEntry {
        path: "crates/eliot-store",
        package: "eliot-store",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "bins/eliotd migration coordination (#1860); extraction owner #19; retirement owner #1189",
        disposition: Some(ComponentDisposition::Retire),
        rationale: "Legacy aggregate store facade. RETIRE only after named Store operations own every reader; gated on #1189.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/eliot-types",
        package: "eliot-types",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/eliot-types area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "app",
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/eliot-windows-ipc",
        package: "eliot-windows-ipc",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/eliot-windows-ipc area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-bootstrap",
        package: "eliot-bootstrap",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #216 via crates/foundation/eliot-bootstrap/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-conformance-contracts",
        package: "eliot-conformance-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #216 via crates/foundation/eliot-conformance-contracts/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-contracts",
        package: "eliot-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #289 via crates/foundation/eliot-contracts/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-evaluation-contracts",
        package: "eliot-evaluation-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/foundation area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script"],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-evidence",
        package: "eliot-evidence",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/foundation area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "config", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-memory-projection-contracts",
        package: "eliot-memory-projection-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "foundation.memory.projection-contracts (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-observation-contracts",
        package: "eliot-observation-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "C0-11 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-protocol",
        package: "eliot-protocol",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/foundation area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "integration",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-receipts",
        package: "eliot-receipts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/foundation area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-rules",
        package: "eliot-rules",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/foundation area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "source"],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-runtime-contracts",
        package: "eliot-runtime-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "C0-04 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-security-contracts",
        package: "eliot-security-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/foundation area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/foundation/eliot-test-support",
        package: "eliot-test-support",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "C0-10 test-support cell (lifecycle_owner C0-10)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: "Test-support fixture plane. KEEP as proof fixtures; never production authority.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "script", "tool"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-authority",
        package: "eliot-authority",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/governor/eliot-budget",
        package: "eliot-budget",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-canonical",
        package: "eliot-canonical",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "ci",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/governor/eliot-change-monitor",
        package: "eliot-change-monitor",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "test"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-config",
        package: "eliot-config",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/governor/eliot-coordination",
        package: "eliot-coordination",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-finish",
        package: "eliot-finish",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "integration",
            "manifest",
            "script",
            "skill",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/governor/eliot-governor",
        package: "eliot-governor",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "integration",
            "manifest",
            "other",
            "plugin",
            "script",
            "skill",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/governor/eliot-integration-coverage",
        package: "eliot-integration-coverage",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-maintenance",
        package: "eliot-maintenance",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "G-19 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "workstream"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-memory-projection-provider",
        package: "eliot-memory-projection-provider",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "governor.memory.projection-provider",
        disposition: Some(ComponentDisposition::Rework),
        rationale: RATIONALE_PROTOTYPE_REWORK,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "workstream"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-module-registry",
        package: "eliot-module-registry",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-observation",
        package: "eliot-observation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #217 via crates/governor/eliot-observation/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "source", "test"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-problem",
        package: "eliot-problem",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["ci", "docs", "manifest", "script", "workstream"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-read",
        package: "eliot-read",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "G-06 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/governor/eliot-session",
        package: "eliot-session",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "integration", "manifest", "workstream"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-skill",
        package: "eliot-skill",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "ci",
            "docs",
            "manifest",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/governor/eliot-task",
        package: "eliot-task",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "integration", "manifest", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/governor/eliot-workscope",
        package: "eliot-workscope",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/governor/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-artifact",
        package: "eliot-artifact",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-build-test-graph",
        package: "eliot-build-test-graph",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-code-cortex",
        package: "eliot-code-cortex",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-code-graph",
        package: "eliot-code-graph",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "tool"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-diagnostic",
        package: "eliot-diagnostic",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-empirical-profile",
        package: "eliot-empirical-profile",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-graph-api",
        package: "eliot-graph-api",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-api",
        package: "eliot-instrument-api",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-cargo",
        package: "eliot-instrument-cargo",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-dotnet",
        package: "eliot-instrument-dotnet",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-nextest",
        package: "eliot-instrument-nextest",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-runner",
        package: "eliot-instrument-runner",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-rustc",
        package: "eliot-instrument-rustc",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-rustfmt",
        package: "eliot-instrument-rustfmt",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-instrument-scip",
        package: "eliot-instrument-scip",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source", "tool"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-observability",
        package: "eliot-observability",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-observability-runtime",
        package: "eliot-observability-runtime",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-process-executor",
        package: "eliot-process-executor",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-product-evaluation",
        package: "eliot-product-evaluation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-r13-harness",
        package: "eliot-r13-harness",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "config", "docs", "manifest", "workstream"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-reports",
        package: "eliot-reports",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "source"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-test-selection",
        package: "eliot-test-selection",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: OWNER_INSTRUMENT_KEEP,
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_INSTRUMENT_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-testd-core",
        package: "eliot-testd-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/instrument/eliot-verifier",
        package: "eliot-verifier",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/instrument/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-host-control-endpoint",
        package: "eliot-host-control-endpoint",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "P-05 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "script"],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-host-service",
        package: "eliot-host-service",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "P-05 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "script",
            "source",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-host-state",
        package: "eliot-host-state",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/kernel/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-installation",
        package: "eliot-installation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "P-08 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-ipc",
        package: "eliot-ipc",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/kernel/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-kernel-core",
        package: "eliot-kernel-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "P-07 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "app",
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-kernel-service",
        package: "eliot-kernel-service",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "P-07 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-ors",
        package: "eliot-ors",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "P-06 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-platform",
        package: "eliot-platform",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/kernel/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "config", "docs", "manifest", "source", "test", "tool",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-platform-windows",
        package: "eliot-platform-windows",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/kernel/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-process",
        package: "eliot-process",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/kernel/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/kernel/eliot-runtime",
        package: "eliot-runtime",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/kernel/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source", "test", "workstream"],
    },
    InventoryEntry {
        path: "crates/meta/eliot-doctor-core",
        package: "eliot-doctor-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/meta/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/meta/eliot-improvement",
        package: "eliot-improvement",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "meta.improvement (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/meta/eliot-learning-activation-assessment",
        package: "eliot-learning-activation-assessment",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "meta.learning.activation_assessment (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "test"],
    },
    InventoryEntry {
        path: "crates/meta/eliot-runtime-status",
        package: "eliot-runtime-status",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/meta/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "tool", "workstream"],
    },
    InventoryEntry {
        path: "crates/meta/eliot-self-quality",
        package: "eliot-self-quality",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "meta.self_quality.diagnosis (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script"],
    },
    InventoryEntry {
        path: "crates/modules/eliot-native-worker-core",
        package: "eliot-native-worker-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "A-13 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/modules/eliot-wasm-runtime",
        package: "eliot-wasm-runtime",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "A-12 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/research/eliot-research-exchange",
        package: "eliot-research-exchange",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #24 via crates/research/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/research/eliot-research-exchange-api",
        package: "eliot-research-exchange-api",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #24 via crates/research/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/research/eliot-researcher",
        package: "eliot-researcher",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #24 via crates/research/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/security/eliot-influence",
        package: "eliot-influence",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/security area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "script", "source", "test"],
    },
    InventoryEntry {
        path: "crates/security/eliot-source-assurance",
        package: "eliot-source-assurance",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/security area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cognitive-quality",
        package: "eliot-cognitive-quality",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.cognitive.quality (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-context",
        package: "eliot-context",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #248 via crates/smart/eliot-context/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-context-admission",
        package: "eliot-context-admission",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.context.admission (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-context-assembly",
        package: "eliot-context-assembly",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.context.assembly (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "ci",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-context-candidates",
        package: "eliot-context-candidates",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.context.candidates (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-context-contracts",
        package: "eliot-context-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.context.contracts (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "ci",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-context-measurement",
        package: "eliot-context-measurement",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.context.measurement (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "ci", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cue-activation",
        package: "eliot-cue-activation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.cue.activation (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cue-binding",
        package: "eliot-cue-binding",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.cue.binding",
        disposition: Some(ComponentDisposition::Rework),
        rationale: RATIONALE_PROTOTYPE_REWORK,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "test"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cue-contracts",
        package: "eliot-cue-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.cue.contracts (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cue-index",
        package: "eliot-cue-index",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.cue.index (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "source", "test"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cue-normalizer",
        package: "eliot-cue-normalizer",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.cue.normalizer",
        disposition: Some(ComponentDisposition::Rework),
        rationale: RATIONALE_PROTOTYPE_REWORK,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "source", "test"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cues",
        package: "eliot-cues",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.cues (component owner TBD); coordinated by bins/eliotd (#1860)",
        disposition: Some(ComponentDisposition::Unknown),
        rationale: "Cue projection/activation donor crate with no module owner record. UNKNOWN: requires owner experiment/disposition; no retirement inferred.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source", "test"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-accessibility",
        package: "eliot-dreamer-accessibility",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.accessibility (admitted via #966 (T8-AS2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-architecture-brief",
        package: "eliot-dreamer-architecture-brief",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.architecture_brief (admitted via #968 (T8-A1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-bundle",
        package: "eliot-dreamer-bundle",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.bundle (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-candidate-validation",
        package: "eliot-dreamer-candidate-validation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.candidate_validation (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-claim-grounding",
        package: "eliot-dreamer-claim-grounding",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.claim_grounding (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-clarification",
        package: "eliot-dreamer-clarification",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.clarification (admitted via #968 (T8-A1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-classification",
        package: "eliot-dreamer-classification",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.classification (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-concept",
        package: "eliot-dreamer-concept",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.concept (admitted via #965 (T8-AS1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-configuration-plan",
        package: "eliot-dreamer-configuration-plan",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.configuration_plan (admitted via #969 (T8-A2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-conflict-analysis",
        package: "eliot-dreamer-conflict-analysis",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.conflict_analysis (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-contracts",
        package: "eliot-dreamer-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.contracts (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-core",
        package: "eliot-dreamer-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.core (component owner TBD); coordinated by bins/eliotd (#1860)",
        disposition: Some(ComponentDisposition::Unknown),
        rationale: "Dreamer core donor crate with no module owner record. UNKNOWN: requires owner experiment/disposition; no retirement inferred.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-curation",
        package: "eliot-dreamer-curation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.curation (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-cycle",
        package: "eliot-dreamer-cycle",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.cycle (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-development-diagnosis",
        package: "eliot-dreamer-development-diagnosis",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.development_diagnosis (admitted via #969 (T8-A2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-episode",
        package: "eliot-dreamer-episode",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.episode (admitted via #965 (T8-AS1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-failure",
        package: "eliot-dreamer-failure",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.failure (admitted via #966 (T8-AS2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-implementation-brief",
        package: "eliot-dreamer-implementation-brief",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.implementation_brief (admitted via #968 (T8-A1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-maintenance-plan",
        package: "eliot-dreamer-maintenance-plan",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.maintenance_plan (admitted via #969 (T8-A2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-memory-repair",
        package: "eliot-dreamer-memory-repair",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.memory_repair (admitted via #966 (T8-AS2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-memory-revision",
        package: "eliot-dreamer-memory-revision",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.memory_revision (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-orchestration-plan",
        package: "eliot-dreamer-orchestration-plan",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.orchestration_plan (admitted via #969 (T8-A2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-orientation",
        package: "eliot-dreamer-orientation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.orientation (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-probe-plan",
        package: "eliot-dreamer-probe-plan",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.probe_plan (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-procedure",
        package: "eliot-dreamer-procedure",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.procedure (admitted via #965 (T8-AS1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-reconsolidation",
        package: "eliot-dreamer-reconsolidation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.reconsolidation (admitted via #966 (T8-AS2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-relation",
        package: "eliot-dreamer-relation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.relation (admitted via #965 (T8-AS1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-research-synthesis",
        package: "eliot-dreamer-research-synthesis",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.research-synthesis (admitted via #995 (A-RESEARCH-SYNTHESIS) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-rival-model",
        package: "eliot-dreamer-rival-model",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.dreamer.rival_model (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-self-query",
        package: "eliot-dreamer-self-query",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.self_query",
        disposition: Some(ComponentDisposition::Rework),
        rationale: RATIONALE_PROTOTYPE_REWORK,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-structure-repair",
        package: "eliot-dreamer-structure-repair",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.dreamer.structure_repair (admitted via #966 (T8-AS2) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-epistemic",
        package: "eliot-epistemic",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.epistemic.position (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-epistemic-context-provider",
        package: "eliot-epistemic-context-provider",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.epistemic.context_provider",
        disposition: Some(ComponentDisposition::Rework),
        rationale: RATIONALE_PROTOTYPE_REWORK,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-epistemic-contracts",
        package: "eliot-epistemic-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.epistemic.contracts (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-experience-projection",
        package: "eliot-experience-projection",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.experience.projection (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-experience-provider",
        package: "eliot-experience-provider",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.experience.provider (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-learning-contracts",
        package: "eliot-learning-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.learning.contracts (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-learning-delta",
        package: "eliot-learning-delta",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.learning.delta (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source", "test"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-learning-overlay",
        package: "eliot-learning-overlay",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "smart.learning.overlay (admitted via #967 (T8-AL1) root workspace membership)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: RATIONALE_ADMITTED_KEEP,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script", "source", "test"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-learning-state-view",
        package: "eliot-learning-state-view",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.learning.state_view (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "test"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-memory-curation",
        package: "eliot-memory-curation",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "crates/smart area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "other", "script"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-memory-curation-contracts",
        package: "eliot-memory-curation-contracts",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.memory.curation_contracts (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other", "script", "source"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-memory-curation-screen",
        package: "eliot-memory-curation-screen",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.memory.curation_screen (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-memory-quality",
        package: "eliot-memory-quality",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.memory.quality (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-reactive-context-plan",
        package: "eliot-reactive-context-plan",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.context.reactive_delivery_plan (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary", "docs", "manifest", "other", "script", "source", "test",
        ],
    },
    InventoryEntry {
        path: "crates/smart/eliot-understanding-assessment",
        package: "eliot-understanding-assessment",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "smart.understanding.assessment (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "other"],
    },
    InventoryEntry {
        path: "crates/storage/eliot-backup",
        package: "eliot-backup",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #10 via crates/storage/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/storage/eliot-blob",
        package: "eliot-blob",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #10 via crates/storage/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/storage/eliot-blob-api",
        package: "eliot-blob-api",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #10 via crates/storage/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "tool",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/storage/eliot-ecxf",
        package: "eliot-ecxf",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #10 via crates/storage/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "manifest", "script", "source", "test", "workstream"],
    },
    InventoryEntry {
        path: "crates/storage/eliot-store-api",
        package: "eliot-store-api",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #10 via crates/storage/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/storage/eliot-store-memory",
        package: "eliot-store-memory",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "storage plane owner #19 (non-runtime reference per #1715)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: "Non-runtime implementation-support reference validating admitted named operations. KEEP as reference only; never a selectable production fallback.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/storage/eliot-store-surreal-adapter",
        package: "eliot-store-surreal-adapter",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #10 via crates/storage/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "test",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/supervision/eliot-watchdog-core",
        package: "eliot-watchdog-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #11 via crates/supervision/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "manifest",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-agent-bridge-core",
        package: "eliot-agent-bridge-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "A-16 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "docs",
            "integration",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-cli",
        package: "eliot-cli",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #7 via crates/surfaces/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "integration",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-controlboard",
        package: "eliot-controlboard",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "A-08 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-mcp",
        package: "eliot-mcp",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #7 via crates/surfaces/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &[
            "binary",
            "config",
            "docs",
            "manifest",
            "other",
            "script",
            "source",
            "workstream",
        ],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-messaging-bridge",
        package: "eliot-messaging-bridge",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #7 via crates/surfaces/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest"],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-notify-core",
        package: "eliot-notify-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #7 via crates/surfaces/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "docs", "manifest", "workstream"],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-skills",
        package: "eliot-skills",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "issue #7 via crates/surfaces/AGENTS.md (nearest instruction owner)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "manifest", "script", "source"],
    },
    InventoryEntry {
        path: "crates/surfaces/eliot-user-broker-core",
        package: "eliot-user-broker-core",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "A-09 (module/package owner record)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["app", "binary", "docs", "manifest", "source", "workstream"],
    },
    InventoryEntry {
        path: "workspace/tools/eliot-live-canary",
        package: "eliot-live-canary",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: true,
        owner: "workspace/tools area owner TBD; coordinated by bins/eliotd (#1860)",
        disposition: None,
        rationale: RATIONALE_REACHABLE,
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["binary", "config", "docs", "manifest", "workstream"],
    },
    InventoryEntry {
        path: "workspace/tools/eliot-runtime-compiler",
        package: "eliot-runtime-compiler",
        kind: ComponentKind::WorkspacePackage,
        bins_reachable: false,
        owner: "workspace tooling owner (developer tool, not production runtime)",
        disposition: Some(ComponentDisposition::Keep),
        rationale: "Developer runtime-compiler tool. KEEP outside the production runtime boundary.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "manifest", "script", "workstream"],
    },
];

/// Excluded scope: one row per standalone package at the pin with the
/// verbatim `#1811` disposition and owner, ordered by manifest directory.
pub const EXCLUDED_SCOPE: &[InventoryEntry] = &[
    InventoryEntry {
        path: "crates/research/eliot-dreamer-source-assurance",
        package: "eliot-dreamer-source-assurance",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "research.source-assurance-role-separation (#692 cell)",
        disposition: Some(ComponentDisposition::Extract),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "script", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-context-compiler-wasm",
        package: "eliot-context-compiler-wasm",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.context.compiler-wasm",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "other", "script", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-cue-activation-wasm",
        package: "eliot-cue-activation-wasm",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.cue.activation-wasm",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "script", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-curation-wasm",
        package: "eliot-dreamer-curation-wasm",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.dreamer.curation-wasm",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "script", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-cycle-wasm",
        package: "eliot-dreamer-cycle-wasm",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.dreamer.cycle-wasm",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-orientation-wasm",
        package: "eliot-dreamer-orientation-wasm",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.dreamer.orientation-wasm",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "other", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-dreamer-research-wasm",
        package: "eliot-dreamer-research-wasm",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.dreamer.research-wasm",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "other", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-memory-applicability",
        package: "eliot-memory-applicability",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.memory.applicability",
        disposition: Some(ComponentDisposition::Rework),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["docs", "other", "source", "workstream"],
    },
    InventoryEntry {
        path: "crates/smart/eliot-memory-curation-screen-wasm",
        package: "eliot-memory-curation-screen-wasm",
        kind: ComponentKind::StandalonePackage,
        bins_reachable: false,
        owner: "smart.memory.curation-screen-wasm",
        disposition: Some(ComponentDisposition::Wrap),
        rationale: "Verbatim #1811 standalone disposition (workstreams/security/standalone-crate-dispositions.toml); confers no workspace/runtime admission.",
        active_reference: ActiveReferenceStatus::ActiveReference,
        hit_classes: &["config", "docs", "workstream"],
    },
];

/// Fail-closed resolution of one reviewer query: a known inventory row, or
/// an unscanned component that stays `UNKNOWN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedComponent<'a> {
    /// The query matched an inventory row by path or package name.
    Known(&'static InventoryEntry),
    /// The query matched nothing, or names live/installed state the scan
    /// never observes; owner, disposition, and active-reference status all
    /// render the fail-closed `UNKNOWN` values below.
    Unscanned(&'a str),
}

impl<'a> ResolvedComponent<'a> {
    /// Owning cell/issue, or the unscanned-surface coordination fallback.
    #[must_use]
    pub fn owner(self) -> &'static str {
        match self {
            Self::Known(entry) => entry.owner,
            Self::Unscanned(_) => UNSCANNED_OWNER,
        }
    }

    /// Migration disposition: the row value for known components (`None`
    /// means reachable, no disposition required), `Unknown` for unscanned.
    #[must_use]
    pub fn disposition(self) -> Option<ComponentDisposition> {
        match self {
            Self::Known(entry) => entry.disposition,
            Self::Unscanned(_) => Some(ComponentDisposition::Unknown),
        }
    }

    /// Why this component carries its disposition.
    #[must_use]
    pub fn rationale(self) -> &'static str {
        match self {
            Self::Known(entry) => entry.rationale,
            Self::Unscanned(_) => UNSCANNED_RATIONALE,
        }
    }

    /// Active-reference status: the row scan for known components,
    /// [`ActiveReferenceStatus::UnscannedUnknown`] for unscanned ones.
    #[must_use]
    pub fn active_reference(self) -> ActiveReferenceStatus {
        match self {
            Self::Known(entry) => entry.active_reference,
            Self::Unscanned(_) => ActiveReferenceStatus::UnscannedUnknown,
        }
    }

    /// Surface classes with reference hits; empty for unscanned components.
    #[must_use]
    pub fn hit_classes(self) -> &'static [&'static str] {
        match self {
            Self::Known(entry) => entry.hit_classes,
            Self::Unscanned(_) => &[],
        }
    }

    /// The queried path for unscanned components, the row path otherwise.
    #[must_use]
    pub fn path(self) -> &'a str {
        match self {
            Self::Known(entry) => entry.path,
            Self::Unscanned(path) => path,
        }
    }

    /// Whether the query matched an inventory row.
    #[must_use]
    pub fn is_known(self) -> bool {
        matches!(self, Self::Known(_))
    }
}

/// Resolve one reviewer query to its inventory row, fail-closed.
///
/// The query matches a manifest directory first, then a package name, across
/// [`INVENTORY`] and [`EXCLUDED_SCOPE`]. Anything else — including installed
/// integrations and live state — resolves to [`ResolvedComponent::Unscanned`],
/// which renders `UNKNOWN` owner, disposition, and active-reference status.
#[must_use]
pub fn resolve(query: &str) -> ResolvedComponent<'_> {
    if let Some(entry) = INVENTORY
        .iter()
        .chain(EXCLUDED_SCOPE.iter())
        .find(|entry| entry.path == query)
    {
        return ResolvedComponent::Known(entry);
    }
    if let Some(entry) = INVENTORY
        .iter()
        .chain(EXCLUDED_SCOPE.iter())
        .find(|entry| entry.package == query)
    {
        return ResolvedComponent::Known(entry);
    }
    ResolvedComponent::Unscanned(query)
}

/// Look up one inventory row by Cargo package name.
#[must_use]
pub fn lookup_by_package(package: &str) -> Option<&'static InventoryEntry> {
    INVENTORY
        .iter()
        .chain(EXCLUDED_SCOPE.iter())
        .find(|entry| entry.package == package)
}

/// One tracked-file surface class from the inventory denominator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceClass {
    /// Surface class (`binary`, `schema`, `skill`, `config`, `ci`, ...).
    pub class: &'static str,
    /// Tracked files in this class at the pin.
    pub file_count: usize,
    /// How a reviewer reaches owner/disposition/impact from this class.
    pub lookup: &'static str,
}

/// Shared lookup note for every surface class.
pub const SURFACE_LOOKUP: &str = "owner/disposition/impact via INVENTORY and EXCLUDED_SCOPE rows matching the surface path or owning binary";

/// Tracked surface denominator at the pin: generated surfaces, schemas,
/// Skills, prompts, configs, CI artifacts, install manifests, and the
/// remaining classes resolve through these rows to their owning rows.
pub const SURFACE_CLASSES: &[SurfaceClass] = &[
    SurfaceClass {
        class: "app",
        file_count: 25,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "binary",
        file_count: 501,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "ci",
        file_count: 11,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "config",
        file_count: 5,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "docs",
        file_count: 1088,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "integration",
        file_count: 46,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "manifest",
        file_count: 182,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "other",
        file_count: 142,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "plugin",
        file_count: 10,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "schema",
        file_count: 86,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "script",
        file_count: 342,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "skill",
        file_count: 23,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "source",
        file_count: 1401,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "test",
        file_count: 558,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "tool",
        file_count: 8,
        lookup: SURFACE_LOOKUP,
    },
    SurfaceClass {
        class: "workstream",
        file_count: 80,
        lookup: SURFACE_LOOKUP,
    },
];

/// One repair impact graph node: a migration fact with an owner, not a
/// support claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactNode {
    /// Stable node id, e.g. `HB1-canonical-finish`.
    pub id: &'static str,
    /// What the node means.
    pub label: &'static str,
}

/// One repair impact graph edge: a blocking/ordering relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactEdge {
    /// Blocking node id.
    pub from: &'static str,
    /// Blocked node id.
    pub to: &'static str,
    /// Why the ordering holds.
    pub relation: &'static str,
}

/// Repair impact graph nodes (`I19.5` order plus the issue work items).
pub const IMPACT_NODES: &[ImpactNode] = &[
    ImpactNode {
        id: "HB1-canonical-finish",
        label: "Hard-boundary repair: strict canonical finish only (I19.5 B)",
    },
    ImpactNode {
        id: "HB2-lossless-payload",
        label: "Hard-boundary repair: lossless generic payload authority (I19.5 B)",
    },
    ImpactNode {
        id: "HB3-one-writer",
        label: "Hard-boundary repair: canonical control records and one online writer composition (I19.5 B)",
    },
    ImpactNode {
        id: "LEGACY-RETIREMENT",
        label: "Legacy-crate retirement: eliot-app/engine/store/types aggregate facades (#1189)",
    },
    ImpactNode {
        id: "KERNEL-STORE-V1-DECODE-REMOVAL",
        label: "Kernel-Store v1 decode removal (sole compat decoder crates/kernel/eliot-kernel-service/src/store_exchange.rs; eliotd v1-compat projection)",
    },
    ImpactNode {
        id: "RELEASE-SURFACE",
        label: "Release surface: docs/release/WINDOWS_X64_RELEASE.md + scripts/build-eliot-windows-x64-release.ps1 gate",
    },
    ImpactNode {
        id: "WINDOWS-PRODUCT-PROOF",
        label: "Windows Product Proof: installed D0/D1 pulse with ProductPulseReceipt (#11)",
    },
    ImpactNode {
        id: "STORE-PATH",
        label: "Store dependency path: admitted named Store operations (owner #19)",
    },
    ImpactNode {
        id: "GOVERNOR-PATH",
        label: "Governor dependency path: eliotd semantic ownership (owner #18)",
    },
];

/// Repair impact graph edges (blocking/ordering relations).
pub const IMPACT_EDGES: &[ImpactEdge] = &[
    ImpactEdge {
        from: "HB1-canonical-finish",
        to: "GOVERNOR-PATH",
        relation: "finish semantics must land in eliotd before facade extraction",
    },
    ImpactEdge {
        from: "HB2-lossless-payload",
        to: "GOVERNOR-PATH",
        relation: "payload authority must precede agent-path cutover",
    },
    ImpactEdge {
        from: "HB3-one-writer",
        to: "STORE-PATH",
        relation: "one-writer composition must precede Store bridge migration",
    },
    ImpactEdge {
        from: "GOVERNOR-PATH",
        to: "LEGACY-RETIREMENT",
        relation: "facade consumers migrate to eliotd before RETIRE",
    },
    ImpactEdge {
        from: "STORE-PATH",
        to: "LEGACY-RETIREMENT",
        relation: "Store readers migrate to named operations before RETIRE",
    },
    ImpactEdge {
        from: "STORE-PATH",
        to: "KERNEL-STORE-V1-DECODE-REMOVAL",
        relation: "v1 compat decoders removable only after v2-only production",
    },
    ImpactEdge {
        from: "GOVERNOR-PATH",
        to: "KERNEL-STORE-V1-DECODE-REMOVAL",
        relation: "eliotd v1-compat projection removable only after v2-only resolution",
    },
    ImpactEdge {
        from: "LEGACY-RETIREMENT",
        to: "RELEASE-SURFACE",
        relation: "release gate must reject retired crates as inputs",
    },
    ImpactEdge {
        from: "KERNEL-STORE-V1-DECODE-REMOVAL",
        to: "RELEASE-SURFACE",
        relation: "release bundle must carry no legacy decode path",
    },
    ImpactEdge {
        from: "RELEASE-SURFACE",
        to: "WINDOWS-PRODUCT-PROOF",
        relation: "installed proof runs from the gated release bundle",
    },
    ImpactEdge {
        from: "HB1-canonical-finish",
        to: "WINDOWS-PRODUCT-PROOF",
        relation: "pulse asserts strict finish",
    },
    ImpactEdge {
        from: "HB2-lossless-payload",
        to: "WINDOWS-PRODUCT-PROOF",
        relation: "pulse asserts lossless payload round-trip",
    },
    ImpactEdge {
        from: "HB3-one-writer",
        to: "WINDOWS-PRODUCT-PROOF",
        relation: "pulse asserts single-writer composition",
    },
];

/// Look up one impact node by id.
#[must_use]
pub fn impact_node(id: &str) -> Option<&'static ImpactNode> {
    IMPACT_NODES.iter().find(|node| node.id == id)
}

/// Edges leaving one impact node.
pub fn impact_edges_from(id: &str) -> impl Iterator<Item = &'static ImpactEdge> + '_ {
    IMPACT_EDGES.iter().filter(move |edge| edge.from == id)
}

/// Edges entering one impact node.
pub fn impact_edges_to(id: &str) -> impl Iterator<Item = &'static ImpactEdge> + '_ {
    IMPACT_EDGES.iter().filter(move |edge| edge.to == id)
}

/// Impact-graph entry node for one inventory row, if the ledger names one.
///
/// `RETIRE` rows of the four aggregate facades enter at `LEGACY-RETIREMENT`,
/// which is blocked by `GOVERNOR-PATH` plus `STORE-PATH` consumer migration
/// and blocks `RELEASE-SURFACE` (`docs/migration/1860-impact-graph.md`: "How
/// to read impact for a row"). All other rows walk the graph from their own
/// plane via [`impact_edges_from`] and [`impact_edges_to`].
#[must_use]
pub fn impact_entry_node(entry: &InventoryEntry) -> Option<&'static str> {
    if entry.disposition != Some(ComponentDisposition::Retire) {
        return None;
    }
    match entry.path {
        "crates/eliot-app"
        | "crates/eliot-engine"
        | "crates/eliot-store"
        | "crates/eliot-types" => Some("LEGACY-RETIREMENT"),
        _ => None,
    }
}

/// First Product Proof plan binding (`I19.2` output; source of record:
/// `docs/migration/1860-product-proof-plan.md`). The plan authorizes exactly
/// one bounded installed pulse and proves nothing until run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductProofPlan {
    /// Plan document path.
    pub plan_path: &'static str,
    /// Coordination owner.
    pub coordinator: &'static str,
    /// Named owner binaries on the installed route under proof.
    pub owner_binaries: &'static [&'static str],
    /// Independent observation and containment binaries.
    pub observers: &'static [&'static str],
    /// Exact entrypoint of the pulse.
    pub entrypoint: &'static str,
    /// Single-identity rule: one pulse binds exactly one of each.
    pub required_identities: &'static str,
    /// Expected installed-route receipt.
    pub expected_receipt: &'static str,
    /// Failure preservation rule.
    pub failure_preservation_rule: &'static str,
    /// Rollback and recovery boundary.
    pub rollback_boundary: &'static str,
    /// Concrete installed-route receipt the plan names.
    pub installed_route_receipt: &'static str,
}

/// The first Product Proof plan: installed route `eliot` CLI -> `eliotd` ->
/// Kernel -> one named Store operation, then direct receipt readback plus one
/// governed read-model observation.
pub const PRODUCT_PROOF_PLAN: ProductProofPlan = ProductProofPlan {
    plan_path: "docs/migration/1860-product-proof-plan.md",
    coordinator: "bins/eliotd migration coordination, executed under issue #11",
    owner_binaries: &["eliot", "eliotd", "eliot-kernel", "eliot-store-surreal"],
    observers: &["eliot-watchdog", "eliot-host"],
    entrypoint: "One admitted capture (or equivalent user input) submitted through the real user surface - the eliot CLI against the installed generation - producing one exact canonical write through eliotd, the Kernel, and one named Store operation, then one direct receipt readback and one governed read-model observation.",
    required_identities: "One pulse binds exactly one of each: source head, normative pair, Cargo lock/toolchain, built artifact digests, installation/lineage/generation, machine/environment class, principal/session, AuthorityEpoch, StateFence, Store namespace/schema/heads, capability registry (#13), scenario set, verifier set, deadlines, cleanup obligations.",
    expected_receipt: "One immutable ProductPulseReceipt: per-stage start/end identities, raw evidence handles, omissions, conflicts, unknowns, cleanup state, verifier receipts, proof ceilings, and a complete invalidation set; aggregate status is the weakest required stage.",
    failure_preservation_rule: "Restart or replace eliotd and the Store bridge/server at predeclared safe points and prove exact rehydration with unchanged canonical readback; reconcile one controlled unknown-commit path by OperationId before retry with no duplicate write; Watchdog observes the interval; failing fixtures and revisions are preserved and every non-passed stage stays visible.",
    rollback_boundary: "Per I19.11 rollback is a generation switch while formats stay compatible, else isolated-backup restore or forward-repair; after the I19.16 no-return boundary, rollback is forward repair/migration. The I19.10 preconditions apply.",
    installed_route_receipt: "ProductPulseReceipt",
};

/// Fail-closed consistency check over the inventory tables: exact pinned
/// counts, one row per path and package, complete fields, closed
/// vocabularies, reachable rows without dispositions, dispositioned rows for
/// every unreachable and standalone package, dangle-free impact edges with
/// no isolated node, and a complete Product Proof plan binding. Any violation
/// fails so a governed refresh must re-project the tables.
pub fn migration_inventory_guard() -> Result<(), String> {
    if INVENTORY_PIN_COMMIT.len() != 40
        || !INVENTORY_PIN_COMMIT
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("migration inventory pin commit is not a commit id".to_owned());
    }
    if INVENTORY.len() != WORKSPACE_MEMBERS {
        return Err(format!(
            "migration inventory names {} packages, expected {WORKSPACE_MEMBERS}; refresh the projection",
            INVENTORY.len()
        ));
    }
    if EXCLUDED_SCOPE.len() != STANDALONE_PACKAGES {
        return Err(format!(
            "migration inventory names {} standalone packages, expected {STANDALONE_PACKAGES}; refresh the projection",
            EXCLUDED_SCOPE.len()
        ));
    }
    guard_workspace_rows()?;
    guard_excluded_rows()?;
    guard_impact_graph()?;
    guard_surface_classes()?;
    guard_product_proof_plan()?;
    Ok(())
}

/// Check the workspace rows: one row per path and package, reachable rows
/// without dispositions, every unreachable row dispositioned, and the exact
/// pinned reachability counts.
fn guard_workspace_rows() -> Result<(), String> {
    let mut reachable = 0;
    let mut unreachable = 0;
    for (index, row) in INVENTORY.iter().enumerate() {
        check_row(row, index, ComponentKind::WorkspacePackage)?;
        if row.bins_reachable {
            if row.disposition.is_some() {
                return Err(format!(
                    "migration inventory row {} is reachable but carries a disposition",
                    row.path
                ));
            }
            reachable += 1;
        } else {
            if row.disposition.is_none() {
                return Err(format!(
                    "migration inventory row {} is unreachable but carries no disposition",
                    row.path
                ));
            }
            unreachable += 1;
        }
        for prior in &INVENTORY[..index] {
            if prior.path == row.path {
                return Err(format!(
                    "migration inventory names {} twice; exactly one row per path",
                    row.path
                ));
            }
            if prior.package == row.package {
                return Err(format!(
                    "migration inventory names package {} twice; exactly one row per package",
                    row.package
                ));
            }
        }
    }
    if reachable != BINS_REACHABLE || unreachable != BINS_UNREACHABLE {
        return Err(format!(
            "migration inventory reachability {reachable}/{unreachable} does not match the pinned {BINS_REACHABLE}/{BINS_UNREACHABLE}; refresh the projection"
        ));
    }
    if unreachable < AUDIT_UNREACHABLE_PREMISE {
        return Err(format!(
            "migration inventory dispositions {unreachable} unreachable packages, below the audit premise {AUDIT_UNREACHABLE_PREMISE}"
        ));
    }
    Ok(())
}

/// Check the excluded-scope rows: one row per path, no reachable marking,
/// and a disposition on every row.
fn guard_excluded_rows() -> Result<(), String> {
    for (index, row) in EXCLUDED_SCOPE.iter().enumerate() {
        check_row(row, index, ComponentKind::StandalonePackage)?;
        if row.bins_reachable {
            return Err(format!(
                "migration inventory standalone row {} is marked reachable",
                row.path
            ));
        }
        if row.disposition.is_none() {
            return Err(format!(
                "migration inventory standalone row {} carries no disposition",
                row.path
            ));
        }
        for prior in &EXCLUDED_SCOPE[..index] {
            if prior.path == row.path {
                return Err(format!(
                    "migration inventory names standalone {} twice; exactly one row per path",
                    row.path
                ));
            }
        }
    }
    Ok(())
}

/// Check the impact graph: complete nodes, unique ids, no isolated node,
/// and dangle-free edges with non-empty relations.
fn guard_impact_graph() -> Result<(), String> {
    for node in IMPACT_NODES {
        if node.id.is_empty() || node.label.is_empty() {
            return Err("migration impact graph has a node with an empty field".to_owned());
        }
    }
    for (index, node) in IMPACT_NODES.iter().enumerate() {
        for prior in &IMPACT_NODES[..index] {
            if prior.id == node.id {
                return Err(format!(
                    "migration impact graph names node {} twice",
                    node.id
                ));
            }
        }
        let incident = IMPACT_EDGES
            .iter()
            .filter(|edge| edge.from == node.id || edge.to == node.id)
            .count();
        if incident == 0 {
            return Err(format!(
                "migration impact graph node {} is isolated",
                node.id
            ));
        }
    }
    for edge in IMPACT_EDGES {
        if edge.relation.is_empty() {
            return Err(format!(
                "migration impact graph edge {}->{} has an empty relation",
                edge.from, edge.to
            ));
        }
        if impact_node(edge.from).is_none() || impact_node(edge.to).is_none() {
            return Err(format!(
                "migration impact graph edge {}->{} dangles",
                edge.from, edge.to
            ));
        }
    }
    Ok(())
}

/// Check the surface classes: complete rows with unique classes.
fn guard_surface_classes() -> Result<(), String> {
    for (index, surface) in SURFACE_CLASSES.iter().enumerate() {
        if surface.class.is_empty() || surface.lookup.is_empty() || surface.file_count == 0 {
            return Err(format!(
                "migration inventory surface class row {index} is incomplete"
            ));
        }
        for prior in &SURFACE_CLASSES[..index] {
            if prior.class == surface.class {
                return Err(format!(
                    "migration inventory names surface class {} twice",
                    surface.class
                ));
            }
        }
    }
    Ok(())
}

/// Check the Product Proof plan binding: complete fields and a concrete
/// installed-route receipt.
fn guard_product_proof_plan() -> Result<(), String> {
    let plan = &PRODUCT_PROOF_PLAN;
    if plan.plan_path.is_empty()
        || plan.coordinator.is_empty()
        || plan.owner_binaries.is_empty()
        || plan.observers.is_empty()
        || plan.entrypoint.is_empty()
        || plan.required_identities.is_empty()
        || plan.expected_receipt.is_empty()
        || plan.failure_preservation_rule.is_empty()
        || plan.rollback_boundary.is_empty()
        || plan.installed_route_receipt.is_empty()
    {
        return Err("migration inventory Product Proof plan binding is incomplete".to_owned());
    }
    if plan.installed_route_receipt != "ProductPulseReceipt" {
        return Err(
            "migration inventory Product Proof plan names no concrete installed-route receipt"
                .to_owned(),
        );
    }
    Ok(())
}

/// Check one inventory row: expected kind, complete fields, closed
/// vocabularies, and a status consistent with its reference hits.
fn check_row(row: &InventoryEntry, index: usize, kind: ComponentKind) -> Result<(), String> {
    if row.kind != kind {
        return Err(format!(
            "migration inventory row {} has the wrong component kind",
            row.path
        ));
    }
    if row.path.is_empty()
        || row.package.is_empty()
        || row.owner.is_empty()
        || row.rationale.is_empty()
    {
        return Err(format!(
            "migration inventory row {index} has an empty field"
        ));
    }
    if let Some(disposition) = row.disposition
        && !ALL_COMPONENT_DISPOSITIONS.contains(&disposition)
    {
        return Err(format!(
            "migration inventory row {} carries a disposition outside the closed vocabulary",
            row.path
        ));
    }
    if !ALL_ACTIVE_REFERENCE_STATUSES.contains(&row.active_reference) {
        return Err(format!(
            "migration inventory row {} carries an active-reference status outside the closed vocabulary",
            row.path
        ));
    }
    if !ALL_COMPONENT_KINDS.contains(&row.kind) {
        return Err(format!(
            "migration inventory row {} carries a component kind outside the closed vocabulary",
            row.path
        ));
    }
    let hits = !row.hit_classes.is_empty();
    let active = row.active_reference == ActiveReferenceStatus::ActiveReference;
    if hits != active {
        return Err(format!(
            "migration inventory row {} carries status {} with inconsistent reference hits",
            row.path,
            row.active_reference.as_str()
        ));
    }
    Ok(())
}
