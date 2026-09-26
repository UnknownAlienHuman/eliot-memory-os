//! Current-consumer / disposition inventory for the `eliot-app` facade.
//!
//! Status (`crates/eliot-app/AGENTS.md`): `crates/eliot-app` and its
//! `eliot-governor` binary are a legacy migration and regression facade. They
//! are not the current production Governor composition root and are not root
//! `default-members`.
//!
//! Work-item mapping:
//!
//! - W-Work8 (inventory current consumers): [`current_consumer_inventory`].
//! - W-Work9 (disposition per consumer): [`Disposition`],
//!   [`ConsumerEntry`].
//! - W-Work10 (prevent new ownership in the facade):
//!   [`contains_forbidden_owner_symbol`], [`assert_no_new_ownership`].
//! - Acceptance A8 (machine-readable inventory): [`current_consumer_inventory`].
//! - Acceptance A10 (deny-gate on new ownership): [`assert_no_new_ownership`].
//! - W-13-guard (bind through #13, keep package out of root default-members):
//!   [`default_members_guard`].
//!
//! This module inventories current *consumers* (callers/paths that still
//! terminate at the facade), never command names as features. The existence of
//! an `eliot-governor` command group, test, or old caller does not create
//! current ownership (`crates/eliot-app/AGENTS.md`).
//!
//! Docs receipts: route
//! sha256:3b48a99600fedffe66803194fe07fb9652a3c36fe3eb774a59645bfb28529506,
//! read sha256:760ad380ba3da04f1ef82ef6aadd71da1b12c82bc743c2045f16851b86e3ef81.

/// Disposition of one current consumer of the legacy facade.
///
/// Serves W-Work9: every inventoried consumer carries an explicit terminal
/// state — extraction to its declared current owner, a temporary fixture with
/// proof/expiry/removal condition, or deletion as obsolete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Behavior moves to the declared current owner; the facade keeps no copy.
    ExtractToCurrentOwner {
        /// Declared current owner (crate/binary path), e.g.
        /// `"bins/eliot + crates/surfaces/eliot-cli"`.
        owner: &'static str,
    },
    /// Compatibility fixture kept only while the named consumer needs it.
    TemporaryFixture {
        /// Named current consumer.
        consumer: &'static str,
        /// Proof the path still terminates here (script/test/manifest path).
        proof: &'static str,
        /// Expiry milestone (issue or retirement handle), e.g. `"retirement-1189"`.
        expiry: &'static str,
        /// Condition whose satisfaction removes the fixture.
        removal_condition: &'static str,
    },
    /// No current consumer; remove as obsolete.
    ///
    /// Terminal arm of W-Work9, exercised when a removal unit lands (not yet
    /// constructed by the inventory below, which records only live consumers).
    #[allow(dead_code)]
    DeleteAsObsolete,
}

/// One current consumer of the legacy facade plus its disposition.
///
/// Serves W-Work8/W-Work9/A8: machine-readable `(consumer, path, disposition)`
/// triple. `path` is the repository path that proves the consumer still
/// terminates at the facade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerEntry {
    /// Named current consumer.
    pub consumer: &'static str,
    /// Repository path proving the consumer terminates at the facade.
    pub path: &'static str,
    /// Terminal disposition for this consumer.
    pub disposition: Disposition,
}

/// Machine-readable inventory of the current consumers of the facade.
///
/// Serves W-Work8 / Acceptance A8. Lists ONLY current consumers — command
/// names are not inventoried as features.
pub fn current_consumer_inventory() -> Vec<ConsumerEntry> {
    vec![
        ConsumerEntry {
            consumer: "codex plugin runtime (release bundle)",
            path: "scripts/build-eliot-windows-x64-release.ps1",
            disposition: Disposition::TemporaryFixture {
                consumer: "codex plugin runtime (release bundle)",
                proof: "scripts/build-eliot-windows-x64-release.ps1 bundle assertions",
                expiry: "retirement-1189",
                removal_condition: "plugin manifest resolves to declared current owner binary",
            },
        },
        ConsumerEntry {
            consumer: "claude desktop/connector staging",
            path: "scripts/build-claude-desktop-extension.ps1",
            disposition: Disposition::TemporaryFixture {
                consumer: "claude desktop/connector staging",
                proof: "scripts/build-claude-desktop-extension.ps1, scripts/test-claude-connector.ps1",
                expiry: "retirement-1189",
                removal_condition: "connector manifest resolves to declared current owner binary",
            },
        },
        ConsumerEntry {
            consumer: "opencode/claude hook manifests",
            path: "plugin/eliot-governor/hooks/hooks.json",
            disposition: Disposition::TemporaryFixture {
                consumer: "opencode/claude hook manifests",
                proof: "plugin/eliot-governor/hooks/hooks.json, integrations/*",
                expiry: "retirement-1189",
                removal_condition: "hook manifests resolve to declared current owner binary",
            },
        },
        ConsumerEntry {
            consumer: "operator credential docs path",
            path: "docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md",
            disposition: Disposition::ExtractToCurrentOwner {
                owner: "bins/eliot + crates/surfaces/eliot-cli",
            },
        },
        ConsumerEntry {
            consumer: "historical regression fixtures (legacy scope)",
            path: "crates/eliot-app/tests",
            disposition: Disposition::TemporaryFixture {
                consumer: "historical regression fixtures (legacy scope)",
                proof: "crates/eliot-app/tests",
                expiry: "issues #7/#8/#9 closure",
                removal_condition: "fixture removed or re-homed with explicit legacy scope",
            },
        },
        ConsumerEntry {
            consumer: "justfile skill-sync line",
            path: "Justfile",
            disposition: Disposition::ExtractToCurrentOwner {
                owner: "bins/eliot",
            },
        },
    ]
}

/// Forbidden owner domains for the facade (`crates/eliot-app/AGENTS.md`).
///
/// Any symbol in one of these domains added to the facade would create a
/// second authority owner, which the facade AGENTS.md forbids. Callers supply
/// the crate's symbol inventory; CI extends the supplied list.
pub const FORBIDDEN_OWNER_SYMBOLS: &[&str] = &[
    "task_owner",
    "workscope_owner",
    "memory_owner",
    "policy_owner",
    "finish_owner",
    "scheduling_owner",
    "module_catalog_owner",
    "store_authority",
    "recovery_owner",
    "provider_owner",
    "agent_runtime_owner",
];

/// Deny-gate predicate: true when any supplied symbol names a forbidden owner
/// domain.
///
/// Serves W-Work10 / Acceptance A10. Pure function over a caller-supplied
/// symbol list; it performs no I/O and inspects no crate internals itself.
pub fn contains_forbidden_owner_symbol(symbols: &[&str]) -> bool {
    symbols.iter().any(|symbol| {
        FORBIDDEN_OWNER_SYMBOLS
            .iter()
            .any(|forbidden| symbol.contains(forbidden))
    })
}

/// Deny-gate: reject any new ownership added to the facade.
///
/// Serves W-Work10 / Acceptance A10. Returns `Err` when any entry of the
/// caller-supplied symbol inventory falls in a forbidden owner domain; `Ok`
/// otherwise. Documented contract: CI extends the supplied list, so widening
/// coverage strengthens the gate without touching this module.
pub fn assert_no_new_ownership(symbols: &[&str]) -> Result<(), &'static str> {
    if contains_forbidden_owner_symbol(symbols) {
        Err("new ownership forbidden in the eliot-app legacy facade")
    } else {
        Ok(())
    }
}

/// Guard keeping the package out of root `default-members`.
///
/// Serves W-13-guard. The caller wires the actual membership fact:
/// `Err` when `is_default_member` is true, `Ok` otherwise.
pub fn default_members_guard(is_default_member: bool) -> Result<(), &'static str> {
    if is_default_member {
        Err("eliot-app must not be a root default-member")
    } else {
        Ok(())
    }
}
