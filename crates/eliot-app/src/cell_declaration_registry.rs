//! Executable readback of the `eliotd` capability-cell declaration projection
//! (issue #18 required work 1, through the #13 contract).
//!
//! The canonical source of the daemon capability cells is
//! `bins/eliotd/Cargo.toml::[package.metadata.eliot]` (`functional_cell_refs`
//! plus exactly one `functional_cell_state_owners` row per cell), and the
//! migration-readable projection lives in
//! `workstreams/core-daemons/capability-cell-registry.contract.toml` as
//! `[[declared_functional_cell]]` rows. Both files are baked at compile time
//! with `include_str!`, so this guard reads the real manifests, never a
//! hand-written copy of them: changing either real file is what makes the
//! guard answer `Err`.
//!
//! What this enforces, and what it does not: exactly one mutable-state owner
//! per declared cell, distinct owners across cells, one-to-one agreement
//! between the manifest source and the contract projection, and the honest
//! proof ceiling — while only a declaration projection exists, the contract
//! must keep declaring the executable-registry residual instead of silently
//! claiming a generated `CapabilityCellRegistry` (audit 5848256288, audit
//! 5848557601 item 1). Proof entrypoints, contract digests, runtime
//! generations and Product Pulse binding remain the #13 executable-registry
//! work; this guard keeps the declaration layer truthful until that lands.

/// Baked canonical cell source: `[package.metadata.eliot]` of the production
/// Governor daemon composition root.
const ELIOTD_MANIFEST: &str = include_str!("../../../bins/eliotd/Cargo.toml");

/// Baked declaration projection of that source.
const CELL_CONTRACT: &str =
    include_str!("../../../workstreams/core-daemons/capability-cell-registry.contract.toml");

/// Contract rows must point back at exactly this source, never duplicate it.
const CONTRACT_DECLARED_BY: &str =
    "bins/eliotd/Cargo.toml::package.metadata.eliot.functional_cell_refs";

/// While only a declaration projection exists, the contract must keep saying
/// so. Lifting any of these markers without the executable registry behind
/// them is an overclaim, and this guard refuses it.
const REQUIRED_SUPPORT_MARKER: &str = "EXECUTABLE_REGISTRY_MISSING";
const REQUIRED_STATUS_MARKER: &str = "PENDING";
const REQUIRED_PROOF_CEILING: &str = "CAPABILITY_CELL_REGISTRY_SOURCE_EDGE_CANDIDATE";

/// Missing-input diagnostic for a baked declaration field.
fn missing(what: impl AsRef<str>) -> String {
    format!("baked declaration input is missing {}", what.as_ref())
}

/// Fail when the baked `eliotd` cell declaration and its contract projection
/// disagree, when a cell has zero or two mutable-state owners, or when the
/// contract stops declaring its executable-registry residual.
pub fn cell_declaration_guard() -> Result<(), String> {
    let manifest: toml::Value = toml::from_str(ELIOTD_MANIFEST)
        .map_err(|error| format!("baked bins/eliotd/Cargo.toml does not parse: {error}"))?;
    let contract: toml::Value = toml::from_str(CELL_CONTRACT)
        .map_err(|error| format!("baked cell contract does not parse: {error}"))?;

    let eliot = manifest
        .get("package")
        .and_then(|package| package.get("metadata"))
        .and_then(|metadata| metadata.get("eliot"))
        .ok_or_else(|| missing("[package.metadata.eliot] in bins/eliotd/Cargo.toml"))?;

    let refs = eliot
        .get("functional_cell_refs")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            "baked eliotd declaration carries no functional_cell_refs array".to_owned()
        })?;
    if refs.is_empty() {
        return Err("baked eliotd declaration names no capability cell".to_owned());
    }
    let mut cells: Vec<&str> = Vec::new();
    for cell in refs {
        let cell = cell.as_str().ok_or_else(|| {
            "baked eliotd functional_cell_refs carries a non-string cell".to_owned()
        })?;
        if cells.contains(&cell) {
            return Err(format!(
                "baked eliotd declaration names capability cell {cell} twice"
            ));
        }
        cells.push(cell);
    }

    let owner_rows = eliot
        .get("functional_cell_state_owners")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            "baked eliotd declaration carries no functional_cell_state_owners array".to_owned()
        })?;
    let mut owners: Vec<(&str, &str)> = Vec::new();
    for row in owner_rows {
        let cell = row
            .get("cell")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| "baked eliotd state-owner row names no cell".to_owned())?;
        let owner = row
            .get("owner")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| missing(format!("owner for cell {cell}")))?;
        if !cells.contains(&cell) {
            return Err(format!(
                "baked eliotd state-owner row names cell {cell}, which functional_cell_refs does not declare"
            ));
        }
        if owners.iter().any(|(known, _)| *known == cell) {
            return Err(format!(
                "capability cell {cell} carries two mutable-state owners; exactly one owner per state is required"
            ));
        }
        owners.push((cell, owner));
    }
    for cell in &cells {
        if !owners.iter().any(|(known, _)| known == cell) {
            return Err(format!(
                "capability cell {cell} has no mutable-state owner; a cell with an undeclared state owner is a registry defect"
            ));
        }
    }
    let mut seen_owners: Vec<&str> = Vec::new();
    for (cell, owner) in &owners {
        if seen_owners.contains(owner) {
            return Err(format!(
                "mutable-state owner {owner} (cell {cell}) owns a second cell state; one owner per state means no shared owner"
            ));
        }
        seen_owners.push(*owner);
    }

    let declared = contract
        .get("declared_functional_cell")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "baked cell contract carries no declared_functional_cell rows".to_owned())?;
    let mut projected: Vec<(&str, &str, &str)> = Vec::new();
    for row in declared {
        let cell = row
            .get("cell")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| "baked cell contract row names no cell".to_owned())?;
        let owner = row
            .get("mutable_state_owner")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| missing(format!("mutable_state_owner for cell {cell}")))?;
        let declared_by = row
            .get("declared_by")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| missing(format!("declared_by source for cell {cell}")))?;
        if declared_by != CONTRACT_DECLARED_BY {
            return Err(format!(
                "baked cell contract row for cell {cell} points at {declared_by} instead of the canonical manifest source"
            ));
        }
        if projected.iter().any(|(known, _, _)| *known == cell) {
            return Err(format!(
                "baked cell contract projects capability cell {cell} twice"
            ));
        }
        projected.push((cell, owner, declared_by));
    }
    for cell in &cells {
        let Some((_, owner, _)) = projected.iter().find(|(known, _, _)| known == cell) else {
            return Err(format!(
                "manifest capability cell {cell} has no contract projection row; the projection fell behind its source"
            ));
        };
        let manifest_owner = owners
            .iter()
            .find(|(known, _)| known == cell)
            .map(|(_, owner)| *owner)
            .unwrap_or_default();
        if *owner != manifest_owner {
            return Err(format!(
                "contract projection for cell {cell} names mutable-state owner {owner} but the manifest names {manifest_owner}"
            ));
        }
    }
    for (cell, _, _) in &projected {
        if !cells.contains(cell) {
            return Err(format!(
                "contract projects capability cell {cell}, which the manifest source does not declare"
            ));
        }
    }

    let support = contract
        .get("implementation_support")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| "baked cell contract carries no implementation_support marker".to_owned())?;
    if !support.contains(REQUIRED_SUPPORT_MARKER) {
        return Err(format!(
            "cell contract claims implementation_support {support} without the executable-registry residual; only a declaration projection exists"
        ));
    }
    let status = contract
        .get("status")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| "baked cell contract carries no status marker".to_owned())?;
    if !status.contains(REQUIRED_STATUS_MARKER) {
        return Err(format!(
            "cell contract claims status {status} while the executable registry is still pending"
        ));
    }
    let ceiling = contract
        .get("proof_ceiling")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| "baked cell contract carries no proof_ceiling".to_owned())?;
    if ceiling != REQUIRED_PROOF_CEILING {
        return Err(format!(
            "cell contract claims proof ceiling {ceiling}; raising it requires the executable registry, not this declaration projection"
        ));
    }
    Ok(())
}
