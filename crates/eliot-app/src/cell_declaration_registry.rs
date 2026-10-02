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

    let cells = manifest_cells(eliot)?;
    let owners = manifest_owners(eliot, &cells)?;
    check_contract_mirror(&contract, &cells, &owners)?;
    check_residual_markers(&contract)?;
    Ok(())
}

/// Reads the declared capability cells: non-empty, all strings, no duplicates.
fn manifest_cells(eliot: &toml::Value) -> Result<Vec<String>, String> {
    let refs = eliot
        .get("functional_cell_refs")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            "baked eliotd declaration carries no functional_cell_refs array".to_owned()
        })?;
    if refs.is_empty() {
        return Err("baked eliotd declaration names no capability cell".to_owned());
    }
    let mut cells: Vec<String> = Vec::new();
    for cell in refs {
        let cell = cell.as_str().ok_or_else(|| {
            "baked eliotd functional_cell_refs carries a non-string cell".to_owned()
        })?;
        if cells.iter().any(|known| known == cell) {
            return Err(format!(
                "baked eliotd declaration names capability cell {cell} twice"
            ));
        }
        cells.push(cell.to_owned());
    }
    Ok(cells)
}

/// Reads the mutable-state owners: exactly one owner per declared cell,
/// every row names a declared cell, no shared owner across cells.
fn manifest_owners(eliot: &toml::Value, cells: &[String]) -> Result<Vec<(String, String)>, String> {
    let owner_rows = eliot
        .get("functional_cell_state_owners")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            "baked eliotd declaration carries no functional_cell_state_owners array".to_owned()
        })?;
    let mut owners: Vec<(String, String)> = Vec::new();
    for row in owner_rows {
        let cell = row
            .get("cell")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| "baked eliotd state-owner row names no cell".to_owned())?;
        let owner = row
            .get("owner")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| missing(format!("owner for cell {cell}")))?;
        if !cells.iter().any(|known| known == cell) {
            return Err(format!(
                "baked eliotd state-owner row names cell {cell}, which functional_cell_refs does not declare"
            ));
        }
        if owners.iter().any(|(known, _)| known == cell) {
            return Err(format!(
                "capability cell {cell} carries two mutable-state owners; exactly one owner per state is required"
            ));
        }
        owners.push((cell.to_owned(), owner.to_owned()));
    }
    for cell in cells {
        if !owners.iter().any(|(known, _)| known == cell) {
            return Err(format!(
                "capability cell {cell} has no mutable-state owner; a cell with an undeclared state owner is a registry defect"
            ));
        }
    }
    let mut seen_owners: Vec<&str> = Vec::new();
    for (cell, owner) in &owners {
        if seen_owners.contains(&owner.as_str()) {
            return Err(format!(
                "mutable-state owner {owner} (cell {cell}) owns a second cell state; one owner per state means no shared owner"
            ));
        }
        seen_owners.push(owner);
    }
    Ok(owners)
}

/// Checks the contract projection against the manifest source in both
/// directions: every manifest cell has exactly one projection row naming the
/// same owner, every projection row names a manifest cell, and every row
/// points back at the canonical source instead of duplicating it.
fn check_contract_mirror(
    contract: &toml::Value,
    cells: &[String],
    owners: &[(String, String)],
) -> Result<(), String> {
    let declared = contract
        .get("declared_functional_cell")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "baked cell contract carries no declared_functional_cell rows".to_owned())?;
    let mut projected: Vec<(String, String)> = Vec::new();
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
        if projected.iter().any(|(known, _)| known == cell) {
            return Err(format!(
                "baked cell contract projects capability cell {cell} twice"
            ));
        }
        projected.push((cell.to_owned(), owner.to_owned()));
    }
    for cell in cells {
        let Some((_, owner)) = projected.iter().find(|(known, _)| known == cell) else {
            return Err(format!(
                "manifest capability cell {cell} has no contract projection row; the projection fell behind its source"
            ));
        };
        let manifest_owner = owners
            .iter()
            .find(|(known, _)| known == cell)
            .map(|(_, owner)| owner.as_str())
            .unwrap_or_default();
        if owner != manifest_owner {
            return Err(format!(
                "contract projection for cell {cell} names mutable-state owner {owner} but the manifest names {manifest_owner}"
            ));
        }
    }
    for (cell, _) in &projected {
        if !cells.contains(cell) {
            return Err(format!(
                "contract projects capability cell {cell}, which the manifest source does not declare"
            ));
        }
    }
    Ok(())
}

/// Refuses a contract that stops declaring its executable-registry residual:
/// the support, status, and proof-ceiling markers must keep saying that only
/// a declaration projection exists.
fn check_residual_markers(contract: &toml::Value) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::{
        CELL_CONTRACT, CONTRACT_DECLARED_BY, ELIOTD_MANIFEST, cell_declaration_guard,
        check_contract_mirror, check_residual_markers, manifest_cells, manifest_owners,
    };

    /// The real baked pair the production guard reads.
    const REAL_MANIFEST: &str = ELIOTD_MANIFEST;
    const REAL_CONTRACT: &str = CELL_CONTRACT;

    /// The real declaration block, parsed the way the guard parses it.
    fn real_eliot_metadata() -> toml::Value {
        let manifest: toml::Value = toml::from_str(REAL_MANIFEST)
            .unwrap_or_else(|error| panic!("the real eliotd manifest must parse: {error}"));
        manifest
            .get("package")
            .and_then(|package| package.get("metadata"))
            .and_then(|metadata| metadata.get("eliot"))
            .cloned()
            .unwrap_or_else(|| panic!("the real eliotd manifest carries [package.metadata.eliot]"))
    }

    /// The real contract projection, parsed the way the guard parses it.
    fn real_contract() -> toml::Value {
        toml::from_str(REAL_CONTRACT)
            .unwrap_or_else(|error| panic!("the real cell contract must parse: {error}"))
    }

    /// Replace the first occurrence of `from` in REAL baked text with `to`.
    ///
    /// `cell_declaration_guard` reads compile-time `include_str!` bytes with
    /// no arguments, so an arm is driven by mutating that exact text once and
    /// handing the result to the production stage the guard calls. `from`
    /// must occur in the real file: a drifting anchor panics loudly instead
    /// of quietly passing a hand-written fixture no real file ever produced.
    fn replace_once(text: &str, from: &str, to: &str) -> String {
        let Some(at) = text.find(from) else {
            panic!("mutation anchor is absent from the baked text: {from}");
        };
        let mut mutated = String::with_capacity(text.len() + to.len());
        mutated.push_str(&text[..at]);
        mutated.push_str(to);
        mutated.push_str(&text[at + from.len()..]);
        mutated
    }

    /// Parse one mutation of the real manifest and run the real cell reader.
    fn cells_of_mutated_manifest(from: &str, to: &str) -> Result<Vec<String>, String> {
        let mutated: toml::Value = toml::from_str(&replace_once(REAL_MANIFEST, from, to))
            .unwrap_or_else(|error| panic!("the mutated manifest must still parse: {error}"));
        let eliot = mutated
            .get("package")
            .and_then(|package| package.get("metadata"))
            .and_then(|metadata| metadata.get("eliot"))
            .cloned()
            .unwrap_or_else(|| panic!("the mutated manifest must still declare the cells"));
        manifest_cells(&eliot)
    }

    /// Parse one mutation of the real manifest and run the real owner reader.
    fn owners_of_mutated_manifest(from: &str, to: &str) -> Result<Vec<(String, String)>, String> {
        let mutated: toml::Value = toml::from_str(&replace_once(REAL_MANIFEST, from, to))
            .unwrap_or_else(|error| panic!("the mutated manifest must still parse: {error}"));
        let eliot = mutated
            .get("package")
            .and_then(|package| package.get("metadata"))
            .and_then(|metadata| metadata.get("eliot"))
            .cloned()
            .unwrap_or_else(|| panic!("the mutated manifest must still declare the cells"));
        let cells = manifest_cells(&eliot)?;
        manifest_owners(&eliot, &cells)
    }

    /// The real declared cells and their real owners, as the guard reads them.
    fn real_declaration() -> (Vec<String>, Vec<(String, String)>) {
        let eliot = real_eliot_metadata();
        let cells = manifest_cells(&eliot)
            .unwrap_or_else(|reason| panic!("the real declaration must name its cells: {reason}"));
        let owners = manifest_owners(&eliot, &cells).unwrap_or_else(|reason| {
            panic!("the real declaration must name one owner per cell: {reason}")
        });
        (cells, owners)
    }

    /// Run the real contract-mirror stage over one mutation of the real contract.
    fn mirror_of_mutated_contract(from: &str, to: &str) -> Result<(), String> {
        let mutated: toml::Value = toml::from_str(&replace_once(REAL_CONTRACT, from, to))
            .unwrap_or_else(|error| panic!("the mutated contract must still parse: {error}"));
        let (cells, owners) = real_declaration();
        check_contract_mirror(&mutated, &cells, &owners)
    }

    /// Run the real residual-marker stage over one mutation of the real contract.
    fn markers_of_mutated_contract(from: &str, to: &str) -> Result<(), String> {
        let mutated: toml::Value = toml::from_str(&replace_once(REAL_CONTRACT, from, to))
            .unwrap_or_else(|error| panic!("the mutated contract must still parse: {error}"));
        check_residual_markers(&mutated)
    }

    #[test]
    fn claiming_a_generated_executable_registry_is_refused() {
        // Arm: the real contract's `implementation_support` drops the
        // executable-registry residual and claims a generated registry, which
        // the contract's own `[confirmed_gap]` contradicts. Status and ceiling
        // are untouched, so only the support-marker check can catch this
        // overclaim; it must refuse while #13's registry is still absent.
        let result = markers_of_mutated_contract(
            "implementation_support = \"ROUTING_METADATA_PRESENT_DAEMON_CELLS_DECLARED_EXECUTABLE_REGISTRY_MISSING\"\n",
            "implementation_support = \"ROUTING_METADATA_PRESENT_EXECUTABLE_REGISTRY_GENERATED\"\n",
        );

        assert_eq!(
            result,
            Err("cell contract claims implementation_support ROUTING_METADATA_PRESENT_EXECUTABLE_REGISTRY_GENERATED without the executable-registry residual; only a declaration projection exists".to_owned()),
            "claiming a generated executable registry must be refused"
        );
    }

    #[test]
    fn raising_the_proof_ceiling_without_the_registry_is_refused() {
        // Arm: the real contract's `proof_ceiling` is raised to a generated
        // registry ceiling while the executable `CapabilityCellRegistry` is
        // still absent (#13 scope). Support and status markers are untouched
        // and still carry their residual, so only the exact-ceiling comparison
        // can refuse the overclaim; this test pins that the ceiling must not be
        // raised by editing the contract alone.
        let result = markers_of_mutated_contract(
            "proof_ceiling = \"CAPABILITY_CELL_REGISTRY_SOURCE_EDGE_CANDIDATE\"\n",
            "proof_ceiling = \"CAPABILITY_CELL_REGISTRY_GENERATED\"\n",
        );

        assert_eq!(
            result,
            Err("cell contract claims proof ceiling CAPABILITY_CELL_REGISTRY_GENERATED; raising it requires the executable registry, not this declaration projection".to_owned()),
            "the ceiling must not be raisable without the executable registry"
        );
    }

    #[test]
    fn a_projection_naming_another_owner_than_the_manifest_is_refused() {
        // Arm: the real projected row for `governor.daemon.skill-catalogue`
        // keeps its cell and its provenance, but names a different
        // mutable-state owner than the real manifest row. Both directions of
        // the mirror still find exactly one row per cell, so only the owner
        // comparison can catch a second owner being claimed, and it must
        // report both the projected and the manifest owner.
        let result = mirror_of_mutated_contract(
            "mutable_state_owner = \"eliot_skill::SkillCatalogue\"\n",
            "mutable_state_owner = \"eliot_skill::RenamedSkillCatalogue\"\n",
        );

        assert_eq!(
            result,
            Err("contract projection for cell governor.daemon.skill-catalogue names mutable-state owner eliot_skill::RenamedSkillCatalogue but the manifest names eliot_skill::SkillCatalogue".to_owned()),
            "a projection claiming another owner must be refused, naming both owners"
        );
    }

    #[test]
    fn a_projection_pointing_elsewhere_than_the_source_is_refused() {
        // Arm (I2.23 forbids a second handwritten owner list): the real
        // projected row for `governor.daemon.composition` keeps the right cell
        // and the right owner, but its `declared_by` is repointed at the facade
        // file instead of the canonical manifest source. Cell set and owners
        // still agree, so only the provenance check can catch a projection
        // that re-declares ownership locally.
        let result = mirror_of_mutated_contract(
            "declared_by = \"bins/eliotd/Cargo.toml::package.metadata.eliot.functional_cell_refs\"\n",
            "declared_by = \"crates/eliot-app/src/cell_declaration_registry.rs\"\n",
        );

        assert_eq!(
            result,
            Err("baked cell contract row for cell governor.daemon.composition points at crates/eliot-app/src/cell_declaration_registry.rs instead of the canonical manifest source".to_owned()),
            "a projection that declares its own source must be refused by name"
        );
    }

    #[test]
    fn a_contract_row_for_an_undeclared_cell_is_refused() {
        // Arm: the real generated contract block projects a ninth cell the
        // real manifest never declares. Every manifest cell is still projected
        // with its own owner, so the forward pass succeeds; only the reverse
        // pass can catch a projection with no declaration behind it.
        let invented = "governor.daemon.fabricated";
        let extra = format!(
            "[[declared_functional_cell]]\ncell = \"{invented}\"\ndeclared_by = \
             \"{CONTRACT_DECLARED_BY}\"\nmutable_state_owner = \
             \"eliotd::FabricatedMutableStateOwner\"\n"
        );
        let result = mirror_of_mutated_contract(
            "# END GENERATED declared_functional_cell",
            &format!("{extra}# END GENERATED declared_functional_cell"),
        );

        assert_eq!(
            result,
            Err(format!(
                "contract projects capability cell {invented}, which the manifest source does not declare"
            )),
            "a projected cell with no manifest declaration must be refused"
        );
    }

    #[test]
    fn a_declared_cell_with_no_owner_row_is_refused() {
        // Arm (I2.23: a cell with an undeclared state owner is a registry
        // defect): the real `governor.daemon.learning-closure` ref stays
        // declared but its owner row is removed. Refs and owner rows no longer
        // describe the same set, yet the eliotd guard reads that as a plain
        // length mismatch; this guard must instead name the specific cell that
        // has no owner, because that is the defect an operator has to fix.
        let result = owners_of_mutated_manifest(
            "  { cell = \"governor.daemon.learning-closure\", state = \"learning-closure\", owner = \"eliot_governor::LearningClosureService\" },\n",
            "",
        );

        assert_eq!(
            result,
            Err("capability cell governor.daemon.learning-closure has no mutable-state owner; a cell with an undeclared state owner is a registry defect".to_owned()),
            "a declared cell with no owner row must be named as a registry defect"
        );
    }

    #[test]
    fn one_owner_claiming_two_cells_is_refused() {
        // Arm: the real `governor.daemon.skill-catalogue` row is pointed at the
        // composition owner. Each cell still carries exactly one owner row and
        // every row still names a declared cell, so both the duplicate-cell and
        // the undeclared-cell rules pass; only the no-shared-owner rule can
        // catch one symbol owning two mutable states, and it must refuse.
        let row = "  { cell = \"governor.daemon.skill-catalogue\", state = \"skill-catalogue\", owner = \"eliot_skill::SkillCatalogue\" },\n";
        let result = owners_of_mutated_manifest(
            row,
            "  { cell = \"governor.daemon.skill-catalogue\", state = \"skill-catalogue\", owner = \"eliotd::DaemonComposition\" },\n",
        );

        assert_eq!(
            result,
            Err("mutable-state owner eliotd::DaemonComposition (cell governor.daemon.skill-catalogue) owns a second cell state; one owner per state means no shared owner".to_owned()),
            "one owner across two cells must be refused, naming the owner and cell"
        );
    }

    #[test]
    fn one_cell_with_two_mutable_state_owners_is_refused() {
        // Arm (the audit 5848256288 P2 shape): the real declaration gives
        // `governor.daemon.composition` a second mutable-state owner row. The
        // ref list is untouched, so the cell is still declared exactly once
        // and nothing is malformed; only the "exactly one owner per mutable
        // state" rule can catch a second owner, and it must refuse rather than
        // accept the row and keep going.
        let first = "  { cell = \"governor.daemon.composition\", state = \"daemon-composition\", owner = \"eliotd::DaemonComposition\" },\n";
        let result = owners_of_mutated_manifest(
            first,
            &format!(
                "{first}  {{ cell = \"governor.daemon.composition\", state = \
                 \"daemon-composition-contender\", owner = \"eliotd::SecondComposition\" }},\n"
            ),
        );

        assert_eq!(
            result,
            Err("capability cell governor.daemon.composition carries two mutable-state owners; exactly one owner per state is required".to_owned()),
            "a second owner row for one cell must be refused by name"
        );
    }

    #[test]
    fn real_generated_declarations_satisfy_the_facade_guard() {
        // The positive case is the shipped one: the real eliotd declaration
        // and its real contract projection agree, one owner per declared cell
        // with no owner shared, and the contract still declares the
        // executable-registry residual instead of claiming #13's registry.
        assert_eq!(
            cell_declaration_guard(),
            Ok(()),
            "the committed declaration/contract pair must satisfy the facade guard"
        );

        let (cells, owners) = real_declaration();
        assert_eq!(
            cells.len(),
            8,
            "the real eliotd declaration names its eight daemon cells"
        );
        assert_eq!(
            owners.len(),
            cells.len(),
            "every declared cell carries exactly one mutable-state owner row"
        );

        // Every projected row points back at the canonical source instead of
        // duplicating it, and each names the owner's manifest row.
        let projected = real_contract()
            .get("declared_functional_cell")
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| panic!("the real contract carries its projection rows"))
            .iter()
            .map(|row| {
                let cell = row.get("cell").and_then(toml::Value::as_str);
                let owner = row.get("mutable_state_owner").and_then(toml::Value::as_str);
                let declared_by = row.get("declared_by").and_then(toml::Value::as_str);
                (cell, owner, declared_by)
            })
            .collect::<Vec<(Option<&str>, Option<&str>, Option<&str>)>>();
        assert_eq!(
            projected.len(),
            cells.len(),
            "the contract projects one row per declared cell"
        );
        for (cell, owner, declared_by) in projected {
            assert_eq!(
                declared_by,
                Some(CONTRACT_DECLARED_BY),
                "every projected row must point back at the canonical manifest source"
            );
            let cell = cell.unwrap_or_else(|| panic!("every projected row names a cell"));
            let manifest_owner = owners
                .iter()
                .find(|(known, _)| known == cell)
                .map(|(_, owner)| owner.as_str());
            assert_eq!(
                owner, manifest_owner,
                "the projected owner must be the owner's manifest row for {cell}"
            );
        }
    }
}
