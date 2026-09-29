//! Executable capability-cell registry readback and enforcement (#18,
//! AUD-5848557601-1; I2.23).
//!
//! The canonical cell declaration lives in
//! `bins/eliotd/Cargo.toml::[package.metadata.eliot]`; the #13 contract
//! repeats it as the GENERATED `[[declared_functional_cell]]` block. The
//! scripts gate keeps the two files in agreement; this module compiles both
//! texts into the daemon and rechecks their real content at composition
//! time, so a binary built from a diverged tree refuses to start instead of
//! running on a stale registry. Values are compared cell by cell (cell id,
//! state name, owner symbol); bare existence or list length proves nothing.
//!
//! [`enforce_declared_cells`] runs from
//! [`DaemonComposition::start`](super::DaemonComposition::start), whose
//! production caller is `daemon_runtime` composition.

use thiserror::Error;

/// Manifest declaration baked at compile time.
const MANIFEST_TEXT: &str = include_str!("../../Cargo.toml");
/// #13 contract text baked at compile time.
const CONTRACT_TEXT: &str =
    include_str!("../../../workstreams/core-daemons/capability-cell-registry.contract.toml");
/// Manifest section carrying the declaration.
const MANIFEST_SECTION: &str = "[package.metadata.eliot]";
/// Contract markers bounding the generated block.
const CONTRACT_BEGIN: &str = "BEGIN GENERATED declared_functional_cell";
const CONTRACT_END: &str = "END GENERATED declared_functional_cell";

/// One declared capability cell with its single mutable-state owner.
///
/// Mirrors one `functional_cell_state_owners` row of the manifest, in
/// manifest order. [`enforce_declared_cells`] proves the mirror against the
/// baked manifest text, so this table can never silently diverge from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeclaredCell {
    /// Cell id from `functional_cell_refs`.
    pub cell: &'static str,
    /// Mutable-state name from `functional_cell_state_owners`.
    pub state: &'static str,
    /// Sole mutable-state owner symbol.
    pub owner: &'static str,
}

/// Compiled registry: the daemon cells in manifest order.
pub const DECLARED_CELLS: &[DeclaredCell] = &[
    DeclaredCell {
        cell: "governor.daemon.composition",
        state: "daemon-composition",
        owner: "eliotd::DaemonComposition",
    },
    DeclaredCell {
        cell: "governor.daemon.startup-binding",
        state: "startup-capability-bindings",
        owner: "eliotd::StartupCapabilityBindings",
    },
    DeclaredCell {
        cell: "governor.daemon.poll-contour",
        state: "daemon-poll-contour",
        owner: "eliotd::daemon_runtime::run",
    },
    DeclaredCell {
        cell: "governor.daemon.kernel-transport",
        state: "daemon-kernel-transport",
        owner: "eliotd::DaemonKernelClient",
    },
    DeclaredCell {
        cell: "governor.daemon.operator-replay",
        state: "operator-replay",
        owner: "eliotd::controlboard_adapters::SharedOperatorReplay",
    },
    DeclaredCell {
        cell: "governor.daemon.skill-catalogue",
        state: "skill-catalogue",
        owner: "eliot_skill::SkillCatalogue",
    },
    DeclaredCell {
        cell: "governor.daemon.capability-admission",
        state: "capability-admission-view",
        owner: "eliotd::capability_evidence_wiring::GovernorCapabilityAdmission",
    },
    DeclaredCell {
        cell: "governor.daemon.learning-closure",
        state: "learning-closure",
        owner: "eliot_governor::LearningClosureService",
    },
];

/// Typed registry refusal: values name the exact divergent content.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CellRegistryError {
    /// The baked manifest declaration does not parse fail-closed.
    #[error("capability-cell manifest is malformed: {detail}")]
    MalformedManifest {
        /// What the manifest scanner rejected.
        detail: String,
    },
    /// The baked contract block does not parse fail-closed.
    #[error("capability-cell contract block is malformed: {detail}")]
    MalformedContract {
        /// What the contract scanner rejected.
        detail: String,
    },
    /// `functional_cell_refs` and `functional_cell_state_owners` disagree.
    #[error("capability-cell refs/owners disagree: {detail}")]
    RefsOwnersMismatch {
        /// The exact disagreement.
        detail: String,
    },
    /// A manifest cell has no generated contract row.
    #[error("capability cell has no contract row: {cell}")]
    MissingContractCell {
        /// Manifest cell id without a contract row.
        cell: String,
    },
    /// A contract row names a cell the manifest does not declare.
    #[error("contract row names an undeclared cell: {cell}")]
    UndeclaredContractCell {
        /// Contract cell id absent from the manifest.
        cell: String,
    },
    /// Manifest and contract name different owners for one cell.
    #[error(
        "capability-cell owner mismatch for {cell}: manifest {manifest_owner}, contract {contract_owner}"
    )]
    ContractOwnerMismatch {
        /// Cell id whose owners disagree.
        cell: String,
        /// Owner named by the manifest.
        manifest_owner: String,
        /// Owner named by the contract row.
        contract_owner: String,
    },
    /// The compiled table disagrees with the baked manifest.
    #[error(
        "compiled registry drift for {cell}: table {compiled_owner}, manifest {manifest_owner}"
    )]
    CompiledTableDrift {
        /// Cell id whose records disagree.
        cell: String,
        /// Owner carried by [`DECLARED_CELLS`].
        compiled_owner: String,
        /// Owner parsed from the manifest.
        manifest_owner: String,
    },
    /// One owner symbol is claimed by two cells (I2.23 second-owner defect).
    #[error("owner {owner} is claimed by {first_cell} and {second_cell}")]
    DuplicateOwner {
        /// Owner symbol claimed twice.
        owner: String,
        /// First cell claiming it.
        first_cell: String,
        /// Second cell claiming it.
        second_cell: String,
    },
}

/// One manifest owner row: cell, state name, owner symbol.
struct ManifestCell {
    cell: String,
    state: String,
    owner: String,
}

/// One contract row: cell id and mutable-state owner.
struct ContractCell {
    cell: String,
    owner: String,
}

/// Recheck the baked declaration against the baked contract and the
/// compiled table, failing closed on any content divergence.
///
/// # Errors
///
/// Returns [`CellRegistryError`] naming the exact divergent content when
/// the manifest and contract disagree, the compiled table drifts from the
/// manifest, or one owner is claimed twice.
pub fn enforce_declared_cells() -> Result<(), CellRegistryError> {
    let manifest = parse_manifest(MANIFEST_TEXT)?;
    let contract = parse_contract(CONTRACT_TEXT)?;
    enforce_manifest_contract_agreement(&manifest, &contract)?;
    enforce_compiled_table(&manifest)?;
    Ok(())
}

/// Prove the manifest and contract name the same cells with the same owners.
fn enforce_manifest_contract_agreement(
    manifest: &[ManifestCell],
    contract: &[ContractCell],
) -> Result<(), CellRegistryError> {
    for declared in manifest {
        match contract.iter().find(|row| row.cell == declared.cell) {
            None => {
                return Err(CellRegistryError::MissingContractCell {
                    cell: declared.cell.clone(),
                });
            }
            Some(row) if row.owner != declared.owner => {
                return Err(CellRegistryError::ContractOwnerMismatch {
                    cell: declared.cell.clone(),
                    manifest_owner: declared.owner.clone(),
                    contract_owner: row.owner.clone(),
                });
            }
            Some(_) => {}
        }
    }
    for row in contract {
        if !manifest.iter().any(|declared| declared.cell == row.cell) {
            return Err(CellRegistryError::UndeclaredContractCell {
                cell: row.cell.clone(),
            });
        }
    }
    Ok(())
}

/// Prove the compiled table repeats the manifest cell for cell.
fn enforce_compiled_table(manifest: &[ManifestCell]) -> Result<(), CellRegistryError> {
    for declared in manifest {
        if !compiled_matches(declared) {
            return Err(compiled_drift(declared));
        }
    }
    if DECLARED_CELLS.len() != manifest.len() {
        let extra = DECLARED_CELLS.iter().find(|compiled| {
            !manifest
                .iter()
                .any(|declared| declared.cell == compiled.cell)
        });
        let cell = extra.map_or("<unknown>", |compiled| compiled.cell);
        return Err(CellRegistryError::CompiledTableDrift {
            cell: cell.to_owned(),
            compiled_owner: extra.map_or("", |compiled| compiled.owner).to_owned(),
            manifest_owner: "<undeclared>".to_owned(),
        });
    }
    Ok(())
}

/// Whether the compiled table carries this exact manifest record.
fn compiled_matches(declared: &ManifestCell) -> bool {
    DECLARED_CELLS.iter().any(|compiled| {
        compiled.cell == declared.cell
            && compiled.state == declared.state
            && compiled.owner == declared.owner
    })
}

/// Drift error for a manifest cell the compiled table misrepresents.
fn compiled_drift(declared: &ManifestCell) -> CellRegistryError {
    let compiled_owner = DECLARED_CELLS
        .iter()
        .find(|compiled| compiled.cell == declared.cell)
        .map_or("<missing>", |compiled| compiled.owner);
    CellRegistryError::CompiledTableDrift {
        cell: declared.cell.clone(),
        compiled_owner: compiled_owner.to_owned(),
        manifest_owner: declared.owner.clone(),
    }
}

/// Parse the manifest refs and owner rows with cross-checks.
fn parse_manifest(text: &str) -> Result<Vec<ManifestCell>, CellRegistryError> {
    let section = manifest_section(text)?;
    let refs = string_array(&section, "functional_cell_refs")?;
    let owners = owner_rows(&section)?;
    if refs.len() != owners.len() {
        return Err(CellRegistryError::RefsOwnersMismatch {
            detail: format!(
                "refs carry {} cells, owners carry {}",
                refs.len(),
                owners.len()
            ),
        });
    }
    for reference in &refs {
        if !owners.iter().any(|row| &row.cell == reference) {
            return Err(CellRegistryError::RefsOwnersMismatch {
                detail: format!("ref {reference} has no owner row"),
            });
        }
    }
    for row in &owners {
        if !refs.iter().any(|reference| *reference == row.cell) {
            return Err(CellRegistryError::RefsOwnersMismatch {
                detail: format!("owner row {} has no ref", row.cell),
            });
        }
    }
    require_distinct_owners(
        &owners
            .iter()
            .map(|row| (row.cell.clone(), row.owner.clone()))
            .collect::<Vec<(String, String)>>(),
    )?;
    Ok(owners)
}

/// Lines of the manifest declaration section.
fn manifest_section(text: &str) -> Result<Vec<&str>, CellRegistryError> {
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() == MANIFEST_SECTION {
            let mut section = Vec::new();
            for line in lines.by_ref() {
                if line.trim_start().starts_with('[') {
                    break;
                }
                section.push(line);
            }
            return Ok(section);
        }
    }
    Err(CellRegistryError::MalformedManifest {
        detail: format!("{MANIFEST_SECTION} section is missing"),
    })
}

/// Quoted string entries of one manifest array key.
fn string_array(section: &[&str], key: &str) -> Result<Vec<String>, CellRegistryError> {
    let malformed = |detail: &str| CellRegistryError::MalformedManifest {
        detail: format!("{key}: {detail}"),
    };
    let body = array_body(section, key)?;
    let mut values = Vec::new();
    for line in body {
        let entry = strip_comment(line);
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let entry = entry.strip_suffix(',').unwrap_or(entry).trim();
        if !(entry.starts_with('"') && entry.ends_with('"') && entry.len() >= 2) {
            return Err(malformed("entry is not one quoted string"));
        }
        let value = entry[1..entry.len() - 1].trim().to_owned();
        if value.is_empty() {
            return Err(malformed("entry is empty"));
        }
        if values.iter().any(|seen| *seen == value) {
            return Err(malformed(&format!("duplicate entry {value}")));
        }
        values.push(value);
    }
    if values.is_empty() {
        return Err(malformed("array is empty"));
    }
    Ok(values)
}

/// Inline-table rows of `functional_cell_state_owners`.
fn owner_rows(section: &[&str]) -> Result<Vec<ManifestCell>, CellRegistryError> {
    let malformed = |detail: &str| CellRegistryError::MalformedManifest {
        detail: format!("functional_cell_state_owners: {detail}"),
    };
    let mut rows = Vec::new();
    for line in array_body(section, "functional_cell_state_owners")? {
        let entry = strip_comment(line).trim().to_owned();
        if entry.is_empty() {
            continue;
        }
        let entry = entry.strip_suffix(',').unwrap_or(&entry).trim();
        let table = entry
            .strip_prefix('{')
            .and_then(|inner| inner.strip_suffix('}'))
            .ok_or_else(|| malformed("row is not one inline table"))?;
        let (mut cell, mut state, mut owner) = (None, None, None);
        for pair in split_pairs(table) {
            let (key, value) =
                quoted_pair(&pair).ok_or_else(|| malformed("pair is not key = \"value\""))?;
            match key {
                "cell" if cell.is_none() => cell = Some(value),
                "state" if state.is_none() => state = Some(value),
                "owner" if owner.is_none() => owner = Some(value),
                _ => return Err(malformed("row carries an unknown or repeated key")),
            }
        }
        let (Some(cell), Some(state), Some(owner)) = (cell, state, owner) else {
            return Err(malformed("row misses cell, state, or owner"));
        };
        if rows.iter().any(|row: &ManifestCell| row.cell == cell) {
            return Err(malformed(&format!("duplicate cell {cell}")));
        }
        rows.push(ManifestCell { cell, state, owner });
    }
    if rows.is_empty() {
        return Err(malformed("no owner rows"));
    }
    Ok(rows)
}

/// Raw lines between `key = [` and its closing bracket.
fn array_body<'a>(section: &[&'a str], key: &str) -> Result<Vec<&'a str>, CellRegistryError> {
    let malformed = || CellRegistryError::MalformedManifest {
        detail: format!("{key}: array is missing or unterminated"),
    };
    let mut lines = section.iter();
    let open = lines
        .find(|line| {
            let head = strip_comment(line).trim();
            head == format!("{key} = [") || head == format!("{key}=[")
        })
        .ok_or_else(malformed)?;
    let mut body = Vec::new();
    if open.contains(']') {
        return Err(malformed());
    }
    for line in lines {
        let entry = strip_comment(line);
        match entry.find(']') {
            None => body.push(*line),
            Some(end) => {
                let head = entry[..end].trim();
                if !head.is_empty() {
                    body.push(*line);
                }
                if !strip_comment(&entry[end + 1..]).trim().is_empty() {
                    return Err(malformed());
                }
                return Ok(body);
            }
        }
    }
    Err(malformed())
}

/// Text before a `#` comment marker outside quotes.
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, byte) in line.char_indices() {
        if byte == '"' {
            quoted = !quoted;
        } else if byte == '#' && !quoted {
            return &line[..index];
        }
    }
    line
}

/// Quote-aware comma split of one inline table body.
fn split_pairs(table: &str) -> Vec<String> {
    let mut pairs = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, byte) in table.char_indices() {
        if byte == '"' {
            quoted = !quoted;
        } else if byte == ',' && !quoted {
            pairs.push(table[start..index].trim().to_owned());
            start = index + 1;
        }
    }
    pairs.push(table[start..].trim().to_owned());
    pairs
}

/// One `key = "value"` pair with a non-empty value.
fn quoted_pair(pair: &str) -> Option<(String, String)> {
    let (key, value) = pair.split_once('=')?;
    let value = value.trim();
    if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
        return None;
    }
    let value = value[1..value.len() - 1].trim().to_owned();
    if value.is_empty() || value.contains('"') {
        return None;
    }
    Some((key.trim().to_owned(), value))
}

/// Parse the generated contract rows between the markers.
fn parse_contract(text: &str) -> Result<Vec<ContractCell>, CellRegistryError> {
    let malformed = |detail: &str| CellRegistryError::MalformedContract {
        detail: detail.to_owned(),
    };
    let begin = text
        .lines()
        .position(|line| line.contains(CONTRACT_BEGIN))
        .ok_or_else(|| malformed("generated block begin marker is missing"))?;
    let end = text
        .lines()
        .position(|line| line.contains(CONTRACT_END))
        .ok_or_else(|| malformed("generated block end marker is missing"))?;
    if end <= begin {
        return Err(malformed("generated block markers are out of order"));
    }
    let mut rows = Vec::new();
    let mut cell: Option<String> = None;
    let mut owner: Option<String> = None;
    let flush = |cell: &mut Option<String>,
                 owner: &mut Option<String>,
                 rows: &mut Vec<ContractCell>|
     -> Result<(), CellRegistryError> {
        if cell.is_none() && owner.is_none() {
            return Ok(());
        }
        let (Some(cell), Some(owner)) = (cell.take(), owner.take()) else {
            return Err(malformed("row misses cell or mutable_state_owner"));
        };
        if rows.iter().any(|row: &ContractCell| row.cell == cell) {
            return Err(malformed(&format!("duplicate cell {cell}")));
        }
        rows.push(ContractCell { cell, owner });
        Ok(())
    };
    for line in text.lines().skip(begin + 1).take(end - begin - 1) {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        if entry == "[[declared_functional_cell]]" {
            flush(&mut cell, &mut owner, &mut rows)?;
            continue;
        }
        if let Some(value) = keyed_value(entry, "cell") {
            if cell.is_some() {
                return Err(malformed("row repeats cell"));
            }
            cell = Some(value);
            continue;
        }
        if let Some(value) = keyed_value(entry, "mutable_state_owner") {
            if owner.is_some() {
                return Err(malformed("row repeats mutable_state_owner"));
            }
            owner = Some(value);
            continue;
        }
    }
    flush(&mut cell, &mut owner, &mut rows)?;
    if rows.is_empty() {
        return Err(malformed("no declared cells"));
    }
    require_distinct_owners(
        &rows
            .iter()
            .map(|row| (row.cell.clone(), row.owner.clone()))
            .collect::<Vec<(String, String)>>(),
    )?;
    Ok(rows)
}

/// Value of one top-level `key = "value"` contract line.
fn keyed_value(line: &str, key: &str) -> Option<String> {
    let (name, value) = line.split_once('=')?;
    if name.trim() != key {
        return None;
    }
    quoted_pair(line).map(|(_, value)| value)
}

/// Reject one owner symbol claimed by two cells.
fn require_distinct_owners(cells: &[(String, String)]) -> Result<(), CellRegistryError> {
    for (index, (cell, owner)) in cells.iter().enumerate() {
        for (other_cell, other_owner) in &cells[..index] {
            if other_owner == owner {
                return Err(CellRegistryError::DuplicateOwner {
                    owner: owner.clone(),
                    first_cell: other_cell.clone(),
                    second_cell: cell.clone(),
                });
            }
        }
    }
    Ok(())
}
