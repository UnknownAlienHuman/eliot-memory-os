//! Issue #1025, Finding 4: the declared contract topology must equal the real
//! one.
//!
//! The audit found `module.toml depends_on` under-declaring real contract
//! dependencies - here `eliot-runtime-contracts`, which I14.29 makes a genuine
//! edge because the Context side validates against the owner-issued Kernel
//! capacity vocabulary rather than restating it. A manifest that under-declares
//! is not self-correcting: nothing else compares the two, so the drift returned
//! after the first repair.
//!
//! This check derives BOTH sides from the checked-in files and compares them as
//! sets, so adding a Cargo edge without updating `depends_on` (or declaring a
//! dependency the crate does not have) fails here instead of silently going
//! stale again. It reads the crate's own manifest and module descriptor, so it
//! needs no build-time generation step.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

/// The crate's own `Cargo.toml`, checked in beside the source.
const CARGO_TOML: &str = include_str!("../Cargo.toml");
/// The cell descriptor whose `depends_on` this check owns.
const MODULE_TOML: &str = include_str!("../module.toml");

/// Internal dependency names this crate declares through `[dependencies]`.
///
/// `foo.workspace = true`, `foo = { ... }` and `foo = "1.2.3"` all name the same
/// dependency; only the key matters here, and the exact version/feature form is
/// not part of the contract topology the manifest declares.
fn internal_cargo_dependencies() -> BTreeSet<String> {
    let dependencies: BTreeSet<String> = dependencies_of(CARGO_TOML)
        .into_iter()
        .filter(|name| name.starts_with("eliot-"))
        .collect();
    assert!(
        !dependencies.is_empty(),
        "the [dependencies] table must be readable, otherwise this check would compare two empty sets and pass vacuously"
    );
    dependencies
}

/// The dependency names `module.toml` declares in `depends_on`.
fn declared_depends_on() -> BTreeSet<String> {
    let line = MODULE_TOML
        .lines()
        .find(|line| line.trim_start().starts_with("depends_on"))
        .expect("module.toml declares depends_on");
    let list = line
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(list, _)| list)
        .expect("depends_on is a single-line list");
    let declared: BTreeSet<String> = list
        .split(',')
        .map(|entry| entry.trim().trim_matches('"').to_owned())
        .filter(|entry| !entry.is_empty())
        .collect();
    assert!(
        !declared.is_empty(),
        "an empty depends_on must fail here rather than silently accept an under-declared cell"
    );
    declared
}

// WORK_UNIT_CASE: 1025/1
#[test]
fn declared_depends_on_matches_the_real_cargo_contract_topology() {
    let declared = declared_depends_on();
    let actual = internal_cargo_dependencies();

    let undeclared: Vec<&String> = actual.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "every normal Cargo dependency must appear in module.toml depends_on; undeclared: {undeclared:?}"
    );

    let phantom: Vec<&String> = declared.difference(&actual).collect();
    assert!(
        phantom.is_empty(),
        "module.toml must not declare a dependency the crate does not have; phantom: {phantom:?}"
    );
}

// WORK_UNIT_CASE: 1025/2
#[test]
fn the_kernel_capacity_vocabulary_edge_is_declared() {
    // The specific drift the audit named, pinned by its cause: this crate
    // validates against owner-issued Kernel capacity evidence (I14.29
    // `DownstreamHeadroomReservation`), so omitting it would under-declare a
    // real contract edge even if every other edge happened to match.
    assert!(
        declared_depends_on().contains("eliot-runtime-contracts"),
        "eliot-runtime-contracts is a real contract dependency and must stay declared"
    );
    assert!(
        internal_cargo_dependencies().contains("eliot-runtime-contracts"),
        "the Cargo edge this declaration names is still present"
    );
    assert!(
        CARGO_TOML.contains("eliot-runtime-contracts.workspace = true"),
        "the capacity vocabulary is reused verbatim from its owner, never restated locally"
    );
    assert!(
        MODULE_TOML.contains("I14.29"),
        "the descriptor records why this edge exists, so a future reader can re-derive it"
    );
}

// WORK_UNIT_CASE: 1025/3
#[test]
fn the_dependency_reader_admits_every_manifest_spelling() {
    // The reader above is the whole guard, so it is proved against the three
    // spellings the workspace actually uses plus the tables it must ignore.
    for (manifest, expected) in [
        ("[dependencies]\na.workspace = true\n", vec!["a"]),
        ("[dependencies]\nb = \"1.2.3\"\n", vec!["b"]),
        (
            "[dependencies]\nc = { path = \"../c\", version = \"0.1.0\" }\n",
            vec!["c"],
        ),
        // `[dev-dependencies]` and `[build-dependencies]` are not production
        // contract topology and must not be admitted by the reader.
        ("[dev-dependencies]\nd.workspace = true\n", vec![]),
        ("[build-dependencies]\ne.workspace = true\n", vec![]),
    ] {
        let read = dependencies_of(manifest);
        assert_eq!(
            read,
            expected.iter().map(|name| (*name).to_owned()).collect(),
            "the reader must read exactly the normal dependency table of {manifest:?}"
        );
    }
}

/// The `internal_cargo_dependencies` body over an arbitrary manifest text, so
/// the real check and the spelling cases cannot drift apart.
fn dependencies_of(manifest: &str) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependencies = trimmed == "[dependencies]";
            continue;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, _)) = trimmed.split_once('=') else {
            continue;
        };
        // oo.workspace = true declares the dependency oo; the
        // .workspace suffix is how the value is sourced, not part of the name.
        let name = name
            .trim()
            .strip_suffix(".workspace")
            .unwrap_or(name.trim());
        if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_lowercase()) {
            continue;
        }
        dependencies.insert(name.to_owned());
    }
    dependencies
}
