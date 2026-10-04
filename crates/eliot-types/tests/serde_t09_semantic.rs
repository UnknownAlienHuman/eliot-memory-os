//! Issue #938 (`F-DENY-T09`, child `#938` of family `T09`): the allocated
//! decoder proof for the whole T09 slice -
//! `crates/eliot-types/src/semantic_memory.rs`,
//! `crates/eliot-types/src/distillation.rs`,
//! `crates/eliot-types/src/replay.rs` and
//! `crates/eliot-types/src/safety.rs` - and the sixteen preserved acceptance
//! cases, one marker per case.
//!
//! NOTHING IN THIS FILE HAS BEEN EXECUTED BY ITS WRITER. Not one test below has
//! been run, compiled or linted by the agent that wrote it. Every assertion
//! states what the delivered decoder IS FOR, derived by reading the production
//! source and the container, not what it was observed to do at runtime. A green
//! run of this file is compatible with every assertion in it being wrong, and
//! nothing here may be read as an execution result, a case tally or a pass
//! count.
//!
//! Fixtures are stored as RAW JSON TEXT inside
//! `crates/eliot-types/tests/data/serde_t09_memory_safety.json` (another
//! writer's file) and handed to the deserializer unparsed. A `serde_json::Value`
//! intermediate collapses a repeated object member before the decoder ever sees
//! it, so it could not prove case 5; every decoder call in this file therefore
//! receives the stored string itself. NO `Value` EVER REACHES A DECODER here.
//! The `Value` uses are exactly three kinds, all of them ABOUT the container or
//! AFTER the fact:
//!
//! - the CONTAINER itself (`corpus`, `raw`, `documents`, `meta_types`,
//!   `container_fixture_keys`, `known_non_clean_rows`), which is data about
//!   fixtures and about recorded exceptions, never an input to a decoder;
//! - WITNESSES that re-read a stored document a decoder has already accepted or
//!   refused, purely to compare a decoded field against that document's own
//!   stored value, to name the members a document carries, or to name the member
//!   a refusal message quotes; and
//! - the ONE shared lexical decoder
//!   `eliot_types::strict_json_has_no_duplicate_members`
//!   (`crates/eliot-types/src/strict_json.rs:118`), which is the production
//!   answer to case 5 and case 15 and is reached on purpose.
//!
//! Where this file edits a stored document it edits RAW TEXT
//! (`without_top_level_member`, `with_top_level_member_replaced`,
//! `with_added_top_level_member`): no `Value` is ever re-serialized on the way
//! to a decoder. Each of those three helpers re-parses its own result as a
//! WITNESS and asserts the member it claims to have removed, replaced or added
//! really is in that state, so a broken edit surfaces as a precondition failure
//! instead of a silent pass.
//!
//! Requirements the container satisfies, MEASURED by reading it (this file
//! asserts them, so a container change is visible here):
//!
//! - `fixtures` values are JSON STRINGS holding wire text; where a group of
//!   documents is needed (`c14`, `c16`) the ARRAY is inside one string;
//! - `c2_<Type>_canonical` exists for exactly the four `sd`-row safety records
//!   and holds the derived serializer's own compact output, which is what case
//!   2 compares the re-encoded bytes against;
//! - a per-case refusal fixture either INJECTS one member (the token is PRESENT
//!   in the text) or OMITS one member (the token is ABSENT from the text), and
//!   the two preconditions are proved by two DIFFERENT helpers -
//!   `assert_injected_member_refused` and `assert_omitted_member_refused`. No
//!   omission document is ever passed to the injection helper and no injection
//!   document is ever passed to the omission helper;
//! - `known_non_clean` holds nine recorded-not-fixed rows and its ids and count
//!   are DERIVED at runtime by `known_non_clean_ids`, never hard-coded here;
//! - `c16_area_scope_probes` holds documents whose members are all foreign to
//!   this slice's records and at least one of which is a real type name
//!   allocated to a DIFFERENT family of the frozen inventory.
//!
//! KNOWN NON-CLEAN, recorded in the container's `known_non_clean` array and
//! asserted there as recorded-not-fixed, never as a pass or as a refusal. The
//! container carries NINE rows and every id is consumed by this suite, in both
//! directions (case 13): four `replay.rs` wire defaults; the `sd8` disposition
//! that an omitted `IncidentRecord::campaign_integrity` decodes to an explicit
//! `None`; the `MemoryUtilitySourceRecord::payload: Value` collapse; the real MCP
//! byte ingress still parsing the line into a `serde_json::Value` at
//! `crates/eliot-app/src/mcp_stdio.rs:2133` before any `#938` decoder runs;
//! `crates/eliot-engine/src/safety.rs::RestoreService::rollback_isolated` still
//! gating rollback on four conditions that do not include the decoded receipt's
//! effect binding; and the RECORDED ABSENCE of any alias, rename or flatten
//! migration surface in the four allocated files. Cases 13, 15 and 16 check those
//! rows against the production source. Nothing in this file states any of them is
//! repaired, and nothing here states the rollback gate refuses.
//!
//! THREE CASES HAVE NO FIXTURE BY DESIGN and each is bound to a recorded row
//! instead, so `meta.case_count` stays sixteen without a document being invented:
//! cases 9 and 10 to `c9_c10_no_legacy_migration_surface`, and case 13 to `rp1`..
//! `rp4`. No stored key begins with `c9_`, `c10_` or `c13_`, and case 9 asserts
//! that.
//!
//! WHERE A DUPLICATE MEMBER IS AND IS NOT REFUSED, kept apart throughout:
//! a repeated DECLARED member of the struct itself is `duplicate field`, from the
//! derive's own per-field check (`serde_derive-1.0.229/src/de/struct_.rs:266-273`)
//! and NOT from `deny_unknown_fields`; a repeated key inside a
//! `deserialize_strict_btree_map` member is `duplicate map key`; the shared
//! lexical decoder reports `StrictJsonErrorKind::DuplicateKey`; and a repeated key
//! inside a `serde_json::Value`-typed member is last-wins and invisible to any
//! typed decoder. Case 5 exercises each of those four at its own layer.
//!
//! Rules exercised (verbatim):
//! - `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12` -
//!   "authority, scope, effect, privacy, ordering and receipt fields are never
//!   silently defaulted;"
//! - `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:14` -
//!   "canonical hashes use normalized versioned serialization;"
//! - `docs/architecture/I05-16-common-durable-fields.md:44` -
//!   "Absence of a closure or coverage record means `unknown`, not
//!   unrestricted/complete."
//! - `docs/architecture/I05-16-common-durable-fields.md:46` -
//!   "Fields that do not apply remain explicit `None`; they are not silently
//!   omitted from the semantic model."
//! - `docs/architecture/I05-22-schema-and-migration-rules.md:4` -
//!   "core schema is explicit and versioned;"
//! - `docs/architecture/I05-22-schema-and-migration-rules.md:12` -
//!   "every migration produces schema snapshot and receipt;"
//! - `docs/architecture/I05-13-backup-and-restore.md:38` -
//!   "Backup existence is not recovery proof."
//! - `docs/architecture/A13-07-backups-restore-and-migration.md:16` -
//!   "Cutover requires separate authority."
//! - `docs/architecture/I07-27-evidence-execution-parsing-evaluation-and-independence.md:24` -
//!   "Parser success is not execution; execution is not independent
//!   verification; independence is not correctness." This suite may assert SHAPE
//!   and REFUSAL only. A fixture is never executed evidence and nothing here may
//!   be read as crash recovery, purge completion, real replay or
//!   Product/release acceptance.

#![allow(clippy::expect_used, clippy::too_many_lines)]

use eliot_types::{
    BackupManifest, ExperienceFormationResult, IncidentRecord, MemoryDistillationApplyReceipt,
    MemoryDistillationCandidate, MemoryUtilitySourceRecord, ReplayRun, RestorePlan, RestoreReceipt,
    RestoreStatus, SCHEMA_VERSION, StrictJsonErrorKind, TaskMeaningFrame,
    memory_compression_artifact_schema, memory_distillation_plan_schema,
    strict_json_has_no_duplicate_members,
};

// ---------------------------------------------------------------------------
// The fixture container and its contract-fixed helpers.
// ---------------------------------------------------------------------------

/// The container file's own TEXT, read with `std::fs::read_to_string` and
/// returned with no parsing, re-serialization or normalization of any kind. This
/// is the ONLY route on which the container's physical member order is
/// observable, so it is the route the one order claim in case 1 is read through.
fn corpus_text() -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("serde_t09_memory_safety.json");
    std::fs::read_to_string(&path).expect("serde_t09_memory_safety.json must exist")
}

/// The raw fixture corpus, read exactly as
/// `crates/eliot-types/tests/data/serde_t09_memory_safety.json` stores it. The
/// `Value` only carries the stored strings out of this loader; what reaches a
/// type's deserializer is the stored wire text itself, byte for byte, with
/// every repeated object member intact.
fn corpus() -> serde_json::Value {
    serde_json::from_str(&corpus_text()).expect("serde_t09_memory_safety.json must be valid JSON")
}

/// One fixture's own text, byte for byte, with no re-serialization: a repeated
/// member and the exact member order both survive, which a `Value` round trip
/// would destroy.
fn raw(name: &str) -> String {
    corpus()
        .get("fixtures")
        .and_then(|fixtures| fixtures.get(name))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the corpus must contain fixture {name}"))
        .to_owned()
}

/// One GROUP fixture: a single stored string that holds a JSON array of wire
/// documents. The string is split HERE and each element is then handed to a
/// decoder as raw text, so grouping never normalizes anything.
fn documents(name: &str) -> Vec<String> {
    serde_json::from_str(&raw(name)).unwrap_or_else(|error| {
        panic!("{name} must hold one JSON array of wire documents as its stored string: {error}")
    })
}

/// The allocated type names, exactly as the container's `meta.types` records
/// them. The inventory itself is frozen and owned elsewhere; this only reads the
/// copy the container carries so the two cannot drift silently.
fn meta_types() -> Vec<String> {
    corpus()
        .get("meta")
        .and_then(|meta| meta.get("types"))
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the corpus must carry `meta.types`"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("`meta.types` must hold strings"))
                .to_owned()
        })
        .collect()
}

/// Every fixture key the container stores, as it stores them. Read through the
/// container's own `fixtures` object, never through a table kept beside it.
fn container_fixture_keys() -> Vec<String> {
    corpus()
        .get("fixtures")
        .and_then(serde_json::Value::as_object)
        .expect("the corpus must carry a `fixtures` object")
        .keys()
        .cloned()
        .collect()
}

/// The container's `known_non_clean` rows, in the container's own order.
fn known_non_clean_rows() -> Vec<serde_json::Value> {
    corpus()
        .get("known_non_clean")
        .and_then(serde_json::Value::as_array)
        .expect("the corpus must carry a `known_non_clean` array")
        .clone()
}

/// The ids the container's `known_non_clean` rows carry, DERIVED at runtime and
/// never hard-coded, together with the count, so a row added or removed is
/// visible in case 13 instead of being asserted away here.
fn known_non_clean_ids() -> Vec<String> {
    known_non_clean_rows()
        .iter()
        .map(|row| {
            row.get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("every `known_non_clean` row must carry a text `id`"))
                .to_owned()
        })
        .collect()
}

/// One `known_non_clean` row by its `id`.
fn row_by_id(id: &str) -> serde_json::Value {
    known_non_clean_rows()
        .into_iter()
        .find(|row| row.get("id").and_then(serde_json::Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("the corpus must carry a `known_non_clean` row with id {id}"))
}

/// One repository file, read as text, by a path RELATIVE TO THE REPOSITORY ROOT
/// that the caller spells out. `relative` is joined onto this workspace member's
/// own manifest directory, so nothing here depends on the process's current
/// directory and nothing leaves the repository.
fn repository_text(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("the repository file {relative} must exist for this assertion: {error}")
    })
}

/// One production file's text, by its repository-relative path.
fn production_text(path: &str) -> String {
    repository_text(path)
}

/// This file's own TEXT, so "no stored fixture is unnamed here" is a check this
/// file CAN FAIL, not a comparison of two hand-typed lists.
///
/// WHY A HAND-COPIED KEY LIST COULD NOT FAIL, measured in the sibling #933 file:
/// it compared a hand-copied `FIXTURE_KEYS` array against the container's own
/// `fixtures` keys, and that array was referenced only inside the orphan check
/// itself and at no `raw()` call site. Adding one key to the container, adding
/// the same key to the array and bumping its declared length left every assertion
/// passing, because nothing connected the array to any read. The array was a
/// second transcription of the container that the container's owner could satisfy
/// without this file ever naming the key.
///
/// This constant removes the second transcription. The expectation is now
/// derived from the FILE ITSELF and from the CONTAINER: a stored fixture is
/// covered only if its exact key token appears in this file's source, which is
/// the same property that makes a `raw(..)` read of it possible. The other
/// direction needs no list either - every read goes through `raw`, which panics
/// naming the key it could not find, so a key this file names and the container
/// does not store fails at the read site.
const SOURCE: &str = include_str!("serde_t09_semantic.rs");

/// The sixteen case markers. The slugs are this delivery's own naming
/// convention: the issue's case table fixes the case NUMBERS and the required
/// observable results, and `TASK.md:62` fixes the `// WORK_UNIT_CASE: 938/<case>`
/// marker shape, but not these slugs. Case 1 asserts that this list is exactly
/// the set of marker lines in this file's own text, each appearing once, and that
/// every one of them sits above a `fn` whose name is the slug.
const CASE_MARKERS: [&str; 16] = [
    "938/c1_allocation_complete",
    "938/c2_unchanged_valid_bytes",
    "938/c3_unknown_outer_field_refused",
    "938/c4_unknown_nested_field_refused",
    "938/c5_duplicate_keys_refused",
    "938/c6_wrong_or_unknown_tags_refused",
    "938/c7_missing_or_empty_required_ids_refused",
    "938/c8_unsupported_versions_refused",
    "938/c9_recorded_absence_of_legacy_migration_surface",
    "938/c10_unsafe_absent_identity_or_lineage_refuses",
    "938/c11_opaque_data_cannot_smuggle_control_meaning",
    "938/c12_proposed_or_verified_is_not_applied",
    "938/c13_exact_exceptions_invalidate_on_use_change",
    "938/c14_bounded_malformed_inputs_panic_free",
    "938/c15_decoder_refuses_before_trusted_output",
    "938/c16_scope_schema_routing_dependencies_visibility_unchanged",
];

/// The allocated types whose HOME BINDING a case owns, computed from the
/// CONTAINER and the FIXED naming rule - never from a list typed here.
///
/// The rule is `c<N>_<Type>_canonical` and `c<N>_<Type>_<property>_refuse`
/// (`TASK-938-W2-T09-CORPUS.md`), so a fixture key binds a type to a case only
/// when the segment right after `c<N>_` is a type name the container's own
/// `meta.types` records. The area keys `c<N>_<area>_<slug>` bind no type, because
/// `area`, `distillation`, `frame`, `ingress`, `ledger`, `manifest`, `replay`,
/// `safety` and `semantic_memory` are not type names.
fn types_bound_to_case(case: &str) -> Vec<String> {
    let slug = case.split_once('/').map_or("", |(_, slug)| slug);
    // The case number is what comes AFTER the leading `c`: the marker slug is
    // `c<N>_<rest>` and the prefix below is rebuilt as `c{digits}_`, so the digits must
    // be read from `slug` with that `c` stripped first. `take_while` then stops at the
    // `_`, which is what keeps the two-digit cases `c10`..`c16` from swallowing the rest
    // of the slug.
    let number = slug.strip_prefix('c').unwrap_or(slug);
    let digits: String = number.chars().take_while(char::is_ascii_digit).collect();
    assert!(
        !digits.is_empty(),
        "a case marker slug must start with `c` followed by its case number, as `c<N>_<rest>`: \
         {case}"
    );
    let prefix = format!("c{digits}_");
    assert_eq!(
        slug.strip_prefix(prefix.as_str()),
        Some(
            number
                .strip_prefix(digits.as_str())
                .and_then(|rest| rest.strip_prefix('_'))
                .unwrap_or("")
        ),
        "the rebuilt prefix `c{digits}_` must be a real prefix of the slug `{slug}`, or the case \
         number was read from the wrong place: {case}"
    );
    let types = meta_types();
    let mut bound: Vec<String> = container_fixture_keys()
        .iter()
        .filter_map(|key| {
            let rest = key.strip_prefix(prefix.as_str())?;
            types
                .iter()
                .find(|type_name| {
                    rest.starts_with(type_name.as_str()) && rest[type_name.len()..].starts_with('_')
                })
                .cloned()
        })
        .collect();
    bound.sort();
    bound.dedup();
    bound
}

/// This suite's own repository-relative path, as the frozen inventory names it. One
/// definition, so case 1 can assert that the `#938` allocation row names THIS file
/// without a second transcription of the path.
const SELF_TEST_FILE: &str = "crates/eliot-types/tests/serde_t09_semantic.rs";

/// The four canonical documents case 2 owns. Every one must be bound to case 2
/// by the container's own `c2_<Type>_canonical` key, and no other type may be,
/// so this list can neither name a type with no canonical document nor leave one
/// this case should have read.
const CASE2_BOUND_TYPES: [&str; 4] = [
    "BackupManifest",
    "RestorePlan",
    "RestoreReceipt",
    "IncidentRecord",
];

/// The four `rp` exception ids of `replay.rs`. These four ARE fixed: they are
/// the four declarations that really carry a wire default there, which case 13
/// derives from the production source and checks against the container's rows.
const REPLAY_DEFAULT_ROW_IDS: [&str; 4] = ["rp1", "rp2", "rp3", "rp4"];

/// The member `c5_safety_duplicate_backup_id_refuse` repeats, pinned by the
/// fixture's own name and by `TASK.md:131`, which names `backup_id` in the
/// repeated-member counterexample for a backup record.
const DUPLICATE_BACKUP_ID: &str = "backup_id";
/// The member `c5_frame_duplicate_task_id_refuse` repeats, pinned by the
/// fixture's name and by `TASK.md:113`, which spells the counterexample
/// `{"frame":{"task_id":"task-a","task_id":"task-b", ...}}`.
const DUPLICATE_TASK_ID: &str = "task_id";
/// The MAP key `c5_frame_duplicate_entity_role_key_refuse` repeats, pinned by
/// the fixture's name and by `TASK.md:119`, which spells the counterexample
/// `{"frame":{"entity_roles":{"subject":"first","subject":"second"}, ...}}`.
const DUPLICATE_ENTITY_ROLE_KEY: &str = "subject";
/// The wrapper member the two ingress counterexamples place the repeated member
/// inside (`TASK.md:113` and `:119`).
const INGRESS_FRAME_MEMBER: &str = "frame";
/// `TaskMeaningFrame`'s lineage map
/// (`crates/eliot-types/src/semantic_memory.rs:97-98`).
const ENTITY_ROLES: &str = "entity_roles";
/// The effect-bearing members of the safety family whose omission case 7 and
/// case 9 assert, spelled once so the assertions name exact keys.
const SURREAL_SOURCE_ENDPOINT: &str = "surreal_source_endpoint";
const SURREAL_SOURCE_STORAGE_REF: &str = "surreal_source_storage_ref";
const BLOB_PAYLOAD_ROOT: &str = "blob_payload_root";
const TARGET_ENDPOINT: &str = "target_endpoint";
const TARGET_STORAGE_REF: &str = "target_storage_ref";
const EXACT_ACTION_HASH: &str = "exact_action_hash";
/// `BackupManifest`'s one decoder-enforced version member
/// (`crates/eliot-types/src/safety.rs:129-130`).
const SCHEMA_VERSION_MEMBER: &str = "schema_version";
/// The enclosing member `c4_safety_unknown_nested_member_refuse` injects into.
const CHECKSUMS_MEMBER: &str = "checksums";
/// The outcome tag of the two internally tagged result enums
/// (`crates/eliot-types/src/semantic_memory.rs:237` and `:248`) and the member one
/// of their variants declares (`semantic_memory.rs:243`).
const OUTCOME_TAG: &str = "outcome";
const FORMATION_CASE_MEMBER: &str = "experience_case";
const OUTCOME_REASON_MEMBER: &str = "reason";
/// `ReplayRun`'s and `RestoreReceipt`'s control members, named so an assertion
/// can say which member it edited.
const REPLAY_STATUS: &str = "status";
const RESTORE_STATUS: &str = "status";
/// The campaign-integrity member whose disposition is the `safety.rs` writer's,
/// not this file's (`crates/eliot-types/src/safety.rs:778`).
const CAMPAIGN_INTEGRITY: &str = "campaign_integrity";
/// The four members case 15 adds to a restore receipt. Each is a word that would
/// raise proof if it were accepted, which is why the case's claim is that they
/// are all REFUSED.
const PROOF_RAISING_MEMBERS: [&str; 4] = ["applied", "recovered", "erased", "authorized"];
/// The words case 11 requires the inert source payload to actually contain, so
/// the fixture's premise - source text may mention restore, erasure or
/// authorization - is proved present rather than assumed.
const CONTROL_MEANING_WORDS: [&str; 3] = ["restore", "erasure", "authorization"];

/// Every fixture-key-SHAPED token this file's own text carries inside a double
/// quoted literal, e.g. `"c5_frame_duplicate_task_id_refuse"`.
///
/// A token qualifies when it is `c<digits>_<alphanumerics and underscores>`, which
/// is the fixed naming rule the container itself uses. The `c{digits}_` format
/// string, the `c2_{type}_canonical` construction and the `c7_`/`c9_` prefixes do
/// NOT qualify, because their tail is empty or is not literal text, so what comes
/// back is a set of literal names this file NAMES rather than a set it builds.
///
/// This is the second direction of the oracle, and it exists because the first one
/// cannot fail for a name this file invents: it walks the container's keys. This
/// walk goes the other way and needs no list typed here either - it reads this
/// file's own source and asks the container whether each name exists.
fn fixture_key_tokens_in_source() -> Vec<String> {
    let bytes = SOURCE.as_bytes();
    let mut tokens: Vec<String> = Vec::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let after_opening = cursor + 1;
        let mut end = after_opening;
        while end < bytes.len() && bytes[end] != b'"' && bytes[end] != b'\n' {
            end += 1;
        }
        let literal = SOURCE.get(after_opening..end).unwrap_or_default();
        let shape: String = literal
            .chars()
            .take_while(|character| {
                *character == 'c'
                    || *character == '_'
                    || character.is_ascii_digit()
                    || character.is_ascii_lowercase()
            })
            .collect();
        let digits = shape
            .chars()
            .skip(1)
            .take_while(char::is_ascii_digit)
            .count();
        let tail = shape.get(1 + digits..).unwrap_or_default();
        // A bare `c7_` PREFIX is not a name, and neither is a literal that carries
        // characters the naming rule does not allow: the tail after `c<digits>_` must
        // be non-empty and the whole literal must be the token.
        // `digits` is a COUNT of the case-number digits, so "the case number is
        // present" is `digits > 0` and nothing else: a literal like `c_foo` has no
        // digits at all and must not be read as a key-shaped name.
        let is_key_shape =
            digits > 0 && tail.starts_with('_') && tail.len() > 1 && shape.len() == literal.len();
        if is_key_shape && !tokens.contains(&shape.clone()) {
            tokens.push(shape.clone());
        }
        cursor = end + 1;
    }
    tokens.sort();
    tokens
}

/// NO SILENT ORPHANS, checked against something that can fail, in BOTH directions.
///
/// Direction 1, derived from the FILE and the CONTAINER: every key the container
/// stores must either be NAMED in this file's own text - which is what a `raw(..)`
/// read of it is - or be one of the names the FIXED naming rule CONSTRUCTS from the
/// container's own `meta.types`, namely `c2_<Type>_canonical` for an allocated type.
/// That constructed family is the one this file reads by construction rather than by
/// name, and case 2 additionally checks that every one of those documents is a real
/// JSON object or bare variant string, so it is not an unexamined hole. Every other
/// stored key must be named literally here, which means a key the container's owner
/// adds fails HERE.
///
/// Direction 2, derived from the FILE alone and checked against the CONTAINER: every
/// fixture-key-shaped name this file's own text carries must be a key the container
/// stores, one of the derived `c2_<Type>_canonical` names, or a `known_non_clean`
/// row id. A name this file invents therefore fails at the oracle rather than at a
/// read site, and neither direction needs a hand-typed key list.
fn assert_no_silent_orphans() {
    let container_keys = container_fixture_keys();
    assert!(
        !container_keys.is_empty(),
        "the container must store at least one fixture"
    );
    let constructed = constructed_canonical_names(&meta_types());
    for key in &container_keys {
        let token = format!("\"{key}\"");
        assert!(
            SOURCE.contains(token.as_str()) || constructed.contains(key),
            "the container stores fixture {key}, but no line of this file names it and it is not \
             a `c2_<Type>_canonical` of an allocated type: that is a silent orphan. Either a test \
             must read {key}, or the container must drop it, or its type must be recorded in \
             `meta.types` so the derived family covers it"
        );
    }
    let row_ids = known_non_clean_ids();
    for token in fixture_key_tokens_in_source() {
        assert!(
            container_keys.contains(&token)
                || constructed.contains(&token)
                || row_ids.contains(&token),
            "this file names `{token}`, and the container stores no such fixture key and carries \
             no such `known_non_clean` row id: a name that exists only here. The container's \
             fixture keys are {container_keys:?} and its row ids are {row_ids:?}"
        );
    }
}

/// Every fixture key the FIXED naming rule constructs from the container's own
/// `meta.types`: one `c2_<Type>_canonical` per allocated type. Derived from the
/// CONTAINER, never typed here.
fn constructed_canonical_names(types: &[String]) -> Vec<String> {
    types
        .iter()
        .map(|type_name| format!("c2_{type_name}_canonical"))
        .collect()
}

// ---------------------------------------------------------------------------
// Raw-text document surgery. Every one of these edits RAW TEXT; none of them
// parses a document into a `Value` on the way to a decoder, and each one re-reads
// its own result as a witness and asserts the edit it claims.
// ---------------------------------------------------------------------------

/// The index just past the JSON string that starts at `start`, honouring
/// backslash escapes. `None` when the bytes are not a well-formed string.
fn scan_json_string(bytes: &[u8], start: usize) -> Option<usize> {
    if *bytes.get(start)? != b'"' {
        return None;
    }
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'"' => return Some(cursor + 1),
            _ => cursor += 1,
        }
    }
    None
}

/// The index just past the JSON value that starts at `start`: a string, a
/// brace/bracket-balanced object or array, or a bare scalar up to the next
/// separator. `None` when the value is not closed.
fn scan_json_value(bytes: &[u8], start: usize) -> Option<usize> {
    match *bytes.get(start)? {
        b'"' => scan_json_string(bytes, start),
        b'{' | b'[' => {
            let mut cursor = start;
            let mut depth = 0_usize;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'"' => cursor = scan_json_string(bytes, cursor)?,
                    b'{' | b'[' => {
                        depth += 1;
                        cursor += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        cursor += 1;
                        if depth == 0 {
                            return Some(cursor);
                        }
                    }
                    _ => cursor += 1,
                }
            }
            None
        }
        _ => {
            let mut cursor = start;
            while cursor < bytes.len()
                && bytes[cursor] != b','
                && bytes[cursor] != b'}'
                && bytes[cursor] != b']'
            {
                cursor += 1;
            }
            Some(cursor)
        }
    }
}

/// One top-level member's byte span in a stored document.
struct RawMemberSpan {
    /// where the CUT starts: the member's key token, or the separator comma
    /// before it when it is the object's last member;
    start: usize,
    /// where the member's VALUE starts;
    value_start: usize,
    /// where the member's VALUE ends;
    value_end: usize,
    /// where the CUT ends: after the separator comma that follows the value, or
    /// at the end of the value when it is the object's last member;
    end: usize,
}

/// Locate ONE top-level member of a JSON object by its exact, unescaped key
/// text. The key is compared as raw bytes, so every key this file looks up is
/// spelled in plain ASCII and needs no unescaping. The scan never leaves the
/// object's top level, so a key inside a nested object or inside a string is
/// invisible to it.
fn top_level_member_span(document: &str, member: &str) -> RawMemberSpan {
    let bytes = document.as_bytes();
    let mut cursor = bytes
        .iter()
        .position(|byte| *byte == b'{')
        .unwrap_or_else(|| {
            panic!("a stored document this file edits must be a JSON object, not a bare scalar")
        });
    cursor += 1;
    loop {
        // At a MEMBER BOUNDARY: just after `{`, or just after a previous member's
        // value. One optional separator comma, then whitespace.
        while cursor < bytes.len() && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b',')
        {
            cursor += 1;
        }
        assert!(
            cursor < bytes.len() && bytes[cursor] != b'}',
            "the stored document must carry a top-level member `{member}`"
        );
        let key_start = cursor;
        let key_end = scan_json_string(bytes, cursor)
            .unwrap_or_else(|| panic!("the stored document must be well-formed JSON"));
        let key = document.get(cursor + 1..key_end - 1).map(str::to_owned);
        cursor = key_end;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        assert_eq!(
            bytes.get(cursor),
            Some(&b':'),
            "a top-level member must be followed by `:`"
        );
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let value_start = cursor;
        let value_end = scan_json_value(bytes, cursor)
            .unwrap_or_else(|| panic!("the value of a top-level member must be well-formed JSON"));
        // STEP OVER every member that is not the one asked for. An earlier version
        // asserted on the first key it saw and panicked for any document whose
        // requested member was not FIRST, which is false for most of this corpus:
        // `status` is the LAST member of the ReplayRun document, `payload` is the
        // fifth of the source record and `exact_action_hash` the eighth of the restore
        // plan. Walking the object is what "the top level" means.
        if key.as_deref() != Some(member) {
            cursor = value_end;
            continue;
        }
        let mut end = value_end;
        while end < bytes.len() && bytes[end].is_ascii_whitespace() {
            end += 1;
        }
        let mut start = key_start;
        if bytes.get(end) == Some(&b',') {
            end += 1;
        } else {
            // The last member of the object: the separator to cut is the comma
            // BEFORE it, so the result stays a well-formed object.
            while start > 0 && bytes[start - 1].is_ascii_whitespace() {
                start -= 1;
            }
            if start > 0 && bytes[start - 1] == b',' {
                start -= 1;
            }
        }
        return RawMemberSpan {
            start,
            value_start,
            value_end,
            end,
        };
    }
}

/// One stored document with ONE OCCURRENCE of a top-level member REMOVED, as raw
/// text. Used to build an omission document out of a stored one without asking the
/// container for a second document per member.
///
/// THE PRECONDITION IS "ONE FEWER OCCURRENCE", NOT "NO OCCURRENCE LEFT". The stored
/// `c5_frame_duplicate_task_id_refuse` carries `task_id` TWICE, and case 10 uses this
/// helper to drop the FIRST pair and keep the retained last value as its accepted
/// counterpart - so demanding that the member be gone entirely asserted something
/// false about that document. A `Value` witness cannot see the difference at all,
/// because it collapses the pair to one key either way; the count is read out of the
/// RAW TEXT of both documents, which is the only route that can tell them apart.
fn without_top_level_member(document: &str, member: &str) -> String {
    let span = top_level_member_span(document, member);
    let mut edited = String::with_capacity(document.len());
    edited.push_str(&document[..span.start]);
    edited.push_str(&document[span.end..]);
    assert_eq!(
        repeats(&edited, member),
        repeats(document, member).saturating_sub(1),
        "the edited document must carry exactly one `\"{member}\"` occurrence FEWER than the \
         original: the edit removes one occurrence and no other"
    );
    edited
}

/// One stored document with ONE top-level member's VALUE REPLACED by a raw JSON
/// literal, as raw text. The key and every other byte are untouched. The result
/// is re-read as a WITNESS and asserted to carry exactly `literal` under
/// `member`.
fn with_top_level_member_replaced(document: &str, member: &str, literal: &str) -> String {
    let span = top_level_member_span(document, member);
    let mut edited = String::with_capacity(document.len());
    edited.push_str(&document[..span.value_start]);
    edited.push_str(literal);
    edited.push_str(&document[span.value_end..]);
    assert_eq!(
        witness(&edited).get(member).cloned(),
        Some(witness(literal)),
        "the edited document must carry `{member}` with exactly the requested literal"
    );
    edited
}

/// One stored document with ONE NEW top-level member appended, as raw text. Used
/// only to prove that an added proof-raising member is REFUSED. The result is
/// re-read as a WITNESS and asserted to carry the new member.
fn with_added_top_level_member(document: &str, member: &str, literal: &str) -> String {
    let trimmed = document.trim_end();
    let close = trimmed
        .rfind('}')
        .unwrap_or_else(|| panic!("a stored document must be a JSON object to take a new member"));
    let mut edited = String::with_capacity(document.len() + member.len() + literal.len() + 8);
    edited.push_str(&trimmed[..close]);
    edited.push_str(", \"");
    edited.push_str(member);
    edited.push_str("\": ");
    edited.push_str(literal);
    edited.push('}');
    assert_eq!(
        witness(&edited).get(member).cloned(),
        Some(witness(literal)),
        "the edited document must really carry the added member `{member}`"
    );
    edited
}

/// One stored document with a SECOND `"<nested>": <literal>` member added inside
/// the OBJECT value of `member`, as raw text. Used to build the one repeated member
/// a typed decoder genuinely cannot see - one inside a `serde_json::Value`-typed
/// member's own object - without inventing a fixture. The result is re-read as a
/// WITNESS and asserted to carry the nested member twice in the raw text while the
/// witness parse keeps one, which is the collapse this helper exists to stage.
fn with_repeated_nested_member(
    document: &str,
    member: &str,
    nested: &str,
    literal: &str,
) -> String {
    let span = top_level_member_span(document, member);
    let object = document
        .get(span.value_start..span.value_end)
        .unwrap_or_default()
        .to_owned();
    assert!(
        object.starts_with('{') && object.ends_with('}'),
        "`{member}` must hold a JSON OBJECT for a repeat to be added inside it"
    );
    let mut edited = String::with_capacity(document.len() + nested.len() + literal.len() + 8);
    edited.push_str(&document[..span.value_end - 1]);
    edited.push_str(", \"");
    edited.push_str(nested);
    edited.push_str("\": ");
    edited.push_str(literal);
    edited.push_str(&document[span.value_end - 1..]);
    assert_eq!(
        repeats(&edited, nested),
        2,
        "the edited document must really carry `\"{nested}\"` twice"
    );
    assert_eq!(
        witness(&edited)
            .get(member)
            .and_then(|inner| inner.get(nested))
            .cloned(),
        Some(witness(literal)),
        "the witness parse must retain only the LAST `{nested}` copy, which is the collapse this \
         helper stages"
    );
    edited
}

/// The INNER `frame` document of an ingress counterexample, taken out of the stored
/// wrapper `{"frame": <frame>}` as RAW TEXT.
///
/// The real input type is `TaskMeaningToolInput`
/// (`crates/eliot-app/src/mcp_stdio.rs:2739-2743`), which is PRIVATE to
/// `crates/eliot-app`, so this crate cannot name it and this file makes NO end-to-end
/// claim about it. The wrapper is cut lexically rather than through a
/// `serde_json::Value` on purpose: a `Value` parse is exactly the step that erases
/// the repeat (adjudicated case (a): `serde_json`'s `Value` deserializer inserts
/// members with no duplicate check, `serde_json-1.0.151/src/value/de.rs:139-142`),
/// so going through one would hand the typed decoder the collapsed document and prove
/// nothing. `None` when the wrapper does not have that exact shape.
fn ingress_frame_document(document: &str) -> Option<&str> {
    let wrapper = format!("\"{INGRESS_FRAME_MEMBER}\":");
    let rest = document.strip_prefix('{')?.strip_prefix(wrapper.as_str())?;
    rest.strip_suffix('}')
}

// ---------------------------------------------------------------------------
// Decode and comparison helpers.
// ---------------------------------------------------------------------------

/// The one decode entry point this file uses: the stored raw text goes straight
/// into the deserializer, with no intermediate document of any kind.
fn decode<T: serde::de::DeserializeOwned>(document: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(document)
}

/// A WITNESS parse, used only to compare an already-decoded field against a
/// stored document's own value, to name the members a document carries, or to
/// re-read this file's own edits. It never feeds a type's decoder.
fn witness(document: &str) -> serde_json::Value {
    serde_json::from_str(document)
        .unwrap_or_else(|error| panic!("this stored document must parse as JSON: {error}"))
}

/// One member of a stored document as text, owned.
fn member_text(document: &str, member: &str) -> String {
    witness(document)
        .get(member)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the document must carry a string member `{member}`"))
        .to_owned()
}

/// One member of a stored document as an owned `Value`, which is how an ABSENT
/// member, an explicit `null` and a value stay three different facts
/// (`docs/architecture/I05-16-common-durable-fields.md:46`).
fn member_value(document: &str, member: &str) -> serde_json::Value {
    witness(document)
        .get(member)
        .cloned()
        .unwrap_or_else(|| panic!("the document must carry a member `{member}`"))
}

/// How many times the RAW text carries `"<member>"`. A repeated member is exactly
/// what a `Value` intermediate would have collapsed, so this count is the proof
/// that the raw route saw something the value route cannot see.
fn repeats(document: &str, member: &str) -> usize {
    let needle = format!("\"{member}\"");
    document.matches(needle.as_str()).count()
}

/// Every raw string value the RAW text carries under `member`, in the order the
/// bytes carry them and WITHOUT unescaping. This is the only way to see BOTH
/// sides of a repeated member: a `Value` parse keeps only the last one. Both
/// sides are compared as raw text, so no unescaping is needed.
fn raw_string_values(document: &str, member: &str) -> Vec<String> {
    let needle = format!("\"{member}\"");
    let bytes = document.as_bytes();
    let mut values = Vec::new();
    let mut from = 0_usize;
    while let Some(at) = document
        .get(from..)
        .and_then(|rest| rest.find(needle.as_str()))
    {
        let key_end = from + at + needle.len();
        let mut cursor = key_end;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b':') {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'"') {
                let value_end = scan_json_string(bytes, cursor)
                    .unwrap_or_else(|| panic!("a raw value of `{member}` must be a JSON string"));
                values.push(
                    document
                        .get(cursor + 1..value_end - 1)
                        .unwrap_or_else(|| panic!("a raw value of `{member}` must be in bounds"))
                        .to_owned(),
                );
            }
        }
        from = key_end;
    }
    values
}

/// A document's own top-level member names, in the order the DECODED map yields
/// them. `serde_json::Map` is a `BTreeMap` unless the `preserve_order` feature is
/// enabled, so this is ALPHABETICAL and it is used for set membership only.
fn top_level_members(document: &str) -> Vec<String> {
    witness(document)
        .as_object()
        .unwrap_or_else(|| panic!("this document must be a JSON object"))
        .keys()
        .cloned()
        .collect()
}

/// One member's FIRST entry, as its own object: the member names of one element
/// of a nested array of objects, used to prove WHERE an injected member sits.
fn first_entry_members(document: &str, array_member: &str) -> Vec<String> {
    witness(document)
        .get(array_member)
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| {
            panic!("the document must carry `{array_member}` with at least one object entry")
        })
        .keys()
        .cloned()
        .collect()
}

/// The member a serde refusal message quotes after `marker`, e.g. the member
/// after `unknown field`, `missing field` or `unknown variant`. `None` when the
/// message does not quote one. This is how an assertion names the EXACT member
/// the delivered decoder objected to without this file guessing which key the
/// container chose.
fn quoted_member(message: &str, marker: &str) -> Option<String> {
    let after_marker = message.split_once(marker)?.1;
    let quoted = after_marker.split_once('`')?.1;
    Some(quoted.split_once('`')?.0.to_owned())
}

/// Whether `document` parses as a JSON document at all. Used only to state that
/// a malformed group really contains bytes no decoder can read, never as an input
/// to a type's decoder.
fn is_not_json(document: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(document).is_err()
}

/// One Rust variant or field identifier as its `snake_case` wire spelling, which
/// is what a `#[serde(rename_all = "snake_case")]` enum derives. Used to DERIVE a
/// closed variant set from the production source instead of typing one here.
fn camel_to_snake(name: &str) -> String {
    let mut spelled = String::with_capacity(name.len() + 4);
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                spelled.push('_');
            }
            spelled.push(character.to_ascii_lowercase());
        } else {
            spelled.push(character);
        }
    }
    spelled
}

/// One Rust variant name as its `SCREAMING_SNAKE_CASE` wire spelling, which is
/// what a `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` enum derives. Used to
/// show that the preserved spelling of `ExperienceMaturityState` really is a
/// different wire form from its neighbours' `snake_case`.
fn camel_to_screaming_snake(name: &str) -> String {
    camel_to_snake(name).to_uppercase()
}

/// The variant names the production source declares between `declaration` and the
/// enum's closing brace, read from the source text. Used so a closed variant set
/// is a fact about the source rather than a list typed in this file.
fn enum_variants(source: &str, declaration: &str) -> Vec<String> {
    let at = source
        .find(declaration)
        .unwrap_or_else(|| panic!("the production file must declare `{declaration}`"));
    let body = &source[at..];
    let mut variants = Vec::new();
    for line in body.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed == "}" {
            break;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        let candidate = trimmed.trim_end_matches(',').trim_end_matches('{').trim();
        let identifier: String = candidate
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect();
        if identifier
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_uppercase())
        {
            variants.push(identifier);
        }
    }
    assert!(
        !variants.is_empty(),
        "the production file must declare at least one variant after `{declaration}`"
    );
    variants
}

/// Every allocated type name the FROZEN INVENTORY records, across all of its
/// `[[allocations]]` rows. Read from the inventory text, so the "allocated to a
/// different family" claim in case 16 is a fact about the inventory rather than a
/// list typed here.
fn inventory_allocated_types() -> Vec<String> {
    let inventory = repository_text(
        "crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml",
    );
    let mut names: Vec<String> = Vec::new();
    for line in inventory.lines() {
        let Some(list) = line.trim().strip_prefix("types = [") else {
            continue;
        };
        let list = list.trim_end_matches(']');
        for quoted in list.split('"').skip(1).step_by(2) {
            if quoted.is_empty() {
                continue;
            }
            names.push(quoted.to_owned());
        }
    }
    assert!(
        !names.is_empty(),
        "the frozen inventory must record allocated type lists this case can compare against"
    );
    names.sort();
    names.dedup();
    names
}

/// A type name reduced to the form a `snake_case` member and a `CamelCase` type
/// share, so a member named `provider_invocation_attempt` can be compared with a
/// type named `ProviderInvocationAttempt`.
fn normalize_type_name(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// Assert that the types this case OWNS are exactly the types the CONTAINER binds
/// to it, in both directions.
///
/// 1. every type the case names is bound to `case` by the container's own fixture
///    keys, so a case cannot claim a type with no document; and
/// 2. every type the container binds to `case` is named by the case, so an
///    allocated type cannot be left with a home case that never says it owns it.
///
/// Direction 2 needs its own assertion: an equal length plus direction 1 does not
/// imply it, because a `touched` list that repeats one name satisfies both while
/// an owned type goes unnamed.
///
/// WHAT THIS DOES NOT CLAIM: `touched` is not every type whose decoder runs
/// anywhere in the body. A case may legitimately decode a type another case
/// binds - a carrier decoded only to reach a nested decoder - and every such
/// decode is written down with the type's role in a comment at the call site.
fn assert_case_binding(case: &str, touched: &[&str]) {
    let bound = types_bound_to_case(case);
    for name in touched {
        assert!(
            bound.iter().any(|entry| entry.as_str() == *name),
            "case {case} names {name}, which the container's own fixture keys do not bind to it; \
             bound there: {bound:?}"
        );
    }
    for name in &bound {
        assert!(
            touched.contains(&name.as_str()),
            "the container binds {name} to {case}, so that case must name it as one of the types \
             it owns; the case names {touched:?}"
        );
    }
}

/// Assert a refusal caused by an INJECTED member: this helper PROVES THE TOKEN IS
/// PRESENT in the stored text.
///
/// The precondition is the opposite of `assert_omitted_member_refused`'s, and
/// passing an omission document here can never pass: a document built by deleting
/// one member carries that member's name nowhere. It then asserts the decode
/// fails, that the message is of the named kind, and that the refusal names the
/// injected token.
fn assert_injected_member_refused<T>(document: &str, label: &str, token: &str, needle: &str)
where
    T: serde::de::DeserializeOwned,
{
    assert!(
        document.contains(token),
        "{label} must actually carry the injected token `{token}` under test"
    );
    let Err(error) = decode::<T>(document) else {
        panic!("{label} must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains(needle),
        "{label} must be refused as `{needle}`, got: {message}"
    );
    assert!(
        message.contains(token),
        "{label}'s refusal must name `{token}`, got: {message}"
    );
}

/// Assert a refusal caused by an OMITTED member: this helper PROVES THE TOKEN IS
/// ABSENT from the stored text, at any depth.
///
/// The two refusal helpers differ in exactly the precondition each one proves, and
/// getting them backwards turns a correct fixture into a test that cannot pass. It
/// then asserts the decode fails, that the message is a `missing field` refusal,
/// and that the refusal names the member anyway - which is what serde's own
/// `missing field` error does, so the name is available from the message even
/// though it is gone from the document.
fn assert_omitted_member_refused<T>(document: &str, label: &str, member: &str)
where
    T: serde::de::DeserializeOwned,
{
    assert!(
        !document.contains(&format!("\"{member}\"")),
        "{label} must actually OMIT `{member}`, and must not carry it at any depth"
    );
    let Err(error) = decode::<T>(document) else {
        panic!("{label} must be refused for the absent member `{member}`");
    };
    let message = error.to_string();
    assert!(
        message.contains("missing field"),
        "{label} must be refused as `missing field`, got: {message}"
    );
    assert!(
        message.contains(member),
        "{label}'s refusal must name the absent member `{member}`, got: {message}"
    );
}

/// Assert a refusal caused by a REPEATED DECLARED member of `T` itself. This helper
/// PROVES THE REPEAT IS PRESENT IN THE STORED TEXT, exactly twice.
///
/// The needle is `duplicate field`, and that is deliberate: it is the DERIVE's own
/// check (`serde_derive-1.0.229/src/de/struct_.rs:266-273`), which fires before the
/// repeated value is visited, so this helper must never be used for a repeated key
/// inside a map - that is `duplicate map key`, raised by a
/// `deserialize_strict_btree_map` visitor - nor for a repeated key inside a
/// `serde_json::Value` member, which is not refused at all.
fn assert_duplicate_field_refused<T>(document: &str, label: &str, member: &str)
where
    T: serde::de::DeserializeOwned,
{
    assert_eq!(
        repeats(document, member),
        2,
        "{label} must carry `\"{member}\"` exactly twice, or it is not a repeated declared member"
    );
    let Err(error) = decode::<T>(document) else {
        panic!("{label} must be refused: a repeated declared member is `duplicate field`");
    };
    let message = error.to_string();
    assert!(
        message.contains("duplicate field"),
        "{label} must be refused as `duplicate field`, got: {message}"
    );
    assert!(
        message.contains(member),
        "{label}'s refusal must name the repeated member `{member}`, got: {message}"
    );
}

/// Assert a refusal caused by an UNKNOWN MEMBER whose exact name this file does
/// not choose: the name is READ BACK OUT OF THE DELIVERED REFUSAL MESSAGE, and
/// then three facts are proved about it.
///
/// 1. it is not a member the ACCEPTED canonical document carries, so the refusal
///    cannot be about something the canonical also has;
/// 2. it really occurs in the refused document's own text, so the refusal is
///    caused by that token and nothing else; and
/// 3. the accepted canonical DECODES as the same type, which is the control: the
///    two documents differ by the injected member and nothing else this file can
///    see.
///
/// The member's name is returned so the caller can prove WHERE it sits.
fn assert_unknown_member_refused<T>(document: &str, canonical: &str, label: &str) -> String
where
    T: serde::de::DeserializeOwned,
{
    assert_ne!(
        document, canonical,
        "{label} must actually differ from the accepted canonical document"
    );
    let accepted: T = decode(canonical).unwrap_or_else(|error| {
        panic!("the canonical document must decode as the same type: {error}")
    });
    drop(accepted);
    let canonical_members = top_level_members(canonical);
    let Err(error) = decode::<T>(document) else {
        panic!("{label} must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains("unknown field"),
        "{label} must be refused as `unknown field`, got: {message}"
    );
    let member = quoted_member(&message, "unknown field")
        .unwrap_or_else(|| panic!("{label}'s refusal must name the unknown member: {message}"));
    assert!(
        !canonical_members.contains(&member),
        "{label}'s unknown member `{member}` is also a member of the accepted canonical document, \
         so the refusal is not caused by an added member; canonical members: {canonical_members:?}"
    );
    assert!(
        document.contains(&format!("\"{member}\"")),
        "{label}'s refusal names `{member}`, which its own text does not carry: the refusal is not \
         caused by that token"
    );
    member
}

/// A document round-trips AS BYTES: it decodes, and re-encoding the decoded value
/// reproduces the document EXACTLY, so the accepted bytes of that type are proven
/// unchanged by this delivery. A second decode/re-encode cycle must then reproduce
/// the same bytes, so a value's re-encoded form is a fixed point.
///
/// The ONE reason the stored-bytes comparison can fail is that the document is not
/// the derived serializer's own compact output - for a member of type
/// `serde_json::Value` that is IMPOSSIBLE, because a `Value`'s object keys
/// re-encode alphabetically, which is why this helper is used only for documents
/// with no `Value` member and `assert_round_trip_identical` is used for the rest.
/// NO DIGEST is computed anywhere in this file: the claim is the encoded BYTES.
fn assert_bytes_unchanged<T>(type_name: &str, label: &str, document: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    assert!(
        !document.trim().is_empty(),
        "the canonical document {label} must not be empty"
    );
    let first: T = decode(document)
        .unwrap_or_else(|error| panic!("{label} must decode as {type_name}: {error}"));
    let once = serde_json::to_string(&first)
        .unwrap_or_else(|error| panic!("{type_name} must re-encode: {error}"));
    assert_eq!(
        once, document,
        "{label} must be the derived serializer's own compact output, so the accepted bytes of \
         {type_name} are compared against the bytes themselves"
    );
    let second: T = decode(&once)
        .unwrap_or_else(|error| panic!("the re-encoded {type_name} must decode again: {error}"));
    let twice = serde_json::to_string(&second)
        .unwrap_or_else(|error| panic!("the re-decoded {type_name} must re-encode: {error}"));
    assert_eq!(
        twice, once,
        "{label}: a second decode/re-encode cycle must not move a single byte"
    );
}

/// The decoded value carries EXACTLY the document's own members:
/// `serde_json::to_value` of the decoded value equals a witness parse of the
/// stored text. This is the "the decode erased nothing and invented nothing"
/// check, the executable form of "this document changed no status, created no
/// receipt, no authority and no effect", and it is member-order-insensitive,
/// which is what makes it usable for a document holding a `serde_json::Value`
/// member.
fn assert_round_trip_identical<T>(document: &str, label: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let decoded: T =
        decode(document).unwrap_or_else(|error| panic!("{label} must decode: {error}"));
    let re_encoded = serde_json::to_value(&decoded)
        .unwrap_or_else(|error| panic!("{label} must re-encode: {error}"));
    assert_eq!(
        re_encoded,
        witness(document),
        "{label}: the decoded value must carry exactly the document's own members - nothing \
         erased, nothing invented, nothing promoted"
    );
}

/// Assert that `document` is REFUSED by `T` without panicking, unwinding or
/// aborting. The `catch_unwind` is the whole point of case 14: a bounded malformed
/// input must fail, and it must fail as an ordinary error. There is no `unwrap` on
/// the result and no `#[should_panic]`: a document that decodes is reported as
/// such, never accommodated.
fn assert_panic_free_refusal<T>(document: &str, label: &str)
where
    T: serde::de::DeserializeOwned,
{
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode::<T>(document)));
    let result = outcome.unwrap_or_else(|_| panic!("{label} must not panic while being decoded"));
    assert!(
        result.is_err(),
        "{label} must be refused by its decoder, not accepted"
    );
}

/// One decoded `Option` member must agree with the stored document's own value for
/// that member, whichever of the states the document is in. An explicit `null` must
/// be `None`, and a value must decode to that value: that is what keeps "explicitly
/// `None`" and "silently omitted" different facts
/// (`docs/architecture/I05-16-common-durable-fields.md:46`).
///
/// The parameter is `Option<&T>`, not `&Option<T>`: this helper OWNS its signature
/// (it is private to this file and every call site is below), and a borrow of an
/// `Option` is the shape clippy rejects because it cannot be `None`-checked without
/// a deref. Callers pass `field.as_ref()`, which borrows exactly the same member.
fn assert_nullable_member_agrees<T>(decoded: Option<&T>, member: &str, document: &str)
where
    T: serde::Serialize,
{
    let stored = member_value(document, member);
    assert_eq!(
        serde_json::to_value(decoded).expect("an Option member must re-encode"),
        stored,
        "the decoded `{member}` must agree with the document's own value for it"
    );
    if stored.is_null() {
        assert!(
            decoded.is_none(),
            "an explicit `null` for `{member}` must decode to `None`: a field that does not apply \
             remains an explicit `None` and is not silently omitted \
             (docs/architecture/I05-16-common-durable-fields.md:46)"
        );
    }
}

/// The type name and the repository-relative source file a scope probe's own
/// `message` names, read back OUT OF THE FIXTURE so this file types neither.
///
/// The expected shape is `<TypeName> is real at <path>.rs:<line>`, with the line
/// optional in the text that follows. `None` when the message does not carry that
/// shape, which is a fixture defect rather than a production one.
fn probe_claim(message: &str) -> Option<(String, String)> {
    let (before, after) = message.split_once(" is real at ")?;
    let type_name = before.split_whitespace().last()?.to_owned();
    let path = after
        .split(':')
        .next()?
        .trim()
        .trim_end_matches('.')
        .to_owned();
    if type_name.is_empty() || path.is_empty() {
        return None;
    }
    Some((type_name, path))
}

/// Every ATTRIBUTE BLOCK in `source`, one entry per declaration, with a multi-line
/// `#[serde(...)]` joined into the single text it really is.
///
/// This exists because a raw substring scan cannot answer "does any declaration carry
/// this attribute". `crates/eliot-types/src/safety.rs:775` writes "no
/// `#[serde(alias)]`" inside a DOC COMMENT in order to deny the alias, and a scan of
/// raw text reads that denial as an occurrence. A doc comment never starts with
/// `#[`, so requiring that a block's first trimmed line does is what separates a
/// declaration from prose about one.
fn attribute_blocks(source: &str) -> Vec<String> {
    let mut blocks: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for line in source.lines() {
        match current.as_mut() {
            Some(block) => {
                block.push_str(line);
                block.push('\n');
                if attribute_is_closed(block) {
                    blocks.push(current.take().unwrap_or_default());
                }
            }
            None => {
                if line.trim_start().starts_with("#[") {
                    current = Some(format!("{line}\n"));
                    if attribute_is_closed(current.as_deref().unwrap_or_default()) {
                        blocks.push(current.take().unwrap_or_default());
                    }
                }
            }
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }
    blocks
}

/// Whether an attribute block's brackets are balanced, i.e. the block is complete.
fn attribute_is_closed(block: &str) -> bool {
    block.matches('[').count() == block.matches(']').count()
}

/// The `#[...]` attribute lines immediately above `declaration`, as one text.
///
/// Only lines that literally start with `#[` are collected, walking upwards until
/// the first line that does not - so a DOC COMMENT above the attributes is never
/// read as an attribute, and a `serde(default)` mentioned inside prose cannot be
/// mistaken for one. That distinction is what makes the `sd8` and case-10
/// assertions about members with long disposition comments exact.
///
/// `declaration` MAY SIT IN THE MIDDLE OF A LINE - a struct FIELD is indented, so the
/// text before it ends with that field's own indentation rather than with a newline.
/// `str::lines()` yields that trailing fragment as a final element, so walking
/// `lines().rev()` from it sees an item that is not a line at all, decides it is not an
/// attribute and stops - collecting nothing. An earlier version had exactly that bug:
/// it worked for every TOP-LEVEL `pub struct`/`pub enum` (whose declaration starts at
/// column 0, where there is no fragment) and silently returned an empty string for every
/// FIELD. That made a positive field assertion fail and a negated one pass for the wrong
/// reason. The partial line is therefore dropped before the walk upwards.
fn attributes_above(source: &str, declaration: &str) -> String {
    let at = source
        .find(declaration)
        .unwrap_or_else(|| panic!("the production file must declare `{declaration}`"));
    let mut head = &source[..at];
    if !head.is_empty() && !head.ends_with('\n') {
        // Drop the remainder of the line the declaration sits on, keeping the newline
        // that ends the line before it.
        head = &head[..head.rfind('\n').unwrap_or(0)];
    }
    let mut collected: Vec<&str> = Vec::new();
    for line in head.lines().rev() {
        if line.trim_start().starts_with("#[") {
            collected.push(line.trim());
            continue;
        }
        break;
    }
    collected.reverse();
    collected.join("\n")
}

/// Whether the production text declares `declaration` immediately under an
/// attribute carrying `attribute`, e.g. `deny_unknown_fields` or
/// `rename_all = "snake_case"`. Read from the source rather than asserted through
/// a document, because "closed" and "spelled this way" are declaration
/// properties.
fn declaration_carries(source: &str, declaration: &str, attribute: &str) -> bool {
    attributes_above(source, declaration).contains(attribute)
}

/// `symbol`'s declaration line plus the following lines of its own file, up to
/// `lines` of them. Used to read a PRODUCTION CALLER's gate without editing it.
fn declaration_window(source: &str, symbol: &str, lines: usize) -> String {
    let at = source
        .find(symbol)
        .unwrap_or_else(|| panic!("the production file must declare `{symbol}`"));
    source
        .lines()
        .skip(source[..at].lines().count().saturating_sub(1))
        .take(lines)
        .collect::<Vec<&str>>()
        .join("\n")
}

/// Every `pub <member>` declaration in `source` that carries `#[serde(default` on
/// the attribute line immediately above it, in file order. This is how case 13
/// checks the container's `rp` rows against the real source instead of against a
/// list typed here: if a `replay.rs` default is added or removed, the set changes
/// and the container's rows stop matching it.
fn defaulted_members(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut members = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("#[serde(default") {
            continue;
        }
        for follow in lines.iter().skip(index + 1) {
            let Some(rest) = follow.trim_start().strip_prefix("pub ") else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            if !name.is_empty() {
                members.push(name);
            }
            break;
        }
    }
    members
}

/// The one `ReplayRun` document the corpus stores, with its status corrected to a
/// spelling the closed enum really declares, so a replay identity can be compared
/// as bytes. The spelling is DERIVED from the production enum, not typed here.
fn accepted_replay_run_document() -> String {
    let replay = production_text("crates/eliot-types/src/replay.rs");
    assert!(
        declaration_carries(
            &replay,
            "pub enum ReplayRunStatus",
            "rename_all = \"snake_case\""
        ),
        "crates/eliot-types/src/replay.rs: `ReplayRunStatus` must stay a snake_case closed enum"
    );
    let legal = enum_variants(&replay, "pub enum ReplayRunStatus");
    let spelling = legal
        .iter()
        .map(|variant| camel_to_snake(variant))
        .find(|spelling| spelling == "completed")
        .unwrap_or_else(|| {
            panic!("`ReplayRunStatus` must declare a `Completed` variant; measured: {legal:?}")
        });
    with_top_level_member_replaced(
        &raw("c6_replay_unknown_status_variant_refuse"),
        REPLAY_STATUS,
        &format!("\"{spelling}\""),
    )
}

/// The one `ExperienceFormationResult` document the corpus stores, with its
/// `outcome` tag corrected to the variant whose payload it actually carries, so the
/// internally tagged enum has an ACCEPTED counterpart for the refused one.
fn accepted_formation_result_document() -> String {
    with_top_level_member_replaced(
        &raw("c6_semantic_memory_wrong_outcome_payload_refuse"),
        OUTCOME_TAG,
        "\"nothing_to_learn\"",
    )
}

// ---------------------------------------------------------------------------
// Case 1 - the four-file, type and exception accounting.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c1_allocation_complete
#[test]
fn c1_allocation_complete() {
    // (a) The container itself, on the shape its writer's brief fixes.
    let container = corpus();
    let meta = container
        .get("meta")
        .unwrap_or_else(|| panic!("the corpus must carry `meta`"));
    let mut meta_keys: Vec<&str> = meta.as_object().map_or_else(
        || panic!("`meta` must be a JSON object"),
        |object| object.keys().map(String::as_str).collect(),
    );
    meta_keys.sort_unstable();
    assert_eq!(
        meta_keys,
        vec![
            "allocated_type_count",
            "case_count",
            "family",
            "inventory",
            "issue",
            "raw_bytes_rule",
            "types",
        ],
        "`meta` must carry exactly its seven documented keys. There is deliberately NO \
         `known_unused` list, so the coverage oracle of this file is `SOURCE` plus the \
         container's own `fixtures` key set, and an assertion requiring a `known_unused` list \
         would be asserting a key that does not exist"
    );
    assert_eq!(
        meta.get("issue").and_then(serde_json::Value::as_u64),
        Some(938),
        "the corpus must name issue 938"
    );
    assert_eq!(
        meta.get("family").and_then(serde_json::Value::as_str),
        Some("T09"),
        "the corpus must name family T09"
    );
    assert_eq!(
        meta.get("case_count").and_then(serde_json::Value::as_u64),
        Some(16),
        "the corpus must record the sixteen preserved acceptance cases"
    );
    assert_eq!(
        meta.get("allocated_type_count")
            .and_then(serde_json::Value::as_u64),
        Some(160),
        "the corpus must record the 160 allocated types"
    );
    assert!(
        meta.get("inventory")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .contains("#938"),
        "the corpus must name the frozen inventory allocation it claims to cover"
    );
    assert!(
        meta.get("raw_bytes_rule")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .contains("string"),
        "the corpus must record the raw-bytes rule: a repeated member survives only inside a \
         string"
    );
    let types = meta_types();
    assert_eq!(
        types.len(),
        160,
        "`meta.types` must name the 160 allocated types the frozen row counts"
    );
    assert_eq!(
        types.first().map(String::as_str),
        Some("ApplicabilityVerdict"),
        "`meta.types` must begin with the first name of the frozen row"
    );
    assert_eq!(
        types.last().map(String::as_str),
        Some("VerifiedEpisodeProjection"),
        "`meta.types` must end with the last name of the frozen row"
    );
    let mut unique = types.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        types.len(),
        "`meta.types` must not repeat a type: the allocated list is a set"
    );
    // NO SILENT ORPHANS, against the file and the container.
    assert_no_silent_orphans();
    let mut top_level_keys: Vec<&str> = container.as_object().map_or_else(
        || panic!("the corpus must be a JSON object"),
        |object| object.keys().map(String::as_str).collect(),
    );
    top_level_keys.sort_unstable();
    assert_eq!(
        top_level_keys,
        vec!["fixtures", "known_non_clean", "meta"],
        "the container must carry exactly `meta`, `fixtures` and `known_non_clean`"
    );
    // The ORDER claim, read from the container's own bytes and never from the
    // decoded map above, which cannot carry it.
    let stored = corpus_text();
    let offset_of = |key: &str| {
        let token = format!("\"{key}\"");
        stored
            .find(token.as_str())
            .unwrap_or_else(|| panic!("the container must carry a top-level key `{key}`"))
    };
    let (meta_at, fixtures_at, rows_at) = (
        offset_of("meta"),
        offset_of("fixtures"),
        offset_of("known_non_clean"),
    );
    assert!(
        meta_at < fixtures_at && fixtures_at < rows_at,
        "the container must physically carry `meta`, then `fixtures`, then `known_non_clean`. \
         Measured offsets were meta {meta_at}, fixtures {fixtures_at}, known_non_clean {rows_at}"
    );

    // (b) The sixteen markers, read out of this file's OWN text.
    assert_case_binding("938/c1_allocation_complete", &[]);
    let mut markers_seen: Vec<&str> = CASE_MARKERS.to_vec();
    markers_seen.sort_unstable();
    let mut unique_markers = markers_seen.clone();
    unique_markers.dedup();
    assert_eq!(
        unique_markers.len(),
        CASE_MARKERS.len(),
        "this file must carry sixteen DISTINCT case markers"
    );
    for marker in CASE_MARKERS {
        let line = format!("// WORK_UNIT_CASE: {marker}");
        assert_eq!(
            SOURCE.matches(line.as_str()).count(),
            1,
            "the marker line `{line}` must appear exactly once in this file: one marker per case, \
             no duplicates and no renamed slugs"
        );
        let slug = marker.split_once('/').map_or("", |(_, slug)| slug);
        assert!(
            SOURCE.contains(&format!("fn {slug}(")),
            "the marker {marker} must sit above the `#[test]` function named after its slug"
        );
    }

    // (c) The frozen allocation row itself: the four production files, the
    // family, the row count and the readiness this issue does not flip.
    let inventory = repository_text(
        "crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml",
    );
    let allocation_start = inventory
        .find("child = \"#938\"")
        .unwrap_or_else(|| panic!("the frozen inventory must carry the `child = \"#938\"` row"));
    let allocation = inventory[allocation_start..]
        .split("\n[[allocations]]")
        .next()
        .unwrap_or_default();
    assert!(
        allocation.contains("family = \"T09\""),
        "the #938 allocation row must name family T09"
    );
    assert!(
        allocation.contains("row_count = 160"),
        "the #938 allocation row must count 160 allocated types"
    );
    for source_file in [
        "crates/eliot-types/src/distillation.rs",
        "crates/eliot-types/src/replay.rs",
        "crates/eliot-types/src/safety.rs",
        "crates/eliot-types/src/semantic_memory.rs",
    ] {
        assert!(
            allocation.contains(&format!("\"{source_file}\"")),
            "the #938 allocation row must name {source_file} as one of its four source files"
        );
        // Read it, so a row naming a file that is not there fails here.
        let _ = production_text(source_file);
    }
    assert!(
        allocation.contains("readiness = \"READY_FOR_REPAIR\""),
        "the #938 allocation row must still read READY_FOR_REPAIR: this issue does not flip the \
         frozen inventory, which belongs to #929"
    );
    // RECORDED, NOT DEMANDED. The frozen row and `scripts/serde_boundary_inventory.py`
    // are card READ ONLY and their regeneration belongs to #929, so this card cannot
    // produce an UNPLANNED marker and an earlier version demanded one - an assertion
    // that can never pass in this work unit. The claim this file CAN make, and does,
    // is the measured state: the row names THIS suite as its test file, whatever
    // lifecycle marker it currently carries, and the marker is reported verbatim so
    // the gap is visible rather than asserted away.
    let test_file_line = allocation
        .lines()
        .find(|line| line.trim_start().starts_with("test_files"))
        .unwrap_or_else(|| {
            panic!("the #938 allocation row must carry a `test_files` entry naming this suite")
        });
    assert!(
        test_file_line.contains(SELF_TEST_FILE),
        "the #938 allocation row must name THIS suite (`{SELF_TEST_FILE}`) as its test file. \
         Measured line: {test_file_line}"
    );
    let planned = test_file_line.contains(":planned");
    let recorded_test_bytes = allocation
        .lines()
        .find(|line| line.trim_start().starts_with("test_bytes"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    // WHAT IS TRUE AND THIS CARD OWNS: a row that marks the suite `:planned` must
    // also record zero bytes for it. That is internally consistent today, and it is
    // the one thing about the marker this file can check without demanding a
    // regeneration that belongs to #929. The `:planned` marker itself is a RECORDED
    // gap, reported here and owned by #929 - the inventory and
    // `scripts/serde_boundary_inventory.py` are card READ ONLY, so this work unit
    // cannot and must not remove it.
    if planned {
        assert!(
            recorded_test_bytes.ends_with("= 0"),
            "a `:planned` test file must be recorded with zero bytes, or the row is inconsistent \
             with its own marker. Measured `test_files`: {test_file_line}; measured \
             `{recorded_test_bytes}`"
        );
    }

    // (d) The four-file allocation, proved by DECODING one representative record
    // per production file out of raw stored text, not by the existence of a file.
    // `meta.types` must record each representative as allocated.
    for (type_name, production_file) in [
        ("BackupManifest", "crates/eliot-types/src/safety.rs"),
        ("ReplayRun", "crates/eliot-types/src/replay.rs"),
        (
            "MemoryUtilitySourceRecord",
            "crates/eliot-types/src/distillation.rs",
        ),
        (
            "TaskMeaningFrame",
            "crates/eliot-types/src/semantic_memory.rs",
        ),
    ] {
        assert!(
            types.iter().any(|name| name == type_name),
            "{type_name} must be one of the 160 allocated names the container records, because it \
             is the representative of {production_file}"
        );
    }
    let manifest: BackupManifest = decode(&raw("c2_BackupManifest_canonical"))
        .expect("src/safety.rs: the canonical BackupManifest must decode");
    assert_eq!(
        manifest.backup_id,
        member_text(&raw("c2_BackupManifest_canonical"), DUPLICATE_BACKUP_ID),
        "src/safety.rs: the decoded manifest must carry the document's own backup_id"
    );
    let run: ReplayRun = decode(&accepted_replay_run_document()).expect(
        "src/replay.rs: the stored ReplayRun document must decode once its status is legal",
    );
    assert!(
        !run.sealed_input_hash.is_empty() && !run.reproducibility_hash.is_empty(),
        "src/replay.rs: the decoded ReplayRun must carry its own two replay-identity hashes"
    );
    let formed: ExperienceFormationResult = decode(&accepted_formation_result_document()).expect(
        "src/semantic_memory.rs: the stored result document must decode once its tag matches \
                 its payload",
    );
    assert!(
        serde_json::to_value(&formed)
            .expect("a result must re-encode")
            .get(OUTCOME_TAG)
            .is_some(),
        "src/semantic_memory.rs: the decoded result must carry its own `outcome` tag"
    );
    let source_record: MemoryUtilitySourceRecord = decode(&raw(
        "c11_ledger_value_payload_mentions_restore_decodes_inert",
    ))
    .expect("src/distillation.rs: the stored source record must decode");
    assert_eq!(
        source_record.record_ref,
        member_text(
            &raw("c11_ledger_value_payload_mentions_restore_decodes_inert"),
            "record_ref"
        ),
        "src/distillation.rs: the decoded source record must carry the document's own record_ref"
    );

    // (e) The declaration properties this delivery had to preserve, read from the
    // production source text.
    let safety = production_text("crates/eliot-types/src/safety.rs");
    let replay = production_text("crates/eliot-types/src/replay.rs");
    let semantic = production_text("crates/eliot-types/src/semantic_memory.rs");
    let distillation = production_text("crates/eliot-types/src/distillation.rs");
    for (source, declaration) in [
        (&safety, "pub struct BackupManifest"),
        (&safety, "pub struct BackupChecksum"),
        (&safety, "pub struct RestorePlan"),
        (&safety, "pub struct RestoreReceipt"),
        (&semantic, "pub struct TaskMeaningFrame"),
        (&semantic, "pub struct ExperienceProblemFrame"),
        (&replay, "pub struct ReplayRun"),
        (&distillation, "pub struct MemoryUtilitySourceRecord"),
    ] {
        assert!(
            declaration_carries(source, declaration, "deny_unknown_fields"),
            "{declaration} must carry `deny_unknown_fields`: an ordinary closed record is what \
             makes an unknown protected field a refusal at all"
        );
    }
    assert!(
        safety.contains("fn deserialize_manifest_schema_version"),
        "src/safety.rs: the manifest's decoder-pinned version hook must exist; case 8 exercises it"
    );
    assert!(
        safety.contains("fn deserialize_required_nullable"),
        "src/safety.rs: the refusing decoder the effect-bearing members carry must exist; case 7 \
         exercises it"
    );
    for path in [
        "crates/eliot-types/src/semantic_memory.rs",
        "crates/eliot-types/src/distillation.rs",
    ] {
        let source = if path.ends_with("semantic_memory.rs") {
            &semantic
        } else {
            &distillation
        };
        assert!(
            source.contains("fn deserialize_strict_btree_map"),
            "{path}: the private duplicate-rejecting map visitor must exist; case 5 exercises it"
        );
    }
    assert_eq!(
        semantic.matches("tag = \"outcome\"").count(),
        2,
        "src/semantic_memory.rs: `ExperienceFormationResult` and `ContrastiveAbstractionResult` \
         must both stay internally tagged on `outcome`; case 6 exercises the tag/payload refusal"
    );
    let screaming = "rename_all = \"SCREAMING_SNAKE_CASE\"";
    assert_eq!(
        semantic.matches(screaming).count(),
        1,
        "src/semantic_memory.rs: exactly ONE enum may carry the SCREAMING_SNAKE_CASE spelling"
    );
    assert!(
        declaration_carries(&semantic, "pub enum ExperienceMaturityState", screaming),
        "src/semantic_memory.rs: `ExperienceMaturityState` must keep its SCREAMING_SNAKE_CASE \
         spelling while its neighbours are snake_case"
    );
    // The two spellings really do differ for the SAME variant, so the attribute is
    // load-bearing and this delivery preserved a wire difference rather than a
    // cosmetic one.
    let maturity = enum_variants(&semantic, "pub enum ExperienceMaturityState");
    let first_variant = maturity.first().unwrap_or_else(|| {
        panic!("`ExperienceMaturityState` must declare a variant: {maturity:?}")
    });
    assert_ne!(
        camel_to_screaming_snake(first_variant),
        camel_to_snake(first_variant),
        "the SCREAMING_SNAKE_CASE spelling of `{first_variant}` must differ from its snake_case \
         spelling, or the preserved attribute is not load-bearing"
    );
    for neighbour in ["pub enum MemoryKind", "pub enum MemoryNeed"] {
        assert!(
            declaration_carries(&semantic, neighbour, "rename_all = \"snake_case\""),
            "src/semantic_memory.rs: {neighbour} must stay snake_case, so the two spellings really \
             do differ and this delivery preserved both"
        );
    }
}

// ---------------------------------------------------------------------------
// Case 2 - accepted canonical bytes, replay identity and digest material.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c2_unchanged_valid_bytes
#[test]
fn c2_unchanged_valid_bytes() {
    // Every type this case reads must be one the CONTAINER binds to case 2 by its
    // own `c2_<Type>_canonical` key, and no other type may be bound, so this
    // const can neither name a type with no canonical document nor leave one this
    // case should have read.
    assert_case_binding("938/c2_unchanged_valid_bytes", &CASE2_BOUND_TYPES);

    // (a) The three `sd`-row safety records, compared as BYTES against their own
    // stored text. `IncidentRecord` is handled by the round-trip identity check
    // below because its `campaign_integrity` member is a large nested record whose
    // member order this file does not pin.
    assert_bytes_unchanged::<BackupManifest>(
        "BackupManifest",
        "c2_BackupManifest_canonical",
        &raw("c2_BackupManifest_canonical"),
    );
    assert_bytes_unchanged::<RestorePlan>(
        "RestorePlan",
        "c2_RestorePlan_canonical",
        &raw("c2_RestorePlan_canonical"),
    );
    assert_bytes_unchanged::<RestoreReceipt>(
        "RestoreReceipt",
        "c2_RestoreReceipt_canonical",
        &raw("c2_RestoreReceipt_canonical"),
    );
    assert_round_trip_identical::<IncidentRecord>(
        &raw("c2_IncidentRecord_canonical"),
        "c2_IncidentRecord_canonical",
    );

    // (b) The replay identity and the canonical digest material: `ReplayRun`'s two
    // hash members carry NO wire default
    // (`crates/eliot-types/src/replay.rs:151-153`), so the accepted document
    // carries them and re-encoding reproduces them byte for byte.
    let replay_document = accepted_replay_run_document();
    assert_bytes_unchanged::<ReplayRun>(
        "ReplayRun",
        "the stored ReplayRun document with a legal status",
        &replay_document,
    );
    let run: ReplayRun =
        decode(&replay_document).expect("the accepted replay document must decode");
    for (hash_member, decoded) in [
        ("sealed_input_hash", run.sealed_input_hash.clone()),
        ("reproducibility_hash", run.reproducibility_hash.clone()),
    ] {
        assert_eq!(
            repeats(&replay_document, hash_member),
            1,
            "the accepted ReplayRun document must carry `{hash_member}` exactly once"
        );
        assert_eq!(
            decoded,
            member_text(&replay_document, hash_member),
            "the decoded ReplayRun must carry its own `{hash_member}`, unchanged: those members \
             carry no wire default, so an absent one cannot pass for a sealed one"
        );
    }
    // The internally tagged result enum keeps its wire shape byte for byte, tag
    // included.
    assert_bytes_unchanged::<ExperienceFormationResult>(
        "ExperienceFormationResult",
        "the stored result document with its tag matched to its payload",
        &accepted_formation_result_document(),
    );
    // A distillation candidate keeps its bytes too, `automatic_apply_allowed`
    // included.
    assert_bytes_unchanged::<MemoryDistillationCandidate>(
        "MemoryDistillationCandidate",
        "c12_distillation_candidate_automatic_apply_allowed_inert",
        &raw("c12_distillation_candidate_automatic_apply_allowed_inert"),
    );
    // (c) Every stored canonical this file reads BY CONSTRUCTION rather than by
    // name is checked to be a real JSON document, so the derived family is not an
    // unexamined hole.
    let constructed = constructed_canonical_names(&meta_types());
    for key in container_fixture_keys() {
        if !constructed.contains(&key) {
            continue;
        }
        let document = raw(&key);
        let parsed = witness(&document);
        assert!(
            parsed.is_object() || parsed.is_string(),
            "{key} must be a JSON object or a bare variant string"
        );
    }
}

// ---------------------------------------------------------------------------
// Case 3 - an unknown OUTER protected field is refused.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c3_unknown_outer_field_refused
#[test]
fn c3_unknown_outer_field_refused() {
    assert_case_binding("938/c3_unknown_outer_field_refused", &[]);
    // The ordinary envelope is closed: `BackupManifest` declares
    // `deny_unknown_fields` (`crates/eliot-types/src/safety.rs:121`), which is
    // what makes an unknown outer member a refusal instead of a silently dropped
    // field.
    assert!(
        declaration_carries(
            &production_text("crates/eliot-types/src/safety.rs"),
            "pub struct BackupManifest",
            "deny_unknown_fields"
        ),
        "src/safety.rs: BackupManifest must stay closed for an unknown outer member to refuse"
    );
    let canonical = raw("c2_BackupManifest_canonical");
    let injected = raw("c3_safety_unknown_outer_member_refuse");
    let member = assert_unknown_member_refused::<BackupManifest>(
        &injected,
        &canonical,
        "c3_safety_unknown_outer_member_refuse",
    );
    assert!(
        !top_level_members(&canonical).contains(&member),
        "the injected member `{member}` must be a NEW outer member, which is case 3's claim"
    );
    // The CONTROL, spelled out here: the same type accepts the canonical document
    // and carries its own `backup_id`, so the refusal above is caused by the
    // injected member and not by an otherwise-broken fixture.
    let accepted: BackupManifest = decode(&canonical).expect("the canonical manifest must decode");
    assert_eq!(
        accepted.backup_id,
        member_text(&canonical, DUPLICATE_BACKUP_ID),
        "the accepted counterpart must carry the document's own backup_id"
    );
}

// ---------------------------------------------------------------------------
// Case 4 - an unknown NESTED protected field is refused.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c4_unknown_nested_field_refused
#[test]
fn c4_unknown_nested_field_refused() {
    assert_case_binding("938/c4_unknown_nested_field_refused", &[]);
    // The NESTED owner type carries the refusal, not the envelope:
    // `BackupChecksum` is closed at `crates/eliot-types/src/safety.rs:233-235`.
    assert!(
        declaration_carries(
            &production_text("crates/eliot-types/src/safety.rs"),
            "pub struct BackupChecksum",
            "deny_unknown_fields"
        ),
        "src/safety.rs: BackupChecksum must stay closed for a nested unknown member to refuse"
    );
    let canonical = raw("c2_BackupManifest_canonical");
    let injected = raw("c4_safety_unknown_nested_member_refuse");
    let member = assert_unknown_member_refused::<BackupManifest>(
        &injected,
        &canonical,
        "c4_safety_unknown_nested_member_refuse",
    );
    // DEPTH TWO, proved from the fixture's own bytes: the member the refusal names
    // is inside the first `checksums` entry and is not a member of the envelope.
    assert!(
        !top_level_members(&injected).contains(&member),
        "the injected member `{member}` must NOT be at the outer level, which is case 3's claim"
    );
    assert!(
        first_entry_members(&injected, CHECKSUMS_MEMBER).contains(&member),
        "the injected member `{member}` must sit inside the first `checksums` entry, so the \
         refusal comes from the nested owner's own closure"
    );
    assert!(
        !first_entry_members(&canonical, CHECKSUMS_MEMBER).contains(&member),
        "the accepted canonical's first `checksums` entry must not carry `{member}`: the two \
         documents differ by that one nested member"
    );
    let accepted: BackupManifest = decode(&canonical).expect("the canonical manifest must decode");
    assert!(
        !accepted.checksums.is_empty(),
        "the canonical manifest must carry at least one checksum, or there is no depth-two level \
         to inject into"
    );
}

// ---------------------------------------------------------------------------
// Case 5 - duplicate keys, from RAW BYTES only.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c5_duplicate_keys_refused
#[test]
fn c5_duplicate_keys_refused() {
    assert_case_binding("938/c5_duplicate_keys_refused", &[]);

    // (a) A repeated MAP key is REFUSED, and this is one of the two duplicate
    // shapes the delivered decoders really do refuse:
    // `TaskMeaningFrame::entity_roles` goes through the private
    // `deserialize_strict_btree_map`
    // (`crates/eliot-types/src/semantic_memory.rs:16`, applied at `:264-265`),
    // whose visitor errors with `duplicate map key` BEFORE the entry is inserted
    // (`semantic_memory.rs:41-46`).
    let entity_roles_document = raw("c5_frame_duplicate_entity_role_key_refuse");
    assert_eq!(
        repeats(&entity_roles_document, DUPLICATE_ENTITY_ROLE_KEY),
        2,
        "c5_frame_duplicate_entity_role_key_refuse must carry `\"{DUPLICATE_ENTITY_ROLE_KEY}\"` \
         exactly twice, or it is not the counterexample this case is about"
    );
    let Err(error) = decode::<TaskMeaningFrame>(&entity_roles_document) else {
        panic!("a repeated entity_roles map key must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains("duplicate map key"),
        "the repeated entity_roles key must be refused as `duplicate map key`, got: {message}"
    );

    // (b) The SHARED lexical decoder refuses all three counterexamples with the
    // same failure class: `strict_json_has_no_duplicate_members`
    // (`crates/eliot-types/src/strict_json.rs:118`) observes members through
    // `MapAccess` before any `Value` exists (`strict_json.rs:194-205`).
    for (fixture, member) in [
        ("c5_safety_duplicate_backup_id_refuse", DUPLICATE_BACKUP_ID),
        ("c5_frame_duplicate_task_id_refuse", DUPLICATE_TASK_ID),
        (
            "c5_frame_duplicate_entity_role_key_refuse",
            DUPLICATE_ENTITY_ROLE_KEY,
        ),
    ] {
        let document = raw(fixture);
        assert_eq!(
            repeats(&document, member),
            2,
            "{fixture} must carry `\"{member}\"` exactly twice"
        );
        let Err(error) = strict_json_has_no_duplicate_members(document.as_bytes()) else {
            panic!("{fixture} is a lexical duplicate, so the shared decoder must refuse it");
        };
        assert_eq!(
            error.kind,
            StrictJsonErrorKind::DuplicateKey,
            "{fixture} must be refused by the shared decoder as a duplicate object member"
        );
    }

    // (c) THE OTHER DUPLICATE SHAPE, AT THE LAYER WHERE THE DERIVE REFUSES IT. A
    // repeated DECLARED member of the struct itself raises `duplicate field`, before
    // the repeated value is even read, and that is a property of the DERIVE and not
    // of `deny_unknown_fields`: `serde_derive` emits, once per derived field, an arm
    // that returns `Error::duplicate_field` when that field is already `Some`
    // (`serde_derive-1.0.229/src/de/struct_.rs:266-273`), and the check sits BEFORE
    // the visit (`:253-273`). The field's TYPE IS IRRELEVANT to it: a `null` sets
    // `Some(None)`, which is still `is_some`, so `Option`, `String`, `Value` and
    // `deserialize_with` fields all get the identical arm. `BackupManifest::backup_id`
    // (`crates/eliot-types/src/safety.rs:123`, attribute at `:121`) and
    // `TaskMeaningFrame::task_id` (`crates/eliot-types/src/semantic_memory.rs:257`,
    // attribute at `:255`) are plain derived `String` fields of a
    // `deny_unknown_fields` struct with no `flatten` and no `skip_deserializing`, so
    // both documents refuse. `duplicate field` is asserted here and
    // `duplicate map key` in (a) above, and the two are kept apart.
    assert_duplicate_field_refused::<BackupManifest>(
        &raw("c5_safety_duplicate_backup_id_refuse"),
        "c5_safety_duplicate_backup_id_refuse",
        DUPLICATE_BACKUP_ID,
    );
    assert_duplicate_field_refused::<TaskMeaningFrame>(
        &raw("c5_frame_duplicate_task_id_refuse"),
        "c5_frame_duplicate_task_id_refuse",
        DUPLICATE_TASK_ID,
    );
    // The two raw values are still proved DIFFERENT, so the refusal above is a
    // refusal of a real rewrite and not of two identical copies.
    for (fixture, member) in [
        ("c5_safety_duplicate_backup_id_refuse", DUPLICATE_BACKUP_ID),
        ("c5_frame_duplicate_task_id_refuse", DUPLICATE_TASK_ID),
    ] {
        let values = raw_string_values(&raw(fixture), member);
        assert_eq!(
            values.len(),
            2,
            "{fixture} must carry two raw `{member}` values"
        );
        assert_ne!(
            values[0], values[1],
            "{fixture}'s two `{member}` values must DIFFER, or nothing was being rewritten"
        );
    }

    // (d) LAST-WINS IS REAL IN EXACTLY ONE PLACE REACHABLE FROM HERE, and this is
    // that place: a key repeated INSIDE the object of a `serde_json::Value`-typed
    // member. `serde_json`'s own `Value` deserializer inserts each member with no
    // duplicate check (`serde_json-1.0.151/src/value/de.rs:139-142`) into a
    // `BTreeMap`-backed `Map`, so the earlier copy is dropped before any typed
    // decoder sees it. The repeated member is therefore BUILT HERE, as raw text,
    // inside the stored opaque payload - no fixture is invented and no `Value` ever
    // reaches a decoder on the way in. The three documented consequences are each
    // asserted: the raw text carries both copies, the lexical decoder still refuses,
    // and the typed decoder ACCEPTS and cannot see the repeat.
    let payload_fixture = "c11_ledger_value_payload_mentions_restore_decodes_inert";
    let payload_document = raw(payload_fixture);
    let repeated_payload_member = "text";
    let collapsed = with_repeated_nested_member(
        &payload_document,
        "payload",
        repeated_payload_member,
        "\"the erased first copy\"",
    );
    assert_eq!(
        repeats(&collapsed, repeated_payload_member),
        2,
        "the edited source record must carry `\"{repeated_payload_member}\"` twice inside its \
         `payload` object"
    );
    let Err(lexical) = strict_json_has_no_duplicate_members(collapsed.as_bytes()) else {
        panic!("the lexical decoder sees the repeat inside the payload object and must refuse it");
    };
    assert_eq!(
        lexical.kind,
        StrictJsonErrorKind::DuplicateKey,
        "the repeat inside the `Value` member must be visible to the lexical decoder"
    );
    let accepted_record: MemoryUtilitySourceRecord = decode(&collapsed).expect(
        "a repeat INSIDE a `Value` member is accepted: the declared type is \
                 `serde_json::Value`, which is the documented collapse exception this case records",
    );
    assert_eq!(
        accepted_record
            .payload
            .get(repeated_payload_member)
            .and_then(serde_json::Value::as_str),
        Some("the erased first copy"),
        "the decoded record must carry the LAST raw `payload.{repeated_payload_member}` value: a \
         `Value` member cannot express a repeat, so the typed decoder never sees one. \
         Recorded-not-fixed by the container's `c11_payload_value_duplicate_collapsed` row"
    );
}

// ---------------------------------------------------------------------------
// Case 6 - unknown variants and wrong payloads.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c6_wrong_or_unknown_tags_refused
#[test]
fn c6_wrong_or_unknown_tags_refused() {
    assert_case_binding("938/c6_wrong_or_unknown_tags_refused", &[]);

    // (a) An unknown `ReplayRunStatus` variant refuses: the enum is a plain
    // snake_case `enum` (`crates/eliot-types/src/replay.rs:180`) with no
    // `#[serde(other)]` arm, so an unknown spelling cannot become data. The legal
    // spellings are DERIVED from the production enum and the offending one is read
    // back out of the delivered message, so this file guesses neither.
    let replay = production_text("crates/eliot-types/src/replay.rs");
    let legal: Vec<String> = enum_variants(&replay, "pub enum ReplayRunStatus")
        .iter()
        .map(|variant| camel_to_snake(variant))
        .collect();
    assert!(
        !legal.is_empty(),
        "the legal ReplayRunStatus spellings must be derivable from the production source"
    );
    let unknown_status = raw("c6_replay_unknown_status_variant_refuse");
    let Err(error) = decode::<ReplayRun>(&unknown_status) else {
        panic!("an unknown ReplayRunStatus variant must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains("unknown variant"),
        "an unknown status variant must be refused as `unknown variant`, got: {message}"
    );
    let variant = quoted_member(&message, "unknown variant")
        .unwrap_or_else(|| panic!("the refusal must name the unknown variant, got: {message}"));
    assert_eq!(
        variant,
        member_text(&unknown_status, REPLAY_STATUS),
        "the refused variant must be exactly the document's own `status` token"
    );
    assert!(
        !legal.contains(&variant),
        "`{variant}` must not be one of the spellings `ReplayRunStatus` really declares \
         ({legal:?}); the delivered decoder refused it, so it must be outside the closed set"
    );
    // The CONTROL: the same document with a legal spelling decodes, so the refusal
    // above is caused by that one token and nothing else.
    let accepted_document = accepted_replay_run_document();
    let accepted: ReplayRun =
        decode(&accepted_document).expect("the corrected document must decode");
    let corrected_token = member_text(&accepted_document, REPLAY_STATUS);
    assert!(
        legal.contains(&corrected_token),
        "the corrected status `{corrected_token}` must be one of the spellings this file derived \
         from the source ({legal:?}), or the control proves nothing"
    );
    // COMPARED AS VALUES, NOT AS TEXT. `to_string` of a unit enum variant yields the
    // QUOTED wire form (`"completed"`), while `member_text` yields the document's own
    // unquoted token (`completed`), so comparing the two as strings could never hold and
    // the control was failing on quotation marks rather than on the claim. Both sides
    // are compared as `serde_json::Value`, which is the same comparison without the
    // encoding difference.
    assert_eq!(
        serde_json::to_value(&accepted.status).expect("a status must re-encode"),
        member_value(&accepted_document, REPLAY_STATUS),
        "the CONTROL: the corrected run decodes and carries the legal spelling, as a VALUE and \
         not as quoted text"
    );

    // (b) An internally tagged result enum whose tag and payload disagree refuses.
    // `ExperienceFormationResult`
    // (`crates/eliot-types/src/semantic_memory.rs:237-248`) is
    // `#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]` with
    // the single variant field `experience_case: Box<ExperienceCase>` (`:241-243`).
    //
    // THE INJECTED DEFECT HERE IS THE UNKNOWN KEY, NOT THE OMISSION. The stored
    // document is exactly `{"outcome":"formed","reason":"c6 tag and payload disagree"}`,
    // which carries TWO independent defects at once: `experience_case` is omitted AND
    // `reason` is a member of the OTHER variant. The refusal is `unknown field
    // \`reason\`, expected \`experience_case\`` because serde raises the two in a FIXED
    // ORDER, and the order is what decides which one is reported:
    //
    // - `deny_unknown_fields` is an IN-LOOP check: it fires the moment an unrecognised
    //   key is VISITED, while the derived `visit_map` is still walking the map.
    // - `missing field` is a POST-LOOP check: the derived code first consumes the whole
    //   map, collecting each declared field into an `Option`, and only afterwards asks
    //   whether any of them is still `None`.
    //
    // So a document that both omits a required member and carries an unknown member
    // ALWAYS refuses as `unknown field` first, and the omission can never be the
    // reported cause. Internally tagged enums sharpen this rather than soften it: the
    // tag and the remaining content are buffered and re-deserialized as a unit before
    // the variant is chosen, so the variant's own field set is what the `expected`
    // list names - which is why the message here names `experience_case` and not the
    // whole enum.
    //
    // `unknown field` is therefore the CORRECT refusal and the sharpest available one:
    // it names the offending key AND the exact field set the chosen variant accepts.
    // `assert_omitted_member_refused` is deliberately NOT used on this document: that
    // helper's precondition is that the ABSENCE is the injected defect, and here it is
    // not, so using it would demand a `missing field` refusal this decoder cannot
    // produce. The helper keeps its own semantics for the `c7` omission rows, where the
    // documents carry nothing unknown and nothing is preempted.
    let wrong_payload = raw("c6_semantic_memory_wrong_outcome_payload_refuse");
    assert!(
        !wrong_payload.contains(&format!("\"{FORMATION_CASE_MEMBER}\"")),
        "the wrong-payload document must really OMIT `{FORMATION_CASE_MEMBER}`, so that the \
         case exercises the disagreement between the tag and the payload it carries \
         instead of a document that is merely incomplete"
    );
    assert!(
        wrong_payload.contains(&format!("\"{OUTCOME_REASON_MEMBER}\"")),
        "the wrong-payload document must carry the payload member of the OTHER variant \
         (`{OUTCOME_REASON_MEMBER}`), or this is not a tag/payload disagreement"
    );
    let Err(unknown_payload) = decode::<ExperienceFormationResult>(&wrong_payload) else {
        panic!(
            "c6_semantic_memory_wrong_outcome_payload_refuse must be refused: its `outcome` tag \
             selects a variant whose payload does not declare the member the document carries"
        )
    };
    let unknown_payload_message = unknown_payload.to_string();
    assert!(
        unknown_payload_message.contains("unknown field"),
        "the refusal must be `unknown field`, which is the IN-LOOP `deny_unknown_fields` check \
         pre-empting the post-loop `missing field` check, got: {unknown_payload_message}"
    );
    assert!(
        unknown_payload_message.contains(OUTCOME_REASON_MEMBER),
        "the refusal must name the offending key `{OUTCOME_REASON_MEMBER}`, got: \
         {unknown_payload_message}"
    );
    assert!(
        unknown_payload_message.contains(FORMATION_CASE_MEMBER),
        "the refusal's `expected` list is the CHOSEN VARIANT's field set, so it must name \
         `{FORMATION_CASE_MEMBER}`: that is what makes this the sharpest available refusal, \
         because it states both the offending key and what the variant does accept, got: \
         {unknown_payload_message}"
    );
    assert!(
        !unknown_payload_message.contains("missing field"),
        "the omission of `{FORMATION_CASE_MEMBER}` must NOT be the reported cause here: \
         `deny_unknown_fields` fires in-loop and pre-empts the post-loop `missing field` \
         check, so a `missing field` message would mean a different mechanism ran. Got: \
         {unknown_payload_message}"
    );
    // The tag the refusal was about, read out of the document itself, so the CONTROL
    // below can show that the two tags really differ.
    let refused_tag = member_text(&wrong_payload, OUTCOME_TAG);
    // The CONTROL, built from raw text: the SAME bytes with the tag that matches
    // the payload decode, which is the whole content of the case.
    let corrected = accepted_formation_result_document();
    let formed: ExperienceFormationResult = decode(&corrected).unwrap_or_else(|accept_error| {
        panic!(
            "the same document with its tag corrected to the variant that declares \
                 `{OUTCOME_REASON_MEMBER}` must decode, or the refusal above was not caused by \
                 the tag/payload disagreement: {accept_error}"
        )
    });
    assert_eq!(
        serde_json::to_value(&formed)
            .expect("a result must re-encode")
            .get(OUTCOME_TAG)
            .cloned(),
        Some(member_value(&corrected, OUTCOME_TAG)),
        "the corrected document must decode as the variant its payload belongs to"
    );
    assert_ne!(
        refused_tag,
        member_text(&corrected, OUTCOME_TAG),
        "the refused tag and the corrected tag must differ, or nothing was corrected"
    );
}

// ---------------------------------------------------------------------------
// Case 7 - missing or empty protected identity.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c7_missing_or_empty_required_ids_refused
#[test]
fn c7_missing_or_empty_required_ids_refused() {
    assert_case_binding(
        "938/c7_missing_or_empty_required_ids_refused",
        &[
            "BackupManifest",
            "RestorePlan",
            "RestoreReceipt",
            "IncidentRecord",
        ],
    );

    // (a) The seven omitted effect-bearing members. Each is decoded through the
    // module-local `deserialize_required_nullable`
    // (`crates/eliot-types/src/safety.rs:112`), so an absent key is `missing
    // field` and the refusal names it, while an explicit `null` stays legal.
    // `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12`:
    // "authority, scope, effect, privacy, ordering and receipt fields are never
    // silently defaulted."
    let canonical_manifest = raw("c2_BackupManifest_canonical");
    for (fixture, member) in [
        (
            "c7_BackupManifest_surreal_source_endpoint_absent_refuse",
            SURREAL_SOURCE_ENDPOINT,
        ),
        (
            "c7_BackupManifest_surreal_source_storage_ref_absent_refuse",
            SURREAL_SOURCE_STORAGE_REF,
        ),
        (
            "c7_BackupManifest_blob_payload_root_absent_refuse",
            BLOB_PAYLOAD_ROOT,
        ),
    ] {
        assert_omitted_member_refused::<BackupManifest>(&raw(fixture), fixture, member);
    }
    let canonical_plan = raw("c2_RestorePlan_canonical");
    for (fixture, member) in [
        (
            "c7_RestorePlan_target_endpoint_absent_refuse",
            TARGET_ENDPOINT,
        ),
        (
            "c7_RestorePlan_target_storage_ref_absent_refuse",
            TARGET_STORAGE_REF,
        ),
        (
            "c7_RestorePlan_exact_action_hash_absent_refuse",
            EXACT_ACTION_HASH,
        ),
    ] {
        assert_omitted_member_refused::<RestorePlan>(&raw(fixture), fixture, member);
    }
    assert_omitted_member_refused::<RestoreReceipt>(
        &raw("c7_RestoreReceipt_exact_action_hash_absent_refuse"),
        "c7_RestoreReceipt_exact_action_hash_absent_refuse",
        EXACT_ACTION_HASH,
    );

    // (b) THE CONTROL for all seven, and the `None` clause of
    // `docs/architecture/I05-16-common-durable-fields.md:46`: the canonical document
    // carries the key - as a value OR as an explicit `null` - and the decoded
    // `Option` agrees with whichever of the two it is. An explicit `null` therefore
    // decodes to `None` and is NOT the same fact as an absent key.
    let manifest: BackupManifest =
        decode(&canonical_manifest).expect("the canonical manifest must decode");
    assert_nullable_member_agrees(
        manifest.surreal_source_endpoint.as_ref(),
        SURREAL_SOURCE_ENDPOINT,
        &canonical_manifest,
    );
    assert_nullable_member_agrees(
        manifest.surreal_source_storage_ref.as_ref(),
        SURREAL_SOURCE_STORAGE_REF,
        &canonical_manifest,
    );
    assert_nullable_member_agrees(
        manifest.blob_payload_root.as_ref(),
        BLOB_PAYLOAD_ROOT,
        &canonical_manifest,
    );
    let plan: RestorePlan =
        decode(&canonical_plan).expect("the canonical restore plan must decode");
    assert_nullable_member_agrees(
        plan.target_endpoint.as_ref(),
        TARGET_ENDPOINT,
        &canonical_plan,
    );
    assert_nullable_member_agrees(
        plan.target_storage_ref.as_ref(),
        TARGET_STORAGE_REF,
        &canonical_plan,
    );
    assert_nullable_member_agrees(
        plan.exact_action_hash.as_ref(),
        EXACT_ACTION_HASH,
        &canonical_plan,
    );
    let canonical_receipt = raw("c2_RestoreReceipt_canonical");
    let receipt: RestoreReceipt =
        decode(&canonical_receipt).expect("the canonical restore receipt must decode");
    assert_nullable_member_agrees(
        receipt.exact_action_hash.as_ref(),
        EXACT_ACTION_HASH,
        &canonical_receipt,
    );

    // (c) `IncidentRecord::campaign_integrity`, the `sd8` disposition row. The
    // document's name says `_absent_explicit_unknown`, and that is exactly what
    // the delivered decoder does: the member carries NEITHER `#[serde(default)]`
    // NOR the refusing decoder
    // (`crates/eliot-types/src/safety.rs:778`), so an absent key DECODES to an
    // explicit `None` - unknown, never a validity claim
    // (`docs/architecture/I05-16-common-durable-fields.md:44`). Asserting a refusal
    // here would be asserting one the delivered decoder does not perform.
    assert!(
        !declaration_carries(
            &production_text("crates/eliot-types/src/safety.rs"),
            "pub campaign_integrity:",
            "serde(default)"
        ),
        "src/safety.rs: the `sd8` disposition is that `campaign_integrity` carries no wire \
         default and no refusing decoder"
    );
    let canonical_incident = raw("c2_IncidentRecord_canonical");
    let incident: IncidentRecord =
        decode(&canonical_incident).expect("the canonical IncidentRecord must decode");
    assert_round_trip_identical::<IncidentRecord>(
        &canonical_incident,
        "c2_IncidentRecord_canonical",
    );
    assert!(
        witness(&canonical_incident)
            .get(CAMPAIGN_INTEGRITY)
            .is_some(),
        "the canonical IncidentRecord must carry `{CAMPAIGN_INTEGRITY}`"
    );
    let explicit_unknown_fixture = "c7_IncidentRecord_campaign_integrity_absent_explicit_unknown";
    let explicit_unknown = raw(explicit_unknown_fixture);
    assert!(
        !explicit_unknown.contains(&format!("\"{CAMPAIGN_INTEGRITY}\"")),
        "{explicit_unknown_fixture} must really OMIT `{CAMPAIGN_INTEGRITY}`"
    );
    let unknown: IncidentRecord = decode(&explicit_unknown).unwrap_or_else(|error| {
        panic!(
            "the recorded `sd8` disposition is that an absent `{CAMPAIGN_INTEGRITY}` decodes to an \
             explicit `None`; if that changed, this assertion must change with it and the \
             disposition must be reported: {error}"
        )
    });
    // THE DECODED FIELD, NOT THE RE-ENCODED DOCUMENT. An earlier version asserted on
    // `to_value(&unknown).get(CAMPAIGN_INTEGRITY).is_none()`, which asked the SERIALIZE
    // side to drop a key it is required to emit: `campaign_integrity` is a plain
    // `Option<T>` with no `skip_serializing_if`, so the re-encoded document carries
    // `"campaign_integrity": null` - which is the `I05-16:46` explicit-`None` rule
    // working, not a missing member. The claim belongs on the value the decoder
    // produced.
    assert!(
        unknown.campaign_integrity.is_none(),
        "an omitted `{CAMPAIGN_INTEGRITY}` must decode to an explicit `None` - unknown, never a \
         validity claim"
    );
    assert_eq!(
        serde_json::to_value(&unknown)
            .expect("an IncidentRecord must re-encode")
            .get(CAMPAIGN_INTEGRITY)
            .cloned(),
        Some(serde_json::Value::Null),
        "and the re-encoded record must then CARRY the member as an explicit `null`: a field that \
         does not apply remains an explicit `None` and is not silently omitted from the semantic \
         model (docs/architecture/I05-16-common-durable-fields.md:46)"
    );
    assert!(
        incident.campaign_integrity.is_some(),
        "the CONTROL: the canonical incident carries the member and its decode keeps it"
    );
    assert_eq!(
        serde_json::to_value(&incident)
            .expect("an IncidentRecord must re-encode")
            .get(CAMPAIGN_INTEGRITY)
            .map(serde_json::Value::is_object),
        Some(true),
        "the CONTROL's re-encoded member must be the campaign-integrity OBJECT, not a null"
    );
}

// ---------------------------------------------------------------------------
// Case 8 - an unsupported or misselected version cannot become valid input.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c8_unsupported_versions_refused
#[test]
fn c8_unsupported_versions_refused() {
    assert_case_binding("938/c8_unsupported_versions_refused", &[]);
    // THE NAMED ENFORCING BOUNDARY: `BackupManifest.schema_version` is pinned
    // INSIDE its `Deserialize` by `deserialize_manifest_schema_version`
    // (`crates/eliot-types/src/safety.rs:77-88`), which compares the member
    // against `crate::SCHEMA_VERSION` (`crates/eliot-types/src/lib.rs:499`) and
    // errors otherwise. Both directions of the misselection refuse.
    let canonical = raw("c2_BackupManifest_canonical");
    let accepted: BackupManifest = decode(&canonical).expect("the canonical manifest must decode");
    assert_eq!(
        member_text(&canonical, SCHEMA_VERSION_MEMBER),
        SCHEMA_VERSION,
        "the canonical manifest must carry the crate's adopted schema version, which is the only \
         value the decoder admits"
    );
    assert_eq!(
        accepted.schema_version, SCHEMA_VERSION,
        "the decoded manifest must carry that same version"
    );
    let misselected = raw("c8_manifest_misselected_schema_version_refuse");
    assert_ne!(
        misselected, canonical,
        "the misselected-version document must differ from the canonical one"
    );
    assert_ne!(
        member_text(&misselected, SCHEMA_VERSION_MEMBER),
        SCHEMA_VERSION,
        "the misselected document must really carry a version the decoder does not admit"
    );
    let Err(error) = decode::<BackupManifest>(&misselected) else {
        panic!("a misselected schema version must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains("unsupported backup manifest schema_version"),
        "the refusal must come from the manifest's own version hook, got: {message}"
    );
    assert!(
        message.contains(&member_text(&misselected, SCHEMA_VERSION_MEMBER)),
        "the refusal must name the rejected version, got: {message}"
    );
    // An ABSENT version member is refused by name, through the omission helper's
    // precondition, never through the injection helper's. The two refusals are
    // DIFFERENT and are kept apart here: the misselected row raises the custom pin
    // error from `deserialize_manifest_schema_version`
    // (`crates/eliot-types/src/safety.rs:83-85`), while the absent row raises serde's
    // own `missing field`, because `schema_version` carries `deserialize_with` with
    // NO `serde(default)` beside it (`:123-124`), so serde must find the key.
    let absent_version = raw("c8_manifest_missing_schema_version_refuse");
    assert_omitted_member_refused::<BackupManifest>(
        &absent_version,
        "c8_manifest_missing_schema_version_refuse",
        SCHEMA_VERSION_MEMBER,
    );
    let Err(absent_error) = decode::<BackupManifest>(&absent_version) else {
        panic!("an absent schema_version must be refused");
    };
    let absent_message = absent_error.to_string();
    assert!(
        !absent_message.contains("unsupported backup manifest schema_version"),
        "the absent-version refusal must be serde's own `missing field` and NOT the version pin: \
         the pin can only run on a value it has been given, and an omitted key gives it none. Got: \
         {absent_message}"
    );
    let misselected_message = error.to_string();
    assert!(
        !misselected_message.contains("missing field"),
        "the misselected-version refusal must come from the pin and NOT from an absent member, or \
         the two rows would be one refusal instead of two. Got: {misselected_message}"
    );

    // RECORDED, NOT INVENTED: the other version-shaped members of this family are
    // plain `String`s whose equality lives in a caller, so no decoder compares
    // them. `BackupManifest::governor_version`
    // (`crates/eliot-types/src/safety.rs:128`) is the one beside the enforced
    // member, and the restore records carry no version at all.
    let safety = production_text("crates/eliot-types/src/safety.rs");
    assert!(
        declaration_window(&safety, "pub governor_version:", 1).contains(": String"),
        "src/safety.rs: `governor_version` is a plain String whose comparison lives in a caller, \
         which is the fact case 8 records rather than asserts away"
    );
    for fixture in [
        "c2_RestorePlan_canonical",
        "c2_RestoreReceipt_canonical",
        "c2_IncidentRecord_canonical",
    ] {
        assert!(
            !top_level_members(&raw(fixture))
                .iter()
                .any(|member| member == SCHEMA_VERSION_MEMBER),
            "{fixture} must carry no `schema_version` member: `BackupManifest` is the only record \
             of this family with an enclosing version, and no version field is invented here"
        );
    }
}

// ---------------------------------------------------------------------------
// Case 9 - no trial migration was invented.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c9_recorded_absence_of_legacy_migration_surface
#[test]
fn c9_recorded_absence_of_legacy_migration_surface() {
    assert_case_binding("938/c9_recorded_absence_of_legacy_migration_surface", &[]);
    // Case 9's SUBJECT FOR THIS ISSUE IS THE RECORDED ABSENCE of any legacy
    // migration surface, and the container records that absence as one of its nine
    // `known_non_clean` rows. There is deliberately NO fixture for this case: the
    // issue's case-9 row reads "Named legacy migration preserves
    // provenance/loss/ceiling", and with no `alias`, no `rename` and no `flatten`
    // in the four allocated files there is no named legacy form to preserve
    // anything from, so inventing a migration document would invent the very thing
    // the row records as absent.
    let absence = row_by_id("c9_c10_no_legacy_migration_surface");
    let absence_text = |field: &str| -> String {
        absence
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                panic!("the `c9_c10_no_legacy_migration_surface` row must carry a text `{field}`")
            })
            .to_owned()
    };
    assert_eq!(
        absence.get("path").and_then(serde_json::Value::as_str),
        Some("crates/eliot-types/src/distillation.rs"),
        "the recorded-absence row must name the file it was measured on"
    );
    let property = absence_text("property").to_lowercase();
    let observed = absence_text("observed");
    let observed_lower = observed.to_lowercase();
    // THE ROW'S SUBSTANCE, NOT ITS WORDING. This row is an OBSERVABLE plus the
    // mechanisms that were searched, and this file asserts each of those four
    // mechanisms and the measured result, rather than any one phrase: the row was
    // legitimately re-worded from "no serde alias, no renamed member and no flatten"
    // to "anchored serde attribute lines containing alias ... returns ZERO hits",
    // which is STRONGER because it records HOW the search was anchored. A matcher
    // that pins the earlier wording would break the next honest edit of the row and
    // would be making this test dictate the corpus's prose.
    assert!(
        property.contains("cases 9 and 10") && property.contains("no fixture row"),
        "the row's own `property` must say that cases 9 and 10 have no fixture row, which is the \
         fact this case exists to hold in place; property says: {property}"
    );
    assert!(
        observed_lower.contains("observable") && observed_lower.contains("measured"),
        "the row must present its content as a measured OBSERVABLE plus the mechanism searched, \
         not as a verdict or a passed boolean; observed says: {observed}"
    );
    // The four alternative-spelling mechanisms, each of which the row reports as
    // returning ZERO hits: an alternate member name, flattened nesting, a wire
    // rename, and a hand-written Deserialize impl.
    for mechanism in ["alias", "flatten", "rename =", "deserialize"] {
        assert!(
            observed_lower.contains(mechanism),
            "the row must name the `{mechanism}` mechanism among those it searched, or the absence \
             is not recorded as searched: {observed}"
        );
    }
    assert!(
        observed_lower.contains("zero hits"),
        "the row must record the MEASURED result of each search - zero hits - rather than assert an \
         absence it never looked for: {observed}"
    );
    assert!(
        observed_lower.contains("in all four files"),
        "the row must scope its measurement to the whole allocated family, not to one file: {observed}"
    );
    // The anchoring, and WHY it matters: an unanchored search would match the
    // `serde(alias` token inside the sd8 disposition comment that DENIES the alias.
    assert!(
        observed_lower.contains("anchor"),
        "the row must say the search pattern was ANCHORED to an attribute position, which is what \
         makes a doc comment count as nothing: {observed}"
    );
    assert!(
        observed_lower.contains("denies the alias") || observed_lower.contains("denial"),
        "the row must record why anchoring was necessary - a doc comment denies the alias, so an \
         unanchored search would read a denial as evidence: {observed}"
    );
    let owner = absence_text("owner");
    for file in [
        "crates/eliot-types/src/distillation.rs",
        "crates/eliot-types/src/replay.rs",
        "crates/eliot-types/src/safety.rs",
        "crates/eliot-types/src/semantic_memory.rs",
    ] {
        assert!(
            owner.contains(file),
            "the recorded-absence row must name {file} as one of the four files measured, so the \
             absence is scoped to the whole allocated family; owner says: {owner}"
        );
    }
    let why = absence_text("why_it_is_recorded_and_not_fixed");
    let why_lower = why.to_lowercase();
    assert!(
        why_lower.contains("recorded"),
        "the row must say in its own words that the disposition is RECORDED rather than repaired, \
         which is what accounts for cases 9 and 10 without a fixture; it says: {why}"
    );
    assert!(
        why_lower.contains("cases 9 and 10"),
        "the row must name BOTH cases it accounts for, so neither is silently missing while \
         `meta.case_count` stays sixteen; it says: {why}"
    );
    assert!(
        why_lower.contains("no row is deleted"),
        "the row must state that nothing was deleted to suppress the gap, which is what makes the \
         absence a record rather than an erasure; it says: {why}"
    );

    // (a) The absence is ALSO measured here, from the PRODUCTION SOURCE rather than
    // accepted from the row: none of the four allocated files declares a
    // `serde(alias`, a `rename =` or a `flatten`, so there is no second spelling for
    // a version to select and nothing for a migration to interpret.
    for (path, declaration) in [
        (
            "crates/eliot-types/src/distillation.rs",
            "pub struct MemoryDistillationCandidate",
        ),
        ("crates/eliot-types/src/replay.rs", "pub struct ReplayRun"),
        ("crates/eliot-types/src/safety.rs", "pub struct RestorePlan"),
        (
            "crates/eliot-types/src/semantic_memory.rs",
            "pub struct TaskMeaningFrame",
        ),
    ] {
        let source = production_text(path);
        // ATTRIBUTE BLOCKS, never raw text: `crates/eliot-types/src/safety.rs:775`
        // writes "no `#[serde(alias)]`" inside a DOC COMMENT in order to deny the
        // alias, and a raw substring scan reads that denial as an occurrence.
        let attributes = attribute_blocks(&source);
        assert!(
            !attributes.is_empty(),
            "{path}: the file must declare attributes for this absence to mean anything"
        );
        for attribute in ["alias", "rename =", "flatten"] {
            let declared: Vec<&String> = attributes
                .iter()
                .filter(|block| block.contains(attribute))
                .collect();
            assert!(
                declared.is_empty(),
                "{path}: no ATTRIBUTE may carry `{attribute}`, or a legacy spelling exists and a \
                 versioned compatibility owner is required \
                 (docs/architecture/I05-22-schema-and-migration-rules.md:12). Measured: {declared:?}"
            );
        }
        assert!(
            declaration_carries(&source, declaration, "deny_unknown_fields"),
            "{path}: {declaration} must stay closed while cases 9 and 10 assert that no alias \
             surface exists"
        );
    }

    // (b) NO MIGRATION DOCUMENT EXISTS, in this case or anywhere in the corpus: any
    // stored key that claims one fails here. `c9_`, `c10_` and `c13_` are included
    // because cases 9, 10 and 13 are the three cases the container accounts for by
    // a recorded row instead of a document.
    let invented: Vec<String> = container_fixture_keys()
        .into_iter()
        .filter(|key| {
            key.starts_with("c9_")
                || key.starts_with("c10_")
                || key.starts_with("c13_")
                || key.contains("legacy")
                || key.contains("migration")
                || key.contains("alias")
        })
        .collect();
    assert!(
        invented.is_empty(),
        "no fixture key may claim a legacy or migration interpretation of this family, because \
         none is named, versioned or receipted: {invented:?}"
    );
    // CASE-INSENSITIVE: the substance is that the row names the ONE versioned surface in
    // the family, and it must be the member cases 7 and 8 already exercise. Spelling
    // `backupmanifest.schema_version` differently is not a different claim.
    assert!(
        observed_lower.contains("backupmanifest.schema_version"),
        "the row must record that the ONLY versioned surface in the family is \
         `BackupManifest.schema_version`, which cases 7 and 8 already exercise; a version select is \
         not a migration surface: {observed}"
    );
}

// ---------------------------------------------------------------------------
// Case 10 - the unsafe half of the same boundary: an absent protected
// identity, lineage or authority refuses.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c10_unsafe_absent_identity_or_lineage_refuses
#[test]
fn c10_unsafe_absent_identity_or_lineage_refuses() {
    assert_case_binding("938/c10_unsafe_absent_identity_or_lineage_refuses", &[]);

    // Case 10 shares case 9's RECORDED ABSENCE row: the issue's case-10 row reads
    // "Named legacy migration preserves provenance/loss/ceiling; unsafe missing
    // identity/lineage/authority refuses". With no alias, rename or flatten there
    // is no named legacy form whose provenance could be preserved, so this case
    // accounts for its half - the refusals - and there is deliberately NO fixture
    // for it. `TASK.md:53`: "Do not let default-empty identity/evidence satisfy a
    // current-task boundary."
    let absence = row_by_id("c9_c10_no_legacy_migration_surface");
    let why = absence
        .get("why_it_is_recorded_and_not_fixed")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| {
            panic!("the `c9_c10_no_legacy_migration_surface` row must carry a text `why` clause")
        })
        .to_owned();
    // LOWER-CASE THE HAYSTACK, not the needle: the row writes "Cases 9 and 10" with a
    // capital C, and matching a lower-case needle against the raw text failed on
    // wording alone. The substance asserted here is that the row accounts for BOTH
    // cases and says neither is silently missing.
    let why_lower = why.to_lowercase();
    assert!(
        why_lower.contains("cases 9 and 10"),
        "the recorded row must account for BOTH case 9 and case 10, so neither case is silently \
         missing while `meta.case_count` stays sixteen; it says: {why}"
    );
    assert!(
        why_lower.contains("not silently missing"),
        "the recorded row must say the two cases are NOT silently missing, which is what a \
         recorded observable buys; it says: {why}"
    );
    assert!(
        why_lower.contains("meta.case_count"),
        "the recorded row must tie the accounting to `meta.case_count`, so the sixteen cases stay \
         accounted for in total; it says: {why}"
    );

    // (a) What replaced the silent default, stated as a refusal: a formerly
    // wire-defaulted member that is now absent is `missing field`, and the decoder
    // offers NO interpretation of the omission. The absence of any migration
    // vocabulary in the refusal is the executable form of "nothing is upgraded
    // silently" (`TASK.md:54`, `I05-22:12`: "every migration produces schema
    // snapshot and receipt").
    let omission = raw("c7_RestorePlan_exact_action_hash_absent_refuse");
    assert_omitted_member_refused::<RestorePlan>(
        &omission,
        "c7_RestorePlan_exact_action_hash_absent_refuse",
        EXACT_ACTION_HASH,
    );
    let Err(error) = decode::<RestorePlan>(&omission) else {
        panic!("the omitted effect binding must be refused");
    };
    let message = error.to_string().to_lowercase();
    for vocabulary in ["legacy", "migrat", "upgrade", "default"] {
        assert!(
            !message.contains(vocabulary),
            "the refusal must be a plain missing-field refusal and must not mention \
             `{vocabulary}`: no silent upgrade or legacy interpretation exists. Got: {message}"
        );
    }
    // The CONTROL: the same document WITH the member present decodes and carries
    // it, so the omission is the only difference this file can see.
    let canonical_plan = raw("c2_RestorePlan_canonical");
    assert!(
        canonical_plan.contains(&format!("\"{EXACT_ACTION_HASH}\"")),
        "the canonical plan must carry `{EXACT_ACTION_HASH}` explicitly"
    );
    let plan: RestorePlan = decode(&canonical_plan).expect("the canonical plan must decode");
    assert_nullable_member_agrees(
        plan.exact_action_hash.as_ref(),
        EXACT_ACTION_HASH,
        &canonical_plan,
    );

    // (b) The one `TaskMeaningFrame` document the corpus stores is the case-5
    // duplicate; dropping its FIRST `task_id` pair as raw text leaves a
    // single-valued frame, which is the accepted counterpart this case builds its
    // omission documents from. The edit keeps the LAST raw value, and both facts
    // are asserted below.
    let duplicated = raw("c5_frame_duplicate_task_id_refuse");
    let frame_document = without_top_level_member(&duplicated, DUPLICATE_TASK_ID);
    assert_eq!(
        repeats(&frame_document, DUPLICATE_TASK_ID),
        1,
        "the frame document this case edits must carry `task_id` exactly once"
    );
    let frame: TaskMeaningFrame =
        decode(&frame_document).expect("the de-duplicated frame document must decode");
    assert_eq!(
        frame.task_id,
        member_text(&frame_document, DUPLICATE_TASK_ID),
        "the accepted frame must carry its own `task_id`, unchanged"
    );

    // (c) A MISSING protected identity refuses. `TaskMeaningFrame::task_id`
    // (`crates/eliot-types/src/semantic_memory.rs:257`) is a declared `String` with
    // NO `#[serde(default)]` and no struct-wide default, so an absent identity is
    // `missing field` and never an empty identity promoted to a current-task
    // boundary (`TASK.md:53`).
    assert_omitted_member_refused::<TaskMeaningFrame>(
        &without_top_level_member(&frame_document, DUPLICATE_TASK_ID),
        "the frame document with `task_id` deleted",
        DUPLICATE_TASK_ID,
    );

    // (d) A MISSING lineage map refuses for the same reason:
    // `TaskMeaningFrame::entity_roles`
    // (`crates/eliot-types/src/semantic_memory.rs:264-265`) is required, so an
    // absent lineage map is `missing field` rather than an empty one that could
    // satisfy a coverage boundary. "Zero observed items, absent denominator and
    // complete-empty input are different facts" (`TASK.md:53`).
    assert!(
        frame_document.contains(&format!("\"{ENTITY_ROLES}\"")),
        "this case's lineage half needs a frame-shaped document that carries `{ENTITY_ROLES}`, or \
         there is no lineage member to delete"
    );
    assert_omitted_member_refused::<TaskMeaningFrame>(
        &without_top_level_member(&frame_document, ENTITY_ROLES),
        "the frame document with `entity_roles` deleted",
        ENTITY_ROLES,
    );

    // (e) An EMPTY protected identity is ACCEPTED, and that acceptance is RECORDED
    // here with its reason instead of being asserted as a property: no allocated
    // validator on `TaskMeaningFrame` inspects its identity members, so an empty
    // string decodes as an empty string. Recorded-not-fixed; the owner is
    // `crates/eliot-types/src/semantic_memory.rs`.
    let emptied = with_top_level_member_replaced(&frame_document, DUPLICATE_TASK_ID, "\"\"");
    let empty_frame: TaskMeaningFrame = decode(&emptied).unwrap_or_else(|error| {
        panic!(
            "the delivered decoder admits an empty `{DUPLICATE_TASK_ID}`; if that closed, this \
             assertion must change with it and the disposition must be reported: {error}"
        )
    });
    assert!(
        empty_frame.task_id.is_empty(),
        "an emptied identity must decode as an empty identity, which is the recorded non-clean \
         behaviour: `TaskMeaningFrame` declares no validator over its identity members"
    );
    assert_eq!(
        repeats(&emptied, DUPLICATE_TASK_ID),
        1,
        "the emptied document must still carry exactly one `{DUPLICATE_TASK_ID}` key: this is an \
         empty value, not a repeated member"
    );

    // (f) The retained `Option`s of `replay.rs` are the other half of this
    // boundary and are NOT refusals: their absence decodes to `None`, which is
    // unknown, never a validity claim. Asserted against the DELIVERED source and
    // recorded as such; case 13 checks the container's rows against the same four
    // declarations.
    let replay = production_text("crates/eliot-types/src/replay.rs");
    let defaulted = defaulted_members(&replay);
    for member in ["evaluation_integrity_receipt", "authoritative_replay"] {
        assert!(
            defaulted.contains(&member.to_owned()),
            "crates/eliot-types/src/replay.rs: `{member}` still carries a wire default, so its \
             absence decodes to `None` - unknown, never a validity claim - and that is \
             recorded-not-fixed, not asserted as a refusal. Measured defaults: {defaulted:?}"
        );
    }
    for member in ["sealed_input_hash", "reproducibility_hash", "uncertainty"] {
        assert!(
            !defaulted.contains(&member.to_owned()),
            "crates/eliot-types/src/replay.rs: `{member}` must carry NO wire default, so an \
             absent reproducibility input cannot pass for a sealed one"
        );
    }
    // The one retained `Option` of the safety family, from W1's own disposition: it
    // decodes to `None` and case 7 proves it against a stored document.
    assert!(
        !declaration_carries(
            &production_text("crates/eliot-types/src/safety.rs"),
            "pub campaign_integrity:",
            "serde(default)"
        ),
        "src/safety.rs: the `sd8` disposition is that `campaign_integrity` carries no wire default \
         and no refusing decoder, so an omitted key is an explicit `None` - case 7 asserts the \
         decode, not a refusal"
    );
    // And the lineage map of case 10 (d) really is required rather than defaulted:
    // it is guarded by the duplicate-rejecting visitor, not by a wire default.
    assert!(
        attributes_above(
            &production_text("crates/eliot-types/src/semantic_memory.rs"),
            "pub entity_roles:"
        )
        .contains("deserialize_strict_btree_map"),
        "src/semantic_memory.rs: `{ENTITY_ROLES}` must carry the duplicate-rejecting visitor and \
         NOT a wire default, which is why its absence refuses"
    );
}

// ---------------------------------------------------------------------------
// Case 11 - an opaque source payload cannot smuggle control meaning.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c11_opaque_data_cannot_smuggle_control_meaning
#[test]
fn c11_opaque_data_cannot_smuggle_control_meaning() {
    assert_case_binding("938/c11_opaque_data_cannot_smuggle_control_meaning", &[]);
    // `MemoryUtilitySourceRecord::payload` (`crates/eliot-types/src/distillation.rs:102`)
    // is a `serde_json::Value`. It is DATA, and this case proves three things: the
    // fixture really does mention a control word, the payload decodes VERBATIM, and
    // the decoded record carries EXACTLY the document's own members - so the
    // mention changed no status, created no receipt, no authority and no effect.
    let fixture = "c11_ledger_value_payload_mentions_restore_decodes_inert";
    let document = raw(fixture);
    let stored_payload = member_value(&document, "payload");
    assert!(
        stored_payload.is_object() || stored_payload.is_array(),
        "{fixture} must carry a structured `payload`, not a bare scalar"
    );
    let lowered = stored_payload.to_string().to_lowercase();
    let mentioned: Vec<&str> = CONTROL_MEANING_WORDS
        .iter()
        .copied()
        .filter(|word| lowered.contains(word))
        .collect();
    assert!(
        !mentioned.is_empty(),
        "{fixture} must really mention restore, erasure or authorization in its payload text, or \
         it does not test that source text may mention them without commanding an effect. It \
         mentions: {mentioned:?}"
    );
    let record: MemoryUtilitySourceRecord = decode(&document)
        .unwrap_or_else(|error| panic!("{fixture} must decode as inert data: {error}"));
    assert_eq!(
        record.payload, stored_payload,
        "the opaque payload must decode VERBATIM: it is stored data, not an instruction"
    );
    // The whole-record identity check: nothing was erased and nothing invented.
    assert_round_trip_identical::<MemoryUtilitySourceRecord>(&document, fixture);

    // THE RECORDED EXCEPTION, checked against the source and against the
    // container's own row: a repeated member INSIDE this payload cannot be
    // expressed to the decoder at all, because the declared type is a `Value`. The
    // fixture's name says `decodes_inert`, not `refuse`, and this file asserts
    // exactly that.
    let distillation = production_text("crates/eliot-types/src/distillation.rs");
    assert!(
        declaration_window(&distillation, "pub payload:", 1).contains("Value"),
        "src/distillation.rs: `MemoryUtilitySourceRecord::payload` must stay a `serde_json::Value`: \
         that is the documented collapse exception this case records"
    );
    let collapse_row = known_non_clean_rows()
        .into_iter()
        .find(|row| {
            let property = row
                .get("property")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let observed = row
                .get("observed")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let text = format!("{property}{observed}");
            text.contains("payload") && text.to_lowercase().contains("collaps")
        })
        .expect("the corpus must record the `payload: Value` collapse exception as a row");
    assert_eq!(
        collapse_row.get("path").and_then(serde_json::Value::as_str),
        Some("crates/eliot-types/src/distillation.rs"),
        "the collapse row must name the file that declares the `Value` member"
    );
    // SCOPED TO THE CASE THAT OWNS THIS EXCEPTION, NOT TO THE WORD "payload". An
    // earlier version matched ANY key containing `payload` that ends in `_refuse`,
    // which caught two honest keys about different members:
    // `c6_semantic_memory_wrong_outcome_payload_refuse` (a tag/payload disagreement
    // in a result enum) and `c7_BackupManifest_blob_payload_root_absent_refuse` (a
    // `PathRef` locator). The claim is about the `MemoryUtilitySourceRecord::payload`
    // member only, so it is asked of the case that documents it.
    assert!(
        !container_fixture_keys()
            .iter()
            .any(|key| key.starts_with("c11_") && key.ends_with("_refuse")),
        "no `c11` fixture key may claim the `payload: Value` member is a refusal: a repeated \
         member inside a `Value` collapses before any decoder sees it. Measured keys: {:?}",
        container_fixture_keys()
            .iter()
            .filter(|key| key.starts_with("c11_"))
            .collect::<Vec<&String>>()
    );
    // RECORDED, NOT INVENTED: `payload: Value` carries NO size ceiling anywhere in
    // `crates/eliot-types/src/distillation.rs`, so a decoded source payload is
    // unbounded. No `MAX_*` constant is asserted or added here.
}

// ---------------------------------------------------------------------------
// Case 12 - a proposed, completed or verified value is not authority.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c12_proposed_or_verified_is_not_applied
#[test]
fn c12_proposed_or_verified_is_not_applied() {
    assert_case_binding("938/c12_proposed_or_verified_is_not_applied", &[]);

    // (a) `automatic_apply_allowed: true` is DATA, not permission.
    // `MemoryDistillationCandidate::automatic_apply_allowed`
    // (`crates/eliot-types/src/distillation.rs:234`) is a plain `bool` with no
    // validator over it, no `alias` and no default, so the flag decodes as written
    // and grants nothing: the whole decoded record carries exactly the document's
    // own members.
    let candidate_fixture = "c12_distillation_candidate_automatic_apply_allowed_inert";
    let candidate_document = raw(candidate_fixture);
    assert_eq!(
        member_value(&candidate_document, "automatic_apply_allowed"),
        serde_json::Value::Bool(true),
        "{candidate_fixture} must really carry `automatic_apply_allowed: true`, or it does not \
         test that the flag is inert"
    );
    let candidate: MemoryDistillationCandidate = decode(&candidate_document)
        .unwrap_or_else(|error| panic!("{candidate_fixture} must decode as data: {error}"));
    assert!(
        candidate.automatic_apply_allowed,
        "the decoded candidate must carry the flag as written: it is data, and this file changes \
         no policy to make it anything else"
    );
    assert_round_trip_identical::<MemoryDistillationCandidate>(
        &candidate_document,
        candidate_fixture,
    );

    // (b) An apply receipt that carries WRITE RECEIPTS is not proof of execution.
    // `MemoryDistillationApplyReceipt`
    // (`crates/eliot-types/src/distillation.rs:300-310`) carries no status, mode,
    // authority or permission member at all - which is why the corpus's key says
    // `write_receipts_inert` and not `completed`: there is no `Completed` to carry.
    let receipt_fixture = "c12_distillation_apply_receipt_write_receipts_inert";
    let receipt_document = raw(receipt_fixture);
    let stored_receipt = witness(&receipt_document);
    for member in ["status", "mode", "authority", "permission"] {
        assert!(
            stored_receipt.get(member).is_none(),
            "{receipt_fixture} must carry no `{member}` member: the type declares none, so a \
             decoded receipt cannot be read as a completion or permission claim"
        );
    }
    let apply_receipt: MemoryDistillationApplyReceipt = decode(&receipt_document)
        .unwrap_or_else(|error| panic!("{receipt_fixture} must decode as data: {error}"));
    for (decoded_len, member) in [
        (apply_receipt.selected.len(), "selected"),
        (
            apply_receipt.rejected_candidate_ids.len(),
            "rejected_candidate_ids",
        ),
        (apply_receipt.write_receipts.len(), "write_receipts"),
    ] {
        assert_eq!(
            decoded_len,
            stored_receipt
                .get(member)
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| panic!("{receipt_fixture} must carry a `{member}` array"))
                .len(),
            "the decoded apply receipt must carry exactly the document's own `{member}`"
        );
    }
    assert!(
        !apply_receipt.write_receipts.is_empty(),
        "{receipt_fixture} must carry at least one write receipt, or it does not test that carried \
         write receipts are not execution proof"
    );
    assert_round_trip_identical::<MemoryDistillationApplyReceipt>(
        &receipt_document,
        receipt_fixture,
    );

    // (c) A `VerifiedOnly` restore receipt is not owner issuance and not cutover
    // authority. The spelling is pinned in BOTH directions against the enum's own
    // DERIVED variant set, and the decoded receipt carries exactly the document's
    // own members. `docs/architecture/A13-07-backups-restore-and-migration.md:16`:
    // "Cutover requires separate authority"; `I05-13:38`: "Backup existence is not
    // recovery proof."
    let safety = production_text("crates/eliot-types/src/safety.rs");
    let legal_status: Vec<String> = enum_variants(&safety, "pub enum RestoreStatus")
        .iter()
        .map(|variant| camel_to_snake(variant))
        .collect();
    let verified_only = legal_status
        .iter()
        .find(|spelling| *spelling == "verified_only")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        serde_json::to_string(&RestoreStatus::VerifiedOnly).expect("a status must re-encode"),
        format!("\"{verified_only}\""),
        "`RestoreStatus::VerifiedOnly` must re-encode to the spelling this file derived from the \
         enum's own declared variants ({legal_status:?})"
    );
    let canonical_receipt = raw("c2_RestoreReceipt_canonical");
    let receipt: RestoreReceipt =
        decode(&canonical_receipt).expect("the canonical restore receipt must decode");
    // COMPARED AS VALUES, NOT AS TEXT. `to_string` of a unit enum variant yields the
    // QUOTED wire form (`"verified_only"`), while `member_text` yields the document's own
    // unquoted token (`verified_only`); the comparison above was failing on quotation
    // marks, not on the claim. Note the sibling assertion just above is correct AS
    // WRITTEN because both of ITS sides are quoted text.
    assert_eq!(
        serde_json::to_value(receipt.status).expect("a status must re-encode"),
        member_value(&canonical_receipt, RESTORE_STATUS),
        "the decoded restore receipt must carry the status the container's canonical document \
         states, compared as a VALUE and not as quoted text"
    );
    assert_round_trip_identical::<RestoreReceipt>(
        &canonical_receipt,
        "c2_RestoreReceipt_canonical",
    );
    // A STRONGER status decodes as data too and gains no member: the status is a
    // recorded fact about the document, not an authority this decoder reconstructs.
    let stronger = legal_status
        .iter()
        .find(|spelling| *spelling == "restored_to_new_root")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "`RestoreStatus` must declare a `RestoredToNewRoot` variant for this case to \
                 compare a stronger recorded status against; measured: {legal_status:?}"
            )
        });
    let promoted = with_top_level_member_replaced(
        &canonical_receipt,
        RESTORE_STATUS,
        &format!("\"{stronger}\""),
    );
    let promoted_receipt: RestoreReceipt = decode(&promoted).unwrap_or_else(|error| {
        panic!("a stronger recorded status must still decode as data: {error}")
    });
    assert_eq!(
        serde_json::to_string(&promoted_receipt.status).expect("a status must re-encode"),
        format!("\"{stronger}\""),
        "the decoded receipt must carry the stronger status it was given, and no other spelling"
    );
    assert_round_trip_identical::<RestoreReceipt>(&promoted, "the promoted-status receipt");
}

// ---------------------------------------------------------------------------
// Case 13 - the exact exceptions, checked against the real source.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c13_exact_exceptions_invalidate_on_use_change
#[test]
fn c13_exact_exceptions_invalidate_on_use_change() {
    assert_case_binding("938/c13_exact_exceptions_invalidate_on_use_change", &[]);

    // (a) Case 13's subject IS the retained exceptions: the issue's acceptance row
    // for cases 13-14 reads "Exact exceptions invalidate on relevant source/caller
    // change; bounded malformed/property inputs are panic-free". In this slice the
    // exceptions are the four `replay.rs` wire defaults the card forbids repairing,
    // so they are `known_non_clean` ROWS and there is deliberately NO fixture for
    // this case: inventing one would claim a refusal the delivered decoder does not
    // perform.
    let ids = known_non_clean_ids();
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        ids.len(),
        "every `known_non_clean` row must carry a DISTINCT id, so no exception is counted twice"
    );
    for row_id in REPLAY_DEFAULT_ROW_IDS {
        assert!(
            ids.iter().any(|id| id == row_id),
            "the corpus must carry the `{row_id}` exception row. The container's rows are: {ids:?}"
        );
    }

    // (b) Each row names its owner file and states that it is retained rather than
    // repaired. The container's own field names are the record: `id`, `path`,
    // `property`, `observed`, `why_it_is_recorded_and_not_fixed`, `owner`.
    for row_id in REPLAY_DEFAULT_ROW_IDS {
        let row = row_by_id(row_id);
        for field in [
            "id",
            "path",
            "property",
            "observed",
            "why_it_is_recorded_and_not_fixed",
            "owner",
        ] {
            let value = row
                .get(field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("the row {row_id} must carry a text `{field}`"));
            assert!(
                !value.trim().is_empty(),
                "the row {row_id} must give one clause of `{field}`"
            );
        }
        let path = row
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let owner = row
            .get("owner")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert_eq!(
            path, "crates/eliot-types/src/replay.rs",
            "the row {row_id} must be about `crates/eliot-types/src/replay.rs`"
        );
        assert!(
            owner.contains(path.as_str()),
            "the row {row_id} must name its own path in its owner clause, so the repair owner is \
             unambiguous; owner says: {owner}"
        );
        // CASE-INSENSITIVE: the substance is that the row records its file as card
        // READ ONLY, which is why the exception is retained instead of repaired. An
        // honest rewording to "read-only" must not break this.
        assert!(
            owner.to_lowercase().contains("read only")
                || owner.to_lowercase().contains("read-only"),
            "the row {row_id} must record that its file is card READ ONLY, which is why the \
             exception is retained instead of repaired; owner says: {owner}"
        );
        let why = row
            .get("why_it_is_recorded_and_not_fixed")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        assert!(
            why.contains("record"),
            "the row {row_id} must say in its own words that the disposition is recorded; it \
             says: {why}"
        );
    }

    // (c) NO ROW IS CLAIMED AS A REFUSAL. Every exception member is named from the
    // row's own `property` text, and no stored fixture key may claim a refusal for
    // any of them - a repeated or absent `Option` member DECODES, and naming it
    // `_refuse` would be a false claim.
    let container_keys = container_fixture_keys();
    for row_id in REPLAY_DEFAULT_ROW_IDS {
        let property = row_by_id(row_id)
            .get("property")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let member = property
            .split("::")
            .nth(1)
            .and_then(|rest| rest.split(':').next())
            .unwrap_or_default()
            .trim()
            .to_owned();
        assert!(
            !member.is_empty(),
            "the row {row_id} must name its member after a `::`, or this case cannot check it"
        );
        let claimed: Vec<&String> = container_keys
            .iter()
            .filter(|key| key.contains(member.as_str()) && key.ends_with("_refuse"))
            .collect();
        assert!(
            claimed.is_empty(),
            "the row {row_id} records `{member}` as decoding rather than refusing, so no fixture \
             may claim it as a refusal: {claimed:?}"
        );
    }

    // (d) THE `c7` SET IS A DIFFERENT SET, so the two cannot be confused: the
    // members those seven refusal documents omit are the effect-bearing ones, and
    // none of them is a member any exception row describes.
    let exception_members: Vec<String> = REPLAY_DEFAULT_ROW_IDS
        .iter()
        .map(|row_id| {
            row_by_id(row_id)
                .get("property")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .split("::")
                .nth(1)
                .and_then(|rest| rest.split(':').next())
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .collect();
    let case7_keys: Vec<&String> = container_keys
        .iter()
        .filter(|key| key.starts_with("c7_"))
        .collect();
    assert!(
        !case7_keys.is_empty(),
        "the corpus must carry the `c7` omission documents, or this case cannot show the two sets \
         apart"
    );
    for member in [
        SURREAL_SOURCE_ENDPOINT,
        SURREAL_SOURCE_STORAGE_REF,
        BLOB_PAYLOAD_ROOT,
        TARGET_ENDPOINT,
        TARGET_STORAGE_REF,
        EXACT_ACTION_HASH,
    ] {
        assert!(
            case7_keys.iter().any(|key| key.contains(member)),
            "the `c7` set must include the omitted `{member}` refusal document"
        );
        assert!(
            !exception_members.contains(&member.to_owned()),
            "`{member}` must not be a member an exception row describes: it refuses, so the two \
             sets are different"
        );
    }
    // The one `c7` document that is NOT a refusal is named for what it is, and the
    // name is honest: `campaign_integrity` decodes to an explicit `None`.
    let explicit_unknown_keys: Vec<&&String> = case7_keys
        .iter()
        .filter(|key| !key.ends_with("_refuse"))
        .collect();
    assert_eq!(
        explicit_unknown_keys.len(),
        1,
        "exactly one `c7` document must not be a refusal - the `sd8` explicit-unknown one - so \
         the refusal set and the disposition set cannot be confused: {explicit_unknown_keys:?}"
    );
    assert!(
        explicit_unknown_keys[0].contains(CAMPAIGN_INTEGRITY)
            && explicit_unknown_keys[0].ends_with("_absent_explicit_unknown"),
        "the non-refusing `c7` document must be the `campaign_integrity` one and must be named \
         for the disposition it really has: {explicit_unknown_keys:?}"
    );

    // (e) `rp1..rp4` against the REAL source: the set of `#[serde(default`-carrying
    // declarations in `replay.rs` is derived from the production text, and each row
    // must name one of them. This is the check that invalidates on an attribute
    // change.
    let replay = production_text("crates/eliot-types/src/replay.rs");
    let defaulted = defaulted_members(&replay);
    assert_eq!(
        defaulted.len(),
        REPLAY_DEFAULT_ROW_IDS.len(),
        "crates/eliot-types/src/replay.rs must still carry exactly one `#[serde(default` \
         declaration per exception row, and the container carries four rows. Measured: \
         {defaulted:?}"
    );
    for member in &defaulted {
        let named = REPLAY_DEFAULT_ROW_IDS.iter().any(|row_id| {
            row_by_id(row_id)
                .get("observed")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_lowercase()
                .replace('_', " ")
                .contains(&member.to_lowercase().replace('_', " "))
        });
        assert!(
            named,
            "the real defaulted declaration `{member}` must be described by one of \
             `rp1..rp4`, or the container is hiding a default this delivery did not repair"
        );
    }
    // (f) The invalidation CONDITION is the frozen inventory's own: an exact exception
    // invalidates on a change to the attribute, the caller, the schema or the owner.
    // Asserted as the four conditions the inventory must name, not as one sentence:
    // pinning the exact wording would break the next honest rewording of a file this
    // issue is not allowed to edit.
    let inventory = repository_text(
        "crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml",
    );
    let inventory_lower = inventory.to_lowercase();
    for condition in ["invalidate", "attribute", "caller", "schema", "owner"] {
        assert!(
            inventory_lower.contains(condition),
            "the frozen inventory must state that an exact exception `{condition}` change \
             invalidates it, which is the invalidation condition this case asserts; the searched \
             text is the frozen inventory itself"
        );
    }

    // (g) THE FOUR LINE NUMBERS, MEASURED from the production text and matched
    // against the rows. `rp2` is the row that states the file-wide count, and it must
    // state FOUR and not two: the file carries one `#[serde(default`-carrying
    // declaration at each of the four measured lines, and a row that said "two" would
    // be hiding two of them from the reader of this suite.
    let replay_lines: Vec<&str> = replay.lines().collect();
    let measured_lines: Vec<usize> = replay_lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains("#[serde(default"))
        .map(|(index, _)| index + 1)
        .collect();
    assert_eq!(
        measured_lines.len(),
        REPLAY_DEFAULT_ROW_IDS.len(),
        "the number of `#[serde(default` declarations measured in replay.rs must equal the number \
         of exception rows. Measured lines: {measured_lines:?}"
    );
    let row_text = |row_id: &str| -> String {
        let row = row_by_id(row_id);
        [
            "property",
            "observed",
            "why_it_is_recorded_and_not_fixed",
            "owner",
        ]
        .iter()
        .copied()
        .map(|field| {
            row.get(field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
        })
        .collect::<Vec<&str>>()
        .join(" ")
    };
    for line in &measured_lines {
        let citation = format!(":{line}");
        let citing: Vec<&str> = REPLAY_DEFAULT_ROW_IDS
            .iter()
            .copied()
            .filter(|row_id| row_text(row_id).contains(&citation))
            .collect();
        assert!(
            !citing.is_empty(),
            "the defaulted declaration at `crates/eliot-types/src/replay.rs:{line}` must be cited \
             by one of the exception rows, or a real wire default is undocumented. Measured lines: \
             {measured_lines:?}"
        );
    }
    let counting: Vec<&str> = REPLAY_DEFAULT_ROW_IDS
        .iter()
        .copied()
        .filter(|row_id| {
            measured_lines
                .iter()
                .all(|line| row_text(row_id).contains(&format!(":{line}")))
        })
        .collect();
    assert_eq!(
        counting.len(),
        1,
        "exactly ONE row may state the file-wide count of replay.rs wire defaults, and it must \
         cite every measured line. Measured: {counting:?}"
    );
    let counting_id = counting[0];
    let counting_text = row_text(counting_id);
    let counting_lower = counting_text.to_lowercase();
    // The COUNT is derived from the source, not typed: `measured_lines.len()` defaults are
    // counted here, and the row must state that same count. Case-insensitively, because
    // "four" and "FOUR" are the same claim.
    let count_word = match measured_lines.len() {
        4 => "four",
        5 => "five",
        6 => "six",
        other => panic!(
            "the replay.rs default count moved to {other}; this assertion's wording must be \
             re-derived for it rather than silently kept"
        ),
    };
    assert!(
        counting_lower.contains(count_word),
        "the row that states the file-wide count (`{counting_id}`) must state the count this file \
         MEASURED - {count_word} - because that many `#[serde(default` declarations exist in \
         replay.rs at {measured_lines:?}. It says: {counting_text}"
    );
    assert!(
        counting_lower.contains("not two"),
        "the row must explicitly contrast the measured count with the smaller number, so a reader \
         cannot mistake it for a two-default file. It says: {counting_text}"
    );

    // (h) EVERY RECORDED ROW IS CONSUMED BY THIS SUITE, and the count is DERIVED from
    // the container in both directions. The nine ids below are the ones this file
    // reads by id or by content; nothing hard-codes "nine", so a row added to or
    // removed from the container changes this equality instead of being absorbed.
    let row_whose_path_ends_with = |suffix: &str, member: &str| -> String {
        known_non_clean_rows()
            .into_iter()
            .find(|row| {
                row.get("path")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|path| path.ends_with(suffix))
                    && row
                        .get("property")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .contains(member)
            })
            .and_then(|row| {
                row.get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| {
                panic!("the corpus must carry a row about `{member}` in a `{suffix}` file")
            })
    };
    let mut consumed: Vec<String> = REPLAY_DEFAULT_ROW_IDS
        .iter()
        .map(|row_id| (*row_id).to_owned())
        .collect();
    consumed.push("c9_c10_no_legacy_migration_surface".to_owned());
    consumed.push("c15_ingress_duplicate_erased_before_decoder".to_owned());
    consumed.push("c15_rollback_receipt_not_owner_issuance".to_owned());
    consumed.push(row_whose_path_ends_with("distillation.rs", "payload"));
    consumed.push(row_whose_path_ends_with("safety.rs", "campaign_integrity"));
    consumed.sort();
    consumed.dedup();
    let mut container_ids = ids.clone();
    container_ids.sort();
    assert_eq!(
        consumed, container_ids,
        "every `known_non_clean` row the container stores must be read by this suite, and every row \
         this suite reads must be one the container stores. Measured container ids: {container_ids:?}"
    );
    // Every row is RECORDED, not repaired: each one states its disposition in its own
    // `why_it_is_recorded_and_not_fixed` clause.
    for row in known_non_clean_rows() {
        let row_id = row
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let why = row
            .get("why_it_is_recorded_and_not_fixed")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        let owner = row
            .get("owner")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert!(
            why.contains("record"),
            "the row {row_id} must say in its own words that the disposition is recorded rather than \
             repaired; it says: {why}"
        );
        assert!(
            !owner.is_empty(),
            "the row {row_id} must name an owner, or an exception has nobody to invalidate it"
        );
    }
}

// ---------------------------------------------------------------------------
// Case 14 - bounded malformed inputs are panic-free.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c14_bounded_malformed_inputs_panic_free
#[test]
fn c14_bounded_malformed_inputs_panic_free() {
    assert_case_binding("938/c14_bounded_malformed_inputs_panic_free", &[]);
    // One stored string holds the whole group, so nothing is normalized by being
    // grouped. Every document is handed RAW to the decoder inside `catch_unwind`:
    // a bounded malformed input must fail, and it must fail as an ordinary error.
    // There is no `unwrap` on the result and no `#[should_panic]`.
    //
    // THE TYPE: the group is decoded as `BackupManifest`, the representative closed
    // record of this slice (`crates/eliot-types/src/safety.rs:122`, closed at
    // `:121`). Every document of the group is aimed at that type, which is the
    // contract this file states for the corpus writer.
    let fixture = "c14_area_bounded_malformed_and_wrong_type_documents";
    let group = documents(fixture);
    assert!(
        !group.is_empty(),
        "{fixture} must carry at least one bounded malformed document"
    );
    let mut syntax_invalid = 0_usize;
    for (index, document) in group.iter().enumerate() {
        let label = format!("{fixture}[{index}]");
        assert_panic_free_refusal::<BackupManifest>(document, label.as_str());
        if is_not_json(document) {
            syntax_invalid += 1;
        }
    }
    assert!(
        syntax_invalid > 0,
        "{fixture} must contain at least one document that is not valid JSON at all, or the group \
         tests only schema refusals and not malformed bytes"
    );
}

// ---------------------------------------------------------------------------
// Case 15 - the actual decoder refuses before a caller holds a value.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c15_decoder_refuses_before_trusted_output
#[test]
fn c15_decoder_refuses_before_trusted_output() {
    assert_case_binding("938/c15_decoder_refuses_before_trusted_output", &[]);

    // (a) THE ACTUAL DECODER REFUSES BEFORE A CALLER HOLDS A VALUE. Each of the
    // four proof-raising words is added to the accepted canonical restore receipt as
    // raw text and handed straight to `RestoreReceipt`; the type is closed
    // (`crates/eliot-types/src/safety.rs:353-355`), so the added member is refused by
    // name and no value is produced for a caller to hold.
    let canonical = raw("c2_RestoreReceipt_canonical");
    let accepted: RestoreReceipt = decode(&canonical).expect("the canonical receipt must decode");
    assert_eq!(
        accepted.restore_receipt_id,
        member_text(&canonical, "restore_receipt_id"),
        "the CONTROL: the canonical receipt decodes and carries its own identity"
    );
    for member in PROOF_RAISING_MEMBERS {
        let document = with_added_top_level_member(&canonical, member, "true");
        assert_injected_member_refused::<RestoreReceipt>(
            &document,
            &format!("the canonical receipt with `{member}` added"),
            member,
            "unknown field",
        );
    }

    // (b) THE INGRESS RECORD, quoted from the container's own row and checked
    // against the real production source. `McpDaemon::handle_line` still parses the
    // raw line into a `serde_json::Value`
    // (`crates/eliot-app/src/mcp_stdio.rs:2133-2134`) before any `#938` decoder runs,
    // and the consumer
    // `crates/eliot-app/src/mcp_stdio/task_handlers.rs::dispatch_task_meaning`
    // (`:838`) calls `serde_json::from_value` at `:839` on that already-collapsed
    // document.
    let ingress_row = row_by_id("c15_ingress_duplicate_erased_before_decoder");
    assert_eq!(
        ingress_row.get("path").and_then(serde_json::Value::as_str),
        Some("crates/eliot-app/src/mcp_stdio.rs"),
        "the ingress row must name the file that owns the byte ingress"
    );
    let mcp = production_text("crates/eliot-app/src/mcp_stdio.rs");
    let handle_line = declaration_window(&mcp, "async fn handle_line(", 40);
    assert!(
        handle_line.contains("serde_json::from_str(line)"),
        "crates/eliot-app/src/mcp_stdio.rs: `McpDaemon::handle_line` must still parse the raw line \
         with `serde_json::from_str`, which is the lossy step this row records"
    );
    assert!(
        !mcp.contains("strict_json"),
        "crates/eliot-app/src/mcp_stdio.rs must still NOT use the shared duplicate-rejecting \
         decoder `eliot_types::strict_json_value` \
         (crates/eliot-types/src/strict_json.rs:96): that is the recorded defect, not a repair"
    );
    assert!(
        mcp.contains("struct TaskMeaningToolInput"),
        "crates/eliot-app/src/mcp_stdio.rs: the wrapper type the ingress reaches must exist"
    );
    let handlers = production_text("crates/eliot-app/src/mcp_stdio/task_handlers.rs");
    let dispatch = declaration_window(&handlers, "fn dispatch_task_meaning(", 6);
    assert!(
        dispatch.contains("serde_json::from_value"),
        "crates/eliot-app/src/mcp_stdio/task_handlers.rs: `dispatch_task_meaning` must still decode \
         a `Value`, so the typed decoder never sees the original bytes"
    );
    let ipc = production_text("crates/eliot-app/src/named_pipe_ipc.rs");
    let relay = declaration_window(&ipc, "async fn relay_request(", 12);
    assert!(
        relay.contains("serde_json::to_string(request)"),
        "crates/eliot-app/src/named_pipe_ipc.rs: `relay_request` must still re-serialize the \
         already-normalized `Value`, the second ingress surface of the same defect"
    );

    // (c) THE TWO COUNTEREXAMPLES, from the container's raw text. Each is a real
    // lexical duplicate that the shared decoder refuses and that the lossy ingress
    // parse silently collapses, with the retained value being the LAST one - which
    // is why nothing downstream can prove the original byte stream. The typed
    // decoder DOES refuse the inner frame, which is why these two documents carry no
    // `_refuse` in their names.
    // The `path` is where the repeated member REALLY sits in the ingress document, so
    // the erasure is looked for where it happens: `frame.task_id` in one document,
    // `frame.entity_roles.subject` in the other.
    for (fixture, member, path) in [
        (
            "c15_ingress_mcp_line_duplicate_task_id",
            DUPLICATE_TASK_ID,
            vec![INGRESS_FRAME_MEMBER, DUPLICATE_TASK_ID],
        ),
        (
            "c15_ingress_mcp_line_duplicate_entity_role",
            DUPLICATE_ENTITY_ROLE_KEY,
            // THE REPEAT IS TWO LEVELS DOWN IN THIS ONE. `subject` is a KEY of the
            // `entity_roles` MAP, so it sits at frame.entity_roles.subject, not at
            // frame.subject. An earlier version looked for it one level too shallow
            // and so asserted a shape this document never had.
            vec![
                INGRESS_FRAME_MEMBER,
                ENTITY_ROLES,
                DUPLICATE_ENTITY_ROLE_KEY,
            ],
        ),
    ] {
        let document = raw(fixture);
        assert_eq!(
            repeats(&document, member),
            2,
            "{fixture} must carry `\"{member}\"` exactly twice: it is the audit's counterexample"
        );
        assert!(
            document.contains(&format!("\"{INGRESS_FRAME_MEMBER}\"")),
            "{fixture} must place the repeated member inside its `{INGRESS_FRAME_MEMBER}` wrapper"
        );
        let values = raw_string_values(&document, member);
        assert_eq!(
            values.len(),
            2,
            "{fixture} must carry two raw `{member}` values"
        );
        assert_ne!(
            values[0], values[1],
            "{fixture}'s two `{member}` values must DIFFER, or nothing is being rewritten"
        );
        let Err(error) = strict_json_has_no_duplicate_members(document.as_bytes()) else {
            panic!("{fixture} is a lexical duplicate the shared decoder must refuse");
        };
        assert_eq!(
            error.kind,
            StrictJsonErrorKind::DuplicateKey,
            "{fixture} must be refused by the shared decoder as a duplicate object member"
        );
        // THE EVIDENCE OF ERASURE, ON THE ROUTE THE INGRESS ACTUALLY TAKES. This is
        // adjudicated case (f): a `from_value` ingress receives a document whose
        // repeat was already collapsed at case (a), so the collapse is a property of
        // the lossy parse and NOT of the typed decoder. The witness parse below is
        // that lossy parse, and it is deliberately the ONLY route here that is
        // allowed to lose the repeat.
        let collapsed = witness(&document);
        // WHERE the repeated member really sits, computed ONCE and named, so both
        // failure messages below quote the same path instead of one of them
        // interpolating the raw `Vec` and the other a joined string.
        let repeated_at = path.join(".");
        let mut cursor = &collapsed;
        for step in &path {
            cursor = cursor.get(*step).unwrap_or_else(|| {
                panic!(
                    "{fixture}: the lossy route must still reach `{step}` on the way to `{member}`, \
                     because the erasure is observable at {repeated_at} and nowhere shallower"
                )
            });
        }
        let retained = cursor.as_str().unwrap_or_else(|| {
            panic!(
                "{fixture}: the repeated member at {repeated_at} must be a string in the lossy \
                 projection"
            )
        });
        assert_eq!(
            retained, values[1],
            "{fixture}: the lossy `Value` route the ingress actually takes must retain the LAST \
             `{member}` value, which is the erasure this case records"
        );
        // THE INNER FRAME IS REFUSED BY THE TYPED DECODER, on the RAW inner bytes.
        // This is the only end-to-end claim made here, and it stops at the frame: the
        // wrapper type `TaskMeaningToolInput` is private to `crates/eliot-app`, so no
        // refusal is claimed for it - the container's
        // `c15_ingress_duplicate_erased_before_decoder` row records that the repeat is
        // already gone by the time such a decoder could run.
        let inner = ingress_frame_document(&document).unwrap_or_else(|| {
            panic!(
                "{fixture} must be the real ingress shape `{{\"{INGRESS_FRAME_MEMBER}\": <frame>}}`, \
                 so the inner frame can be handed to the typed decoder"
            )
        });
        assert_eq!(
            repeats(inner, member),
            2,
            "{fixture}: the inner frame document must carry `\"{member}\"` exactly twice, so the \
             refusal below is caused by the repeat and not by the wrapper"
        );
        let Err(inner_error) = decode::<TaskMeaningFrame>(inner) else {
            panic!(
                "{fixture}: the INNER frame must be refused by `TaskMeaningFrame`, which is the \
                 typed decoder the ingress eventually reaches"
            );
        };
        let inner_message = inner_error.to_string();
        // TWO MEMBERS, TWO MECHANISMS, TWO NEEDLES - never one needle for both.
        //
        // `task_id` is a plain derived `String`, so its repeat is refused by the
        // DERIVE's own per-field check, which interpolates the field's wire name:
        // `serde_derive-1.0.229/src/de/struct_.rs:266-273` emits
        // `Error::duplicate_field(#deser_name)` when the field is already `Some`, before
        // the repeated value is visited. That is why the message may be required to NAME
        // `task_id`.
        //
        // `subject` is not a field at all: it is a KEY of the `entity_roles` MAP, which
        // carries `#[serde(deserialize_with = "deserialize_strict_btree_map")]`
        // (`crates/eliot-types/src/semantic_memory.rs:264-265`, visitor defined at `:16`
        // and erroring at `:41-43`). That visitor raises a BARE
        // `Error::custom("duplicate map key")` and deliberately does not echo the key -
        // the shared lexical decoder's `DuplicateKey` does not echo it either
        // (`crates/eliot-types/src/strict_json.rs:39`, redacted by design at `:64-66`).
        // So requiring this message to contain `subject` would demand a disclosure the
        // decoder deliberately does not make, and I will not weaken the map assertion to
        // "the decode fails" either: it asserts the refusal CLASS.
        let derived_member = member == DUPLICATE_TASK_ID;
        let needle = if derived_member {
            "duplicate field"
        } else {
            "duplicate map key"
        };
        assert!(
            inner_message.contains(needle),
            "{fixture}: the inner frame's refusal must be `{needle}`, got: {inner_message}"
        );
        if derived_member {
            assert!(
                inner_message.contains(member),
                "{fixture}: the DERIVE's `duplicate field` refusal interpolates the field's wire \
                 name, so it must name `{member}`, got: {inner_message}"
            );
        } else {
            assert!(
                !inner_message.contains(&format!("`{member}`")),
                "{fixture}: the map visitor's refusal must NOT echo the repeated key - it is a \
                 bare `duplicate map key` by design, so a message naming `{member}` would mean a \
                 different mechanism had fired. Got: {inner_message}"
            );
        }
    }

    // (d) THE ROLLBACK CONSUMER, quoted from the container's own row and checked
    // against the real production source. `RestoreService::rollback_isolated`
    // (`crates/eliot-engine/src/safety.rs:711`) still gates rollback on
    // `RestoredToNewRoot + verified_manifest + verified_checksums + matching target`
    // (`:729-732`), and that GATE reads no `exact_action_hash`, no `dry_run` and no
    // owner issuance. The control below proves the measured lines really are that
    // function's own gate. Nothing here claims the gate refuses or that it was
    // repaired.
    let rollback_row = row_by_id("c15_rollback_receipt_not_owner_issuance");
    assert_eq!(
        rollback_row.get("path").and_then(serde_json::Value::as_str),
        Some("crates/eliot-engine/src/safety.rs"),
        "the rollback row must name the file that owns the consumer"
    );
    let engine_safety = production_text("crates/eliot-engine/src/safety.rs");
    let rollback = declaration_window(&engine_safety, "pub fn rollback_isolated(", 60);
    let gate_at = rollback.find("restore_report.receipt.status").unwrap_or_else(|| {
        panic!(
            "crates/eliot-engine/src/safety.rs: `rollback_isolated` must still gate on the decoded \
             receipt's status, or the recorded row is stale"
        )
    });
    let after_gate = &rollback[gate_at..];
    let gate = after_gate.split("return Err(").next().unwrap_or(after_gate);
    for token in [
        "RestoreStatus::RestoredToNewRoot",
        "verified_manifest",
        "verified_checksums",
        "same_path",
    ] {
        assert!(
            gate.contains(token),
            "crates/eliot-engine/src/safety.rs: the rollback gate must still test `{token}`, or \
             the recorded row is stale; the measured gate is: {gate}"
        );
    }
    for token in [EXACT_ACTION_HASH, "dry_run", "owner"] {
        assert!(
            !gate.contains(token),
            "crates/eliot-engine/src/safety.rs: the rollback gate must still NOT read `{token}`, \
             which is the recorded defect and NOT a repair; the measured gate is: {gate}"
        );
    }
    // The dependency edge that keeps the owner-issued receipt unnameable from the
    // consumer is a fact of the manifest, and it is asserted because it is what
    // makes the ceiling structural.
    let engine_manifest = repository_text("crates/eliot-engine/Cargo.toml");
    assert!(
        !engine_manifest.contains("eliot-backup"),
        "crates/eliot-engine/Cargo.toml must declare no `eliot-backup` dependency, so the \
         owner-issued receipt type cannot be named from the consumer at all"
    );
}

// ---------------------------------------------------------------------------
// Case 16 - scope, schema, routing, dependencies and visibility unchanged.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 938/c16_scope_schema_routing_dependencies_visibility_unchanged
#[test]
fn c16_scope_schema_routing_dependencies_visibility_unchanged() {
    assert_case_binding(
        "938/c16_scope_schema_routing_dependencies_visibility_unchanged",
        &[],
    );

    // (a) The published schemas still expose the protected members, which is the
    // observable part of "no schema and no policy change": these functions are
    // derived from the types themselves
    // (`crates/eliot-types/src/distillation.rs:344-357`).
    let plan_schema = memory_distillation_plan_schema();
    for required in [
        "snapshot_revision",
        "protected_refs",
        "expected_active_bytes_delta",
        "unresolved_items",
    ] {
        assert!(
            plan_schema.to_string().contains(required),
            "the published distillation plan schema must still require `{required}`"
        );
    }
    let compression_schema = memory_compression_artifact_schema();
    for required in [
        "preserved_exact_atoms",
        "applicability_boundary",
        "counterexamples",
        "replay_requirement",
        "candidate_only",
    ] {
        assert!(
            compression_schema.to_string().contains(required),
            "the published compression artifact schema must still require `{required}`"
        );
    }

    // (b) The dependency edges this issue may not add. `eliot-types` gains no
    // dependency, and `eliot-engine` keeps its absent one.
    let types_manifest = repository_text("crates/eliot-types/Cargo.toml");
    assert!(
        !types_manifest.contains("eliot-backup"),
        "crates/eliot-types/Cargo.toml must not gain an `eliot-backup` dependency: these records \
         are NOT the distinct backup-journal types"
    );
    assert!(
        !repository_text("crates/eliot-engine/Cargo.toml").contains("eliot-backup"),
        "crates/eliot-engine/Cargo.toml must still declare no `eliot-backup` dependency"
    );

    // (c) The scope: the sibling suites are untouched by this delivery, which is
    // readable from their own text. Each must still carry its own issue marker and
    // must not carry this issue's.
    for (sibling, its_own_issue) in [
        ("crates/eliot-types/tests/serde_t05_antigravity.rs", "934"),
        ("crates/eliot-types/tests/serde_t10_skill.rs", "939"),
    ] {
        let text = production_text(sibling);
        assert!(
            text.contains(&format!("Issue #{its_own_issue}")),
            "{sibling} must still name its own issue"
        );
        assert!(
            !text.contains("WORK_UNIT_CASE: 938/"),
            "{sibling} must carry no #938 marker: the sixteen cases belong to exactly one suite"
        );
        assert!(
            !text.contains("serde_t09_semantic"),
            "{sibling} must not reach into this suite's fixture set"
        );
    }

    // (d) The scope probes: a member name that is a real type name OUTSIDE this
    // slice's allocation is not accepted as one here. Each probe is handed RAW to the
    // representative closed record and must be refused by name, every one of its
    // members must be foreign to the canonical manifest AND to the 160 allocated
    // names, and the real type each probe names in its own `message` must really be
    // declared in the file that message cites.
    //
    // The per-probe claim is deliberately NOT "allocated to another family of the
    // frozen inventory": `IncidentDisposition` is named by the third probe and is
    // declared at `crates/agent/eliot-agent-coordinator/src/provider_account_catalogue.rs`,
    // which the frozen inventory does not cover at all. Requiring an inventory row for
    // every probe would assert something false about a real type, so the per-probe
    // check is the ALLOCATION boundary (derived from `meta.types`) plus the file the
    // probe itself cites, and the "allocated to another family" claim is asserted
    // over the GROUP, where it is true.
    let probe_fixture = "c16_area_scope_probes";
    let probes = documents(probe_fixture);
    assert!(
        !probes.is_empty(),
        "{probe_fixture} must carry at least one scope probe"
    );
    let canonical_manifest = raw("c2_BackupManifest_canonical");
    let accepted: BackupManifest =
        decode(&canonical_manifest).expect("the canonical manifest must decode");
    assert_eq!(
        accepted.backup_id,
        member_text(&canonical_manifest, DUPLICATE_BACKUP_ID),
        "the CONTROL: the canonical manifest decodes, so the refusals below are caused by the \
         out-of-slice member names"
    );
    let manifest_members = top_level_members(&canonical_manifest);
    let types = meta_types();
    let elsewhere: Vec<String> = inventory_allocated_types()
        .into_iter()
        .filter(|name| !types.contains(name))
        .map(|name| normalize_type_name(&name))
        .collect();
    assert!(
        !elsewhere.is_empty(),
        "the frozen inventory must record type names allocated outside this slice, or the scope \
         probe cannot be checked against anything"
    );
    let mut probes_naming_another_family = 0_usize;
    for (index, probe) in probes.iter().enumerate() {
        let label = format!("{probe_fixture}[{index}]");
        assert_unknown_member_refused::<BackupManifest>(probe, &canonical_manifest, label.as_str());
        let probe_members = top_level_members(probe);
        for member in &probe_members {
            assert!(
                !manifest_members.contains(member),
                "{label}: the member `{member}` must be foreign to this slice's records, or the \
                 probe is not a scope probe"
            );
            assert!(
                !types.iter().any(|allocated| allocated == member),
                "{label}: the member `{member}` must be outside the 160 allocated names of \
                 `meta.types`, which is this case's allocation claim"
            );
        }
        if probe_members
            .iter()
            .any(|member| elsewhere.contains(&normalize_type_name(member)))
        {
            probes_naming_another_family += 1;
        }
        // THE PROBE'S OWN CLAIM, read back out of the fixture and checked against the
        // repository: the type it names is real and is declared in the file it cites.
        let message = member_text(probe, "message");
        let (claimed_type, claimed_path) = probe_claim(&message).unwrap_or_else(|| {
            panic!(
                "{label}: its `message` must name a real type and the file it is declared in, in \
                    the `<TypeName> is real at <path>.rs:<line>` form: {message}"
            )
        });
        assert!(
            !types.contains(&claimed_type),
            "{label}: `{claimed_type}` is named by the probe as being outside this slice's \
             allocation, so it must not be one of the 160 names `meta.types` records"
        );
        let claimed_source = repository_text(&claimed_path);
        assert!(
            claimed_source.contains(&format!("struct {claimed_type}"))
                || claimed_source.contains(&format!("enum {claimed_type}")),
            "{label}: `{claimed_type}` must really be declared in {claimed_path}, which is what \
             makes the probe's member name a REAL type name rather than an invented one"
        );
    }
    let probe_total = probes.len();
    assert!(
        probes_naming_another_family > 0,
        "at least one probe must carry a member that is the name of a real type the frozen \
         inventory allocates to ANOTHER family, or the group does not show that an out-of-slice \
         type name is not accepted as one. Measured: {probes_naming_another_family} of {probe_total}"
    );

    // (e) The visibility fact a test CAN read: every type this file names is
    // imported from the crate ROOT, so the delivery added no `pub use` and widened
    // no `pub`. The imports at the top of this file compile against `eliot_types`
    // and nothing else.
    assert!(
        types_manifest.contains("[lints]"),
        "crates/eliot-types/Cargo.toml must keep inheriting the workspace lints, which is where \
         this file's own `#![allow(clippy::expect_used)]` is scoped"
    );
    // BOUNDED CLAIM, NOT ASSERTED: the byte-identity of
    // `crates/eliot-types/src/{semantic_memory,distillation,replay,strict_json}.rs`,
    // the absence of any `Cargo.lock` line change, the absence of any `pub use` or
    // visibility change and the absence of any algorithm change are facts about a
    // DIFF, not about a test's runtime. They are stated here and bounded by
    // `docs/architecture/I07-27-evidence-execution-parsing-evaluation-and-independence.md:24`:
    // parser success is not execution. What this file checks instead is every part
    // of that claim a decoder can observe: the published schemas above, the
    // declaration closures in case 1, the dependency edges above, the sibling suites
    // above, the scope probes above, and case 1's reading that the four-file
    // allocation row still reads READY_FOR_REPAIR.
}
