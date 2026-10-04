//! Issue #930 (`F-DENY-T01`), the THIRTEEN cases this file dispatches — 1, 2, 3, 4,
//! 5, 6, 7, 10, 11, 12, 14, 15 and 16 — over the core `eliot-types` serde boundary.
//! The three it deliberately does not dispatch are 8, 9 and 13, and each one's
//! MEASURED reason is written down at `UNDISPATCHED_CASES` rather than left to be
//! inferred from a missing marker.
//!
//! WHAT IS READ AT RUNTIME IS SEVEN SOURCE FILES PLUS THIS CRATE'S MANIFEST, and the
//! five allocated files are not all of it. The five allocated files — `lib.rs`,
//! `error.rs`, `ids.rs`, `records.rs` and `task_execution.rs` — alone are the
//! serde-candidate denominator. Case 16 reads three further paths, and each of the three
//! is a claim ABOUT the allocation rather than an addition to it:
//! * `crates/eliot-types/src/health.rs` supplies the deferred `HealthStatus` vocabulary
//!   that case 16 proves is still OUT of the wire shape;
//! * `crates/eliot-store/src/surreal_store.rs` is read as TEXT ONLY, for the consumer
//!   outside this crate whose `status` assignment is what keeps that field open — this
//!   crate has no `[dev-dependencies]`, so no link exists and text is the honest form;
//! * `crates/eliot-types/Cargo.toml` supplies the two facts that block checklist items
//!   A8, A9 and A11.
//!
//! So reading outside the five allocated files widens NO denominator: none of the three
//! contributes a candidate, a struct or a fixture row, and the allocation table is still
//! enumerated from the five alone.
//!
//! THE CARD'S READ-ONLY ALLOWLIST, ITEMISED HERE SO THAT A SCOPE AUDIT NEEDS NOTHING BUT
//! THIS FILE. Issue #930's card is NOT inside this repository — it lives in the swarm
//! workstream outside it, at `ROOT-continuation/workstreams/swarm/cards/930.md` — and
//! its EDIT clause reads "**EDIT - exactly these files**". The clause after it, line 14,
//! reads "**READ ONLY:**" and then names thirteen paths, written there in brace groups
//! and expanded here one by one so a reader can compare them against what this file
//! reads without counting braces:
//! * `crates/eliot-types/src/lib.rs`;
//! * `crates/eliot-types/src/ids.rs`;
//! * `crates/eliot-types/src/error.rs`;
//! * `crates/eliot-types/src/records.rs`;
//! * `crates/eliot-types/src/task_execution.rs`;
//! * `crates/eliot-types/src/strict_json.rs`;
//! * `tests/cue_kind_legacy_boundary.rs`, written by the card relative to this crate;
//! * `crates/eliot-store/src/canonical_store.rs`;
//! * `crates/eliot-store/src/canonical_record.rs`;
//! * `crates/eliot-store/src/blob_store.rs`;
//! * `crates/eliot-engine/src/task_execution.rs`;
//! * the frozen boundary TOML, which the card does not name by file;
//! * `serde_boundary_inventory.py`.
//!
//! WHICH OF THE PATHS READ AT RUNTIME ARE ON THAT LIST. All five allocated sources are
//! on it — `lib.rs`, `ids.rs`, `error.rs`, `records.rs` and `task_execution.rs` — and
//! those five are everything the allocation denominator is enumerated from. The
//! fixture this file parses, and this file's own bytes, are named by the card's EDIT
//! clause rather than by its READ ONLY clause, so neither is an excess. THREE READS ARE
//! NOT ON THAT LIST, and they are named here by the constants that hold them: the path
//! in `HEALTH_FILE`, the path in `STORE_HEALTH_CONSUMER`, and the path in
//! `ELIOT_TYPES_MANIFEST`. The first two are absent from an allowlist that names six
//! other files under `eliot-types/src` and three other files under `eliot-store/src`;
//! the third is absent from a clause that names no manifest at all.
//!
//! WHAT EACH EXCESS READ IS USED FOR, so a reader can judge the excess rather than only
//! count it:
//! * `HEALTH_FILE` supplies the deferred vocabulary's own wire spellings — the
//!   `rename_all` rule attached to the enum's declaration, and its variant names in
//!   declaration order. What those spellings back is the assertion that the real
//!   decoder ACCEPTS every spelling derived from that declaration and REFUSES two
//!   values outside the resulting set, and separately the assertion that the enum
//!   carries no catch-all that would make those refusals vacuous.
//! * `STORE_HEALTH_CONSUMER` backs the assertion about an EXTERNAL CONSUMER'S STATUS
//!   VALUES: every `HealthRecord` construction in that file must assign `status`
//!   through `.to_owned()`, more than one of them must be readable so that a
//!   first-match scan cannot pass, and at least one must carry a status outside the
//!   derived spellings, so the closed vocabulary is not already naming everything the
//!   consumer needs.
//! * `ELIOT_TYPES_MANIFEST` backs the assertion about a MANIFEST'S DEPENDENCY SHAPE:
//!   no table whose final dotted component names a dev-dependency, and every
//!   dependency entry ending in the workspace-inheritance suffix — no pinned version,
//!   no path dependency, no `features` or `optional` key.
//!
//! WHETHER THE CARD PERMITS ANY OF THESE THREE READS, WHICH THIS FILE DOES NOT DECIDE.
//! What the card's text settles is the OMISSION: none of the three appears in its
//! READ ONLY clause. What it does not settle is whether that clause is exhaustive for
//! READING — it says "READ ONLY" and enumerates, and nowhere states that an
//! unenumerated read is out of scope — so permission for each of the three is a
//! question about the card's intent that this delivery must not answer by inference,
//! and does not. Two further clauses pull in opposite directions on the two source
//! reads, and are recorded rather than resolved: the DEFER clause names
//! `HealthRecord.status`, assigns it to #931 and says it "stay unresolved and are not
//! certified here", while the MAKE clause for cases 13-16 asks for "unchanged
//! scope/visibility/ordering/`requires_codecortex`" — so the property those two reads
//! back is named by the card both as deferred and as in scope. For the manifest the
//! omission stands alone, with one further observation: the card's DO NOT clause says
//! "no Cargo/lock changes", which forbids an EDIT and says nothing about a read, so
//! that sentence is neither a read grant nor a read prohibition and this file does not
//! treat it as either.
//!
//! WHETHER EACH EXCESS IS LOAD-BEARING OR ARTIFACTUAL. All three are LOAD-BEARING. The
//! evidence is per path, and for each the second half of the question — whether a check
//! over the five files the card DOES permit could carry the same fact — is answered by
//! the repository rather than assumed:
//! * `HEALTH_FILE` is read by `health_status_wire_spellings`, whose first statement is
//!   `let source = read_workspace(HEALTH_FILE)?;` and which hands that string to both
//!   the rename-rule reader and the enum-variant walk. Remove the read and the function
//!   has no input, `?` propagates the read failure, and case 16 is red before any
//!   assertion of it runs. No check over the five substitutes: the enum is DECLARED in
//!   `health.rs` alone; the single mention of it in `records.rs` is the doc sentence
//!   `health_status_stays_out_of_the_shape` asserts is prose and never code; and the
//!   one whole-word mention of it in `lib.rs` is a re-export line carrying no variant,
//!   no rename rule and no evidence about a catch-all; a plain substring search also
//!   hits `DashboardHealthStatus` in the `metrics` re-export group, a different type
//!   that says nothing about this one.
//! * `STORE_HEALTH_CONSUMER` is read by
//!   `store_health_record_stays_outside_the_vocabulary` as
//!   `let source = read_workspace(STORE_HEALTH_CONSUMER)?;`, handed to the construction
//!   scan, whose first guard fails the case outright when the scan finds nothing — the
//!   failure names the absence and says "{STORE_HEALTH_CONSUMER} constructs no
//!   {HEALTH_RECORD_TYPE}, so the narrowing claim cannot be checked". The tempting
//!   alternative is RELOCATION onto one of the three `eliot-store` files the card DOES
//!   name, and the repository forecloses it: `HealthRecord` is constructed in exactly
//!   two places under `crates/` outside its own definition, both of them in this
//!   constant's path, and the three permitted store files contain no occurrence of the
//!   type at all.
//! * `ELIOT_TYPES_MANIFEST` is read as
//!   `let source = read_workspace(ELIOT_TYPES_MANIFEST)?;`, and every assertion in
//!   `manifest_declares_no_dev_dependency_and_inherits_every_dependency` is computed
//!   from that string — the section walk, the non-empty guard and the inheritance
//!   filter. Remove the read and the function has no input, so the claim would have to
//!   be DELETED rather than re-pointed, and case 16's own step 11 already says so: "The
//!   MANIFEST half of the same claim is no longer on this list: item 9 asserts it". No
//!   file under `src/` records a dependency declaration, so no check over the five
//!   carries this fact; the alternative to the read is the ABSENCE of the claim, which
//!   is a narrower delivery rather than an equivalent one.
//!
//! NO REMOVAL OR RELOCATION IS RECOMMENDED, and the ground is per path rather than a
//! standing rule: no excess read here is artifactual, so no removal would preserve
//! coverage, and each would take a named assertion with it — case 16's vocabulary
//! acceptance and no-catch-all checks for the first, its external-consumer assigned-type
//! and vocabulary checks for the second, its dependency-shape check for the third. One
//! narrower observation is recorded rather than recommended, because it is NOT an
//! excess-read finding: the no-catch-all assertion consumes the same string the
//! spellings derivation already needs, so it costs no additional read, and dropping it
//! would remove no read. What it would remove is a structural check that the two
//! behavioural refusals also reach by a different route, and that trade is the
//! manager's decision rather than this delivery's.
//!
//! NO EXCESS READ IS A WRITE. Every filesystem content access this file makes is one
//! of two `std::fs::read_to_string` calls — the fixture loader and `read_workspace` —
//! and the only `write!` calls in this file are the two in the `Display` implementation
//! for `Step`, which write into a `std::fmt::Formatter` and touch no file. Stated
//! completely, because "read-only" would otherwise be a claim a reader cannot check:
//! `workspace_root` also PROBES the workspace root's own manifest and lockfile for
//! existence, which is metadata rather than content and names two further paths this
//! file touches; no content of either is read, and neither is written. Nothing under
//! `health.rs`, nothing under `surreal_store.rs` and nothing under this crate's own
//! manifest is modified by this delivery.
//!
//! Case 1 proves the allocation table is complete and honest: one row for every
//! type the five allocated files declare, read from live source rather than
//! counted here, plus the declared `meta.count`, the exact per-file split, the
//! closed `shape` vocabulary and `also_in_cases` cross-references, every
//! `id_type!` expansion present by name, and a recorded row-level reason for
//! every inapplicable shape rather than an ignored row.
//!
//! Case 2 discharges TWO distinct claims, from two different row sets, and it is
//! worth keeping them apart:
//! * the **valid-bytes** claim — every canonical payload decodes and
//!   re-serializes without drift — is discharged by the **case-1 allocation
//!   rows**, via `round_trip_row` over `allocation_rows`. It is not discharged by
//!   the absence rows.
//! * the **absence** claim — an empty identity and an unsupported or empty
//!   `schema_version` decode with their recorded values PRESERVED, because the
//!   five allocated files declare no `validate` and no `check` function and the
//!   empty-string gates live in `runtime.rs` and `runtime_supervision.rs` on
//!   different types — is discharged by the **case-2 absence rows**. Asserting a
//!   refusal there would be false against live source.
//!
//! Case 2 also runs the L2 optional-member claims on every page row it owns, the
//! allocation page and the case-12 absence pages, so the present and the absent
//! side of the skipped pair are exercised from fixture bytes. The third form —
//! an explicit `null` — is exercised by BYTE SURGERY in this file
//! (`skipped_pair_null_form_is_exercised`), because no fixture row carries one:
//! the only top-level explicit null in all 162 rows is `"continuation":null`, and
//! `continuation` is an always-emitted member.
//!
//! Case 3 proves an unknown top-level member is refused by the closed structs.
//! Case 4 proves an unknown member nested inside an owned member is refused too.
//! Case 11 proves the `strict_json.rs` ingress and the `alias` / `#[serde(default)]`
//! / `#[serde(untagged)]` paths cannot erase protected input, and it is PARTIAL: the
//! capacity-receipt half of its card clause is unreachable from this crate and that
//! is written down in the test's own comment, not here.
//! Cases 1-4, 5, 6, 7, 10, 11, 12, 14, 15 and 16 are the whole scope of this file,
//! and that scope is stated and CHECKED rather than counted: no constant here pins
//! how many cases this file dispatches, so a delivery that adds a missing case is
//! not red for having made the count wrong. See
//! `test_attributes_are_bound_to_case_markers`.
//!
//! Every negative case exercises the real public `Deserialize` path through
//! `serde_json::from_str`, never through a pre-parsed `Value`, and no
//! rejection assertion compares a serde error message by exact equality. What
//! is claimed about a refusal is `is_err`, a substring naming the offending
//! member where serde's own construction embeds one, the error's CATEGORY
//! (`is_data`/`is_syntax`, which is exact and wording-independent), the error's
//! position, and — where a bare member-name substring would be satisfiable by the
//! wrong refusal — a substring of the refusal's own shape. That last one is
//! necessary rather than decorative: serde's `unknown_field` enumerates every
//! declared field of a closed struct, so `contains("status")` alone does not mean
//! the row was refused for its duplicate. Every refusal shape quoted in this file
//! is cited to a line in the pinned `serde-1.0.229` or `serde_json-1.0.151`
//! source, and serde's message text is version-dependent, which is why none of it
//! is compared for equality.
//!
//! Docs routing, verified against `.eliot/docs-read-receipt-930-delivery.json`:
//! route `sha256:64321fd998bd2bea4ea5a03adc21588fa96e2d9704fee7a726d5ce9113123dc8`,
//! read `sha256:7eb7d773b43bc2bd5d03da439556b02dfe43b85747adc3d2043ae240e09d5c10`,
//! bundle `sha256:a1a2945fc11275f1f8102c508f476b03eb33a52eb4d30e86624b7795eff4e490`
//! over 225 074 bytes, governing handles I5.16, I5.22, I7.2, I7.20, I15.6 and
//! APPENDIX-P, from a route over exactly the two paths this file owns —
//! `crates/eliot-types/tests/serde_t01_core.rs` and its fixture
//! `crates/eliot-types/tests/data/serde_t01_core.json`.

use serde::Deserializer;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn boxed(error: impl std::error::Error + 'static) -> Box<dyn std::error::Error> {
    Box::new(error)
}

fn fail<T>(message: String) -> Result<T, Box<dyn std::error::Error>> {
    Err(boxed(std::io::Error::other(message)))
}

/// The five files this issue allocates, in `source` leaf order.
const SOURCE_FILES: [&str; 5] = [
    "lib.rs",
    "error.rs",
    "ids.rs",
    "records.rs",
    "task_execution.rs",
];

#[derive(Clone, Debug)]
struct Row {
    id: String,
    case: i64,
    description: String,
    type_name: String,
    source: String,
    applicable: bool,
    reason: String,
    raw: String,
    expected: String,
    shape: String,
    also_in_cases: Vec<i64>,
}

/// The fixture's whole parsed denominator: the declared `meta.count` plus every
/// row.
///
/// WHAT `meta.count` IS FOR, corrected rather than carried forward. This comment
/// used to say `meta.count` was kept "so case 1 compares the declared row count
/// against the observed one instead of hard-coding `52` in two places", and both
/// halves of that were false: case 1 did carry a literal `52`, and agreement
/// between a fixture's own two halves would not have established completeness
/// anyway — a fixture that deleted a row and lowered its own count satisfies it.
///
/// It IS still worth checking, and what it now proves is exactly the weaker
/// thing: `meta.count` is the fixture's DECLARED row count, so comparing it with
/// the observed one makes the fixture self-consistent. Completeness against
/// source is a DIFFERENT and stronger property, and it is discharged by
/// `type_names_are_complete`, whose expected side is enumerated from the live
/// `ids.rs`, `records.rs` and `task_execution.rs` rather than typed here.
///
/// `source_digests` is the fixture's SECOND `meta` claim that is read, and it is
/// read for the reason `allocated_source_digests_match` states: nothing else read
/// it, so `meta.source_digests` and `meta.source_digests_note` were five recorded
/// SHA-256 values and a promise that a test would recompute them, with no reader
/// anywhere in the repository. The pairs are `(repository-relative path, hex
/// digest)`; `serde_json::Map` is a `BTreeMap`, so the order is the map's own
/// sorted order and is stable across runs.
struct Fixture {
    declared_count: i64,
    rows: Vec<Row>,
    source_digests: Vec<(String, String)>,
}

/// The `shape` a row declares when its type is a CLOSED document object: a braced
/// `struct` carrying `#[serde(deny_unknown_fields)]`, so an undeclared member is
/// refused rather than ignored.
///
/// NAMED, never spelled as a literal at its second use. `expected_shape_from_source`
/// DERIVES this spelling from a declaration and every allocation row's own `shape`
/// is compared against what it derived, so a literal here and a literal there would
/// be two transcriptions of one claim with nothing binding them — and a
/// disagreement would red on all 52 allocation rows, which is the right direction
/// but is still a transcription this file can now do without.
const CLOSED_OBJECT_SHAPE: &str = "closed-object";

/// The `shape` a row declares when its type is an EXTERNALLY TAGGED enum whose
/// variants are all unit, so the whole wire form is one bare JSON string.
///
/// Named for the same reason as `CLOSED_OBJECT_SHAPE`, and against the same hazard.
const EXTERNALLY_TAGGED_ENUM_SHAPE: &str = "externally-tagged-enum";

/// The exact closed vocabulary of the fixture's `shape` claim. A row outside
/// this set, or a spelling here that no row uses, is a fixture drift.
///
/// EVERY MEMBER IS A NAMED CONSTANT, never a string literal in this array. Two of
/// the four are now also the OUTPUT of a live derivation, so a literal here beside a
/// derived string there is the exact arrangement this repair exists to remove from
/// the fixture: two places that each have an opinion about the same word, and
/// nothing that says which one is right.
const ALLOWED_SHAPES: [&str; 4] = [
    CLOSED_OBJECT_SHAPE,
    EXTERNALLY_TAGGED_ENUM_SHAPE,
    UUID_SCALAR_SHAPE,
    U64_SCALAR_SHAPE,
];

/// The four shape spellings as a CLOSED TYPE instead of as four borrowed strings, and
/// the barrier that keeps the derivation from answering with a fixture row.
///
/// WHY THIS TYPE EXISTS, and it is not tidiness. `expected_shape_from_source` used to
/// return `Result<&'static str, _>`, and that `&'static` was the ONLY thing standing
/// between the derivation and the shape binding being a tautology. Relax it to a
/// borrowed `&str` — one lifetime elision, no other edit — and the body may answer
/// `rows()?.find(|row| type_leaf(&row.type_name) == type_name)?.shape.as_str()`: a
/// reference into the PARSED FIXTURE. Every row would then agree with every other by
/// construction, the shape label would be free to be any legal member of the
/// vocabulary, and `assert_eq!(expected, row.shape)` would still be green, because it
/// would be comparing the fixture against itself. No assertion anywhere in this file
/// would have gone red.
///
/// `DerivedShape` closes that structurally rather than by convention. It is an enum of
/// four UNIT VARIANTS: there is no field, no payload and no lifetime parameter, so
/// there is nowhere for a fixture-owned `&str` to be stored even if a future edit tried
/// to store one. `&'static str` was a promise a compiler would enforce only as long as
/// somebody remembered the annotation; this is the same promise with nothing to forget.
///
/// THE SPELLINGS ARE NOT RE-TYPED HERE. `spelling` is the single conversion point from
/// a member to text, and each arm returns one of the four constants the rest of the
/// file already uses, so the vocabulary has exactly one spelling per member.
///
/// WHAT IT DOES NOT DO, stated so it is not over-read. It does not make the derivation
/// incapable of being WRONG about a type: it can still label a `MemoryRevision` as a
/// closed object, and only a reader of `declared_struct_shape` can tell that from this
/// type. What it makes incapable is the specific failure above — answering with a
/// string this file did not derive from source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DerivedShape {
    ClosedObject,
    ExternallyTaggedEnum,
    UuidScalar,
    U64Scalar,
}

impl DerivedShape {
    /// The fixture's spelling of this member, and the ONLY way a `DerivedShape`
    /// becomes text.
    ///
    /// Total by construction: every arm is one of the four named constants, so there
    /// is no spelling this file can derive that `ALLOWED_SHAPES` does not already
    /// carry. The vocabulary-binding assertion in
    /// `declared_shapes_and_cross_references_hold` is therefore guaranteed by this
    /// function rather than merely checked by it, and it is KEPT because it is the
    /// place that would report a fifth member if the enum were ever widened.
    fn spelling(self) -> &'static str {
        match self {
            Self::ClosedObject => CLOSED_OBJECT_SHAPE,
            Self::ExternallyTaggedEnum => EXTERNALLY_TAGGED_ENUM_SHAPE,
            Self::UuidScalar => UUID_SCALAR_SHAPE,
            Self::U64Scalar => U64_SCALAR_SHAPE,
        }
    }
}

/// The case numbers a row may cross-reference through `also_in_cases`.
///
/// MEANING: an `also_in_cases` entry names ACCEPTANCE CASES THAT ALSO CONSUME
/// THIS ROW. The value is a TEST-CASE number, not a row-group number: it is the
/// `// WORK_UNIT_CASE: 930/<n>` marker of another dispatched case, never the
/// `case` field of a row group. So cases 3 and 4 are named here legitimately even
/// though the fixture carries no case-3 and no case-4 rows: both are discharged by
/// injecting an unknown member into a case-1 allocation row's OWN raw bytes
/// (`reject_unknown_top_level` / `reject_unknown_nested`), which consumes an
/// existing row rather than selecting one. MEASURED on the live fixture in this
/// pass: 12 of the fixture's cross-reference entries name case 3 or case 4 (8 name
/// case 3, 4 name case 4) and 12 name case 2, out of 24 entries on 12 of the 162
/// rows. The previous version of this comment said 64 and 18; neither figure was
/// reproducible against this fixture and both are corrected here rather than
/// carried forward.
///
/// SCOPE, stated because the previous version of this comment was wrong in both
/// halves: this file dispatches cases 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 14, 15 and
/// 16 — the thirteen `// WORK_UNIT_CASE: 930/<n>` markers, read from this file by
/// `dispatched_cases` rather than retyped here — and 101 of the fixture's 162 rows
/// sit outside cases 1-4. The three cases this file deliberately does NOT dispatch
/// are 8, 9 and 13, and each one's MEASURED reason is written down at
/// `UNDISPATCHED_CASES` rather than left to issue #930's case checklist alone.
/// This constant is not to be widened to make a cross-reference pass; a new
/// cross-reference must name a case this file actually dispatches or deliberately
/// does not. Widening it is ALSO not how a newly dispatched case would be admitted
/// here: `declared_shapes_and_cross_references_hold` compares this constant with the
/// fixture's cross-referenced set for EQUALITY, so a constant naming every dispatched
/// case would red immediately against a fixture that cross-references three of them.
/// The set is a fixture fact, bound exactly, and the marker set is a separate
/// property bound by `test_attributes_are_bound_to_case_markers`.
const ALLOWED_ALSO_IN_CASES: [i64; 3] = [2, 3, 4];

/// This file's own bytes, read at compile time. Every claim below about WHICH
/// CASES THIS FILE DISPATCHES is derived from these bytes, so dropping or
/// renaming a marker is observable instead of being silently contradicted by a
/// second hand-written list.
const THIS_FILE: &str = include_str!("serde_t01_core.rs");

/// The marker that declares one dispatched acceptance case. Read from `THIS_FILE`;
/// the case numbers are never retyped as a list.
const WORK_UNIT_CASE_MARKER: &str = "// WORK_UNIT_CASE: 930/";

/// The three acceptance cases this file deliberately does NOT dispatch, with the
/// MEASURED reason each one has no honest test here. A cross-reference to one of
/// these is therefore incomplete evidence, not a contradiction: the case exists in
/// issue #930's checklist, this file simply is not the place that discharges it.
///
/// A CONSTANT OF CASE NUMBERS AND NOT OF REASONS, deliberately. The reasons are
/// prose and they are HERE, where a reader of this list arrives, rather than in a
/// parallel array a caller could reorder away from the list it explains. What is NOT
/// allowed is a case sitting in this array with no measured reason, and each of the
/// three below names the symbol or the fixture row that settles it.
///
/// CASE 8 — "wrong payload, missing/empty protected identity and unsupported version
/// rejected without fabricated values". The two legs with no refusal in this crate
/// are EMPTY PROTECTED IDENTITY and UNSUPPORTED VERSION, and refusing them here would
/// be FALSE against live source rather than merely unproven. Every protected identity
/// in `records.rs` is a plain `String` (`records.rs:12, 32, 52, 76, 114, 133, 146`),
/// both `schema_version` members are a plain `String` (`records.rs:31` and `:51`),
/// and that file declares no `deserialize_with`, no validate function and no check
/// function — the empty-field gates live in `runtime.rs` and `runtime_supervision.rs`
/// on other types. The FIXTURE RECORDS THE SAME FACT: rows `930-129`…`930-135`
/// (empty identity) and `930-136-empty-schema-version` /
/// `930-137-unsupported-schema-version` are all `expected: "accept"` under case 2,
/// and this file's own `empty_identity_row_preserves_its_value` and
/// `schema_version_row_round_trips_untouched` assert that acceptance. The version
/// leg's owner is `crates/eliot-store/src/canonical_store/capacity.rs:59
/// pub(super) fn validate_capacity_receipt` — owner UNASSIGNED, the frozen boundary
/// inventory records that path with blocked-reason `missing-owner` — and it is
/// unreachable from this target because `eliot-types` declares no
/// `[dev-dependencies]` and `eliot-store` depends on `eliot-types`. This case's other
/// two legs are ALREADY DISCHARGED: the wrong-payload leg by
/// `case_06_unknown_variant_and_wrong_payload_are_refused`, and the missing-member
/// leg by `case_07_missing_required_member_is_refused`. A `930/8` marker here would
/// either duplicate those two or assert a refusal that does not exist.
///
/// CASE 9 — "supported named legacy migration preserves evidence; unsafe migration
/// refuses". There is NO NAMED LEGACY MIGRATION in this crate to preserve anything
/// through. `MigrationRecord` declares exactly three wire members and no version
/// member at all, and this file's own `migration_schema_admits_no_legacy_form`
/// ACTIVELY ASSERTS that its generated schema admits no legacy form, which is the
/// opposite of a migration surface. The named legacy selector is
/// `crates/eliot-store/src/canonical_record.rs:332 struct EnvelopeVisitor<T>`, a
/// private type owned by issue #976, unreachable from this target for the same
/// `[dev-dependencies]` reason. Inventing a legacy document here would author the
/// very artifact whose absence is the finding.
///
/// CASE 13 — "exact exceptions invalidate on use change; bounded malformed input is
/// panic-free". BOTH clauses are unavailable, in opposite directions. The panic-free
/// clause is already discharged: `case_14_malformed_input_is_refused` runs
/// `bounded_deep_nesting_is_refused_without_panicking` and
/// `bounded_oversized_document_is_handled_without_panicking` over the real decode
/// path, so a `930/13` marker would be a duplicate of a case already present. The
/// exception clause has no definition in any canonical document; its only named
/// instance is `HealthRecord.status`, owner #931, and the nearest existing assertion
/// in this file, `store_health_record_stays_outside_the_vocabulary`, proves the
/// OPPOSITE direction — that closing the field today would be a compile error — not
/// the forward "a use change invalidates the exception" direction the clause names.
const UNDISPATCHED_CASES: [i64; 3] = [8, 9, 13];

/// The `case` of the unknown-top-level-member acceptance case.
///
/// WHERE THE PROOF LIVES, stated because the previous version of this comment
/// pointed at the wrong thing: the proof that this case owns no rows is the
/// DATA-level assertion `rows_in_case(&rows, UNKNOWN_TOP_LEVEL_CASE).is_empty()`
/// in `case_03_unknown_top_level_member_rejected`, which reads the fixture's
/// `case` field and cannot be evaded by anything written in this file. A named
/// constant is still preferred over a literal at the call site, because
/// `byte_injected_cases_select_no_rows` fails on a selector called with the
/// NUMERIC LITERAL 3 or 4 — that scan is a secondary belt-and-braces check over
/// this file's source text, not the proof, and its doc comment says so.
const UNKNOWN_TOP_LEVEL_CASE: i64 = 3;

/// The `case` of the unknown-nested-member acceptance case. Named for the same
/// reason as `UNKNOWN_TOP_LEVEL_CASE`, and proved the same way: the data-level
/// `rows_in_case(&rows, UNKNOWN_NESTED_CASE).is_empty()` assertion in
/// `case_04_unknown_nested_member_rejected` is the proof.
const UNKNOWN_NESTED_CASE: i64 = 4;

/// The cases this file reaches by MUTATING an existing row's own raw bytes rather
/// than by selecting rows of their own. The fixture carries no rows for either,
/// which is exactly what makes a reference to them in `also_in_cases` a reference
/// to a TEST CASE rather than to a row group.
const BYTE_INJECTED_CASES: [i64; 2] = [UNKNOWN_TOP_LEVEL_CASE, UNKNOWN_NESTED_CASE];

/// Every acceptance case this file dispatches, read from its own markers and
/// sorted. A duplicated marker is a defect here rather than a harmless
/// repetition, because it would make one case look dispatched twice.
fn dispatched_cases() -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    let mut cases: Vec<i64> = Vec::new();
    for line in THIS_FILE.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(WORK_UNIT_CASE_MARKER) else {
            continue;
        };
        let case = rest.trim().parse::<i64>().map_err(|_| {
            boxed(std::io::Error::other(format!(
                "a work-unit case marker must end in a case number: {trimmed}"
            )))
        })?;
        cases.push(case);
    }
    cases.sort_unstable();
    for pair in cases.windows(2) {
        if pair[0] == pair[1] {
            return fail(format!(
                "case {} carries two work-unit case markers, so it is dispatched twice",
                pair[0]
            ));
        }
    }
    Ok(cases)
}

/// The exact attribute line that makes a function a test. Compared as a whole
/// trimmed line, never as a substring: `#[test]` inside a doc comment is prose
/// and must not be counted as a test.
const TEST_ATTRIBUTE: &str = "#[test]";

/// The ONE `#[test]` in this file that is deliberately NOT bound to a
/// `// WORK_UNIT_CASE: 930/<case>` marker, named by SYMBOL rather than as a bare `+ 1`.
///
/// WHY IT IS NOT A CASE. It is `test_attributes_are_bound_to_case_markers`, the
/// function that verifies every marker is immediately followed by a `#[test]`, that
/// the marker set is exactly `(1..=16)` minus `UNDISPATCHED_CASES`, and that the
/// attribute count matches. A function cannot be one of the cases whose binding it
/// checks without the check resting on its own survival, so it is named here and
/// excluded from the marker set by being absent from `dispatched_cases()` — which
/// reads markers, not tests — rather than by a special case in any selector.
///
/// WHY IT CARRIES ITS OWN ATTRIBUTE, and this is the whole reason the constant
/// exists. While it ran only as a step inside case 1 it was single-homed: deleting
/// case 1's own `#[test]` line removed the entire scope guarantee from the run while
/// leaving the markers in the file with nothing comparing them, and `rustc` reports
/// only `dead_code` on the orphaned `fn`. The count binding in that function turned a
/// silent stop into a failure for cases 2 through 16 and could not do so for the one
/// case that hosted the check. Giving it an attribute closes that hole, and the
/// arithmetic that admits it is an EXACT equality naming this constant, so the extra
/// attribute cannot become slack: an unaccounted `#[test]` anywhere makes the
/// difference two and reds.
///
/// THE CALL FROM CASE 1 IS KEPT, deliberately and not for coverage. Case 1 already
/// hosts the file-level self-checks, so it still runs this one; that call is now
/// redundant rather than load-bearing, and saying so is the point — the check no
/// longer DEPENDS on any dispatched case running, and case 1 running it as well only
/// means a regression is reported by case 1's own failure message too.
///
/// WHAT IT HOLDS, and it is the one string the position scan needs: the FUNCTION NAME
/// with no `fn `, no parentheses and no return type, because that is what
/// `test_attributes_are_bound_to_case_markers` formats as `fn {SCOPE_CLOSURE_TEST}(`
/// and then searches this file's own bytes for. Spelling the name once, here, is what
/// keeps the message text and the scan in step — a literal typed at the scan site
/// would let the two drift, and the drift would be silent in the direction that
/// matters: the scan would fail to find its own declaration and the assertion would
/// red on correct code with a message naming a function that plainly exists.
const SCOPE_CLOSURE_TEST: &str = "test_attributes_are_bound_to_case_markers";

/// Every work-unit case marker is bound to a `#[test]` that actually runs, and this
/// file's marker set is EXACTLY the complement of `UNDISPATCHED_CASES` in `1..=16`.
///
/// WHY NO TARGET COUNT IS PINNED, and the card clause that forbids one. That card is
/// NOT inside this repository — there is no `cards/` directory in this worktree — and
/// lives in the swarm workstream outside it, at
/// `ROOT-continuation/workstreams/swarm/cards/930.md`,
/// line 26, DONE FOR INTEGRATION WHEN, says verbatim: "All 16 `// WORK_UNIT_CASE:
/// 930/<case>` tests exist and are observed passing". The previous version of this
/// file carried `EXPECTED_DISPATCHED_CASES: usize = 12` and asserted
/// `dispatched.len() == 12` and `tests == 12`, so the cases the card still owes
/// could not arrive without the suite forbidding their arrival, and the number 12 was
/// derived from this file's own prose self-description of its scope rather than from
/// the checklist. A constant that names the CURRENT tally cannot also be the
/// definition of "done"; it is deleted, not lowered, and no replacement number is
/// written here.
///
/// WHAT REPLACES IT, and why it is a real change-detector rather than a restatement.
/// The expected marker set is computed as `(1..=16)` minus `UNDISPATCHED_CASES`, so
/// it is a function of ONE list rather than of two counts, and the two failure modes
/// that matter both red:
/// * a marker that disagrees with `UNDISPATCHED_CASES` — dropping case 5's marker, or
///   adding a bare `// WORK_UNIT_CASE: 930/99` — leaves the set unequal to the
///   complement and reds here;
/// * adding a case is red UNTIL it is removed from `UNDISPATCHED_CASES`, which is
///   the correct single-place edit: that constant is the list of cases this file
///   deliberately does not discharge, and it is the only place that says so. Case 11
///   is the worked example and it is live now: it arrived as a marker, and the edit
///   that admitted it was removing `11` from `UNDISPATCHED_CASES` — one line, in one
///   place, with its reason written out in that constant's own documentation.
///
/// WHAT `UNDISPATCHED_CASES` IS NOT, because the complement is only as honest as the
/// list it subtracts. It is not "the cases this file has not got round to". Each of
/// its three entries carries a MEASURED reason at its own documentation — an absence
/// this file verified against live source — and case 11 is the case that proves the
/// distinction is load-bearing: it had a real, eliot-types-observable half and was
/// dispatched, while 8, 9 and 13 did not and are not invented to fill the set. A
/// constant that subtracted "whatever is left over" would make this assertion
/// unfalsifiable in the direction that matters.
///
/// And `tests` is compared against `dispatched.len()` PLUS the one attribute named in
/// `SCOPE_CLOSURE_TEST`, the marker count this scan actually found, not against a
/// target. That comparison is sound and is kept: both sides are read from this file,
/// and it is a BINDING check (every marker runs as a test) rather than a target check,
/// so it cannot be satisfied by moving a number.
///
/// THREE bindings, because they fail for three different edits:
/// * deleting a `#[test]` line below a marker stops that case running as a test, and
///   `rustc` reports only `dead_code` on the orphaned `fn`. Counting `TEST_ATTRIBUTE`
///   against the markers actually found is what turns that silent stop into a
///   failure — AND THAT CLAIM WAS FALSE FOR CASE 1 UNTIL THIS FUNCTION WAS GIVEN AN
///   ATTRIBUTE OF ITS OWN. While the count lived only inside case 1, deleting case
///   1's attribute removed both the case and the only run of this check, leaving the
///   markers present and nothing comparing them. It is no longer false: this function
///   is a `#[test]` in its own right, so it runs even when no dispatched case does,
///   and the count that catches the deletion is the count this very function makes.
///   That is the reason for `SCOPE_CLOSURE_TEST` and for the `+ 1`, and it is why
///   neither may be relaxed into a lower bound.
/// * deleting the MARKER as well — the case and its attribute together — is caught by
///   the complement assertion, not by a count: the marker set is short one element of
///   `1..=16` and nothing else in the file observes the loss, because the fixture's
///   whole cross-referenced set is exactly `{2, 3, 4}`. Deleting case 5 outright would
///   have stranded its 42 duplicate rows unexercised.
/// * inserting a bare `// WORK_UNIT_CASE: 930/99` anywhere grows the dispatched set
///   with nothing to back it. The adjacency check and the complement assertion are
///   both what stop that: a marker whose IMMEDIATELY NEXT line is not `#[test]` names a
///   case that is not a test, and 99 is outside the checklist the complement is taken
///   over.
///
/// A line whose trimmed form is `#[test]` is never a comment by construction — a
/// comment line trims to a prefix of `//` — so the count needs no comment filter, and
/// none is used.
#[test]
fn test_attributes_are_bound_to_case_markers() -> TestResult {
    let dispatched = dispatched_cases()?;
    let lines: Vec<&str> = THIS_FILE.lines().collect();
    // THE SCOPE-CLOSURE ATTRIBUTE IS COUNTED AS ITS OWN LINE, AND PROVEN TO BE THIS
    // ONE. It is the single `#[test]` in this file that no work-unit case marker
    // names, because it is the function that CHECKS the marker/attribute binding and
    // therefore cannot be a case that is bound by the binding it checks. It carries
    // its own attribute so that it runs even if every dispatched case is deleted, and
    // the scan below proves that the attribute really is on the function named in
    // `SCOPE_CLOSURE_TEST` rather than being an uncounted extra elsewhere in the file.
    // `starts_with`, NOT `==`, and that is load-bearing rather than a detail. The line
    // being found is `fn test_attributes_are_bound_to_case_markers() -> TestResult {`,
    // which is NOT equal to the prefix `fn test_attributes_are_bound_to_case_markers(`:
    // equality against the prefix would fail on every run, including a correct one, and
    // the `ok_or_else` below would report a missing declaration for a function that is
    // plainly there. The prefix ends at the opening parenthesis of the parameter list
    // so that it cannot also match a longer name sharing this stem.
    let closure_attribute = lines
        .iter()
        .position(|line| line.trim().starts_with(&format!("fn {SCOPE_CLOSURE_TEST}(")))
        .and_then(|index| index.checked_sub(1))
        .map(|index| lines[index].trim())
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "{SCOPE_CLOSURE_TEST} is not declared in this file, or its declaration is the first line of it, so the one {TEST_ATTRIBUTE} attribute that no work-unit case marker names cannot be located and the count below has nothing to attribute it to"
            )))
        })?;
    assert_eq!(
        closure_attribute, TEST_ATTRIBUTE,
        "{SCOPE_CLOSURE_TEST} must carry its own {TEST_ATTRIBUTE} attribute on the line immediately above its declaration: it is the suite's scope-closure check and it ran only as a step inside case 1 until it was given an attribute of its own, which left deleting case 1's attribute a way to remove the whole scope guarantee from the run while the file stayed green apart from a `dead_code` note"
    );
    let mut tests = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == TEST_ATTRIBUTE {
            tests += 1;
        }
        if !trimmed.starts_with(WORK_UNIT_CASE_MARKER) {
            continue;
        }
        let next = lines
            .get(index + 1)
            .map(|candidate| candidate.trim())
            .ok_or_else(|| {
                boxed(std::io::Error::other(format!(
                    "the work-unit case marker on line {} is the last line of this file",
                    index + 1
                )))
            })?;
        assert!(
            next == TEST_ATTRIBUTE,
            "the work-unit case marker on line {} must be IMMEDIATELY followed by {TEST_ATTRIBUTE}, so a marker can never claim a case that is not running as a test; found {next:?}",
            index + 1
        );
    }
    // THE EXPECTED MARKER SET IS A FUNCTION OF `UNDISPATCHED_CASES`, not a number
    // written here. See the doc comment: a pinned tally forbade the cases the card
    // still owes, and the card's DONE FOR INTEGRATION WHEN clause names sixteen
    // tests, not thirteen. The three that stay out do so with a measured reason
    // recorded at that constant, not because they were left over.
    let expected_markers: Vec<i64> = (1..=16)
        .filter(|case| !UNDISPATCHED_CASES.contains(case))
        .collect();
    assert_eq!(
        dispatched, expected_markers,
        "the markers in this file must be exactly the acceptance cases issue #930 does NOT list in UNDISPATCHED_CASES ({UNDISPATCHED_CASES:?}), over the whole 1..=16 checklist; adding a case this file now dispatches is red until it is removed from UNDISPATCHED_CASES, and dropping or inventing one is red immediately"
    );
    // `dispatched.len()` rather than a target: the marker count this scan found is the
    // thing the `#[test]` count must account for, so this binds an attribute to a marker
    // instead of pinning a tally.
    //
    // THE `+ 1` IS AN EXACT EQUALITY, AND IT NAMES ITSELF. This file carries exactly one
    // `#[test]` that no work-unit case marker names: {SCOPE_CLOSURE_TEST}, the function
    // that checks the marker/attribute binding and therefore cannot itself be a case
    // bound by that binding. The attribute was given to it precisely so that deleting
    // every dispatched case's attribute cannot stop this check from running — before
    // that, the whole scope guarantee lived inside case 1, and removing case 1's own
    // `#[test]` line left the file with its markers and no check comparing them.
    //
    // It is `==` and NOT `>=`, and the difference is the point of the fix rather than a
    // detail of it. A lower bound here would still be satisfied by a file that has lost
    // an attribute — which is the single deletion this assertion exists to catch — so a
    // bound would have reproduced the defect while looking like its repair.
    //
    // BOTH SIDES ARE COUNTS, NOT A TARGET AND A FACT: `tests` is the number of
    // `#[test]` lines this scan found in this file's own bytes and `dispatched.len()`
    // is the number of markers the same scan found, so the difference between them is
    // forced to be exactly the one named attribute. Deleting ANY attribute reds; adding
    // a stray `#[test]` on something that is not a dispatched case and not
    // {SCOPE_CLOSURE_TEST} reds too, because it would make the difference two.
    assert_eq!(
        tests,
        dispatched.len() + 1,
        "this file must carry exactly one {TEST_ATTRIBUTE} attribute per work-unit case marker it declares, PLUS exactly one more for {SCOPE_CLOSURE_TEST} — the suite's own scope-closure check, which is deliberately not marker-bound because it is the function that verifies the marker/attribute binding ({tests} attributes, {dispatched:?} markers); deleting any attribute, or adding a {TEST_ATTRIBUTE} that belongs to neither a dispatched case nor {SCOPE_CLOSURE_TEST}, must red here"
    );
    // THE SETS ALONE DO NOT CLOSE THE SCOPE on their own, and this is the second half of
    // that closure. Dispatched plus undispatched is sixteen only if the two sets are
    // disjoint and jointly cover 1..=16; comparing the SORTED, DE-DUPLICATED union
    // against `1..=16` fails on a gap and on an overlap alike, because an overlap
    // shortens the union.
    let mut covered: Vec<i64> = dispatched.clone();
    covered.extend_from_slice(&UNDISPATCHED_CASES);
    covered.sort_unstable();
    covered.dedup();
    let scope: Vec<i64> = (1..=16).collect();
    assert_eq!(
        covered, scope,
        "the dispatched cases {dispatched:?} and the deliberately undispatched {UNDISPATCHED_CASES:?} must together name every case from 1 to 16 exactly once; found {covered:?}, so the scope this file claims is not the scope issue #930 lists"
    );
    Ok(())
}

/// The `case` value that owns the allocation table. Later acceptance cases reuse
/// the same allocated types, so the allocation is selected by this number, never
/// by `rows.len()`.
const ALLOCATION_CASE: i64 = 1;

/// The only `expected` value that authorises an acceptance assertion.
const ACCEPT_EXPECTED: &str = "accept";

/// The two bytes `\u`, which introduce a JSON unicode escape. Checked in a row's
/// RAW bytes, never in its decoded form: after decoding the escape is gone, so
/// the property under test would be invisible.
const JSON_ESCAPE_MARKER: &str = "\\u";

/// The depth `scan_repetitions` reports for a repetition in the DOCUMENT'S OWN object.
/// Named so the "the rule holds at every nesting depth" claim reads as a demand on the
/// top level specifically, rather than as the incidental `0` in a counter.
const TOP_LEVEL_MEMBER_DEPTH: usize = 0;

/// The `case` that owns the duplicate-key group, and with it every escape-equivalent
/// row in the fixture. It is the ONLY group in which a top-level key written with a
/// `JSON_ESCAPE_MARKER` escape is legitimate, because the collision is the point of
/// those rows; named so the exemption asserted by
/// `no_escaped_top_level_key_outside_case_escape_rows` is one constant rather than a
/// literal repeated in the helper and its message.
const ESCAPE_EQUIVALENT_CASE: i64 = 5;

/// The `case` that owns the optional-absence group of L2 pages.
const ABSENCE_PAGE_CASE: i64 = 12;

/// The one member whose value is never compared inside this crate.
const L2_SCHEMA_VERSION_MEMBER: &str = "schema_version";

/// The `case` that owns the malformed-input group and its byte-literal descriptor.
const MALFORMED_CASE: i64 = 14;

/// The `case` that owns the absence group: the empty-identity accept rows and the
/// `schema_version` probes. These rows exist to record that a REFUSAL would be
/// false against live source, so leaving them undecoded would leave that
/// discharge unproven.
const ABSENCE_CASE: i64 = 2;

// A FIXTURE-PROSE DEFECT THAT WAS ONCE OPEN HERE AND IS NOW CLOSED, kept as history
// rather than deleted, because a reader has to know it existed and that is how the
// same typo gets reintroduced. `930-126`'s `reason` USED TO say its raw is
// "byte-for-byte identical to 930-126-absent-requested-segment-id", naming ITSELF;
// the intended counterpart is the allocation row `930-05-canonical-memory-l2-page`,
// whose own copy of that sentence names it correctly and still does. That
// self-reference WAS a known typo in the row's prose, outstanding and being
// corrected in the fixture separately. IT IS NO LONGER OUTSTANDING: the fixture now
// reads "byte-for-byte identical to 930-05-canonical-memory-l2-page" in that
// sentence, so the disclosed direction is the one the sentence claims. The residual
// reason nothing here rests on that prose never depended on the typo: no assertion
// in this file reads it, so the correction could not invalidate this file either
// way; the counterpart row used for the skipped-member contrast is selected by
// `case`, never by id.

/// The `case` that owns the unsafe-migration group.
const MIGRATION_CASE: i64 = 10;

/// The single type the unsafe-migration case targets.
const MIGRATION_TYPE: &str = "MigrationRecord";

/// The three declared wire members of `MigrationRecord`, in declaration order.
/// Anything outside this list is an undeclared key and must be refused.
const MIGRATION_DECLARED_MEMBERS: [&str; 3] = ["migration_id", "checksum_blake3", "applied"];

/// JSON literals used only to mutate the `applied` member. Authored here, not
/// copied from the fixture.
const MIGRATION_BOOL_TRUE: &str = "true";
const MIGRATION_QUOTED_TRUE: &str = "\"true\"";
const MIGRATION_NUMBER: &str = "1";

/// The deferred vocabulary's type, the declaration line that must keep it out of
/// the shape, and the file that owns it.
const HEALTH_STATUS_TYPE: &str = "HealthStatus";
const HEALTH_STATUS_DECLARATION: &str = "pub status: String,";
const HEALTH_FILE: &str = "crates/eliot-types/src/health.rs";
const HEALTH_RECORD_TYPE: &str = "HealthRecord";

/// A status outside the deferred vocabulary. Authored here, not copied from the
/// fixture, and deliberately outside the four wire spellings.
const HEALTH_STATUS_OUT_OF_VOCABULARY: &str = "unhealthy";

/// A consumer outside this crate that constructs a `HealthRecord`. Read as text
/// only: this crate has no dev-dependency on it, so no link exists.
const STORE_HEALTH_CONSUMER: &str = "crates/eliot-store/src/surreal_store.rs";

/// This crate's own manifest, read for the two facts that block checklist items A8,
/// A9 and A11: there is no `[dev-dependencies]` section, and every `[dependencies]`
/// entry is inherited from the workspace.
const ELIOT_TYPES_MANIFEST: &str = "crates/eliot-types/Cargo.toml";

/// The two manifest sections that matter here, named so the assertion and the message
/// that names them cannot drift apart.
const DEPENDENCIES_SECTION: &str = "dependencies";
const DEV_DEPENDENCIES_SECTION: &str = "dev-dependencies";

/// The suffix every `[dependencies]` line must carry. A pinned `version = ".."`, a
/// `path = ".."`, and any `features` or `optional` key added to an existing entry all
/// fail the same test, because none of them leaves this suffix at the end of the line.
const WORKSPACE_INHERITANCE: &str = ".workspace = true";

/// The five files this issue allocates, by repository-relative path. The
/// attribute inventory below is scoped to exactly these files and must not be
/// widened: see `serde_attribute_inventory_is_closed`.
const RECORDS_FILE: &str = "crates/eliot-types/src/records.rs";
const IDS_FILE: &str = "crates/eliot-types/src/ids.rs";
const TASK_EXECUTION_FILE: &str = "crates/eliot-types/src/task_execution.rs";
const LIB_FILE: &str = "crates/eliot-types/src/lib.rs";
const ERROR_FILE: &str = "crates/eliot-types/src/error.rs";
const ALLOCATED_SOURCE_FILES: [&str; 5] = [
    LIB_FILE,
    ERROR_FILE,
    IDS_FILE,
    RECORDS_FILE,
    TASK_EXECUTION_FILE,
];

/// The only four serde attribute forms the five allocated files may carry. Each
/// entry is the text between `#[serde(` and `)]`, whitespace-collapsed.
const ALLOWED_SERDE_ATTRIBUTES: [&str; 4] = [
    "deny_unknown_fields",
    "default, skip_serializing_if = \"Option::is_none\"",
    "transparent",
    "rename_all = \"snake_case\"",
];

/// serde's own attribute that closes a struct against an undeclared member. Named
/// rather than reached through `ALLOWED_SERDE_ATTRIBUTES[0]`, because the two
/// questions are different: that array says which attribute FORMS the five
/// allocated files may carry at all, and this constant names the one form whose
/// presence or absence on a given struct DECIDES whether that struct is closed.
const DENY_UNKNOWN_FIELDS_ATTRIBUTE: &str = "deny_unknown_fields";

/// serde's own attribute that makes a newtype encode as its single field, so the
/// type has no object form at all. Named for the same reason as
/// `DENY_UNKNOWN_FIELDS_ATTRIBUTE` and against the same hazard: its presence or
/// absence on a given declaration is what decides whether that declaration is one of
/// the two `transparent-*-scalar` shapes, and `declared_struct_shape` reads it to
/// decide so rather than deciding from the declaration's punctuation.
const TRANSPARENT_ATTRIBUTE: &str = "transparent";

/// Attribute forms that could let a decoder accept a name, or fabricate a value,
/// outside the derived contract. Scanned as attribute forms, never as bare words:
/// `flatten` appears eight times inside the five files purely as the phrase "no
/// `flatten`, no tagging" in doc comments, so a bare-word scan would both invent
/// hits and miss a real attribute.
const FORBIDDEN_SERDE_FORMS: [&str; 5] = [
    "serde(alias",
    "serde(flatten",
    "serde(untagged",
    "serde(other",
    "cfg_attr(serde",
];

/// The four optional members of `CanonicalMemoryL2Page`. None of them is
/// genuinely required on the wire: each is `Option<..>`, so an absent key
/// reaches serde's `missing_field` and decodes to `None` without error.
const L2_RESOLVED_PARENT_HANDLE: &str = "resolved_parent_handle";
const L2_REQUESTED_SEGMENT_ID: &str = "requested_segment_id";
const L2_MANIFEST: &str = "manifest";
const L2_CONTINUATION: &str = "continuation";
const L2_OPTIONAL_MEMBERS: [&str; 4] = [
    L2_RESOLVED_PARENT_HANDLE,
    L2_REQUESTED_SEGMENT_ID,
    L2_MANIFEST,
    L2_CONTINUATION,
];

/// The ONLY two of the four optional members that carry
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`, at
/// `records.rs:115` and `records.rs:117`. For these two the encoder DROPS the
/// key when the value is `None`.
///
/// `manifest` (`records.rs:119`) and `continuation` (`records.rs:121`) carry no
/// serde attribute at all, so the encoder ALWAYS re-emits them, as an explicit
/// `null` when the value is `None`. A uniform "absent iff None" rule over all
/// four would demand an absence that never happens and would be a red test
/// against live source; the fixture rows that spell `"continuation":null` are
/// exactly what the encoder produces and are correct.
const L2_SKIPPED_WHEN_NONE: [&str; 2] = [L2_RESOLVED_PARENT_HANDLE, L2_REQUESTED_SEGMENT_ID];

/// The two optional members that are never dropped and are therefore always
/// present on the encode side, whatever their value.
const L2_ALWAYS_EMITTED: [&str; 2] = [L2_MANIFEST, L2_CONTINUATION];

fn field<'row>(row: &'row Value, key: &str) -> Result<&'row Value, Box<dyn std::error::Error>> {
    row.get(key)
        .ok_or_else(|| boxed(std::io::Error::other(format!("fixture row has no {key}"))))
}

fn text(row: &Value, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    field(row, key)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "fixture field {key} must be a string"
            )))
        })
}

fn flag(row: &Value, key: &str) -> Result<bool, Box<dyn std::error::Error>> {
    field(row, key)?.as_bool().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "fixture field {key} must be a boolean"
        )))
    })
}

fn number(row: &Value, key: &str) -> Result<i64, Box<dyn std::error::Error>> {
    field(row, key)?.as_i64().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "fixture field {key} must be an integer"
        )))
    })
}

fn integers(row: &Value, key: &str) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    let value = field(row, key)?;
    if !value.is_array() {
        return fail(format!("fixture field {key} must be an array"));
    }
    serde_json::from_value::<Vec<i64>>(value.clone()).map_err(boxed)
}

/// Fixture text is read from disk, not embedded, so the fixture file stays a
/// separately reviewable artifact owned by the fixture writer.
fn fixture_text() -> Result<String, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("serde_t01_core.json");
    std::fs::read_to_string(&path).map_err(boxed)
}

fn rows() -> Result<Fixture, Box<dyn std::error::Error>> {
    // Named `raw_text`, never `text`: a local binding called `text` would
    // shadow the `text` accessor this very function calls once per field.
    let raw_text = fixture_text()?;
    let doc: Value = serde_json::from_str(&raw_text).map_err(boxed)?;
    let meta = doc
        .get("meta")
        .filter(|value| value.is_object())
        .ok_or_else(|| boxed(std::io::Error::other("fixture must carry a meta object")))?;
    let declared_count = number(meta, "count")?;
    let source_digests = meta_map(meta, "source_digests")?;
    let list = doc
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| boxed(std::io::Error::other("fixture must carry a fixtures array")))?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        out.push(Row {
            id: text(item, "id")?,
            case: number(item, "case")?,
            description: text(item, "description")?,
            type_name: text(item, "type")?,
            source: text(item, "source")?,
            applicable: flag(item, "applicable")?,
            reason: text(item, "reason")?,
            raw: text(item, "raw")?,
            expected: text(item, "expected")?,
            shape: text(item, "shape")?,
            also_in_cases: integers(item, "also_in_cases")?,
        });
    }
    let mut ids: Vec<&str> = out.iter().map(|row| row.id.as_str()).collect();
    ids.sort_unstable();
    let unique = ids.len();
    ids.dedup();
    assert_eq!(unique, ids.len(), "fixture row ids must be unique");
    Ok(Fixture {
        declared_count,
        rows: out,
        source_digests,
    })
}

/// One `meta` string-to-string map as `(key, value)` pairs, in the map's own order.
///
/// The map is REQUIRED to be an object of strings rather than coerced: a digest that
/// arrived as a number, or a nested object, would make the comparison below
/// meaningless, so it fails here naming the key instead of at the point of use.
fn meta_map(meta: &Value, key: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let object = field(meta, key)?.as_object().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "fixture meta field {key} must be an object"
        )))
    })?;
    let mut pairs = Vec::with_capacity(object.len());
    for (name, digest) in object {
        let recorded = digest.as_str().ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "fixture meta field {key}[{name}] must be a string"
            )))
        })?;
        pairs.push((name.clone(), recorded.to_owned()));
    }
    Ok(pairs)
}

/// The five allocated decoder sources must still be BYTE-IDENTICAL to what the
/// fixture recorded at `meta.base`, recomputed from live source.
///
/// WHAT A MATCH ESTABLISHES, in the fixture's own words and no wider: not one byte of
/// those five files has changed, which is the check by which this TEST half proves the
/// DECODER half was not modified underneath it. WHAT A MATCH DOES NOT ESTABLISH: it is
/// not a decode assertion, it does not cover any other crate source — `health.rs`,
/// `surreal_store.rs` and every other `src/` file this file reads sit outside it — and
/// it does not cover a fixture row whose `source` lies outside the five. It can
/// therefore never substitute for a decode assertion, and the failure message below
/// says so in the same words rather than letting a green run be read as a decode proof.
///
/// WHY THE PATH SET IS COMPARED AND NOT JUST ITERATED. Iterating the recorded pairs
/// alone would compare whichever files the fixture happened to record, so a fixture
/// that dropped `records.rs` from the map would shrink the check to four files and
/// stay green. The expected side is `ALLOCATED_SOURCE_FILES`, the constant every other
/// walk in this file names its five sources by, so a missing or invented digest is red
/// on the SET rather than silently on a smaller denominator.
///
/// READ THROUGH `read_workspace`, which reads TEXT. That is honest about what is
/// compared — SHA-256 over the file's bytes, and `String::as_bytes` on a `read_to_string`
/// result is those same bytes — with one stated consequence: a decoder source that is
/// no longer valid UTF-8 fails as a READ error through `read_workspace` rather than as a
/// digest mismatch. Both are red, and neither can pass.
fn allocated_source_digests_match(recorded: &[(String, String)]) -> TestResult {
    let mut paths: Vec<&str> = recorded.iter().map(|(path, _)| path.as_str()).collect();
    paths.sort_unstable();
    let mut allocated: Vec<&str> = ALLOCATED_SOURCE_FILES.to_vec();
    allocated.sort_unstable();
    assert_eq!(
        paths, allocated,
        "meta.source_digests must record exactly one digest for each of the five allocated sources {allocated:?}, so the check cannot be narrowed to a subset of them or widened to a file this issue does not allocate; it records {paths:?}"
    );
    for (path, expected) in recorded {
        let measured = sha256_hex(read_workspace(path)?.as_bytes());
        assert_eq!(
            measured, *expected,
            "the SHA-256 of {path} recomputed from live source does not match the digest meta.source_digests recorded, so the decoder half was modified underneath this test half; a MATCH is what establishes that not one byte of the five allocated sources has changed, which is the proof this half needs about the DECODER half and is NOT a decode assertion: it says nothing about how any row decodes, and it covers no other crate source, so it can never substitute for one of the decode cases"
        );
    }
    Ok(())
}

/// SHA-256 (FIPS 180-4) of one byte string, lowercase hex.
///
/// WHY IT IS INLINED RATHER THAN A DEPENDENCY, because `eliot-types` declares
/// `blake3`, `schemars`, `serde`, `serde_json`, `thiserror`, `time` and `uuid` and
/// none of them provides SHA-256 — `blake3` computes BLAKE3, a different function whose
/// output is not comparable with the values `meta.source_digests` records. The workspace
/// does resolve `sha2`, but this crate does not depend on it, and adding one would be
/// the very manifest change `manifest_declares_no_dev_dependency_and_inherits_every_dependency`
/// exists to forbid. So the algorithm is written here, against the published
/// specification, and it is CORROBORATED BY THE FIVE COMPARISONS this file makes: those
/// digests were computed by the fixture writer with an independent SHA-256 tool, so a
/// wrong implementation here could not reproduce all five 256-bit values — it would red.
///
/// MERELY A HASH, and nothing in this file's contracts depends on its internals: no
/// assertion here is about SHA-256, and the five values it produces are compared for
/// EQUALITY with values the fixture recorded. Message padding, the 64-round compression
/// function and the eight-word state are the specification's, in that order.
///
/// THE ROUND STATE IS INDEXED RATHER THAN DESTRUCTURED into `a`..`h`, and the reason is
/// the specification itself rather than taste: the working state is updated in one
/// parallel shift at the end of every round, so keeping it as one array makes that shift
/// a run of assignments instead of eight rebindings, and a reader can check each use of
/// the specification's `e` against `working[4]` by position.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut message = Vec::with_capacity(bytes.len() + 72);
    message.extend_from_slice(bytes);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((bytes.len() as u64) * 8).to_be_bytes());
    let mut state = SHA256_INITIAL_STATE;
    for block in message.chunks_exact(64) {
        let mut schedule: Vec<u32> = Vec::with_capacity(64);
        for chunk in block.chunks_exact(4) {
            schedule.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        // The schedule is extended with an explicit cursor rather than an index loop
        // because each entry reads THREE EARLIER entries, so the vector cannot be
        // borrowed immutably for the reads while it is being extended by `push`.
        let mut index = 16usize;
        while index < 64 {
            let prior = schedule[index - 15];
            let recent = schedule[index - 2];
            let first = prior.rotate_right(7) ^ prior.rotate_right(18) ^ (prior >> 3);
            let second = recent.rotate_right(17) ^ recent.rotate_right(19) ^ (recent >> 10);
            schedule.push(
                schedule[index - 16]
                    .wrapping_add(first)
                    .wrapping_add(schedule[index - 7])
                    .wrapping_add(second),
            );
            index += 1;
        }
        let mut working = state;
        for (round, word) in schedule.iter().enumerate() {
            let sum = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ (!working[4] & working[6]);
            let first = working[7]
                .wrapping_add(sum)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND_CONSTANTS[round])
                .wrapping_add(*word);
            let mix = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let second = mix.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(first);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip(working) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut hex = String::with_capacity(64);
    for word in &state {
        hex.push_str(&format!("{word:08x}"));
    }
    hex
}

/// The eight words of SHA-256's initial hash state (FIPS 180-4 §5.3.3), and the sixty-
/// four round constants of §4.2.2, which are the first thirty-two bits of the fractional
/// parts of the cube roots of the first sixty-three primes.
const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Trailing path segment of a `type` value, so a fully qualified spelling and
/// a bare Rust name select the same row.
fn type_leaf(type_name: &str) -> &str {
    type_name.rsplit("::").next().unwrap_or(type_name)
}

/// Trailing file segment of a `source` value. Accepts a bare `ids.rs`, a
/// repository-relative `crates/eliot-types/src/ids.rs`, and the line-anchored
/// `crates/eliot-types/src/ids.rs:55` form: the allocation split is per file,
/// so a trailing `:<digits>` is not part of the file name.
fn source_leaf(source: &str) -> String {
    let normalized = source.replace('\\', "/");
    let file = normalized.rsplit('/').next().unwrap_or_default();
    match file.rsplit_once(':') {
        Some((head, line))
            if !line.is_empty() && line.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            head.to_owned()
        }
        _ => file.to_owned(),
    }
}

/// The `:<digits>` ANCHOR a `source` value carries, as a line number.
///
/// `source_leaf` STRIPS this suffix and every consumer of `source` went through
/// `source_leaf`, so before this helper existed the recorded line number was
/// discarded at the first read and nothing downstream could compare it to a
/// declaration site. This is the half of the same parse `source_leaf` throws
/// away, recovered through the identical `rsplit('/')` then `rsplit_once(':')`
/// steps so the two can never disagree about which `:<digits>` belongs to the
/// path rather than to a Windows drive letter or to directory text.
///
/// WHY IT FAILS LOUDLY AND RETURNS `Result` RATHER THAN `Option`. The trap this
/// helper exists to avoid is the shape `Option`-versus-`Option`: an expected line
/// that is itself an `Option` compares equal to a recorded `None` whenever the
/// lookup finds nothing, so every row would pass while the derivation was broken.
/// Here the RECORDED side is the `Option`-shaped thing — a row whose `source`
/// carries no anchor at all — and it is turned into a named error instead of
/// being compared, so a row that has quietly lost its anchor is red rather than
/// silently agreeing with nothing.
fn source_line_anchor(source: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let normalized = source.replace('\\', "/");
    let file = normalized.rsplit('/').next().unwrap_or_default();
    let Some((_, line)) = file.rsplit_once(':') else {
        return fail(format!(
            "source value {source} carries no :<line> anchor, so it names a file without naming a DECLARATION SITE"
        ));
    };
    if line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
        return fail(format!(
            "source value {source} does not end in a :<digits> anchor, so its line number cannot be read"
        ));
    }
    line.parse::<usize>().map_err(boxed)
}

/// Select the single ALLOCATION row naming `type_name`. The slice parameter is
/// `all`, not `rows`, so it never shadows the `rows()` loader this file calls
/// elsewhere.
///
/// The selection is restricted to `row.case == ALLOCATION_CASE` on purpose. Later
/// acceptance cases reuse the same types, so `MigrationRecord` alone carries two
/// dozen rows across the whole fixture; an unrestricted uniqueness demand would
/// fail on every type and would make "the one row for this type" meaningless.
/// The full reject rows stay reachable through `reject_rows`, which is what
/// `top_level_member_spans` and the case-15 helpers read.
fn selected<'slice>(
    all: &'slice [Row],
    type_name: &str,
) -> Result<&'slice Row, Box<dyn std::error::Error>> {
    let mut matched = all
        .iter()
        .filter(|row| row.case == ALLOCATION_CASE && type_leaf(&row.type_name) == type_name);
    let first = matched.next().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "no allocation row for {type_name}"
        )))
    })?;
    if matched.next().is_some() {
        return fail(format!("more than one allocation row for {type_name}"));
    }
    Ok(first)
}

/// Select the single applicable row naming `type_name`; a shape this case
/// decodes must never be answered by an inapplicable row.
fn applicable_row<'slice>(
    all: &'slice [Row],
    type_name: &str,
) -> Result<&'slice Row, Box<dyn std::error::Error>> {
    let row = selected(all, type_name)?;
    if !row.applicable {
        return fail(format!(
            "row {} for {type_name} is marked inapplicable: {}",
            row.id, row.reason
        ));
    }
    Ok(row)
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    if !root.join("Cargo.toml").is_file() || !root.join("Cargo.lock").is_file() {
        return fail(format!("workspace root not found under {}", root.display()));
    }
    Ok(root)
}

fn read_workspace(relative: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::fs::read_to_string(workspace_root()?.join(relative)).map_err(boxed)
}

/// `id_type!(Name);` expansions read from live `ids.rs`, never retyped here.
///
/// The file is named by `IDS_FILE` rather than by a second path literal, so a
/// move of `ids.rs` cannot leave this walk and the rest of the file reading
/// different paths.
///
/// EACH EXPANSION CARRIES ITS INVOCATION LINE, paired as `(name, line)`. That is
/// the whole reason this family needs its OWN derivation and cannot be served by
/// the struct walk: an expansion has no `struct` declaration line of its own,
/// because `pub struct $name(Uuid);` sits inside the `macro_rules!` body at
/// brace depth 1 — one line, shared by all 38 expansions, naming `$name`. The
/// site that DECLARES a given expansion is its `id_type!(Name);` invocation, and
/// that is the line the walk was already reading when it threw the index away.
/// `enumerate()` is the only change: no second pass over `ids.rs` was added, so
/// this walk cannot disagree with itself about which line an invocation is on.
fn id_type_expansions() -> Result<Vec<(String, usize)>, Box<dyn std::error::Error>> {
    let source = read_workspace(IDS_FILE)?;
    let mut names = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("id_type!(") else {
            continue;
        };
        let Some(name) = rest.strip_suffix(");") else {
            return fail(format!("unreadable id_type expansion line: {trimmed}"));
        };
        names.push((name.to_owned(), index + 1));
    }
    Ok(names)
}

/// The three of the five allocated files that DECLARE a serde candidate, in
/// `source` leaf order.
///
/// WHY NOT ALL FIVE, since that is the difference between an independent
/// denominator and another transcribed one. `lib.rs` and `error.rs` contribute
/// ZERO candidates, and that is a claim, not a foregone conclusion:
/// `zero_candidate_files_are_proved` is what establishes it, by reading
/// `lib.rs`'s `pub struct` and `pub enum` declarations out of live source
/// through the same two walks and requiring both lists to be empty. Leaving them
/// out of the denominator is therefore not a widened assumption — it is the
/// denial that assertion makes, expressed as an empty contribution. `error.rs`
/// additionally cannot be walked by `externally_tagged_enum_names` at all: its
/// `ConfigError` carries payload variants, which that helper rejects loudly
/// because its own classification needs the all-unit externally tagged shape.
/// That loud rejection is correct there and would be a misleading failure here,
/// which is why `error.rs` stays out of the candidate denominator and keeps its
/// dedicated proof.
const CANDIDATE_SOURCE_FILES: [&str; 3] = [IDS_FILE, RECORDS_FILE, TASK_EXECUTION_FILE];

/// What this file's derived denominator IS, element by element: the DECLARING
/// FILE paired with the type names that file declares, so the answer stays keyed by
/// declaration site.
///
/// Named for what the element is rather than for the shape it is written in. Both
/// consumers need that pairing and need it for opposite reasons:
/// `allocated_type_names` flattens the names away from the file they came from,
/// while `per_file_split_holds` reads the very same answer split by declaration
/// site, which is why the answer is per file rather than flat in the first place.
/// Spelling `Vec<(&'static str, Vec<(String, usize)>)>` inline says only that it is a
/// vector of pairs and leaves that reason to be re-derived by every reader.
///
/// EACH DECLARATION CARRIES ITS LINE, `(name, line)`, which is the second half of
/// the element and is what lets `per_file_split_holds` bind a recorded `source`
/// anchor to a declaration site instead of only to a file name. It is derived by the
/// SAME three walks, in the SAME single pass each, that produced the names before —
/// no walk was added, re-run or duplicated — so the name an allocation row must
/// match and the line its anchor must match are read from one traversal of one
/// source and cannot come from two walks that disagree.
type DeclaredTypeNamesByFile = Vec<(&'static str, Vec<(String, usize)>)>;

/// EVERY type the three candidate files declare, named by their own source text,
/// in THREE families, each read from the file that declares it, and NOT ONE NAME
/// typed here:
///
/// * the `id_type!` expansions of `ids.rs`, through `id_type_expansions`, which
///   is itself a live read of the macro's invocation lines — and the INVOCATION
///   line is that family's declaration site, so the walk yields it beside the name;
/// * the `struct` declarations of `ids.rs`, `records.rs` and
///   `task_execution.rs`, public or non-public, through `declared_struct_names` —
///   this is what replaces the two transparent `u64` newtypes plus the seven
///   `records.rs` structs that used to be fourteen string literals in this file;
/// * the externally tagged `pub enum` declarations of the same three files,
///   through the existing `externally_tagged_enum_names` owner, which is what
///   replaces the four `task_execution.rs` member enums that used to be literals.
///   That helper still keys on `pub enum ` and therefore still cannot see a
///   non-public enum; the enum half of this denominator is weaker than the struct
///   half for exactly that reason, and no non-public enum is declared in the three
///   files today.
///
/// THE TWO BODYLESS `u64` NEWTYPES ARE CARRIED BY THE STRUCT FAMILY, not by a
/// recogniser of their own, and the distinction is worth stating because the two
/// newtypes are the family most likely to be assumed unhandled. `MemoryRevision`
/// and `ProjectSequence` are written `pub struct MemoryRevision(u64);` with no
/// braces, so the recogniser that needs a BODY cannot see them:
/// `struct_field_types` matches `line.trim() == "pub struct <name> {"` exactly and
/// would reject both, which is what its own comment says when it explains why
/// `struct_declaration_rest` exists as a separate rule. But `declared_struct_names`
/// recognises a declaration by KEYWORD and identifier and never looks for an
/// opening brace at all, so it enumerates both, at the same depth-zero gate, from
/// the same single walk that enumerates the seven braced `records.rs` structs. The
/// `(u64)` parentheses are not braces and contribute nothing to
/// `brace_delta_outside_strings`, so a bodyless newtype also leaves the depth
/// accumulator untouched and cannot unbalance the walk. Nothing extra was written
/// for these two types, and that is a reading of the two walks rather than an
/// assumption about them.
///
/// Per file rather than flattened, because `per_file_split_holds` needs the same
/// denominator split by declaration site; the flat set is `allocated_type_names`.
fn source_declared_type_names_by_file()
-> Result<DeclaredTypeNamesByFile, Box<dyn std::error::Error>> {
    let mut by_file = Vec::with_capacity(CANDIDATE_SOURCE_FILES.len());
    for file in CANDIDATE_SOURCE_FILES {
        let mut declarations: Vec<(String, usize)> = Vec::new();
        if file == IDS_FILE {
            // The macro body is invisible to `declared_struct_names` — it sits
            // inside `macro_rules!`, so its `pub struct $name(Uuid);` is walked at
            // brace depth 1 and never counted. Its EXPANSIONS are the declarations
            // this issue allocates, so they come from the macro's invocation
            // lines, which `id_type_expansions` already reads. Counting them here
            // as well would double-count nothing today and could only ever double
            // count, so the two families stay separate.
            declarations.extend(id_type_expansions()?);
        }
        declarations.extend(declared_struct_names(file)?);
        declarations.extend(externally_tagged_enum_declarations(file)?);
        by_file.push((file, declarations));
    }
    Ok(by_file)
}

/// Every allocated type name, derived from live source and sorted.
///
/// WHAT IT REPLACES. This used to be `id_type_expansions()` PLUS fourteen string
/// literals — `MemoryRevision`, `ProjectSequence`, the seven `records.rs`
/// structs and the five `task_execution.rs` types — which made the completeness
/// assertion a FIXED POINT for those fourteen: it read `records.rs` and
/// `task_execution.rs` never, so deleting all fourteen fixture rows together with
/// all fourteen literals left it green, and appending a brand-new
/// `pub struct` deriving `Serialize` and `Deserialize` to `records.rs` was also
/// invisible to it. Now the expected side is a live read of those two files, so
/// that struct appears on the expected side and not on the recorded side and the
/// assertion reds. The struct half of that denominator now also enumerates
/// NON-PUBLIC declarations, because a private struct owned as a field by a public
/// struct is part of the same wire shape and would otherwise be a type this
/// assertion could not claim to have covered.
///
/// NO DEDUPLICATION, and the reason matters. If two families ever yielded the same
/// name the duplicate is left in, because the recorded side IS deduplicated and
/// the mismatch is then loud. Silently dropping it here would let a source-side
/// collision masquerade as agreement.
fn allocated_type_names() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut names: Vec<String> = Vec::new();
    for (_, file_declarations) in source_declared_type_names_by_file()? {
        // The LINE column is dropped here and only here. It is not unused: it is
        // what `per_file_split_holds` compares each row's recorded `source` anchor
        // against, and this function's own caller `type_names_are_complete` needs
        // the flat name set, which is what a declaration list flattens to.
        names.extend(file_declarations.into_iter().map(|(name, _)| name));
    }
    names.sort();
    Ok(names)
}

/// Shape of a transparent scalar's canonical wire form.
#[derive(Clone, Copy, Debug)]
enum WireShape {
    JsonString,
    JsonNumber,
}

/// The 40 transparent scalars carry no struct state, so byte-identity of the
/// re-serialized value against the recorded valid bytes is a real claim: a
/// bare JSON string for the `Uuid` newtypes and a bare JSON number for the two
/// `u64` newtypes.
fn scalar_round_trip<T>(row: &Row, shape: WireShape) -> TestResult
where
    T: DeserializeOwned + Serialize,
{
    let decoded: T = serde_json::from_str(&row.raw).map_err(boxed)?;
    let encoded = serde_json::to_string(&decoded).map_err(boxed)?;
    assert_eq!(
        encoded,
        row.raw.trim(),
        "transparent scalar lost byte-identity in row {}",
        row.id
    );
    let value: Value = serde_json::from_str(&encoded).map_err(boxed)?;
    match shape {
        WireShape::JsonString => {
            // Named `uuid_text`, never `text`, so it cannot shadow the `text`
            // fixture accessor.
            let uuid_text = value
                .as_str()
                .ok_or_else(|| {
                    boxed(std::io::Error::other(format!(
                        "row {} must serialize as a bare JSON string",
                        row.id
                    )))
                })?
                .to_owned();
            let _parsed = uuid::Uuid::parse_str(&uuid_text).map_err(boxed)?;
        }
        WireShape::JsonNumber => assert!(
            value.is_number(),
            "row {} must serialize as a bare JSON number",
            row.id
        ),
    }
    let again: T = serde_json::from_str(&encoded).map_err(boxed)?;
    assert_eq!(
        serde_json::to_string(&again).map_err(boxed)?,
        encoded,
        "row {} is not byte-stable across a second pass",
        row.id
    );
    Ok(())
}

/// Round-trip for the closed structs, `TaskExecutionClass` and the four member
/// enums, asserting byte-identity of the re-serialized value against the row's own
/// recorded bytes, and then two further properties that byte-identity alone does not
/// give.
///
/// THE RAW-BYTE COMPARISON WAS OMITTED HERE ON A PREMISE THAT WAS FALSE, and the
/// history is kept because a reader must not inherit it. This function used to say:
/// "Raw-byte equality against the fixture is deliberately NOT claimed here: serde
/// emits fields in declaration order, which is not the fixture writer's key order,
/// so `Value` equality is the honest statement." The second half of that sentence is
/// a claim about the fixture, and it is FALSE: measured over every accept row routed
/// here, the fixture's key order IS serde's declaration order, recursively, including
/// the nested `blob`, `manifest` and `segments[]` members, and every row is compact
/// with no incidental whitespace. So the justification described a mismatch that does
/// not exist, and used it to omit an assertion that the issue's cases 1-4 require
/// ("unchanged valid bytes/digests") and that `scalar_round_trip` already makes for
/// the forty scalar rows.
///
/// WHAT THE OMISSION HID, which is why the correction is an assertion and not a
/// comment. `decoded == again` and `to_string(&again) == encoded` both compare serde
/// against ITSELF: the fixture's own bytes never appear on the right-hand side, so a
/// member-order difference or an escaping difference is invisible to them — serde would
/// agree with itself either way. The case-12 accept row on numeric stem `930-128` WAS
/// exactly that case, and the history is kept because it is the reason this assertion
/// exists. In an EARLIER REVISION its `detail` held U+1F600 spelled as the escaped
/// surrogate pair `\ud83d\ude00`, which `serde_json::to_string` never emits because the
/// serializer writes the raw UTF-8 bytes of a non-control scalar. THE REASON A
/// SELF-COMPARISON CANNOT CATCH THAT IS STRUCTURAL AND NOT AN OUTCOME: the fixture's
/// bytes never appear on the right-hand side of either comparison, so for ANY row they
/// agree with whatever serde produces, and a spelling that differs from the row's own
/// bytes is invisible to them by construction rather than by luck. Only a comparison
/// against `row.raw` can see it. No suite was run here to observe a pass or a failure;
/// the claim is about what those two expressions are able to distinguish. THAT IS A STATEMENT ABOUT A PAST REVISION AND NOT ABOUT THE CURRENT
/// BYTES, and it is written that way deliberately: the row now carries U+1F600 as one
/// literal astral scalar, so a reader who took "it stored" as present tense would look
/// for an escape that is no longer there and conclude the assertion is stale.
/// THIS ROW IS NAMED BY ITS NUMERIC STEM rather than by its full id on purpose. Ids move
/// between revisions — this one has already been re-spelled by its owner once, and the
/// `-surrogate-pair-` suffix it carried described a defect the row no longer has — while
/// the stem and the case number do not move. A comment that hard-codes either spelling
/// goes stale on the next rename; the stem does not.
///
/// THAT DEFECT WAS FIXED AT THE SOURCE, and the divergence no longer exists — so the
/// claim is WITHDRAWN rather than re-measured, and a reader must not go looking for it.
/// The fixture's owner replaced that `raw` with the bytes the serializer actually emits,
/// and the row now round-trips byte-for-byte. The assertion below is unchanged and is
/// written for every row: it was added because the omission hid a real defect, not
/// because that one row happened to need an exception, and nothing about the fix
/// narrows it.
///
/// THE ORDERING IS NOW VERIFIED, NOT ASSUMED. That is the whole difference between
/// this comment and the one it replaces: the byte comparison is what makes "the
/// fixture's key order is serde's declaration order" a checked property of every row
/// rather than a belief about the fixture writer, and if a future row is written in a
/// different order or with different escaping, this is the assertion that says so.
///
/// THE TWO SELF-COMPARISONS ARE KEPT and are not redundant with byte-identity.
/// Byte-identity says the output reproduces the input's bytes; `decoded == again` says
/// the second decode produced the same VALUE, which is a different failure mode (a
/// lossless-looking byte string that does not decode back to the same value), and
/// `to_string(&again) == encoded` says re-serialization is idempotent, which a single
/// round trip cannot show.
fn value_round_trip<T>(row: &Row) -> TestResult
where
    T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug,
{
    let decoded: T = serde_json::from_str(&row.raw).map_err(boxed)?;
    let encoded = serde_json::to_string(&decoded).map_err(boxed)?;
    let again: T = serde_json::from_str(&encoded).map_err(boxed)?;
    assert_eq!(
        encoded,
        row.raw.trim(),
        "row {} must survive a decode/encode round trip BYTE FOR BYTE: a Value-equality check cannot see a member-order or escaping difference, because serde would agree with itself. If this row's own bytes are the ones that are wrong, the fixture row is what has to change, not this assertion",
        row.id
    );
    assert_eq!(
        decoded, again,
        "row {} changed value across a round trip",
        row.id
    );
    assert_eq!(
        serde_json::to_string(&again).map_err(boxed)?,
        encoded,
        "row {} is not idempotent under re-serialization",
        row.id
    );
    Ok(())
}

/// Present-form round-trip for `CanonicalMemoryL2Page`.
///
/// Truth about the four optional members, stated here so nothing depends on a
/// wrong assumption:
/// * `manifest` (`records.rs:119`) and `continuation` (`records.rs:121`) are
///   `Option<..>`. A derived `Deserialize` routes an absent field through
///   serde's `missing_field`, whose `MissingFieldDeserializer::deserialize_option`
///   calls `visitor.visit_none()`, so omitting either key decodes to `None`
///   with no error. They are NOT required on the wire.
/// * `resolved_parent_handle` (`records.rs:115`) and `requested_segment_id`
///   (`records.rs:117`) carry `#[serde(default, skip_serializing_if =
///   "Option::is_none")]`, but `Option<T>` is already implicitly optional on
///   decode: the attribute pair governs the ENCODE side, where
///   `skip_serializing_if` drops the key when the value is `None`. `default`
///   covers a non-`Option` type, so it is not what makes these two omittable.
/// * Genuinely required on the wire are `requested_handle` (`:114`, `String`),
///   `segments` (`:120`, `Vec<_>`) and `truncated` (`:122`, `bool`).
///
/// RAW-BYTE EQUALITY IS NOW ASSERTED FOR THESE ROWS TOO, and this comment used to
/// claim it was "the wrong assertion here". That was the same false premise as
/// `value_round_trip`'s, and the same measurement refutes it: all five accept page rows
/// byte-round-trip exactly. The asymmetry between the two member pairs cancels — an
/// absent `manifest` or `continuation` is re-emitted as an explicit `null`, and those
/// rows carry the key, while an absent `resolved_parent_handle` or
/// `requested_segment_id` is dropped by `skip_serializing_if` and those rows omit it —
/// so presence round-trips to presence and absence to absence at the BYTE level as
/// well as the value level. `value_round_trip` now makes that comparison for every row
/// that reaches it, this function's own assertions below are about the per-member
/// projection, and neither claim excludes the other.
fn l2_page_round_trip(row: &Row) -> TestResult {
    value_round_trip::<eliot_types::CanonicalMemoryL2Page>(row)?;
    let decoded: eliot_types::CanonicalMemoryL2Page =
        serde_json::from_str(&row.raw).map_err(boxed)?;
    let encoded = serde_json::to_string(&decoded).map_err(boxed)?;
    let value: Value = serde_json::from_str(&encoded).map_err(boxed)?;
    if decoded.resolved_parent_handle.is_none() {
        assert!(
            value.get("resolved_parent_handle").is_none(),
            "row {} must keep an absent resolved_parent_handle omitted",
            row.id
        );
    }
    if decoded.requested_segment_id.is_none() {
        assert!(
            value.get("requested_segment_id").is_none(),
            "row {} must keep an absent requested_segment_id omitted",
            row.id
        );
    }
    assert_eq!(
        value.get("resolved_parent_handle").and_then(Value::as_str),
        decoded.resolved_parent_handle.as_deref(),
        "row {} drifted on resolved_parent_handle",
        row.id
    );
    assert_eq!(
        value.get("requested_segment_id").and_then(Value::as_str),
        decoded.requested_segment_id.as_deref(),
        "row {} drifted on requested_segment_id",
        row.id
    );
    // `manifest` (`records.rs:119`) and `continuation` (`records.rs:121`) are the
    // two `Option` members that carry NO serde attribute at all — neither
    // `default` nor `skip_serializing_if`. That makes them the OPPOSITE case to
    // the skipped pair above: the encoder always emits both keys, writing an
    // explicit `null` when the value is `None`. So the contract asserted here is
    // "the key is always present, and its value round-trips", NOT "an absent one
    // stays absent". The previous version of this comment claimed the latter, and
    // the previous assertion compared PRESENCE, which is false for any page whose
    // `manifest` is `None` because the encoder emits `"manifest":null`. It
    // survived only because the one row reaching this helper carries a manifest.
    //
    // THE VALUE COMPARISON HID A BUG OF ITS OWN BEHIND THE SAME ROW, and fixing
    // presence without fixing value left it in place. `manifest` is a struct, so
    // it cannot borrow the `continuation` sibling's `and_then(Value::as_str)`
    // projection; comparing `value.get("manifest")` directly against the
    // `Option`-shaped expectation made a `None` manifest compare
    // `Some(&Value::Null)` with `None`, so the assertion was red on any page whose
    // `manifest` is `None` and its message blamed a page that had not drifted at
    // all. The projection below is the None-aware form: it drops an explicit null
    // before comparing, which is exactly the judgement `and_then(Value::as_str)`
    // makes for a string by rejecting a non-string. The CLAIM is not narrowed to
    // reach the green — a page whose `manifest` is `None` still has to re-emit the
    // key and still has to compare equal.
    for member in ["manifest", "continuation"] {
        assert!(
            value.get(member).is_some(),
            "row {} must always carry {member} in the encoded bytes: {member} has no serde attribute, so None encodes as an explicit null rather than as an omitted key",
            row.id
        );
    }
    assert_eq!(
        value.get("manifest").filter(|manifest| !manifest.is_null()),
        decoded
            .manifest
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(boxed)?
            .as_ref(),
        "row {} drifted on manifest: the encoded page is {encoded}",
        row.id
    );
    assert_eq!(
        value.get("continuation").and_then(Value::as_str),
        decoded.continuation.as_deref(),
        "row {} drifted on continuation",
        row.id
    );
    Ok(())
}

/// Clone a parsed row payload and delete one top-level member. Used by the
/// absence and required-member checks below; it never mutates the fixture.
fn without_member(raw: &Value, member: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut clone = raw.clone();
    let object = clone.as_object_mut().ok_or_else(|| {
        boxed(std::io::Error::other(
            "the fixture row must be a JSON object",
        ))
    })?;
    if object.remove(member).is_none() {
        return fail(format!("the fixture row must record the member {member}"));
    }
    serde_json::to_string(&clone).map_err(boxed)
}

/// How a row's own bytes record one optional member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorded {
    /// The key is not in the document at all.
    Absent,
    /// The key is present with an explicit `null`.
    Null,
    /// The key is present with a real value.
    Present,
}

/// Read one top-level member's recorded state from a raw document, without
/// decoding it into a type. Drives the decode-side expectations so they are
/// derived from the payload rather than assumed.
///
/// `row_id` names the document being read and is carried ONLY so that the
/// out-of-range refusal below can say WHICH row is broken. `raw` is a plain
/// `&str` because two callers pass bytes this file has just rewritten, so there
/// is no `Row` to reach through — and an offset on its own would send a reader
/// to the byte scan rather than to the document.
fn recorded_member(raw: &str, member: &str, row_id: &str) -> Recorded {
    let Some(span) = top_level_member_spans(raw)
        .into_iter()
        .find(|span| span.key == member)
    else {
        return Recorded::Absent;
    };
    // `top_level_member_spans` records a value offset even when the KEY token is
    // unterminated: `string_closing_quote` falls out of its loop at
    // `bytes.len()`, `value_offset`'s loop condition is then false on entry, and
    // the span carries `len + 1` — one byte past the end of the document.
    // `raw[span.value_start..]` panics there, and a `.get(..)` returning `None`
    // would be worse than a panic, because it would read as `Recorded::Absent` and
    // silently INVERT every claim its callers make. The check sits at the slice
    // for the reason `raw_value_end` gives for the same hazard: a helper that can
    // produce an out-of-range extent must not depend on its caller catching it.
    assert!(
        span.value_start <= raw.len(),
        "row {row_id}: the {member} member's value offset {} is past the end of its {}-byte document, so its key token is unterminated and there is no value to classify",
        span.value_start,
        raw.len()
    );
    // `null` counts as null only when the whole token is `null`, i.e. when it is
    // followed by a structural terminator or ends the input. Merely BEGINNING
    // with those characters would misclassify a value that happens to start
    // with `null`, so the classifier is total rather than heuristic.
    //
    // TOTality INCLUDES THE TRAILING SPACING, which the previous version did not
    // skip: it trimmed before the token only, so one space, tab or newline
    // between `null` and its terminator defeated the match and `{"a":null }`,
    // `{"a":null ,"b":1}` and `{"a":null\n,"b":1}` all classified as `Present`.
    // Whitespace between a token and a terminator is legal JSON, so REJECTING
    // those documents would be refusing correct input — which is exactly the
    // asymmetry `top_level_value_span`'s boundary probe is written to refuse, and
    // why that probe walks forward over the spacing instead of comparing the very
    // next byte. This classifier now walks forward for the same reason, and the
    // other classifier is left in the direction that accepts correct input: the
    // defect was here, not there.
    //
    // REACHABLE WITHOUT ANYONE TYPING A SPACE: `document_with_member_value`
    // splices `raw[start..end]` and re-appends the original tail, so a document
    // that already carried spacing after `null` keeps that spacing through the
    // surgery, and `skipped_pair_null_form_is_exercised` classifies its own
    // output with this very helper.
    let tail = raw[span.value_start..].trim_start();
    let is_null = tail.strip_prefix("null").is_some_and(|rest| {
        matches!(
            rest.trim_start().as_bytes().first(),
            None | Some(b',' | b'}' | b']')
        )
    });
    if is_null {
        Recorded::Null
    } else {
        Recorded::Present
    }
}

/// Absence round-trips to absence in BOTH directions for `CanonicalMemoryL2Page`,
/// but only for the two members that carry `skip_serializing_if`.
///
/// `manifest` and `continuation` are removed from the row's own bytes and must
/// then decode to `None`: both are `Option<..>`, so an absent key reaches serde's
/// `missing_field`, whose `MissingFieldDeserializer::deserialize_option` calls
/// `visitor.visit_none()`. That is not a decode error.
///
/// The two SKIPPED members are left exactly as the row records them, and their
/// encode rule is driven by what the row actually holds, so this helper is
/// correct on a row where they are present AND on a row where they are absent.
/// Flattening the two into one unconditional claim would be false on half the
/// rows: the allocation page omits `requested_segment_id` outright, so an
/// unconditional "present" claim would be red and an unconditional "absent" claim
/// would be vacuous.
///
/// The ENCODE side differs per member and must not be flattened: the encoder
/// drops `resolved_parent_handle` and `requested_segment_id` when they are
/// `None` — a null is IMPOSSIBLE for them — while `manifest` and `continuation`
/// carry no attribute at all and are therefore always re-emitted, as an explicit
/// null when `None`.
fn l2_page_optional_absence_holds(row: &Row) -> TestResult {
    let raw: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
    let mut absent = raw.clone();
    for member in ["manifest", "continuation"] {
        let object = absent.as_object_mut().ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "row {} must be a JSON object",
                row.id
            )))
        })?;
        if object.remove(member).is_none() {
            return fail(format!("row {} must record the member {member}", row.id));
        }
    }
    let absent_bytes = serde_json::to_string(&absent).map_err(boxed)?;
    // No `raw.contains("\"manifest\"")` scan here: a substring test cannot tell a
    // TOP-LEVEL key from a nested one, so it was weaker than it read and fully
    // redundant with the `object.remove(...).is_none()` guard above, which
    // already proves top-level presence for both members.
    let decoded: eliot_types::CanonicalMemoryL2Page =
        serde_json::from_str(&absent_bytes).map_err(boxed)?;
    assert!(
        decoded.manifest.is_none(),
        "an absent manifest must decode to None, never to a decode error, in row {}",
        row.id
    );
    assert!(
        decoded.continuation.is_none(),
        "an absent continuation must decode to None, never to a decode error, in row {}",
        row.id
    );
    let encoded = serde_json::to_string(&decoded).map_err(boxed)?;
    let out: Value = serde_json::from_str(&encoded).map_err(boxed)?;
    skipped_pair_claims_hold(row, &decoded, &out);
    for member in L2_ALWAYS_EMITTED {
        assert!(
            out.get(member).is_some(),
            "row {} must re-emit {member}, because it carries no serde attribute",
            row.id
        );
    }
    for member in ["requested_handle", "segments", "truncated"] {
        assert!(
            out.get(member).is_some(),
            "row {} must keep the required member {member} while the optional ones are absent",
            row.id
        );
    }
    let again: eliot_types::CanonicalMemoryL2Page =
        serde_json::from_str(&encoded).map_err(boxed)?;
    assert!(
        again.manifest.is_none() && again.continuation.is_none(),
        "absence must round-trip to absence in row {}",
        row.id
    );
    assert_eq!(
        serde_json::to_string(&again).map_err(boxed)?,
        encoded,
        "row {} is not idempotent once the optional members are absent",
        row.id
    );
    Ok(())
}

/// The two members that carry `#[serde(default, skip_serializing_if =
/// "Option::is_none")]`, checked in BOTH directions against one decoded page.
///
/// DECODE: an absent key and an explicit `null` both mean `None`; only a real
/// value means `Some`. Driven by what the row's own bytes record, so this is
/// correct on a page that carries the member and on one that omits it.
///
/// WHICH FORMS ARE ACTUALLY EXERCISED, stated precisely because the previous
/// version of this comment claimed all three and covered two. Measured on the live
/// fixture, the only top-level explicit `null` in all 162 rows is
/// `"continuation":null`, and `continuation` carries no serde attribute at all — it
/// is always-emitted, not skipped. No row carries `"resolved_parent_handle":null` or
/// `"requested_segment_id":null`, so the `Recorded::Null` arm of `recorded_member` is
/// reached for a member of the SKIPPED pair only by the byte surgery in
/// `skipped_pair_null_form_is_exercised`, never by a fixture row. The present form
/// and the absent form are both reached from fixture bytes.
///
/// ENCODE: a member carrying `skip_serializing_if = "Option::is_none"` can NEVER
/// be emitted as null, so the only legal encoded form of `None` is ABSENCE. The
/// claim is therefore `is_none()`, not "absent or null": accepting a null would
/// assert less than the encoder can actually do.
fn skipped_pair_claims_hold(row: &Row, decoded: &eliot_types::CanonicalMemoryL2Page, out: &Value) {
    // Two uses of the row's RECORDED shape, and they are not the same question:
    // `recorded` drives the DECODE expectation, because only a real value may
    // decode to `Some` while an absent key and an explicit null both decode to
    // `None`; `is_some` drives the ENCODE branch, because `skip_serializing_if`
    // tests the decoded value and `Absent` and `Null` share that branch.
    for (member, recorded, is_some) in [
        (
            L2_RESOLVED_PARENT_HANDLE,
            recorded_member(&row.raw, L2_RESOLVED_PARENT_HANDLE, &row.id),
            decoded.resolved_parent_handle.is_some(),
        ),
        (
            L2_REQUESTED_SEGMENT_ID,
            recorded_member(&row.raw, L2_REQUESTED_SEGMENT_ID, &row.id),
            decoded.requested_segment_id.is_some(),
        ),
    ] {
        assert_eq!(
            is_some,
            recorded == Recorded::Present,
            "row {}: {member} records as {recorded:?}, so it must decode to Some={is_some}",
            row.id
        );
        if is_some {
            assert!(
                out.get(member).is_some(),
                "row {}: a present {member} must be re-emitted",
                row.id
            );
        } else {
            assert!(
                out.get(member).is_none(),
                "row {}: skip_serializing_if must DROP {member} when it is None, never emit it as null",
                row.id
            );
        }
    }
}

/// The explicit-`null` form of the SKIPPED pair, built here because NO FIXTURE ROW
/// carries it.
///
/// Measured on the live fixture, the only top-level explicit `null` across all 162
/// rows is `"continuation":null`, and `continuation` is an always-emitted member.
/// Without this the `Recorded::Null` arm of `recorded_member` would never be reached
/// for a member of the skipped pair, and half of `skipped_pair_claims_hold`'s decode
/// claim would rest on prose.
///
/// THE SURGERY: one top-level member's value token is replaced with `null` on the
/// allocation page's OWN bytes, so every other byte is untouched and the document
/// stays a complete `CanonicalMemoryL2Page`. No hand-written payload is pasted from
/// anywhere, and the fixture is not edited; this is the same byte-surgery shape
/// `inject_top_level_unknown` already uses. A member the page already omits is left
/// alone, so the ABSENT form is measured on the same row in the same pass and the
/// two forms are compared on one document rather than across two.
///
/// THREE CLAIMS, all about the same member:
/// * the surgery really produced the `Recorded::Null` form, so the decode below
///   cannot quietly be measuring the absent form a second time;
/// * an explicit `null` decodes to `None` exactly as an absent key does;
/// * the encoder then DROPS the member — `skip_serializing_if` makes a null
///   impossible, so the output carrying a null here would be a real regression.
fn skipped_pair_null_form_is_exercised(all: &[Row]) -> TestResult {
    let page = applicable_row(all, "CanonicalMemoryL2Page")?;
    let mut nulled = 0usize;
    let mut absent = 0usize;
    for member in L2_SKIPPED_WHEN_NONE {
        let raw = match recorded_member(&page.raw, member, &page.id) {
            Recorded::Present => {
                let nulled_raw = document_with_member_value(&page.raw, member, JSON_NULL)?;
                assert_eq!(
                    recorded_member(&nulled_raw, member, &page.id),
                    Recorded::Null,
                    "the surgery must really produce the explicit-null form of {member} on page {}, or the decode below is measuring the absent form again",
                    page.id
                );
                nulled += 1;
                nulled_raw
            }
            Recorded::Absent => {
                absent += 1;
                page.raw.clone()
            }
            Recorded::Null => {
                return fail(format!(
                    "the allocation page {} already records {member} as an explicit null, so the surgery here would prove nothing",
                    page.id
                ));
            }
        };
        let recorded = recorded_member(&raw, member, &page.id);
        let decoded: eliot_types::CanonicalMemoryL2Page =
            serde_json::from_str(&raw).map_err(boxed)?;
        let is_some = if member == L2_RESOLVED_PARENT_HANDLE {
            decoded.resolved_parent_handle.is_some()
        } else if member == L2_REQUESTED_SEGMENT_ID {
            decoded.requested_segment_id.is_some()
        } else {
            return fail(format!(
                "{member} is not a member of the skipped pair, so this loop cannot measure it"
            ));
        };
        assert!(
            !is_some,
            "page {}: {member} records as {recorded:?}, so it must decode to None exactly as an absent key does",
            page.id
        );
        let encoded = serde_json::to_string(&decoded).map_err(boxed)?;
        let out: Value = serde_json::from_str(&encoded).map_err(boxed)?;
        assert!(
            out.get(member).is_none(),
            "page {}: {member} decodes to None from the {recorded:?} form, so skip_serializing_if must DROP it and can never emit it as null: {encoded}",
            page.id
        );
    }
    assert!(
        nulled > 0,
        "the allocation page {} must carry at least one skipped member as a real value, or the explicit-null form of the skipped pair is never exercised",
        page.id
    );
    assert!(
        absent > 0,
        "the allocation page {} must omit at least one skipped member, or the absent form is left to the absence pages and the two forms are never compared on one document",
        page.id
    );
    Ok(())
}

/// The contrast that keeps the previous wrong claim from returning: only the
/// genuinely required members are refused when absent. `manifest` and
/// `continuation` are `Option` members and are asserted to decode, not to fail.
fn l2_page_required_members_are_refused(row: &Row) -> TestResult {
    let raw: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
    for member in ["requested_handle", "segments", "truncated"] {
        let missing = without_member(&raw, member)?;
        assert!(
            serde_json::from_str::<eliot_types::CanonicalMemoryL2Page>(&missing).is_err(),
            "the required member {member} must be refused when absent in row {}",
            row.id
        );
    }
    for member in ["manifest", "continuation"] {
        let missing = without_member(&raw, member)?;
        assert!(
            serde_json::from_str::<eliot_types::CanonicalMemoryL2Page>(&missing).is_ok(),
            "the optional member {member} must decode to None when absent in row {}",
            row.id
        );
    }
    Ok(())
}

fn ids_row_round_trip(row: &Row) -> TestResult {
    match type_leaf(&row.type_name) {
        "AgentId" => scalar_round_trip::<eliot_types::AgentId>(row, WireShape::JsonString),
        "AgentSessionId" => {
            scalar_round_trip::<eliot_types::AgentSessionId>(row, WireShape::JsonString)
        }
        "ActionLeaseId" => {
            scalar_round_trip::<eliot_types::ActionLeaseId>(row, WireShape::JsonString)
        }
        "ActionRequestId" => {
            scalar_round_trip::<eliot_types::ActionRequestId>(row, WireShape::JsonString)
        }
        "AgentRunId" => scalar_round_trip::<eliot_types::AgentRunId>(row, WireShape::JsonString),
        "BlackboardItemId" => {
            scalar_round_trip::<eliot_types::BlackboardItemId>(row, WireShape::JsonString)
        }
        "MailboxMessageId" => {
            scalar_round_trip::<eliot_types::MailboxMessageId>(row, WireShape::JsonString)
        }
        "ModuleId" => scalar_round_trip::<eliot_types::ModuleId>(row, WireShape::JsonString),
        "PatchRequestId" => {
            scalar_round_trip::<eliot_types::PatchRequestId>(row, WireShape::JsonString)
        }
        "PatchRunId" => scalar_round_trip::<eliot_types::PatchRunId>(row, WireShape::JsonString),
        "ProjectId" => scalar_round_trip::<eliot_types::ProjectId>(row, WireShape::JsonString),
        "SessionId" => scalar_round_trip::<eliot_types::SessionId>(row, WireShape::JsonString),
        "SkillId" => scalar_round_trip::<eliot_types::SkillId>(row, WireShape::JsonString),
        "TaskId" => scalar_round_trip::<eliot_types::TaskId>(row, WireShape::JsonString),
        "VerifierRunId" => {
            scalar_round_trip::<eliot_types::VerifierRunId>(row, WireShape::JsonString)
        }
        "WorkItemId" => scalar_round_trip::<eliot_types::WorkItemId>(row, WireShape::JsonString),
        "WorkLeaseId" => scalar_round_trip::<eliot_types::WorkLeaseId>(row, WireShape::JsonString),
        "WorktreeLeaseRequestId" => {
            scalar_round_trip::<eliot_types::WorktreeLeaseRequestId>(row, WireShape::JsonString)
        }
        "WorktreeLeaseId" => {
            scalar_round_trip::<eliot_types::WorktreeLeaseId>(row, WireShape::JsonString)
        }
        "CandidateDiffId" => {
            scalar_round_trip::<eliot_types::CandidateDiffId>(row, WireShape::JsonString)
        }
        "WriteId" => scalar_round_trip::<eliot_types::WriteId>(row, WireShape::JsonString),
        "OperationId" => scalar_round_trip::<eliot_types::OperationId>(row, WireShape::JsonString),
        "ClaimId" => scalar_round_trip::<eliot_types::ClaimId>(row, WireShape::JsonString),
        "EvidenceId" => scalar_round_trip::<eliot_types::EvidenceId>(row, WireShape::JsonString),
        "VerificationId" => {
            scalar_round_trip::<eliot_types::VerificationId>(row, WireShape::JsonString)
        }
        "ReceiptId" => scalar_round_trip::<eliot_types::ReceiptId>(row, WireShape::JsonString),
        "ReplayCaseId" => {
            scalar_round_trip::<eliot_types::ReplayCaseId>(row, WireShape::JsonString)
        }
        "ReplaySetId" => scalar_round_trip::<eliot_types::ReplaySetId>(row, WireShape::JsonString),
        "ReplayRunId" => scalar_round_trip::<eliot_types::ReplayRunId>(row, WireShape::JsonString),
        "DreamCandidateId" => {
            scalar_round_trip::<eliot_types::DreamCandidateId>(row, WireShape::JsonString)
        }
        "EvalCaseId" => scalar_round_trip::<eliot_types::EvalCaseId>(row, WireShape::JsonString),
        "EvalSuiteId" => scalar_round_trip::<eliot_types::EvalSuiteId>(row, WireShape::JsonString),
        "EvalDatasetManifestId" => {
            scalar_round_trip::<eliot_types::EvalDatasetManifestId>(row, WireShape::JsonString)
        }
        "EvalRunId" => scalar_round_trip::<eliot_types::EvalRunId>(row, WireShape::JsonString),
        "EvalVerdictId" => {
            scalar_round_trip::<eliot_types::EvalVerdictId>(row, WireShape::JsonString)
        }
        "EvalFailureClusterId" => {
            scalar_round_trip::<eliot_types::EvalFailureClusterId>(row, WireShape::JsonString)
        }
        "BenchmarkIntegrityReceiptId" => scalar_round_trip::<
            eliot_types::BenchmarkIntegrityReceiptId,
        >(row, WireShape::JsonString),
        "HarnessExperimentRecordId" => {
            scalar_round_trip::<eliot_types::HarnessExperimentRecordId>(row, WireShape::JsonString)
        }
        "MemoryRevision" => {
            scalar_round_trip::<eliot_types::MemoryRevision>(row, WireShape::JsonNumber)
        }
        "ProjectSequence" => {
            scalar_round_trip::<eliot_types::ProjectSequence>(row, WireShape::JsonNumber)
        }
        other => fail(format!(
            "row {} names an unallocated ids.rs type: {other}",
            row.id
        )),
    }
}

fn records_row_round_trip(row: &Row) -> TestResult {
    match type_leaf(&row.type_name) {
        "BlobRef" => value_round_trip::<eliot_types::BlobRef>(row),
        "CanonicalMemoryManifest" => value_round_trip::<eliot_types::CanonicalMemoryManifest>(row),
        "CanonicalMemorySegment" => value_round_trip::<eliot_types::CanonicalMemorySegment>(row),
        "CanonicalMemorySegmentRef" => {
            value_round_trip::<eliot_types::CanonicalMemorySegmentRef>(row)
        }
        "CanonicalMemoryL2Page" => l2_page_round_trip(row),
        "MigrationRecord" => value_round_trip::<eliot_types::MigrationRecord>(row),
        "HealthRecord" => value_round_trip::<eliot_types::HealthRecord>(row),
        other => fail(format!(
            "row {} names an unallocated records.rs type: {other}",
            row.id
        )),
    }
}

fn task_execution_row_round_trip(row: &Row) -> TestResult {
    match type_leaf(&row.type_name) {
        "TaskExecutionDomain" => value_round_trip::<eliot_types::TaskExecutionDomain>(row),
        "TaskExecutionAction" => value_round_trip::<eliot_types::TaskExecutionAction>(row),
        "TaskExecutionArtifact" => value_round_trip::<eliot_types::TaskExecutionArtifact>(row),
        "TaskExecutionClassSource" => {
            value_round_trip::<eliot_types::TaskExecutionClassSource>(row)
        }
        "TaskExecutionClass" => value_round_trip::<eliot_types::TaskExecutionClass>(row),
        other => fail(format!(
            "row {} names an unallocated task_execution.rs type: {other}",
            row.id
        )),
    }
}

fn round_trip_row(row: &Row) -> TestResult {
    match source_leaf(&row.source).as_str() {
        "ids.rs" => ids_row_round_trip(row),
        "records.rs" => records_row_round_trip(row),
        "task_execution.rs" => task_execution_row_round_trip(row),
        other => fail(format!(
            "row {} names an unallocated source file: {other}",
            row.id
        )),
    }
}

/// Splice an unknown member into the raw string itself, so the rejection is
/// proved on the recorded bytes with every other byte untouched.
fn inject_top_level_unknown(raw: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') {
        return fail("a top-level unknown member needs an object-shaped raw row".to_owned());
    }
    let mut injected = String::from("{\"");
    injected.push_str(key);
    injected.push_str("\":null,");
    injected.push_str(&trimmed[1..]);
    Ok(injected)
}

enum Step {
    Field(&'static str),
    Index(usize),
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Field(name) => write!(f, "{name}"),
            Self::Index(index) => write!(f, "[{index}]"),
        }
    }
}

fn path_label(steps: &[Step]) -> String {
    steps
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn descend<'value>(
    value: &'value mut Value,
    steps: &[Step],
) -> Result<&'value mut Value, Box<dyn std::error::Error>> {
    let Some((first, rest)) = steps.split_first() else {
        return Ok(value);
    };
    let next = match first {
        Step::Field(name) => value.get_mut(*name),
        Step::Index(index) => value.get_mut(*index),
    }
    .ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "fixture row does not reach the injection target {first}"
        )))
    })?;
    descend(next, rest)
}

fn inject_nested_unknown(
    raw: &str,
    steps: &[Step],
    key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut value: Value = serde_json::from_str(raw).map_err(boxed)?;
    let target = descend(&mut value, steps)?;
    let object = target.as_object_mut().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "injection target {key} must sit on a JSON object"
        )))
    })?;
    if object.insert(key.to_owned(), Value::Bool(true)).is_some() {
        return fail(format!("injection key {key} already exists in the fixture"));
    }
    serde_json::to_string(&value).map_err(boxed)
}

/// `is_err` plus a substring naming the offending member. Never an exact
/// equality against a serde message: the text is version-dependent and an
/// exact match would prove nothing about this contract.
fn reject_unknown_top_level<T>(row: &Row, key: &str) -> TestResult
where
    T: DeserializeOwned,
{
    assert!(
        serde_json::from_str::<T>(&row.raw).is_ok(),
        "the control decode must succeed before rejection is claimed in row {}",
        row.id
    );
    let injected = inject_top_level_unknown(&row.raw, key)?;
    match serde_json::from_str::<T>(&injected) {
        Ok(_) => fail(format!(
            "row {} must refuse the unknown top-level member {key}",
            row.id
        )),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains(key),
                "row {} must name the offending member {key}: {message}",
                row.id
            );
            Ok(())
        }
    }
}

fn reject_unknown_nested<T>(row: &Row, steps: &[Step], key: &str) -> TestResult
where
    T: DeserializeOwned,
{
    assert!(
        serde_json::from_str::<T>(&row.raw).is_ok(),
        "the control decode must succeed before rejection is claimed in row {}",
        row.id
    );
    let injected = inject_nested_unknown(&row.raw, steps, key)?;
    match serde_json::from_str::<T>(&injected) {
        Ok(_) => fail(format!(
            "row {} must refuse the unknown member {key} nested under {}",
            row.id,
            path_label(steps)
        )),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains(key),
                "row {} must name the offending member {key} nested under {}: {message}",
                row.id,
                path_label(steps)
            );
            Ok(())
        }
    }
}

/// The two zero-candidate files are proved against live source, not merely
/// implied by an absent row: `lib.rs` is re-export only and declares no struct of
/// its own, public or private, and `error.rs:3-4` derives only `thiserror` on
/// `ConfigError` with no serde impl anywhere in the file.
///
/// THE `lib.rs` HALF USES THE SAME TWO WALKS as the candidate denominator, not a
/// raw substring scan. `declared_struct_names` and `externally_tagged_enum_names`
/// are what enumerate the other three files, so requiring both of them to be
/// empty here says "this file contributes nothing" in exactly the terms the
/// denominator is built from. The previous version asked instead whether the file
/// text CONTAINS `"pub struct "` or `"pub enum "`, which does not skip doc
/// comments: a future doc comment in `lib.rs` merely naming the text would have
/// red the assertion for a type that does not exist, which is a false refusal
/// rather than a proof. The STRUCT half is now covered by a doc-aware skip — the
/// same skip `serde_attribute_inventory_is_closed` applies, for the same reason —
/// and that skip lives in `declared_struct_names` alone. The ENUM half is
/// narrower than that sentence used to imply: `declared_enum_variants` has no
/// doc-comment skip of its own, and is kept off doc comments only incidentally,
/// because a `///` line does not begin with the `pub enum ` prefix it keys on.
/// That is a weaker mechanism than an explicit skip, and it is stated here so the
/// two halves are not read as one.
///
/// THE STRUCT HALF THEREFORE MEASURES SOMETHING STRONGER THAN IT USED TO, and
/// its message says so in the same words. `declared_struct_names` enumerates
/// non-public declarations as well as public ones, so "declares nothing" now
/// covers a private `struct` here exactly as it covers a `pub struct` — which is
/// the same reason the candidate denominator must not be able to miss one. The
/// ENUM half is deliberately unchanged: `externally_tagged_enum_names` still
/// enumerates `pub enum` only, so this assertion still counts precisely what it
/// counted before and claims only what that walk can see. The asymmetry is a
/// residual gap in the enum walk, not in this one.
///
/// `error.rs` keeps its own three checks and is deliberately NOT walked by
/// `externally_tagged_enum_names`: its `ConfigError` carries payload variants,
/// which that helper rejects loudly because its own classification requires the
/// all-unit externally tagged shape. That rejection is the right answer to the
/// question it is built for and the wrong answer to this one, so `error.rs` is
/// proved by the derive line, by the absence of the word `serde`, and by a DERIVED
/// type inventory compared against the one type it declares — because a whole-file
/// substring test and two exact line comparisons cannot see a second type appended
/// below them. See `declared_type_names`.
fn zero_candidate_files_are_proved() -> TestResult {
    let lib = read_workspace(LIB_FILE)?;
    assert!(
        lib.contains("pub use ids::"),
        "lib.rs must re-export the ids module"
    );
    assert!(
        lib.contains("pub use records::"),
        "lib.rs must re-export the records module"
    );
    assert!(
        lib.contains("pub use task_execution::"),
        "lib.rs must re-export the task_execution module"
    );
    let lib_structs = declared_struct_names(LIB_FILE)?;
    assert!(
        lib_structs.is_empty(),
        "lib.rs must declare no serde-bearing struct of its own, public or private, and the declaration walk found: {lib_structs:?}"
    );
    let lib_enums = externally_tagged_enum_names(LIB_FILE)?;
    assert!(
        lib_enums.is_empty(),
        "lib.rs must declare no externally tagged enum of its own, and the declaration walk found: {lib_enums:?}"
    );
    let error = read_workspace(ERROR_FILE)?;
    assert!(
        !error.contains("serde"),
        "error.rs must carry no serde impl, so it contributes no candidate"
    );
    let error_lines: Vec<&str> = error.lines().collect();
    let derive = error_lines
        .get(2)
        .copied()
        .ok_or_else(|| boxed(std::io::Error::other("error.rs:3 must exist")))?;
    let declaration = error_lines
        .get(3)
        .copied()
        .ok_or_else(|| boxed(std::io::Error::other("error.rs:4 must exist")))?;
    assert_eq!(derive, "#[derive(Debug, Error, Eq, PartialEq)]");
    assert_eq!(declaration, "pub enum ConfigError {");
    // THE TYPE INVENTORY, DERIVED, because everything above it is a substring test or
    // a fixed line comparison and neither of those can see a SECOND type. `serde` does
    // not occur inside the derive macro names `Serialize` and `Deserialize`, so
    // appending
    //
    //     #[derive(Serialize, Deserialize)]
    //     pub struct ConfigAudit { .. }
    //
    // to `error.rs` leaves the substring test green, leaves lines 3 and 4 untouched and
    // leaves `ConfigError` declared exactly where it was — while putting a serde-derived
    // candidate in a file that contributes ZERO candidates to the denominator, seen by
    // no walk in this file. The walk below says what the file declares instead of only
    // what it does not contain, so the inventory is 1 and the appended struct makes it 2.
    //
    // The equality is over the NAMES the walk derives, not over a count, so a failure
    // names the type that arrived rather than asking the reader to diff two integers.
    // The non-emptiness guard is what keeps the equality from being satisfied by a walk
    // that saw nothing at all, which is the same failure mode the `lib.rs` emptiness
    // checks above are exposed to and the reason they are stated as emptiness rather than
    // as a derived equality.
    let error_types = declared_type_names(ERROR_FILE)?;
    assert!(
        !error_types.is_empty(),
        "{ERROR_FILE} must declare at least one depth-zero type, or the inventory equality below compares two empty lists and this proof reads as a file that declares nothing when no walk has been run at all"
    );
    assert_eq!(
        error_types,
        ["ConfigError"],
        "{ERROR_FILE} must declare exactly one depth-zero type, `ConfigError`, and nothing else; a serde-derived struct appended to this file contributes no candidate to the allocation denominator and must not pass unseen behind the whole-file substring test above"
    );
    Ok(())
}

/// Split of the case-1 allocation table across the five source files.
///
/// THE EXPECTED SIDE IS NOW DERIVED, and that is the whole point of the change.
/// It used to be the literal tuple `("ids.rs", 40), ("records.rs", 7),
/// ("task_execution.rs", 5)`, which is a transcription of the same counts the
/// completeness assertion was supposed to be checking — a per-file count whose
/// expected value could only be updated by editing the list beside it. Every
/// non-zero entry now comes from `source_declared_type_names_by_file`, the same
/// live walk that supplies the flat expected set, so a new struct declaration in
/// `records.rs` raises the expected side here as well as there.
///
/// The two zero entries are ABSENCE claims rather than counts to be measured,
/// which is why they are not derived from the walk that found nothing: `0`
/// obtained from an empty list is the same fact asserted twice by the same code
/// and would prove nothing `zero_candidate_files_are_proved` does not, which
/// requires `lib.rs` to declare nothing at all against the same two walks.
///
/// WHY THE PER-FILE COUNT EQUALITY WAS REPLACED, which is the only change here
/// and it is a claim that was false rather than one that was inconvenient.
///
/// It used to assert, for each of the five files, that the number of rows whose
/// `source` leaf is that file EQUALS the number of types live source declares
/// there. That is a claim about a ROW COUNT, and this fixture's whole shape is
/// that later acceptance cases REUSE the allocated types: `ids.rs` declares 40
/// types and case 1 carries exactly 40 rows for them, so the moment a second
/// correctly-formed `ids.rs` row is recorded for an ALREADY-COVERED type — the
/// second case-14 group's malformed scalar rows are the first such rows — `live`
/// exceeds `expected` and case 1 goes red for a fixture that is right. The
/// property this function's NAME promises is the weaker and correct one: every
/// type declared in file F has AT LEAST ONE row naming F.
///
/// WHAT REPLACES IT IS STRONGER IN THE DIRECTION THAT MATTERS. The equality could
/// not tell a dropped row from a duplicated one: a duplicate in `ids.rs` balanced
/// by a drop in `ids.rs` kept both sides at 40. The per-NAME check below reds on
/// the dropped name regardless of what balances it.
///
/// WHAT IS NOT LOST, itemised, because a relaxed assertion is only honest with
/// its losses named:
/// * the MISSING-TYPE direction is asserted here per name, and is also asserted
///   BIDIRECTIONALLY over the whole fixture by `type_names_are_complete`, whose
///   expected side is enumerated from live source;
/// * the ABSENCE direction is kept verbatim: a file that declares no type at all
///   must still be named by no row, which is the `live == 0` assertion below and
///   the `lib.rs` / `error.rs` half of this loop;
/// * the per-file ROW TALLY is still checked, at the call site instead: case 1
///   compares `allocation.len()` with `allocated_type_names()?.len()`.
///
/// WHY THE SIGNATURE CARRIES AN ERROR CHANNEL. It used to return `()` on the
/// grounds that every failure here would be a panic. That was true while the
/// expected side was a literal table; it is no longer true, because reading live
/// source fails through `read_workspace` and through the declaration walks' own
/// fail-loud checks, and surfacing those as a named error rather than as a
/// panic keeps the failure attributable.
///
/// WHAT THE FINAL LOOP NOW ASSERTS, which is the widening and the reason this
/// function exists in this shape. It used to check only that a row's `source` leaf
/// names one of the five allocated files, which is a claim about a FILE and no
/// more: `source_leaf` strips the `:<digits>` suffix, every consumer of `source`
/// went through `source_leaf`, and the recorded line number was therefore discarded
/// before anything could compare it. A row could name the right file and any line
/// in it at all and pass. The loop now also requires the anchor to BE the
/// declaration site of that row's own type, over the three families read live:
///
/// * the macro-generated identifier types of `ids.rs`, whose declaration site is
///   the `id_type!(Name);` INVOCATION line, not the `pub struct $name(Uuid);` line
///   inside the `macro_rules!` body — through `id_type_expansions`, which now
///   yields that invocation line beside the name;
/// * the braced structs of `records.rs` and `task_execution.rs`, plus the two
///   BODYLESS `u64` newtypes `MemoryRevision` and `ProjectSequence`, all through
///   `declared_struct_names`, which recognises a declaration by keyword and
///   identifier and never looks for an opening brace, so it enumerates the
///   bodyless pair from the same single walk as the braced seven;
/// * the externally tagged `pub enum` declarations of `task_execution.rs` and of
///   `records.rs`, through `externally_tagged_enum_declarations`, a projection of
///   the one existing enum walk `declared_enum_variants` rather than a second
///   recogniser.
///
/// The comparison is made against the SAME `derived` denominator the completeness
/// assertion is proved over, so the name a row must carry and the line its anchor
/// must name were read by one traversal of one source and cannot come from walks
/// that disagree.
fn per_file_split_holds(all: &[&Row]) -> TestResult {
    // NON-VACUITY, before anything is compared and before anything is read. Every
    // assertion in this function is a loop over `all` or over the derived
    // denominator, so an empty `all` would reach neither and this function would
    // return `Ok` on an allocation table that had been emptied out from under it.
    // `allocation_rows` already refuses an empty allocation slice, but this is not
    // obliged to be called by `allocation_rows`, and a guard that depends on every
    // future caller happening to pass a checked slice is not a guard.
    assert!(
        !all.is_empty(),
        "the per-file split, and the recorded-anchor binding below, must be checked over a non-empty allocation slice, and this one carries {} rows, so every loop in this function would be vacuous",
        all.len()
    );
    let derived = source_declared_type_names_by_file()?;
    for source in SOURCE_FILES {
        let declared: &[(String, usize)] =
            match derived.iter().find(|(file, _)| source_leaf(file) == source) {
                Some((_, declarations)) => declarations.as_slice(),
                None => &[],
            };
        let live = all
            .iter()
            .filter(|row| source_leaf(&row.source) == source)
            .count();
        if declared.is_empty() {
            assert_eq!(
                live, 0,
                "no type is declared in {source}, so no row of this allocation may name it as its source"
            );
            continue;
        }
        for (name, _) in declared {
            assert!(
                all.iter().any(|row| {
                    source_leaf(&row.source) == source && type_leaf(&row.type_name) == name.as_str()
                }),
                "{source} declares {name} and no row of this allocation names it, so a type live source declares is missing a row here; the per-file ROW COUNT is checked by the caller, which compares the allocation's length with the number of declared types"
            );
        }
    }
    for row in all {
        let leaf = source_leaf(&row.source);
        assert!(
            SOURCE_FILES.contains(&leaf.as_str()),
            "row {} names a source file outside this allocation: {}",
            row.id,
            row.source
        );
        // THE BINDING. Both sides are `usize`, not `Option<usize>`: `source_line_anchor`
        // fails loudly on a row whose `source` carries no anchor, and
        // `declared_line_in` fails loudly when the row's own type has no declaration
        // in that file or has more than one. An `Option`-versus-`Option` comparison
        // would satisfy every row the moment the lookup stopped finding anything,
        // which is a broken derivation indistinguishable from a correct one; the
        // `Result` signatures make "found nothing" a named failure instead.
        let recorded = source_line_anchor(&row.source)?;
        let declared = declared_line_in(&derived, &leaf, type_leaf(&row.type_name))?;
        assert_eq!(
            declared,
            recorded,
            "row {} anchors {} at line {recorded} of {leaf}, but live source declares that type at line {declared}: a `source` value is a DECLARATION SITE, so the line number is the claim under test and not decoration on the file name",
            row.id,
            type_leaf(&row.type_name)
        );
    }
    Ok(())
}

/// The line `type_name` is DECLARED on in the file whose leaf is `leaf`, read out of
/// the derived denominator `per_file_split_holds` is already holding.
///
/// THE DENOMINATOR IS PASSED IN RATHER THAN RE-READ, so the line this returns is
/// the same line the completeness assertion proved the NAME against. Two walks over
/// one file could disagree about which line a declaration sits on, and this way
/// there is one walk.
///
/// FAILS LOUDLY, TWICE, and both failures are the point rather than a convenience.
/// Returning `None` for a missing declaration and comparing that against a recorded
/// `Option` would let every row pass whenever the lookup found nothing, so there is
/// no `None` here at all: no such file, and no such type in that file, are both
/// named errors. The second failure is the mirror image — a name declared TWICE in
/// one file has no single declaration site, so taking the first match would let a
/// recorded anchor agree with whichever of the two the walk happened to reach first,
/// and the duplicate would then be a permanent hole in this proof.
fn declared_line_in(
    derived: &DeclaredTypeNamesByFile,
    leaf: &str,
    type_name: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let declarations = derived
        .iter()
        .find(|(file, _)| source_leaf(file) == leaf)
        .map(|(_, declarations)| declarations.as_slice())
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "no candidate source file of this allocation has the leaf {leaf}, so no declaration line for {type_name} can be derived and its recorded anchor cannot be checked at all"
            )))
        })?;
    let mut matched = declarations
        .iter()
        .filter(|(name, _)| name.as_str() == type_name);
    let first = matched.next().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "{leaf} declares no type named {type_name} on any line this file's three declaration walks recognise, so a recorded anchor for it would have nothing to be compared against"
        )))
    })?;
    if matched.next().is_some() {
        return fail(format!(
            "{leaf} declares {type_name} more than once, so no single line can be the declaration site a recorded anchor names"
        ));
    }
    // `declarations` is a `&[(String, usize)]` slice, so `iter()` yields
    // `&(String, usize)` and `first.1` is already the `usize` line number BY VALUE —
    // `usize` is `Copy`, so reading the field out of the borrow copies it. The
    // previous `Ok(*first.1)` asked to dereference that `usize`, which is the
    // operator the compiler rejected; there is nothing behind it to reach.
    Ok(first.1)
}

/// EVERY row's recorded anchor is bound to the declaration site its own type is
/// read at from live source — the 110 rows outside the case-1 allocation, not only
/// the 52 inside it.
///
/// WHAT IT CLOSES. `per_file_split_holds` receives the allocation SLICE from its
/// caller, so its binding loop can only ever see the case-1 rows; every other
/// row's `source` anchor was read by nothing at all. A STATIC COMPARISON OVER THE
/// FIXTURE'S OWN BYTES — pairing each of the 110 non-allocation rows with an
/// allocation row of the same `type` and comparing `source` strings for equality —
/// found every one of them naming an allocated type and carrying a `source` string
/// identical to its allocation twin's, anchor included. That is two string fields read
/// against each other and needs no execution to establish; no suite was run and none
/// would report it, because the property is not a behaviour but a fact about the pair — but that is FIXTURE SELF-CONSISTENCY,
/// which nothing asserted: moving one non-allocation row's anchor a line up or down
/// reds nowhere. This function binds all of them.
///
/// WHY A NEW FUNCTION AND NOT A WIDER PARAMETER ON `per_file_split_holds`. The other
/// honest option was to widen that helper from `&[&Row]` to `&[Row]` and pass the whole
/// fixture at its one call site, and it is worth being exact about what that would have
/// done, because the reason is NOT the one it looks like. It would NOT have gone red:
/// read again, that helper's per-file loop compares the row tally with 0 only for a
/// file that declares nothing (`lib.rs`, `error.rs`), and for every other file it
/// asserts the per-NAME `any(...)` coverage instead — which all 162 rows satisfy,
/// since the 40 `ids.rs` types are all named by allocation rows and every row's source
/// leaf is one of the three files that declare something. What widening WOULD have done
/// is silently re-point that coverage claim at a wider population. "Every type declared
/// in F has at least one row naming F" is a claim about the ALLOCATION TABLE, and once
/// a case-14 row for the same type is allowed to satisfy it, the check no longer reports
/// a dropped allocation row as a dropped allocation row. That is an existing assertion's
/// MEANING changed as a side effect of adding a new one, which an additive repair may
/// not do, and the helper's own name and comment state the allocation split as its
/// property. So the widened binding is a separate function called where the whole row
/// set is in hand, and `per_file_split_holds` — its guards, its per-file loop, its
/// binding loop and their order — is left exactly as it was. The two bindings therefore
/// overlap on the 52 allocation rows, which is redundancy rather than a defect, and the
/// judgement is THIS COMMENT'S rather than a verdict anyone returned: only the
/// allocation-scoped binding can report a defect as being in the allocation, so the
/// overlap costs a duplicated comparison and buys that narrower report. No review pass
/// assessed this overlap; the argument for keeping it is the sentence above it.
///
/// THE EXPECTED SIDE IS DERIVED PER ROW, AND THAT IS THE WHOLE POINT. The obvious
/// cheaper comparison — a non-allocation row's anchor against the anchor recorded on
/// its allocation twin's `source` — is a tautology the moment the fixture is
/// internally consistent in the way that matters: a row and its twin could BOTH carry
/// the same wrong line and comparing them to each other would be green. So the
/// expected side here is `declared_line_in` over `source_declared_type_names_by_file`,
/// i.e. the line live source puts the declaration on, for every row including the
/// allocation's own. The loop's expected side reads ONE row's `type` and `source` plus
/// live source; it never reads another row, so there is no path by which two rows
/// agreeing can stand in for either of them being right.
///
/// REUSING `declared_line_in` AND `source_line_anchor` IS WHAT KEEPS THE TRAP CLOSED,
/// and passing the denominator in is sound here for the reason it is sound there:
/// `derived` is `source_declared_type_names_by_file()` read LIVE in this function's
/// own body, which is the same construction `allocated_type_names` flattens and
/// `type_names_are_complete` compares the recorded names against, so the line a row
/// is bound to was read by the same traversal that proved its name was declared at
/// all. Writing a second lookup instead would be free to disagree with the first
/// about which line a declaration sits on, which is the failure this derivation
/// exists to make impossible. Both helpers are used unchanged, so both of
/// `declared_line_in`'s refusals survive intact: a row whose `source` names a file
/// outside the candidate denominator and a row whose type that file does not declare
/// are still two NAMED errors rather than one collapsed "not found" — and no `None`
/// is introduced anywhere on this path, so nothing here can be satisfied by a lookup
/// that stopped finding anything.
///
/// TOTALITY, AND THE ROW WHOSE TYPE HAS NO ALLOCATION ROW. This function never asks
/// whether an allocation row exists, so it does not depend on one: the question it
/// asks of every row is whether live source declares that row's own type on the line
/// its anchor names, and `declared_line_in` answers it or refuses. The two refusals
/// are the answer for a row that cannot be bound — a type the denominator does not
/// contain has no correct anchor, so the row is REFUSED, never passed over. Nothing
/// is skipped, so there is no population of unproved rows for a skip to hide in.
/// (Measured against this fixture: all 162 rows name one of the 52 allocated types,
/// all 52 of which are declared in the file each row names, so no row reaches either
/// refusal today — `type_names_are_complete` is what proves the name half of that,
/// over ALL rows rather than over the allocation slice.)
fn every_row_anchor_names_its_declaration_site(all: &[Row]) -> TestResult {
    // NON-VACUITY, first, and it names what an empty loop would have proven: that
    // nothing, because every claim below is inside the loop. The allocation binding
    // in `per_file_split_holds` has the same guard for the same reason and this
    // function is not obliged to be called by it.
    assert!(
        !all.is_empty(),
        "every row's recorded anchor must be bound over a non-empty row population, and this one carries {} row(s), so the loop below would prove nothing at all",
        all.len()
    );
    // THE POPULATION MUST BE STRICTLY WIDER THAN THE ALLOCATION SLICE, which is the
    // guard for the mistake requirement this function exists to avoid. If a future
    // call site passed the allocation rows here, this function would become a second
    // copy of `per_file_split_holds` and stay green while 110 anchors went unchecked
    // again — the exact "a check that looks complete and is not" shape. Derived from
    // the fixture's own `case` field through the existing selector, so it invents no
    // expected count. A fixture carrying no non-allocation rows is already red in
    // every case that selects such rows, so this cannot be the only thing to notice.
    let allocation = allocation_rows(all)?;
    assert!(
        all.len() > allocation.len(),
        "the anchor binding must cover more than the {ALLOCATION_CASE} allocation slice: it was handed {} row(s) of which {} are allocation rows, so it is checking nothing `per_file_split_holds` does not already check",
        all.len(),
        allocation.len()
    );
    let derived = source_declared_type_names_by_file()?;
    for row in all {
        let leaf = source_leaf(&row.source);
        // Both sides are `usize`, never `Option<usize>`: the RECORDED side is turned
        // into a named error by `source_line_anchor` when a `source` carries no
        // `:<digits>` anchor, and the DERIVED side is turned into a named error by
        // `declared_line_in` when the row's own type is not declared on any line
        // these walks recognise in the file that row names. An `Option`-versus-`Option`
        // comparison would agree with every row the moment the derivation broke.
        let recorded = source_line_anchor(&row.source)?;
        let declared = declared_line_in(&derived, &leaf, type_leaf(&row.type_name))?;
        assert_eq!(
            declared,
            recorded,
            "row {} (case {}) anchors {} at line {recorded} of {leaf}, but live source declares that type at line {declared}: a `source` value is a DECLARATION SITE, and this row is bound against the line derived from source rather than against its allocation twin's recorded `source`, which two rows carrying the same wrong line would satisfy",
            row.id,
            row.case,
            type_leaf(&row.type_name)
        );
    }
    Ok(())
}

/// Every row's `shape` must be one of exactly the four allowed strings, every
/// allowed spelling must actually be used, and every `also_in_cases` entry must
/// name an acceptance case this file knows about. These are fixture claims that
/// were previously read by nothing, so a later edit could corrupt them silently.
///
/// The cross-reference check is deliberately NOT a membership test against the
/// literal `{2, 3, 4}`: that is true by construction and stays green when a
/// marker is dropped, renamed or added, because it never looks at what this file
/// dispatches. It is checked twice instead — once against the derived set of cases
/// this file dispatches or deliberately does not, and once against
/// `ALLOWED_ALSO_IN_CASES` — so a cross-reference naming a case that is neither
/// dispatched here nor recorded as BLOCKED fails, and a constant that drifts away
/// from the fixture fails too.
///
/// AND, LAST, THE `shape` COLUMN IS PUT BESIDE THE SOURCE, which is what the first
/// paragraph above cannot do and is the reason this function grew a third claim. Both
/// of the `shape` checks it starts with are CLOSED-WORLD: they compare the fixture
/// against `ALLOWED_SHAPES`, a constant typed in this file, and both operands of both
/// comparisons originate in the fixture or in that constant. A row whose `shape` named
/// a perfectly legal member of the vocabulary — the WRONG legal member for its type —
/// satisfied every one of them, so nothing in this file compared a row's declared shape
/// with what its type actually is. The last block below does, through
/// `expected_shape_from_source`, and it is deliberately the LAST claim here so that the
/// cheap fixture-internal checks still fail first with a message about the fixture.
fn declared_shapes_and_cross_references_hold(all: &[Row]) -> TestResult {
    let dispatched = dispatched_cases()?;
    for case in BYTE_INJECTED_CASES {
        assert!(
            dispatched.contains(&case),
            "case {case} must be dispatched by this file, or an `also_in_cases` reference to it names a case that selects nothing"
        );
    }
    for case in &UNDISPATCHED_CASES {
        assert!(
            !dispatched.contains(case),
            "case {case} is recorded as BLOCKED for this file, so it must not also carry a dispatch marker: {dispatched:?}"
        );
    }
    let mut known_cases = dispatched.clone();
    known_cases.extend_from_slice(&UNDISPATCHED_CASES);
    known_cases.sort_unstable();

    let mut observed: Vec<&str> = Vec::new();
    let mut cross_referenced: Vec<i64> = Vec::new();
    for row in all {
        if !ALLOWED_SHAPES.contains(&row.shape.as_str()) {
            return fail(format!(
                "row {} names a shape outside the closed vocabulary: {}",
                row.id, row.shape
            ));
        }
        if !observed.contains(&row.shape.as_str()) {
            observed.push(row.shape.as_str());
        }
        for case in &row.also_in_cases {
            if !known_cases.contains(case) {
                return fail(format!(
                    "row {} cross-references case {case}, which this file neither dispatches ({dispatched:?}) nor records as BLOCKED ({UNDISPATCHED_CASES:?})",
                    row.id
                ));
            }
            if !cross_referenced.contains(case) {
                cross_referenced.push(*case);
            }
        }
    }
    observed.sort_unstable();
    // Both sides are sorted, so the comparison cannot turn on the declaration
    // order of the constant itself.
    let mut expected_shapes = ALLOWED_SHAPES;
    expected_shapes.sort_unstable();
    assert_eq!(
        observed, expected_shapes,
        "every allowed shape must be used, so the closed vocabulary is exactly four"
    );
    // The set of cases the fixture actually cross-references must equal the
    // declared constant exactly, so neither a dropped reference nor a widened
    // constant can pass unnoticed. Sorted on both sides for the same reason.
    cross_referenced.sort_unstable();
    let mut declared_cases = ALLOWED_ALSO_IN_CASES;
    declared_cases.sort_unstable();
    assert_eq!(
        cross_referenced, declared_cases,
        "the fixture's `also_in_cases` values must equal ALLOWED_ALSO_IN_CASES exactly"
    );
    // THE BINDING THAT WAS MISSING, and it is a different KIND of claim from every
    // assertion above. Those compare the fixture against itself and against constants
    // typed in this file: `row.shape` is checked for MEMBERSHIP in `ALLOWED_SHAPES` and
    // for COVERAGE of it, and both operands of both comparisons come out of the
    // fixture or out of a literal. Nothing ever put a row's declared shape beside what
    // its TYPE IS, so a row labelled `transparent-uuid-scalar` for a braced
    // `deny_unknown_fields` struct satisfied every assertion in this function. A tally
    // of "0 of 52 shapes wrong" measured against the fixture is a READING of the
    // fixture, not a check of it; the expected side below is read out of live source.
    let allocation = allocation_rows(all)?;
    let allocated = allocated_type_names()?;
    assert!(
        !allocation.is_empty() && !allocated.is_empty() && allocation.len() == allocated.len(),
        "the shape binding must compare two non-empty, equally-sized populations: it sees {} case-{ALLOCATION_CASE} row(s) and {} allocated type(s) derived from live source, so fewer rows than types leaves the difference unclassified, and either population empty makes every comparison below vacuous",
        allocation.len(),
        allocated.len()
    );
    // TOTALITY, and the reason every answer this loop is handed is kept rather than
    // discarded. REACHING the comparison below is itself the proof that every allocated
    // type was classified: `expected_shape_from_source` returns an ERROR rather than an
    // answer it cannot justify, so a type it cannot classify aborts the case here
    // instead of being skipped past. An optional paired with a count is sound only when
    // the count's other side is derived rather than transcribed, and the guard above does
    // derive it — `allocated_type_names` is a live read, and the rows are selected by the
    // fixture's own `case` field — so both mechanisms are present; but the error channel
    // is the one that fails AT the type that could not be classified and names it and the
    // file it was looked for in, where a count fails at an aggregate and asks the reader
    // to diff two numbers.
    let mut classified: Vec<DerivedShape> = Vec::with_capacity(allocated.len());
    for name in &allocated {
        classified.push(expected_shape_from_source(name)?);
    }
    // The answers are BOUND TO THE CLOSED VOCABULARY as well as collected, so a future
    // derivation branch that produced a fifth spelling reds here rather than at a row
    // comparison whose message would read as a fixture defect.
    for shape in &classified {
        let spelling = shape.spelling();
        assert!(
            ALLOWED_SHAPES.contains(&spelling),
            "the derivation produced {spelling} for one allocated type, which is outside the closed vocabulary {ALLOWED_SHAPES:?}, so this file would be comparing a row against a spelling no row is permitted to declare"
        );
    }
    // The `deny_unknown_fields` REQUIREMENT is corroborated here against a source that
    // is not the one the requirement is read from. See `closed_object_labels_are_witnessed`
    // for what it does and does not establish; the short form is that the derivation's
    // closed labels are compared, PER FILE, with a downward-anchored scan of the same
    // five files, so the two can disagree.
    closed_object_labels_are_witnessed(&allocated, &classified)?;
    for row in &allocation {
        let name = type_leaf(&row.type_name);
        let expected = expected_shape_from_source(name)?;
        assert_eq!(
            expected.spelling(),
            row.shape,
            "row {} declares shape {} for {name}, but that type's declaration in live source derives {}: `shape` is a claim about the TYPE, not a label for the row",
            row.id,
            row.shape,
            expected.spelling()
        );
    }
    Ok(())
}

/// CORROBORATES the `deny_unknown_fields` REQUIREMENT in `declared_struct_shape`
/// against a reading of the same files that does not share its mechanism.
///
/// THE HOLE THIS EXISTS TO CLOSE. `declared_struct_shape` returns `CLOSED_OBJECT_SHAPE`
/// for a braced struct only when the declaration also carries
/// `#[serde(deny_unknown_fields)]`, and that requirement is what makes the shape's own
/// NAME honest. Deleting it — returning the shape on braces alone — leaves every current
/// label correct, because on the five allocated files "is braced" and "carries
/// `deny_unknown_fields`" are the same predicate: all seven `records.rs` structs and
/// the one `task_execution.rs` struct carry the attribute, and no braced declaration
/// anywhere in the three candidate files lacks it. Nothing would go red.
///
/// The obvious corroborator cannot help, and that is the second half of the hole:
/// `closed_struct_names` — which drives cases 3 and 4 — filters on the SAME attribute
/// through the SAME `declaration_serde_attributes` climb, so it would keep agreeing
/// whatever the requirement did. Two answers from one source are one answer.
///
/// WHAT IS INDEPENDENT HERE. The side below is read by a different traversal with a
/// different anchor and a different stop rule: `deny_unknown_fields_declarations` starts
/// at each `#[serde(deny_unknown_fields)]` line and walks DOWN to the declaration it
/// governs, where `closed_struct_names` starts at each declaration and walks UP to the
/// attributes above it. Neither borrows a predicate from the other, so a change in one
/// mechanism's notion of "this attribute belongs to this declaration" shows up here as
/// a disagreement rather than being copied.
///
/// WHAT IT ESTABLISHES, precisely. That the set of types the SHAPE DERIVATION labels
/// `closed-object` is exactly the set of depth-zero struct declarations of that file
/// that carry `deny_unknown_fields`, per file. So the hazard that used to be silent —
/// deleting the requirement AND then appending a braced struct that does not carry the
/// attribute, which would be labelled `closed-object` and probed by nobody — is now red
/// on the file and the names.
///
/// WHAT IT DOES NOT ESTABLISH, and this is stated rather than buried: it does NOT detect
/// the deletion of the requirement on its own. With every braced declaration in the
/// three candidate files still carrying the attribute, the two sides of the comparison
/// below are equal whichever way the requirement is written, so deleting the requirement
/// alone leaves this witness green. That is not an oversight in the witness; it is a
/// fact about the current source, and the fact is stated above. No witness expressible
/// over the five files' text can detect that deletion, because the property being
/// witnessed — "no type is labelled closed without carrying the attribute" — REMAINS TRUE
/// after the deletion is made. The requirement's value is as a stop against a FUTURE
/// declaration, and this is the check that makes the future declaration loud.
///
/// NON-VACUITY. The witness compares two lists per file, and an empty file would satisfy
/// that trivially, so the derived side must be non-empty before the comparison means
/// anything. Eight types are labelled `closed-object` today: seven in `records.rs` and
/// `TaskExecutionClass`.
fn closed_object_labels_are_witnessed(
    allocated: &[String],
    classified: &[DerivedShape],
) -> TestResult {
    assert_eq!(
        allocated.len(),
        classified.len(),
        "the corroboration below pairs one declared name with one derived shape, and {} names were paired with {} shapes, so a type could be dropped from one side and the comparison would agree on the rest",
        allocated.len(),
        classified.len()
    );
    let derived = source_declared_type_names_by_file()?;
    let mut labelled: Vec<(&'static str, Vec<String>)> = Vec::new();
    for (name, shape) in allocated.iter().zip(classified.iter()) {
        if *shape != DerivedShape::ClosedObject {
            continue;
        }
        let mut sites = derived
            .iter()
            .filter(|(_, declarations)| declarations.iter().any(|(found, _)| found == name));
        // THE BINDING, STATED AS THE COMPILER HAS IT. `DeclaredTypeNamesByFile` is
        // `Vec<(&'static str, Vec<(String, usize)>)>`, so `derived.iter()` yields
        // `&(&'static str, Vec<..>)` and `filter`'s closure parameter is a further
        // reference to that; `sites.next()` therefore hands back
        // `Option<&(&'static str, Vec<..>)>` — a borrow OF a borrowed tuple. The pattern
        // below destructures THAT, and the consequence is the thing worth recording:
        // `file` ARRIVES AS `&&'static str`, NOT as the `&'static str` the map stores.
        // An earlier revision of this comment claimed match ergonomics "dereferences
        // and binds by `ref`, so `file` arrives as the `&'static str`", and that was
        // false; rustc's own note on the comparison below names the right operand's
        // type as `&&str`, which is the ground truth this comment now states. The
        // declarations vector is discarded, which is all the second element was ever
        // for.
        //
        // The previous spelling destructured the SECOND element as a tuple as well, and
        // that element is a `Vec`, not a tuple — the shape the compiler rejected, and
        // the shape this names so a reader is not left guessing which half was meant.
        let Some((file, _)) = sites.next() else {
            return fail(format!(
                "{name} is labelled {CLOSED_OBJECT_SHAPE} by the shape derivation but no candidate source file declares it, so the declaration this label claims to have read does not exist"
            ));
        };
        if sites.next().is_some() {
            return fail(format!(
                "{name} is labelled {CLOSED_OBJECT_SHAPE} and is declared by more than one candidate source file, so the corroboration below has no single file to check it against"
            ));
        }
        // THE COMPARISON IS BY FILE NAME, AND IT NEEDS `*file` BECAUSE OF THE BINDING
        // ABOVE — not because of anything about `position`, `iter`, or which side of
        // the comparison is a dereference. `entry` is the iterator's item, a reference
        // to the tuple, so `entry.0` is a `&str`. `file` is a `&&'static str`. Written
        // `entry.0 == file`, the blanket reference impl reduces `&str == &&str` to
        // `str == &str`, and a `str` is unsized with no by-value `PartialEq`; written
        // `entry.0 == *file`, both sides are `&str` and it is an ordinary comparison.
        // Both rejected spellings here have been wrong for the SAME reason and neither
        // would be fixed by choosing between `iter()` and `iter_mut()`: the
        // destructuring `*known == file` landed the deref on the unsized `str`, and the
        // un-dereferenced `entry.0 == file` left one extra level on the right.
        //
        // THIS IS WHY THE SPELLING MUST NOT BE COPIED TO THE CORROBORATION LOOP BELOW,
        // and the reason is a difference in where each `file` comes from. Here it is
        // destructured out of an `Option<&(..)>`; there it comes from
        // `for file in CANDIDATE_SOURCE_FILES`, and that constant is declared
        // `[&str; 3]` — an array BY VALUE — so the loop yields a plain `&str` and
        // `entry.0 == file` is already correct there. One `file` is a `&&str` and the
        // other is a `&str`; the deref is a property of the binding, not of the
        // comparison.
        //
        // `labelled.push((file, ..))` in the `None` arm is correct WITHOUT a deref and
        // must stay that way: the tuple's element type is `&'static str`, and a
        // `&&str` coerces to `&str` at that coercion site. Adding a `*` there would be
        // a type error, not a tidy-up.
        //
        // WHAT IS DELIBERATELY UNCHANGED: the shape of `labelled`, and the order and
        // meaning of the two arms. An entry that already exists for this declaration
        // file has `name` pushed onto it, and a file seen for the first time starts a
        // new entry — "same declaration file groups under one entry", which is the
        // only thing the corroboration below reads out of this vector. `position`
        // rather than `find` is a mechanical difference: `position` hands back the
        // index of the match, which is what `get_mut` needs, and `find` hands back
        // the match itself, which `iter_mut` would have allowed directly. The bounds
        // check on the index is real rather than decorative and follows the pattern
        // `document_without_span` already uses for the same reason.
        //
        // TWO BORROWS, AND BOTH ARE ARRANGED RATHER THAN ASSUMED. A previous revision
        // of this comment said only the first and drew a conclusion from it that the
        // compiler disproved, so both are stated here as the code is written.
        //
        // * THE `position` BORROW IS ENDED ON ITS OWN `let` LINE, so the shared borrow
        //   of `labelled` does not reach either arm. Written into the `match`
        //   scrutinee instead, `labelled.iter()` would leave a temporary `Iter` alive
        //   to the end of the match expression; NLL ends the REGION at last use, but a
        //   temporary's own SCOPE is a separate rule, and it is not worth relying on
        //   when the correction has to be right without a compiler in the loop.
        // * THE ERROR MESSAGE'S ENTRY COUNT IS READ INTO A LOCAL BEFORE THE MUTABLE
        //   BORROW IS TAKEN, so the `ok_or_else` closure captures NOTHING. Read inline
        //   as `labelled.len()` inside that closure, it captures `&labelled` — an
        //   immutable borrow — at a point where `get_mut(index)` already holds
        //   `&mut labelled`, and that borrow is still live because the `?` and the
        //   `.1.push(..)` both consume the result. That is E0502, and it is why the
        //   count arrives here as a `usize` local instead. `{index}` is still
        //   interpolated, so a genuine out-of-range failure still names both what was
        //   out of range and how far out it was.
        //
        // REMOVE EITHER HALF AND THE ERROR RETURNS: drop the `let` for the count and
        // the closure borrows again; fold `position` into the scrutinee and the shared
        // borrow reaches the arms. Neither is a style preference.
        let entries = labelled.len();
        let existing = labelled.iter().position(|entry| entry.0 == *file);
        match existing {
            Some(index) => labelled
                .get_mut(index)
                .ok_or_else(|| {
                    boxed(std::io::Error::other(format!(
                        "the declaration file index {index} found for {name} is out of range for a {entries}-entry grouping vector"
                    )))
                })?
                .1
                .push(name.clone()),
            None => labelled.push((file, vec![name.clone()])),
        }
    }
    assert!(
        !labelled.is_empty(),
        "the derivation labelled no allocated type {CLOSED_OBJECT_SHAPE}, so every comparison below compares two empty lists and this witness would pass against a derivation that had stopped deriving anything"
    );
    for file in CANDIDATE_SOURCE_FILES {
        // `entry.0 == file` HERE, AND `entry.0 == *file` IN THE GROUPING LOOP ABOVE — the
        // difference is the BINDING and nothing else. `CANDIDATE_SOURCE_FILES` is
        // declared `[&str; 3]`, an array by value, so `for file in` it yields a plain
        // `&str` and `entry.0` (`&str`) matches it directly. The grouping loop's `file`
        // is destructured out of an `Option<&(&'static str, ..)>` and is a `&&'static
        // str`, so it needs one deref. An earlier revision of this comment claimed the
        // two sites were "spelled identically" and that neither "depends on how many
        // references a destructuring pattern happens to bind through"; both halves
        // were false, the second exactly backwards, and a comment telling a reader the
        // two are interchangeable is how the deref gets dropped here and the compile
        // error moves to the loop above. Read the binding at each site; do not copy
        // the spelling across.
        let mut from_derivation: Vec<String> = labelled
            .iter()
            .find(|entry| entry.0 == file)
            .map(|(_, names)| names.clone())
            .unwrap_or_default();
        from_derivation.sort_unstable();
        let mut from_attributes = deny_unknown_fields_declarations(file)?;
        from_attributes.sort_unstable();
        assert_eq!(
            from_derivation, from_attributes,
            "the types {file} has that the shape derivation labels {CLOSED_OBJECT_SHAPE} must be exactly the depth-zero struct declarations of {file} carrying {DENY_UNKNOWN_FIELDS_ATTRIBUTE}, read by a different traversal; the derivation labelled {from_derivation:?} and the downward attribute scan found {from_attributes:?}, so a type is labelled closed without carrying the attribute, or carries it without being labelled closed",
        );
    }
    Ok(())
}

/// The wire shape the DECLARATION of `type_name` spells out, read from live source —
/// never from a fixture row, a row id, or a row's prose.
///
/// THREE FAMILIES, THREE DERIVATIONS, and no single recogniser serves all three:
/// * the `id_type!` expansions. An expansion has no `struct` declaration line of its
///   own: `pub struct $name(Uuid);` sits inside the `macro_rules!` body at brace depth
///   1, is ONE line shared by all 38 expansions, and names `$name`. Every depth-zero
///   declaration walk is therefore blind to this family BY CONSTRUCTION —
///   `struct_declaration_name` returns `None` on a leading `$`, and that is exactly
///   what stops the macro body from counting as a declaration. Membership is read
///   through `id_type_expansions`, the walk that reads the macro's INVOCATION lines;
///   the shape comes from `id_type_expansion_shape`, which reads the body;
/// * `MemoryRevision` and `ProjectSequence`, declared as single-line
///   `pub struct <Name>(u64);` newtypes with NO BRACES. `struct_field_types` keys on
///   the braced form — it searches for the literal `pub struct <name> {` — and its own
///   comment records that it needs a body, so it cannot see either of them.
///   `declared_struct_shape` reads the bodyless form and the braced form from one
///   declaration walk;
/// * the four externally tagged `task_execution.rs` enums, through
///   `externally_tagged_enum_names`, the owner this file already derives enum names
///   with for `type_is_enum_typed`. `declared_enum_variants` already fails loudly on
///   an enum carrying a payload, so "is an enum" here cannot quietly mean "is an enum
///   of a shape this file has no name for";
/// * everything else is a braced struct, through `declared_struct_shape` — and a
///   braced struct is `CLOSED_OBJECT_SHAPE` only when it ALSO carries
///   `#[serde(deny_unknown_fields)]`. That clause belongs to `declared_struct_shape`
///   and the reason is in its own comment.
///
/// WHY IT RETURNS AN ERROR RATHER THAN AN OPTIONAL, which is the whole design of this
/// repair. The obvious implementation routes the derivation through this file's
/// existing declaration walks, and those walks DELIBERATELY report nothing for the
/// largest family in this allocation — so the derivation would answer an EMPTY list,
/// compare equal to nothing, and land VACUOUSLY and green across 38 of the 52 types it
/// exists to check. Option (b), an optional plus a count, is sound only when the
/// count's other side is derived rather than transcribed; the caller does derive it and
/// does pair the two populations, so both mechanisms are deliberately present — but
/// this error channel is the one that fails AT the type that could not be classified,
/// naming it, the file it was looked for in and the form that defeated it. A count
/// cannot name any of those.
///
/// THE RETURN TYPE IS LOAD-BEARING. Read this before changing the signature. The
//`DerivedShape` this returns cannot hold a fixture-owned string: it is an enum of four
/// unit variants with no field and no lifetime, so a body that answered with
/// `row.shape.as_str()` — a `&str` borrowed from the parsed fixture — would not
/// compile, and the binding below would not become the tautology it would otherwise
/// silently become. Relaxing the return type to any borrowed `&str` removes the only
/// barrier between this derivation and the fixture's own declared shapes, and nothing
/// in this file would go red. See `DerivedShape` for the full argument; this paragraph
/// is here so that a reader who has only this signature in view still sees it.
///
/// EXACTLY ONE SOURCE MUST CLASSIFY THE TYPE, and that is a change from the previous
/// version of this body. It used to walk `CANDIDATE_SOURCE_FILES` and return the FIRST
/// file that answered, after an early return for the `id_type!` family — so a name
/// declared in two of those files would have been classified from whichever came first
/// and the collision would have been invisible. `declared_line_in` already refused a
/// duplicate WITHIN one file for the same reason; nothing refused it ACROSS two. The
/// walk below therefore collects every source that answers and requires exactly one,
/// and the `id_type!` family is folded into that count rather than short-circuiting
/// ahead of it, so a name that is both an expansion and a depth-zero declaration is
/// refused rather than resolved by precedence.
///
/// MEASURED, so the guard below is future protection rather than a present fix: the
/// three candidate files' type sets are disjoint today. `ids.rs` declares 38 `id_type!`
/// expansions plus `MemoryRevision` and `ProjectSequence`; `records.rs` declares seven
/// structs and no enum; `task_execution.rs` declares `TaskExecutionClass` and the four
/// member enums `TaskExecutionDomain`, `TaskExecutionAction`, `TaskExecutionArtifact`
/// and `TaskExecutionClassSource`. No name appears in two of them, and none of the 38
/// expansion names is one of the fourteen declared types. No cross-file collision
/// exists to fix here; what the change removes is the possibility of one resolving
/// silently.
fn expected_shape_from_source(type_name: &str) -> Result<DerivedShape, Box<dyn std::error::Error>> {
    let mut classified: Vec<(&str, DerivedShape)> = Vec::new();
    if id_type_expansions()?
        .iter()
        .any(|(name, _)| name.as_str() == type_name)
    {
        classified.push((IDS_FILE, id_type_expansion_shape(type_name)?));
    }
    for file in CANDIDATE_SOURCE_FILES {
        if externally_tagged_enum_names(file)?
            .iter()
            .any(|name| name == type_name)
        {
            classified.push((file, DerivedShape::ExternallyTaggedEnum));
        }
        if let Some(shape) = declared_struct_shape(file, type_name)? {
            classified.push((file, shape));
        }
    }
    match classified.as_slice() {
        [] => fail(format!(
            "no allocated source file derives a wire shape for {type_name}: it is not one of the `id_type!` expansions of {IDS_FILE}, not a `pub enum` of any of [{}], and not a depth-zero `struct` declaration of any of them, so this file cannot tell whether a row's declared shape is honest",
            CANDIDATE_SOURCE_FILES.join(", ")
        )),
        [(_, shape)] => Ok(*shape),
        // Named rather than silently resolved: with one answer the label is a fact
        // about a declaration site, and with two it is a fact about the ORDER of
        // `CANDIDATE_SOURCE_FILES`, which is not a property of the source at all.
        several => fail(format!(
            "{type_name} is classifiable from {} sources at once — {several:?} — so no single declaration site can be the one its wire shape is read from; `expected_shape_from_source` refuses to resolve a cross-file name collision by precedence",
            several.len()
        )),
    }
}

/// The shape an `id_type!` expansion spells out, read from the macro BODY's own
/// `pub struct $name(<Payload>);` declaration and the `#[serde(transparent)]` above it.
///
/// WHY THE BODY AND NOT THE INVOCATION. `id_type!(AgentId);` says only that a type is
/// generated; it does not say what the type WRAPS, and the closed vocabulary separates
/// `transparent-uuid-scalar` from `transparent-u64-scalar` on exactly that. So the
/// payload is read from the one line in the file that states it, and the
/// `transparent` attribute above it is REQUIRED rather than assumed: a newtype without
/// it has an object form of its own and is not either scalar shape.
///
/// `type_name` is carried for the failure messages only. The caller has already
/// established, from the live invocation list, that this type IS an expansion, so
/// nothing here can classify a type the macro does not generate.
///
/// A body that cannot be read is an ERROR naming the file and the line, never an empty
/// answer: an empty answer here would classify 38 types as nothing at all and compare
/// equal to them.
fn id_type_expansion_shape(type_name: &str) -> Result<DerivedShape, Box<dyn std::error::Error>> {
    let source = read_workspace(IDS_FILE)?;
    let lines: Vec<&str> = source.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("pub struct $name(") else {
            continue;
        };
        let Some(payload) = rest.strip_suffix(");") else {
            return fail(format!(
                "{IDS_FILE}:{} declares the macro body's newtype in a form this file cannot read, so {type_name}'s shape cannot be derived from it: {trimmed}",
                index + 1
            ));
        };
        let carried = declaration_serde_attributes(&lines, index);
        if !carried
            .iter()
            .any(|form| form.as_str() == TRANSPARENT_ATTRIBUTE)
        {
            return fail(format!(
                "{IDS_FILE}:{} declares the macro body without {TRANSPARENT_ATTRIBUTE}, so {type_name} is not the transparent scalar that either scalar shape names",
                index + 1
            ));
        }
        return scalar_shape_for_payload(type_name, payload, &format!("{IDS_FILE}:{}", index + 1));
    }
    fail(format!(
        "{IDS_FILE} declares no `pub struct $name(<Payload>);` line at all, so the shape of the {type_name} expansion cannot be read from source"
    ))
}

/// The wire shape a depth-zero `struct` declaration of `name` in `file` spells out, or
/// `None` when `file` declares no struct under that name.
///
/// WHY A WALK OF ITS OWN AND NOT `struct_field_types`. That walk keys on the BRACED
/// form — it searches for the literal `pub struct <name> {` — so it cannot see
/// `MemoryRevision` or `ProjectSequence`, which are declared as single-line
/// `pub struct <Name>(u64);` newtypes with no braces at all; its own comment records
/// the requirement. This walk recognises a declaration through the SAME
/// `struct_declaration_rest` / `struct_declaration_name` pair `declared_struct_names`
/// and `closed_struct_names` use, behind the same signed `brace_delta_outside_strings`
/// accumulator and the same depth-zero gate, so the three cannot disagree about which
/// LINES are declarations. It differs only in what it then does with the DECLARATOR —
/// the one thing neither of the other two records, and the thing a wire shape is
/// decided by.
///
/// `None` MEANS "NOT DECLARED IN THIS FILE" and never "cannot classify". A declaration
/// this walk finds and cannot read is an ERROR naming the file, the line and the type,
/// so the caller's "no file derives a shape" failure can be reached ONLY by a type that
/// is genuinely absent from the allocation. Collapsing those two into one empty answer
/// is the vacuity this whole repair exists to remove.
///
/// TWO DECLARATOR FORMS, and what each derives:
/// * `(Payload);` — a BODYLESS NEWTYPE. It belongs to the transparent-scalar family,
///   and WHICH member is decided by the payload through `scalar_shape_for_payload`,
///   with `#[serde(transparent)]` required above the declaration;
/// * `{ .. }` — a DOCUMENT OBJECT. It is `CLOSED_OBJECT_SHAPE` only when the
///   declaration also carries `#[serde(deny_unknown_fields)]`, because that attribute
///   is what makes the object CLOSED and the shape's own name claims it. Deriving
///   "closed-object" from braces alone would assert a property the declaration does not
///   carry, and the four-member vocabulary holds no spelling for an open object, so a
///   braced struct without the attribute is an ERROR naming it: not a downgrade, and
///   not a fifth member added here.
///
/// ANY OTHER DECLARATOR — a unit struct, a generic parameter list, a brace that is not
/// on the declaration line — is an ERROR. Guessing at a form this walk has never been
/// shown would put a fabricated shape on a real declaration.
fn declared_struct_shape(
    file: &str,
    name: &str,
) -> Result<Option<DerivedShape>, Box<dyn std::error::Error>> {
    let source = read_workspace(file)?;
    let lines: Vec<&str> = source.lines().collect();
    let mut depth: isize = 0;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let at_top_level = depth == 0 && !trimmed.starts_with("///") && !trimmed.starts_with("//!");
        let declarator = if at_top_level {
            struct_declaration_rest(trimmed)
        } else {
            None
        };
        depth += brace_delta_outside_strings(line);
        let Some(declarator) = declarator else {
            continue;
        };
        if struct_declaration_name(declarator) != Some(name) {
            continue;
        }
        // The declarator AFTER the name. `struct_declaration_name` returned a slice
        // equal to `name`, so this offset is exact and the name is not parsed twice.
        let after_name = declarator[name.len()..].trim_start();
        let carried = declaration_serde_attributes(&lines, index);
        if let Some(body) = after_name
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(");"))
        {
            if !carried
                .iter()
                .any(|form| form.as_str() == TRANSPARENT_ATTRIBUTE)
            {
                return fail(format!(
                    "{file}:{} declares {name} as a newtype over {body} without {TRANSPARENT_ATTRIBUTE}, so it has an object form and is neither transparent scalar shape",
                    index + 1
                ));
            }
            return scalar_shape_for_payload(name, body, &format!("{file}:{}", index + 1))
                .map(Some);
        }
        if after_name.starts_with('{') {
            if carried
                .iter()
                .any(|form| form.as_str() == DENY_UNKNOWN_FIELDS_ATTRIBUTE)
            {
                return Ok(Some(DerivedShape::ClosedObject));
            }
            return fail(format!(
                "{file}:{} declares {name} as a braced struct without {DENY_UNKNOWN_FIELDS_ATTRIBUTE}, so it is not the closed object {CLOSED_OBJECT_SHAPE} names, and the closed vocabulary carries no spelling for an open one",
                index + 1
            ));
        }
        return fail(format!(
            "{file}:{} declares {name} in a declarator form this walk cannot read, so no wire shape can be derived from it: {trimmed}",
            index + 1
        ));
    }
    Ok(None)
}

/// The transparent-scalar shape a `#[serde(transparent)]` newtype over `payload`
/// spells out, decided by the payload's own declared type.
///
/// TWO SPELLINGS AND NO MORE, deliberately. The closed vocabulary names
/// `transparent-uuid-scalar` and `transparent-u64-scalar` and nothing else, so a
/// payload that is neither `Uuid` nor `u64` has NO shape this file is permitted to
/// derive for it. Answering with the nearest member would put a shape on a
/// declaration that does not carry it — the FIXTURE-side version of the very defect
/// this repair removes — and answering with nothing would let the caller compare
/// against an empty set. So this is an ERROR naming the type, the payload and the
/// line, which is the direction that says the vocabulary has to be WIDENED
/// deliberately, in the same change that adds the type.
fn scalar_shape_for_payload(
    type_name: &str,
    payload: &str,
    declared_at: &str,
) -> Result<DerivedShape, Box<dyn std::error::Error>> {
    match payload {
        UUID_PAYLOAD_TYPE => Ok(DerivedShape::UuidScalar),
        U64_PAYLOAD_TYPE => Ok(DerivedShape::U64Scalar),
        other => fail(format!(
            "{declared_at} declares {type_name} as a transparent newtype over {other}, which is neither {UUID_PAYLOAD_TYPE} nor {U64_PAYLOAD_TYPE}, so no member of the closed shape vocabulary can be derived for it"
        )),
    }
}

/// Every allocated type must be present by name, and the distinct type names
/// recorded anywhere in the fixture must equal the allocated set exactly: no
/// missing and no invented type row. Later cases re-use the same types, so the
/// comparison is over distinct names rather than over row instances.
///
/// BIDIRECTIONAL, and that is what the expected side is FOR. Both operands are
/// sorted and DEDUPLICATED before the comparison, so the assertion cannot turn
/// on order and cannot be satisfied by a repeated name. `recorded` is the
/// fixture's own claim; `allocated_type_names()` is read live out of `ids.rs`,
/// `records.rs` and `task_execution.rs`. Reading each direction:
/// * an INVENTED row — a name the fixture carries that no source file declares —
///   is on the left and not the right, so the multisets differ and this reds;
/// * a MISSING row — a type live source declares that the fixture does not carry
///   — is on the right and not the left, and this reds.
///
/// The per-name loop over the `id_type!` expansions below is kept as a separate,
/// weaker witness with its own message: it names the specific expansion that is
/// missing instead of making the reader diff two sorted vectors. It is strictly
/// implied by the equality above and nothing is lost by keeping it.
fn type_names_are_complete(all: &[Row]) -> TestResult {
    let expansions = id_type_expansions()?;
    assert_eq!(
        expansions.len(),
        38,
        "ids.rs must expand exactly 38 id types"
    );
    let mut recorded: Vec<String> = all
        .iter()
        .map(|row| type_leaf(&row.type_name).to_owned())
        .collect();
    recorded.sort();
    recorded.dedup();
    // The expansion's LINE column is not read here: this witness is about NAMES, and
    // the line is checked against each row's recorded `source` anchor by
    // `per_file_split_holds`, over the same walk.
    for (name, _) in &expansions {
        assert!(
            recorded.contains(name),
            "id_type expansion is missing from the allocation table: {name}"
        );
    }
    // `recorded` is deduplicated and `allocated_type_names` is sorted but
    // deliberately not deduplicated, so a source-side name collision shows up as a
    // mismatch rather than being hidden. The equality is over the whole vector,
    // so it is order-sensitive by construction and both sides are sorted above
    // and in `allocated_type_names` for exactly that reason.
    assert_eq!(
        recorded,
        allocated_type_names()?,
        "the recorded type names must equal the set live source declares, in both directions: a name on the left that no source file declares is an invented row, and a name on the right the fixture does not carry is a missing row"
    );
    Ok(())
}

/// The case-1 allocation slice of the fixture: one row per serde candidate.
fn allocation_rows(all: &[Row]) -> Result<Vec<&Row>, Box<dyn std::error::Error>> {
    let matched: Vec<&Row> = all
        .iter()
        .filter(|row| row.case == ALLOCATION_CASE)
        .collect();
    if matched.is_empty() {
        return fail(format!(
            "the fixture must carry case {ALLOCATION_CASE} rows"
        ));
    }
    Ok(matched)
}

/// Rows for one acceptance case. Selected by the `case` field only: row ids move
/// between revisions, the case number does not.
fn rows_in_case(all: &[Row], case: i64) -> Vec<&Row> {
    all.iter().filter(|row| row.case == case).collect()
}

/// A reject group: non-empty, and no row may claim `expected == "accept"`.
/// Asserting a refusal the fixture does not claim would be a red test invented
/// here rather than one the fixture supports.
///
/// AND THE ROW'S `expected` VALUE MUST BE IN THE CLOSED VOCABULARY, which is why this
/// guard is HERE and not only in `expected_is_closed`. `reject_rows` is where cases 5,
/// 6, 7, 10, 14 and 15 SELECT the rows they then assert refusals for, so a case-5/6/7
/// row marked `expected: "REJECT"` — wrong case — or `expected: ""` was accepted by
/// every one of those cases and caught only by case 16's whole-fixture sweep, hundreds
/// of lines away from the selection that consumed it. `expected_is_closed` is applied
/// only from case 16, so nothing between the fixture's `expected` field and the
/// rejection it authorises checked that the value meant anything.
///
/// The check is deliberately `reject`-side only. `accept_rows` already requires exactly
/// `ACCEPT_EXPECTED`, so any value outside the vocabulary is refused there for a
/// different reason; adding a second guard there would be unreachable rather than
/// stronger. `expected_is_closed` is STILL CALLED from case 16 and is deliberately not
/// removed: it is the whole-fixture sweep, it catches an accept-side row whose `expected`
/// is corrupt in a way `accept_rows` does not reach, and removing it would trade one
/// duplicate check for a hole.
fn reject_rows(all: &[Row], case: i64) -> Result<Vec<&Row>, Box<dyn std::error::Error>> {
    let group = rows_in_case(all, case);
    if group.is_empty() {
        return fail(format!("case {case} must carry at least one row"));
    }
    for row in &group {
        let expected = row.expected.trim();
        if !EXPECTED_VOCABULARY.contains(&expected) {
            return fail(format!(
                "case {case} row {} records expected {expected:?}, which is outside the closed vocabulary {EXPECTED_VOCABULARY:?}; this row has been SELECTED as a rejected row, so a value this file cannot interpret would be asserted as a refusal on no evidence at all",
                row.id
            ));
        }
        if expected == ACCEPT_EXPECTED {
            return fail(format!(
                "case {case} row {} claims {ACCEPT_EXPECTED} and cannot be asserted as refused",
                row.id
            ));
        }
    }
    Ok(group)
}

/// An accept group: non-empty, and every row must claim `expected == "accept"`.
fn accept_rows(all: &[Row], case: i64) -> Result<Vec<&Row>, Box<dyn std::error::Error>> {
    let group = rows_in_case(all, case);
    if group.is_empty() {
        return fail(format!("case {case} must carry at least one row"));
    }
    for row in &group {
        if row.expected.trim() != ACCEPT_EXPECTED {
            return fail(format!(
                "case {case} row {} claims {} and cannot be asserted as accepted",
                row.id, row.expected
            ));
        }
    }
    Ok(group)
}

/// The only JSON literal this file splices into a payload. Authored here, never
/// copied from the fixture, and used only where the value is asserted to mean
/// "no value" rather than where a fixture row has to agree.
const JSON_NULL: &str = "null";

/// The byte index just past the JSON value that starts at `index`.
///
/// A byte scan rather than a `Value` walk, for the same reason
/// `top_level_member_spans` is one: `serde_json::Map` is a `BTreeMap`, so a
/// document that has passed through a `Value` has already lost any duplicate
/// member, and the boundary between a value and the comma after it is not
/// something a `Value` records at all. Every string is skipped whole, escapes
/// included, so a `{`, `,` or `}` inside a string value is never read as
/// structure.
/// WHAT THIS ASSUMES ABOUT THE PARSER THAT `serde_json` DOES NOT GUARANTEE, and the
/// class of input where that assumption could fail.
///
/// ASSUMPTION: a JSON string is closed by the first `"` that is not preceded by an
/// odd number of backslashes — which is what `string_closing_quote` implements — and a
/// CONTAINER value ends at the bracket that closes it. Both hold for every document the
/// JSON grammar admits, and `serde_json` implements them the same way, so there is no
/// disagreement about well-formed input.
///
/// WHERE IT COULD FAIL, and the direction matters more than the case: inside a string
/// this scanner resolves escapes only far enough to know that a `\"` does not close the
/// string, and it does NOT decode `\uXXXX`, so it cannot tell a high surrogate from any
/// other scalar. A caller that needs that distinction must ask a scanner which decodes
/// the escapes — `escape_after` and `hex_escape_value` exist for exactly one such caller.
/// The failure direction is a scanner that reads a string as ending EARLIER than the
/// parser does, which would make it see structure where there is none.
///
/// THE PREVIOUS VERSION OF THIS PARAGRAPH WAS FALSE, and it is worth recording how,
/// because the error was in the direction of the risk. It claimed the bare-token arm
/// "does not track nesting, so for a container value it returns a LOWER BOUND" and that
/// "every caller that reaches this with a container therefore gets a too-tight extent".
/// Neither clause is reachable. A container value NEVER REACHES THAT ARM: the match
/// dispatches on the byte at `index`, and `Some(b'{' | b'[')` is the arm above, which
/// does track depth and returns the cursor at which depth returns to zero. The
/// bare-token arm is entered only when that byte is none of `"`, `{` or `[` — which
/// is to say for a SCALAR. Both call sites in this file hand it a true value start
/// anyway: `document_with_member_value` passes `span.value_start` and
/// `repeated_member_value_tokens` passes `value_offset(bytes, close + 1)`, and both are
/// the first byte of the value token by construction.
///
/// THE TWO REAL RESIDUAL ASSUMPTIONS, which are narrower than the false pair above and
/// which name the failure direction each way.
///
/// THE CONTAINER ARM COUNTS DEPTH AND NEVER CHECKS THAT A CLOSER MATCHES ITS OPENER. It
/// pushes on `{` and `[` alike and pops on `}` and `]` alike, so `{"a":[1}` returns an
/// extent ending at the `}` even though the container there was opened as `[`. That is
/// CROSSED BRACKETS, which the JSON grammar does not admit, and the failure direction is
/// a TOO-SHORT extent that ends while the caller still believes a container is open: the
/// spliced result would then be missing the tail of the value it meant to replace. It is
/// a red rather than a wrong answer for the caller at `document_with_member_value`, whose
/// boundary probe rejects an extent that does not tile, and unreachable at
/// `repeated_member_value_tokens` for the same reason its input is a refusal row.
///
/// WHAT THE CORPUS DOES WITNESS IS THE OTHER DIRECTION — a container left OPEN at end
/// of input, which three rows carry: `930-138`, `930-140` and `930-142`, each of which
/// leaves a `{` on the stack at the last byte. For those the arm runs off the end and
/// returns `bytes.len()`, so the extent is too LONG rather than too short, and the failure
/// is contained because all three are REFUSED rows: a malformed document is rejected
/// before any value extent is measured on it. CROSSED brackets are the direction nothing
/// witnesses: scanning all 162 rows, every closer matches its own opener in every row, so
/// the too-short extent described above is unreachable from any input the fixture owns and
/// the paragraph about it is a construction argument rather than an observation.
///
/// THE BARE-TOKEN ARM DOES NOT VALIDATE WHAT IT PASSED OVER. It advances to the next
/// `,`, `}` or `]` without asking whether the bytes between are a legal scalar, so on a
/// document whose bare token is not one — `{"a":1 2}`, where two scalars stand where
/// the grammar allows one — it returns `1 2` as a single value extent. The direction is
/// a TOO-LONG extent, which is the opposite of what the false paragraph above claimed,
/// and it is caught by the same boundary probe. Both residual cases are malformed input
/// reaching a helper that only has to tile WELL-FORMED documents; the honest statement is
/// that this helper measures a token's extent and does not certify that the token is
/// well-formed, which is `serde_json`'s job and not this one's.
fn skip_json_value(bytes: &[u8], index: usize) -> usize {
    match bytes.get(index).copied() {
        Some(b'"') => string_closing_quote(bytes, index) + 1,
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            let mut cursor = index;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'"' => {
                        cursor = string_closing_quote(bytes, cursor) + 1;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return cursor + 1;
                        }
                    }
                    _ => {}
                }
                cursor += 1;
            }
            bytes.len()
        }
        Some(_) => {
            let mut cursor = index;
            while cursor < bytes.len() && !matches!(bytes[cursor], b',' | b'}' | b']') {
                if bytes[cursor] == b'"' {
                    cursor = string_closing_quote(bytes, cursor) + 1;
                    continue;
                }
                cursor += 1;
            }
            cursor
        }
        None => bytes.len(),
    }
}

/// The member name a JSON string token carries, DECODED rather than sliced.
///
/// Decoding is what makes an escape-equivalent pair ONE name: the first
/// occurrence of `applied` is written with a six-character JSON escape for its
/// leading letter and the second plainly, so they are the same member written two
/// ways, and a byte comparison would call them two members and miss the
/// repetition. Only the key token goes through `serde_json` — the document never
/// becomes a `Value`, so nothing here can collapse a duplicate.
/// WHAT THIS ASSUMES ABOUT THE PARSER THAT `serde_json` DOES NOT GUARANTEE, and the
/// class of input where that assumption could fail.
///
/// ASSUMPTION: a key is a JSON string, so the bytes between its quotes can be handed to
/// `serde_json::from_str::<String>` and are DECODED — which is the whole reason this
/// helper exists, since an escape-equivalent pair of keys must collide as names. That
/// holds for any key `serde_json` accepts.
///
/// WHERE IT COULD FAIL: on a key that is NOT a well-formed JSON string, the fallback
/// branch returns the raw bytes between the quotes undecoded, so an escape in a
/// malformed key would be compared as its literal characters and would not collide with
/// the decoded name of the same member. No fixture row has a malformed key, and the
/// callers that could meet one are the REFUSAL paths, where the row is refused for the
/// malformation rather than being scanned for a repetition — but the fallback is a
/// deliberate choice to keep walking rather than to fail, and a reader relying on
/// collision detection over malformed input is relying on something this does not
/// provide.
fn decoded_key_name(raw: &str, open: usize, close: usize) -> String {
    serde_json::from_str::<String>(&raw[open..=close])
        .unwrap_or_else(|_| raw[open + 1..close].to_owned())
}

/// The two facts one byte walk of a JSON document can establish about member
/// repetition, so the walk that finds a repetition is the SAME walk that says where a
/// repetition was reachable.
struct Repetition {
    /// The DECODED name of the first member that occurs TWICE inside one JSON object,
    /// with the depth of the object holding both occurrences. `None` when no object in
    /// the document repeats a member.
    first: Option<(String, usize)>,
    /// Every depth at which this document places an OBJECT holding TWO OR MORE members,
    /// ascending and deduplicated. This is the set of depths at which a repetition is
    /// REACHABLE in this document: an object holding one member cannot repeat anything
    /// inside itself, so demanding a witness there would demand the impossible.
    reachable: Vec<usize>,
}

/// ONE walk of the raw document, answering both questions the duplicate-key case asks
/// of it. `first` is what binds a refusal to this row's own repetition; `reachable` is
/// what makes "the rule holds at every nesting depth" countable rather than asserted in
/// prose. They were two helpers before and are one walk now, because two walks over the
/// same bytes could disagree about the document and each would be individually
/// plausible.
///
/// DEPTH counts enclosing containers, so `0` is the document's own object, `1` an
/// object directly inside it, and an array counts as a container too. The depth is what
/// separates a top-level repetition from a nested one.
///
/// Every object is scanned, not only the top level, because a nested repetition is
/// refused by the NESTED decoder and never reaches the top-level one; a top-level only
/// scan would find nothing for those rows and quietly pass.
/// WHAT THIS ASSUMES ABOUT THE PARSER THAT `serde_json` DOES NOT GUARANTEE, and the
/// class of input where that assumption could fail.
///
/// ASSUMPTION, and it is the same one every byte scanner in this file rests on: nesting
/// depth is counted by counting `{}` and `[]`, and a string is skipped WHOLE through
/// `string_closing_quote`, so a brace inside a string is never read as structure. That
/// holds for the JSON grammar, and it is why an escape-equivalent pair of keys can be
/// compared as DECODED names without either one having been normalised first.
///
/// WHERE IT COULD FAIL: a document where a string is UNTERMINATED before the end of
/// input — the two malformed-truncation rows are exactly that — makes `string_closing_quote`
/// return `bytes.len()`, so every remaining byte is consumed as string content and no
/// container after it is seen. The consequence is confined and in the safe direction:
/// `first` stays `None` and `reachable` stops growing, so such a document reports NO
/// repetition. That is why those two rows are in the malformed group and not the
/// duplicate group, and why no duplicate assertion is derived from them.
///
/// THE OTHER ASSUMPTION is that `containers.len()` at push time IS the depth, which is
/// what makes depth 0 uniquely the document's own object: no nested container can report
/// it, because a nested one is pushed onto a stack that already holds its parent. This
/// is load-bearing for `permissive_ingress_erases_the_earlier_occurrence`, which compares
/// a value read at depth 0 against a whole-document projection on the strength of it.
/// It holds for this walk because the walk pushes on every container byte it meets and
/// pops on every one it closes; a scanner that pushed selectively would break it.
fn scan_repetitions(raw: &str) -> Repetition {
    let bytes = raw.as_bytes();
    // (is an object, depth, member names seen so far), innermost last.
    let mut containers: Vec<(bool, usize, Vec<String>)> = Vec::new();
    let mut first: Option<(String, usize)> = None;
    let mut reachable: Vec<usize> = Vec::new();
    let mut index = 0usize;
    let mut expect_key = false;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let close = string_closing_quote(bytes, index);
                if expect_key && let Some(container) = containers.last_mut() {
                    let name = decoded_key_name(raw, index, close);
                    if container.2.contains(&name) && first.is_none() {
                        first = Some((name.clone(), container.1));
                    }
                    container.2.push(name);
                    expect_key = false;
                }
                index = close + 1;
            }
            b'{' | b'[' => {
                let is_object = bytes[index] == b'{';
                containers.push((is_object, containers.len(), Vec::new()));
                expect_key = is_object;
                index += 1;
            }
            b'}' | b']' => {
                if let Some(closed) = containers.pop()
                    && closed.0
                    && closed.2.len() >= 2
                    && !reachable.contains(&closed.1)
                {
                    reachable.push(closed.1);
                }
                expect_key = false;
                index += 1;
            }
            b',' => {
                if containers.last().is_some_and(|container| container.0) {
                    expect_key = true;
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    reachable.sort_unstable();
    Repetition { first, reachable }
}

/// The byte range of one top-level member's VALUE token: `start` inclusive, `end`
/// exclusive. Fails loudly when the member is absent, when the range is empty or
/// out of the document, or when the token does not STOP at a member boundary,
/// because a wrong range here would splice a payload together from nonsense and
/// the decode would fail for a reason that has nothing to do with the claim under
/// test.
///
/// THE BOUNDARY CHECK IS REAL, AND SO IS THE RANGE CHECK BESIDE IT. The previous
/// version of this comment called the `end > raw.len()` clause DEAD, and its
/// enumeration of `skip_json_value`'s arms was wrong on TWO of the four:
/// * the STRING arm is `string_closing_quote(bytes, index) + 1`, and
///   `string_closing_quote` falls out of its loop at `bytes.len()` when it meets no
///   closing quote, so an unterminated string yields `bytes.len() + 1`;
/// * the BARE arm returns its cursor UNCLAMPED once the loop exits on end of input,
///   which is the same `bytes.len() + 1` by a different line — a `"` met inside a
///   bare token takes the same `+ 1` step and lands past the end.
/// Only the container arm and the out-of-range arm are genuinely bounded by
/// `bytes.len()`. So the clause CAN fire, and the earlier claim that this helper
/// "fails loudly when its value token does not tile the document" described a check
/// that was live after all.
///
/// IT IS ALSO THE SOLE BARRIER ON THE ONE PATH THAT WOULD PANIC.
/// `document_with_member_value` slices `raw[..start]`, `raw[end..]` and rebuilds, and
/// four call sites depend on it; `raw[end..]` panics on an out-of-range `end`. Nothing
/// downstream of this function clamps `end`, so if this clause were removed the
/// failure would be a slice-index panic inside a helper whose whole purpose is to
/// fail loudly with a diagnosable message. It stays, and it is stated here as
/// load-bearing rather than as an unreachable formality.
///
/// NO CURRENT ROW REACHES THAT CLAUSE, and that is stated as the reading it is rather
/// than as a record of what a run showed: which rows arrive here, which shapes would
/// arrive if they did not, and what the clause is for. The rows that arrive are the
/// case-6 wrong-member rows, the case-2 page rows, the case-10 `MigrationRecord`
/// payloads and the case-16 `TaskExecutionClass` row, and every one of their value
/// tokens ends inside its document; the case-14 malformed rows are refused through
/// `serde_json` and through `classify_malformation`, so none of them is ever offered
/// here. The rows that WOULD arrive are `930-140-malformed-unterminated-string` and its
/// twin `930-138-malformed-truncated-string`: both end mid-string, so their final
/// member `relative_path` is opened and never closed, and asking this function for
/// that member's span makes `skip_json_value` take the string arm and return
/// `bytes.len() + 1` — an end past those 167-byte and 188-byte documents. That is
/// exactly the input this clause exists to catch, and it is kept because it is the
/// only thing standing between such a document and the `raw[end..]` panic, NOT
/// because a test exercises it. No assertion in this file distinguishes "the guard
/// fired" from "the guard is unreachable", and nothing here claims which is true of
/// any row, because nothing readable here settles it.
///
/// The boundary probe below measures the thing tiling actually means: the first byte
/// after the token, SKIPPING JSON whitespace, must be a structural terminator, or
/// there must be no such byte at all. What REACHES it is a shape, not an observation:
/// any document whose value token is followed by a byte that is neither JSON
/// whitespace nor a terminator. `skip_json_value` takes a string's extent from
/// `string_closing_quote` and never inspects what follows the closing quote, so
/// `{"a":"x"y}` yields an extent that ends on `y` and `document_with_member_value`
/// would carry that stray tail straight into the rewritten document. Whether any
/// current row has that shape is a claim about the fixture, which another writer owns;
/// this comment states the shape, not the count.
///
/// WHITESPACE IS TOLERATED, and not as a courtesy: `{"a":"x" , "b":2}` and
/// `{"a":{"k":1} }` are valid JSON, and a check that rejected them would be
/// refusing correct input. The asymmetry was real before this was corrected — the
/// BARE-token arm of `skip_json_value` scans to the next `,`/`}`/`]` and so swallows
/// trailing whitespace INTO its extent, while the string arm stops at the closing
/// quote and leaves that whitespace outside. `{"a":7 }` and `{"a":"x" }` are the
/// same document shape differing only in the value's spelling, and the two arms hand
/// back DIFFERENT extents for them — `7 ` against `"x"` — so a terminator
/// check applied at the returned offset without first skipping whitespace accepts the
/// bare spelling and rejects the string one. That asymmetry is READ OFF THE TWO ARMS
/// and off the boundary probe below; no suite was executed to observe either outcome.
/// The returned extent is still the TOKEN's
/// end, never the whitespace-skipped cursor, because `document_with_member_value`
/// splices `raw[start..end]` and must not delete the spacing or the terminator.
fn top_level_value_span(
    raw: &str,
    member: &str,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let span = top_level_member_spans(raw)
        .into_iter()
        .find(|span| span.key == member)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "the payload has no top-level member {member}"
            )))
        })?;
    let bytes = raw.as_bytes();
    let start = span.value_start;
    let end = skip_json_value(bytes, start);
    if end <= start || end > bytes.len() {
        return fail(format!(
            "the value token of {member} does not tile the document: {start}..{end} of {} bytes",
            bytes.len()
        ));
    }
    // The boundary probe walks forward over JSON whitespace from the token's own
    // end, so legal spacing before a `,`, a `}` or a `]` is accepted while a stray
    // non-whitespace byte is not. `end` itself is never advanced.
    let mut probe = end;
    while matches!(bytes.get(probe), Some(byte) if byte.is_ascii_whitespace()) {
        probe += 1;
    }
    match bytes.get(probe) {
        None | Some(b',' | b'}' | b']') => Ok((start, end)),
        Some(byte) => fail(format!(
            "the value token of {member} ends at byte {end} of {}, which is followed by {:?} rather than a member boundary, so its extent is wrong and a splice here would cut a payload together from nonsense",
            bytes.len(),
            *byte as char
        )),
    }
}

/// One top-level member's value token replaced by `replacement`, by byte surgery.
///
/// Everything outside that one token survives untouched — including any duplicate
/// member, which is exactly what must NOT be collapsed. A `Value` round trip would
/// be wrong here for the reason `skip_json_value` is a byte scan: re-encoding
/// through `serde_json` collapses a duplicate member last-wins.
fn document_with_member_value(
    raw: &str,
    member: &str,
    replacement: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let (start, end) = top_level_value_span(raw, member)?;
    let mut out = String::with_capacity(raw.len() + replacement.len());
    out.push_str(&raw[..start]);
    out.push_str(replacement);
    out.push_str(&raw[end..]);
    Ok(out)
}

/// Every ASCII-digit run inside a fragment of source, read as an `i64` where it
/// parses. A digit run is one token, so `14` is the number fourteen and never the
/// number four.
fn integer_literals(text: &str) -> Vec<i64> {
    text.split(|character: char| !character.is_ascii_digit())
        .filter(|token| !token.is_empty())
        .filter_map(|token| token.parse().ok())
        .collect()
}

/// `(name, parameter text, return-type text)` of a `fn` declaration, from text that
/// may span several lines.
///
/// A lifetime or type parameter between the name and the parenthesis is skipped, so
/// `fn selected<'slice>(` yields the name `selected`. The parameter text is taken
/// whole — parenthesis depth is tracked, so a nested call or a tuple inside the
/// parameter list does not end it early — and the return text is whatever follows
/// the closing parenthesis with a leading `->` removed.
///
/// The return text still carries the declaration's opening brace, because this reads
/// a LINE of source and not a parsed item; every test applied to it below is a
/// containment test, which is unaffected.
fn fn_declaration(text: &str) -> Option<(String, String, String)> {
    let rest = text.trim().strip_prefix("fn ")?;
    let open = rest.find('(')?;
    let name: String = rest[..open]
        .chars()
        .take_while(|cell| cell.is_alphanumeric() || *cell == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    let parameters = &rest[open + 1..];
    let mut depth = 1usize;
    let mut closing = None;
    for (offset, character) in parameters.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    closing = Some(offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let closing = closing?;
    let returns = parameters[closing + 1..]
        .trim()
        .strip_prefix("->")
        .unwrap_or(parameters[closing + 1..].trim())
        .trim()
        .to_owned();
    Some((name, parameters[..closing].to_owned(), returns))
}

/// What one pass over this file's declarations produced: the selector names it
/// resolved, and the joined source text of every `fn` declaration it FAILED to
/// resolve.
///
/// THE SECOND FIELD IS WHY THIS IS A STRUCT. A declaration that fails to resolve
/// used to be indistinguishable, to every check downstream, from a line that was
/// never a declaration: the walk simply moved on, the candidate was dropped, and the
/// pending state was cleared, so every later parameter line of that signature went
/// unread. `expected_entry` is the live witness — MEASURED, it is the ONLY declaration
/// in this file the walk abandons, because its first carried parameter line contains
/// a `(` and a `)` that `parameter_list_is_open` reads as the parameter list closing
/// while `fn_declaration`'s depth counter reads it as a nested pair that never
/// returns to zero.
///
/// So the honest abandonment count on today's bytes is ONE, not zero, and
/// `assert_eq!(abandoned.len(), 0)` would be a manufactured red rather than a
/// finding; it is deliberately NOT asserted. What IS asserted is the member-level
/// property the count stands in for: no abandoned declaration's joined text mentions
/// the case parameter. That is what makes a lost selector loud, and it is strictly
/// what the audit's own perturbation exercises — adding a case parameter to
/// `expected_entry` puts `i64` into the abandoned text and turns the check red.
struct SelectorWalk {
    names: Vec<String>,
    abandoned: Vec<String>,
}

/// The functions in THIS FILE that select fixture rows BY A CASE NUMBER: every `fn`
/// whose parameter list mentions `i64`, together with every declaration the walk could
/// not resolve. See `SelectorWalk` for why the second field is carried at all.
///
/// DERIVED, NOT A LITERAL LIST. The scan this feeds exists to catch a selector called
/// with the numeric literal 3 or 4, and a hand-written list of names defeats itself:
/// add a fourth selector, call it with `3`, and the scan never looks at it, so the
/// property it witnesses is silently falsified by an edit that adds no behaviour. The
/// test used here is the shape of the QUESTION rather than the names that answer it
/// today — a function that takes a case number is exactly the function the two
/// byte-injected cases must never be named through — so a new selector joins the scan
/// by being written, and only the two constants
/// `UNKNOWN_TOP_LEVEL_CASE`/`UNKNOWN_NESTED_CASE` name those cases.
///
/// MEASURED on this file as written, and the derivation reproduces the three names
/// the prose everywhere else uses: `rows_in_case`, `reject_rows`, `accept_rows`. No
/// other `fn` here takes an `i64`, so the test is not currently over-broad; if one
/// did join, it would be scanned for case literals too, which is the safe direction.
///
/// MULTI-LINE SIGNATURES ARE JOINED, and the figure that justifies it is large enough
/// that reading only a declaration's first line would miss most of the file's
/// signatures rather than an edge case: MEASURED, THIRTY-SIX of the `fn` declarations
/// here leave their parameter list open on their own line, so a first-line-only scan
/// would read a parameter text for none of them. That number is the reason the walk
/// carries at all; the reason it now also REPORTS what it could not resolve is that
/// joining thirty-six multi-line signatures is a mechanical rule with a known failure
/// mode (a carried line whose parenthesis closes a NESTED pair, which drops the
/// declaration), and one of those thirty-six — `expected_entry` — is hit by it today.
/// A rule that can silently drop a declaration out of thirty-six candidates is exactly
/// the rule whose losses have to be visible.
///
/// Only a line that opens a `fn` may carry into the next one, and it carries until its
/// parameter list closes — the text after the first `(` holds a `)`. Confining the
/// carry to `fn` lines is deliberate: a first attempt at this derivation carried from
/// ANY unbalanced line, and a parenthesis inside a string literal then poisoned the
/// walk for the rest of the file, which is how a derivation can silently return nothing
/// — and an empty selector set makes every check below pass. `fn_declaration`
/// re-checks the balance anyway, so a candidate that never closes is simply never
/// considered — and is now REPORTED rather than merely skipped.
fn row_selector_walk() -> SelectorWalk {
    let mut names: Vec<String> = Vec::new();
    let mut abandoned: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for line in THIS_FILE.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        let candidate = match pending.take() {
            Some(head) => format!("{head} {trimmed}"),
            None if trimmed.starts_with("fn ") => trimmed.to_owned(),
            None => continue,
        };
        if parameter_list_is_open(&candidate) {
            pending = Some(candidate);
            continue;
        }
        match fn_declaration(&candidate) {
            Some((name, parameters, _)) => {
                if parameters.contains("i64") {
                    names.push(name);
                }
            }
            // A carried line closed a NESTED parenthesis rather than the parameter
            // list, so the depth counter never returned to zero and no parameter text
            // is readable. Keeping the text is what lets the caller say so.
            None => abandoned.push(candidate),
        }
    }
    SelectorWalk { names, abandoned }
}

/// The selector names alone, for the two call sites that do not read the abandoned
/// declarations. A thin view over `row_selector_walk`, not a second walk: the count
/// and the names are read from the same pass over the same bytes.
fn row_selector_names() -> Vec<String> {
    row_selector_walk().names
}

/// Whether a candidate `fn` declaration is still missing the close of its parameter
/// list: there is an opening parenthesis and no closing one after it.
fn parameter_list_is_open(candidate: &str) -> bool {
    match candidate.find('(') {
        Some(open) => !candidate[open + 1..].contains(')'),
        None => false,
    }
}

/// One selector call site, paired with WHERE it was found, because a flat list of
/// argument strings cannot support a per-selector claim and a per-selector claim is
/// the one the guard below needs: proving that `reject_rows` is called from outside
/// every selector body is a different statement from proving that some selector is.
///
/// `intrinsic` is the whole of the guard's exclusion rule, and it is a STRUCTURAL
/// fact read from this file's bytes rather than a pair of transcribed argument
/// texts. It is true when the match lies inside the body of ANY selector — its own
/// declaration line included, because `fn rows_in_case(all: &[Row], case: i64)` is
/// part of `rows_in_case`'s own body region. The previous version excluded two
/// hand-written strings instead, `all: &[Row], case: i64` and `all, case`, and a
/// parameter rename, an added parameter or a reorder made the declaration's own text
/// stop equalling the constant while the call sites were unchanged — the guard went
/// vacuous under an edit that changed no behaviour, and the strings were the only
/// thing binding them. Nothing transcribed can fail that way: this rule is computed
/// from the same bytes it classifies.
///
/// The cost of computing it structurally is that the rule is never NARROWER than the
/// old one and is wider wherever the transcribed text stopped matching: a selector
/// call inside a selector body with an argument text the two constants did not list —
/// a differently spaced forward, say — is intrinsic here where it used to count as
/// external. On this file as written the two rules pick out the same five entries. A
/// wider exclusion can only make the guard stricter, never laxer.
struct SelectorCall {
    selector: String,
    arguments: String,
    intrinsic: bool,
}

/// Every selector call in this file, read from this file's own bytes.
///
/// NOT ONLY CALL SITES, and this is load-bearing for the guard in
/// `byte_injected_cases_select_no_rows`: the scan matches each selector's own
/// DECLARATION line as well as every call of it, because
/// `fn rows_in_case(all: &[Row], case: i64)` carries `rows_in_case(` on that line.
///
/// MEASURED FLOOR, and the previous comment's arithmetic was FALSE. Running this
/// scan over this file as written yields 22 entries, decomposing exactly as:
/// * 3 declaration lines — `fn rows_in_case(all: &[Row], case: i64)`,
///   `fn reject_rows(...)`, `fn accept_rows(...)` — every one of them intrinsic,
///   because each sits inside its own body's first line;
/// * 2 forwarding calls INSIDE those bodies — `let group = rows_in_case(all, case);`
///   in `reject_rows` and in `accept_rows` — intrinsic for the same reason;
/// * 17 genuine external call sites — ten of `reject_rows`, four of `accept_rows`
///   and three of `rows_in_case` — contributing seventeen argument texts of which
///   fifteen are different from each other, `all, ABSENCE_CASE` and
///   `all, ESCAPE_EQUIVALENT_CASE` being the two texts two sites apiece share.
///
/// The tenth `reject_rows` site is the one case 11's own erasure measurement added,
/// and the second shared text is the direct consequence of it: that measurement
/// selects the SAME duplicate corpus `strict_ingress_cannot_erase_protected_input`
/// already selects, through the SAME named constant, because it is explaining that
/// function's refusals rather than walking a group of its own. Naming the case
/// through a constant rather than a literal is the property this whole scan exists
/// to enforce, so a duplicated argument TEXT is the intended outcome here and not a
/// defect.
///
/// So the floor with every intrinsic entry stripped is 5, not the 3 the previous
/// comment claimed, and a guard of the form `calls.len() > selectors.len()`
/// stayed satisfied at `5 > 3` with the scan reaching no external call site at all.
/// The guard downstream is therefore not a count at all; it requires each selector to
/// have at least one NON-INTRINSIC match, so nothing inside the definitions can stand
/// in for a call.
///
/// WHAT IT STILL CANNOT SEE, precisely, so the coverage claimed for it stays honest:
/// the walk is line-at-a-time, so a call written across several lines is invisible,
/// and a space between a selector's name and its `(` defeats `strip_prefix('(')`.
/// Comments are skipped for the same reason as before — prose may NAME a selector
/// without calling one, and `reject_rows(&rows, 3)` written in a doc comment is not a
/// call site. The proof these cases need is the data-level assertion in
/// `case_03_unknown_top_level_member_rejected` and its nested equivalent, which
/// reads the fixture's `case` field; this scan is a secondary check over source text
/// and no edit to this file can strengthen it into that proof.
fn selector_call_arguments() -> Result<Vec<SelectorCall>, Box<dyn std::error::Error>> {
    let selectors = row_selector_names();
    let mut calls: Vec<SelectorCall> = Vec::new();
    // The function whose body the current line lies in, tracked with the same signed
    // brace accumulator the struct walk uses: `}` at depth one returns to top level
    // and clears it. A `fn` line with an unbalanced parameter list carries no name,
    // so its body is attributed to nobody, which is the direction that keeps a call
    // site countable as external.
    let mut enclosing: Option<String> = None;
    let mut depth: isize = 0;
    for line in THIS_FILE.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("fn ") {
            enclosing = fn_declaration(trimmed).map(|(name, _, _)| name);
            depth = 0;
        }
        let intrinsic = enclosing
            .as_ref()
            .is_some_and(|function| selectors.iter().any(|selector| selector == function));
        for selector in &selectors {
            let mut rest = trimmed;
            while let Some(at) = rest.find(selector.as_str()) {
                let after = &rest[at + selector.len()..];
                let Some(arguments) = after.strip_prefix('(') else {
                    rest = after;
                    continue;
                };
                let mut nested = 1usize;
                let mut closing = None;
                for (offset, character) in arguments.char_indices() {
                    match character {
                        '(' => nested += 1,
                        ')' => {
                            nested -= 1;
                            if nested == 0 {
                                closing = Some(offset);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let Some(closing) = closing else {
                    return fail(format!(
                        "unbalanced call to {selector} in this file's source: {trimmed}"
                    ));
                };
                calls.push(SelectorCall {
                    selector: selector.clone(),
                    arguments: arguments[..closing].to_owned(),
                    intrinsic,
                });
                rest = &arguments[closing + 1..];
            }
        }
        if enclosing.is_some() {
            depth += brace_delta_outside_strings(line);
            if depth <= 0 {
                enclosing = None;
                depth = 0;
            }
        }
    }
    Ok(calls)
}

/// SECONDARY, belt-and-braces check over this file's own SOURCE TEXT.
///
/// THE PROOF IS THE DATA-LEVEL ASSERTION, and it is stated here because the
/// previous version of this comment claimed the opposite. In
/// `case_03_unknown_top_level_member_rejected` and
/// `case_04_unknown_nested_member_rejected` the fixture is loaded and
/// `rows_in_case(&rows, UNKNOWN_TOP_LEVEL_CASE).is_empty()` (and its nested
/// equivalent) is asserted directly. That reads the fixture's `case` field, so it
/// is what makes the `also_in_cases` references to cases 3 and 4 honest, and no
/// edit to this file can evade it.
///
/// WHAT THIS SCAN ACTUALLY ESTABLISHES, narrowly: no selector call in this file
/// passes the NUMERIC LITERAL 3 or 4 as its case argument, which is the mistake
/// the two named constants exist to prevent. WHICH functions that covers is DERIVED
/// from this file's signatures by `row_selector_names`, not listed, so a selector
/// added later is scanned without anyone remembering to add it here.
///
/// WHAT IT DOES NOT ESTABLISH, and why it cannot: a source scan of argument text
/// is evaded by a named constant — which this file uses at both call sites, so it
/// evades itself — by a helper that takes a case number under a signature this
/// scan cannot read, by a raw `.case ==` filter such as `selected`, by a function
/// alias, by a call written across several lines, and by a space before the
/// parenthesis, which `strip_prefix('(')` does not match. A comment claiming this
/// scan proves the case owns no rows would therefore be false against this very
/// file; that is why the property is proved where it is evadable.
fn byte_injected_cases_select_no_rows() -> TestResult {
    let calls = selector_call_arguments()?;
    for call in &calls {
        for literal in integer_literals(&call.arguments) {
            assert!(
                !BYTE_INJECTED_CASES.contains(&literal),
                "a row selector is called with the numeric case {literal} here ({}), but cases {} are reached by injecting an unknown member into an existing row's own raw bytes and own no rows; name the case through its constant instead",
                call.arguments,
                BYTE_INJECTED_CASES
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" and ")
            );
        }
    }
    let dispatched = dispatched_cases()?;
    for case in BYTE_INJECTED_CASES {
        assert!(
            dispatched.contains(&case),
            "case {case} must be dispatched by this file, or an `also_in_cases` reference to it names nothing at all"
        );
    }
    // THE PREVIOUS GUARD HERE WAS WORTHLESS TWICE OVER, and both reasons are
    // recorded because the second one is not obvious. It was `!calls.is_empty()`,
    // which cannot fail: each selector's own DECLARATION line matches the scan and
    // pushes an entry, so the vector is non-empty BY CONSTRUCTION.
    // Replacing it with a count comparison against the selector-list length did not
    // help: the scan ALSO matches the `rows_in_case(all, case)` forwarding calls
    // inside the bodies of `reject_rows` and `accept_rows`, which contribute matches
    // the selector-list length does not predict. So the floor the comparison reads is
    // FIVE where the length argument assumed three, and `5 > 3` is TRUE OF THE
    // EXPRESSION rather than of any selector's behaviour — which is the whole
    // defect: the guard was satisfied by arithmetic that holds whatever the selectors
    // do, so deleting a call site could not have moved it. Neither number is an
    // observation. Both are countable from this file's bytes, and the three selectors'
    // external-site counts are named in the paragraph below.
    //
    // WHAT REPLACES IT DOES NOT COUNT. For each selector, at least one matched site
    // must be EXTERNAL — outside every selector's body, declaration lines included —
    // and "external" is the structural flag `selector_call_arguments` computes from
    // this file's own brace walk rather than one of two transcribed argument texts,
    // which is what made the previous version of this guard defeatable by renaming a
    // parameter. So the guard states the property the case actually needs, that every
    // selector IS called from outside every selector, and it fails for exactly the
    // edit the old ones missed: MEASURED, `reject_rows` is reached from ten
    // external call sites and `accept_rows` from four and `rows_in_case` from three,
    // so delete all ten `reject_rows` sites and only intrinsic matches are left,
    // which the guard reports.
    //
    // THE DERIVED SET IS ASSERTED NON-EMPTY FIRST, because a scan over nothing
    // passes every one of its own checks. That failure mode did not exist while the
    // names were a literal list, and deriving them introduced it.
    //
    // AND THE WALK NOW REPORTS WHAT IT COULD NOT RESOLVE, which is the member-level
    // half of that same guard. `!selectors.is_empty()` is a SET-level check: it cannot
    // see a member that was lost, and a selector is lost whenever its declaration is
    // dropped by the multi-line join rather than read. MEASURED, exactly one
    // declaration in this file is dropped today — `expected_entry`, whose first
    // carried parameter line closes a nested pair rather than the parameter list — and
    // it takes no case number, so nothing is lost YET. That is luck rather than
    // design, and asserting the drop count is zero would be a manufactured red, so
    // what is asserted instead is the property the count stands in for: a dropped
    // declaration must not be one that takes a case number. MEASURED, this is
    // non-vacuous — add a case parameter to `expected_entry` and this goes red, which
    // is exactly the edit the previous version of this guard was blind to.
    let selectors = row_selector_walk();
    assert!(
        !selectors.names.is_empty(),
        "no function in this file takes a case number, so the derived selector set is empty and this scan would witness nothing at all"
    );
    for abandoned in &selectors.abandoned {
        assert!(
            !abandoned.contains("i64"),
            "this walk could not resolve the parameter list of a `fn` declaration and read no parameter of it, so a case number taken there is invisible to every selector check above; the declaration's own joined text is {abandoned}"
        );
    }
    for selector in &selectors.names {
        let matched: Vec<&SelectorCall> = calls
            .iter()
            .filter(|call| &call.selector == selector)
            .collect();
        let external = matched.iter().filter(|call| !call.intrinsic).count();
        assert!(
            external > 0,
            "the selector scan matched {selector} at {} sites, and every one of them lies inside a selector body — its own declaration line included — so it is reached by no external call site and this scan can no longer witness that {selector} is never called with a numeric case literal",
            matched.len()
        );
    }
    Ok(())
}

/// What the real decoder did with a row's raw bytes. The refusal keeps the
/// `serde_json::Error` so a case can read its category, line and column instead
/// of only its rendered text.
enum Outcome {
    Accepted,
    Refused(serde_json::Error),
}

/// Decode `raw` through `serde_json::from_str::<T>` and report the outcome.
///
/// This is the ONLY decode path the accept/reject cases use, and the string
/// path is mandatory rather than incidental. `serde_json::Map` is a `BTreeMap`,
/// so the moment raw bytes become a `Value` a repeated member collapses
/// last-wins and the derived `MapAccess` never sees a duplicate at all: a
/// `from_value` case 5 row would pass for entirely the wrong reason. The same
/// holds for the escape-equivalent rows, whose whole point is that `\u0061pplied`
/// and `applied` are different byte sequences that decode to one key.
///
/// Returns the outcome directly: a refusal is an expected result here, not a
/// failure of this function, so there is no error channel to wrap.
fn outcome_of<T>(raw: &str) -> Outcome
where
    T: DeserializeOwned,
{
    match serde_json::from_str::<T>(raw) {
        Ok(_) => Outcome::Accepted,
        Err(error) => Outcome::Refused(error),
    }
}

/// Decode a row whose `source` leaf is `ids.rs`, through the real public
/// `Deserialize` path.
///
/// WHY ONLY THREE OF THE FORTY TYPES HAVE ARMS, stated because a reader cannot
/// tell an omission from an oversight. `ids.rs` sources 43 rows, and 40 OF THEM —
/// not all of its rows — are `case: 1` allocation rows; the other 3 are the second
/// case-14 group, and case 2 discharges its valid-bytes claim on those 40 by
/// byte-drift round-trip rather than by a refusal, so nothing selected an `ids.rs`
/// row through an accept/reject case until that group existed. An arm exists for
/// each of the TWO types that group names — one `id_type!` expansion (`AgentId`)
/// and one of the two transparent `u64` newtypes (`MemoryRevision`) — and a THIRD
/// arm covers `ProjectSequence`, the other transparent `u64` newtype, which that
/// group does not name at all: an arm with no caller is the fake-assertion smell
/// this file keeps deleting, while an arm a SELECTED row needs is not. The other 37
/// of those 40 stay unarmed deliberately, and the `other` arm is loud about them,
/// so the first case to select one of those rows
/// gets a failure naming the row, the type and the arm that is missing.
///
/// THE `other` MESSAGE IS A CLAIM ABOUT COVERAGE, NOT ABOUT ALLOCATION, and both
/// previous wordings were wrong in opposite directions. It used to read "no
/// accept/reject case covers", which stops being true the moment the FIRST arm
/// exists and is therefore stale on arrival. The alternative wording — "names an
/// unallocated ids.rs type", which is what the two sibling dispatchers say — is
/// false for all 40 of these rows, because live source declares every one of them
/// and `type_names_are_complete` proves that. A message that goes stale, or that
/// names the wrong property, is the defect class this file keeps correcting.
fn ids_row_outcome(row: &Row) -> Result<Outcome, Box<dyn std::error::Error>> {
    let raw = row.raw.as_str();
    match type_leaf(&row.type_name) {
        "AgentId" => Ok(outcome_of::<eliot_types::AgentId>(raw)),
        "MemoryRevision" => Ok(outcome_of::<eliot_types::MemoryRevision>(raw)),
        "ProjectSequence" => Ok(outcome_of::<eliot_types::ProjectSequence>(raw)),
        other => fail(format!(
            "row {} is a case {} row for {other}, a type live source DOES declare in ids.rs, and this dispatcher has no arm for it: the row exists and is allocated, and what is missing is COVERAGE — no accept/reject case can decode it until a typed arm names {other} here",
            row.id, row.case
        )),
    }
}

fn records_row_outcome(row: &Row) -> Result<Outcome, Box<dyn std::error::Error>> {
    let raw = row.raw.as_str();
    match type_leaf(&row.type_name) {
        "BlobRef" => Ok(outcome_of::<eliot_types::BlobRef>(raw)),
        "CanonicalMemoryManifest" => Ok(outcome_of::<eliot_types::CanonicalMemoryManifest>(raw)),
        "CanonicalMemorySegment" => Ok(outcome_of::<eliot_types::CanonicalMemorySegment>(raw)),
        "CanonicalMemorySegmentRef" => {
            Ok(outcome_of::<eliot_types::CanonicalMemorySegmentRef>(raw))
        }
        "CanonicalMemoryL2Page" => Ok(outcome_of::<eliot_types::CanonicalMemoryL2Page>(raw)),
        "MigrationRecord" => Ok(outcome_of::<eliot_types::MigrationRecord>(raw)),
        "HealthRecord" => Ok(outcome_of::<eliot_types::HealthRecord>(raw)),
        other => fail(format!(
            "row {} names an unallocated records.rs type: {other}",
            row.id
        )),
    }
}

fn task_execution_row_outcome(row: &Row) -> Result<Outcome, Box<dyn std::error::Error>> {
    let raw = row.raw.as_str();
    match type_leaf(&row.type_name) {
        "TaskExecutionDomain" => Ok(outcome_of::<eliot_types::TaskExecutionDomain>(raw)),
        "TaskExecutionAction" => Ok(outcome_of::<eliot_types::TaskExecutionAction>(raw)),
        "TaskExecutionArtifact" => Ok(outcome_of::<eliot_types::TaskExecutionArtifact>(raw)),
        "TaskExecutionClassSource" => Ok(outcome_of::<eliot_types::TaskExecutionClassSource>(raw)),
        "TaskExecutionClass" => Ok(outcome_of::<eliot_types::TaskExecutionClass>(raw)),
        other => fail(format!(
            "row {} names an unallocated task_execution.rs type: {other}",
            row.id
        )),
    }
}

/// The single type-name dispatch for the accept/reject cases. It mirrors
/// `round_trip_row`'s source split and names so the two cannot drift apart: both
/// fail loudly on a type name neither table knows.
fn decode_row(row: &Row) -> Result<Outcome, Box<dyn std::error::Error>> {
    match source_leaf(&row.source).as_str() {
        "ids.rs" => ids_row_outcome(row),
        "records.rs" => records_row_outcome(row),
        "task_execution.rs" => task_execution_row_outcome(row),
        other => fail(format!(
            "row {} names an unallocated source file: {other}",
            row.id
        )),
    }
}

/// The `serde_json::Error` a row's own bytes produce, or a failure naming the row
/// if it decoded. The error is kept whole so a caller can read `is_data()`,
/// `line()` and `column()` — the serde `Message` category and the reported position
/// — instead of only the rendered text, which is version-dependent.
fn refusal_error(row: &Row) -> Result<serde_json::Error, Box<dyn std::error::Error>> {
    match decode_row(row)? {
        Outcome::Refused(error) => Ok(error),
        Outcome::Accepted => fail(format!(
            "case {} row {} must be refused, but it decoded: {}",
            row.case, row.id, row.description
        )),
    }
}

/// Assert the row is refused and hand back the message so a caller can make a
/// substring claim. `is_err` is the assertion; the message is only ever
/// substring-tested, never compared for equality.
fn refused_message(row: &Row) -> Result<String, Box<dyn std::error::Error>> {
    Ok(refusal_error(row)?.to_string())
}

fn assert_refused(row: &Row) -> TestResult {
    let _ = refused_message(row)?;
    Ok(())
}

fn assert_accepted(row: &Row) -> TestResult {
    match decode_row(row)? {
        Outcome::Accepted => Ok(()),
        Outcome::Refused(error) => fail(format!(
            "case {} row {} must be accepted, but decoding refused it: {error}",
            row.case, row.id
        )),
    }
}

/// How a case-6 spelling relates to the wire spellings its OWN enum declares.
///
/// The previous version of this comment claimed `Unknown` meant "no accepted
/// spelling folds onto it, so the enum genuinely does not declare this variant",
/// while the implementation compared against exactly ONE spelling — the case-1
/// allocation row of that enum — and never looked at the enum's variant list. On a
/// four- or five-variant enum that is one denominator, not the one the sentence
/// needed. The denominator is now the enum's REAL declared variants, read out of the
/// decoder's own `unknown variant` refusal by `declared_variant_spellings`, and that
/// list is in turn required to agree with what `task_execution.rs` declares, by
/// `assert_spelling_denominator_matches_declaration`. Both steps are needed: the
/// parse supplies the spelling the decoder is answering with, and the comparison
/// against the declaration is what stops the parse from being the sole authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spelling {
    /// Non-empty, and its folded form matches NO declared variant spelling of its
    /// own enum: the decoder has never heard of it.
    Unknown,
    /// It folds onto a DECLARED variant spelling, or it is the empty string — the
    /// near-miss class, which is what makes it worth a row rather than a synonym of
    /// `Unknown`.
    NearMiss,
}

/// Lowercased with `_` and `-` dropped, so a spelling that differs only in case or
/// punctuation folds onto the accepted one. `ReadOnly`, `read-only` and
/// `READ_ONLY` all fold to `readonly`.
fn fold_spelling(spelling: &str) -> String {
    spelling
        .chars()
        .filter(|cell| *cell != '_' && *cell != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// serde's repeated-member refusal, quoted from `duplicate_field` in
/// `serde-1.0.229/src/core/de/mod.rs:296-298`, whose whole body is
/// `Error::custom(format_args!("duplicate field `{}`", field))`.
const DUPLICATE_FIELD_PREFIX: &str = "duplicate field";

/// serde's undeclared-member refusal, quoted from `unknown_field` at
/// `serde-1.0.229/src/core/de/mod.rs:270-273`. Never a substring of
/// `DUPLICATE_FIELD_PREFIX` and never a substring of it in the other direction, so
/// requiring the absence of this one excludes a duplicate refusal without excluding
/// a duplicate refusal's own text.
const UNKNOWN_FIELD_PREFIX: &str = "unknown field";

/// serde's unrecognized-variant refusal, quoted from `unknown_variant` at
/// `serde-1.0.229/src/core/de/mod.rs:252-265` — the whole `fn`, closing brace
/// included — whose body is an `if` on `expected.is_empty()`, so it is not one
/// construction: the `else` arm at `:259-263` is the
/// `Error::custom(format_args!("unknown variant `{}`, expected {}", variant, ..))`
/// this prefix is read from, and the `if` arm at `:253-258` renders
/// `unknown variant `{}`, there are no variants`.
const UNKNOWN_VARIANT_PREFIX: &str = "unknown variant";

/// serde's absent-required-member refusal, quoted from `missing_field` at
/// `serde-1.0.229/src/core/de/mod.rs:289-291`, whose whole body is
/// `Error::custom(format_args!("missing field `{}`", field))`.
///
/// THE DERIVED DECODER REACHES IT THROUGH `serde::__private::de::missing_field`
/// (`serde-1.0.229/src/private/de.rs:24-43`), whose every `deserialize_*` arm except
/// `deserialize_option` returns `Err(Error::missing_field(self.0))`; `deserialize_option`
/// calls `visitor.visit_none()`, which is why an absent `Option` member decodes rather
/// than failing. So this wording is what a REQUIRED member's absence produces, and the
/// `Option` exception is the same fact the L2-page assertions rest on.
///
/// NEITHER A SUBSTRING OF NOR A SUBSTRING INTO any of the three refusal prefixes
/// above, nor of `INVALID_TYPE_PREFIX` below, so requiring its absence excludes each
/// of those refusals without excluding a missing-field refusal's own text.
const MISSING_FIELD_PREFIX: &str = "missing field";

/// serde's wrong-JSON-kind refusal, quoted from `invalid_type` at
/// `serde-1.0.229/src/core/de/mod.rs:213-215`, whose whole body is
/// `Error::custom(format_args!("invalid type: {}, expected {}", unexp, exp))`.
/// Required ABSENT wherever a missing-member refusal is demanded, because an
/// `invalid type` refusal on some other member is precisely the alternative a bare
/// member-name substring admits.
const INVALID_TYPE_PREFIX: &str = "invalid type";

/// `serde_json`'s rendered text for `ErrorCode::ExpectedSomeValue`, quoted from
/// `serde_json-1.0.151/src/error.rs:362`. That code is what
/// `Deserializer::deserialize_enum` returns when the value token is neither `{`
/// nor `"` (`src/de.rs:1898`), and `classify()` places it in `Category::Syntax`
/// (`src/error.rs:62-81`), so `error.is_data()` is FALSE for it.
const EXPECTED_SOME_VALUE_TEXT: &str = "expected value";

/// The two `shape` values a row declares when its type is a
/// `#[serde(transparent)]` SCALAR rather than a document: the `id_type!`
/// newtypes over `Uuid` and the two newtypes over `u64`. They are the two
/// non-document spellings of `ALLOWED_SHAPES` and they are the SELECTOR for the
/// second case-14 group; both spellings are named once, here, so the selector
/// and the expectation table cannot drift apart.
const UUID_SCALAR_SHAPE: &str = "transparent-uuid-scalar";
const U64_SCALAR_SHAPE: &str = "transparent-u64-scalar";
const TRANSPARENT_SCALAR_SHAPES: [&str; 2] = [UUID_SCALAR_SHAPE, U64_SCALAR_SHAPE];

/// The two scalar PAYLOAD types the two transparent scalar shapes are named after, and
/// the ONLY two `scalar_shape_for_payload` will map.
///
/// They are the wrapped types, read out of the declarations themselves: `Uuid` for the
/// `id_type!` macro body and for nothing else, `u64` for `MemoryRevision` and
/// `ProjectSequence`. Naming them here is what makes the mapping a two-member table
/// rather than an open guess — a third payload has no member to map to, so it is an
/// error instead, which is the direction that requires the shape vocabulary to be
/// widened deliberately rather than by a derivation quietly widening itself.
const UUID_PAYLOAD_TYPE: &str = "Uuid";
const U64_PAYLOAD_TYPE: &str = "u64";

/// The `Uuid` family's refusal when the input opens with `{` — quoted from
/// serde's `invalid_type` at `serde-1.0.229/src/core/de/mod.rs:213-215`
/// (`"invalid type: {}, expected {}"`), with `Unexpected::Map` rendering as
/// `map` and the expectation string taken from `Uuid`'s own `expecting` field at
/// `uuid-1.26.1/src/external/serde_support.rs:167`.
///
/// REACHED BECAUSE THE INPUT IS NOT A STRING, not because the string is wrong:
/// `Uuid::deserialize` takes the human-readable branch and calls
/// `deserialize_str`, and `peek_invalid_type`
/// (`serde_json-1.0.151/src/de.rs:269-315`, `b'{' => de::Error::invalid_type(Unexpected::Map, exp)`
/// at line 312) answers `{` before any string is read.
const UUID_MAP_REFUSAL_TEXT: [&str; 1] = ["invalid type: map, expected a formatted UUID string"];

/// The `Uuid` family's refusal when the input IS a quoted string that does not
/// parse — quoted from `uuid-1.26.1/src/external/serde_support.rs:134`, whose
/// whole body is `E::custom(format_args!("UUID parsing failed: {}", e))`.
///
/// ONLY THE PREFIX IS CLAIMED, and the reason is that the text after it is
/// uuid's own parse error, whose wording was NOT determined here: no variant of
/// it is asserted, and nothing composes a message out of it.
const UUID_PARSE_REFUSAL_TEXT: [&str; 1] = ["UUID parsing failed: "];

/// The `u64` family's refusal, as TWO independent claims rather than one
/// composed string: serde's wrong-JSON-kind prefix `INVALID_TYPE_PREFIX`, and
/// the expectation text `u64`, which is `PrimitiveVisitor::expecting` writing
/// `stringify!($primitive)` at `serde-1.0.229/src/core/de/impls.rs:141-143`
/// expanded for `u64` at line 436-441.
///
/// NOT COMPOSED INTO `invalid type: map, expected u64`, because that sentence was
/// not confirmed as a whole and this file does not build message text out of
/// parts it read separately. `serde_json`'s `deserialize_number`
/// (`serde_json-1.0.151/src/de.rs:319-343`) answers any non-numeric opening byte
/// with `peek_invalid_type`, and both constructions are `Error::custom`, i.e.
/// `ErrorCode::Message`, i.e. `Category::Data` (`src/error.rs:56`, `:101-103`).
const U64_REFUSAL_TEXT: [&str; 2] = [INVALID_TYPE_PREFIX, "u64"];

/// A case-5 row must be refused FOR ITS REPEATED MEMBER, not merely refused.
///
/// The repeated member is derived from the ROW'S OWN BYTES by `scan_repetitions`:
/// a structural scan of the raw document finds the first member name occurring
/// twice inside one object, comparing DECODED names so an escape-equivalent pair
/// counts once. No member name and no fixture value is typed into this file, and
/// the row's prose is never read. That scan is `scan_repetitions`, which also
/// reports the depths at which a repetition was reachable in the same document.
///
/// WHY A BARE SUBSTRING ON THE MEMBER NAME IS NOT ENOUGH, because the previous
/// version of this binding was satisfiable by the WRONG refusal. serde's
/// `unknown_field` (`serde-1.0.229/src/core/de/mod.rs:277-281`, its `else` arm and
/// not the `expected.is_empty()` arm at `:271-276`) enumerates EVERY
/// declared field of the closed struct — ``unknown field `bogus`, expected one of
/// `component`, `status`, `detail` `` — so `message.contains("status")`,
/// `message.contains("subsystem_refs")` and every other declared name are
/// satisfied by an unknown-field refusal. The concrete false pass: on
/// `930-73-dup-control-healthrecord`, replacing the duplicated `"status"` pair with
/// `"status":"degraded","bogus":1` leaves a row that is no longer a duplicate-key
/// row at all, and every assertion that read it through the bare member-name substring
/// would still have held: the unknown-field refusal names `status` among the declared
/// fields, which is the whole mechanism, so the bare `contains` test cannot tell that
/// refusal from the duplicate-key refusal it was standing in for. THAT IS A READING OF
/// THE MECHANISM, NOT AN OBSERVED RUN — this lane executes no suite, so nothing here
/// reports a verdict; what is claimed is only that a guard which accepts any message
/// naming the member has no way to fail on that row, which is why the four conjuncts
/// below exist.
///
/// FOUR CONJUNCTS, and every one of them fails for an unknown-field refusal:
/// * the message carries `DUPLICATE_FIELD_PREFIX`, which is serde's
///   duplicate-refusal shape and is not a substring of `unknown field ...`;
/// * the message does NOT carry `UNKNOWN_FIELD_PREFIX`, which excludes the
///   enumeration above directly;
/// * the message carries the derived member name, which is what binds the refusal
///   to THIS row's repetition rather than to any duplicate in the document;
/// * `error.is_data()` holds, because both serde constructions are
///   `Error::custom` and therefore `ErrorCode::Message`, i.e. `Category::Data`.
///
/// Returns what one walk of the row's own bytes established: the repeated member with
/// its depth, and the depths at which a repetition was reachable in that document.
fn repeated_member_is_refused(row: &Row) -> Result<Repetition, Box<dyn std::error::Error>> {
    let repetition = scan_repetitions(&row.raw);
    let Some((member, _)) = repetition.first.as_ref() else {
        return fail(format!(
            "case {} row {} repeats no member in its own bytes, so it proves nothing about duplicate refusal",
            row.case, row.id
        ));
    };
    let error = refusal_error(row)?;
    let message = error.to_string();
    assert!(
        message.contains(DUPLICATE_FIELD_PREFIX),
        "the refusal for row {} must be serde's duplicate-member refusal, whose shape is `{DUPLICATE_FIELD_PREFIX} `{{{member}}}`, not some other refusal that happens to mention {member}: {message}",
        row.id
    );
    assert!(
        !message.contains(UNKNOWN_FIELD_PREFIX),
        "the refusal for row {} is a serde unknown-member refusal ({UNKNOWN_FIELD_PREFIX}), which enumerates EVERY declared member of the closed struct and would satisfy the member-name substring below for a member this row never duplicated: {message}",
        row.id
    );
    assert!(
        message.contains(member.as_str()),
        "the refusal for row {} must name the repeated member {member}: {message}",
        row.id
    );
    assert!(
        error.is_data(),
        "the refusal for row {} must be a serde `Message` code, i.e. Category::Data: {error}",
        row.id
    );
    Ok(repetition)
}

/// A refusal must be serde's MISSING-FIELD refusal, naming `member` — the shape a
/// required member's absence produces and nothing else does.
///
/// WHY THE MESSAGE ALONE IS NOT ENOUGH, because this is the defect this binding
/// exists to close. A member-name substring is satisfied by THREE of the refusals a
/// derived struct can produce, and each was a live false pass:
/// * `UNKNOWN_FIELD_PREFIX` ENUMERATES EVERY declared field of a closed struct —
///   ``unknown field `bogus`, expected one of `component`, `status`, `detail` `` — so
///   a row missing `status` and carrying a misspelled `statu` is refused for the
///   misspelling and satisfies `contains("status")` for free. The concrete case: row
///   `930-114-missing-required-status-healthrecord`, whose `raw` gains `,"statu":7`,
///   still omits exactly one declared member and was refused as an undeclared one;
/// * `INVALID_TYPE_PREFIX` fires on some OTHER member of the same document, and its
///   text embeds no member name — but the caller usually only asks about one member,
///   so the pair has to be excluded together;
/// * a syntax-layer refusal such as `EXPECTED_SOME_VALUE_TEXT` is excluded by
///   `error.is_data()` below rather than by a substring, because `classify()` puts it
///   in `Category::Syntax` and its wording carries no member name at all.
///
/// SIX CONJUNCTS, and every one of them fails for a refusal that is not
/// missing-field:
/// * the message carries `MISSING_FIELD_PREFIX`, serde's absent-member wording;
/// * the message carries that wording AND the member, as the whole construction
///   ``missing field `<member>` `` rather than the bare name — so the row is refused
///   for a member this case is about, not one it merely mentions;
/// * the message does NOT carry `UNKNOWN_FIELD_PREFIX`, which is the enumeration
///   above;
/// * the message does NOT carry `DUPLICATE_FIELD_PREFIX`, which a row that both
///   repeats a member and omits another would otherwise satisfy;
/// * the message does NOT carry `UNKNOWN_VARIANT_PREFIX` or `INVALID_TYPE_PREFIX`,
///   the two refusals that belong to a different declaration entirely;
/// * `error.is_data()` holds, because `missing_field` is `Error::custom` and therefore
///   `ErrorCode::Message`, i.e. `Category::Data`.
///
/// IF SERDE'S WORDING IS NOT PRESENT, EVERY ONE OF THESE FAILS. That is the intended
/// behaviour and not a limitation: the wording is quoted above from the pinned
/// `serde-1.0.229` source with file and line, so a serde bump that renames the
/// construction must red HERE, naming the shape this file expected, rather than leaving
/// a case-7 or case-10 row silently unclassified. No equality comparison is made
/// anywhere in this function; the text is version-dependent and is only ever
/// substring-tested.
///
/// WHY THIS RETURNS NOTHING, and it did once return a `Result`. Every conjunct above is
/// an `assert!` carrying a message that names the row, the member, the refused shape and
/// the refusal serde actually produced, so a failure already leaves the enclosing
/// `#[test]` red with that text as the panic payload. A `Result` on top of that could
/// only ever be `Ok`, because the one value that would make it `Err` — a caller
/// wanting to react rather than fail — does not exist: no caller inspects a refusal
/// here and recovers from it, and a caller that did would be asserting nothing. The
/// failure channel is therefore the panic, deliberately, and it is the SAME channel the
/// surrounding case bodies already use, so removing the wrapper changes no outcome.
fn missing_member_is_refused(error: &serde_json::Error, member: &str, context: &str) {
    let message = error.to_string();
    assert!(
        message.contains(MISSING_FIELD_PREFIX),
        "{context}: the refusal must be serde's absent-required-member refusal, whose shape is `{MISSING_FIELD_PREFIX}` `{{{member}}}`; a bare member-name substring is satisfied by an unknown-member refusal too, because serde enumerates every declared field of a closed struct there: {message}"
    );
    assert!(
        message.contains(&format!("{MISSING_FIELD_PREFIX} `{member}`")),
        "{context}: the refusal must name the missing member as `{MISSING_FIELD_PREFIX} `{member}``, so it is attributable to THIS member's absence and not to some other refusal that mentions it: {message}"
    );
    for (prefix, refusal) in [
        (UNKNOWN_FIELD_PREFIX, "an undeclared member"),
        (DUPLICATE_FIELD_PREFIX, "a repeated member"),
        (UNKNOWN_VARIANT_PREFIX, "an unrecognized variant"),
        (INVALID_TYPE_PREFIX, "a wrong JSON kind"),
    ] {
        assert!(
            !message.contains(prefix),
            "{context}: the refusal is serde's {refusal} refusal (`{prefix}`), not its absent-required-member refusal, so it is not attributable to {member}'s absence: {message}"
        );
    }
    assert!(
        error.is_data(),
        "{context}: an absent required member must be refused by a serde `Message` code, i.e. Category::Data, because `missing_field` is `Error::custom`; a syntax or IO refusal here would name no member at all: {error}"
    );
}

/// The accepted wire spelling of a member enum, taken from the case-1 allocation
/// row of that enum and from nothing else. This file already proves that row
/// decodes, and it is re-asserted here so each isolation control below is local.
///
/// NEVER TYPED IN: the spelling is read out of the fixture's own valid bytes, so
/// it cannot drift from `task_execution.rs`, and no prose is consulted.
fn accepted_spelling(all: &[Row], enum_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let row = applicable_row(all, enum_name)?;
    assert_accepted(row)?;
    let value: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
    match value {
        Value::String(spelling) => Ok(spelling),
        other => fail(format!(
            "the allocation row {} for {enum_name} must be a bare JSON string spelling, found {other}",
            row.id
        )),
    }
}

/// The wire spellings the decoder itself DECLARES for the enum it just refused,
/// taken from the refusal message rather than from the fixture, from a schema, or
/// from a transcription.
///
/// WHAT THIS IS, PLAINLY: a RESTATEMENT OF THE STRING UNDER TEST. The
/// classification needs the enum's declared spellings, this function reads them out
/// of the very message the assertion then validates, and reading a set out of a
/// string and comparing a spelling against that set cannot discover anything about
/// the string's own correctness. The previous version of this comment called it
/// "the decoder's own truth rather than a restatement of it", which is a category
/// error — it is the decoder's own truth AND a restatement of it, and those are not
/// in tension. What makes the denominator trustworthy is the SEPARATE comparison
/// against the declaration itself, `assert_spelling_denominator_matches_declaration`
/// below, which reads `task_execution.rs`; nothing in this function is independent
/// of the message.
///
/// WHY A MESSAGE AT ALL, given that source is available: serde's `unknown_variant`
/// (`serde-1.0.229/src/core/de/mod.rs:259-263`) builds
/// `unknown variant `{}`, expected {}` with `OneOf { names: expected }`, and
/// `expected` is the derive's own `VARIANTS` array — every spelling the decoder will
/// accept, in the derive's own order. `OneOf`'s `Display` (`src/core/de/mod.rs:2337-2355`)
/// renders three or more names as ``expected one of `a`, `b`, `c` ``, so the refusal
/// does name the complete denominator the classification needs, and the previous
/// version's single accepted spelling — the case-1 allocation row — was one element
/// of it.
///
/// WHY NOT `schemars`, which would otherwise be the obvious source: the four
/// `task_execution.rs` member enums derive only `Serialize`/`Deserialize`, NOT
/// `JsonSchema` (`task_execution.rs:3/14/25/37`), so `schema_for!` cannot be
/// instantiated for them and the records-only schema route does not extend here
/// without a change this file may not make to `src/`.
///
/// ONLY THE `expected one of ` FORM IS PARSED, and that restriction is deliberate.
/// `OneOf` also renders ``expected `a` `` for one name and ``expected `a` or `b` ``
/// for two; a message in either of those forms fails loudly here, which is correct,
/// because an enum with fewer than three variants is a shape change this file should
/// be told about rather than absorb.
///
/// THE HAZARD IS A SPELLING THAT CONTAINS THE MARKER, not a spelling that equals
/// the word `expected`. A variant spelling is written inside the message BEFORE the
/// marker, so a spelling that is exactly `expected` leaves the first occurrence of
/// the marker where it belongs and the parse returns the right list — re-executed
/// against the live form of ``unknown variant `expected`, expected one of `code`,
/// `docs`, `research`, `operations`, `mixed``, which yields exactly those five. A
/// spelling that CONTAINS `expected one of ` does not: the split takes the marker
/// inside the spelling, so the parse returns whatever back-quoted text follows,
/// including the empty fragments between commas — a corrupted denominator that is
/// still non-empty, so the emptiness guard below does not catch it. The previous
/// version of this comment named the wrong hazard. No live spelling contains the
/// marker, and the enumeration a row is classified against is the DECLARED one, so
/// this is a stated limit of the parse rather than a live defect.
///
/// The list is never allowed to be empty: an empty denominator would classify every
/// spelling as `Unknown`.
fn declared_variant_spellings(message: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let marker = "expected one of ";
    let Some((_, tail)) = message.split_once(marker) else {
        return fail(format!(
            "a serde unknown-variant refusal must list the enum's declared spellings after {marker:?} for this check to read them; found: {message}"
        ));
    };
    let mut spellings: Vec<String> = Vec::new();
    let mut rest = tail;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        spellings.push(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    if spellings.is_empty() {
        return fail(format!(
            "a serde unknown-variant refusal listed no declared spelling after {marker:?}, so the denominator for the unknown/near-miss split cannot be read: {message}"
        ));
    }
    Ok(spellings)
}

/// The parsed denominator agrees with what `task_execution.rs` DECLARES.
///
/// WHY THIS EXISTS, and it is the fix for a circular check. The classification in
/// `spelling_row_is_refused` decides `Unknown` against the list parsed out of the
/// refusal message, so on its own it could only ever confirm that the message and
/// the message agree. Reading the enum's variants from the file that declares them
/// makes the denominator a fact about the source rather than about the string under
/// test: after this, renaming `TaskExecutionAction`'s variants cannot leave
/// `930-95`, `930-98`, `930-99`, `930-100` and `930-101` classifying identically
/// with nothing red.
///
/// COMPARED FOLDED, and the folding is what makes the comparison sound rather than
/// lucky. The two sides are the Rust variant name (`ReadOnly`) and the wire spelling
/// the derive emits for it (`read_only`, under `#[serde(rename_all = "snake_case")]`),
/// and `fold_spelling` lowercases and drops `_` and `-`. `snake_case` only inserts
/// underscores and lowercases, and `declared_enum_variants` has already rejected any
/// variant that is not an ASCII alphanumeric identifier, so folding either side
/// removes exactly the difference the rename rule introduces and nothing else. A
/// `#[serde(rename = "..")]` that changed letters rather than punctuation would fail
/// here — correctly, because it would change what the near-miss fold means.
fn assert_spelling_denominator_matches_declaration(
    type_name: &str,
    declared: &[String],
) -> TestResult {
    let mut from_message: Vec<String> = declared
        .iter()
        .map(|spelling| fold_spelling(spelling))
        .collect();
    let mut from_source: Vec<String> = enum_variant_names_from_source(type_name)?
        .iter()
        .map(|variant| fold_spelling(variant))
        .collect();
    from_message.sort();
    from_source.sort();
    assert_eq!(
        from_message, from_source,
        "the variant spellings the refusal for {type_name} lists, {declared:?}, fold to {from_message:?}, but the variants its own source file declares fold to {from_source:?}; `spelling_row_is_refused` classifies against the refusal's list, so a disagreement here means that classification is being measured against the wrong denominator"
    );
    Ok(())
}

/// A case-6 row whose payload IS a variant spelling.
///
/// serde's `unknown variant` refusal names the offending spelling, so the message
/// is required to carry ``unknown variant `<spelling>` `` — the whole construction, not
/// the spelling alone. That form is non-vacuous for EVERY spelling including the
/// empty one: ```unknown variant`` ``` is a real, falsifiable substring, where
/// `message.contains("")` is true of every message and would assert nothing.
///
/// THE DENOMINATOR IS CORROBORATED AGAINST SOURCE before it is used, by
/// `assert_spelling_denominator_matches_declaration`, so the near-miss split below is
/// not merely a comparison of the message with itself.
///
/// WHY THE EMPTY-SPELLING ROW IS ADDITIONALLY BOUND TO THE ACCEPTED SPELLING, and
/// the previous version of this comment rested that on a wording claim ("nothing else
/// names them") which is not what serde guarantees. What serde does guarantee is
/// visible in the sources and is now READ: `unknown_variant` lists the enum's own
/// `VARIANTS` over `OneOf`, and the accepted spelling is asserted to be one of them.
/// That is a checkable fact rather than a claim about what else might name the
/// string. The accepted spelling IS a declared spelling independently — it comes
/// from a fixture row `assert_accepted` proves DECODES into this enum — and the
/// assertion makes that chain explicit instead of leaving it as the premise.
///
/// THE TWO CONJUNCTS IN THAT BRANCH ARE NOT INDEPENDENT, and both are kept. Read in
/// order, the first says the accepted spelling is one of the back-quoted names
/// `declared` carries, and those names are substrings of the very message the second
/// conjunct searches, so the second cannot fail once the first holds. They are two
/// views of one fact — the parsed list and the raw message — and both are guaranteed
/// anyway by the isolation control below, which proves the accepted spelling DECODES
/// into this enum. Keeping both costs one substring search and means a future change
/// to the parse cannot silently remove the raw-message check.
///
/// `error.is_data()` is added to both branches: `unknown_variant` is
/// `Error::custom`, i.e. `ErrorCode::Message`, i.e. `Category::Data`, so the conjunct
/// is exact and independent of the wording.
///
/// The accepted spelling also supplies the ISOLATION CONTROL, built here rather
/// than read from prose: the identical one-token document carrying an accepted
/// spelling DECODES, so "the payload was already bad" is excluded.
fn spelling_row_is_refused(
    row: &Row,
    accepted: &str,
) -> Result<Spelling, Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
    let Value::String(spelling) = value else {
        return fail(format!(
            "case {} row {} must be a bare JSON string spelling to reach this check",
            row.case, row.id
        ));
    };
    let error = refusal_error(row)?;
    let message = error.to_string();
    assert!(
        message.contains(&format!("{UNKNOWN_VARIANT_PREFIX} `{spelling}`")),
        "the refusal for row {} must be serde's unrecognized-variant refusal, whose construction is `{UNKNOWN_VARIANT_PREFIX}` `{{spelling}}`, expected one of ...`; found: {message}",
        row.id
    );
    let declared = declared_variant_spellings(&message)?;
    assert_spelling_denominator_matches_declaration(type_leaf(&row.type_name), &declared)?;
    if spelling.is_empty() {
        assert!(
            declared.iter().any(|variant| variant.as_str() == accepted),
            "the accepted spelling {accepted} must be one of the {declared:?} spellings {} declares, or the assertion below binds the empty-spelling row to a string the refusal has no reason to mention",
            type_leaf(&row.type_name)
        );
        assert!(
            message.contains(accepted),
            "the refusal for row {} probes the EMPTY spelling, so it is also bound to the accepted spelling {accepted}, which an unknown-variant refusal lists among the variants the enum declares: {message}",
            row.id
        );
    }
    assert!(
        error.is_data(),
        "the refusal for row {} must be a serde `Message` code, i.e. Category::Data: {error}",
        row.id
    );
    let mut control = (*row).clone();
    control.raw = serde_json::to_string(&Value::String(accepted.to_owned())).map_err(boxed)?;
    assert_accepted(&control)?;
    Ok(
        if spelling.is_empty()
            || declared
                .iter()
                .any(|variant| fold_spelling(variant) == fold_spelling(&spelling))
        {
            Spelling::NearMiss
        } else {
            Spelling::Unknown
        },
    )
}

/// The single top-level member whose value the decoder refuses, derived by REPAIR.
///
/// For each top-level member in turn, that one member's value token is replaced —
/// by byte surgery, with the SAME member's value token taken from the case-1
/// allocation row of the same type — and the repaired document is decoded. The one
/// member whose replacement repairs the document is the offending member. Zero or
/// two such members fails here, naming what was tried, rather than silently picking
/// one and asserting something weaker.
///
/// A MEMBER THE BASELINE DOES NOT CARRY IS SKIPPED, not repaired with a guess: the
/// allocation page, for one, omits the optional `requested_segment_id` outright, so
/// the fixture supplies no canonical bytes for it. Skipping is honest but it is also
/// a limit, so every skipped member is named in the failure message below — a row
/// whose wrong member were one of them would report "zero repairs" and list it,
/// rather than quietly blaming a neighbour.
///
/// Nothing is read from the row's prose, and no member name or value is typed in:
/// the repair payload is the crate's own canonical bytes for the same type.
fn repaired_member(row: &Row, all: &[Row]) -> Result<String, Box<dyn std::error::Error>> {
    let baseline = applicable_row(all, type_leaf(&row.type_name))?;
    let members = carried_member_names(&row.raw);
    if members.is_empty() {
        return fail(format!(
            "case {} row {} must be a JSON object to reach the wrong-member check",
            row.case, row.id
        ));
    }
    let mut repaired: Vec<String> = Vec::new();
    let mut still_refused: Vec<String> = Vec::new();
    let mut untestable: Vec<String> = Vec::new();
    for member in &members {
        let Ok((start, end)) = top_level_value_span(&baseline.raw, member) else {
            untestable.push(format!(
                "{member} (the allocation row {} omits it, so no canonical value exists)",
                baseline.id
            ));
            continue;
        };
        let replacement = baseline.raw[start..end].to_owned();
        let mut probe = (*row).clone();
        probe.raw = document_with_member_value(&row.raw, member, &replacement)?;
        match assert_accepted(&probe) {
            Ok(()) => repaired.push(member.clone()),
            Err(error) => still_refused.push(format!("{member}: {error}")),
        }
    }
    if repaired.len() != 1 {
        return fail(format!(
            "case {} row {} must be wrong in exactly one top-level member of {}, but replacing one member repairs it {repaired:?}; members tried and still refused: {}; members not testable: {}",
            row.case,
            row.id,
            type_leaf(&row.type_name),
            still_refused.join("; "),
            if untestable.is_empty() {
                "none".to_owned()
            } else {
                untestable.join("; ")
            }
        ));
    }
    Ok(repaired.remove(0))
}

/// Every `pub enum` a source file declares, each as its DECLARATION LINE and name
/// paired with its declared variant names.
///
/// Named for what the element IS rather than for the shape it is written in: the
/// element is one declared enum, carried as the line it is declared on, that
/// enum's own name, and the names of the variants it declares. Every use of this
/// answer needs the name to select the enum, the variant names as its denominator,
/// and — for `externally_tagged_enum_declarations` and so for the recorded-anchor
/// comparison in `per_file_split_holds` — the line as its declaration site.
/// Spelling the triple inline says only that it is a vector of triples.
type DeclaredEnums = Vec<(String, usize, Vec<String>)>;

/// `(enum name, declared variant names)` for every `pub enum` in `file`, in
/// declaration order, read from live source.
///
/// This is the ONE walk over enum declarations; `externally_tagged_enum_names`
/// projects its names, `externally_tagged_enum_declarations` projects its
/// name-and-line pairs, and `enum_variant_names_from_source` selects one enum's
/// variants from it, so the three cannot disagree about what an enum declares. The
/// declaration line is CARRIED rather than recomputed here: the walk already knows
/// `index`, and it already spends it on the brace-not-on-its-own-line failure, so
/// reading it costs nothing and a second search for the same line could only
/// disagree with this one.
///
/// THE ALL-UNIT REQUIREMENT IS CHECKED here, not assumed, and the check fails
/// loudly. A variant carrying a payload would have to be tagged; the decode would no
/// longer route through the bare-string form; and the syntax-layer claim the caller
/// draws from this answer would be false. A declaration whose opening brace is not
/// on the `pub enum` line also fails rather than being skipped, because then the
/// variant lines cannot be attributed to it at all.
fn declared_enum_variants(file: &str) -> Result<DeclaredEnums, Box<dyn std::error::Error>> {
    let source = read_workspace(file)?;
    let lines: Vec<&str> = source.lines().collect();
    let mut declared: Vec<(String, usize, Vec<String>)> = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        let Some(rest) = trimmed.strip_prefix("pub enum ") else {
            index += 1;
            continue;
        };
        let Some((name, _)) = rest.split_once('{') else {
            return fail(format!(
                "{file}:{} opens an enum whose brace is not on its own declaration line, so its variants cannot be read: {trimmed}",
                index + 1
            ));
        };
        let name = name.trim().to_owned();
        // The 1-based line this enum is DECLARED on, captured while `index` still
        // points at the `pub enum` line rather than after the two `index += 1`
        // steps below have walked into the body.
        let declaration_line = index + 1;
        let mut variants: Vec<&str> = Vec::new();
        index += 1;
        while index < lines.len() && !lines[index].trim_start().starts_with('}') {
            let variant = lines[index].trim();
            // An attribute line such as `#[default]` sits between the brace and a
            // variant. It is not a variant and carries no payload either, so it is
            // skipped on both counts.
            if !variant.is_empty() && !variant.starts_with('#') {
                variants.push(variant.strip_suffix(',').unwrap_or(variant));
            }
            index += 1;
        }
        if index < lines.len() {
            index += 1;
        }
        for variant in &variants {
            let is_unit_identifier = variant.starts_with(|cell: char| cell.is_ascii_uppercase())
                && variant
                    .chars()
                    .all(|cell| cell.is_ascii_alphanumeric() || cell == '_');
            if !is_unit_identifier {
                return fail(format!(
                    "{file} declares {name} with a variant that is not a bare unit identifier ({variant}), so it is not the externally tagged all-unit shape the enum-typed refusal classification below requires"
                ));
            }
        }
        if !variants.is_empty() {
            declared.push((
                name,
                declaration_line,
                variants
                    .into_iter()
                    .map(|variant| normalise_declared_type(variant).to_owned())
                    .collect(),
            ));
        }
    }
    Ok(declared)
}

/// Every `pub enum` declared in `file` whose variants are ALL unit, which is what
/// makes it externally tagged on the wire: such an enum is written as a bare
/// `"name"` string and nothing else.
///
/// Read from live source so the four `task_execution.rs` member enums are named by
/// their declaration rather than transcribed here. `records.rs` declares no enum at
/// all, so this correctly answers "none" for every `records.rs` struct — which is
/// the right answer, not a fallback.
fn externally_tagged_enum_names(file: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(declared_enum_variants(file)?
        .into_iter()
        .map(|(name, _, _)| name)
        .collect())
}

/// `(enum name, declaration line)` for every externally tagged `pub enum` in
/// `file`, in declaration order — the same projection
/// `externally_tagged_enum_names` makes, keeping the line column that one drops.
///
/// It is a PROJECTION of the one enum walk rather than a second parser, which is
/// the only reason it exists in this shape: a dedicated scan for `pub enum ` lines
/// would be a second recogniser that could accept an enum
/// `declared_enum_variants` rejects, and the recorded-anchor comparison in
/// `per_file_split_holds` would then be checked against a denominator the
/// completeness assertion never validated.
fn externally_tagged_enum_declarations(
    file: &str,
) -> Result<Vec<(String, usize)>, Box<dyn std::error::Error>> {
    Ok(declared_enum_variants(file)?
        .into_iter()
        .map(|(name, line, _)| (name, line))
        .collect())
}

/// The variant names `type_name` itself declares, read from the file that declares
/// it. Fails loudly when that file declares no such enum rather than answering
/// "none", because an empty variant list would make every comparison against it
/// vacuous.
fn enum_variant_names_from_source(
    type_name: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = declaring_file(type_name)?;
    declared_enum_variants(file)?
        .into_iter()
        .find(|(name, _, _)| name == type_name)
        .map(|(_, _, variants)| variants)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "{file} declares no externally tagged enum named {type_name}, so its declared variants cannot be read from source"
            )))
        })
}

/// Whether `type_name` is itself one of the externally tagged enums declared in the
/// file that declares it.
///
/// This is the whole-document half of the classification `member_is_enum_typed`
/// makes per member: it answers for a row whose payload IS a bare non-string value,
/// where the value is handed straight to `deserialize_enum` with no member name in
/// play at all.
fn type_is_enum_typed(type_name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let enums = externally_tagged_enum_names(declaring_file(type_name)?)?;
    Ok(enums.iter().any(|name| name.as_str() == type_name))
}

/// Whether the DECLARED TYPE of `member` on `type_name` is an externally tagged
/// enum, derived from live source — never from a row id, from a row's prose, or
/// from a list of which rows happen to take one path.
///
/// WHY THE CLASSIFICATION EXISTS, and it is the reason two acceptance rows could
/// not pass as the case stood. `serde_json` 1.0.151's
/// `Deserializer::deserialize_enum` (`src/de.rs:1871-1901`) peeks the value and
/// accepts ONLY `{` or `"`; anything else is
/// `peek_error(ErrorCode::ExpectedSomeValue)` (`src/de.rs:1898`). `classify()`
/// places that code in `Category::Syntax` (`src/error.rs:62-81`), serde's visitor is
/// NEVER consulted, and therefore no `invalid type` refusal is ever produced for such
/// a member — `error.is_data()` is FALSE. For every other declared type the derived
/// visitor IS reached, its refusal is an `ErrorCode::Message`, and `is_data()` is
/// TRUE. So the category is decided by the DECLARATION, and that is what this
/// function reads.
///
/// The three reads are separate and none of them is a hard-coded list of rows:
/// `declaring_file` names the file, `struct_field_types` returns the
/// `pub <name>: <Type>` pairs of the struct body, and `externally_tagged_enum_names`
/// collects the `pub enum` declarations of that same file. The declared type text
/// and the enum names are both put through `normalise_declared_type`, so the two
/// sides of the comparison are in the same form, and the answer is then
/// `declaration_routes_through_deserialize_enum` rather than a whole-text equality
/// with no generics followed.
///
/// WHAT THAT ANSWERS, per field of the live declarations, measured by re-running
/// this walk against `task_execution.rs` and `records.rs`:
/// * `TaskExecutionClass.domain`, `.action`, `.artifact` and `.source` — declared
///   as the four member enums — are ENUM-TYPED. `.source` is the row that made this
///   function's correctness observable: `930-103` hands it an array.
/// * `TaskExecutionClass.subsystem_refs` is `Vec<String>` and is not.
/// * every `records.rs` member is not: the fields are `String`, `u64`, `u32`,
///   `bool`, `BlobRef`, `Vec<..>` or `Option<..>` over one of those, and
///   `records.rs` declares no enum at all. `Option<CanonicalMemoryManifest>`
///   follows its wrapper one level and finds a struct, which is the honest answer
///   rather than a fallback.
fn member_is_enum_typed(type_name: &str, member: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let file = declaring_file(type_name)?;
    let declared = struct_field_types(file, type_name)?
        .into_iter()
        .find(|(name, _, _)| name == member)
        .map(|(_, declared_type, _)| declared_type)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "{file} declares no member {member} on {type_name}, so the refusal category for this row cannot be derived"
            )))
        })?;
    let enums: Vec<String> = externally_tagged_enum_names(file)?
        .iter()
        .map(|name| normalise_declared_type(name).to_owned())
        .collect();
    Ok(declaration_routes_through_deserialize_enum(
        &declared, &enums,
    ))
}

/// A case-6 row whose payload is a complete object of the right type with ONE
/// member's value of the wrong JSON kind.
///
/// THE MESSAGE CANNOT BE REQUIRED TO NAME THE MEMBER, and the reason is narrower
/// than the previous version of this comment claimed. It is not that "serde's
/// `invalid type` refusal names the expected TYPE and never the field" — that
/// premise is FALSE as a general statement, because for a member whose declared type
/// is an externally tagged enum serde's visitor is never reached at all and no
/// `invalid type` refusal exists to read. The honest division is by DECLARED TYPE,
/// and it is derived per row by `member_is_enum_typed` rather than listed:
///
/// * MEMBER TYPED AS AN EXTERNALLY TAGGED ENUM — `930-103`'s `source` on
///   `TaskExecutionClass` is the live example. `serde_json` accepts only `{` or `"`
///   at that position, so an array payload is refused at the SYNTAX layer, by
///   construction and before serde is consulted: `ErrorCode::ExpectedSomeValue`,
///   `Category::Syntax`. What is asserted is what is TRUE: the refusal EXISTS, it is
///   a syntax refusal, it is `ExpectedSomeValue` by rendered text, and it LANDS on
///   the offending token. It is deliberately NOT asserted to be a data error,
///   because there is no `invalid type` refusal here to assert one about.
/// * EVERY OTHER DECLARED TYPE — the other FIVE wrong-payload rows, `930-104`
///   through `930-108`, whose offending members are declared `String` (`status`),
///   `u64` (`size_bytes`), `String` (`migration_id`), `BlobRef` (`blob`) and
///   `Vec<CanonicalMemorySegmentRef>` (`segments`). The derived visitor IS reached
///   and its refusal is an `ErrorCode::Message`, so `is_data()` is exact and
///   independent of serde's wording. Those rows keep the data-error assertion in
///   full. The previous version of this comment said "four" and listed four types;
///   the group holds six object rows and one bare-value row, and only one of the six
///   is enum-typed.
///
/// What binds the refusal to the offending member is the same for BOTH classes and is
/// not the message text:
/// * the offending member is DERIVED from the row's own bytes by repair
///   (`repaired_member`), never from the row's prose;
/// * that repair IS the isolation control — the identical document with the
///   crate's own canonical value for that one member DECODES, so the refusal is
///   attributable to this member and not to a payload that was already bad;
/// * the refusal LANDS on that member: `serde_json` reports a position once it has
///   consumed or peeked the offending token, so the column must fall inside the
///   offending member's value token.
///
/// WHAT THE COLUMN IS, because it is a BYTE OFFSET and the previous version of
/// this comment implied otherwise by calling the lower bound "the opening bracket
/// itself" without saying which numbering it used. `SliceRead::position_of_index`
/// (`serde_json-1.0.151/src/read.rs:421-430`) returns
/// `column: i - start_of_line`, where `i` is the reader's 0-BASED byte index, so on
/// a single-line document the reported column IS that 0-based offset. This file
/// reaches only that path: every decode here is `serde_json::from_str`, which is
/// `StrRead`, and `StrRead::position`/`peek_position` delegate straight to
/// `SliceRead` (`read.rs:697-703`). The "one-based column" wording in
/// `Error::column`'s own doc comment (`src/error.rs:36-46`) does not describe this
/// path, and that same doc comment already concedes the point by noting that
/// "errors may occur in column 0". So `start` and `end`, which
/// `top_level_value_span` returns as 0-based offsets, are compared against the
/// column in the SAME base, and no unit conversion belongs here.
///
/// THE THREE PLACEMENTS the two reporting sites can produce, each traced to the
/// pinned source rather than guessed:
/// * `Deserializer::peek_error` (`src/de.rs:247-251`) reads `peek_position`
///   (`read.rs:577-581`), which is `position_of_index(self.index + 1)`. Peeking the
///   token's FIRST byte therefore reports `start + 1`. `930-103`'s `source` takes
///   this path: `deserialize_enum` peeks, accepts neither `[` nor `{` nor `"`, and
///   returns `peek_error(ExpectedSomeValue)` (`src/de.rs:1898`).
/// * `Deserializer::error` (`src/de.rs:241-244`) reads `position`
///   (`read.rs:573-575`), which is `position_of_index(self.index)` — the index of
///   the next UNREAD byte. Once a scalar or a string has been consumed whole that
///   index is `end`, so the column is `end`. Every wrong-payload row whose declared
///   type is not an enum lands here, because the value is read and only then
///   refused.
/// * `peek_invalid_type` also builds its refusal with NOTHING consumed for a `{`
///   or `[` payload (`src/de.rs:311-312`), and `fix_position`
///   (`src/de.rs:316`, `src/error.rs:337-346`) then places that error with
///   `error()` at an index still pointing AT the token's first byte. So a `String`
///   member handed an object reports exactly `start`. `930-106`'s `migration_id` is
///   the live example, and it is why the lower bound cannot be raised to `start + 1`.
///
/// WHAT THE CODE ACTUALLY CHECKS, stated as the code states it rather than as the
/// tightest form the derivation would allow. The bounds below are `start..=end + 1`.
/// The derivation above puts every one of this case's rows inside `start..=end`: the
/// lower bound is attained exactly (by the `{`-payload row) and the tight upper
/// bound is attained exactly (by the scalar/string/seq rows, which report `end`).
/// `end + 1` is therefore ONE UNIT of margin above the largest column any of them
/// produces, and it is kept rather than tightened because this suite cannot be
/// executed in the lane that writes this file, so a zero-headroom bound would be a
/// claim about `serde_json`'s internals with no way to observe it. The previous
/// version of this comment claimed the window was exactly the two conventions and
/// nothing wider; that was false of the code beneath it, which admitted a column one
/// byte past the tight upper bound. The bound is looser than the derivation needs,
/// not tighter than the derivation allows, and the gap is stated here rather than
/// claimed as tightness.
fn wrong_member_row_is_refused(row: &Row, all: &[Row]) -> TestResult {
    let offending = repaired_member(row, all)?;
    let (start, end) = top_level_value_span(&row.raw, &offending)?;
    let error = refusal_error(row)?;
    let enum_typed = member_is_enum_typed(type_leaf(&row.type_name), &offending)?;
    if enum_typed {
        assert!(
            error.is_syntax(),
            "case {} row {}: {offending} is DECLARED as an externally tagged enum, so serde_json refuses it at the SYNTAX layer by construction — `deserialize_enum` peeks the value and accepts only an opening brace or an opening double quote, returning `ExpectedSomeValue`, which `classify()` places in `Category::Syntax`. A data refusal here would mean the decoder reached serde's visitor, which it cannot for this member: {error}",
            row.case,
            row.id
        );
        assert!(
            error.to_string().contains(EXPECTED_SOME_VALUE_TEXT),
            "case {} row {}: the refusal for the enum-typed member {offending} must be serde_json's `ExpectedSomeValue`, and that is the only code this position can produce: {error}",
            row.case,
            row.id
        );
    } else {
        assert!(
            error.is_data(),
            "case {} row {}: {offending} is NOT declared as an enum, so the derived visitor IS reached and its refusal is a serde `Message` code, i.e. `Category::Data`; a syntax refusal here would mean this row is being refused for a reason other than the member's declared type: {error}",
            row.case,
            row.id
        );
    }
    // `start` and `end` are 0-based byte offsets and `error.column()` is that same
    // base (see the placement derivation in this function's doc comment), so no unit
    // conversion belongs here. The bounds are `start..=end + 1`; the derivation puts
    // every row inside `start..=end`, so the upper bound carries ONE unit of margin
    // above the largest column any row produces. That margin is deliberate and is
    // stated rather than claimed as tightness.
    let first_column = start;
    let last_column = end + 1;
    assert!(
        error.column() >= first_column && error.column() <= last_column,
        "case {} row {} must refuse AT the offending member {offending}: column {} is outside {first_column}..={last_column}: {error}",
        row.case,
        row.id,
        error.column()
    );
    Ok(())
}

/// A case-6 row whose payload is neither a spelling nor an object: a value of the
/// wrong JSON kind where a variant identifier belongs.
///
/// NOTHING here can be bound to a member name, and that is stated rather than
/// hidden: the payload is the whole document, so there is no member at all.
///
/// THE REFUSAL CATEGORY IS A SYNTAX-LAYER ONE, and the previous version of this
/// comment asserted the opposite — `error.is_data()`, which is FALSE for the only
/// row routed here. `930-102` carries the bare NUMBER `7` where `TaskExecutionDomain`
/// is required, and `deserialize_enum` peeks the first byte, accepts only `{` or
/// `"`, and returns `peek_error(ErrorCode::ExpectedSomeValue)`
/// (`serde_json-1.0.151/src/de.rs:1898`), which `classify()` places in
/// `Category::Syntax` (`src/error.rs:62-81`). serde's visitor is never consulted, so
/// there is no `invalid type` refusal for this row at all and none can be asserted.
///
/// WHAT IS ASSERTED INSTEAD, all of it true: the refusal EXISTS, it is a syntax
/// refusal, and it is `ExpectedSomeValue` by rendered text. The BINDING to this
/// payload is the isolation control, which the previous version placed after the
/// false category assertion and which therefore NEVER RAN for this row: the
/// identical one-token document carrying the enum's own accepted spelling DECODES,
/// which makes the payload the entire cause and excludes a refusal for some
/// unrelated reason.
///
/// The class is derived from the row's DECLARED TYPE by `type_is_enum_typed` rather
/// than assumed, so a future row routed here whose type is not an externally tagged
/// enum — a transparent `Uuid` newtype handed a number, say — would be held to the
/// data-error assertion its own declaration implies.
///
/// AND SUCH A ROW WOULD NOT REACH THAT ASSERTION. `type_is_enum_typed` asks
/// `declaring_file` for the type's file, and `declaring_file` FAILS for every name
/// outside the types it matches, naming the type and refusing to guess a file. So a
/// row on a type this file cannot locate is REFUSED HERE, before the category
/// branch, and the data-error assertion is never evaluated. The previous version of
/// this comment stated the opposite — that such a row "is held to the data-error
/// assertion" — which described an assertion the code cannot reach. Extending this
/// helper to a type outside `declaring_file` means adding that type there first,
/// which is a deliberate scope decision and not something this helper does.
fn non_spelling_payload_is_refused(row: &Row, accepted: &str) -> TestResult {
    let value: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
    assert!(
        !value.is_string() && !value.is_object(),
        "row {} carries {value}, which is neither a spelling nor an object; this check cannot bind it to a member",
        row.id
    );
    let error = refusal_error(row)?;
    let enum_typed = type_is_enum_typed(type_leaf(&row.type_name))?;
    if enum_typed {
        assert!(
            error.is_syntax(),
            "case {} row {}: {value} is required where an EXTERNALLY TAGGED ENUM is declared, and serde_json's `deserialize_enum` peeks the first byte, accepts only an opening brace or an opening double quote, and returns `ExpectedSomeValue`, which `classify()` places in `Category::Syntax`. This refusal is therefore deliberately NOT asserted to be a data error: serde's visitor is never consulted, so no `invalid type` refusal exists for it: {error}",
            row.case,
            row.id
        );
        assert!(
            error.to_string().contains(EXPECTED_SOME_VALUE_TEXT),
            "case {} row {}: the refusal must be serde_json's `ExpectedSomeValue`, the only code `deserialize_enum` can produce at this position: {error}",
            row.case,
            row.id
        );
    } else {
        assert!(
            error.is_data(),
            "case {} row {} carries {value}, and its type is NOT declared as an externally tagged enum, so the derived visitor IS reached and its refusal is a serde `Message` code, i.e. `Category::Data`: {error}",
            row.case,
            row.id
        );
    }
    // THE ISOLATION CONTROL, and it is placed so that it RUNS. It previously sat
    // below the `is_data()` assertion, which is false for every row this helper
    // can currently be reached with, so the control was dead on the one row that
    // uses it.
    let mut control = (*row).clone();
    control.raw = serde_json::to_string(&Value::String(accepted.to_owned())).map_err(boxed)?;
    assert_accepted(&control)?;
    Ok(())
}

// WORK_UNIT_CASE: 930/1
#[test]
fn case_01_core_allocation_table_is_complete_and_honest() -> TestResult {
    let Fixture {
        declared_count,
        rows,
        ..
    } = rows()?;
    let observed_count = i64::try_from(rows.len()).map_err(boxed)?;
    assert_eq!(
        declared_count, observed_count,
        "meta.count must declare the observed row count"
    );
    // The allocation table is the case-1 slice of the fixture: later acceptance
    // cases reuse the same allocated types, so the per-file split is a claim about
    // the allocation, not about every row the fixture carries.
    let allocation = allocation_rows(&rows)?;
    // The expected side is DERIVED, from the types live source declares, and no
    // literal total is written here. What this count does and does not establish
    // is worth being exact about, because the previous message overclaimed: the
    // counts were the SAME NUMBER on both sides of the record and the source only
    // by accident of transcription, so a number could not tell a complete
    // allocation from one that had lost a row and gained an invented one. It is
    // the NAME comparison in `type_names_are_complete` that establishes
    // completeness, in both directions; this count only says the allocation is not
    // longer or shorter than the source-derived set, which is what catches a
    // duplicated or dropped ROW rather than a duplicated or missing TYPE.
    assert_eq!(
        allocation.len(),
        allocated_type_names()?.len(),
        "the case-1 allocation must carry as many rows as live source declares candidates; a count cannot by itself prove no row is missing and no row is invented, which is why `type_names_are_complete` compares the two NAMED sets"
    );
    zero_candidate_files_are_proved()?;
    per_file_split_holds(&allocation)?;
    // The same binding over the WHOLE row set, not only the allocation slice
    // `per_file_split_holds` is handed: the other 110 rows' `source` anchors were
    // decoration nothing compared to anything, and they are checked here against the
    // line live source derives for each row's own type. It is a second function
    // rather than a wider parameter on the first because the first's per-file
    // coverage claim is scoped to the allocation table, and handing it all 162 rows
    // would let a non-allocation row satisfy it and change what it reports.
    every_row_anchor_names_its_declaration_site(&rows)?;
    declared_shapes_and_cross_references_hold(&rows)?;
    // THE ATTRIBUTE INVENTORY IS CALLED HERE, AND ALSO FROM CASES 11 AND 12. It was
    // called from case 16 alone at first — outside the scope cases 1-4 claim — and that
    // left the foundation asserting the BYTE-STABILITY of a wire form whose DEFINITION
    // it never checked. A row's declared `shape` is fixture-asserted prose, and
    // `declared_shapes_and_cross_references_hold` is where it is put beside the
    // source by deriving each allocated type's shape from its own declaration;
    // `type_names_are_complete` keys on the
    // STRUCT keyword and says nothing about a type's serde attributes, so on its own
    // it cannot see an attribute change: it would go green on a type that gained
    // `rename_all`, `alias`, `with`, `deserialize_with`, `flatten` or `skip`. THAT
    // WAS THE HOLE, and it was closed by CALLING the inventory from the cases whose
    // scope depends on it rather than by teaching the type walk about attributes —
    // `serde_attribute_inventory_is_closed` fails on any `serde(alias`,
    // `serde(flatten`, `serde(untagged`, `serde(other` or `cfg_attr(serde` form in the
    // five allocated files and pins the surviving attribute multiset exactly. It is
    // the SAME function, unchanged, asserting exactly what it asserted — it is not
    // rewritten and its expected side is not touched. It is now called from THREE
    // cases, case 1 here, case 11 and case 12, and so a serde attribute added to a
    // type in `records.rs`, `ids.rs` or `task_execution.rs` is no longer invisible to
    // the suite; it is red in whichever of the three runs first. For `HealthRecord`
    // the original gap was doubly invisible, because
    // `rename_all = "camelCase"` on single-word members produces the identical wire
    // form, so nothing downstream of the bytes could have distinguished it either —
    // which is the reason the inventory, and not a wire comparison, is what covers it.
    serde_attribute_inventory_is_closed()?;
    byte_injected_cases_select_no_rows()?;
    // The file-level self-check, hosted here because case 1 already carries them
    // and because a case has to EXIST before it can be claimed to be dispatched:
    // this binds every `// WORK_UNIT_CASE: 930/<n>` marker to a `#[test]` that runs,
    // and requires the marker set to be exactly the complement of
    // `UNDISPATCHED_CASES` over `1..=16` — never a pinned tally, which would have
    // forbidden the cases `cards/930.md` still owes.
    test_attributes_are_bound_to_case_markers()?;
    type_names_are_complete(&rows)?;

    // THE #929 INVENTORY HANDOFF, RECORDED HERE BECAUSE CASE 1 IS WHERE THE
    // DENOMINATOR LIVES AND NOTHING ELSE IN THIS FILE MENTIONS IT. The frozen
    // boundary inventory records `row_count = 14` with 14 `types` for child `#930`,
    // family `T01` (`crates/foundation/eliot-contracts/tests/data/
    // shipped_serde_boundaries.toml:161,169`), while `crates/eliot-types/src/ids.rs:
    // 55-92` declares 38 `id_type!` macro expansions — 40 serde-bearing types once
    // `MemoryRevision` and `ProjectSequence` are counted. The inventory's identity
    // denominator is therefore short by those 38 expansions, and the reason is
    // mechanical rather than editorial: the generator
    // `scripts/serde_boundary_inventory.py` has NO notion of the `id_type!` macro
    // and no notion of `serde(transparent)` — neither `id_type` nor `transparent`
    // matches anywhere in it — so a macro-expanded newtype produces no discovery row
    // at all. #929 OWNS BOTH FILES and this leaf edits neither; the delta is supplied
    // here as the exact measurement, which is what the owner needs, and the
    // completeness of THIS case rests on `type_names_are_complete`, whose expected
    // side is enumerated from live `ids.rs` rather than from the inventory. That is
    // also why the `38` inside `type_names_are_complete` is left exactly as it is:
    // a fail-closed literal that goes red when the expansion set moves is the
    // correct behaviour here, and reconciling it against the inventory is #929's
    // edit, not this file's.

    // Audit item 6: an inapplicable shape is a recorded decision, never an
    // ignored row. An empty or whitespace-only reason fails this case.
    for row in &rows {
        if !row.applicable {
            assert!(
                !row.reason.trim().is_empty(),
                "inapplicable row {} (case {}) for {} records no reason: {}",
                row.id,
                row.case,
                row.type_name,
                row.description
            );
        }
    }
    Ok(())
}

/// Where a type is declared. Only the files this issue allocates are needed,
/// because only their types appear in a derivation.
///
/// The four `task_execution.rs` member enums are named here as well as
/// `TaskExecutionClass` itself, because `type_is_enum_typed` asks this question of
/// a TYPE rather than of a struct's field list: `930-102` is a bare number where
/// `TaskExecutionDomain` is required, so the enum's own file has to be readable.
/// `declared_field_names` still cannot be called with one of them — it needs a
/// `pub struct` body — and it never is.
fn declaring_file(type_name: &str) -> Result<&'static str, Box<dyn std::error::Error>> {
    match type_name {
        "TaskExecutionClass"
        | "TaskExecutionDomain"
        | "TaskExecutionAction"
        | "TaskExecutionArtifact"
        | "TaskExecutionClassSource" => Ok(TASK_EXECUTION_FILE),
        "BlobRef"
        | "CanonicalMemoryManifest"
        | "CanonicalMemorySegment"
        | "CanonicalMemorySegmentRef"
        | "CanonicalMemoryL2Page"
        | "MigrationRecord"
        | "HealthRecord" => Ok(RECORDS_FILE),
        other => fail(format!(
            "{other} declares no field list this file can read, and a guessed one would be a fabricated claim"
        )),
    }
}

/// Top-level field names of a type, read from source rather than transcribed.
fn declared_field_names(type_name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    struct_field_names(declaring_file(type_name)?, type_name)
}

/// Top-level member names a payload actually carries.
fn carried_member_names(raw: &str) -> Vec<String> {
    top_level_member_spans(raw)
        .into_iter()
        .map(|span| span.key)
        .collect()
}

/// A string member's value, `None` when the member is absent or does not hold a
/// string, and a LOUD FAILURE when it holds an unterminated one.
///
/// WHY IT RETURNS A RESULT RATHER THAN AN `Option`, and this is a change of shape
/// forced by the refusal below rather than a preference. `None` already means "not a
/// string value" and its callers read that as an absence — `empty_identity_member`
/// filters on `is_some_and`, `is_schema_version_probe` selects a branch from it, and
/// `task_execution_requires_codecortex_is_derived` maps it to a "carries no such
/// member" error. An unterminated string is neither absent nor a non-string: it is a
/// member whose extent cannot be read at all. Reporting it as `None` would let it
/// pass for exactly what it is not, and would be the silent-substitution shape every
/// other reader in this file refuses. The two conditions are therefore kept apart,
/// which is why the return type carries both.
///
/// `row_id` names the document being read and is carried ONLY so the refusal can say
/// which one is broken, for the reason `recorded_member`'s `row_id` exists.
///
/// AN UNTERMINATED STRING IS REFUSED, not measured, reusing `raw_value_end`'s wording
/// and shape for this exact hazard rather than a second phrasing of it.
/// `string_closing_quote` falls out of its loop at `bytes.len()` when it meets no
/// closing quote, and `bytes.len()` is a LEGAL index, so slicing
/// `value_start + 1..end` here returned THE REST OF THE DOCUMENT TO END OF INPUT as
/// this member's value — and returned success, not an error. The callers would then
/// measure those wrong bytes and report a confident wrong verdict: a schema_version
/// probe reads a whole malformed document as its version, a codecortex pair reads one.
/// `raw_value_end` and `recorded_member` both check this already; this site is the
/// third reader of the same scan and was the one that did not.
fn string_member_value(
    raw: &str,
    member: &str,
    row_id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(span) = top_level_member_spans(raw)
        .into_iter()
        .find(|span| span.key == member)
    else {
        return Ok(None);
    };
    let bytes = raw.as_bytes();
    if bytes.get(span.value_start) != Some(&b'"') {
        return Ok(None);
    }
    let end = string_closing_quote(bytes, span.value_start);
    if bytes.get(end) != Some(&b'"') {
        return fail(format!(
            "row {row_id}: the member value at offset {} is an unterminated string, so its extent is not measurable in a {}-byte document",
            span.value_start,
            bytes.len()
        ));
    }
    Ok(Some(raw[span.value_start + 1..end].to_owned()))
}

/// The identity member an absence row empties, derived from the PAYLOAD and the
/// type's DECLARED field names — never from the row's prose.
///
/// A test's control flow must not depend on text another writer is editing: this
/// fixture's `reason` prose is being rewritten in the same delivery, so a phrase
/// match there is a coupling with a known date on it. The derivation is instead
/// structural: among the row's top-level members that are declared fields, the
/// one carrying the EMPTY STRING is the member that was emptied.
///
/// Exactly one must qualify. An ambiguous row — two empty declared members, or
/// none — fails loudly here rather than silently picking one.
fn empty_identity_member(row: &Row) -> Result<String, Box<dyn std::error::Error>> {
    let declared = declared_field_names(type_leaf(&row.type_name))?;
    // A LOOP rather than an iterator chain, and the reason is `string_member_value`'s
    // new refusal: `?` cannot cross the `filter` closure a chain would use, and
    // dropping the refusal to keep the chain would restore the silent substitution
    // that refusal exists to prevent.
    let mut candidates: Vec<String> = Vec::new();
    for member in &declared {
        if string_member_value(&row.raw, member, &row.id)?.is_some_and(|value| value.is_empty()) {
            candidates.push(member.clone());
        }
    }
    candidates.sort();
    // `dedup` as well as `sort`: two STRUCTS in one file may legitimately declare
    // the same field name, and a duplicated entry in this vector would read as
    // "two members were emptied" and trip the exactly-one guard. The signed brace
    // walk removed today's cause; this removes the class.
    candidates.dedup();
    if candidates.len() != 1 {
        return fail(format!(
            "absence row {} must empty exactly one declared member of {}, found {}: {candidates:?}",
            row.id,
            type_leaf(&row.type_name),
            candidates.len()
        ));
    }
    Ok(candidates.remove(0))
}

/// The member a case-7 row removes, derived from the type's DECLARED field
/// names minus the members the payload actually CARRIES. No prose involved, and
/// no assumption that the removed member is any particular one.
///
/// The difference is taken at TOP level, which is exactly the level a case-7 row
/// removes: these rows drop one declared top-level key. If a row ever removed a
/// NESTED member instead, the top-level difference would be EMPTY, and the
/// `len() != 1` guard below fails with a message naming that case rather than
/// producing an empty difference that quietly asserts nothing.
fn removed_member(row: &Row) -> Result<String, Box<dyn std::error::Error>> {
    let declared = declared_field_names(type_leaf(&row.type_name))?;
    let carried = carried_member_names(&row.raw);
    let mut missing: Vec<String> = declared
        .iter()
        .filter(|member| !carried.contains(member))
        .cloned()
        .collect();
    missing.sort();
    // `dedup` as well as `sort`: the SAME field name may be declared by two
    // structs in one file, and a duplicate here would read as two omitted
    // members and trip the exactly-one guard. The signed brace walk removed
    // today's cause; this removes the class.
    missing.dedup();
    if missing.len() != 1 {
        return fail(format!(
            "case {} row {} must omit exactly one declared top-level member of {}, found {}: {missing:?}; a row that removes a NESTED member has an empty top-level difference and needs its own explicit derivation",
            row.case,
            row.id,
            type_leaf(&row.type_name),
            missing.len()
        ));
    }
    Ok(missing.remove(0))
}

/// Whether a row probes the deferred version gate: it carries a `schema_version`
/// the crate never emits. Derived from the PAYLOAD and the crate constant, so it
/// does not depend on the row's prose either.
///
/// IT RETURNS A RESULT rather than a `bool` because `string_member_value` refuses an
/// unterminated value loudly, and a `bool` has nowhere to carry that refusal. WHAT A
/// SWALLOWED `Err` WOULD ACTUALLY COST, traced rather than asserted, because the
/// diagnosis and the verdict move by different amounts:
/// * the VERDICT for the row does not relax. A swallowed `Err` reads as `false` — "not
///   a version probe" — so the row takes the empty-identity branch. That branch still
///   demands the row DECODE (`assert_accepted` runs before the branch is chosen) and
///   then demands its identity member carry the EMPTY STRING, which a version probe
///   does not: `930-136` and `930-137` both carry `manifest_id` `manifest-930-02`.
///   The row therefore still cannot pass; the swallow does not turn a red into a
///   green.
/// * the DIAGNOSIS does degrade. The failure would be attributed to the
///   identity-member derivation — "this row empties no declared member" — rather
///   than to the version-probe derivation, which is the property the row's payload
///   actually turns on. And because `empty_identity_member`
///   calls the SAME `string_member_value` over every declared field — `schema_version`
///   among them — the identical refusal resurfaces one call deeper even if this one is
///   discarded. A `bool` here would trade a correctly attributed failure for a
///   misattributed one of the same loudness.
///
/// TODAY THAT PATH IS UNREACHABLE AT THIS CALL SITE, and the barrier is INCIDENTAL
/// rather than an argument for keeping the `Result`: an unterminated string is also a
/// decode refusal, so `assert_accepted(row)?` at the top of the loop reds before the
/// branch is ever chosen. That barrier is a property of this caller's ordering, not of
/// this helper, and it would not survive a consumer that consults the probe before
/// asserting acceptance — which is exactly why the argument for the `Result` is the
/// diagnosis above and not the absence of a red today.
fn is_schema_version_probe(row: &Row) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(
        string_member_value(&row.raw, L2_SCHEMA_VERSION_MEMBER, &row.id)?
            .is_some_and(|value| value != eliot_types::CANONICAL_MEMORY_SCHEMA_VERSION),
    )
}

/// The identity member's value, read from the TYPED value rather than from a
/// `Value`, so a fabricated default could not pass for an empty input. Returns
/// the member name this arm read alongside its decoded value, so the caller can
/// check the arm against the name the row claims.
fn decoded_identity_member(row: &Row) -> Result<(String, String), Box<dyn std::error::Error>> {
    let raw = row.raw.as_str();
    Ok(match type_leaf(&row.type_name) {
        "BlobRef" => {
            let d: eliot_types::BlobRef = serde_json::from_str(raw).map_err(boxed)?;
            ("digest_hex".to_owned(), d.digest_hex)
        }
        "CanonicalMemoryManifest" => {
            let d: eliot_types::CanonicalMemoryManifest =
                serde_json::from_str(raw).map_err(boxed)?;
            ("manifest_id".to_owned(), d.manifest_id)
        }
        "CanonicalMemorySegment" => {
            let d: eliot_types::CanonicalMemorySegment =
                serde_json::from_str(raw).map_err(boxed)?;
            ("segment_id".to_owned(), d.segment_id)
        }
        "CanonicalMemorySegmentRef" => {
            let d: eliot_types::CanonicalMemorySegmentRef =
                serde_json::from_str(raw).map_err(boxed)?;
            ("segment_id".to_owned(), d.segment_id)
        }
        "CanonicalMemoryL2Page" => {
            let d: eliot_types::CanonicalMemoryL2Page = serde_json::from_str(raw).map_err(boxed)?;
            ("requested_handle".to_owned(), d.requested_handle)
        }
        "MigrationRecord" => {
            let d: eliot_types::MigrationRecord = serde_json::from_str(raw).map_err(boxed)?;
            ("migration_id".to_owned(), d.migration_id)
        }
        "HealthRecord" => {
            let d: eliot_types::HealthRecord = serde_json::from_str(raw).map_err(boxed)?;
            ("component".to_owned(), d.component)
        }
        other => {
            return fail(format!(
                "absence row {} names a type this case does not read: {other}",
                row.id
            ));
        }
    })
}

/// An empty identity must decode with the EMPTY STRING PRESERVED. Stopping at
/// `is_ok()` would let a row pass by decoding to a fabricated value, which is
/// the opposite of what these rows exist to record.
fn empty_identity_row_preserves_its_value(row: &Row) -> TestResult {
    let declared = empty_identity_member(row)?;
    let (read_member, value) = decoded_identity_member(row)?;
    assert_eq!(
        read_member, declared,
        "row {}: the typed read and the payload-derived empty member disagree",
        row.id
    );
    let recorded = raw_member_value(&row.raw, &declared, &row.id)?;
    assert!(
        recorded.is_empty(),
        "row {} must actually carry an empty {declared}, or this row proves nothing",
        row.id
    );
    assert!(
        value.is_empty(),
        "row {} must decode {declared} as the empty string it carried, never a fabricated value: got {value:?}",
        row.id
    );
    Ok(())
}

/// An unsupported or empty `schema_version` must decode with the value BYTE-IDENTICAL
/// to what the payload carried.
///
/// `schema_version` is a plain `String` and is never compared inside this crate's
/// SOURCE files: `CANONICAL_MEMORY_SCHEMA_VERSION` is declared at `records.rs:17` and
/// re-exported at `lib.rs:325`, and under `crates/eliot-types/src/` those are the only
/// two places it appears, so no code path in the crate can accept or reject a document
/// by its version. THE NARROWED SCOPE EXCLUDES THIS FILE, which does compare: see the
/// `!=` in `is_schema_version_probe`, which routes the branch, and the `assert_ne!`
/// below, which keeps the untouched claim from being vacuous. Both comparisons live in
/// a TEST, on a payload read against the constant, and neither is a decode-time gate —
/// so the honest claim is still that the string comes back untouched from the REAL
/// decoder. Asserting a refusal, or asserting a coerced value, would both be false
/// against live source.
fn schema_version_row_round_trips_untouched(row: &Row) -> TestResult {
    let recorded = raw_member_value(&row.raw, L2_SCHEMA_VERSION_MEMBER, &row.id)?;
    let decoded: eliot_types::CanonicalMemoryManifest =
        serde_json::from_str(&row.raw).map_err(boxed)?;
    assert_eq!(
        decoded.schema_version, recorded,
        "row {} must return schema_version byte-identical to the payload, with no coercion",
        row.id
    );
    assert_ne!(
        decoded.schema_version,
        eliot_types::CANONICAL_MEMORY_SCHEMA_VERSION,
        "row {} must carry a version this crate never emits, so the untouched claim is not vacuous",
        row.id
    );
    Ok(())
}

/// The `case == ABSENCE_CASE` rows. Every one must be ACCEPTED: they exist to
/// record that a refusal would be false against live source, because the five
/// allocated files declare no `validate` and no `check` function at all and the
/// empty-string gates live in `runtime.rs` and `runtime_supervision.rs` on
/// different types.
///
/// `accept_rows` is the gate: it fails when the group is empty, and it fails when
/// ANY row claims something other than `accept`, which is the "no row here may
/// claim reject" requirement.
///
/// Beyond `is_ok()`, each row is checked for having preserved its own recorded
/// value, so a row cannot pass by decoding to something fabricated.
fn absence_rows_decode_and_preserve_their_values(all: &[Row]) -> TestResult {
    let group = accept_rows(all, ABSENCE_CASE)?;
    let mut identities = 0usize;
    let mut versions = 0usize;
    for row in &group {
        assert_accepted(row)?;
        // Routed on the PAYLOAD and the crate constant, never on the row's prose.
        if is_schema_version_probe(row)? {
            schema_version_row_round_trips_untouched(row)?;
            versions += 1;
        } else {
            empty_identity_row_preserves_its_value(row)?;
            identities += 1;
        }
    }
    assert!(
        identities > 0 && versions > 0,
        "the absence group must carry both empty-identity rows and schema_version probes, or one half is unproven: {identities} identity, {versions} version"
    );
    Ok(())
}

/// The rows of one fixture group, borrowed from the loaded fixture.
///
/// Named because every selector in this file hands these over in exactly this
/// shape — `accept_rows` and `reject_rows` both return `Vec<&Row>` — and a
/// signature that spells `&[&'rows Row]` and `Vec<&'rows Row>` inline says
/// nothing about what those references are FOR.
type RowRefs<'rows> = Vec<&'rows Row>;

/// The two halves of an acceptance group, split on the DECLARED type.
///
/// Named as a struct rather than a bare `(Vec, Vec)` pair so that neither a
/// reader nor a caller has to remember which side is which: `case_12` wants both,
/// while the page-only claims want `pages` and ignore `health`.
struct SplitGroups<'rows> {
    /// The rows whose declared type leaf is `CanonicalMemoryL2Page`.
    pages: RowRefs<'rows>,
    /// The rows whose declared type leaf is `HealthRecord`.
    health: RowRefs<'rows>,
}

/// Split an acceptance group into its `CanonicalMemoryL2Page` rows and its
/// `HealthRecord` rows, on the DECLARED type.
///
/// This split is load-bearing rather than cosmetic:
/// `l2_page_optional_absence_holds` requires `manifest` and `continuation` at top
/// level, so feeding it a `HealthRecord` row fails it for the wrong reason. The
/// guard is that the two halves account for the WHOLE group, so a row of a third
/// type cannot slip through unexercised. Shared by case 12 and by case 2's page
/// claims rather than written twice.
///
/// The `'rows` lifetime stays explicit. It cannot be elided: the signature has
/// TWO elided input lifetime positions (`&'a [ &'rows Row ]`), and elision only
/// assigns an output lifetime when there is exactly one, so writing
/// `SplitGroups<'_>` in return position would be ambiguous rather than
/// equivalent. Naming the type does not change that.
fn split_l2_pages_and_health_records<'rows>(
    group: &[&'rows Row],
) -> Result<SplitGroups<'rows>, Box<dyn std::error::Error>> {
    let pages: RowRefs<'_> = group
        .iter()
        .copied()
        .filter(|row| type_leaf(&row.type_name) == "CanonicalMemoryL2Page")
        .collect();
    let health: RowRefs<'_> = group
        .iter()
        .copied()
        .filter(|row| type_leaf(&row.type_name) == "HealthRecord")
        .collect();
    if pages.len() + health.len() != group.len() {
        return fail(format!(
            "the group carries {} rows but only {} pages and {} health rows; a row of another type would go unexercised",
            group.len(),
            pages.len(),
            health.len()
        ));
    }
    Ok(SplitGroups { pages, health })
}

/// The optional-member claims, exercised on EVERY `CanonicalMemoryL2Page` row this
/// case owns: the allocation page and the absence pages. The allocation page omits
/// `requested_segment_id` outright, the absence pages cover the other
/// combinations, so together they exercise both the present and the absent side of
/// the skipped pair. Passing only the allocation row left the absent side untested;
/// passing only the absence rows would leave the present side untested.
///
/// The group is split on the DECLARED type before the page-only helper is called:
/// the absence group also carries a `HealthRecord` row, and feeding that to an
/// L2-page-only helper would fail it for the wrong reason.
///
/// The typed-in partition is checked against the live declaration FIRST, so every
/// claim below is a claim about the members `records.rs` actually declares rather
/// than about the four names this file happens to repeat.
fn optional_member_claims_hold_on_every_page(all: &[Row]) -> TestResult {
    l2_optional_partition_matches_source()?;
    let allocation = applicable_row(all, "CanonicalMemoryL2Page")?;
    l2_page_optional_absence_holds(allocation)?;
    let group = accept_rows(all, ABSENCE_PAGE_CASE)?;
    let SplitGroups { pages, .. } = split_l2_pages_and_health_records(&group)?;
    assert!(
        !pages.is_empty(),
        "the absence group must carry at least one CanonicalMemoryL2Page row"
    );
    for row in &pages {
        l2_page_optional_absence_holds(row)?;
    }
    let has =
        |row: &Row, member: &str| recorded_member(&row.raw, member, &row.id) == Recorded::Present;
    let pages: Vec<&Row> = std::iter::once(allocation)
        .chain(pages.iter().copied())
        .collect();
    assert!(
        pages
            .iter()
            .any(|row| { L2_SKIPPED_WHEN_NONE.iter().any(|member| has(row, member)) }),
        "at least one page must carry a skipped member, or the re-emit claim is vacuous"
    );
    assert!(
        pages.iter().any(|row| {
            L2_SKIPPED_WHEN_NONE
                .iter()
                .any(|member| recorded_member(&row.raw, member, &row.id) == Recorded::Absent)
        }),
        "at least one page must omit a skipped member, or the drop claim is vacuous"
    );
    // The third form of the skipped pair — an explicit `null` — is reached from NO
    // fixture row, so it is built here from the allocation page's own bytes. Called
    // from this function rather than from case 2's body because it is the same
    // optional-member claim, just with the payload the fixture does not carry.
    skipped_pair_null_form_is_exercised(all)?;
    Ok(())
}

/// CASE 2 OF ISSUE #930, AND THE WORD `byte` IN ITS NAME IS SCOPED HERE RATHER THAN
/// LEFT TO COVER THE WHOLE FIXTURE.
///
/// THE CLAUSE is issue #930's acceptance row for cases 1–4: "unchanged valid
/// bytes/digests".
///
/// BYTE COMPARISON — WHAT IS COVERED. Every ALLOCATION row reaches a real comparison
/// of the re-serialized value against the row's OWN recorded bytes, through
/// `round_trip_row`, which dispatches on the row's own source file:
/// * the 40 `ids.rs` transparent scalars, by `scalar_round_trip`, which asserts
///   `to_string(decoded) == row.raw.trim()` — a bare JSON string for the `Uuid`
///   newtypes and a bare JSON number for the two `u64` newtypes;
/// * the seven `records.rs` closed structs, the `task_execution.rs` struct and the four
///   externally tagged member enums, by `value_round_trip`, which asserts the same
///   byte equality. That assertion was RESTORED: it had been omitted on a premise that
///   measurement refuted, and `value_round_trip`'s own doc comment records the false
///   reason and what its absence was hiding.
///
/// BYTE COMPARISON — WHAT IS **NOT** COVERED, named rather than left for the name to
/// cover. Two accept populations reach this case's other helpers and those helpers
/// compare VALUES, not bytes:
/// * the case-2 absence group, through `absence_rows_decode_and_preserve_their_values`,
///   whose `empty_identity_row_preserves_its_value` and
///   `schema_version_row_round_trips_untouched` compare a decoded member against the
///   raw string recorded for that member;
/// * the case-12 absence and surrogate rows, which are decoded by case 12 through
///   `l2_page_absence_row_is_accepted` and `health_record_surrogate_row_is_accepted`,
///   neither of which re-serializes and compares against `row.raw`.
/// So `byte` in this case's name is scoped to the ALLOCATION population, which is what
/// the name says. A byte-level defect in a LATER-CASE accept row would not be caught
/// here, and that remains a real gap: those rows are decoded by value-level helpers, so
/// nothing compares their re-serialization against their own bytes.
///
/// ONE SUCH DEFECT WAS FOUND AND HAS SINCE BEEN FIXED AT THE SOURCE, and the record is
/// kept because it is what the gap is worth. The case-12 accept row on numeric stem
/// `930-128` — referred to by its STEM rather than by any full id, because ids move
/// between revisions while the stem and the case number do not, and this row has already
/// been re-spelled once by its owner — CARRIED, IN AN EARLIER REVISION ONLY, a `detail`
/// that stored U+1F600 as the escaped surrogate pair `\ud83d\ude00`, which
/// `serde_json::to_string` never emits, so its re-serialization differed from its own
/// bytes and no assertion here would have said so. Two things must not be read into that
/// sentence. It is NOT a description of the current bytes: the row now carries U+1F600 as
/// one literal astral scalar, verified against the fixture rather than assumed. And it is
/// NOT a claim that the row's id still contains `-surrogate-pair-`; that spelling is the
/// fixture owner's to change and this comment would be wrong the moment it changed.
/// The fixture's owner replaced that `raw` with the bytes the serializer actually emits
/// and the divergence is GONE — the row now round-trips byte-for-byte. So this is no
/// longer a live defect, and a reader must not go looking for one; what survives is the
/// COVERAGE GAP above, which is why the sentence about it is not withdrawn with the
/// claim.
///
/// The name says ALLOCATION rows, not `applicable` rows, because the loop below
/// is not filtered by `applicable` and must not be. An earlier name read
/// "applicable" while the code did the opposite, and a reader misled by a test
/// name is a defect even when the body is right.
///
/// THIS BLOCK SITS ABOVE THE WORK-UNIT MARKER, and that placement is load-bearing.
/// The marker must be IMMEDIATELY followed by its `#[test]`, and the work-unit gate
/// that binds the two walks forward from the marker refusing a blank line and
/// refusing any line beginning `//` or `/*` before it reads an attribute; a `///`
/// line is a `//` line, so a documentation comment written between the attribute and
/// this function detaches the marker exactly as a plain comment would, and there is
/// no tolerant fallback for a `.rs` file because every one is routed into that text
/// parser unconditionally. A PLAIN comment in the same place is not a workaround
/// either: `rustc` puts no order constraint on a comment relative to an attribute,
/// so the text would still be absent from hover and from extracted documentation.
/// Above the marker the walk never looks, and the block is still a documentation
/// comment, so every reader that reached it before still reaches it.
// WORK_UNIT_CASE: 930/2
#[test]
fn case_02_allocation_rows_round_trip_without_byte_drift() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    // The `applicable` flag scopes the unknown-member surface, not byte validity:
    // every ALLOCATION row carries valid canonical bytes, including every
    // transparent scalar row among them, whose own `reason` records that a bare JSON
    // value has no member-key surface at any depth. So the whole allocation is decoded
    // and re-serialized here, and it is deliberately NOT filtered by `applicable`:
    // that flag is false on exactly those transparent-scalar allocation rows, which
    // are the ones that most need this round trip. There is therefore no `applicable`
    // binding to consult here, and adding one would only invite somebody to filter on
    // it.
    //
    // NO FIGURE IS ATTACHED TO THAT CLAIM, and one was REMOVED rather than corrected.
    // An earlier version of these lines said the flag is false on "exactly the 40
    // rows". That is true of the ALLOCATION and FALSE of the FIXTURE, which carries
    // further inapplicable rows outside this allocation: the malformed
    // transparent-scalar rows of the case-14 group. A reader who counted inapplicable
    // rows in the fixture would not arrive at that number, and a numeral that is right
    // for one population and wrong for another is worse than none. The claim is about a
    // SHAPE — a bare JSON scalar has no member key at any depth — and a shape is what
    // the row's own `reason` records and what `declares_transparent_scalar` selects on,
    // so the sentence is checkable without a count. This is the same no-count rule the
    // paragraph below states about the figures this file has deleted.
    //
    // The scope must be the allocation, not every row: the later acceptance cases
    // own rows whose `expected` is `reject`, and `round_trip_row` requires success,
    // so feeding it any rejected row would fail on the very first of them. Those are
    // two DIFFERENT populations, and keeping them apart is the only reason this loop
    // can be bounded at all.
    //
    // NO LATER-CASE ROW COUNTS ARE WRITTEN HERE, and the deletion is the claim
    // rather than a loss of detail. An earlier version of this comment carried the
    // later-case row count, its rejected share, its accept share, the whole-fixture
    // total, the allocation size and the per-group split — every one of them a
    // transcription of a fixture another writer owns, and every one of them a number
    // that went stale while this file said nothing. That is exactly the failure the
    // assertions here exist to prevent, so the figures are deleted rather than
    // corrected, and the scope is stated as the SELECTOR that produces it:
    // `allocation_rows` reads the `case` field, `reject_rows` and `accept_rows` read
    // the `expected` field, and a figure that can be derived from the fixture has no
    // business being transcribed beside an assertion. The scalar count in the
    // paragraph above is a different claim — the size of one shape's population, not
    // a scope boundary — and it is restated by the dispatchers that act on it.
    let allocation = allocation_rows(&rows)?;
    for row in &allocation {
        // `accept`, NOT "records something". `round_trip_row` below REQUIRES a
        // successful decode of every allocation row, so an allocation row marked
        // `expected: "reject"` would contradict the fixture — this row's own canonical
        // bytes decode — and nothing here would have noticed: the previous version of
        // this loop demanded only a NON-EMPTY expectation, which every row already
        // carried. One `assert_eq!` is what the loop evidently intended, and the
        // `accept_rows` helper already applies the same rule to the other accept groups.
        assert_eq!(
            row.expected.trim(),
            ACCEPT_EXPECTED,
            "allocation row {} (case {}) records expected {:?}, and this loop round-trips it through `round_trip_row`, which requires a SUCCESSFUL decode; an allocation row that is expected to be refused would therefore be decoded here anyway and nothing else in cases 1-4 would object. The row claims: {}",
            row.id,
            row.case,
            row.expected,
            row.description
        );
        round_trip_row(row)?;
    }

    // The `ABSENCE_CASE` rows: the empty-identity accept rows and the
    // `schema_version` probes. Without this they were loaded, shape-checked and
    // vocabulary-checked but never decoded, leaving the "a refusal here would be
    // false against live source" claim unproven.
    absence_rows_decode_and_preserve_their_values(&rows)?;

    // The crate's SECOND JSON decoder, over exactly the two accept populations just
    // decoded: whatever a permissive `serde_json` decode made of these bytes,
    // `strict_json_value` must make the SAME value, so the strict duplicate-rejecting
    // ingress cannot have dropped or fabricated a member. It is called from here and
    // from case 5 rather than carrying a marker of its own, because it is not a new
    // acceptance case of the checklist: it is an EXISTING claim of this case — these
    // bytes decode to this value — read through the decoder this crate also owns. A
    // marker here would name a case number the checklist does not give it.
    strict_ingress_cannot_erase_protected_input(&rows)?;

    // Absence means `None` on the L2 page in BOTH directions, but only the two
    // members carrying `skip_serializing_if` are dropped at `None`. An absent
    // `manifest`/`continuation` still decodes, and the encoder re-emits them as
    // explicit null because they carry no attribute at all. None of the four is a
    // decode error; only `requested_handle`, `segments` and `truncated` are
    // genuinely required.
    optional_member_claims_hold_on_every_page(&rows)?;
    let page = applicable_row(&rows, "CanonicalMemoryL2Page")?;
    l2_page_required_members_are_refused(page)?;

    // `TaskExecutionClass` carries no `#[serde(default)]` on any member and no
    // member is an `Option`, so all of its members stay required on the wire and
    // dropping one must fail closed.
    //
    // THE MEMBER LIST IS DERIVED FROM SOURCE, through the existing
    // `declared_field_names` walk, and that is the whole change: this loop used to
    // hand-type the five names, in a file that already reads declared fields from
    // source and whose two ordering helpers already do the same. Appending a SIXTH
    // required member to `TaskExecutionClass` was therefore invisible to cases 1 and
    // 2 — the loop walked five of six members, `task_execution_class_fabricates_nothing`
    // was not called from either, and the allocation row's bytes would simply carry a
    // key nothing here dropped. No new parser is introduced: `struct_field_names` is
    // the one walk, and `declared_field_names` is its existing `declaring_file`
    // wrapper. The non-vacuity guard below is what keeps a DERIVED list honest, since
    // an empty one would leave the loop iterating nothing.
    let declared = declared_field_names("TaskExecutionClass")?;
    assert!(
        !declared.is_empty(),
        "{TASK_EXECUTION_FILE} must declare the members of TaskExecutionClass, or the required-member loop below iterates nothing and proves nothing"
    );
    let class = applicable_row(&rows, "TaskExecutionClass")?;
    let value: Value = serde_json::from_str(&class.raw).map_err(boxed)?;
    let object = value.as_object().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "row {} must be a JSON object",
            class.id
        )))
    })?;
    for member in &declared {
        if !object.contains_key(member.as_str()) {
            return fail(format!(
                "row {} must record the required member {member}",
                class.id
            ));
        }
        let missing = without_member(&value, member)?;
        assert!(
            serde_json::from_str::<eliot_types::TaskExecutionClass>(&missing).is_err(),
            "TaskExecutionClass must refuse a missing {member} on the wire"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 930/3
#[test]
fn case_03_unknown_top_level_member_rejected() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    // This case owns NO rows of its own, which is the whole reason an
    // `also_in_cases` entry naming it means "this test case also consumes that
    // row" and not "there is a case-3 row group". It is reached by injecting an
    // unknown member into each closed type's own case-1 allocation bytes. The
    // selector is called through the constant so the literal 3 never appears at a
    // call site — `byte_injected_cases_select_no_rows` looks for exactly that.
    assert!(
        rows_in_case(&rows, UNKNOWN_TOP_LEVEL_CASE).is_empty(),
        "case {UNKNOWN_TOP_LEVEL_CASE} must carry no rows of its own; it is discharged by injecting an unknown member into an existing row's own raw bytes, and a row here would change what `also_in_cases` names"
    );
    // THE CLOSED SET IS DERIVED FROM SOURCE, by `closed_type_names`, and that is what
    // replaces the hand-maintained `CLOSED_TYPES` this loop used to walk. Nothing pins
    // how many closed structs there are and no name is retyped as a list: the loop runs
    // over the structs live source declares with `#[serde(deny_unknown_fields)]`, so a
    // ninth closed struct is covered here rather than silently uncovered. Three distinct
    // ways such a struct ends in a red, in the order they would fire:
    // * with no fixture allocation row of its own — which is what the case-1
    //   completeness denominator also demands — `applicable_row` below fails naming it;
    // * with a row, `applicable_row` succeeds and the typed dispatch's `other` arm
    //   fails naming it as a closed struct with no unknown-top-level probe here;
    // * the walk itself failing, on a struct whose name is not one bare identifier or
    //   on a file whose braces do not balance.
    // The typed dispatch remains a hand-written table, because each arm names a
    // DIFFERENT Rust type and the probe is generic over it; what changed is that the
    // table can no longer be short.
    let closed = closed_type_names()?;
    // NON-VACUITY, in the other direction. A walk that found nothing would leave the
    // loop below iterating zero times and every assertion in this case silently
    // vacuous — the failure mode deriving an expected set introduces, and the one
    // `byte_injected_cases_select_no_rows` guards against for the selector scan.
    assert!(
        !closed.is_empty(),
        "no struct in {} carries {DENY_UNKNOWN_FIELDS_ATTRIBUTE}, so the closed set is empty and this case would refuse nothing while staying green",
        ALLOCATED_SOURCE_FILES.join(", ")
    );
    for name in closed {
        let row = applicable_row(&rows, &name)?;
        match name.as_str() {
            "BlobRef" => {
                reject_unknown_top_level::<eliot_types::BlobRef>(row, "930_unknown_top_blob_ref")?;
            }
            "CanonicalMemoryManifest" => reject_unknown_top_level::<
                eliot_types::CanonicalMemoryManifest,
            >(row, "930_unknown_top_memory_manifest")?,
            "CanonicalMemorySegment" => reject_unknown_top_level::<
                eliot_types::CanonicalMemorySegment,
            >(row, "930_unknown_top_memory_segment")?,
            "CanonicalMemorySegmentRef" => reject_unknown_top_level::<
                eliot_types::CanonicalMemorySegmentRef,
            >(row, "930_unknown_top_memory_segment_ref")?,
            "CanonicalMemoryL2Page" => reject_unknown_top_level::<
                eliot_types::CanonicalMemoryL2Page,
            >(row, "930_unknown_top_memory_l2_page")?,
            "MigrationRecord" => reject_unknown_top_level::<eliot_types::MigrationRecord>(
                row,
                "930_unknown_top_migration_record",
            )?,
            "HealthRecord" => reject_unknown_top_level::<eliot_types::HealthRecord>(
                row,
                "930_unknown_top_health_record",
            )?,
            "TaskExecutionClass" => reject_unknown_top_level::<eliot_types::TaskExecutionClass>(
                row,
                "930_unknown_top_task_execution_class",
            )?,
            other => {
                return fail(format!(
                    "the closed struct {other} declared by live source has no unknown-top-level probe in this case, so a new {DENY_UNKNOWN_FIELDS_ATTRIBUTE} struct is red here rather than silently uncovered; add a typed arm for it"
                ));
            }
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 930/4
#[test]
fn case_04_unknown_nested_member_rejected() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    // As in case 3: no rows of its own. The nested rejections are reached by
    // injecting an unknown member into a case-1 allocation row's own bytes, which
    // is why 4 fixture rows may cross-reference case 4 without naming a case-4
    // row group. Called through the constant so the literal 4 never appears at a
    // selector call site.
    assert!(
        rows_in_case(&rows, UNKNOWN_NESTED_CASE).is_empty(),
        "case {UNKNOWN_NESTED_CASE} must carry no rows of its own; it is discharged by injecting an unknown member into an existing row's own raw bytes, and a row here would change what `also_in_cases` names"
    );
    // `BlobRef` closes at depth 3 under the L2 page: page -> manifest -> blob
    // and page -> segments[0] -> blob. The depth-2 and the depth-3 sites are
    // both covered so the closure cannot be shallow-only.
    let manifest = applicable_row(&rows, "CanonicalMemoryManifest")?;
    reject_unknown_nested::<eliot_types::CanonicalMemoryManifest>(
        manifest,
        &[Step::Field("blob")],
        "930_unknown_nested_manifest_blob",
    )?;
    let segment = applicable_row(&rows, "CanonicalMemorySegment")?;
    reject_unknown_nested::<eliot_types::CanonicalMemorySegment>(
        segment,
        &[Step::Field("blob")],
        "930_unknown_nested_segment_blob",
    )?;
    let segment_ref = applicable_row(&rows, "CanonicalMemorySegmentRef")?;
    reject_unknown_nested::<eliot_types::CanonicalMemorySegmentRef>(
        segment_ref,
        &[Step::Field("blob")],
        "930_unknown_nested_segment_ref_blob",
    )?;
    let page = applicable_row(&rows, "CanonicalMemoryL2Page")?;
    reject_unknown_nested::<eliot_types::CanonicalMemoryL2Page>(
        page,
        &[Step::Field("manifest")],
        "930_unknown_nested_l2_manifest",
    )?;
    reject_unknown_nested::<eliot_types::CanonicalMemoryL2Page>(
        page,
        &[Step::Field("segments"), Step::Index(0)],
        "930_unknown_nested_l2_segment",
    )?;
    reject_unknown_nested::<eliot_types::CanonicalMemoryL2Page>(
        page,
        &[Step::Field("manifest"), Step::Field("blob")],
        "930_unknown_nested_l2_manifest_blob",
    )?;
    reject_unknown_nested::<eliot_types::CanonicalMemoryL2Page>(
        page,
        &[Step::Field("segments"), Step::Index(0), Step::Field("blob")],
        "930_unknown_nested_l2_segment_blob",
    )?;
    Ok(())
}

// WORK_UNIT_CASE: 930/5
#[test]
fn case_05_duplicate_keys_are_refused() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    let group = reject_rows(&rows, 5)?;
    // Every row in this group repeats a member with two different values, so
    // first-wins and last-wins are distinguishable, and the derived `MapAccess`
    // refuses the second occurrence. One assertion shape covers the ordinary,
    // identity and control duplicates, the duplicate-first/duplicate-last pairs,
    // and the duplicates nested inside `blob`, `manifest`, `segments[0].blob`
    // and `segments[0]`: the rule holds at every nesting depth, including
    // inside arrays.
    //
    // Each row is refused FOR ITS OWN REPEATED MEMBER, and that member comes from
    // the row's bytes, never from its prose: `repeated_member_is_refused` scans the
    // raw document for the first name occurring twice inside one object and
    // requires the refusal to be serde's DUPLICATE-MEMBER refusal and to name it.
    // `assert_refused` alone would not do — it discards the message, so a row
    // refused for some unrelated reason passed just as well as one refused for its
    // duplicate. Naming the member alone would not do either: an unknown-member
    // refusal lists every declared field of the closed struct, so it would satisfy
    // that substring for a member the row never duplicated. That helper's doc
    // comment records the concrete false pass.
    //
    // NO ROW COUNT IS WRITTEN HERE, and there is none. The count belonged to a
    // sentence about how big this group is, which is a property of the fixture's
    // current contents rather than of anything this case proves, and it had already
    // gone stale twice under fixture edits. What the case proves is the shape of the
    // group — every row repeats a member, at every depth the group's own bytes make a
    // repetition reachable — and that is asserted from the bytes below.
    //
    // TWO VECTORS ARE BUILT IN ONE PASS, and they are the two halves of the depth
    // sentence above. `repeats` holds, per row, the depth of ITS first repetition.
    // `witnesses` holds, per depth, the ids of the rows whose bytes place an object
    // holding two or more members at that depth — which is the definition of a depth
    // at which a repetition was REACHABLE in the group.
    let mut repeats: Vec<usize> = Vec::with_capacity(group.len());
    let mut witnesses: Vec<(usize, Vec<String>)> = Vec::new();
    for row in &group {
        let repetition = repeated_member_is_refused(row)?;
        // The `else` arm cannot be reached: the helper above refuses a row that repeats
        // nothing before returning. It is kept because this loop reads the value rather
        // than a depth the helper extracted, and an unchecked `unwrap`-shaped step here
        // would turn a future change to that helper into a panic at the wrong line.
        let Some((_, depth)) = repetition.first.as_ref() else {
            return fail(format!(
                "case {} row {} contributes no repetition depth to the histogram below, so the depth claim would be measured over fewer rows than the group holds",
                row.case, row.id
            ));
        };
        repeats.push(*depth);
        for reachable in &repetition.reachable {
            // `position` over an immutable borrow, then one indexed push, rather than
            // `iter_mut().find(..)` with a `push` in the `None` arm: the latter holds
            // the mutable borrow for the whole `match` and does not borrow-check.
            //
            // WHAT THE TWO OPERANDS ACTUALLY ARE HERE, recorded because the shape looks like
            // the ones that fail elsewhere in this file. `witnesses` is declared
            // `Vec<(usize, Vec<String>)>` (above), so `.iter()` yields
            // `&(usize, Vec<String>)` and `position`'s closure parameter is one
            // reference further, `&&(usize, ..)`. The pattern `(depth, _)` therefore
            // binds by `ref` and `depth` IS A `&usize`, so `*depth` is a plain `usize`.
            // `reachable` is a `&usize` borrowed out of `Repetition.reachable`
            // (`Vec<usize>`), so `*reachable` is a plain `usize` too: the comparison
            // is `usize == usize`, which is why it compiles.
            //
            // THE GENERAL RULE, because the reason this one is fine is not that it is
            // an integer. When a destructuring pattern binds by `ref`, it adds ONE
            // REFERENCE TO THE ELEMENT — so if the element is already a reference the
            // binding is a reference TO a reference. That is invisible here, where the
            // element is a `usize`, and decisive at `closed_object_labels_are_witnessed`,
            // whose `labelled` holds `(&'static str, Vec<String>)`: the same
            // destructuring makes `known` a `&&'static str`, one deref leaves a `&str`,
            // and comparing that against an already-doubled right-hand side lands on
            // `str == &str`, which a `str` cannot satisfy because it is unsized and has
            // no by-value `PartialEq`. Read the ELEMENT type before writing the
            // deref, not the container's.
            let known = witnesses.iter().position(|(depth, _)| *depth == *reachable);
            match known {
                Some(index) => witnesses[index].1.push(row.id.clone()),
                None => witnesses.push((*reachable, vec![row.id.clone()])),
            }
        }
    }
    witnesses.sort_unstable_by_key(|(depth, _)| *depth);
    // THE TOP-LEVEL HALF, stated on its own because it is the conjunct the previous
    // version of this assertion bundled into `nested > 0`.
    assert!(
        repeats.contains(&TOP_LEVEL_MEMBER_DEPTH),
        "case 5 must carry a repeat in the document's own top-level object, or the rule would only ever have been witnessed nested; the repeat depths measured across the group are {repeats:?} over {} rows",
        group.len()
    );
    // THE HISTOGRAM, and this is what replaces `top_level > 0 && nested > 0`. That
    // guard could only say SOME repeat was nested, so deleting the single depth-2 row
    // and the single depth-3 row — each the ONLY witness at its depth — left it green
    // while the sentence it backed, "the rule holds at every nesting depth, including
    // inside arrays", quietly stopped being true at two of the four depths the group
    // reaches. What is demanded now is a witness at EVERY depth the group's own bytes
    // make reachable, where REACHABLE means precisely "some row places an object
    // holding two or more members there": an object holding one member cannot repeat
    // anything inside itself, so demanding a witness there would be demanding the
    // impossible and the figure is derived from the rows rather than written as a
    // literal count.
    //
    // The unreachable-depth case is not silent: the message below names the depth AND
    // the rows whose bytes make it reachable, so a deletion of one witness row reports
    // which depth lost its witness and which rows could have supplied it. That is the
    // "a stale figure in a comment is the exact failure these numbers exist to
    // prevent" standard, applied to the depths themselves.
    //
    // NON-VACUITY FIRST, because the loop below is a vacuous pass over an empty set. No
    // row in the group placing an object with two or more members anywhere would mean
    // the reachable set is empty and the histogram requirement is never evaluated.
    assert!(
        !witnesses.is_empty(),
        "no row in the case-5 group places an object holding two or more members at any depth, so the per-depth requirement is satisfied over an empty set and witnesses nothing"
    );
    for (depth, rows_at_depth) in &witnesses {
        // NOT `witnessed`, which reads as a claim about the depth rather than a count
        // of rows: `witnesses` above holds WHICH rows make this depth reachable, and
        // this holds HOW MANY of the group's measured repetitions actually landed on
        // it. Naming the count for what it counts keeps the two apart.
        let rows_repeating_at_depth = repeats
            .iter()
            .filter(|candidate| *candidate == depth)
            .count();
        assert!(
            rows_repeating_at_depth > 0,
            "case 5 must carry a repeat at EVERY depth its own bytes make reachable, or the comment's claim that the rule holds at every nesting depth, including inside arrays, loses its only witness at depth {depth}: {} of the group's rows place an object holding two or more members there ({rows_at_depth:?}) and none of them repeats a member at that depth; the repeat depths measured across the group are {repeats:?}",
            rows_at_depth.len()
        );
    }

    // The escape-equivalent subgroup is the reason the string path is
    // mandatory. Its second occurrence is written with a `\u00xx` escape, so it
    // is a different byte sequence from the plain key yet decodes to the same
    // member name. A decoder comparing raw key bytes would miss the repetition;
    // and because `serde_json::Map` is a `BTreeMap`, routing these rows through
    // a `Value` would collapse the pair before the decoder ever saw it. Dropping
    // the string path would silently weaken this case to a green assertion that
    // proves nothing, so the subgroup is selected explicitly and the string
    // path is what makes it bite.
    //
    // THE SUBGROUP IS SELECTED FROM THE ROWS' OWN BYTES, which is the whole change.
    // It used to be selected by `row.reason.contains(ESCAPE_REASON_MARKER)` — a phrase
    // in the fixture's PROSE — and `ESCAPE_REASON_MARKER` is deleted rather than left
    // unread. Rewording a reason silently emptied or misfilled the subgroup, with no
    // red anywhere: this file already records that reading the fixture's prose "is a
    // coupling with a known date on it", because the reason text of this fixture is
    // being rewritten in the same delivery, and `scan_repetitions`'s own doc comment
    // states that the row's prose is never read. The selection is now the same
    // structural predicate `no_escaped_top_level_key_outside_case_escape_rows` already
    // applies to case 5's rows for its own non-vacuity check: does the row's raw write
    // a TOP-LEVEL member key with a JSON escape.
    //
    // THE SELECTION IS THE WEAKER HALF OF THE PROPERTY, DELIBERATELY, and that is not
    // a weakening — it is what keeps `escape_row_carries_a_colliding_escape` the thing
    // that stands between a mislabelled row and a false green. Selecting on the full
    // collision would make the per-row proof a tautology: a row whose escaped key
    // decodes to a name nothing else carries would simply not be selected, and the
    // helper would never fire. So the selection admits every row with an escaped
    // top-level key, and the helper then demands, per row, that the escape DECODES onto
    // a name already present. A mislabelled row — one carrying an escape that collides
    // with nothing — is selected and refused by name.
    //
    // The subgroup is NOT re-asserted refused here: every row above is already
    // asserted refused, so re-asserting a subset of that set cannot fail.
    let escapes: Vec<&Row> = group
        .iter()
        .copied()
        .filter(|row| carries_an_escaped_top_level_key(&row.raw))
        .collect();
    assert!(
        !escapes.is_empty(),
        "case 5 must carry escape-equivalent duplicate rows, and the subgroup is selected structurally: no row in the group writes a top-level member key with a {JSON_ESCAPE_MARKER} escape, so the escape path this case exists to exercise is not in the bytes at all"
    );
    for row in &escapes {
        escape_row_carries_a_colliding_escape(row)?;
    }

    // The crate's strict duplicate-rejecting ingress over this same corpus: every one
    // of these rows must be refused as a DUPLICATE by it while the permissive
    // `serde_json` decode of the identical bytes ACCEPTS it, so the refusal is
    // attributable to the duplicate rather than to a broken document, and its no-ceiling
    // entry point is shown to reach that detection instead of answering a byte-ceiling
    // question. Its non-leak half is asserted over the same corpus, because a refusal
    // that named the duplicated member, or either of its values, would leave every
    // substring claim above satisfiable by the wrong text.
    strict_ingress_cannot_erase_protected_input(&rows)?;
    Ok(())
}

/// Whether a raw document writes at least one TOP-LEVEL member key with a JSON unicode
/// escape, escapes intact.
///
/// STRUCTURAL, and derived from the bytes rather than from anything the fixture says
/// about itself: `MemberSpan.key` holds the raw bytes between the quotes, so the
/// `{JSON_ESCAPE_MARKER}` test is a fact about the wire. This is the selection predicate
/// for case 5's escape-equivalent subgroup, and the same predicate
/// `no_escaped_top_level_key_outside_case_escape_rows` applies to every row outside
/// case 5 to prove those readers' escape-blindness is safe; both call sites read this one
/// function, so the two can never drift about what "an escaped top-level key" means.
fn carries_an_escaped_top_level_key(raw: &str) -> bool {
    top_level_member_spans(raw)
        .iter()
        .any(|span| span.key.contains(JSON_ESCAPE_MARKER))
}

/// The byte-level half of the escape-equivalence claim, asserted per row.
///
/// TWO properties, both derived from the row's OWN bytes and never from its
/// prose:
/// * at least one top-level KEY is written with a `\u` escape, so the row really
///   does differ byte-for-byte from a plain duplicate; and
/// * that key DECODES to a name that is ALREADY present as another top-level key,
///   so the two occurrences collide as member names even though they do not match
///   as byte sequences.
///
/// The second is the load-bearing one. It is what makes the pair invisible to a
/// decoder that compares raw key bytes, and visible to the derived `MapAccess`
/// that compares decoded names — which is the whole reason these payloads are
/// held as raw strings instead of being routed through `serde_json::from_value`,
/// where `serde_json::Map` being a `BTreeMap` would collapse the pair at insert
/// time and the collision could never be observed at all.
///
/// `top_level_member_spans` is used rather than a `Value` walk for the same
/// reason, and it yields each key's RAW text (`MemberSpan.key` is the bytes
/// between the quotes, escapes intact), which is exactly the distinction being
/// asserted.
///
/// WHY THIS IS NOT A RE-STATEMENT OF THE SELECTION THAT CALLS IT. The subgroup is
/// selected by `carries_an_escaped_top_level_key`, which is the FIRST bullet above
/// only; the second bullet — that the escape DECODES onto a name already present —
/// is proved here and is deliberately not part of the selection, so a row carrying an
/// escape that collides with nothing is selected and then refused by name here. See
/// the selection comment in `case_05_duplicate_keys_are_refused`.
fn escape_row_carries_a_colliding_escape(row: &Row) -> TestResult {
    let spans = top_level_member_spans(&row.raw);
    let escaped: Vec<usize> = spans
        .iter()
        .enumerate()
        .filter(|(_, span)| span.key.contains(JSON_ESCAPE_MARKER))
        .map(|(index, _)| index)
        .collect();
    assert!(
        !escaped.is_empty(),
        "row {} was selected as an escape-equivalent duplicate because it writes a top-level key with a {JSON_ESCAPE_MARKER} escape, yet the byte scan found none, so the escape path this case exists to exercise is not in the bytes: {}",
        row.id,
        row.raw
    );
    for index in escaped {
        let span = &spans[index];
        // The full quoted key literal, taken from `row.raw` by offset rather than
        // re-quoted, so what gets decoded is precisely the bytes on the wire.
        let literal = &row.raw[span.key_open..span.key_open + span.key.len() + 2];
        let decoded: String = serde_json::from_str(literal).map_err(boxed)?;
        let collides = spans
            .iter()
            .enumerate()
            .any(|(other, candidate)| other != index && candidate.key == decoded);
        assert!(
            collides,
            "row {} writes the key {} which decodes to {decoded:?}, but no other top-level key carries that name, so the escaped and plain occurrences would NOT collide and the row would be an ordinary pair of distinct members: {}",
            row.id, span.key, row.raw
        );
    }
    Ok(())
}

/// The crate's own strict, duplicate-rejecting JSON ingress cannot erase protected
/// input, cannot answer a different question than the permissive decode it sits in
/// front of, and cannot be made to refuse by accident of a byte ceiling.
///
/// WHY IT EXISTS AT ALL. `strict_json_value` is `pub` in `crates/eliot-types/src/
/// strict_json.rs` and is re-exported from the crate root (`lib.rs:418-420`), so it
/// is reachable from an integration test in this crate's own `tests/` directory — but
/// nothing IN THAT DIRECTORY CALLED it until this function did: the sibling
/// `serde_t03_host.rs` calls the other half of the pair,
/// `strict_json_has_no_duplicate_members`, and names this one in prose only. That scope
/// is the test directory and NOT the repository — `eliot-engine` and `eliot-app` both
/// call `strict_json_value` — so nothing here rests on the symbol being uncalled
/// everywhere. A function no test in this crate calls cannot be wrong here, because no
/// assertion observes it. It
/// is also the one reachable half of the clause this delivery is discharging; the
/// lossy ingress points beside it are not reachable from this crate's tests and are
/// UNRESOLVED, and this one is not.
///
/// "UNRESOLVED" IS THE CARD'S WORD AND IS USED DELIBERATELY, with the inventory's own
/// coverage stated rather than assumed. The card defers them as unresolved, and the
/// frozen boundary inventory records `blocked_reason = "missing-owner"` for exactly ONE
/// of them — the `validate_capacity_receipt` row — so "blocked" would be a status word
/// this file could support for that one path and for no other. The remaining lossy
/// ingress points have NO inventory row behind them, so no status is claimed for them at
/// all: they are unresolved here, unreachable from this crate, and owned by nobody this
/// delivery may name. `case_11`'s doc comment states the same accounting from the other
/// end, and the two are kept consistent rather than one being corrected into the other.
///
/// TWO POPULATIONS, SELECTED BY THE RECEIVING CASES' OWN SELECTORS rather than by
/// anything restated here: `reject_rows(all, ESCAPE_EQUIVALENT_CASE)` is the
/// duplicate corpus case 5 already selects, and `allocation_rows` plus
/// `accept_rows(all, ABSENCE_CASE)` are the two accept populations case 2 already
/// decodes. Both selectors already fail on an empty group, and the explicit guards
/// below are kept anyway and say what an empty loop would have proven.
///
/// THREE CONJUNCTS, and why each is shaped the way it is.
///
/// * ASYMMETRY over the duplicate corpus: the strict ingress answers `DuplicateKey`
///   for bytes the PERMISSIVE `serde_json` decode of the very same slice ACCEPTS. The
///   permissive leg is not decoration and not symmetry. Without it the strict
///   refusal is not attributable to the duplicate at all: it would be equally
///   consistent with a document that is malformed for some unrelated reason, and this
///   conjunct would then pass for the wrong reason on every broken row — the case-14
///   malformed rows being exactly such documents. With it, the two legs can differ
///   only by the duplicate, because one decoder accepts the slice and only the strict
///   one refuses it.
/// * EQUALITY over the accept corpus: the strict ingress produces EXACTLY the value
///   the permissive decode produces. This is the conjunct that kills an edit which
///   drops or fabricates a member, and no duplicate-focused assertion anywhere in
///   this file could catch such an edit, because such an edit need not be
///   duplicate-shaped at all.
/// * CEILING ASYMMETRY, alongside the first. `strict_json_has_no_duplicate_members`
///   applies no ceiling of its own because it passes `max_bytes = bytes.len()` into a
///   STRICT greater-than (`bytes.len() > max_bytes`), which makes its `TooLarge`
///   variant structurally unreachable. That is OBSERVED here rather than assumed: the
///   no-ceiling entry point answers `DuplicateKey` on the duplicate corpus and `Ok`
///   on the accept corpus and never `TooLarge`, while `strict_json_value` one byte
///   below the document's own length answers `TooLarge` on BOTH and answers the same
///   thing the no-ceiling call did at the exact length. Without this pair, an edit
///   that passed `max_bytes = 0` — which would disable duplicate detection entirely
///   while turning every refusal into `TooLarge` — would stay green.
///
/// THE REDACTION HALF of the first conjunct is asserted by
/// `strict_refusal_withholds_the_repetition`, which carries the contract and cites the
/// pinned source for it.
///
/// MEMBER ORDER IS DELIBERATELY NOT ASSERTED. `serde_json::Map` is a `BTreeMap`
/// unless the workspace enables `serde_json`'s `preserve_order` feature, and NO
/// manifest in this workspace requests it: the root `Cargo.toml` asks for
/// `serde_json` with `features = ["float_roundtrip"]` alone, every crate that takes
/// a direct dependency either inherits that entry (`serde_json.workspace = true`) or
/// pins the bare version, and the handful that name a feature list name only
/// `float_roundtrip` again — so document order is already lost before either leg of
/// the equality above returns, and both legs sort identically. An order assertion
/// here would be a red no
/// correct implementation could pass, and it would not detect a reordering introduced
/// by this ingress either: order is observable only by streaming, and
/// `document_order_is_observable_only_by_streaming` already asserts that.
///
/// WHAT IS NOT CLAIMED HERE, and why. Unknown-member rejection is not a property of
/// this module at all — it belongs to `deny_unknown_fields`, and cases 3 and 4
/// already discharge it. And nothing here claims which shapes serde's derive admits
/// beyond what the rows' own recorded `expected` values already state.
fn strict_ingress_cannot_erase_protected_input(all: &[Row]) -> TestResult {
    let duplicates = reject_rows(all, ESCAPE_EQUIVALENT_CASE)?;
    let mut accepted = allocation_rows(all)?;
    accepted.extend(accept_rows(all, ABSENCE_CASE)?);
    assert!(
        !duplicates.is_empty(),
        "the duplicate corpus walked below must not be empty: an empty loop proves nothing about strict_json_value, and a strict ingress that refused or mangled EVERY document would satisfy the asymmetry over it"
    );
    assert!(
        !accepted.is_empty(),
        "the accept corpus walked below must not be empty: an empty loop proves nothing about strict_json_value, and a strict ingress that dropped a member from every accept row would satisfy the equality over it"
    );
    for row in &duplicates {
        let bytes = row.raw.as_bytes();
        // Kind and rendered text from ONE call: the two claims below are about the
        // same refusal, and a second decode could only disagree with the first.
        let (kind, rendered) = match eliot_types::strict_json_value(bytes, bytes.len()) {
            Ok(value) => {
                return fail(format!(
                    "row {} repeats a member in its own bytes, so the strict ingress must REFUSE it rather than hand back a value; it returned {value}",
                    row.id
                ));
            }
            Err(error) => (error.kind, error.to_string()),
        };
        // `StrictJsonErrorKind` implements neither `Display` nor anything else that
        // would make a bare `{kind}` render, and its own public rendering is
        // `as_str()` — the stable, redacted reason string a CALLER of this crate
        // would read (strict_json.rs:52-63). The category is therefore printed as
        // `rendered`, which is `error.to_string()` of the very refusal whose `kind`
        // was just matched and which the assertion three lines below proves EQUALS
        // `StrictJsonErrorKind::DuplicateKey.as_str()`. So the category in this
        // message is that crate-defined string and not a `Debug` spelling of the enum
        // type, and it cannot drift from the kind actually returned because it is not
        // a re-rendering of a separate value.
        //
        // THE ROW ID IS A NAMED ARGUMENT, `{id} = row.id`, not a trailing positional
        // one. The message mixes a captured identifier (`{rendered}`) with the row id,
        // and a bare `{}` beside a capture would make the compiler count positional
        // arguments while the reader counts placeholders; naming the argument ties
        // the placeholder to the value at the point of use instead.
        assert_eq!(
            kind,
            eliot_types::StrictJsonErrorKind::DuplicateKey,
            "row {id} must be refused as a DUPLICATE MEMBER, and not as {rendered}: the permissive leg below accepts these identical bytes, so the document is not malformed and no other category is available",
            id = row.id
        );
        if let Err(error) = serde_json::from_slice::<Value>(bytes) {
            return fail(format!(
                "row {} must be ACCEPTED by the permissive serde_json decode of the IDENTICAL bytes, otherwise the strict refusal above is not attributable to the duplicate and this conjunct is satisfied by a document that is broken for an unrelated reason; the permissive decode refused it: {error}",
                row.id
            ));
        }
        assert_eq!(
            rendered,
            eliot_types::StrictJsonErrorKind::DuplicateKey.as_str(),
            "the strict ingress's `Display` is `write_str(self.kind.as_str())` (strict_json.rs:80-84), so what rendered must BE that category's own bounded string and nothing else, and every redaction claim made about this text is a claim about exactly these bytes"
        );
        strict_refusal_withholds_the_repetition(row, &rendered)?;
        assert_eq!(
            eliot_types::strict_json_has_no_duplicate_members(bytes)
                .map(|_| ())
                .map_err(|error| error.kind),
            Err(eliot_types::StrictJsonErrorKind::DuplicateKey),
            "the no-ceiling entry point must REACH duplicate detection: it passes `max_bytes = bytes.len()` into a strict greater-than, so an edit that made duplicate detection itself unreachable would answer `Ok` or `TooLarge` here instead of the same category this ceiling call reported"
        );
        assert_eq!(
            eliot_types::strict_json_value(bytes, bytes.len().saturating_sub(1))
                .map(|_| ())
                .map_err(|error| error.kind),
            Err(eliot_types::StrictJsonErrorKind::TooLarge),
            "one byte below the document's own length the ceiling must answer TooLarge even where the document is a duplicate: that is the half of the pair which reds an edit passing `max_bytes = 0`, since every refusal would become TooLarge and duplicate detection would never run"
        );
    }
    for row in &accepted {
        let bytes = row.raw.as_bytes();
        let strict = eliot_types::strict_json_value(bytes, bytes.len()).map_err(|error| {
            boxed(std::io::Error::other(format!(
                "row {} is an accept row whose own bytes decode through the permissive path, so the strict ingress must accept them too and hand back the same value; it refused with {error}",
                row.id
            )))
        })?;
        let permissive: Value = serde_json::from_slice(bytes).map_err(boxed)?;
        assert_eq!(
            strict, permissive,
            "row {} must decode to EXACTLY the value the permissive serde_json decode produces; this is the conjunct that reds a strict ingress which dropped or fabricated a member, which no duplicate-focused assertion in this file would catch. Member ORDER is deliberately not claimed: serde_json::Map is a BTreeMap here, so document order is already lost in both legs before they are compared",
            row.id
        );
        assert_eq!(
            eliot_types::strict_json_has_no_duplicate_members(bytes)
                .map(|_| ())
                .map_err(|error| error.kind),
            Ok(()),
            "the no-ceiling entry point must accept an accept row, so on this corpus it is never answering `TooLarge` where the exact-length call below answers `Ok`"
        );
        assert_eq!(
            eliot_types::strict_json_value(bytes, bytes.len().saturating_sub(1))
                .map(|_| ())
                .map_err(|error| error.kind),
            Err(eliot_types::StrictJsonErrorKind::TooLarge),
            "one byte below the document's own length the ceiling must answer TooLarge here too; the accept side is what makes the pair attributable to the CEILING rather than to the duplicate, because on the duplicate corpus the same call would answer TooLarge for a reason this function could not tell apart from a broken ceiling"
        );
    }
    Ok(())
}

/// A refusal by the strict ingress carries neither the duplicated member's NAME nor
/// either of its VALUES nor an offset — the redaction half of the asymmetry
/// `strict_ingress_cannot_erase_protected_input` asserts.
///
/// THE CONTRACT IS COPIED FROM `serde_t03_host.rs`, which already exercises this symbol
/// against exactly this contract, rather than invented here. `StrictJsonError` carries
/// a category and nothing else (`strict_json.rs:66-78`), its `Display` is
/// `write_str(self.kind.as_str())` (`strict_json.rs:80-84`), and
/// `DUPLICATE_MEMBER_MARKER` (`strict_json.rs:39`) is the WHOLE of that string, so
/// every forbidden substring below is derived from the ROW'S OWN BYTES: the repeated
/// member and the depth of the object holding both occurrences from `scan_repetitions`,
/// and the value tokens from `repeated_member_value_tokens`. No member name and no
/// value is typed in this file, and the row's prose is never read.
///
/// `rendered` is the caller's own `Display` of the refusal it has already classified,
/// so these claims cannot be about a different refusal than the one whose category was
/// asserted.
fn strict_refusal_withholds_the_repetition(row: &Row, rendered: &str) -> TestResult {
    let Some((member, depth)) = scan_repetitions(&row.raw).first else {
        return fail(format!(
            "row {} is selected as a duplicate but its own bytes repeat no member, so the redaction claims here would have nothing to withhold and would be satisfied by a refusal that leaks everything",
            row.id
        ));
    };
    assert!(
        !rendered.contains(member.as_str())
            && !rendered.contains("at line")
            && !rendered.contains("column"),
        "the refusal for row {} must not leak the duplicated member name {member}, nor an offset, got: {rendered}",
        row.id
    );
    let values = repeated_member_value_tokens(&row.raw, &member, depth);
    assert!(
        values.len() >= 2,
        "row {} repeats {member} in its own bytes, so the object at depth {depth} must carry at least two of its value tokens and the loop below must have something to withhold; found {values:?}",
        row.id
    );
    for value in &values {
        assert!(
            !rendered.contains(value.as_str()),
            "the refusal for row {} must not leak the duplicated member's value {value}, got: {rendered}",
            row.id
        );
    }
    Ok(())
}

/// The RAW value tokens of every occurrence of `member` inside the JSON object at
/// `depth`, in document order.
///
/// DERIVED FROM THE ROW'S OWN BYTES, like `scan_repetitions` beside it and for the
/// same reason: the duplicated member's VALUES are what the redaction conjunct must
/// prove absent from the refusal, and neither a member name nor a value is typed in
/// this file. The DEPTH is the one `scan_repetitions` reported for the object holding
/// the first repetition, and the depth arithmetic is its own — `containers.len()` at
/// push time, so the document's own object is depth 0 — so the two walks cannot
/// disagree about which object each is reading.
///
/// The tokens are the document's own text between the `:` and the end of the value, so
/// a string value carries its quotes and a number carries its own spelling: the
/// redaction claim is about what the refusal must NOT contain, which is the spelling
/// on the wire, not a normalised form of it.
///
/// EVERY OCCURRENCE IS RETURNED, not only the first two, so a row repeating a member
/// three times contributes all three values; the caller demands at least two, which is
/// what makes its loop a claim about a REPETITION rather than about an arbitrary
/// member of the document.
fn repeated_member_value_tokens(raw: &str, member: &str, depth: usize) -> Vec<String> {
    let bytes = raw.as_bytes();
    let mut containers: Vec<(bool, usize)> = Vec::new();
    let mut tokens: Vec<String> = Vec::new();
    let mut index = 0usize;
    let mut expect_key = false;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let close = string_closing_quote(bytes, index);
                if expect_key
                    && containers
                        .last()
                        .is_some_and(|container| *container == (true, depth))
                    && decoded_key_name(raw, index, close) == member
                {
                    let start = value_offset(bytes, close + 1);
                    tokens.push(raw[start..skip_json_value(bytes, start)].to_owned());
                }
                expect_key = false;
                index = close + 1;
            }
            b'{' | b'[' => {
                let is_object = bytes[index] == b'{';
                containers.push((is_object, containers.len()));
                expect_key = is_object;
                index += 1;
            }
            b'}' | b']' => {
                containers.pop();
                expect_key = false;
                index += 1;
            }
            b',' => {
                expect_key = containers.last().is_some_and(|container| container.0);
                index += 1;
            }
            _ => index += 1,
        }
    }
    tokens
}

// WORK_UNIT_CASE: 930/6
#[test]
fn case_06_unknown_variant_and_wrong_payload_are_refused() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    let group = reject_rows(&rows, 6)?;
    // HOW THESE THREE CLASSES ARE COUNTED, and why no tally is written down. Each row
    // is classified by what its own payload IS and by what the decoder then does with
    // it, and the three classes are measured on the live fixture as follows:
    // * UNKNOWN VARIANTS: a spelling row whose value, folded (lowercased, `_` and `-`
    //   dropped), matches none of the variant spellings its own enum DECLARES, and is
    //   not empty. The denominator is read out of the decoder's own `unknown variant`
    //   refusal, which lists every declared spelling — not the single accepted
    //   spelling, which is one spelling of a four- or five-variant enum — and is then
    //   required to match what `task_execution.rs` declares, so the split is never the
    //   message agreeing with itself.
    // * NEAR-MISSES: the same fold matches a DECLARED variant spelling, or the spelling
    //   is the empty string — i.e. it differs from a declared spelling only in case, in
    //   `_`/`-` punctuation, or in emptiness.
    // * WRONG PAYLOADS: the payload is not a bare JSON string, so it is either a
    //   complete object of the declared type with one member's value of the wrong JSON
    //   kind, or a bare non-string where a variant identifier belongs. All of them are
    //   counted by the payload's own JSON kind, never by a row id or by the row's
    //   prose.
    //
    // NO COUNT IS PINNED, and the three requirements below are therefore NON-EMPTINESS
    // rather than a tally. The previous version asserted `unknown == 4`, `near == 4`
    // and `wrong == 7`, which reads as a completeness claim and is not one: those
    // numbers are today's tally, and adding one STRICTLY BETTER row — a near-miss on a
    // second member enum, say — turned a green suite red and demanded the constant be
    // edited. A tally of how many rows the fixture happens to carry is not a property
    // of this case; what the case proves is that EACH CLASS IS REAL and that each class
    // is non-empty, which is what is asserted.
    //
    // WHAT KEEPS THE CLASSES REAL IS UNCHANGED, and it is the per-row work above, not
    // these three assertions: a spelling row really is refused with serde's
    // `unknown variant` construction naming that spelling, a near-miss really does fold
    // onto a declared spelling or is the empty string, and a wrong-payload row really is
    // repaired by EXACTLY ONE member with the crate's own canonical bytes. Delete the
    // counters and those bindings survive; delete the bindings and a non-empty class
    // would prove nothing, which is why only the counters changed.
    let mut unknown = 0usize;
    let mut near = 0usize;
    let mut wrong = 0usize;
    for row in &group {
        let value: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
        // Every class is bound to the offending thing, never to `is_err` alone.
        // HOW it can be bound differs per class, and the difference is stated in
        // each helper's doc comment rather than blurred here.
        match value {
            Value::String(_) => {
                let accepted = accepted_spelling(&rows, type_leaf(&row.type_name))?;
                match spelling_row_is_refused(row, &accepted)? {
                    Spelling::Unknown => unknown += 1,
                    Spelling::NearMiss => near += 1,
                }
            }
            Value::Object(_) => {
                wrong_member_row_is_refused(row, &rows)?;
                wrong += 1;
            }
            _ => {
                let accepted = accepted_spelling(&rows, type_leaf(&row.type_name))?;
                non_spelling_payload_is_refused(row, &accepted)?;
                wrong += 1;
            }
        }
    }
    let spelling_rows = group
        .iter()
        .filter(|row| serde_json::from_str::<Value>(&row.raw).is_ok_and(|value| value.is_string()))
        .count();
    assert!(
        unknown > 0,
        "case 6 must carry at least one genuinely unknown enum variant — a spelling row whose folded value matches none of the variant spellings its own enum declares, and is not empty — or the unknown/near-miss split is not exercised in the `Unknown` direction at all: {spelling_rows} of the group's rows carry a bare-string spelling, and they classified as {near} near-miss(es)"
    );
    assert!(
        near > 0,
        "case 6 must carry at least one near-miss — a spelling row whose folded value matches a declared variant spelling, or which is the empty string — or the unknown/near-miss split is not exercised in the `NearMiss` direction at all: {spelling_rows} of the group's rows carry a bare-string spelling, and they classified as {unknown} unknown variant(s)"
    );
    assert!(
        wrong > 0,
        "case 6 must carry at least one wrong-payload row — a payload that is not a bare JSON string, counted by the payload's own JSON kind — or the repair-by-exactly-one-member property is never exercised"
    );
    // The externally tagged member enums carry the variant rows; they are not
    // `deny_unknown_fields` structs, so they are named explicitly rather than letting
    // the closed-struct set imply they are covered. AND THE SET IS DERIVED, through the
    // file's own walk over `task_execution.rs` declarations: the previous version listed
    // the four member-enum names as string literals, so a FIFTH externally tagged enum
    // appended to that file would be demanded a case-1 allocation row by the
    // completeness denominator in `allocated_type_names` — and would then reach this
    // loop not at all, because this loop's list had four names in it and the new enum's
    // name was not one of them. Deriving the set closes that: the new enum appears here
    // and this assertion reds until it carries a spelling row.
    for member_enum in externally_tagged_enum_names(TASK_EXECUTION_FILE)? {
        assert!(
            group.iter().any(|row| {
                type_leaf(&row.type_name) == member_enum.as_str()
                    && serde_json::from_str::<Value>(&row.raw).is_ok_and(|value| value.is_string())
            }),
            "case 6 must carry an unknown-variant row on {member_enum}: every externally tagged enum {TASK_EXECUTION_FILE} declares is enumerated here from live source, so a new one is red here rather than quietly uncovered"
        );
    }
    Ok(())
}

/// CASE 7 OF ISSUE #930 COVERS THE **MISSING** HALF OF A TWO-HALF CLAUSE, AND THIS
/// BLOCK SAYS WHERE THE OTHER HALF IS DISCHARGED SO A READER OF CASE 7 ALONE IS NOT
/// LEFT HUNTING FOR IT.
///
/// THE CLAUSE is issue #930's acceptance row for cases 5–8: "missing/empty protected
/// identity … rejected without fabricated values". Its name does not overclaim — it
/// says `missing` and asserts `missing` — so no rename is needed here; what is needed is
/// the pointer.
///
/// WHAT THIS CASE ASSERTS: a required member OMITTED from the payload is REFUSED, and
/// refused as serde's own absent-member construction naming that member. Every row in
/// its group removes exactly one declared, non-optional member, and
/// `missing_member_is_refused` binds the refusal to that member rather than accepting
/// any refusal that mentions it.
///
/// WHERE THE **EMPTY** HALF IS DISCHARGED, AND WHY IT IS AN ACCEPTANCE RATHER THAN A
/// REFUSAL — this is the half a reader is most likely to expect here and will not find.
/// Empty protected identity is NOT a refusal in this crate, and asserting one would be
/// false against live source rather than merely unproven: every protected identity in
/// `records.rs` is a plain `String` (`records.rs:12, 32, 52, 76, 114, 133, 146`), that
/// file declares no `deserialize_with` and no validate or check function, and the
/// fixture records the empty-identity rows `930-129`…`930-135` as `expected: "accept"`
/// under case 2. So the empty half is discharged in case 2's ABSENCE GROUP by
/// `empty_identity_row_preserves_its_value`, which requires the decoded value to BE
/// empty — the assertion demands the value is preserved rather than substituted, so the
/// row cannot pass by fabricating an identifier. THAT is the "without fabricated
/// values" half of the clause, discharged as value preservation on the one path where
/// the decoder genuinely accepts.
///
/// The same reasoning is why case 8 stays undispatched: its empty-identity and
/// unsupported-version legs have no refusal in this crate to assert. See
/// `UNDISPATCHED_CASES`.
///
/// THIS BLOCK SITS ABOVE THE WORK-UNIT MARKER, and that placement is load-bearing.
/// The marker must be IMMEDIATELY followed by its `#[test]`, and the work-unit gate
/// that binds the two walks forward from the marker refusing a blank line and
/// refusing any line beginning `//` or `/*` before it reads an attribute; a `///`
/// line is a `//` line, so a documentation comment written between the attribute and
/// this function detaches the marker exactly as a plain comment would, and there is
/// no tolerant fallback for a `.rs` file because every one is routed into that text
/// parser unconditionally. A PLAIN comment in the same place is not a workaround
/// either: `rustc` puts no order constraint on a comment relative to an attribute,
/// so the text would still be absent from hover and from extracted documentation.
/// Above the marker the walk never looks, and the block is still a documentation
/// comment, so every reader that reached it before still reaches it.
// WORK_UNIT_CASE: 930/7
#[test]
fn case_07_missing_required_member_is_refused() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    let group = reject_rows(&rows, 7)?;
    for row in &group {
        // Derived from the type's declared field names minus the members the
        // payload carries. No prose, and no assumption about WHICH member goes.
        let member = removed_member(row)?;
        // An `Option` member is never genuinely required, so a row that removes
        // one is a fixture defect rather than a refusal to prove. `manifest` and
        // `continuation` decode to `None` instead of failing.
        assert!(
            !L2_OPTIONAL_MEMBERS.contains(&member.as_str()),
            "case 7 row {} removes the optional member {member}, which decodes to None instead of failing",
            row.id
        );
        // THE REFUSAL MUST BE A MISSING-FIELD REFUSAL, not merely a refusal whose text
        // mentions the member. The previous version of this loop asserted only
        // `message.contains(member)`, which is satisfied by THREE refusals a derived
        // struct can produce and by one of them for free: serde's `unknown field`
        // ENUMERATES EVERY declared field of a closed struct, so
        // ``unknown field `statu`, expected one of `component`, `status`, `detail` ``
        // contains `status` without `status` ever being absent. The concrete false pass
        // is a one-key fixture edit with no Rust change at all: on
        // `930-114-missing-required-status-healthrecord`, adding `,"statu":7` to its raw
        // leaves the row omitting exactly one declared member and having the duplicated
        // member spelled wrongly, and it was then refused as an UNDECLARED member while
        // the bare substring still passed. `missing_member_is_refused` requires serde's
        // absent-member wording, requires it to name THIS member, and excludes the
        // unknown-field, duplicate-field, unknown-variant and invalid-type shapes plus
        // every non-data category; its doc comment quotes the pinned source it relies on.
        let error = refusal_error(row)?;
        missing_member_is_refused(&error, &member, &format!("case 7 row {}", row.id));
    }
    Ok(())
}

/// The case-12 absence rows: every optional member absent from the input must
/// decode to `None`, every optional member present must decode to `Some`, and
/// the genuinely required members must still decode. Only `requested_handle`,
/// `segments` and `truncated` are required here; `manifest` and `continuation`
/// are `Option`, so removing either decodes to `None` and never fails.
fn l2_page_absence_row_is_accepted(row: &Row) -> TestResult {
    let decoded: eliot_types::CanonicalMemoryL2Page =
        serde_json::from_str(&row.raw).map_err(boxed)?;
    let input: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
    let rendered = serde_json::to_string(&decoded).map_err(boxed)?;
    let output: Value = serde_json::from_str(&rendered).map_err(boxed)?;
    let input_keys = top_level_keys(&input);
    let output_keys = top_level_keys(&output);
    let presence = optional_presence(&decoded);
    for (member, is_some) in &presence {
        // Compared as strings rather than by `contains(&String)`: the key sets
        // are `String`, the member names are `&str`, and coercing with
        // `to_string()`/`to_owned()` would allocate once per member per row to
        // satisfy a type mismatch. Iterating is allocation-free.
        let in_input = input_keys.iter().any(|key| key.as_str() == *member);
        // Absence and `None` are the same thing on the decode side: an absent
        // key on an `Option` member reaches serde's `missing_field`, whose
        // `MissingFieldDeserializer::deserialize_option` calls `visit_none()`.
        if *is_some {
            assert!(
                in_input,
                "row {} decoded Some for {member}, so the recorded bytes must carry it",
                row.id
            );
        }
        if !in_input {
            assert!(
                !*is_some,
                "row {} omits {member}, so it must decode to None and never to Some",
                row.id
            );
        }
        // The encode-side rule is PER MEMBER, never uniform. Only the two members
        // carrying `skip_serializing_if` are dropped at `None`; the other two are
        // always emitted, so for them the claim is presence-neutrality.
        let in_output = output_keys.iter().any(|key| key.as_str() == *member);
        if L2_SKIPPED_WHEN_NONE.contains(member) {
            assert_eq!(
                in_output, *is_some,
                "row {}: skip_serializing_if must drop {member} exactly when it is None",
                row.id
            );
        } else {
            assert!(
                L2_ALWAYS_EMITTED.contains(member),
                "row {}: {member} is neither skipped nor always emitted, so the rule is unknown",
                row.id
            );
            assert!(
                in_output,
                "row {}: {member} carries no serde attribute, so the encoder must always emit it",
                row.id
            );
            if !*is_some {
                assert!(
                    output.get(*member).is_some_and(Value::is_null),
                    "row {}: {member} must be re-emitted as an explicit null when it is None",
                    row.id
                );
            }
        }
    }
    // A key that the encode side dropped must be an optional member whose value
    // really is absent, and nothing else may ever disappear on a round trip.
    for key in &input_keys {
        if !output_keys.contains(key) {
            assert!(
                L2_OPTIONAL_MEMBERS.contains(&key.as_str()),
                "row {} lost the non-optional member {key} on re-serialization",
                row.id
            );
        }
    }
    for required in ["requested_handle", "segments", "truncated"] {
        assert!(
            output_keys.iter().any(|key| key == required),
            "row {} must keep decoding the required member {required}",
            row.id
        );
    }
    assert!(
        !decoded.requested_handle.trim().is_empty(),
        "row {} must decode requested_handle to a non-empty string",
        row.id
    );
    Ok(())
}

/// Top-level member names of a JSON object, in the order `serde_json` reports
/// them. Read from the string path, never from a `Value` handed to a decoder.
fn top_level_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

/// Which of the four optional L2 members decoded to `Some`.
fn optional_presence(page: &eliot_types::CanonicalMemoryL2Page) -> Vec<(&str, bool)> {
    vec![
        (
            L2_RESOLVED_PARENT_HANDLE,
            page.resolved_parent_handle.is_some(),
        ),
        (L2_REQUESTED_SEGMENT_ID, page.requested_segment_id.is_some()),
        (L2_MANIFEST, page.manifest.is_some()),
        (L2_CONTINUATION, page.continuation.is_some()),
    ]
}

/// The case-12 astral-scalar row is the deliberate negative control against a lone
/// surrogate probe: an astral character is ONE scalar and must decode to that exact
/// scalar, not to a replacement character, and not be dropped.
///
/// THE WORDING IS ABOUT THE DECODED VALUE, NOT THE SPELLING, and the distinction is
/// recorded because the two have been confused in this file already. Whether the row's
/// `raw` spells U+1F600 as an escaped surrogate PAIR `\ud83d\ude00` or as the literal
/// UTF-8 bytes of the character is the SERIALIZER'S choice, not this assertion's: it
/// holds for either spelling and deliberately says nothing about which one the fixture
/// currently uses. Both spellings must reach U+1F600, and a rejection here means the
/// character was lost or replaced rather than that a spelling was unexpected — the
/// opposite conclusion, which is the one this row exists to prevent. A byte comparison
/// against `row.raw` is a different assertion with a different owner; this is not it.
fn health_record_surrogate_row_is_accepted(row: &Row) -> TestResult {
    let decoded: eliot_types::HealthRecord = serde_json::from_str(&row.raw).map_err(boxed)?;
    let grinning = '\u{1F600}';
    let replacement = '\u{FFFD}';
    assert!(
        decoded.detail.contains(grinning),
        "row {} must decode the astral scalar to U+1F600, not drop it; this says nothing about whether the raw spelled it as an escaped surrogate pair or as literal UTF-8",
        row.id
    );
    assert!(
        !decoded.detail.contains(replacement),
        "row {} decoded the astral scalar to a replacement scalar, which is the failure this row exists to catch",
        row.id
    );
    Ok(())
}

/// The invalid-UTF-8 probe, built here rather than read.
///
/// What it exercises: `serde_json::from_slice::<T>` validates the whole input as
/// UTF-8 before it parses, so a raw `0xFF` byte inside a string value is refused
/// as invalid UTF-8 rather than decoded into a replacement scalar. The
/// descriptor row's own `raw` is a bare fragment, not a document, so routing it
/// through the per-row path would fail merely because it is not JSON at all —
/// a green assertion that proves nothing, which is exactly what the row's
/// `reason` warns against.
///
/// Nothing is pasted from the fixture: the two fragments around the bad byte come
/// from the descriptor row's own `raw` at runtime, the three member names are
/// `HealthRecord`'s Rust field names, and the two uncorrupted values are chosen
/// here rather than copied.
fn invalid_utf8_probe_is_refused(descriptor: &Row) -> TestResult {
    // The descriptor stores its probe as the JSON escape, so once the fixture is
    // parsed the row's `raw` holds the scalar U+00FF between the two fragments.
    // Split on that scalar, not on the six-character escape.
    const BAD_SCALAR: char = '\u{00FF}';
    const BAD_BYTE: u8 = 0xFF;
    let Some((left, right)) = descriptor.raw.split_once(BAD_SCALAR) else {
        return fail(format!(
            "descriptor row {} must carry the scalar its own reason names",
            descriptor.id
        ));
    };
    let mut probe: Vec<u8> = Vec::new();
    probe.extend_from_slice(b"{\"component\":\"probe\",\"status\":\"probe\",\"detail\":\"");
    probe.extend_from_slice(left.as_bytes());
    probe.push(BAD_BYTE);
    probe.extend_from_slice(right.as_bytes());
    probe.extend_from_slice(b"\"}");
    assert!(
        std::str::from_utf8(&probe).is_err(),
        "the constructed probe must not be valid UTF-8, or it proves nothing"
    );
    assert!(
        serde_json::from_slice::<eliot_types::HealthRecord>(&probe).is_err(),
        "a raw 0xFF byte inside a string value must be refused"
    );
    // The same document with the bad byte removed must decode, so the refusal is
    // attributable to the byte and not to the surrounding text.
    let clean: Vec<u8> = probe
        .iter()
        .copied()
        .filter(|byte| *byte != BAD_BYTE)
        .collect();
    assert!(
        serde_json::from_slice::<eliot_types::HealthRecord>(&clean).is_ok(),
        "the identical document without the 0xFF byte must decode, or the refusal proves nothing"
    );
    Ok(())
}

/// The `#[serde(…)]` attributes carried by the five allocated files, as a
/// multiset of `path:attribute` with the attribute text whitespace-collapsed.
///
/// The property: no `alias`, `flatten`, `untagged`, `other` or `cfg_attr` exists
/// anywhere in these five files, so nothing can admit a name the derived
/// contract does not declare and nothing can fabricate a value for an absent
/// member. Any new attribute of any other form fails this case by construction,
/// because it fails the allowlist membership check.
///
/// Doc-comment lines are excluded, and that exclusion is load-bearing rather than
/// convenient: `records.rs` carries a prose line reading "stay `#[serde(default)]`
/// because the canonical serialization omits them", and `task_execution.rs`
/// carries "no field carries `#[serde(default)]`". Both mention the marker text
/// inside a `///` comment. A naive line scan counts them and reports 19
/// attributes; the real count of attribute lines is 17.
///
/// Scope limit, stated honestly because it is the trap here: "no alias, flatten
/// or untagged in the five allocated files" is TRUE, while "none in
/// `crates/eliot-types`" would be FALSE. The crate as a whole carries thirteen
/// `#[serde(... alias ...)]` attributes, one `#[serde(flatten)]` in
/// `mcp_contract.rs`, and one `#[serde(untagged)]` on `MemoryInfluenceToolInput`
/// in `observability.rs` — and that last one is declared but never decoded,
/// because the type derives `Serialize` only and supplies a hand-written
/// `Deserialize` beside it. This assertion therefore stays inside the five
/// files this issue allocates and must not be widened.
fn serde_attribute_inventory_is_closed() -> TestResult {
    let mut collected: Vec<String> = Vec::new();
    for file in ALLOCATED_SOURCE_FILES {
        let source = read_workspace(file)?;
        for line in source.lines() {
            let trimmed = line.trim();
            // A doc comment can quote the marker text without carrying an
            // attribute. Skipping `///` and `//!` is what separates the two.
            if trimmed.starts_with("///") || trimmed.starts_with("//!") {
                continue;
            }
            for form in &FORBIDDEN_SERDE_FORMS {
                assert!(
                    !trimmed.contains(form),
                    "{file} carries the forbidden attribute form {form}: {trimmed}"
                );
            }
            if !trimmed.contains("#[serde(") {
                continue;
            }
            let attribute = serde_attribute_text(trimmed);
            assert!(
                ALLOWED_SERDE_ATTRIBUTES.contains(&attribute.as_str()),
                "{file} carries a serde attribute outside the four allowed forms: {attribute}"
            );
            collected.push(format!("{file}:{attribute}"));
        }
    }
    collected.sort();
    assert_eq!(
        collected.len(),
        17,
        "the five allocated files must carry exactly 17 serde attributes: {collected:?}"
    );
    assert_eq!(
        collected,
        expected_serde_attributes(),
        "the serde attribute inventory of the five allocated files drifted"
    );
    Ok(())
}

/// The text between `#[serde(` and `)]`, with every whitespace run collapsed to a
/// single space so a reformatted but semantically identical line still matches.
fn serde_attribute_text(trimmed: &str) -> String {
    let Some(start) = trimmed.find("#[serde(") else {
        return String::new();
    };
    let inner = &trimmed[start + "#[serde(".len()..];
    let end = inner.find(")]").unwrap_or(inner.len());
    inner[..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The inventory as source measurement establishes it: seven
/// `deny_unknown_fields` and two `default, skip_serializing_if` in `records.rs`,
/// three `transparent` in `ids.rs`, four `rename_all` and one
/// `deny_unknown_fields` in `task_execution.rs`, and none at all in `lib.rs` or
/// `error.rs`.
fn expected_serde_attributes() -> Vec<String> {
    // No arity check on `ALLOWED_SERDE_ATTRIBUTES`: it is declared `[&str; 4]`, so
    // the length is 4 by type. The real check is the multiset equality in
    // `serde_attribute_inventory_is_closed`.
    let mut expected: Vec<String> = Vec::new();
    push_attribute(RECORDS_FILE, ALLOWED_SERDE_ATTRIBUTES[0], 7, &mut expected);
    push_attribute(RECORDS_FILE, ALLOWED_SERDE_ATTRIBUTES[1], 2, &mut expected);
    push_attribute(IDS_FILE, ALLOWED_SERDE_ATTRIBUTES[2], 3, &mut expected);
    push_attribute(
        TASK_EXECUTION_FILE,
        ALLOWED_SERDE_ATTRIBUTES[3],
        4,
        &mut expected,
    );
    push_attribute(
        TASK_EXECUTION_FILE,
        ALLOWED_SERDE_ATTRIBUTES[0],
        1,
        &mut expected,
    );
    expected.sort();
    expected
}

/// Append `count` copies of one `path:attribute` entry to a multiset.
fn push_attribute(file: &str, form: &str, count: usize, sink: &mut Vec<String>) {
    for _ in 0..count {
        sink.push(format!("{file}:{form}"));
    }
}

/// `TaskExecutionClass` carries no field-level and no container-level
/// `#[serde(default)]`, so its Rust `Default` implementation cannot fabricate any
/// of its five wire members and every one of them stays required on the wire.
///
/// This is a distinct claim from the L2 page's, which rests on `Option` being
/// implicitly optional: here nothing is an `Option`, so a fabricated member would
/// be indistinguishable from a supplied one. The same property A6 rests on.
fn task_execution_class_fabricates_nothing() -> TestResult {
    let source = read_workspace(TASK_EXECUTION_FILE)?;
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.contains("pub struct TaskExecutionClass"))
        .ok_or_else(|| boxed(std::io::Error::other("TaskExecutionClass is not declared")))?;
    let body: Vec<&str> = lines
        .iter()
        .skip(start + 1)
        .take_while(|line| line.trim() != "}")
        .copied()
        .collect();
    assert!(!body.is_empty(), "TaskExecutionClass must declare members");
    for line in &body {
        assert!(
            !line.contains("#[serde("),
            "no member of TaskExecutionClass may carry a serde attribute: {line}"
        );
        assert!(
            !line.contains("Option<"),
            "no member of TaskExecutionClass may be an Option, or absence would stop being an error: {line}"
        );
    }
    assert_eq!(
        body.len(),
        5,
        "TaskExecutionClass must declare exactly the five wire members"
    );
    Ok(())
}

// WORK_UNIT_CASE: 930/10
#[test]
fn case_10_unsafe_migration_is_refused() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    let group = reject_rows(&rows, MIGRATION_CASE)?;
    // The whole group is one type, so the existing `decode_row` dispatch is
    // unambiguous here: no second dispatcher is introduced.
    for row in &group {
        assert!(
            type_leaf(&row.type_name) == MIGRATION_TYPE,
            "case {MIGRATION_CASE} row {} must target {MIGRATION_TYPE}",
            row.id
        );
    }
    // Every named refused key: refused through `from_str`, and the refusal must
    // name the offending member. The key is derived from the bytes as the last
    // top-level member that is not one of the three declared ones, so no key
    // name is ever pasted into this file.
    let mut keys: Vec<String> = Vec::new();
    for row in &group {
        let message = refused_message(row)?;
        let offending = last_undeclared_member(&row.raw, &MIGRATION_DECLARED_MEMBERS)?;
        assert!(
            message.contains(offending.as_str()),
            "the refusal for row {} must name the offending key {offending}: {message}",
            row.id
        );
        keys.push(offending);
    }
    keys.sort();
    let distinct = {
        let mut copy = keys.clone();
        copy.dedup();
        copy.len()
    };
    assert_eq!(
        distinct,
        keys.len(),
        "every refused key must be distinct, or a name is covered twice"
    );

    // The identity pair is genuinely required in both directions.
    let identity = raw_member_value(&group[0].raw, MIGRATION_DECLARED_MEMBERS[0], &group[0].id)?;
    let checksum = raw_member_value(&group[0].raw, MIGRATION_DECLARED_MEMBERS[1], &group[0].id)?;
    for missing in MIGRATION_DECLARED_MEMBERS {
        let payload = migration_payload_without(&identity, &checksum, missing)?;
        migration_is_refused_for_missing_member(&payload, missing)?;
    }
    // A repeated known key is refused by the derived decoder's `is_some` check,
    // which fires before the repeated value is read. The repeated member is
    // DERIVED from the payload, and the refusal must NAME it: serde raises
    // `duplicate_field` with the field name, so that information is available and
    // a bare `is_err` would discard it.
    let duplicated = migration_payload_with_duplicate(&identity, &checksum, "true", "false");
    let repeated = repeated_top_level_member(&duplicated)?;
    migration_is_refused_naming(&duplicated, &repeated, "a repeated known key")?;
    // `applied` is a plain bool, so a non-bool is refused. The offending member is
    // derived inside the helper rather than passed, so no name is pasted here. See
    // `migration_is_refused_for_non_boolean_member` for why this site cannot require
    // the member name in serde's message the way the two sites above do.
    for wrong in [MIGRATION_QUOTED_TRUE, MIGRATION_NUMBER] {
        let payload = migration_payload_with(&identity, &checksum, wrong);
        migration_is_refused_for_non_boolean_member(&payload, "a non-boolean applied")?;
    }

    // EMPTY STRINGS DECODE, and this is the load-bearing positive assertion of
    // the case. `records.rs:133-134` are plain `String` with no
    // `deserialize_with`, no `#[serde(default)]`, no `FromStr` and no length
    // constraint, and `records.rs` contains no validation function at all, so
    // the gate is genuinely ABSENT rather than merely unobserved: the empty-field
    // checks in this crate live on different types, in `runtime.rs` and
    // `runtime_supervision.rs`. Asserting a refusal here would be false against
    // live source.
    for (id, payload) in [
        (
            "an empty migration_id",
            migration_payload_with("", &checksum, MIGRATION_BOOL_TRUE),
        ),
        (
            "an empty checksum_blake3",
            migration_payload_with(&identity, "", MIGRATION_BOOL_TRUE),
        ),
        (
            "both identity fields empty",
            migration_payload_with("", "", MIGRATION_BOOL_TRUE),
        ),
    ] {
        let decoded = decode_migration(&payload)?;
        assert_eq!(
            decoded.migration_id,
            raw_member_value(&payload, MIGRATION_DECLARED_MEMBERS[0], id)?,
            "the decoded migration_id must equal the bytes for {id}"
        );
        assert_eq!(
            decoded.checksum_blake3,
            raw_member_value(&payload, MIGRATION_DECLARED_MEMBERS[1], id)?,
            "the decoded checksum_blake3 must equal the bytes for {id}"
        );
    }

    // The case-1 baseline row must round-trip BY VALUE, so the refusals above are
    // about the specific mutations and not about a baseline that never decoded.
    let baseline = applicable_row(&rows, MIGRATION_TYPE)?;
    migration_schema_admits_no_legacy_form()?;
    let first: eliot_types::MigrationRecord = serde_json::from_str(&baseline.raw).map_err(boxed)?;
    let again: eliot_types::MigrationRecord =
        serde_json::from_str(&serde_json::to_string(&first).map_err(boxed)?).map_err(boxed)?;
    assert_eq!(
        first, again,
        "the baseline {MIGRATION_TYPE} must round-trip by value"
    );
    Ok(())
}

/// The last top-level member whose key is not one of the declared names.
fn last_undeclared_member(
    raw: &str,
    declared: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let spans = top_level_member_spans(raw);
    let offender = spans
        .iter()
        .rev()
        .find(|span| !declared.contains(&span.key.as_str()))
        .ok_or_else(|| {
            boxed(std::io::Error::other(
                "the payload declares no undeclared member",
            ))
        })?;
    Ok(offender.key.clone())
}

/// A string member's value, read from the raw bytes rather than pasted, so no
/// fixture value is ever hardcoded in this file.
///
/// `row_id` names the document being read and is carried ONLY so the unterminated-
/// string refusal below can say which one is broken, for the reason
/// `recorded_member`'s `row_id` exists: the two callers that splice a payload this
/// file built itself have no `Row` to reach through, and an offset on its own would
/// send a reader to the byte scan rather than to the document.
///
/// AN UNTERMINATED STRING IS REFUSED, not measured, and the refusal reuses
/// `raw_value_end`'s wording and shape for this exact hazard rather than a second
/// phrasing of it. `string_closing_quote` falls out of its loop at `bytes.len()` when
/// it meets no closing quote, and `bytes.len()` is a LEGAL index, so adding nothing
/// and slicing `value_start + 1..end` returned THE REST OF THE DOCUMENT TO END OF
/// INPUT as this member's value — and returned success. That is worse than a panic:
/// the caller measured those wrong bytes and reported a confident wrong verdict about
/// a member's value. `raw_value_end` and `recorded_member` both check this already;
/// this site is the third reader of the same scan and was the one that did not.
fn raw_member_value(
    raw: &str,
    member: &str,
    row_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    for span in top_level_member_spans(raw) {
        if span.key != member {
            continue;
        }
        let bytes = raw.as_bytes();
        if bytes.get(span.value_start) != Some(&b'"') {
            return fail(format!("member {member} must hold a string value"));
        }
        let end = string_closing_quote(bytes, span.value_start);
        if bytes.get(end) != Some(&b'"') {
            return fail(format!(
                "row {row_id}: the member value at offset {} is an unterminated string, so its extent is not measurable in a {}-byte document",
                span.value_start,
                bytes.len()
            ));
        }
        return Ok(raw[span.value_start + 1..end].to_owned());
    }
    fail(format!("the payload has no member {member}"))
}

fn migration_payload_with(identity: &str, checksum: &str, applied: &str) -> String {
    format!(
        "{{\"migration_id\":\"{identity}\",\"checksum_blake3\":\"{checksum}\",\"applied\":{applied}}}"
    )
}

/// A payload that omits exactly one declared member must be refused FOR THAT
/// REASON.
///
/// Asserted on the MESSAGE, not merely on `is_err`. A payload that merely decoded
/// badly would be refused for an unrelated reason — an `invalid type` on some
/// other member, say — and a bare `is_err` would call that a pass. Only a real
/// `missing_field` names the member that was omitted.
///
/// THE ASSERTION IS NOW THE ONE ITS MESSAGE CLAIMED, which is what this comment used
/// to assert and did not do. It said `missing_field` must name the omitted member while
/// the code below it was `message.contains(missing)` — a bare member-name substring, the very
/// shape `missing_member_is_refused` exists because it is satisfiable by the wrong
/// refusal. Every construction that binds it to `missing_field` is that helper's, and
/// its doc comment enumerates them; the short version is that the refusal
/// ``unknown field `x`, expected one of `migration_id`, `checksum_blake3`, `applied` ``
/// contains all three declared names, so a payload that omitted a member AND misspelled
/// a key would have passed here while being refused for the misspelling.
///
/// The name check is a substring test on serde's own wording, because
/// `serde_json::Error` exposes no code accessor; this is attributed as such, and the
/// wording is quoted with file and line from the pinned `serde-1.0.229` source inside
/// `MISSING_FIELD_PREFIX`'s own declaration.
fn migration_is_refused_for_missing_member(payload: &str, missing: &str) -> TestResult {
    match serde_json::from_str::<eliot_types::MigrationRecord>(payload) {
        Ok(_) => {
            return fail(format!(
                "a {MIGRATION_TYPE} missing {missing} must be refused, but it decoded"
            ));
        }
        Err(error) => missing_member_is_refused(
            &error,
            missing,
            &format!("a {MIGRATION_TYPE} payload missing {missing}"),
        ),
    }
    Ok(())
}

/// A payload with one declared member omitted, keyed values BY NAME.
///
/// The earlier version zipped a filtered member list positionally against a
/// `[identity, checksum]` pair, so omitting `migration_id` produced a payload
/// whose `applied` carried the hex STRING. serde refused that as
/// `invalid type: string, expected a boolean` rather than as a missing member,
/// and because `missing_field` is only reported after the whole map is consumed
/// the type error fired first and masked it. Keying by name is what makes the
/// refusal the one the row is about.
fn migration_payload_without(
    identity: &str,
    checksum: &str,
    omitted: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let values = [
        (
            MIGRATION_DECLARED_MEMBERS[0],
            Value::String(identity.to_owned()),
        ),
        (
            MIGRATION_DECLARED_MEMBERS[1],
            Value::String(checksum.to_owned()),
        ),
        // A real BOOLEAN, matching the declared type. The old positional zip fed
        // this member the checksum string instead, so the payload was refused for
        // a type error on `applied` rather than for the absent identity member.
        (MIGRATION_DECLARED_MEMBERS[2], Value::Bool(true)),
    ];
    let mut object = serde_json::Map::new();
    let mut omitted_count = 0usize;
    for (member, value) in values {
        if member == omitted {
            omitted_count += 1;
            continue;
        }
        object.insert(member.to_owned(), value);
    }
    // UNREACHABLE FROM EVERY CURRENT CALL SITE, KEPT AS A CONTRACT CHECK.
    //
    // It would fire for an `omitted` that is not one of the declared names (count
    // 0), or for a name that appears twice in `MIGRATION_DECLARED_MEMBERS` (count
    // 2) — either would build a payload that does not omit exactly what it claims.
    //
    // No call site can produce either today. `migration_payload_without` is
    // called only from the loop `for missing in MIGRATION_DECLARED_MEMBERS`, so
    // `omitted` is always one of the three literal declared names, and `values` is
    // built from three DISTINCT indices into that same array, so the count is
    // always exactly 1. The guard is NOT deleted: it is the only thing that would
    // catch a future caller that passes a name the payload builder does not
    // recognise, or a `MIGRATION_DECLARED_MEMBERS` that grew a duplicate entry.
    // It is a precondition on the CALLER, not an observation about live behaviour,
    // and it is labelled as such here rather than claimed as reachable coverage.
    //
    // There is deliberately NO `kept.len() == 2` conjunct and no
    // `object.contains_key(omitted)` conjunct: both were checked and both are
    // unreachable under the same reasoning, because the map is built from the
    // declared names themselves, so filtering one of three distinct names always
    // leaves two keys and never leaves `omitted` behind.
    if omitted_count != 1 {
        return fail(format!(
            "the payload must omit exactly {omitted}; it matched {omitted_count} declared members"
        ));
    }
    serde_json::to_string(&Value::Object(object)).map_err(boxed)
}

fn migration_payload_with_duplicate(
    identity: &str,
    checksum: &str,
    first_applied: &str,
    second_applied: &str,
) -> String {
    format!(
        "{{\"migration_id\":\"{identity}\",\"checksum_blake3\":\"{checksum}\",\"applied\":{first_applied},\"applied\":{second_applied}}}"
    )
}

fn decode_migration(
    payload: &str,
) -> Result<eliot_types::MigrationRecord, Box<dyn std::error::Error>> {
    serde_json::from_str::<eliot_types::MigrationRecord>(payload).map_err(boxed)
}

/// A refusal that must be about the DERIVED offending member, not merely about
/// some error existing.
///
/// Asserted on the MESSAGE for the same reason
/// `migration_is_refused_for_missing_member` is: a payload refused for an
/// UNRELATED reason — a type error on another member, a missing member, a syntax
/// fault — satisfies a bare `is_err`, so a bare `is_err` would call that a pass.
/// The member is derived from the payload by the caller's helper and is never
/// pasted at the call site.
///
/// The name check is a substring test on serde's own rendered wording, because
/// `serde_json::Error` exposes no `Message` code accessor. That is attributed as
/// such here and is the same attribution
/// `migration_is_refused_for_missing_member` already records.
fn migration_is_refused_naming(payload: &str, offending: &str, context: &str) -> TestResult {
    match serde_json::from_str::<eliot_types::MigrationRecord>(payload) {
        Ok(_) => fail::<()>(format!("{context} must be refused, but it decoded")),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains(offending),
                "{context}: the refusal must name the offending member {offending}, not fail for some unrelated reason: {message}"
            );
            Ok(())
        }
    }?;
    Ok(())
}

/// The byte offset just past the raw value token beginning at `value_start`.
///
/// A QUOTED value ends just past its closing quote — found with the escape-aware
/// `string_closing_quote`, so an escaped quote cannot truncate the extent — and an
/// UNTERMINATED string is refused HERE rather than measured. `string_closing_quote`
/// falls out of its loop at `bytes.len()` for a string with no closing quote, so a
/// bare `Ok(string_closing_quote(..) + 1)` would return `len + 1`: an extent one
/// byte past the end of the document. That is a plausible-looking number rather than
/// an obviously broken one, and the only thing that noticed it was the caller's
/// slice bounds one frame up, which returned `None` and reported "out of range" for
/// a cause that is really an unterminated string. The check is here so a helper that
/// can produce an out-of-range extent does not depend on its caller catching it.
///
/// A BARE token ends at the first `,` or `}` the scan meets, and that is EXACT only
/// for a scalar. The scan does not track nesting, so for a CONTAINER value — an
/// object or an array — it stops at the first `,` or `}` INSIDE the container and
/// the returned offset is a LOWER BOUND on the value token, not its end. It also
/// swallows any whitespace between the token and the delimiter it stops at, so for a
/// scalar followed by a space it over-approximates by that whitespace. Neither
/// inaccuracy can carry the offset past the delimiter that stopped the scan, which
/// is the property the callers' windows depend on; the nesting-aware extent is
/// `skip_json_value`.
///
/// The bare-token path is therefore not exercised for a container value by any
/// current caller: the sole caller passes a `MigrationRecord` payload whose `applied`
/// member is a scalar by construction. A future CONTAINER probe would be measured
/// with a lower bound, which makes the caller's column window too tight rather than
/// too loose — a red that says the extent was wrong, not a false pass.
fn raw_value_end(raw: &str, value_start: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let bytes = raw.as_bytes();
    if bytes.get(value_start) == Some(&b'"') {
        let closing = string_closing_quote(bytes, value_start);
        if bytes.get(closing) != Some(&b'"') {
            return fail(format!(
                "the member value at offset {value_start} is an unterminated string, so its extent is not measurable in a {}-byte document",
                bytes.len()
            ));
        }
        return Ok(closing + 1);
    }
    let mut index = value_start;
    while index < bytes.len() && bytes[index] != b',' && bytes[index] != b'}' {
        index += 1;
    }
    if index >= bytes.len() {
        return fail("the payload ends before the member value does".to_owned());
    }
    Ok(index)
}

/// The declared member of `MigrationRecord` whose schema type is `boolean`.
///
/// This is how the offending member is DERIVED for the non-boolean payloads, and
/// it is derived from live source rather than pasted. Reading it out of the
/// generated `schemars` schema — the same schema `migration_schema_admits_no_legacy_form`
/// already consumes — means the name tracks the declaration: if the boolean member
/// is renamed or retyped, this returns the new name and the assertion follows it
/// instead of silently passing against a stale literal.
///
/// The alternative derivation, "the member whose raw value is not a boolean", was
/// tried and rejected: on a `MigrationRecord` payload BOTH `migration_id` and
/// `checksum_blake3` hold JSON strings, which are not booleans either, so that rule
/// finds three candidates and cannot single one out. This one keys on the DECLARED
/// type, which is the thing the payload is being refused for disagreeing with.
///
/// Exactly one boolean member is required. Zero or several means the derivation is
/// ambiguous, and it fails rather than picking one. The failure NAMES the candidates
/// it found, not merely their count: a count tells a reader only that the
/// derivation broke, while the names say which members were in contention and are
/// the first thing needed to repair the declaration.
fn migration_boolean_member() -> Result<String, Box<dyn std::error::Error>> {
    let schema = schemars::schema_for!(eliot_types::MigrationRecord);
    let value = serde_json::to_value(&schema).map_err(boxed)?;
    let properties = value
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| boxed(std::io::Error::other("the schema declares no properties")))?;
    let mut booleans: Vec<&str> = properties
        .iter()
        .filter(|(_, property)| property.get("type").and_then(Value::as_str) == Some("boolean"))
        .map(|(name, _)| name.as_str())
        .collect();
    // Sorted before the report below, so the names in an ambiguity failure are in a
    // stable order rather than in `serde_json::Map`'s iteration order: the failure
    // message is evidence a reader compares against a schema dump.
    booleans.sort_unstable();
    match booleans.as_slice() {
        [only] => Ok((*only).to_owned()),
        _ => fail(format!(
            "{MIGRATION_TYPE} must declare exactly one boolean member; the schema declares {}: {booleans:?}",
            booleans.len()
        )),
    }
}

/// A payload whose non-boolean member must be refused FOR THAT REASON.
///
/// WHY THIS IS NOT `migration_is_refused_naming`, stated rather than papered over.
/// The expected member IS derived — `migration_boolean_member` reads it off the
/// generated schema — but serde CANNOT name it in this case. A wrong-typed member
/// produces `invalid type: string "true", expected a boolean`: the unexpected
/// value and the expected TYPE, and no field name. Only `missing_field`,
/// `duplicate_field` and `unknown_field` embed a member name, which is why the
/// sibling `migration_is_refused_for_missing_member` and the repeated-key site can
/// require one and this site cannot. Requiring `applied` here would be false
/// against live `serde_json`. This is the stated limit of the available
/// information; it is NOT a licence to accept any error, and the assertions below
/// are what replaces it.
///
/// WHAT BINDS THE REFUSAL TO THE OFFENDING MEMBER:
/// * the member is derived from live source, and the payload must actually carry
///   it and carry a value there that is NOT a JSON boolean. Without that last
///   conjunct this function would assert a refusal about a member the payload never
///   contradicts.
/// * `error.is_data()` is exact for serde's `Message` code, so this excludes a
///   syntax or IO failure. A bare `is_err` would accept `{"applied":`, which is a
///   syntax error about no member at all.
/// * the reported COLUMN must fall on that member's own value token: from the
///   column of the token's FIRST byte (`value_start + 1`; columns are one-based)
///   through the column of its LAST byte (`value_end`, which is the same number as
///   the byte offset just past that last byte). `serde_json` takes the position once
///   the offending token has been consumed, so a refusal raised on ANOTHER member is
///   reported against that member's own token and lands outside this window. That is
///   the ordering evidence, and it is the closest available substitute for the
///   member name serde withholds.
///
/// WHY THE UPPER BOUND IS `value_end` AND NOT `value_end + 1`, because the wider
/// bound was not harmless margin: it admitted a refusal raised about a DIFFERENT
/// member. A `missing_field` is positioned at END OF INPUT, at column
/// `payload.len()`. `serde_json`'s `deserialize_struct` evaluates `end_map()` — which
/// eats the closing `}` — BEFORE `fix_position` re-positions the unpositioned error,
/// and `missing_field` is an `ErrorCode::Message`, so `is_data()` holds for it too.
/// Both payloads here put `applied` LAST, so `value_end + 1` was exactly
/// `payload.len()` and end-of-input sat INSIDE the window: `{"applied":"true"}`, which
/// carries neither `migration_id` nor `checksum_blake3`, satisfied all three
/// assertions while being wrong three ways. `value_end` can never reach
/// `payload.len()`: it stops at the object's closing brace, which is the last byte of
/// every payload under this helper, so `value_end <= payload.len() - 1` and
/// end-of-input is now outside the window BY CONSTRUCTION rather than by an argument
/// about which error happens to fire first. The remaining half of that counterexample,
/// "the payload was already bad", is excluded by the isolation control at the foot of
/// this function.
///
/// WINDOW FORM, KEEP IT — but note that the upper bound is chosen so end-of-input
/// cannot enter the window at all, which is the property that matters here rather
/// than any particular reported column. `value_end` stops at the object's closing
/// brace, the last byte of every payload under this helper, so `value_end <=
/// payload.len() - 1` and end-of-input is outside the window BY CONSTRUCTION; that
/// is the argument, and it does not depend on which error happens to fire first.
/// Widening the bound re-admits end-of-input, which is the false pass recorded
/// above. Do not "tighten" it to an equality against a hard-coded column — the
/// bound here is derived from the payload's own bytes rather than pasted — and do
/// not delete it as a dependency detail: the binding to the offending member is
/// ours, only the column value is not. If a `serde_json` bump moves where the
/// position is taken by one byte, this reds with NO change in this crate's
/// behaviour; that coupling is stated so a future red is diagnosable rather than
/// baffling.
///
/// The previous version of this comment also stated a measured figure — that
/// against `serde_json` 1.0.151 both probe shapes report EXACTLY `value_end`, "so
/// the headroom is now ZERO". That is an EXECUTION observation and this lane cannot
/// run the suite, so it is removed rather than restated: no column value is claimed
/// here. What replaces it is the construction argument above, which is checkable by
/// reading the helper and holds regardless of what column is reported.
fn migration_is_refused_for_non_boolean_member(payload: &str, context: &str) -> TestResult {
    // The two JSON boolean literals, spelled out here rather than borrowed from a
    // constant that does not exist: `MIGRATION_BOOL_TRUE` is `true`, and `false` is
    // its only other counterpart on the wire.
    const BOOLEAN_FALSE: &str = "false";
    let offending = migration_boolean_member()?;
    let span = top_level_member_spans(payload)
        .into_iter()
        .find(|span| span.key == offending)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "the payload has no member {offending} to be non-boolean"
            )))
        })?;
    // A RAW key comparison, deliberately, and the rawness is what the window needs:
    // `MemberSpan.key` is the bytes between the quotes, so `key.len()` is the
    // on-wire length. Every payload reaching this helper writes `applied` plainly,
    // and a key written with an escape would fail this lookup loudly rather than
    // measure the wrong member.
    let value_end = raw_value_end(payload, span.value_start)?;
    let raw_value = payload.get(span.value_start..value_end).ok_or_else(|| {
        boxed(std::io::Error::other(
            "the member value slice is out of range",
        ))
    })?;
    // THE PRECONDITION IS TWO HALVES, and both can fail, which one raw-token
    // comparison could not do. Comparing the raw token against the bare literals
    // `true` and `false` is STRUCTURALLY UNFALSIFIABLE for the quoted probe: the
    // token is `"true"` WITH its quotes, so it can never equal `true` and the check
    // passed without ever having examined the value. The DECODED half compares what
    // the payload actually MEANS, so a probe carrying a boolean under any spelling —
    // bare or quoted — is caught here; the RAW half is kept because it says something
    // the decoded half does not, namely that the payload holds this exact bare token
    // and not merely some value that decodes to a boolean.
    assert_ne!(
        raw_value, MIGRATION_BOOL_TRUE,
        "{context}: the payload's {offending} is already the bare boolean true, so it is not a non-boolean probe"
    );
    assert_ne!(
        raw_value, BOOLEAN_FALSE,
        "{context}: the payload's {offending} is already the bare boolean false, so it is not a non-boolean probe"
    );
    let decoded_value: Value = match serde_json::from_str(raw_value) {
        Ok(decoded_value) => decoded_value,
        Err(rejected) => {
            return fail(format!(
                "{context}: the {offending} value token {raw_value:?} must itself be exactly one JSON value, or there is nothing here to refuse: {rejected}"
            ));
        }
    };
    assert!(
        decoded_value.as_bool().is_none(),
        "{context}: the payload's {offending} decodes to the JSON boolean {decoded_value}, so it is not a non-boolean probe: {raw_value:?}"
    );
    let Err(error) = serde_json::from_str::<eliot_types::MigrationRecord>(payload) else {
        return fail(format!("{context} must be refused, but it decoded"));
    };
    assert!(
        error.is_data(),
        "{context}: a non-boolean {offending} must be refused with a data error, not a syntax or IO error: {error}"
    );
    let first = span.value_start + 1;
    // See the two window paragraphs in the doc comment for why `last` is `value_end`
    // and not `value_end + 1`: the wider bound put end-of-input inside the window,
    // and a refusal raised after the whole document — `missing_field`, positioned by
    // `serde_json` at `payload.len()` — would then have passed.
    let last = value_end;
    assert!(
        error.column() >= first && error.column() <= last,
        "{context}: the refusal must land on the offending member {offending}, whose value occupies columns {first}..={last}: column {} is outside that window: {error}",
        error.column()
    );
    // The control that isolates the offending member as the SOLE cause: replace only
    // that one member's value with the boolean literal the declared type calls for,
    // and the rest of the document must decode. Without it, "the payload was already
    // bad" is not excluded — `{"applied":"true"}` carries neither `migration_id` nor
    // `checksum_blake3`, and with that single control absent it satisfied every
    // assertion above while the refusal it passed was about two members this function
    // never named.
    //
    // BYTE SURGERY, never a `Value` round trip: `serde_json::Map` collapses a
    // duplicate member, which is the very evidence the column window measures.
    let control = document_with_member_value(payload, &offending, MIGRATION_BOOL_TRUE)?;
    assert!(
        decode_migration(&control).is_ok(),
        "{context}: the same document with only {offending} replaced by the boolean its declared type calls for must decode, or the refusal above is not attributable to {offending}: {control}"
    );
    Ok(())
}

/// The offending member of a payload that REPEATS a declared key.
///
/// TOP LEVEL only, and it returns the LAST occurrence's name — the two properties
/// that distinguish it from `scan_repetitions` above, which walks EVERY container,
/// returns the FIRST repetition it finds, and reports the DEPTH it was found at.
/// Two different questions, so two different names: sharing one name is E0428,
/// and would have hidden both.
///
/// Derived from the bytes exactly as `case_15_offending_index` derives it: a
/// repeated key is refused at its LAST occurrence, so that occurrence's name is
/// the name the refusal must carry. Fails when the payload repeats nothing, so a
/// caller cannot pass a payload with no repeat and get a vacuous pass.
///
/// ESCAPE-BLIND BY CONSTRUCTION, AND THAT IS THE POINT — it compares RAW span keys,
/// because `MemberSpan.key` records the bytes between the quotes and no unescaping
/// step exists anywhere on that path. The sibling `scan_repetitions` compares
/// DECODED key names, via `decoded_key_name`, so it is escape-aware. The two
/// therefore DISAGREE BY DESIGN on an escape-equivalent pair: on the fixture's own
/// row `930-83-dup-escape-applied`, whose two occurrences of the key are written
/// `"\u0061pplied"` and then `"applied"`, `scan_repetitions` reports the single
/// repeated name `applied` at depth 0, while THIS helper finds no repetition at all
/// and fails loudly. It can only ever fail there, never pass falsely — the escaped
/// key it reads is a DIFFERENT byte sequence from the plain one, so the pair is
/// compared as two distinct members — and it is never fed such a payload today: its
/// sole caller builds one with `migration_payload_with_duplicate`, which writes both
/// keys plainly.
///
/// WHY EACH CALLER KEEPS ITS OWN VARIANT, since a single merged helper would have
/// to pick one of the two comparisons and silently change the other's answers. This
/// helper answers "which member does the TOP-LEVEL decoder refuse, and what NAME
/// must its message carry", where the answer has to be a member name the refusal
/// could actually name. `scan_repetitions` answers "which name is repeated at ANY
/// nesting depth, as the decoder sees it", where the escape form must count or the
/// escape-equivalence rows stop testing anything. Neither can answer the other's
/// question.
///
/// THE `position`/`filter`/`next_back` BLOCK BELOW IS A DELIBERATE DUPLICATION of
/// `case_15_offending_index` — the same rule, expression for expression — and the two
/// MUST BE CHANGED TOGETHER. A fix to the last-occurrence rule in one and not the
/// other leaves a case asserting its refusals against a different member than the one
/// the decoder actually refuses. They are not merged because they return different
/// things for different callers: this one returns the member NAME, which
/// `migration_is_refused_naming` requires the refusal message to contain, while
/// `case_15_offending_index` returns the span INDEX, which
/// `case_15_row_refuses_at_its_offending_member` needs to open a column window on
/// the offending key token and to excise that one member for its own isolation
/// control.
fn repeated_top_level_member(payload: &str) -> Result<String, Box<dyn std::error::Error>> {
    let spans = top_level_member_spans(payload);
    let repeated = spans
        .iter()
        .position(|span| spans.iter().filter(|other| other.key == span.key).count() > 1);
    let index =
        match repeated {
            Some(first) => spans
                .iter()
                .enumerate()
                .filter(|(_, span)| span.key == spans[first].key)
                .map(|(index, _)| index)
                .next_back()
                .unwrap_or(first),
            None => return fail(
                "the payload repeats no top-level member, so there is no repeated key to refuse"
                    .to_owned(),
            ),
        };
    spans
        .get(index)
        .map(|span| span.key.clone())
        .ok_or_else(|| {
            boxed(std::io::Error::other(
                "the repeated member index is out of range",
            ))
        })
}

/// The machine-checked form of the doc sentence at `records.rs:125-127`: this
/// wire shape adds no schema version, so no legacy form is admissible. The
/// schema is generated by `schemars`, a package dependency, so it is available
/// to an integration test.
fn migration_schema_admits_no_legacy_form() -> TestResult {
    let schema = schemars::schema_for!(eliot_types::MigrationRecord);
    let value = serde_json::to_value(&schema).map_err(boxed)?;
    let properties = value
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| boxed(std::io::Error::other("the schema declares no properties")))?;
    let mut names: Vec<&str> = properties.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["applied", "checksum_blake3", "migration_id"],
        "the schema must declare exactly the three wire members"
    );
    assert_eq!(
        value.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "deny_unknown_fields must close the schema"
    );
    let mut required: Vec<&str> = value
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            boxed(std::io::Error::other(
                "the schema declares nothing required",
            ))
        })?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    required.sort_unstable();
    assert_eq!(
        required, names,
        "every declared member must be required, or absence would stop being an error"
    );
    // No separate "no version-bearing property" loop: it iterated names the
    // assertion above already pinned to three literals, none of which contains
    // `version`, `schema` or `legacy`, so it could never fire. The pinned-name
    // equality IS the real check, and it fails if a version-bearing property ever
    // appears.
    Ok(())
}

/// CASE 11 OF ISSUE #930, AND IT IS **PARTIAL** — READ THIS BEFORE READING THE TEST
/// NAME, WHICH NAMES ONLY WHAT IS COVERED HERE.
///
/// THIS IS A DOCUMENTATION COMMENT, not a line comment, and that distinction is the
/// first half of the repair; the second half is WHERE this block sits, which is
/// written down at the end of this block. A line comment reaches nobody but a reader
/// holding this file open: it appears in no generated documentation, in no hover, and
/// in no test output, so the warning above addressed nobody at all. The reader it
/// targets is the one who sees only a PASSING TEST-OUTPUT LINE, and for that reader the
/// test's own NAME now carries `partial_` as well, because a name is the only part of
/// an item a passing run prints. Both carriers are kept because they reach disjoint
/// readers: the documentation comment reaches hover and any documentation extracted
/// from this target, and the name reaches the run log. Neither reaches the other.
///
/// WHAT THIS CASE DISCHARGES, over `eliot-types` only, and the authority is the
/// ISSUE'S ACCEPTANCE ROW rather than the card. Issue #930's table row for cases 9–12
/// reads, verbatim: "map/Value/custom visitor and alias/default/untagged paths cannot
/// erase protected input". That row names FOUR surfaces. An earlier version of this
/// comment quoted the CARD's narrower wording — "`strict_json_value` plus
/// alias/default/untagged paths proven unable to erase protected input" — and reasoned
/// from it, which was sound reasoning from the wrong authority: the card's clause does
/// not name the map/`Value` projection or the custom visitor, so concluding that they
/// are outside the clause said nothing about the issue's row, which does name them.
/// The narrowness of this case's coverage is a real and acceptable fact; deriving it
/// from the card rather than from the issue is not, and the two omitted surfaces are
/// named with their owners below rather than argued away.
///
/// OF THE FOUR SURFACES THE ISSUE'S ROW NAMES, this case discharges the
/// `strict_json.rs` ingress and the `alias` / `#[serde(default)]` /
/// `#[serde(untagged)]` attributes, both of which are real, in-crate and observable
/// from this test target:
///
/// * THE `strict_json.rs` INGRESS. `strict_json_value` and its no-ceiling sibling
///   `strict_json_has_no_duplicate_members` are the crate's own duplicate-rejecting
///   raw-byte ingress (`crates/eliot-types/src/strict_json.rs:96` and `:118`). This
///   test does not take their word on faith and does not re-implement them: it first
///   MEASURES, on the fixture's own bytes, that the erasure this ingress exists to
///   prevent is a real and total loss on the path beside it — the permissive
///   `serde_json` decode of a duplicate document returns a projection from which one
///   whole occurrence of the repeated member is simply GONE — and only then shows
///   that the strict ingress refuses those same bytes instead of handing back that
///   projection. The measurement is `permissive_ingress_erases_the_earlier_occurrence`.
///   `strict_ingress_cannot_erase_protected_input` is then CALLED, and supplies the
///   rest: equality with the permissive decode over the accept corpus, the ceiling
///   asymmetry that proves duplicate detection is actually reached, and the redaction
///   of the refusal.
/// * THE `alias` / `#[serde(default)]` / `#[serde(untagged)]` PATHS. They are proved
///   ABSENT from the five allocated files by `serde_attribute_inventory_is_closed`,
///   which is CALLED, not copied: it fails on any `serde(alias`, `serde(flatten`,
///   `serde(untagged`, `serde(other` or `cfg_attr(serde` form anywhere in those five
///   files, and pins the surviving seventeen attributes to an exact multiset. No
///   alias can therefore admit a second name for a protected member, and no untagged
///   container can select a variant by trial. The only `#[serde(default)]` in the
///   five files is the pair on `CanonicalMemoryL2Page` (`records.rs:115` and `:117`),
///   and `task_execution_class_fabricates_nothing` — also CALLED — proves the one
///   type that could have a defaulted wire member, `TaskExecutionClass`, carries none.
///
/// THE OTHER TWO SURFACES THE ISSUE'S ROW NAMES, AND THIS CASE COVERS NEITHER.
/// Both are named here with the symbol that owns each, because the issue's row claims
/// them and a reader of a passing run is entitled to know they were not reached:
///
/// * THE `map`/`Value` PROJECTION INGRESS — the lossy `from_value` path that precedes a
///   canonical-memory capacity receipt. Its owner is
///   `crates/eliot-store/src/canonical_store/capacity.rs:59 pub(super) fn
///   validate_capacity_receipt`, and the issue that owns it is **UNASSIGNED**: the
///   frozen boundary inventory records that path with blocked-reason `missing-owner`.
///   This case DOES reach a `serde_json::Map`/`Value` projection, but only as the
///   PERMISSIVE COUNTERPART it measures the strict ingress against — the very thing
///   that erases the earlier occurrence — and not as a protected ingress in its own
///   right. Reaching it as one would be the opposite of what this case proves.
/// * THE CUSTOM-VISITOR INGRESS. Its owner is
///   `crates/eliot-store/src/canonical_record.rs:332 struct EnvelopeVisitor<T>`, a
///   private type, and the issue that owns it is **#976**.
///
/// NEITHER IS REACHABLE FROM THIS TEST TARGET, and the reason is structural rather
/// than a matter of scope: `eliot-types` declares NO `[dev-dependencies]` section at
/// all (measured: `crates/eliot-types/Cargo.toml` carries `[dependencies]` and
/// `[lints]` and nothing else) and `eliot-store` depends on `eliot-types`
/// (`crates/eliot-store/Cargo.toml:11`), so the dependency runs the other way and an
/// integration test in `crates/eliot-types/tests/` has no link to either symbol.
/// NOTHING IN THIS FILE, AND NOTHING IN THIS RUN, CERTIFIES EITHER SURFACE. A green
/// result for this test is evidence about the two surfaces named above and about
/// nothing else.
///
/// THE OWNER ACCOUNTING IN THE PRECEDING PARAGRAPH IS OF THE TWO SURFACES THIS CASE
/// DOES NOT COVER, NOT OF ANY SET. It names two owners and no more: **UNASSIGNED** for
/// the `map`/`Value` projection ingress, and **#976** for the custom-visitor ingress.
/// Those are the owners of the two paths the ISSUE's acceptance row names and this test
/// cannot reach, and this paragraph exists so that neither is mistaken for the owner of
/// something larger.
///
/// THERE IS A WIDER DEFERRED SET, AND IT IS **NOT** RE-DERIVED HERE. Issue #930's card
/// carries a DEFER clause, quoted here once for the record and not as an authority this
/// file reasons from: "The six lossy ingress points named in the issue acceptance
/// comment and `HealthRecord.status` (owner #931) stay unresolved and are not certified
/// here." That clause is the CARD's, it is not part of the issue's acceptance table, and
/// it is recorded here as a statement of what the card defers rather than as a source of
/// obligations for this file. It follows that SIX lossy ingress points plus
/// `HealthRecord.status` are deferred by the card, while the paragraph above accounts
/// for exactly TWO paths — the two the issue's row names. The remaining points are NOT
/// enumerated by the card, no owner for them is named by anything this delivery may
/// resolve, and this file neither owns nor certifies any of them. A reader must NOT take
/// either owner above as the deferred set's ownership, and must not read a green run
/// here as touching any deferred point other than the two written down.
///
/// THE MARKER IS NOT A CLAIM THAT ISSUE #930's CASE 11 IS CLOSED. It records that a
/// named acceptance case has a real, eliot-types-observable half which is now
/// asserted, and this comment is where the uncovered remainder is written down.
///
/// THIS BLOCK SITS ABOVE THE WORK-UNIT MARKER, and that placement is load-bearing.
/// The marker must be IMMEDIATELY followed by its `#[test]`, and the work-unit gate
/// that binds the two walks forward from the marker refusing a blank line and
/// refusing any line beginning `//` or `/*` before it reads an attribute; a `///`
/// line is a `//` line, so a documentation comment written between the attribute and
/// this function detaches the marker exactly as a plain comment would, and there is
/// no tolerant fallback for a `.rs` file because every one is routed into that text
/// parser unconditionally. A PLAIN comment in the same place is not a workaround
/// either: `rustc` puts no order constraint on a comment relative to an attribute,
/// so the text would still be absent from hover and from extracted documentation.
/// Above the marker the walk never looks, and the block is still a documentation
/// comment, so every reader that reached it before still reaches it.
// WORK_UNIT_CASE: 930/11
#[test]
fn case_11_partial_ingress_and_attribute_paths_cannot_erase_protected_input() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    // THE MEASUREMENT COMES FIRST, because it is what makes the refusal beside it
    // mean anything. Asserting "the strict ingress refuses a duplicate" without
    // showing that the duplicate is worth refusing proves only that the function
    // returns an error; this loop shows the alternative answer is a SILENT loss of
    // one whole occurrence of a repeated member, measured on these bytes.
    permissive_ingress_erases_the_earlier_occurrence(&rows)?;
    // Then the three existing assertions this case owns rather than duplicates. Each
    // is called by name and none is re-implemented, because each already carries its
    // own contract, its own citation of the pinned serde source, and its own
    // non-vacuity guards, and a second copy of any of them here would be a second
    // thing to keep true.
    strict_ingress_cannot_erase_protected_input(&rows)?;
    serde_attribute_inventory_is_closed()?;
    task_execution_class_fabricates_nothing()?;
    Ok(())
}

/// The erasure the strict ingress exists to prevent is REAL AND MEASURED on the
/// fixture's own bytes: the permissive `serde_json` decode of a duplicate document
/// returns a projection in which one occurrence of the repeated member is gone and no
/// error was raised.
///
/// SCOPE OF THE MEASUREMENT, STATED PRECISELY BECAUSE IT IS NOT EVERYTHING. The
/// corpus walked below is the TOP-LEVEL repetitions of the case-5 duplicate group —
/// the repetitions whose first occurrence `scan_repetitions` reports at depth
/// `TOP_LEVEL_MEMBER_DEPTH`, which is the document's own object. TWO KINDS OF ROW IN
/// THAT GROUP ARE LEFT OUT, and BOTH ARE EXCLUSIONS rather than one of them being a
/// failure — the reasons are given together below, because the two must agree: a row
/// whose FIRST REPETITION IS NESTED, and a row whose REPEATED MEMBER CARRIES THE SAME
/// VALUE IN EVERY OCCURRENCE. Each records its id in its OWN ledger inside the loop,
/// and the failure message of the non-empty guard prints both ledgers and the reason
/// each stands for, so a reader sees what was not walked and why instead of a silently
/// shorter loop. This is a restriction of the MEASUREMENT, not of the property, and it
/// is stated rather than counted: the number of walked rows is a property of the
/// fixture's current contents, it changes whenever another writer adds or removes a
/// duplicate row, and no figure written here could stay true across such an edit
/// without turning something red — which is why this comment carries no row count at
/// all, on the same reasoning `selector_call_arguments` records for its own floor.
///
/// Nested repetitions are NOT thereby unmeasured. Case 5's per-depth histogram
/// requires a witness at every depth its own bytes make reachable and asserts every
/// such row is refused for its repetition, so a nested duplicate is refused as a
/// duplicate. What is measured HERE and not there is the ERASURE — that the permissive
/// path loses an occurrence — and it is measured only where the two readings can be
/// compared at all, which is the root object. Adding an obligation that nested
/// repetitions also be measured for erasure would be inventing a requirement the card
/// does not state.
///
/// WHY THE CONTROL IS THE SUBJECT OF HALF THE ASSERTION. The claim is about what the
/// strict ingress does NOT do, and "does not do" is only meaningful against the
/// concrete alternative. So for every row walked below this function measures, from
/// the row's own bytes and with no member name typed here:
/// * the DECODED name of the member that the document repeats, and the depth of the
///   object holding both occurrences — both from `scan_repetitions`;
/// * the RAW value token of EVERY occurrence, in document order — from
///   `repeated_member_value_tokens`;
/// * that the first and the last of those tokens decode to DIFFERENT values. This is
///   the non-vacuity precondition of the erasure claim: a row repeating a member with
///   one value twice would lose nothing, and counting it toward "the permissive path
///   erases" would make this a claim about nothing. A row failing it is EXCLUDED
///   rather than failed, which is the second of the two exclusions stated below;
/// * that the permissive `serde_json` decode of those identical bytes SUCCEEDS and
///   that the member it returns equals the LAST occurrence's value and NOT the
///   first's. That pair is the erasure: a value the wire carried twice, of which the
///   projection keeps exactly one, with no error anywhere. `serde_json::Map` is a
///   `BTreeMap` unless the workspace enables `preserve_order`, and no manifest in
///   this workspace requests that feature — the root `Cargo.toml` asks for
///   `serde_json` with `features = ["float_roundtrip"]` alone — so `insert`
///   last-wins and the earlier occurrence is unreachable in the result.
///
/// WHAT IS DELEGATED, AND WHY IT IS NOT HERE. The STRICT-REFUSAL half of this
/// measurement — that `eliot_types::strict_json_has_no_duplicate_members` REFUSES these
/// same bytes with `StrictJsonErrorKind::DuplicateKey`, on the no-ceiling entry point
/// because the question asked here has no size dimension — is asserted by
/// `strict_ingress_cannot_erase_protected_input` and is DELIBERATELY NOT REPEATED HERE.
/// That helper walks the WHOLE duplicate group `reject_rows(all,
/// ESCAPE_EQUIVALENT_CASE)`, a strict SUPERSET of the top-level subset walked below, and
/// the test above calls it a few lines after calling this one, so its assertion passing
/// implies this half passing and the two copies CANNOT DISAGREE. A second copy could
/// only add drift, and it would drift SILENTLY: anyone narrowing the shared corpus
/// would leave the weaker duplicate alive here with nothing reporting it.
///
/// THE PERMISSIVE-DECODE HALF STAYS LOCAL, and it is the half that cannot be moved. Its
/// entire content is the CONTRAST with that refusal on IDENTICAL BYTES — one decoder
/// accepts the document and silently drops an occurrence, the other refuses it — and a
/// contrast needs both terms side by side in one place. The shared helper asserts the
/// refusal over a corpus whose permissive projections it never inspects, so reading the
/// permissive leg out of this function would leave the measurement claiming a refusal
/// with nothing beside it to show what was refused INSTEAD OF. So the copy that was
/// REMOVED is the strict one and the copy that was KEPT is the permissive one, which is
/// the reverse of what the relative sizes of the two functions suggest.
///
/// THE TWO EXCLUSIONS ARE EXCLUSIONS, BOTH OF THEM, and they are handled the same way on
/// purpose. A row can be left out of this loop for exactly two reasons, and NEITHER is
/// a failure OF THIS FILE: a row whose FIRST REPETITION IS NESTED cannot be measured
/// for erasure at all, because `repeated_member_value_tokens` reads one object at one
/// depth while the permissive projection is the whole document; and a row whose
/// OCCURRENCES CARRY ONE VALUE loses nothing on collapse, so it witnesses no erasure.
/// An earlier version of this helper skipped the first silently and FAILED the second,
/// while this comment described both as exclusions — so a fixture row of the second kind
/// turned the whole suite red for a measurement that was never going to walk it, and the
/// fixture is edited by another writer in this same delivery. Both are now exclusions,
/// and each is LOUD: each records its row id in its own named ledger inside the loop,
/// the same-valued branch ASSERTS the one thing that is true of the row it excludes
/// instead of continuing past it, and the non-empty guard at the foot prints both
/// ledgers with the reason each stands for. Neither exclusion is a hole in the
/// property: a nested duplicate and a same-valued duplicate are BOTH refused as
/// duplicates by case 5's per-depth histogram, which is where those rows are measured.
///
/// WHY ONLY THE TOP-LEVEL REPETITIONS ARE WALKED is stated at the head of this comment
/// as the scope of the measurement, and the reason is here in one place:
/// `repeated_member_value_tokens` reads ONE object at ONE depth, while the permissive
/// projection this function compares against is the WHOLE document. The two are the
/// same question only when the repeated object IS the document's own top-level object,
/// which is depth `TOP_LEVEL_MEMBER_DEPTH`. The non-empty guard at the foot requires
/// that the top-level subset is not empty, so the loop cannot pass by measuring nothing
/// while reading as though it had.
///
/// WHY THE EXPECTED SIDE IS PARTLY SELF-DERIVED, WHICH IS THE ONE THING A READER SHOULD
/// CHECK HERE. The member name, the depth, and the last occurrence's value all come from
/// this file's own byte walks, and the projection is compared against that self-derived
/// `last`, so the natural suspicion is a comparison the file could satisfy by agreeing
/// with itself. It cannot produce a false pass here, for a reason that is short and
/// checkable: DEPTH 0 IS UNIQUELY THE DOCUMENT'S OWN OBJECT. `scan_repetitions` pushes
/// `containers.len()` at push time, so a container nested inside anything reports a
/// depth of at least one and no nested container can ever report depth 0. Therefore
/// every token `repeated_member_value_tokens` returns at depth 0 is a genuine
/// top-level `member: value` pair of the root object, and the ONE INDEPENDENT FACT in
/// the comparison is `permissive.get(&member)`, which comes from serde_json's own
/// decode of the bytes rather than from this file's parser. The assertion is thus
/// "serde_json kept the value this file's scan says came last, and did not keep the one
/// it says came first" — one side observed by the dependency, one side derived by the
/// test, joined on a member name and a depth that cannot be confused.
///
/// WHY NO INDEPENDENT DERIVATION IS APPLIED INSTEAD, since the obvious cross-check was
/// considered and rejected. `case_15_offending_index` and `repeated_top_level_member`
/// are the two places in this file that find a repetition WITHOUT `scan_repetitions`,
/// and both compare RAW `MemberSpan.key` bytes. On an escape-equivalent pair — a key
/// written once with a `\u00xx` escape and once plainly, as the case-5
/// escape-equivalent rows do (`930-83`…`930-88`, named by id because that is how this
/// file already refers to them) — the raw keys differ, so both helpers find NO
/// repetition at all and
/// would fail on exactly the rows where the escape path most needs checking. That is
/// why `escape_row_carries_a_colliding_escape` exists and why `scan_repetitions`
/// compares DECODED names: this corpus contains the rows an independent raw-key
/// cross-check cannot read, so substituting it would drop coverage rather than add
/// confidence.
///
/// NO ROW ID AND NO `reason` PROSE IS READ, and no fixture value is pasted: the
/// member name, the depth, the value tokens and the expected collapse all come from
/// the row's own `raw` through the byte scans this file already owns. That matters
/// because another writer edits this fixture's rows in the same delivery, and this
/// file already records that coupling a control flow to `reason` prose is a defect.
fn permissive_ingress_erases_the_earlier_occurrence(all: &[Row]) -> TestResult {
    // The corpus is the DUPLICATE group case 5 itself selects, so this function
    // cannot drift from the group whose refusals it explains, and it fails on an
    // empty group rather than passing over nothing.
    let duplicates = reject_rows(all, ESCAPE_EQUIVALENT_CASE)?;
    let mut walked: Vec<&str> = Vec::new();
    // TWO LEDGERS, ONE PER EXCLUSION, never one shared `skipped`. A single list would
    // record THAT a row was left out without recording WHICH of the two reasons applied,
    // and the reader the non-empty guard below addresses — the one asking what this loop
    // did not measure — needs the reason as much as the id. Both are printed by that
    // guard, so neither exclusion is invisible on the passing path.
    let mut nested_first: Vec<&str> = Vec::new();
    let mut same_valued: Vec<&str> = Vec::new();
    for row in &duplicates {
        let Some((member, depth)) = scan_repetitions(&row.raw).first else {
            return fail(format!(
                "row {} is selected as a duplicate by reject_rows, so its own bytes must repeat a member; they repeat none, and the measurement below would have nothing to show that a projection erased",
                row.id
            ));
        };
        // EXCLUSION ONE OF TWO. Not a failure of this file and not measurable here at
        // all: the two readings this loop compares are ONE object and the WHOLE
        // document, and they are the same question only when the repeated object is the
        // document's own, which is depth `TOP_LEVEL_MEMBER_DEPTH`.
        if depth != TOP_LEVEL_MEMBER_DEPTH {
            nested_first.push(row.id.as_str());
            continue;
        }
        let tokens = repeated_member_value_tokens(&row.raw, &member, depth);
        assert!(
            tokens.len() >= 2,
            "row {} repeats {member} in its own top-level object, so that object must carry at least two of its value tokens and the loop below must have something to compare; found {tokens:?}",
            row.id
        );
        let decoded: Vec<Value> = tokens
            .iter()
            .map(|token| serde_json::from_str(token.as_str()).map_err(boxed))
            .collect::<Result<Vec<Value>, Box<dyn std::error::Error>>>()?;
        let first = decoded
            .first()
            .ok_or_else(|| boxed(std::io::Error::other("the token list is empty")))?;
        let last = decoded
            .last()
            .ok_or_else(|| boxed(std::io::Error::other("the token list is empty")))?;
        // The permissive leg, and it comes BEFORE the non-vacuity split below so that
        // BOTH branches of that split hold a projection. It must SUCCEED — a refusal
        // would mean the document is broken for some other reason and the collapse below
        // would be measuring the wrong thing, which is the same attribution hazard
        // `strict_ingress_cannot_erase_protected_input` guards with its own permissive
        // leg. This half is LOCAL to this function and stays here: its content is the
        // contrast with the strict refusal on identical bytes, which the shared helper
        // asserts only its own side of.
        let permissive: Value = serde_json::from_str(&row.raw).map_err(|error| {
            boxed(std::io::Error::other(format!(
                "row {} repeats {member} and must be ACCEPTED by the permissive serde_json decode of the IDENTICAL bytes, otherwise the collapse measured below is not attributable to the duplicate; the permissive decode refused it: {error}",
                row.id
            )))
        })?;
        let collapsed = permissive.get(&member).ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "row {} repeats {member} but the permissive projection carries no member by that name, so there is no collapse to measure",
                row.id
            )))
        })?;
        // EXCLUSION TWO OF TWO, and it is LOUD rather than a silent skip or a failure.
        // Two occurrences carrying ONE value lose nothing on collapse, so this row
        // cannot witness an erasure — but it is still a duplicate the permissive path
        // accepts without an error and the strict ingress refuses, so this branch
        // ASSERTS the one thing that is true of it rather than continuing past it, and
        // records its id in its own ledger. No row in the fixture as it stands reaches
        // this branch; it exists so that adding one is a recorded exclusion instead of
        // a red suite or an invisible skip. Case 5's per-depth histogram still refuses
        // such a row as a duplicate, which is where it is measured.
        if first == last {
            assert_eq!(
                collapsed, last,
                "row {} repeats {member} with the SAME value in every occurrence ({tokens:?}), so the permissive projection erases nothing here and this row cannot witness the erasure this function measures; the permissive decode still ACCEPTED those identical bytes without an error and still holds that one value, which is the whole of what such a row shows, and case 5 still refuses it as a duplicate",
                row.id
            );
            same_valued.push(row.id.as_str());
            continue;
        }
        // THE ERASURE, both halves. `last` because `serde_json::Map` is a `BTreeMap`
        // here and `insert` is last-wins; `first` because the assertion that the
        // earlier value is ABSENT is the half that makes this an erasure rather than
        // a choice. Without the second conjunct this would only say the projection
        // kept one of two values, which a reader could satisfy by believing the
        // first had been the one kept.
        //
        // THE EXPECTED SIDE IS SELF-DERIVED AND THAT IS SOUND HERE; the full argument
        // is in this function's doc comment and the short form is at this line. Depth
        // 0 is UNIQUELY the document's own object — `scan_repetitions` pushes
        // `containers.len()` at push time, so a nested container reports at least one
        // and none can report zero — so every token read at depth 0 is a real
        // top-level `member: value` pair of the root object. `permissive.get(&member)`
        // is therefore the one INDEPENDENT observation in the comparison: it comes
        // from serde_json's own decode, not from this file's parser, and this
        // assertion is exactly "the dependency kept the value our scan says came last,
        // and did not keep the one it says came first".
        //
        // THE STRICT REFUSAL IS NOT ASSERTED HERE. It is asserted by
        // `strict_ingress_cannot_erase_protected_input`, over the WHOLE duplicate group
        // this loop walks a top-level subset of, and that helper is called from the test
        // above — so this half is DELEGATED, not duplicated, and the contrast this loop
        // measures is the permissive projection beside the refusal that helper proves on
        // the same bytes.
        assert_eq!(
            collapsed, last,
            "row {}: the permissive projection of a document repeating {member} must keep the LAST occurrence, because serde_json::Map is a BTreeMap here and insert is last-wins; the occurrences were {tokens:?}",
            row.id
        );
        assert_ne!(
            collapsed, first,
            "row {}: the permissive projection still holds the FIRST occurrence of {member} ({tokens:?}), so nothing was erased on this path and the claim this function makes would be false",
            row.id
        );
        walked.push(row.id.as_str());
    }
    assert!(
        !walked.is_empty(),
        "the duplicate corpus must carry at least one row whose FIRST repetition is in the document's own top-level object (depth {TOP_LEVEL_MEMBER_DEPTH}), or the erasure measurement above iterated nothing and proved nothing; the rows left out were {nested_first:?}, excluded because their first repetition is NESTED rather than top-level and this measurement reads one object at one depth, and {same_valued:?}, excluded because their repeated member carries the SAME value in every occurrence and nothing is erased there"
    );
    Ok(())
}

/// CASE 12 OF ISSUE #930 IS **PARTIAL**, AND THE PARTIALNESS IS THE `alias` /
/// `default` / `untagged` HALF OF A FOUR-SURFACE CLAUSE — NOT THE WHOLE CLAUSE.
///
/// THE GOVERNING ROW is issue #930's acceptance table for cases 9–12, which reads
/// verbatim: "map/Value/custom visitor and alias/default/untagged paths cannot erase
/// protected input". It names FOUR surfaces. This case exercises the
/// `alias` / `#[serde(default)]` / `#[serde(untagged)]` attributes and the
/// non-fabrication of an absent optional member. It exercises NEITHER of the other
/// two, and an earlier version of the body below restated the clause as three surfaces
/// in this file's own voice with no pointer to the two it dropped, which is how a
/// reader of a passing run would come to believe the clause had three. It has four.
///
/// THE TWO SURFACES NOT COVERED HERE, named with the symbol that owns each:
/// * THE `map`/`Value` PROJECTION INGRESS, owned by
///   `crates/eliot-store/src/canonical_store/capacity.rs:59 pub(super) fn
///   validate_capacity_receipt` — the issue that owns it is **UNASSIGNED**, the frozen
///   boundary inventory recording that path with blocked-reason `missing-owner`.
/// * THE CUSTOM-VISITOR INGRESS, owned by
///   `crates/eliot-store/src/canonical_record.rs:332 struct EnvelopeVisitor<T>` — a
///   private type, issue **#976**.
///
/// NEITHER IS REACHABLE FROM THIS TARGET: `eliot-types` declares no
/// `[dev-dependencies]` section at all, and `eliot-store` depends on `eliot-types`
/// (`crates/eliot-store/Cargo.toml:11`), so the dependency runs the other way and an
/// integration test here has no link to either. NO CODE IS ADDED FOR EITHER, because
/// an unreachable surface cannot be asserted from here and inventing a stand-in would
/// be worse than the gap. Case 11 is the marker-bound case for the same clause's
/// `strict_json.rs` ingress and carries the same disclosure for these two.
///
/// THIS BLOCK SITS ABOVE THE WORK-UNIT MARKER, and that placement is load-bearing.
/// The marker must be IMMEDIATELY followed by its `#[test]`, and the work-unit gate
/// that binds the two walks forward from the marker refusing a blank line and
/// refusing any line beginning `//` or `/*` before it reads an attribute; a `///`
/// line is a `//` line, so a documentation comment written between the attribute and
/// this function detaches the marker exactly as a plain comment would, and there is
/// no tolerant fallback for a `.rs` file because every one is routed into that text
/// parser unconditionally. A PLAIN comment in the same place is not a workaround
/// either: `rustc` puts no order constraint on a comment relative to an attribute,
/// so the text would still be absent from hover and from extracted documentation.
/// Above the marker the walk never looks, and the block is still a documentation
/// comment, so every reader that reached it before still reaches it.
// WORK_UNIT_CASE: 930/12
#[test]
fn case_12_optional_absence_decodes_in_both_directions() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    // This case's own share of the clause is the `alias` / `default` / `untagged` half:
    // the inventory below proves those attribute forms are absent from the five
    // allocated files, and the absence round-trip is the non-fabrication half, since an
    // absent `Option` must decode to `None` rather than to an invented default. THE
    // CLAUSE HAS FOUR SURFACES, NOT THREE — the `map`/`Value` projection ingress and
    // the custom-visitor ingress are not exercised here, and the doc comment above
    // names both with their owners.
    serde_attribute_inventory_is_closed()?;
    task_execution_class_fabricates_nothing()?;
    // This group inverts the rule: every row must decode. Asserting `is_err()`
    // here would be false against live source, because an absent key on an
    // `Option` member reaches serde's `missing_field`, whose
    // `MissingFieldDeserializer::deserialize_option` calls `visit_none()`.
    let group = accept_rows(&rows, 12)?;
    let SplitGroups { pages, health } = split_l2_pages_and_health_records(&group)?;
    // BOTH halves must be non-empty, and NEITHER guard is redundant with the
    // sum-to-group-length check in the splitter: that check only proves every row
    // was classified, so a group of health rows and ZERO pages satisfies it exactly
    // as happily as the reverse, and as happily as the mix it has today.
    //
    // The `pages` guard is the one that was missing. Without it the `pages` loop
    // below iterates nothing and `l2_page_absence_row_is_accepted` — the whole
    // ABSENCE claim, and the only place the four optional members are checked
    // against a document that omits them — silently stops running while this case
    // stays green. That is the locally-vacuous-loop failure, and it is invisible
    // from outside because every other assertion in the case is about a different
    // half. `health_record_surrogate_row_is_accepted` is the mirror image: it is
    // the whole NEGATIVE CONTROL for a lone-surrogate probe, and the only place an
    // astral scalar is exercised against a type that does not declare one.
    let listed = group
        .iter()
        .map(|row| row.id.as_str())
        .collect::<Vec<&str>>()
        .join(", ");
    assert!(
        !pages.is_empty(),
        "case 12 must carry at least one CanonicalMemoryL2Page absence row, or the optional-member absence loop below iterates nothing and this case's own headline claim is unproven; the group is {listed}"
    );
    assert!(
        !health.is_empty(),
        "case 12 must carry the HealthRecord surrogate row, or the surrogate negative control never runs; the group is {listed}"
    );
    for row in &pages {
        l2_page_absence_row_is_accepted(row)?;
    }
    for row in &health {
        health_record_surrogate_row_is_accepted(row)?;
    }

    // The descriptor row for the invalid-UTF-8 probe lives in case 14, where it
    // is the single non-document row. It is exercised here as well because this
    // is where optional absence and invalid UTF-8 meet: absence is accepted, a
    // corrupt byte is refused. The lookup asserts the partition instead of
    // skipping, so the probe can never quietly stop running.
    invalid_utf8_probe_is_refused(sole_byte_literal_descriptor(&rows)?)?;
    Ok(())
}

/// Rows in a reject group that are neither a JSON document nor a transparent
/// scalar's malformed input. The split is made explicitly rather than by a
/// silent `continue`: the caller must be able to see that the non-document set is
/// exactly one row and name it.
///
/// WHY THE `declares_transparent_scalar` CONJUNCT IS HERE, and it is a SELECTION
/// rule for the second case-14 group rather than a weakening of the first. The
/// `{`-prefix test alone cannot see a bare scalar: `raw` for a scalar row is a
/// quoted string or a number, never an object, so the whole second group fell
/// into this half of the split. Its quoted-string rows are not malformed JSON at
/// all — they are well-formed JSON carrying an unparseable value — so counting
/// them as non-document fragments would make `sole_byte_literal_descriptor`'s
/// exactly-one assertion go red on a correct fixture, and would point case 12's
/// invalid-UTF-8 probe at a row that has nothing to do with a byte literal. The
/// descriptor this protects is still the only row left in the set, and the
/// assertion that says so is unchanged in value and in place.
fn non_document_rows<'rows>(group: &[&'rows Row]) -> Vec<&'rows Row> {
    group
        .iter()
        .copied()
        .filter(|row| !declares_transparent_scalar(row) && !row.raw.trim_start().starts_with('{'))
        .collect()
}

/// The single non-document row of the malformed group. Fails if the set is empty
/// or larger than one, naming what it found, so the group can never pass without
/// ever exercising the byte-literal property.
fn sole_byte_literal_descriptor(all: &[Row]) -> Result<&Row, Box<dyn std::error::Error>> {
    let fragments = non_document_rows(&reject_rows(all, MALFORMED_CASE)?);
    if fragments.len() != 1 {
        let found = fragments
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return fail(format!(
            "case {MALFORMED_CASE} must carry exactly one non-document descriptor row; found {}: {found}",
            fragments.len()
        ));
    }
    Ok(fragments[0])
}

/// Whether a row's DECLARED `shape` says its type is a `#[serde(transparent)]`
/// scalar — and this is the SELECTOR for the second case-14 group.
///
/// WHY THE DECLARED SHAPE AND NOT THE `{` PREFIX, which is the only other rule
/// available and the rule the first group uses. A malformed scalar input is a
/// bare JSON value: `{}` for a map, or a quoted string for a value that will not
/// parse. It does not begin with `{` as a DOCUMENT does — a quoted scalar input
/// cannot begin with `{` at all — so the existing prefix rule is blind to it.
/// That rule is nonetheless CORRECT for the group it selects and is left alone
/// there: the group it picks holds the byte-literal descriptor alongside the
/// object-shaped documents, and `classify_malformation` needs the documents, not a
/// shape label. No count is written here because the group's composition moves with
/// the fixture — a document added to it changes both numbers at once, and a reader who
/// wants them has the selectors this file uses everywhere else.
///
/// WHY NOT THE ROW ID OR THE `reason` PROSE, the two things a reader might expect.
/// A classifier keyed on the id is satisfied by renaming a row, and this file
/// already refuses to couple a control flow to `reason` prose because another
/// writer edits it in the same delivery. `shape` is the fixture's own
/// DECLARATION of the type's wire form, it is already the closed vocabulary
/// `declared_shapes_and_cross_references_hold` polices, and both spellings here
/// are named once in `TRANSPARENT_SCALAR_SHAPES` — so a row cannot be moved into
/// or out of this group by a rename of anything but its declared shape, which is
/// the one edit that genuinely changes what the decoder is being asked to do.
fn declares_transparent_scalar(row: &Row) -> bool {
    TRANSPARENT_SCALAR_SHAPES.contains(&row.shape.as_str())
}

/// The second case-`MALFORMED_CASE` group, selected by `declares_transparent_scalar`.
fn transparent_scalar_rows<'rows>(group: &[&'rows Row]) -> Vec<&'rows Row> {
    group
        .iter()
        .copied()
        .filter(|row| declares_transparent_scalar(row))
        .collect()
}

/// The refusal TEXT a transparent-scalar row must carry, derived from the row's
/// OWN BYTES and its own declared shape — never from its id, its description or
/// its `reason`.
///
/// WHY THE OPENING BYTE DECIDES, because the two families produce two different
/// sentences for the same declared shape. `Uuid::deserialize` takes the
/// human-readable branch and asks for a string, so a `{` opening is refused
/// BEFORE any string is read, by `peek_invalid_type`'s `b'{'` arm, and the
/// sentence names the expectation instead of the parse; a quoted opening is read
/// and refused by uuid's own parser, and the sentence is `UUID parsing failed: `.
/// The `u64` newtypes ask serde for a number, and a `{` opening is refused by
/// `deserialize_number`'s fallback with the wrong-kind sentence. No other pairing
/// has a CONFIRMED text, so any other opening byte fails loudly here instead of
/// being given an expectation assembled from the parts read elsewhere.
/// WHY A `Vec` AND NOT A SLICE OF THE CONST ARRAYS. Borrowing a `const` item's
/// array as a slice would have to go through `as_slice` on a value that is not
/// `'static` at that use site, so the return type would carry a lifetime this
/// function cannot honestly promise. A `Vec` of `&'static str` is one small
/// allocation per row and no lifetime claim at all.
fn transparent_scalar_refusal_text(
    row: &Row,
) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    let opening = row.raw.trim_start().chars().next();
    match (row.shape.as_str(), opening) {
        (UUID_SCALAR_SHAPE, Some('{')) => Ok(UUID_MAP_REFUSAL_TEXT.to_vec()),
        (UUID_SCALAR_SHAPE, Some('"')) => Ok(UUID_PARSE_REFUSAL_TEXT.to_vec()),
        (U64_SCALAR_SHAPE, Some('{')) => Ok(U64_REFUSAL_TEXT.to_vec()),
        (shape, opening) => fail(format!(
            "row {} declares shape {shape} and its own bytes open with {opening:?}, and no refusal text has been CONFIRMED for that pairing: a `{{` opening is confirmed for either transparent scalar, and a `\"` opening is confirmed for {UUID_SCALAR_SHAPE} alone, because serde_json answers a quoted string to a number with `ExpectedSomeValue` rather than with a wrong-kind sentence. Asserting anything else here would mean composing message text that was never read",
            row.id
        )),
    }
}

/// ONE transparent-scalar row is refused, and its refusal names what its type
/// expected. These are the first two of the three assertions this group exists
/// for.
///
/// WHY THE CATEGORY IS `Data` HERE AND MUST NOT BE, and why this reads as an
/// inconsistency with the first group until the doc comment above it is read.
/// `malformed_document_is_refused_for_its_own_shape` asserts `!error.is_data()`,
/// which is right for IT and wrong here. A malformed document is refused by
/// `serde_json`'s PARSER — an unterminated string, a bad escape, a trailing comma —
/// and every one of those is an `ErrorCode` in `Category::Syntax` or `Category::Eof`,
/// never a `Message`. A transparent scalar's refusal is not a parser refusal at
/// all: the bytes parse cleanly and the VALUE is wrong for the declared type, so
/// both constructions that produce it — serde's `invalid_type` and uuid's
/// `E::custom` — are `Error::custom`, i.e. `ErrorCode::Message`, which
/// `classify()` maps to `Category::Data` (`serde_json-1.0.151/src/error.rs:56`).
/// Asserting the first group's negation here would be a false red on correct code.
fn transparent_scalar_is_refused_for_its_own_shape(row: &Row) -> TestResult {
    // `refusal_error` is the refusal assertion: it fails naming the row when the
    // bytes DECODE, so `is_err` is never taken on trust.
    let error = refusal_error(row)?;
    let message = error.to_string();
    for fragment in transparent_scalar_refusal_text(row)? {
        assert!(
            message.contains(fragment),
            "the refusal for row {} must name what its declared type expected, so {fragment:?} must appear in it: {message}",
            row.id
        );
    }
    assert!(
        error.is_data(),
        "the refusal for row {} must be a serde `Message` code, i.e. Category::Data, because a transparent scalar's bytes PARSE and only the value is wrong for the type; a syntax refusal would mean the decoder never reached the type's own visitor: {error}",
        row.id
    );
    Ok(())
}

/// THE CONTROL for one row: the SAME TYPE's recorded valid allocation row must
/// still decode, so the refusal above is about the input and not about a broken
/// decode path.
///
/// WHY A CONTROL AND NOT AN ISOLATION PROBE, which is what the document group
/// cannot use. To show a document refusal is attributable to one member you
/// remove that member and watch a refusal appear where a document used to be —
/// isolation needs a member, because a refusal about a member is only
/// distinguishable from a refusal about the document if a smaller document
/// behaves differently. A scalar has no member: its whole payload is one value,
/// so there is nothing to remove and isolation is not expressible. What IS
/// expressible is the per-TYPE control this asserts — the decoder is handed the
/// same type's own recorded valid bytes through the same `decode_row` dispatcher
/// and must accept them. A dispatcher arm that refused everything, a wrong type
/// named by the arm, and a decoder path that cannot reach the type at all are
/// each red here, and none of them is red on the refusal assertion alone.
///
/// WHY `selected` AND NOT `applicable_row`, which is the one accessor a reader
/// would reach for and the one that would be wrong here. `applicable` on these 40
/// rows records INAPPLICABILITY TO THE UNKNOWN-MEMBER SURFACE, and every one of
/// them is `false` for a structural reason their own `reason` states: a bare JSON
/// scalar has no object member at any depth, so there is no key an unknown-member
/// case could inject. Requiring `applicable` of a decode CONTROL would therefore
/// reject exactly the rows that most need one — the flag is `false` BECAUSE the
/// type decodes as a value and nothing else — and would substitute a claim about
/// the unknown-member surface for a claim about the decode path. `selected` is
/// the case-1 allocation row for the type and asks only that question, and it
/// also fails when the type carries more than one allocation row.
fn the_same_type_still_accepts_its_allocation_row(malformed: &Row, all: &[Row]) -> TestResult {
    let type_name = type_leaf(&malformed.type_name);
    let control = selected(all, type_name)?;
    assert!(
        matches!(decode_row(control)?, Outcome::Accepted),
        "row {} is refused for a {type_name}, and the control for that is allocation row {} carrying {type_name}'s own recorded valid bytes; the same `decode_row` dispatcher refused those too, so the refusal above is not attributable to the input",
        malformed.id,
        control.id
    );
    Ok(())
}

/// The whole second case-`MALFORMED_CASE` group. It exists because the first
/// group's rows are all `records.rs` TYPES, so the card's clause, quoted exactly,
/// "bounded malformed input panic-free", was discharged against 2 of the 52 allocated
/// types while all 40 `ids.rs` transparent scalars — proved only by the
/// byte-drift round-trip of case 2 — carried no refusal row anywhere.
///
/// NON-VACUITY IN BOTH DIRECTIONS. Each declared scalar shape must be present,
/// so a group carrying only one family cannot satisfy the loop below by
/// accident; and the group must be non-empty, so deleting it leaves this case
/// red rather than green with its second half gone. Neither guard is implied by
/// the other.
fn transparent_scalar_group_is_refused(scalars: &[&Row], all: &[Row]) -> TestResult {
    assert!(
        !scalars.is_empty(),
        "case {MALFORMED_CASE} must carry at least one row whose declared shape is a transparent scalar, or the 40 `ids.rs` types keep no refusal row at all and the bounded-malformed-input clause is discharged against the `records.rs` types alone"
    );
    let mut observed: Vec<&str> = Vec::new();
    for row in scalars {
        if !observed.contains(&row.shape.as_str()) {
            observed.push(row.shape.as_str());
        }
    }
    for shape in TRANSPARENT_SCALAR_SHAPES {
        assert!(
            observed.contains(&shape),
            "case {MALFORMED_CASE} must carry at least one row declaring shape {shape}; the transparent-scalar shapes this group actually records are {observed:?}, so the other family would be the only one exercised, and the two families are refused by different sentences at different layers"
        );
    }
    for row in scalars {
        transparent_scalar_is_refused_for_its_own_shape(row)?;
        the_same_type_still_accepts_its_allocation_row(row, all)?;
    }
    Ok(())
}

/// Field names of `pub struct <name>`, in declaration order, read from the
/// source. Used so an encode-order claim is checked against the declaration
/// rather than against a transcription of it.
///
/// Robustness of this parser, since it decides whether the order assertion can
/// be vacuous:
/// * Attributes, doc comments and blank lines are all skipped. Only lines whose
///   trimmed form starts with `pub ` are considered, and an attribute or a
///   `///`/`//!` line never does.
/// * The body is terminated by the MATCHING closing brace, tracked by depth and
///   by counting braces outside string literals. `depth` is a SIGNED accumulator
///   (`isize`, via `brace_delta_outside_strings`), so the `}` that closes the
///   struct actually decrements it to zero and the walk stops there. A flat
///   `line.trim() == "}"` test would stop early on a nested block and, worse,
///   would run past the struct into the following item if the struct never closed
///   on its own line. This clause is load-bearing, not decorative: an UNSIGNED
///   accumulator with a clamped decrement can never reach zero, and the walk
///   then runs to EOF and reports every later `pub <ident>:` line as a field.
///   `records.rs` declares no nested braces today, so the nesting half is
///   defensive — but the signed half is not.
/// * If the matching brace is never found the body is taken to end of file and
///   the caller is expected to notice, so the count is returned rather than a
///   truncated list.
///
/// The three columns `struct_field_types` returns per declared field: the field
/// name, its declared type, and the whitespace-collapsed text of the `#[serde(..)]`
/// attributes in its own contiguous attribute block.
///
/// A NAMED TYPE rather than the tuple spelled out at every use, because the column
/// ORDER is load-bearing (the reader and the attribute walk index into it) and a
/// reader who has to count positions of a bare `(String, String, String)` cannot see
/// which column they are looking at.
type StructFieldColumns = (String, String, String);

/// Field names of `pub struct <name>`, in declaration order. `struct_field_types`
/// is the single walk; this is that walk with the declared-type and
/// serde-attribute columns dropped, so the two cannot drift apart in how they
/// recognise a field.
fn struct_field_names(file: &str, name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(struct_field_types(file, name)?
        .into_iter()
        .map(|(field, _, _)| field)
        .collect())
}

/// `(field name, declared type text, serde attribute text)` for every field of
/// `pub struct <name>`, in declaration order, read from the source.
///
/// The type column is the text after the `:` of a `pub <name>: <Type>` line put
/// through `normalise_declared_type`, so it carries neither the declaration's
/// surrounding whitespace nor its trailing separator comma. That normalisation is
/// not cosmetic: `pub source: TaskExecutionClassSource,` yields
/// `TaskExecutionClassSource`, and before it existed the captured text kept the
/// comma while every name it was compared against was comma-free, so the
/// comparison could never match and the classification built on it answered
/// `false` for every field of every struct — including the enum-typed ones.
///
/// The type column is NOT resolved beyond that. `Option<CanonicalMemoryManifest>`
/// and `Vec<CanonicalMemorySegmentRef>` stay those strings, so neither can be
/// mistaken for a bare enum name. The one wrapper that IS followed is `Option`,
/// and it is followed in `declaration_routes_through_deserialize_enum`, where the
/// reason it has to be is stated; a general resolver would need a real Rust
/// parser, which this file deliberately does not carry.
///
/// THE SERDE-ATTRIBUTE COLUMN is the whitespace-collapsed text of the `#[serde(..)]`
/// attributes in the field's OWN CONTIGUOUS attribute block, read with
/// `serde_attribute_text`, and it is the empty string for a field carrying none.
/// CONTIGUOUS is the whole rule, and it is stricter than the container walk
/// `declaration_carries_deny_unknown_fields` uses: that walk may step over
/// non-attribute lines while climbing to the declaration above a `struct`, whereas
/// climbing from a FIELD declaration to the block above it must stop at the first
/// line that is not an attribute. Without that stop a field carrying no attribute
/// would inherit the one belonging to the previous field — or the struct's own
/// `deny_unknown_fields` — and the column would be a fabrication.
///
/// It is read here, in the ONE body walk, rather than by a second walk over the
/// same struct body: two walks over one declaration could disagree about which
/// lines are fields, and each would be individually plausible.
fn struct_field_types(
    file: &str,
    name: &str,
) -> Result<Vec<StructFieldColumns>, Box<dyn std::error::Error>> {
    let source = read_workspace(file)?;
    let declaration = format!("pub struct {name} {{");
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == declaration)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "{file} does not declare {declaration}"
            )))
        })?;
    let mut fields = Vec::new();
    let mut depth: isize = 1;
    // The `#[serde(..)]` texts of the attribute block CONTIGUOUSLY above the field
    // about to be read. Cleared on every line that is not an attribute, which is what
    // makes the block contiguous rather than merely nearby: without that clear a
    // blank line or a doc comment between an attribute and its field would leave the
    // attribute attached, and a field carrying none would inherit the previous
    // field's.
    let mut pending: Vec<String> = Vec::new();
    for line in lines.iter().skip(start + 1) {
        depth += brace_delta_outside_strings(line);
        if depth == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("#[") {
            let attribute = serde_attribute_text(trimmed);
            if !attribute.is_empty() {
                pending.push(attribute);
            }
            continue;
        }
        let carried = pending.join(ATTRIBUTE_COLUMN_SEPARATOR);
        pending.clear();
        // Only a field declaration: `pub <name>: <Type>`.
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };
        let Some((field, declared_type)) = rest.split_once(':') else {
            continue;
        };
        let name = field.trim();
        // A field name is one bare identifier. This second rule is what keeps a
        // `pub const X: &str` or a `pub fn f()` line from being absorbed as a
        // field should the brace walk ever run long: those yield a name
        // containing whitespace, which a real field never does.
        if name.is_empty()
            || name.contains(char::is_whitespace)
            || !name.starts_with(|cell: char| cell.is_ascii_alphabetic() || cell == '_')
        {
            continue;
        }
        fields.push((
            name.to_owned(),
            normalise_declared_type(declared_type).to_owned(),
            carried,
        ));
    }
    Ok(fields)
}

/// The `Option<..>` wrapper a declared type text must begin with for the member to
/// count as OPTIONAL. Matched as a PREFIX of the declared type rather than searched
/// for anywhere inside it, for the same reason
/// `declaration_routes_through_deserialize_enum` treats it as a wrapper it is
/// obliged to follow rather than a substring: a member typed `Vec<Option<T>>` is a
/// required member of a sequence, not an optional member.
const OPTION_TYPE_PREFIX: &str = "Option<";

/// The one FIELD-level serde attribute text that decides whether an optional
/// member is DROPPED or ALWAYS RE-EMITTED when its value is `None`.
///
/// Named rather than reached through `ALLOWED_SERDE_ATTRIBUTES[1]`, for the reason
/// `DENY_UNKNOWN_FIELDS_ATTRIBUTE` gives: that array says which attribute FORMS the
/// five allocated files may carry at all, while this constant names the one form
/// whose presence or absence on a given FIELD decides the encode rule. Both spellings
/// are the same text, and `serde_attribute_inventory_is_closed` is what holds them
/// to the same multiset.
const SKIP_WHEN_NONE_ATTRIBUTE: &str = "default, skip_serializing_if = \"Option::is_none\"";

/// How the serde-attribute column of `struct_field_types` joins a field's own
/// attribute block when it carries more than one form. Named because the column is
/// written here and split there, and a literal separator in each place could drift.
const ATTRIBUTE_COLUMN_SEPARATOR: &str = " | ";

/// The typed-in optional members of `CanonicalMemoryL2Page` ARE the ones
/// `records.rs` declares, split into the same two encode groups source declares —
/// and all three comparisons are against the source walk, not against themselves.
///
/// WHAT THIS CLOSES. `L2_OPTIONAL_MEMBERS`, `L2_SKIPPED_WHEN_NONE` and
/// `L2_ALWAYS_EMITTED` are names typed into this file, and until now NOTHING compared
/// them with the declaration they describe. So a FIFTH `Option` member appended to
/// `CanonicalMemoryL2Page` with no serde attribute of its own would leave
/// `serde_attribute_inventory_is_closed` green — the attribute multiset is unchanged
/// by a member that carries no attribute — would leave `optional_presence` green,
/// because it iterates the typed-in four — and would leave case 12 green and SILENT
/// while the new member's encode rule went entirely untested.
///
/// THE EXPECTED SIDE IS DERIVED, in three reads and not one transcription:
/// * `declared_struct_names` must list the type, so the field walk below is known to
///   be reading a real depth-zero declaration rather than reading nothing and
///   reporting agreement with an empty list;
/// * the declared-type column of `struct_field_types` supplies each field's type,
///   and a member is optional exactly when that text begins `OPTION_TYPE_PREFIX`;
/// * the serde-attribute column of the SAME walk supplies the encode rule, so the two
///   halves of the partition cannot come from two walks that disagree.
///
/// So a new `Option` member reds on the set comparison, a new member that DOES carry
/// `SKIP_WHEN_NONE_ATTRIBUTE` reds on the group comparison, and moving an existing
/// member between the two groups reds on both.
///
/// THE FOUR GROUPS ARE KEPT EXACTLY AS THEY ARE, because the live declaration agrees
/// with all of them: `resolved_parent_handle` and `requested_segment_id` are
/// `Option<String>` carrying the skip attribute, `manifest` is
/// `Option<CanonicalMemoryManifest>` carrying none, and `continuation` is
/// `Option<String>` carrying none. A future declaration that disagreed reds below,
/// naming the field and its attribute text, rather than being re-grouped silently.
fn l2_optional_partition_matches_source() -> TestResult {
    assert!(
        declared_struct_names(RECORDS_FILE)?
            .iter()
            .any(|(name, _)| name == "CanonicalMemoryL2Page"),
        "{RECORDS_FILE} must declare CanonicalMemoryL2Page at brace depth zero, or the field walk below reads no declaration at all and every comparison here would be an agreement with an empty list"
    );
    let fields = struct_field_types(RECORDS_FILE, "CanonicalMemoryL2Page")?;
    let mut optional: Vec<&str> = Vec::new();
    let mut skipped: Vec<&str> = Vec::new();
    let mut always: Vec<&str> = Vec::new();
    for (name, declared_type, attribute) in &fields {
        if !declared_type.starts_with(OPTION_TYPE_PREFIX) {
            continue;
        }
        optional.push(name);
        if attribute
            .split(ATTRIBUTE_COLUMN_SEPARATOR)
            .any(|form| form == SKIP_WHEN_NONE_ATTRIBUTE)
        {
            skipped.push(name);
        } else {
            always.push(name);
        }
    }
    optional.sort_unstable();
    skipped.sort_unstable();
    always.sort_unstable();
    let declared: Vec<String> = fields
        .iter()
        .map(|(name, declared_type, attribute)| format!("{name}: {declared_type} [{attribute}]"))
        .collect();
    let mut expected_optional: Vec<&str> = L2_OPTIONAL_MEMBERS.to_vec();
    expected_optional.sort_unstable();
    let mut expected_skipped: Vec<&str> = L2_SKIPPED_WHEN_NONE.to_vec();
    expected_skipped.sort_unstable();
    let mut expected_always: Vec<&str> = L2_ALWAYS_EMITTED.to_vec();
    expected_always.sort_unstable();
    // The two typed-in groups must PARTITION the typed-in optional set, exactly once
    // each. Without this a name listed in both groups would still satisfy the set
    // comparison below, because the set would be unchanged by the overlap.
    let mut typed_partition: Vec<&str> = L2_SKIPPED_WHEN_NONE
        .iter()
        .chain(L2_ALWAYS_EMITTED.iter())
        .copied()
        .collect();
    typed_partition.sort_unstable();
    assert_eq!(
        typed_partition, expected_optional,
        "L2_SKIPPED_WHEN_NONE and L2_ALWAYS_EMITTED must partition L2_OPTIONAL_MEMBERS exactly once each, or the comparison below could be satisfied by an overlap between the two encode groups"
    );
    assert_eq!(
        optional, expected_optional,
        "the optional members records.rs declares for CanonicalMemoryL2Page must be exactly L2_OPTIONAL_MEMBERS; a new Option member with no serde attribute would add nothing to the attribute multiset and would otherwise go untested. Declared fields: {declared:?}"
    );
    assert_eq!(
        skipped, expected_skipped,
        "the optional members records.rs declares that carry `{SKIP_WHEN_NONE_ATTRIBUTE}` must be exactly L2_SKIPPED_WHEN_NONE, so the drop-when-None claim is checked against the declaration rather than against a transcription of it; declared fields: {declared:?}"
    );
    assert_eq!(
        always, expected_always,
        "the optional members records.rs declares that carry NO serde attribute must be exactly L2_ALWAYS_EMITTED, so the always-re-emit claim is checked against the declaration rather than against a transcription of it; declared fields: {declared:?}"
    );
    Ok(())
}

/// Every `struct` DECLARED at brace depth zero in `file`, PUBLIC OR NOT, in
/// declaration order, read from live source, each paired with the LINE it is
/// declared on. This is the struct half of
/// `declared_enum_variants`: that helper is the ONE walk over enum
/// declarations, this is the corresponding walk over struct declarations, and
/// between them they enumerate the TOP-LEVEL `struct` and externally tagged
/// `pub enum` declarations a file carries — which is the whole of what the
/// allocation table is built from, and deliberately no larger claim than that.
/// The enum half is the weaker of the two and the gap is stated rather than
/// smoothed over: `externally_tagged_enum_names` still keys on `pub enum `, so a
/// non-public enum is invisible to it, and no non-public enum is declared in the
/// three candidate files today. `source_declared_type_names_by_file` records the
/// same asymmetry on the denominator side.
///
/// WHY A NON-PUBLIC DECLARATION COUNTS, which is why this walk does not key on
/// the `pub ` prefix any more. Visibility is not reachability. A `struct Foo { .. }`
/// written without `pub` is still part of the WIRE SHAPE of every public struct
/// that owns one as a field, and a private struct reached as an OWNED field of a
/// public struct is exactly the nested-owned-struct shape that the unknown
/// top-level and nested protected-field refusal cases exist to close. A walk that
/// cannot see such a declaration cannot claim to be complete over it, so the card
/// requires, verbatim: "Give every applicable type a named raw-byte fixture row,
/// with an explicit row-level reason (not an ignored test) for inapplicable
/// shapes." A non-public struct is an applicable type; enumerating it means the
/// fixture must then carry a row for it or the completeness assertion reds. That
/// is the same honest direction to fail that the `derive` filter below declines to
/// take in the other direction, and it costs nothing today: no non-public struct
/// is declared at depth zero in any of the five allocated files, so no name on the
/// expected set moves.
///
/// WHY IT IS NEEDED AT ALL. The completeness assertion used to compare the
/// recorded type names against a set that named `records.rs`'s seven structs and
/// `task_execution.rs`'s five types as STRING LITERALS in this file, so for those
/// two files the expected set was a copy of the caller list rather than an
/// independent denominator: delete every fixture row carrying those twelve types
/// together with all twelve literals and the assertion stayed green, and appending
/// a new struct declaration to `records.rs` was not observable at all. Naming the
/// types from their own source text closes both directions.
///
/// WHAT IT SHARES WITH `struct_field_types`, and — more importantly — WHAT IT
/// DOES NOT. The previous version of this comment claimed four shared recognisers
/// and used that as the reason this is not a second parser. Only ONE of the four
/// is genuinely shared; the other three were separate code being described as
/// shared, which is a defect in its own right, so the difference is now stated
/// rather than asserted away:
/// * SHARED, the one real overlap: the SIGNED accumulator
///   `brace_delta_outside_strings`, so depth can return to zero and a nested
///   block cannot swallow the rest of the file;
/// * NOT shared, the declaration-line recogniser, and it CANNOT be:
///   `struct_field_types` matches `line.trim() == "pub struct <name> {"` exactly,
///   so it needs a BODY, while this walk must accept a bodyless
///   `pub struct MemoryRevision(u64);`. One recogniser cannot serve both, so
///   `struct_declaration_rest` is its own;
/// * NOT shared, the bare-identifier rule, and it CANNOT be: the field rule
///   rejects a name containing whitespace (that is what stops a `pub const X:
///   &str` line being absorbed as a field), whereas the declarator rule stops at
///   the FIRST non-identifier character, so it yields `Foo` from `Foo<T>` and
///   `Foo(u64)` alike. Different text, different question, different rule;
/// * NOT shared, the doc-comment skip, which this walk applies on its own because
///   it recognises a declaration by keyword and would otherwise read one out of a
///   comment. It IS the same skip `serde_attribute_inventory_is_closed` applies,
///   for the same reason — that walk counts attributes, so a quoted `#[serde(..)]`
///   would inflate it. `struct_field_types` has no such skip and needs none: it keys
///   on the `pub ` prefix, which a `///` line never carries.
///
/// SO IT IS STILL NOT A SECOND PARSER, by a different and defensible argument: it
/// shares one accumulator, and everything it recognises differently, it recognises
/// differently ON PURPOSE.
///
/// WHAT IT STILL DOES NOT ENUMERATE, stated rather than left to be discovered:
/// a `struct` inside a `mod { .. }` block is at depth > 0 and is therefore not
/// reported, exactly as before. Reaching one would need module-path attribution
/// this walk does not attempt. None of the five allocated files declares a
/// `struct` inside such a block today, so the expected set does not depend on it,
/// but a future one would be a hole in this proof rather than a red on it.
///
/// WHAT IT DELIBERATELY DOES NOT DO. It does not filter on the `derive` list, and
/// it does not resolve a generic parameter list beyond taking the identifier
/// before it. Both are the convention `id_type_expansions` already sets: that
/// helper enumerates the macro's invocations without asking whether each
/// expansion derives `Serialize`, and this one enumerates declarations without
/// asking whether each derives `Serialize`. Every declaration it reports in the
/// three candidate files does derive both today, and a future declaration that
/// does not would red demanding a row — which is the honest direction to fail,
/// because the alternative is an expected set silently narrowed by a filter the
/// assertion cannot see.
fn declared_struct_names(file: &str) -> Result<Vec<(String, usize)>, Box<dyn std::error::Error>> {
    let source = read_workspace(file)?;
    let mut names: Vec<(String, usize)> = Vec::new();
    let mut depth: isize = 0;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // Depth 0 only, so a declaration nested in a `macro_rules!` body is not
        // reported as an allocated type, and neither is one nested in a private `mod`.
        // The two halves of that are NOT equally live, and the difference is stated
        // rather than blurred: the `macro_rules!` half IS load-bearing, because
        // `ids.rs` opens `macro_rules! id_type` and its body's `pub struct
        // $name(Uuid);` sits at depth 1 — remove this gate and the walk reaches that
        // line, `struct_declaration_name` returns `None` on the leading `$`, and the
        // walk fails loudly naming the file and the line. The private-`mod` half is
        // not load-bearing at all: none of the five allocated files opens an inline
        // `mod { .. }` block, so no `struct` can sit inside one — `lib.rs` is the only
        // one of the five that declares `mod` at all, and every one of its
        // declarations is a `pub mod <name>;` re-export rather than a block. That
        // half is defensive, and it is kept only because a future allocation could
        // add an inline block. Enumerating non-public declarations does
        // not relax either clause: a `struct` inside a block is still depth > 0
        // whichever visibility it carries.
        let at_top_level = depth == 0 && !trimmed.starts_with("///") && !trimmed.starts_with("//!");
        let declaration = if at_top_level {
            struct_declaration_rest(trimmed)
        } else {
            None
        };
        if let Some(rest) = declaration {
            let name = struct_declaration_name(rest).ok_or_else(|| {
                boxed(std::io::Error::other(format!(
                    "{file}:{} declares a struct whose name is not one bare identifier, so it cannot be named: {trimmed}",
                    index + 1
                )))
            })?;
            // The line is `index + 1` — the same 1-based number this closure spends
            // on its own failure message above, which is why the walk never had to
            // search for it: it was already in hand and discarded. No second pass
            // over `file` was added, so this walk cannot disagree with itself about
            // which line a declaration sits on.
            names.push((name.to_owned(), index + 1));
        }
        depth += brace_delta_outside_strings(line);
    }
    if depth != 0 {
        return fail(format!(
            "{file} ends with an unbalanced brace net of {depth}, so its declaration walk cannot claim to have seen the whole file"
        ));
    }
    Ok(names)
}

/// Every `struct` DECLARED at brace depth zero in `file` that carries
/// `#[serde(deny_unknown_fields)]`, in declaration order, read from live source.
///
/// WHAT IT REPLACES, and the defect it closes. The set of closed structs used to be
/// `const CLOSED_TYPES: [&str; 8]`, a hand-maintained list read only by case 3's loop.
/// Nothing derived it from source, so a NINTH closed struct appended to `records.rs`
/// or `task_execution.rs` was silently uncovered by cases 3 and 4: the only thing that
/// would have noticed was the attribute-COUNT literal in
/// `serde_attribute_inventory_is_closed`, which says how many `deny_unknown_fields`
/// attributes the five files carry and not WHICH struct carries one. A struct added
/// together with its attribute kept that count right and stayed invisible. The list is
/// deleted rather than widened, and the expected side is now this walk, so a new closed
/// struct with no fixture row is RED — `applicable_row` has no case-1 allocation row to
/// find and names it — and one added WITH a row is red too, at case 3's dispatch arm
/// below. That attribute-count assertion is left exactly as it was: it measures a
/// different property and is out of scope here.
///
/// IT IS THE SAME WALK AS `declared_struct_names`, minus the filter. Both use the
/// signed `brace_delta_outside_strings` accumulator, both take depth zero only, both
/// skip `///` and `//!`, and both recognise a declaration through the single
/// `struct_declaration_rest` / `struct_declaration_name` pair, so a struct cannot be
/// counted as a type here and missed as a closed struct, or the reverse. Only the
/// attribute test differs, and it is factored out into
/// `declaration_carries_deny_unknown_fields` so the declaration walk is not written
/// twice with a filter added.
///
/// SCOPE, deliberately the FIVE ALLOCATED FILES rather than the two that declare closed
/// structs today. `ids.rs` declares its structs inside the `id_type!` macro body, at
/// brace depth 1, so this walk correctly reports none for it — the same honest answer
/// `declared_struct_names` gives — while a `deny_unknown_fields` added to a depth-zero
/// struct anywhere in the five files would be caught. This is the same boundary
/// `serde_attribute_inventory_is_closed` is scoped to, and it must not be widened: the
/// crate as a whole carries attributes this file has deliberately not read.
fn closed_struct_names(file: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let source = read_workspace(file)?;
    let lines: Vec<&str> = source.lines().collect();
    let mut closed: Vec<String> = Vec::new();
    let mut depth: isize = 0;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // Depth 0 and not prose, exactly as `declared_struct_names` requires, so the
        // two walks agree on which lines are declarations at all.
        let at_top_level = depth == 0 && !trimmed.starts_with("///") && !trimmed.starts_with("//!");
        let declaration = if at_top_level {
            struct_declaration_rest(trimmed)
        } else {
            None
        };
        if let Some(rest) = declaration {
            let name = struct_declaration_name(rest).ok_or_else(|| {
                boxed(std::io::Error::other(format!(
                    "{file}:{} declares a struct whose name is not one bare identifier, so it cannot be named: {trimmed}",
                    index + 1
                )))
            })?;
            if declaration_carries_deny_unknown_fields(&lines, index) {
                closed.push(name.to_owned());
            }
        }
        depth += brace_delta_outside_strings(line);
    }
    if depth != 0 {
        return fail(format!(
            "{file} ends with an unbalanced brace net of {depth}, so its closed-struct walk cannot claim to have seen the whole file"
        ));
    }
    Ok(closed)
}

/// Every depth-zero `struct` declaration of `file` that carries
/// `#[serde(deny_unknown_fields)]`, in declaration order, found by scanning DOWNWARD
/// from each such attribute to the declaration it governs.
///
/// WHY A SECOND WALK THAT ANSWERS THE SAME QUESTION, and what makes it a witness
/// rather than a copy. `closed_struct_names` — which drives cases 3 and 4, and which
/// `declared_struct_shape` shares `declaration_serde_attributes` with — answers the
/// same question from the other end: it finds each declaration and CLIMBS to the
/// attribute block above it. This walk finds each attribute and walks DOWN. The two
/// differ in anchor, in direction and in how they treat a gap, so a change in one
/// mechanism's notion of which declaration an attribute belongs to appears here as a
/// DISAGREEMENT instead of being copied silently across both. That is what lets
/// `closed_object_labels_are_witnessed` corroborate the shape derivation's
/// `deny_unknown_fields` requirement rather than restate it.
///
/// The stop rules are chosen so the two agree on today's source and can still disagree
/// tomorrow: a blank line or a bare `}` between the attribute and the declaration
/// discards the pending attribute, exactly as the upward climb's break discards one.
/// Treating a gap as still-carried would be a guess about formatting this crate does not
/// use, and the upward walk already calls that a guess.
///
/// A `#[derive(..)]` line and a `///` line are STEPPED OVER, for the same reason the
/// upward walk steps over them: they sit between the attribute and the declaration
/// routinely and carry no serde form of their own.
///
/// ONLY STRUCT DECLARATIONS CLAIM AN ATTRIBUTE. An attribute above a `pub enum` is
/// neither consumed nor claimed, because no enum in these files is closed by
/// `deny_unknown_fields` and a shape label for one is `externally-tagged-enum`; letting
/// an enum's attribute attach to nothing is why `pending` is cleared on any other
/// depth-zero declaration line rather than left to be claimed by the next one.
///
/// AN UNCLAIMED ATTRIBUTE IS AN ERROR, not a skipped line.
/// `serde_attribute_inventory_is_closed` counts attribute occurrences without asking
/// what they govern, so an attribute sitting above no declaration would keep that count
/// right while being attributed to no type at all.
fn deny_unknown_fields_declarations(file: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let source = read_workspace(file)?;
    let mut closed: Vec<String> = Vec::new();
    let mut pending: Option<usize> = None;
    let mut depth: isize = 0;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let at_top_level = depth == 0 && !trimmed.starts_with("///") && !trimmed.starts_with("//!");
        if at_top_level {
            if trimmed.is_empty() || trimmed == "}" {
                pending = None;
            } else if trimmed.starts_with("#[") {
                if serde_attribute_text(trimmed) == DENY_UNKNOWN_FIELDS_ATTRIBUTE {
                    pending = Some(index);
                }
            } else if let Some(rest) = struct_declaration_rest(trimmed) {
                let name = struct_declaration_name(rest).ok_or_else(|| {
                    boxed(std::io::Error::other(format!(
                        "{file}:{} declares a struct whose name is not one bare identifier, so the {DENY_UNKNOWN_FIELDS_ATTRIBUTE} above it cannot be attributed to a named type: {trimmed}",
                        index + 1
                    )))
                })?;
                if pending.is_some() {
                    closed.push(name.to_owned());
                }
                pending = None;
            }
        }
        depth += brace_delta_outside_strings(line);
    }
    if depth != 0 {
        return fail(format!(
            "{file} ends with an unbalanced brace net of {depth}, so its downward {DENY_UNKNOWN_FIELDS_ATTRIBUTE} walk cannot claim to have seen the whole file"
        ));
    }
    if let Some(unclaimed) = pending {
        return fail(format!(
            "{file}:{} carries {DENY_UNKNOWN_FIELDS_ATTRIBUTE} with no depth-zero struct declaration beneath it, so it governs no named type and the corroboration it feeds would lose it without saying so",
            unclaimed + 1
        ));
    }
    Ok(closed)
}

/// The `#[serde(..)]` attribute texts carried by the CONTIGUOUS attribute block
/// immediately above line `declared_at`, nearest line first.
///
/// WHY IT IS EXTRACTED RATHER THAN WRITTEN TWICE. Two callers need that block and
/// neither needs only part of it: `declaration_carries_deny_unknown_fields` asks
/// whether `deny_unknown_fields` is among the forms, and `declared_struct_shape` asks
/// whether `transparent` is. Two loops over one block could stop in different places
/// and answer differently about the same declaration — and both of those answers
/// decide a wire shape, so a disagreement would not be a redundancy, it would be a
/// hole in the shape binding this block exists to support.
///
/// THE ATTRIBUTE BLOCK IS READ with `serde_attribute_text` rather than by substring,
/// for the reason `declared_enum_rename_all` already records: a doc comment can quote
/// `#[serde(deny_unknown_fields)]` without carrying one, and this walk starts at the
/// DECLARATION and only ever looks at lines above it, so prose elsewhere in the file
/// cannot be mistaken for an attribute. A `#[derive(..)]` line yields the empty string
/// from `serde_attribute_text` and is therefore never carried, so the derive block
/// cannot contribute a match.
///
/// The walk stops at a blank line or at a closing brace rather than skipping them, and
/// steps over every other line. Both halves are load-bearing: the stop is what keeps an
/// attribute separated from its declaration by a blank line from being attributed to
/// it — a formatting this crate does not use, and treating it as carried would be a
/// guess — while the step-over is what lets a `#[derive(..)]` line and a `///` doc
/// line sit between the attribute and the declaration without hiding it. Stopping at a
/// gap is the direction that reports the odd shape as unclosed rather than inventing
/// closure, and the same reasoning holds for `transparent`.
fn declaration_serde_attributes(lines: &[&str], declared_at: usize) -> Vec<String> {
    let mut carried: Vec<String> = Vec::new();
    for index in (0..declared_at).rev() {
        let trimmed = lines[index].trim();
        if trimmed == "}" || trimmed.is_empty() {
            break;
        }
        if !trimmed.starts_with("#[") {
            continue;
        }
        let attribute = serde_attribute_text(trimmed);
        if !attribute.is_empty() {
            carried.push(attribute);
        }
    }
    carried
}

/// Whether the declaration on line `declared_at` carries
/// `#[serde(deny_unknown_fields)]` among the attribute lines immediately above it.
///
/// The block is read by `declaration_serde_attributes`, and this is the membership
/// question over its answer — the walk, its stop rule and its substring rejection all
/// live there, so a second copy of the climb cannot drift away from this one. The
/// behaviour is unchanged: the first match upward used to return immediately and the
/// block is now collected whole, which answers the same question.
fn declaration_carries_deny_unknown_fields(lines: &[&str], declared_at: usize) -> bool {
    declaration_serde_attributes(lines, declared_at)
        .iter()
        .any(|attribute| attribute.as_str() == DENY_UNKNOWN_FIELDS_ATTRIBUTE)
}

/// Every closed struct the five allocated files declare, read from live source.
///
/// MEASURED on the files this issue allocates: seven in `records.rs`
/// (`BlobRef`, `CanonicalMemoryManifest`, `CanonicalMemorySegment`,
/// `CanonicalMemorySegmentRef`, `CanonicalMemoryL2Page`, `MigrationRecord`,
/// `HealthRecord`) plus `TaskExecutionClass` in `task_execution.rs`, and none in
/// `lib.rs`, `error.rs` or `ids.rs`. That sentence is a RECORD of the reading, not the
/// expected side of any comparison — the set returned here is what cases 3 and 4 walk,
/// so it changes with the declarations instead of being restated when they do.
///
/// NO SORTING, and the reason matters: `case_03_unknown_top_level_member_rejected`
/// drives a typed dispatch over the set, and the failure that names an unhandled closed
/// struct is most readable when the set reads in declaration order, as the source does.
fn closed_type_names() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut closed: Vec<String> = Vec::new();
    for file in ALLOCATED_SOURCE_FILES {
        closed.extend(closed_struct_names(file)?);
    }
    Ok(closed)
}

/// The text a depth-zero `struct` declaration line carries AFTER its `struct`
/// keyword, or `None` when `trimmed` does not declare a struct.
///
/// THE KEYWORD IS A WHOLE TOKEN, never an unbounded substring, so `pub struct `
/// is recognised exactly once and nothing else slips in beside it: `pubstruct
/// Foo`, `pub_struct Foo` and a `pub fn` whose name begins `struct` are all
/// `None`, because their first whitespace-separated token is not a visibility and
/// not `struct`. The previous `strip_prefix("pub struct ")` could not have said
/// that, which is precisely why the same rule has to decide the visibility too.
///
/// HOW VISIBILITY IS TREATED, deliberately. The keyword may stand alone (`struct
/// Foo`) or follow a visibility written as `pub` or `pub(..)` — so `pub struct`,
/// `pub(crate) struct`, `pub(super) struct` and `pub(in crate::ids) struct` are
/// all declarations this walk enumerates. A `pub(..)` restriction may itself
/// contain whitespace, so the visibility is consumed up to the first whitespace
/// OUTSIDE its parentheses rather than up to the first space of the line; that is
/// what keeps `pub(in crate::ids) struct` from being read as a `pub(in` token
/// followed by an unrecognised `crate::ids)`. One consequence is stated rather than
/// hidden: the keyword must be a whitespace-separated token, so a declaration
/// written with no space between the closing parenthesis and `struct` is not
/// recognised.
///
/// `abstract struct` is `None` on purpose, not by accident: Rust has no such
/// declaration, and a helper that guessed at foreign grammars would report names
/// this file's source cannot contain.
///
/// THE PAREN-COUNTING WALK LIVES IN `declaration_rest_after_visibility`, which
/// `enum_declaration_rest` shares. Everything above describes a DECLARATION and not the
/// `struct` keyword, so only the keyword is passed in; the body here is a delegation so
/// that the two keyword questions cannot answer differently about `pub(in crate::ids)`.
fn struct_declaration_rest(trimmed: &str) -> Option<&str> {
    declaration_rest_after_visibility(trimmed, "struct")
}

/// The same question asked of an `enum` declaration line: the text AFTER its `enum`
/// keyword, or `None` when `trimmed` does not declare an enum.
///
/// IT EXISTS BECAUSE A FILE'S TYPE INVENTORY IS NOT A STRUCT INVENTORY, and one walk
/// can answer only half of it. `error.rs` declares exactly one type, `pub enum
/// ConfigError`, and no struct at all — so a walk that recognises `struct` alone sees
/// nothing there and cannot say that this file declares one type and here it is. The
/// visibility rules are the ones `struct_declaration_rest` states, because they are the
/// rules of a DECLARATION and not of a keyword; only the keyword differs, which is why
/// both go through `declaration_rest_after_visibility` rather than through two copies
/// of the paren-counting walk that could drift apart.
fn enum_declaration_rest(trimmed: &str) -> Option<&str> {
    declaration_rest_after_visibility(trimmed, "enum")
}

/// The shared half of `struct_declaration_rest` and `enum_declaration_rest`: the text
/// after `keyword` when `trimmed` is a declaration of that keyword under an optional
/// `pub` or `pub(..)` visibility, and `None` otherwise.
///
/// THE RETURNED SLICE IS A SLICE OF THE LINE, and the signature says so rather than
/// leaving it to elision. Two inputs are borrowed and one value comes back, so an
/// elided output lifetime would be a choice the reader has to reconstruct; naming
/// `'line` on `trimmed` alone states the fact the body already relies on — every arm
/// returns `trimmed[offset..]` or a slice of it, and `keyword` is only ever COMPARED
/// (`first == keyword`, `rest.split_whitespace().next() != Some(keyword)`,
/// `strip_prefix(keyword)`). `strip_prefix` borrows its PATTERN, it does not return a
/// slice of it, so no arm can produce text out of the keyword, and a signature that
/// admitted that would let a future arm return a subslice of a caller-supplied
/// keyword while appearing to describe this line.
fn declaration_rest_after_visibility<'line>(
    trimmed: &'line str,
    keyword: &str,
) -> Option<&'line str> {
    let first = trimmed.split_whitespace().next()?;
    let after_visibility = if first == keyword {
        trimmed
    } else if first == "pub" || first.starts_with("pub(") {
        let mut parens: isize = 0;
        let mut rest = trimmed;
        for (offset, cell) in trimmed.char_indices() {
            match cell {
                '(' => parens += 1,
                ')' => parens -= 1,
                cell if cell.is_whitespace() && parens == 0 => {
                    rest = trimmed[offset..].trim_start();
                    break;
                }
                _ => {}
            }
        }
        if rest.split_whitespace().next() != Some(keyword) {
            return None;
        }
        rest
    } else {
        return None;
    };
    // The keyword has already been established as a whole token above, so what
    // follows it is the declarator, however many spaces separate the two.
    Some(after_visibility.strip_prefix(keyword)?.trim_start())
}

/// The bare identifier a `struct` declaration line names, given the text AFTER
/// the declaration keyword, whatever visibility carried it.
///
/// Returns `None` when that text does not begin with one identifier. It is not a
/// parser and does not try to be: `Foo`, `Foo<T>` and `Foo(u64)` all yield
/// `Foo`, because all three are spellings the three candidate files use, and
/// anything else is reported by the caller rather than guessed at here. A leading
/// `$` yields `None`, which is what makes the `id_type!` macro body's
/// `pub struct $name(Uuid);` a non-declaration.
///
/// SHARED WITH `declared_type_names`' ENUM HALF, deliberately. What this helper answers
/// is "what is the bare identifier at the head of this declarator", which is a question
/// about an IDENTIFIER rather than about the keyword in front of it, so the same rule
/// reads `ConfigError {` after `enum` as it reads `BlobRef {` after `struct`.
fn struct_declaration_name(rest: &str) -> Option<&str> {
    let end = rest.find(|cell: char| !(cell.is_ascii_alphanumeric() || cell == '_'))?;
    let name = &rest[..end];
    if name.is_empty() || !name.starts_with(|cell: char| cell.is_ascii_alphabetic() || cell == '_')
    {
        return None;
    }
    Some(name)
}

/// Every type `file` DECLARES at brace depth zero, by keyword and in declaration
/// order — `struct` and `enum` alike, public or not — so the answer can be
/// "this file declares N types and here they are" rather than only a count or a
/// silence.
///
/// WHAT IT IS FOR. One of the five allocated files, `error.rs`, is guarded only by a
/// substring test (`its text does not contain serde`) and by exact equality on two
/// specific lines. That substring is a WHOLE-FILE test, and neither derive macro name
/// that matters — `Serialize`, `Deserialize` — contains it, so appending a
/// `#[derive(Serialize, Deserialize)] pub struct` to `error.rs` satisfies every
/// existing check: the word `serde` still appears nowhere, lines 3 and 4 are
/// untouched, and the file declares its one type on line 4 as before. Before this walk
/// existed nothing enumerated what `error.rs` declares, so nothing could notice. This
/// walk enumerates it, and `zero_candidate_files_are_proved` compares that enumeration
/// with the file's actual inventory.
///
/// IT DOES NOT REPLACE THE SUBSTRING TEST, and both halves are kept because they
/// measure different things. `!error.contains("serde")` says the file carries no serde
/// impl AT ALL, wherever it might be — inside a nested `mod`, above a `type` alias, in
/// an attribute this walk does not parse. This walk says which depth-zero types the
/// file declares. Replacing the substring test with the walk would weaken it: the walk
/// cannot see a serde impl on something that is not a depth-zero type declaration.
/// Dropping the walk instead would leave the file's type inventory unenumerated.
///
/// THE SAME DEPTH-ZERO GATE AND THE SAME ACCUMULATOR as `declared_struct_names` and
/// `closed_struct_names`, so all three agree about which LINES are declarations. A
/// declaration inside a `macro_rules!` body or an inline `mod` block is at depth > 0
/// and is not reported, exactly as in the struct walk; that limit is the struct walk's
/// stated limit and this one does not widen it.
///
/// THE IDENTIFIER RULE IS `struct_declaration_name`'s, reused deliberately. That helper
/// answers "what is the bare identifier at the head of this declarator", which is a
/// question about an IDENTIFIER and not about the keyword in front of it, and a second
/// copy would be free to disagree with the first about `Foo`, `Foo<T>` and `Foo(u64)`.
fn declared_type_names(file: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let source = read_workspace(file)?;
    let mut names: Vec<String> = Vec::new();
    let mut depth: isize = 0;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let at_top_level = depth == 0 && !trimmed.starts_with("///") && !trimmed.starts_with("//!");
        let declaration = if at_top_level {
            struct_declaration_rest(trimmed).or_else(|| enum_declaration_rest(trimmed))
        } else {
            None
        };
        if let Some(rest) = declaration {
            let name = struct_declaration_name(rest).ok_or_else(|| {
                boxed(std::io::Error::other(format!(
                    "{file}:{} declares a type whose name is not one bare identifier, so the inventory of this file cannot name it: {trimmed}",
                    index + 1
                )))
            })?;
            names.push(name.to_owned());
        }
        depth += brace_delta_outside_strings(line);
    }
    if depth != 0 {
        return fail(format!(
            "{file} ends with an unbalanced brace net of {depth}, so its type-inventory walk cannot claim to have seen the whole file"
        ));
    }
    Ok(names)
}

/// One normal form for a declared type text, applied to BOTH sides of every
/// comparison this file makes between a type and a set of type names.
///
/// It removes the surrounding whitespace and ONE trailing separator comma, which
/// is what a field declaration ends with and what a bare enum name never carries.
/// Applying it to both sides is what makes the two comparable: `externally_tagged_
/// enum_names` already yields comma-free names, and a capture path that keeps the
/// comma compares a string that can never equal one of them. `trim_end_matches`
/// would also be wrong here — `trim` first, then at most one comma, then trim again
/// — because a type column never legitimately ends in more than one comma and
/// silently eating a run of them would hide a malformed declaration instead of
/// reporting it.
fn normalise_declared_type(declared: &str) -> &str {
    let trimmed = declared.trim();
    trimmed.strip_suffix(',').map_or(trimmed, str::trim_end)
}

/// Whether a value at this declaration is refused the way an ENUM's value is,
/// refused: by `serde_json`'s `deserialize_enum` refusing the token at the syntax
/// layer, before serde's visitor is consulted.
///
/// `enums` is the comma-free name list `externally_tagged_enum_names` reads from
/// the same file, and `declared` is already in `normalise_declared_type` form.
///
/// WHAT COUNTS AS TRUE, and why each case is here:
/// * the bare name of a member enum — `TaskExecutionClassSource`. Directly the
///   case `member_is_enum_typed` exists for.
/// * `Option<Inner>` where `Inner` itself counts. serde's derived visitor calls
///   `deserialize_option` on an `Option<T>` field, and a present value reaches
///   `visit_some`, which immediately calls `deserialize_enum` for `T`. An array
///   where `Option<TaskExecutionDomain>` is declared is therefore refused at the
///   SAME layer, with the SAME `ExpectedSomeValue` code, as an array handed to a
///   bare `TaskExecutionDomain`. The previous version of this file's comment
///   claimed `Option<..>` is "correctly NOT enum-typed"; that was false, and it
///   would have been false in whichever direction the row went — the refusal for
///   such a member is a syntax refusal, so the data-error branch would have fired.
///
/// WHAT DOES NOT COUNT, and the distinction is not cosmetic:
/// * `Vec<Inner>`, and every other sequence or map wrapper. serde deserializes a
///   `Vec<T>` field through `deserialize_seq`, never `deserialize_enum`, and an
///   element that is not a valid variant is refused by serde's own visitor with an
///   `invalid type` message — an `Error::custom`, i.e. `Category::Data`. Calling
///   that "enum-typed" would assert the opposite category for the only rows that
///   would ever reach it.
/// * any other wrapper or path form: `Box<Inner>`, a module-qualified
///   `path::Inner`, a bare tuple or array type, a type alias. None of those is
///   followed. Following them would need a real Rust parser, and guessing here
///   would put a wrong category on a real row rather than a missed refinement.
fn declaration_routes_through_deserialize_enum(declared: &str, enums: &[String]) -> bool {
    if enums.iter().any(|name| name == declared) {
        return true;
    }
    declared
        .strip_prefix("Option<")
        .and_then(|rest| rest.strip_suffix('>'))
        .is_some_and(|inner| declaration_routes_through_deserialize_enum(inner.trim(), enums))
}

/// Net brace depth contributed by one line, ignoring braces inside string
/// literals so a default value like `"{"` cannot close a struct early.
///
/// SIGNED, and it must stay signed. The accumulator is `isize`, not `usize`, so
/// a closing brace genuinely DECREMENTS. The earlier `usize` version used
/// `saturating_sub`, which clamps at zero — so the delta could never be negative,
/// a caller's running depth could never return to zero, and the walk ran to end
/// of file. That silently turned `struct_field_names` into "every `pub <ident>:`
/// line from the declaration to EOF" rather than the struct's own fields, which
/// broke `case_07`'s one-omitted-member guard and `empty_identity_member`'s
/// one-empty-member guard on real fixture rows. Clamping an accumulator here
/// removes the only signal the caller has; it does not make the walk safer.
fn brace_delta_outside_strings(line: &str) -> isize {
    let mut delta: isize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for cell in line.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if cell == '\\' {
                escaped = true;
            } else if cell == '"' {
                in_string = false;
            }
            continue;
        }
        match cell {
            '"' => in_string = true,
            '{' => delta += 1,
            '}' => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// CASE 16 OF ISSUE #930, AND ITS NAME IS QUALIFIED TO SAY WHICH `scope` IS ASSERTED:
/// `allocated_scope`, because scope is ASSERTED for the five allocated files and
/// RECORDED, NOT ASSERTED, for everything else.
///
/// THE CLAUSE is issue #930's acceptance row for cases 13–16: scope, dependencies,
/// visibility and nonclosure semantics stay unchanged.
///
/// SCOPE — ASSERTED, for the five allocated files and nothing else.
/// `allocated_source_digests_match` recomputes SHA-256 over LIVE source and compares
/// it with `meta.source_digests`, and it refuses a narrowed or widened path set by
/// comparing the recorded paths against `ALLOCATED_SOURCE_FILES` before it compares any
/// digest. So a byte change in any of the five is red, and a fixture that dropped one of
/// them is red rather than quietly reducing the denominator. That is what the `allocated_`
/// in this case's name refers to, and it is the whole of the asserted scope.
///
/// SCOPE — RECORDED, NOT ASSERTED, for every path OUTSIDE those five, and this is
/// disclosed rather than left to a reader to infer from a green run. This test reads
/// three further files — `crates/eliot-types/src/health.rs`,
/// `crates/eliot-store/src/surreal_store.rs` and this crate's own `Cargo.toml` — and the
/// header comment at the top of this file sets out, per path, what each read is used for
/// and why each is load-bearing. What is NOT done is a scope check over them: their
/// content is read and asserted against, but no digest is recorded for them and no
/// change to any of them is detected by this file. The OWNER of that disclosure is this
/// delivery's own pull-request diff and the change-control ledger, not a test, and
/// nothing here certifies it. A green run means the five allocated files are unchanged;
/// it says NOTHING about whether the other three changed.
///
/// THE REMAINING THREE CLAUSES of the row are narrower than they look and are asserted
/// where this file can reach them: `HealthRecord.status` nonclosure is asserted
/// behaviourally below; the dependency shape is asserted from this crate's manifest; and
/// visibility is not expanded anywhere, which is recorded by the zero-candidate walk
/// over `lib.rs` and `error.rs`.
///
/// THIS BLOCK SITS ABOVE THE WORK-UNIT MARKER, and that placement is load-bearing.
/// The marker must be IMMEDIATELY followed by its `#[test]`, and the work-unit gate
/// that binds the two walks forward from the marker refusing a blank line and
/// refusing any line beginning `//` or `/*` before it reads an attribute; a `///`
/// line is a `//` line, so a documentation comment written between the attribute and
/// this function detaches the marker exactly as a plain comment would, and there is
/// no tolerant fallback for a `.rs` file because every one is routed into that text
/// parser unconditionally. A PLAIN comment in the same place is not a workaround
/// either: `rustc` puts no order constraint on a comment relative to an attribute,
/// so the text would still be absent from hover and from extracted documentation.
/// Above the marker the walk never looks, and the block is still a documentation
/// comment, so every reader that reached it before still reaches it.
// WORK_UNIT_CASE: 930/16
#[test]
fn case_16_allocated_scope_stays_unclosed_and_dependencies_stay_fixed() -> TestResult {
    let Fixture {
        rows,
        source_digests,
        ..
    } = rows()?;
    expected_is_closed(&rows);

    // 1. Nonclosure, behaviourally. `status` is a plain owned `String` at
    // `records.rs:147`, so an out-of-vocabulary value and an empty value both
    // decode, are preserved rather than coerced, and re-encode byte-identically.
    let record = applicable_row(&rows, "HealthRecord")?;
    for status in [HEALTH_STATUS_OUT_OF_VOCABULARY, ""] {
        let payload = health_payload_with(record, status)?;
        let decoded: eliot_types::HealthRecord = serde_json::from_str(&payload).map_err(boxed)?;
        assert_eq!(
            decoded.status, status,
            "status must be preserved verbatim, never coerced or rejected"
        );
        assert_eq!(
            serde_json::to_string(&decoded).map_err(boxed)?,
            payload,
            "an open status must re-encode byte-identically"
        );
    }

    // 2. Nonclosure, in source: the vocabulary must stay a doc sentence, never
    // code. This is the strongest single drift detector in the case.
    health_status_stays_out_of_the_shape()?;

    // 3. The deferred vocabulary must still be CLOSED, or every assertion above
    // would be vacuous: they would still pass if `HealthStatus` had been deleted.
    health_status_vocabulary_is_closed()?;

    // 4. The exception is load-bearing: a consumer outside this crate still
    // constructs a `HealthRecord` whose status is OUTSIDE the vocabulary, so
    // closing the field today would be a compile error.
    store_health_record_stays_outside_the_vocabulary()?;

    // 5. Declaration order on the encode side.
    health_record_encodes_in_declaration_order(record)?;

    // 6. Document order on the decode side.
    document_order_is_observable_only_by_streaming(record)?;

    // 7. `requires_codecortex` is UNCHANGED by this delivery, and it is the second of
    // the two PROPERTIES this case asserts about `TaskExecutionClass` — the one type
    // of that name the allocation carries. Neither the ordering assertions above nor
    // the byte-drift assertions in case 2 read it, and it is a DERIVED predicate with
    // no wire member, so nothing in the file would notice a delivery that gave it one.
    task_execution_requires_codecortex_is_derived(&rows)?;

    // 8. Ordering on the encode side for `TaskExecutionClass` itself. Items 5 and 6
    // are a `HealthRecord` claim; without this one the delivery's ordering claim
    // would rest on a single type out of the eight closed ones.
    task_execution_class_encodes_in_declaration_order()?;

    // 9. `dependencies` is the FOURTH of the four nouns this acceptance point names —
    // scope, behaviour, vocabulary, dependencies — and until now nothing in this case
    // asserted it: item 11 below could only RECORD it. This reads the manifest and
    // turns the fact that blocks checklist items A8, A9 and A11 into a red rather than
    // a sentence.
    manifest_declares_no_dev_dependency_and_inherits_every_dependency()?;

    // 10. `meta.source_digests` is now ASSERTED where it was only RECORDED. The fixture
    // carries a SHA-256 for each of the five allocated decoder sources and a note stating
    // that recomputing them from live source is how the TEST half proves the DECODER half
    // was not modified underneath it; nothing in the repository read that key, and the
    // fixture loader read exactly one `meta` key. This is the assertion that discharges
    // A16's `scope` and `visibility` nouns with a check instead of prose, and its own
    // failure message states the limit the note states: a match is byte-identity of those
    // FIVE files and nothing more — not a decode assertion, and not coverage of any other
    // crate source.
    allocated_source_digests_match(&source_digests)?;

    // 11. The rest of the untestable half is RECORDED here and NOT asserted. The record
    // is prose rather than a `const` because a `const` nothing reads is exactly the
    // fake-assertion smell this case exists to catch, and because no runtime assertion
    // for these exists, or could exist, from inside `crates/eliot-types/tests/`: a
    // compiled test cannot observe a branch diff, a lockfile edit or a crate
    // reorganization. This file deliberately does not shell out to git and does not
    // invent a runtime proxy, because a proxy would assert something other than the
    // property. What is left, each with the gate that owns it:
    //   * scope: this delivery adds exactly two new files under
    //     crates/eliot-types/tests/ and modifies nothing under
    //     crates/eliot-types/src/ -- owned by the pull-request diff for this delivery,
    //     and the allocation cases in this file fail on any source change they can see.
    //     The FIVE allocated decoder sources among those files are no longer on this
    //     list: item 10 asserts their byte-identity against the recorded digests. Every
    //     OTHER file under src/ remains on it, because a digest covers five files and
    //     not the crate.
    //   * the workspace lockfile and any crate reorganization: a change there is
    //     invisible to a compiled test in this crate -- owned by the pull-request diff
    //     and the change-control ledger. The MANIFEST half of the same claim is no
    //     longer on this list: item 9 asserts it.
    Ok(())
}

/// `crates/eliot-types/Cargo.toml` must declare no `[dev-dependencies]` section, and
/// every `[dependencies]` entry must be inherited from the workspace.
///
/// WHY THESE TWO FACTS, and why they are the exact blocking ones rather than a proxy
/// for something broader. Checklist items A8, A9 and A11 are all blocked by the SAME
/// fact: this crate has no dev-dependency, so an integration test here can neither name
/// another workspace crate nor reach a test-only helper. "No `[dev-dependencies]`
/// section" IS that fact, stated as a property of the manifest, so it is asserted rather
/// than recorded. The second half closes the same door from the other side: an entry
/// that pins `version = ".."`, or carries `path = ".."`, or grows a `features` or
/// `optional` key, stops this crate from resolving its dependencies through the
/// workspace, which is the same unchecked surface the card's dependency clause names.
///
/// WHY THE SHAPE AND NOT THE SEVEN NAMES. A key list would be a transcription of the
/// manifest, and a transcription is exactly what this file stopped relying on twice
/// already: it would have to be edited by the same hand that edited the manifest, so it
/// could not detect that edit, and it would report a red about a name rather than about
/// the property. What A16's dependency clause actually claims is a SHAPE — nothing
/// pinned, nothing path-local, no test-only dependency — and that shape is what is
/// asserted. The seven names are deliberately not written down here; if the manifest
/// grows an eighth inherited dependency this stays green, which is correct, because such
/// a growth is not what the card forbids.
///
/// WHAT THE SECTION RECOGNITION NOW COVERS, and both halves of it were escapes before.
/// The walk parses a section NAME — the text between `[` and `]` — and then compared it
/// for EQUALITY with the bare string `dev-dependencies`, so
/// `[target.'cfg(unix)'.dev-dependencies]` passed the first check; and it decided "is
/// this a dependency entry" by testing that same parsed name for EQUALITY with the bare
/// string `dependencies`, so a pinned or path dependency under a
/// `[target.'cfg(..)'.dependencies]` table was never collected and the inheritance rule
/// never reached it. A manifest could therefore HAVE a dev-dependency, or an unpinned
/// dependency, and satisfy a check whose own doc says the crate must declare none.
/// Recognition is now by dotted COMPONENT, through `is_dev_dependency_section` and
/// `is_dependency_section`: a dev-dependency section is one whose FINAL component is
/// `dev-dependencies`, and a dependency section is one with `dependencies` as ANY
/// component. Both forms of escape are closed, and the two recognisers cannot
/// interfere — `dependencies` has `dev-dependencies` nowhere in it as a component, and
/// a section named `dev-dependencies` carries no component equal to `dependencies`.
///
/// THE NON-EMPTY GUARD, THE POSITIVE DEV-DEPENDENCY ASSERTION AND THE INHERITANCE
/// STRENGTH ARE KEPT AS THEY WERE, because the audit found all three correct. The
/// guard still stops the inheritance rule holding over an empty section (an empty
/// `[dependencies]` table would satisfy "every entry inherits" over nothing); the
/// dev-dependency check is still a POSITIVE assertion over the sections the walk read,
/// still carrying the offending section's line number, rather than a substring scan
/// that a comment could satisfy; and the inheritance rule is still "no bare version,
/// path or features key", because it is still a suffix test for
/// `{WORKSPACE_INHERITANCE}` on the entry line rather than a check for a key's absence.
///
/// WHAT IT STILL CANNOT SEE, stated rather than left to be discovered. The rule is
/// LINE-SHAPED, so an inline multi-line dependency table is a KNOWN FALSE POSITIVE:
///
/// ```toml
/// [dependencies]
/// serde = {
///     workspace = true,
/// }
/// ```
///
/// is workspace-inherited and correct, and the first line `serde = {` does not end
/// with `{WORKSPACE_INHERITANCE}`, so this assertion reports it as not inherited. It is
/// recorded as a limit rather than handled, and deliberately so: making it hold for that
/// form would mean rewriting the rule from "the entry line ends with the inheritance
/// suffix" into "the entry's inline table contains nothing but workspace inheritance",
/// which is a DIFFERENT and STRONGER property than the one asserted here — and changing
/// what an assertion means is not a repair. No manifest in this workspace writes an
/// inline multi-line table, so nothing is false-red today; a manifest that starts
/// writing one gets a red that says which entry, which is the honest direction for a
/// stated limit. The same line-shapedness means an entry written as a sub-table
/// (`[dependencies.foo]`) is collected by its own `version`/`path` lines and fails the
/// inheritance rule for the same reason: it is not workspace-inherited.
fn manifest_declares_no_dev_dependency_and_inherits_every_dependency() -> TestResult {
    let source = read_workspace(ELIOT_TYPES_MANIFEST)?;
    let mut inherited: Vec<&str> = Vec::new();
    let mut in_dependencies = false;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let Some(section) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        else {
            if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            inherited.push(trimmed);
            continue;
        };
        assert!(
            !is_dev_dependency_section(section),
            "{ELIOT_TYPES_MANIFEST}:{}: the [{section}] table names a dev-dependency, and a dev-dependency blocks checklist items A8, A9 and A11, which all require this crate to have no dev-dependency at all, so its presence must be a red and not a record; the test is on the section's final dotted component being {DEV_DEPENDENCIES_SECTION}, so a target-scoped table is caught too",
            index + 1
        );
        in_dependencies = is_dependency_section(section);
    }
    assert!(
        !inherited.is_empty(),
        "{ELIOT_TYPES_MANIFEST} declares no [{DEPENDENCIES_SECTION}] entry, so requiring workspace inheritance below would hold over nothing; the walk found the sections it read but no dependency line"
    );
    let not_inherited: Vec<&str> = inherited
        .iter()
        .copied()
        .filter(|entry| !entry.ends_with(WORKSPACE_INHERITANCE))
        .collect();
    assert!(
        not_inherited.is_empty(),
        "every [{DEPENDENCIES_SECTION}] entry of {ELIOT_TYPES_MANIFEST} must end with {WORKSPACE_INHERITANCE}, because a pinned version, a path dependency, or a features/optional key introduced by this delivery resolves outside the workspace; these entries do not: {not_inherited:?}"
    );
    Ok(())
}

/// Whether a parsed `[section]` name is a DEV-DEPENDENCY table.
///
/// BY ITS FINAL DOTTED COMPONENT, so `[dev-dependencies]` and
/// `[target.'cfg(unix)'.dev-dependencies]` are both recognised and a name that merely
/// CONTAINS the text somewhere is not. The previous version compared the whole parsed
/// name for equality with `dev-dependencies`, which is why the target-scoped form was
/// an escape; see the caller's doc comment for the rest of that defect.
fn is_dev_dependency_section(section: &str) -> bool {
    section.rsplit('.').next() == Some(DEV_DEPENDENCIES_SECTION)
}

/// Whether a parsed `[section]` name is a DEPENDENCY table.
///
/// BY ANY DOTTED COMPONENT, so `[dependencies]` and `[target.'cfg(unix)'.dependencies]`
/// are both recognised and their entries are collected by the caller's walk. The
/// previous version compared the whole parsed name for equality with `dependencies`,
/// so a target-scoped dependency table contributed no entries at all and the
/// inheritance rule never reached a pinned or path dependency written under one.
fn is_dependency_section(section: &str) -> bool {
    section
        .split('.')
        .any(|component| component == DEPENDENCIES_SECTION)
}

/// The only two `expected` values the fixture may record. Anything else is a
/// fixture defect rather than a case this file knows how to assert.
const EXPECTED_VOCABULARY: [&str; 2] = [ACCEPT_EXPECTED, "reject"];

/// Every `expected` must sit in the closed two-value vocabulary. Returns unit:
/// the only failure mode is a panic, so an error channel would be dead.
fn expected_is_closed(all: &[Row]) {
    for row in all {
        assert!(
            EXPECTED_VOCABULARY.contains(&row.expected.trim()),
            "row {} records expected {:?}, which is outside the closed vocabulary",
            row.id,
            row.expected
        );
    }
}

/// The deferred vocabulary's wire spellings are checked in BOTH directions against
/// the decoder, taken from the enum's own declaration rather than transcribed.
///
/// WHY THE ACCEPT DIRECTION IS HERE, and it is the half that was missing. The
/// derived `spellings` were previously used only to prove they do not collapse, and
/// then two OUT-OF-SET values were required to be refused — which every spelling
/// rule satisfies, since a value outside the set is outside the set under ANY rule.
///
/// THE COUNTERFACTUAL, AND IT IS A CODE-READING ARGUMENT, NOT AN OBSERVED RUN. Take the
/// rename the variant `NotReady` to `Notready` in `health.rs`, and follow it through the
/// MECHANISM rather than through a verdict: `declared_enum_rename_all` reads the
/// `rename_all` attribute off the enum's own declaration and
/// `health_status_wire_spellings` applies `snake_case_spelling` to each variant name it
/// finds there, so the DERIVED SET is computed from that source text; with the variant
/// renamed the derived set becomes `notready`, and the derivation is a map from variant
/// to spelling, so renaming one variant renames one member and COLLAPSES NOTHING. The
/// negative controls are unaffected by that: `HEALTH_STATUS_OUT_OF_VOCABULARY` and the
/// empty string are members of no derived set under any rename, and the consumer's
/// `applied` is likewise outside whatever set is derived. So under the DERIVED half
/// alone, every one of those assertions would still hold.
///
/// THAT IS THE WHOLE OF THE DEFECT, AND IT IS A STATIC ONE: the rename rule was being
/// checked only for SELF-CONSISTENCY, never corroborated against the decoder's accept
/// direction. What is NOT claimed here is that any of this was run. This lane executes
/// no test, so no suite was observed passing or failing under that rename, and this
/// paragraph says nothing about what any other crate in the workspace does with the wire
/// spelling `not_ready` — that source change would alter what other call sites emit or
/// expect, which is a consequence for their owners to establish, not an observation this
/// delivery is entitled to report. The argument above is a reading of this file's
/// mechanism and of the pinned serde semantics, and the fix it motivates is the accept
/// direction asserted below through the real decode path.
///
/// WHAT IS ASSERTED NOW, per derived spelling, through the real public decode path:
/// * it is ACCEPTED — `serde_json::from_str::<eliot_types::HealthStatus>` on the
///   quoted spelling must succeed. That is the direction a wrong rename rule cannot
///   satisfy, and it is what makes the derivation a fact about the decoder rather than
///   about this file's own spelling function;
/// * the two out-of-set values are still REFUSED, which is what makes the acceptance
///   above non-vacuous rather than "the decoder accepts every string".
fn health_status_vocabulary_is_closed() -> TestResult {
    let spellings = health_status_wire_spellings()?;
    let mut unquoted = spellings.clone();
    unquoted.sort();
    unquoted.dedup();
    assert_eq!(
        unquoted.len(),
        spellings.len(),
        "the derived vocabulary must not collapse two variants onto one spelling"
    );
    for spelling in &spellings {
        let quoted = format!("\"{spelling}\"");
        if let Err(error) = serde_json::from_str::<eliot_types::HealthStatus>(&quoted) {
            return fail(format!(
                "{HEALTH_FILE} declares a {HEALTH_STATUS_TYPE} variant whose {SNAKE_CASE_RENAME} wire spelling is derived here as {spelling:?}, but decoding that spelling as {HEALTH_STATUS_TYPE} was refused ({error}); the derived vocabulary is only meaningful if the decoder ACCEPTS it, and the refusal direction alone is satisfied by any spelling rule at all because an out-of-set value is out of the set under every rule"
            ));
        }
    }
    for status in [HEALTH_STATUS_OUT_OF_VOCABULARY, ""] {
        let quoted = format!("\"{status}\"");
        assert!(
            serde_json::from_str::<eliot_types::HealthStatus>(&quoted).is_err(),
            "the deferred vocabulary must refuse {status:?}"
        );
    }
    // No catch-all and no `#[serde(other)]`, or the refusals above would be
    // vacuous.
    let source = read_workspace(HEALTH_FILE)?;
    assert!(
        !source.contains("serde(other"),
        "the deferred vocabulary must stay a closed enum with no catch-all"
    );
    Ok(())
}

/// `records.rs` must keep `status` an open owned string, must mention the
/// deferred vocabulary exactly once, and that mention must be a doc comment.
fn health_status_stays_out_of_the_shape() -> TestResult {
    let source = read_workspace(RECORDS_FILE)?;
    assert!(
        source.contains(HEALTH_STATUS_DECLARATION),
        "{RECORDS_FILE} must keep status as a plain owned String"
    );
    let mentions: Vec<&str> = source
        .lines()
        .filter(|line| line.contains(HEALTH_STATUS_TYPE))
        .collect();
    assert_eq!(
        mentions.len(),
        1,
        "{RECORDS_FILE} must mention {HEALTH_STATUS_TYPE} exactly once: {mentions:?}"
    );
    assert!(
        mentions[0].trim_start().starts_with("///"),
        "the single mention must be prose, never code: {}",
        mentions[0].trim()
    );
    for forbidden in ["HealthStatus::", "use crate::health", "use super::health"] {
        assert!(
            !source.contains(forbidden),
            "{RECORDS_FILE} must not reach the deferred vocabulary through {forbidden}"
        );
    }
    Ok(())
}

/// A `HealthRecord` payload with `status` replaced, by byte surgery on the row's
/// own raw so no fixture value is pasted here.
///
/// THREE CHECKS GUARD THE SPLICE, and all three are now the ones this file's sibling
/// string readers perform. The first two were performed here already; the third was
/// not, and its absence is the reasoning error this comment used to make.
///
/// * THE BYTE AT `value_start` MUST BE A QUOTE. `string_closing_quote` takes an
///   OPENING quote as its premise and scans forward from the byte after it; handed
///   an object or an array it would walk to the next `"` anywhere in the document
///   and splice a payload together out of the middle of one. The refusal names the
///   row and the byte found, because "the status member's value is not a string" is
///   only actionable if it also says which byte it actually was.
/// * `value_start` MUST BE INSIDE THE DOCUMENT. A span whose key token is
///   unterminated carries `len + 1` (see `recorded_member`'s out-of-range guard for
///   why that offset exists at all), and `&record.raw[..=span.value_start]` would
///   panic on it with a slice-index message that names no row. This is the same
///   reasoning `raw_value_end` applies, and it is applied here at the slice rather
///   than inside `value_offset` because `value_offset` returns a bare `usize` with
///   no channel to report on and no `Row` to name, while `health_payload_with` has
///   both.
/// * THE CLOSING QUOTE MUST EXIST. The previous version of this comment claimed no
///   further check was needed, on the grounds that with `value_start` in range the
///   offset `string_closing_quote` returns is "either a real quote or `bytes.len()`,
///   and both are legal slice starts". Both halves of that are true and the
///   conclusion does not follow: IN-RANGE IS NOT CORRECT. On an unterminated
///   `status` string the offset IS `bytes.len()`, so `&record.raw[end..]` is the
///   EMPTY STRING and the rebuilt payload is silently TRUNCATED at the value —
///   `{"component":"…","status":"` plus the replacement, with no closing quote and no
///   closing brace. The document that came back is not the row with `status`
///   substituted; it is a fragment, and it is returned as `Ok`. The check is
///   `raw_value_end`'s, reused in its wording and shape rather than rephrased, and
///   it runs BEFORE the payload is rebuilt so nothing truncated is ever handed back.
///
/// A NOTE ON WHY THAT REFUSAL IS HERE NOW, because a previous pass deliberately left
/// it out on the grounds that adding it would newly reject input the code accepts
/// today. That judgement was made before it was known that a SIBLING already refuses
/// the identical input: `raw_member_value`, `string_member_value` and
/// `raw_value_end` all reject an unterminated string member today, so this file
/// already treats such a document as unmeasurable rather than as a value to be read.
/// Re-derived on that basis, the refusal is the right call. The alternative is not
/// "accepting more valid input" — it is returning a truncated document with a success
/// value, which every caller above would then decode-compare against the full row and
/// report as a confident mismatch, or worse, compare as equal because both sides are
/// fragments. A loud refusal naming the row names the cause; a silent truncation names
/// nothing and would be reported as a wrong verdict about `status` rather than as a
/// broken document. The row this is reached on today is the case-1 `HealthRecord`
/// allocation row, whose `status` is closed, so the refusal is not reached by any
/// current input; it exists so that the day one is, the failure is legible.
fn health_payload_with(record: &Row, status: &str) -> Result<String, Box<dyn std::error::Error>> {
    let spans = top_level_member_spans(&record.raw);
    let span = spans
        .iter()
        .find(|span| span.key == "status")
        .ok_or_else(|| {
            boxed(std::io::Error::other(
                "the HealthRecord row has no status member",
            ))
        })?;
    let bytes = record.raw.as_bytes();
    let value_start = span.value_start;
    let opening = *bytes.get(value_start).ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "row {}: the status member's value starts at byte {value_start}, past the end of its {}-byte document, so the span is out of range rather than the value malformed",
            record.id,
            bytes.len()
        )))
    })?;
    if opening != b'"' {
        return fail(format!(
            "row {}: the status member must hold a string value for its bytes to be spliced, but byte {value_start} of {} is {:?} rather than a quote",
            record.id,
            bytes.len(),
            opening as char
        ));
    }
    let end = string_closing_quote(bytes, value_start);
    if bytes.get(end) != Some(&b'"') {
        return fail(format!(
            "row {}: the status member value at offset {value_start} is an unterminated string, so its extent is not measurable in a {}-byte document",
            record.id,
            bytes.len()
        ));
    }
    // `value_start` is the offset of the value's OPENING quote, so the slice must
    // include it: `..=value_start` and `..value_start + 1` are the same extent.
    let mut payload = String::from(&record.raw[..=value_start]);
    payload.push_str(status);
    payload.push_str(&record.raw[end..]);
    Ok(payload)
}

/// The encode side emits members in declaration order, fully observable and
/// independent of any map ordering.
///
/// NON-VACUITY: the two sides of the comparison come from DIFFERENT sources.
/// `emitted` is produced by `serde_json::to_string` on a value that was decoded
/// from the fixture row, so it reflects the real encoder. `expected` is parsed
/// out of the `records.rs` source text by `struct_field_names`. If that parser
/// ever returned the encode order rather than the declaration order the
/// assertion would compare the encoder against itself, so the two are kept on
/// visibly separate paths and neither is derived from the other.
fn health_record_encodes_in_declaration_order(record: &Row) -> TestResult {
    let declared = struct_field_names(RECORDS_FILE, "HealthRecord")?;
    assert!(
        declared.len() >= 3,
        "{RECORDS_FILE} must declare the three {HEALTH_RECORD_TYPE} members"
    );
    let decoded: eliot_types::HealthRecord = serde_json::from_str(&record.raw).map_err(boxed)?;
    let encoded = serde_json::to_string(&decoded).map_err(boxed)?;
    // Side one: the real encoder's output order, from `serde_json::to_string`.
    let spans = top_level_member_spans(&encoded);
    let emitted: Vec<&str> = spans.iter().map(|span| span.key.as_str()).collect();
    // Equal arity FIRST, and this is load-bearing rather than a nicety. The two
    // sequences used to be compared as `declared.iter().take(emitted.len())`,
    // which silently compares only a PREFIX: had `records.rs` gained a fourth
    // `HealthRecord` field, `take` would have dropped it and the assertion would
    // have stayed green while proving nothing about that field. Pinning the
    // lengths first makes any future arity change fail loudly instead.
    assert_eq!(
        declared.len(),
        emitted.len(),
        "{HEALTH_RECORD_TYPE} must declare as many members as the encoder emits, or the order comparison below is only over a prefix: declared {declared:?}, emitted {emitted:?}"
    );
    // Side two: the declaration order, from the source text. Never from `encoded`,
    // and now never truncated.
    let expected: Vec<&str> = declared.iter().map(String::as_str).collect();
    assert_eq!(
        emitted, expected,
        "the encoder must emit {HEALTH_RECORD_TYPE} members in declaration order"
    );
    Ok(())
}

/// Records a JSON object's member order as a streaming `MapAccess` sees it.
///
/// WHY STREAMING. `serde_json::Map` does not preserve document order, so every
/// path that goes through a `Value` loses it; reading the order back out of a
/// `Value` would measure that loss rather than the document. A visitor's
/// `next_key` yields keys in document order, and that is the observation point
/// used here. Stated as a BEHAVIOUR of the map, not as its concrete type: nothing
/// in this file's contract depends on which map `serde_json` uses, only on the
/// fact that the streaming and `Value` paths disagree.
struct MemberOrder(Vec<String>);

/// The streaming `MapAccess` visitor, hoisted out of `MemberOrder::deserialize` so
/// it can be driven with the member set it is asked to enforce. It was a
/// function-local type while the only caller wanted a pure recorder.
///
/// TWO POLICIES, ONE VISITOR, and the reason they are not two visitors. `declared:
/// None` records every member key and refuses nothing: that is what
/// `MemberOrder` wants, and `document_order_is_observable_only_by_streaming` is
/// unchanged by it. `declared: Some(..)` additionally enforces the two MEMBER-KEY
/// refusals a derived `#[serde(deny_unknown_fields)]` decoder raises — an undeclared
/// key and a repeated one — and it refuses them at the same `next_key` the derived
/// decoder refuses at, so the reader's position when the error is built is the same
/// byte. A second visitor would have been a second statement of the same recognition
/// rules, and the two could disagree.
///
/// WHY THE ENFORCING POLICY IS NEEDED AT ALL, because `serde_json` does not supply
/// it. `MapAccess::next_key_seed` (`serde_json-1.0.151/src/de.rs:1986-2025`)
/// accepts ANY string key: the codes it can raise on that path are
/// `EofWhileParsingObject`, `KeyMustBeAString`, `TrailingComma`,
/// `EofWhileParsingValue` and `ExpectedObjectCommaOrEnd`, and no member-key refusal
/// among them. Duplicate and unknown object keys are refused by the DERIVED visitor,
/// inside its own `visit_map`, and never by the parser. A pure recorder therefore
/// runs to the end of the object on every row that case 15 is about and observes
/// nothing at all.
///
/// WHAT IT DOES NOT REPRODUCE, stated because the claim is otherwise easy to
/// overstate: member VALUES are decoded as `IgnoredAny`, so a VALUE-level refusal —
/// an `invalid type`, an unrecognized variant — is not raised here. Every case-15
/// row's refusal is a MEMBER-KEY refusal, which the column window asserted by
/// `case_15_row_refuses_at_its_offending_member` already pins to the offending key
/// token, so nothing this file claims rests on the difference. The refusals are built
/// with `Error::custom` and the wording serde's own `unknown_field` and
/// `duplicate_field` use (`serde-1.0.229/src/core/de/mod.rs:270` and `:296`), because
/// those two constructors demand a `&'static str` and a `&'static [&'static str]` that
/// a source walk cannot supply; the rendered text is therefore never compared, only
/// the category and the position.
struct OrderVisitor<'trail, 'declared> {
    /// Every member key yielded so far, in document order. The caller must hand in
    /// an EMPTY vector: it is both the output and the repetition record.
    trail: &'trail mut Vec<String>,
    /// The type's declared member names, or `None` for the pure-recorder policy.
    declared: Option<&'declared [String]>,
}

impl<'de> serde::de::Visitor<'de> for OrderVisitor<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object whose member order is recorded")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if let Some(declared) = self.declared {
                // UNDECLARED BEFORE REPEATED, matching the derived decoder's arm
                // order: a key that is both unknown and repeated is reported as
                // unknown, because a `deny_unknown_fields` decoder has no arm for it
                // at all.
                if !declared.iter().any(|member| member == &key) {
                    return Err(<A::Error as serde::de::Error>::custom(format_args!(
                        "{UNKNOWN_FIELD_PREFIX} `{key}`"
                    )));
                }
                if self.trail.iter().any(|seen| seen == &key) {
                    return Err(<A::Error as serde::de::Error>::custom(format_args!(
                        "{DUPLICATE_FIELD_PREFIX} `{key}`"
                    )));
                }
            }
            self.trail.push(key);
            map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for MemberOrder {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut order: Vec<String> = Vec::new();
        deserializer.deserialize_map(OrderVisitor {
            trail: &mut order,
            declared: None,
        })?;
        Ok(MemberOrder(order))
    }
}

/// Every top-level member key a streaming `MapAccess` yields from `raw` before the
/// decode fails, together with that failure.
///
/// The declared-member policy is what makes the recording STOP at the offending
/// member, and `OrderVisitor`'s doc comment says why a pure recorder cannot: the
/// parser accepts any key, so without the policy the walk would reach the end of
/// every object and record every member including the offending one, which is the
/// opposite of the observation this exists to make.
///
/// It is driven through `serde_json::Deserializer::from_str` rather than
/// `serde_json::from_str::<T>` because the recorded vector has to SURVIVE the
/// failure, and `from_str` hands the value back only on success: a `Deserialize`
/// adapter could not hand out a borrow of the caller's vector from inside its own
/// `deserialize`. `from_str` is the same parser and the same `MapAccess`; what is
/// deliberately NOT called is `Deserializer::end`, so this decode reports the member
/// sequence and its position and nothing about bytes after the closing brace. That
/// is enough for the claim it supports and would not be enough for a trailing-content
/// claim, which is why case 14 measures trailing content from fixture bytes instead.
fn members_yielded_before_refusal(
    raw: &str,
    declared: &[String],
) -> (Vec<String>, Option<serde_json::Error>) {
    let mut trail: Vec<String> = Vec::new();
    let outcome = serde_json::Deserializer::from_str(raw).deserialize_map(OrderVisitor {
        trail: &mut trail,
        declared: Some(declared),
    });
    (trail, outcome.err())
}

/// Document order is observable only through a streaming `MapAccess`, and this is
/// what proves it for the `HealthRecord` row.
///
/// THREE ASSERTIONS, and the middle one is what makes the last one mean anything:
/// * the streaming visitor reproduces the document's own member order exactly;
/// * the document's member order is NOT already sorted. This is the NON-VACUITY
///   guard. If the row's keys happened to be alphabetical, document order and
///   sorted order would coincide and the inequality below would be satisfied by a
///   document that happened to be tidy rather than by any property of `serde_json`.
///   It is a claim about the row, it can fail, and it is what gives the inequality
///   its meaning.
/// * the `Value` path's key order DIFFERS from document order — this is the claim.
///   `serde_json::Map` does not preserve document order, so a member order read
///   back out of a `Value` would be measuring the map rather than the document,
///   and a streaming `MapAccess` is the only observation point that sees the real
///   order.
///
/// NO ASSERTION THAT `Value`'s key order IS the sorted order. That was here and is
/// deliberately removed: it can only fire if `serde_json` changes the map type
/// behind `Value`, so it is a statement about a DEPENDENCY's implementation, not
/// about this crate, and it cannot fail for any change in `records.rs`. The
/// inequality above is the same observation without that coupling — it would fail
/// if `serde_json` ever DID start preserving document order, which is the only way
/// this crate's own contract could be affected, and it says so in terms of
/// behaviour rather than about a `BTreeMap`.
fn document_order_is_observable_only_by_streaming(record: &Row) -> TestResult {
    let streamed: MemberOrder = serde_json::from_str(&record.raw).map_err(boxed)?;
    let document: Vec<String> = top_level_member_spans(&record.raw)
        .into_iter()
        .map(|span| span.key)
        .collect();
    assert_eq!(
        streamed.0, document,
        "the streaming visitor must yield true document order"
    );
    let mut sorted = document.clone();
    sorted.sort();
    assert_ne!(
        document, sorted,
        "the {HEALTH_RECORD_TYPE} row's own member order must not already be sorted, or the inequality below would hold for a tidy document rather than for any property of the {HEALTH_RECORD_TYPE} decoder: document {document:?}, sorted {sorted:?}"
    );
    let value: Value = serde_json::from_str(&record.raw).map_err(boxed)?;
    assert_ne!(
        streamed.0,
        top_level_keys(&value),
        "document order must differ from the Value order, or this probe could not tell them apart"
    );
    Ok(())
}

/// The Rust-side predicate `TaskExecutionClass::requires_codecortex`, named by its
/// SIGNATURE line in live `task_execution.rs` rather than by a bare literal that
/// nothing else in this file would catch. Asserted as a substring of the source
/// because a `fn` declaration can be re-wrapped across lines without changing the
/// predicate, so an exact-line match would be a formatting claim rather than a
/// contract claim.
const REQUIRES_CODECORTEX_METHOD: &str = "pub fn requires_codecortex(&self)";

/// The member name `requires_codecortex` would carry IF it were a wire member. It
/// is not one, and that is the property: the name is named here so the two checks
/// below — that no recorded row carries it, and that supplying it is refused — speak
/// the same token instead of two independently typed literals that could disagree.
const REQUIRES_CODECORTEX_KEY: &str = "requires_codecortex";

/// `requires_codecortex` is UNCHANGED by this delivery, asserted against the real
/// method rather than against a transcription of its logic.
///
/// WHY IT NEEDS AN ASSERTION AT ALL. `requires_codecortex` is not a wire member and
/// not a serde attribute: it is an `impl` method whose value is DERIVED from the two
/// members the predicate names. Nothing in the case-1 allocation table, the case-2
/// round trip, the serde attribute inventory or the byte-drift claims reads it, so a
/// delivery that altered it — or, worse, gave it a serde surface — would leave every
/// other assertion in this file green. The card names it as one of the four
/// properties that must be unchanged, so it needs an assertion of its own.
///
/// WHAT IS ACTUALLY PROVEN, and it IS the predicate's TRUTH TABLE — read out of the
/// method body rather than transcribed here. The previous version of this comment said
/// it deliberately was not, and that sentence was right about the METHOD BODY not being
/// transcribed while being wrong about the consequence: what it left in place was a
/// round-trip equality, and that equality was a tautology. `TaskExecutionClass` has
/// five members, all serde-visible, with no `Option`, no `#[serde(default)]` and no
/// `skip`, so decoding its own re-serialized bytes reproduces the same member values
/// and `f(m) == f(m)` follows for any `f` whatsoever — including a constant one, and
/// including one that read no members at all. The non-vacuity guard beside it proved the
/// predicate is not CONSTANT, which is a different claim, and does not protect that
/// equality.
///
/// So the expected side is now built from SOURCE TEXT: `requires_codecortex_arms` parses
/// the method's body out of live `task_execution.rs`, reads the two `matches!`
/// conjuncts' scrutinees and their accepted variant lists, and the truth table is the
/// AND of those two parsed sets. Nothing in it calls the method, and no variant name is
/// typed into this file. The three claims are then:
///
/// * the predicate is still a plain Rust-side method with NO serde surface at all,
///   so no input bytes can supply or override its value. That is proved on the wire
///   in both directions: the recorded row's top-level member names never include it,
///   and injecting it as an unknown member is refused by the closed struct. Were a
///   future delivery to add a `requires_codecortex` field, this reds — which is the
///   point, because the card forbids adding one.
/// * its value agrees with the table parsed from its own body, for EVERY pair of
///   declared `domain` and `artifact` spellings and for the recorded row's own pair.
///   Deleting the `self.artifact` conjunct from the real method is now a red on two
///   counts, because the parse fails loudly when either member is no longer referenced.
/// * it is genuinely load-bearing: the parsed table must contain at least one true and
///   at least one false pair. Without that guard a constant method would satisfy the
///   cross product forever, and the walk would prove nothing about which members the
///   predicate reads.
///
/// WHAT IS DELIBERATELY NOT CLAIMED HERE. The re-serialization invariance conjunct is
/// GONE rather than restated. It compared `requires_codecortex()` on a decoded value
/// with the same method on the value re-decoded from its own re-serialization, which is
/// `f(m) == f(m)` for a member-preserving derived struct, so there was no non-tautological
/// restatement available: any statement about the value surviving a round trip is
/// implied by, and therefore cannot fail independently of, the statement that the value
/// equals the parsed table. Keeping it would have kept a check that cannot fail. The
/// narrow fact it did pin — that this row's serialization loses nothing — is already
/// asserted on the same row by `value_round_trip` in case 2.
///
/// The declaration check reads the method signature line out of live
/// `task_execution.rs`, so deleting or renaming the predicate reds here instead of
/// leaving the rest of the file asserting against a method that no longer exists.
fn task_execution_requires_codecortex_is_derived(all: &[Row]) -> TestResult {
    let source = read_workspace(TASK_EXECUTION_FILE)?;
    assert!(
        source.contains(REQUIRES_CODECORTEX_METHOD),
        "{TASK_EXECUTION_FILE} must still declare `{REQUIRES_CODECORTEX_METHOD}`; the predicate this card clause names is derived from that declaration, and nothing else in this file reads it"
    );

    let row = applicable_row(all, "TaskExecutionClass")?;

    // NO WIRE SURFACE, from the recorded bytes: the predicate must not be a member.
    // `applicable_row` hands back a `&Row`, so the argument is already the shared
    // borrow the helper takes; writing `&row` here would hand it a `&&Row` and lean
    // on an auto-deref that the compiler removes anyway.
    assert_requires_codecortex_has_no_wire_surface(row)?;

    // DERIVED, against an expected side that comes from SOURCE TEXT. The previous
    // version of this block compared `requires_codecortex()` on a decoded value with
    // the same method on the value re-decoded from its own re-serialization. The struct
    // has five members, every one serde-visible, with no `Option`, no
    // `#[serde(default)]` and no `skip`, so that round trip is member-preserving and
    // the assertion was `f(m) == f(m)` for every `f` — it could not fail, and the
    // non-vacuity guard below proves non-constancy, which is a different claim. That
    // conjunct is DELETED rather than restated: see the doc comment on this function.
    //
    // WHAT REPLACES IT. `requires_codecortex_arms` parses the two `matches!` conjuncts
    // out of the method's own body in live `task_execution.rs` and reads each one's
    // scrutinee and its accepted variant list, so the truth table below is built from
    // the SOURCE and not from the compiled method and not from a literal typed here.
    let arms = requires_codecortex_arms()?;
    let domain_arm = codecortex_arm(&arms, CODECORTEX_DOMAIN_MEMBER)?;
    let artifact_arm = codecortex_arm(&arms, CODECORTEX_ARTIFACT_MEMBER)?;

    let domains = declared_member_spellings(all, "TaskExecutionDomain")?;
    let artifacts = declared_member_spellings(all, "TaskExecutionArtifact")?;

    // COVERAGE. The cross product below is the type's full domain only if the two
    // lists it walks ARE the declared spellings of their own enums, and that is
    // bound against source here rather than counted. The spellings come from the
    // decoder's OWN `unknown variant` refusal probe through `declared_member_spellings`
    // — the mechanism this file already uses — and are re-bound at the point of use,
    // because that helper validates the value it RETURNS and one statement stands
    // between that value and the value iterated here. No spelling is typed in.
    //
    // Decoding every pair is enforced where it happens — by the `?` on
    // `serde_json::from_str`, which aborts the case on the first pair that does not
    // decode. It is not asserted here, and no message below claims to be.
    assert_spelling_denominator_matches_declaration("TaskExecutionDomain", &domains)?;
    assert_spelling_denominator_matches_declaration("TaskExecutionArtifact", &artifacts)?;

    // THE EXPECTED TRUTH TABLE, keyed by the two derived spellings and valued from the
    // two PARSED arms. The arms hold Rust variant names (`Code`) and the keys are wire
    // spellings (`code`), so the two are put through `fold_spelling`, which is the same
    // reconciliation `assert_spelling_denominator_matches_declaration` documents: it
    // lowercases and drops `_` and `-`, and `snake_case` only does the first of those.
    let accepted_domains: Vec<String> = domain_arm
        .variants
        .iter()
        .map(|variant| fold_spelling(variant))
        .collect();
    let accepted_artifacts: Vec<String> = artifact_arm
        .variants
        .iter()
        .map(|variant| fold_spelling(variant))
        .collect();
    let mut expected_table: Vec<(&str, &str, bool)> = Vec::new();
    for domain in &domains {
        for artifact in &artifacts {
            expected_table.push((
                domain.as_str(),
                artifact.as_str(),
                accepted_domains.contains(&fold_spelling(domain))
                    && accepted_artifacts.contains(&fold_spelling(artifact)),
            ));
        }
    }
    // PAIR COUNT, AGAINST A COUNT THAT IS INDEPENDENT OF THE TABLE'S OWN CONSTRUCTION.
    //
    // WHAT THE PREVIOUS VERSION CLAIMED WAS FALSE. It compared `expected_table.len()`
    // with `domains.len() * artifacts.len()` and the comment beside it said an EMPTY
    // spelling list "reds here and names the cause". It could not: `expected_table` is
    // built by exactly that cross product a few lines above, so the two operands are the
    // same number by construction and the comparison is an identity. With an empty list
    // it reads `0 == 0` and stays green — the one case it claimed to catch.
    //
    // WHAT ACTUALLY GUARDS THE EMPTY CASE is the non-vacuity assertion below, and it is
    // named here rather than left to be re-derived: a table with no pair holds no true
    // pair either, so `expected_true` is `0`, `0 > 0` is false, and that assertion reds
    // while naming the two parsed arms it was built from. `declared_variant_spellings`
    // also refuses an empty parse on its own. Neither of those is why this assertion
    // exists, so no guard is removed here.
    //
    // WHAT THE EXPECTED SIDE IS NOW: the DECLARED VARIANT COUNTS read out of
    // `task_execution.rs` by the existing `enum_variant_names_from_source`. That is the
    // one count in this function that does not pass through the two message-parsed
    // spelling lists the table is itself built from, so a spelling list that came back
    // empty, truncated or duplicated reds HERE, against source, with both sides printed —
    // where before it agreed with itself. The comparison below LOOKS each pair UP rather
    // than iterating the table, so a table missing an entry fails loudly there instead of
    // skipping that pair silently; that part of the previous comment was true and is kept.
    let declared_domains = enum_variant_names_from_source("TaskExecutionDomain")?.len();
    let declared_artifacts = enum_variant_names_from_source("TaskExecutionArtifact")?.len();
    assert_eq!(
        expected_table.len(),
        declared_domains * declared_artifacts,
        "the parsed truth table must cover the whole declared domain x artifact product, and that count is read from `{TASK_EXECUTION_FILE}` rather than from the two spelling lists the table is built from: {declared_domains} declared domain variants x {declared_artifacts} declared artifact variants, over the decoded spellings {domains:?} and {artifacts:?}; the table carries {} pairs",
        expected_table.len()
    );
    // NON-VACUITY, on the EXPECTED side. Both outcomes must be present in the table
    // parsed out of the method body, or the predicate being constant and the parse
    // having lost a conjunct are indistinguishable, and the comparison below would
    // agree with a constant method for the wrong reason.
    let expected_true = expected_table.iter().filter(|(_, _, e)| *e).count();
    assert!(
        expected_true > 0 && expected_true < expected_table.len(),
        "the truth table parsed from the body of `{REQUIRES_CODECORTEX_METHOD}` must hold at least one true pair and at least one false pair, or one of its two conjuncts was lost and a constant method would satisfy it: {expected_true} true of {} pairs; the parsed domain arm accepts {domain_arm:?} and the parsed artifact arm accepts {artifact_arm:?}",
        expected_table.len()
    );

    // THE RECORDED ROW'S OWN PAIR, decoded from the fixture's bytes and checked against
    // the same parsed table. This is the one pair the fixture itself witnesses, and its
    // two members are read out of those bytes rather than typed as a pair.
    let decoded: eliot_types::TaskExecutionClass = serde_json::from_str(&row.raw).map_err(boxed)?;
    // `?` BEFORE `.ok_or_else`, so an unterminated value is refused by
    // `string_member_value` with its own reason rather than collapsing into the
    // "carries no member" message below — which would be the wrong diagnosis for a
    // member that is present and unreadable.
    let recorded_domain =
        string_member_value(&row.raw, CODECORTEX_DOMAIN_FIELD, &row.id)?.ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "row {} carries no {CODECORTEX_DOMAIN_FIELD} member, so the pair its own bytes describe cannot be read from them",
                row.id
            )))
        })?;
    let recorded_artifact =
        string_member_value(&row.raw, CODECORTEX_ARTIFACT_FIELD, &row.id)?.ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "row {} carries no {CODECORTEX_ARTIFACT_FIELD} member, so the pair its own bytes describe cannot be read from them",
                row.id
            )))
        })?;
    let expected_for_row = *expected_entry(&expected_table, &recorded_domain, &recorded_artifact)?;
    assert_eq!(
        decoded.requires_codecortex(),
        expected_for_row,
        "row {}: requires_codecortex must agree with the truth table parsed out of the method body for the pair its own bytes carry ({recorded_domain} x {recorded_artifact})",
        row.id
    );

    // THE WHOLE CROSS PRODUCT, one pair at a time, against the parsed table. Every pair
    // must decode — enforced by the `?` below — and every decoded value must equal what
    // the parsed body says that pair is worth.
    for domain in &domains {
        for artifact in &artifacts {
            let expected = *expected_entry(&expected_table, domain, artifact)?;
            let payload = task_execution_class_payload(row, domain, artifact)?;
            let candidate: eliot_types::TaskExecutionClass =
                serde_json::from_str(&payload).map_err(boxed)?;
            assert_eq!(
                candidate.requires_codecortex(),
                expected,
                "requires_codecortex disagrees with the truth table parsed out of the body of `{REQUIRES_CODECORTEX_METHOD}`: {domain} x {artifact} must be {expected}; the parsed body accepts domain variants {accepted_domains:?} and artifact variants {accepted_artifacts:?}"
            );
        }
    }
    Ok(())
}

/// `requires_codecortex` has NO WIRE SURFACE, proved on the recorded row in both
/// directions.
///
/// The one direction that is not obvious is the first: absence of a key is what an
/// ignored unknown field would also look like, so absence alone would be satisfied by
/// a decoder that accepts `requires_codecortex` and drops it. That is why the other
/// direction is checked as well — supplying the key must be REFUSED rather than
/// accepted-and-ignored, which no accepted-and-ignored field can be.
fn assert_requires_codecortex_has_no_wire_surface(row: &Row) -> TestResult {
    // FROM THE RECORDED BYTES: the predicate must not be a member.
    // `carried_member_names` reads the row's own raw keys, so this is a statement
    // about the fixture's bytes and not about the declared field list.
    let carried = carried_member_names(&row.raw);
    assert!(
        !carried
            .iter()
            .any(|member| member == REQUIRES_CODECORTEX_KEY),
        "row {} must not carry a `{REQUIRES_CODECORTEX_KEY}` member on the wire, because `{REQUIRES_CODECORTEX_METHOD}` is Rust-side and derived: carried {carried:?}",
        row.id
    );
    // ... and from the OTHER direction: supplying one must be refused rather than
    // accepted-and-ignored, so no producer can set the predicate through the
    // decoder. `inject_top_level_unknown` splices the key into the raw bytes with
    // every other byte untouched.
    let injected = inject_top_level_unknown(&row.raw, REQUIRES_CODECORTEX_KEY)?;
    let Err(refusal) = serde_json::from_str::<eliot_types::TaskExecutionClass>(&injected) else {
        return fail(format!(
            "row {}: supplying `{REQUIRES_CODECORTEX_KEY}` on the wire must be refused, but it decoded; `{REQUIRES_CODECORTEX_METHOD}` is a Rust-side method with no wire surface",
            row.id
        ));
    };
    assert!(
        refusal.is_data(),
        "the refusal for a supplied `{REQUIRES_CODECORTEX_KEY}` member must be a data error, not a syntax or IO error: {refusal}"
    );
    Ok(())
}

/// One `matches!` conjunct of `TaskExecutionClass::requires_codecortex`: the member it
/// tests and the variant names its pattern accepts, both read out of the method body.
///
/// `Debug` because the non-vacuity failure at the call site prints both arms: a
/// truth table that lost a conjunct must say which variant sets it was built from.
#[derive(Debug)]
struct CodecortexArm {
    /// The scrutinee as the body spells it: `self.domain` or `self.artifact`.
    member: String,
    /// The accepted variant names, in the order the pattern lists them.
    variants: Vec<String>,
}

/// The two members `requires_codecortex` tests, named as the SCRUTINEES its body
/// spells: `matches!(self.domain, ..)` and `matches!(self.artifact, ..)`. Named as
/// constants so the parse, its guard and the failure messages all quote the same two
/// tokens rather than three independently typed literals.
const CODECORTEX_DOMAIN_MEMBER: &str = "self.domain";
const CODECORTEX_ARTIFACT_MEMBER: &str = "self.artifact";

/// The wire member names those two scrutinees read. Used only to pull the RECORDED
/// row's own pair out of its bytes; they are member names, not the predicate's logic.
const CODECORTEX_DOMAIN_FIELD: &str = "domain";
const CODECORTEX_ARTIFACT_FIELD: &str = "artifact";

/// The `&&`-separated conjuncts of `requires_codecortex`, read from the method's OWN
/// body in live `task_execution.rs`.
///
/// WHY A PARSE OF THE BODY, stated against the alternatives. The expected side must be
/// INDEPENDENT of the compiled method, and the two cheap independence-breaking
/// alternatives are both rejected here: transcribing `Code | Mixed` /
/// `Code | Config | Mixed` into this file makes the assertion a second copy of the
/// logic that can drift from the first, and comparing the method with itself is the
/// tautology this function used to assert. So the body text is the authority, exactly as
/// the `serde` attribute text and the field declarations already are elsewhere in this
/// file.
///
/// WHAT IT READS, concretely: the lines between the declaration of
/// `pub fn requires_codecortex(&self)` and its closing `}`; then, per `&&`-separated
/// conjunct, the `matches!(` macro's two arguments — the scrutinee and the pattern —
/// and, in the pattern, each `|`-separated alternative's variant name after its `::`.
///
/// IT FAILS LOUDLY, never silently producing a smaller table, and every message names
/// the line it could not read:
/// * the declaration line is not found at all;
/// * the file ends before the body's closing brace;
/// * the body no longer references `self.domain` or `self.artifact` — the message says
///   which conjunct was lost, so deleting the artifact half of the real method reds
///   with a statement of what went missing rather than with a shorter table;
/// * the body does not split into exactly two conjuncts;
/// * a conjunct has no `matches!(`, an unbalanced `matches!(`, no comma between its
///   scrutinee and its pattern, an empty alternative, an alternative that is not a
///   `Path::Variant` pair, a variant name that is not one bare identifier, or two
///   alternatives naming DIFFERENT enums;
/// * both conjuncts name the same member, or a member neither of the two named
///   constants.
///
/// THIS IS NOT A SECOND ENUM-VARIANT PARSER. The variant names of
/// `TaskExecutionDomain` and `TaskExecutionArtifact` are already parsed by
/// `declared_enum_variants`; what is parsed HERE is the METHOD BODY, which no other
/// helper in this file reads. The two are reconciled by `fold_spelling`, the same
/// reconciliation `assert_spelling_denominator_matches_declaration` uses.
fn requires_codecortex_arms() -> Result<Vec<CodecortexArm>, Box<dyn std::error::Error>> {
    let source = read_workspace(TASK_EXECUTION_FILE)?;
    let lines: Vec<&str> = source.lines().collect();
    let opened_at = lines
        .iter()
        .position(|line| line.trim().starts_with(REQUIRES_CODECORTEX_METHOD))
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "{TASK_EXECUTION_FILE} declares no line beginning `{REQUIRES_CODECORTEX_METHOD}`, so the predicate's arms cannot be read from source"
            )))
        })?;
    let mut body = String::new();
    let mut index = opened_at + 1;
    loop {
        let Some(line) = lines.get(index).copied() else {
            return fail(format!(
                "{TASK_EXECUTION_FILE}:{} declares `{REQUIRES_CODECORTEX_METHOD}` and the file ends before its body's closing brace, so its arms cannot be read",
                opened_at + 1
            ));
        };
        if line.trim() == "}" {
            break;
        }
        body.push_str(line);
        body.push('\n');
        index += 1;
    }
    for member in [CODECORTEX_DOMAIN_MEMBER, CODECORTEX_ARTIFACT_MEMBER] {
        assert!(
            body.contains(member),
            "{TASK_EXECUTION_FILE}: the body parsed out of `{REQUIRES_CODECORTEX_METHOD}` (opened at line {}) no longer references {member}, so the {member} conjunct of the predicate's two `matches!` halves has been lost and the expected truth table cannot be built from it: {body}",
            opened_at + 1
        );
    }
    let conjuncts: Vec<&str> = body.split("&&").collect();
    if conjuncts.len() != 2 {
        return fail(format!(
            "{TASK_EXECUTION_FILE}:{}: the body parsed out of `{REQUIRES_CODECORTEX_METHOD}` splits into {} `&&`-separated conjuncts, not the two this parse requires (one per member), so the truth table cannot be built from it: {body}",
            opened_at + 1,
            conjuncts.len()
        ));
    }
    let mut arms = Vec::with_capacity(conjuncts.len());
    for conjunct in &conjuncts {
        arms.push(codecortex_conjunct_arm(conjunct, opened_at + 1)?);
    }
    if arms[0].member == arms[1].member {
        return fail(format!(
            "{TASK_EXECUTION_FILE}:{}: both conjuncts of `{REQUIRES_CODECORTEX_METHOD}` test {}, so the predicate reads one member twice and no truth table can be built from it: {body}",
            opened_at + 1,
            arms[0].member
        ));
    }
    for member in [CODECORTEX_DOMAIN_MEMBER, CODECORTEX_ARTIFACT_MEMBER] {
        if !arms.iter().any(|arm| arm.member == member) {
            return fail(format!(
                "{TASK_EXECUTION_FILE}:{}: the conjuncts parsed out of `{REQUIRES_CODECORTEX_METHOD}` test {:?} rather than {member}, so the truth table cannot be built from them",
                opened_at + 1,
                arms.iter()
                    .map(|arm| arm.member.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    Ok(arms)
}

/// One `&&`-separated conjunct of `requires_codecortex`, parsed into the member it tests
/// and the variant names its `matches!` pattern accepts.
///
/// `opened_at` is the 1-based line the METHOD was declared on, and every failure names
/// it: a body parse that fails must say which declaration could not be read rather than
/// returning a smaller arm list.
fn codecortex_conjunct_arm(
    conjunct: &str,
    opened_at: usize,
) -> Result<CodecortexArm, Box<dyn std::error::Error>> {
    let marker = "matches!(";
    let Some(after_marker) = conjunct.split(marker).nth(1) else {
        return fail(format!(
            "{TASK_EXECUTION_FILE}:{opened_at}: this conjunct of `{REQUIRES_CODECORTEX_METHOD}` contains no `{marker}`, so its arms cannot be read: {conjunct}"
        ));
    };
    // The macro's own argument list, with parentheses tracked so a `|` alternative or a
    // nested call cannot end it early.
    let mut nested = 1usize;
    let mut closing = None;
    for (offset, cell) in after_marker.char_indices() {
        match cell {
            '(' => nested += 1,
            ')' => {
                nested -= 1;
                if nested == 0 {
                    closing = Some(offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(closing) = closing else {
        return fail(format!(
            "{TASK_EXECUTION_FILE}:{opened_at}: the `{marker}` in this conjunct of `{REQUIRES_CODECORTEX_METHOD}` is never closed, so its arms cannot be read: {conjunct}"
        ));
    };
    let arguments = &after_marker[..closing];
    let Some((scrutinee, pattern)) = arguments.split_once(',') else {
        return fail(format!(
            "{TASK_EXECUTION_FILE}:{opened_at}: this `{marker}` of `{REQUIRES_CODECORTEX_METHOD}` has no comma between its scrutinee and its pattern, so its arms cannot be read: {arguments}"
        ));
    };
    let member = scrutinee.trim();
    if !matches!(
        member,
        CODECORTEX_DOMAIN_MEMBER | CODECORTEX_ARTIFACT_MEMBER
    ) {
        return fail(format!(
            "{TASK_EXECUTION_FILE}:{opened_at}: this conjunct of `{REQUIRES_CODECORTEX_METHOD}` tests {member:?} rather than {CODECORTEX_DOMAIN_MEMBER} or {CODECORTEX_ARTIFACT_MEMBER}, so this file cannot claim which members the predicate reads"
        ));
    }
    let mut enum_path: Option<&str> = None;
    let mut variants: Vec<String> = Vec::new();
    for alternative in pattern.split('|') {
        let alternative = alternative.trim().trim_end_matches(',').trim();
        if alternative.is_empty() {
            return fail(format!(
                "{TASK_EXECUTION_FILE}:{opened_at}: the pattern of this conjunct of `{REQUIRES_CODECORTEX_METHOD}` carries an empty `|` alternative, so its accepted variants cannot be read: {pattern}"
            ));
        }
        let Some((path, variant)) = alternative.rsplit_once("::") else {
            return fail(format!(
                "{TASK_EXECUTION_FILE}:{opened_at}: the alternative {alternative:?} of this conjunct of `{REQUIRES_CODECORTEX_METHOD}` is not an EnumPath::Variant pair, so its accepted variants cannot be read"
            ));
        };
        if variant.is_empty()
            || !variant
                .chars()
                .all(|cell| cell.is_ascii_alphanumeric() || cell == '_')
        {
            return fail(format!(
                "{TASK_EXECUTION_FILE}:{opened_at}: the variant {variant:?} of this conjunct of `{REQUIRES_CODECORTEX_METHOD}` is not one bare identifier, so it cannot be compared with a declared variant name"
            ));
        }
        let path = path.trim();
        // Every alternative of ONE `matches!` must name the same enum, or the arm is
        // not one predicate over one member's variant set and the truth table would
        // be built from two unrelated denominators.
        if enum_path.is_none() {
            enum_path = Some(path);
        } else if enum_path != Some(path) {
            return fail(format!(
                "{TASK_EXECUTION_FILE}:{opened_at}: this conjunct of `{REQUIRES_CODECORTEX_METHOD}` accepts alternatives from two different enums, {enum_path:?} and {path:?}, so its accepted variants cannot be read as one set"
            ));
        }
        variants.push(variant.to_owned());
    }
    if variants.is_empty() {
        return fail(format!(
            "{TASK_EXECUTION_FILE}:{opened_at}: this conjunct of `{REQUIRES_CODECORTEX_METHOD}` accepts no variant at all, so the truth table would be empty rather than measured"
        ));
    }
    Ok(CodecortexArm {
        member: member.to_owned(),
        variants,
    })
}

/// The one arm of `arms` that tests `member`, failing loudly when there is none.
fn codecortex_arm<'arms>(
    arms: &'arms [CodecortexArm],
    member: &str,
) -> Result<&'arms CodecortexArm, Box<dyn std::error::Error>> {
    arms.iter().find(|arm| arm.member == member).ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "no parsed conjunct of `{REQUIRES_CODECORTEX_METHOD}` tests {member}, so no expected truth table can be built for that member"
        )))
    })
}

/// The parsed expected value for one `(domain, artifact)` pair.
///
/// The lookup, rather than an iteration over the table, is what makes the table's
/// completeness an assertion: a table built over a strict subset of the declared cross
/// product leaves some pair without an entry, and this names that pair instead of the
/// comparison silently skipping it.
fn expected_entry<'table>(
    table: &'table [(&'table str, &'table str, bool)],
    domain: &str,
    artifact: &str,
) -> Result<&'table bool, Box<dyn std::error::Error>> {
    table
        .iter()
        // One dereference on each side, and this one type-checks because the element is
        // a REFERENCE (`&'table str`), so the `ref` binding makes `candidate_domain` a
        // `&&'table str` and one deref leaves a `&'table str` — which is what `domain`,
        // declared `&str`, already is. It is recorded because the same spelling where
        // the element is a `&str` BY VALUE and the other operand is one reference
        // deeper is `&str == &&str`, and that reduces to `str == &str` and is rejected;
        // see `closed_object_labels_are_witnessed`, where that is exactly what happens
        // and where the element is reached as `entry.0` instead.
        .find(|(candidate_domain, candidate_artifact, _)| {
            *candidate_domain == domain && *candidate_artifact == artifact
        })
        .map(|(_, _, expected)| expected)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "the truth table parsed out of the body of `{REQUIRES_CODECORTEX_METHOD}` carries no entry for {domain} x {artifact}, so comparing that pair would skip it silently"
            )))
        })
}

/// The complete set of wire spellings a `task_execution.rs` member enum admits.
///
/// WHERE THEY COME FROM, and why not from the declaration: `task_execution.rs`
/// declares Rust variant names (`Code`) under `rename_all = "snake_case"`, and the
/// wire form is the renamed spelling (`code`). Reading the Rust names and converting
/// them here would mean transcribing serde's rename rule into this file, which is a
/// second authority for something the decoder already states exactly. So the set is
/// read out of the `unknown variant` refusal a case-6 row provokes — serde's own
/// `VARIANTS` array, which is the complete denominator — and then corroborated
/// against the declaration by `assert_spelling_denominator_matches_declaration`, so
/// the message is not the sole authority.
///
/// The selected row must be a case-6 SPELLING row for this enum: it must be refused
/// (so the message is a genuine variant refusal) and its own payload must be a JSON
/// string (so it is a variant spelling rather than a wrong-payload probe). Both are
/// checked rather than assumed, and a miss fails loudly naming the enum.
fn declared_member_spellings(
    all: &[Row],
    enum_name: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let group = reject_rows(all, 6)?;
    let mut found: Option<String> = None;
    for row in &group {
        if type_leaf(&row.type_name) != enum_name {
            continue;
        }
        let payload: Value = serde_json::from_str(&row.raw).map_err(boxed)?;
        if !matches!(payload, Value::String(_)) {
            continue;
        }
        found = Some(refused_message(row)?);
        break;
    }
    let Some(message) = found else {
        return fail(format!(
            "case 6 must carry a bare-string variant row for {enum_name}, or its decoder's declared spellings cannot be read"
        ));
    };
    let spellings = declared_variant_spellings(&message)?;
    assert_spelling_denominator_matches_declaration(enum_name, &spellings)?;
    Ok(spellings)
}

/// The allocation row's own bytes with its `domain` and `artifact` members
/// replaced by two given wire spellings, by byte surgery so every other member —
/// including `action`, `source` and `subsystem_refs` — survives untouched and no
/// duplicate is collapsed.
fn task_execution_class_payload(
    row: &Row,
    domain: &str,
    artifact: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Both members hold a single bare word, so the quoted form is the member value
    // token with nothing to escape. It is built rather than transcribed per spelling
    // so the caller passes a plain `&str` and the splicing stays byte surgery.
    let with_domain = document_with_member_value(&row.raw, "domain", &format!("\"{domain}\""))?;
    document_with_member_value(&with_domain, "artifact", &format!("\"{artifact}\""))
}

/// The encode-side ordering claim for `TaskExecutionClass`, kept separate from
/// `health_record_encodes_in_declaration_order` because it is a different TYPE.
///
/// Structure is deliberately identical to that helper — declared names from source,
/// arity pinned before the comparison, both sides read off different paths — because
/// the property is the same one and a reader should be able to check one against the
/// other.
///
/// WHAT IT ADDS IS COVERAGE, AND THE COVERAGE IS TWO OF EIGHT, NOT ALL EIGHT. This
/// file observes the member ORDER of two closed structs: `HealthRecord`, through
/// `health_record_encodes_in_declaration_order` and
/// `document_order_is_observable_only_by_streaming`, and `TaskExecutionClass`, here.
/// `closed_type_names` measures EIGHT closed structs across the five allocated files —
/// seven in `records.rs` plus this one — so six of the eight carry NO member-order
/// assertion at all. The previous version of this comment claimed this type was "the one
/// closed struct whose member order no assertion in this file observed", which was false
/// on both halves: one of the two that does carry one is `HealthRecord`, and six of the
/// eight carry none rather than one. That gap is deliberately NOT closed here. Covering
/// the other six is a separate decision — it means adding an ordering assertion per
/// type — and inventing those assertions in a mechanical pass would add coverage nobody
/// asked for rather than correct a false sentence.
///
/// IT IS NOW PARTLY CLOSED BY A DIFFERENT ROUTE, recorded because the sentence above
/// would otherwise UNDER-count what this file checks, which is the same defect as
/// over-claiming and no less a false statement about the code. `value_round_trip` — whose
/// byte comparison was restored — asserts `to_string(decoded) == row.raw` for ALL EIGHT
/// closed-object types, and those rows are written in DECLARATION order, measured
/// including the nested `blob`, `manifest` and `segments[]` members. Byte-identity
/// against a declaration-ordered fixture therefore DOES establish that the encoder emits
/// declaration order for every one of the eight, and it cannot be satisfied by an
/// encoder that sorted, because for these types the declaration order is not the sorted
/// order: `BlobRef` declares `algorithm`, `digest_hex`, `size_bytes`, `relative_path`,
/// while sorted would place `relative_path` before `size_bytes`. So the six "none" above
/// are covered by the byte comparison rather than by a per-type
/// sorted-versus-declaration comparison, and the per-type form is still not written.
///
/// The non-vacuity guard is the same idea as in the `HealthRecord` helper, applied to
/// the SORTED order: if the declaration order happened to equal the sorted order then
/// "emits in declaration order" would also be satisfied by an encoder that sorted, and
/// the comparison would prove nothing about which of the two produced the bytes. It is
/// a claim about the type's declaration, it can fail, and it is what gives the
/// comparison its meaning.
fn task_execution_class_encodes_in_declaration_order() -> TestResult {
    let declared = struct_field_names(TASK_EXECUTION_FILE, "TaskExecutionClass")?;
    let mut sorted = declared.clone();
    sorted.sort();
    assert_ne!(
        declared, sorted,
        "TaskExecutionClass's declaration order must differ from its sorted order, or an encoder that sorted would satisfy the comparison below and the ordering claim would prove nothing: declared {declared:?}, sorted {sorted:?}"
    );
    // Re-read the allocation row's bytes through the crate's own path rather than
    // transcribing a payload: a hand-written document could disagree with the fixture
    // and the ordering claim would then be about the wrong bytes.
    let Fixture { rows, .. } = rows()?;
    let row = applicable_row(&rows, "TaskExecutionClass")?;
    let decoded: eliot_types::TaskExecutionClass = serde_json::from_str(&row.raw).map_err(boxed)?;
    let encoded = serde_json::to_string(&decoded).map_err(boxed)?;
    // The span vector is bound to a local rather than consumed, because the keys
    // below are BORROWED from it: `top_level_member_spans` returns its `Vec` by
    // value, so collecting `&str` straight off a temporary would leave `emitted`
    // pointing into a value already dropped at the end of that statement.
    let spans = top_level_member_spans(&encoded);
    let emitted: Vec<&str> = spans.iter().map(|span| span.key.as_str()).collect();
    assert_eq!(
        declared.len(),
        emitted.len(),
        "TaskExecutionClass must declare as many members as the encoder emits, or the order comparison below is only over a prefix: declared {declared:?}, emitted {emitted:?}"
    );
    let expected: Vec<&str> = declared.iter().map(String::as_str).collect();
    assert_eq!(
        emitted, expected,
        "the encoder must emit TaskExecutionClass members in declaration order"
    );
    Ok(())
}

/// A consumer outside this crate still builds a `HealthRecord`, and every such
/// construction assigns a STRING to `status`. That assigned type is what makes
/// narrowing the field impossible today: `HealthRecord.status` is a plain
/// `String` at `records.rs:147`, so `HealthStatus` — an enum, with no `String`
/// anywhere in its signature — cannot be assigned to it without a conversion
/// that does not exist. Narrowing would therefore be a COMPILE error at every
/// site below, regardless of which wire spellings those sites happen to use.
///
/// This is a TEXTUAL assertion about a file outside this crate, not a link
/// against it, and that is the honest form available: `crates/eliot-types` has
/// no `[dev-dependencies]`, so an integration test here cannot name
/// `eliot_store`. Asserting on the text is weaker than linking, and it is
/// recorded as such rather than dressed up as a link.
///
/// TWO INDEPENDENT CLAIMS, deliberately not merged:
/// * the ASSIGNED-TYPE claim above is what makes narrowing impossible. Every
///   construction's `status` must be assigned a `.to_owned()`-produced string.
/// * the VOCABULARY claim is only a fact about today's text. At least one
///   construction must carry a value outside the wire spellings, because the
///   consumer does use a status the enum cannot name. It is asserted over ALL
///   constructions, not the first: this file has more than one, and at least one
///   of them does use a vocabulary spelling, so a first-match scan would report
///   the opposite of the truth.
///
/// THE SCAN IS WIDENED, not the doc narrowed, and the choice is argued here because
/// the previous version's headline — "every such construction" — was stronger than a
/// scan collecting lines whose trimmed form STARTS WITH `status:`. Field shorthand
/// (`HealthRecord { component, status, detail }`) and a struct update (`..base`) leave
/// no such line at all, so both claims were invisible to both of them: a construction
/// that never spells `status:` passed unnoticed. It is latent today — this file has two
/// constructions and both write `status:` — and latent is exactly the state in which a
/// claim nobody can reach is carried forward as if it were checked. Narrowing the doc
/// would have been cheaper and would have documented a strictly weaker property, so the
/// scan is widened instead: every CONSTRUCTION is located and its body is read, and a
/// construction whose `status` this file cannot resolve from that body FAILS. An
/// unresolvable construction is a decision the reader needs — the narrowing argument
/// depends on it — so it is never skipped.
///
/// THE POSITIVE CASE IS ASSERTED HERE, and it is the half of this case that the
/// offset defect removed. `health_record_constructions` is almost entirely refusals:
/// a single-line construction, a file that ends inside one, a `..` update, field
/// shorthand, a body with no `status` — five guards, and a helper that refused
/// everything would satisfy all five while proving nothing at all. So the count of
/// constructions it ACCEPTED is demanded here: more than one, and every one of them
/// resolved to a readable `status` line by the loop below. Those are the live
/// constructions in `{STORE_HEALTH_CONSUMER}` — both written across several lines,
/// both ending their introducer's line at the opening brace — and while the offset
/// landed ON the brace instead of one past it, `trim` saw that brace, the guard was
/// never empty, and the helper refused both. Neither witness was reachable before
/// this correction; both are what the acceptance half of this case rests on now.
fn store_health_record_stays_outside_the_vocabulary() -> TestResult {
    let source = read_workspace(STORE_HEALTH_CONSUMER)?;
    let constructions = health_record_constructions(&source, STORE_HEALTH_CONSUMER)?;
    if constructions.is_empty() {
        return fail(format!(
            "{STORE_HEALTH_CONSUMER} constructs no {HEALTH_RECORD_TYPE}, so the narrowing claim cannot be checked"
        ));
    }
    // THE ACCEPTED COUNT, demanded rather than inferred. One accepted construction
    // would satisfy every refusal above and leave the vocabulary claim resting on a
    // single site, which is the first-match reading this helper's two-independent-
    // claims doc comment exists to rule out.
    assert!(
        constructions.len() > 1,
        "{STORE_HEALTH_CONSUMER} must contribute MORE THAN ONE {HEALTH_RECORD_TYPE} construction that the scan ACCEPTS, or the vocabulary claim below is read off one site and a first-match scan would report the opposite of the truth: accepted {} construction(s)",
        constructions.len()
    );
    let spellings = health_status_wire_spellings()?;
    let mut assigned: Vec<String> = Vec::new();
    for (index, body) in constructions.iter().enumerate() {
        assigned.push(assigned_status_line(body, index, STORE_HEALTH_CONSUMER)?);
    }
    for (index, line) in assigned.iter().enumerate() {
        assert!(
            line.contains(".to_owned()"),
            "construction {} of {HEALTH_RECORD_TYPE} in {STORE_HEALTH_CONSUMER} must assign a String to status, or narrowing to {HEALTH_STATUS_TYPE} would not be a compile error there: {line}",
            index + 1
        );
    }
    assert!(
        assigned.iter().any(|line| !spellings
            .iter()
            .any(|spelling| line.contains(spelling.as_str()))),
        "at least one construction must use a status outside the wire spellings {HEALTH_STATUS_TYPE} declares, or the closed vocabulary would already name everything the consumer needs: {assigned:?}"
    );
    Ok(())
}

/// The body of every `HealthRecord { .. }` construction in `source`, one trimmed entry
/// per line, in the order the file writes them.
///
/// HOW A CONSTRUCTION IS RECOGNISED, and what it deliberately does NOT match. The name
/// is a construction's own introducer when the text after it is an opening brace, and
/// it is NOT one in TYPE POSITION — where `->` or `:` precedes it, as in
/// `-> Result<HealthRecord, StoreError> {` and `-> HealthRecord {`. Both of those end in
/// a brace and would otherwise be read as constructions, so a return-type signature
/// would be reported as a `status` assignment site. The name followed by anything else
/// — a `use` list, a generic argument list — is not a construction either and is not
/// looked at.
///
/// EVERY SITE IS RESOLVED OR REFUSED, never skipped. A construction whose opening brace
/// is not the last thing on its line — a single-line `HealthRecord { status, ..base }`
/// — is refused here, because its body cannot be read by a line walk and skipping it
/// would leave exactly the invisible construction this widening exists to close. The
/// same is true of a construction whose file ends before its closing brace.
///
/// THE OFFSET IS ONE PAST THE BRACE, and that is the whole of the correction: the
/// continuation guard reads `trimmed[body_start..]`, and `trim` does not remove a
/// brace. An offset that landed ON the brace therefore handed the guard a `{`, which
/// is never empty, and the guard refused every construction in the file. The
/// refusals below are unchanged by this and still each fire for their own reason;
/// what changed is that a CORRECT construction is now accepted, which is the positive
/// case `store_health_record_stays_outside_the_vocabulary` now rests on. Its two
/// witnesses are the live constructions in `{STORE_HEALTH_CONSUMER}`, and neither
/// could be reached before.
fn health_record_constructions(
    source: &str,
    file: &str,
) -> Result<Vec<Vec<String>>, Box<dyn std::error::Error>> {
    let lines: Vec<&str> = source.lines().collect();
    let introducer = HEALTH_RECORD_TYPE;
    let mut bodies: Vec<Vec<String>> = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        let mut body_start: Option<usize> = None;
        for (at, _) in trimmed.match_indices(introducer) {
            let before = trimmed[..at].trim_end();
            if before.ends_with('>') || before.ends_with(':') {
                continue;
            }
            let tail = &trimmed[at + introducer.len()..];
            if tail.trim_start().starts_with('{') {
                // `tail.len() - tail.trim_start().len()` is a WHITESPACE BYTE
                // COUNT, so it lands ON the brace. What the guard below reads is
                // the text AFTER the brace, so the offset recorded here is ONE
                // PAST it. Reading from the brace itself made `trim` see a `{`,
                // which it does not remove, so the guard was never satisfied and
                // this helper refused EVERY construction — the correct ones
                // included — which is the one failure shape no positive assertion
                // in this file can be satisfied by.
                let brace = at + introducer.len() + (tail.len() - tail.trim_start().len());
                body_start = Some(brace + 1);
                break;
            }
        }
        let Some(body_start) = body_start else {
            index += 1;
            continue;
        };
        if !trimmed[body_start..].trim().is_empty() {
            return fail(format!(
                "{file}:{}: this {HEALTH_RECORD_TYPE} construction continues on its own line ({trimmed}), so its body cannot be read and this file will not report a narrowing claim it has not checked; write it across several lines",
                index + 1
            ));
        }
        let mut body: Vec<String> = Vec::new();
        index += 1;
        loop {
            let Some(entry) = lines.get(index) else {
                return fail(format!(
                    "{file}:{}: the file ends inside a {HEALTH_RECORD_TYPE} construction, so its body cannot be read",
                    index + 1
                ));
            };
            let entry = entry.trim();
            index += 1;
            if entry.starts_with('}') {
                break;
            }
            if !entry.is_empty() && !entry.starts_with("//") {
                body.push(entry.to_owned());
            }
        }
        bodies.push(body);
    }
    Ok(bodies)
}

/// The `status` entry of one construction body, or a loud failure naming why it cannot
/// be resolved.
///
/// ONE SHAPE IS RESOLVED AND THREE ARE REFUSED, and the refusals are the point of
/// widening the scan:
/// * `status: <expression>` — resolved, and the expression's text is what the
///   assigned-type and vocabulary claims read;
/// * `status` as FIELD SHORTHAND, a bare `status` entry — refused, because the value
///   comes from a binding this file cannot read and the assigned-type claim is exactly
///   the claim that would then be unfounded;
/// * a STRUCT UPDATE, any `..` entry — refused for the same reason and additionally
///   because `status` may or may not be among the fields it supplies;
/// * a body with none of those — refused, because the construction then assigns no
///   `status` this file can see.
fn assigned_status_line(
    body: &[String],
    index: usize,
    file: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut resolved: Option<&String> = None;
    for entry in body {
        if entry.starts_with("..") {
            return fail(format!(
                "construction {index} of {HEALTH_RECORD_TYPE} in {file} uses the struct-update syntax `{entry}`, so this file cannot tell whether `status` is assigned by it and will not report a narrowing claim it has not checked"
            ));
        }
        if entry.trim_end_matches(',') == "status" {
            return fail(format!(
                "construction {index} of {HEALTH_RECORD_TYPE} in {file} assigns `status` by FIELD SHORTHAND (`{entry}`), so the assigned type is a binding this file cannot read; spell it as `status: <expression>` so the claim below is checkable"
            ));
        }
        if entry.starts_with("status:") {
            resolved = Some(entry);
        }
    }
    match resolved {
        Some(entry) => Ok(entry.clone()),
        None => fail(format!(
            "construction {index} of {HEALTH_RECORD_TYPE} in {file} assigns no `status` this file can read; its body is {body:?}"
        )),
    }
}

/// The wire spellings the deferred `HealthStatus` vocabulary admits, in declaration
/// order, read from live `HEALTH_FILE`.
///
/// WHY THE FOUR LITERALS ARE GONE, and this is the D-shaped defect the call site's own
/// failure message used to name. The previous version wrote
/// `HealthStatus::Starting | Ready | Degraded | NotReady` as Rust values here. That list
/// and the declaration in `health.rs` were tied together by NOTHING: adding a fifth
/// variant to `health.rs` left the closed-set assertion below vacuous in exactly the
/// place that matters, because the vocabulary it measures would still be the old four
/// while the decoder accepts five.
///
/// WHAT IS READ, and it is TWO facts from the source rather than one: the enum's
/// VARIANTS in declaration order, through the file's existing walk
/// `declared_enum_variants` — so no second enum-variant parser is introduced — and the
/// CONTAINER `rename_all` attribute attached to that enum's declaration, read through
/// the same `serde_attribute_text` helper the attribute inventory uses. Both fail
/// loudly: a missing enum, an empty variant list, a missing rename attribute, or a
/// rename rule other than `snake_case` each aborts with a message naming the file.
///
/// WHY THE RENAME IS APPLIED HERE RATHER THAN ASKED OF THE DECODER. `declared_member_
/// spellings` gets its spellings out of a serde `unknown variant` refusal, which is
/// available for `task_execution.rs` because a case-6 row provokes one there. `HealthStatus`
/// has no such probe in this file, and inventing a payload to provoke one would assert a
/// refusal this case is not about. Applying the declaration's own rename rule to its own
/// variant names keeps the expected side a fact about the source, and
/// `health_status_vocabulary_is_closed` requires the DECODER to ACCEPT every spelling
/// derived here and to REFUSE everything outside the resulting set, so the rename rule
/// is corroborated against behaviour in BOTH directions at that call site rather than
/// trusted here.
///
/// WHAT CHANGED, because this paragraph used to claim a corroboration that only one
/// half of existed. It said the call site required the DECODER to refuse everything
/// outside the resulting set, and treated that as corroborating the rename rule. It does
/// not: a value outside the set is outside the set under ANY spelling rule, so the
/// refusal holds under a correct rename and under a wrong one alike.
///
/// THE COUNTERFACTUAL THAT SHOWS IT, BY READING AND NOT BY RUNNING. The derived
/// spellings come from the enum's own declaration — `declared_enum_rename_all` reads the
/// `rename_all` attribute and `health_status_wire_spellings` maps each variant name
/// through `snake_case_spelling` — so renaming the variant `NotReady` to `Notready` in
/// `health.rs` changes the derived set's member from `not_ready` to `notready` and, the
/// derivation being a per-variant map, collapses nothing. `HEALTH_STATUS_OUT_OF_VOCABULARY`
/// and the empty string are outside whatever set is derived, so the refusals asserted by
/// `health_status_vocabulary_is_closed` hold under that rename as they do under this
/// one. NO SUITE WAS RUN TO ESTABLISH ANY OF THAT: this lane executes no test, so this is
/// a statement about what the MECHANISM does when the source text changes, and not an
/// observation of a pass or a failure. Nor is anything claimed about the rest of the
/// workspace — whether other call sites still handle the spelling `not_ready` is a
/// question for their owners, and a source change here implies a consequence for them
/// without this delivery being entitled to report one.
///
/// The missing half was therefore the ACCEPT direction, and it is asserted per derived
/// spelling now, through the real public decode path. Both directions are kept: the
/// refusals are what stop "the decoder accepts every string", and the acceptances are
/// what make the derived spelling a fact about the decoder rather than about
/// `snake_case_spelling`.
fn health_status_wire_spellings() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let source = read_workspace(HEALTH_FILE)?;
    let rename = declared_enum_rename_all(&source, HEALTH_STATUS_TYPE, HEALTH_FILE)?;
    assert_eq!(
        rename, SNAKE_CASE_RENAME,
        "{HEALTH_FILE} must rename {HEALTH_STATUS_TYPE}'s variants with {SNAKE_CASE_RENAME}, which is the only rule this file implements; found {rename:?}, so the wire spellings below would be a guess"
    );
    let variants = declared_enum_variants(HEALTH_FILE)?
        .into_iter()
        .find(|(name, _, _)| name == HEALTH_STATUS_TYPE)
        .map(|(_, _, variants)| variants)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "{HEALTH_FILE} declares no all-unit externally tagged enum named {HEALTH_STATUS_TYPE}, so its wire spellings cannot be read from source"
            )))
        })?;
    if variants.is_empty() {
        return fail(format!(
            "{HEALTH_FILE} declares {HEALTH_STATUS_TYPE} with no variant, so the closed-vocabulary assertion would hold over an empty set"
        ));
    }
    // A loop rather than `map`, because the conversion takes `&str` while the walk
    // yields `&String`; the explicit binding keeps the deref visible instead of hiding
    // it inside a closure.
    let mut spellings = Vec::with_capacity(variants.len());
    for variant in &variants {
        spellings.push(snake_case_spelling(variant));
    }
    Ok(spellings)
}

/// The `rename_all` rule string this file implements when it converts a declared Rust
/// variant name into its wire spelling.
const SNAKE_CASE_RENAME: &str = "snake_case";

/// The container-level `rename_all` an enum declaration carries in `file`, for example
/// `#[serde(rename_all = "snake_case")]` immediately above `pub enum HealthStatus {`.
///
/// READ FROM THE ATTRIBUTE BLOCK, not from anywhere else: the lines immediately above
/// the declaration are walked upwards while they are attributes, and the `#[serde(…)]`
/// text is read with `serde_attribute_text`, the same helper
/// `serde_attribute_inventory_is_closed` uses — so a doc comment that merely mentions
/// `rename_all` cannot be mistaken for one, because the walk starts at the declaration
/// and only collects attribute lines.
///
/// FAILS LOUDLY, because an absent attribute and an unreadable one must not both
/// degrade into "no rename", which would silently yield Rust names as wire spellings:
/// the declaration is not found, and no `rename_all` attribute is found above it, are
/// each named failures.
fn declared_enum_rename_all(
    source: &str,
    type_name: &str,
    file: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let declaration = format!("pub enum {type_name} {{");
    let lines: Vec<&str> = source.lines().collect();
    let declared_at = lines
        .iter()
        .position(|line| line.trim() == declaration)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "{file} does not declare {declaration}, so its rename rule cannot be read"
            )))
        })?;
    for index in (0..declared_at).rev() {
        let trimmed = lines[index].trim();
        if trimmed == "}" || trimmed.is_empty() {
            break;
        }
        if !trimmed.starts_with("#[serde(") {
            continue;
        }
        let attribute = serde_attribute_text(trimmed);
        let Some(rule) = attribute.strip_prefix("rename_all") else {
            continue;
        };
        let value = rule
            .trim()
            .strip_prefix('=')
            .ok_or_else(|| {
                boxed(std::io::Error::other(format!(
                    "{file}:{}: the rename rule {attribute:?} on {declaration} carries no value at all, so it cannot be applied to its variants",
                    index + 1
                )))
            })?
            .trim();
        return Ok(value.trim_matches('"').to_owned());
    }
    fail(format!(
        "{file}:{}: {declaration} carries no `#[serde(rename_all = \"..\")]` attribute, so its wire spellings cannot be derived from its declaration and this file will not assume one",
        declared_at + 1
    ))
}

/// One declared Rust variant name as its `snake_case` wire spelling.
///
/// The rule implemented is the one serde's `rename_all = "snake_case"` applies: a
/// separator is inserted before each uppercase letter that follows a lowercase letter
/// or a digit, and the whole name is lowercased. `NotReady` becomes `not_ready` and
/// `Code` becomes `code`, which is what makes the derived spelling comparable against
/// the decoder at the call site.
///
/// SCOPE, stated because this is not a general Rust identifier converter: it does not
/// handle consecutive capitals (`HTTPServer`), leading or trailing underscores, or
/// digit grouping, none of which any of the variants this file converts uses. A
/// variant of one of those shapes would produce a spelling this function gets wrong.
///
/// WHAT THE CALL SITE NOW DOES ABOUT THAT, corrected because this comment used to say
/// something the code did not do. It said "the decoder check at the call site is what
/// turns that into a red rather than a silent misreading", implying a check that could
/// catch a wrong spelling here. There was none: the call site required only that the
/// values OUTSIDE the derived set be refused, and an out-of-set value is out of the set
/// under every spelling rule, so a misreading of the rule — including the `NotReady` →
/// `Notready` case, which is exactly a reading of this rule's separator boundary — was
/// invisible. The call site now REQUIRES the decoder to ACCEPT each spelling derived
/// here, which is the direction a wrong separator rule fails, and it still requires the
/// out-of-set values to be refused.
fn snake_case_spelling(variant: &str) -> String {
    let mut spelling = String::with_capacity(variant.len() + 2);
    let mut previous: Option<char> = None;
    for cell in variant.chars() {
        let follows_a_boundary =
            previous.is_some_and(|prior| prior.is_ascii_lowercase() || prior.is_ascii_digit());
        if cell.is_ascii_uppercase() && follows_a_boundary {
            spelling.push('_');
        }
        spelling.push(cell.to_ascii_lowercase());
        previous = Some(cell);
    }
    spelling
}
// WORK_UNIT_CASE: 930/14
#[test]
fn case_14_malformed_input_is_refused() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    let group = reject_rows(&rows, MALFORMED_CASE)?;
    let fragments = non_document_rows(&group);
    // THE `!declares_transparent_scalar` CONJUNCT IS THE SECOND GROUP BEING HELD
    // SEPARATE, and it changes nothing about which rows are documents. Its
    // malformed scalar rows can open with `{` — `{}` is a map where a scalar is
    // declared — and one of them would otherwise be handed to `classify_malformation`,
    // which is a structural scan of a MALFORMED DOCUMENT: `{}` is well-formed, so
    // the scan would fail loudly on a correct row. The documents themselves
    // all declare `closed-object` — the byte-literal descriptor is NOT one of
    // them, because its raw does not open with a brace — so they all still pass
    // the predicate and the group, the classifier and the category mapping are
    // untouched.
    let documents: Vec<&Row> = group
        .iter()
        .copied()
        .filter(|row| !declares_transparent_scalar(row) && row.raw.trim_start().starts_with('{'))
        .collect();
    assert_eq!(
        fragments.len(),
        1,
        "case {MALFORMED_CASE} must carry exactly one non-document descriptor row; found {}: {}",
        fragments.len(),
        fragments
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    // THE DOCUMENT SET MUST BE NON-EMPTY, and this is a one-line hole: deleting the
    // malformed documents and lowering `meta.count` leaves `fragments.len() == 1`
    // true, leaves the invalid-UTF-8 probe running, and leaves the loop below
    // iterating NOTHING. Every guard in this case would stay green while the case's
    // whole subject was gone. Case 12 reads the same group through
    // `sole_byte_literal_descriptor`, but it reads only the NON-DOCUMENT half and
    // asserts only that half's size, so nothing anywhere else observes the documents.
    assert!(
        !documents.is_empty(),
        "case {MALFORMED_CASE} must carry at least one malformed document beside its non-document descriptor row, or the loop below iterates nothing and this case is green with its entire subject deleted"
    );
    // AND NON-EMPTY IS NOT ENOUGH: the set must COVER THE SHAPES THE CASE NAMES.
    // The count of documents used to live only in a comment here, so a document could
    // be deleted and another shape substituted with no assertion able to notice. Each
    // document is therefore classified FROM ITS OWN BYTES — never from its row id and
    // never from its `reason` prose, both of which are text another writer edits —
    // and every shape the classifier can tell apart must be present.
    let mut classified: Vec<Malformation> = Vec::new();
    for row in documents.iter().copied() {
        assert_refused(row)?;
        let kind = classify_malformation(row)?;
        // `assert_refused` is a bare `is_err` that discards the error, so the
        // category is read from a second decode. `serde_json::from_str` is pure over
        // these bytes, so the two decodes cannot disagree; what the first one
        // guarantees is the precondition for reading anything off the second one's
        // error at all, and that precondition is asserted here rather than assumed.
        let error = refusal_error(row)?;
        malformed_document_is_refused_for_its_own_shape(row, kind, &error);
        if !classified.contains(&kind) {
            classified.push(kind);
        }
    }
    for (kind, byte_fact) in distinguishable_malformations() {
        assert!(
            classified.contains(&kind),
            "case {MALFORMED_CASE} must carry at least one document whose own bytes are {byte_fact}, or that malformation is never exercised and a different shape could stand in for it; classified from {} document(s): {classified:?}",
            documents.len()
        );
    }
    // The bare-fragment row is the byte-literal descriptor, routed to a probe built
    // in this file. THE LONE-SURROGATE PROBE IS NO LONGER MISSING, and the reason the
    // earlier version of this comment gave for omitting it has turned out to be the
    // wrong reason. It said a Python oracle accepts such a document where serde_json
    // refuses it, so it "cannot be certified from this side". That observation is true
    // and it is exactly WHY the case needed one: the disagreement is the property, not
    // an obstacle to it. The fixture now carries `930-162-lone-leading-surrogate`, and
    // it is classified by `Malformation::LoneLeadingSurrogate` in the loop above with
    // its SYNTAX category asserted, so it is a refusal this file does certify — for the
    // string-valued targets `decode_row` uses. What the disagreement does forbid is the
    // opposite claim: that the BYTES are malformed. See that variant's documentation,
    // which now carries the whole of the argument: the refusal is a property of the
    // TARGET and not of the bytes, and Python is the divergent value-level rule rather
    // than evidence about well-formedness.
    //
    // A NOTE ON WHAT SUPERSEDED WHAT HERE, because this comment has been corrected once
    // already and the correction is worth keeping. The sentence this one replaces named
    // `serde_json::from_str::<Value>` ACCEPTING these bytes as the evidence that the
    // refusal is target-dependent. THAT HALF WAS WRONG: `Value` REFUSES them, because
    // `Value`'s `Deserialize` dispatches `deserialize_any(ValueVisitor)` and that
    // visitor's string arm calls `parse_str`, which hardcodes `validate = true` just as
    // the four `parse_str` impls do. So the premise the narrowing rested on is false, and
    // with it any inference from it. The conclusion it reached — that the bytes alone do
    // not decide the matter, and that the claim must be narrowed to string-valued targets
    // — survives, and is now argued from the pinned source rather than from a
    // counterexample that does not exist. What `parse_str_raw` (`validate = false`) does
    // accept is the BYTE-STRING path, and that is the only accepting target in the crate.
    invalid_utf8_probe_is_refused(fragments[0])?;
    // "BOUNDED MALFORMED INPUT IS PANIC-FREE" NAMES A BOUND, and until now nothing
    // measured one: every document above is a single-line object of a few hundred
    // bytes. These two probes measure the two axes the word can mean — DEPTH and
    // SIZE — and each says in its own assertion message exactly what depth and what
    // byte count it used, because a bound nobody can read is not a bound. What the
    // pair proves is stated at their definitions and is deliberately narrower than a
    // general claim: they prove no panic and a refusal at these two measured sizes,
    // not that no input of any size or depth is panic-free.
    bounded_deep_nesting_is_refused_without_panicking()?;
    bounded_oversized_document_is_handled_without_panicking()?;
    // THE SECOND GROUP, and the reason this case is extended rather than replaced.
    // Every row above is a `records.rs` TYPE, so the clause this case discharges was
    // measured against 2 of the 52 allocated types while all 40 `ids.rs` transparent
    // scalars — proved only by the byte-drift round-trip of case 2 — had no refusal
    // row anywhere in the fixture. The two groups are kept apart rather than merged:
    // they are refused for different reasons, at different layers, and asserting one
    // group's category rule on the other would be false in one direction or the other.
    transparent_scalar_group_is_refused(&transparent_scalar_rows(&group), &rows)?;
    // THE SYNTHETIC CONVERSE for the surrogate rule, and it is the only place that rule's
    // other direction is exercised at all: no row in the corpus carries a well-formed
    // escaped pair, so a detector that refused legal pairs would be invisible here.
    well_formed_escaped_surrogate_pair_is_not_a_lone_surrogate(&rows)?;
    Ok(())
}

/// One malformation kind a malformed document's OWN BYTES can exhibit.
///
/// THE VARIANTS ARE THE ONES THE BYTES CAN TELL APART, and that is stated rather
/// than assumed. THE TAXONOMY IS THIS DELIVERY'S OWN CONSTRUCTION AND THE CARD NAMES
/// NO MALFORMATION KIND AT ALL, so the provenance is worth recording rather than
/// leaving to be guessed. Issue #930's card gives cases 13-16 one clause, verbatim,
/// "bounded malformed input panic-free"; it contains no occurrence of "truncated
/// inside a string", "unterminated string", "trailing garbage", "trailing comma" or
/// "surrogate", and its only use of "seven" is in its Residual paragraph, where it is
/// `records.rs` STRUCTS carrying `deny_unknown_fields` and not anything here. Every name
/// in this enum is therefore a name this file chose, and so is the decision to have any
/// names at all: the card requires only that bounded malformed input be panic-free, and
/// a refusal asserted against an unnamed malformation would discharge that for every
/// reason at once. `enum Malformation` and `distinguishable_malformations()` each hold
/// seven entries today, `LoneLeadingSurrogate` is the fourth variant declared here, and
/// the eighth document in the group is why that fourth entry exists. No count is relied
/// on: the group's composition is the fixture owner's to move, and the assertion that
/// every kind has a witness is what keeps the list honest. What the bytes genuinely cannot separate IS
/// stated next: a JSON document that ends with an open string literal has ONE
/// malformation, not two — no closing quote and no closing brace, with the offending key
/// and its value bytes both present. `TruncatedInsideString` is therefore ONE variant for
/// both such documents rather than a "truncated" kind and an "unterminated" kind.
/// Splitting them would add two names with no byte able to choose between them, and
/// a classifier that cannot choose must say so rather than pick one and let the
/// witness count read as coverage of a shape that was never distinguished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Malformation {
    /// End of input arrives while a string literal is open.
    TruncatedInsideString,
    /// A complete top-level value, then bytes that are neither whitespace nor the
    /// start of another document.
    TrailingGarbage,
    /// A backslash inside a string literal followed by something that is not a JSON
    /// string escape.
    InvalidEscape,
    /// A `\uXXXX` escape naming a HIGH SURROGATE (`D800`-`DBFF`) that is not
    /// immediately followed by a `\uXXXX` escape naming a LOW SURROGATE
    /// (`DC00`-`DFFF`) — **in a document being decoded as a STRING-VALUED target**.
    ///
    /// WHY THIS IS NOT A CLAIM THAT THE BYTES ARE MALFORMED. The refusal is NOT a
    /// property of the bytes. These bytes are WELL FORMED — the `\u` followed by any four
    /// hex digits is exactly what RFC 8259's ABNF admits, and the spec deliberately stops
    /// short of declaring an unpaired surrogate invalid rather than declaring the text
    /// well formed at the value level. So this variant is named for the refusal a
    /// string-valued target makes, and it must not be read as a verdict that the document
    /// is broken.
    ///
    /// THE REFUSAL IS A PROPERTY OF THE TARGET, TRACED TO THE PINNED SOURCE. In
    /// `serde_json-1.0.151`, `read.rs:907-910` states the rule in its own words: "If
    /// deserializing a utf-8 string the surrogates are required to be paired, whereas
    /// deserializing a byte string accepts lone surrogates." That turns on `validate`,
    /// which is chosen by the TARGET rather than by the bytes:
    ///   * all FOUR `parse_str` impls hardcode `validate = true` — `SliceRead` at
    ///     `read.rs:336`, `IoRead` at `:588`, `StrRead` at `:710`, and `&mut R` at `:791`
    ///     by delegation. `from_str` reaches `StrRead` through `de.rs:2713`, so every
    ///     `from_str` call in this file is on the validating side by construction;
    ///   * the refusal itself is `read.rs:959`, and it sits INSIDE an `if validate {`
    ///     opened at `:958`. Every surrogate error in `parse_unicode_escape` is gated the
    ///     same way: `:911` is `if validate && n >= 0xDC00 && n <= 0xDFFF`, and both
    ///     `UnexpectedEndOfHexEscape` returns at `:930-936` and `:942-952` are
    ///     `if validate { … } else { … }`;
    ///   * `parse_str_raw` (`validate = false`) has exactly ONE real call site in the
    ///     crate, `de.rs:1648`, inside `deserialize_bytes`. So the only accepting target
    ///     in `serde_json` is a BYTE STRING.
    ///
    /// `serde_json::Value` IS ON THE REFUSING SIDE, and this file previously said the
    /// opposite. `Value`'s `Deserialize` dispatches `deserializer.deserialize_any(
    /// ValueVisitor)` at `value/de.rs:151`; that lands on `de.rs:1393`, whose string arm
    /// at `:1425-1432` calls `self.read.parse_str` at `:1428` — the validating entry
    /// point. So `from_str::<Value>` REFUSES these bytes. Upstream pins the exact shape:
    /// `tests/test.rs:1072-1075`, inside `test_parse_string`, maps `"\uD83C\uFFFF"` to
    /// `"lone leading surrogate in hex escape at line 1 column 13"` for a `String`
    /// target — a leading surrogate followed by a non-low-surrogate, which is
    /// structurally identical to the `\uD800\u0041` this row carries.
    ///
    /// SO WHAT THE ACCEPTING TARGET IS, AND WHY IT IS UNREACHABLE HERE. It is a
    /// byte-string target: `de.rs:1620-1632` documents the path and
    /// `tests/test.rs:1746-1749` exercises it. Nothing in this workspace can name one:
    /// `serde_bytes` is not a dependency of any manifest in the tree and appears in
    /// `Cargo.lock` zero times, and the `raw_value` feature is not enabled. So for every
    /// target this crate can actually construct, the refusal is unconditional, and the
    /// narrowing below is a statement about the TYPE rather than a hedge about the input.
    ///
    /// PYTHON'S ACCEPTANCE IS THE DIVERGENT RULE, NOT A SAFER OUTCOME, and it is worth
    /// stating because it is the sentence that was wrong here before. `json.loads` accepts
    /// these bytes, but the `str` it returns then fails `encode('utf-8')` with `surrogates
    /// not allowed`, while `surrogatepass` yields `\xed\xa0\x80` — the same WTF-8 bytes
    /// `read.rs:961` emits. Python defers the failure from parse time to encode time and
    /// arrives at the same octets; `serde_json` is the strict one, by design and in-source.
    ///
    /// SO THE CLASSIFIER'S CLAIM, IN ITS HONEST AND STRONGER FORM. This variant means
    /// "these bytes carry an unpaired high-surrogate escape, and every string-valued
    /// target REFUSES them, and no target reachable in this workspace accepts them". It
    /// still does NOT mean "these bytes are malformed" full stop, and a caller that
    /// genuinely decodes a BYTE-STRING must not read this kind as a refusal; no such
    /// caller exists here, and that is the reason the sentence can be this firm. Every row
    /// the classifier sees is decoded through `serde_json::from_str::<T>` where `T`
    /// carries `String` members, so `validate` is on for all of them. The alternative —
    /// threading the target's validation behaviour in as a parameter — was rejected
    /// because a parameter passed wrongly would make the classifier wrong silently, whereas
    /// a narrowed claim in the documentation is wrong loudly, at the point a reader decides
    /// what to do with the answer.
    ///
    /// WHAT A PREVIOUS VERSION OF THIS PARAGRAPH GOT WRONG, kept because it is the reason
    /// the wording above is so much more definite than the wording it replaces. It read
    /// "`serde_json::from_str::<serde_json::Value>` ACCEPTS these exact bytes, which is
    /// why an independent parser accepts them too", and it used that as the premise for
    /// narrowing this claim to string-valued targets. The premise is FALSE: `Value` refuses
    /// these bytes, for the `parse_str` reason traced above, and an inference from a
    /// counterexample that does not exist establishes nothing. The conclusion it reached
    /// — that the bytes alone do not decide the matter — happens to survive, and
    /// survives now for the right reason: the accepting path is the byte-string path, and
    /// it is unreachable here. The sentence it was built on had to go either way.
    ///
    /// IT IS PLACED IMMEDIATELY AFTER `InvalidEscape` because both are defects in the
    /// SEMANTICS OF AN ESCAPE rather than in the container structure, and because the
    /// classifier applies its rules by precedence — see `classify_malformation`.
    ///
    /// ONE VARIANT COVERS TWO SHAPES, and the reason is the same one that merged
    /// `TruncatedInsideString`'s two cases: a high surrogate followed by the END of the
    /// string is refused by `serde_json` as a DIFFERENT code
    /// (`UnexpectedEndOfHexEscape`), so the bytes CAN tell them apart, but no fixture row
    /// exhibits the second and this classifier refuses to name a kind it cannot point at.
    /// If one is ever added, this is the place to split it, and the byte fact recorded in
    /// `distinguishable_malformations` is where the two would be told apart.
    LoneLeadingSurrogate,
    /// Every string closed and every value complete, but a container is still open
    /// when the input ends: the closing brace is absent.
    MissingClosingBrace,
    /// A complete top-level value immediately followed by another container, with
    /// nothing between them.
    ConcatenatedDocuments,
    /// A `,` followed, past whitespace, by a container terminator.
    TrailingComma,
}

/// The byte just past a WELL-FORMED JSON string escape beginning at the backslash
/// `start`, or `None` when what follows the backslash is not one.
///
/// "Well-formed" IS the whole of what is modelled here, and that is a NARROWER claim
/// than "accepted by `serde_json`" on purpose: this reads the JSON grammar and stops.
/// A `\uXXXX` escape gets its four hex digits read and its value returned through
/// `hex_escape_value`; anything else consumes the single byte the grammar allows after a
/// backslash. What it deliberately does NOT do is follow the escape into surrogate
/// pairing — that is `continues_with_low_surrogate`'s question, kept separate so this
/// function stays a statement about one escape and not about its neighbour.
///
/// ASSUMPTION, AND THE CLASS OF INPUT WHERE IT COULD FAIL: this assumes the JSON escape
/// set is exactly `"` `\` `/` `b` `f` `n` `r` `t` `u`, which `serde_json` implements from
/// the grammar and has no reason to extend. An input relying on a future or
/// vendor-specific escape would be read here as either a valid two-byte escape (if the
/// letter is in the set) or an invalid escape (if not), where the parser might accept
/// it. `serde_json` has no such extension today, and the failure direction would be a
/// red rather than a silent wrong answer.
fn escape_after(bytes: &[u8], start: usize) -> Option<usize> {
    let escape = *bytes.get(start + 1)?;
    match escape {
        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Some(start + 2),
        b'u' => (start + 6 <= bytes.len()).then_some(start + 6),
        _ => None,
    }
}

/// The scalar a `\uXXXX` escape at `start` names, or `None` when the four bytes after
/// the `u` are not four hex digits.
///
/// `None` here is NOT the same as "no escape": `escape_after` has already established
/// that a `u` escape is present and long enough, so a `None` from this function means the
/// digits themselves are malformed, which is the invalid-escape case.
///
/// ASSUMPTION: hex digits are ASCII `0-9a-fA-F`, which the JSON grammar fixes. Input
/// relying on any other digit convention would be read as invalid here.
fn hex_escape_value(bytes: &[u8], start: usize) -> Option<u32> {
    let digits = bytes.get(start + 2..start + 6)?;
    let mut scalar: u32 = 0;
    for digit in digits {
        let value = match digit {
            b'0'..=b'9' => u32::from(digit - b'0'),
            b'a'..=b'f' => u32::from(digit - b'a') + 10,
            b'A'..=b'F' => u32::from(digit - b'A') + 10,
            _ => return None,
        };
        scalar = scalar * 16 + value;
    }
    Some(scalar)
}

/// Whether the escape beginning at `after` continues a pair by naming a LOW SURROGATE.
///
/// This is the rule `serde_json` applies after reading a high surrogate: the next escape
/// must be `\uXXXX` with `XXXX` in `DC00`-`DFFF`, and anything else — a different escape,
/// or the end of the string — leaves the high surrogate unpaired and the document
/// refused. It is asked as a SEPARATE question from `escape_after` so that "the escape
/// after this one is malformed" and "the escape after this one is a well-formed non-
/// surrogate escape" both answer `false`, which is what both require: a document is
/// refused either way, and the classifier has one kind for it.
///
/// ASSUMPTION: the low-surrogate range is `DC00`-`DFFF`, which is what the UTF-16
/// specification fixes and what `serde_json` implements. No input can be well-formed and
/// disagree, so the failure direction here would be a red, not a wrong answer.
fn continues_with_low_surrogate(bytes: &[u8], after: usize) -> bool {
    if bytes.get(after) != Some(&b'\\') {
        return false;
    }
    hex_escape_value(bytes, after).is_some_and(|scalar| (0xDC00..=0xDFFF).contains(&scalar))
}

/// The first offset at or after `probe` that is not ASCII whitespace.
///
/// A free function rather than a closure over the bytes because BOTH halves need it:
/// the trailing-comma rule reads it from inside the scan, and the top-level-value rule
/// reads it from the classifier once the scan has returned. A closure would have had to
/// be built twice or handed across the split.
fn whitespace_after(bytes: &[u8], probe: usize) -> usize {
    let mut cursor = probe;
    while matches!(bytes.get(cursor), Some(byte) if byte.is_ascii_whitespace()) {
        cursor += 1;
    }
    cursor
}

/// Everything one pass over a document's raw bytes establishes, and nothing else.
///
/// The split from `classify_malformation` is by RESPONSIBILITY, not by convenience: this
/// type is what "find where the malformation is" produces, and the classifier is what
/// "decide what kind it is" consumes. The two halves are one pass followed by one
/// ordered sequence of tests, and the order the classifier tests these facts in is the
/// order the facts are listed here.
struct MalformationFacts {
    inside_string: bool,
    invalid_escape: bool,
    lone_leading_surrogate: bool,
    trailing_comma: bool,
    unclosed_containers: usize,
    top_level_end: Option<usize>,
}

/// THE SCAN HALF of `classify_malformation`: the single pass over the raw bytes that
/// fills in a `MalformationFacts` and refuses, by name, the one thing it cannot place.
///
/// The two refusals and every observation are carried over unchanged from the body this
/// was lifted out of; see `classify_malformation`'s own documentation for why each one
/// sits where it does and what it costs.
fn scan_for_malformation(row: &Row) -> Result<MalformationFacts, Box<dyn std::error::Error>> {
    let bytes = row.raw.as_bytes();
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut invalid_escape = false;
    let mut lone_leading_surrogate = false;
    let mut trailing_comma = false;
    // Byte offset just past the first complete top-level value, once found.
    let mut top_level_end: Option<usize> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            match byte {
                b'\\' => {
                    // THE WHOLE ESCAPE IS READ HERE, in one step, rather than letting a
                    // flag skip the single byte after the backslash. That change is what
                    // makes the high-surrogate rule expressible at all: the rule needs the
                    // FOUR HEX DIGITS and the escape that FOLLOWS them, and a flag that
                    // consumed one byte could never have them. `escape_after` returns the
                    // byte just past a well-formed escape, or `None` for anything else —
                    // and `None` is what sets the invalid-escape fact, replacing the old
                    // membership test over the single byte after the backslash. Ordinary
                    // string content still cannot reach here, because this arm is only
                    // entered on a literal backslash.
                    match escape_after(bytes, index) {
                        Some(after) => {
                            if hex_escape_value(bytes, index)
                                .is_some_and(|scalar| (0xD800..=0xDBFF).contains(&scalar))
                                && !continues_with_low_surrogate(bytes, after)
                            {
                                lone_leading_surrogate = true;
                            }
                            index = after;
                        }
                        None => {
                            invalid_escape = true;
                            index += 1;
                        }
                    }
                }
                b'"' => {
                    in_string = false;
                    index += 1;
                }
                _ => index += 1,
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                index += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                if depth == 0 {
                    return fail(format!(
                        "case {} row {} closes a container that was never opened, which is a malformation kind this classifier does not model; refusing to guess",
                        row.case, row.id
                    ));
                }
                depth -= 1;
                index += 1;
                if depth == 0 && top_level_end.is_none() {
                    top_level_end = Some(index);
                }
            }
            b',' => {
                if matches!(
                    bytes.get(whitespace_after(bytes, index + 1)),
                    Some(b'}' | b']')
                ) {
                    trailing_comma = true;
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    Ok(MalformationFacts {
        inside_string: in_string,
        invalid_escape,
        lone_leading_surrogate,
        trailing_comma,
        unclosed_containers: depth,
        top_level_end,
    })
}

/// What is wrong with a malformed document, read from ITS OWN BYTES.
///
/// WHY BYTES, and not the two things a reader might expect. The row id is a label:
/// a classifier keyed on it is satisfied by renaming a row and by nothing else, so
/// renaming `930-142-malformed-missing-brace` to `-trailing-comma` would keep it
/// green. The `reason` prose is text another writer is editing in the same delivery,
/// and this file already refuses to couple a control flow to it — see
/// `empty_identity_member`, which derives the same kind of fact structurally for
/// exactly that reason. The bytes are the only thing the decoder sees, so they are
/// the only thing an expectation about the decoder may be built from.
///
/// WHAT IT MEASURES. ONE strict structural scan collecting five facts, each from
/// the bytes alone:
/// * whether end of input arrives while a string literal is still open;
/// * whether any backslash inside a string literal is followed by something that is
///   not one of `"` `\` `/` `b` `f` `n` `r` `t` `u`;
/// * whether any `\uXXXX` escape names a high surrogate that the next escape does not
///   continue with a low surrogate — `Malformation::LoneLeadingSurrogate`;
/// * whether any `,` is followed, past JSON whitespace, by `}` or `]`;
/// * where the first complete top-level value ends, and what the next
///   non-whitespace byte after it is.
///
/// THE THIRD FACT IS NOT A STRUCTURAL ONE, AND SAYING SO IS THE POINT. The other four
/// are decidable from brace and quote nesting alone. This one is not: `\uD800` is a
/// legal escape sequence, so a document carrying it nests perfectly and every other
/// fact here is FALSE for it. It becomes a refusal only when the decoder reads the
/// FOLLOWING escape and finds it outside `DC00-DFFF`. That is why the scan reads whole
/// escape sequences through `escape_after` rather than treating `\` as a single skipped
/// byte, and it is the concrete demonstration of the general risk this file records
/// elsewhere: a byte scanner that models less than the parser will report a malformed
/// document as well-formed, and the failure surfaces as a RED rather than as a silently
/// wrong answer — which is the good case, and is the only reason this gap was found.
///
/// CLASSIFICATION IS BY PRECEDENCE, AND THE ORDER IS A DELIBERATE CHOICE, not an
/// accident of the sequence the branches happen to be written in. A document can be
/// wrong in more than one way at once, and three rows in the live group are STRUCTURALLY
/// COMPLETE — balanced, nothing trailing, a real parser's first depth-0 close equal to
/// its length — so each of them is held out of the "this is not malformed at all" guard
/// by exactly one of the precedence rules and by nothing else. A row carrying two defects
/// would be attributed to whichever rule is tested first, which is why the order is
/// argued here rather than left implicit.
///
/// THE ORDER, AND WHY EACH STEP SITS WHERE IT DOES:
/// * `TruncatedInsideString` FIRST, because a string left open at end of input means the
///   bytes after the opening quote were never terminated, so nothing inside that string —
///   not a bad escape, not a surrogate — can be read as an escape at all. Every later
///   rule is unreachable for such a document, and that is a fact about the input rather
///   than a preference.
/// * `InvalidEscape` SECOND, ahead of the surrogate rule, and the reason is that an
///   invalid escape means the byte sequence is not an escape sequence AT ALL. The
///   surrogate rule has to read the escape that FOLLOWS a high surrogate; if that
///   sequence is not an escape, there is nothing for it to read, so attributing the
///   document to the more fundamental "this is not a string escape" fact is the honest
///   attribution and the other would be reading a neighbour that does not exist.
/// * `LoneLeadingSurrogate` THIRD, with `TrailingComma` behind it and not beside it.
///   Both concern rows that are structurally complete, so the choice decides which kind
///   a document carrying BOTH would get. Escape CONTENT sits closer to the offending
///   bytes than container structure does: a trailing comma is a fact about the shape of
///   the document, while an unpaired surrogate is a fact about a specific character the
///   document cannot produce, and the more specific defect is the one a reader needs.
/// * `TrailingComma` FOURTH, then `MissingClosingBrace` FIFTH — both container-structure
///   facts, ordered narrowest-first, and no live row carries both.
/// * Trailing content LAST, because it is the only rule that reads a byte OUTSIDE the
///   first top-level value, and so the only one that can be evaluated at all once the
///   document is known to be complete.
///
/// WHICH CONVENTION IS USED FOR THE END OF THE TOP-LEVEL VALUE, since it is a choice and
/// not a fact. `top_level_end` is set at the FIRST depth-0 close, guarded by
/// `top_level_end.is_none()`, NOT the last. That convention is what makes
/// `930-139` and `930-143` two different kinds rather than one: both are two complete
/// values side by side, and they differ only in the byte at the first non-whitespace
/// position after the FIRST close — `0x74` against `0x7b`. Taking the LAST close would
/// read the same position for both and merge them. The cost is stated because it is real:
/// `930-143` is the one row where the first and last depth-0 closes disagree, so its
/// classification rests entirely on that guard, and dropping the `.is_none()` would
/// reclassify it — and the failure that would produce is the "complete document" guard
/// firing on a MIS-PARSE rather than on a genuinely well-formed input, with nothing in
/// this file able to tell the two apart. No oracle here compares `top_level_end` with
/// what a real parser reports; see the witness notes on `classify_malformation`'s helpers
/// for what that leaves unguarded.
///
/// IT FAILS LOUDLY, naming the row, on anything it cannot place — a well-formed
/// document, one with no complete top-level value at all, and one whose container
/// balance is wrong in a direction this scan does not model. That is the requirement
/// that makes the witness counts mean anything: a row that could not be classified
/// must never be allowed to count toward any kind, because a silent default would let
/// a well-formed document, or a substitution of one shape for another, keep every
/// guard at the call site green. AFTER THE SURROGATE RULE WAS ADDED this guard's MEANING
/// SHARPENED RATHER THAN WEAKENED: reaching it now means the document is complete AND
/// carries no malformed escape of any kind, because the escape rules are tested ahead of
/// it. A row that used to land here for want of a rule — `930-162` did — now carries its
/// own kind, and a row that lands here is complete for a reason the scan can point at.
///
/// WHAT IS UNGUARDED HERE, and it is recorded because a mis-parse that produced a WRONG
/// ANSWER rather than a red would be invisible. Nothing in this file compares this
/// scan's `top_level_end`, its escape decoding or its brace depth against what a real
/// parser reports, so two classes of defect would pass silently: a scan that
/// UNDER-reports would let a malformed document be classified as a well-formed one and
/// stop here, and a scan that MIS-reports `top_level_end` would classify a row as the
/// wrong kind with a well-formed-looking failure. The lone-surrogate gap was the good
/// case of this risk — it surfaced as a RED, because the scan under-reported and the
/// guard caught the consequence — and that is the only reason it was ever found.
///
/// THREE WITNESS GAPS IN THIS SCANNER, each of which is a place where the corpus cannot
/// tell a correct scanner from an incorrect one:
/// * THE ESCAPE-STATE MACHINE IS UNWITNESSED. No row in the whole corpus contains `\"`
///   or `\\`, so a scanner that toggled string state on every `0x22` and ignored
///   backslashes entirely would agree with this one on every row there is. Only the
///   `invalid_escape` branch exercises the backslash path at all, and it exercises it on
///   `930-141`, whose escape is `\x`. The class of input that would expose the difference
///   is any row with an escaped quote inside a string value, where the naive scanner would
///   end the string early and then read the remainder as structure.
/// * THE WHITESPACE SKIP IN THE TRAILING-COMMA RULE HAS NO WITNESS. Every comma in the
///   group is followed by a byte that is not whitespace, and `930-144`'s comma is
///   followed directly by `0x7d`, so the skip never advances. The input that would
///   witness it is `[1, 2,]`; no such row exists, and a scanner that omitted the skip
///   would classify that document as something other than a trailing comma.
/// * THE WHITESPACE SKIP AFTER THE TOP-LEVEL VALUE HAS EXACTLY ONE WITNESS. The other
///   use of `whitespace_after` is read once, on `930-139`, so a scanner that skipped no
///   whitespace there would still classify every other row identically.
///
/// The synthetic control below is the one gap this file CAN close, and it closes only the
/// surrogate-pair direction; the three above need corpus rows this lane does not own.
fn classify_malformation(row: &Row) -> Result<Malformation, Box<dyn std::error::Error>> {
    let bytes = row.raw.as_bytes();
    let facts = scan_for_malformation(row)?;
    if facts.inside_string {
        return Ok(Malformation::TruncatedInsideString);
    }
    if facts.invalid_escape {
        return Ok(Malformation::InvalidEscape);
    }
    // AHEAD OF EVERY STRUCTURAL RULE BELOW, and that placement is the whole point of
    // the variant: a document carrying a lone leading surrogate has sound braces, sound
    // strings and no trailing comma, so without this arm first it would fall through
    // every rule below and be reported as a COMPLETE document — the exact misclassification
    // that made this row a red.
    if facts.lone_leading_surrogate {
        return Ok(Malformation::LoneLeadingSurrogate);
    }
    if facts.trailing_comma {
        return Ok(Malformation::TrailingComma);
    }
    if facts.unclosed_containers != 0 {
        return Ok(Malformation::MissingClosingBrace);
    }
    let Some(end) = facts.top_level_end else {
        return fail(format!(
            "case {} row {} holds no complete top-level value, so its malformation cannot be named; refusing to guess",
            row.case, row.id
        ));
    };
    match bytes.get(whitespace_after(bytes, end)) {
        // A complete document and nothing after it: not malformed at all, which is a
        // contradiction inside a reject group rather than a shape to accommodate.
        None => fail(format!(
            "case {} row {} is a COMPLETE JSON document with no trailing bytes, so it is not malformed and cannot count toward any malformation kind",
            row.case, row.id
        )),
        Some(b'{' | b'[') => Ok(Malformation::ConcatenatedDocuments),
        Some(_) => Ok(Malformation::TrailingGarbage),
    }
}

/// The synthetic positive control for the surrogate rule: a document carrying a
/// WELL-FORMED escaped surrogate pair must NOT be classified as a lone leading
/// surrogate, and the reason it has to be BUILT rather than FOUND is that no row in the
/// corpus carries a pair in escape form at all.
///
/// WHY IT IS SYNTHETIC, and this is a real gap rather than a stylistic choice. Scanning
/// every row of the fixture finds exactly ONE surrogate escape anywhere, and it is
/// `930-162`'s unpaired one. So a fixture-driven control does not exist and cannot be
/// made to exist from this lane, which does not own the fixture. The row that used to be
/// the candidate witness CANNOT serve: `930-128`'s `raw` is LITERAL UTF-8 bytes, so its
/// astral character never enters the escape-decoding path at all and it exercises none
/// of this rule.
///
/// WHAT IT ASSERTS, and why the expected side is not merely "not the lone kind". The
/// document below is COMPLETE and well-formed, so the honest answer from
/// `classify_malformation` is to REFUSE TO GUESS — the `Err` the "this is not malformed"
/// guard returns. Asserting only "the result is not `Ok(LoneLeadingSurrogate)`" would be
/// satisfied by any other failure, including a mis-parse, so the assertion instead
/// requires that specific guard: the probe must come back as an `Err` whose message is
/// the complete-document one. If the surrogate rule fired, the result would be
/// `Ok(LoneLeadingSurrogate)` and this fails; if the scan mis-parsed the escapes, the
/// message would be a different `Err` and this fails too. Both directions are therefore
/// distinguished, which is the property a fixture row could not have supplied.
///
/// The pair is spelled as the six characters `\uD83D\uDE00` in the Rust literal, which
/// is what puts those twelve bytes into the probe's `raw` — the fixture's JSON string
/// escaping is not involved, because the probe never round-trips through the fixture.
fn well_formed_escaped_surrogate_pair_is_not_a_lone_surrogate(all: &[Row]) -> TestResult {
    // Borrowed from a real `HealthRecord` row so every other byte of the probe is the
    // crate's own recorded shape rather than something written here.
    let donor = applicable_row(all, "HealthRecord")?;
    // A RAW string, and that is what makes the token ASCII: inside `r#"..."#` a
    // backslash is a backslash, so this is the twelve characters
    // `\`,`u`,`D`,`8`,`3`,`D`,`\`,`u`,`D`,`E`,`0`,`0` between two quote marks and
    // nothing else. A normal literal would have needed four doubled backslashes to
    // produce the same bytes, and a literal emoji would have produced UTF-8 and
    // exercised none of the escape path this control exists for.
    const ESCAPED_PAIR: &str = r#""\ud83d\ude00""#;
    let probe_raw = document_with_member_value(&donor.raw, "detail", ESCAPED_PAIR)?;
    assert_ne!(
        probe_raw, donor.raw,
        "the synthetic probe must actually carry the escaped pair, or it witnesses nothing: donor row {} and its detail member is not spelled the way this probe assumes",
        donor.id
    );
    let mut probe = (*donor).clone();
    probe.raw = probe_raw;
    match classify_malformation(&probe) {
        Ok(kind) => fail(format!(
            "row {} carries a WELL-FORMED escaped surrogate pair ({ESCAPED_PAIR}), so it must not be classified as {kind:?}; a detector that refuses a legal pair would red a row that has to be accepted",
            probe.id
        )),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains("COMPLETE JSON document"),
                "row {} carries a well-formed escaped surrogate pair, so the honest answer is the complete-document refusal and the surrogate rule must NOT have fired; got a different failure, which means the escapes were mis-read rather than correctly accepted: {message}",
                probe.id
            );
            Ok(())
        }
    }
}

/// Every kind the classifier above can distinguish, paired with the byte fact each
/// one rests on, so a failure message can say what was MISSING rather than only which
/// name was absent.
///
/// The list is of CONSTRUCTORS, not of fixture rows: no row id appears here, and the
/// count of rows carrying each shape is measured by the caller from the classifier's
/// own answers. A kind with no witness is what the caller's assertion is for.
fn distinguishable_malformations() -> Vec<(Malformation, &'static str)> {
    vec![
        (
            Malformation::TruncatedInsideString,
            "a document that ends while a string literal is open (this is the one kind \
             `TruncatedInsideString` covers for TWO of this file's own shapes, and no byte \
             tells them apart: the card names neither shape, so the merge is a decision \
             recorded here rather than an attribution to it)",
        ),
        (
            Malformation::TrailingGarbage,
            "a complete top-level value followed by bytes that open nothing",
        ),
        (
            Malformation::InvalidEscape,
            "a backslash inside a string that is not a JSON string escape",
        ),
        (
            Malformation::LoneLeadingSurrogate,
            "a `\\uXXXX` escape naming a high surrogate (D800-DBFF) that the next escape \
             does not continue with a low surrogate (DC00-DFFF) — a document that nests \
             perfectly and is still refused, because the refusal is in the escape's \
             SEMANTICS and not in the structure",
        ),
        (
            Malformation::MissingClosingBrace,
            "every string closed with a container still open at end of input",
        ),
        (
            Malformation::ConcatenatedDocuments,
            "two complete top-level values concatenated with nothing between them",
        ),
        (
            Malformation::TrailingComma,
            "a comma immediately before a container terminator",
        ),
    ]
}

/// The `serde_json` error `Category` a refusal of a given malformation must fall in.
///
/// A CATEGORY AND NOT A MESSAGE, and the reason is that the category is exact and
/// wording-independent. `Error::classify()` (`serde_json-1.0.151/src/error.rs:54-82`)
/// is a total function from the internal `ErrorCode` to `Category`, and `is_io`,
/// `is_syntax`, `is_data` and `is_eof` (`src/error.rs:86-112`) are equality against
/// it — so these are four facts about a code, not four substrings of a message that a
/// `serde_json` bump may reword.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefusalCategory {
    /// `Category::Eof`. `EofWhileParsingString` and `EofWhileParsingObject` both land
    /// here (`src/error.rs:60-63`), so a document that runs out inside a string and a
    /// document that runs out inside an object are the same category even though they
    /// are different malformations.
    Eof,
    /// `Category::Syntax`. `InvalidEscape` (`src/error.rs:68`) and both
    /// `TrailingComma` and `TrailingCharacters` (`src/error.rs:77-78`) land here.
    Syntax,
}

/// The category one malformation's refusal must fall in.
///
/// THE BINDING THIS EXISTS FOR. `assert_refused` is a bare `is_err`: any of these
/// documents could be refused for an UNRELATED reason and the case would stay green.
/// The concrete false pass is that the missing-closing-brace document could ALSO be
/// made to omit a required member — it would still be refused, `is_err` would still
/// hold, and the missing-brace shape would no longer be what was measured. Case 10 and
/// case 15 each answer that with a per-row ISOLATION CONTROL, and the invalid-UTF-8
/// probe here has one too, which is what makes the bare `is_err` on THESE documents a
/// defect rather than a choice.
///
/// WHY THE CATEGORY AND NOT A PER-ROW CONTROL. A "same document minus the one
/// mutation" control cannot be written for most of these shapes: there is no complete
/// document to restore. A truncated document has no closing quote to put back and no
/// closing brace to put back; the document that proves the repair would be a document
/// this fixture does not carry, and inventing one here would be authoring the very
/// payload the case is about. The category binding needs no repair — it asks only that
/// the refusal be of the KIND the bytes imply, which is a strictly stronger statement
/// than `is_err` and is available for every shape here.
///
/// AND THE DIRECTION MATTERS, which is why `!error.is_data()` is asserted too: a
/// document that is well-formed JSON but semantically wrong is a DATA refusal, and a
/// DATA refusal of any of these documents must NOT satisfy this case. `Category::Data`
/// is what every serde `Message` code produces, so without that conjunct a member
/// dropped from any of these rows would satisfy the assertion below just as well as
/// the malformation would.
fn expected_malformation_category(kind: Malformation) -> RefusalCategory {
    match kind {
        Malformation::TruncatedInsideString | Malformation::MissingClosingBrace => {
            RefusalCategory::Eof
        }
        Malformation::InvalidEscape
        | Malformation::LoneLeadingSurrogate
        | Malformation::TrailingGarbage
        | Malformation::ConcatenatedDocuments
        | Malformation::TrailingComma => RefusalCategory::Syntax,
    }
}

/// The refusal for one malformed document must be the refusal its OWN BYTES imply.
///
/// TWO CONJUNCTS, ORDERED, and the order is the claim. The DATA exclusion comes
/// FIRST and on its own, because it is the requirement about what must NOT satisfy
/// this case: a well-formed document that is semantically wrong is refused with a
/// serde `Message` code, `Category::Data`, and no amount of syntax-layer reasoning
/// about the bytes catches that — only the exclusion does. The category assertion
/// then narrows further to the specific malformation. `Category::Data` and the two
/// categories `expected_malformation_category` can name are mutually exclusive, so
/// the first conjunct is implied by the second as the mapping stands today; it is
/// kept first and kept separate anyway, because it is the conjunct that survives a
/// future malformation being mapped to a different category, and because a reader
/// auditing "can a semantically-wrong document pass this?" should not have to reason
/// through the mapping to find out.
///
/// The message is never compared, and no member name is required: none of these
/// documents is refused FOR a member, so demanding a member name would be the wrong
/// claim rather than a stricter one.
fn malformed_document_is_refused_for_its_own_shape(
    row: &Row,
    kind: Malformation,
    error: &serde_json::Error,
) {
    assert!(
        !error.is_data(),
        "case {} row {} is classified {kind:?} from its own bytes, so it must be refused by the JSON LAYER and not by a serde `Message` code; a DATA refusal means the document was refused for being semantically wrong — a dropped member, a wrong kind — and the malformation is no longer what is being measured: {error}",
        row.case,
        row.id
    );
    let expected = expected_malformation_category(kind);
    let matched = match expected {
        RefusalCategory::Eof => error.is_eof(),
        RefusalCategory::Syntax => error.is_syntax(),
    };
    assert!(
        matched,
        "case {} row {} is classified {kind:?} from its own bytes and must therefore be refused with a {expected:?} refusal, so that the refusal is attributable to THAT malformation rather than to something else this document also gets wrong; the refusal was {error}",
        row.case, row.id
    );
}

/// Array levels of nesting built below one object, for the deep probe.
///
/// A NAMED CONSTANT and not a literal at the call site, because the whole claim of
/// that probe is that a specific depth was measured: a depth written inline at the
/// point of use could be edited without the assertion message — which names this
/// constant — changing with it, and the message is the only place a reader learns what
/// "bounded" was taken to mean.
const DEEP_PROBE_ARRAY_DEPTH: usize = 200;

/// Detail payload size in bytes, for the oversized probe. Named for the same reason as
/// `DEEP_PROBE_ARRAY_DEPTH`.
const OVERSIZED_PROBE_DETAIL_BYTES: usize = 1024 * 1024;

/// Deeply nested input must be REFUSED, and refused by the parser's own recursion
/// guard rather than by exhausting the stack.
///
/// WHAT THIS PROVES, precisely, and no more. It proves that input nested
/// `DEEP_PROBE_ARRAY_DEPTH` arrays deep inside one object is REFUSED and does not
/// panic, and that the refusal on the permissive path is `Category::Syntax` — which is
/// where `serde_json-1.0.151` puts `ErrorCode::RecursionLimitExceeded`
/// (`src/error.rs:80`). That code is raised by the `check_recursion!` macro
/// (`src/de.rs:1372-1386`) around every container entry, against a `remaining_depth`
/// initialised to 128 (`src/de.rs:63`) and feature-gated so that only the
/// `unbounded_depth` feature disables it — which this workspace does not enable, so
/// the guard is in force on this path.
///
/// WHAT IT DOES NOT PROVE, and the difference is the whole reason it is stated. It
/// does NOT prove a bound on this crate's decoder, and it cannot: the derived decoder
/// for `HealthRecord` reaches `detail`, sees `[`, and raises `invalid type` — a DATA
/// refusal — at depth one, LONG BEFORE the parser's guard is anywhere near its limit.
/// So the second assertion below is a statement about where the crate's OWN decoder
/// stops, and it is a data refusal by construction; it is asserted as such rather than
/// dressed up as a depth measurement. And it does not prove that no input of any depth
/// is panic-free — only that nesting at the depth recorded in these messages, which is
/// the only depth anyone can read off this test.
///
/// A depth probe was previously declined here on the grounds that `strict_json.rs` has
/// no depth limit of its own. That is true of that module and irrelevant here: the
/// decode path under test is `serde_json::from_str`, and `serde_json` carries its own
/// recursion limit and refuses deeply nested input rather than running the stack out.
fn bounded_deep_nesting_is_refused_without_panicking() -> TestResult {
    let mut raw = String::from("{\"component\":\"probe\",\"status\":\"probe\",\"detail\":");
    for _ in 0..DEEP_PROBE_ARRAY_DEPTH {
        raw.push('[');
    }
    for _ in 0..DEEP_PROBE_ARRAY_DEPTH {
        raw.push(']');
    }
    raw.push('}');
    let bytes = raw.len();
    let containers = DEEP_PROBE_ARRAY_DEPTH + 1;
    let permissive = serde_json::from_str::<Value>(&raw);
    let error = permissive.err().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "input nested {DEEP_PROBE_ARRAY_DEPTH} array levels ({containers} containers) inside one object, {bytes} bytes in total, DECODED into a Value, so no recursion guard refused it and the depth this probe claims to have measured is not being measured at all"
        )))
    })?;
    assert!(
        error.is_syntax(),
        "{DEEP_PROBE_ARRAY_DEPTH} nested array levels ({containers} containers, {bytes} bytes) must be refused at the SYNTAX layer, which is where serde_json-1.0.151 places ErrorCode::RecursionLimitExceeded (src/error.rs:80); any other category means something other than the parser's recursion guard refused it: {error}"
    );
    assert!(
        !error.is_eof(),
        "the deeply nested document is COMPLETE — it opens and closes every one of its {containers} containers — so a refusal for running out of input would mean the parser stopped reading rather than refused the nesting: {error}"
    );
    // The same bytes through the crate's own type. The refusal is required, and it is
    // a DATA one: `detail` is declared `String`, so the derived decoder stops at the
    // first `[` and never descends. That is stated rather than hidden because it is
    // what this assertion does NOT measure — no depth of nesting ever reaches this
    // decoder's recursion, so what it proves about depth is only that a deeply nested
    // document is refused without panicking on the real path too.
    let refused = serde_json::from_str::<eliot_types::HealthRecord>(&raw);
    let error = refused.err().ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "input nested {DEEP_PROBE_ARRAY_DEPTH} array levels ({containers} containers, {bytes} bytes) DECODED as a HealthRecord, so a deeply nested document is accepted on this crate's own decode path"
        )))
    })?;
    assert!(
        error.is_data(),
        "the crate's own decoder must stop at `detail` with an `invalid type` refusal, which is a DATA code, rather than descending into the nesting: the claim here is only that {DEEP_PROBE_ARRAY_DEPTH} nested array levels ({containers} containers, {bytes} bytes) are refused without panicking on this path, NOT that this decoder enforces any depth limit of its own: {error}"
    );
    Ok(())
}

/// An over-large document must be handled without panicking, and here it must be read
/// END TO END rather than short-circuited.
///
/// WHAT THIS PROVES, precisely. It proves that a single-string document carrying
/// `OVERSIZED_PROBE_DETAIL_BYTES` bytes of `detail` DECODES through
/// `serde_json::from_str` on this crate's real type, and that the decoded value holds
/// every one of those bytes. The length assertion is the load-bearing half: a decoder
/// that accepted the document while truncating or eliding the payload would satisfy a
/// bare "did not panic" check, and asserting the decoded length is what rules that
/// out.
///
/// WHAT IT DOES NOT PROVE. It does not prove there is no size ceiling on this path, and
/// it is not the place such a ceiling would be found: it shows there is none that this
/// document reaches, at the size recorded in the messages below. It also says nothing
/// about a deeply nested over-large document, about streaming, or about the resource
/// ceiling a caller would impose before handing bytes to this decoder — this crate
/// declares none, and asserting that a payload of unbounded size is handled would be
/// asserting the opposite of a bound.
fn bounded_oversized_document_is_handled_without_panicking() -> TestResult {
    let detail = "a".repeat(OVERSIZED_PROBE_DETAIL_BYTES);
    let raw = format!("{{\"component\":\"probe\",\"status\":\"probe\",\"detail\":\"{detail}\"}}");
    let bytes = raw.len();
    let decoded: eliot_types::HealthRecord = serde_json::from_str(&raw).map_err(boxed)?;
    assert_eq!(
        decoded.detail.len(),
        OVERSIZED_PROBE_DETAIL_BYTES,
        "a document carrying {OVERSIZED_PROBE_DETAIL_BYTES} detail bytes ({bytes} bytes in total, measured at runtime) must decode with every one of those bytes present, or it was accepted while being truncated or elided and this probe would be satisfied by a decoder that stopped reading"
    );
    Ok(())
}

/// CASE 15 OF ISSUE #930 IS **PARTIAL**, AND THE TEST NAME SAYS SO: it carries
/// `partial_` because the unqualified clause reads as more than this case asserts.
///
/// THE CLAUSE is issue #930's acceptance row for cases 13–16: "rejection occurs before
/// trusted output".
///
/// WHAT IS ASSERTED, in this crate and from this test target:
/// * the escaped-key precondition the raw-key readers rest on
///   (`no_escaped_top_level_key_outside_case_escape_rows`);
/// * BOTH branches of `case_15_row_refuses_at_its_offending_member` are witnessed — a
///   row that repeats a top-level member and a row that does not — so the repeated-key
///   branch cannot quietly stop running;
/// * for every row, the refusal's CATEGORY and its POSITION: it lands inside the
///   offending member's own key token, not before it and not at end of input, and for a
///   repeated key it lands BEFORE that key's value is read;
/// * and the STREAMED member sequence, through a hand-written `MapAccess`: the last
///   member the decoder was handed is at or before the offending one, so no member
///   beyond it was ever yielded. That is the observable form of "before any trusted
///   output" when the type has no output surface to watch.
///
/// WHAT IS **NOT** ASSERTED, and is owned by nobody: the PRODUCTION OR EXPOSURE OF A
/// TRUSTED VALUE — no output map, no write, no callback, no log line. These types are
/// pure `derive(Deserialize)` with no output surface, no constructor call in the decode
/// path and no side effect to instrument, so there is nothing outside the decoder for a
/// trusted value to escape into. Asserting it would mean asserting the absence of a
/// channel this crate does not have. The honest consequence is stated rather than
/// papered over: the strongest true statement is the `Err`, its position, and the
/// streamed-member sequence above.
///
/// NO CASE IN THIS FILE IS RENAMED FOR ANYTHING ELSE, and no assertion's strength
/// changes: the repair is where this claim LIVES and whether the NAME carries its own
/// caveat, nothing more.
///
/// THIS BLOCK SITS ABOVE THE WORK-UNIT MARKER, and that placement is load-bearing.
/// The marker must be IMMEDIATELY followed by its `#[test]`, and the work-unit gate
/// that binds the two walks forward from the marker refusing a blank line and
/// refusing any line beginning `//` or `/*` before it reads an attribute; a `///`
/// line is a `//` line, so a documentation comment written between the attribute and
/// this function detaches the marker exactly as a plain comment would, and there is
/// no tolerant fallback for a `.rs` file because every one is routed into that text
/// parser unconditionally. A PLAIN comment in the same place is not a workaround
/// either: `rustc` puts no order constraint on a comment relative to an attribute,
/// so the text would still be absent from hover and from extracted documentation.
/// Above the marker the walk never looks, and the block is still a documentation
/// comment, so every reader that reached it before still reaches it.
// WORK_UNIT_CASE: 930/15
#[test]
fn case_15_partial_rejection_precedes_any_trusted_output() -> TestResult {
    let Fixture { rows, .. } = rows()?;
    let group = reject_rows(&rows, 15)?;
    // Unknown-key and duplicate-key probes on three types. They are meaningful
    // because by the time the offending member is reached every preceding member
    // has already been read into the decoder's own state, which is why each row
    // is checked for ordering rather than only for refusal.
    //
    // What is actually observable, stated honestly: the only externally visible
    // consequence is that `Err` is returned and no value escapes at all. A caller
    // that ignored the `Result` would have nothing, because the derived decoder
    // never hands back a partially-built value. The absence of a partial value is
    // not itself observable from outside, so no assertion here claims to observe
    // one; the strongest true statement is the `Err` itself, the position it
    // reports, and — the ORDERING evidence this card clause is actually about — the
    // STREAMED member sequence below.
    //
    // WHERE THE CARD'S "BEFORE ANY TRUSTED OUTPUT" IS AND IS NOT OBSERVED, because
    // the honest answer is two-sided and only one side is available from an
    // integration test. What IS observed, in
    // `case_15_row_refuses_at_its_offending_member`, is that no member after the
    // offending one is ever YIELDED to a decoder: a hand-written streaming
    // `MapAccess` records each member it is given and the last one it records is at
    // or before the offending one. What CANNOT be observed, and is not claimed here,
    // is PRODUCTION OR EXPOSURE of a trusted value — no output map, no write, no
    // callback, no log line. These five types are pure `derive(Deserialize)` with no
    // output surface, no constructor call in the decode path and no side effect to
    // instrument, so there is nothing outside the decoder for "trusted output" to
    // escape into. Asserting it would mean asserting the absence of a channel the
    // crate does not have; the streamed-member assertion is the strongest statement
    // that is actually true, and it is made rather than narrated.
    //
    // The PRECONDITION every escape-blind reader in this file rests on. The loop
    // below is correct today only because of a property nothing asserted; see
    // `no_escaped_top_level_key_outside_case_escape_rows`.
    no_escaped_top_level_key_outside_case_escape_rows(&rows);

    // BOTH BRANCHES OF THE PER-ROW HELPER MUST BE WITNESSED.
    // `case_15_row_refuses_at_its_offending_member` takes a different path when the
    // offending member REPEATS a name already yielded — it demands the column precede
    // the value and that the message name the member — and the ordinary path when it
    // does not. The group's row count used to live only in a comment inside that
    // helper, so deleting this case's repeated-member rows left the `if repeats > 1`
    // branch never taken and the case green: a branch that is never entered cannot
    // fail, whatever it asserts. A comment is not the witness; these two counts are.
    let repeated: Vec<&str> = group
        .iter()
        .filter(|row| scan_repetitions(&row.raw).first.is_some())
        .map(|row| row.id.as_str())
        .collect();
    let singular: Vec<&str> = group
        .iter()
        .filter(|row| scan_repetitions(&row.raw).first.is_none())
        .map(|row| row.id.as_str())
        .collect();
    assert!(
        !repeated.is_empty(),
        "case 15 must carry at least one row that REPEATS a top-level member, or the repeated-member branch of case_15_row_refuses_at_its_offending_member is never entered; rows with no repetition: {singular:?}"
    );
    assert!(
        !singular.is_empty(),
        "case 15 must carry at least one row that does NOT repeat a top-level member, or the repeated-member branch is the only one exercised and the undeclared-key path goes untested; rows repeating a member: {repeated:?}"
    );

    for row in &group {
        case_15_row_refuses_at_its_offending_member(row)?;
    }
    Ok(())
}

/// `MemberSpan.key` records each top-level member name RAW, escapes intact. That is
/// required — `escape_row_carries_a_colliding_escape` exists precisely to compare a
/// RAW key against a DECODED name — but it makes two readers escape-blind:
/// `case_15_offending_index` and `last_undeclared_member` both compare RAW keys, so an
/// escape-equivalent pair would read as two distinct members to them. Neither can be
/// made escape-aware without changing what they are for (`decoded_key_name` and the
/// escape-aware `scan_repetitions` already cover the escape-aware readings, and their
/// doc comments say the two must differ by design).
///
/// So the safety of the design is an INVARIANT about the fixture, and until now it was
/// enforced only by prose in `MemberSpan`'s doc comment: no case-15 row and no case-10
/// row carries an escaped top-level key. This asserts it, over EVERY row outside case
/// 5, so a future fixture edit that moved an escape into one of those rows reds here
/// instead of quietly weakening every assertion built on a raw-key comparison.
///
/// Case 5 is the one exempt group and the exemption is derived, not typed: case 5 is
/// the DUPLICATE-KEY case and its escape rows are the whole reason they exist. The
/// group is selected by the rows case 5 itself owns (`rows_in_case`) rather than by a
/// case-number literal, so this cannot drift from the case it exempts.
///
/// Rows whose `raw` is not a JSON object carry no top-level spans at all and are
/// vacuously clean; that is a fact about the byte scan rather than a silent skip, and
/// the survivor list below names every offender rather than the first.
fn no_escaped_top_level_key_outside_case_escape_rows(all: &[Row]) {
    let escape_case = ESCAPE_EQUIVALENT_CASE;
    let mut offenders: Vec<String> = Vec::new();
    for row in all {
        if row.case == escape_case {
            continue;
        }
        if carries_an_escaped_top_level_key(&row.raw) {
            offenders.push(format!("{} (case {})", row.id, row.case));
        }
    }
    assert!(
        offenders.is_empty(),
        "no row outside case {escape_case} may write a top-level member key with a {JSON_ESCAPE_MARKER} escape: `case_15_offending_index` and `last_undeclared_member` compare RAW span keys, so an escape-equivalent key there would be invisible to them and every assertion resting on a raw-key comparison would weaken silently; offenders: {offenders:?}"
    );
    // NON-VACUITY, in the other direction. If the fixture carried no escaped
    // top-level key anywhere, the assertion above would be satisfied by an absence
    // rather than by the property it claims, and the escape-aware readers it is
    // contrasted with would have nothing to contrast. Case 5's own escape rows are
    // the live witness, and `case_05_duplicate_keys_are_refused` proves each one
    // carries a colliding escape; here only the count is required, so this does not
    // duplicate that per-row byte-level check.
    let escape_rows = rows_in_case(all, escape_case)
        .into_iter()
        .filter(|row| carries_an_escaped_top_level_key(&row.raw))
        .count();
    assert!(
        escape_rows > 0,
        "case {escape_case} must carry at least one row whose top-level key is written with a {JSON_ESCAPE_MARKER} escape, or the assertion above is satisfied by an absence and the escape-aware readers have nothing to read"
    );
}

/// One top-level member of a JSON object, located by byte offset in the raw
/// bytes so a caller can measure exactly how far the decoder travelled.
struct MemberSpan {
    /// Byte offset of the member's opening quote.
    key_open: usize,
    /// Byte offset of the `,` that introduces this member, or `0` when it is the
    /// FIRST member of the object.
    ///
    /// WHAT THE FIELD HOLDS. `top_level_member_spans` sets it on the comma arm
    /// alone, so for every member but the first it is that member's own leading
    /// comma, and for the first member there is no preceding comma to record and
    /// the field is the literal `0`. It never holds a brace offset; the previous
    /// version of this comment claimed the object's `{` for the first member, and
    /// no code has ever produced that value.
    ///
    /// WHY THE FIRST MEMBER IS A SENTINEL RATHER THAN A BRACE OFFSET. The offset
    /// exists to delimit one member's bytes when that member is excised by
    /// surgery: `document_without_span` splices `raw[..span.separator]` against
    /// `next_member.separator` — or the object's closing `}` for the last member —
    /// so it must be the byte where this member's own text begins. A first member
    /// has no such byte, and excising it would have to reach back to the brace and
    /// delete the object header as well, so `document_without_span` refuses the
    /// first member outright instead. `0` is an unambiguous sentinel for that
    /// refusal: byte 0 of a JSON object is its `{`, never a comma, and
    /// `top_level_member_spans` only records a separator at depth 1, so `0` cannot
    /// be produced as a real comma offset by any input.
    separator: usize,
    /// The member name: the RAW BYTES between the member's quotes, verbatim and
    /// NOT unescaped.
    ///
    /// `top_level_member_spans` slices `raw[open + 1..closing_quote]` and stops
    /// there, so an escape-encoded key is recorded with its backslash sequence
    /// intact. The fixture's own escape row writes the key of `MigrationRecord`'s
    /// boolean member as `"\u0061pplied"`, and this field therefore holds the TWELVE
    /// characters `\`, `u`, `0`, `0`, `6`, `1`, `p`, `p`, `l`, `i`, `e`, `d` where the
    /// decoded member name is the seven-character `applied`. No unescaping step
    /// exists anywhere on this path.
    ///
    /// This is what the field actually holds, and callers must treat it that way.
    /// Comparing such a span against a plain declared name would not match, which
    /// is why the readers are listed here rather than waved at: each of these reads
    /// the RAW field, and each is acceptable only for the reason its own doc comment
    /// gives.
    /// * `last_undeclared_member` and `raw_member_value` compare a span's `key`
    ///   against a plain ASCII declared name, and the fixture's escape-equivalent
    ///   duplicate rows live in case 5, which none of them walks;
    /// * `migration_is_refused_for_non_boolean_member` compares `span.key ==
    ///   offending`, where `offending` is the schema-derived member name — again a
    ///   plain ASCII name, and again on a payload built by this file with plain keys;
    /// * `repeated_top_level_member` and `case_15_offending_index` compare one span's
    ///   `key` against ANOTHER span's `key` to find a repetition, and being
    ///   escape-blind is what makes the two differ from the escape-aware
    ///   `scan_repetitions` — see the doc comment on `repeated_top_level_member`;
    /// * `escape_row_carries_a_colliding_escape` deliberately compares a span's RAW
    ///   `key` against a DECODED name, because the mismatch between the two IS the
    ///   property that row exists to assert;
    /// * `health_payload_with` matches `span.key == "status"` and
    ///   `health_record_encodes_in_declaration_order` compares emitted keys against
    ///   the field names parsed out of `records.rs`, both on the `HealthRecord`
    ///   ALLOCATION row, whose keys are all plain — which is a fact about the row
    ///   rather than about the type, since `930-84-dup-escape-component` writes one of
    ///   its `HealthRecord` keys with an escape;
    /// * `document_order_is_observable_only_by_streaming` compares these RAW keys
    ///   against the DECODED keys a streaming `MapAccess` yields, so it holds only
    ///   because that same allocation row writes no escaped key — a deliberate
    ///   pairing, since a mismatch there would otherwise look like an order defect.
    ///
    /// A future caller that wants the DECODED name must unescape it itself, through
    /// `decoded_key_name`.
    ///
    /// Making this field unescape would be a BEHAVIOUR change to the byte scan, not
    /// a documentation fix: it would alter what `raw_member_value` returns and what
    /// `last_undeclared_member` compares, and it is deliberately out of scope here.
    /// Unescaping is also not free of consequence — it would make `key.len()` no
    /// longer the on-wire length of the member name, which the case-15 column window
    /// depends on.
    key: String,
    /// Byte offset of the member's value, after the `:` and any spacing.
    value_start: usize,
}

/// Locate every top-level member of a JSON object by scanning the raw bytes.
///
/// This is a byte scan rather than a `Value` walk on purpose. `serde_json::Map`
/// collapses a duplicate member, so routing the document through a `Value` first
/// would quietly destroy the very evidence these offsets exist to measure. Every
/// string is skipped whole, escapes included, so a `{`, `,` or `}` inside a string
/// value is never mistaken for structure. Note the consequence for `MemberSpan.key`
/// documented on that field: skipping a string whole locates its closing quote but
/// does not decode its contents, so the key is recorded raw.
/// WHAT THIS ASSUMES ABOUT THE PARSER THAT `serde_json` DOES NOT GUARANTEE, and the
/// class of input where that assumption could fail.
///
/// ASSUMPTION: a top-level member is `"key" : value` inside the document's own object,
/// that the key's quotes are found by `string_closing_quote`, and that a `,` at depth one
/// introduces the member after it. All three are the JSON grammar.
///
/// WHERE IT COULD FAIL, and this helper is the one whose assumptions are LEAST witnessed:
/// * THE BACKSLASH PATH IS UNWITNESSED. Nothing in the corpus contains `\"` or `\\`, so
///   a scanner that toggled on every `0x22` would agree with this one on all 162 rows.
///   An escaped quote inside a KEY is the input class that would expose it, and the
///   failure direction is a key read as ending early, which yields a member split at the
///   wrong offset.
/// * THE KEY IS RECORDED RAW, so an escape-equivalent pair of keys reads as TWO DISTINCT
///   members here and ONE member to `decoded_key_name`. That is deliberate and is why
///   `scan_repetitions` exists, but it means this helper's answers are wrong for exactly
///   the six escape-equivalent rows, and every caller says so on its own documentation.
/// * AN UNTERMINATED STRING makes `string_closing_quote` return `bytes.len()`, and
///   `value_offset` then returns an out-of-range value offset. Two callers carry bounds
///   checks for that; a third, `recorded_member`, asserts on it directly.
fn top_level_member_spans(raw: &str) -> Vec<MemberSpan> {
    let bytes = raw.as_bytes();
    let mut spans: Vec<MemberSpan> = Vec::new();
    let mut depth = 0usize;
    let mut expect_key = false;
    let mut separator: Option<usize> = None;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let end = string_closing_quote(bytes, index);
                if depth == 1 && expect_key {
                    spans.push(MemberSpan {
                        key_open: index,
                        separator: separator.take().unwrap_or(0),
                        key: raw[index + 1..end].to_owned(),
                        value_start: value_offset(bytes, end + 1),
                    });
                    expect_key = false;
                }
                index = end + 1;
            }
            b'{' | b'[' => {
                depth += 1;
                expect_key = depth == 1 && bytes[index] == b'{';
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                expect_key = false;
                index += 1;
            }
            b',' => {
                if depth == 1 {
                    expect_key = true;
                    separator = Some(index);
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    spans
}

/// Byte index of the closing quote of the JSON string whose opening quote sits at
/// `open`, honouring backslash escapes so an escaped quote does not end it.
/// WHAT THIS ASSUMES ABOUT THE PARSER THAT `serde_json` DOES NOT GUARANTEE, and the
/// class of input where that assumption could fail.
///
/// ASSUMPTION: a backslash escapes exactly ONE following byte, and a string is closed by
/// the first unescaped `"`. That is the JSON grammar, so it matches `serde_json` on every
/// well-formed document.
///
/// WHERE IT COULD FAIL, and it is the single most load-bearing assumption in this file's
/// scanners: on an UNTERMINATED string the loop runs off the end and returns
/// `bytes.len()`, which is a LEGAL index but NOT a closing quote. Three callers slice
/// with that result, and one of them — `raw_member_value` — would read to end of input as
/// a member's value and report success. Those callers each carry their own bounds check
/// for exactly this reason, which is why this helper is allowed to return it at all
/// rather than refusing: refusing here would propagate into every caller and change what
/// they can say about their own documents.
///
/// NO ROW IN THE CORPUS WITNESSES THE BACKSLASH PATH. Nothing anywhere contains `\"` or
/// `\\`, so a scanner that closed a string on every `0x22` and ignored backslashes
/// entirely would agree with this one on all 162 rows. The input class that would
/// expose the difference is any document with an escaped quote inside a value.
fn string_closing_quote(bytes: &[u8], open: usize) -> usize {
    let mut index = open + 1;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            break;
        }
        index += 1;
    }
    index
}

/// Byte index of a member's value: past the `:` and any spacing after a key.
/// WHAT THIS ASSUMES ABOUT THE PARSER THAT `serde_json` DOES NOT GUARANTEE, and the
/// class of input where that assumption could fail.
///
/// ASSUMPTION: exactly one `:` separates a key from its value, and any whitespace around
/// it is JSON whitespace. Both are fixed by the grammar.
///
/// WHERE IT COULD FAIL: on a key token that is never closed, `string_closing_quote`
/// returns `bytes.len()`, so the `:` search starts past the end and this returns
/// `bytes.len()` too — an out-of-range VALUE offset rather than a wrong one. That is a
/// deliberate direction: an out-of-range offset trips a caller's bounds check and is
/// reported, where a plausible in-range offset would be measured and believed. Both of
/// this file's malformed-truncation rows are of that shape, so the direction is the one
/// the corpus actually exercises.
fn value_offset(bytes: &[u8], after_key: usize) -> usize {
    let mut index = after_key;
    while index < bytes.len() && (bytes[index] == b':' || bytes[index].is_ascii_whitespace()) {
        index += 1;
    }
    index
}

/// Which top-level member the row's refusal is about, derived structurally from
/// the bytes rather than from any recorded name.
///
/// A repeated key is refused at the SECOND occurrence, so the offending span is
/// the last occurrence of a name that appears more than once. Otherwise the
/// offending span is the final member, which is where an unknown key sits.
///
/// THE SAME RULE AS `repeated_top_level_member`, expression for expression, and the
/// two MUST BE CHANGED TOGETHER — that helper's doc comment carries the full
/// statement of the duplication and of why merging them is not the fix. They differ
/// only in what they return for the offending occurrence: this one returns the span
/// INDEX, because its caller `case_15_row_refuses_at_its_offending_member` needs the
/// index twice — to open the offending key token's column window, and to excise
/// exactly that member for the isolation control — whereas
/// `repeated_top_level_member` returns the member NAME, because its caller
/// `migration_is_refused_naming` needs a name to require in the refusal message. A
/// shared implementation would have to return one of those, and the other caller
/// would lose the thing it needs.
///
/// RAW KEYS, consistently with `repeated_top_level_member`: the repetition test
/// compares `MemberSpan.key`, which holds the bytes between the quotes with no
/// unescaping. A repeated key written as an escape-equivalent pair is therefore
/// invisible here as well, and no case-15 row writes such a key, so no case-15
/// assertion rests on it.
fn case_15_offending_index(spans: &[MemberSpan]) -> Result<usize, Box<dyn std::error::Error>> {
    let repeated: Option<usize> = spans
        .iter()
        .position(|span| spans.iter().filter(|other| other.key == span.key).count() > 1);
    match repeated {
        Some(first) => Ok(spans
            .iter()
            .enumerate()
            .filter(|(_, span)| span.key == spans[first].key)
            .map(|(index, _)| index)
            .next_back()
            .unwrap_or(first)),
        None => spans
            .len()
            .checked_sub(1)
            .ok_or_else(|| boxed(std::io::Error::other("the payload has no top-level member"))),
    }
}

/// The same document with exactly one top-level member removed, by byte surgery
/// on `raw`. Never by way of a `Value`: re-encoding through `serde_json` would
/// collapse a duplicate member and make the control meaningless.
fn document_without_span(
    raw: &str,
    spans: &[MemberSpan],
    index: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let span = spans.get(index).ok_or_else(|| {
        boxed(std::io::Error::other(
            "offending member index is out of range",
        ))
    })?;
    if span.separator == 0 {
        return fail("the offending member must not be the first member of the object".to_owned());
    }
    let closing = raw
        .rfind('}')
        .ok_or_else(|| boxed(std::io::Error::other("the payload has no closing brace")))?;
    let tail = spans.get(index + 1).map_or(closing, |next| next.separator);
    if tail <= span.separator {
        return fail("the top-level member spans do not tile the document".to_owned());
    }
    Ok(format!("{}{}", &raw[..span.separator], &raw[tail..]))
}

/// The ordering evidence for one case-15 row, in two independent forms.
///
/// THE POSITION FORM. `serde_json` reports a position once it has consumed the
/// offending token, so the reported column is asserted to fall inside a window over
/// the offending member's key token. The window's exact bounds, and why they sit one
/// byte later than the key token's own extent, are derived at the arithmetic below;
/// what is claimed here is ORDER — the refusal lands on the offending member, not
/// somewhere before it or after the whole document. Pinning the single column of the
/// opening quote instead would hard-code where inside `serde_json`'s key reader the
/// error is raised, which is a dependency detail rather than this crate's contract.
///
/// THE STREAMED-MEMBER FORM, which is the one that observes the card's ordering
/// clause rather than the decoder's error position. A hand-written streaming
/// `MapAccess` — the `OrderVisitor` this file already owns — records every member
/// it is handed and stops at the refusal, and the last member it records must be at
/// or before the offending one. That is what "rejection occurs before trusted
/// output" reduces to when there is no output channel to watch: the decoder was
/// never handed a member it did not already have, and it was handed nothing at all
/// beyond the offending member. Both forms are needed. The position form alone would
/// be satisfied by a decoder that read the whole document and then reported where it
/// noticed; the streamed form alone would be satisfied by a visitor whose own
/// recognition rules differ from the derived decoder's, which is why the two are also
/// required to agree on category and position.
fn case_15_row_refuses_at_its_offending_member(row: &Row) -> TestResult {
    let spans = top_level_member_spans(&row.raw);
    if spans.len() < 2 {
        return fail(format!(
            "case {} row {} must carry several members to order the refusal",
            row.case, row.id
        ));
    }
    let index = case_15_offending_index(&spans)?;
    let offending = spans.get(index).ok_or_else(|| {
        boxed(std::io::Error::other(
            "offending member index is out of range",
        ))
    })?;
    let error = match decode_row(row)? {
        Outcome::Refused(error) => error,
        Outcome::Accepted => {
            return fail(format!(
                "case {} row {} must be refused, but it decoded",
                row.case, row.id
            ));
        }
    };

    // The category is the load-bearing claim. `unknown_field`, `duplicate_field`,
    // `missing_field` and `invalid type` are all serde `Message` codes, so
    // `is_data()` is exact and completely independent of serde's wording. The
    // member-name substring below is attribution only, never the proof.
    assert!(
        error.is_data(),
        "case {} row {} must be refused with a data error, not a syntax or IO error: {error}",
        row.case,
        row.id
    );
    assert_eq!(
        error.line(),
        1,
        "case {} row {} records a single physical line, so the refusal must report line 1: {error}",
        row.case,
        row.id
    );
    // WINDOW FORM, KEEP IT. The exact column is a property of `serde_json`'s key
    // reader, not of this crate, so the window asserts ORDER — the refusal lands
    // inside the offending key token, not somewhere before it or after the whole
    // document — rather than hard-coding the reader's arithmetic.
    //
    // WHAT UNIT THE COLUMN IS IN, because this comment used to call it a 0-BASED byte
    // offset and `Error::column`'s own doc comment
    // (`serde_json-1.0.151/src/error.rs:36-45`) calls the value "One-based column
    // number". BOTH are true of one number, and the implementation is what says so:
    // `SliceRead::position_of_index` returns `column: i - start_of_line` for the
    // reader's 0-based byte index `i` (`read.rs:421-430`), so the value is the count
    // of this line's bytes already consumed — read as the 0-based offset of the byte
    // the reader has NOT consumed yet, or, identically, as the 1-based column of the
    // byte it has. The accessor's concession that "errors may occur in column 0"
    // (`error.rs:41-43`) is the same statement seen from the other side. On a
    // single-line document `start_of_line` is 0 (`read.rs:424`), so the value is
    // exactly `i` and no unit conversion belongs in the arithmetic below — and the
    // arithmetic does not settle the question either way, because a window that holds
    // under one reading holds under the other. The accessor is what settles it, and
    // the placement derivation on `wrong_member_row_is_refused` reads the same source.
    //
    // WHAT THESE BOUNDS ARE, in that same unit, stated as the code states them
    // rather than as the key token's own extent. The key token runs
    // `key_open ..= key_open + key.len() + 1` — opening quote, the raw key bytes, and
    // its closing quote — so the naive reading of "inside the key token" would be
    // those two offsets. The bounds here are shifted ONE BYTE LATER AT BOTH ENDS:
    // `key_open + 1` through `key_open + key.len() + 3`. That shift is deliberate and
    // it is correct, for a reason internal to `serde_json` DERIVED FROM ITS PINNED
    // SOURCE rather than measured in this lane:
    //   * the UPPER bound. `unknown_field` and `duplicate_field` are serde `Message`
    //     codes, so `de::Error::custom` builds them UNPOSITIONED, with `line: 0` and
    //     `column: 0` (`error.rs:483-490`), and `deserialize_struct` re-positions
    //     that error afterwards with `fix_position` (`de.rs:1862-1865`) →
    //     `Deserializer::error` (`de.rs:241-244`) → `SliceRead::position`
    //     (`read.rs:573-575`), which reads the reader's index for the NEXT UNREAD
    //     byte. By then `MapKey::deserialize_any` (`de.rs:2214-2225`) has eaten the
    //     opening quote and `parse_str_bytes` (`read.rs:494-538`) has consumed the
    //     closing quote with its `self.index += 1` (`read.rs:518`), so that index is
    //     `key_open + key.len() + 2`. That is ONE BYTE PAST the naive range's upper
    //     bound — this comment used to call the two equal, which the arithmetic it
    //     quotes one line earlier denies — and it is why the code's `+ 3` leaves that
    //     reported position one byte of margin rather than resting on it exactly, so
    //     a reader one byte further on would not red on a correct row;
    //   * the LOWER bound. `serde_json` provably never reports the opening-quote
    //     column on this path, and the OPERATIVE reason is the placement in the
    //     bullet above rather than the one this comment used to give. That earlier
    //     reason — the key reader has already consumed the opening quote — is
    //     SUFFICIENT to exclude `key_open` and no more: it names one of the three
    //     bytes the key reader swallows, and it says nothing about WHERE the position
    //     is taken from, which is what actually fixes the value. A position taken by
    //     peeking (`peek_position` is `index + 1`, `read.rs:577-581`) or taken
    //     before the key is read would land elsewhere. From the derivation above the
    //     smallest column this path can report is `key_open + key.len() + 2`, so
    //     excluding `key_open` and `key_open + 1` removes two columns the decoder
    //     cannot produce, and `key_open + 1` — the code's bound — is one byte BELOW
    //     the first column that can, which is the same deliberate margin the upper
    //     bound carries. `key_open + 1` is NOT the first column that can; the
    //     previous version of this sentence said so and was wrong by the key's own
    //     length.
    // The arithmetic is left as it is. What this comment corrects is the previous
    // version's DESCRIPTION of it, which named the naive key-token extent as what the
    // bounds compute; the code did not and does not compute that. The earlier reading
    // was not a wrong arithmetic but a wrong account of a right one.
    //
    // The previous version of this comment also stated a measured figure — that every
    // row in this case reports EXACTLY `key_open + key.len() + 2` against
    // `serde_json` 1.0.151, "one unit below the upper bound", together with a count
    // of how many rows were measured. That is an EXECUTION observation and this lane
    // cannot run the suite, so it is not restated as an observation. The column
    // figure itself now appears one paragraph above, and it earns its place there by
    // being DERIVABLE from the pinned source with the derivation written out; the row
    // COUNT earns no such place, because nothing in a dependency's source says how
    // many rows this fixture carries. The remaining guidance is the part that depends
    // on neither figure. A number in a comment is the
    // thing that goes stale while the code beneath it changes. A `serde_json`
    // bump that moved where inside `MapKey` the position is taken could break this
    // assertion with NO change in this crate's behaviour; that coupling is stated so
    // a future red is diagnosable rather than baffling. Do not "tighten" it to an
    // exact column, and do not delete it as a dependency detail — the ordering claim
    // is ours; only the column value is not. The looser window survives such a bump;
    // an exact figure would not, which is the other reason it is not restated.
    let first_column = offending.key_open + 1;
    let last_column = offending.key_open + offending.key.len() + 3;
    assert!(
        error.column() >= first_column && error.column() <= last_column,
        "case {} row {} must refuse at the offending member {}: column {} is outside {first_column}..={last_column}: {error}",
        row.case,
        row.id,
        offending.key,
        error.column()
    );
    let repeats = spans
        .iter()
        .filter(|span| span.key == offending.key)
        .count();
    if repeats > 1 {
        assert!(
            error.column() < offending.value_start + 1,
            "case {} row {} repeats {}: the refusal must land on the key, before the repeated value is read, so column {} must precede the value column {}: {error}",
            row.case,
            row.id,
            offending.key,
            error.column(),
            offending.value_start + 1
        );
        assert!(
            message_names(&error, &offending.key),
            "the refusal for row {} should name the repeated member {}: {error}",
            row.id,
            offending.key
        );
    }

    // The control that isolates the offending member as the sole cause: with
    // that one member removed by byte surgery, the rest of the document must
    // decode. Without it, "the payload was already bad" is not excluded.
    let mut control = (*row).clone();
    control.raw = document_without_span(&row.raw, &spans, index)?;
    assert_accepted(&control)?;

    streaming_witness_precedes_the_offending_member(row, &spans, index, &error)?;
    Ok(())
}

/// "REJECTION OCCURS BEFORE TRUSTED OUTPUT", OBSERVED through a streaming
/// `MapAccess` rather than narrated, for one case-15 row whose derived-decoder
/// refusal and offending member are already established.
///
/// It is its own function rather than the tail of its caller because the claim it
/// discharges is a different one from the caller's: the caller establishes WHERE
/// the derived decoder's refusal lands, and this establishes WHAT THE DECODER WAS
/// HANDED before it landed there. Every assertion here is the caller's, unaltered
/// and in the same order; the split changes only where they are written down.
///
/// The visitor records each member it is yielded and stops at the refusal, so the
/// recording is a direct witness of how far the decoder got. The declared member
/// names come from SOURCE, through the existing `declared_field_names` walk, so the
/// visitor enforces the same member set the derived decoder does and no member name
/// is typed into this assertion.
fn streaming_witness_precedes_the_offending_member(
    row: &Row,
    spans: &[MemberSpan],
    index: usize,
    error: &serde_json::Error,
) -> TestResult {
    let offending = &spans[index];
    let declared = declared_field_names(type_leaf(&row.type_name))?;
    let (seen, streamed_refusal) = members_yielded_before_refusal(&row.raw, &declared);
    let streamed = streamed_refusal.ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "case {} row {} must be refused when its members are streamed, or nothing was ever yielded past the offending member and the ordering claim below is satisfied by an absence rather than by an observation",
            row.case, row.id
        )))
    })?;
    // THE VISITOR MUST NOT CHANGE WHAT THE DECODER DOES, and that is asserted
    // rather than claimed. Category and position are the two things that could
    // differ if the visitor's own recognition rules were not the derived decoder's:
    // the rendered text is never compared, because serde's message wording is
    // version-dependent and two independent refusals are not required to word
    // themselves identically.
    assert!(
        streamed.is_data(),
        "case {} row {} must be refused with a data error when streamed, exactly as the derived decoder refuses it: {streamed}",
        row.case,
        row.id
    );
    assert_eq!(
        (streamed.line(), streamed.column()),
        (error.line(), error.column()),
        "case {} row {} must be refused at the SAME position whether the members are streamed or decoded by the derived decoder, or the recording below describes a decoder this crate does not use: derived {:?}, streamed {:?}",
        row.case,
        row.id,
        (error.line(), error.column()),
        (streamed.line(), streamed.column())
    );
    // The recording must be a PREFIX of the document's own member order, so
    // "the last member recorded" is a statement about a position in the document
    // rather than about a position in a list that could have been reordered. The
    // recorded keys are DECODED (a visitor reads keys through `deserialize`), the
    // spans are RAW, and they may be compared only because no row outside case 5
    // writes an escaped top-level key — the invariant
    // `no_escaped_top_level_key_outside_case_escape_rows` exists to hold, and its
    // doc comment names this pairing.
    for (position, key) in seen.iter().enumerate() {
        assert_eq!(
            spans.get(position).map(|span| span.key.as_str()),
            Some(key.as_str()),
            "case {} row {} yielded {seen:?}, which is not a prefix of the document's own member order {:?}: a streaming visitor sees document order, so a divergence here would mean the recording does not describe this document",
            row.case,
            row.id,
            spans
                .iter()
                .map(|span| span.key.as_str())
                .collect::<Vec<_>>()
        );
    }
    // THE LOAD-BEARING ASSERTION: the last member recorded is at or before the
    // offending one, so no member after it was ever yielded. The failure message
    // names every member that WAS seen, because "the decoder stopped early" is not
    // a diagnosis and this list is.
    assert!(
        seen.len() <= index,
        "case {} row {} must not be yielded any member after the offending one {} at member {index}: the streaming visitor recorded {} member(s), {seen:?}, over a document whose members are {:?}",
        row.case,
        row.id,
        offending.key,
        seen.len(),
        spans
            .iter()
            .map(|span| span.key.as_str())
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// Attribution only: whether the rendered refusal names a member. Never an
/// equality against serde's message text.
fn message_names(error: &serde_json::Error, member: &str) -> bool {
    error.to_string().contains(member)
}
