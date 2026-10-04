//! #758 typed sandboxed execution proof matrix (lane W4).
//!
//! Twenty-six marker tests, one substantive test per
//! `// WORK_UNIT_CASE: 758/<n>`, over the REAL Wasmtime component engine and
//! the read-only #760 neutral contract. No mock engine, no `todo!`, no
//! ignored/empty/count-only case, no substitute for the six-world run.
//!
//! Evidence classes used here:
//!
//! - **real engine execution**: real component bytes are preflighted, hashed
//!   and compiled by the configured provider
//!   (`WasmtimeComponentEngine::new_for_admitted_limits`), the component type
//!   is inspected, the component is instantiated on the empty linker, and the
//!   guest function is actually called. Hostile components below are built in
//!   this file as component-model text so the denial being proved is the one
//!   the real engine reports.
//! - **real contract validation**: `check_governed_admission`,
//!   `preflight_bytes`, `read_bounded_artifact`,
//!   `require_absolute_artifact_path`, `ModuleContractKit` and
//!   `ModuleTestCapsule` run for real; those guarantees are defined to deny
//!   BEFORE any engine, filesystem or provider work, so proving them needs no
//!   engine.
//! - **source guard**: only where the guarantee is a property of an owner
//!   file's text that no public API can observe. Case 26 is the declared
//!   whole-file source-guard case; every other case that needs one marks its
//!   own narrower guard inline at its use site (the typed leaf walkers in
//!   case 9, the "no synchronous compile-cancellation claim" in case 14, the
//!   cache-identity composition in case 22, and the rest).
//!
//! SOURCE-GUARD SWEEP (W4, 2026-10-04). Every `TYPED_EXECUTION_SOURCE`
//! text-search assertion in this file was classified, and none was deleted or
//! weakened. Each one now carries an inline note naming its verdict:
//! - **CONVERTED** — real-engine proof of the same property now exists and can
//!   fail. Some were converted by assertions this sweep ADDED (case 13's
//!   fuel-metering pair, case 14's stage-code rendering, case 22's isolated
//!   allow-list leg, case 21's and case 23's store-scoped observation
//!   equalities); the rest were already carried by executed assertions in the
//!   same test, and the note names which one.
//! - **NOT CONVERTIBLE** — no executed alternative exists from an external test
//!   target, with the reason and the production lines recorded inline:
//!   doc-comment prose, whole-file or whole-manifest ABSENCE claims, a negative
//!   global scan for cross-invocation state, a private struct's per-slot
//!   digests, the private `EpochDriver` teardown ordering, and the whole typed
//!   DOMAIN request/result lane, whose `TypedDomainRequest` payloads are
//!   crate-private generated bindgen types.
//! - **UNAUTHORABLE FIXTURE** — case 15's `memory_grow_failed` post-approval
//!   growth-failure path, which the pinned engine makes unreachable from any
//!   authored component. Escalated, not weakened.
//!
//! The report for this sweep is
//! `control-20260923-impl/v2/issues/758/SOURCE-GUARD-SWEEP-W4-20261004.md`.
//!
//! INTEGRATION-TEST BOUNDARY: the capsule-domain entry
//! `execute_capsule_domain_experimental` takes a `&TypedDomainRequest`, whose
//! variant payloads are crate-private generated bindgen types
//! (`crate::typed_bindings::*`; `mod typed_bindings;` is private in
//! `src/lib.rs`), so this external test cannot construct that request. The
//! in-crate `six_world_capsule_drive::every_frozen_world_executes_its_real_domain_export_through_the_neutral_capsule`
//! test constructs the requests and drives both domain entries for all six
//! worlds through the real engine. Case 3 below separately binds each frozen
//! world's checked-in fixture to its neutral kit/capsule and executes that
//! fixture's real `describe` export in this integration-test binary.

use std::path::Path;

use eliot_wasm_host::{
    CAPABILITY_INTRODUCTION_REQUIRED, CliError, ExecutionMode, GovernedAdmission, LEGACY_EXPORT,
    LEGACY_WORLD, MAX_ARTIFACT_BYTES, PreflightError, TYPED_PACKAGE_ID, TYPED_WIT_VERSION,
    TypedDescriptor, TypedExecutionError, TypedReceipt, TypedStage, TypedWorld,
    check_governed_admission, default_experimental_limits, execute_describe_experimental,
    execute_governed_refusal, parse_args, preflight_bytes, read_bounded_artifact,
    require_absolute_artifact_path, typed_wit_digest,
};
use eliot_wasm_runtime::capsule::{ModuleContractKit, ModuleTestCapsule};
use eliot_wasm_runtime::component_contract::{
    AbiDescriptor, ProofCeiling, TYPED_ABI_REVISION, TypedContractError, TypedWorld as NeutralWorld,
};
use eliot_wasm_runtime::{
    CancellationPolicy, CapabilityId, InvocationLimits, ProofStage, Sha256Digest,
};

// Owner files this file's source guards inspect. `include_str!` reads them at
// build time, and each guard pins an exact source string, so a guard moves when
// its owner file moves. `typed_execution.rs` and `receipt_bridge.rs` are this
// lane's own #758 edit targets; `wasmtime_provider.rs`,
// `artifact_preflight.rs`, `typed_bindings.rs`, both manifests and
// `capsule.rs` are read only here.
const TYPED_EXECUTION_SOURCE: &str = include_str!("../src/typed_execution.rs");
const TYPED_BINDINGS_SOURCE: &str = include_str!("../src/typed_bindings.rs");
const ARTIFACT_PREFLIGHT_SOURCE: &str = include_str!("../src/artifact_preflight.rs");
const WASMTIME_PROVIDER_SOURCE: &str = include_str!("../src/wasmtime_provider.rs");
const RECEIPT_BRIDGE_SOURCE: &str = include_str!("../src/receipt_bridge.rs");
const HOST_MANIFEST: &str = include_str!("../Cargo.toml");
const NEUTRAL_MANIFEST: &str =
    include_str!("../../../crates/modules/eliot-wasm-runtime/Cargo.toml");
const NEUTRAL_CAPSULES_SOURCE: &str =
    include_str!("../../../crates/modules/eliot-wasm-runtime/src/capsule.rs");

/// The instance count production stamps on every successful typed receipt.
///
/// This mirrors PRODUCTION's value and is not an independent expectation:
/// `TypedReceipt` is built with the bare field `instances: 1` at
/// `bins/eliot-wasm-host/src/typed_execution.rs:1061` (descriptor lane) and
/// `:2162` (domain lane), and production names no constant for it — the
/// `typed_execution` re-export block in `src/lib.rs:108-114` exports
/// `TypedReceipt` (whose `instances` field is the produced value, not the
/// expected one) but no `*_INSTANCES` constant, so the expectation is not
/// reachable from this integration test without a production change. This one
/// named site replaces the anonymous `1` literals that would otherwise drift
/// silently. CHANGE PRODUCTION AND THIS TOGETHER: if either
/// `src/typed_execution.rs:1061` or `:2162` stops being `instances: 1`, this
/// constant must change in the same commit.
const PRODUCTION_SUCCESS_INSTANCES: u32 = 1;

/// The exact component interface export spelling the Host requires: the
/// frozen package id plus the world's interface name.
fn typed_export_name(world: TypedWorld) -> String {
    format!("{TYPED_PACKAGE_ID}/{}", world.interface_name())
}

/// Both exact export spellings the frozen contract accepts for one world
/// (`eliot:current@0.1.0/<interface>` and `eliot:current/<interface>@0.1.0`).
/// A bare interface name proves nothing and is never one of them.
fn accepted_export_spellings(world: TypedWorld) -> [String; 2] {
    [
        format!("{TYPED_PACKAGE_ID}/{}", world.interface_name()),
        format!(
            "eliot:current/{}@{TYPED_WIT_VERSION}",
            world.interface_name()
        ),
    ]
}

/// Unwraps a fixture construction result with an explicit failure message.
fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("#758 typed fixture could not be built: {error:?}"),
    }
}

fn narrow_u32(value: usize) -> u32 {
    match u32::try_from(value) {
        Ok(narrow) => narrow,
        Err(error) => panic!("#758 typed fixture offset exceeds the core 32-bit range: {error}"),
    }
}

/// Escapes the two characters a WebAssembly text data literal must escape.
fn wat_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_component(text: &str) -> Vec<u8> {
    match wat::parse_str(text) {
        Ok(bytes) => bytes,
        Err(error) => panic!("#758 typed fixture text is not a valid component: {error}"),
    }
}

/// Checked-in fixture path. One file per `TypedWorld`, plus the other
/// checked-in fixtures the same directory carries (the hostile and
/// over-reporting ones).
fn fixture_file(name: &str) -> String {
    format!("tests/data/typed-components/{name}.wat")
}

fn load_fixture_file(name: &str) -> Vec<u8> {
    let path = fixture_file(name);
    match wat::parse_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("#758 fixture {path} must be a parseable component: {error}"),
    }
}

fn load_fixture(world: TypedWorld) -> Vec<u8> {
    load_fixture_file(world.world_name())
}

const fn neutral_world(world: TypedWorld) -> NeutralWorld {
    match world {
        TypedWorld::ContextAdmission => NeutralWorld::ContextAdmission,
        TypedWorld::ContextAssembly => NeutralWorld::ContextAssembly,
        TypedWorld::CueActivation => NeutralWorld::CueActivation,
        TypedWorld::DreamerHandler => NeutralWorld::DreamerHandler,
        TypedWorld::MemoryCurationScreen => NeutralWorld::MemoryCurationScreen,
        TypedWorld::DreamerCycle => NeutralWorld::DreamerCycle,
    }
}

/// Per-world #760 contract kit whose artifact digest and length are exactly
/// that world fixture's preflight bytes.
fn world_kit(world: TypedWorld, artifact: &[u8]) -> ModuleContractKit {
    let preflight = must(preflight_bytes(artifact));
    let neutral = neutral_world(world);
    ModuleContractKit {
        package_id: TYPED_PACKAGE_ID.to_owned(),
        world: neutral,
        abi: must(AbiDescriptor::new(
            neutral,
            format!("fixture-native-contract/{}", world.world_name()),
            "fixture-native-revision-1".to_owned(),
            typed_wit_digest(),
        )),
        artifact_digest: preflight.digest.clone(),
        artifact_len: preflight.byte_len,
        interface_digest: Sha256Digest::of_bytes(
            format!("758-interface/{}", world.world_name()).as_bytes(),
        ),
        declared_imports: Vec::new(),
        declared_exports: vec![neutral.interface_name().to_owned()],
        state_contract_digest: Sha256Digest::of_bytes(
            format!("758-state-contract/{}", world.world_name()).as_bytes(),
        ),
        proof_ceiling: ProofCeiling::CandidateOnly,
        governed: false,
    }
}

/// Per-world #760 test capsule bound to that world's kit, world and domain
/// operation, carrying the exact fixture bytes as its bounded evidence.
fn world_capsule(world: TypedWorld, kit: &ModuleContractKit, artifact: &[u8]) -> ModuleTestCapsule {
    let neutral = neutral_world(world);
    ModuleTestCapsule {
        kit_digest: must(kit.digest()),
        component: must(CapabilityId::new(format!(
            "typed-fixture-{}",
            world.world_name()
        ))),
        world: neutral,
        operation: neutral.domain_func().to_owned(),
        stage: ProofStage::Invocation,
        fixture: artifact.to_vec(),
        expected: b"Completed".to_vec(),
        max_input_bytes: match u64::try_from(artifact.len()) {
            Ok(bytes) => bytes,
            Err(error) => panic!("#758 fixture length exceeds the capsule input bound: {error}"),
        },
        max_output_bytes: 16_384,
        max_work: 50_000,
        oracle: format!("fixture-oracle/{}", world.world_name()),
    }
}

/// A descriptor that satisfies every identity check the Host makes, so the
/// only reason a case denies is the case under test.
///
/// This is the crate's own [`TypedDescriptor`] — the exact type
/// `execute_describe_experimental` returns — not a local copy of it. All six
/// fields are `pub` and the type derives `Clone`, so a hostile guest is
/// expressed by cloning the honest one and changing the single field that
/// lies. Building the guest text from the crate's real type keeps the fixture
/// and the validated receipt structurally identical.
fn cooperative_guest() -> TypedDescriptor {
    TypedDescriptor {
        world_name: TypedWorld::CueActivation.world_name().to_owned(),
        package_id: TYPED_PACKAGE_ID.to_owned(),
        abi_revision: TYPED_ABI_REVISION,
        native_contract: "fixture-native-contract".to_owned(),
        native_revision: "fixture-native-revision".to_owned(),
        abi_digest: typed_wit_digest().as_str().to_owned(),
    }
}

/// What the hostile guest's `describe` core function actually does. Every
/// variant keeps the exported signature exact, so the denial under test is
/// reached after the component-type preflight, never substituted by it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DescribeKind {
    Return,
    Trap,
    GrowOnePage,
}

/// Options for the hostile `cue-activation` component builder.
struct CueOptions {
    kind: DescribeKind,
    include_domain_export: bool,
    extra_core_module: bool,
    extra_core_memory: bool,
    extra_core_table: bool,
    world_len_override: Option<u32>,
    describe_decl: Option<&'static str>,
    domain_decl: Option<&'static str>,
    export_name: Option<String>,
    second_export: bool,
    ambient_import: Option<String>,
}

impl Default for CueOptions {
    fn default() -> Self {
        Self {
            kind: DescribeKind::Return,
            // The default fixture exports BOTH interface functions with the
            // exact frozen WIT signature, so it clears the component-type
            // preflight and the denial under test is reached afterwards.
            include_domain_export: true,
            extra_core_module: false,
            extra_core_memory: false,
            extra_core_table: false,
            world_len_override: None,
            describe_decl: None,
            domain_decl: None,
            export_name: None,
            second_export: false,
            ambient_import: None,
        }
    }
}

fn cooperative_cue_artifact() -> Vec<u8> {
    cue_activation_artifact(&cooperative_guest(), &CueOptions::default())
}

/// The real checked-in `dreamer-cycle` fixture: the honest world component most
/// of the negative fixtures in the same directory are derived from.
fn real_cycle_fixture() -> Vec<u8> {
    load_fixture(TypedWorld::DreamerCycle)
}

/// Default lifted `describe`: the exact generated binding signature lifted over
/// the guest's exported memory and canonical realloc.
const DEFAULT_DESCRIBE_DECL: &str = "(func $describe (type $ca-describe)\n    \
    (canon lift (core func $core-describe) (memory $memory) (realloc $realloc)))";

/// Default declared domain function. Its body is never reached by the denial
/// cases: it only has to carry the exact WIT signature.
///
/// A component-level `func` definition has no free body in the text format: the
/// pinned parser accepts only an import, an alias, or a `canon lift`
/// (`FuncKind::parse`, wast-256.0.0/src/component/func.rs:294-313, which after
/// the type use requires `parser.parens(|p| { p.parse::<kw::canon>()?; ... })`).
/// The trapping body therefore lives in the core function this export lifts,
/// and stays exactly `(unreachable)`.
const DEFAULT_DOMAIN_DECL: &str = "(func $activate (type $ca-activate)\n    \
    (canon lift (core func $core-activate) (memory $memory) (realloc $realloc)))";

/// Fixed base address, in the core module's exported linear memory, of the
/// lowered `describe` return block.
///
/// `describe` returns one `abi-descriptor` record, and a result that does not
/// fit the flat-result limit lowers to ONE indirect pointer: the pinned
/// validator sets `MAX_FLAT_FUNC_RESULTS: usize = 1`
/// (wasmparser-0.256.0 `src/validator/component_types.rs:35`, applied at `:129`
/// and at `:1276-1296`, where an overflowing result list is cleared and exactly
/// one pointer is pushed for `Abi::Lift` at `:1290-1292`), and
/// `src/validator/component.rs:1343` computes that lowered signature while
/// `:1365` refuses a lifted core signature that differs from it. Eleven flat
/// `i32` results are therefore refused there, so the core `describe` returns
/// the address of this block instead of leaving the values on the stack.
///
/// The block is eleven 4-byte slots holding exactly the eleven values that
/// record flattens to, in the field order the WIT record declares
/// (`wit/typed/descriptor.wit:28-35`): the five reported strings as
/// `(pointer, length)` pairs, plus `abi-revision`.
///
/// Occupancy of the emitted core module, and why this base is free:
/// - `[0, 16)` is reserved and never written by anything the template emits;
/// - the five `(data ...)` segments occupy `[16, realloc_offset)`, where
///   `realloc_offset` is the end of the last segment and is exactly the single
///   pointer `$realloc` hands out, so nothing is ever allocated above it;
/// - measured over every descriptor this file builds, `realloc_offset` is at
///   most 190 bytes (the longest field set is case 24's planted secret: 16
///   + 14 + 19 + 54 + 23 + 64), so a
///   block at `[1024, 1068)` clears the data segments by 834 bytes and stays
///   inside the single declared page (65536 bytes).
///
/// `cue_activation_artifact` asserts that measured invariant, so a future
/// longer descriptor fails loudly at build time instead of silently aliasing
/// the block.
const DESCRIBE_RETURN_BASE: u32 = 1024;

/// The `i32` slots of the lowered `describe` return block: the five reported
/// strings as `(pointer, length)` pairs, plus `abi-revision`.
const DESCRIBE_RETURN_SLOTS: usize = 11;

/// The flat core `describe` body: an optional prologue that trips a resource
/// ceiling, then a store of each of the descriptor's eleven canonical-ABI
/// return values into the block at [`DESCRIBE_RETURN_BASE`], and that block's
/// address as the single result. `spans` carries the `(pointer, length)` pair
/// of each reported string, already laid out in the core module's linear
/// memory.
fn describe_body(fields: &TypedDescriptor, spans: &[(u32, u32)], options: &CueOptions) -> String {
    let prologue = match options.kind {
        DescribeKind::GrowOnePage => "(drop (memory.grow (i32.const 1)))\n",
        _ => "",
    };
    let (world_ptr, world_len) = spans[0];
    let (package_ptr, package_len) = spans[1];
    let (contract_ptr, contract_len) = spans[2];
    let (revision_ptr, revision_len) = spans[3];
    let (digest_ptr, digest_len) = spans[4];
    let world_len = options.world_len_override.unwrap_or(world_len);
    if let DescribeKind::Trap = options.kind {
        return "(unreachable)".to_owned();
    }
    // The same eleven values, in the same order, that the stack form pushed:
    // each reported string as `(pointer, length)` in WIT field order, with
    // `abi-revision` third.
    let values = [
        world_ptr,
        world_len,
        package_ptr,
        package_len,
        fields.abi_revision,
        contract_ptr,
        contract_len,
        revision_ptr,
        revision_len,
        digest_ptr,
        digest_len,
    ];
    let mut body = String::new();
    for (slot, value) in values.iter().enumerate() {
        let address = DESCRIBE_RETURN_BASE + narrow_u32(slot * 4);
        body.push_str("(i32.store (i32.const ");
        body.push_str(&address.to_string());
        body.push_str(") (i32.const ");
        body.push_str(&value.to_string());
        body.push_str("))\n");
    }
    body.push_str("(i32.const ");
    body.push_str(&DESCRIBE_RETURN_BASE.to_string());
    body.push(')');
    format!("{prologue}{body}")
}
/// Builds a real component-model `cue-activation` component whose exported
/// signature is the exact frozen WIT signature of both interface functions,
/// with a parameterisable `describe` body.
///
/// The core module carries two extra core functions beside `describe`:
/// `$activate-core`, whose body is the `(unreachable)` the domain export lifts,
/// and `$partial-core`, the discriminator body the wrongly-typed `describe`
/// export of case 7 lifts. Both are lifted, so both core signatures are exactly
/// the canonical-ABI lowering of the component type they are lifted at:
/// `$ca-activate` lowers to one indirect `i32` parameter and one indirect `i32`
/// result (its request record exceeds `MAX_FLAT_FUNC_PARAMS` and its
/// `result<outcome, error>` payload does not fit one flat value), and
/// `$ca-describe-partial` lowers to one indirect `i32` result.
fn cue_activation_artifact(fields: &TypedDescriptor, options: &CueOptions) -> Vec<u8> {
    let values = [
        fields.world_name.as_str(),
        fields.package_id.as_str(),
        fields.native_contract.as_str(),
        fields.native_revision.as_str(),
        fields.abi_digest.as_str(),
    ];
    let mut offset: u32 = 16;
    let mut spans: Vec<(u32, u32)> = Vec::new();
    let mut segments: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let len = narrow_u32(value.len());
        spans.push((offset, len));
        segments.push(format!(
            "(data (i32.const {offset}) \"{}\")\n",
            wat_literal(value)
        ));
        offset += len;
    }
    let data = segments.concat();
    let results = describe_body(fields, &spans, options);
    let realloc_offset = offset;
    // The data segments and the `$realloc` pointer must both stay below the
    // fixed lowered-return block, or the descriptor bytes the lifted return
    // block points at would be overwritten. See `DESCRIBE_RETURN_BASE`.
    assert!(
        realloc_offset + narrow_u32(DESCRIBE_RETURN_SLOTS * 4) <= DESCRIBE_RETURN_BASE,
        "#758 typed fixture descriptor data would overlap the describe return block: \
         realloc_offset {realloc_offset} + {DESCRIBE_RETURN_SLOTS} slots"
    );
    let describe_decl = options
        .describe_decl
        .map_or_else(|| DEFAULT_DESCRIBE_DECL.to_owned(), str::to_owned);
    let domain_decl = options
        .domain_decl
        .map_or_else(|| DEFAULT_DOMAIN_DECL.to_owned(), str::to_owned);
    let ambient_import = options
        .ambient_import
        .as_deref()
        .map_or_else(String::new, |name| {
            // A component `func` param carries its name as a string literal
            // (`ComponentFunctionParam::parse`, wast-256.0.0/src/component/
            // types.rs:785-793, parses `name: &'a str` first); a bare
            // `(param i32)` is rejected there. The imported name and the single
            // `i32` parameter type are unchanged.
            format!("(import \"{name}\" (func $ambient (param \"value\" i32)))\n")
        });
    let extra_module = if options.extra_core_module {
        "  (core module $extra (func (export \"unused\")))\n  \
         (core instance $extra (instantiate $extra))\n"
    } else {
        ""
    };
    // A SECOND defined memory in the SAME core module. Multi-memory is
    // compiled on by default in the pinned engine (`Config::wasm_multi_memory`
    // is documented `true` by default at wasmtime-47.0.4 `src/config.rs:1186`
    // and `configured_engine` at `src/wasmtime_provider.rs:792-806` never
    // disables it), so this component is VALID and reaches instantiation; only the
    // Store's memory COUNT can refuse it. The extra memory is unreferenced and
    // unexported, so every alias, export and body in the template is unchanged:
    // the one difference between this fixture and the cooperative one is the
    // count the engine is asked to honour.
    let extra_memory = if options.extra_core_memory {
        "    (memory $extra-memory 1)\n"
    } else {
        ""
    };
    // A SECOND defined table in the SAME core module, for the table-COUNT
    // ceiling. It is the exact table-shaped twin of `extra_memory` above and
    // carries the same single-variable argument: `MAX_TYPED_TABLES = 1`
    // (`src/typed_execution.rs:58`) reaches the engine as the Store's table
    // count (`src/typed_execution.rs:1425`, read back through
    // `StoreState::tables` at `:1501-1503`), and the count is checked by
    // `StoreOpaque::bump_resource_counts`
    // (`StoreLimits` snapshots `ResourceLimiter::tables` as
    // `StoreOpaque::table_limit`, wasmtime-47.0.4 `src/runtime/store.rs:936-943`;
    // `wasmtime-environ-47.0.4/src/module.rs:566-570` counts the tables the
    // core module DEFINES, so both tables below are counted), whose `bump`
    // bails at `src/runtime/store.rs:1523` before any table is allocated. The
    // extra table is unreferenced and unexported, so every alias, export and
    // body in the template is unchanged: the one difference between this
    // fixture and the cooperative one is the count the engine is asked to
    // honour.
    // TWO tables, not one, and the reason is arithmetic rather than taste. The
    // base template declares exactly one memory at `(memory (export "memory") 1)`
    // and NO table at all, so injecting a single extra table would leave the
    // module declaring ONE table - equal to `MAX_TYPED_TABLES = 1`, and
    // `bump(&mut table_count, 1, 1, "table")` computes `1 > 1` as false, so
    // nothing would bail and the count ceiling would never be exercised. The
    // memory leg works precisely because its base declaration exists. Two
    // injected tables make the module declare 2 against a maximum of 1.
    let extra_table = if options.extra_core_table {
        "    (table $extra-table-a 1 funcref)\n    (table $extra-table-b 1 funcref)\n"
    } else {
        ""
    };
    let domain_export = if options.include_domain_export {
        "    (export \"activate\" (func $activate))\n"
    } else {
        ""
    };
    let export_name = options.export_name.as_deref().map_or_else(
        || typed_export_name(TypedWorld::CueActivation),
        str::to_owned,
    );
    let second_export = if options.second_export {
        format!(
            "  (instance $second\n    (export \"describe\" (func $describe))\n\
             {domain_export}  )\n  (export \"{TYPED_PACKAGE_ID}/screen\" (instance $second))\n"
        )
    } else {
        String::new()
    };
    let text = format!(
        r#"(component
{CUE_TYPES}{ambient_import}  (core module $guest
    (memory (export "memory") 1)
{extra_memory}{extra_table}    {data}    (func $realloc (param i32 i32 i32 i32) (result i32)
      (i32.const {realloc_offset}))
    (func $activate-core (param i32) (result i32)
      (unreachable))
    (func $partial-core (result i32)
      (i32.const 0))
    (func $describe (result i32)
      {results})
    (export "activate" (func $activate-core))
    (export "partial" (func $partial-core))
    (export "describe" (func $describe))
    (export "realloc" (func $realloc)))
  (core instance $guest (instantiate $guest))
{extra_module}  (alias core export $guest "describe" (core func $core-describe))
  (alias core export $guest "memory" (core memory $memory))
  (alias core export $guest "realloc" (core func $realloc))
  (alias core export $guest "activate" (core func $core-activate))
  (alias core export $guest "partial" (core func $core-partial))
  {describe_decl}
  {domain_decl}
  (instance $iface
    (export "describe" (func $describe))
{domain_export}  )
  (export "{export_name}" (instance $iface))
{second_export})
"#
    );
    parse_component(&text)
}

fn run_describe(
    world: TypedWorld,
    artifact: &[u8],
    limits: &InvocationLimits,
) -> Result<(TypedReceipt, TypedDescriptor), TypedExecutionError> {
    execute_describe_experimental(world, artifact, limits)
}

/// Requires the exact typed variant, and prints the whole error when it is not.
fn require_denied(
    outcome: Result<(TypedReceipt, TypedDescriptor), TypedExecutionError>,
    expected: &TypedExecutionError,
) {
    match outcome {
        Err(actual) => assert_eq!(actual, *expected, "wrong typed denial"),
        Ok(_) => panic!("typed execution must deny: {expected}"),
    }
}

fn staged(stage: TypedStage, cause: TypedExecutionError) -> TypedExecutionError {
    TypedExecutionError::Staged {
        stage,
        cause: Box::new(cause),
    }
}

fn engine(code: &str) -> TypedExecutionError {
    TypedExecutionError::Engine(code.to_owned())
}

/// Every bounded string the receipt carries, for the redaction and bound proof.
fn receipt_strings(receipt: &TypedReceipt) -> Vec<String> {
    let mut values = vec![
        receipt.proof.clone(),
        receipt.world.clone(),
        receipt.package_id.clone(),
        receipt.engine_version.clone(),
        receipt.stage.clone(),
        receipt.terminal.clone(),
        receipt.artifact_digest.as_str().to_owned(),
        receipt.wit_digest.as_str().to_owned(),
        receipt.cache_identity.as_str().to_owned(),
        receipt.input_digest.as_str().to_owned(),
        receipt.output_digest.as_str().to_owned(),
    ];
    values.extend(receipt.actual_imports.clone());
    values.extend(receipt.actual_exports.clone());
    values.extend(
        [
            &receipt.operation_id,
            &receipt.task_id,
            &receipt.fence_epoch,
            &receipt.policy_id,
        ]
        .into_iter()
        .flatten()
        .cloned(),
    );
    values
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The exact `cue-activation` WIT surface, transcribed from the read-only
/// `wit/typed/cue-activation.wit` so the hostile components typecheck against
/// the same signature the Host's generated binding requires. Field names carry
/// no ABI meaning; the structure does.
const CUE_TYPES: &str = r#"
(type $ca-abi (record (field "world-name" string) (field "package-id" string) (field "abi-revision" u32) (field "native-contract" string) (field "native-revision" string) (field "abi-digest" string)))
(type $ca-describe (func (result $ca-abi)))
(type $ca-describe-string (func (result string)))
(type $ca-describe-partial (func (result (record (field "world-name" string)))))
(type $ca-completeness (enum "complete" "truncated" "source-unavailable" "stale" "no-direct-match"))
(type $ca-proof (enum "observation" "candidate-only" "admission" "assembly" "activation" "screen" "cycle" "handler"))
(type $ca-bound-kind (enum "depth" "fanout" "results" "nodes" "edges" "work" "path-len" "seeds" "direct" "derived" "trace-steps" "output-bytes"))
(type $ca-seed (record (field "cue-id" string) (field "comparison-key" string) (field "normalization-profile" string)))
(type $ca-edge (record (field "edge-id" string) (field "from-handle" string) (field "to-handle" string) (field "weight-milli" u32)))
(type $ca-bounds (record (field "max-depth" u8) (field "max-fanout" u16) (field "max-results" u16) (field "max-nodes" u32) (field "max-edges" u32) (field "max-work" u64) (field "max-path-len" u16) (field "max-seeds" u16) (field "max-direct" u16) (field "max-derived" u16) (field "max-trace-steps" u16) (field "max-output-bytes" u32) (field "activation-threshold" u16)))
(type $ca-request (record (field "schema-revision" u32) (field "request-id" string) (field "seeds" (list $ca-seed)) (field "snapshot-id" string) (field "relation-edges" (list $ca-edge)) (field "bounds" $ca-bounds) (field "fence-epoch" string) (field "fence-generation" u64) (field "normalization-profile" string) (field "observed-at-ms" s64) (field "deadline-ms" (option s64)) (field "cancelled" bool)))
(type $ca-direct (record (field "target" string) (field "strength" u16) (field "seed" string)))
(type $ca-derived (record (field "target" string) (field "strength" u16) (field "path" (list string)) (field "seed" string)))
(type $ca-trace-step (record (field "node" string) (field "depth" u8) (field "strength" u16)))
(type $ca-trace (record (field "steps" (list $ca-trace-step)) (field "inspected-nodes" u32) (field "inspected-edges" u32)))
(type $ca-body (record (field "request-id" string) (field "snapshot-id" string) (field "direct" (list $ca-direct)) (field "derived" (list $ca-derived)) (field "trace" $ca-trace) (field "completeness" $ca-completeness) (field "frontier" (list string)) (field "output-bytes" u32) (field "proof-ceiling" $ca-proof) (field "result-digest" string)))
(type $ca-outcome (variant (case "activated" $ca-body)))
(type $ca-malformed (record (field "field" string) (field "human-detail" string)))
(type $ca-bound (record (field "bound" $ca-bound-kind) (field "human-detail" string)))
(type $ca-stale (record (field "human-detail" string)))
(type $ca-schema (record (field "want-revision" u32) (field "got-revision" u32) (field "human-detail" string)))
(type $ca-internal (record (field "human-detail" string)))
(type $ca-error (variant (case "malformed" $ca-malformed) (case "bound-exceeded" $ca-bound) (case "stale-snapshot" $ca-stale) (case "unsupported-schema" $ca-schema) (case "internal" $ca-internal)))
(type $ca-activate (func (param "request" $ca-request) (result (result $ca-outcome (error $ca-error)))))
"#;

fn require_governed(result: Result<(), TypedExecutionError>, expected: &TypedExecutionError) {
    match result {
        Err(actual) => assert_eq!(actual, *expected, "wrong governed denial"),
        Ok(()) => panic!("governed execution must deny: {expected}"),
    }
}

fn governed_admission(world: TypedWorld, artifact_digest: Sha256Digest) -> GovernedAdmission {
    GovernedAdmission {
        world,
        operation_id: "operation-758".to_owned(),
        task_id: "task-758".to_owned(),
        scope_id: "scope-758".to_owned(),
        fence_epoch: "fence-758".to_owned(),
        policy_id: "policy-758".to_owned(),
        artifact_digest,
        proof_ceiling: ProofCeiling::Admission,
    }
}

fn denial_of(error: &TypedExecutionError) -> String {
    error.to_string()
}

// WORK_UNIT_CASE: 758/1
#[test]
fn governed_absent_invalid_and_stale_admission_denies_exactly() {
    // Absent admission. `execute_governed_refusal` presents a well-formed but
    // unadmitted record and must still fail closed.
    require_governed(
        execute_governed_refusal(),
        &TypedExecutionError::GovernedAdmissionRequired,
    );
    assert_eq!(
        TypedExecutionError::GovernedAdmissionRequired.to_string(),
        "KERNEL_ADMISSION_REQUIRED"
    );
    require_governed(
        check_governed_admission(TypedWorld::ContextAdmission, None, None, None),
        &TypedExecutionError::GovernedAdmissionRequired,
    );

    let digest = Sha256Digest::of_bytes(b"758-case-1");
    let admission = governed_admission(TypedWorld::ContextAdmission, digest.clone());

    // No bound digest: an explicit governed attempt carries no admission
    // channel, so the artifact binding can never be satisfied.
    require_governed(
        check_governed_admission(TypedWorld::ContextAdmission, None, None, Some(&admission)),
        &TypedExecutionError::AdmissionMismatch("artifact-digest".to_owned()),
    );
    // Stale/wrong digest against a presented record.
    require_governed(
        check_governed_admission(
            TypedWorld::ContextAdmission,
            Some(&Sha256Digest::of_bytes(b"758-stale-digest")),
            None,
            Some(&admission),
        ),
        &TypedExecutionError::AdmissionMismatch("artifact-digest".to_owned()),
    );
    // World disagreement is its own typed denial, not the unadmitted default.
    require_governed(
        check_governed_admission(
            TypedWorld::DreamerCycle,
            Some(&digest),
            None,
            Some(&admission),
        ),
        &TypedExecutionError::AdmissionMismatch("world".to_owned()),
    );

    // Invalid records are denied by the owned record validator, never
    // silently repaired.
    for invalid in [
        String::new(),
        "https://registry.invalid/admission".to_owned(),
        "op\u{7}eration".to_owned(),
        "o".repeat(600),
    ] {
        let mut broken = admission.clone();
        broken.operation_id = invalid;
        require_governed(
            check_governed_admission(
                TypedWorld::ContextAdmission,
                Some(&digest),
                None,
                Some(&broken),
            ),
            &TypedExecutionError::LimitDenied("admission-field".to_owned()),
        );
    }

    // A well-formed record whose world and artifact agree is still denied: no
    // live Kernel channel re-anchors its freshness, so staleness is never
    // provable and the default fails closed.
    require_governed(
        check_governed_admission(
            TypedWorld::ContextAdmission,
            Some(&digest),
            None,
            Some(&admission),
        ),
        &TypedExecutionError::GovernedAdmissionRequired,
    );
    assert_eq!(
        TypedExecutionError::AdmissionMismatch("world".to_owned()).to_string(),
        "ADMISSION_MISMATCH:world"
    );
    assert_eq!(
        TypedExecutionError::LimitDenied("admission-field".to_owned()).to_string(),
        "LIMIT_DENIED:admission-field"
    );
}

// WORK_UNIT_CASE: 758/2
#[test]
fn governed_arbitrary_and_relative_artifact_sources_are_denied() {
    let digest = Sha256Digest::of_bytes(b"758-case-2");
    let admission = governed_admission(TypedWorld::CueActivation, digest.clone());

    // A caller-supplied path on the governed lane is refused before the
    // presented admission record is consulted, so it cannot become a hidden
    // acquisition channel and never falls back to the experimental mode.
    for source in [
        Path::new("C:\\eliot\\arbitrary.wasm"),
        Path::new("guest.wasm"),
        Path::new("https://example.invalid/guest.wasm"),
        Path::new("oci://eliot/guest"),
    ] {
        require_governed(
            check_governed_admission(
                TypedWorld::CueActivation,
                Some(&digest),
                Some(source),
                Some(&admission),
            ),
            &TypedExecutionError::GovernedAdmissionRequired,
        );
    }

    // The bounded local artifact layer refuses relative spellings instead of
    // resolving them against the process working directory.
    assert_eq!(
        require_absolute_artifact_path(Path::new("tests/fixtures/guest.wat")),
        Err(PreflightError::NotAbsolute)
    );
    assert_eq!(
        require_absolute_artifact_path(Path::new("guest.wat")),
        Err(PreflightError::NotAbsolute)
    );
    assert_eq!(
        require_absolute_artifact_path(&must(std::env::current_dir())),
        Ok(())
    );
    assert_eq!(
        PreflightError::NotAbsolute.to_string(),
        "PREFLIGHT_NOT_ABSOLUTE"
    );

    // URL/authority-shaped sources are denied before any filesystem access.
    for remote in [
        "https://example.invalid/guest.wasm",
        "oci://eliot/guest",
        "file://guest.wasm",
    ] {
        assert_eq!(
            read_bounded_artifact(Path::new(remote)),
            Err(PreflightError::ArbitraryPathDenied),
            "remote source must be denied: {remote}"
        );
    }
    assert_eq!(
        PreflightError::ArbitraryPathDenied.to_string(),
        "PREFLIGHT_ARBITRARY_PATH_DENIED"
    );

    // Positive control: compile the checked-in WAT fixture, then read those
    // same component bytes from one owned absolute local path.
    let expected = load_legacy_guest();
    let absolute = std::env::temp_dir().join(format!(
        "eliot-758-case-2-{}-{}.wasm",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    assert_eq!(require_absolute_artifact_path(&absolute), Ok(()));
    let mut file = must(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&absolute),
    );
    let write_result = std::io::Write::write_all(&mut file, &expected);
    drop(file);
    if let Err(error) = write_result {
        must(std::fs::remove_file(&absolute));
        panic!("positive-control fixture could not be written: {error}");
    }
    let read_result = read_bounded_artifact(&absolute);
    must(std::fs::remove_file(&absolute));
    let (bytes, preflight) = must(read_result);
    assert_eq!(preflight.digest, Sha256Digest::of_bytes(&bytes));
    assert_eq!(preflight.byte_len, bytes.len() as u64);
    assert_eq!(bytes, expected);
}

// WORK_UNIT_CASE: 758/3
#[test]
fn every_six_typed_worlds_component_executes_through_its_neutral_capsule_pair() {
    let worlds = TypedWorld::all();
    assert_eq!(worlds.len(), 6);
    let mut observed: Vec<String> = Vec::new();

    for world in worlds {
        let artifact = load_fixture(world);
        let preflight = must(preflight_bytes(&artifact));

        // The kit/capsule pair is bound to THIS fixture's preflight bytes, not
        // to a name, a path or an expected digest pasted from elsewhere.
        let kit = world_kit(world, &artifact);
        let capsule = world_capsule(world, &kit, &artifact);
        assert_eq!(kit.artifact_digest, preflight.digest);
        assert_eq!(kit.artifact_len, preflight.byte_len);
        assert_eq!(capsule.fixture.as_slice(), artifact.as_slice());
        assert!(!kit.governed, "experimental lane kit must not be governed");
        assert!(kit.validate().is_ok());
        assert_eq!(kit.digest(), Ok(capsule.kit_digest.clone()));
        assert!(capsule.validate(&kit).is_ok());
        assert_eq!(capsule.world.world_name(), world.world_name());
        assert_eq!(capsule.operation.as_str(), world.domain_func());
        assert_eq!(capsule.stage, ProofStage::Invocation);

        // The single typed invocation of this world's real component, through
        // the real Wasmtime provider: the fixture is preflighted, hashed and
        // compiled from the same buffer, its type is inspected, it is
        // instantiated on the empty linker and `describe` is actually called.
        let limits = default_experimental_limits(preflight.digest.clone());
        let (receipt, descriptor) =
            must(run_describe(world, &artifact, &limits).map_err(|error| error.to_string()));
        assert_eq!(receipt.world, world.world_name());
        assert_eq!(descriptor.world_name, world.world_name());
        assert_eq!(receipt.artifact_digest, preflight.digest);
        assert_eq!(receipt.artifact_bytes, preflight.byte_len);
        assert!(receipt.actual_imports.is_empty());
        assert_eq!(receipt.actual_exports.len(), 1);
        assert!(
            accepted_export_spellings(world).contains(&receipt.actual_exports[0]),
            "unexpected export spelling: {:?}",
            receipt.actual_exports[0]
        );
        assert_eq!(receipt.instances, PRODUCTION_SUCCESS_INSTANCES);
        assert_eq!(receipt.stage, TypedStage::Cleanup.as_str());
        assert_eq!(receipt.terminal, "Completed");
        observed.push(world.world_name().to_owned());
    }

    // Denominator: every frozen world ran once. No world is skipped, probed,
    // retried on another world, or served from a cache entry.
    assert_eq!(observed.len(), 6);
    for world in worlds {
        assert!(observed.contains(&world.world_name().to_owned()));
    }
    // A governed kit is refused on this lane (source contract): the
    // experimental receipt can never satisfy governed proof.
    //
    // NOT CONVERTIBLE (retained deliberately). Both guards pin the refusal
    // production implements at
    // `bins/eliot-wasm-host/src/typed_execution.rs:2312-2316`, inside
    // `execute_capsule_domain_experimental` (`:2295`), whose
    // `request: &TypedDomainRequest` parameter (`:2300`) carries six
    // `Box<crate::typed_bindings::<world>::…>` payloads (`:1855-1892`) while
    // `mod typed_bindings;` is private (`src/lib.rs:41`). An external test
    // target can neither construct nor obtain such a request, so no executed
    // alternative exists from this binary. Certified, not converted.
    assert!(TYPED_EXECUTION_SOURCE.contains("\"kit-governed\".to_owned()"));
    assert!(TYPED_EXECUTION_SOURCE.contains("if kit.governed {"));
}

// WORK_UNIT_CASE: 758/4
#[test]
fn experimental_receipt_cannot_claim_governed_proof() {
    let artifact = cooperative_cue_artifact();
    let digest = Sha256Digest::of_bytes(&artifact);
    let limits = default_experimental_limits(digest);
    let (receipt, _) = must(
        run_describe(TypedWorld::CueActivation, &artifact, &limits)
            .map_err(|error| error.to_string()),
    );

    // Real executed receipt: the proof string is the experimental code and is
    // not the governed or the legacy code.
    assert_eq!(receipt.proof, "NON_GOVERNED_EXPERIMENTAL");
    assert_eq!(receipt.proof, ExecutionMode::LocalExperimental.proof());
    assert_ne!(receipt.proof, ExecutionMode::Governed.proof());
    assert_ne!(receipt.proof, ExecutionMode::LegacyOnly.proof());
    assert_eq!(ExecutionMode::Governed.proof(), "GOVERNED_ADMISSION");
    assert_eq!(ExecutionMode::LegacyOnly.proof(), "LEGACY_ONLY");

    // The neutral kit carries only the lowest non-admission ceiling, and a
    // governed kit is refused by the capsule lane before any engine work.
    let kit = world_kit(TypedWorld::CueActivation, &artifact);
    assert_eq!(kit.proof_ceiling, ProofCeiling::CandidateOnly);
    assert_ne!(kit.proof_ceiling, ProofCeiling::Admission);
    let mut governed = kit.clone();
    governed.governed = true;
    // The governed refusal is the Host lane rule, not a neutral-kit defect:
    // the kit still validates, so nothing but the lane decides it.
    assert!(governed.validate().is_ok());
    assert!(governed.governed);
    // NOT CONVERTIBLE (retained deliberately). Both guards below pin the
    // capsule lane's governed-kit refusal, which production implements at
    // `bins/eliot-wasm-host/src/typed_execution.rs:2312-2316` inside
    // `execute_capsule_domain_experimental` (`:2295`). That entry takes
    // `request: &TypedDomainRequest` (`:2300`), whose six variants each hold a
    // `Box<crate::typed_bindings::<world>::…>` payload (`:1855-1892`) while
    // `mod typed_bindings;` is private (`src/lib.rs:41`), so an external test
    // target can neither construct nor obtain a request and can never enter
    // that function. No executed alternative exists from here; the refusal is
    // proven in-crate by the neutral-capsule drive in
    // `src/typed_execution.rs`. The second guard is a verbatim duplicate of the
    // case-3 guard at test `:932`; both are kept.
    assert!(TYPED_EXECUTION_SOURCE.contains("pub fn execute_capsule_domain_experimental("));
    assert!(TYPED_EXECUTION_SOURCE.contains("if kit.governed {"));

    // The shared projection only carries the ceiling it was handed, and the
    // host never derives a governed ceiling on this lane.
    assert!(RECEIPT_BRIDGE_SOURCE.contains("proof_ceiling,"));
    assert!(RECEIPT_BRIDGE_SOURCE.contains("let mut shared = eliot_wasm_runtime::TypedReceipt {"));
    // CONVERTED (already executed): the real proof of this guard is
    // `assert_eq!(receipt.proof, ExecutionMode::LocalExperimental.proof())`
    // above, bound to production
    // `bins/eliot-wasm-host/src/typed_execution.rs:1044`
    // (`proof: ExecutionMode::LocalExperimental.proof().to_owned()`) and read
    // off a receipt the real engine produced. That assertion can fail if the
    // production assignment drifts; this text search cannot. Guard kept.
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("proof: ExecutionMode::LocalExperimental.proof().to_owned()")
    );
}

// WORK_UNIT_CASE: 758/5
#[test]
fn legacy_world_requires_explicit_selection_and_is_never_promoted() {
    // Real engine input: the checked-in legacy `run` component compiles and
    // reports zero imports, but its `run` export must never satisfy a typed
    // world selection or auto-upgrade to typed execution.
    let artifact = load_legacy_guest();
    let digest = Sha256Digest::of_bytes(&artifact);
    let limits = default_experimental_limits(digest.clone());
    require_denied(
        run_describe(TypedWorld::ContextAdmission, &artifact, &limits),
        &TypedExecutionError::LegacyMismatch,
    );

    // Issue #21: an explicit zero host-call budget is a closed-world
    // declaration, not a limit denial. Zero must pass the limit gate and reach
    // world selection, where the legacy fixture denies as `LegacyMismatch`.
    let mut zero_budget = default_experimental_limits(digest);
    zero_budget.max_host_calls = 0;
    require_denied(
        run_describe(TypedWorld::ContextAdmission, &artifact, &zero_budget),
        &TypedExecutionError::LegacyMismatch,
    );

    // The legacy identity is not selectable as a typed world, in the Host
    // table or in the neutral contract, and no frozen world name equals it.
    assert_eq!(TypedWorld::parse(LEGACY_WORLD), None);
    assert_eq!(TypedWorld::parse(LEGACY_EXPORT), None);
    assert_eq!(TypedWorld::parse("guest"), None);
    for world in TypedWorld::all() {
        assert_ne!(world.world_name(), LEGACY_WORLD);
        assert_ne!(world.world_name(), LEGACY_EXPORT);
    }
    assert_eq!(LEGACY_WORLD, "eliot:wasm/guest");
    assert_eq!(LEGACY_EXPORT, "run");
    assert!(matches!(
        NeutralWorld::parse(LEGACY_WORLD),
        Err(TypedContractError::LegacyRejected(_))
    ));
    assert!(matches!(
        NeutralWorld::parse(LEGACY_EXPORT),
        Err(TypedContractError::LegacyRejected(_))
    ));
    assert!(ExecutionMode::LegacyOnly.proof().contains("LEGACY_ONLY"));
    assert_eq!(
        TypedExecutionError::LegacyMismatch.to_string(),
        "LEGACY_MISMATCH"
    );

    // The CLI never promotes a legacy spelling onto a typed lane.
    assert!(matches!(
        parse_args::<_, &str>([
            "--experimental-typed-component",
            "C:\\eliot\\legacy.wasm",
            "--world",
            LEGACY_WORLD,
        ]),
        Err(CliError::UnknownWorld(_))
    ));
}

// WORK_UNIT_CASE: 758/6
#[test]
fn unknown_ambiguous_and_incompatible_world_selections_fail_closed() {
    // Unknown/incompatible spellings are denied, never auto-probed.
    for unknown in [
        "not-a-world",
        "context-admission ",
        "Context-Admission",
        "admission",
    ] {
        assert_eq!(TypedWorld::parse(unknown), None, "unknown world: {unknown}");
    }
    assert!(matches!(
        NeutralWorld::parse("not-a-world"),
        Err(TypedContractError::UnknownWorld(_))
    ));
    assert!(matches!(
        parse_args::<_, &str>([
            "--experimental-typed-component",
            "C:\\eliot\\typed.wasm",
            "--world",
            "not-a-world",
        ]),
        Err(CliError::UnknownWorld(_))
    ));

    // Ambiguous: a component exporting two interfaces selects no single world.
    let ambiguous = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            include_domain_export: true,
            second_export: true,
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&ambiguous);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &ambiguous, &limits),
        &TypedExecutionError::WorldSelection {
            reason: "ambiguous-exports".to_owned(),
        },
    );

    // Foreign package spelling: the interface name alone never proves identity.
    let foreign_package = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            include_domain_export: true,
            export_name: Some("other:package/activation".to_owned()),
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&foreign_package);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &foreign_package, &limits),
        &TypedExecutionError::MissingExport("activation".to_owned()),
    );

    // Incompatible: a real `cue-activation` component presented for the
    // `context-admission` world is a missing export for that world.
    let cue = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            include_domain_export: true,
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&cue);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::ContextAdmission, &cue, &limits),
        &TypedExecutionError::MissingExport("admission".to_owned()),
    );
}

// WORK_UNIT_CASE: 758/7
#[test]
fn missing_or_wrong_descriptor_and_domain_exports_are_denied_before_instantiation() {
    // Positive control: the same component with both exports present is
    // accepted, so the denials below are discriminators.
    let complete = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            include_domain_export: true,
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&complete);
    let limits = default_experimental_limits(digest);
    assert!(run_describe(TypedWorld::CueActivation, &complete, &limits).is_ok());

    // Missing domain export: the interface exports `describe` only.
    let missing_domain = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            include_domain_export: false,
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&missing_domain);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &missing_domain, &limits),
        &TypedExecutionError::MissingExport("activate".to_owned()),
    );

    // Wrongly typed domain export: a scalar domain type at the exact core
    // signature the domain core function already has, so the component itself
    // stays valid and only the exported domain type is wrong.
    let wrong_domain = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            include_domain_export: true,
            domain_decl: Some(
                "(func $activate (param u32) (result u32)\n    \
                 (canon lift (core func $core-activate) (memory $memory) (realloc $realloc)))",
            ),
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&wrong_domain);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &wrong_domain, &limits),
        &TypedExecutionError::ExportTypeMismatch("activate".to_owned()),
    );

    // Wrongly typed descriptor export: the partial descriptor type at the exact
    // core signature its discriminator core function has.
    let wrong_descriptor = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            include_domain_export: true,
            describe_decl: Some(
                "(func $describe (type $ca-describe-partial)\n    \
                 (canon lift (core func $core-partial) (memory $memory) (realloc $realloc)))",
            ),
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&wrong_descriptor);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &wrong_descriptor, &limits),
        &TypedExecutionError::ExportTypeMismatch("describe".to_owned()),
    );
    assert_eq!(
        TypedExecutionError::MissingExport("activate".to_owned()).to_string(),
        format!("{CAPABILITY_INTRODUCTION_REQUIRED}:activate")
    );
    assert_eq!(
        TypedExecutionError::ExportTypeMismatch("activate".to_owned()).to_string(),
        "EXPORT_TYPE_MISMATCH:activate"
    );
}

// WORK_UNIT_CASE: 758/8
#[test]
fn malformed_core_module_is_rejected_distinctly_from_a_component() {
    // A core module is refused by preflight, before compilation, with its own
    // typed reason and never as a compile failure.
    let mut core = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    core.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        preflight_bytes(&core),
        Err(PreflightError::CoreModuleRejected)
    );
    let digest = Sha256Digest::of_bytes(&core);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::ContextAdmission, &core, &limits),
        &TypedExecutionError::Artifact(PreflightError::CoreModuleRejected),
    );
    assert_eq!(
        PreflightError::CoreModuleRejected.to_string(),
        "PREFLIGHT_CORE_MODULE_REJECTED"
    );

    // A component-preambled but malformed payload reaches the engine and is
    // reported as the staged compile failure it is.
    let mut malformed = vec![0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x01, 0x00];
    malformed.extend_from_slice(b"not-a-component-body");
    let digest = Sha256Digest::of_bytes(&malformed);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &malformed, &limits),
        &staged(TypedStage::Compile, engine("compile:component-error")),
    );

    // Preamble and length boundaries are their own typed denials.
    assert_eq!(preflight_bytes(&[]), Err(PreflightError::Empty));
    assert_eq!(
        preflight_bytes(&[0x00, 0x61, 0x73, 0x6D]),
        Err(PreflightError::MalformedPreamble)
    );
    assert_eq!(
        preflight_bytes(b"not-webassembly-bytes"),
        Err(PreflightError::MalformedPreamble)
    );
}

// WORK_UNIT_CASE: 758/9
#[test]
fn artifact_raw_input_and_leaf_bounds_are_checked_before_allocation() {
    // Artifact bound: an oversized buffer is refused by length before any
    // magic/marker inspection and before any engine exists.
    let oversize = usize::try_from(MAX_ARTIFACT_BYTES).map_or(1, |bytes| bytes + 1);
    let mut buffer = vec![0u8; oversize];
    buffer[0] = 0x00;
    assert_eq!(
        preflight_bytes(&buffer),
        Err(PreflightError::TooLarge {
            actual: MAX_ARTIFACT_BYTES + 1,
            max: MAX_ARTIFACT_BYTES,
        })
    );

    // The bounded acquisition refuses a non-regular file instead of reading it.
    let directory = must(std::env::current_dir()).join("tests/fixtures");
    assert!(matches!(
        read_bounded_artifact(&directory),
        Err(PreflightError::Unreadable(_))
    ));

    // Descriptor string ceiling: the CHECKED-IN `output-oversize` fixture reports a
    // 1024-byte `native-contract`, so the denial under test is the real ceiling
    // on real engine input, with the exact field name.
    let oversize = load_fixture_file("output-oversize");
    let digest = Sha256Digest::of_bytes(&oversize);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &oversize, &limits),
        &staged(
            TypedStage::Output,
            TypedExecutionError::OutputViolation("native-contract".to_owned()),
        ),
    );

    // Positive control: the honest `dreamer-cycle` fixture with a real 1024-byte
    // budget and the honest descriptor completes.
    let honest = real_cycle_fixture();
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&honest));
    let (receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &honest, &limits).map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.terminal, "Completed");

    // Declared source guard for the per-leaf typed string/list/item ceilings,
    // which live on the domain request path: the walkers bound each leaf
    // individually and `bound_request` runs before any lowering or dispatch.
    //
    // NOT CONVERTIBLE (retained deliberately). All five guards are reachable
    // only through `execute_domain_lane`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:2107` calls
    // `bound_request`, `:2121` calls `dispatch_domain`), and every entry into
    // it needs a `&TypedDomainRequest` whose payloads are crate-private
    // generated bindgen types (`:1855-1892`, `mod typed_bindings;` private at
    // `src/lib.rs:41`). `MAX_TYPED_STRING_BYTES` / `MAX_TYPED_LIST_ITEMS`
    // (`:50`, `:52`) are read only by `TypedBound::text` / `TypedBound::list`
    // (`:845-869`), whose every caller is one of the `bound_*` walkers the
    // domain request path owns. The descriptor lane reached from this test
    // target bounds reported strings with a DIFFERENT ceiling,
    // `MAX_DESCRIPTOR_STRING_BYTES` (`:42`, applied by `bounded_descriptor_string`
    // at `:528`), which the executed `OutputViolation("native-contract")`
    // denial above already proves. Both ceilings are proven on real engine
    // input by the in-crate domain drive in this module.
    assert!(TYPED_EXECUTION_SOURCE.contains("const MAX_TYPED_STRING_BYTES: usize = 4_096;"));
    assert!(TYPED_EXECUTION_SOURCE.contains("const MAX_TYPED_LIST_ITEMS: usize = 256;"));
    assert!(TYPED_EXECUTION_SOURCE.contains("fn texts(&mut self, values: &[String])"));
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("bound_request(world, request, admitted, &mut input_bound)?;")
    );
    assert!(TYPED_EXECUTION_SOURCE
        .contains("let (descriptor, result, usage) = dispatch_domain(world, engine, component, limits, request)?;"));
}

// WORK_UNIT_CASE: 758/10
#[test]
fn the_same_buffer_is_hashed_and_compiled_and_a_foreign_digest_denies() {
    let artifact = cooperative_cue_artifact();
    let digest = Sha256Digest::of_bytes(&artifact);

    // Positive: the receipt reports the digest and length of the buffer it
    // actually compiled.
    let limits = default_experimental_limits(digest.clone());
    let (receipt, _) = must(
        run_describe(TypedWorld::CueActivation, &artifact, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.artifact_digest, digest);
    assert_eq!(receipt.artifact_bytes, artifact.len() as u64);

    // A buffer that hashes outside the admitted allow-list is the owned typed
    // `ADMISSION_MISMATCH`, never a limit denial and never a stale cache hit.
    let foreign = default_experimental_limits(Sha256Digest::of_bytes(b"758-other-artifact"));
    require_denied(
        run_describe(TypedWorld::CueActivation, &artifact, &foreign),
        &TypedExecutionError::AdmissionMismatch("cache-artifact".to_owned()),
    );

    // Same-buffer proof: the allow-list names the ORIGINAL fixture digest while
    // a mutated buffer is presented. If the Host reread a path or trusted a
    // cached digest, this would execute; it must deny on the presented bytes.
    let mut mutated = artifact.clone();
    mutated.push(0x00);
    require_denied(
        run_describe(TypedWorld::CueActivation, &mutated, &limits),
        &TypedExecutionError::AdmissionMismatch("cache-artifact".to_owned()),
    );

    // The mutation is real: the presented bytes hash differently.
    assert_ne!(Sha256Digest::of_bytes(&mutated), digest);

    // Declared source guard: both the revalidation and the compile take the
    // same `&[u8]`; neither takes a path, a name or a URL.
    //
    // CONVERTED (already executed). The real proof of all three guards is
    // executed above and can fail if production drifts:
    // - `assert_eq!(receipt.artifact_digest, digest)` /
    //   `assert_eq!(receipt.artifact_bytes, artifact.len() as u64)` bind the
    //   receipt to the compiled buffer and cover the provider seam
    //   (`bins/eliot-wasm-host/src/typed_execution.rs:1024` builds the provider
    //   from that same `artifact`, `:1047-1048` records its digest and length);
    //   `artifact` here is generated in this file and never written to disk, so
    //   a receipt reporting its hash is a receipt about the PRESENTED bytes.
    // - the two `AdmissionMismatch("cache-artifact")` denials above are
    //   produced by the allow-list consult on the hash of the buffer handed in
    //   (`:728` re-hash, `:734-737` the denial), which is why the mutated
    //   buffer denies while the identical un-mutated one executes. Both
    //   denials happen before `build_typed_dispatch_provider` is reached
    //   (`:1022` before `:1024`), so no engine exists to serve a stale entry.
    assert!(TYPED_EXECUTION_SOURCE.contains("let digest = Sha256Digest::of_bytes(artifact);"));
    assert!(TYPED_EXECUTION_SOURCE.contains(
        "let cache_identity = check_cache_identity(world, artifact, &preflight.digest, limits)?;"
    ));
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("let provider = build_typed_dispatch_provider(world, limits, artifact)?;")
    );
}

// WORK_UNIT_CASE: 758/11
#[test]
fn actual_forbidden_imports_are_rejected_before_instantiation() {
    // Real engine, real CHECKED-IN input: the `forbidden-import` fixture is the
    // honest `dreamer-cycle` surface plus one ambient WASI clock import. The
    // denial comes from the observed component TYPE, before instantiation.
    let imported = load_fixture_file("forbidden-import");
    let digest = Sha256Digest::of_bytes(&imported);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &imported, &limits),
        &TypedExecutionError::ForbiddenImport("wasi:clocks/wall-clock@0.2.0".to_owned()),
    );

    // A long ambient import name is bounded, so no unbounded
    // attacker-controlled string reaches the denial.
    let long_name = format!("eliot:ambient/{}", "x".repeat(200));
    let imported = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            ambient_import: Some(long_name),
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&imported);
    let limits = default_experimental_limits(digest);
    match run_describe(TypedWorld::CueActivation, &imported, &limits) {
        Err(TypedExecutionError::ForbiddenImport(name)) => {
            assert_eq!(name.chars().count(), 96);
        }
        other => panic!("wrong denial for a long ambient import: {other:?}"),
    }

    // Positive: the honest CHECKED-IN `dreamer-cycle` fixture reports zero
    // actual imports.
    let closed = real_cycle_fixture();
    let digest = Sha256Digest::of_bytes(&closed);
    let limits = default_experimental_limits(digest);
    let (receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &closed, &limits).map_err(|error| error.to_string()),
    );
    assert!(receipt.actual_imports.is_empty());

    // A descriptor/manifest claim cannot introduce an import in the neutral
    // contract either: a kit declaring one is refused exactly.
    let mut kit = world_kit(TypedWorld::CueActivation, &closed);
    kit.declared_imports
        .push("wasi:filesystem/types".to_owned());
    assert_eq!(kit.validate(), Err(TypedContractError::ImportMismatch));
}

// WORK_UNIT_CASE: 758/12
#[test]
fn a_lying_descriptor_cannot_grant_imports_or_change_policy() {
    // Real CHECKED-IN input: the three reported-field lies. Each is the honest
    // `dreamer-cycle` surface with exactly ONE reported field changed, so the
    // denial under test is that field's own identity rule and nothing else.
    // `validate_descriptor` checks world-name, then package-id, then
    // abi-revision, in that order, and each lie is denied before the next rule.
    for (fixture, field) in [
        ("lying-world-name", "world-name"),
        ("lying-package-id", "package-id"),
        ("lying-abi-revision", "abi-revision"),
    ] {
        let artifact = load_fixture_file(fixture);
        let limits = default_experimental_limits(Sha256Digest::of_bytes(&artifact));
        require_denied(
            run_describe(TypedWorld::DreamerCycle, &artifact, &limits),
            &staged(
                TypedStage::Output,
                TypedExecutionError::OutputViolation(field.to_owned()),
            ),
        );
    }

    // A descriptor claiming capabilities does not grant an ambient import:
    // the actual import is refused from the component type before any guest
    // code runs, so a reported capability claim buys nothing.
    let mut claiming = cooperative_guest();
    claiming.native_contract = "grants-wasi-stdio".to_owned();
    let artifact = cue_activation_artifact(
        &claiming,
        &CueOptions {
            ambient_import: Some("eliot:ambient/stdio".to_owned()),
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&artifact);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &artifact, &limits),
        &TypedExecutionError::ForbiddenImport("eliot:ambient/stdio".to_owned()),
    );

    // A wrong ABI digest is caught at the descriptor stage, not repaired. Real
    // CHECKED-IN input: the `lying-descriptor` fixture reports
    // `0000...0000` while every other identity field is honest.
    let liar = load_fixture_file("lying-descriptor");
    let digest = Sha256Digest::of_bytes(&liar);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &liar, &limits),
        &staged(
            TypedStage::Descriptor,
            TypedExecutionError::OutputViolation("abi-digest".to_owned()),
        ),
    );

    // Positive: the honest CHECKED-IN fixture is accepted and its reported ABI
    // digest is the digest of the exact frozen WIT bytes.
    let honest = real_cycle_fixture();
    let digest = Sha256Digest::of_bytes(&honest);
    let limits = default_experimental_limits(digest);
    let (_, descriptor) = must(
        run_describe(TypedWorld::DreamerCycle, &honest, &limits).map_err(|error| error.to_string()),
    );
    assert_eq!(descriptor.abi_digest, typed_wit_digest().as_str());
    assert_eq!(descriptor.package_id, TYPED_PACKAGE_ID);
    assert_eq!(descriptor.abi_revision, TYPED_ABI_REVISION);
    assert_eq!(descriptor.world_name, "dreamer-cycle");
}

// WORK_UNIT_CASE: 758/13
#[test]
fn infinite_loop_exhausts_fuel_at_the_stage_it_reaches() {
    // Real engine, real CHECKED-IN input: the `looping-describe` fixture's
    // `describe` has no exit, so the fuel-metered policy stops it and the
    // denial is reported at the descriptor stage it reached.
    let spinner = load_fixture_file("looping-describe");
    let digest = Sha256Digest::of_bytes(&spinner);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &spinner, &limits),
        &staged(TypedStage::Descriptor, engine("FuelExhausted")),
    );
    assert_eq!(
        denial_of(&staged(TypedStage::Descriptor, engine("FuelExhausted"))),
        "STAGE:descriptor:ENGINE:FuelExhausted"
    );

    // The same input under a tighter admitted fuel budget denies identically:
    // descriptor/initialization run inside the one guarded envelope, so the
    // budget applies before the domain export is ever reached.
    let mut starved = default_experimental_limits(Sha256Digest::of_bytes(&spinner));
    starved.max_fuel = 20_000;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &spinner, &starved),
        &staged(TypedStage::Descriptor, engine("FuelExhausted")),
    );

    // The INITIALIZATION half the issue names: a CHECKED-IN fixture whose core
    // module `(start ...)` loop has no exit. Initialization is untrusted
    // execution inside the same guarded envelope, so the engine really does
    // terminate it -- and `map_instantiate_error` reads the real trap code
    // through the shared `trap_termination` classifier, so this leg reports the
    // same owner-typed cause the descriptor leg reports through
    // `map_call_error`. The stage stays the one actually reached.
    let initializer = load_fixture_file("instantiation-start-loop");

    // Under the fuel-metered policy the store has fuel, the `(start ...)` loop
    // burns it, the engine raises `Trap::OutOfFuel`, and `trap_termination`
    // yields `FuelExhausted`. The policy is SELECTED and then ASSERTED, not
    // assumed.
    let start_fuel = default_experimental_limits(Sha256Digest::of_bytes(&initializer));
    assert_eq!(
        start_fuel.epoch.cancellation,
        CancellationPolicy::EpochAndFuel
    );
    assert!(start_fuel.max_fuel > 0);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &initializer, &start_fuel),
        &staged(TypedStage::Instantiate, engine("FuelExhausted")),
    );

    // Under the epoch-only policy `typed_fuel_budget` installs no fuel at all,
    // so the injected epoch deadline is the terminator: the engine raises
    // `Trap::Interrupt` and `trap_termination` yields `EpochDeadline`. A fuel
    // budget is therefore NOT what stops initialization here.
    let mut start_epoch = default_experimental_limits(Sha256Digest::of_bytes(&initializer));
    start_epoch.epoch.cancellation = CancellationPolicy::EpochInterruption;
    assert_eq!(
        start_epoch.epoch.cancellation,
        CancellationPolicy::EpochInterruption
    );
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &initializer, &start_epoch),
        &staged(TypedStage::Instantiate, engine("EpochDeadline")),
    );

    // Positive control: the honest CHECKED-IN fixture completes inside the same
    // budget, so fuel is available and the denial is caused by the loop.
    let honest = real_cycle_fixture();
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&honest));
    let (receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &honest, &limits).map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.terminal, "Completed");
    assert!(receipt.fuel_consumed <= 50_000);

    // EXECUTED PROOF that the fuel-metered store IS the store the guest
    // actually ran in, and that the budget is policy-gated. Production measures
    // `fuel_consumed` as `budget - store.get_fuel()` and only when
    // `typed_fuel_budget` returned `Some`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:1587-1590`), and
    // `typed_fuel_budget` returns `Some` only under `EpochAndFuel`
    // (`:1407-1412`). Two failable consequences, both read off real receipts:
    //
    // - a COMPLETING call that reports fuel consumed cannot have run in a store
    //   the budget never reached, because `run_guarded` builds exactly one
    //   store (`:1583`) and runs the instantiate-and-describe closure on it
    //   (`:1585`);
    // - the SAME buffer under `EpochInterruption` with a ONE-unit fuel ceiling
    //   COMPLETING is the discriminator. If that one unit had been installed,
    //   the pinned engine would raise `Trap::OutOfFuel` and the denial above
    //   would land at the descriptor stage; instead the call completes, which
    //   is only reachable through the `EpochInterruption => None` arm (`:1410`)
    //   and the `None` arm of the measurement (`:1589`). The epoch deadline is
    //   pushed to the lane maximum here so the deadline cannot be what ends the
    //   call and the completion is attributable to the absent fuel alone.
    assert!(
        receipt.fuel_consumed > 0,
        "a completing fuel-metered typed call must have consumed fuel from the metered store"
    );
    let mut unmetered = default_experimental_limits(Sha256Digest::of_bytes(&honest));
    unmetered.epoch.cancellation = CancellationPolicy::EpochInterruption;
    // NOT asserted here: `unmetered.epoch.cancellation` against the literal it
    // was just assigned from. That compares a test-authored value with itself,
    // production is not involved, and no change in production could fail it.
    // What is actually under test is the EXECUTED outcome below, which is
    // driven by what production reads off that envelope.
    unmetered.epoch.deadline_ticks = eliot_wasm_runtime::MAX_EPOCH_DEADLINE_TICKS;
    unmetered.max_fuel = 1;
    let (unmetered_receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &honest, &unmetered)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(
        unmetered_receipt.terminal, "Completed",
        "epoch-only execution must install no fuel budget at all"
    );
    // `fuel_consumed` is deliberately NOT asserted here. Production returns
    // `None` for a store with no fuel meter and the receipt renders that as
    // `0` at the `None => 0` arm, so the value is fixed by the envelope the
    // test just built rather than by anything the engine did, and it is
    // subsumed by the `Completed` assertion above. The executed proof that a
    // metered call really consumes fuel is the `> 0` assertion in the metered
    // leg above, which production's own counter can falsify.

    // Declared source guard: the store (fuel, epoch deadline and resource
    // limits) is built before instantiation and the descriptor call, both
    // inside the same guarded closure.
    //
    // CONVERTED: the executed assertions that now carry these two guards are
    // the `receipt.fuel_consumed > 0` / `unmetered_receipt.terminal ==
    // "Completed"` pair above, bound to production
    // `bins/eliot-wasm-host/src/typed_execution.rs:1583-1590` (the one store,
    // the one driver, the one closure, and the fuel measurement read from that
    // store) and `:1407-1412` (`typed_fuel_budget`). Both can fail; the text
    // search cannot.
    assert!(TYPED_EXECUTION_SOURCE.contains("run_guarded(engine, limits, |store| {"));
    assert!(TYPED_EXECUTION_SOURCE.contains("fn run_guarded<T>("));
    // Declared source guard: BOTH untrusted-execution legs read the cause from
    // the real engine trap code through one shared classifier, so the
    // initialization denials asserted above are the owner-typed fuel/epoch
    // causes rather than an untyped stage string.
    //
    // CONVERTED (already executed), each guard named:
    // - `fn trap_termination` / `OutOfFuel => FuelExhausted`: the
    //   `staged(Descriptor, engine("FuelExhausted"))` denial asserted above for
    //   the `looping-describe` fixture is produced by `map_call_error`
    //   (`:1316-1317`) from the real `Trap::OutOfFuel` the engine raised; the
    //   code string `FuelExhausted` exists nowhere else in that path.
    // - `Interrupt => EpochDeadline`: the
    //   `staged(Instantiate, engine("EpochDeadline"))` denial asserted above for
    //   the `instantiation-start-loop` fixture comes from
    //   `map_instantiate_error` (`:1343-1344`) on a real `Trap::Interrupt`, and
    //   the descriptor-stage `EpochDeadline` denials in case 14 from the same
    //   arm.
    // - `if let Some(termination) = trap_termination(error) {`: that is the
    //   `map_instantiate_error` arm at `:1343`, and the instantiate-stage
    //   `FuelExhausted` and `EpochDeadline` denials asserted above are
    //   reachable only through it.
    // - `ContextAdmission::instantiate(...)`: `:1642`, and the executed
    //   `context-admission` fixture in the case-3 and case-26 loops returns a
    //   receipt, which requires that exact call to have succeeded on the empty
    //   linker.
    assert!(
        TYPED_EXECUTION_SOURCE.contains(
            "fn trap_termination(error: &wasmtime::Error) -> Option<EngineTermination> {"
        )
    );
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("wasmtime::Trap::OutOfFuel => EngineTermination::FuelExhausted,")
    );
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("wasmtime::Trap::Interrupt => EngineTermination::EpochDeadline,")
    );
    assert!(
        TYPED_EXECUTION_SOURCE.contains("if let Some(termination) = trap_termination(error) {")
    );
    // CONVERTED: `CancellationPolicy::EpochInterruption => None` is
    // `typed_fuel_budget`'s `None` arm at
    // `bins/eliot-wasm-host/src/typed_execution.rs:1410`. The executed proof is
    // the `unmetered_receipt.terminal == "Completed"` assertion above: the same
    // buffer under `EpochInterruption` with `max_fuel = 1` completes instead of
    // dying on `Trap::OutOfFuel`, so no fuel was installed.
    assert!(TYPED_EXECUTION_SOURCE.contains("CancellationPolicy::EpochInterruption => None,"));
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("ContextAdmission::instantiate(&mut *store, component, &linker)")
    );
}

// WORK_UNIT_CASE: 758/14
#[test]
fn the_supported_deadline_is_independent_of_fuel() {
    // Real engine, real CHECKED-IN input: the `deadline-no-fuel` fixture burns
    // wall time on a counted integer spin with no memory traffic, so only the
    // injected epoch/wall deadline can stop it.
    let spinner = load_fixture_file("deadline-no-fuel");
    let mut epoch_only = default_experimental_limits(Sha256Digest::of_bytes(&spinner));
    // The policy is SELECTED and then ASSERTED, not assumed: under
    // `EpochInterruption` `typed_fuel_budget` installs no fuel at all, so a
    // `FuelExhausted` here would mean the policy did not select what the
    // deadline proof rests on.
    epoch_only.epoch.cancellation = CancellationPolicy::EpochInterruption;
    assert_eq!(
        epoch_only.epoch.cancellation,
        CancellationPolicy::EpochInterruption
    );
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &spinner, &epoch_only),
        &staged(TypedStage::Descriptor, engine("EpochDeadline")),
    );

    // Same shape of input under the fuel-metered policy: a DIFFERENT exact
    // terminal. The deadline therefore decides independently of fuel.
    let looping = load_fixture_file("looping-describe");
    let fuel_only = default_experimental_limits(Sha256Digest::of_bytes(&looping));
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &looping, &fuel_only),
        &staged(TypedStage::Descriptor, engine("FuelExhausted")),
    );

    // A fuel budget of one under the epoch-only policy still ends at the
    // deadline, never at a fuel denial: fuel is not the decider there.
    let mut starved = default_experimental_limits(Sha256Digest::of_bytes(&spinner));
    starved.epoch.cancellation = CancellationPolicy::EpochInterruption;
    starved.max_fuel = 1;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &spinner, &starved),
        &staged(TypedStage::Descriptor, engine("EpochDeadline")),
    );

    // EXECUTED PROOF that the compile-stage CODE is rendered by production and
    // not by this file. `TypedStage::as_str`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:127-136`, the
    // `Self::Compile => "compile"` arm at `:130`) is what `Display for
    // TypedStage` delegates to (`:139-143`), and that is the `stage` the
    // `Staged` arm of `Display for TypedExecutionError` formats (`:323`). Both
    // assertions below can fail if either production mapping drifts, and
    // neither compares a test-authored value against itself.
    assert_eq!(TypedStage::Compile.as_str(), "compile");
    assert_eq!(
        denial_of(&staged(
            TypedStage::Compile,
            engine("compile:component-error")
        )),
        "STAGE:compile:ENGINE:compile:component-error"
    );

    // Declared source guard: no synchronous compile-cancellation is claimed.
    // Compilation is synchronous, the compile stage is named but never
    // reported as aborted, and the epoch driver exists only around the
    // guarded invocation.
    //
    // NOT CONVERTIBLE, each guard named (retained deliberately):
    // - "Compilation in\n/// this Host is synchronous" and "no
    //   compile-cancellation or compile-abort" are DOC-COMMENT PROSE
    //   (`bins/eliot-wasm-host/src/typed_execution.rs:104-107`). A comment is
    //   not behaviour and no execution can falsify its wording.
    // - `struct EpochDriver {` (`:1519`) and `impl Drop for EpochDriver {`
    //   (`:1559`) are a PRIVATE struct and its teardown impl. Spawning a driver
    //   has no observable effect beyond the epoch terminations already executed
    //   above, and the ORDER of `stop`/`join` inside `Drop` (`:1560-1565`) is
    //   unobservable from outside the crate: no exported symbol exposes driver
    //   state, and a joined thread and an abandoned one differ only in timing.
    //   The observable consequence of per-invocation teardown — an interrupted
    //   call leaving nothing behind for the next one — is executed in case 21.
    assert!(TYPED_EXECUTION_SOURCE.contains("Compilation in\n/// this Host is synchronous"));
    // CONVERTED: the executed proof is the `starved` leg above plus its case-13
    // twin `unmetered_receipt.terminal == "Completed"`: the same buffer under
    // `EpochInterruption` with a ONE-unit fuel ceiling ends at the deadline (or
    // completes, for an honest buffer) instead of on `Trap::OutOfFuel`, which
    // is only reachable if `typed_fuel_budget`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:1407-1412`) returned `None`.
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("fn typed_fuel_budget(limits: &InvocationLimits) -> Option<u64> {")
    );
    // CONVERTED: the `EpochInterruption => None` arm at
    // `bins/eliot-wasm-host/src/typed_execution.rs:1410`; see the case-13
    // `unmetered_receipt` assertions, which execute that arm.
    assert!(TYPED_EXECUTION_SOURCE.contains("CancellationPolicy::EpochInterruption => None,"));
    assert!(TYPED_EXECUTION_SOURCE.contains("struct EpochDriver {"));
    assert!(TYPED_EXECUTION_SOURCE.contains("impl Drop for EpochDriver {"));
    assert!(TYPED_EXECUTION_SOURCE.contains("no compile-cancellation or compile-abort"));
    // CONVERTED: the executed proof is the `TypedStage::Compile.as_str()` /
    // staged-rendering pair added above, bound to production
    // `bins/eliot-wasm-host/src/typed_execution.rs:130`, `:139-143` and `:323`.
    assert!(TYPED_EXECUTION_SOURCE.contains("Self::Compile => \"compile\","));
}

// WORK_UNIT_CASE: 758/15
#[test]
fn memory_growth_and_memory_count_bounds_are_enforced() {
    // Real engine, real CHECKED-IN input: the `memory-growth` fixture allocates
    // until a grow is refused. The pinned `StoreLimits` denies growth softly,
    // so `memory.grow` returns -1, the guest runs to completion, and the recorded
    // limit hit still denies the call at the cleanup stage.
    let grower = load_fixture_file("memory-growth");
    let digest = Sha256Digest::of_bytes(&grower);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &grower, &limits),
        &staged(TypedStage::Cleanup, engine("MemoryLimit")),
    );

    // Positive control: a growth inside the admitted ceiling is ALLOWED and its
    // measurement reaches the receipt, so the denial above is the ceiling and
    // not a broken growth callback.
    let grower = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            kind: DescribeKind::GrowOnePage,
            ..CueOptions::default()
        },
    );
    let mut roomy = default_experimental_limits(Sha256Digest::of_bytes(&grower));
    roomy.max_memory_bytes = 131_072;
    let (receipt, _) = must(
        run_describe(TypedWorld::CueActivation, &grower, &roomy).map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.terminal, "Completed");
    assert_eq!(receipt.peak_memory_bytes, Some(131_072));

    // And with the default one-page ceiling the very same bytes deny.
    let strict = default_experimental_limits(Sha256Digest::of_bytes(&grower));
    require_denied(
        run_describe(TypedWorld::CueActivation, &grower, &strict),
        &staged(TypedStage::Cleanup, engine("MemoryLimit")),
    );

    // THE MEMORY-COUNT HALF, EXECUTED. `MAX_TYPED_MEMORIES = 1` reaches the
    // engine as the Store's memory count (`Store::limiter` snapshots
    // `ResourceLimiter::memories` as `StoreOpaque::memory_limit`,
    // wasmtime-47.0.4 `src/runtime/store.rs:936-943`), and the count is checked
    // by `StoreOpaque::bump_resource_counts`
    // (`src/runtime/store.rs:1519-1543`, bail at `:1523`, reached from
    // `Instance::new_raw` at `src/runtime/instance.rs:309` via the component's
    // own core-module instantiation at
    // `src/runtime/component/instance.rs:838-841`) BEFORE any memory is
    // allocated and therefore before `memory_growing` can ever run. Two
    // consequences this leg pins down, both read off the executed value:
    // `limit_hit` stays `None`, so the count refusal is NOT typed as a memory
    // ceiling by this Host; and `map_instantiate_error`
    // (`src/typed_execution.rs:1322-1355`, `fn map_instantiate_error`) cannot
    // classify it either --
    // `is_instance_limit_error` requires "instance" in the message
    // (`src/wasmtime_provider.rs:767-770`) and the memory-count bail spells
    // "memory count too high", so the check misses; a `bail!` message is not a
    // `wasmtime::Trap`, so `trap_termination` returns `None`; and the message
    // matches none of "import"/"export"/"missing"/"type".
    //
    // So the real, observable denial is the staged GENERIC component-error
    // instantiation denial, and that is what is asserted. The ceiling is
    // enforced by the Store limiter, not TYPED as a memory ceiling by the
    // host: `MAX_TYPED_MEMORIES` bounds the count and the excess component is
    // refused, but the refusal carries no memory-count code of its own. The
    // discriminator is the identical `GrowOnePage` component above, built by
    // the same generator one memory shorter, which completes under the same
    // envelope -- so the second declared memory is what causes this denial.
    let two_memories = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            extra_core_memory: true,
            ..CueOptions::default()
        },
    );
    let count_limits = default_experimental_limits(Sha256Digest::of_bytes(&two_memories));
    let Err(observed_count_refusal) =
        run_describe(TypedWorld::CueActivation, &two_memories, &count_limits)
    else {
        panic!("a component declaring more memories than the configured maximum must be refused");
    };
    assert_eq!(
        observed_count_refusal,
        staged(
            TypedStage::Instantiate,
            engine("instantiate:component-error")
        ),
        "the memory-count ceiling is refused, not typed as a memory ceiling"
    );
    assert_eq!(
        denial_of(&observed_count_refusal),
        "STAGE:instantiate:ENGINE:instantiate:component-error"
    );

    // Declared source guard for the memory-COUNT ceiling: `InvocationLimits`
    // carries no memory count, so the Host fixes it and forwards it to the
    // engine's `StoreLimits` (a refused growth sets the recorded limit hit).
    //
    // CONVERTED (already executed), each guard named, all bound to
    // `bins/eliot-wasm-host/src/typed_execution.rs`:
    // - `MAX_TYPED_MEMORIES = 1` (`:55`) and `.memories(MAX_TYPED_MEMORIES)`
    //   (`:1423`): the `two_memories` leg above declares TWO core memories and
    //   is refused at instantiation, while the byte-identical-one-memory
    //   component from the same generator completes under the same envelope.
    //   One is the only ceiling that makes those two outcomes differ.
    // - `.memory_size(usize::try_from(limits.max_memory_bytes))` (`:1422`): the
    //   sub-page leg below sets `max_memory_bytes = 32_768` against a
    //   component whose declared minimum is one page and gets a
    //   `staged(Instantiate, engine("MemoryLimit"))` denial. A ceiling that
    //   were not forwarded could not refuse the component at all.
    // - `self.limit_hit.get_or_insert(ResourceLimitHit::Memory)` (`:1463`):
    //   the cause `MemoryLimit` is produced ONLY by `resource_limit_error`
    //   (`:1270-1276`, `:1272`) from a recorded `limit_hit`, and
    //   `map_instantiate_error` reads `limit_hit` before the engine message
    //   (`:1326-1328`). The memory-COUNT refusal above proves the converse,
    //   that a refusal with `limit_hit == None` surfaces as the generic
    //   `instantiate:component-error` instead.
    assert!(TYPED_EXECUTION_SOURCE.contains("const MAX_TYPED_MEMORIES: usize = 1;"));
    assert!(TYPED_EXECUTION_SOURCE.contains(".memories(MAX_TYPED_MEMORIES)"));
    assert!(
        TYPED_EXECUTION_SOURCE.contains(".memory_size(usize::try_from(limits.max_memory_bytes)")
    );
    assert!(
        TYPED_EXECUTION_SOURCE.contains("self.limit_hit.get_or_insert(ResourceLimitHit::Memory);")
    );
    // NOT CONVERTIBLE — UNAUTHORABLE FIXTURE (retained deliberately). This is
    // the POST-APPROVAL growth-failure path
    // (`bins/eliot-wasm-host/src/typed_execution.rs:1468-1472`), and the pinned
    // engine makes it unreachable from any authored component. Reaching it needs
    // the limiter to ALLOW a growth and the allocation to fail afterwards; every
    // Wasm-reachable refusal is decided BEFORE approval: `Memory::grow`
    // There are EXACTLY TWO call sites of `memory_grow_failed` in the pinned
    // engine's memory-growth path, and BOTH are unreachable from an authored
    // component. An earlier version of this comment named only the second and
    // was therefore incomplete.
    //
    // (1) `memory.rs:641-646` — reached only when
    // `!self.ty().allow_growth_to(new_byte_size)`, i.e. a growth this linear
    // memory's TYPE cannot represent. `allow_growth_to` returns `true`
    // immediately for any memory with a non-default page size and otherwise
    // admits growth for the standard 64 KiB-page memories these fixtures
    // declare, so this branch is not taken. A limiter failure here would call
    // `memory_grow_failed` at `:644` BEFORE the store limiter ever approves,
    // which is why the approval story below does not cover this path.
    //
    // (2) `memory.rs:715-724` — reached only when the underlying HOST
    // allocator's `grow_to` returns an error, i.e. a real allocation failure,
    // after the store limiter has already approved. A guest-declared maximum
    // cannot get here: `StoreLimits::memory_growing` returns `Ok(false)` for
    // `desired > limit` and for `desired > maximum`, so the growth is refused
    // at `:650-657` and the closure holding the "Memory maximum size exceeded"
    // bail at `:666-670` never runs. An authored component cannot provoke a
    // host allocation failure either.
    //
    // Escalated, not weakened: the growth-refusal proof this file does have is
    // the `memory_growing` not-allowed branch exercised by the `memory-growth`
    // fixture above, which is a different production line.
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("fn memory_grow_failed(&mut self, _error: wasmtime::Error)")
    );

    // THE MEMORY-BYTE CEILING ITSELF, TIGHTENED BELOW THE DECLARED MINIMUM AND
    // EXECUTED. Every leg above varies the ceiling by whole pages and always
    // reaches `describe`; this leg drops `max_memory_bytes` to HALF a page,
    // below the single page every fixture here declares as its memory minimum,
    // so the engine refuses the component BEFORE any linear memory exists and
    // the denial lands on a different stage and a different code. That is the
    // one shape the source guard above cannot produce: it needs the forwarded
    // ceiling to reach the Store's limiter, not a line of owner text.
    //
    // Where the refusal is produced, verified by opening each range:
    // - the ceiling is `limits.max_memory_bytes`, forwarded to
    //   `wasmtime::StoreLimitsBuilder::memory_size`
    //   (`src/typed_execution.rs:1422`), and `StoreLimits::memory_growing`
    //   returns `Ok(false)` for any `desired > limit`
    //   (wasmtime-47.0.4 `src/runtime/limits.rs:337-355`, the comparison at
    //   `:344`);
    // - the limiter is consulted BEFORE the memory is allocated, from
    //   `Memory::new_dynamic` (`src/runtime/vm/memory.rs:249`) into
    //   `Memory::limit_new` (`src/runtime/vm/memory.rs:299-354`), whose
    //   `limiter.memory_growing(0, minimum, maximum)` at `:344-348` bails at
    //   `:349` when the limiter says no; the component's own core instance
    //   reaches that allocator through `Instance::new_raw`'s
    //   `allocate_instance(limiter.as_deref_mut(), ...)`
    //   (`src/runtime/instance.rs:327-336`) called from the component
    //   initializer (`src/runtime/component/instance.rs:838-841`);
    // - this Host records the refusal: `StoreState::memory_growing` stores
    //   `ResourceLimitHit::Memory` in `limit_hit` on the not-allowed branch
    //   (`src/typed_execution.rs:1446-1466`, `:1462-1464`);
    // - and `map_instantiate_error` consults `limit_hit` FIRST, before it reads
    //   the engine message at all (`src/typed_execution.rs:1326-1328`), so the
    //   typed cause is the owner-typed `MemoryLimit` from
    //   `resource_limit_error` (`src/typed_execution.rs:1270-1276`, mapping
    //   `ResourceLimitHit::Memory` to `EngineTermination::MemoryLimit` at
    //   `:1272`), NOT a substring of the engine's own "memory minimum size of
    //   1 pages exceeds memory limits" bail. No generic internal-error prose is
    //   reported as normal control behaviour: the cause is the exact owner-typed
    //   limit code.
    //
    // The stage is the one actually reached -- component instantiation, before
    // the descriptor call -- from `describe_cue_activation`'s instantiate arm
    // (`src/typed_execution.rs:1711-1717`), so it is `Instantiate`, not the
    // `Cleanup` the soft growth refusal above reports.
    //
    // Half a page is as far below as this lane can go: a ZERO ceiling is refused
    // by the Host's own envelope validation (`src/typed_execution.rs:511-524`)
    // as `LIMIT_DENIED:envelope` before the engine is ever built, so it would
    // prove the envelope gate, not the Store ceiling.
    //
    // The component is the byte-identical one the completing and denying legs
    // above already drive, which is asserted rather than assumed, so the ONLY
    // difference between the completed receipt and this denial is the ceiling.
    let half_page = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            kind: DescribeKind::GrowOnePage,
            ..CueOptions::default()
        },
    );
    assert_eq!(
        half_page, grower,
        "the tightened-ceiling leg must drive the identical component bytes as the legs above"
    );
    let mut sub_page = default_experimental_limits(Sha256Digest::of_bytes(&half_page));
    sub_page.max_memory_bytes = 32_768;
    let Err(observed_byte_ceiling) = run_describe(TypedWorld::CueActivation, &half_page, &sub_page)
    else {
        panic!("a memory ceiling below the declared one page must refuse the component");
    };
    assert_eq!(
        observed_byte_ceiling,
        staged(TypedStage::Instantiate, engine("MemoryLimit")),
        "the tightened memory-byte ceiling must refuse at instantiation with the typed cause"
    );
    assert_eq!(
        denial_of(&observed_byte_ceiling),
        "STAGE:instantiate:ENGINE:MemoryLimit"
    );
}

// WORK_UNIT_CASE: 758/16
#[test]
fn table_instance_and_resource_bounds_are_enforced() {
    // Real engine, real CHECKED-IN input: the `table-exhaustion` fixture allocates
    // table elements until a grow is refused. As with memory, the pinned
    // `StoreLimits` denies softly, so `table.grow` returns -1 and the recorded
    // limit hit denies the call at the cleanup stage.
    let grower = load_fixture_file("table-exhaustion");
    let digest = Sha256Digest::of_bytes(&grower);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &grower, &limits),
        &staged(TypedStage::Cleanup, engine("TableLimit")),
    );

    // Real engine: two core instances under a one-instance ceiling deny at
    // instantiation.
    let two_instances = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            extra_core_module: true,
            ..CueOptions::default()
        },
    );
    let mut starved = default_experimental_limits(Sha256Digest::of_bytes(&two_instances));
    starved.max_instances = 1;
    require_denied(
        run_describe(TypedWorld::CueActivation, &two_instances, &starved),
        &staged(TypedStage::Instantiate, engine("InstanceLimit")),
    );

    // Positive control: the honest CHECKED-IN `dreamer-cycle` fixture still
    // executes under the default ceilings, so the two denials above are the
    // ceilings and not a broken component.
    let cooperative = real_cycle_fixture();
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    let (receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.terminal, "Completed");
    assert_eq!(receipt.instances, PRODUCTION_SUCCESS_INSTANCES);

    // Declared source guard: table elements/count and instance count are all
    // forwarded to the engine's `StoreLimits`.
    //
    // CONVERTED (already executed), each guard named, all bound to
    // `bins/eliot-wasm-host/src/typed_execution.rs`:
    // - `MAX_TYPED_TABLES = 1` (`:58`) and `.tables(MAX_TYPED_TABLES)` (`:1425`):
    //   the `two_tables` leg below declares TWO core tables and is refused at
    //   instantiation, while the same generator's one-table component completes
    //   under the same ceilings and envelope.
    // - `.table_elements(usize::try_from(limits.max_table_elements))` (`:1424`):
    //   the `table-exhaustion` denial above at the default eight elements and
    //   the `one_element` denial below at one element are the SAME fixture
    //   under two ceilings, so the forwarded value is what moved.
    // - `.instances(usize::try_from(limits.max_instances))` (`:1426`): the
    //   `two_instances` leg above sets `max_instances = 1` against a
    //   two-core-instance component and gets
    //   `staged(Instantiate, engine("InstanceLimit"))`.
    // - `fn table_growing(` (`:1474`): the `TableLimit` cause above and below
    //   exists only via `resource_limit_error` (`:1270-1276`, `:1273`) from a
    //   recorded `limit_hit`, and the pinned engine decides every
    //   Wasm-reachable table refusal inside that call —
    //   `StoreLimits::table_growing` returns `Ok(false)` for `desired > limit`
    //   (wasmtime-47.0.4 `src/runtime/limits.rs:366-384`, `:373`) and for
    //   `desired > maximum` (`:375`), so the not-allowed branch at `:1486` is
    //   the one that runs.
    // - `if is_instance_limit_error(error) {` (`:1332`): `InstanceLimit` is
    //   produced only at `:1333` inside that branch, so the `two_instances`
    //   denial is the executed witness; the `two_memories` and `two_tables`
    //   denials, whose engine messages do not match that classifier, land on
    //   the generic `:1352-1353` fallback instead, which is the discriminator.
    assert!(TYPED_EXECUTION_SOURCE.contains("const MAX_TYPED_TABLES: usize = 1;"));
    assert!(TYPED_EXECUTION_SOURCE.contains(".tables(MAX_TYPED_TABLES)"));
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains(".table_elements(usize::try_from(limits.max_table_elements)")
    );
    assert!(TYPED_EXECUTION_SOURCE.contains(".instances(usize::try_from(limits.max_instances)"));
    assert!(TYPED_EXECUTION_SOURCE.contains("fn table_growing("));
    assert!(TYPED_EXECUTION_SOURCE.contains("if is_instance_limit_error(error) {"));

    // THE TABLE-ELEMENT CEILING, TIGHTENED AND EXECUTED. The default admits
    // EIGHT elements (`default_experimental_limits`,
    // `src/typed_execution.rs:471`); this leg admits ONE, which is exactly the
    // fixture's own declared table minimum `(table 1 256 funcref)`
    // (`tests/data/typed-components/table-exhaustion.wat:127`), so the guest is
    // refused its very first `table.grow`. The refusal is still the engine's own
    // soft refusal: `wasmtime::StoreLimits::table_growing` returns `Ok(false)`
    // for any `desired > limit` (wasmtime-47.0.4 `src/runtime/limits.rs:366-384`,
    // the comparison at `:373`), so `table.grow` returns -1, the guest runs to
    // completion, and `StoreState::table_growing` records
    // `ResourceLimitHit::Table` in `limit_hit` on the not-allowed branch
    // (`src/typed_execution.rs:1474-1489`, `:1485-1487`). `run_guarded` then
    // denies the COMPLETED call at teardown from that recorded hit
    // (`src/typed_execution.rs:1591` and `:1593-1606`, the staged refusal at
    // `:1596`), which `resource_limit_error` renders as the owner-typed
    // `TableLimit` (`src/typed_execution.rs:1270-1276`, mapping
    // `ResourceLimitHit::Table` to `EngineTermination::TableLimit` at `:1273`).
    // The tightened value is therefore not decoration: it is what moves the
    // refusal from the tail of the guest's growth attempts to its very first
    // one, and the denial still names the ceiling that refused it. One element is
    // the floor this lane can reach: a ZERO ceiling is refused by the Host's own
    // envelope validation (`src/typed_execution.rs:511-524`) as
    // `LIMIT_DENIED:envelope` before any engine work, and the fixture's declared
    // one-element minimum is already admitted at a ceiling of one, so an
    // instantiation-time element refusal is unreachable here and is NOT claimed.
    let mut one_element = default_experimental_limits(Sha256Digest::of_bytes(&grower));
    one_element.max_table_elements = 1;
    let Err(observed_element_ceiling) =
        run_describe(TypedWorld::DreamerCycle, &grower, &one_element)
    else {
        panic!("a one-element table ceiling must refuse a fixture that grows its table");
    };
    assert_eq!(
        observed_element_ceiling,
        staged(TypedStage::Cleanup, engine("TableLimit")),
        "the tightened table-element ceiling must produce the exact typed refusal"
    );
    assert_eq!(
        denial_of(&observed_element_ceiling),
        "STAGE:cleanup:ENGINE:TableLimit"
    );

    // THE TABLE-COUNT CEILING, EXECUTED. `MAX_TYPED_TABLES = 1` is a Host
    // constant with no `InvocationLimits` field behind it
    // (`src/typed_execution.rs:56-58`), forwarded to the engine's Store as
    // `StoreLimitsBuilder::tables` (`src/typed_execution.rs:1425`) and read back
    // through `StoreState::tables` (`src/typed_execution.rs:1501-1503`). This
    // component declares TWO core tables in the same core module, and the base
    // template declares none, so the engine really is asked to honour a count
    // of two against `MAX_TYPED_TABLES = 1`, and the count really is
    // checked: `Store::limiter` snapshots the limiter's `tables()` into
    // `StoreOpaque::table_limit` (wasmtime-47.0.4 `src/runtime/store.rs:936-943`,
    // assignment at `:942`), `StoreOpaque::bump_resource_counts` compares the
    // core module's DEFINED table count against it
    // (wasmtime-environ-47.0.4 `src/module.rs:566-570`; the comparison itself in
    // `src/runtime/store.rs:1519-1543`, the table `bump` at `:1540` over an
    // `if new > max` check whose own `bail!` is at `:1523`) and it runs from
    // `Instance::new_raw` (`src/runtime/instance.rs:309`) on the component's own
    // core instantiation (`src/runtime/component/instance.rs:838-841`), BEFORE
    // any table is allocated and therefore before `table_growing` can ever run.
    //
    // Three consequences, all read off the executed value and none invented:
    // `limit_hit` stays `None`, so this Host does NOT type a count refusal as a
    // table ceiling; `map_instantiate_error`
    // (`src/typed_execution.rs:1322-1355`) cannot classify it either --
    // `is_instance_limit_error` requires "instance" in the message
    // (`src/wasmtime_provider.rs:767-770`) and this bail spells "resource limit
    // exceeded: table count too high at 2"; the bail is not a `wasmtime::Trap`,
    // so `trap_termination` returns `None` (`src/typed_execution.rs:1293-1302`);
    // and the message matches none of "import"/"export"/"missing"/"type" in the
    // `:1346-1354` fallbacks. The real, observable denial is therefore the
    // staged generic component-error instantiation denial, asserted in full
    // below with its exact rendered string -- the ceiling IS enforced by the
    // Store limiter; it simply carries no table-count code of its own, and this
    // leg pins that down instead of pretending one exists. The discriminator is
    // the cooperative component, built by the same generator one table shorter,
    // which completes under the very same envelope.
    let two_tables = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            extra_core_table: true,
            ..CueOptions::default()
        },
    );
    let count_limits = default_experimental_limits(Sha256Digest::of_bytes(&two_tables));
    let Err(observed_table_count_refusal) =
        run_describe(TypedWorld::CueActivation, &two_tables, &count_limits)
    else {
        panic!("a component declaring more tables than the configured maximum must be refused");
    };
    assert_eq!(
        observed_table_count_refusal,
        staged(
            TypedStage::Instantiate,
            engine("instantiate:component-error")
        ),
        "the table-count ceiling is refused, not typed as a table ceiling"
    );
    assert_eq!(
        denial_of(&observed_table_count_refusal),
        "STAGE:instantiate:ENGINE:instantiate:component-error"
    );

    // The discriminator, executed: the same generator with no second table
    // completes under the same ceilings and the same envelope. The allow-listed
    // digest is the cooperative component's own preflight digest, so the only
    // difference from the refusing run above is the table count.
    let cooperative_single_table = cooperative_cue_artifact();
    let cooperative_limits =
        default_experimental_limits(Sha256Digest::of_bytes(&cooperative_single_table));
    assert_eq!(cooperative_limits.max_memory_bytes, 65_536);
    assert_eq!(cooperative_limits.max_table_elements, 8);
    let (cooperative_receipt, _) = must(
        run_describe(
            TypedWorld::CueActivation,
            &cooperative_single_table,
            &cooperative_limits,
        )
        .map_err(|error| error.to_string()),
    );
    assert_eq!(cooperative_receipt.terminal, "Completed");
    assert_eq!(cooperative_receipt.instances, PRODUCTION_SUCCESS_INSTANCES);
}

// WORK_UNIT_CASE: 758/17
#[test]
fn a_guest_typed_error_is_distinct_from_a_trap() {
    // The name covers both halves of one distinction; they live in two places,
    // and this comment says which is which, because the halves are not reachable
    // from the same place.
    //
    // THE TYPED-ERR HALF IS PROVEN IN-CRATE, NOT HERE. It is proven in
    // `src/typed_execution.rs` by the named helper
    // `six_world_capsule_drive::assert_guest_typed_error_is_a_distinct_executed_outcome_from_a_trap`,
    // called from
    // `every_frozen_world_executes_its_real_domain_export_through_the_neutral_capsule`
    // (`src/typed_execution.rs:5673-5674` declares the test, `:5693` is the
    // call: `every_frozen_world_executes_its_real_domain_export_through_the_neutral_capsule`
    // -> `assert_guest_typed_error_is_a_distinct_executed_outcome_from_a_trap`).
    // It cannot live in any `tests/` target,
    // and that is a reachability fact rather than a preference: the domain
    // entries take a `&TypedDomainRequest` whose variant payloads are
    // crate-private generated bindgen types, and `mod typed_bindings;` is
    // private in `src/lib.rs`, so an external test cannot construct the request
    // and cannot reach either domain entry at all (the crate states this in the
    // comment above
    // `every_frozen_world_executes_its_real_domain_export_through_the_neutral_capsule`,
    // `src/typed_execution.rs:5666-5672`, line 5669: "`mod typed_bindings`
    // is private in `src/lib.rs`"). That helper decides the typed-`Err`
    // branch from executed values only — the retained terminal result and the
    // terminal a terminated guest never produces. None of that is restated or
    // re-derived here, and this file previously stood in for it with
    // `TYPED_EXECUTION_SOURCE.contains(...)` checks: a search of the
    // production file's own text is not an execution, and those checks stayed
    // green even if the engine-to-`GuestError` mapping were deleted, so they
    // proved nothing and are gone.
    //
    // WHAT THIS TEST PROVES ON ITS OWN IS THE EXECUTED TRAP HALF: real
    // component bytes, the real Wasmtime engine, a real `(unreachable)` in the
    // guest's `describe`, and the typed denial the engine actually reports. This
    // overlaps case 18
    // (`the_unreachable_guest_path_is_a_trap_not_a_guest_error`), which asserts
    // the same executed denial and adds a positive control and the
    // not-rewritten-as-anything-else checks. The overlap is deliberate: the trap
    // obligation is real, and neither test substitutes for the other.
    let trapper = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            kind: DescribeKind::Trap,
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&trapper);
    let limits = default_experimental_limits(digest);
    let Err(observed_trap) = run_describe(TypedWorld::CueActivation, &trapper, &limits) else {
        panic!("a trapped guest must not produce a receipt");
    };
    assert_eq!(
        observed_trap,
        staged(TypedStage::Descriptor, engine("Trap(GuestTrap)"))
    );
}

// WORK_UNIT_CASE: 758/18
#[test]
fn the_unreachable_guest_path_is_a_trap_not_a_guest_error() {
    let trapper = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            kind: DescribeKind::Trap,
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&trapper);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &trapper, &limits),
        &staged(TypedStage::Descriptor, engine("Trap(GuestTrap)")),
    );
    assert_eq!(
        denial_of(&staged(TypedStage::Descriptor, engine("Trap(GuestTrap)"))),
        "STAGE:descriptor:ENGINE:Trap(GuestTrap)"
    );

    // It is not rewritten as a guest error, an output violation, or a limit
    // denial.
    assert!(!matches!(
        run_describe(TypedWorld::CueActivation, &trapper, &limits),
        Err(TypedExecutionError::OutputViolation(_)
            | TypedExecutionError::LimitDenied(_)
            | TypedExecutionError::GovernedAdmissionRequired)
    ));

    // Positive control: the same component with a returning `describe`
    // completes, so the trap is caused by the unreachable instruction.
    let cooperative = cue_activation_artifact(&cooperative_guest(), &CueOptions::default());
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    let (receipt, _) = must(
        run_describe(TypedWorld::CueActivation, &cooperative, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.terminal, "Completed");
}

// WORK_UNIT_CASE: 758/19
#[test]
fn output_size_schema_and_identity_violations_are_denied() {
    // Over-long descriptor field: exact field name, output stage. Real CHECKED-IN
    // input (`output-oversize` reports 1024 bytes of `native-contract`).
    let oversize = load_fixture_file("output-oversize");
    let digest = Sha256Digest::of_bytes(&oversize);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &oversize, &limits),
        &staged(
            TypedStage::Output,
            TypedExecutionError::OutputViolation("native-contract".to_owned()),
        ),
    );

    // Output ceiling: the honest descriptor's measured output exceeds a tiny
    // admitted ceiling, reported as the engine's output termination.
    let cooperative = real_cycle_fixture();
    let mut tight = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    tight.max_output_bytes = 32;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &tight),
        &staged(TypedStage::Output, engine("OutputLimit")),
    );

    // Foreign world identity in the output: exact field name.
    let mut foreign = cooperative_guest();
    foreign.world_name = "dreamer-cycle".to_owned();
    assert_descriptor_denied(&foreign, "world-name");

    // Hostile lifted length: the guest reports a string length far past its
    // linear memory. The host refuses the lift itself rather than allocating
    // the declared size first.
    let hostile = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            world_len_override: Some(0xFFFF_FFFF),
            ..CueOptions::default()
        },
    );
    let digest = Sha256Digest::of_bytes(&hostile);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &hostile, &limits),
        &staged(TypedStage::Descriptor, engine("describe:component-call")),
    );

    // Declared source guard: the domain-leg hostile lifted list is refused by
    // the per-leaf list ceiling on the checked-in `host-lifting-list` fixture's
    // own terms (`MAX_TYPED_LIST_ITEMS`), never after the host allocated it.
    let lifting = load_fixture_file("host-lifting-list");
    let digest = Sha256Digest::of_bytes(&lifting);
    let limits = default_experimental_limits(digest);
    let (receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &lifting, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.terminal, "Completed");
    // NOT CONVERTIBLE (retained deliberately). This guard is a verbatim
    // duplicate of the case-9 guard, and `MAX_TYPED_LIST_ITEMS`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:52`) is read only by
    // `TypedBound::list` (`:855-869`), whose every caller is a `bound_*` walker
    // on the domain REQUEST path — `bound_request` is reached only from
    // `execute_domain_lane` (`:2107`), which needs a `&TypedDomainRequest` this
    // external test target cannot build. The executed leg above is the honest
    // half of this fixture: its `describe` really does run and complete, which
    // is what makes the domain leg's list ceiling reachable in-crate at all.
    assert!(TYPED_EXECUTION_SOURCE.contains("const MAX_TYPED_LIST_ITEMS: usize = 256;"));
}

// WORK_UNIT_CASE: 758/20
#[test]
fn proof_authority_and_effect_escalation_is_rejected() {
    // Identity escalation in the output: a guest cannot claim another world,
    // package or ABI revision.
    let mut foreign_world = cooperative_guest();
    foreign_world.world_name = "dreamer-handler".to_owned();
    assert_descriptor_denied(&foreign_world, "world-name");

    let mut foreign_package = cooperative_guest();
    foreign_package.package_id = "eliot:wasm@1.0.0".to_owned();
    assert_descriptor_denied(&foreign_package, "package-id");

    let mut foreign_revision = cooperative_guest();
    foreign_revision.abi_revision = TYPED_ABI_REVISION + 1;
    assert_descriptor_denied(&foreign_revision, "abi-revision");

    // Authority escalation through the governed envelope: a locator-shaped or
    // control-character identity is malformed, not a remote authority.
    let mut remote = governed_admission(
        TypedWorld::CueActivation,
        Sha256Digest::of_bytes(b"758-case-20"),
    );
    remote.policy_id = "https://kernel.invalid/authority".to_owned();
    require_governed(
        remote.validate(),
        &TypedExecutionError::LimitDenied("admission-field".to_owned()),
    );

    // Effect/proof escalation in the neutral contract: a kit whose ABI
    // revision is not the frozen one is invalid, and a descriptor field with a
    // control character is refused exactly.
    let artifact = cooperative_cue_artifact();
    let mut kit = world_kit(TypedWorld::CueActivation, &artifact);
    kit.abi.abi_revision = TYPED_ABI_REVISION + 1;
    assert_eq!(
        kit.validate(),
        Err(TypedContractError::InvalidKit("abi".to_owned()))
    );
    assert!(matches!(
        AbiDescriptor::new(
            NeutralWorld::CueActivation,
            "native\u{7}contract".to_owned(),
            "native-revision".to_owned(),
            typed_wit_digest(),
        ),
        Err(TypedContractError::DescriptorField(_))
    ));

    // The CHECKED-IN `raised-proof-ceiling` fixture is the domain-leg half of this
    // case: its `describe` is honest, so it reaches the domain export, and only
    // the claimed ceiling is raised to the top of the enum. On this lane the
    // denial is the identity/output gate below; the ceiling comparison itself is
    // the declared source guard at the end of this test, because reaching the
    // domain export needs a typed request an integration test cannot build.
    let raiser = load_fixture_file("raised-proof-ceiling");
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&raiser));
    let (receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &raiser, &limits).map_err(|error| error.to_string()),
    );
    assert_eq!(receipt.terminal, "Completed");

    // Declared source guard: a guest ceiling above the admitted ceiling is
    // refused by rank, never accepted because it is well formed.
    //
    // NOT CONVERTIBLE (retained deliberately). `check_ceiling`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:919-928`, the rank compare
    // at `:924`) has no caller outside the six `check_<world>_result` result
    // gates (`:3470`, `:3489`, `:3524`, `:3529`, `:3561`, `:3584`, `:3607`,
    // `:3635`), and those gates run only from `dispatch_domain` (`:3651`),
    // i.e. the domain RESULT path — which needs a `&TypedDomainRequest` and the
    // admitted echo identity this external test target cannot construct. The
    // `raised-proof-ceiling` leg above is the honest half that can run from
    // here: its `describe` really executes, which is what makes the domain
    // ceiling gate reachable in-crate.
    assert!(TYPED_EXECUTION_SOURCE.contains("fn check_ceiling("));
    assert!(TYPED_EXECUTION_SOURCE.contains("if observed > proof_rank(admitted) {"));
}

// WORK_UNIT_CASE: 758/21
#[test]
fn cancellation_preserves_the_actual_stage_and_cleanup() {
    let cooperative = real_cycle_fixture();
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    let (baseline, _) = must(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &limits)
            .map_err(|error| error.to_string()),
    );

    // Before compile/instantiate: envelope and admission denials happen with
    // no engine, and no stage is invented for them.
    let mut bad_stack = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    bad_stack.max_stack_bytes = 4_096;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &bad_stack),
        &TypedExecutionError::LimitDenied("stack".to_owned()),
    );
    let mut zero_epoch = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    zero_epoch.epoch.deadline_ticks = 0;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &zero_epoch),
        &TypedExecutionError::LimitDenied("epoch".to_owned()),
    );
    let mut starved_epoch = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    starved_epoch.epoch.deadline_ticks = 4_096;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &starved_epoch),
        &TypedExecutionError::LimitDenied("epoch".to_owned()),
    );
    let mut no_output = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    no_output.max_output_bytes = 0;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &no_output),
        &TypedExecutionError::LimitDenied("envelope".to_owned()),
    );
    let foreign = default_experimental_limits(Sha256Digest::of_bytes(b"758-not-this-buffer"));
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &foreign),
        &TypedExecutionError::AdmissionMismatch("cache-artifact".to_owned()),
    );

    // During bounded execution: the interruption reports the stage actually
    // reached and the run terminates.
    let spinner = load_fixture_file("deadline-no-fuel");
    let mut epoch_only = default_experimental_limits(Sha256Digest::of_bytes(&spinner));
    epoch_only.epoch.cancellation = CancellationPolicy::EpochInterruption;
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &spinner, &epoch_only),
        &staged(TypedStage::Descriptor, engine("EpochDeadline")),
    );

    // Cleanup: the interrupted call released its store, driver and per-call
    // engine, so the next call is byte-identical to the baseline.
    let (after, _) = must(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(after.semantic_digest, baseline.semantic_digest);
    assert_eq!(after.cache_identity, baseline.cache_identity);
    assert_eq!(after.stage, TypedStage::Cleanup.as_str());

    // EXECUTED PROOF that the interrupted call's PER-STORE measurement did not
    // survive it. `fuel_consumed` is read from that call's own store as
    // `budget - store.get_fuel()`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:1587-1590`) and is
    // deliberately EXCLUDED from `semantic_digest` (`:753-793` pushes no fuel
    // field), so it is an independent observation the next call had to
    // reproduce from its own store. The two equalities above cannot show this:
    // `semantic_digest` and `cache_identity` agree whether or not a store's
    // fuel counter leaked, so without this assertion the leak would be
    // invisible.
    assert_eq!(
        after.fuel_consumed, baseline.fuel_consumed,
        "the interrupted call's fuel measurement must not survive into the next call"
    );

    // Declared source guard: the epoch driver is joined in `Drop`, so every
    // exit path tears the driver down before the engine is dropped.
    //
    // CONVERTED (partially; scope stated precisely). All four guards describe
    // `bins/eliot-wasm-host/src/typed_execution.rs:1559-1566` (`Drop`:
    // `stop.store` at `:1561`, `handle.join()` at `:1563`) and the explicit
    // `drop(driver)` at `:1586`, which runs AFTER the closure returns on every
    // exit path, including the `EpochDeadline` exit this test just executed.
    // The executed witness is the pair above: the interrupted call's
    // store-scoped fuel measurement is gone, and the next call's is its own.
    // What is NOT claimed: whether the driver THREAD was joined, as
    // opposed to merely left harmless, is unobservable from outside the crate —
    // no exported symbol exposes driver state, and the observable difference
    // between the two is timing only. Guard kept for that narrower claim.
    assert!(TYPED_EXECUTION_SOURCE.contains("impl Drop for EpochDriver {"));
    assert!(TYPED_EXECUTION_SOURCE.contains("self.stop.store(true, Ordering::Release);"));
    assert!(TYPED_EXECUTION_SOURCE.contains("let _ = handle.join();"));
    assert!(TYPED_EXECUTION_SOURCE.contains("drop(driver);"));
}

// WORK_UNIT_CASE: 758/22
#[test]
fn cache_identity_binds_artifact_policy_abi_and_engine() {
    let artifact = real_cycle_fixture();
    let digest = Sha256Digest::of_bytes(&artifact);
    let limits = default_experimental_limits(digest.clone());

    // DETERMINISM CONTROL, NOT EVIDENCE THAT A SLOT IS BOUND. Both receipts
    // below come from the ONE `dreamer-cycle` buffer under the ONE envelope
    // `limits`, so `cache_identity` and `semantic_digest` are each a pure
    // function of that single (artifact, envelope, world) input. Neither
    // comparison varies anything, so neither can attribute an identity to a
    // slot: `cache_identity` is a pure function of one input, and
    // `semantic_digest` (`src/typed_execution.rs:753-793`) is strictly broader
    // because it also folds in the output, stage and terminal, so it is a wider
    // determinism control rather than an independent confirmation of the
    // cache-identity slot. Both are kept because determinism across two
    // independent real invocations is worth asserting. The evidence that a slot
    // is BOUND is the `assert_ne!` legs below.
    let (first, _) = must(
        run_describe(TypedWorld::DreamerCycle, &artifact, &limits)
            .map_err(|error| error.to_string()),
    );
    let (second, _) = must(
        run_describe(TypedWorld::DreamerCycle, &artifact, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(first.cache_identity, second.cache_identity);
    assert_eq!(first.semantic_digest, second.semantic_digest);
    // Real execution on both calls, not a cache pass: the receipt is produced
    // only after the component was instantiated and the descriptor was called.
    assert_eq!(first.instances, PRODUCTION_SUCCESS_INSTANCES);
    assert_eq!(first.stage, TypedStage::Cleanup.as_str());
    assert_eq!(second.stage, TypedStage::Cleanup.as_str());

    // Policy is bound, ISOLATED: `max_output_bytes` reaches
    // `typed_policy_digest` (`src/typed_execution.rs:658`) and does NOT reach
    // `typed_engine_configuration_digest` (`:641`, which binds version, target,
    // fuel/epoch mode, stack, memory/table/instances), so this leg moves the
    // policy slot alone.
    let mut other_policy = default_experimental_limits(digest.clone());
    other_policy.max_output_bytes += 1;
    let (policy_receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &artifact, &other_policy)
            .map_err(|error| error.to_string()),
    );
    assert_ne!(policy_receipt.cache_identity, first.cache_identity);

    // POLICY SLOT, ISOLATED ON THE ADMITTED ALLOW-LIST ALONE — and this is the
    // leg that carries the `typed_policy_digest` guard below. Widening the
    // allow-list moves `typed_policy_digest`'s allow-list tail and NOTHING
    // else: `artifact` is the presented buffer's own digest and `artifact_bytes`
    // its own length, and `typed_engine_configuration_digest`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:639-650`) reads only
    // `max_memory_bytes`, `max_table_elements`, `max_instances`, `consume_fuel`
    // and compile-time constants — never the allow-list. Same buffer, same
    // world, same every ceiling: the artifact digest and length equalities
    // below assert that, so a composed identity that failed to bind the
    // allow-list would report the same `cache_identity` for both runs. The
    // added digest belongs to no artifact presented here, so it cannot change
    // what executed.
    let mut widened = default_experimental_limits(digest.clone());
    widened
        .artifact_access
        .allowed_digests
        .insert(Sha256Digest::of_bytes(b"758-unrelated-admitted-artifact"));
    let (widened_receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &artifact, &widened)
            .map_err(|error| error.to_string()),
    );
    // ISOLATION PRECONDITIONS, NOT PROOF. These three state what this leg
    // deliberately holds constant. Both runs execute the SAME buffer, so both
    // sides' `artifact_digest`, `artifact_bytes` and `wit_digest` are read off
    // that one buffer by production and are equal for every possible
    // production state: they are controls, and they are kept because they
    // document the precondition that makes the assertion below meaningful. The
    // PROOF is the single `assert_ne!` that follows, and it is the one a
    // production change can turn red.
    assert_eq!(
        widened_receipt.artifact_digest, first.artifact_digest,
        "only the admitted allow-list may move in this leg"
    );
    assert_eq!(
        widened_receipt.artifact_bytes, first.artifact_bytes,
        "only the admitted allow-list may move in this leg"
    );
    assert_eq!(
        widened_receipt.wit_digest, first.wit_digest,
        "the ABI binding must be unchanged when only the allow-list moves"
    );
    assert_ne!(
        widened_receipt.cache_identity, first.cache_identity,
        "the admitted artifact allow-list must be bound into the cache identity"
    );

    // Engine configuration is bound: different memory/table/instance ceilings
    // are a different identity even with the same artifact and world.
    //
    // PRECISE SCOPE, because the evidence must not be overstated: as composed,
    // every limit-derived engine input (`max_memory_bytes`,
    // `max_table_elements`, `max_instances`, and the `epoch.cancellation`-driven
    // `consume_fuel`) is ALSO a field of `typed_policy_digest`
    // (`src/typed_execution.rs:658-666`), and the only engine-digest inputs the
    // policy digest omits are compile-time constants (`:639-650`: `ENGINE_VERSION`,
    // target, `PROVIDER_STACK_SIZE`, `MAX_TYPED_MEMORIES`, `MAX_TYPED_TABLES`).
    // This leg therefore proves the ceiling is bound INTO the identity; it
    // cannot, from an integration test, separate the engine slot from the
    // policy slot, because `TypedCacheIdentity` is private
    // (`src/typed_execution.rs:601`) and its per-slot digests are not exported
    // (`src/lib.rs:108-114`). Reported as the missing production surface; the
    // policy leg above is the isolated one.
    let mut other_engine = default_experimental_limits(digest.clone());
    other_engine.max_memory_bytes = 131_072;
    let (engine_receipt, _) = must(
        run_describe(TypedWorld::DreamerCycle, &artifact, &other_engine)
            .map_err(|error| error.to_string()),
    );
    assert_ne!(engine_receipt.cache_identity, first.cache_identity);

    // Artifact is bound: a different byte sequence is a different identity.
    //
    // This leg moves the artifact AND the world AND the policy allow-list at
    // once (`first` is `dreamer-cycle`, this runs `cue-activation`, and each
    // envelope allow-lists only its own digest, which `typed_policy_digest`
    // folds in at `src/typed_execution.rs:673-676`), so on its own it proves
    // only that this other component is a different identity. The isolated
    // artifact proof is the paired leg immediately below it.
    let mut other_fields = cooperative_guest();
    other_fields.native_revision = "fixture-native-revision-2".to_owned();
    let other_artifact = cue_activation_artifact(&other_fields, &CueOptions::default());
    let other_limits = default_experimental_limits(Sha256Digest::of_bytes(&other_artifact));
    let (artifact_receipt, _) = must(
        run_describe(TypedWorld::CueActivation, &other_artifact, &other_limits)
            .map_err(|error| error.to_string()),
    );
    assert_ne!(artifact_receipt.cache_identity, first.cache_identity);
    assert_ne!(artifact_receipt.artifact_digest, first.artifact_digest);

    // Artifact slot, ISOLATED. Same world (`CueActivation` for both), same
    // ceilings, and ONE envelope whose allow-list carries BOTH digests, so
    // `typed_policy_digest` is byte-identical across the two runs and
    // `typed_engine_configuration_digest` and `typed_abi_digest` are unchanged
    // by construction. The artifact digest and its length are therefore the only
    // inputs that differ, and a composed identity that did not bind them would
    // report the same `cache_identity` for both.
    let paired_base = cooperative_cue_artifact();
    let mut paired_limits = default_experimental_limits(Sha256Digest::of_bytes(&paired_base));
    paired_limits
        .artifact_access
        .allowed_digests
        .insert(Sha256Digest::of_bytes(&other_artifact));
    let (paired_first, _) = must(
        run_describe(TypedWorld::CueActivation, &paired_base, &paired_limits)
            .map_err(|error| error.to_string()),
    );
    let (paired_second, _) = must(
        run_describe(TypedWorld::CueActivation, &other_artifact, &paired_limits)
            .map_err(|error| error.to_string()),
    );
    // `world`, `engine_version` and `wit_digest` are held CONSTANT BY
    // CONSTRUCTION in this pair and are deliberately NOT asserted: both calls
    // pass the same `TypedWorld::CueActivation` literal and the same
    // `paired_limits` value, and production assigns `world` from that literal,
    // `engine_version` from `ENGINE_VERSION` and `wit_digest` from
    // `typed_wit_digest()` unconditionally. Comparing those three would
    // compare a constant with itself and could not fail, which is a stand-in
    // rather than evidence. The three assertions below are the load-bearing
    // ones, and they are the ones a production change can turn red.
    assert_ne!(paired_first.artifact_digest, paired_second.artifact_digest);
    assert_ne!(paired_first.artifact_bytes, paired_second.artifact_bytes);
    assert_ne!(paired_first.cache_identity, paired_second.cache_identity);

    // ABI/world is bound: another frozen world's real component has a
    // different identity.
    //
    // PRECISE SCOPE: as above, this leg moves the artifact, its length, the
    // world and the policy allow-list together, because a component's exported
    // interface IS its world, so no integration test can hold the artifact fixed
    // while changing the ABI slot. It proves a different frozen world is a
    // different identity; isolating the ABI slot needs the per-slot digest of
    // `TypedCacheIdentity.abi` (`src/typed_execution.rs:610`), which production
    // does not export. Reported as the missing production surface.
    let other_world = load_fixture(TypedWorld::ContextAdmission);
    let world_limits = default_experimental_limits(Sha256Digest::of_bytes(&other_world));
    let (world_receipt, _) = must(
        run_describe(TypedWorld::ContextAdmission, &other_world, &world_limits)
            .map_err(|error| error.to_string()),
    );
    assert_ne!(world_receipt.cache_identity, first.cache_identity);

    // Declared source guard: the identity is exactly artifact+length+engine
    // configuration+ABI+policy, and carries no name, path, generation, fence
    // or proof value.
    //
    // MIXED, each guard named (all retained):
    // - `typed_policy_digest` (`:656`): CONVERTED. The new `widened` leg above
    //   executes the allow-list tail of that function's canonical string
    //   (`:673-676`) in isolation — same buffer, same world, same ceilings, only
    //   the admitted allow-list widened — so the denial-free identity change
    //   below is attributable to the policy slot and to nothing else.
    // - `struct TypedCacheIdentity {` (`:601`) and the five-slot format string
    //   (`:619`): NOT CONVERTIBLE. The struct is private and the per-slot
    //   digests are never exported (`src/lib.rs:108-114` re-exports the receipt
    //   but no `TypedCacheIdentity` surface), so only the folded digest is
    //   observable; the SLOT COUNT and the exact separator/order cannot be
    //   falsified by execution from an integration test target. Escalated: the
    //   missing surface is the per-slot digests of
    //   `bins/eliot-wasm-host/src/typed_execution.rs:602-612`.
    // - `typed_engine_configuration_digest` (`:639`) and `typed_abi_digest`
    //   (`:683`): NOT CONVERTIBLE, and the two PRECISE SCOPE comments above
    //   already state why — every limit-derived engine input is also a policy
    //   input, so no envelope can move the engine slot alone, and a component's
    //   exported interface IS its world, so no buffer can move the ABI slot
    //   alone. Escalated: the same missing per-slot surface.
    assert!(TYPED_EXECUTION_SOURCE.contains("struct TypedCacheIdentity {"));
    assert!(TYPED_EXECUTION_SOURCE.contains("\"758-typed-cache-identity|{}|{}|{}|{}|{}\""));
    assert!(
        TYPED_EXECUTION_SOURCE
            .contains("fn typed_engine_configuration_digest(limits: &InvocationLimits)")
    );
    // CONVERTED: the executed `widened_receipt.cache_identity !=
    // first.cache_identity` assertion above, bound to production
    // `bins/eliot-wasm-host/src/typed_execution.rs:673-676`.
    assert!(TYPED_EXECUTION_SOURCE.contains("fn typed_policy_digest(limits: &InvocationLimits)"));
    assert!(TYPED_EXECUTION_SOURCE.contains("fn typed_abi_digest(world: TypedWorld)"));
}

// WORK_UNIT_CASE: 758/23
#[test]
fn a_failed_invocation_does_not_contaminate_the_next_one() {
    let cooperative = real_cycle_fixture();
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&cooperative));
    let (baseline, _) = must(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &limits)
            .map_err(|error| error.to_string()),
    );
    let (baseline_repeat, _) = must(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(baseline.semantic_digest, baseline_repeat.semantic_digest);

    // Two independent failures on real input: a guest trap and fuel exhaustion at
    // the descriptor stage.
    let trapper = cue_activation_artifact(
        &cooperative_guest(),
        &CueOptions {
            kind: DescribeKind::Trap,
            ..CueOptions::default()
        },
    );
    let trap_limits = default_experimental_limits(Sha256Digest::of_bytes(&trapper));
    require_denied(
        run_describe(TypedWorld::CueActivation, &trapper, &trap_limits),
        &staged(TypedStage::Descriptor, engine("Trap(GuestTrap)")),
    );
    let spinner = load_fixture_file("looping-describe");
    let spin_limits = default_experimental_limits(Sha256Digest::of_bytes(&spinner));
    require_denied(
        run_describe(TypedWorld::DreamerCycle, &spinner, &spin_limits),
        &staged(TypedStage::Descriptor, engine("FuelExhausted")),
    );

    // The next independent call is byte-identical to the pre-failure baseline:
    // no store, fuel budget, epoch deadline or measurement carried over.
    let (after, _) = must(
        run_describe(TypedWorld::DreamerCycle, &cooperative, &limits)
            .map_err(|error| error.to_string()),
    );
    assert_eq!(after.semantic_digest, baseline.semantic_digest);
    assert_eq!(after.cache_identity, baseline.cache_identity);
    assert_eq!(after.artifact_digest, baseline.artifact_digest);
    assert_eq!(after.output_digest, baseline.output_digest);
    assert_eq!(after.terminal, "Completed");
    // `instances` is deliberately NOT asserted here. Production stamps it as the
    // bare literal `1` at both receipt construction sites, so it is not read
    // from a counter or from the store, and the earlier inference that "no Store
    // or instance handle survived the two failures" did not follow from it: both
    // assertions below would have held no matter what the two failures did. The
    // executed proof that each call measured its OWN store is the fuel and peak
    // measurement block immediately after this one, which compares values the
    // engine actually produced and therefore can fail.

    // EXECUTED PROOF that each call measured its OWN store. The two
    // observations below are read from the store of the call that produced
    // them (`bins/eliot-wasm-host/src/typed_execution.rs` fuel at the
    // `StoreState::finish_measurements` call and memory peak at the same
    // site) and are deliberately EXCLUDED from `semantic_digest`, so the
    // equalities above are blind to them: a leaked store, fuel budget or
    // measurement would leave `semantic_digest`, `cache_identity`, the
    // digests and the instance count untouched while moving these. Each can
    // fail, because production reads both off a real meter.
    assert_eq!(
        after.fuel_consumed, baseline.fuel_consumed,
        "a failed invocation must not leave its store's fuel measurement behind"
    );
    assert_eq!(
        after.peak_memory_bytes, baseline.peak_memory_bytes,
        "a failed invocation must not leave its store's peak-memory observation behind"
    );
    // `table_elements` is deliberately NOT asserted, and the reason is a fact
    // about the fixture rather than about the host. The honest cycle fixture
    // this case drives declares NO table at all — `dreamer-cycle.wat` has no
    // `(table ...)` form anywhere — so `StoreState::table_elements` is
    // initialised `None` and nothing ever writes it, because `observe_table`
    // is fed only by a `table_growing` callback that this module never
    // triggers. Both sides would therefore be `None`, and comparing `None`
    // with `None` passes for every possible production state: it is a
    // stand-in, not evidence. Observing a table here needs a fixture that
    // declares one, which is the `table-exhaustion` case's job and not this
    // one's.

    // Declared source guard: every call builds a fresh engine, component,
    // store and driver; this module holds no cross-invocation state.
    //
    // CONVERTED for the store (`:1583`, the first guard): the three executed
    // observation equalities above are the witness. They can only hold if the
    // third call built a store whose fuel counter, peak-memory tracker and
    // table-element tracker started empty, which is what
    // `wasmtime::Store::new(engine, StoreState { … peak_memory_bytes: None, …
    // })` at `bins/eliot-wasm-host/src/typed_execution.rs:1418-1434` provides
    // and only a per-call store can provide.
    assert!(TYPED_EXECUTION_SOURCE.contains("let mut store = new_store(engine, limits)?;"));
    // NOT CONVERTIBLE (retained deliberately). `EpochDriver::spawn` (`:1525`)
    // is reached from `run_guarded` (`:1584`) and its handle is dropped at
    // `:1586`; a private driver thread leaves no observable trace beyond the
    // epoch terminations case 13 and case 14 already execute, and no exported
    // symbol exposes driver state, so spawn/teardown cannot be falsified from
    // outside the crate. The observable consequence of a per-call driver — the
    // next call reproducing its own measurements — is the assertion above.
    assert!(TYPED_EXECUTION_SOURCE.contains("let driver = EpochDriver::spawn(engine, limits)?;"));
    // NOT CONVERTIBLE — NEGATIVE GLOBAL SCAN (retained deliberately). This
    // loop asserts the ABSENCE of five static/cell constructs anywhere in
    // `bins/eliot-wasm-host/src/typed_execution.rs`. An absence claim over a
    // whole owner file's text has no executed witness: there is no API that
    // enumerates a module's statics, and no fixture can make a
    // never-referenced `OnceLock` observable. The executed partial substitute
    // is the observation-equality triple above, which catches cross-invocation
    // state that actually affects a call and cannot catch state that does not.
    for global in [
        "static MEMORY",
        "static mut",
        "OnceLock",
        "lazy_static",
        "thread_local",
    ] {
        assert!(
            !TYPED_EXECUTION_SOURCE.contains(global),
            "cross-invocation state found: {global}"
        );
    }
}

// WORK_UNIT_CASE: 758/24
#[test]
fn receipt_bounds_and_secret_redaction_hold() {
    // Real executed guest carrying a planted secret in a descriptor field.
    let secret = "sk-758-planted-secret-value-must-never-reach-a-receipt";
    let mut fields = cooperative_guest();
    fields.native_contract = secret.to_owned();
    let artifact = cue_activation_artifact(&fields, &CueOptions::default());
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&artifact));
    let (receipt, _) = must(
        run_describe(TypedWorld::CueActivation, &artifact, &limits)
            .map_err(|error| error.to_string()),
    );

    // The secret changes the measured output identity but never appears in the
    // receipt, which carries digests and bounded codes only.
    let clean = cooperative_cue_artifact();
    let clean_limits = default_experimental_limits(Sha256Digest::of_bytes(&clean));
    let (clean_receipt, _) = must(
        run_describe(TypedWorld::CueActivation, &clean, &clean_limits)
            .map_err(|error| error.to_string()),
    );
    assert_ne!(receipt.output_digest, clean_receipt.output_digest);

    for value in receipt_strings(&receipt) {
        assert!(!value.contains(secret), "secret leaked into the receipt");
        assert!(
            !value.contains("tests/"),
            "path leaked into the receipt: {value}"
        );
        assert!(
            !value.contains('\\'),
            "path leaked into the receipt: {value}"
        );
        assert!(value.len() <= 512, "unbounded receipt value: {value}");
        assert!(!value.chars().any(char::is_control) || value == receipt.terminal);
    }
    for digest in [
        &receipt.artifact_digest,
        &receipt.wit_digest,
        &receipt.cache_identity,
        &receipt.input_digest,
        &receipt.output_digest,
    ] {
        assert!(is_digest(digest.as_str()));
    }
    assert_eq!(receipt.actual_imports.len(), 0);

    // The receipt record itself carries no path, payload or secret FIELD (the
    // prose may name what is excluded; the declared fields may not hold it).
    //
    // NOT CONVERTIBLE (retained deliberately). This scans the DECLARED FIELD
    // LIST of `pub struct TypedReceipt`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:193-251`) out of the source
    // text. "No field named path/secret/payload/raw/token exists" is a claim
    // about a declaration, not about behaviour, and no run can falsify it: a
    // field that nothing populates produces no observation. The executed
    // substitute is the loop above, which walks EVERY reachable receipt string
    // — proof, world, package, engine version, stage, terminal, both identity
    // digests, cache identity, input/output digests, the actual import/export
    // lists and the four optional identity fields
    // (`bins/eliot-wasm-host/src/typed_execution.rs:195-250`) — and fails on
    // the planted secret, on `tests/`, on a backslash, on control characters
    // and on any value over 512 bytes, then requires all five digest fields to
    // be lowercase 64-hex. It cannot prove a field that production never fills.
    let declaration = TYPED_EXECUTION_SOURCE
        .split("pub struct TypedReceipt {")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap_or("");
    let fields: Vec<&str> = declaration
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub "))
        .filter_map(|rest| rest.split(':').next())
        .collect();
    assert!(fields.len() >= 20, "receipt fields: {fields:?}");
    for forbidden in ["path", "secret", "payload", "raw", "token"] {
        assert!(
            !fields.iter().any(|name| name.contains(forbidden)),
            "receipt declares a {forbidden} field"
        );
    }

    // Denial strings carry no payload either: only bounded codes.
    assert_eq!(
        TypedExecutionError::OutputViolation("world-name".to_owned()).to_string(),
        "OUTPUT_VIOLATION:world-name"
    );
    assert_eq!(
        TypedExecutionError::ForbiddenImport("eliot:ambient/env".to_owned()).to_string(),
        format!("{CAPABILITY_INTRODUCTION_REQUIRED}:eliot:ambient/env")
    );
}

// WORK_UNIT_CASE: 758/25
#[test]
fn the_semantic_receipt_is_deterministic_and_timing_stays_observational() {
    let artifact = real_cycle_fixture();
    let limits = default_experimental_limits(Sha256Digest::of_bytes(&artifact));

    let (first, _) = must(
        run_describe(TypedWorld::DreamerCycle, &artifact, &limits)
            .map_err(|error| error.to_string()),
    );
    let (second, _) = must(
        run_describe(TypedWorld::DreamerCycle, &artifact, &limits)
            .map_err(|error| error.to_string()),
    );

    // Deterministic semantic identity: every semantic field and the digest
    // agree across independent real invocations.
    assert_eq!(first.semantic_digest, second.semantic_digest);
    assert_eq!(first.proof, second.proof);
    assert_eq!(first.world, second.world);
    assert_eq!(first.package_id, second.package_id);
    assert_eq!(first.artifact_digest, second.artifact_digest);
    assert_eq!(first.artifact_bytes, second.artifact_bytes);
    assert_eq!(first.engine_version, second.engine_version);
    assert_eq!(first.wit_digest, second.wit_digest);
    assert_eq!(first.cache_identity, second.cache_identity);
    assert_eq!(first.actual_imports, second.actual_imports);
    assert_eq!(first.actual_exports, second.actual_exports);
    assert_eq!(first.input_digest, second.input_digest);
    assert_eq!(first.input_bytes, second.input_bytes);
    assert_eq!(first.output_digest, second.output_digest);
    assert_eq!(first.output_bytes, second.output_bytes);
    assert_eq!(first.instances, second.instances);
    assert_eq!(first.stage, second.stage);
    assert_eq!(first.terminal, second.terminal);

    // Observational timing is recorded on its own field, never inside the
    // semantic identity.
    //
    // NOT CONVERTIBLE (retained deliberately). These assertions read the BODY
    // of `fn semantic_digest`
    // (`bins/eliot-wasm-host/src/typed_execution.rs:753-793`) out of the source
    // text and ask which field names it does not mention. The EXCLUSION claim
    // they make has no executed witness from this target, and the reason is a
    // reachability fact rather than an omission: to falsify "observation is
    // excluded" a test needs two completed receipts with every SEMANTIC field
    // equal and some OBSERVATION different, and no such pair exists here. Every
    // field of `InvocationLimits` is an input to `typed_policy_digest`
    // (`:656-678`) and therefore to `cache_identity`, which IS a semantic
    // field (`:767`), so no envelope can hold the identity fixed while changing
    // an observation; and the only lever that moves `fuel_consumed`,
    // `peak_memory_bytes` or `table_elements` without moving the buffer is a
    // ceiling, which moves the identity with it. The executed evidence in this
    // test is therefore the DETERMINISM direction only: two independent real
    // invocations of the same buffer under the same envelope agree on
    // `semantic_digest` across every semantic field (asserted above) while
    // `elapsed_ms` is measured per call. Case 13, case 21 and case 23 execute
    // the same three observational fields as real values and show they vary
    // with the call rather than with the identity.
    let observation_fields = [
        "elapsed_ms",
        "fuel_consumed",
        "peak_memory_bytes",
        "table_elements",
    ];
    let digest_body = TYPED_EXECUTION_SOURCE
        .split("fn semantic_digest(receipt: &TypedReceipt) -> Sha256Digest {")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap_or("");
    assert!(!digest_body.is_empty());
    assert!(!digest_body.contains("semantic_digest"));
    for field in observation_fields {
        assert!(
            !digest_body.contains(field),
            "observation leaked into the semantic digest: {field}"
        );
    }
    let shared_body = RECEIPT_BRIDGE_SOURCE
        .split("fn shared_semantic_digest(receipt: &eliot_wasm_runtime::TypedReceipt) -> Sha256Digest {")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap_or("");
    assert!(!shared_body.is_empty());
    for field in observation_fields {
        assert!(
            !shared_body.contains(field),
            "observation leaked into the shared semantic digest: {field}"
        );
    }
    // NOT CONVERTIBLE (retained deliberately): both are DOC-COMMENT PROSE on
    // the `elapsed_ms` and `semantic_digest` fields
    // (`bins/eliot-wasm-host/src/typed_execution.rs:245` and `:249`). A comment
    // is not behaviour; nothing that executes can falsify its wording.
    assert!(TYPED_EXECUTION_SOURCE.contains("    /// Observation-only wall time in milliseconds."));
    assert!(
        TYPED_EXECUTION_SOURCE.contains("    /// Deterministic semantic digest (excludes timing).")
    );
}

// WORK_UNIT_CASE: 758/26
#[test]
fn the_production_binding_path_has_zero_ambient_inheritance_one_engine_and_no_missing_world() {
    // Real production path: every frozen world's checked-in component is
    // compiled by the configured provider, inspected, instantiated on the
    // empty linker and executed, with zero ambient imports and exactly one
    // interface export.
    for world in TypedWorld::all() {
        let artifact = load_fixture(world);
        let preflight = must(preflight_bytes(&artifact));
        let limits = default_experimental_limits(preflight.digest.clone());
        let (receipt, _) =
            must(run_describe(world, &artifact, &limits).map_err(|error| error.to_string()));
        assert!(
            receipt.actual_imports.is_empty(),
            "ambient import in {world}"
        );
        assert_eq!(receipt.actual_exports.len(), 1);
        assert!(
            accepted_export_spellings(world).contains(&receipt.actual_exports[0]),
            "unexpected export spelling: {:?}",
            receipt.actual_exports[0]
        );
        assert_eq!(receipt.world, world.world_name());
        assert_eq!(receipt.package_id, TYPED_PACKAGE_ID);
        assert_eq!(receipt.engine_version, "47.0.4");
        assert_eq!(receipt.engine_version, neutral_engine_version());
        assert_eq!(receipt.wit_digest, typed_wit_digest());
        assert!(is_digest(receipt.cache_identity.as_str()));
        // One typed binding per world, from the single WIT directory.
        assert!(TYPED_BINDINGS_SOURCE.contains(&format!("world: \"{}\",", world.world_name())));
    }

    // Source guard: no WASI anywhere in the typed composition.
    //
    // NOT CONVERTIBLE (retained deliberately) — these are ABSENCE claims over
    // whole-file and whole-manifest text. No execution can falsify "this string
    // does not appear anywhere in this file": there is no API that enumerates a
    // crate's dependencies or its source text, and no fixture can make an
    // unreferenced `wasmtime_wasi` import observable at run time. This is the
    // case-26 whole-file source guard the header declares.
    assert!(!HOST_MANIFEST.contains("wasmtime-wasi"));
    assert!(!HOST_MANIFEST.contains("wasmtime_wasi"));
    assert!(!TYPED_EXECUTION_SOURCE.contains("wasmtime_wasi"));
    assert_eq!(
        HOST_MANIFEST.matches("wasmtime.workspace = true").count(),
        1
    );
    // CONVERTED (already executed). The real proof that the linker is EMPTY is
    // the six-world loop above plus the case-11 denial: each world's real
    // component reports `actual_imports.is_empty()` and exactly one export
    // AFTER a successful instantiation, and the `forbidden-import` fixture —
    // the honest `dreamer-cycle` surface plus one ambient WASI clock import —
    // is refused as `ForbiddenImport("wasi:clocks/wall-clock@0.2.0")` by the
    // component-TYPE preflight
    // (`bins/eliot-wasm-host/src/typed_execution.rs:1090-1097`), before
    // instantiation, so an ambient import could not be satisfied even if one
    // were offered. A non-empty linker or any host function would break both.
    assert!(TYPED_EXECUTION_SOURCE.contains("wasmtime::component::Linker::new(engine)"));

    // Source guard: no second neutral-runtime engine and no second provider.
    assert!(
        !NEUTRAL_MANIFEST.contains("wasmtime"),
        "the neutral runtime crate must not depend on an engine"
    );
    assert!(!NEUTRAL_CAPSULES_SOURCE.contains("wasmtime::"));
    assert_eq!(
        WASMTIME_PROVIDER_SOURCE
            .matches("pub fn new_for_admitted_limits")
            .count(),
        1
    );
    assert_eq!(
        TYPED_BINDINGS_SOURCE
            .matches("wasmtime::component::bindgen!({")
            .count(),
        6
    );
    assert_eq!(
        TYPED_BINDINGS_SOURCE.matches("path: \"wit/typed\"").count(),
        6
    );
    assert!(!TYPED_BINDINGS_SOURCE.contains("wit/typed-v"));

    // Source guard: no legacy byte-runner fallback and no auto-upgrade on the
    // typed lane.
    //
    // MIXED, each guard named (all retained):
    // - `call_run` / `guest_exec::` absences: NOT CONVERTIBLE, absence claims
    //   over one owner file's whole text, as above. The executed PARTIAL
    //   substitute is case 5: the checked-in legacy `run` component, presented
    //   for a frozen world, is denied `LegacyMismatch` three times — including
    //   under a zero host-call budget — so no legacy byte-runner fallback
    //   served it. That catches a fallback that would have EXECUTED; it cannot
    //   catch a reference no path reaches.
    // - the legacy-export compare and its `LegacyMismatch` return: CONVERTED
    //   (already executed). They are
    //   `bins/eliot-wasm-host/src/typed_execution.rs:1112-1113`, inside
    //   `preflight_component_type`, and the `LegacyMismatch` denials asserted
    //   in case 5 are produced by exactly those two lines on a real compiled
    //   legacy component. `check_governed_admission` and the neutral
    //   `NeutralWorld::parse` assertions in that same case prove the identity is
    //   unselectable, and `parse_args` proves the CLI never auto-promotes it.
    assert!(!TYPED_EXECUTION_SOURCE.contains("call_run"));
    assert!(!TYPED_EXECUTION_SOURCE.contains("guest_exec::"));
    assert!(TYPED_EXECUTION_SOURCE.contains("if *name == crate::typed_bindings::LEGACY_EXPORT"));
    assert!(TYPED_EXECUTION_SOURCE.contains("return Err(TypedExecutionError::LegacyMismatch);"));

    // Source guard: artifact acquisition has no network/registry/discovery
    // path; `://` is a denial marker only.
    assert!(ARTIFACT_PREFLIGHT_SOURCE.contains("fn reject_remote_artifact_source"));
    assert!(ARTIFACT_PREFLIGHT_SOURCE.contains("ArbitraryPathDenied"));
    assert!(!ARTIFACT_PREFLIGHT_SOURCE.contains("reqwest"));
    assert!(!ARTIFACT_PREFLIGHT_SOURCE.contains("std::net::"));

    // Denominator: all six worlds, host and neutral agree, none is missing.
    assert_eq!(TypedWorld::all().len(), 6);
    assert_eq!(NeutralWorld::all().len(), 6);
    for host in TypedWorld::all() {
        assert_eq!(
            host.world_name(),
            neutral_world(host).world_name(),
            "world name disagreement"
        );
        assert_eq!(host.domain_func(), neutral_world(host).domain_func());
        assert!(
            Path::new(&fixture_file(host.world_name())).is_file(),
            "missing fixture for {host}"
        );
    }
}

/// Asserts the exact output-stage denial for a descriptor field.
fn assert_descriptor_denied(fields: &TypedDescriptor, field: &str) {
    let artifact = cue_activation_artifact(fields, &CueOptions::default());
    let digest = Sha256Digest::of_bytes(&artifact);
    let limits = default_experimental_limits(digest);
    require_denied(
        run_describe(TypedWorld::CueActivation, &artifact, &limits),
        &staged(
            TypedStage::Output,
            TypedExecutionError::OutputViolation(field.to_owned()),
        ),
    );
}

/// The checked-in legacy `run` fixture: real engine input, never a typed world.
fn load_legacy_guest() -> Vec<u8> {
    match wat::parse_file("tests/fixtures/guest.wat") {
        Ok(bytes) => bytes,
        Err(error) => panic!("legacy fixture must be readable: {error}"),
    }
}

/// The pinned neutral engine version the host's receipts must equal.
fn neutral_engine_version() -> &'static str {
    eliot_wasm_runtime::component_contract::TYPED_ENGINE_VERSION
}
