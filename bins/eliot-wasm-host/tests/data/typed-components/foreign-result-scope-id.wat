;; ELIOT typed NEGATIVE fixture for #758: a world result that returns a FOREIGN
;; scope-id, so the host's scope-id ownership gate is proven to DENY and not
;; merely to execute. `scope-id` is compared in EIGHT production `check_echo`
;; sites -- five on the request side and three on the result side, enumerated in
;; (e) -- and, before this fixture, asserted by no test at all: every
;; checked-in fixture echoed it out of the lowered request.
;;
;; (a) PROVENANCE AND EVERY DIFFERENCE.
;; The TYPE DECLARATIONS are byte for byte the sibling's, and the sibling's are
;; the frozen WIT surface: every record field, enum case, variant case and
;; function signature in this file is that world's own
;; bins/eliot-wasm-host/wit/typed/memory-curation-screen.wit surface, field for
;; field and in WIT order. A record field the WIT does not declare would be a
;; different interface rather than a variation of this one, which
;; `fn execute_domain_lane` refuses before dispatch (see the
;; `preflight_component_type` -> `typecheck_world_signatures` bullet in (c)).
;; Structurally copied from
;; bins/eliot-wasm-host/tests/data/typed-components/memory-curation-screen.wat
;; (which is itself derived from
;; bins/eliot-wasm-host/wit/typed/memory-curation-screen.wit). The complete list
;; of differences from that sibling is exactly four, and the type declarations
;; are not one of them:
;;   1. this header block replaces the copied fixture's header block;
;;   2. the two in-body comment blocks that have to describe this fixture's
;;      forgery are replaced by this fixture's own: the trailing comment of
;;      `describe` (sibling memory-curation-screen.wat:133-140 -- the WHOLE
;;      trailing comment block, whose `describe` opens at sibling :141) and the
;;      comment above `screen` (sibling :160-163). Both replacements are
;;      comments only;
;;      no instruction, address, data segment, export, import, helper or memory
;;      declaration is touched by either, and `describe`'s body below them is
;;      byte for byte the sibling's;
;;   3. inside `screen`, the `scope-id` echo -- the `$n` length load from the
;;      request, the 512-byte clamp, the `$copy` call into the 0x1400 scratch
;;      block, and the two result stores at 2080/2084 -- is REPLACED by two
;;      stores of a forged literal pointer/length pair. The guest therefore no
;;      longer writes the 0x1400 scratch block; 0x1400 remains the host
;;      `realloc` bump base exactly as in the sibling, unchanged. The `$n` local
;;      and the `$copy` helper are still used by the `operation-id`, `task-id`
;;      and `fence-epoch` echoes, so no helper is added, dropped or changed;
;;   4. ONE data segment is ADDED, at 0x900, carrying the forged literal. No
;;      other data segment is added, removed, moved or resized.
;; Nothing else differs. Same single 1-page memory `(memory (export "memory") 1 1)`,
;; same guest bump allocator base `$bump` = 5120 (0x1400), same `$copy` and
;; `$realloc` helper bodies, same honest `describe`, same honest `operation-id`,
;; `task-id` and `fence-epoch` echoes, same zeroed `fence-generation` /
;; `eligibility` / `state` / `output-bytes` / `proof-ceiling` bytes and same
;; zero-length `protection`/`findings` lists, zero imports, exactly one exported
;; interface `eliot:current/screen@0.1.0` exposing only `describe` and the world
;; domain function `screen`. No bulk-memory instruction, no `memory.fill`, no
;; second memory, no second export.
;;
;; (b) DERIVED ADDRESS ARITHMETIC for the forged store.
;; `screen` returns ONE core value: a lifted result that does not fit
;; MAX_FLAT_FUNC_RESULTS = 1 (wasmparser-0.252.0
;; src/validator/component_types.rs:36) clears the flat results and pushes
;; exactly one pointer for `Abi::Lift` (same file :1272-1274), a signature the
;; export check enforces at src/validator/component.rs:1328 and :1350.
;; With that one pointer = 2048 (0x800):
;;   2048        `result<screen-outcome, screen-error>` discriminant, one byte
;;               (variant_static, wasmtime-environ-47.0.4/src/component/types.rs:841);
;;               payload_offset32 = align_to(1, 8) = 8 (types.rs:950; align 8 because
;;               screen-result-body carries fence-generation's u64) -> payload 2056
;;   2056        `screen-outcome` variant case discriminant; payload_offset32 =
;;               align_to(1, 8) = 8 (types.rs:950) -> payload 2064
;;   2064        screen-result-body record base
;; screen-result-body (bins/eliot-wasm-host/wit/typed/memory-curation-screen.wit:101)
;; declares `operation-id: string` (:102), `task-id: string` (:103) and
;; `scope-id: string` (:104) as its first three fields. A WIT `string` lowers to
;; POINTER_PAIR, size32 = 8 and align32 = 4 (types.rs:707-709), placed by
;; next_field32 (types.rs:756-759: offset = align_to(offset, 4) + 8, returning
;; offset - 8). Walking the field order from offset 0:
;;   operation-id: align_to(0, 4) + 8 = 8   -> record offset 0  -> 2064 / 2068
;;   task-id:      align_to(8, 4) + 8 = 16  -> record offset 8  -> 2072 / 2076
;;   scope-id:     align_to(16, 4) + 8 = 24 -> record offset 16 -> 2080 / 2084
;; So the forged pair is 2064 + 16 = 2080 (ptr) and 2084 (len), which is exactly
;; what this file writes:
;;   (i32.store (i32.const 2080) (i32.const 2304))  ;; ptr = 0x900, the forged literal
;;   (i32.store (i32.const 2084) (i32.const 32))    ;; len = 32 bytes, the literal's real length
;; CROSS-CHECK. Only one checked-in sibling stores the SAME record
;; (`screen-result-body`): memory-curation-screen.wat:186-187 stores
;; 2080 = 5120 (its scope scratch block) and 2084 = $n, i.e. the same two
;; addresses. The other screen-world sibling, guest-typed-error.wat, does NOT
;; store this record -- it writes the `err` arm (guest-typed-error.wat:192-197,
;; the exported `screen` that stores the result discriminant 1 at 2048 and the
;; `screen-error` case discriminant 1 at 2056), so it cannot corroborate the
;; offsets and is not cited as if it could. The same arithmetic is therefore
;; corroborated by two siblings that store a DIFFERENT record with the same
;; four-string prefix, which pins the pointer-pair stride and the 2064 record
;; base independently of this file:
;;   context-assembly.wat:196-197 -- `$active_view`'s THIRD field `scope-id`
;;     (context-assembly.wat:78, after `operation-id` at :76 and `task-id` at
;;     :77) at record offset 16 -> 2080 / 2084, and its
;;     `operation-id`/`task-id`/`fence-epoch` at :184-185/:190-191/:202-203;
;;   context-admission.wat:447-448 -- admitted-context-set's `scope-id` is its
;;     FOURTH field there (context-admission.wat:293, after `attempt-id`), so
;;     the same stride puts it at record offset 24 -> 2088 / 2092, which is
;;     where that sibling stores it.
;; No address here was chosen by hand. The forged literal lives at 0x900 (2304),
;; inside the same single page, above the highest result-tuple store at 2092
;; (0x82c) and below the 0x1000/0x1200/0x1600 scratch blocks, so 0x900..0x91f
;; collides with nothing.
;;
;; WHY THE FORGED LITERAL CANNOT EQUAL THE ADMITTED VALUE. It is a fixed 32-byte
;; constant, "forged-scope-id-758-not-admitted", planted by a data segment, and
;; `screen` never reads the request for it. Every admitted scope-id checked in
;; this repository is a short token: "sc" (the test-module constant
;; `const SCOPE_ID: &str = "sc"` in src/typed_execution.rs -- cited by symbol and
;; quoted source text, not by line, because that file is edited underneath this
;; comment) or
;; "scope-758" (the `scope-758` literal in the `governed_admission` fixture in
;; tests/typed_execution.rs - cited by name, not by line, because that file is
;; being edited underneath this comment). 32 printable bytes beginning with
;; "forged" cannot equal a 2-byte or a 10-byte token, and because the value is
;; not derived from the lowered request, NO request content can make the
;; comparison pass -- which is exactly the property an echo fixture lacks.
;;
;; (c) THE FORGED FIELD IS THE FIRST CHECK THAT CAN FAIL. This block cites by
;; SYMBOL, not by line: every `fn` named below lives in src/typed_execution.rs
;; and every backquoted string is verbatim source text, so the block survives
;; edits made above the cited statements. A quote too long for one comment line
;; is WRAPPED across consecutive `;;` lines, with nothing elided inside the
;; quoted span: rejoin those lines before comparing. Where a statement's
;; leading `let <binding> =` is not quoted, the quoted text is the call
;; expression exactly as it appears on its own source line. In call order
;; through `fn execute_domain_lane` -- the interior lane whose body ends
;; `Ok((receipt, result))` -- every check that runs before the forged
;; comparison still passes:
;;   `admitted.validate()?;`                     -- the test's own admitted
;;                                                 record; not guest-supplied.
;;   `if request.world() != world {`            -- the caller passes this world's
;;                                                 own generated request.
;;   `bound_request(world, request, admitted, &mut input_bound)?;` /
;;   `input_bound.finish(limits.max_input_bytes)?;`
;;                                               -- request-side only; the forged
;;                                                 field is on the result side.
;;   `preflight_bytes(artifact)?;` /
;;   `validate_limits(limits, &preflight.digest)?;` /
;;   `check_cache_identity(world, artifact, &preflight.digest, limits)?;`
;;                                               -- digest/limit/identity checks
;;                                                 over the presented bytes; the
;;                                                 limits are the test's.
;;   `preflight_component_type(world, engine, component)?;` -- inside `fn
;;   preflight_component_type` (src/typed_execution.rs): `if let Some(import) =
;;   imports.first()` requires the imports to be empty (this fixture imports
;;   nothing); `if exports.is_empty()` requires at least one export; `if
;;   exports.len() != 1` requires exactly one; `if *name ==
;;   crate::typed_bindings::LEGACY_EXPORT || *name == "run"` rejects the legacy
;;   `run` export; `export_matches_interface(name, world.interface_name())` --
;;   `TypedWorld::interface_name` (src/typed_bindings.rs:132) -> "screen", i.e.
;;   "eliot:current/screen@0.1.0" (TYPED_PACKAGE_ID src/typed_bindings.rs:24),
;;   which is what this file exports -- requires the export name to match;
;;   `ComponentItem::ComponentInstance` requires the export to be a component
;;   instance; the `for (name, item) in interface_type.exports(engine)` loop
;;   permits no callable or structural export outside `describe` and `screen`;
;;   `component_function` must resolve both in the instance type; and
;;   `typecheck_world_signatures(world, &descriptor, &domain, component)?`,
;;   whose `TypedWorld::MemoryCurationScreen` arm requires this component's
;;   declared `screen` parameter, result and error types to match
;;      `(wit::ScreenRequest,),` and `(Result<wit::ScreenOutcome,
;;      wit::ScreenError>,)`, the two argument lines of the `typecheck::<..>`
;;      generic as they stand on their own source lines.
;;      That is the check that requires the DECLARED TYPES ABOVE to equal the
;;      frozen WIT records -- record for record, field for field, in WIT order --
;;      and it is the check a WIT-absent record field fails. The mismatch is
;;      returned by the `TypedWorld::MemoryCurationScreen` arm of
;;      `fn typecheck_world_signatures` as the statement below, quoted
;;      VERBATIM: only its 12-space leading indentation is trimmed, nothing
;;      else is changed, the `map_err` wrapper and the `.to_owned()` included.
;; .map_err(|_| TypedExecutionError::ExportTypeMismatch("screen".to_owned()))?;
;;      It is returned before `screen` is dispatched at all. Nothing below is
;;      reached if it fails, so this file's type declarations are load-bearing
;;      for this fixture, not decoration.
;;   `validate_descriptor(world, &descriptor, limits.max_output_bytes)` -- inside
;;   `fn validate_descriptor`: `if descriptor.world_name != world.world_name()`
;;   -> `TypedWorld::world_name` (src/typed_bindings.rs:119) ->
;;   "memory-curation-screen";
;;   `if descriptor.package_id != crate::typed_bindings::TYPED_PACKAGE_ID`;
;;   `if descriptor.abi_revision != TYPED_ABI_REVISION`; then the five
;;   `bounded_descriptor_string(...)` calls. `describe` is copied verbatim from
;;   the honest sibling, so every one of these reads its true value.
;;   `validate_descriptor_abi_digest(&descriptor)` -- inside `fn
;;   validate_descriptor_abi_digest`: `if descriptor.abi_digest !=
;;   typed_wit_digest().as_str()`. The abi-digest data segment is copied
;;   verbatim from memory-curation-screen.wat:200, so it is the real digest of
;;   the frozen WIT bytes, not a fixture-chosen value.
;;   `check_result(&result, admitted, &mut output_bound)` -- inside `fn
;;   check_result`, the arm `TypedDomainOutcome::MemoryCurationScreen(value)`
;;   is the BRACED BLOCK quoted verbatim in (d), NOT the collapsed arrow
;;   expression a one-line paraphrase would suggest; inside `fn
;;   check_screen_result` `let R::Screened(body) = value;` binds because this
;;   file writes the ok discriminant 0 at 2048 and the "screened" case
;;   discriminant 0 at 2056.
;;   `check_echo(&body.operation_id, &admitted.operation_id, "operation-id")?;`
;;      -- PASSES: this fixture still copies `operation-id` out of the lowered
;;      request (memory-curation-screen.wat:170-175 kept here), and the caller
;;      builds that request's operation-id from the admitted record --
;;      `operation_id: admitted.operation_id.clone()` in `fn screen_request` in
;;      src/typed_execution.rs -- so observed == admitted.
;;   `check_echo(&body.task_id, &admitted.task_id, "task-id")?;` -- PASSES,
;;      same reason: the honest echo at memory-curation-screen.wat:176-181 reads
;;      the request, whose task-id is the admitted one --
;;      `task_id: admitted.task_id.clone()` in the same `fn screen_request`.
;;   `check_echo(&body.scope_id, &admitted.scope_id, "scope-id")?;`
;;      <-- THIS FIXTURE FORGES THIS FIELD. First failure.
;; Nothing after that `check_echo` is reached. For the record, the checks after
;; it would have passed anyway: `check_echo(&body.fence_epoch,
;; &admitted.fence_epoch, "fence-epoch")?;` echoes the request honestly
;; (memory-curation-screen.wat:188-193 kept here, request fence-epoch admitted at
;; `fence_epoch: admitted.fence_epoch.clone()` in `fn screen_request`), and the
;; `check_ceiling` of `ceiling_screen(body.proof_ceiling)` against
;; `admitted.proof_ceiling` (field `"proof-ceiling"`) reads the zeroed
;; `proof-ceiling` byte as enum case 0 = "observation", `const fn proof_rank`
;; rank 0, which is not above any admitted ceiling (`const fn proof_rank` in
;; src/typed_execution.rs).
;;
;; (d) THE PRODUCTION LINE THAT COMPARES THE FORGED FIELD, BY SYMBOL. Each item
;; is a `fn` name in bins/eliot-wasm-host/src/typed_execution.rs plus the
;; verbatim source text of the statement, deliberately NOT a line number: this
;; file is edited underneath its own header, and a bare `:NNNN` rots silently.
;;   fn check_screen_result
;;     let R::Screened(body) = value;
;;     check_echo(&body.scope_id, &admitted.scope_id, "scope-id")?;
;;   <-- THE LINE THAT COMPARES THE FORGED FIELD
;; reached from `fn check_result`, whose arm selects it. That arm is a BRACED
;; BLOCK in the source, quoted here exactly as it appears and not collapsed
;; onto one line:
;;     TypedDomainOutcome::MemoryCurationScreen(value) => {
;;         check_screen_result(value, admitted, bound)
;;     }
;; The comparison that fires is inside `fn check_echo`, whose signature spans
;; five lines in the source; the body is quoted verbatim below:
;;   fn check_echo(
;;     observed: &str,
;;     admitted: &str,
;;     field: &'static str,
;; ) -> Result<(), TypedExecutionError> {
;;     if observed != admitted {
;;         return Err(TypedExecutionError::OutputViolation(field.to_owned()));
;;     }
;;     Ok(())
;; }
;; so the denial is `TypedExecutionError::OutputViolation("scope-id")` -- the
;; resulting VALUE, with `field` = "scope-id"; the source expression is the
;; `field.to_owned()` quoted above, not a literal. The caller
;; stages it as TypedStage::Output at
;;     check_result(&result, admitted, &mut output_bound)
;;         .map_err(|error| staged(TypedStage::Output, error))?;
;; inside `fn execute_domain_lane`, whose body ends `Ok((receipt, result))`.
;;
;; (e) LIMITS OF THIS FIXTURE, stated rather than hidden.
;;   - It proves the `check_echo` denial for the SCREEN world's scope-id only.
;;     `TypedDomainOutcome::MemoryCurationScreen` is the only arm that reaches
;;     the forged-field `check_echo` in (d). The `:NNNN` figures in this bullet
;;     are line positions of `check_echo` CALL SITES, which have no symbol of
;;     their own; re-derive them from the `fn`s named in (c) and (d) above.
;;     There are EIGHT `check_echo` scope-id sites in the crate: five on
;;     the REQUEST side (:3163 :3213 :3263 :3291 :3318, one per world) and three
;;     on the RESULT side (:3468 admission, :3522 assembly, :3605 screen). This
;;     file reaches exactly one of the three result-side sites and says nothing
;;     about the other seven.
;;   - It denies at the OUTPUT stage, so no receipt, no shared receipt and no
;;     semantic digest is produced; the fixture cannot also demonstrate a
;;     successful run.
;;   - The two earlier echo checks in the same function pass because the honest
;;     echoes read the request and the caller's request carries the admitted
;;     values. A caller that passed a request disagreeing with its own admitted
;;     record would fail at the `operation-id` `check_echo` first, and this
;;     fixture would then prove nothing. That coupling is a property of the ECHO
;;     mechanism, not of this forgery: the forged scope-id is request-independent
;;     by construction.
;;   - The forged literal is longer than any admitted leaf, so the denial is a
;;     value denial; the fixture does not separately exercise a same-length
;;     different-value case.
(component
  (type $abi_descriptor (record
    (field "world-name" string)
    (field "package-id" string)
    (field "abi-revision" u32)
    (field "native-contract" string)
    (field "native-revision" string)
    (field "abi-digest" string)
  ))
  (type $source_member (record
    (field "member-id" string)
    (field "provenance" (list string))
    (field "conflict" (list string))
  ))
  (type $source_availability (enum "available" "unavailable" "stale" "partial" "truncated" "unprocessed"))
  (type $screen_request (record
    (field "schema-revision" u32)
    (field "operation-id" string)
    (field "task-id" string)
    (field "scope-id" string)
    (field "fence-epoch" string)
    (field "fence-generation" u64)
    (field "source-id" string)
    (field "snapshot-revision" string)
    (field "members" (list $source_member))
    (field "availability" $source_availability)
    (field "profile-id" string)
    (field "rule-ids" (list string))
    (field "deadline-ms" (option s64))
    (field "cancelled" bool)
    (field "predecessor-digest" (option string))
  ))
  (type $eligibility_status (enum "eligible-for-semantic-curation" "ineligible-protected" "ineligible-malformed" "ineligible-stale" "ineligible-unavailable" "ineligible-partial" "unknown"))
  (type $protection_decision (enum "protected" "unprotected" "protection-unknown"))
  (type $protection_assessment (record
    (field "member-id" string)
    (field "decision" $protection_decision)
  ))
  (type $finding_class (enum "provenance-gap" "conflict-ambiguity"))
  (type $finding_proof (enum "deterministic"))
  (type $curation_finding (record
    (field "finding-id" string)
    (field "member-id" string)
    (field "rule-id" string)
    (field "class" $finding_class)
    (field "evidence" (list string))
    (field "invariant" string)
    (field "proof" $finding_proof)
    (field "digest" string)
  ))
  (type $screen_coverage (record
    (field "members" u32)
    (field "assessed" u32)
    (field "omitted" u32)
  ))
  (type $screen_frontier (record
    (field "cursor" (option string))
    (field "remaining" u32)
  ))
  (type $result_state (enum "complete" "partial" "incomplete" "unknown"))
  (type $proof_ceiling (enum "observation" "candidate-only" "admission" "assembly" "activation" "screen" "cycle" "handler"))
  (type $screen_result_body (record
    (field "operation-id" string)
    (field "task-id" string)
    (field "scope-id" string)
    (field "fence-epoch" string)
    (field "fence-generation" u64)
    (field "eligibility" $eligibility_status)
    (field "protection" (list $protection_assessment))
    (field "findings" (list $curation_finding))
    (field "coverage" $screen_coverage)
    (field "frontier" $screen_frontier)
    (field "state" $result_state)
    (field "output-bytes" u32)
    (field "proof-ceiling" $proof_ceiling)
    (field "result-digest" string)
  ))
  (type $screen_outcome (variant
    (case "screened" $screen_result_body)
  ))
  (type $screen_malformed (record
    (field "field" string)
    (field "human-detail" string)
  ))
  (type $screen_cancelled (record
    (field "human-detail" string)
  ))
  (type $screen_schema (record
    (field "want-revision" u32)
    (field "got-revision" u32)
    (field "human-detail" string)
  ))
  (type $screen_internal (record
    (field "human-detail" string)
  ))
  (type $screen_error (variant
    (case "malformed" $screen_malformed)
    (case "cancelled-screen" $screen_cancelled)
    (case "unsupported-schema" $screen_schema)
    (case "internal" $screen_internal)
  ))
  (type $f-describe (func (result $abi_descriptor)))
  (type $f-domain (func (param "request" $screen_request) (result (result $screen_outcome (error $screen_error)))))
  (core module $guest
    (memory (export "memory") 1 1)
    (global $bump (mut i32) (i32.const 5120))
    (func $copy (param $dst i32) (param $src i32) (param $len i32)
      (local $i i32)
      (block $done
        (loop $next
          (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
          (i32.store8 (i32.add (local.get $dst) (local.get $i)) (i32.load8_u (i32.add (local.get $src) (local.get $i))))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $next))))
    (func $realloc (param $old i32) (param $old_size i32) (param $align i32) (param $new_size i32) (result i32)
      (local $ptr i32)
      (local.set $ptr (global.get $bump))
      (local.set $ptr (i32.and (i32.add (local.get $ptr) (i32.sub (local.get $align) (i32.const 1)))
                 (i32.xor (local.get $align) (i32.const -1))))
      (global.set $bump (i32.add (local.get $ptr) (local.get $new_size)))
      (local.get $ptr))
    ;; `describe`: the frozen WIT abi-descriptor, five static strings and
    ;; the frozen ABI revision, in WIT field order. A lifted export flattens
    ;; its result to at most MAX_FLAT_FUNC_RESULTS = 1 core value, so the
    ;; core function returns ONE pointer into exported linear memory
    ;; (wasmparser-0.252.0 src/validator/component_types.rs:36, :130 and
    ;; :1261-1274, enforced at src/validator/component.rs:1328 and :1350).
    ;; Retptr base 0x600: past the last descriptor byte at 0x48a and below
    ;; the 0x800 result tuple, so it collides with nothing in this memory.
    ;; Copied verbatim from memory-curation-screen.wat: this fixture's forgery
    ;; lives in `screen` below, never in the descriptor.
    (func (export "describe") (result i32)
      ;; world-name
      (i32.store (i32.const 1536) (i32.const 1024))
      (i32.store (i32.const 1540) (i32.const 22))
      ;; package-id
      (i32.store (i32.const 1544) (i32.const 1046))
      (i32.store (i32.const 1548) (i32.const 19))
      ;; abi-revision
      (i32.store (i32.const 1552) (i32.const 1))
      ;; native-contract
      (i32.store (i32.const 1556) (i32.const 1065))
      (i32.store (i32.const 1560) (i32.const 28))
      ;; native-revision
      (i32.store (i32.const 1564) (i32.const 1093))
      (i32.store (i32.const 1568) (i32.const 5))
      ;; abi-digest
      (i32.store (i32.const 1572) (i32.const 1098))
      (i32.store (i32.const 1576) (i32.const 64))
      (i32.const 1536))
    ;; `screen`: the admitted typed request arrives already lowered into guest
    ;; memory. `operation-id`, `task-id` and `fence-epoch` are copied back out of
    ;; the request, so the host echo checks for THOSE fields compare values the
    ;; guest actually read. `scope-id` is not echoed at all: it is the forged
    ;; literal below.
    (func (export "screen") (param $req i32) (result i32)
      (local $n i32)
      ;; result ok case: the WIT success variant
      (i32.store (i32.const 2048) (i32.const 0))
      ;; variant "screen-outcome" selects WIT case "screened"
      (i32.store (i32.const 2056) (i32.const 0))
      ;; echo "operation-id" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 8))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 4096) (i32.load (i32.add (local.get $req) (i32.const 4))) (local.get $n))
      (i32.store (i32.const 2064) (i32.const 4096))
      (i32.store (i32.const 2068) (local.get $n))
      ;; echo "task-id" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 16))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 4608) (i32.load (i32.add (local.get $req) (i32.const 12))) (local.get $n))
      (i32.store (i32.const 2072) (i32.const 4608))
      (i32.store (i32.const 2076) (local.get $n))
      ;; IDENTITY FORGERY: `scope-id` is NOT copied from the lowered request.
      ;; screen-result-body.scope-id is its THIRD field
      ;; (memory-curation-screen.wit:104); a string lowers to a (ptr, len)
      ;; POINTER_PAIR of 8 bytes (wasmtime-environ-47.0.4/src/component/types.rs
      ;; :707-709), so operation-id occupies record offset 0 (2064/2068),
      ;; task-id offset 8 (2072/2076) and scope-id offset 16
      ;; (2064 + 16 = 2080 and 2084; record base 2064 derived in the header).
      ;; The pair points at this file's own data-segment literal "forged-scope-
      ;; id-758-not-admitted" at 0x900 = 2304, length 32. No admitted scope-id
      ;; can equal it, and no request content can change it, so check_echo on
      ;; "scope-id" must deny.
      (i32.store (i32.const 2080) (i32.const 2304))
      (i32.store (i32.const 2084) (i32.const 32))
      ;; echo "fence-epoch" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 32))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 5632) (i32.load (i32.add (local.get $req) (i32.const 28))) (local.get $n))
      (i32.store (i32.const 2088) (i32.const 5632))
      (i32.store (i32.const 2092) (local.get $n))
      (i32.const 2048))
    (export "realloc" (func $realloc))
    (data (i32.const 1024) "memory-curation-screen")
    (data (i32.const 1046) "eliot:current@0.1.0")
    (data (i32.const 1065) "eliot-memory-curation-screen")
    (data (i32.const 1093) "0.1.0")
    (data (i32.const 1098) "6e878cbb40e2060fd2d570345a1b0105920a0398b3c70e2c4e1f9b7eb291a0e6")
    (data (i32.const 2304) "forged-scope-id-758-not-admitted")
  )
  (core instance $guest (instantiate $guest))
  (alias core export $guest "memory" (core memory $memory))
  (alias core export $guest "realloc" (core func $realloc))
  (alias core export $guest "describe" (core func $describe))
  (alias core export $guest "screen" (core func $domain))
  (func $describe (type $f-describe)
    (canon lift (core func $describe) (memory $memory) (realloc $realloc)))
  (func $domain (type $f-domain)
    (canon lift (core func $domain) (memory $memory) (realloc $realloc)))
  (instance $iface
    (export "abi-descriptor" (type $abi_descriptor))
    (export "curation-finding" (type $curation_finding))
    (export "eligibility-status" (type $eligibility_status))
    (export "finding-class" (type $finding_class))
    (export "finding-proof" (type $finding_proof))
    (export "proof-ceiling" (type $proof_ceiling))
    (export "protection-assessment" (type $protection_assessment))
    (export "protection-decision" (type $protection_decision))
    (export "result-state" (type $result_state))
    (export "screen-cancelled" (type $screen_cancelled))
    (export "screen-coverage" (type $screen_coverage))
    (export "screen-error" (type $screen_error))
    (export "screen-frontier" (type $screen_frontier))
    (export "screen-internal" (type $screen_internal))
    (export "screen-malformed" (type $screen_malformed))
    (export "screen-outcome" (type $screen_outcome))
    (export "screen-request" (type $screen_request))
    (export "screen-result-body" (type $screen_result_body))
    (export "screen-schema" (type $screen_schema))
    (export "source-availability" (type $source_availability))
    (export "source-member" (type $source_member))
    (export "describe" (func $describe))
    (export "screen" (func $domain)))
  (export "eliot:current/screen@0.1.0" (instance $iface))
)
