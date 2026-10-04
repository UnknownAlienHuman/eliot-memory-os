;; ELIOT typed NEGATIVE fixture for #758: a world result that returns a FOREIGN
;; operation-id, so the host's echo ownership gate is proven to DENY and not
;; merely to execute. Every checked-in fixture before this one echoes the
;; admitted identity out of the lowered request; this one is the operation-id
;; half of the missing denial half.
;;
;; (a) PROVENANCE AND EVERY DIFFERENCE.
;; The TYPE DECLARATIONS are byte for byte the sibling's, and the sibling's are
;; the frozen WIT surface: every record field, enum case, variant case and
;; function signature in this file is that world's own
;; bins/eliot-wasm-host/wit/typed/dreamer-cycle.wit surface, field for field and
;; in WIT order. A record field the WIT does not declare is a different
;; interface, not a variation of this one, and
;; `fn execute_domain_lane` proves that difference is fatal rather than
;; cosmetic: see the `preflight_component_type` -> `typecheck_world_signatures`
;; bullet in (c). An earlier revision of this file declared a
;; second, WIT-absent field `"bound"` on `$cycle_bound`; it has been removed, and
;; WIT dreamer-cycle.wit:168 (`record cycle-bound { human-detail: string }`) and
;; sibling dreamer-cycle.wat:95-97 (the same single field) are what this file now
;; declares. No other type declaration here ever departed from the frozen WIT.
;; Structurally copied from
;; bins/eliot-wasm-host/tests/data/typed-components/dreamer-cycle.wat (which is
;; itself derived from bins/eliot-wasm-host/wit/typed/dreamer-cycle.wit). The
;; complete list of differences from that sibling is exactly four, and the type
;; declarations are not one of them:
;;   1. this header block replaces the copied fixture's header block;
;;   2. the two in-body comment blocks that have to describe this fixture's
;;      forgery are replaced by this fixture's own: the trailing comment of
;;      `describe` (sibling dreamer-cycle.wat:133-140 -- the WHOLE trailing
;;      comment block, whose `describe` opens at sibling :141) and the comment
;;      above `step` (sibling :160-163). Both replacements are comments only; no
;;      instruction, address, data segment, export, import, helper or memory
;;      declaration is touched by either, and `describe`'s body below them is
;;      byte for byte the sibling's;
;;   3. inside `step`, the `operation-id` echo -- the `$n` length load, the
;;      512-byte clamp, the `$copy` call into the 0x1000 scratch block, and the
;;      two result stores at 2064/2068 -- is REPLACED by two stores of a forged
;;      literal pointer/length pair. The 0x1000 scratch block is therefore no
;;      longer written by this fixture and stays reserved and unused. The
;;      `$n` local and the `$copy` helper are still used by the `state.fence-epoch`
;;      echo, so no helper is added, dropped or changed;
;;   4. ONE data segment is ADDED, at 0x900, carrying the forged literal. No
;;      other data segment is added, removed, moved or resized.
;; Nothing else differs. Same single 1-page memory `(memory (export "memory") 1 1)`,
;; same guest bump allocator base `$bump` = 5120 (0x1400), same `$copy` and
;; `$realloc` helper bodies, same honest `describe`, same honest `state.fence-epoch`
;; echo, same zeroed `from-phase`/`to-phase`/`disposition`/`proof-ceiling` bytes,
;; same zero-length `emitted`/`frontier` lists, zero imports, exactly one exported
;; interface `eliot:current/cycle@0.1.0` exposing only `describe` and the world
;; domain function `step`. No bulk-memory instruction, no `memory.fill`, no second
;; memory, no second export.
;;
;; (b) DERIVED ADDRESS ARITHMETIC for the forged store.
;; `step` returns ONE core value: a lifted result that does not fit
;; MAX_FLAT_FUNC_RESULTS = 1 (wasmparser-0.252.0
;; src/validator/component_types.rs:36) clears the flat results and pushes
;; exactly one pointer for `Abi::Lift` (same file :1272-1274), a signature the
;; export check enforces at src/validator/component.rs:1328 and :1350.
;; With that one pointer = 2048 (0x800):
;;   2048        `result<cycle-outcome, cycle-error>` discriminant, one byte
;;               (variant_static, wasmtime-environ-47.0.4/src/component/types.rs:841);
;;               payload_offset32 = align_to(1, 8) = 8 (types.rs:950; align 8 because
;;               cycle-step-result carries dreamer-state's u64) -> payload 2056
;;   2056        `cycle-outcome` variant case discriminant; payload_offset32 =
;;               align_to(1, 8) = 8 (types.rs:950) -> payload 2064
;;   2064        cycle-step-result record base
;; cycle-step-result (bins/eliot-wasm-host/wit/typed/dreamer-cycle.wit:133) declares
;; `operation-id: string` as its FIRST field (:134). A WIT `string` lowers to
;; POINTER_PAIR, size32 = 8 and align32 = 4 (types.rs:707-709), placed by
;; next_field32 (types.rs:756-759: offset = align_to(offset, 4) + 8, returning
;; offset - 8). From offset 0: align_to(0, 4) + 8 = 8 -> the field sits at record
;; offset 0. So:
;;   2064 + 0 = 2064 -> (ptr), 2068 -> (len)
;; which is exactly what this file writes:
;;   (i32.store (i32.const 2064) (i32.const 2304))   ;; ptr  = 0x900, the forged literal
;;   (i32.store (i32.const 2068) (i32.const 36))     ;; len  = 36 bytes, the literal's real length
;; CROSS-CHECK against the two checked-in siblings that store the SAME record,
;; `cycle-step-result`, at the SAME base: dreamer-cycle.wat:174-175
;; (2064 = 4096 scratch, 2068 = $n) and raised-proof-ceiling.wat:209-210
;; (2064 = 4096 scratch, 2068 = $n). Neither address was chosen by hand here.
;; The forged literal lives at 0x900 (2304), which is inside the same single
;; page, above the last result-tuple store and below the 0x1000/0x1200 scratch
;; blocks, so it collides with nothing: 0x900..0x923 is written by this file's
;; own data segment and by nothing else. The last result-tuple store this file
;; performs is the `state.fence-epoch` length at 2120, i.e. the
;; `(i32.store (i32.const 2120) (local.get $n))` inside `step` below, covering
;; 2120..2124 = 0x848..0x84c; 2128 is `state.fence-generation`, which this
;; fixture never writes. The `describe` retptr block is at 0x600 (1536), i.e.
;; every `(i32.store (i32.const 1536) ...)` / `(i32.store (i32.const 1540)
;; ...)` pair of the exported `describe` below, so 0x900 sits ABOVE it, not
;; below it.
;;
;; WHY THE FORGED LITERAL CANNOT EQUAL THE ADMITTED VALUE. It is a fixed
;; 36-byte constant, "forged-operation-id-758-not-admitted", planted by a data
;; segment; the guest never reads the request for it, so no admitted value can
;; make it match. Every admitted operation-id checked in this repository is a
;; short token: "op" (the test-module constant `const OPERATION_ID: &str = "op"`
;; in src/typed_execution.rs -- cited by symbol and quoted source text, not by
;; line, because that file is edited underneath this comment) or "operation-758"
;; (the `operation-758` literal in the `governed_admission` fixture in
;; tests/typed_execution.rs - cited by name, not by line, because that file is
;; being edited underneath this comment). 36 printable bytes that begin with "forged"
;; cannot equal a 2-byte or a 12-byte token.
;;
;; (c) THE FORGED FIELD IS THE FIRST CHECK THAT CAN FAIL. This block cites by
;; SYMBOL, not by line: every `fn` named below lives in src/typed_execution.rs
;; and every backquoted string is verbatim source text, so the block survives
;; edits made above the cited statements. In call order through `fn
;; execute_domain_lane` -- the interior lane whose body ends
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
;;   `TypedWorld::interface_name` (src/typed_bindings.rs:133) -> "cycle", i.e.
;;   "eliot:current/cycle@0.1.0" — one of TWO export SPELLINGS the admission
;;   gate accepts. `export_matches_interface` (src/typed_bindings.rs:181) admits
;;   the first alternative, `format!("{TYPED_PACKAGE_ID}/{interface}")` at
;;   src/typed_bindings.rs:185, which yields `eliot:current@0.1.0/cycle` because
;;   `TYPED_PACKAGE_ID` is "eliot:current@0.1.0" (src/typed_bindings.rs:24); and
;;   the second alternative,
;;   `format!("eliot:current/{interface}@{TYPED_WIT_VERSION}")` at
;;   src/typed_bindings.rs:186, which yields `eliot:current/cycle@0.1.0` because
;;   `TYPED_WIT_VERSION` is "0.1.0" (src/typed_bindings.rs:26). The string named
;;   on the line above is the SECOND one, not the first.
;;   CAREFUL: OF THOSE TWO SPELLINGS, THIS FILE EXPORTS ONLY THE SECOND. What it
;;   plants as the lie is the bare `eliot:current@0.1.0` in the abi-descriptor's
;;   "package-id" field (`describe` below; data segment at 1037, length 19), which
;;   is this fixture family's lie and the reason a sibling fixture exists at all.
;;   An earlier version of this comment said "which is what this file exports" and
;;   contradicted its own fixture body.
;;   `ComponentItem::ComponentInstance` requires the export to be a component
;;   instance; the `for (name, item) in interface_type.exports(engine)` loop
;;   permits no callable or structural export outside `describe` and `step`;
;;   `component_function` must resolve both in the instance type; and
;;   `typecheck_world_signatures(world, &descriptor, &domain, component)?`,
;;   whose `TypedWorld::DreamerCycle` arm requires this component's declared
;;   `step` parameter, result and error types to match
;;      `(wit::CycleStepInput,), (Result<wit::CycleOutcome, wit::CycleError>,)`.
;;      That is the check that requires the DECLARED TYPES ABOVE to equal the
;;      frozen WIT records -- record for record, field for field, in WIT order --
;;      and it is the check a WIT-absent record field fails: inside `fn
;;      typecheck_world_signatures`, the TypedWorld::DreamerCycle arm carries the
;;      verbatim statement
;;      `.map_err(|_| TypedExecutionError::ExportTypeMismatch("step".to_owned()))?;`
;;      (leading indentation trimmed), so the mismatch is denied before `step`
;;      is dispatched at all. Nothing below is reached if it fails, so this
;;      file's type declarations are load-bearing for this fixture, not
;;      decoration.
;;   `validate_descriptor(world, &descriptor, limits.max_output_bytes)` -- inside
;;   `fn validate_descriptor`: `if descriptor.world_name != world.world_name()`
;;   -> `TypedWorld::world_name` (src/typed_bindings.rs:120) -> "dreamer-cycle";
;;   `if descriptor.package_id != crate::typed_bindings::TYPED_PACKAGE_ID`;
;;   `if descriptor.abi_revision != TYPED_ABI_REVISION`; then the five
;;   `bounded_descriptor_string(...)` calls. `describe` is copied verbatim from
;;   the honest sibling, so every one of these reads its true value.
;;   `validate_descriptor_abi_digest(&descriptor)` -- inside `fn
;;   validate_descriptor_abi_digest`: `if descriptor.abi_digest !=
;;   typed_wit_digest().as_str()`. The abi-digest data segment is copied
;;   verbatim from dreamer-cycle.wat:205, so it is the real digest of the frozen
;;   WIT bytes, not a fixture-chosen value.
;;   `check_result(&result, admitted, &mut output_bound)` -- inside `fn
;;   check_result`, the arm `TypedDomainOutcome::DreamerCycle(value) =>
;;   check_cycle_result(value, admitted, bound)`; inside `fn check_cycle_result`
;;   `let R::Stepped(body) = value;` binds because this file writes the ok
;;   discriminant 0 at 2048 and the "stepped" case discriminant 0 at 2056.
;;   `check_echo(&body.operation_id, &admitted.operation_id, "operation-id")?;`
;;      <-- THIS FIXTURE FORGES THIS FIELD. First failure.
;; Everything after that `check_echo` is never reached. For the record, the
;; checks after it would have passed anyway: the `check_echo` of
;; `&body.state.fence_epoch` against `&admitted.fence_epoch` (field
;; `"fence-epoch"`) echoes the request honestly (dreamer-cycle.wat:194-196 kept
;; here, and the caller builds that request's `state.fence-epoch` from the
;; admitted record -- `fence_epoch: admitted.fence_epoch.clone()` inside
;; `state: cycle_wit::DreamerState { ... }` of `fn cycle_request` in
;; src/typed_execution.rs -- so observed == admitted), and the `check_ceiling`
;; of `ceiling_cycle(body.proof_ceiling)` against `admitted.proof_ceiling`
;; (field `"proof-ceiling"`) reads the zeroed `proof-ceiling` byte as enum case
;; 0 = "observation", `fn proof_rank` rank 0, which is not above any admitted
;; ceiling (`fn proof_rank` in src/typed_execution.rs).
;;
;; (d) THE PRODUCTION LINE THAT COMPARES THE FORGED FIELD, BY SYMBOL. Each item
;; is a `fn` name in bins/eliot-wasm-host/src/typed_execution.rs plus the
;; verbatim source text of the statement, deliberately NOT a line number: this
;; file is edited underneath its own header, and a bare `:NNNN` rots silently.
;;   fn check_cycle_result
;;     let R::Stepped(body) = value;
;;     check_echo(&body.operation_id, &admitted.operation_id, "operation-id")?;
;;   <-- THE LINE THAT COMPARES THE FORGED FIELD
;; reached from `fn check_result`, whose
;;     TypedDomainOutcome::DreamerCycle(value) => check_cycle_result(value, admitted, bound)
;; arm selects it. The comparison that fires is inside `fn check_echo`:
;;   fn check_echo(
;;     observed: &str,
;;     admitted: &str,
;;     field: &'static str,
;; ) -> Result<(), TypedExecutionError> {
;;     if observed != admitted {
;;         return Err(TypedExecutionError::OutputViolation(field.to_owned()));
;;     }
;; so the denial is TypedExecutionError::OutputViolation("operation-id"). The
;; caller stages it as TypedStage::Output at
;;     check_result(&result, admitted, &mut output_bound)
;;         .map_err(|error| staged(TypedStage::Output, error))?;
;; inside `fn execute_domain_lane`, whose body ends `Ok((receipt, result))`.
;;
;; (e) LIMITS OF THIS FIXTURE, stated rather than hidden.
;;   - It proves the `check_echo` denial for the CYCLE world's operation-id only.
;;     `TypedDomainOutcome::DreamerCycle` is the only arm that reaches the
;;     forged-field `check_echo` in (d). The `:NNNN` figures in this bullet are
;;     line positions of `check_echo` CALL SITES, which have no symbol of their
;;     own; re-derive them from the `fn`s named in (c) and (d) above.
;;     There are TWELVE `check_echo` operation-id sites in the crate: six on the
;;     REQUEST side (:3161 :3211 :3239 -- the activation world's `request-id` --
;;     :3261 :3289 :3316, one per world) and six on the RESULT side (:3466
;;     admission, :3520 assembly, :3560 activation, :3583 handler, :3603 screen,
;;     :3629 cycle). This file reaches exactly one of the six result-side sites
;;     and says nothing about the other eleven.
;;   - It denies at the OUTPUT stage. Nothing downstream of `check_result` -- no
;;     receipt, no shared receipt, no semantic digest -- is produced, so the
;;     fixture cannot also demonstrate a successful foreign-echo-free run.
;;   - The forged literal is longer than any admitted leaf, so it also proves
;;     the gate compares by value and not by length; it does NOT separately
;;     exercise the length-only path, because the denial is a value denial.
;;   - The fixture still echoes `state.fence-epoch` honestly. That is deliberate:
;;     forging it too would move the first failure to the `fence-epoch`
;;     `check_echo` that follows it, and would prove nothing about the
;;     `operation-id` `check_echo` in (d).
(component
  (type $abi_descriptor (record
    (field "world-name" string)
    (field "package-id" string)
    (field "abi-revision" u32)
    (field "native-contract" string)
    (field "native-revision" string)
    (field "abi-digest" string)
  ))
  (type $cycle_phase (enum "validated" "bundle-validated" "screened" "model-observed" "grounding-validated" "common-validated" "handler-observed" "intrinsic-output-checked" "external-admission" "closure-observed"))
  (type $request_kind (enum "bundle-validation" "curation-screen" "model-invocation" "grounding" "common-validation" "semantic-handler" "intrinsic-output" "external-admission" "closure" "effect-reconciliation" "clarification"))
  (type $pending_request (record
    (field "request-id" string)
    (field "operation-id" string)
    (field "idempotency-key" string)
    (field "kind" $request_kind)
  ))
  (type $outcome_disposition (enum "accepted" "rejected" "not-attempted" "completed" "partial" "failed-before-effect" "unknown" "cancelled" "expired" "superseded" "unavailable" "stale"))
  (type $observed_outcome (record
    (field "request-id" string)
    (field "operation-id" string)
    (field "disposition" $outcome_disposition)
    (field "evidence-digest" string)
  ))
  (type $dreamer_state (record
    (field "schema-version" u32)
    (field "phase" $cycle_phase)
    (field "revision" u32)
    (field "state-digest" string)
    (field "pending" (list $pending_request))
    (field "observed" (list $observed_outcome))
    (field "fence-epoch" string)
    (field "fence-generation" u64)
  ))
  (type $cycle_policy (record
    (field "schema-version" u32)
    (field "policy-revision" string)
    (field "max-records" u16)
    (field "max-requests" u16)
    (field "max-canonical-bytes" u32)
  ))
  (type $cycle_step_input (record
    (field "schema-revision" u32)
    (field "operation-id" string)
    (field "task-id" string)
    (field "scope-id" string)
    (field "fence-epoch" string)
    (field "fence-generation" u64)
    (field "state" $dreamer_state)
    (field "policy" $cycle_policy)
    (field "deadline-ms" (option s64))
    (field "cancelled" bool)
    (field "predecessor-digest" (option string))
  ))
  (type $step_disposition (enum "advanced" "waiting" "blocked" "stale" "cancelled" "expired"))
  (type $inert_owner_request (record
    (field "request-id" string)
    (field "operation-id" string)
    (field "kind" $request_kind)
    (field "target-note" string)
  ))
  (type $proof_ceiling (enum "observation" "candidate-only" "admission" "assembly" "activation" "screen" "cycle" "handler"))
  (type $cycle_step_result (record
    (field "operation-id" string)
    (field "from-phase" $cycle_phase)
    (field "to-phase" $cycle_phase)
    (field "disposition" $step_disposition)
    (field "state" $dreamer_state)
    (field "emitted" (list $inert_owner_request))
    (field "frontier" (list string))
    (field "proof-ceiling" $proof_ceiling)
    (field "result-digest" string)
  ))
  (type $cycle_outcome (variant
    (case "stepped" $cycle_step_result)
  ))
  (type $cycle_malformed (record
    (field "field" string)
    (field "human-detail" string)
  ))
  (type $cycle_stale (record
    (field "human-detail" string)
  ))
  (type $cycle_bound (record
    (field "human-detail" string)
  ))
  (type $cycle_schema (record
    (field "want-revision" u32)
    (field "got-revision" u32)
    (field "human-detail" string)
  ))
  (type $cycle_internal (record
    (field "human-detail" string)
  ))
  (type $cycle_error (variant
    (case "malformed" $cycle_malformed)
    (case "stale-transition" $cycle_stale)
    (case "bound-exceeded" $cycle_bound)
    (case "unsupported-schema" $cycle_schema)
    (case "internal" $cycle_internal)
  ))
  (type $f-describe (func (result $abi_descriptor)))
  (type $f-domain (func (param "input" $cycle_step_input) (result (result $cycle_outcome (error $cycle_error)))))
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
    ;; Retptr base 0x600: past the last descriptor byte at 0x478 and below
    ;; the 0x800 result tuple, so it collides with nothing in this memory.
    ;; Copied verbatim from dreamer-cycle.wat: this fixture's forgery lives in
    ;; `step` below, never in the descriptor.
    (func (export "describe") (result i32)
      ;; world-name
      (i32.store (i32.const 1536) (i32.const 1024))
      (i32.store (i32.const 1540) (i32.const 13))
      ;; package-id
      (i32.store (i32.const 1544) (i32.const 1037))
      (i32.store (i32.const 1548) (i32.const 19))
      ;; abi-revision
      (i32.store (i32.const 1552) (i32.const 1))
      ;; native-contract
      (i32.store (i32.const 1556) (i32.const 1056))
      (i32.store (i32.const 1560) (i32.const 19))
      ;; native-revision
      (i32.store (i32.const 1564) (i32.const 1075))
      (i32.store (i32.const 1568) (i32.const 5))
      ;; abi-digest
      (i32.store (i32.const 1572) (i32.const 1080))
      (i32.store (i32.const 1576) (i32.const 64))
      (i32.const 1536))
    ;; `step`: the admitted typed request arrives already lowered into guest
    ;; memory. The request's own "fence-epoch" (record offset 28/32) is copied
    ;; into the result's "state.fence-epoch", which the host echo check pins.
    ;; `operation-id` is not echoed at all: it is the forged literal below.
    (func (export "step") (param $req i32) (result i32)
      (local $n i32)
      ;; result ok case: the WIT success variant
      (i32.store (i32.const 2048) (i32.const 0))
      ;; variant "cycle-outcome" selects WIT case "stepped"
      (i32.store (i32.const 2056) (i32.const 0))
      ;; IDENTITY FORGERY: `operation-id` is NOT copied from the lowered
      ;; request. cycle-step-result.operation-id is record offset 0 (first field,
      ;; dreamer-cycle.wit:134) and a string lowers to a (ptr, len) POINTER_PAIR
      ;; of 8 bytes (wasmtime-environ-47.0.4/src/component/types.rs:707-709) at
      ;; 2064 + 0 = 2064 and 2068 (record base 2064 derived in the header).
      ;; The pair points at this file's own data-segment literal "forged-
      ;; operation-id-758-not-admitted" at 0x900 = 2304, length 36. No admitted
      ;; operation-id can equal it, so check_echo must deny.
      (i32.store (i32.const 2064) (i32.const 2304))
      (i32.store (i32.const 2068) (i32.const 36))
      ;; echo the lowered request's OWN "fence-epoch" (record offset 28/32);
      ;; Canonical-ABI derivation, pinned to wasmtime 47.0.4 /
      ;; wasmtime-environ-47.0.4 (CARGO_HOME registry):
      ;;   result<cycle-outcome, cycle-error> retptr base 0x800 (2048);
      ;;     discriminant at +0 (CanonicalAbiInfo::variant_static,
      ;;     wasmtime-environ-47.0.4/src/component/types.rs:841; payload at
      ;;     payload_offset32 = align_to(1, align32) = 8, types.rs:950) -> 2056
      ;;   cycle-outcome "stepped" payload at 2056 + 8 = 2064 (types.rs:950)
      ;;   cycle-step-result.state at record offset 16 (operation-id string
      ;;     8 bytes at 0; from-phase/to-phase/disposition one-byte enums at
      ;;     8/9/10, so align_to(11, 8) = 16; CanonicalAbiInfo::next_field32,
      ;;     types.rs:756) -> 2080
      ;;   dreamer-state.fence-epoch at record offset 36 (u32 0, enum 4,
      ;;     u32 8, state-digest 12, pending 20, observed 28 -> align_to(36,4)=36)
      ;;     -> 2080 + 36 = 2116 (ptr), 2120 (len, POINTER_PAIR 8 bytes,
      ;;     types.rs:707)
      ;; Writing 2124/2128 would place the pair in the pad before
      ;; fence-generation and inside fence-generation itself.
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 32))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 4608) (i32.load (i32.add (local.get $req) (i32.const 28))) (local.get $n))
      (i32.store (i32.const 2116) (i32.const 4608))
      (i32.store (i32.const 2120) (local.get $n))
      (i32.const 2048))
    (export "realloc" (func $realloc))
    (data (i32.const 1024) "dreamer-cycle")
    (data (i32.const 1037) "eliot:current@0.1.0")
    (data (i32.const 1056) "eliot-dreamer-cycle")
    (data (i32.const 1075) "0.1.0")
    (data (i32.const 1080) "6e878cbb40e2060fd2d570345a1b0105920a0398b3c70e2c4e1f9b7eb291a0e6")
    (data (i32.const 2304) "forged-operation-id-758-not-admitted")
  )
  (core instance $guest (instantiate $guest))
  (alias core export $guest "memory" (core memory $memory))
  (alias core export $guest "realloc" (core func $realloc))
  (alias core export $guest "describe" (core func $describe))
  (alias core export $guest "step" (core func $domain))
  (func $describe (type $f-describe)
    (canon lift (core func $describe) (memory $memory) (realloc $realloc)))
  (func $domain (type $f-domain)
    (canon lift (core func $domain) (memory $memory) (realloc $realloc)))
  (instance $iface
    (export "abi-descriptor" (type $abi_descriptor))
    (export "cycle-bound" (type $cycle_bound))
    (export "cycle-error" (type $cycle_error))
    (export "cycle-internal" (type $cycle_internal))
    (export "cycle-malformed" (type $cycle_malformed))
    (export "cycle-outcome" (type $cycle_outcome))
    (export "cycle-phase" (type $cycle_phase))
    (export "cycle-policy" (type $cycle_policy))
    (export "cycle-schema" (type $cycle_schema))
    (export "cycle-stale" (type $cycle_stale))
    (export "cycle-step-input" (type $cycle_step_input))
    (export "cycle-step-result" (type $cycle_step_result))
    (export "dreamer-state" (type $dreamer_state))
    (export "inert-owner-request" (type $inert_owner_request))
    (export "observed-outcome" (type $observed_outcome))
    (export "outcome-disposition" (type $outcome_disposition))
    (export "pending-request" (type $pending_request))
    (export "proof-ceiling" (type $proof_ceiling))
    (export "request-kind" (type $request_kind))
    (export "step-disposition" (type $step_disposition))
    (export "describe" (func $describe))
    (export "step" (func $domain)))
  (export "eliot:current/cycle@0.1.0" (instance $iface))
)
