;; ELIOT typed NEGATIVE fixture for case 14 of #758: "supported deadline
;; independent of fuel; no false synchronous compile-cancellation guarantee".
;;
;; A guest that burns wall time without burning fuel and without touching memory
;; can only be stopped by the injected epoch/wall deadline. This component's
;; `describe` is exactly that: an unbounded counted integer spin on locals -- an
;; inner counter bounded at 20000 per outer turn, inside an outer loop whose
;; back-edge never exits -- with no memory traffic, no host call and no ambient
;; capability, so the resource and output ceilings are silent and the admitted
;; fuel budget is not even installed when the cancellation policy is
;; `EpochInterruption`.
;;
;; The result is `wasmtime::Trap::Interrupt`, mapped by `map_call_error`
;; (`bins/eliot-wasm-host/src/typed_execution.rs`, fn `map_call_error`, which
;; returns `TypedExecutionError::Engine(format!("{termination:?}"))` from
;; `trap_termination`) to `EngineTermination::EpochDeadline` -- the exact arm fn
;; `trap_termination` reads is
;; `wasmtime::Trap::Interrupt => EngineTermination::EpochDeadline,` -- and is
;; reported as `TypedExecutionError::Engine("EpochDeadline")` staged at
;; `TypedStage::Descriptor`. The deadline comes from the host-driven epoch pump
;; (`EpochDriver::spawn`, `bins/eliot-wasm-host/src/typed_execution.rs`,
;; lines 1525-1556), which forces the epoch once
;; `wall_deadline_ms` expires: a real supported interruption, not a dropped
;; caller future and not a claimed synchronous compile cancellation.
;;
;; Memory map: 0x0000-0x03ff reserved, 0x0400 descriptor strings,
;; 0x0800 the lowered `step` result tuple, 0x1000 and 0x1200 the two echo scratch
;; blocks, 0x1400 the bump region the host `realloc` hands out while lowering the request.
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
    ;; `describe`: the frozen WIT abi-descriptor shape. The signature is the
    ;; single `i32` retptr that `canon lift` of a record flattening to more than
    ;; `MAX_FLAT_FUNC_RESULTS` (1) core values demands: wasmparser-0.252.0
    ;; `validator/component_types.rs`:36 and :1261-1276 clear the flat results
    ;; and push exactly one pointer for `Abi::Lift`, and
    ;; `validator/component.rs`:1328/:1350 require that one-pointer signature.
    ;;
    ;; The spin below is the whole obligation of this file: with
    ;; `CancellationPolicy::EpochInterruption` the store carries NO fuel at all
    ;; (`typed_fuel_budget`, `bins/eliot-wasm-host/src/typed_execution.rs`
    ;; lines 1407-1412, whose `None` arm is
    ;; `CancellationPolicy::EpochInterruption => None,`; and
    ;; `new_store`, same file lines 1414-1443, never calls `set_fuel`, which is
    ;; only reached at same-file lines 1436-1439), so the only thing that
    ;; can end this call is the injected epoch/wall deadline
    ;; (`EpochDriver::spawn`, same file lines 1525-1556; `Trap::Interrupt` maps to
    ;; `EngineTermination::EpochDeadline` at same-file line 1297, the arm quoted
    ;; in the header above). No retptr region is written
    ;; and no descriptor value is produced, because adding a store or a return
    ;; here would destroy exactly the obligation this file exists to prove.
    (func (export "describe") (result i32)
      (local $outer i32)
      (local $inner i32)
      (local $acc i64)
      ;; Counted and completely silent: this spin touches locals only. The inner
      ;; counter is bounded at 20000 per outer turn, but the OUTER back-edge is an
      ;; UNCONDITIONAL `(br $ol)`, so control never leaves the outer loop: the
      ;; declared `(result i32)` is validated by an unreachable frame rather than
      ;; by a terminal value, which is why there is no return constant here and
      ;; why the descriptor is produced by no path. It loads nothing, stores
      ;; nothing, grows nothing and calls nothing, so no memory, table or output
      ;; ceiling can account for stopping it; with the admitted
      ;; `CancellationPolicy::EpochInterruption` there is no fuel installed, so
      ;; the injected epoch/wall deadline is the only terminator.
      (loop $ol
        (local.set $inner (i32.const 0))
        (local.set $acc (i64.add (local.get $acc) (i64.const 1)))
        (loop $il
          (local.set $acc (i64.mul (local.get $acc) (i64.const 3)))
          (local.set $acc (i64.add (local.get $acc) (i64.const 1)))
          (local.set $inner (i32.add (local.get $inner) (i32.const 1)))
          (br_if $il (i32.lt_u (local.get $inner) (i32.const 20000))))
        (local.set $outer (i32.add (local.get $outer) (i32.const 1)))
        (br $ol)))
    ;; `step`: the admitted typed request arrives already lowered into guest
    ;; memory. The closed WIT result tuple is written in full and every
    ;; identity field is copied back out of the request, so the host echo
    ;; check compares values the guest actually read.
    (func (export "step") (param $req i32) (result i32)
      (local $n i32)
      ;; result ok case: the WIT success variant
      (i32.store (i32.const 2048) (i32.const 0))
      ;; variant "cycle-outcome" selects WIT case "stepped"
      (i32.store (i32.const 2056) (i32.const 0))
      ;; echo "operation-id" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 8))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 4096) (i32.load (i32.add (local.get $req) (i32.const 4))) (local.get $n))
      (i32.store (i32.const 2064) (i32.const 4096))
      (i32.store (i32.const 2068) (local.get $n))
      ;; echo the lowered request's OWN "fence-epoch" (record offset 28/32);
      ;; canonical-ABI: `state.fence-epoch` is dreamer-state record offset 36
      ;; (next_field32, wasmtime-environ-47.0.4/src/component/types.rs:756) as a
      ;; POINTER_PAIR (wasmtime-environ-47.0.4/src/component/types.rs:707) -> 2080 + 36 = 2116 (ptr) and 2120 (len).
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
