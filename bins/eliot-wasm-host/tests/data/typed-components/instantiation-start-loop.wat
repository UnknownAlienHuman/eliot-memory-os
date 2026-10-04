;; ELIOT typed NEGATIVE fixture for case 13 of #758: "infinite loop fuel
;; exhaustion, including descriptor/initialization" -- the INITIALIZATION half.
;;
;; `looping-describe.wat` covers the descriptor half. This fixture covers the
;; other half the issue names: the component's own initialization is untrusted
;; execution too (issue #758 P6.2: "The descriptor call and component
;; initialization are untrusted execution and must receive the same applicable
;; limits, not only the later domain call").
;;
;; The core module declares a `(start ...)` function whose loop has no exit.
;; `describe_dreamer_cycle` (`bins/eliot-wasm-host/src/typed_execution.rs`,
;; fn `describe_dreamer_cycle`, lines 1809-1842) runs
;; `DreamerCycle::instantiate` inside `run_guarded`, so the admitted fuel
;; budget (`typed_fuel_budget`, same file lines 1407-1412), the store resource
;; ceilings (`new_store`, same file lines 1414-1443) and the epoch deadline
;; (`EpochDriver::spawn`, same file lines 1525-1556) all apply to it exactly as
;; they apply to the later `describe`
;; call. The engine therefore genuinely terminates this instantiation: with
;; `EpochAndFuel` it is `wasmtime::Trap::OutOfFuel`
;; (wasmtime-environ-47.0.4 `trap_encoding.rs`:145, "all fuel consumed by
;; WebAssembly"), and with `EpochInterruption` it is `Trap::Interrupt`
;; (same file :141, "interrupt").
;;
;; WHAT THE HOST REPORTS: the typed fuel/epoch cause this case requires.
;; `describe_dreamer_cycle` routes the instantiate failure through
;; `map_instantiate_error` (`bins/eliot-wasm-host/src/typed_execution.rs`,
;; fn `map_instantiate_error`, lines 1322-1355, applied at same-file
;; lines 1818-1823), which
;; classifies in this order:
;; `store.data().limit_hit` first (same file lines 1326-1328), then
;; `is_instance_limit_error` (same-file lines 1332-1334, which needs "instance"
;; plus -- `bins/eliot-wasm-host/src/wasmtime_provider.rs`, fn
;; `is_instance_limit_error`, lines 767-770, the only `wasmtime_provider.rs` in
;; the repository -- "limit"/"maximum"), then the shared
;; `trap_termination` classifier
;; (same-file lines 1343-1345), and only then the substring fallbacks for
;; "import" (same-file lines 1347-1348),
;; "export"/"missing"/"type" (same-file lines 1349-1352). Component
;; initialization is
;; untrusted execution too and runs inside the same guarded envelope as the
;; descriptor call, so an instantiation the engine terminates with a real trap
;; carries the owner-typed cause read from the real engine trap code, never
;; from message text: `trap_termination`
;; (`bins/eliot-wasm-host/src/typed_execution.rs`,
;; fn `trap_termination`, lines 1293-1302) maps
;; `Trap::OutOfFuel` to `EngineTermination::FuelExhausted` (same-file line 1296,
;; `wasmtime::Trap::OutOfFuel => EngineTermination::FuelExhausted,`) and
;; `Trap::Interrupt` to `EngineTermination::EpochDeadline` (same-file line 1297,
;; `wasmtime::Trap::Interrupt => EngineTermination::EpochDeadline,`).
;;
;; So this fixture denies with `Engine("FuelExhausted")` under the default
;; `EpochAndFuel` policy and `Engine("EpochDeadline")` under
;; `CancellationPolicy::EpochInterruption`, both staged `TypedStage::Instantiate`
;; by the `staged` wrapper at `bins/eliot-wasm-host/src/typed_execution.rs`
;; lines 1817-1823. The untyped
;; `Engine("instantiate:component-error")` (same file line 1353) is now only the
;; fallback
;; for an engine error that is not a trap at all. This is the same classifier
;; `map_call_error` (`bins/eliot-wasm-host/src/typed_execution.rs`,
;; fn `map_call_error`, lines 1304-1320) applies to the later `describe`/domain
;; leg, so
;; both untrusted-execution legs carry the same typed cause.
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
    ;; Component initialization that never returns. A core-module start function
    ;; is ordinary untrusted guest execution that runs inside
    ;; `DreamerCycle::instantiate`, i.e. inside the one guarded envelope of
    ;; `run_guarded` (`bins/eliot-wasm-host/src/typed_execution.rs`,
    ;; fn `run_guarded`, lines 1578-1610) and therefore under the same
    ;; fuel budget, store resource ceilings and epoch deadline as `describe`
    ;; (`typed_fuel_budget`, same file lines 1407-1412; `new_store`, same file
    ;; lines 1414-1443;
    ;; `EpochDriver::spawn`, same file lines 1525-1556). It touches no memory and calls nothing, so only
    ;; fuel exhaustion or the epoch deadline can stop it. The two exports below
    ;; are never reached, which is the point, and each names its whole
    ;; difference from `dreamer-cycle.wat`: `step` is that fixture's `step`
    ;; unchanged, and `describe` differs from it in exactly one respect -- the
    ;; descriptor retptr base is 0x0c00 here instead of 0x600 there, with the
    ;; same eleven-word record written at 3072..3116 instead of 1536..1580.
    (func $init (local $spin i64)
      (loop $forever
        (local.set $spin (i64.add (local.get $spin) (i64.const 1)))
        (br $forever)))
    (start $init)
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
    ;; the frozen ABI revision, lowered in WIT field order into guest memory.
    ;;
    ;; This body carries the honest `dreamer-cycle` descriptor VALUES and is
    ;; dead code: `(start $init)` above never returns, so instantiation never
    ;; completes and this export is never called. It is not byte-identical to
    ;; `dreamer-cycle.wat`'s `describe`: that one returns 1536 (0x600) and
    ;; writes the eleven-word record at 1536..1580, this one returns 3072
    ;; (0x0c00) and writes the same eleven values at 3072..3116. The store and
    ;; the single returned pointer are still written here, because the
    ;; obligation this file proves is that component INITIALIZATION is
    ;; terminated by the fuel/epoch policy, and `$init` -- not this body --
    ;; is what runs. Nothing below weakens or shortens the start loop.
    ;;
    ;; `canon lift` flattens `abi-descriptor` to ELEVEN core values (five
    ;; `string` fields as (ptr, len) plus `abi-revision: u32`), but a lifted
    ;; RESULT that does not fit `MAX_FLAT_FUNC_RESULTS` (1) lowers to a SINGLE
    ;; pointer to guest-owned memory: wasmparser-0.252.0
    ;; `validator/component_types.rs`:36 and :1261-1276 clear the flat results
    ;; and push exactly one pointer for `Abi::Lift`, and
    ;; `validator/component.rs`:1328/:1350 require that one-pointer signature.
    ;; The returned pointer is 0x0c00; the eleven words occupy 0x0c00..0x0c2b.
    ;; Occupied: 0x0400..0x0477 the descriptor strings, 0x0800..0x0878 the
    ;; `step` result tuple, 0x1000 and 0x1200 the two echo scratch blocks, 0x1400 the
    ;; `realloc` bump region. `$init` writes nothing at all, so it collides
    ;; with nothing. 0x0c00 is clear of all of the above.
    (func (export "describe") (result i32)
      (i32.store (i32.const 3072) (i32.const 1024))
      (i32.store (i32.const 3076) (i32.const 13))
      (i32.store (i32.const 3080) (i32.const 1037))
      (i32.store (i32.const 3084) (i32.const 19))
      (i32.store (i32.const 3088) (i32.const 1))
      (i32.store (i32.const 3092) (i32.const 1056))
      (i32.store (i32.const 3096) (i32.const 19))
      (i32.store (i32.const 3100) (i32.const 1075))
      (i32.store (i32.const 3104) (i32.const 5))
      (i32.store (i32.const 3108) (i32.const 1080))
      (i32.store (i32.const 3112) (i32.const 64))
      (i32.const 3072)
    )
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
