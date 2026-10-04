;; ELIOT typed NEGATIVE fixture for case 16 of #758: "table/instance/resource/
;; host-lifting exhaustion" -- the host-lifting half.
;;
;; A guest that can make the HOST allocate and measure is a host-lifting
;; exhaustion risk, so every list leaf is bounded before it is folded into the
;; call's output budget. `check_cycle_result` (typed_execution.rs:3605-3632)
;; measures `state.pending` with `TypedBound::list` (:838-848), which refuses
;; more than `MAX_TYPED_LIST_ITEMS` (256) items with
;; `TypedExecutionError::LimitDenied("typed-list")`, staged at
;; `TypedStage::Output` by `execute_domain_lane` (:2113-2114).
;;
;; This component is an honest `dreamer-cycle` fixture except for two things.
;; The hostile lifted length: `describe` reports the true frozen descriptor, the
;; domain result echoes the admitted `operation-id` and `fence-epoch` and
;; claims the lowest proof ceiling, and only `state.pending` carries 300
;; elements. And where the `describe` retarea sits: base 0x0c00 here, its eleven
;; core words ending 0x0c2b, against `dreamer-cycle.wat`'s 0x0600 -- the same
;; eleven values, so nothing about the reported descriptor changes. The type
;; surface, the `$copy` helper, `realloc`, the `(global $bump (mut i32) (i32.const
;; 45056))` bump start, the echo copies and all five `(data ...)` segments are
;; otherwise identical to that sibling. Every earlier check therefore passes and
;; the list item ceiling is provably the denial.
;;
;; Memory map: 0x0000-0x03ff reserved, 0x0400 descriptor strings,
;; 0x0800 the lowered `step` result tuple, 0x1000 and 0x1200 the two echo
;; scratch blocks -- `operation-id` at 0x1000 and `state.fence-epoch` at 0x1200,
;; each copy capped at 512 bytes --
;; 0x8000..0xa0d0 the 300-element hostile `state.pending` region
;; (32768 .. 32768 + 300*28 = 41168, the 28-byte `pending-request` record), and
;; 0xb000 the bump region the host `realloc` hands out while lowering the
;; request.
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
    (global $bump (mut i32) (i32.const 45056))
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
    ;; `canon lift` flattens `abi-descriptor` to ELEVEN core values (five
    ;; `string` fields as (ptr, len) plus `abi-revision: u32`), but a lifted
    ;; RESULT that does not fit `MAX_FLAT_FUNC_RESULTS` (1) lowers to a SINGLE
    ;; pointer to guest-owned memory: wasmparser-0.256.0
    ;; `validator/component_types.rs`:35 and :1276-1296 clear the flat results
    ;; and push exactly one pointer for `Abi::Lift`, and
    ;; `validator/component.rs`:1343/:1365 require that one-pointer signature.
    ;; The returned pointer is 0x0c00; the eleven words occupy 0x0c00..0x0c2b.
    ;; Occupied: 0x0400..0x0477 the descriptor strings, 0x0800..0x0878 the
    ;; `step` result tuple, 0x1000 and 0x1200 the two echo scratch blocks, 0x8000..0xa0d0
    ;; the hostile `state.pending` region, 0xb000 the `realloc` bump region.
    ;; 0x0c00 is clear of all five and inside the single exported page.
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
      ;; Hostile lifted length: `state.pending` is a `list<pending_request>` of
      ;; 300 elements pointing into the zeroed high region of this memory
      ;; (32768 .. 32768 + 300*28 = 41168, inside the 1-page core memory and
      ;; clear of every other region above; the `realloc` bump region starts at
      ;; 45056 so nothing this call lowers can overlap it). The host lifts all
      ;; 300 records and then measures the result, so the item ceiling -- not the
      ;; engine -- is what refuses it.
      ;; canonical-ABI: `state.pending` is dreamer-state record offset 20
      ;; (next_field32, wasmtime-environ-47.0.4/src/component/types.rs:756) as a
      ;; POINTER_PAIR (types.rs:707) -> 2080 + 20 = 2100 (ptr) and 2104 (len).
      (i32.store (i32.const 2100) (i32.const 32768))
      (i32.store (i32.const 2104) (i32.const 300))
      ;; echo "operation-id" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 8))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 4096) (i32.load (i32.add (local.get $req) (i32.const 4))) (local.get $n))
      (i32.store (i32.const 2064) (i32.const 4096))
      (i32.store (i32.const 2068) (local.get $n))
      ;; echo "state.fence-epoch" back out of the lowered request
      ;; canonical-ABI: `state.fence-epoch` is dreamer-state record offset 36
      ;; (next_field32, wasmtime-environ-47.0.4/src/component/types.rs:756) as a
      ;; POINTER_PAIR (types.rs:707) -> 2080 + 36 = 2116 (ptr) and 2120 (len).
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
    (export "describe" (func $describe))
    (export "step" (func $domain)))
  (export "eliot:current/cycle@0.1.0" (instance $iface))
)
