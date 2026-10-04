;; ELIOT typed NEGATIVE fixture for item 9 and P6.2 of #758: "artifact/raw-
;; input/item/string/list bounds before unbounded allocation" -- the
;; host-lifting STRING half, sibling of `host-lifting-list.wat`.
;;
;; A guest that can make the HOST allocate and measure is a host-lifting
;; exhaustion risk, so every string leaf is bounded as it is read, before it is
;; folded into the call's output budget. `check_cycle_result`
;; (`bins/eliot-wasm-host/src/typed_execution.rs`, fn `check_cycle_result`,
;; lines 3622-3649) charges `state.state-digest` with
;; `TypedBound::text` (same file, lines 845-853, whose guard is
;; `if value.len() > MAX_TYPED_STRING_BYTES {`), which refuses a lifted string
;; longer than
;; `MAX_TYPED_STRING_BYTES` (4096, same-file line 50) with
;; `TypedExecutionError::LimitDenied("typed-string")`, staged at
;; `TypedStage::Output` by `execute_domain_lane` (same file, lines 2130-2131).
;;
;; This component is an honest `dreamer-cycle` fixture except for these
;; differences, ALL FOUR of them: (1) the hostile lifted length below;
;; (2) where the `describe` retarea sits; (3) the bump start; and (4) the sixth
;; `(data ...)` segment this file adds. Stating the count matters, because a
;; reader who assumes this fixture's allocator behaves as `dreamer-cycle.wat`'s
;; would be wrong.
;; The hostile lifted length: `describe` reports the true frozen descriptor, the
;; domain result echoes the admitted `operation-id` and `fence-epoch` and claims
;; the lowest proof ceiling, every list leaf is left empty, and only
;; `state.state-digest` carries 4097 bytes -- exactly one byte past the host's
;; per-string ceiling. And where the `describe` retarea sits: base 0x0c00 here,
;; its eleven core words ending 0x0c2b, against `dreamer-cycle.wat`'s 0x0600 --
;; the same eleven values, so nothing about the reported descriptor changes.
;; Every earlier check therefore passes (in `check_cycle_result` the only prior
;; charge is the two-byte echoed `operation-id`) and the string ceiling is
;; provably the denial.
;;
;; Memory map (all within the single 1-page core memory, `1 1`):
;;   0x0000-0x03ff  reserved, never written
;;   0x0400-0x0477  descriptor strings (data segments at 0x400/0x40d/0x420/
;;                  0x433/0x438)
;;   0x0800-0x0878  the lowered `step` result tuple (retptr base 0x800; the
;;                  `state` record at 0x820, so `state-digest` at 0x82c/0x830
;;                  and `fence-epoch` at 0x844/0x848)
;;   0x0c00-0x0c2b  the `describe` retptr record (eleven core words)
;;   0x1000         `operation-id` echo scratch
;;   0x1200         `state.fence-epoch` echo scratch
;;   0x2000-0x3001  the hostile 4097-byte `state.state-digest` region
;;                  (8192 .. 8192 + 4097 = 12289). No byte is stored here:
;;                  exactly as the sibling `host-lifting-list.wat` builds its
;;                  300-element leaf, the region is the ZEROED high part of
;;                  this one-page memory, and every NUL byte is valid UTF-8 in
;;                  a lifted `string`, so the host really does lift 4097 bytes.
;;   0x3040-0x3051  this fixture's own label, immediately above the hostile
;;                  region so a memory dump identifies it
;;   0xb000         the `realloc` bump region the host calls while lowering the
;;                  request; starts at 45056, far above every other region
;;
;; Canonical-ABI offsets derived for wasmtime 47.0.4 /
;; wasmtime-environ-47.0.4 (CARGO_HOME registry), the same derivation the
;; sibling fixtures record:
;;   result<cycle-outcome, cycle-error> retptr base 0x800 (2048)
;;     discriminant at +0 (CanonicalAbiInfo::variant_static,
;;     wasmtime-environ-47.0.4/src/component/types.rs:841; payload at
;;     payload_offset32 = align_to(1, align32) = 8,
;;     wasmtime-environ-47.0.4/src/component/types.rs:950) -> 2056
;;   cycle-outcome "stepped" payload at 2056 + 8 = 2064
;;     (wasmtime-environ-47.0.4/src/component/types.rs:950)
;;   cycle-step-result.state at record offset 16 (operation-id string 8 bytes
;;     at 0; from-phase/to-phase/disposition one-byte enums at 8/9/10, so
;;     align_to(11, 8) = 16; CanonicalAbiInfo::next_field32,
;;     wasmtime-environ-47.0.4/src/component/types.rs:756)
;;     -> 2080
;;   dreamer-state.state-digest at record offset 12 (u32 `schema-version` 0,
;;     enum `phase` 4, u32 `revision` 8, then CanonicalAbiInfo::next_field32
;;     wasmtime-environ-47.0.4/src/component/types.rs:756) -> 2080 + 12 = 2092
;;     (ptr), 2096 (len, POINTER_PAIR 8
;;     bytes, wasmtime-environ-47.0.4/src/component/types.rs:707)
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
    ;; pointer to guest-owned memory: wasmparser-0.252.0
    ;; `validator/component_types.rs`:36 and :1261-1276 clear the flat results
    ;; and push exactly one pointer for `Abi::Lift`, and
    ;; `validator/component.rs`:1328/:1350 require that one-pointer signature.
    ;; The returned pointer is 0x0c00; the eleven words occupy 0x0c00..0x0c2b.
    ;; 0x0c00 is clear of the descriptor strings, of the 0x800 result tuple, of
    ;; the 0x1000/0x1200 echo scratch and of the 0x2000 hostile string region,
    ;; and inside the single exported page.
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
      ;; Hostile lifted length, and nothing else: `state.state-digest` is the
      ;; FIRST charged string leaf that this world's echo checks do not pin to
      ;; an admitted value, so it is the first charge that can fail for this
      ;; fixture. Its 4097 bytes are the zeroed high part of this single-page
      ;; core memory (8192 .. 8192 + 4097 = 12289, inside the 1-page memory,
      ;; clear of the descriptor strings, the result tuple, the `describe`
      ;; retptr and both echo scratch blocks, and well below the 45056 `realloc`
      ;; bump region, so nothing this call lowers can overlap it). Every NUL
      ;; byte is valid UTF-8 in a lifted `string`, so the host really lifts all
      ;; 4097 bytes and the denial is its own per-string ceiling -- not a fuel,
      ;; memory or list-item exhaustion: the string is exactly one byte above
      ;; `MAX_TYPED_STRING_BYTES` (4096) and every list leaf of this result is
      ;; left empty.
      ;; canonical-ABI: `state.state-digest` is dreamer-state record offset 12
      ;; (next_field32, wasmtime-environ-47.0.4/src/component/types.rs:756) as a
      ;; POINTER_PAIR (wasmtime-environ-47.0.4/src/component/types.rs:707) -> 2080 + 12 = 2092 (ptr) and 2096 (len).
      (i32.store (i32.const 2092) (i32.const 8192))
      (i32.store (i32.const 2096) (i32.const 4097))
      (i32.const 2048))
    (export "realloc" (func $realloc))
    (data (i32.const 1024) "dreamer-cycle")
    (data (i32.const 1037) "eliot:current@0.1.0")
    (data (i32.const 1056) "eliot-dreamer-cycle")
    (data (i32.const 1075) "0.1.0")
    (data (i32.const 1080) "6e878cbb40e2060fd2d570345a1b0105920a0398b3c70e2c4e1f9b7eb291a0e6")
    ;; This fixture's own label, immediately above the hostile 0x2000 region
    ;; (it ends at 12289 = 0x3001) and far below the 0xb000 `realloc` bump, so
    ;; a memory dump of the page identifies which fixture refused.
    (data (i32.const 12352) "758/9-typed-string")
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
