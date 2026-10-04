;; ELIOT typed fixture component for the frozen `memory-curation-screen` world.
;; Derived from bins/eliot-wasm-host/wit/typed/memory-curation-screen.wit: every type, field,
;; case and function below is that world's own WIT surface. Zero imports, exactly
;; one exported interface `eliot:current/screen@0.1.0` exposing `describe` and the world
;; domain function `screen`.
;;
;; Memory map: 0x0000-0x03ff reserved, 0x0400 descriptor strings,
;; 0x0800 the lowered `screen` result tuple, 0x1000, 0x1200, 0x1400 and 0x1600
;; the four echo scratch blocks (each copy is capped at 512 bytes, so they span
;; 0x1000..0x17ff), and 0x1400 the bump region the host `realloc` hands out
;; while lowering the request -- the same 0x1400 as the third scratch block.
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
    ;; memory. The closed WIT result tuple is written in full and every
    ;; identity field is copied back out of the request, so the host echo
    ;; check compares values the guest actually read.
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
      ;; echo "scope-id" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 24))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 5120) (i32.load (i32.add (local.get $req) (i32.const 20))) (local.get $n))
      (i32.store (i32.const 2080) (i32.const 5120))
      (i32.store (i32.const 2084) (local.get $n))
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
