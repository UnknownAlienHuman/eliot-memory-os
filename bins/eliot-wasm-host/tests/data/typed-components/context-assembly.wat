;; ELIOT typed fixture component for the frozen `context-assembly` world.
;; Derived from bins/eliot-wasm-host/wit/typed/context-assembly.wit: every type, field,
;; case and function below is that world's own WIT surface. Zero imports, exactly
;; one exported interface `eliot:current/assembly@0.1.0` exposing `describe` and the world
;; domain function `assemble`.
;;
;; Memory map: 0x0000-0x03ff reserved, 0x0400 descriptor strings,
;; 0x0800 the lowered `assemble` result tuple, 0x1000, 0x1200, 0x1400 and 0x1600
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
  (type $admitted_atom_ref (record
    (field "atom-id" string)
    (field "representation-digest" string)
    (field "source-digest" string)
  ))
  (type $proof_ceiling (enum "observation" "candidate-only" "admission" "assembly" "activation" "screen" "cycle" "handler"))
  (type $serialized_measurement (record
    (field "byte-count" u64)
    (field "stu-estimate" (option u64))
    (field "exact-token-count" (option u64))
    (field "serializer" string)
    (field "schema-revision" string)
    (field "input-digest" string)
    (field "output-digest" string)
    (field "proof-ceiling" $proof_ceiling)
  ))
  (type $assembly_request (record
    (field "schema-revision" u32)
    (field "operation-id" string)
    (field "task-id" string)
    (field "scope-id" string)
    (field "fence-epoch" string)
    (field "fence-generation" u64)
    (field "admitted" (list $admitted_atom_ref))
    (field "admitted-digest" string)
    (field "recipe-digest" string)
    (field "measurement" $serialized_measurement)
    (field "deadline-ms" (option s64))
    (field "cancelled" bool)
    (field "predecessor-digest" (option string))
  ))
  (type $rendered_atom (record
    (field "atom-id" string)
    (field "rendered-digest" string)
    (field "source-digest" string)
  ))
  (type $selection_proof (record
    (field "admitted-digest" string)
    (field "rendered-digest" string)
    (field "member-count" u32)
  ))
  (type $quality_dimension (enum "acceptance-decision-coverage" "causal-operational-sufficiency" "exact-anchor-provenance-coverage" "freshness-state-fence-coherence" "rivals-conflicts-unknowns-visibility" "negative-memory-invariant-coverage" "verifier-action-readiness" "route-accessibility-layout-risk" "instruction-sufficiency" "payload-handle-reconstruction-cost" "known-omissions-expansion-paths" "telemetry-measurement-cost-coverage"))
  (type $dimension_status (enum "pass" "fail" "unknown"))
  (type $quality_result (record
    (field "dimension" $quality_dimension)
    (field "status" $dimension_status)
    (field "evidence" string)
    (field "measurement" string)
    (field "failed-invariant" (option string))
    (field "proof-ceiling" $proof_ceiling)
  ))
  (type $quality_scorecard (record
    (field "results" (list $quality_result))
  ))
  (type $active_view (record
    (field "operation-id" string)
    (field "task-id" string)
    (field "scope-id" string)
    (field "fence-epoch" string)
    (field "fence-generation" u64)
    (field "admitted-digest" string)
    (field "members" (list $rendered_atom))
    (field "selection" $selection_proof)
    (field "quality" $quality_scorecard)
    (field "measurement" $serialized_measurement)
    (field "omission-evidence" (list string))
    (field "frontier" (list string))
    (field "proof-ceiling" $proof_ceiling)
    (field "canonical-digest" string)
  ))
  (type $assembly_result (variant
    (case "assembled" $active_view)
  ))
  (type $assembly_malformed (record
    (field "field" string)
    (field "human-detail" string)
  ))
  (type $assembly_selection (record
    (field "human-detail" string)
  ))
  (type $assembly_quality (record
    (field "human-detail" string)
  ))
  (type $assembly_measurement (record
    (field "human-detail" string)
  ))
  (type $assembly_schema (record
    (field "want-revision" u32)
    (field "got-revision" u32)
    (field "human-detail" string)
  ))
  (type $assembly_internal (record
    (field "human-detail" string)
  ))
  (type $assembly_error (variant
    (case "malformed" $assembly_malformed)
    (case "selection-mismatch" $assembly_selection)
    (case "quality-incomplete" $assembly_quality)
    (case "measurement-mismatch" $assembly_measurement)
    (case "unsupported-schema" $assembly_schema)
    (case "internal" $assembly_internal)
  ))
  (type $f-describe (func (result $abi_descriptor)))
  (type $f-domain (func (param "request" $assembly_request) (result (result $assembly_result (error $assembly_error)))))
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
    ;; (wasmparser-0.256.0 src/validator/component_types.rs:35, :129 and
    ;; :1279-1292, enforced at src/validator/component.rs:1343 and :1365).
    ;; Retptr base 0x600: past the last descriptor byte at 0x47e and below
    ;; the 0x800 result tuple, so it collides with nothing in this memory.
    (func (export "describe") (result i32)
      ;; world-name
      (i32.store (i32.const 1536) (i32.const 1024))
      (i32.store (i32.const 1540) (i32.const 16))
      ;; package-id
      (i32.store (i32.const 1544) (i32.const 1040))
      (i32.store (i32.const 1548) (i32.const 19))
      ;; abi-revision
      (i32.store (i32.const 1552) (i32.const 1))
      ;; native-contract
      (i32.store (i32.const 1556) (i32.const 1059))
      (i32.store (i32.const 1560) (i32.const 22))
      ;; native-revision
      (i32.store (i32.const 1564) (i32.const 1081))
      (i32.store (i32.const 1568) (i32.const 5))
      ;; abi-digest
      (i32.store (i32.const 1572) (i32.const 1086))
      (i32.store (i32.const 1576) (i32.const 64))
      (i32.const 1536))
    ;; `assemble`: the admitted typed request arrives already lowered into guest
    ;; memory. The closed WIT result tuple is written in full and every
    ;; identity field is copied back out of the request, so the host echo
    ;; check compares values the guest actually read.
    (func (export "assemble") (param $req i32) (result i32)
      (local $n i32)
      ;; result ok case: the WIT success variant
      (i32.store (i32.const 2048) (i32.const 0))
      ;; variant "assembly-result" selects WIT case "assembled"
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
    (data (i32.const 1024) "context-assembly")
    (data (i32.const 1040) "eliot:current@0.1.0")
    (data (i32.const 1059) "eliot-context-assembly")
    (data (i32.const 1081) "0.1.0")
    (data (i32.const 1086) "6e878cbb40e2060fd2d570345a1b0105920a0398b3c70e2c4e1f9b7eb291a0e6")
  )
  (core instance $guest (instantiate $guest))
  (alias core export $guest "memory" (core memory $memory))
  (alias core export $guest "realloc" (core func $realloc))
  (alias core export $guest "describe" (core func $describe))
  (alias core export $guest "assemble" (core func $domain))
  (func $describe (type $f-describe)
    (canon lift (core func $describe) (memory $memory) (realloc $realloc)))
  (func $domain (type $f-domain)
    (canon lift (core func $domain) (memory $memory) (realloc $realloc)))
  (instance $iface
    (export "describe" (func $describe))
    (export "assemble" (func $domain)))
  (export "eliot:current/assembly@0.1.0" (instance $iface))
)
