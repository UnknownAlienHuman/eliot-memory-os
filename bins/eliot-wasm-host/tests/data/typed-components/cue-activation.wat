;; ELIOT typed fixture component for the frozen `cue-activation` world.
;; Derived from bins/eliot-wasm-host/wit/typed/cue-activation.wit: every type, field,
;; case and function below is that world's own WIT surface. Zero imports, exactly
;; one exported interface `eliot:current/activation@0.1.0` exposing `describe` and the world
;; domain function `activate`.
;;
;; Memory map: 0x0000-0x03ff reserved, 0x0400 descriptor strings,
;; 0x0800 the lowered `activate` result tuple, 0x1000 and 0x1200 the two echo scratch
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
  (type $seed_cue (record
    (field "cue-id" string)
    (field "comparison-key" string)
    (field "normalization-profile" string)
  ))
  (type $relation_edge (record
    (field "edge-id" string)
    (field "from-handle" string)
    (field "to-handle" string)
    (field "weight-milli" u32)
  ))
  (type $activation_bounds (record
    (field "max-depth" u8)
    (field "max-fanout" u16)
    (field "max-results" u16)
    (field "max-nodes" u32)
    (field "max-edges" u32)
    (field "max-work" u64)
    (field "max-path-len" u16)
    (field "max-seeds" u16)
    (field "max-direct" u16)
    (field "max-derived" u16)
    (field "max-trace-steps" u16)
    (field "max-output-bytes" u32)
    (field "activation-threshold" u16)
  ))
  (type $activation_request (record
    (field "schema-revision" u32)
    (field "request-id" string)
    (field "seeds" (list $seed_cue))
    (field "snapshot-id" string)
    (field "relation-edges" (list $relation_edge))
    (field "bounds" $activation_bounds)
    (field "fence-epoch" string)
    (field "fence-generation" u64)
    (field "normalization-profile" string)
    (field "observed-at-ms" s64)
    (field "deadline-ms" (option s64))
    (field "cancelled" bool)
  ))
  (type $direct_activation (record
    (field "target" string)
    (field "strength" u16)
    (field "seed" string)
  ))
  (type $derived_activation (record
    (field "target" string)
    (field "strength" u16)
    (field "path" (list string))
    (field "seed" string)
  ))
  (type $trace_step (record
    (field "node" string)
    (field "depth" u8)
    (field "strength" u16)
  ))
  (type $activation_trace (record
    (field "steps" (list $trace_step))
    (field "inspected-nodes" u32)
    (field "inspected-edges" u32)
  ))
  (type $completeness (enum "complete" "truncated" "source-unavailable" "stale" "no-direct-match"))
  (type $proof_ceiling (enum "observation" "candidate-only" "admission" "assembly" "activation" "screen" "cycle" "handler"))
  (type $activation_result_body (record
    (field "request-id" string)
    (field "snapshot-id" string)
    (field "direct" (list $direct_activation))
    (field "derived" (list $derived_activation))
    (field "trace" $activation_trace)
    (field "completeness" $completeness)
    (field "frontier" (list string))
    (field "output-bytes" u32)
    (field "proof-ceiling" $proof_ceiling)
    (field "result-digest" string)
  ))
  (type $activation_outcome (variant
    (case "activated" $activation_result_body)
  ))
  (type $activation_malformed (record
    (field "field" string)
    (field "human-detail" string)
  ))
  (type $bound_kind (enum "depth" "fanout" "results" "nodes" "edges" "work" "path-len" "seeds" "direct" "derived" "trace-steps" "output-bytes"))
  (type $activation_bound (record
    (field "bound" $bound_kind)
    (field "human-detail" string)
  ))
  (type $activation_stale (record
    (field "human-detail" string)
  ))
  (type $activation_schema (record
    (field "want-revision" u32)
    (field "got-revision" u32)
    (field "human-detail" string)
  ))
  (type $activation_internal (record
    (field "human-detail" string)
  ))
  (type $activation_error (variant
    (case "malformed" $activation_malformed)
    (case "bound-exceeded" $activation_bound)
    (case "stale-snapshot" $activation_stale)
    (case "unsupported-schema" $activation_schema)
    (case "internal" $activation_internal)
  ))
  (type $f-describe (func (result $abi_descriptor)))
  (type $f-domain (func (param "request" $activation_request) (result (result $activation_outcome (error $activation_error)))))
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
    ;; Retptr base 0x600: past the last descriptor byte at 0x47a and below
    ;; the 0x800 result tuple, so it collides with nothing in this memory.
    (func (export "describe") (result i32)
      ;; world-name
      (i32.store (i32.const 1536) (i32.const 1024))
      (i32.store (i32.const 1540) (i32.const 14))
      ;; package-id
      (i32.store (i32.const 1544) (i32.const 1038))
      (i32.store (i32.const 1548) (i32.const 19))
      ;; abi-revision
      (i32.store (i32.const 1552) (i32.const 1))
      ;; native-contract
      (i32.store (i32.const 1556) (i32.const 1057))
      (i32.store (i32.const 1560) (i32.const 20))
      ;; native-revision
      (i32.store (i32.const 1564) (i32.const 1077))
      (i32.store (i32.const 1568) (i32.const 5))
      ;; abi-digest
      (i32.store (i32.const 1572) (i32.const 1082))
      (i32.store (i32.const 1576) (i32.const 64))
      (i32.const 1536))
    ;; `activate`: the admitted typed request arrives already lowered into guest
    ;; memory. The closed WIT result tuple is written in full and every
    ;; identity field is copied back out of the request, so the host echo
    ;; check compares values the guest actually read.
    (func (export "activate") (param $req i32) (result i32)
      (local $n i32)
      ;; result ok case: the WIT success variant
      (i32.store (i32.const 2048) (i32.const 0))
      ;; variant "activation-outcome" selects WIT case "activated"
      (i32.store (i32.const 2052) (i32.const 0))
      ;; echo "request-id" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 8))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 4096) (i32.load (i32.add (local.get $req) (i32.const 4))) (local.get $n))
      (i32.store (i32.const 2056) (i32.const 4096))
      (i32.store (i32.const 2060) (local.get $n))
      ;; echo "snapshot-id" back out of the lowered request
      (local.set $n (i32.load (i32.add (local.get $req) (i32.const 24))))
      (if (i32.gt_u (local.get $n) (i32.const 512)) (then (local.set $n (i32.const 512))))
      (call $copy (i32.const 4608) (i32.load (i32.add (local.get $req) (i32.const 20))) (local.get $n))
      (i32.store (i32.const 2064) (i32.const 4608))
      (i32.store (i32.const 2068) (local.get $n))
      (i32.const 2048))
    (export "realloc" (func $realloc))
    (data (i32.const 1024) "cue-activation")
    (data (i32.const 1038) "eliot:current@0.1.0")
    (data (i32.const 1057) "eliot-cue-activation")
    (data (i32.const 1077) "0.1.0")
    (data (i32.const 1082) "6e878cbb40e2060fd2d570345a1b0105920a0398b3c70e2c4e1f9b7eb291a0e6")
  )
  (core instance $guest (instantiate $guest))
  (alias core export $guest "memory" (core memory $memory))
  (alias core export $guest "realloc" (core func $realloc))
  (alias core export $guest "describe" (core func $describe))
  (alias core export $guest "activate" (core func $domain))
  (func $describe (type $f-describe)
    (canon lift (core func $describe) (memory $memory) (realloc $realloc)))
  (func $domain (type $f-domain)
    (canon lift (core func $domain) (memory $memory) (realloc $realloc)))
  (instance $iface
    (export "describe" (func $describe))
    (export "activate" (func $domain)))
  (export "eliot:current/activation@0.1.0" (instance $iface))
)
