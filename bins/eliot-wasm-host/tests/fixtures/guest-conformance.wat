(component
  (type $bytes (list u8))
  (type $run-result (result $bytes (error string)))
  (type $run (func (param "input" $bytes) (result $run-result)))
  (core module $guest
    (type $run (func (param i32 i32) (result i32)))
    ;; Seed-prefixed conformance transform: the first 8 input bytes carry
    ;; the little-endian seed, and every output byte is the wrapping sum of
    ;; the input byte and the seed byte at the same position modulo 8.
    ;; This replicates the declared reference core byte for byte, so the
    ;; differential harness compares real guest execution against it.
    (func $run (type $run)
      (local $i i32)
      (local $out i32)
      (local $seed_byte i32)
      (local.set $out
        (call $realloc (i32.const 0) (i32.const 0) (i32.const 1) (local.get 1)))
      (local.set $i (i32.const 0))
      (block $done
        (loop $mix
          (br_if $done (i32.ge_u (local.get $i) (local.get 1)))
          (local.set $seed_byte
            (i32.load8_u
              (i32.add (local.get 0) (i32.rem_u (local.get $i) (i32.const 8)))))
          (i32.store8
            (i32.add (local.get $out) (local.get $i))
            (i32.add
              (i32.load8_u (i32.add (local.get 0) (local.get $i)))
              (local.get $seed_byte)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $mix)))
      ;; Canonical result area: ok discriminant word, output pointer,
      ;; output length. Mirrors the checked-in echo guest layout exactly.
      (i32.store (i32.const 32) (i32.const 0))
      (i32.store (i32.const 36) (local.get $out))
      (i32.store (i32.const 40) (local.get 1))
      (i32.const 32))
    (func $realloc (param i32 i32 i32 i32) (result i32)
      (local $align i32)
      (local $ptr i32)
      (local.set $align
        (select (i32.const 1) (local.get 2) (i32.eqz (local.get 2))))
      (local.set $ptr
        (i32.and
          (i32.add (global.get $heap) (i32.sub (local.get $align) (i32.const 1)))
          (i32.xor
            (i32.sub (local.get $align) (i32.const 1))
            (i32.const -1))))
      (global.set $heap (i32.add (local.get $ptr) (local.get 3)))
      (local.get $ptr))
    (memory (export "memory") 1)
    (global $heap (mut i32) (i32.const 64))
    (export "run" (func $run))
    (export "realloc" (func $realloc))
  )
  (core instance $guest (instantiate $guest))
  (alias core export $guest "run" (core func $run))
  (alias core export $guest "memory" (core memory $memory))
  (alias core export $guest "realloc" (core func $realloc))
  (func $run (type $run)
    (canon lift (core func $run) (memory $memory) (realloc $realloc)))
  (export "run" (func $run))
)
