;; ELIOT typed fixture component that returns its OWN typed WIT error for the
;; frozen `memory-curation-screen` world (#758 marker 17: typed guest error
;; versus trap). Copied from the world's success fixture
;; `memory-curation-screen.wat` -- same type surface, same `describe`, same
;; `realloc` -- with three differences: that fixture's `$copy` echo helper and
;; its four echo copies are dropped, one data segment carries the error
;; detail, and `screen` differs in one way: it returns the `err` arm of the
;; same WIT signature `result<screen-outcome, screen-error>` with a REAL,
;; guest-produced `screen-error` value. It is NOT a trap: no `unreachable`, no
;; `memory.grow` fault, no fuel or epoch exhaustion. `unreachable` is
;; `TypedExecutionError` at stage `invoke`; this is
;; `TypedDomainResult::GuestError` with `ScreenError::CancelledScreen`
;; retained verbatim.
;;
;; World wiring (must match the host kit/capsule that drives this fixture):
;; - WIT source: bins/eliot-wasm-host/wit/typed/memory-curation-screen.wit
;; - export name: eliot:current/screen@0.1.0 (package id `eliot:current@0.1.0`)
;; - domain func: `screen`; descriptor probe: `describe`
;; - interface digest for the kit: sha256 of that one .wit file's bytes
;; - abi-digest the guest `describe` must report: the frozen `typed_wit_digest()`
;;   over all seven wit/typed files, i.e. the same value every per-world fixture
;;   reports.
;;
;; Memory map: 0x0000-0x03ff reserved, 0x0400 descriptor strings, 0x0600 the
;; `describe` retarea, 0x0800 the lowered `screen` result tuple, 0x0900 the one
;; error-detail byte -- carried by this file's extra
;; `(data (i32.const 2304) "x")` segment, not stored by any instruction; the
;; `screen` body writes that byte's pointer/length pair into the retarea (along
;; with the two variant discriminants at 0x800 and 0x858, both documented below) --
;; and 0x1400 the bump region the host `realloc` hands out while lowering the
;; request.
;;
;; Canonical-ABI layout of the returned retarea (base = the pointer this core
;; function returns, 0x800; the host requires `base % align32 == 0`, 0x800 is
;; 8-aligned). Sizes/offsets follow wasmtime 47's store layout: `u64` is
;; (size 8, align 8), `bool`/enum are (1, 1), string/list are (8, 4), and every
;; record is stored INLINE (only strings and lists are pointer pairs). A
;; variant is a join: its 1-byte discriminant sits at the start and EVERY case
;; payload starts at the same offset, so on the err arm the byte at 0x008 is
;; `screen-error`'s own discriminant:
;;   0x000 result discriminant            1 = err          <- the typed-Err arm
;;   0x008 screen-error discriminant      1 = "cancelled-screen"
;;   0x00c screen-cancelled.human-detail  POINTER_PAIR spanning 0x00c..0x013:
;;                                    ptr = 0x900 at 0x00c, len = 1 at 0x010
;; The ok arm's `screen-outcome` discriminant occupies the same byte 0x008 and is
;; selected only when the result discriminant at 0x000 is 0. The err payload
;; starts at result payload_offset32 = align_to(1, align 8) = 8; screen-error's
;; payload starts 4 bytes past its discriminant because its widest case
;; (`screen-malformed`, two strings) aligns to 4.
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
    (func $realloc (param $old i32) (param $old_size i32) (param $align i32) (param $new_size i32) (result i32)
      (local $ptr i32)
      (local.set $ptr (global.get $bump))
      (local.set $ptr (i32.and (i32.add (local.get $ptr) (i32.sub (local.get $align) (i32.const 1)))
                 (i32.xor (local.get $align) (i32.const -1))))
      (global.set $bump (i32.add (local.get $ptr) (local.get $new_size)))
      (local.get $ptr))
    ;; `describe`: the frozen WIT abi-descriptor, five static strings and the
    ;; frozen ABI revision, in WIT field order. A lifted export flattens its
    ;; result to at most MAX_FLAT_FUNC_RESULTS = 1 core value, so the core
    ;; function returns ONE pointer into exported linear memory.
    ;; Retptr base 0x600: past the last descriptor byte at 0x48a and below the
    ;; 0x800 result tuple, so it collides with nothing in this memory.
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
    ;; memory and is not needed here; this export returns the `err` arm of the
    ;; world's own `result<screen-outcome, screen-error>` with a real
    ;; `screen-error` value the guest itself writes.
    (func (export "screen") (param $req i32) (result i32)
      ;; result err arm: result discriminant 1, distinct from the ok arm
      (i32.store8 (i32.const 2048) (i32.const 1))
      ;; variant "screen-error" selects WIT case "cancelled-screen" (disc 1);
      ;; this is the same byte the ok arm uses for the "screened" discriminant
      (i32.store8 (i32.const 2056) (i32.const 1))
      ;; screen-cancelled.human-detail: the real detail byte at 0x900
      (i32.store (i32.const 2060) (i32.const 2304))
      (i32.store (i32.const 2064) (i32.const 1))
      (i32.const 2048))
    (export "realloc" (func $realloc))
    (data (i32.const 1024) "memory-curation-screen")
    (data (i32.const 1046) "eliot:current@0.1.0")
    (data (i32.const 1065) "eliot-memory-curation-screen")
    (data (i32.const 1093) "0.1.0")
    (data (i32.const 1098) "6e878cbb40e2060fd2d570345a1b0105920a0398b3c70e2c4e1f9b7eb291a0e6")
    (data (i32.const 2304) "x")
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
    (export "describe" (func $describe))
    (export "screen" (func $domain)))
  (export "eliot:current/screen@0.1.0" (instance $iface))
)
