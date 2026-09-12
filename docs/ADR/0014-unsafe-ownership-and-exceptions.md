# ADR 0014: Unsafe ownership and audited exceptions

## Status

Accepted for issue #728, Wave A, at worktree base
`1cb9ac63ce0bf2a7606e0c89910fb5a21f1299f2`. This record is the I2.5
explicit-crate listing for the current manifest denominator: one canonical
owner (`eliot-platform-windows`) and four audited exceptions
(`eliot-windows-ipc`, `eliot-ipc`, `eliot-host`, `eliot-watchdog`).

Residual, stated honestly: this worktree predates the hardening merges for
#789 (PR #1156, `4baaeaae`), #791 (PR #1157, `04fa44d2`), and #860
(PR #1158, `455d45f1` per the work-unit record). Merge-base checks in this
worktree confirm #1156 and #1157 are not ancestors of the base commit, and
the #1158 merge commit is absent from the local clone. Obligation rows below
therefore cite that hardening as the target coverage the Wave C/D oracle
must revalidate at integration; they do not claim the hardened source is
present in this tree.

## Context

I2.5 (`docs/architecture/I02-05-unsafe-policy.md`) permits `unsafe` only in
explicitly listed crates — `eliot-platform-windows`, `eliot-platform-unix`,
and, when necessary, a separate audited FFI bridge — and requires every
unsafe block to carry a `// SAFETY:` rationale, a local invariant test, and
an owning reviewer. Domain, contract, and Kernel pure-core crates use
`#![forbid(unsafe_code)]`. Per I0.6, fixing the allowlist is a load-bearing
default, which is why it needs an ADR rather than a comment thread.

The actual manifest denominator at the base commit, verified by inspection
rather than memory, is:

| Manifest | `unsafe_code` | `unsafe_op_in_unsafe_fn` |
|---|---|---|
| `crates/kernel/eliot-platform-windows/Cargo.toml:47` | `allow` | `deny` (`:48`) |
| `crates/eliot-windows-ipc/Cargo.toml:28` | `allow` | `deny` (`:29`) |
| `crates/kernel/eliot-ipc/Cargo.toml:26` | `allow` | unset |
| `bins/eliot-host/Cargo.toml:43` | `allow` | unset |
| `bins/eliot-watchdog/Cargo.toml:37` | `allow` | unset |

The workspace root (`Cargo.toml:331`) sets `unsafe_code = "forbid"`, so these
five are the complete current denominator: no other member manifest sets
`allow`. There is no `eliot-platform-unix` workspace member in this tree, so
the I2.5 unix entry names no current package; admitting one later requires an
ADR amendment, not a silent manifest edit.

History constrains the shape. ADR 0002 established `eliot-windows-ipc` as the
sole unsafe Win32 descriptor boundary so that one audited FFI call would not
spread unsafe into daemon, engine, store, or types crates. I10.8.12 then set
the extraction direction — `eliot-windows-ipc` responsibilities migrate into
`eliot-platform-windows`, `eliot-process`, and `eliot-ipc` — which makes the
windows-ipc exception explicitly transitional. The hardening issues sharpen
each boundary without widening it: #789 bounds every unsafe family in
`eliot-windows-ipc` (Slice A: `OwnedHandle` sentinel plus wide-input
bounds), #791 bounds every unsafe family in `eliot-ipc` (Waves A–C, twelve
sites: lib wrappers, frame-codec buffer invariants), and #860 types the
`Drop` paths in `eliot-platform-windows` (single-attempt restore with
retained fail-stop). All three merged remotely after this worktree's base.

## Decision

One package holds at most one row below; one row owns exactly one package.
A package with `unsafe_code = "allow"` and no row here is a defect, and a row
with no matching manifest `allow` is stale: both fail closed under the Wave D
oracle. A manifest comment pointing at a row is navigation, not proof —
comments and package presence cannot manufacture safety. The sentence
"Windows requires unsafe" appears nowhere below as a rationale and is never
an accepted rationale: each row names the exact FFI operation, why this
package rather than the canonical owner performs it, and what would remove
the need.

<a id="row-eliot-platform-windows"></a>

### Row `eliot-platform-windows`: canonical owner, not an exception

Package `eliot-platform-windows` (`crates/kernel/eliot-platform-windows`),
kernel/platform plane, `src/lib.rs` (about one hundred forty-five `unsafe`
tokens at base). Permitted boundary classes: Win32 FFI through `windows-sys`
and `windows` limited to named-pipe peer expectation and authentication,
SDDL/DACL construction and readback verification, SID and session identity,
Job Object mechanics, process identity and exit observation, named mutexes
(`CreateMutexW`, `ReleaseMutex`, `CloseHandle`), `GetLastError` capture, and
`LocalFree` pairing. It is its own canonical owner, assigned by the kernel
subtree instructions (Windows process, Job Object, service, and
protected-path mechanics) together with the shared convergence issue #100.

This package owns the FFI because the provider-neutral platform ports need
exactly one audited Windows adapter; every other package consumes typed
results (`NamedPipePeerExpectation`, `NamedPipePeerSet`) instead of raw
handles. Prohibited expansion: no task, memory, policy, or finish semantics;
no second pipe or process owner; raw security descriptors never cross its
public boundary (the `eliot-ipc` descriptor struct stays private as the
enforcing pattern). Memory, privilege, handle, thread, callback, and unwind
risks: handle leak or double close, omitted `LocalFree`, TOCTOU between path
check and use, mutex abandonment, stale `GetLastError` reads, and unwinding
across an `extern` boundary. Required proof: the Wave C source-coverage
oracle (`safety_coverage`: path, item, span, form, and digest per site with
operation-specific pointer, buffer, UTF-16, handle, callback, thread,
impersonation, ABI, and unwind obligations), an adjacent operation-specific
`// SAFETY:` comment per site, and an owning reviewer; the #860 typed-`Drop`
hardening is the target coverage. Evidence ceiling: policy plus comment plus
source coverage only — no claim of universal undefined-behavior absence.
Review, removal, and migration trigger: any new unsafe family needs a new
decision before merge; any family extracted elsewhere shrinks this row.
Relation to I2.5: this row is the named canonical crate.

<a id="row-eliot-windows-ipc"></a>

### Row `eliot-windows-ipc`: audited process and handle bridge (exception 1 of 4)

Package `eliot-windows-ipc` (`crates/eliot-windows-ipc`), Instrument and
process-execution plane: it backs the single audited Windows
`ProcessExecutor` semantics of I10.8.2 and retains the L3 pipe-descriptor
boundary of ADR 0002. Sources: `src/lib.rs` (`unsafe impl Send` for
`DirectoryOplockGuard` at `:234` and for `OwnedHandle` at `:651`,
`CreateEventW`, overlapped oplock buffers, guardian launch), plus the helper
bins `src/bin/eliot-process-guardian.rs` and the test-support-only
`src/bin/eliot-credential-suite-guard.rs`. Permitted classes: suspended
`CreateProcessW` launch with Job Object assignment before resume, handle
wrapper `Send` impls, oplock event and buffer ownership, and pipe
`SECURITY_ATTRIBUTES` construction for the Tokio handoff. Canonical owner
for process mechanics is `eliot-platform-windows`; this package holds the
boundary only until the I10.8.12 extraction into `eliot-platform-windows`
and `eliot-process` completes.

This package owns the FFI, rather than the canonical owner, for the reason
ADR 0002 gives: keeping the audited guardian and descriptor calls inside one
tiny internal crate prevents unsafe from spreading into the daemon, engine,
store, or types crates, and the Instrument Plane needs one production
executor implementation rather than per-caller launch dialects. Prohibited
expansion: token rotation, handshake validation, replay defense, deadlines,
and action authority stay in safe Rust above this helper; no new syscall
families; the bins remain helpers, never services. Risks: lifetime of the
security-attributes pointer handed to Tokio, stability of the overlapped and
oplock buffers submitted to the kernel (boxed allocations whose addresses
must not move), handle-ownership transfer into `OwnedHandle`, `Send` across
threads, and overly wide oplock or guardian inputs. Required proof:
operation-specific `// SAFETY:` per site, local invariant tests, an owning
reviewer, and the #789 Slice A hardening (`OwnedHandle` sentinel plus
wide-input bounds) as target coverage. Evidence ceiling: policy plus comment
plus source coverage only. Review, removal, and migration trigger:
completion of the I10.8.12 extraction turns this manifest to `forbid`; any
new family before then is a Contract Challenge, not an edit. Relation to
I2.5: first instance of the separate audited FFI bridge.

<a id="row-eliot-ipc"></a>

### Row `eliot-ipc`: named-pipe transport adapter (exception 2 of 4)

Package `eliot-ipc` (`crates/kernel/eliot-ipc`), kernel transport plane:
the bounded EBP/1 contract and its Windows named-pipe adapter. Source:
`src/lib.rs` — the private `PipeSecurityDescriptor` built with
`ConvertStringSecurityDescriptorToSecurityDescriptorW` (`:1683`, `:1727`)
with `LocalFree` pairing (`:1700`, `:1744`, `:1796` including `Drop`), and
`BorrowedHandle::borrow_raw` sites (`:1853`–`:2200`) where server-owned pipe
handles are borrowed. Permitted classes: SDDL-to-descriptor conversion with
paired release inside the private struct, and raw-handle borrows only where
the owning pipe handle provably outlives the borrow. Canonical owner for
pipe security semantics is `eliot-platform-windows`, whose
`NamedPipePeerExpectation` and `NamedPipePeerSet` types this adapter
consumes.

This package owns the FFI because the transport adapter must hand Tokio a
valid `SECURITY_ATTRIBUTES` at pipe-creation time, and the raw descriptor
never crosses the package's public boundary — the struct is private, so
callers cannot name, retain, or free the descriptor. Prohibited expansion:
no second descriptor owner, no free-text SDDL (input comes only from the
typed expectation), no handle sharing beyond the server lifetime.
Risks: omitted or duplicated `LocalFree`, descriptor use-after-free,
`borrow_raw` outliving its owner, SDDL content smuggled outside the typed
expectation, and unwinding between conversion and release. Required proof:
operation-specific `// SAFETY:` per site, local invariant tests, an owning
reviewer, and the #791 Waves A–C hardening (twelve bounded sites) as target
coverage. Evidence ceiling: policy plus comment plus source coverage only;
no IPC-completion or product claim follows. Review, removal, and migration
trigger: descriptor construction migrating fully into
`eliot-platform-windows` turns this manifest to `forbid`; a new unsafe
family without a row fails closed. Relation to I2.5: second instance of the
separate audited FFI bridge.

<a id="row-eliot-host"></a>

### Row `eliot-host`: SCM entry trampoline (exception 3 of 4)

Package `eliot-host` (`bins/eliot-host`), runtime composition-root plane
(Host lifecycle and journal boundary, issue #14). Source: `src/main.rs` —
`unsafe fn service_launch_options` (`:466`, SCM `ServiceMain` argv UTF-16
walk bounded by `MAX_SERVICE_ARG_UNITS`) and the `SetServiceStatus` calls
(`:447`, `:462`). Permitted classes: the SCM entry trampoline only —
reading the service argv vector and writing `SERVICE_STATUS`. The target
canonical owner for SCM argv mechanics is `eliot-platform-windows`.

This package owns the FFI because a Windows service must enter through the
SCM `ServiceMain` signature, whose `argv` arrives as raw UTF-16 pointers
that cannot be read without raw-pointer dereference; everything past the
trampoline is safe (`HostLaunchOptions::validate_service_main_argv`).
Prohibited expansion: no further Win32 calls, no handle or pump logic, no
argv widening — exactly one argument, NUL-terminated, within the length
bound. Risks: `from_raw_parts` over SCM-owned memory valid only for the
call, unbounded reads (closed by the bound plus terminator scan), null
entries, running on the SCM thread, and no unwinding across the boundary.
Required proof: operation-specific `// SAFETY:` at each block, unit tests
over the safe validator (null, empty, overlong, multi-arg, non-canonical
argv), and an owning reviewer. Evidence ceiling: policy plus comment plus
source coverage only. Review, removal, and migration trigger: extracting the
argv parser into `eliot-platform-windows` turns this manifest to `forbid`;
any additional unsafe family is rejected. Relation to I2.5: third instance
of the separate audited FFI bridge, narrowed to service entry.

<a id="row-eliot-watchdog"></a>

### Row `eliot-watchdog`: SCM entry trampoline under failure-domain separation (exception 4 of 4)

Package `eliot-watchdog` (`bins/eliot-watchdog`), independent supervision
plane (issue #16): a separate service outside the Host and Kernel failure
domain. Source: `src/main.rs` — `unsafe fn service_launch_options`
(`:212`, same bounded argv shape as Host) and `unsafe extern "system" fn
service_control` (`:248`). Permitted classes: the SCM entry trampoline and
the control-handler status dispatch only. The target canonical owner for SCM
argv mechanics is `eliot-platform-windows`.

This package owns the FFI for the same entry-signature reason as Host, with
one extra constraint that only Watchdog carries: the entry code must not
acquire IPC handles, Job memberships, or spool and store writes that would
couple it into the Host or Kernel failure domain (I8.1, I1.6) — Watchdog
that cannot survive `eliotd` failure is not supervision. Prohibited
expansion: no semantic observation, spool writes, or store access inside
unsafe; no new families; unknown control codes receive a neutral status,
never a panic across `extern "system"` (which would abort). Risks: the same
argv lifetime and bound risks as Host, plus control-code dispatch on an SCM
thread and abort-on-unwind across the system boundary. Required proof:
operation-specific `// SAFETY:` at each block, unit tests over the safe
validators (`validate_watchdog_service_main_argv`,
`validate_watchdog_scm_bootstrap`: null, empty, overlong, multi-arg,
non-canonical inputs), and an owning reviewer. Evidence ceiling: policy plus
comment plus source coverage only. Review, removal, and migration trigger:
shared-parser extraction into `eliot-platform-windows` turns this manifest
to `forbid`; any coupling of Watchdog entry to Host or Kernel state is a
defect regardless of memory safety. Relation to I2.5: fourth and last
instance of the separate audited FFI bridge.

## Consequences

The manifest Wave B change is four comment lines, one per exception
manifest, each pointing at its exact row above; lint values, dependencies,
features, and ordering are untouched. Operation-specific coverage is Wave C
writer work and token-identity plus case coverage is Wave D writer work —
this ADR is the policy they hang from, not their proof. Because the local
tree predates #1156, #1157, and #1158, integration must revalidate every
"target coverage" citation above against the merged source before any claim
stronger than policy/comment/coverage is made. Future exceptions need an ADR
amendment, an owning reviewer, and oracle coverage before merge; silent
manifest widening is a scope-drift defect. No other ADR was modified, and
`0014` was verified free before writing.

## Acceptance evidence

- `docs/ADR/0014-unsafe-ownership-and-exceptions.md` did not exist before
  this change (`Test-Path` returned false) and follows the full 0009 shape:
  title, Status, Context, Decision, Consequences, Acceptance evidence.
- The five-row denominator above reproduces the actual manifests:
  `eliot-platform-windows:47`, `eliot-windows-ipc:28`, `eliot-ipc:26`,
  `eliot-host:43`, `eliot-watchdog:37`, with the workspace root forbidding
  `unsafe_code` at `Cargo.toml:331` and no `eliot-platform-unix` member
  present.
- Each of the four exception manifests carries exactly one comment
  referencing its exact row anchor (`#row-eliot-windows-ipc`,
  `#row-eliot-ipc`, `#row-eliot-host`, `#row-eliot-watchdog`); missing,
  duplicate, unknown, or stale rows fail closed under the Wave D oracle.
- `git diff --check` is clean and `git diff --stat` shows comment-only
  additions in the four manifests.
- Proof ceiling: this ADR plus manifest comments plus the Wave C/D oracle
  prove ownership, adjacency, and operation-specific coverage only. No
  universal memory-safety, IPC-completion, runtime, or product claim follows
  from issue #728.
