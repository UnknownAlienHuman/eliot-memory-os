# Dependency policy decision: Wasmtime 47.0.4

Date: 2026-08-24  
Scope: `eliot-wasm-host` and the workspace dependency graph  
Status: accepted for the recovery-program dependency gate

## Decision

Pin the workspace `wasmtime` dependency to exactly `47.0.4`, preserving the
existing feature set: `default-features = false`, `component-model`,
`cranelift`, `runtime`, and `std`. The lockfile is regenerated with Cargo and
must retain the exact `47.0.4` graph.

The workspace `rust-version` is raised from `1.89` to `1.94`. Wasmtime 47.0.4
declares Rust `1.94.0` as its minimum supported compiler; keeping the old
workspace MSRV would make the pinned dependency claim dishonest. This
supersedes the older 1.89 planning baseline in ADR 0001 for this workspace.

## Why this version

The canonical implementation profile names the Wasmtime 47.x component-runtime
candidate in
[`ELIOT_IMPLEMENTATION.md` I0.2](architecture/ELIOT_IMPLEMENTATION.md#i02-current-compatibility-baseline).
Version 47.0.4 is the smallest exact release that satisfies the recovery gate's
current security evidence:

- RustSec [RUSTSEC-2026-0222](https://rustsec.org/advisories/RUSTSEC-2026-0222.html)
  marks `>=47.0.3` as patched.
- RustSec [RUSTSEC-2026-0223](https://rustsec.org/advisories/RUSTSEC-2026-0223.html)
  marks `>=47.0.3` as patched.
- The upstream [Wasmtime v47.0.4 release](https://github.com/bytecodealliance/wasmtime/releases/tag/v47.0.4)
  was published 2026-08-20 and records fixes for guest-controlled host heap
  allocation through WASIp3 streams and a filesystem sandbox escape involving
  trailing slashes.

No advisory is ignored or downgraded in `deny.toml`.

## W0-03 bans remediation

The nine internal manifests that previously used unversioned path
dependencies now declare the workspace package version `0.1.0` on all 17
internal path edges. This keeps `wildcards = "deny"` active and makes the
workspace dependency graph explicit for Cargo and cargo-deny. The affected
manifests are `eliot-agent-codex`, `eliot-code-cortex`, `eliot-code-graph`,
`eliot-diagnostic`, `eliot-instrument-dotnet`, `eliot-instrument-nextest`,
`eliot-instrument-rustfmt`, `eliot-testd-core`, and `eliot-understanding`.

## License admission

`cargo deny check licenses` identified these additional SPDX expressions
requiring explicit admission across the pre-upgrade and upgraded
Wasmtime/Cranelift and existing Ed25519 closures:

- `Apache-2.0 WITH LLVM-exception` (Cranelift and Wasmtime packages);
- `BSD-3-Clause` (`curve25519-dalek`).
- `Zlib` (`foldhash`, introduced by the Wasmtime/Cranelift graph).

All three are permissive, OSI-approved licenses already consistent with the
canonical implementation policy's permissive dependency profile. They are
explicitly allowlisted, rather than covered by a wildcard or an advisory
exception. `MIT`, `Apache-2.0`, `BSD-2-Clause`, and `Unicode-3.0` remain
allowlisted because they are already present in the workspace closure.

## Compatibility and risk

The selected features intentionally exclude Wasmtime defaults such as async,
GC, profiling, pooling allocator, and component-model async. The upgrade does
change the transitive Cranelift/Wasmtime graph and raises the compiler floor;
focused `eliot-wasm-host` compile, test, Clippy, advisory, and license checks
are required before the W0 gate can be accepted.

## Rollback

Rollback is a single manifest/lockfile change to the prior exact
`wasmtime = 40.0.0` graph, but that state is not security-acceptable while the
current advisories apply. A rollback therefore requires a new dated security
decision and an independently verified patched release; `deny.toml` must not
gain an ignore entry to make the old graph pass.
