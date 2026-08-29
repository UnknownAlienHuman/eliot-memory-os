# Supported repository scripts

Scripts are narrow wrappers around current source contracts. Their presence does
not create authority, implementation support, runtime readiness, or Product
Proof. Start from the owning issue/PR and use the smallest applicable entrypoint.

Do not select a script because its filename sounds broader or more final. A
script without a current consumer, owner, proof ceiling, and removal path is
retired rather than preserved as archaeology.

## Repository verification

| Script | Purpose | Proof ceiling |
|---|---|---|
| `verify.ps1` | Current Windows developer verification: normative identity, architecture-boundary audit, nearest-path agent guardrails, runtime-source hygiene, agent-bridge public protocol policy, Cargo metadata, formatting, and workspace check | Source/build candidate only |
| `verify.sh` | Unix-compatible counterpart for the current bounded source checks | Source/build candidate only |
| `verify-normative.ps1` | Recompute canonical Architecture/Implementation digests and pair key; reject predecessor copies | Normative artifact identity only |
| `verify-normative.sh` | Unix-compatible normative-pair verifier | Normative artifact identity only |
| `audit-architecture-boundaries.py` | Scan declared core/daemon runtime roots for forbidden dependencies, SurrealDB leakage, untracked direct process launch, and production placeholders | Static source/build architecture evidence only |
| `verify-agent-guardrails.py` | Require bounded nearest-path owner/proof/stop instructions for core and daemon source subtrees | Routing/control-plane evidence only |
| `audit-runtime-source-hygiene.py` | Expose unsafe, panic/unwrap/expect, ambient configuration, unbounded-output, blocking-sleep, and source-concentration risks in runtime roots | Static source-quality signals only |
| `verify-agent-bridge-protocol.py` | Reject raw canonical Frame ingress, host-minted authority fields, validation bypass, correlation loss, and mandatory cancellation prose | Static protocol/source-policy evidence only |
| `verify-lint-policy.ps1` | Verify the current Rust lint-policy configuration and declared exceptions | Static source-policy evidence only |

Normal iteration uses `just quick` or `scripts/verify.ps1`. The manual Source
Candidate Gate in `.github/workflows/source-candidate.yml` owns the expensive
workspace check/Clippy/test/build breadth. Neither path proves an installed or
healthy runtime.

### Architecture-boundary audit

Run the deterministic negative fixtures and then the current-tree scan:

```powershell
python scripts/audit-architecture-boundaries.py --self-test
python scripts/audit-architecture-boundaries.py
```

Use `--json-out <path>` only for a current issue/PR or CI artifact. Generated
audits are not committed as authority. Findings have three distinct meanings:

- `HARD_VIOLATION` — an untracked contradiction; verification fails;
- `TRACKED_DEBT` — an exact current path with owning issue and removal condition;
- `AUDIT_SIGNAL` — review evidence such as a large composition root or stale debt entry; it is not conformance or authority.

The policy is `config/architecture-boundaries.toml`. An exception must name one
exact path/package, issue, reason, and removal condition. Wildcards and unnamed
legacy allowances are rejected. A clean audit does not prove runtime behavior,
process containment, store correctness, or Product acceptance.

### Nearest-path agent guardrails

```powershell
python scripts/verify-agent-guardrails.py --self-test
python scripts/verify-agent-guardrails.py
```

The verifier requires the routing files at `bins/AGENTS.md` and the declared
Governor, Instrument, Kernel, Meta, Module, Research, Storage, Supervision, and
Surface subtrees. Each file must remain bounded, name current owner issues,
require current-`main` issue/branch/PR/write-scope discipline, state authority
and canonical-write limits, and expose a proof plus stop condition.

These files narrow work; they cannot grant authority beyond the root
instructions, owning issue, or normative pair. A clean result proves only that
the expected routing surfaces exist and contain the required boundaries. It
does not prove the implementation follows them.

### Runtime-source hygiene

```powershell
python scripts/audit-runtime-source-hygiene.py --self-test
python scripts/audit-runtime-source-hygiene.py
```

The scanner masks comments and literals and ignores the suffix after the first
file-level `cfg(test)` boundary. Actual unsafe code in a composition binary is a
`HARD_VIOLATION`. Panic/unwrap/expect, ambient environment/current-directory
access, potentially unbounded or discarded process output, blocking sleeps,
missing crate-root unsafe prohibitions, and source concentration remain
`AUDIT_SIGNAL` review evidence.

Signals do not fail integration and do not force a split by count or line
volume. Review the exact path, owner, effect, failure behavior, and replacement
boundary. JSON output is permitted only as a current issue/PR or CI artifact;
it is not committed as a support report. A clean scan is not runtime, process,
store, security, or Product proof.

### Agent-bridge public protocol policy

```powershell
python scripts/verify-agent-bridge-protocol.py --self-test
python scripts/verify-agent-bridge-protocol.py
```

The verifier is bound to the public `eliot-agent-bridge` stdin request enum, the
inert host request/cancellation contracts, and the stateless host gateway. It
requires typed `invoke`/`cancel`, strict unknown-field rejection, validation
before the trusted port call, exact host correlation and cancellation-target
preservation, optional cancellation prose, and a typed fail-closed Kernel gap.

It rejects public raw canonical `Frame` forwarding and host fields that would
mint or carry Kernel/Governor-owned principal, Session/task/WorkScope,
`RequestIdentity`, State Fence, Authority Epoch, idempotency/cancellation
identity, absolute deadline, or effect ceiling. Its self-test covers both the
accepted contract and the named regression classes.

A clean result proves only the current public source boundary. It does not
establish a live Kernel host-request endpoint, RequestIdentity issuance,
Governor dispatch, external effects, reconnect behavior, Edge Proof, or Product
support. The complete integration remains owned by issue #77.

## Release and installation

| Script | Purpose | Boundary |
|---|---|---|
| `build-eliot-windows-x64-release.ps1` | Build the declared Windows x64 release inputs and unsigned bundle | Build/staging only; no signing, installation, or live support |
| `finalize-eliot-windows-x64-release.ps1` | Sign/finalize and independently read back the declared release artifacts | Release-artifact evidence only; no installed-state claim |
| `invoke-eliot-windows-x64-production.ps1` | Execute the supported manifest-bound production invocation/installation flow | Uses the current release and installation contracts; live acceptance remains issue #11 |

Read `docs/release/WINDOWS_X64_RELEASE.md` before using these scripts. The
canonical user/operator command surface is `eliot.exe`; scripts do not create a
parallel CLI or permit direct storage/process authority.

## Integration packaging and probes

| Script | Purpose | Boundary |
|---|---|---|
| `build-claude-desktop-extension.ps1` | Build the current Claude Desktop extension package from repository sources | Package construction only |
| `test-claude-connector.ps1` | Run the bounded current Claude connector probe/fixture path | Integration evidence for its exact fingerprint only |
| `eliot-mcp-reference-client.ps1` | Reference MCP client for protocol/bridge diagnostics | Diagnostic/client evidence; no canonical authority |

Current integration semantics live in `docs/integrations/`. Provider versions,
accounts, routes, and host behavior are requalified per issue; an old successful
probe is not current support.

## Isolated test execution

| Script | Purpose | Boundary |
|---|---|---|
| `run-isolated-tests.ps1` | Provision an owned Windows/Surreal test namespace, run one selected package/test profile, and preserve bounded evidence/cleanup disposition | Exact selected Module/Edge evidence only |

This script is not a generic production runner and cannot turn a fake or
in-memory test into real store/runtime proof. Invoke it from an owning issue with
an exact test selector and current Surreal artifact identity.

## Admission rule for a new script

A new script requires:

- one current owning issue and consumer;
- a stable source contract or command it wraps;
- exact inputs, identity, side effects, and cleanup boundary;
- a declared proof ceiling and failure behavior;
- no hidden credentials, broad filesystem mutation, or alternative authority
  path;
- a documentation entry here and a removal condition.

Campaign names, milestone numbers, `final`/`certified` labels, dated audit
wrappers, and convenience aliases around legacy binaries are rejected. Current
findings belong in the issue/PR or CI artifacts, not in a new report-generating
script.
