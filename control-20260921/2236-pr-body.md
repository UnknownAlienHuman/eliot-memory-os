# PR body — 1805: bind instrument results to exact executable identities (integrated)

Rework branch `work/1805-exec-identity` at `30358ba3` (Implements #1805),
integrated onto current main in `codex/1805-exec-identity-integration`
(candidate `94763444`; original ancestry `13e0b067`, `c4699c9f`,
`30358ba3` preserved; `origin/main` and `1a18895e` verified ancestors;
tree clean, no extra delta).

Scope: (a) `InstrumentRunner::launch_verified` plus
`VerificationRunnerService::run_current` enforce the identity so a swapped
executable loses PASS; (b) argv-to-argv contract (`binds_argv` against
sealed request/launch argv, never invocation filters) with
`From<ExecutableObservation>` plus `bridge_executor_observation`
conversion; (c) digest-pinning claims stay at the intent-sealed
`executable_sha256` at launch while `ProviderRegistry::ready` keeps the
honest follow-up wording; (d) Windows hashing under deny-write opens
mirroring the launch-lease posture (retained cross-launch pin stays with
the kernel lease). Defects fixed: instrument label on `new()`,
`InvalidArguments` cause, `ArgvMismatch` binding verdict (never transient
`Unavailable`), PATHEXT plus separator-file plus Unix exec-bit handling,
decoder-only PASS documented, temp drop guards in tests.

Docs-read receipts: route
`sha256:e5811876580d12360a6cc75925fa3212b4131f22c56cd3b385d3c9a60ed1383d`,
read
`sha256:e9e24b4857921fb12eb16d4d1475b152e1765566fc4e335592fa5477ce1619b8`,
bundle sha256
`e2b2172244f475a3508c85aa0becda9ff276a76882b035cb8504d39221ff5f56`;
matched routes: generic-source, instrument-verification,
workspace-governance, repository-root; 59 required items read before
mutation (handles A0.1, A0.2, A0.3, A0.4, A0.6, A2.3, A5.5, A10.4, A10.8,
A14.6, A14.7, A14.8, APPENDIX-J, APPENDIX-P, I0.3, I0.4, I0.5, I0.13,
I0.14, I2.17, I2.20, I2.21, I2.22, I2.23, I10.8.1–I10.8.19, I10.8, I10.9,
I10.10, I16.17, I17, I18, plus the ten required files); owning fragments
I18.1 (`e2b2b680…`), I18.2 (`df328516…`), I18.6 (`d6317991…`), I18.8
(`d2e1b9db…`) read directly. Reading attestation: full bundle (3856
lines) + nearest AGENTS + issue/PR read before the no-mutation decision.

Gates (single runs): eliot-instrument-runner 11/11,
eliot-process-executor 30/30, eliot-engine verification::current 3/3
(includes a real `cargo nextest` process and a real compiled probe
binary); `cargo fmt --check` clean; `cargo clippy` zero new hits (4
pre-existing `expect_used` in executor test helpers).

Known honest bounds (in code, not footnotes): tool version and
environment digest are attested, never observed; hash race narrowed to
the observation instant; retained cross-launch pin is the kernel lease
(other owner). Production eliotd/testd wiring and worker/Kernel joint
proof belong to their owners; no API change here, so no handoff pending.

Worker verdict: READY-NEEDS-REAUDIT. Full evidence:
`control-20260921/2236-integrated-delivery.md`.
