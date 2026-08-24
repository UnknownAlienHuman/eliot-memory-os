# W0-02 ContractChallenge: Cargo lint inheritance for intentional FFI

Status: `CONTRACT_CHALLENGE_ACCEPTED`

Requested mechanism:

- The recovery program requires all eleven listed packages to use `[lints] workspace = true` and to express intentional unsafe exceptions pointwise.

Current tool constraint:

- The workspace policy sets `unsafe_code = "forbid"`.
- Rust `forbid` cannot be lowered by a source-level `allow` attribute.
- Cargo 1.97 inherits `workspace.lints` as one table. A package cannot combine `[lints] workspace = true` with package overrides, and Cargo has no per-tool-group inheritance switch.
- Therefore an intentional Windows FFI package cannot both inherit the complete table and override only `unsafe_code` under the current policy.

Rejected shortcuts:

1. Do not lower the workspace default from `forbid` to `deny` merely to make the requested syntax possible.
2. Do not leave the five FFI packages with only `[lints.rust]`; that silently drops all workspace Clippy coverage.
3. Do not add `clippy::all` or `clippy::pedantic` allow blocks.
4. Do not pretend that `[lints.clippy] workspace = true` is partial inheritance; Cargo treats lint configuration inheritance at the top-level `[lints]` table.

Root decision:

- Safe packages use `[lints] workspace = true`.
- The five intentional FFI packages retain minimal explicit Rust exceptions (`unsafe_code = "allow"` where required and `unsafe_op_in_unsafe_fn = "deny"`).
- They duplicate the exact effective workspace Clippy policy until Cargo supports partial inheritance or a first-party generated lint-profile owner is admitted.
- Verification must compare the effective policy and run focused `clippy --all-targets -- -D warnings`; manifest syntax alone is not acceptance evidence.

This is a tool-compatibility deviation, not a waiver of lint coverage and not authority to broaden unsafe code.

## Empirical rebaseline

The recovery program's stated warning counts do not describe the frozen
`d40a0a1` source once the complete workspace Clippy policy is restored.
The first focused command

`cargo clippy -p eliot-platform-windows --all-targets --locked --message-format short -- -D warnings`

reported 244 blockers: one production `too_many_lines` and 243 test-target
`expect_used`, `unwrap_used`, or `print_stderr` diagnostics. This is a
causal consequence of adding the previously omitted workspace policy to the
package and compiling test targets; it is not evidence that only eight
`missing_errors_doc` findings existed.

Root execution rule:

- do not restore greenness with crate-wide, module-wide, or global
  `allow` attributes;
- repair test fixtures in file-owned lanes using typed `Result` propagation
  or explicit expected-error matching;
- refactor the production long function without semantic changes;
- rerun focused and then workspace Clippy after every bounded lane;
- treat every count as revision-bound evidence, not as a timeless requirement.

The inheritance deviation is accepted; W0-02 implementation remains open until
the resulting effective policy is warning-free.
