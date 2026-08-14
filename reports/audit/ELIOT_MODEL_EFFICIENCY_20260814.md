# ELIOT model and OpenCode efficiency telemetry — 2026-08-14

Status: operational telemetry and candidate-routing guidance. This report is not product authority, a benchmark suite, `CELL_ACCEPTED`, or release proof.

## Final campaign snapshot

- OpenCode CLI: `1.4.3`.
- Project campaign cutoff: session `created >= 1786717816656`.
- Final registry count: **82 sessions**.
- Substantive implementation/audit sessions: **74**.
- CLI/config/permission/bootstrap control sessions: **8**.
- Maximum simultaneous OpenCode agents: **5**, each with an independent session and task-specific context.
- The final agreed expansion after the 66-session checkpoint was exactly 16 substantive launches.

## Context consumption

The original high first-turn cost was primarily MCP schema injection, not Eliot alone:

- `--pure` with five non-Eliot MCP entries still enabled: first-turn input `63,252`, total `65,401` tokens.
- New process-local all-MCP-off control: first-turn input `9,050`, total `10,972` tokens.
- Reduction: `54,202` first-turn input tokens, approximately `85.7%`.

After all MCP entries, instructions, plugins and Eliot policy files were disabled, real multi-step OpenCode Go Luna tasks still accumulated approximately `76,917` to `118,856` cached input tokens. Recursive process inspection showed zero MCP descendants during those batches. The remaining consumption therefore came mainly from agents reading the nearly 1 MB Implementation document, the other authority artifacts, source files and Cargo output.

## Effective OpenCode configuration

Global CLI config:

- `C:/Users/kleym/.config/opencode/opencode.jsonc`
- observed SHA-256 after all-off normalization: `af5b618a...`
- `instructions = []`
- `plugin = []`
- MCP entries `context7`, `eliot`, `terminator`, `wow_api`, `codebase_memory`, and `github`: all `enabled = false`

Reversible backups:

- Eliot policy backup: `C:/Users/kleym/AppData/Local/Temp/opencode-eliot-policy-backup-20260814-160713`
- pre-all-off CLI config backup: `C:/Users/kleym/AppData/Local/Temp/opencode-cli-mcp-backup-20260814-1625/opencode.jsonc`

Every governed campaign launch also supplied a process-local all-MCP-off `OPENCODE_CONFIG_CONTENT`, `--pure`, an isolated worktree and a unique task-specific prompt. No shared context prefix was used.

## Final process restart proof

After every OpenCode task completed, the old OpenCode CLI server and OpenCode-host Eliot integration process trees were stopped with zero survivors. Fresh processes were launched:

- desktop PID at observation: `29948`;
- desktop-owned CLI server PID: `12540`;
- explicit hidden CLI server PID: `8872`.

Post-restart `debug config --pure` again reported zero instructions/plugins and all six MCP entries disabled. The new OpenCode roots had eight descendants and zero MCP descendants. PIDs are transient; the configuration and process-shape assertions require a fresh probe after another restart.

## Model effectiveness observed

### Native GPT-5.6 Sol

Best lane for authority, lifecycle, persistence and runtime semantics. Sol gates found defects that survived green package tests, including:

- G-03 minting canonical TaskContracts from proposals, incomplete lifecycle and unstable `Debug` retry identity;
- G-10 incomplete async blueprint saga and proofless readiness;
- A-01/A-03/A-05 execution through P-03 without `DispatchPermit`, incomplete non-fresh continuity and unsealed `NARROW`;
- P-11 pre-poll abort registry leak and platform-error-to-saturation overclaim;
- G-17 receipt/accounting gaps, which Sol then repaired before integration.

Use Sol for architecture-sensitive implementation, semantic repair and final independent gates.

### Native GPT-5.6 Luna

Efficient for bounded source review, Cargo gates, focused negative tests and contained fixes. Luna successfully diagnosed the supervisor load flake and exposed major P-05/S-04/A-12/G-10 candidate gaps. However its G-10 repair still missed the normative blueprint saga and complete readiness/fingerprint contract.

Use native Luna for small or well-bounded tasks and independent first-pass review. Require Sol when authority or lifecycle semantics remain material.

### OpenCode Go GPT-5.6 Luna

Useful for rapidly producing isolated source candidates, tests and ordinary state machines. It produced working scaffolds for G-03, G-10, P-02, P-05, P-06, P-11, S-03, S-04, A-10, A-12, A-13 and several repairs.

Recurring limitations:

- package-local green tests concealed authority-critical gaps;
- sealed Cargo dependency graphs were sometimes missed unless the exact edges were written directly into the prompt;
- lifecycle, persistence, proof and readiness semantics were commonly incomplete;
- two long launches hung before useful work and required one clean bounded retry;
- large authority/source reads remained expensive even with all MCP disabled.

Use OpenCode Go Luna for candidate construction with exact file ownership and an explicit direct-dependency list. Never integrate its authority-sensitive output without native review.

### DeepSeek V4 Flash

Useful for exact mechanical inventory, manifest normalization and simple bounded edits. It should not own semantic contracts, authority decisions, persistence recovery or acceptance claims.

## Routing rule retained after the campaign

1. Mechanical inventory or exact manifest work: DeepSeek V4 Flash if needed.
2. Bounded implementation candidate: OpenCode Go Luna or native Luna.
3. Native Luna first-pass audit and focused repair for small surfaces.
4. Native Sol for authority/runtime/persistence architecture and independent final gates.
5. Package tests prove compilation behavior only; root integration and semantic acceptance remain separate.

## Eliot writeback state

Successful candidate-only memory records:

- revision 253: `3d99a515-f04c-449f-82df-71dd3e5d3cb3`;
- revision 254 correction: `1c46f0e5-260b-40e0-8815-432ae6108805`;
- revision 255 restart/quality update: `6e3d8d5c-2f11-4a72-9b34-8b2c5f3d1e90`, exact readback verified.

The final 82-session update was not written because the Codex Eliot tool returned `Transport closed` twice after the required OpenCode process restart. No third bypass was attempted. The Git report is the durable fallback until the Codex plugin/task transport is restarted.
