# #870 T15/V2 — clean-toolchain-bootstrap probe evidence (O1, 2026-10-06)

## What this proves
A real compile of the checker-embedded probe source for the pinned guest
target, using a freshly bootstrapped toolchain installed from the accepted
Declaration values — no ambient-toolchain mutation, no target install from
any guest lane. This is the "separate clean-environment execution evidence"
required by T15/V2 (audit `issues/870/ISSUE-AUDIT.md`:20-21).

## Scope limits (honest ceiling)
- Clean TOOLCHAIN bootstrap (fresh `RUSTUP_HOME`/`CARGO_HOME`), not a clean
  machine or container: the Docker daemon is unavailable on this host
  (`docker info` fails: no engine at the Desktop pipe), so no container run
  was possible. The fresh homes contained only what was installed below.
- The checker reports `clean_bootstrap_qualified: false` BY DESIGN
  (`scripts/verify-wasm-toolchain.py:221,397` — never assigned True, so the
  checker cannot self-certify); this transcript is the external evidence.
- No binary committed: artifact identified by SHA-256 + size + header only.
- Ambient toolchain unmodified: every rustup command below ran with
  `RUSTUP_HOME`/`CARGO_HOME` pointed at the fresh root; no `target add`
  was run anywhere (the guest target arrived via `toolchain install
  --target`, i.e. bootstrap, not repair). The checker source contains no
  `target add` (pinned by `test_probe_argv_pins_wasip2_without_manual_target_add`).

## Bootstrap (commands, <CLEAN_ROOT> = fresh empty dir created this session)
1. `rustup toolchain install 1.97.1 --profile default --target wasm32-wasip2 --no-self-update`
   -> `1.97.1-x86_64-pc-windows-msvc installed - rustc 1.97.1 (8bab26f4f 2026-07-14)`
2. `rustup component add --toolchain 1.97.1 clippy rustfmt rust-analyzer rust-src`
   -> clippy/rustfmt up to date (default profile); rust-analyzer + rust-src downloaded
3. `rustup target list --installed --toolchain 1.97.1`
   -> `wasm32-wasip2`, `x86_64-pc-windows-msvc` (exactly the declared targets)
4. `rustup run 1.97.1 rustc --version --verbose`
   -> `release: 1.97.1`, `commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452`,
   `host: x86_64-pc-windows-msvc`

Declaration consumed (`rust-toolchain.toml`): channel `1.97.1`, profile
`default`, components `clippy/rustfmt/rust-analyzer/rust-src`, targets
`x86_64-pc-windows-msvc + wasm32-wasip2`, digest
`3e4ff676e17256f09ffe298ec7b04d476d76df8c55d6fd4bd939b27d190dd3bd`.

## Probe (repo checker against the bootstrap)
`python -B scripts/verify-wasm-toolchain.py --root . --probe --format json`
with the fresh `RUSTUP_HOME`/`CARGO_HOME` (branch `conv/O1/870`, == main):

- `status: PASS`, `reason: LOCAL_COMPONENT_COMPILED`, `compilable: true`
- `compiler_commit: 8bab26f4f68e0e26f0bb7960be334d5b520ea452` (freshly
  downloaded pinned compiler, matches the accepted release)
- `probe_sha256: 536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4`
  == sha256 of `PROBE_SOURCE` (`scripts/verify-wasm-toolchain.py:40`,
  `b"fn main() {}\n"`): the artifact came from exactly the embedded source
- `artifact_sha256: d20f66eeda4984cd06492d6d5a77e0d68f5ff47363c6c312598651cafed63e9b`,
  `artifact_bytes: 2848797` (header gate `COMPONENT_HEADER`, :42, passed —
  otherwise the checker reports `COMPILE_ARTIFACT_INVALID`)
- `declaration_sha256: 3e4ff676…` (same digest the lane binds: R3 feed holds
  on this head)

## Environment
Windows host, worktree detached at `conv/O1/870` (content == `origin/main`);
fresh toolchain homes removed after the run except this record.
