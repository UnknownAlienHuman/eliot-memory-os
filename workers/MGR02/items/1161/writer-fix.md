# WRITER-1161b fix record (MGR02 item 1161)

- Role: WRITER-1161b, single bounded fix for `manual_let_else`.
- Branch: `regression/7-claude-correlation` (base `c24ba219`, root base `8820296a12059037706790310b5ae0b633105a96`).
- File touched (code): `bins/eliot-agent-bridge/src/main.rs`
- Function: `write_response`, lines 309-316 after fix (was 309-319).
- Diff stat: 6 insertions, 9 deletions, 1 file.

## Before (lines 309-319)

```rust
fn write_response(response: &Response) -> StdioWriteReceipt {
    let mut framed = match serde_json::to_vec(response) {
        Ok(framed) => framed,
        Err(_) => {
            return StdioWriteReceipt {
                bytes: 0,
                flushed: false,
                cause: StdioBreakCause::SerializeFailed,
            };
        }
    };
```

## After (lines 309-316)

```rust
fn write_response(response: &Response) -> StdioWriteReceipt {
    let Ok(mut framed) = serde_json::to_vec(response) else {
        return StdioWriteReceipt {
            bytes: 0,
            flushed: false,
            cause: StdioBreakCause::SerializeFailed,
        };
    };
```

- Semantics preserved: same `SerializeFailed` return (`bytes: 0, flushed: false`), same subsequent `framed.push(b'\n')` / borrow. No other lines changed.
- Pre-existing warnings left alone: `trivially_copy` at :209/:223 and 2x `eliot-mcp` `doc_markdown` not touched.

## Verification (only allowed check)

- Command: `cargo check -p eliot-agent-bridge --all-targets`
- Exit code: 0
- Did NOT run: `cargo test`, workspace `cargo clippy`, harness (manager runs workspace clippy).

## No-allow attestation

- No `#[allow]` added (none in diff, none in function).
- No other files touched in code change (only `bins/eliot-agent-bridge/src/main.rs` plus this evidence file).
- No amend of `c24ba219`, no rebase. New commit only.
