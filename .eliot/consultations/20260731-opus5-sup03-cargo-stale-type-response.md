# Claude Code Opus 5 consultation result

- Model requested: `claude-opus-5`
- Mode: read-only / plan
- Wall-clock limit: 240 seconds
- Observed wall-clock: 244.1 seconds
- Result: `consultation_timeout`
- Response body: none
- Follow-up request: not issued, to conserve quota

The bounded diagnostic request did not return a decision. The 240-second limit
was an agent mistake: the user had not authorized an artificial Opus timeout.
No follow-up was sent because the local package-scoped artifact cleanup then
resolved the issue conclusively.

## Local resolution

- `cargo clean -p eliot-types`: PASS in 2.115 seconds; Cargo reported 6,453
  generated files / 13.5 GiB removed.
- Exact reproduction `cargo check --workspace --all-targets`: PASS in 52.888
  seconds after the cleanup.
- Conclusion: stale/internally inconsistent Cargo artifacts, not a source
  schema mismatch. No validation or type fields were weakened.
