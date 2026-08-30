## I3.3. Installation Survey

Survey safely discovers:

```text
Codex CLI/Desktop;
Claude Code/Desktop;
OpenCode;
Antigravity/agy;
Git and Git worktrees;
VS Code / JetBrains;
Rust toolchain;
LSP servers;
MCP configurations;
known code graph tools;
local model runtimes;
registered browsers/professional tools;
SurrealDB installations;
optional cloud CLIs.
```

Probe order:

```text
known configuration paths and manifests;
PATH metadata;
file version/signature;
only then a safe `--version` or initialization probe without secrets or elevated rights.
```

A discovered executable is not started automatically as a trusted Module.

Existing SurrealDB processes/installations are observations or import candidates, not implicit members of the ELIOT store lineage. Setup never kills, adopts or reuses an unrelated process merely because its port or binary name matches. The installer chooses and records an installation-owned loopback endpoint/data root, verifies the owning PID/artifact/HostState lineage before every start/reconnect, and returns a Recovery Directive on collision. Legacy data enters only through an explicit read-only inspection/import/migration path.

