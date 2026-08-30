## I3.7. Plugin registration

Setup installs a bridge or plugin only after preview:

```text
files to modify;
exact config block;
installed hooks;
registered MCP server;
tool/skill count;
rollback copy;
expected IntegrationCoverageProfile.
```

After installation, `eliot doctor integration <profile>` checks hash, active registrations, hook events, and handshake. Installation success is not runtime liveness.

