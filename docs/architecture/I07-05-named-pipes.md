## I7.5. Named pipes

```text
\\.\pipe\eliot\kernel\frontdoor
\\.\pipe\eliot\kernel\store
\\.\pipe\eliot\kernel\daemon\<generation>
\\.\pipe\eliot\module\<module_id>\<generation>
\\.\pipe\eliot\watchdog\signals
```

ACL allows only expected service/user SID. Each launched child also presents random nonce delivered via protected inherited handle/file, not command line.

### Agent-facing transport profiles

```text
stdio shim
  DEFAULT: agent starts a near-stateless bridge which connects to Kernel front door;

loopback Streamable HTTP
  OPTIONAL: for local hosts that cannot manage stdio reliably; disabled by default;

remote transport
  FORBIDDEN for normal MCP/control access in the first line.
```

The loopback HTTP profile binds only `127.0.0.1`/`::1`, requires a scoped short-lived bearer credential issued through local setup, enforces the same Session/authority contracts, and exposes no admin or database surface. It validates `Host` and, for browser-originated requests, `Origin` against the exact loopback profile; non-loopback, ambiguous and DNS-rebinding forms are rejected. Binding `0.0.0.0`, trusting loopback without host validation, or reusing the local credential remotely is forbidden. Losing the HTTP bridge does not affect Kernel or canonical state. Future online access is limited to the separate bounded Dreamer gateway of I9.13/I15.13.

