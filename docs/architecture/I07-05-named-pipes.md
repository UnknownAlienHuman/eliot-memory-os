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

normal remote MCP/control transport
  FORBIDDEN: the local bridge and Kernel control surface are not published remotely;

single-owner remote question profile
  OPTIONAL, after installation and explicit enablement: separate eliot-dream-gateway
  behind the owner's Cloudflare Tunnel and Access boundary, under I9.13/I15.13.
```

The loopback HTTP profile binds only `127.0.0.1`/`::1`, requires a scoped short-lived bearer credential issued through local setup, enforces the same Session/authority contracts, and exposes no admin or database surface. It validates `Host` and, for browser-originated requests, `Origin` against the exact loopback profile; non-loopback, ambiguous and DNS-rebinding forms are rejected. Binding `0.0.0.0`, trusting loopback without host validation, or reusing the local credential remotely is forbidden. Losing the HTTP bridge does not affect Kernel or canonical state.

The separate remote gateway has its own loopback origin listener and exact public Host/Origin policy. Cloudflare performs external authentication; the gateway verifies Cloudflare's signed assertion before accessing its Kernel-admitted read profile. Neither the public hostname nor a forwarded identity header is sufficient authentication. The ordinary bridge's local credential is never accepted as a remote credential. Local IPC principal, nonce, SID and Authority Epoch binding remain governed by I15.2.
