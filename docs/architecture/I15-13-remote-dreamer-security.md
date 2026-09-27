## I15.13. Remote Dreamer security

The first remote deployment is single-owner. External access and its administration use the owner's Cloudflare account. ELIOT builds no user accounts, password verification or OAuth authorization server. Cloudflare login does not grant remote ELIOT administration or bypass local process isolation.

```text
separate gateway process, disabled until explicitly enabled;
Cloudflare Tunnel to a loopback-only origin and owner-restricted Access policy;
Cloudflare assertion validation at ingress and origin;
exact admitted owner user identity or designated owner service identity;
one Kernel-issued owner principal with a restricted remote-read profile;
explicit WorkScope, QueryIntent, authority/fence and expiry checks;
rate, concurrency, deadline, input, output and released-resource limits;
read bundle compiled locally by the existing read/visibility owners;
no arbitrary handle expansion, local tools, remote writes or agent launch;
redacted output and safe expiring citations;
Watchdog security events without credentials or raw private payloads;
independent emergency disable and invalidation of remote grants/resources.
```

The origin verifies signature, allowed algorithm, exact trusted issuer and application audience, expiry and applicable not-before constraints of Cloudflare's signed assertion. Unverifiable assertions are rejected. Untrusted headers and caller-selected key URLs are never identity evidence. Cloudflare's opaque OAuth client token is not decoded as a JWT or reused on the Kernel IPC leg. User and service-token identity forms are distinguished explicitly; an empty user subject cannot identify the owner.

Cloudflare identity aliases are deployment configuration for the one owner, not ELIOT accounts or a second Session store. Kernel validates the admitted gateway process and approved read profile under I15.2. Remote input cannot select a principal, manufacture a Session, widen WorkScope/effects or revive a revoked binding. Authentication establishes request origin, not knowledge truth or permission to execute embedded instructions.

Secrets remain behind their existing protected providers or the upstream tunnel's protected credential file. No service secret, OAuth token, assertion, cookie or management credential enters source control, argv, logs, model context or canonical memory. Answers are not publicly cached. Authentication and disclosure checks apply to answer URLs as well as MCP calls.

Access-policy changes and credential revocation must not be presented as instant invalidation of already verified offline assertions. The local emergency action closes remote admission and invalidates the affected Kernel binding and released resources. Gateway/tunnel failure cannot expose an unauthenticated fallback or stop normal local Kernel operation.
