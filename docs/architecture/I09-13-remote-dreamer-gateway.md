## I9.13. Remote Dreamer gateway

Optional process `eliot-dream-gateway`, independently enabled after installation. The first remote profile serves one owner through that owner's Cloudflare Tunnel and Access application. Cloudflare Managed OAuth supplies interactive client authentication; explicitly designated owner automation may use Cloudflare Service Auth. ELIOT provides no external login, account, OAuth authorization-server or refresh-token service.

Allowed:

```text
authenticated bounded question/recall within predefined WorkScope visibility;
read-only answer items from a locally compiled, policy-admitted redacted bundle;
answers with citations and gateway-scoped signed references;
principal-bound expiring answer-resource expansion with fresh visibility checks;
audit and security signals to their existing owners.
```

The remote MCP compatibility profile exposes only `search` and `fetch`. These aliases translate to existing query/read semantics and introduce no new canonical hot operation. `search` carries bounded query data under the explicitly bound read profile and resolvable QueryIntent; it cannot select arbitrary scope or obtain raw retrieval access. `fetch` accepts only a previously released gateway answer reference. Input/output schemas come from the same typed adapter contracts as their implementation.

The Governor read/visibility owners compile the bundle and decide disclosure. Kernel issues the owner principal and operational Session/fence binding from admitted local process metadata and mechanically enforces grants admitted by the existing policy owners. External request fields, MCP initialization and Cloudflare subject text cannot mint those identities. A remote profile never inherits the owner's administrative or local write authority.

Forbidden:

```text
direct database/retrieval API or raw canonical browsing;
local filesystem/tool access;
memory write or agent-launch authority;
Kernel/Host/ELIOT administration and unrestricted control operations;
raw operational telemetry or broad project enumeration;
secret-bearing bundles or arbitrary handle expansion.
```

Remote references never expose local `eliot://`, filesystem or blob paths, database keys or reusable internal capabilities. Gateway signatures protect answer-resource integrity and do not replace Cloudflare authentication. Every expansion rechecks principal, grant, scope, revision, expiry, erasure and current visibility. The returned full item is the bounded redacted answer resource, not an unfiltered source represented as a harmless reference.

Remote input is always instruction-tainted data. Query text and tool output do not become executable instructions. The gateway may retain only bounded, disposable released-resource projections; it owns no canonical memory or alternative semantic retrieval database. It can be disabled independently without disabling local ELIOT.

Google Drive is not an ELIOT data source or authentication bridge in this profile. A client's separately authorized Google connector neither grants ELIOT access to Drive nor grants its users access to ELIOT.
