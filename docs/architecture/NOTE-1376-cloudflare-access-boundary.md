# Design note: single-owner remote access through the owner's Cloudflare account (#1376)

Status: design note (pre-install). Companion to the full decision handoff in
`T14.md`; the adopted contract is the amended
[I7.5](I07-05-named-pipes.md), [I9.13](I09-13-remote-dreamer-gateway.md),
[I15.13](I15-13-remote-dreamer-security.md) and
[A9.6](A09-06-remote-dreamer.md). Owner decision 2026-09-14; canonical scope
clarification 2026-09-22. Vendor documentation checked 2026-09-26 (see
References). No endpoint is deployed and no authentication code is changed by
this note; runtime implementation is deferred behind the install phase.

## 1. Selected connection path

ChatGPT reaches ELIOT as a remote MCP client over one owner-controlled path:

```text
ChatGPT MCP connector (OAuth client)
  -> Cloudflare edge: one Access application, owner-only policy,
     Managed OAuth with dynamic client registration [C1][C2]
  -> cloudflared Tunnel (locally managed, Windows service) with the
     originRequest Access gate before forwarding [C3][C8]
  -> loopback-only eliot-dream-gateway on the owner's PC, /mcp only,
     exposing search/fetch over the admitted read profile [O1][O2]
  -> Kernel-admitted restricted remote-read profile (I9.13/I15.13)
```

Owner automation on an explicitly enabled remote machine uses the same origin
through a designated Cloudflare Service Auth token instead of interactive
OAuth [C7]. The ordinary local stdio/IPC path is unchanged.

## 2. Endpoint and owner selected

- Public endpoint: one owner-controlled hostname fronting one Access
  application (exact hostname chosen at setup time, after install).
- Gateway endpoint: the separate `eliot-dream-gateway` process bound to an
  explicitly configured loopback address/port; MCP compatibility profile
  `search`/`fetch` only, with URL-based citations to gateway answer
  resources [O1].
- Owner: the single ELIOT owner. The owner's Cloudflare identity (exact
  issuer/user/sub match) and, when configured, one designated Service Auth
  identity (exact issuer/service/common_name match) map to one Kernel-issued
  owner principal with a restricted remote-read profile. No ELIOT user
  accounts, login flow, password verification, OAuth authorization server, or
  refresh-token store is built [C5][C6].

## 3. Assertion handling at the origin

Every gateway request validates the `Cf-Access-Jwt-Assertion` signed
assertion: signature and allowed algorithm, exact trusted issuer and
application audience, expiry and applicable not-before constraints, keys only
from the configured team's trusted endpoint [C5]. The opaque OAuth client
token is never decoded as a JWT or forwarded to Kernel. A service-token
assertion with an empty user subject never identifies the owner [C6]. Neither
the public hostname nor a forwarded identity header is authentication.

## 4. Negative boundaries

The remote client receives no database credentials, no raw canonical
browsing, no local filesystem or tool access, no write or agent-launch
authority, no Kernel/Host/ELIOT administrative control, and no unfiltered
operational telemetry. Remote input stays instruction-tainted data; gateway
signatures protect answer-resource integrity and never replace Cloudflare
authentication; security signals go to Watchdog. Acceptance of the deferred
implementation items must restate these boundaries and name the actual
endpoint and owner selected at setup.

## 5. Rejected alternatives

- A Worker, MCP portal, or other extra proxy hop in front of the gateway:
  the documented managed authorization path avoids another secret-bearing
  component [C1][C2].
- A tunnel to the ordinary agent bridge or any remote MCP/control surface:
  forbidden by I7.5.
- An ELIOT-built login, account, or OAuth service: explicitly out of scope
  for this phase by owner decision.
- Google Drive as transport or identity into ELIOT: the owner's ChatGPT
  Google Drive connection stays a separate authorization boundary with no
  Google token or Drive synchronization added to ELIOT [O5].

## 6. References (checked 2026-09-26)

- [C1] Cloudflare Managed OAuth (open beta):
  <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/> —
  Access serves OAuth (discovery, dynamic client registration) for a
  self-hosted application; origin requests carry a signed Access assertion.
  Announcement: <https://blog.cloudflare.com/managed-oauth-for-access/>;
  changelog: <https://developers.cloudflare.com/changelog/post/2026-03-20-managed-oauth/>.
- [C2] Cloudflare Secure MCP servers:
  <https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/> —
  Access handles the OAuth flow for MCP clients; the MCP server implements
  no authorization logic.
- [C3] Cloudflare Tunnel origin parameters:
  <https://developers.cloudflare.com/tunnel/reference/origin-parameters/> —
  `originRequest.access` makes `cloudflared` validate the Access JWT before
  proxying to the origin.
- [C4] Cloudflare self-hosted Access application:
  <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/> —
  application type used for the owner-only policy.
- [C5] Cloudflare JWT validation:
  <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/> —
  validate signature, issuer, application audience (AUD tag), and time
  claims at the origin.
- [C6] Cloudflare application token:
  <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/> —
  user versus service-token identity forms; empty service-token subject.
- [C7] Cloudflare service tokens:
  <https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/> —
  machine access via Service Auth with the `CF-Access-Client-Id` and
  `CF-Access-Client-Secret` headers (same page as T14 [V2]; header and
  policy mechanics confirmed current across September 2026 sources).
- [C8] Cloudflare locally managed tunnel:
  <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/create-local-tunnel/> —
  file-based local tunnel configuration.
- [O1] OpenAI MCP integration: <https://developers.openai.com/api/docs/mcp> —
  `search`/`fetch` compatibility shapes, structured results, URL-based
  citations.
- [O2] OpenAI developer mode:
  <https://developers.openai.com/api/docs/guides/developer-mode> — remote
  MCP server connection options, including OAuth.
- [O3] Connectors in ChatGPT:
  <https://help.openai.com/en/articles/11487775-connectors-in-chatgpt> —
  ChatGPT connector surface.
- [O4] Developer mode and MCP apps in ChatGPT:
  <https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt-beta> —
  remote MCP servers in ChatGPT; local servers need a tunnel.
- [O5] Google Drive app and setup in ChatGPT:
  <https://help.openai.com/en/articles/10929079-google-drive-app-and-setup-in-chatgpt> —
  Drive connects to ChatGPT under its own permissions; not a bridge into
  ELIOT.
