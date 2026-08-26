# Unknowns and next probes

## Static-audit boundary

The current audit intentionally did not install or execute package code. The following items remain unknown because package bytes, public sources and official prose do not expose enough evidence.

## Priority unknowns

| Priority | Unknown | Why it matters | Safe next probe without package execution |
|---:|---|---|---|
| P0 | Independently pinned APT signing-key fingerprint | same-origin key+metadata does not independently prove repository identity | locate fingerprint in Perplexity security/docs/support or NVIDIA cross-publication; verify through a second authenticated channel |
| P0 | Exact license/source offer for core binaries and ASAR | determines auditability, redistribution and supply-chain assurance | request SBOM, source offer, license list and build attestation for build 50522 |
| P0 | Exact hashes/sizes/licenses of post-launch model, engine, Python and container downloads | package is not self-contained; disk and trust boundary lives in bootstrap payloads | extract all catalog structs/URLs/digests from binary; query repository metadata/API only, without downloading payloads |
| P0 | Telemetry payload, opt-out and behavior before consent/sign-in | packaged app statically defaults Sentry/Datadog on | inspect privacy docs and static serializer/event schemas; request vendor payload schema |
| P1 | Local search index implementation | official announcement says local index; bundled config calls air-gapped backend future | search exact index/storage symbols/schema in sidecar and frontend; obtain official architecture clarification |
| P1 | Runtime proof of sandbox fail-closed behavior | official claim is strong but static branch cannot prove exact installed behavior | only under a separately authorized disposable VM: remove/untrust bwrap, attempt harmless tool call, capture process/mount/network evidence |
| P1 | PII classifier defaults, false-negative behavior and grant persistence | outbound privacy depends on classifier/consent semantics | static extraction of settings/default tables; vendor test documentation; runtime test only with synthetic PII and explicit authorization |
| P1 | Update mechanism and provenance | Electron Linux update commands appear no-op; APT likely owns updates | inspect official installation/update docs and future repository snapshots; do not run updater |
| P1 | Complete uninstall/cleanup behavior | `postrm` leaves user data/model/container cleanup unspecified | vendor cleanup docs; static catalog of data roots/container labels; runtime only in disposable VM |
| P2 | SQLite schema migrations, transaction isolation and writer ownership | durable tasks/history can corrupt or split under failure | continue static SQL/migration extraction; request schema docs/source |
| P2 | Exact role and ABI of `libaic.so` | large native opaque component in multimodal path | symbol/version/string analysis and dependency map; no dynamic loading |
| P2 | Credential storage and broker authentication | search/connectors depend on signed-in session | static keyring/API call analysis; vendor security design docs |

## Downloads deliberately not performed

The following large/executable payloads were **not** downloaded:

- Qwen/PPLX/Nemotron model weights;
- vLLM or Perplexity Docker/OCI images;
- private llama.cpp binaries;
- Python wheels/venv dependencies;
- Windows/amd64 package binary after arm64 was selected as primary target;
- any update payload.

The amd64 package stanza was inspected, but its 173,985,420-byte `.deb` was not needed to reconstruct the initial DGX Spark/Arm path.

## Next static probes in recommended order

### 1. Vendor provenance request

Ask Perplexity for:

- official signing-key fingerprint published independently of package origin;
- SBOM/SPDX/CycloneDX for build 50522;
- core license and source-offer status;
- reproducible-build or signed provenance statement;
- payload manifest for model/container/Python downloads;
- data/telemetry/retention and cleanup documentation.

### 2. Complete binary schema extraction

Without executing the binary:

- enumerate all SQLite `CREATE TABLE/INDEX` strings;
- recover model/engine catalog records into a structured JSON inventory;
- enumerate URLs, repository IDs, digests, expected sizes and hardware predicates;
- map RPC methods to Rust source-module strings;
- map preference keys and defaults;
- hash every evidence excerpt back to its source binary.

### 3. ASAR security review

Continue source-visible review of:

- Electron permission policy;
- IPC/RPC allowlist and preload exposure;
- deep-link validation;
- updater no-op/platform branches;
- telemetry initialization and filters;
- privileged host-setup command validation;
- PII consent surface lifecycle.

### 4. Public artifact monitoring

Check for later publication of:

- Perplexity technical report and Local Knowledge Work Bench;
- exact 20260824 model repository/license;
- public localharness/RPC source;
- SBOM/source package in APT;
- Windows/RTX release artifacts.

Record publication date and exact revision; do not silently overwrite this 2026-08-26 snapshot.

## Optional runtime phase — separate authorization required

No runtime phase is needed to complete this static audit. If explicitly authorized later, use a disposable Linux/Arm VM or dedicated DGX test installation with:

- no production credentials/data;
- outbound network capture and domain allowlist;
- filesystem/process/container snapshots before and after each step;
- strict disk budget before model/image downloads;
- synthetic files/PII only;
- install/remove and crash/restart fault cases;
- independent verification of sandbox mounts, network, PII consent, durable job recovery and cleanup;
- destruction/reversion of the disposable environment after evidence export.

Do not run extracted binaries directly from Downloads and do not use user production Docker/Hugging Face caches.

## Stop conditions for any future phase

Stop immediately on:

- signer/hash/size mismatch;
- unexpected redirect or unlisted payload origin;
- credential request outside an explicitly authorized test account;
- unbounded model/image download;
- sandbox fallback to unsandboxed tools;
- raw artifact entering Git;
- package process or service escaping the disposable environment;
- two failed approaches to the same probe without a new discriminating hypothesis.

