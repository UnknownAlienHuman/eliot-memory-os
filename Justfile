set shell := ["pwsh", "-NoLogo", "-NoProfile", "-Command"]

default: quick

docs-shards-self-test:
    python scripts/docs_shards.py self-test

docs-shards:
    python scripts/docs_shards.py verify --root .

docs-router-self-test:
    python scripts/docs_router.py self-test

docs-router:
    python scripts/docs_router.py check --root .

docs-read-self-test:
    python scripts/docs_read.py self-test

doc-code-conformance-self-test:
    python scripts/verify-doc-code-conformance.py --self-test

doc-code-conformance:
    python scripts/verify-doc-code-conformance.py --root .

code-navigation-self-test:
    python scripts/code_navigation.py self-test

code-navigation:
    python scripts/code_navigation.py check --root .

code-navigation-sync:
    python scripts/code_navigation.py sync-index --root .

docs-closure-audit:
    python scripts/docs_closure_audit.py --root .

# Legacy source-shape diagnostic (always NOT_VERIFIED; see module.toml acceptance), e.g. `just work-unit eliot-cue-contracts`.
work-unit crate:
    python scripts/verify-work-unit.py --crate {{crate}} --root .
# Crates that live outside the workspace and outside `exclude`, so no other gate
# covers them. Runs fmt, clippy and tests for each.
[env("CARGO_NET_OFFLINE", "true")]
standalone-crates:
    python scripts/verify-standalone-crates.py --root .

# Fail-closed gate for crates/smart/cognitive-donor-map.toml: every donor
# disposition against current source, one current base for the donor
# dispositions and the topology donor authority, and the authority ceiling
# that keeps a donor from becoming a runtime owner. Metadata evidence only.
cognitive-donor-dispositions:
    python scripts/verify-cognitive-donor-dispositions-816.py --root .

normative:
    pwsh -NoProfile -File scripts/verify-normative.ps1

architecture-boundaries-self-test:
    python scripts/audit-architecture-boundaries.py --self-test

architecture-boundaries:
    python scripts/audit-architecture-boundaries.py

agent-guardrails-self-test:
    python scripts/verify-agent-guardrails.py --self-test

agent-guardrails:
    python scripts/verify-agent-guardrails.py

agent-route-bundles-self-test:
    python scripts/verify-agent-route-bundles.py --self-test

agent-route-bundles:
    python scripts/verify-agent-route-bundles.py

runtime-source-hygiene-self-test:
    python scripts/audit-runtime-source-hygiene.py --self-test

runtime-source-hygiene:
    python scripts/audit-runtime-source-hygiene.py

agent-bridge-protocol-self-test:
    python scripts/verify-agent-bridge-protocol.py --self-test

agent-bridge-protocol:
    python scripts/verify-agent-bridge-protocol.py

core-daemon-inventory-self-test:
    python scripts/verify-core-daemon-inventory.py --self-test

core-daemon-inventory:
    python scripts/verify-core-daemon-inventory.py --root .

dependency-policy-self-test:
    python scripts/verify-dependency-policy.py --self-test

dependency-policy:
    python scripts/verify-dependency-policy.py --root . --profile offline-source

dependency-policy-advisories:
    python scripts/verify-dependency-policy.py --root . --profile current-advisories

dependency-policy-artifacts:
    python scripts/verify-dependency-policy.py --root . --profile offline-source --sbom-out .eliot/dependency-policy-artifacts/sbom.json --license-report-out .eliot/dependency-policy-artifacts/licenses.json --advisory-report-out .eliot/dependency-policy-artifacts/advisories.json

opencode-plugin:
    Get-Content -Raw integrations/opencode/plugins/eliot.js | node --input-type=module --check
    node --test integrations/opencode/tests/eliot-plugin.test.mjs
    Get-Content integrations/opencode/plugin-bridge-contract.json -Raw | ConvertFrom-Json | Out-Null

[env("CARGO_NET_OFFLINE", "true")]
metadata:
    cargo metadata --locked --no-deps --format-version 1 | Out-Null

[env("CARGO_NET_OFFLINE", "true")]
fmt-check:
    cargo fmt --all -- --check

[env("CARGO_NET_OFFLINE", "true")]
check:
    cargo check --locked --workspace --all-targets --offline

clippy:
    cargo clippy --locked --workspace --all-targets -- -D warnings

test:
    cargo test --locked --workspace

operator-check:
    dotnet build apps/Eliot.Operator/Eliot.Operator.csproj --configuration Release

claude-package:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-claude-desktop-extension.ps1

# Rewrites the OpenCode and Claude skill copies from integrations/agent-skills.
# The copies are generated: edit the canonical body, then run this.
sync-skills:
    cargo run --quiet -p eliot -- host skill-sync --repo-root "{{justfile_directory()}}"

# Bounded Quick profile as ordered by scripts/verify.ps1 -Profile Quick. Quick
# success is never Review/release proof. The dependency list below is the
# retained just-quick baseline pinned by scripts/docs_closure_audit.py
# (DOC-GATE-JUST) and by the repository-policy WIRING checker; it runs each
# bounded gate once and is deliberately not routed through the shared profile
# owner, so unlike `verify`/`merge-compile` it does not perform the versioned
# profile admission (issue #1914 W2/W4). `verify` and `merge-compile` below are
# the local entrypoints that reach the one shared resolver; `just quick` is a
# bounded source oracle baseline and claims no versioned-profile parity.
# Quarantined legacy verification lane (issue #1813 W6): the cargo recipes below execute
# directly with no governed profile receipt. Thin-invoker migration to the same named
# profile awaits W4 stage-execution provisions; until then no governed claim rests on
# these gates.
quick: docs-shards-self-test docs-shards docs-router-self-test docs-router docs-read-self-test doc-code-conformance-self-test doc-code-conformance code-navigation-self-test code-navigation docs-closure-audit standalone-crates cognitive-donor-dispositions core-daemon-inventory-self-test core-daemon-inventory normative architecture-boundaries-self-test architecture-boundaries agent-guardrails-self-test agent-guardrails agent-route-bundles-self-test agent-route-bundles runtime-source-hygiene-self-test runtime-source-hygiene agent-bridge-protocol-self-test agent-bridge-protocol metadata fmt-check check

# Complete locked Review profile, sole definition in scripts/verify.ps1.
# Thin invoker only: the shared owner below performs the minimal bootstrap
# build and then resolves the closed profile alias through the one shared
# resolver, so this recipe holds no verifier command list of its own.
verify:
    pwsh -NoProfile -File scripts/verify.ps1 -Profile Review

# Explicit Review alias; identical single Review invocation as `verify`.
verify-review:
    pwsh -NoProfile -File scripts/verify.ps1 -Profile Review

# Automatic merge compile check (accepted issue #3004); sole definition in
# scripts/verify.ps1. Compile-only: zero test execution, no lint-cleanliness
# claim. It enters the same owner, the same closed alias, and the same
# resolver that the automatic ci.yml check reaches through this same script,
# so the revision resolved here is the revision CI resolves.
merge-compile:
    pwsh -NoProfile -File scripts/verify.ps1 -Profile MergeCompile

verify-list:
    pwsh -NoProfile -File scripts/verify.ps1 -List

# #764 affected-component WASM lane (serialized after #750, never wired into
# `quick`/`verify`; #750 stays the owner of workspace verification).
#
# `{{quote(...)}}` keeps each forwarded value one shell literal, so no caller
# input can terminate the command and reach the shell as a second statement.
# Module-name validation, registry membership, manifest/world/capsule freeze,
# the isolated lane target root and the fixed exact-manifest argv are owned by
# scripts/wasm_component_lane.py; these recipes only forward the module name
# and the controller evidence. No cargo invocation, no --workspace, no
# target-dir and no module list live here.
#
# wasm_registry: the helper deliberately contains NO module list, so the
# caller supplies the accepted registry. The default is the bounded TEST
# FIXTURE scripts/testdata/wasm-component-lane/registry.json, whose own
# _provenance field reads "TEST FIXTURE ONLY - not authority" - it is a
# fail-closed placeholder, NOT the canonical registry, and the integrator owns
# the canonical shared registry. Until a real accepted registry is supplied the
# placeholder resolves only the fixture guest and no production module is
# reachable. Override per invocation with the controller's accepted registry:
#   just wasm_registry="<accepted-registry>.json" wasm-build <module>
# wasm_base_sha/wasm_head_sha: controller-supplied frozen source evidence.
# Workers never fetch, pull or rebase here, so the defaults are the helper's
# own 40-zero placeholder SHAs rather than a git-derived or invented value; an
# unsupplied binding stays visibly unbound in the receipt instead of silently
# claiming an identity.
wasm_registry := "scripts/testdata/wasm-component-lane/registry.json"
wasm_base_sha := "0000000000000000000000000000000000000000"
wasm_head_sha := "0000000000000000000000000000000000000000"

# Exact-manifest build of one registered component under the helper's isolated
# lane target root for #870's wasm32-wasip2 target.
#
wasm-build module:
    python scripts/wasm_component_lane.py --build {{quote(module)}} --registry {{quote(wasm_registry)}} --base-sha {{quote(wasm_base_sha)}} --head-sha {{quote(wasm_head_sha)}}

# Declared-capsule-only test of one registered component; never the workspace
# gate, never a second package list.
#
wasm-test module:
    python scripts/wasm_component_lane.py --test {{quote(module)}} --registry {{quote(wasm_registry)}} --base-sha {{quote(wasm_base_sha)}} --head-sha {{quote(wasm_head_sha)}}
