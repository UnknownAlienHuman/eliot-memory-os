set shell := ["pwsh", "-NoLogo", "-NoProfile", "-Command"]

default: quick

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

runtime-source-hygiene-self-test:
    python scripts/audit-runtime-source-hygiene.py --self-test

runtime-source-hygiene:
    python scripts/audit-runtime-source-hygiene.py

agent-bridge-protocol-self-test:
    python scripts/verify-agent-bridge-protocol.py --self-test

agent-bridge-protocol:
    python scripts/verify-agent-bridge-protocol.py

metadata:
    cargo metadata --locked --no-deps --format-version 1 | Out-Null

fmt-check:
    cargo fmt --all -- --check

check:
    cargo check --locked --workspace --all-targets

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
    cargo run --quiet -p eliot-app -- host skill-sync

quick: normative architecture-boundaries-self-test architecture-boundaries agent-guardrails-self-test agent-guardrails runtime-source-hygiene-self-test runtime-source-hygiene agent-bridge-protocol-self-test agent-bridge-protocol metadata fmt-check check

verify:
    pwsh -NoProfile -File scripts/verify.ps1

verify-list:
    pwsh -NoProfile -File scripts/verify.ps1 -List
