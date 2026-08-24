set shell := ["pwsh", "-NoLogo", "-NoProfile", "-Command"]

default: quick

metadata:
    cargo metadata --no-deps --format-version 1 | Out-Null

fmt-check:
    cargo fmt --all -- --check

check:
    cargo check --workspace --all-targets

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

operator-check:
    dotnet build apps/Eliot.Operator/Eliot.Operator.csproj --configuration Release

claude-package:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-claude-desktop-extension.ps1

# Rewrites the OpenCode and Claude skill copies from integrations/agent-skills.
# The copies are generated: edit the canonical body, then run this.
sync-skills:
    cargo run --quiet -p eliot-app -- host skill-sync

quick: metadata fmt-check check

verify:
    pwsh -NoProfile -File scripts/verify.ps1

verify-list:
    pwsh -NoProfile -File scripts/verify.ps1 -List
