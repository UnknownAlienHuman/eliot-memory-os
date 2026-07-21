set shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

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

quick: metadata fmt-check check

verify: metadata fmt-check check clippy test
