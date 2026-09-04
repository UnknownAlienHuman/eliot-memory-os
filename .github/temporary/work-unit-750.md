# Assignment reservation

Owning issue: #750
Implementation PR: pending
Branch: `chore/750-manual-verification-parity`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `.github/workflows/ci.yml`, `.github/workflows/repository-policy.yml`, `Justfile`, `scripts/verify.ps1`, their exact verification fixtures, and this temporary marker. The work establishes one complete locked manual Review profile consumed identically by direct PowerShell, `just quick`, and manually dispatched `ci.yml`, while repository-policy verifies the wiring and manual-only workflow rule.

All supported workflows must remain `workflow_dispatch`-only. Forbidden: `pull_request`, `push`, `schedule`, `workflow_run`, `pull_request_target`, edits to `source-candidate.yml`, Rust/Cargo/lock/deny/toolchain/product source, automatic comments/mutation/merge/release/deployment, skipped mandatory gates, or weaker wrapper-specific profiles.

Dependencies: D-BUILD #746 and D-CLIPPY #748 integrated and green. Issue #750 is the complete corrected execution contract. Rebase on actual current `main`, freeze the current command/trigger/permission denominator before mutation, and remove this marker before the pull request is marked ready.
