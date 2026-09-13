# WORK_UNIT_CASE: 750/10 negative fixture. A duplicated mandatory gate
# name must fail profile validation. (Minimal $steps-shaped snippet.)
$steps = @(
    [pscustomobject]@{ Name = 'cargo-metadata'; Command = { cargo metadata --locked --format-version 1 | Out-Null } },
    [pscustomobject]@{ Name = 'cargo-fmt'; Command = { cargo fmt --all -- --check } },
    [pscustomobject]@{ Name = 'cargo-fmt'; Command = { cargo fmt --all -- --check } },
    [pscustomobject]@{ Name = 'cargo-check-workspace'; Command = { cargo check --locked --workspace --all-targets } },
    [pscustomobject]@{ Name = 'cargo-clippy-workspace'; Command = { cargo clippy --locked --workspace --all-targets -- -D warnings } },
    [pscustomobject]@{ Name = 'cargo-test-workspace'; Command = { cargo test --locked --workspace } },
    [pscustomobject]@{ Name = 'cargo-deny'; Command = { cargo deny check } }
)
