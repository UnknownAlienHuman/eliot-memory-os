# WORK_UNIT_CASE: 750/10 negative fixture. A Review tail missing the
# mandatory workspace-test and deny gates must fail profile validation.
$steps = @(
    [pscustomobject]@{ Name = 'cargo-metadata'; Command = { cargo metadata --locked --format-version 1 | Out-Null } },
    [pscustomobject]@{ Name = 'cargo-fmt'; Command = { cargo fmt --all -- --check } },
    [pscustomobject]@{ Name = 'cargo-check-workspace'; Command = { cargo check --locked --workspace --all-targets } },
    [pscustomobject]@{ Name = 'cargo-clippy-workspace'; Command = { cargo clippy --locked --workspace --all-targets -- -D warnings } }
)
