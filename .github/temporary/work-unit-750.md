# Work unit D-CI

Owning issue: #750

Exclusive implementation scope:
- `.github/workflows/ci.yml`
- `.github/workflows/repository-policy.yml`
- `Justfile`
- `scripts/verify.ps1`
- their existing verification fixtures

Dependencies: D-BUILD #746 and D-CLIPPY #748. Keep `source-candidate.yml` manual and unchanged. Remove this reservation file before the implementation PR is marked ready.
