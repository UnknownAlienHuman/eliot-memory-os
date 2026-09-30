# Report: issue #1225 (N_step9/N_step10 slice) — verifier dispatch probes + oracle identity

Branch `fix/1225-verifier-selftest-MC1`, rebased cleanly onto `origin/main`
(`0738d7ef`). HEAD `5b6fad051`.

## What changed

- N_step9: every self-test refusal is judged twice — once against its own
  rule and once through `verify_all`, the production dispatch owner — with
  exact finding identity (code+path+line+detail), plus a completeness case
  proving EVERY `check_*` rule was exercised (expected set derived from
  module globals, not a hand list). Four previously unjudged production
  rules (fail-closed privilege, locked restore, SDK identity, NuGet
  lock-graph) get committed fixtures plus probes.
- N_step10: the `--json-out` run manifest records the oracle identity
  (versioned closed file set + per-file sha256 + combined digest) under an
  additive `oracle` key, so the independent/manual owner attests the exact
  oracle bytes behind the verdict (I18.27).

Files: `scripts/verify-github-workflows.py` + 12 fixtures under
`scripts/testdata/github-workflows/`. No `check_*` rule semantics changed,
no workflow YAML touched.

## Gates (observed, post-rebase)

- `--self-test`: `GITHUB_WORKFLOW_VERIFIER_SELF_TEST: PASS (128/128)`.
- Manager mutation probe: deleted `check_dotnet_sdk_identity` from the
  `verify_all` dispatch → `SELF_TEST_FAILURE` naming the exact missing
  GWF-014 finding, exit 1; script restored byte-identical afterwards.
- `git diff --check`: clean.

## Docs attestation

Route `sha256:a9792fc7…`, read receipt `sha256:93a83243…`, bundle
`0fe87387…`, routes instrument-verification/release-migration/
workspace-governance, 66 required items. Manager read the decision-relevant
bundle sections (I18.43, I18.47) and the issue-mandated shards I2.8, I2.18,
I18.21, I18.27, I15.4, `.github/README.md` directly. Conformant: oracle
attestation instead of self-certification (I18.27), same script locally
and in CI (I18.21), no workflow trigger/permission change. Full receipt in
`docs-read-receipt.json`.

## Note

Steps 1–8 are pre-existing on main and preserved. The issue's "no
worktrees" line conflicts with lane topology; this branch merges to main,
satisfying the intent.
