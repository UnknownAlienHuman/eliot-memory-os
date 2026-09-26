<!-- eliot-doc-routing:start -->
## Documentation read evidence (machine-verified, #2965)

Run the reader from the repository root, open the verified bundle, and read every
required item before you open this pull request:

```text
python scripts/docs_read.py read --changed-from origin/main --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Copy the resulting identities into the ONE block below and fill every field. The
merge gate recomputes every field against the FINAL merge candidate with the
same `docs_router_core` / `docs_read` algorithms; a plausible-looking digest that
does not reproduce fails closed. Empty values, `see receipts`, `as listed above`,
`<path>`, `<issue title>` and any second copy of this block are rejected. Prose
outside this block never overrides a machine failure. `attestation.statement` is
a separate attributed claim made AFTER the machine fields validate; it never
substitutes for them and never asserts comprehension.

Required items: every routed `required` entry appears exactly once with its exact
current `sha256` and `bytes`. `optional_expansions` is either `"none"` (nothing
was opened) or one object per optional item actually opened, each with its exact
current `sha256` and the boundary-crossing `reason`. `checklist` states whether a
checklist/work-unit record is required by the assignment contract, and binds it
to the final candidate tree.

<!-- eliot-doc-read-evidence:v2:start -->
```json
{
  "attestation": {
    "read_by": "<your identity>",
    "statement": "<I read every required item in this envelope at these exact digests.>"
  },
  "base_sha": "sha256:<git tree object id of the final base>",
  "bundle": {
    "bytes": 0,
    "sha256": "<verified bundle sha256>"
  },
  "candidate": {
    "commit": "<final candidate commit, or null>",
    "tree": "sha256:<git tree object id of the final candidate>"
  },
  "changed_paths": [
    "<every final changed path, including deletions and renames>"
  ],
  "checklist": {
    "bound_candidate_tree": "sha256:<candidate tree, or null>",
    "issue": 0,
    "recorded": false
  },
  "contract_inputs": {
    "handle_index_path": "docs/architecture/handle-index.json",
    "handle_index_sha256": "<current handle index sha256>",
    "normative_pair_path": "docs/normative-pair.toml",
    "normative_pair_sha256": "<current normative pair receipt sha256>",
    "reader_contract": "scripts/docs_read.py@eliot-doc-read-v1",
    "route_rules_path": "docs/architecture/route-rules.toml",
    "route_rules_sha256": "<current route rules sha256>",
    "router_contract": "scripts/docs_router.py+scripts/docs_router_core.py@eliot-doc-routes-v1"
  },
  "matched_routes": [
    "<route id>"
  ],
  "optional_expansions": "none",
  "pair_key": "sha256:<normative pair key>",
  "read_receipt_id": "sha256:<read receipt id>",
  "repository": {
    "name": "eliot-memory-os",
    "owner": "UnknownAlienHuman"
  },
  "required_items": [
    {
      "bytes": 0,
      "handles": [],
      "path": "<repository-relative path>",
      "sha256": "<current sha256>"
    }
  ],
  "route_receipt_id": "sha256:<route receipt id>",
  "schema_version": "eliot-doc-read-pr-evidence-v2",
  "topic": "<the exact causal-property text used for routing>"
}
```
<!-- eliot-doc-read-evidence:v2:end -->
<!-- eliot-doc-routing:end -->

## Owning work

- Issue:
- Workstream entry in `workstreams/ACTIVE.toml`:
- Primary causal property / `FunctionalCapabilityCell`:
- Primary mutable path scope and writer:

## Source identity

- Base branch: `main`
- Base SHA:
- Candidate SHA:
- Confirmed current `main` is an ancestor: yes / no

## Change

- Old failing behavior or missing capability:
- Discriminator:
- Changed source/contracts:
- Explicit non-goals:

## Proof

- Module/shape proof executed:
- Affected Edge Proof executed:
- Product Pulse executed, or exact not-applicable reason:
- Evidence status: `NOT_EXECUTED | SIMULATED | EXECUTED | UNKNOWN_OUTCOME`
- Skipped/failing checks:

## Boundaries

- Mutable state/effects and owner:
- Authority/security/privacy delta:
- Migration, rollback, removal, and branch-retirement plan:
- Residual unknowns:

## Hygiene confirmation

- [ ] No historical audit/report/progress diary/donor dump was added.
- [ ] No `.eliot`, `.codebase-memory`, runtime database, log, report, build output, credential, or local agent state was added.
- [ ] External Eliot Search/Research product documentation remains in its owning repository.
- [ ] Documentation/source references use the canonical files on `main`.
- [ ] The branch will be retired after merge/closure.
