# Claude integration security boundary

Claude is a replaceable host. The Governor remains the authority for task state,
leases, memory lifecycle, verification, completion, and canonical receipts.

## Enforced boundaries

- Claude Code and Claude Desktop receive an authenticated stdio facade over the
  current per-user Governor runtime.
- Runtime and auth generation are bound to each agent session. A rotated
  generation must reconnect and cannot reuse stale authority.
- The compact Claude profile exposes no raw SQL, database credentials, arbitrary
  filesystem or shell access, provider control, patch authority, or unconditional
  completion tool.
- Candidate submission is idempotent and candidate-only. It requires exact scope,
  a retry-stable write ID, applicability bounds, negative constraints,
  provenance, and a freshness rule.
- Host identity grants no controller, worker, auditor, verifier, patch, or
  completion role. Current task-scoped leases are required.
- Hooks may enrich or deny early; they cannot manufacture authority or proof.

## Credentials and package handling

The integrations must not read or copy Claude OAuth/session tokens, provider
caches, private conversations, database passwords, or runtime auth tokens.
Authentication remains owned by Claude's official login flow. Install manifests
and receipts may contain owned paths and hashes but never secret values.

Claude Code installation owns only the ELIOT plugin directory beneath the
current user's Claude skills root. Claude Desktop installation uses the official
MCPB review UI. Neither path may rewrite unrelated settings, provider auth,
services, registry keys, or system `PATH`.

## Rollback

```powershell
.\target\release\eliot-governor.exe host uninstall --host claude
.\target\release\eliot-governor.exe host uninstall --host claude-desktop
```

Uninstall is scoped by the ELIOT-owned install manifest and must refuse content
that no longer matches the installed ownership record.
