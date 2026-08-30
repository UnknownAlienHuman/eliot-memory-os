## I3.13. Uninstall and data disposition

Uninstall is a governed lifecycle, not recursive deletion.

```text
preview affected services, integrations, routes and data roots
→ quiesce agents/jobs and revoke new admissions
→ remove host plugins/hooks/MCP registrations with rollback receipts
→ stop and unregister services
→ DEFAULT: preserve canonical data and offer ECXF export
→ optional privacy purge is a separate explicit authorized operation
→ remove immutable binaries only after reference check
→ leave final uninstall/data-disposition receipt outside the removed runtime.
```

Uninstall never silently deletes memory, backups or unresolved external effects. A failed integration rollback opens a Problem State and leaves exact manual recovery instructions.

