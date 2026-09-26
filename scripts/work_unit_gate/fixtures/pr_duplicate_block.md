<!-- eliot-doc-read-evidence:v2:start -->
```json
{
  "schema_version": "eliot-doc-read-pr-evidence-v2",
  "repository": { "owner": "sanitized", "name": "acceptance" }
}
```
<!-- eliot-doc-read-evidence:v2:end -->

Sanitized duplicate/ambiguous marker sample: the machine-readable evidence block
appears twice in one pull request body, so which statement is authoritative is
undefined. The controller must reject this with `UNKNOWN_OR_DUPLICATE_BLOCK`
rather than silently choosing one.

<!-- eliot-doc-read-evidence:v2:start -->
```json
{
  "schema_version": "eliot-doc-read-pr-evidence-v2",
  "repository": { "owner": "sanitized", "name": "acceptance" }
}
```
<!-- eliot-doc-read-evidence:v2:end -->
