<!-- eliot-doc-routing:start -->
## Documentation read receipt

- Reader command:
- Route receipt ID:
- Read receipt ID:
- Matched route IDs: see receipts
- Required handles, fragment paths, and SHA-256 values read: as listed above
- Verified bundle SHA-256:
- Optional expansions opened and reason:
- Explicit reading attestation: I read all of the required normative documentation for this change.
<!-- eliot-doc-routing:end -->

Sanitized reproduction of the merged #2963 pull request body shape: the
documentation block is free text, every identity field is empty, the matched
route IDs and required fragments are placeholders, and only a prose attestation
is offered. No machine-readable evidence block is present.

The controller must reject this with `EMPTY_DOCUMENTATION_EVIDENCE`; the
attestation sentence cannot make it pass.

## Owning work

- Issue:
- Primary mutable path scope and writer:
