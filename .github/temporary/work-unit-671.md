# Assignment reservation

Owning issue: #671
Implementation PR: #672
Branch: `work/671-dreamer-memory-repair`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: implement A-03 handler family `MemoryRepair` for the exact wire kind `[Repair]`; do not create a `MemoryRepair` wire kind. Consume A-03 validated item/A-05 receipt and owner-issued defect/closure projections; do not compile-link or invoke A-05/A-14b, A-31, external repair/closure algorithms or sibling handlers. Return A-03 `TypedCurationHandlerResult` and preserve screen eligibility/common identities.

The full semantic execution contract is issue #671 and its authoritative correction comment; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
