# Assignment reservation

Owning issue: #667
Implementation PR: #668
Branch: `work/667-dreamer-reconsolidation`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: implement only the A-03 Reconsolidation handler port for wire kind `Reconsolidation`. Consume A-03 validated item/A-05 receipt values and exact parent/reactivation/source/dependency projections; do not compile-link or invoke A-05/A-14b, A-31 or sibling handlers. Return A-03 `TypedCurationHandlerResult` and preserve screen eligibility/common identities.

The full semantic execution contract is issue #667 and its authoritative correction comment; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
