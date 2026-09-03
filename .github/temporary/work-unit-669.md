# Assignment reservation

Owning issue: #669
Implementation PR: #670
Branch: `work/669-dreamer-accessibility`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: implement only the A-03 Accessibility handler port for wire kind `Accessibility`. Exactly one independent axis changes per call; existence/support/accessibility/influence/erasure remain separate. Consume A-03 validated item/A-05 receipt and owner-issued closure values; do not compile-link or invoke A-05/A-14b, A-31, the closure algorithm or sibling handlers. Return A-03 `TypedCurationHandlerResult` and preserve screen eligibility/common identities.

The full semantic execution contract is issue #669 and its authoritative correction comment; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
