# Assignment reservation

Owning issue: #653
Implementation PR: #654
Branch: `work/653-dreamer-classification`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: implement only the A-03 Classification handler port for wire kind `Classification`. Consume A-03 validated item/A-05 receipt values; do not compile-link or invoke A-05/A-14b, A-31 or sibling handlers. Return A-03 `TypedCurationHandlerResult`; preserve screen eligibility and all common identities.

The full semantic execution contract is issue #653 and its authoritative correction comment; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
