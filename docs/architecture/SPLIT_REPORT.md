<!-- generated: eliot-doc-shards-v1 -->
# Documentation sharding integrity report

This report records the deterministic layout migration. It does not add a
third normative source.

- Normative pair key: `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`
- Canonical semantic byte streams changed: **no**
- Legacy file paths retained as compatibility maps: **yes**
- Cross-fragment self-links rewritten only as navigation metadata: **yes**

| Source | Original bytes | Fragments | Largest rendered fragment | Reconstructed SHA-256 |
|---|---:|---:|---:|---|
| Architecture | 149403 | 123 | 10212 | `c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a` |
| Implementation | 999718 | 504 | 25823 | `7805bf238fe91819aba50d7e13aa86a8b977561195dbb98aa979f986e2fab063` |

Verification reconstructs each source by reversing only recorded link-target
rewrites and concatenating fragments in manifest order. Any missing byte,
reordered fragment, stale index, stale compatibility anchor, or changed
fragment hash fails closed.
