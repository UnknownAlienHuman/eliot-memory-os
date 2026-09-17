<!-- generated: eliot-doc-shards-v1 -->
# Documentation sharding integrity report

This report records the deterministic layout migration. It does not add a
third normative source.

- Normative pair key: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`
- Canonical semantic byte streams changed: **no**
- Legacy file paths retained as compatibility maps: **yes**
- Cross-fragment self-links rewritten only as navigation metadata: **yes**

| Source | Original bytes | Fragments | Largest rendered fragment | Reconstructed SHA-256 |
|---|---:|---:|---:|---|
| Architecture | 149403 | 123 | 10212 | `c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a` |
| Implementation | 1003351 | 504 | 25823 | `40b0908a637f46ba6c7c51db08e008673f9232ed74d510d3a4f38489d05d4e89` |

Verification reconstructs each source by reversing only recorded link-target
rewrites and concatenating fragments in manifest order. Any missing byte,
reordered fragment, stale index, stale compatibility anchor, or changed
fragment hash fails closed.
