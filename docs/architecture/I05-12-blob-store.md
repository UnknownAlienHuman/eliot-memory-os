## I5.12. Blob Store

`BlobStore` is a vendor-neutral CAS contract with one active root owner. A co-located or process backend MUST implement the same contract, receipt format, encryption lineage, reachability rules and conformance suite. Kernel routes process-backed requests; `eliotd` decides whether a payload is admissible and later references only a completed `BlobReadyReceipt`. A component that is not the declared active owner never writes the blob filesystem directly. Extraction from an internal backend to `eliot-blob.exe` is a generation cutover: quiesce stages, reconcile temp/ready receipts, fence the old owner, switch the route, then resume.

Logical object identity is scoped by deletion and retention obligations:

```text
ObjectResidencyKey = scope_domain_id + access_domain_id + confidentiality_domain_id +
                     encryption_key_domain_id + retention_domain_id + erasure_domain_id +
                     content_digest
```

`content_digest` includes the active Blob format's algorithm and version; the current default is BLAKE3, but the ownership rule is algorithm-neutral. `scope_domain_id` binds the lawful WorkScope or source namespace; access and confidentiality domains bind principals and disclosure; `encryption_key_domain_id` binds the permitted key lineage; retention and erasure domains bind lifecycle and purge closure. Equal bytes deduplicate only when **all** residency-domain identities are equivalent. Byte equality never permits cross-domain physical co-residency, ciphertext reuse, encryption-key reuse, or coupling of retention and erasure obligations. Moving content between domains is an explicit copy or re-encryption transition with a receipt and an explicit disposition for the old copy—not a metadata relabel.

Physical path is derived from the full residency identity, not from a global content digest alone:

```text
C:\ProgramData\Eliot\blobs\<residency-key-digest>\<prefix>\<content-digest>.blob
```

Algorithm:

```text
stream through privacy/redaction policy;
compute the versioned digest of the exact post-policy canonical bytes;
resolve scope, access, confidentiality, encryption-key, retention and erasure domains and derive the residency key;
retain a separate protected source checksum only when policy permits;
compress and AEAD-encrypt to a temp envelope;
flush and fsync ciphertext plus metadata;
atomic rename;
return immutable `BlobReadyReceipt`/BlobRef only after durable rename and metadata commit;
allow canonical transition to reference only that receipt;
GC only after grace period and a coherent live-set scan.
```

The live set is the union of canonical references under a stable revision fence, unresolved ORS/staged-operation blob references, active export/backup/transfer leases and retention/purge holds. If any required source is unavailable or inconsistent, GC does not delete. A canonical-only reachability scan is insufficient because a durably staged operation may legitimately reference a blob that is not canonical yet.

Encryption uses a random installation master key protected by the platform secret provider and filesystem ACL for the ELIOT service identity; only the Blob Store code path receives the materialized key handle. Blob payloads use versioned per-object/per-scope AEAD envelopes; the master key, plaintext data keys and secrets never enter TOML, canonical memory or logs. This limits accidental exposure but is not claimed as a hard boundary against arbitrary code already compromised under the same privileged OS identity; `dpapi-machine` alone is never treated as authorization. Key rotation creates a new key lineage and background rewrap job; missing key material degrades reads/recovery visibly and never causes plaintext fallback.

`BlobReadyReceipt` binds the logical residency identity, versioned content digest, stored length, compression/encryption format, key lineage, privacy/retention class, erasure domain, durable path generation and operation identity. It proves durable payload availability only; admissibility and semantic meaning remain the later canonical transition.

Inline threshold DEFAULT: 32 KiB. Exact value lives in config/profile.

