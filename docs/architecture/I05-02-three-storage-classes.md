## I5.2. Three storage classes

### Canonical Store

Contains:

```text
cognitive inheritance;
tasks and durable work;
claims/models/evidence/relations;
problems/conflicts/attention;
module/config/policy snapshots;
canonical events, revisions and receipts;
audit records.
```

### Operational Recovery State (`redb`)

Kernel-owned, non-semantic. ORS indexes only operational metadata and stores either an opaque serialized canonical envelope or an immutable encrypted/local payload locator; it never parses that payload as project meaning.

```text
operation/idempotency identity and Ordering Scope sequence;
opaque pending envelope bytes or payload locator + integrity digest;
Authority Epochs;
durable job checkpoint/cancellation metadata;
module/process generations, active Session bindings and active user-broker registrations/epochs;
recovery/problem/incident intents;
integrity anchors needed for Kernel recovery;
control state needed to reconcile after restart.
```

Rules:

```text
original privacy, visibility, taint and retention travel with the pending payload;
semantic fields are not indexed for recall, ranking or Current Epistemic Position;
model/Dreamer/agent queries never receive ORS payload directly;
reconciliation commits or rejects through the same canonical transition path;
resolved payload is deleted or archived under bounded recovery retention;
if ORS cannot durably stage the complete opaque operation, `accepted_pending` is forbidden.
```

ORS does not answer semantic queries and never becomes fallback memory.

Every opaque value is wrapped in a versioned `RecoveryPayloadEnvelope`:

```yaml
contract_version:
operation_or_checkpoint_id:
privacy_and_visibility_class:
key_id_and_ciphertext_or_immutable_locator:
payload_hash_and_length:
authority_epoch_and_state_fence:
created_at_and_expires_at:
```

The installation secret provider owns the key reference. `expires_at` is a cleanup horizon only after a terminal reconciliation/disposition; unresolved operations, unknown external effects and active checkpoints cannot expire automatically. Decryption failure, missing key or hash mismatch creates a Recovery Problem; plaintext fallback and silent deletion are forbidden.

### Blob Store

The store-neutral `BlobStore` contract has exactly one active data-root owner. The default early topology keeps it co-located behind the store/daemon contract; an independent `eliot-blob.exe` generation is a measured isolation/replacement option, not an automatic D2 obligation. During D1 the owner MAY be an explicitly declared internal backend in `eliot-store-surreal` or `eliotd` under the same contract, bounded resources and extractable on-disk format. An internal and process backend may never own the same root concurrently. The capability has no canonical semantic or DB authority and exposes only scoped stage/read/reachability/GC operations.

Content-addressed immutable storage for large payloads:

```text
raw tool outputs produced by governed task activity;
explicit document/source snapshots and Research Packs;
trace/log excerpts or bounded task diagnostics;
artifacts;
module packages;
export segments;
report attachments.
```

Blob Store is a payload substrate, not a corpus-ingestion pipeline. D0–D4 do not watch directories and dump documents, logs or media into ELIOT automatically. Bulk acquisition, parsing, indexing and RAG are governed by Researcher and executed only by admitted providers (I21); Blob Store never becomes the ingestion owner. Ordinary task execution may spool exact large tool output/log evidence when a canonical observation or trace references it. An unreferenced external corpus is not cognitive memory merely because its bytes exist in Blob Store.

