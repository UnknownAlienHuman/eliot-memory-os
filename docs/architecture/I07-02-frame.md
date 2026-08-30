## I7.2. Frame

Conceptual frame, represented by the selected encoding profile:

```yaml
Frame:
  protocol_version:
  encoding_profile:
  connection_id:
  request_id:
  kind: request | response | event | cancel | heartbeat | control
  message_type:
  payload:
  trace_context:
```

Framing uses a 4-byte little-endian unsigned body length followed by the encoded body. The parser reads the prefix into a fixed buffer, rejects zero/oversize values before allocation, then reads exactly that many bytes. `json-v1` body is UTF-8 JSON; other encoding profiles reuse the same frame boundary.

Hard limits:

```text
frame default max: 4 MiB;
hot response default max: 64 KiB;
hard MCP structured response: 256 KiB;
large payload: Blob/Resource handle;
per-connection in-flight requests bounded;
heartbeats, cancellation and recovery frames use reserved control capacity.
```

Unknown fields are tolerated only according to the negotiated protocol minor-version rule. Unknown message types are rejected explicitly; they are never interpreted as generic commands.

### Durable/control event envelope

Request/response correlation is insufficient for reconnect, hot replacement and native host streams. Every durable/control event uses:

```yaml
EventEnvelope:
  stream_id:
  producer_id:
  producer_generation:
  authority_epoch:
  event_id:
  sequence:
  causal_predecessor_refs:
  delivery_class: durable_control | durable_observation | best_effort_telemetry
  ack_required:
  payload_type:
  payload_or_blob_ref:
  state_fence:
  trace_context:
```

`durable_control` and `durable_observation` are delivered at least once. The receiver persists event ID, sequence and disposition; the producer replays unacknowledged events after reconnect. Duplicates are idempotent. Best-effort telemetry is a separate class and may be sampled or dropped only with an explicit telemetry-gap signal.

A generation switch cannot discard an unacknowledged durable stream. Host/native cursors advance only after the admissible raw/hash record, normalized projection and event disposition are durably related.

`EventAckReceipt` uses explicit phases:

```text
RECEIVED
→ DURABLE
→ NORMALIZED
→ APPLIED | REJECTED | UNKNOWN.
```

The producer and consumer declare which phase advances each cursor. A transport acknowledgement cannot impersonate durable or canonical application. Unknown/parse-failed events retain the event identity, raw/redacted source handle and retry/reconciliation route; replay never creates a second logical event.

