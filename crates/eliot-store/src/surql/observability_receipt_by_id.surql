-- The deny-closed ObservabilityWriteReceipt contract carries the stored CONTENT keys only;
-- the schemaless record `id` is excluded so the typed decode stays exact.
SELECT * OMIT id FROM ONLY type::record('observability_receipt', $write_id);
