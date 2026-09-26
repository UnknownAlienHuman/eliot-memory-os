-- The deny-closed WriteReceipt contract carries the stored CONTENT keys only;
-- the schemaless record `id` is excluded so the typed decode stays exact.
SELECT * OMIT id FROM ONLY type::record('write_receipt', $write_id);
