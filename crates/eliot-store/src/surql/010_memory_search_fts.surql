DEFINE ANALYZER IF NOT EXISTS eliot_memory_search_v1
  TOKENIZERS class
  FILTERS lowercase;

DEFINE INDEX IF NOT EXISTS idx_memory_search_projection_fts_v1
  ON TABLE memory_search_projection FIELDS search_document
  FULLTEXT ANALYZER eliot_memory_search_v1 BM25;

RETURN {
  projection_format: 'fts_v1',
  analyzer: 'eliot_memory_search_v1',
  index: 'idx_memory_search_projection_fts_v1',
};
