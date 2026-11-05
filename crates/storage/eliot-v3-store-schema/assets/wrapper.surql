BEGIN TRANSACTION;
{{MIGRATION_ASSETS}}
DEFINE PARAM OVERWRITE $eliot_schema_bundle_format VALUE $bound_schema_bundle_format;
DEFINE PARAM OVERWRITE $eliot_schema_generation VALUE $bound_schema_generation;
DEFINE PARAM OVERWRITE $eliot_schema_bundle_sha256 VALUE $bound_schema_bundle_sha256;
COMMIT TRANSACTION;
