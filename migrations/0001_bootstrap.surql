DEFINE TABLE IF NOT EXISTS health_record SCHEMAFULL;
DEFINE FIELD component ON health_record TYPE string;
DEFINE FIELD status ON health_record TYPE string;
DEFINE FIELD detail ON health_record TYPE string;

DEFINE TABLE IF NOT EXISTS migration_record SCHEMAFULL;
DEFINE FIELD migration_id ON migration_record TYPE string;
DEFINE FIELD checksum_blake3 ON migration_record TYPE string;
DEFINE FIELD applied ON migration_record TYPE bool;
