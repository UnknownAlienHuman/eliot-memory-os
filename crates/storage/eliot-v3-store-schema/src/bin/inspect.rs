#![allow(clippy::print_stdout)]

use eliot_v3_store_schema::{
    bundle_digest_hex, expected_catalog, metadata_bindings, query_corpus_digest_hex,
    validate_assets, MIGRATIONS, QUERIES,
};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    validate_assets()?;
    let metadata = metadata_bindings()?;
    println!("schema_bundle_format={}", metadata.schema_bundle_format);
    println!("schema_generation={}", metadata.schema_generation);
    println!("schema_bundle_sha256={}", bundle_digest_hex()?);
    println!("query_corpus_sha256={}", query_corpus_digest_hex()?);
    println!("migration_assets={}", MIGRATIONS.len());
    println!("fixed_queries={}", QUERIES.len());
    println!("expected_catalog_entries={}", expected_catalog()?.len());
    for query in QUERIES {
        println!(
            "query={} class={:?} max_input_bytes={} max_rows={} max_result_bytes={}",
            query.name,
            query.class,
            query.bounds.max_input_bytes,
            query.bounds.max_rows,
            query.bounds.max_result_bytes
        );
    }
    Ok(())
}
