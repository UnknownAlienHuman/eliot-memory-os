USE NS eliot DB system;

BEGIN TRANSACTION;

UPSERT failure_fingerprint:cognitive_completion_v2_graph_health_schema_drift_20260729 CONTENT {
    project: "eliot-memory-os",
    task_class: "cognitive-field-certification-v2",
    failed_action_pattern: "Run the repository graph_health.surql against the live global Eliot system database after writeback.",
    trigger_pattern: "Post-write Eliot graph-health verification.",
    observed_failure: "The shipped query first failed because it selects relation table produced_by, then an otherwise equivalent retry failed because it selects invalidated_by. Neither table exists in the live schema; the live relation is produces. The shipped query would also later select scope_head, which is absent from the live table list. A bounded equivalent using the actual live tables passed in 1.356 ms with zero orphan, weak, contested, or duplicate-write findings.",
    why_it_failed: "The repository graph-health query and the global live Eliot schema have drifted in relation and revision-table naming.",
    violated_invariant: "A canonical post-write health query should execute against the canonical live memory schema without operator rewrites.",
    affected_files_or_entities: [
        "crates/eliot-store/src/surql/graph_health.surql",
        "global Eliot namespace eliot database system",
        "produced_by versus produces",
        "invalidated_by",
        "scope_head"
    ],
    required_discriminative_check: "Reconcile graph_health.surql with the authoritative live schema or version the health query per schema generation, then require the unmodified canonical query to pass.",
    reopen_conditions: [
        "The repository query or global schema is upgraded.",
        "A future writeback again requires an operator-adapted graph-health query."
    ],
    status: "open_tooling_schema_drift",
    created_at: d"2026-07-29T12:44:26Z",
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 7,
    tags: ["cognitive-completion-v2", "eliot", "graph-health", "schema-drift", "tooling"]
};

COMMIT TRANSACTION;
