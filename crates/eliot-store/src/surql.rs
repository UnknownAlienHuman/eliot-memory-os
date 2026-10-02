pub use crate::surql_templates::{SurqlTemplate, SurqlTemplateRegistry};

mod operation;
pub use operation::NamedSurqlOp;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SurqlAccessClass {
    Read,
    Write,
    Admin,
}

#[cfg(test)]
mod tests {
    use super::{NamedSurqlOp, SurqlAccessClass};
    use eliot_types::{
        ObservabilityKind, ObservabilityWriteReceipt, ObservabilityWriteStatus, ProjectId, TaskId,
        WriteId,
    };

    #[test]
    fn access_classes_cover_representative_operations() {
        assert_eq!(
            NamedSurqlOp::TaskContractById.access_class(),
            SurqlAccessClass::Read
        );
        assert_eq!(
            NamedSurqlOp::ApplyWriteEnvelope.access_class(),
            SurqlAccessClass::Write
        );
        assert_eq!(
            NamedSurqlOp::SchemaMigrateMemorySearch.access_class(),
            SurqlAccessClass::Admin
        );
        assert_eq!(
            NamedSurqlOp::LoadMemorySearchFtsCandidates.access_class(),
            SurqlAccessClass::Read
        );
        assert_eq!(
            NamedSurqlOp::ExplainMemorySearchFts.access_class(),
            SurqlAccessClass::Admin
        );
        assert_eq!(
            NamedSurqlOp::BlobReferenceScan.access_class(),
            SurqlAccessClass::Admin
        );
    }

    #[test]
    fn explicit_ul_assignment_is_idempotent_conflict_checked_and_counter_free() {
        let template = NamedSurqlOp::UpsertUlExperimentAssignmentExplicit.template();

        assert_eq!(
            NamedSurqlOp::UpsertUlExperimentAssignmentExplicit.access_class(),
            SurqlAccessClass::Write
        );
        assert!(template.contains("ordinal: 0"));
        assert!(template.contains("ul_explicit_assignment_conflict"));
        assert!(template.contains("$existing.task_class != $task_class"));
        assert!(template.contains("$existing.arm != $arm"));
        assert!(template.contains("$existing.injection_mode != $injection_mode"));
        assert!(template.contains("$existing.config_hash != $config_hash"));
        assert!(!template.contains("ul_ab_counter"));
        assert!(!template.contains("% 2"));
    }

    #[test]
    fn ordered_tool_observation_projection_contains_order_fields() {
        let template = NamedSurqlOp::ToolObservationsByKind.template();

        assert!(template.contains("memory_revision, project_sequence"));
        assert!(template.contains("ORDER BY memory_revision ASC, project_sequence ASC"));
    }

    #[test]
    fn experience_pattern_revision_lookup_is_exact_latest_first_and_bounded() {
        let template = NamedSurqlOp::ExperiencePatternRevisionsById.template();

        assert!(template.contains("project_id = $project_id"));
        assert!(template.contains("task_id = $task_id"));
        assert!(template.contains("payload.receipt_kind = 'experience_pattern'"));
        assert!(template.contains("payload.receipt_body.pattern_id = $pattern_id"));
        assert!(template.contains("ORDER BY memory_revision DESC, project_sequence DESC"));
        assert!(template.contains("LIMIT 2"));
    }

    #[test]
    fn l0_candidate_load_is_paged_multi_kind_and_does_not_rank() {
        let template = NamedSurqlOp::LoadRecallCandidates.template();

        assert!(template.contains("FROM claim_card"));
        assert!(template.contains("FROM evidence_atom"));
        assert!(template.contains("FROM verification_run"));
        assert!(template.contains("FROM tool_observation"));
        assert!(template.contains("FROM failure_fingerprint"));
        assert!(template.contains("FROM canonical_record"));
        assert!(template.contains("'module_card'"));
        assert!(template.contains("'subsystem_capsule'"));
        assert!(template.contains("'project_charter'"));
        assert!(template.contains("'system_map'"));
        assert!(template.contains("START $start LIMIT $page_limit_plus_one"));
        assert!(template.contains("array::slice($rows, 0, $limit)"));
        assert!(template.contains("$lifecycle_audit"));
        assert!(!template.contains("LIMIT 257"));
        assert!(!template.contains("LIMIT 129"));
        assert!(!template.contains("array::slice($all_candidates, 0, 512)"));
        assert!(!template.contains("string::words"));
        assert!(!template.contains("string::slug"));
        assert!(!template.contains("relevance_score"));
    }

    #[test]
    fn memory_search_fts_is_versioned_bounded_project_scoped_and_additive() {
        let schema = NamedSurqlOp::SchemaMigrateMemorySearchFts.template();
        assert!(schema.contains("DEFINE ANALYZER IF NOT EXISTS eliot_memory_search_v1"));
        assert!(schema.contains("TOKENIZERS class"));
        assert!(schema.contains("idx_memory_search_projection_fts_v1"));
        assert!(schema.contains("FIELDS search_document"));
        assert!(schema.contains("FULLTEXT ANALYZER eliot_memory_search_v1 BM25"));
        assert!(schema.contains("projection_format: 'fts_v1'"));
        assert!(!schema.contains("OVERWRITE"));
        assert!(!schema.contains("REMOVE"));
        assert!(!schema.contains("memory_search_token"));

        let load = NamedSurqlOp::LoadMemorySearchFtsCandidates.template();
        for binding in [
            "$project_id",
            "$exact_handle_parts",
            "$query_text",
            "$candidate_limit",
        ] {
            assert!(load.contains(binding), "missing FTS binding {binding}");
        }
        assert!(load.contains("search_document @0,OR@ $query_text"));
        assert!(load.contains("math::max(search::score(0)) AS relevance_score"));
        assert!(load.contains("GROUP BY handle"));
        assert!(load.contains("$capped_handles.map"));
        assert!(load.contains("array::flatten($rows_nested)"));
        assert!(!load.contains("array::flatten([$rows_nested])"));
        assert!(load.contains("ORDER BY relevance_score DESC, authority_rank DESC, handle ASC"));
        assert_eq!(load.matches("search::score").count(), 2);
        assert!(load.contains("search::score(0) AS segment_relevance_score"));
        assert!(load.contains("OR search_document @0,OR@ $query_text"));
        assert!(load.contains("segment_relevance_score DESC"));
        let Some((_, return_shape)) = load.rsplit_once("RETURN {") else {
            panic!("FTS loader must expose one typed return object");
        };
        assert!(!return_shape.contains("relevance_score"));
        assert!(load.contains("project_id = $project_id"));
        assert!(load.contains("$candidate_limit > 256"));
        assert!(load.contains("$bounded_candidate_limit + 1"));
        assert!(load.contains("LIMIT $candidate_limit_plus_one"));
        assert!(load.contains("array::slice($ordered_handles, 0, $bounded_candidate_limit)"));
        assert!(load.contains("array::len($exact_handles) > 0"));
        assert!(load.contains("projection_format"));
        assert!(load.contains("$family_state[0].status = 'published'"));
        assert!(load.contains("$family_state[0].target_revision = $head.memory_revision"));
        assert!(load.contains("$family_state[0].applied_revision = $head.memory_revision"));
        assert!(load.contains("IF $projection_ready AND $exact_handle != ''"));
        assert!(load.contains("IF !$projection_ready"));
        assert!(!load.contains("memory_search_token"));
        assert!(!load.contains("ambient"));

        let explain = NamedSurqlOp::ExplainMemorySearchFts.template();
        assert!(explain.contains("search_document @0,OR@ $query_text"));
        assert!(explain.contains("math::max(search::score(0)) AS relevance_score"));
        assert!(explain.contains("GROUP BY handle"));
        assert!(explain.contains("ORDER BY relevance_score DESC, authority_rank DESC, handle ASC"));
        assert!(explain.contains("project_id = $project_id"));
        assert!(explain.contains("LIMIT $candidate_limit_plus_one"));
        assert!(explain.contains("EXPLAIN FULL"));
        assert!(!explain.contains("memory_search_token"));
    }

    #[test]
    fn memory_search_projection_format_advances_only_when_explicitly_supplied() {
        let upsert = NamedSurqlOp::UpsertMemorySearchProjection.template();

        assert!(upsert.contains("$projection_format == NONE"));
        assert!(upsert.contains("$projection_format == NULL"));
        assert!(upsert.contains("projection_format: $projection_format"));
        assert!(upsert.contains("UPSERT $state_id MERGE"));
        assert!(!upsert.contains("memory_search_outbox"));
        assert!(!upsert.contains("memory_search_token"));
    }

    #[test]
    fn canonical_write_and_projection_intent_are_one_failure_atomic_transaction() {
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        let Some(transaction) = write.find("BEGIN TRANSACTION;") else {
            panic!("canonical write transaction start is missing");
        };
        let Some(canonical) = write.find("UPSERT type::record('memory_transition'") else {
            panic!("canonical memory transition is missing");
        };
        let Some(failure) = write.find("IF $fail_before_projection_outbox") else {
            panic!("canonical transaction failure injection is missing");
        };
        let Some(outbox) = write.find("UPSERT type::record('memory_search_outbox'") else {
            panic!("cognitive projection outbox write is missing");
        };
        let Some(commit) = write.rfind("COMMIT TRANSACTION;") else {
            panic!("canonical write transaction commit is missing");
        };

        assert!(transaction < canonical);
        assert!(canonical < failure && failure < outbox);
        assert!(outbox < commit);
        assert!(write.contains("families: ['search', 'cue', 'dependency_dirty']"));
        assert!(write.contains("write_id: <string> $envelope.write_id"));
        assert!(!write.contains("'utility']"));
    }

    #[test]
    fn cognitive_projection_claim_is_reclaimable_and_never_crosses_an_older_project_barrier() {
        let claim = NamedSurqlOp::ClaimCognitiveProjectionProject.template();

        assert!(claim.contains("LIMIT 1"));
        assert!(claim.contains("lease_expires_at <= <datetime> $now"));
        assert!(claim.contains("lease_expires_at > <datetime> $now"));
        assert!(claim.contains("AND array::len(("));
        assert!(claim.contains("AND status != 'applied'"));
        assert!(claim.contains("updated_revision < $parent.updated_revision"));
        assert!(claim.contains("created_at < $parent.created_at"));
        assert!(claim.contains("<string> write_id < <string> $parent.write_id"));
        assert!(claim.contains("LET $leased = UPDATE $candidate"));
        assert!(claim.contains("lease_id = $lease_id"));
        assert!(claim.contains("attempt_count = (attempt_count ?? 0) + 1"));
        assert!(claim.contains("write_id: <string> $row.write_id"));

        let enqueue = NamedSurqlOp::EnqueueCognitiveProjectionIntent.template();
        assert!(enqueue.contains("LET $event_id = <string> array::join("));
        assert!(enqueue.contains("$event_id_parts.map(|$fragment| <string> $fragment)"));

        for op in [
            NamedSurqlOp::CompleteCognitiveProjectionThrough,
            NamedSurqlOp::FailCognitiveProjectionRetryable,
            NamedSurqlOp::BlockCognitiveProjection,
        ] {
            let template = op.template();
            assert!(template.contains("LET $owned = SELECT *"));
            assert!(template.contains("lease_id = $lease_id"));
            assert!(template.contains("lease_owner = $lease_owner"));
            assert!(template.contains("<string> $row.write_id IN $bound_write_ids"));
            assert!(template.contains("lease_expires_at > <datetime> $now"));
            assert!(template.contains("LET $owned_rows = $owned ?? []"));
            assert!(template.contains("LET $write_ids = ($write_id_parts ?? []).map(|$parts|"));
            assert!(template.contains("$parts.map(|$fragment| <string> $fragment)"));
            assert!(template.contains(
                "LET $bound_write_ids = ($write_ids ?? []).map(|$write_id| <string> $write_id)"
            ));
            assert!(
                template.contains(
                    "LET $owned_revisions = $owned_rows.map(|$row| $row.updated_revision)"
                )
            );
            assert!(template.contains("math::max($owned_revisions) != $through_revision"));
            assert!(template.contains("$owned_rows.map(|$row| $row.families ?? [])"));
            assert!(template.contains("!($family IN $bound_families)"));
            assert!(template.contains("!($family IN $owned_families)"));
            assert!(template.contains("cognitive_projection_lease_mismatch:owned_count"));
            assert!(template.contains("cognitive_projection_lease_mismatch:row_set"));
            assert!(template.contains("cognitive_projection_lease_mismatch:through_revision"));
            assert!(template.contains("cognitive_projection_lease_mismatch:family_set"));
            assert!(template.contains("THROW $lease_mismatch"));
        }
    }

    #[test]
    fn projection_family_state_is_per_family_revision_fenced_and_utility_can_be_unavailable() {
        let schema = NamedSurqlOp::SchemaMigrateMemorySearch.template();
        let publish = NamedSurqlOp::PublishCognitiveProjectionFamilyState.template();
        let enqueue = NamedSurqlOp::EnqueueCognitiveProjectionIntent.template();
        let complete = NamedSurqlOp::CompleteCognitiveProjectionThrough.template();
        let fail = NamedSurqlOp::FailCognitiveProjectionRetryable.template();
        let block = NamedSurqlOp::BlockCognitiveProjection.template();

        assert!(schema.contains("cognitive_projection_state"));
        assert!(schema.contains("project_id, family UNIQUE"));
        assert!(publish.contains("$target_revision > $existing.target_revision"));
        assert!(publish.contains("$incoming_applied >= $existing_applied"));
        assert!(publish.contains("$effective_status = 'published'"));
        assert!(publish.contains("string::starts_with(<string> write_id, 'dependency-dirty:')"));
        assert!(publish.contains("family: $family"));
        assert!(publish.contains("last_error: $effective_error"));
        assert!(enqueue.contains("IF $mark_dependency_dirty_stale"));
        assert!(enqueue.contains("family: 'dependency_dirty'"));
        assert!(enqueue.contains("'stale'"));
        assert!(complete.contains("LET $remaining = SELECT status, updated_revision"));
        assert!(complete.contains("status: 'published'"));
        assert!(fail.contains("$state.status = 'blocked'"));
        assert!(fail.contains("$state.last_error"));
        assert!(block.contains("status: 'blocked'"));
    }

    #[test]
    fn projection_inventory_is_paged_and_legacy_postings_have_one_explicit_admin_cutover() {
        let backlog = NamedSurqlOp::LoadCognitiveProjectionBacklog.template();
        let inventory = NamedSurqlOp::LoadCognitiveProjectionProjects.template();
        let cutover = NamedSurqlOp::CutoverLegacyMemorySearchPostings.template();

        assert_eq!(backlog.matches("count(id) AS count").count(), 8);
        assert!(!backlog.contains("count() AS count"));
        assert!(inventory.contains("$limit > 100"));
        assert!(inventory.contains("START $start"));
        assert!(inventory.contains("LIMIT $bounded_limit + 1"));
        assert!(inventory.contains("search_applied_revision"));
        assert!(inventory.contains("search_projection_format"));
        assert!(inventory.contains("status = 'pending'"));
        assert!(inventory.contains("status = 'leased'"));
        assert!(inventory.contains("status = 'retryable'"));
        assert!(inventory.contains("status = 'blocked'"));
        assert!(inventory.contains("oldest_pending_created_at"));
        assert_eq!(inventory.matches("count(id) AS count").count(), 4);
        assert!(!inventory.contains("count() AS count"));
        assert_eq!(
            inventory.matches("project_id = $parent.project_id").count(),
            5
        );
        assert!(cutover.contains("projection_format != 'fts_v1'"));
        assert!(cutover.contains("applied_revision != $head.memory_revision"));
        assert!(cutover.contains("REMOVE TABLE IF EXISTS memory_search_token"));
        assert_eq!(
            NamedSurqlOp::CutoverLegacyMemorySearchPostings.access_class(),
            SurqlAccessClass::Admin
        );

        for op in [
            NamedSurqlOp::SchemaMigrateMemorySearch,
            NamedSurqlOp::UpsertMemorySearchProjection,
            NamedSurqlOp::ResetMemorySearchProjection,
            NamedSurqlOp::LoadMemorySearchFtsCandidates,
            NamedSurqlOp::ExplainMemorySearchFts,
        ] {
            assert!(!op.template().contains("memory_search_token"));
        }
    }

    #[test]
    fn cold_projection_resets_are_project_scoped_and_generic_migration_is_non_destructive() {
        for op in [
            NamedSurqlOp::ResetUlReverseDependencyProject,
            NamedSurqlOp::ResetUlArtifactDirtyProject,
        ] {
            let template = op.template();
            assert!(template.contains("WHERE project_id = $project_id"));
            assert!(template.contains("BEGIN TRANSACTION;"));
            assert_eq!(op.access_class(), SurqlAccessClass::Write);
        }
        let cues = NamedSurqlOp::UpsertCueRows.template();
        assert!(cues.contains("IF $replace_project"));
        assert!(cues.contains("DELETE cue_index"));
        assert!(
            !NamedSurqlOp::SchemaMigrateUlArtifacts
                .template()
                .contains("DELETE cue_index")
        );
    }

    #[test]
    fn current_state_resolves_canonical_lifecycle_transitions_with_bounded_reads() {
        let template = NamedSurqlOp::CurrentState.template();

        assert!(template.contains("receipt_kind = 'state_transition'"));
        assert!(template.contains("receipt_body.to_state"));
        assert!(template.contains("LET $resolved = $claims.map"));
        assert!(template.contains("LIMIT 251"));
        assert!(template.contains("array::slice($weak, 0, 50)"));
        assert!(template.contains("lifecycle_state IN ['active', 'restored']"));
        assert!(template.contains("array::len($claims) > 250"));
    }

    #[test]
    fn canonical_queries_are_bounded_and_project_scoped() {
        for op in [
            NamedSurqlOp::CanonicalRecords,
            NamedSurqlOp::CanonicalRecordsBySubjectRef,
            NamedSurqlOp::SleepCandidates,
        ] {
            let template = op.template();
            assert!(template.contains("project_id = $project_id"));
            assert!(template.contains("$limit > 128"));
        }
        let readiness = NamedSurqlOp::LoadUlReadiness.template();
        assert_eq!(readiness.matches("project_id = $project_id").count(), 5);
        for table in [
            "co_change",
            "card_covers",
            "concept_implemented_by",
            "concept_depends_on",
            "capsule_covers",
        ] {
            assert!(readiness.contains(&format!("FROM {table}")));
        }
        assert!(!readiness.contains("type::table"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonical_capacity_is_parent_last_paged_and_segment_deduplicated() {
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        for marker in [
            "'memory_blob_segment'",
            "'cue_binding_page'",
            "'memory_blob_manifest'",
            "canonical_capacity_parent_before_complete_segments",
            "canonical_capacity_parent_before_complete_cue_pages",
            "canonical_capacity_immutable_record_conflict",
        ] {
            assert!(write.contains(marker), "missing capacity marker {marker}");
        }
        for exact_child_binding in [
            "receipt_body.logical_kind = $body.logical_kind",
            "receipt_body.segment_count = $body.segment_count",
            "receipt_body.segment_set_hash_blake3 = $body.segment_set_hash_blake3",
            "receipt_body.blob.algorithm = $body.blob.algorithm",
            "receipt_body.blob.digest_hex = $body.blob.digest_hex",
            "receipt_body.blob.size_bytes = $body.blob.size_bytes",
            "receipt_body.blob.relative_path = $body.blob.relative_path",
            "receipt_body.page_count = $body.cue_page_count",
            "receipt_body.page_set_hash_blake3 = $body.cue_page_set_hash_blake3",
        ] {
            assert!(
                write.contains(exact_child_binding),
                "parent admission omitted exact child binding {exact_child_binding}"
            );
        }
        let l2 = NamedSurqlOp::LoadCanonicalMemoryL2.template();
        for marker in [
            "project_id = $project_id",
            "requested_segment_record_id_parts",
            "type::record('canonical_record', $requested_segment_record_id)",
            "subject_ref = $requested_handle",
            "SELECT VALUE receipt_body_json_b64",
            "$requested_is_segment",
            "requested_segment_body_b64",
            "manifest_bodies_b64",
            "ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC",
            "START $start",
            "LIMIT $limit_plus_one",
            "$limit > 1",
            "canonical_l2_segment_body_not_lossless",
            "canonical_l2_manifest_body_not_lossless",
        ] {
            assert!(l2.contains(marker), "normal L2 loader omitted {marker}");
        }
        assert!(!l2.contains("receipt_body."));
        assert!(!l2.contains("search_text"));
        let admission = NamedSurqlOp::LoadCanonicalMemoryAdmissionChildren.template();
        for marker in [
            "$child_kind = 'segment'",
            "$child_kind != 'cue_page'",
            "project_id = $project_id",
            "subject_ref = <string> $memory_handle",
            "SELECT VALUE receipt_body_json_b64",
            "START $start",
            "LIMIT $limit_plus_one",
        ] {
            assert!(
                admission.contains(marker),
                "admission child loader omitted {marker}"
            );
        }
        for forbidden_prefilter in [
            "segment_set_hash_blake3 =",
            "page_set_hash_blake3 =",
            "blob.digest_hex =",
            "segment_count =",
            "page_count =",
            "receipt_body.parent_handle =",
        ] {
            assert!(
                !admission.contains(forbidden_prefilter),
                "admission loader must not hide mismatched children behind {forbidden_prefilter}"
            );
        }
        assert!(admission.contains("canonical_capacity_unknown_child_kind"));
        assert!(admission.contains("canonical_capacity_child_body_not_lossless"));
        assert!(admission.contains("ORDER BY record_id ASC"));
        assert!(!admission.contains("ORDER BY receipt_body"));
        assert!(admission.contains("$limit > 1"));
        assert!(!admission.contains(".filter(|$row| $row != NONE AND $row != NULL)"));
        let capacity_projection = NamedSurqlOp::LoadCanonicalMemoryProjectionSegments.template();
        assert!(capacity_projection.contains("receipt_kind = 'memory_blob_segment'"));
        assert!(capacity_projection.contains("receipt_body.blob.digest_hex = $blob_digest_hex"));
        assert!(
            capacity_projection
                .contains("receipt_body.segment_set_hash_blake3 = $segment_set_hash_blake3")
        );
        assert!(capacity_projection.contains("ORDER BY receipt_body.ordinal ASC"));
        assert!(capacity_projection.contains("START $start"));

        let rebuild = NamedSurqlOp::LoadRecallCandidates.template();
        assert!(rebuild.contains("receipt_kind = 'memory_blob_manifest'"));
        assert!(rebuild.contains("subject_ref = $parent.subject_ref"));
        assert!(rebuild.contains("source_segment_ordinal"));

        let projection = NamedSurqlOp::UpsertMemorySearchProjection.template();
        assert!(projection.contains("source_segment_ordinal"));
        assert!(projection.contains("fts_segment_ordinal"));
        assert!(projection.contains("source_segment_ordinal ?? 0"));
        let load = NamedSurqlOp::LoadMemorySearchFtsCandidates.template();
        assert!(load.contains("GROUP BY handle"));
        assert!(load.contains("$capped_handles.map"));
        assert!(load.contains("array::flatten($rows_nested)"));
    }

    #[test]
    fn ul_artifact_projection_selects_latest_logical_targets_before_pagination() {
        let template = NamedSurqlOp::LoadUlArtifacts.template();
        let latest = template.find("AND record_id = array::first");
        let pagination = template.find("START $bounded_start");
        assert!(latest.is_some(), "latest-per-target predicate");
        assert!(pagination.is_some(), "stable pagination");
        assert!(latest < pagination);
        assert!(template.contains("subject_ref = $parent.subject_ref"));
        assert!(template.contains("receipt_kind = $parent.receipt_kind"));
        assert!(
            template
                .contains("ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC")
        );
        assert!(template.contains("$limit > 256"));
        assert!(!template.contains("$limit > 128"));
    }

    #[test]
    fn canonical_operator_page_has_stable_unbounded_continuation_order() {
        let template = NamedSurqlOp::CanonicalRecordPage.template();
        assert!(template.contains("project_id = $project_id"));
        assert!(
            template.contains("array::len($receipt_kinds) = 0"),
            "an empty kind filter must provide a project-wide canonical scan"
        );
        assert!(
            template.contains("memory_revision <= $at_revision"),
            "canonical scans must support a stable revision fence"
        );
        assert!(
            template.contains("ORDER BY memory_revision ASC, project_sequence ASC, record_id ASC")
        );
        assert!(template.contains("START $start"));
        assert!(template.contains("$limit > 100"));
        assert!(!template.contains("START 0"));
    }

    #[test]
    fn curation_page_is_task_revision_fenced_and_bounded() {
        let template = NamedSurqlOp::CurationRecordPage.template();
        assert!(template.contains("FROM claim_card"));
        assert!(template.contains("<string> project_id = <string> $project_id"));
        assert!(template.contains("<string> task_id = <string> $task_id"));
        assert!(template.contains("memory_revision <= $at_revision"));
        assert!(template.contains("subject_ref: string::concat('claim:'"));
        assert!(template.contains("lifecycle_transitions: SELECT VALUE receipt_body.to_state"));
        assert!(template.contains("$parent.claim_id"));
        assert!(
            template.contains("ORDER BY memory_revision ASC, project_sequence ASC, claim_id ASC")
        );
        assert!(template.contains("START $start"));
        assert!(template.contains("$limit > 100"));
    }

    #[test]
    fn canonical_authority_queries_are_exact_and_bounded() {
        let latest_entity = NamedSurqlOp::LatestAuthorityObservationsByEntity.template();
        assert!(latest_entity.contains("payload.work_lease.work_lease_id = $entity_ref"));
        assert!(latest_entity.contains("payload.worktree_lease.worktree_lease_id = $entity_ref"));
        assert!(latest_entity.contains("ORDER BY memory_revision DESC"));
        assert!(latest_entity.contains("LIMIT 2"));
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        for approval_kind in [
            "autonomy_approval_request",
            "autonomy_approval_decision",
            "autonomy_approval_consumption",
        ] {
            assert!(write.contains(approval_kind));
        }
        let by_write = NamedSurqlOp::CanonicalRecordByWriteId.template();
        assert!(by_write.contains("write_id = $write_id"));
        assert!(by_write.contains("LIMIT 2"));
        let by_subject = NamedSurqlOp::CanonicalRecordsBySubjectRef.template();
        assert!(by_subject.contains("subject_ref = <string> $subject_ref"));
        assert!(by_subject.contains("ORDER BY memory_revision DESC"));
        let terminal = NamedSurqlOp::MetaPolicyActionsByCandidate.template();
        assert!(terminal.contains("candidate_id = <string> $candidate_id"));
        assert!(terminal.contains("canonical_action = <string> $action"));
        assert!(terminal.contains("LIMIT 2"));
        let trace = NamedSurqlOp::CanonicalTraceByTraceRef.template();
        assert!(trace.contains("trace_ref = <string> $trace_ref"));
        assert!(trace.contains("receipt_body.trace_ref = <string> $trace_ref"));
        assert!(trace.contains("LIMIT 2"));
        let schema = NamedSurqlOp::SchemaMigrate.template();
        assert!(schema.contains("SET trace_ref = <string> receipt_body.trace_ref"));
        assert!(schema.contains("candidate_id = <string> receipt_body.candidate_id"));
        assert!(schema.contains("canonical_action = <string> receipt_body.action"));
        assert!(schema.contains("idx_canonical_project_task_trace"));
        assert!(schema.contains("idx_canonical_project_task_candidate_action"));
    }

    #[test]
    fn canonical_projection_preserves_opaque_json_and_exact_subject_filters() {
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        let read = NamedSurqlOp::CanonicalRecords.template();

        assert!(write.contains("receipt_body_json_b64"));
        assert!(write.contains("trace_ref: $trace_ref"));
        assert!(write.contains("candidate_id: $candidate_id"));
        assert!(write.contains("canonical_action: $canonical_action"));
        assert!(write.contains("subject_ref_fragments"));
        assert!(write.contains("'operator_control_request'"));
        assert!(read.contains("receipt_body_json_b64"));
        assert!(read.contains("subject_ref = <string> $subject_ref_filter"));
        assert!(
            NamedSurqlOp::SleepCandidates
                .template()
                .contains("receipt_body_json_b64")
        );
    }

    #[test]
    fn sleep_candidates_are_backed_by_canonical_records() {
        let template = NamedSurqlOp::SleepCandidates.template();
        assert!(template.contains("FROM canonical_record"));
        assert!(!template.contains("candidates: []"));
        for kind in [
            "procedure_candidate",
            "forgetting_candidate",
            "test_candidate",
            "replay_case_candidate",
            "dream_candidate",
        ] {
            assert!(template.contains(kind));
        }
    }

    #[test]
    fn m2_integrity_records_are_canonical_write_kinds() {
        let template = NamedSurqlOp::ApplyWriteEnvelope.template();
        for kind in [
            "trace_completeness_contract",
            "replay_set",
            "replay_case",
            "replay_input_snapshot",
            "sealed_replay_run",
            "meta_metric_evidence",
            "meta_isolation_rejection",
            "experimental_policy_candidate",
            "meta_policy_promotion",
            "meta_policy_rollback",
            "procedure_candidate",
            "forgetting_candidate",
            "test_candidate",
            "replay_case_candidate",
            "dream_candidate",
        ] {
            assert!(template.contains(&format!("'{kind}'")));
        }
    }

    #[test]
    fn m3_invocation_request_is_exact_canonical_authority() {
        assert!(
            NamedSurqlOp::ApplyWriteEnvelope
                .template()
                .contains("'agent_invocation_request'")
        );
        let current = NamedSurqlOp::LatestAuthorityObservationsByEntity.template();
        assert!(current.contains("$entity_kind = 'agent_invocation_request'"));
        assert!(current.contains("payload.receipt_kind = 'agent_invocation_request'"));
    }

    #[test]
    fn exact_claim_lookup_is_project_scoped_and_unpaginated() {
        let template = NamedSurqlOp::ClaimCardById.template();

        assert!(template.contains("type::record('claim_card', $claim_id)"));
        assert!(template.contains("project_id = $project_id"));
        assert!(template.contains("LIMIT 1"));
    }

    // WORK_UNIT_CASE: 2990/1
    #[test]
    fn observability_receipt_contours_return_stored_content_without_record_metadata() {
        let write_template = NamedSurqlOp::ApplyObservability.template();
        let readback_template = NamedSurqlOp::ObservabilityReceiptById.template();
        let fresh_projection =
            "SELECT * OMIT id FROM ONLY type::record('observability_receipt', $receipt_id)";
        let readback_projection =
            "SELECT * OMIT id FROM ONLY type::record('observability_receipt', $write_id);";

        // Both receipt-returning templates carry exactly one `OMIT id` contour.
        // Pinning the count pins the projection shape: any second receipt
        // contour, or a second `OMIT id` clause, fails here.
        assert_eq!(
            write_template.matches(fresh_projection).count(),
            1,
            "apply_observability must project the fresh receipt exactly once"
        );
        assert_eq!(
            write_template.matches("SELECT * OMIT id").count(),
            1,
            "apply_observability must carry a single OMIT id clause"
        );
        assert_eq!(
            readback_template.matches(readback_projection).count(),
            1,
            "observability_receipt_by_id must project the receipt exactly once"
        );
        assert_eq!(
            readback_template.matches("SELECT * OMIT id").count(),
            1,
            "observability_receipt_by_id must carry a single OMIT id clause"
        );
        assert_eq!(
            readback_template.matches("SELECT").count(),
            1,
            "observability_receipt_by_id must stay a single-statement projection"
        );

        // The projection carries its documented reason inline, so the contour and
        // the reason it exists cannot drift apart silently.
        assert!(
            write_template
                .contains("-- OMIT id: ObservabilityWriteReceipt decodes the CONTENT keys"),
            "the fresh-commit projection must keep its documented OMIT id reason"
        );
        assert!(
            readback_template.contains(
                "The deny-closed ObservabilityWriteReceipt contract carries the stored CONTENT keys only"
            ),
            "the readback projection must keep its documented OMIT id reason"
        );
    }

    // WORK_UNIT_CASE: 2990/2
    #[test]
    fn observability_receipt_pre_reads_never_become_the_returned_value() {
        let write_template = NamedSurqlOp::ApplyObservability.template();
        let fresh_projection =
            "SELECT * OMIT id FROM ONLY type::record('observability_receipt', $receipt_id)";

        // Two bare `SELECT *` reads remain and both are control-flow pre-reads:
        // each binds to its own `LET`, feeds only an existence/conflict decision
        // and never becomes the returned value. The guard pins those two bindings
        // exactly instead of forbidding the `SELECT *` substring, because the
        // honest claim is about which contour is returned to Rust, not about a
        // substring that legitimately exists inside this template.
        let receipt_pre_read =
            "SELECT * FROM ONLY type::record('observability_receipt', $receipt_id);";
        assert_eq!(
            write_template
                .matches("SELECT * FROM ONLY type::record(")
                .count(),
            2,
            "only the two internal pre-reads may use a bare receipt SELECT"
        );
        assert_eq!(
            write_template.matches(receipt_pre_read).count(),
            1,
            "the receipt pre-read contour must appear exactly once"
        );
        let Some(pre_read_at) = write_template.find(receipt_pre_read) else {
            panic!("the receipt pre-read contour must be present");
        };
        assert!(
            write_template[..pre_read_at]
                .trim_end()
                .ends_with("LET $existing_receipt ="),
            "the bare receipt SELECT must stay bound to the $existing_receipt decision variable"
        );
        // Every other use of the pre-read record is a single field or the
        // existence test. A whole-record use would carry the synthetic `id`
        // straight into the returned value, which is the drift this guard exists
        // to stop, so the non-field uses are counted and pinned.
        let pre_read_uses = write_template.matches("$existing_receipt").count();
        let pre_read_field_uses = write_template.matches("$existing_receipt.").count();
        assert_eq!(
            pre_read_uses - pre_read_field_uses,
            2,
            "the pre-read record must be used only by its LET binding and its existence test"
        );
        let immutable_pre_read =
            "SELECT * FROM ONLY type::record($target_table, $envelope.record_id)";
        let Some(immutable_at) = write_template.find(immutable_pre_read) else {
            panic!("the immutable-target pre-read contour must be present");
        };
        let immutable_let =
            "LET $existing_immutable_record = IF $envelope.kind = 'memory_grant_offer' {";
        assert!(
            write_template[..immutable_at]
                .trim_end()
                .ends_with(immutable_let),
            "the bare immutable-target SELECT must stay bound to $existing_immutable_record"
        );

        // The fresh-commit arm's value is exactly the `OMIT id` projection and
        // nothing else is composed onto it, and the transaction returns that arm
        // as its last statement.
        let Some(projection_at) = write_template.find(fresh_projection) else {
            panic!("the fresh-commit receipt projection must be present");
        };
        let Some(commit_at) = write_template.find("COMMIT TRANSACTION;") else {
            panic!("the apply_observability transaction must commit");
        };
        assert_eq!(
            write_template[projection_at + fresh_projection.len()..commit_at].trim(),
            "};",
            "the fresh-commit arm must be exactly the OMIT id projection"
        );
        assert_eq!(
            write_template.matches("RETURN $result;").count(),
            1,
            "apply_observability must return exactly one value"
        );
        assert!(
            write_template
                .trim_end()
                .ends_with("COMMIT TRANSACTION;\nRETURN $result;"),
            "the returned value must be the last statement after the commit"
        );
    }

    // WORK_UNIT_CASE: 2990/3
    #[test]
    fn observability_receipt_projection_and_dto_carry_one_closed_field_set() {
        let write_template = NamedSurqlOp::ApplyObservability.template();
        let probe_id = uuid::Uuid::nil();
        // Deliberately exhaustive probe literal: adding, removing or renaming a
        // field on the closed DTO breaks this literal at compile time, inside the
        // guard itself, so the wire contract cannot drift away from the query
        // without the guard failing. The field names are taken from the type
        // through serde rather than restated as a second hand-written list.
        let probe = ObservabilityWriteReceipt {
            write_id: WriteId::from_uuid(probe_id),
            record_id: "record:parity-probe".to_owned(),
            project_id: ProjectId::from_uuid(probe_id),
            task_id: Some(TaskId::from_uuid(probe_id)),
            kind: ObservabilityKind::ActivationTrace,
            input_hash: "input-hash".to_owned(),
            status: ObservabilityWriteStatus::Committed,
            rejected_reason: Some("parity-probe".to_owned()),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let Ok(serde_json::Value::Object(dto_fields)) = serde_json::to_value(&probe) else {
            panic!("ObservabilityWriteReceipt must serialize as a JSON object");
        };
        let mut dto_keys: Vec<String> = dto_fields.keys().cloned().collect();
        dto_keys.sort();

        // The query side is derived from the bytes production embeds: the stored
        // CONTENT of the receipt record, which is exactly what `SELECT * OMIT id`
        // returns once the synthetic record `id` is removed.
        let content_anchor = "UPSERT type::record('observability_receipt', $receipt_id) CONTENT {";
        assert_eq!(
            write_template.matches(content_anchor).count(),
            1,
            "the receipt CONTENT upsert must appear exactly once"
        );
        let Some(content_body) = group_body_after(write_template, content_anchor) else {
            panic!("the receipt CONTENT body must be brace-balanced");
        };
        let Some(mut stored_keys) = flat_object_keys(content_body) else {
            panic!("the receipt CONTENT must be a flat object literal");
        };
        stored_keys.sort();

        assert_eq!(
            stored_keys, dto_keys,
            "stored receipt CONTENT keys must equal the closed ObservabilityWriteReceipt wire fields"
        );
        assert!(
            !stored_keys.iter().any(|key| key.as_str() == "id"),
            "OMIT id must drop the synthetic record id, never a stored receipt field"
        );

        // Every result branch carries that same set: the three explicit branch
        // literals plus the stored CONTENT the projection reads back. A branch
        // that quietly adds or omits a field changes this count and fails.
        let mut branch_literals = flat_object_keys_in(write_template);
        for literal in &mut branch_literals {
            literal.sort();
        }
        let matching_branches = branch_literals
            .iter()
            .filter(|literal| *literal == &stored_keys)
            .count();
        assert_eq!(
            matching_branches, 4,
            "replay, changed-input conflict, immutable-record conflict and stored CONTENT must all carry the DTO field set"
        );
    }

    // Bounded SurrealQL reader used only by the receipt field-set guard above.
    //
    // It reads exactly the bytes `NamedSurqlOp::template` embeds through
    // `include_str!`, so the guard and production share one text source. It is
    // not a general SurrealQL parser: it assumes no brace inside a string
    // literal, which holds for the receipt templates it is pointed at, and it
    // refuses to guess rather than approximating when a shape is ambiguous.
    fn matching_brace(template: &str, open_at: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (offset, byte) in template.as_bytes()[open_at..].iter().enumerate() {
            match *byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open_at + offset);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Inner body of the `{...}` group whose opening brace ends `anchor`.
    fn group_body_after<'a>(template: &'a str, anchor: &str) -> Option<&'a str> {
        let open_at = template.find(anchor)? + anchor.len() - 1;
        let close_at = matching_brace(template, open_at)?;
        Some(&template[open_at + 1..close_at])
    }

    /// Keys of a flat SurrealQL object literal, or `None` when it is not one.
    ///
    /// A flat literal is a brace group whose top-level comma-separated entries
    /// all read `<identifier>:`. A nested group, an `IF`/`ELSE` arm or a closure
    /// body therefore reads as "not a flat literal" instead of being parsed into
    /// an invented shape.
    fn flat_object_keys(body: &str) -> Option<Vec<String>> {
        let code = body
            .lines()
            .map(|line| line.split_once("--").map_or(line, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n");
        let mut depth = 0usize;
        let mut entries: Vec<String> = Vec::new();
        let mut entry = String::new();
        for character in code.chars() {
            match character {
                '{' | '(' | '[' => {
                    depth += 1;
                    entry.push(character);
                }
                ')' | ']' | '}' => {
                    depth = depth.saturating_sub(1);
                    entry.push(character);
                }
                ',' if depth == 0 => entries.push(std::mem::take(&mut entry)),
                _ => entry.push(character),
            }
        }
        entries.push(entry);
        entries.retain(|entry| !entry.trim().is_empty());
        if entries.is_empty() {
            return None;
        }
        entries
            .iter()
            .map(|entry| {
                let (candidate, _value) = entry.split_once(':')?;
                let candidate = candidate.trim();
                let named = !candidate.is_empty()
                    && candidate
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_');
                named.then(|| candidate.to_owned())
            })
            .collect()
    }

    /// Sorted-pending key lists of every flat object literal in `template`, in
    /// template order. Nested literals are reported alongside their parent.
    fn flat_object_keys_in(template: &str) -> Vec<Vec<String>> {
        template
            .as_bytes()
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'{')
            .filter_map(|(open_at, _byte)| {
                let close_at = matching_brace(template, open_at)?;
                flat_object_keys(&template[open_at + 1..close_at])
            })
            .collect()
    }
}
