FOR $row IN $rows {
  LET $handle = <string> array::join(
    $row.handle_parts.map(|$fragment| <string> $fragment),
    ''
  );
  LET $record_ref = <string> array::join(
    $row.record_ref_parts.map(|$fragment| <string> $fragment),
    ''
  );
  LET $parent_handle = <string> array::join(
    $row.parent_handle_parts.map(|$fragment| <string> $fragment),
    ''
  );
  LET $source_record_ref = <string> array::join(
    $row.source_record_ref_parts.map(|$fragment| <string> $fragment),
    ''
  );
  LET $existing = SELECT * FROM ONLY type::record('memory_search_projection', $row.projection_id);
  IF $existing == NONE OR $existing.updated_revision <= $row.updated_revision {
    IF $row.visible {
      UPSERT type::record('memory_search_projection', $row.projection_id) CONTENT {
        project_id: $project_id,
        handle: $handle,
        parent_handle: $parent_handle,
        record_kind: $row.record_kind,
        record_ref: $record_ref,
        source_record_ref: $source_record_ref,
        source_segment_ordinal: $row.source_segment_ordinal,
        source_segment_count: $row.source_segment_count,
        source_byte_start: $row.source_byte_start,
        source_byte_end_exclusive: $row.source_byte_end_exclusive,
        fts_segment_ordinal: $row.fts_segment_ordinal,
        fts_segment_count: $row.fts_segment_count,
        term_start: $row.term_start,
        term_end_exclusive: $row.term_end_exclusive,
        preview: $row.preview,
        search_text: $row.search_text,
        search_document: $row.search_document,
        cue_text: $row.cue_text,
        scope_text: $row.scope_text,
        concept_text: $row.concept_text,
        task_id: $row.task_id,
        status: $row.status,
        lifecycle: $row.lifecycle,
        authority_rank: $row.authority_rank,
        negative_memory: $row.negative_memory,
        memory_revision: $row.memory_revision,
        project_sequence: $row.project_sequence,
        verification_value: $row.verification_value,
        known_decision_delta: $row.known_decision_delta,
        prior_beneficial_use: $row.prior_beneficial_use,
        contradiction_signal: $row.contradiction_signal,
        harm_signal: $row.harm_signal,
        repetition_signal: $row.repetition_signal,
        distraction_signal: $row.distraction_signal,
        updated_revision: $row.updated_revision,
        source_write_id: $write_id,
        updated_at: time::now(),
      };
    } ELSE {
      DELETE memory_search_projection
      WHERE project_id = $project_id AND handle = $handle;
    };
  };
  IF $row.visible {
    DELETE memory_search_projection
    WHERE project_id = $project_id
      AND handle = $handle
      AND (
        source_segment_ordinal = NONE
        OR (source_segment_ordinal ?? 0) >= $row.source_segment_count
        OR (
          (source_segment_ordinal ?? 0) = $row.source_segment_ordinal
          AND (fts_segment_ordinal ?? 0) >= $row.fts_segment_count
        )
      );
  };
};

IF $advance_state {
  LET $state_id = type::record('memory_search_state', $project_id);
  LET $state = SELECT * FROM ONLY $state_id;
  IF $state == NONE OR $state.applied_revision <= $updated_revision {
    IF $projection_format == NONE OR $projection_format == NULL {
      UPSERT $state_id MERGE {
        project_id: $project_id,
        applied_revision: $updated_revision,
        source_write_id: $write_id,
        updated_at: time::now(),
      };
    } ELSE {
      UPSERT $state_id MERGE {
        project_id: $project_id,
        applied_revision: $updated_revision,
        projection_format: $projection_format,
        source_write_id: $write_id,
        updated_at: time::now(),
      };
    };
  };
};

RETURN {
  project_id: $project_id,
  updated_revision: $updated_revision,
  rows_applied: array::len($rows),
};
