FOR $row IN $rows {
  LET $handle = <string> array::join(
    $row.handle_parts.map(|$fragment| <string> $fragment),
    ''
  );
  LET $record_ref = <string> array::join(
    $row.record_ref_parts.map(|$fragment| <string> $fragment),
    ''
  );
  LET $existing = SELECT * FROM ONLY type::record('memory_search_projection', $row.projection_id);
  IF $existing == NONE OR $existing.updated_revision <= $row.updated_revision {
    DELETE memory_search_token
      WHERE project_id = $project_id AND handle = $handle;
    IF $row.visible {
      UPSERT type::record('memory_search_projection', $row.projection_id) CONTENT {
        project_id: $project_id,
        handle: $handle,
        record_kind: $row.record_kind,
        record_ref: $record_ref,
        preview: $row.preview,
        search_text: $row.search_text,
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
      FOR $posting IN $row.postings {
        UPSERT type::record('memory_search_token', $posting.posting_id) CONTENT {
          project_id: $project_id,
          token: $posting.token,
          handle: $handle,
          authority_rank: $row.authority_rank,
          updated_revision: $row.updated_revision,
          source_write_id: $write_id,
        };
      };
    } ELSE {
      DELETE type::record('memory_search_projection', $row.projection_id);
    };
  };
};

IF $advance_state {
  LET $state_id = type::record('memory_search_state', $project_id);
  LET $state = SELECT * FROM ONLY $state_id;
  IF $state == NONE OR $state.applied_revision <= $updated_revision {
    UPSERT $state_id CONTENT {
      project_id: $project_id,
      applied_revision: $updated_revision,
      source_write_id: $write_id,
      updated_at: time::now(),
    };
  };

  UPSERT type::record('memory_search_outbox', $write_id) MERGE {
    write_id: $write_id,
    project_id: $project_id,
    updated_revision: $updated_revision,
    status: 'applied',
    applied_at: time::now(),
  };
};

RETURN {
  project_id: $project_id,
  updated_revision: $updated_revision,
  rows_applied: array::len($rows),
};
