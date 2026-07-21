LET $head = SELECT * FROM ONLY type::record('scope_head', $request.project_id);
LET $query = <string> array::join(
  $query_fragments.map(|$fragment| <string> $fragment),
  ''
);
LET $normalized_query = string::lowercase(string::trim($query));
LET $normalized_identifier = string::replace($normalized_query, 'claim:', '');
LET $stop_words = [
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'but', 'by', 'do', 'does',
  'for', 'from', 'had', 'has', 'have', 'how', 'i', 'if', 'in', 'into', 'is',
  'it', 'its', 'most', 'no', 'not', 'of', 'on', 'or', 'our', 'so', 'that',
  'the', 'their', 'then', 'there', 'these', 'this', 'through', 'to', 'use',
  'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while', 'who',
  'why', 'will', 'with', 'without', 'you', 'your'
];
LET $query_tokens = array::distinct(
  string::words(string::replace(string::slug($normalized_query), '-', ' '))
    .filter(|$token| string::len($token) >= 3 AND $token NOT IN $stop_words)
);
LET $project_claims = SELECT
    claim_id,
    statement,
    status,
    lifecycle_status,
    payload
  FROM claim_card
  WHERE project_id = $request.project_id;
LET $ranked = $project_claims.map(|$claim| {
  LET $statement = string::lowercase(<string> $claim.statement);
  LET $payload = string::lowercase(<string> $claim.payload);
  LET $topic = string::lowercase(<string> $claim.payload.topic);
  LET $search_text = string::concat(
    $claim.statement,
    ' ',
    <string> $claim.payload.topic,
    ' ',
    <string> $claim.payload.where_applicable,
    ' ',
    <string> $claim.payload.where_not_applicable,
    ' ',
    <string> $claim.payload.negative_constraints
  );
  LET $claim_tokens = array::distinct(
    string::words(string::replace(string::slug(string::lowercase($search_text)), '-', ' '))
      .filter(|$token| string::len($token) >= 3 AND $token NOT IN $stop_words)
  );
  LET $topic_tokens = array::distinct(
    string::words(string::replace(string::slug($topic), '-', ' '))
      .filter(|$token| string::len($token) >= 3 AND $token NOT IN $stop_words)
  );
  LET $token_overlap = array::len(array::intersect($query_tokens, $claim_tokens));
  LET $topic_overlap = array::len(array::intersect($query_tokens, $topic_tokens));
  LET $exact_identifier = IF string::lowercase(<string> $claim.claim_id) = $normalized_identifier
    { 1000 } ELSE { 0 };
  LET $subject_identity = IF $topic = $normalized_query
    OR string::contains($topic, $normalized_query)
    { 300 }
    ELSE IF $topic_overlap >= 4 { 160 }
    ELSE { $topic_overlap * 40 };
  LET $lexical_overlap = IF $statement = $normalized_query { 250 }
    ELSE IF string::contains($statement, $normalized_query) { 140 }
    ELSE IF string::contains($normalized_query, $statement) { 80 }
    ELSE IF string::contains($payload, $normalized_query) { 60 }
    ELSE IF $token_overlap >= 6 { 180 }
    ELSE IF $token_overlap = 5 { 150 }
    ELSE IF $token_overlap = 4 { 120 }
    ELSE IF $token_overlap = 3 { 90 }
    ELSE { 0 };
  LET $task_relation = IF string::contains(
      string::lowercase(<string> $claim.payload.task_id),
      $normalized_query
    ) OR string::contains(
      string::lowercase(<string> $claim.payload.cognitive_run_id),
      $normalized_query
    ) { 120 } ELSE { 0 };
  LET $scope_fit = 20;
  LET $lifecycle_fit = IF $claim.lifecycle_status IN ['active', 'restored', NONE, NULL]
    { 20 } ELSE { -200 };
  LET $evidence_authority = IF $claim.status = 'verified' { 80 }
    ELSE IF $claim.status = 'supported' { 50 }
    ELSE IF $claim.status = 'candidate' { 10 }
    ELSE { -80 };
  LET $prior_decision_delta = IF string::contains(
      string::lowercase(<string> $claim.payload.negative_constraints),
      $normalized_query
    ) OR string::contains(
      string::lowercase(<string> $claim.payload.negative_transfer),
      $normalized_query
    ) { -120 } ELSE { 0 };
  LET $relevance_score = $exact_identifier
    + $subject_identity
    + $lexical_overlap
    + $task_relation
    + $scope_fit
    + $lifecycle_fit
    + $evidence_authority
    + $prior_decision_delta;
  LET $admitted = $normalized_query != '' AND (
    $exact_identifier > 0
    OR $subject_identity > 0
    OR $lexical_overlap > 0
    OR $task_relation > 0
  );
  RETURN {
    claim_id: $claim.claim_id,
    statement: $claim.statement,
    lifecycle_status: $claim.lifecycle_status,
    exact_identifier: $exact_identifier,
    subject_identity: $subject_identity,
    lexical_overlap: $lexical_overlap,
    task_relation: $task_relation,
    scope_fit: $scope_fit,
    lifecycle_fit: $lifecycle_fit,
    evidence_authority: $evidence_authority,
    prior_decision_delta: $prior_decision_delta,
    relevance_score: $relevance_score,
    admitted: $admitted,
  };
});
LET $considered = SELECT * FROM $ranked WHERE admitted = true;
LET $claims = SELECT *
  FROM $considered
  ORDER BY relevance_score DESC, claim_id ASC
  LIMIT 50;
LET $resolved = $claims.map(|$claim| {
  LET $target_refs = [
    <string> $claim.claim_id,
    string::concat('claim:', <string> $claim.claim_id)
  ];
  LET $transitions = SELECT VALUE receipt_body.to_state
    FROM canonical_record
    WHERE project_id = $request.project_id
      AND receipt_kind = 'state_transition'
      AND subject_ref IN $target_refs
    ORDER BY memory_revision DESC, project_sequence DESC
    LIMIT 1;
  LET $lifecycle_state = IF array::len($transitions) > 0 {
    $transitions[0]
  } ELSE IF $claim.lifecycle_status != NONE {
    $claim.lifecycle_status
  } ELSE {
    'active'
  };
  RETURN {
    handle: <string> $claim.claim_id,
    record_type: 'claim_card',
    preview: $claim.statement,
    lifecycle_state: $lifecycle_state,
    exact_identifier: $claim.exact_identifier,
    subject_identity: $claim.subject_identity,
    lexical_overlap: $claim.lexical_overlap,
    task_relation: $claim.task_relation,
    scope_fit: $claim.scope_fit,
    lifecycle_fit: IF $lifecycle_state IN ['active', 'restored'] { 20 } ELSE { -200 },
    evidence_authority: $claim.evidence_authority,
    prior_decision_delta: $claim.prior_decision_delta,
    total: $claim.relevance_score,
  };
});
RETURN {
  project_id: $request.project_id,
  at_revision: IF $head == NONE { 0 } ELSE { $head.memory_revision },
  handles: $resolved.map(|$candidate| {
    RETURN {
      handle: $candidate.handle,
      record_type: $candidate.record_type,
      preview: $candidate.preview,
      lifecycle_state: $candidate.lifecycle_state,
    };
  }),
  query_mode: 'query_aware_semantic_lexical_relational_v2',
  rank_trace: {
    query: $query,
    normalized_query: $normalized_query,
    candidates_considered: array::len($considered),
    candidates_returned: array::len($resolved),
    feature_scores: $resolved.map(|$candidate| {
      RETURN {
        handle: $candidate.handle,
        exact_identifier: $candidate.exact_identifier,
        subject_identity: $candidate.subject_identity,
        lexical_overlap: $candidate.lexical_overlap,
        task_relation: $candidate.task_relation,
        scope_fit: $candidate.scope_fit,
        lifecycle_fit: $candidate.lifecycle_fit,
        evidence_authority: $candidate.evidence_authority,
        prior_decision_delta: $candidate.prior_decision_delta,
        total: $candidate.total,
        reasons: ['deterministic_semantic_lexical_relational_score'],
      };
    }),
    lifecycle_suppressions: [],
    scope_suppressions: [],
    no_useful_memory: array::len($resolved) = 0,
    query_mode: 'query_aware_semantic_lexical_relational_v2',
  },
  truncation: {
    truncated: array::len($considered) > 50,
    limit: 50,
    returned: array::len($resolved),
  },
};
