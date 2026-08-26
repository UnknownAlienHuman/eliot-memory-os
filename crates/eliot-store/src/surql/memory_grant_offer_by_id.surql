LET $offer = SELECT *
FROM ONLY type::record('memory_grant_offer', $grant_id);

RETURN IF $offer = NONE
  OR <string> $offer.project_id != <string> $project_id
  OR <string> $offer.task_id != <string> $task_id
  OR <string> $offer.session_id != <string> $session_id
  OR <string> $offer.kind != 'memory_grant_offer'
  OR <string> $offer.payload.grant_id != <string> $grant_id {
  NONE
} ELSE {
  $offer.payload
};
