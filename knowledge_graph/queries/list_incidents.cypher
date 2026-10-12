// Inferred incidents of one method.
MATCH (i:Incident {method: $method})
RETURN i.incident_id AS incident_id, i.start.epochSeconds AS start,
       i.end.epochSeconds AS end, i.event_count AS event_count
ORDER BY i.start, incident_id
