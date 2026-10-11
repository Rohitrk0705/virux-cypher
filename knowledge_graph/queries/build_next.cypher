// Temporal ordering: link each event to the next one in the same incident.
MATCH (e:Event)-[:PART_OF]->(i:Incident {method: $method})
WITH i, e ORDER BY e.ts, e.event_id
WITH i, collect(e) AS es
UNWIND range(0, size(es) - 2) AS k
WITH i, es[k] AS a, es[k + 1] AS b
MERGE (a)-[n:NEXT {method: $method}]->(b)
SET n.incident_id = i.incident_id,
    n.delta_seconds = b.ts - a.ts
