// NEXT edges of one incident.
MATCH (a:Event)-[n:NEXT {method: $method, incident_id: $incident_id}]->(b:Event)
RETURN a.event_id AS source, b.event_id AS target, n.delta_seconds AS delta_seconds
ORDER BY a.ts, a.event_id
