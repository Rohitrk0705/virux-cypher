// Technique-mapped events of one incident in temporal order.
// One row per event; consecutive repeats are collapsed by the caller.
MATCH (i:Incident {method: $method, incident_id: $incident_id})<-[:PART_OF]-(e:Event)
MATCH (e)-[:MAPS_TO {source: $technique_source}]->(t:Technique)
RETURN t.technique_id AS technique_id, e.ts AS ts, e.event_id AS event_id
ORDER BY e.ts, e.event_id, t.technique_id
