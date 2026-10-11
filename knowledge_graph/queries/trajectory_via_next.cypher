// Same as trajectory.cypher, but ordered purely by walking NEXT edges from the
// incident's first event. Used to check that NEXT encodes the temporal order.
MATCH (i:Incident {method: $method, incident_id: $incident_id})<-[:PART_OF]-(first:Event)
WHERE NOT EXISTS { (:Event)-[:NEXT {method: $method}]->(first) }
MATCH path = (first)-[:NEXT*0..]->(e:Event)
WHERE all(r IN relationships(path) WHERE r.method = $method)
MATCH (e)-[:MAPS_TO {source: $technique_source}]->(t:Technique)
RETURN t.technique_id AS technique_id, e.ts AS ts, e.event_id AS event_id
ORDER BY length(path)
