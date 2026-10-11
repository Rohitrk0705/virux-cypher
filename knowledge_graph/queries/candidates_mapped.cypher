// Events that have an ATT&CK technique from the given source.
MATCH (e:Event)-[:MAPS_TO {source: $source}]->(:Technique)
RETURN DISTINCT e.event_id AS event_id
ORDER BY event_id
