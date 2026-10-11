// Attach ATT&CK techniques (contract 2) to events.
// $rows: list of contract-2 records.   $source: 'ground_truth' or 'mapper'.
UNWIND $rows AS row
MATCH (e:Event {event_id: row.event_id})
MERGE (t:Technique {technique_id: row.technique_id})
SET t.name = row.technique_name
MERGE (ta:Tactic {name: row.tactic})
MERGE (t)-[:BELONGS_TO]->(ta)
MERGE (e)-[m:MAPS_TO {source: $source}]->(t)
SET m.confidence = row.confidence
