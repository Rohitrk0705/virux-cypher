// Upsert Normalized Events (contract 1) and the entities they mention.
// $rows: list of contract-1 events.
UNWIND $rows AS row
MERGE (e:Event {event_id: row.event_id})
SET e.timestamp = datetime(row.timestamp),
    e.ts = datetime(row.timestamp).epochSeconds,
    e.source = row.source,
    e.action = row.action
// drop what an earlier load said about this event, so a changed event is replaced
WITH row, e
CALL (e) {
  OPTIONAL MATCH (e)-[old]-(n) WHERE n:User OR n:Device OR n:IP OR n:Process
  DELETE old
}
MERGE (u:User {name: row.user})
MERGE (u)-[:PERFORMED]->(e)
MERGE (d:Device {name: row.device})
MERGE (e)-[:OCCURRED_ON]->(d)
MERGE (s:IP {address: row.source_ip})
MERGE (e)-[:INVOLVES {role: 'source'}]->(s)
FOREACH (_ IN CASE WHEN row.destination_ip IS NULL THEN [] ELSE [1] END |
  MERGE (x:IP {address: row.destination_ip})
  MERGE (e)-[:INVOLVES {role: 'destination'}]->(x))
FOREACH (_ IN CASE WHEN row.process IS NULL THEN [] ELSE [1] END |
  MERGE (p:Process {name: row.process})
  MERGE (e)-[:EXECUTED]->(p))
