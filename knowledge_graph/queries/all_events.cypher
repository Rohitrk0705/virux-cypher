// Every event with its entities, in temporal order (contract-1 fields; the
// caller turns ts into the timestamp string).
MATCH (u:User)-[:PERFORMED]->(e:Event)-[:OCCURRED_ON]->(d:Device)
MATCH (e)-[:INVOLVES {role: 'source'}]->(s:IP)
OPTIONAL MATCH (e)-[:INVOLVES {role: 'destination'}]->(x:IP)
OPTIONAL MATCH (e)-[:EXECUTED]->(p:Process)
RETURN e.event_id AS event_id, e.ts AS ts, e.source AS source, u.name AS user,
       s.address AS source_ip, x.address AS destination_ip, d.name AS device,
       e.action AS action, p.name AS process
ORDER BY e.ts, e.event_id
