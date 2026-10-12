// Events of one incident with their entities, in temporal order.
// The caller turns ts into the contract-1 timestamp string.
MATCH (i:Incident {method: $method, incident_id: $incident_id})<-[:PART_OF]-(e:Event)
MATCH (u:User)-[:PERFORMED]->(e)-[:OCCURRED_ON]->(d:Device)
MATCH (e)-[:INVOLVES {role: 'source'}]->(s:IP)
OPTIONAL MATCH (e)-[:INVOLVES {role: 'destination'}]->(x:IP)
OPTIONAL MATCH (e)-[:EXECUTED]->(p:Process)
RETURN e.event_id AS event_id, e.ts AS ts, e.source AS source, u.name AS user,
       s.address AS source_ip, x.address AS destination_ip, d.name AS device,
       e.action AS action, p.name AS process,
       e.destination_port AS destination_port, e.byte_count AS byte_count
ORDER BY e.ts, e.event_id
