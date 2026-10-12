// Everything attached to one incident's events, for drawing the incident graph.
MATCH (i:Incident {method: $method, incident_id: $incident_id})<-[:PART_OF]-(e:Event)
OPTIONAL MATCH (u:User)-[:PERFORMED]->(e)
OPTIONAL MATCH (e)-[:OCCURRED_ON]->(d:Device)
OPTIONAL MATCH (e)-[:EXECUTED]->(p:Process)
OPTIONAL MATCH (e)-[m:MAPS_TO {source: $technique_source}]->(t:Technique)
OPTIONAL MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
RETURN e.event_id AS event_id, e.ts AS ts, e.action AS action, e.source AS source,
       u.name AS user, d.name AS device, p.name AS process,
       [(e)-[r:INVOLVES]->(ip:IP) | {address: ip.address, role: r.role, internal: ip.internal}] AS ips,
       t.technique_id AS technique_id, t.name AS technique_name, m.confidence AS confidence,
       collect(ta.name) AS tactics
ORDER BY e.ts, e.event_id
