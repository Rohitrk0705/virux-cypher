// Store inferred incidents and their member events.
// $incidents: [{uid, incident_id, method, window_minutes, start, end, event_ids}]
UNWIND $incidents AS inc
MERGE (i:Incident {uid: inc.uid})
SET i.incident_id = inc.incident_id,
    i.method = inc.method,
    i.window_minutes = inc.window_minutes,
    i.start = datetime({epochSeconds: inc.start}),
    i.end = datetime({epochSeconds: inc.end}),
    i.event_count = size(inc.event_ids)
WITH i, inc
UNWIND inc.event_ids AS event_id
MATCH (e:Event {event_id: event_id})
MERGE (e)-[:PART_OF]->(i)
