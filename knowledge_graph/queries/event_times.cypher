// Epoch seconds for a set of events.
MATCH (e:Event) WHERE e.event_id IN $event_ids
RETURN e.event_id AS event_id, e.ts AS ts
