// Pairs of candidate events that belong together: they share a User, or a
// non-hub Device or IP, and are neighbours on that entity's timeline no more
// than $window_seconds apart. Connected components of these pairs are incidents.
MATCH (e:Event) WHERE e.event_id IN $event_ids
MATCH (e)-[:PERFORMED|OCCURRED_ON|INVOLVES]-(n)
WHERE n:User OR ((n:Device OR n:IP) AND NOT n.hub)
WITH DISTINCT n, e
ORDER BY e.ts, e.event_id
// collect() keeps the order of the preceding ORDER BY
WITH n, collect(e) AS es
UNWIND range(0, size(es) - 2) AS k
WITH n, es[k] AS a, es[k + 1] AS b
WHERE b.ts - a.ts <= $window_seconds
RETURN a.event_id AS a, b.event_id AS b,
       labels(n)[0] AS via, coalesce(n.name, n.address) AS entity
