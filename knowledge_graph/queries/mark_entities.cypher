// Flag internal addresses and shared-infrastructure hubs.
// $internal_prefix: e.g. '10.'   $hub_users: distinct-user threshold.
MATCH (n) WHERE n:Device OR n:IP
OPTIONAL MATCH (n)<-[:OCCURRED_ON|INVOLVES]-(:Event)<-[:PERFORMED]-(u:User)
WITH n, count(DISTINCT u) AS users
SET n.user_count = users,
    n.hub = users >= $hub_users,
    n.internal = CASE WHEN n:IP THEN n.address STARTS WITH $internal_prefix ELSE null END
