// Flag internal addresses and shared-infrastructure hubs.
// $internal_prefix: e.g. '10.'   $hub_users: distinct-user threshold.
// user_count = distinct users whose events touch the entity. The sender address
// of a received e-mail is not counted for the recipient: the recipient never
// used that address, and counting it would turn every workstation that sends
// internal mail into a hub.
MATCH (n) WHERE n:Device OR n:IP
OPTIONAL MATCH (n)<-[r:OCCURRED_ON|INVOLVES]-(e:Event)<-[:PERFORMED]-(u:User)
WHERE NOT (e.action = 'email_received' AND type(r) = 'INVOLVES' AND r.role = 'source')
WITH n, count(DISTINCT u) AS users
SET n.user_count = users,
    n.hub = users >= $hub_users,
    n.internal = CASE WHEN n:IP THEN n.address STARTS WITH $internal_prefix ELSE null END
