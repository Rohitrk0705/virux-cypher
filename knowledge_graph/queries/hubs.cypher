MATCH (n) WHERE (n:Device OR n:IP) AND n.hub
RETURN labels(n)[0] AS label, coalesce(n.name, n.address) AS entity, n.user_count AS users
ORDER BY label, entity
