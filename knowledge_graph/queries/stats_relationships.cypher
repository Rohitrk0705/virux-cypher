MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS count ORDER BY type
