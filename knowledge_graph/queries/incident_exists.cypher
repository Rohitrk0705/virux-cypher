MATCH (i:Incident {method: $method, incident_id: $incident_id})
RETURN count(i) AS n
