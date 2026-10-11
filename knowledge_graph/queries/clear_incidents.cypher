// Drop one method's Incident nodes (and their PART_OF edges).
MATCH (i:Incident {method: $method})
DETACH DELETE i
