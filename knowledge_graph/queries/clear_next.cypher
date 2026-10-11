// Drop one method's NEXT edges.
MATCH (:Event)-[n:NEXT {method: $method}]->(:Event)
DELETE n
