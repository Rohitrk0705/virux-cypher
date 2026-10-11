// Remove every MAPS_TO edge that came from one source.
MATCH (:Event)-[m:MAPS_TO {source: $source}]->(:Technique)
DELETE m
