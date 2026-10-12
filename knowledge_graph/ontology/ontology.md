# Ontology

The graph is built from Normalized Events (contract 1) and Attack Technique
records (contract 2). Constraints and indexes are in `schema.cypher`.

## Nodes

| Label | Key | Other properties | Source |
|---|---|---|---|
| `Event` | `event_id` | `timestamp` (datetime), `ts` (epoch seconds), `source`, `action`, `destination_port`, `byte_count` | contract 1 |
| `User` | `name` | | `user` |
| `Device` | `name` | `user_count`, `hub` | `device` |
| `IP` | `address` | `internal`, `user_count`, `hub` | `source_ip`, `destination_ip` |
| `Process` | `name` | | `process` |
| `Technique` | `technique_id` | `name` | contract 2 |
| `Tactic` | `name` | | contract 2 |
| `Incident` | `uid` (`<method>:<incident_id>`) | `incident_id`, `method`, `window_minutes`, `start`, `end`, `event_count` | inferred |

`user_count` is the number of distinct users whose events touch a Device or IP.
`hub` is true when that count reaches `HUB_USERS`; hubs are shared
infrastructure and are ignored when linking events into incidents.

## Relationships

| Relationship | Properties | Meaning |
|---|---|---|
| `(User)-[:PERFORMED]->(Event)` | | who acted |
| `(Event)-[:OCCURRED_ON]->(Device)` | | host the event was logged on |
| `(Event)-[:INVOLVES]->(IP)` | `role`: `source` or `destination` | addresses in the event |
| `(Event)-[:EXECUTED]->(Process)` | | process, when the event has one |
| `(Event)-[:MAPS_TO]->(Technique)` | `source`: `ground_truth` or `mapper`; `confidence` | ATT&CK mapping |
| `(Technique)-[:BELONGS_TO]->(Tactic)` | | tactic of the technique |
| `(Event)-[:PART_OF]->(Incident)` | | inferred incident membership |
| `(Event)-[:NEXT]->(Event)` | `method`, `incident_id`, `delta_seconds` | next event in time within one incident |

A null `destination_ip` or `process` creates no node and no relationship.

## Temporal layer

`NEXT` links each event to the one that follows it inside the same incident,
ordered by `ts` then `event_id`. It is direction-bearing, so A→B→C and C→B→A
are different graphs. "Before" is not stored: query it as `(a)-[:NEXT*]->(b)`.

## Several views in one graph

An event can carry one `MAPS_TO` edge per `source`, and can belong to one
incident per inference `method` (`heuristic`, `labels`, `mapper`). `NEXT`
edges and `Incident` nodes carry `method`, so the views never mix.
