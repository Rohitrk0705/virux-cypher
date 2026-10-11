# Architecture

## Flow
Logs -> [Agent 1: Log Intelligence] -> Temporal Knowledge Graph (Neo4j)
     -> [Agent 2: Attack Investigation] -- calls --> deterministic tools:
            query_graph / get_events / match_historical / predict_next / lookup_technique
     -> Structured Evidence Bundle
     -> [Agent 3: Explanation] -> analyst report
     -> SOC Dashboard (served by FastAPI)

## Design principle
Core decisions are DETERMINISTIC and auditable:
- knowledge graph construction
- historical similarity
- next-step prediction
Agents ORCHESTRATE and EXPLAIN. An agent never invents a finding.

## Module ownership
| Folder | Purpose |
|---|---|
| data/ | synthetic generator + MITRE data + raw/processed logs |
| core/ | OntoLogX integration glue |
| knowledge_graph/ | Neo4j schema, ontology, Cypher queries |
| temporal/ | timestamps, ordering, trajectory extraction |
| prediction/ | similarity engine + baseline/ML predictors |
| agents/ | the 3 agents + shared tool layer |
| backend/ | FastAPI endpoints + pydantic schemas |
| frontend/ | React dashboard |
| experiments/ | the 3 locked experiments |
| evaluation/ | metrics + scripts |

## Build order (do NOT build UI first)
data -> graph -> ATT&CK mapping -> trajectory -> matching ->
baseline prediction -> tools -> Agent 2 -> backend -> frontend -> Agents 1 & 3
