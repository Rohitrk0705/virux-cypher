# backend — FastAPI

The boundary the frontend builds against. Every endpoint returns data from the Neo4j knowledge
graph and the deterministic core; nothing is mocked.

## Run

```bash
# once
cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cd ../docker && docker compose up -d                 # Neo4j
cd .. && cp .env.example .env
python data/generator/generate.py                     # synthetic dataset -> data/processed/
python -m core.attack_mapper                          # rule-based ATT&CK mapping -> mapped.json
python -m knowledge_graph.build --reset               # load the graph, infer incidents

# every time
cd backend && uvicorn api.main:app --reload           # http://localhost:8000
```

Interactive docs: `http://localhost:8000/docs` (needs internet access, because Swagger UI loads from a CDN;
the schema itself is at `/openapi.json`). `--reload` started from `backend/` only watches `backend/`.

CORS allows `http://localhost:5173` and `http://127.0.0.1:5173` by default; set `CORS_ORIGINS`
(comma-separated) to change it.

There is **no authentication** and **no pagination**. `POST /logs` rewrites shared state (technique
mappings and incidents for everyone). Set `API_TOKEN` in the environment to require an
`X-API-Token` header on `POST /logs`; reads stay open.

## Endpoints

`{id}` is an inferred incident id such as `INC-03265`. Get the list from `GET /incidents`.

| Method and path | Returns | Shape |
|---|---|---|
| `GET /health` | service status, number of events and incidents | `{status, service, neo4j, events, incidents}` |
| `GET /incidents` | all inferred incidents, oldest first | `[{incident_id, start, end, event_count}]` |
| `POST /logs` | ingest events, re-map, re-infer incidents | body: `[Normalized Event]`; response below |
| `GET /events/{id}` | the incident's events in time order | `[Normalized Event]` (contract 1) |
| `GET /graph/{id}` | nodes and edges for a graph view | `{incident_id, nodes, edges}` |
| `GET /trajectory/{id}` | ordered ATT&CK techniques | Attack Trajectory (contract 3) |
| `GET /match/{id}` | most similar historical attacks | Historical Match (contract 4) |
| `GET /predict/{id}` | most probable next techniques | Prediction (contract 5) |
| `GET /investigate/{id}` | runs Agent 2 | Structured Evidence Bundle |
| `GET /explain/{id}` | runs Agent 2 then Agent 3 | `{incident_id, format, generated_by, report}` |
| `GET /technique/{technique_id}` | ATT&CK technique details | `{id, name, tactic, description}` |

Errors always have the shape `{"detail": "<string>"}`:

| Status | When |
|---|---|
| `404` | unknown incident or technique |
| `422` | request body does not match contract 1 (see `POST /logs`), or duplicate `event_id` in one request |
| `401` | `API_TOKEN` is set and the `X-API-Token` header is missing or wrong |
| `503` | the Neo4j driver cannot reach the database |
| `500` | anything else; `detail` is `"internal error"` and the cause is in the server log |

`GET /health` answers `200` even when Neo4j is down, with
`{"status": "degraded", "service": "virux-cypher", "neo4j": false, "events": null, "incidents": null}`.

The contract shapes are in `docs/data-contracts.md`; the Pydantic models are in `api/schemas.py`.
Real responses from a running service are in `evaluation/results/m8_api.txt`.

### Things the frontend should know

- **Incident ids are derived from the incident's first event** (`evt-03265` → `INC-03265`; an event id without
  the `evt-` prefix is used whole). They are stable across restarts, but `POST /logs` re-infers incidents, so
  an id can disappear or a new one appear after it. `/incidents` is ordered by start time.
- **Technique ids.** `/trajectory` uses full ids (`T1059.001`). `/predict` returns parent ids (`T1021`),
  because prediction works on parent techniques. `/events` carries no technique; the event-to-technique link
  is the `MAPS_TO` edges of `/graph`.
- **A technique can appear more than once in a trajectory.** Each step is a run of consecutive events with
  the same technique, stamped with the time that run began.
- **`/technique/{technique_id}`** may return a different `id` than requested when the requested one has been
  revoked by MITRE (`T1070.001` returns `T1685.005`). `tactic` is a comma-separated string when a technique
  has several tactics, and `description` is MITRE's text, which contains Markdown links.
- **`/predict` can return an empty `predictions` list.** That means the history gives no basis for a next
  step (for example the incident already ended with a step that only ever closes historical attacks). The
  `evidence` list always explains why.
- **`/match` returns up to five matches**, best first. `attack_id` is `HIST-C01…` for hand-written
  reference sequences and `HIST-G0016` style for MITRE ATT&CK groups.
- **Most incidents are not attacks.** On the bundled dataset 22 of the 53 inferred incidents contain no
  attack event; the mapper is rule-based and imprecise (see `docs/PROGRESS.md`).
- **`/investigate` and `/explain` are deterministic by default** (an offline scripted policy picks the
  tools). `agent_notes` is commentary, not a finding.

### `POST /logs`

Body: a JSON array of 1 to 5,000 Normalized Events (contract 1). All nine fields are required;
`destination_ip` and `process` may be `null`. An existing `event_id` is replaced.

```json
[{"event_id": "evt-900001", "timestamp": "2026-10-12T10:30:00Z", "source": "windows", "user": "john",
  "source_ip": "10.0.0.11", "destination_ip": null, "device": "WS-01",
  "action": "process_execution", "process": "powershell.exe"}]
```

Response:

```json
{"received": 1, "events_in_graph": 3987, "mapped_events": 413, "incidents": 53, "incidents_touched": []}
```

Validation (any failure is a `422` and nothing is stored):

- `event_id`: 1-128 characters from `A-Z a-z 0-9 . _ : -` (it becomes part of incident ids and URLs)
- `timestamp`: `YYYY-MM-DDTHH:MM:SSZ`, a real UTC date between 1970 and 2100
- every other field: 1-256 characters, no control characters, no leading or trailing whitespace
- no unknown fields, no missing fields, no repeated `event_id` within the request

The request is **one transaction**: events, technique mappings and incidents commit together, and `GET`
requests keep seeing the previous state until then. If anything fails, nothing changes.

`incidents_touched` lists the incidents that now contain one of the submitted events. The call re-maps
every event in the graph (about 0.2 s for the bundled 3,986 events on the development machine); ingests run one at a time. Raw, un-normalized log
lines are not accepted.

### `GET /graph/{id}`

```json
{"incident_id": "INC-03265",
 "nodes": [{"id": "event:evt-03265", "type": "event", "label": "evt-03265",
            "timestamp": "2026-09-17T03:41:31Z", "action": "logon_success", "source": "windows"},
           {"id": "user:elena", "type": "user", "label": "elena"},
           {"id": "ip:10.0.0.14", "type": "ip", "label": "10.0.0.14", "internal": true},
           {"id": "technique:T1078", "type": "technique", "label": "T1078", "name": "Valid Accounts"}],
 "edges": [{"source": "user:elena", "target": "event:evt-03265", "type": "PERFORMED"},
           {"source": "event:evt-03265", "target": "ip:10.0.0.14", "type": "INVOLVES", "role": "destination"},
           {"source": "event:evt-03265", "target": "technique:T1078", "type": "MAPS_TO", "confidence": 0.6},
           {"source": "event:evt-03265", "target": "event:evt-03266", "type": "NEXT", "delta_seconds": 474}]}
```

(The example shows 4 of the incident's 25 nodes and 4 of its 46 edges.)

Node types: `event`, `user`, `device`, `ip`, `process`, `technique`, `tactic`. Edge types: `PERFORMED`,
`OCCURRED_ON`, `INVOLVES`, `EXECUTED`, `MAPS_TO`, `BELONGS_TO`, `NEXT`. Node ids are unique and every
edge refers to nodes in the same response, so the result can be passed to Cytoscape.js after wrapping
each item in `{data: ...}`. Node ids contain `:` and `.`, so look nodes up with `cy.getElementById(id)`
rather than a `#id` selector.

### `GET /investigate/{id}`

```json
{"incident_id": "INC-03265",
 "trajectory": { "...": "contract 3, or null" },
 "event_summary": {"count": 7, "first": "2026-09-17T03:41:31Z", "last": "2026-09-17T04:14:51Z",
                   "users": {"elena": 7}, "devices": {"SRV-DB01": 4, "WS-04": 3},
                   "actions": {"logon_success": 1, "network_connection": 3, "...": "one entry per action"}},
 "historical_matches": { "...": "contract 4, or null" },
 "prediction": { "...": "contract 5, or null if no strong match" },
 "techniques": [{"id": "T1041", "name": "...", "tactic": "Exfiltration", "description": "...",
                 "relation": "in_trajectory"}],
 "steps": [{"tool": "query_graph", "input": {"incident_id": "INC-03265"}, "ok": true,
            "summary": "5 technique step(s): T1078 > T1059.001 > T1068 > T1021.001 > T1041"},
           "... one entry per tool call"],
 "agent": {"llm": "scripted-policy", "complete": true, "stop_reason": "end_turn",
           "tool_calls": 5, "failed_tool_calls": 0},
 "agent_notes": "..."}
```

`prediction` is `null` when Agent 2 did not ask for one (top similarity below 0.5); call `/predict/{id}`
directly if you want a prediction regardless.

### `GET /explain/{id}`

`report` is Markdown with the sections: What was observed, Similar past attacks, Likely next step,
How this was produced, Limits of this report. It is generated from a template; no language model writes it.
Values that come from logs (user, device and action names) and the agent's note are Markdown-escaped, but
render the report with raw HTML disabled all the same.
