# Agent 2 (Attack Investigation) — Tool Contracts

The agent reasons in a loop and calls these DETERMINISTIC tools. It never computes
findings itself; it decides which to call and interprets results.

| Tool | Input | Output |
|---|---|---|
| get_events(incident_id) | incident_id | list[Normalized Event] |
| query_graph(incident_id) | incident_id | Attack Trajectory (contract 3) |
| match_historical(trajectory) | Attack Trajectory | Historical Match (contract 4) |
| predict_next(trajectory) | Attack Trajectory | Prediction (contract 5) |
| lookup_technique(technique_id) | ATT&CK id | {id, name, tactic, description} |

Loop (conceptual):
  goal = "investigate incident X and report"
  trajectory = query_graph(X)
  if suspicious -> events = get_events(X)
  matches = match_historical(trajectory)
  if strong match -> prediction = predict_next(trajectory)
  detail = lookup_technique(<key technique>)
  -> emit Structured Evidence Bundle  ->  Agent 3 explains it

# Agents 1 and 3 — the same loop, their own tools

All three agents run one tool-calling loop (`agents/loop.py`): a policy chooses the next tool,
a workspace validates and runs it, and code assembles the output from tool results. The policy
is the offline scripted policy by default and Claude when `AGENT_LLM=anthropic` (never run
against the real API: no credentials were available).

## Agent 1 (Log Intelligence): raw log records -> Ingest Report

| Tool | Input | Output |
|---|---|---|
| profile_batch() | – | groups of records by detected format, one truncated sample each, parser names |
| parse_group(group_id, parser) | a group and a parser name | events parsed, records rejected by reason |
| quarantine_group(group_id) | a group | records set aside (nothing stored) |
| commit() | – | Normalized Events stored, all events re-mapped to ATT&CK, incidents re-inferred (one transaction) |

Parsers: `normalized_json`, `windows_event_json`, `firewall_kv`, `mail_kv` (`agents/log_agent/parsers.py`).
The agent never writes a field of an event; it names a group and a parser.

Loop (conceptual):
  groups = profile_batch()
  for each group: known format -> parse_group(group, its parser); otherwise quarantine_group(group)
  if anything parsed -> commit()
  -> emit Ingest Report {counts, groups, events (contract 1), techniques (contract 2), steps}

## Agent 3 (Explanation): Structured Evidence Bundle -> report

| Tool | Input | Output |
|---|---|---|
| read_evidence() | – | the bundle's findings in compact form |
| write_section(section) | observed, matches, prediction, method or limits | that section, rendered from the bundle |

Loop (conceptual):
  read_evidence()
  write_section(...) in the order that suits the incident; skipped sections are appended by code
  optional summary in the model's words -> kept only if every id and number in it is in the bundle
  -> emit {incident_id, format, generated_by, report, sections, summary, steps, agent}
