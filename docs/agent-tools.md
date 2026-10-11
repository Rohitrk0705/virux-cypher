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
