# Decisions made autonomously

One line each: what was decided and why. Newest milestone last.

## Process

| # | Decision | Rationale |
|---|---|---|
| P1 | Work is committed on branch `backend-milestones`, not `main`; nothing is pushed. | Keeps `main` untouched until you have read the results; merge is one command. |
| P2 | No `milestone-reviewer` agent is defined in this repo or in `~/.claude/agents`, so each review is done by a general-purpose subagent given a fixed reviewer brief (Blocking / Should-fix / Nits, review only, no edits). | Closest available equivalent; the brief is quoted at the top of `docs/REVIEWS.md`. |
| P3 | `pytest` and `httpx` were added to `backend/requirements.txt`. | Needed to run tests and to test FastAPI endpoints. |
| P4 | Captured run output is stored under `evaluation/results/` and `experiments/results/`. | Every number in `PROGRESS.md` can be traced to a file produced by code. |

## M1 — generator (changes after your approval)

| # | Decision | Rationale |
|---|---|---|
| G1 | `T1070.001` was replaced by `T1685.005` (Clear Windows Event Logs, tactic Defense Impairment). | The downloaded ATT&CK release (v19.2) revokes `T1070.001` in favour of `T1685.005`; labels should use current IDs. Affects one event. `events.json` is byte-identical to before. |
| G2 | The generator checks every technique name and tactic against `data/mitre/techniques.json` when that file exists. | Stops the synthetic labels drifting from real ATT&CK. |

## M2 — knowledge graph

| # | Decision | Rationale |
|---|---|---|
| K1 | `knowledge_graph/neo4j/` is left as a non-package folder; the connection code is `knowledge_graph/connection.py`. | A Python package named `neo4j` inside the project can shadow the Neo4j driver. |
| K2 | One graph holds several views: `MAPS_TO` carries `source` (`ground_truth`, `mapper`); `Incident` and `NEXT` carry `method` (`heuristic`, `labels`, `mapper`). | Lets the leaky and honest pipelines be compared without reloading. |
| K3 | Label-free heuristic candidates: logon failures, privilege changes, RDP/SMB sessions, process executions other than a short list of routine business apps, and any event touching an external address. | Your four categories plus remote sessions; without remote sessions lateral movement can never be grouped. |
| K4 | Linking rule: two candidate events are linked if they share a User, or a non-hub Device or IP, and are neighbours on that entity's timeline within the window. Incidents are connected components. | Deterministic and explainable; every link names the entity it went through. |
| K5 | Hub suppression: a Device or IP used by 4 or more distinct users is ignored for linking (`HUB_USERS = 4`). | Without it the mail server, file server and popular websites join every user's events into one incident per day. |
| K6 | Default window 30 minutes; sweep 5, 15, 30, 60, 120. | 30 minutes is the knee in the sweep; the sweep is reported so the choice is visible. |
| K7 | An inferred incident needs at least 2 events. | A single event is not a multi-step incident. |
| K8 | Inferred incidents are numbered `INC-001…` by start time, per method. These numbers are unrelated to the ground-truth `INC-…` ids in `incidents.json`. | Contract 3 uses the `INC-` form; the evaluation prints the mapping between the two. |
| K9 | Trajectory order is by timestamp then `event_id`; a test checks that walking `NEXT` edges gives the same order. | Same result, simpler query. |

## M3 — ATT&CK mapper

| # | Decision | Rationale |
|---|---|---|
| A1 | The mapper lives in `core/attack_mapper.py`; environment knowledge (servers, admin workstation, service account) lives in `core/environment.py`. | `architecture.md` has no mapping folder; `core/` is the log-to-KG glue. The inventory is what a SOC's CMDB provides and contains nothing about which events are attacks. |
| A2 | Rules follow ATT&CK's own meaning of a tool, not the generator's labels: `cmd.exe` → T1059.003, `whoami.exe` → T1033, `rundll32.exe` → T1218.011, `7z.exe` → T1560.001. | Tuning the rules to the generator would make the "first honest number" dishonest. These show up as real confusions in the evaluation. |
| A3 | Dual-use activity (PowerShell, RDP, SMB, elevation) is not mapped when an administrator or service account performs it from its expected workstation ("expected session", tracked by session origin). | Otherwise every admin action is a false positive. An admin account used from a non-admin workstation is still mapped, which is what catches pattern B's stolen-credential hop. |
| A4 | One technique per event; a contract-2 `tactic` is a single value chosen by the rule and validated against ATT&CK's tactic list for that technique. | Contract 2 has one `tactic` field. |
| A5 | Rule confidences are fixed, hand-assigned values. | Contract 2 needs a number; they are not calibrated and nothing downstream depends on their exact value. |
| A6 | ATT&CK is downloaded by `data/mitre/fetch.py`; the 54 MB STIX bundle is gitignored and the small extracts (`techniques.json`, `groups.json`, `tactics.json`) are committed. | Reproducible without committing a large file. |
