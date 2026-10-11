# Progress

(Summary for the morning is at the top once the run is finished; per-milestone
entries follow.)

## M1 — synthetic data generator — done

- `data/generator/generate.py` → `data/processed/{events,labels,incidents}.json`, seed 42, byte-identical on re-run.
- 3,629 events (3,353 benign, 276 attack = 7.6%), 8 users, 11 devices, 12 days.
- 24 incidents: patterns A–D × 6 (3 base, 1 skip, 1 insert, 1 skip+insert); 4 of the 24 are slow-paced.
- Changed after your approval: ground-truth incident ids are now `GT-001…` (inferred ids are `INC-…`), and `T1070.001` became `T1685.005` to match ATT&CK v19.2 (decisions G1, K8).

## M2 — Neo4j temporal knowledge graph — done

Built: schema and ontology (`knowledge_graph/ontology/`), idempotent loader, 20 reusable Cypher files (`knowledge_graph/queries/`), incident inference (`temporal/incidents.py`), `get_trajectory()` returning contract 3 (`temporal/trajectory.py`), evaluation against `incidents.json` (`evaluation/incident_match.py`), one entry point (`python -m knowledge_graph.build [--reset]`). Captured output: `evaluation/results/m2_build.txt`.

Graph after loading (before the mapper existed):

| Nodes | | Relationships | |
|---|---|---|---|
| Event | 3,629 | PERFORMED | 3,629 |
| User | 8 | OCCURRED_ON | 3,629 |
| Device | 11 | INVOLVES | 5,795 |
| IP | 60 | EXECUTED | 1,282 |
| Process | 24 | MAPS_TO (ground truth) | 276 |
| Technique | 15 | BELONGS_TO | 15 |
| Tactic | 10 | PART_OF | 1,375 |
| Incident | 306 (279 heuristic + 27 labels) | NEXT | 1,069 |
| **Total** | **4,063** | **Total** | **17,070** |

Incident inference against the 24 true incidents, window 30 min:

| Filter | Inferred | No attack event | Incident precision | Exact | Trajectory correct (GT techniques) | Mean coverage | Mean purity | Attack-pair F1 |
|---|---|---|---|---|---|---|---|---|
| heuristic (label-free) | 279 | 253 | 0.093 | 8 / 24 | 11 / 24 | 0.887 | 0.852 | 0.879 |
| labels (leakage, upper bound) | 27 | 0 | 1.000 | 21 / 24 | 21 / 24 | 0.935 | 1.000 | 0.989 |

Window sweep (5, 15, 30, 60, 120 min) for both filters is in `m2_build.txt`.

**Limitations of these numbers (do not quote them without these):**
1. The dataset is easy: incidents sharing a user or device are at least 3 hours apart. Real data would score lower.
2. The `labels` row uses ground truth to pick candidates; it is an upper bound only.
3. The heuristic can never group `file_access` or Office launches, so T1005 and T1204.002 steps (25 attack events) are always missed; its routine-application list equals the generator's benign application list; about two thirds of its candidates are benign web and mail events, which is why 253 of its 279 incidents contain no attack.
4. The 30-minute window was chosen from the sweep on these same 24 incidents.
5. The three slow incidents with step gaps over 30 minutes (GT-014, GT-015, GT-022) fragment under both filters.

Pattern B (account switch to `admin_lee`): the three affected incidents are joined through the pivot workstation's IP, as intended; the reviewer verified this independently. The slow one (GT-015) still fragments because of its step gaps, not because of the account switch.

Review: 2 Blocking (both fixed), 11 Should-fix (9 fixed, 2 TODO). See `REVIEWS.md`.

TODOs carried forward:
- Hub suppression is a global distinct-user count (`HUB_USERS = 4`). Pattern-B grouping depends on the pivot IP staying under it (10.0.0.14 is at 3), and two attacker IPs are already classed as hubs. Make it time-windowed or role-aware.
- `materialize()` clears and rewrites in separate transactions; an API reader could briefly see no incidents.
- `INTERNAL_PREFIX = "10."` is a string prefix; use `ipaddress` for real networks.
- Entity nodes left without events after a changed reload are not garbage-collected (use `--reset` when switching datasets).
