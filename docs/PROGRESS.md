# Progress

(Summary for the morning is at the top once the run is finished; per-milestone
entries follow.)

## M1 — synthetic data generator — done

- `data/generator/generate.py` → `data/processed/{events,labels,incidents}.json`, seed 42, byte-identical on re-run.
- 3,629 events (3,353 benign, 276 attack = 7.6%), 8 users, 11 devices, 12 days.
- 24 incidents: patterns A–D × 6 (3 base, 1 skip, 1 insert, 1 skip+insert); 4 of the 24 are slow-paced.
- Changed after your approval: ground-truth incident ids are now `GT-001…` (inferred ids are `INC-…`), and `T1070.001` became `T1685.005` to match ATT&CK v19.2 (decisions G1, K8).

## M2 — Neo4j temporal knowledge graph — done

> The figures in this section were measured on the first (clean) dataset. Output: `evaluation/results/m2_build_clean.txt`. Figures on the current noisy dataset are in the M3 section.

Built: schema and ontology (`knowledge_graph/ontology/`), idempotent loader, 20 reusable Cypher files (`knowledge_graph/queries/`), incident inference (`temporal/incidents.py`), `get_trajectory()` returning contract 3 (`temporal/trajectory.py`), evaluation against `incidents.json` (`evaluation/incident_match.py`), one entry point (`python -m knowledge_graph.build [--reset]`).

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

Window sweep (5, 15, 30, 60, 120 min) for both filters is in `m2_build_clean.txt`.

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

## M3 — deterministic ATT&CK mapper — done (numbers corrected after review)

Built: `core/attack_mapper.py` (rules, no labels, no LLM), `core/environment.py` (asset inventory), `data/mitre/fetch.py` plus extracts of real MITRE ATT&CK v19.2 (697 techniques, 176 groups, 15 tactics), `evaluation/mapper_eval.py`. Output: `evaluation/results/m3_mapper.txt`, `m3_build.txt`.

ATT&CK v19.2 differs from older releases: Defense Evasion is split into Stealth and Defense Impairment, and `T1070.001` is revoked in favour of `T1685.005`. The generator and mapper use the current ids.

### Mapper accuracy: old inflated figure and corrected figures

Exact technique per event, micro-averaged. "Noisy" is the rebuilt dataset and the one to quote.

| Version | Dataset | Seeds | Precision | Recall | F1 |
|---|---|---|---|---|---|
| First mapper (**inflated, do not quote**) | clean | 42 only | 0.947 | 0.964 | 0.955 |
| First mapper, reviewer's re-run | clean | 12 others | 0.905 mean | 0.921 mean | 0.913 mean (0.886–0.948) |
| Corrected mapper | clean | 13 | 0.916 mean | 0.876 mean | 0.895 mean (sd 0.027, 0.842–0.935) |
| **Corrected mapper** | **noisy** | **42 (dataset on disk)** | **0.587** | **0.880** | **0.705** |
| **Corrected mapper** | **noisy** | **13** | **0.564 mean (sd 0.030)** | **0.887 mean (sd 0.026)** | **0.689 mean (sd 0.027, 0.643–0.755)** |

The drop from 0.955 to 0.689 F1 is almost entirely precision: 0.947 to 0.564. Recall fell from 0.964 to 0.887. Other noisy-profile figures over 13 seeds: detection (flagged at all vs labelled attack) precision 0.610, recall 0.959; micro F1 without brute force 0.562; macro F1 over all techniques 0.548.

Where the precision goes (13 noisy seeds pooled, true / false positives): SMB lateral movement 57 / 731, `cmd.exe` 0 / 305, exfiltration from a server 159 / 250, Office-then-script 73 / 196, PowerShell 386 / 191, copy tools 144 / 139, `7z.exe` 0 / 156, brute force 1,341 / 132. Full table in `m3_mapper.txt`.

What changed between the old and corrected figures:
1. **Multi-seed evaluation.** 13 generator seeds, both profiles, mean and spread.
2. **Exfiltration rule.** No longer uses addresses seen at earlier attack steps. It needs an outbound connection to a destination new to the organisation, from a server or outside business hours. **Volume and port could not be used: contract 1 has neither field, and I did not change a frozen contract.** T1041 recall over noisy seeds is 0.851 mean (0.708–1.000); the server sub-rule has 39% precision; the off-hours sub-rule has no false positives only because benign staff never work nights in this data.
3. **Noisier benign data** (generator `noisy` profile, now the default; `--profile clean` reproduces the first dataset byte-for-byte): staff PowerShell/cmd, SMB shares, UAC prompts, copy and archive tools, home logons, one-off websites, lockout bursts; admin uses Office and can be the victim; servers make legitimate outbound connections; most mail is internal; attacker addresses are unique per incident.

Still true after the fixes: the same author wrote the rules, the generator and the noise. These figures are not real-world detection accuracy.

### Incident inference on the noisy dataset (24 true incidents, window 30 min)

| Filter | Inferred | No attack event | Incident precision | Exact | Trajectory correct, GT techniques | Trajectory correct, mapper techniques (end to end) | Mean coverage | Attack-pair F1 |
|---|---|---|---|---|---|---|---|---|
| heuristic (label-free) | 350 | 320 | 0.086 | 3 / 24 | 7 / 24 | 3 / 24 | 0.817 | 0.835 |
| **mapper (label-free, default)** | 53 | 22 | 0.585 | 9 / 24 | 12 / 24 | **5 / 24** | 0.792 | 0.917 |
| labels (leakage, upper bound) | 31 | 0 | 1.000 | 15 / 24 | 15 / 24 | 6 / 24 | 0.849 | 0.923 |

For comparison, on the clean dataset with the first mapper the mapper filter gave 26 incidents, none false, and 14 / 24 end-to-end trajectories. The honest end-to-end figure is now 5 / 24.

Two reasons beyond the mapper: this draw has 9 slow-paced incidents (the clean draw had 4), which fragment at a 30-minute window even with perfect labels (15 / 24); and the mapper's false positives create 22 incidents with no attack in them. At a 60-minute window the mapper filter reaches 14 exact and 9 end-to-end, but the default was not changed after the fact (decision K11).

Graph on the noisy dataset: 3,986 events, 10 users, 11 devices, 167 IPs, 25 processes, 19 techniques, 11 tactics; 434 incidents across the three filters; 687 `MAPS_TO` edges (275 ground truth, 412 mapper).

Review: 3 Blocking (all fixed), 8 Should-fix (7 fixed). See `REVIEWS.md`.

TODOs carried forward:
- Mapper precision: staff SMB to the file server, `cmd.exe`, server egress and `7z.exe` are the biggest false-positive sources. Not tuned on purpose (decision A12).
- Mapper keeps one session per `(user, device)`; a concurrent attacker and administrator on one host are confused.
- Brute-force burst key is `(source, host)`; password spraying across hosts is missed.
- Benign off-hours activity does not exist in the data, which flatters the off-hours exfiltration sub-rule.
- `INTERNAL_PREFIX` is duplicated in `core/environment.py` and `knowledge_graph/config.py`.

## M4 — historical attack database and similarity — done

Built: `prediction/historical.py` → `data/mitre/historical_attacks.json` (167 MITRE groups with inferred order, 11 hand-written sequences), `prediction/similarity.py` (`match_historical`, contract 4), `evaluation/similarity_eval.py`. Output: `evaluation/results/m4_similarity.txt`.

| Measure | Result | Sample |
|---|---|---|
| Top match is the pattern's own reference, complete ground-truth trajectories | 17 / 18 | A–C incidents |
| Same, pipeline trajectories | 12 / 18 | A–C incidents |
| Same, attack still in progress (strict prefixes) | 34 / 66 | prefixes of A–C incidents |
| Top match is a hand-written sequence | 24 / 24 | all ground-truth incidents |
| Pattern D best similarity | 0.343–0.550; 0.225–0.278 without the 4 overlapping distractors | 6 incidents |
| Attack-free inferred incidents with similarity ≥ 0.5 | 3 / 22 (max 0.667) | pipeline false incidents |

What this means:
- **All matching signal comes from the 11 hand-written sequences**, written by the author of the generator. The real MITRE group records never win on complete trajectories: they are too long (median 17 techniques) to score against a 4–6 step incident.
- **Matching an attack in progress is weak** (34 / 66): the score divides by the longer sequence, so short group records outrank the true reference early on.
- **Pattern D is not really novel**: no single record equals it, but its parts are in the distractors.
- **Brute-force skew: none.** T1110 is 41.5% of attack events but 6 of 114 trajectory steps after collapsing; D-to-other similarity is 0.090 per event and 0.135 collapsed.

Review: 0 Blocking, 7 Should-fix (6 addressed, 1 TODO).

TODO: prefix-aware similarity for in-progress incidents; a containment measure or separate reporting for group records.

## M5 — Markov prediction and evaluation harness — done (numbers corrected after review)

Built: `prediction/markov.py` (`predict_next`, contract 5 with a count-based evidence list), `prediction/static.py` (order-free comparison model), `evaluation/prediction_eval.py`. Output: `evaluation/results/m5_prediction.txt`.

Next-step prediction on ground-truth trajectories, 90 instances from 24 incidents:

| Training data | Top-1 | Top-1 tie-aware | Top-3 | MRR | Correct |
|---|---|---|---|---|---|
| No knowledge (uniform over 222 techniques, analytic) | 0.005 | 0.005 | 0.014 | 0.027 | – |
| Most frequent next step, no context | 0.178 | 0.178 | 0.478 | 0.384 | 16 / 90 |
| MITRE groups only | 0.000 | 0.000 | 0.000 | 0.050 | 0 / 90 |
| **Default: hand-written sequences** | **0.722** | **0.676** | **0.789** | **0.752** | **65 / 90** |
| Groups + hand-written pooled | 0.311 | 0.286 | 0.411 | 0.423 | 28 / 90 |
| Hand-written minus own family's reference (**unseen pattern**) | **0.278** | 0.261 | 0.444 | 0.357 | 25 / 90 |
| Hand-written minus the 4 distractors overlapping D | 0.578 | 0.556 | 0.622 | 0.618 | 52 / 90 |
| Other incidents only, leave-one-out | 0.811 | 0.800 | 0.833 | 0.822 | 73 / 90 |
| Other families' incidents only | 0.078 | 0.047 | 0.189 | 0.143 | 7 / 90 |

How to read it:
- **0.722 is mostly memorisation.** Base incidents (verbatim copies of a training sequence): 42 / 45. Variants: 23 / 45.
- **For a pattern the history has not seen, top-1 is 0.278**, and 0 / 18 and 0 / 24 for patterns A and C.
- **Pattern D scores 14 / 24 only because of the distractors**; 0 / 24 without them.
- **MITRE group data contributes nothing** to prediction (0 / 90 alone; harmful when pooled).
- **Strict end-to-end** (label-free pipeline, counted against all 90 true transitions): **33 / 90 = 0.367**. The pipeline reproduced the true path up to the prediction point for 47 of the 90.

Figures that were wrong before the review and are now removed: "leave-pattern-out with history 0.744" (the held-out pattern's reference was still in the training data; corrected 0.311), and the pipeline table presented as accuracy (it measures agreement with the mapper's own next label: 33 / 70).

Review: 4 Blocking (all fixed), 6 Should-fix (all addressed).

TODO: the cached default predictor is not refreshed when the historical database is rebuilt in a running process.

## M6 — the three experiments — done

Run with `python -m experiments.run_all`. Reports and CSVs: `experiments/results/e1.md`, `e2.md`, `e3.md` plus one CSV per table. Sample throughout: 24 synthetic incidents from 4 templates; 90 next-step instances on ground-truth trajectories.

**E1 — does historical knowledge improve prediction?** Only when the history already contains the attack.

| Condition | Top-1 | Correct |
|---|---|---|
| No knowledge (analytic chance) | 0.005 | – |
| Most frequent next step among other incidents | 0.156 | 14 / 90 |
| History = hand-written sequences (contains the A–C templates) | 0.722 | 65 / 90 |
| History = MITRE groups only | 0.000 | 0 / 90 |
| History with the tested pattern's reference removed | 0.278 | 25 / 90 (A 0/18, B 11/24, C 0/24, D 14/24) |
| …and with the distractors overlapping D removed | 0.133 | 12 / 90 |
| Sibling incidents available, without / with history | 0.811 / 0.811 | 73 / 73 of 90 |
| Strict end-to-end, label-free pipeline, default history | 0.367 | 33 / 90 |

E1 does **not** show that history helps on unseen attacks, and says nothing about independently sourced threat intelligence.

**E2 — does temporal order improve matching and prediction?** Not matching; prediction only when a memorised sequence can be replayed.

- Matching: own reference is the unique top match for 17 / 18 incidents static and 17 / 18 temporal (pipeline: 10 / 18 both). **No improvement.**
- Prediction with the reference in the history: Top-1 65 vs 30 of 90 in favour of temporal, but Top-3 0.789 vs 0.800.
- Prediction with the reference removed: 25 vs 24 of 90, no difference; static has the higher MRR (0.378 vs 0.357).
- On pipeline trajectories temporal has the higher Top-3 in 0 of 4 training conditions, and is worse on every metric with pooled group data (12 vs 17 of 70).

**E3 — known vs variant vs novel.** Works on ground truth, not on the pipeline.

| Input | Correct (leave-one-out thresholds) | Majority baseline | Novel taken for a match | Attack-free incidents taken for a match |
|---|---|---|---|---|
| Ground-truth trajectories, order-aware score | 22 / 24 | 9 / 24 | 0 / 6 | – |
| Ground-truth trajectories, order-free score | 24 / 24 | 9 / 24 | 0 / 6 | – |
| Pipeline trajectories, order-aware score | 13 / 24 | 9 / 24 | 2 / 6 | 3 / 22 |
| Pipeline trajectories, order-free score | 12 / 24 | 9 / 24 | 2 / 6 | 2 / 22 |

"Known" scores 1.000 by construction (verbatim copies of references). On ground truth the order-aware score is worse than the order-free one (22 vs 24).

Review: 2 Blocking (both fixed; they were unsupported or missing sentences, not wrong numbers), 7 Should-fix (all fixed).

## M7 — agent tool layer and Agent 2 — done

Built: `agents/tools/` (the five tools, typed against the contracts), `agents/contracts.py` (contracts and the evidence-bundle types), `agents/investigation_agent/` (the tool-calling loop, the offline scripted policy, a Claude adapter). Run: `python -m agents.investigation_agent <incident_id>`.

- The model only chooses which tool to call. Matching and prediction run on the trajectory the graph returned; the bundle is built by code from tool results; the model's text is confined to `agent_notes`.
- Default is the offline scripted policy (deterministic, no credentials). On the loaded graph it runs on all 53 inferred incidents; 19 reach a prediction.
- **The Claude adapter has never been run against the real API** (no key, package not installed). It is tested only against a stand-in module.
- Tests: 26 in `tests/test_agents.py`, including mock models that supply their own trajectory, put a false claim in an extra argument, invent tool names, never stop, flood one turn with calls, or crash mid-run.

Review: 1 Blocking (fixed: model-written strings could reach the step log), 11 Should-fix (all addressed).

## M8 — FastAPI endpoints, Agents 1 and 3 — done

Built: `backend/api/main.py` and `schemas.py` (eleven endpoints, Pydantic models mirroring the five contracts), `agents/log_agent/` (Agent 1: deterministic ingest), `agents/explanation_agent/` (Agent 3: template report), `backend/README.md` (endpoint documentation for the frontend team). Real responses from a running service: `evaluation/results/m8_api.txt`.

- All eight endpoints you listed return real data, plus `/health`, `/incidents` and `/technique/{technique_id}`. The service starts with `cd backend && uvicorn api.main:app`.
- On the bundled dataset: 53 incidents served; contracts 1, 3, 4 and 5 verified field-for-field by the reviewer across all 53.
- `POST /logs` is one transaction (events, mappings and incidents commit together); a one-event ingest took 0.2 s on this machine.
- No authentication (optional `API_TOKEN` for `POST /logs`), no pagination, no raw-log parsing.

Review: 6 Blocking (all fixed; five were in `POST /logs` and `/health`, one was a false "first seen" in the report), 9 Should-fix (8 fixed, 1 partly).

TODOs carried forward:
- No request byte limit; every ingest re-maps the whole graph; an ingest can change which hosts count as hubs and so regroup existing incidents.
- The ingest lock is per process; run a single worker.
- `/docs` needs internet access (Swagger UI from a CDN).
