# Progress

Last updated after Milestone 8. Branch `backend-milestones`, eight commits ahead of `main`, nothing pushed. 119 tests pass. Every number below was produced by code in this repository; the file that holds it is named next to it. Decisions are in `DECISIONS.md`, reviews in `REVIEWS.md`.

## Summary

### Status

| Milestone | Status | Reviewed | Committed |
|---|---|---|---|
| M1 synthetic data generator | done | within M2/M3 reviews | yes |
| M2 Neo4j temporal knowledge graph | done | yes | yes |
| M3 rule-based ATT&CK mapper | done, numbers corrected | yes | yes |
| M4 historical database and similarity | done | yes | yes |
| M5 Markov prediction and harness | done, numbers corrected | yes | yes |
| M6 experiments E1, E2, E3 | done | yes | yes |
| M7 agent tools and Agent 2 | done | yes | yes |
| M8 FastAPI endpoints, Agents 1 and 3 | done | yes | yes |
| **M9 real-data validation** | **pending, high priority** | – | – |
| **M10 experiment redesign** | **pending** | – | – |
| Harder synthetic dataset with overlapping incidents | not started | – | – |

`frontend/` was never touched.

### The numbers that matter

Sample: one synthetic dataset (noisy profile, seed 42): 3,986 events, 24 attack incidents from 4 templates, 90 next-step instances. The mapper is also scored on 13 generator seeds.

| What | Result | Where |
|---|---|---|
| Mapper, exact technique, micro F1, 13 seeds | 0.689 mean (sd 0.027, range 0.643–0.755); precision 0.564, recall 0.887 | `evaluation/results/m3_mapper.txt` |
| Mapper, first version on clean data (**inflated, kept for the record**) | 0.955 | `evaluation/results/m3_mapper_v1_clean.txt` |
| Incidents inferred by the label-free pipeline | 53, of which 22 contain no attack | `evaluation/results/m3_build.txt` |
| True incidents reproduced event-for-event | 9 / 24 | same |
| True trajectories reproduced end to end | 5 / 24 (with ground-truth labels as an upper bound: 15 / 24 grouped) | same |
| Matching: right reference on top, complete trajectories | 17 / 18 | `evaluation/results/m4_similarity.txt` |
| Matching: right reference on top, attack in progress | 34 / 66 prefixes | same |
| Prediction top-1, history contains the attack's template | 0.722 (65 / 90); base 42 / 45, variants 23 / 45 | `evaluation/results/m5_prediction.txt` |
| Prediction top-1, attack not in the history | 0.278 (25 / 90); 0.133 (12 / 90) without overlapping distractors | `experiments/results/e1.md` |
| Prediction top-1, most-frequent-next-step baseline | 0.156 (14 / 90) | same |
| Prediction top-1, MITRE group data alone | 0.000 (0 / 90) | same |
| Prediction, strict end to end | 0.367 (33 / 90) | `evaluation/results/m5_prediction.txt` |
| E3 known / variant / novel, ground truth | 22 / 24 (order-free score: 24 / 24) | `experiments/results/e3.md` |
| E3 known / variant / novel, pipeline | 13 / 24 against a 9 / 24 majority baseline | same |

### What the results say

1. **The deterministic core works as software**: graph, inference, matching, prediction, agents and API are built, tested, reviewed and reproducible from scratch.
2. **The headline accuracy figures do not survive honest conditions.** The mapper lost a third of its F1 once benign activity looked like real work. End to end, 5 of 24 trajectories are reproduced.
3. **All three experiments are negative or uninformative as designed.** History helps only when it contains the same sequence (memorisation); below that it is under the frequency baseline. Order does not improve matching, and improves prediction only by replaying a memorised sequence. Known/variant/novel separates on ground truth only because "known" incidents are verbatim copies.
4. **Real MITRE group data contributes nothing with this method.** The groups do use this dataset's techniques (between 22 and 124 of 167 groups use each one), so the cause is not missing vocabulary: ATT&CK publishes technique sets without order, and an order inferred from tactic and id yields artificial transitions.
5. **Everything is measured against data, rules, noise and reference sequences written by one author.** None of it is evidence about real logs. That is what M9 is for.

### Decisions made on your behalf that you may want to reverse

Full list in `DECISIONS.md`. The ones with consequences:

- Work is on branch `backend-milestones`, not `main` (P1).
- The generator's default is now the noisy profile; `--profile clean` reproduces the first dataset (A11).
- Exfiltration rule rewritten without attacker-address knowledge; **volume and port were not used because contract 1 has neither field** (A8).
- Mapper rules were deliberately not re-tuned against the noise (A12).
- The 30-minute incident window was kept although 60 scores higher on the noisy data (K11).
- The default predictor ignores MITRE group records (R5).
- Model-facing agent tools take an incident id, not a trajectory, unlike the tool table (T1).
- Agent 2 defaults to an offline scripted policy; the Claude adapter is included but **has never been run against the real API** (T3).
- Agents 1 and 3 are deterministic (rules and a template), with no language model (B4, B5).
- `POST /logs` takes Normalized Events only; raw-log parsing is not built (B3).

### Blockers

None that stopped work. Two things could not be done:

- **Claude adapter untested**: no API key and the `anthropic` package is not installed.
- **Volume- and port-based exfiltration rule**: needs fields that the frozen contract 1 does not have. If you want it, contract 1 needs `bytes_out` and `destination_port` by team agreement.

### Open TODOs (all from reviews)

Graph and inference:
- Hub suppression is a global distinct-user count; an ingest can flip a host to "hub" and regroup existing incidents.
- Slow-paced incidents (steps 15–45 minutes apart) fragment at the 30-minute window.
- `INTERNAL_PREFIX = "10."` is a string prefix, duplicated in two modules.

Mapper:
- Largest false-positive sources: staff SMB to the file server, `cmd.exe`, server egress, `7z.exe`.
- One session per `(user, device)`; password spraying across hosts is missed; no benign off-hours activity exists in the data.

Matching and prediction:
- Similarity is not prefix-aware, so in-progress attacks match poorly.
- The default predictor is cached and not refreshed if the historical database is rebuilt in a running process.

API:
- No request byte limit; every ingest re-maps the whole graph; single-process ingest lock; `/docs` needs internet.

### What I would do next

1. **M9**, because nothing so far says anything about real logs.
2. **M10**, because the experiments cannot give a positive or a meaningful negative answer in their current design.
3. Before either: decide whether contract 1 gains `destination_port` and a byte count. Real Sysmon and firewall data have them, and the exfiltration rule needs them.
4. Run Agent 2 once with a real key to check the Claude adapter.
5. Merge `backend-milestones` into `main` when you are happy with it.

## Pending milestones

### M9 — Real-data validation (HIGH PRIORITY) — pending

**What.** Validate the pipeline on OTRF Security-Datasets (github.com/OTRF/Security-Datasets): real host telemetry in JSON, each dataset mapped to ATT&CK techniques and tactics, with benign events from the same capture window. The synthetic dataset stays as the controlled benchmark; real data is added as external validation, not as a replacement.

**Needs.**
- An adapter from Sysmon / Windows Event Log fields into contract 1, without changing the contract.
- Mapper rules for real event types.

**Why (the motivation to keep).** Every figure in this file is measured against synthetic data whose benign activity, attack templates, mapper rules, noise and historical reference sequences were all written by the same author. The M3 review showed how much that flatters: mapper F1 went from 0.955 to 0.689 just by making benign staff behave more like real users, and the remaining rules are still scored against that author's idea of noise. Nothing here is evidence about real logs until it is run on logs someone else captured and labelled.

**Notes for whoever starts it** (not yet verified against the repository; check before relying on them):
- Confirm the dataset format, how technique labels are attached (per dataset or per event) and whether benign events are really present in the same capture.
- Real Sysmon events carry parent process, command line, ports and more. Contract 1 has none of these, so the adapter will discard most of the signal a real detection rule uses. Expect this to be the main finding, and consider it alongside the open question on extending contract 1.
- The current mapper keys on this bank's inventory (`core/environment.py`) and on action names the generator invented (`rdp_session`, `smb_session`, `privilege_change`). The adapter has to produce those from event ids and logon types, or the rules have to change.
- If labels are per dataset rather than per event, mapper precision cannot be scored per event the way it is now; plan the metric first.

### M10 — Experiment redesign — pending

**What.** Redesign the dataset and the historical database so E1, E2 and E3 can discriminate.

**Needs.**
- 15–20 attack templates with graded similarity to each other, instead of 4.
- A historical database that shares our technique vocabulary and carries usable order.
- E3's known-class incidents changed from verbatim copies to perturbed instances.

**Why (the motivation to keep).** E1, E2 and E3 all came back negative because 24 incidents from only 4 templates give no "similar but not identical" condition. History either contains the exact sequence (memorisation: top-1 0.722, with verbatim base incidents at 42 / 45) or something unrelated (0.133, below the 0.156 frequency baseline). There is nothing in between, so the experiments cannot show a graded benefit even if one exists. E3's "known" class scores 1.000 by construction because its incidents are copies of the reference sequences.

**One correction to the reasoning as recorded.** The MITRE group records do not score 0.000 because of a vocabulary mismatch. They use this dataset's techniques widely: each of the 14 parent techniques appears in between 22 and 124 of the 167 groups (`evaluation/results/m4_similarity.txt`). They score 0.000 because ATT&CK publishes unordered technique sets, and the order we infer from tactic position and technique id produces transitions that are an artefact of sorting. So a redesigned historical database needs **observed order**, not only shared vocabulary; sources with real sequences (incident reports, the ordered procedure examples in ATT&CK campaigns, or OTRF's own simulation plans from M9) would address the actual cause.

**Notes for whoever starts it.**
- Patterns that use the same techniques in different orders are needed for E2; today's patterns already differ as sets, so order cannot matter for matching.
- Distractors and references should come from a source independent of the generator's author. Pattern D's "novel" score rested entirely on overlapping hand-written distractors (14 / 24 with them, 0 / 24 without).
- Keep the protocols already built (`no_own_reference`, `leave_family_out`, tie-aware top-1, strict end-to-end); they are what exposed the problems and will work unchanged on a larger template set.
- More templates also means more than 24 incidents; decide the sample size needed for the differences you want to detect before generating.

---

Per-milestone entries follow, oldest first.

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

## Contract change: `destination_port` and `byte_count` — done

Contract 1 gained two optional, nullable fields (`docs/data-contracts.md`). The generator, graph, API schema, types and mapper use them; both generator profiles are otherwise identical to the earlier datasets, field by field. Everything was regenerated from scratch; 121 tests pass.

Effect of the new exfiltration rule (at least 20 MB sent externally, plus one unusual property), noisy profile, 13 seeds:

| | Before (no volume or port) | After |
|---|---|---|
| Mapper micro precision | 0.564 | 0.585 |
| Mapper micro recall | 0.887 | 0.893 |
| Mapper micro F1 | 0.689 (sd 0.027) | 0.706 (sd 0.027, range 0.665–0.774) |
| T1041 recall | 0.851 | 0.933 |
| T1041 rule precision, pooled | server sub-rule 0.389 | volume rule 0.778 (259 true, 74 false) |

Before: `evaluation/results/m3_mapper_v2_noisy.txt`. After: `evaluation/results/m3_mapper.txt`.

Downstream on seed 42: ground-truth results are unchanged. The label-free pipeline now infers 51 incidents (20 with no attack, was 53 and 22), reproduces 5 / 24 trajectories end to end (unchanged), and E3 on pipeline trajectories is 14 / 24 (was 13 / 24). The 20 MB threshold and the generator's byte counts were chosen by the same author, so this gain is not evidence about real traffic.

## M9 — real-data validation — done

Full write-up: `docs/real-data.md`. Results: `evaluation/results/m9_real_data.txt`, `m9_real_data_apt29.txt`. Code: `data/adapters/otrf.py`, `data/adapters/apt29.py`, `data/adapters/survey.py`, `evaluation/real_data_eval.py`, `evaluation/real_data_apt29.py`, `core/environment.py`, and 23 tool rules plus one file-name rule in `core/attack_mapper.py`.

> **Headline future-work finding.** Contract 1 must carry process lineage (parent process, command line) and process-access targets to represent host-level behavioural techniques; without them, endpoint credential-access attacks are invisible after normalization. The contract was deliberately not expanded in this milestone.

Data: seven OTRF LSASS-dumping captures (MIT licence), 354,229 raw events, one Windows host each, 10–14 minutes each. **Labels are per dataset, not per event, and unordered.** The synthetic benchmark is unchanged and remains the controlled benchmark.

| What | Real data (7 LSASS datasets) | Synthetic, pipeline output |
|---|---|---|
| Events representable in contract 1 | 213,818 of 354,229; 202,193 of those are process-access events that lost their target | all |
| **Mapper, technique set per dataset** | **precision 0.388, recall 0.422, F1 0.404** (45 labelled pairs) | F1 0.882 on the same set measure (n = 1) |
| Mapper per event | cannot be measured (no event labels) | F1 0.706 mean over 13 seeds |
| The technique every dataset is about (T1003.001) | found in **1 of 7** | – |
| Exfiltration (T1041) | 0 of 6; no outbound byte count was actually measured by the capture | recall 0.933 |
| Incidents kept apart, 30-minute window | 2 of 7 captures in a composed timeline; fragile to placement | 8 of 24 reproduced exactly |
| Pipeline trajectory length | 4–116 steps | 1–8 steps |
| Best historical similarity | 0.20–0.25, always a MITRE group record | 1.0 for 3 of 51 inferred incidents |
| Prediction | cannot be scored (labels have no order); outputs are generic | strict end-to-end top-1 0.367 |

Corrected after review: the first version reported F1 0.421 and T1041 in 1 of 6. That one hit rested on a byte count Zeek had estimated from a sequence gap, not observed; with it removed the figure is 0.404.

**What the false positives are.** 252 of the 288 mapped events (87%) come from the operator stopping the packet capture at the end of each recording, which makes Windows run a diagnostic script under the attacker's account. Without that activity precision would be 0.679 (F1 0.521), but the pipeline cannot tell it apart, so 0.388 stays the headline. Either way this data says little about normal background noise.

**Multi-step retry (time-boxed, one dataset).** `apt29` day 1: four hosts, a 25-step emulated intrusion, 196,081 events. It validated **worse**, not better: 1 of 31 labelled techniques found (F1 0.057 exact, 0.125 at parent level), a 5-step trajectory against a 45-step plan. The intrusion happens inside PowerShell sessions, whose content contract 1 cannot hold. One thing did work: the single inferred incident spans two hosts through the shared account. As instructed, work stopped there; the LSASS figures stay as the real-data result. The retry was not separately reviewed.

What works: the adapter, graph load, the mapper on techniques that are a program name (T1082 7/7, T1033 7/7), cross-host grouping by account.

What degrades: trajectories (capture teardown; alternating techniques defeat the collapse of repeats); hub suppression (every host counts as shared infrastructure because of built-in system accounts).

What breaks: any technique that is a behaviour rather than a program name; historical matching; prediction; incident separation when one account is active on several hosts within the window.

What real data could not tell us: per-event accuracy, anything about order, false-alarm rate under normal use, exfiltration detection, and anything about the synthetic attack patterns (valid accounts, brute force, lateral movement and collection do not occur in the LSASS datasets).

Review: 4 Blocking (all fixed; one lowered the headline), 8 Should-fix (all addressed).

TODOs carried forward:
- **Extend contract 1** with parent process, command line and process-access target (the headline finding), then redo this milestone.
- Hub suppression should not count built-in system accounts as users.
- The graph's `IP.internal` flag uses the bank's prefix whatever dataset is loaded.
- Use the ordered command transcript in each LSASS metadata file as an order label.
- Map the 13 unmatched apt29 technique names with MITRE's published crosswalk.

## M10 — experiment redesign — built, reviewed, review fixes applied (docs partly pending)

**Status note (work was cut off by a usage limit here).** The M10 review found 2 Blocking and 11 Should-fix items. The code and result files below already include the fixes (dataset regenerated so that two-edit instances really need two edits; extra rows, per-step and per-template tables, held-out sensitivity, corrected labels and wording). Still to do: copy the review into `REVIEWS.md`, update `DECISIONS.md` X8, rewrite the summary at the top of this file (it still lists M9 and M10 as pending and has stale numbers), and Task 3 (verify Agents 1 and 3).

Reports: `experiments/results_graded/e1.md`, `e2.md`, `e3.md` (+ CSVs). First experiments kept in `experiments/results/`. Code: `experiments/graded.py`, generator profile `graded`, `data/mitre/emulation_plans.json`.

Reproduce: `python data/generator/generate.py --profile graded`; then with `VIRUX_DATASET=graded`: `python -m core.attack_mapper`, `python -m knowledge_graph.build --reset`, `python -m experiments.graded`; then `python -m knowledge_graph.build --reset` without the variable to restore the default graph.

Dataset: 17,707 events, 90 incidents from 18 templates (1 exact, 2 one-edit, 2 two-edit each), 31 techniques, 399 next-step instances. History: template references (leave-own-out) and 8 real ordered emulation plans. No hand-written distractors.

| | First experiments (24 incidents, 90 instances) | Redesigned (90 incidents, 399 instances) |
|---|---|---|
| E1 context-free frequency prior | 0.156 (14 / 90) | 0.138 (55 / 399), built from the other templates |
| E1 related, not identical history | 0.278, from overlapping distractors | **0.323 (129 / 399)**; 69 / 399 with the whole own family removed |
| E1 own template in history | 0.722 (65 / 90) | 0.416 (166 / 399) |
| E1 real independent history | MITRE groups 0.000 | real ordered plans 0.073 (29 / 399); groups 0.020 |
| E2 matching, static vs temporal | 17 vs 17 of 18 | 69 vs 69 of 70 outside the reordered pairs; 0 vs 12 of 20 on them |
| E2 prediction top-1, static vs temporal | 24 vs 25 of 90 | 108 vs 129 of 399 |
| E3 ground truth, order-aware / order-free | 22 / 24 and 24 / 24 | 60 / 78 and 38 / 78 (baseline 30) |
| E3 pipeline | 14 / 24 | 30 / 78, equal to the baseline |

**Does context help?**
- **Historical: only in-vocabulary history written by the same author.** 129 against 55 of 399 (against 71 for the prior that never repeats a step). Gain over the prior by step predicted: +37, -2, +3, +12, +24, so it is not concentrated in the entry steps; with the own family removed the gain is +14. It does not grow steadily with similarity, and history hurts 3 templates (G12, G13, G16). **Real emulation plans do not help**: 29 / 399 alone, and they lower 129 to 116 when added. *(An earlier version of this bullet said the gain was mostly replay of entry sequences, citing 80 of 129 hits at steps 2-3; the review showed the prior already gets 45 of those 80.)*
- **Temporal: order separates attacks with identical technique sets (by construction) and gives a modest top-1 gain (129 vs 108).** No matching gain elsewhere; second-order context adds nothing (order 1 alone: 135).
- **E3:** unrelated attacks are recognised as novel (15 / 15), near relatives are not (4 / 15); known vs variant is close to arithmetic on edit count; nothing holds on the pipeline.

Mapper on the graded dataset: precision 0.496, recall 0.740, F1 0.594 (`evaluation/results/graded/mapper.txt`). The pipeline rows are weak for three reasons, not only missing tool rules: unknown tools, techniques whose events look identical to another's, and one program carrying two labels; incident fragmentation matters as much.
