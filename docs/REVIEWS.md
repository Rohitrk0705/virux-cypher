# Milestone reviews

No `milestone-reviewer` agent is defined, so each review was done by a separate
general-purpose subagent with a fixed brief: review only, no edits; check
correctness, ground-truth leakage, contract conformance, honesty of metrics and
reproducibility of the captured output; report findings as Blocking /
Should-fix / Nits with file:line, evidence and a suggested fix.

Findings are reproduced as the reviewer wrote them. What was done about each
is listed under "Resolution" after each review.

---

## M2 — Neo4j knowledge graph

### Blocking

**1. `knowledge_graph/loader.py:22` (`reset`) crashes, and `knowledge_graph/queries/load_events.cypher:9-20` is not a true upsert, so there is no working way to get a clean graph.**
- `reset()` runs `CALL (n) { ... } IN TRANSACTIONS` through `driver.execute_query`, which uses a managed (explicit) transaction. A read-only query of the same shape through `connection.run_text` gave `Neo.DatabaseError.Transaction.TransactionStartFailed: A query with 'CALL { ... } IN TRANSACTIONS' can only be executed in an implicit transaction`. So `python -m knowledge_graph.build --reset` fails.
- The loader MERGEs edges but never removes old ones. Regenerate with another seed (the same `evt-00001…` ids get different content) and reload: each event keeps its old `PERFORMED`/`OCCURRED_ON`/`INVOLVES`/`EXECUTED` edges plus the new ones. Events then have two users and two source IPs, hub counts and incidents are silently wrong, and `incident_events.cypher` returns duplicate rows.
- "Loading the same files twice leaves the graph unchanged" holds only for identical files.
- Fix: run reset via an auto-commit session or a plain batched delete loop. In `load_events`, delete the event's existing entity edges before MERGE. Add a test that loads a modified event and checks for a single user and source IP.

**2. `evaluation/incident_match.py:79-89` and `SUMMARY_COLUMNS`: `pairP = 1.000` / `pairF1 = 0.879` for the heuristic row is flattering.**
- Pairwise precision is computed over attack-attack pairs only. It can only drop when two different true incidents are merged, which the generator's separation almost rules out, so it is close to vacuous.
- For heuristic W=30 the same clusters hold 854 benign events against 249 attack events, and 253 of 279 inferred incidents contain no attack event at all (incident-level precision 26/279 = 9.3%).
- Counting pairs with at least one attack member gives precision 2042/(2042+209) = 0.907, not 1.000.
- The docstring says benign events are ignored, but the printed table and `m2_build.txt` do not.
- Fix: rename the columns, add a pair precision that counts benign co-members, add incident-level precision, and print a one-line caveat under the table.

### Should-fix

- **`knowledge_graph/build.py` LIMITATION text: "so no two attacks ever overlap" is inaccurate.** The generator separates only on shared user/device, not on IPs. True INC-002 (david) and INC-003 (priya) are 1759 s apart and share attacker IP 203.0.113.118; that is exactly the `merged = 1` at W=60/120.
- **`evaluation/incident_match.py:58-62`: best match by Jaccard is many-to-one.** At W=60/120 both INC-002 and INC-003 claim the same merged cluster and each gets coverage 1.0, inflating `coverage`, `exact` and `traj`. With zero overlap, `best` is an arbitrary cluster and `trajectory_match` could be true by coincidence. Fix: one-to-one assignment; force metrics to 0 when there is no overlap.
- **`evaluation/incident_match.py:64`: `fragments` undercounts.** It ignores attack events that are in no cluster. Evidence: labels W=30, INC-022 shows `cov 0.50, frag 1` although three steps are isolated singletons.
- **`candidates_heuristic.cypher` + `config.py`: the heuristic has a structural ceiling and is tuned to the generator, and neither is disclosed.** 25 attack events can never be candidates (all 19 T1005 `file_access`, all 6 T1204.002 Office executions). `ROUTINE_PROCESSES` is a verbatim copy of the generator's benign staff list. `WINDOW_MINUTES = 30` was chosen from the sweep on the same 24 incidents it is scored on. The "anything external" rule admits 558 benign web and 297 benign mail events (67% of the 1282 candidates).
- **`traj` column for the heuristic row uses ground-truth techniques**, so it measures grouping only; `DEFAULT_TECHNIQUE_SOURCE = ground_truth` becomes leakage once the API calls `get_trajectory` with defaults. Fix: label the column and switch the default to `mapper` in M3.
- **`mark_entities.cypher` + `HUB_USERS`: hub suppression is fragile and global.** Pattern-B grouping hangs on it: all three admin-switch B incidents attach the `admin_lee` SMB event to the victim's events only through the pivot IP, and 10.0.0.14 already has 3 distinct users against a threshold of 4. Attacker IPs 203.0.113.7 and 203.0.113.201 are flagged as hubs because they hit 4 victims. The count is over the whole dataset, so it is non-causal and grows with dataset length.
- **`temporal/incidents.py:68`: inferred ids are unstable and collide with the ground-truth namespace.** Ids are renumbered on every `materialize`, so they change with window, method and new data. Fix: a deterministic content-based id and a distinct prefix for ground truth.
- **`incident_events.cypher`: not ready for the `get_events` tool.** Returns `ts` (epoch) instead of `timestamp`; unused and untested.
- **`load_events.cypher`: a null `user`, `device` or `source_ip` makes MERGE throw and aborts the whole batch.**
- **Later-milestone risks.** `get_trajectory` on an unknown id returns an empty list, indistinguishable from a benign incident. Benign admin activity will get techniques from a rule-based mapper and pollute trajectories. There is no historical vs current split; with 24 incidents from 4 templates, matching and prediction will leak unless the split is designed.
- **`tests/test_graph.py`: the leakage test is a string check on one module.** `test_loader_is_idempotent` compares counts only and rewrites the live database.

### Nits

- `candidate_links.cypher` and `build_next.cypher` rely on `collect()` preserving a preceding `ORDER BY`; say so in a comment.
- `trajectory.cypher`: add `t.technique_id` to the ORDER BY.
- `build.py`: "24 true incidents" is hard-coded.
- `temporal/incidents.py`: clear, write and build-NEXT run as separate transactions, so an API reader can see an empty state.
- `config.py`: `INTERNAL_PREFIX = "10."` ignores 172.16/12 and 192.168/16.
- Mean purity is over the 24 best matches only; note that next to the `false` column.
- Heuristic coverage is partly due to benign events bridging gaps (in INC-015 the e-mail and the PowerShell step are joined only by three benign web connections).

### Reviewer verdict

Core mechanics correct and captured output reproducible (stats, hubs, all sweep rows and per-incident lines matched a read-only recomputation; linking query equals an independent Python reimplementation; NEXT edges and contract 3 verified; inference never reads `incidents.json`; the three admin-switch pattern-B incidents are joined via the pivot IP). Two things needed fixing before commit: the reset/upsert problem and the flattering pairwise precision.

### Resolution

| Finding | Status |
|---|---|
| Blocking 1: reset crashes, loader is not an upsert | **Fixed.** `reset()` is a batched delete loop. `load_events.cypher` drops an event's old entity edges before re-creating them; `test_reloading_a_changed_event_replaces_it` covers it. (The reset did run on the empty database in my first build; the reviewer's failure is on the newer `CALL (n)` form. Either way it is replaced.) |
| Blocking 2: flattering pairwise precision | **Fixed.** Attack-only pair metrics are renamed `atkP/atkR/atkF1`; `pairP` now counts benign co-members; `incP` (incident precision) added; column definitions are in the module docstring and referenced under the table. Heuristic W=30 now reads `incP 0.093`, `pairP 0.907`. |
| LIMITATION wording | Fixed (six numbered limitations printed under the table). |
| Many-to-one best match | Fixed: one-to-one greedy pairing; no overlap scores zero. |
| `fragments` undercounts | Fixed: `unassigned` reported per true incident. |
| Heuristic ceiling and tuning undisclosed | Disclosed in the printed limitations and in `PROGRESS.md`. The heuristic itself is unchanged. |
| `traj` uses ground-truth techniques | Column renamed `trajGT`; `trajMap` (mapper techniques, end to end) added; defaults switch to the mapper in M3. |
| Hub suppression fragile and global | **TODO** (see `PROGRESS.md`). |
| Unstable ids colliding with ground truth | Fixed: inferred ids derive from the earliest event (`INC-00138`); ground truth is `GT-001…`. |
| `incident_events.cypher` not contract 1 | Fixed: `get_incident_events()` wrapper returns contract 1, tested. |
| Null required fields abort a batch | Fixed: the loader rejects them in Python with a clear error. |
| Unknown id returns empty trajectory | Fixed: raises `LookupError`. |
| Weak leakage test | Fixed: query-text checks plus a test that heuristic output is identical with all mappings removed. |
| Nits | Done: `collect()` comment, ORDER BY tie-break, `len(truth)`. **TODO:** non-atomic materialize, `INTERNAL_PREFIX` as a string prefix. |

---

## M3 — deterministic ATT&CK mapper

Reviewed on the first mapper version, against the clean dataset.

### Blocking

**1. `evaluation/mapper_eval.py`, `evaluation/results/m3_mapper.txt`: the headline (micro P 0.947 / R 0.964 / F1 0.955) is a single-seed best case and is printed with no caveat.**
- Seeds 1–12 scored with the unchanged mapper in memory: micro F1 mean 0.913 (range 0.886–0.948), P mean 0.905 (0.882–0.937), R mean 0.921 (0.888–0.960). Seed 42 beats all 12.
- `7z.exe` is never drawn for T1005 at seed 42, so T1005 recall is 1.000; on other seeds it ranges 0.28–1.00 because the mapper sends `7z.exe` to T1560.001. Every T1041 destination happens to have logged in earlier; on other seeds T1041 recall ranges 0.79–1.00.
- The mapper report has no limitations block and does not say that the rules and the generator share an author.
- Fix: report mean/min/max over a fixed list of seeds and print a limitations block. Do not quote 0.955 alone.

**2. `core/attack_mapper.py` (T1041 "address that has logged in before"): 15 of 23 T1041 true positives depend on attacker IPs being reused across incidents.**
- All 23 hits fire the first sub-rule; only 8 of the 23 destinations logged in during the same incident. The other 15 match only because a different incident used that address earlier. The generator draws all attackers from 8 addresses.
- Counterfactual with unique addresses per incident: T1041 recall 0.652; micro P 0.945 / R 0.935 / F1 0.940; detection recall 1.000 → 0.971.
- The server fallback has zero false positives only because no benign server ever connects out.
- Fix: scope the context, report the sub-rules separately, state the dependence; ideally stop reusing a tiny attacker pool and add benign server egress.

**3. `core/attack_mapper.py`, `core/environment.py`: most rules reduce to "a non-admin did X", which separates perfectly only because of how the generator builds benign activity.**
- Benign staff run only 7 applications; they never produce `smb_session`, `rdp_session` or `privilege_change`, and never a `file_access` with a process. T1068 fires on any non-admin `privilege_change`.
- Counterfactuals (benign events edited, labels unchanged): 16 staff notepad launches turned into PowerShell/cmd → micro P 0.853, F1 0.905; 55 such launches → P 0.711; 10% of staff file-share accesses logged as `smb_session` → P 0.780, F1 0.862.
- The allow-list costs nothing because the admin is never the victim; a locally compromised admin workstation yields zero mappings.
- Fix: document as the dominant limitation, add benign noise to the generator (staff scripting, SMB, UAC, admin as victim), and re-report.

### Should-fix

- T1204.002 / T1566.001 look forward 60 minutes, which makes the mapper batch-only and is not in `DECISIONS.md`. Every Office launch in the hour before a script host is flagged; all mail in the dataset is external so "external" filters nothing. Tag only the nearest preceding Office launch.
- Session state: one session per `(user, device)`, last writer wins; TTL runs from session start; `logoff` never clears state; an admin on a server more than 4 hours after RDP is flagged; an attacker on WS-07 from an external address becomes "expected" after 4 hours. None of it tested.
- Macro average covers only the 15 labelled techniques, so false positives on never-labelled techniques are charged to no class (macro P 0.961 > micro P 0.947). Over all 18 classes macro is 0.801 / 0.752 / 0.757.
- T1110 is 120 of 276 labelled events and trivially separable; without it micro is P 0.907 / R 0.936 / F1 0.921.
- `DECISIONS.md` A2 is false for `7z.exe` at seed 42; A1 needs the caveat from Blocking 3; K8 is out of date.
- `PROGRESS.md` has no M3 entry and its M2 table no longer matches the graph.
- `data/mitre/fetch.py`: revoked chains are not resolved (three replacements are themselves not live).
- Tests: none for the TTL, T1041, T1005, T1068 or several Office launches.

### Nits

- Process matching is exact and lower-case; a full path maps to nothing.
- The burst key is `(source_ip, device)`, so spraying across hosts is missed.
- `core/environment.py` duplicates `INTERNAL_PREFIX`.
- `m3_mapper.txt` contains an absolute home path.
- Group techniques come from direct `uses` only, not via software; document it.
- The generator change and the M3 decisions are already in the M2 commit.

### Reviewer verdict

Clean, deterministic, contract-conformant, uses no labels, numbers reproduce. But 0.955 should not be trusted as an indicator of real-world performance: it is the best of 13 seeds, leans on attacker-IP reuse for 65% of its exfiltration hits, and nearly all its precision comes from the generator never letting ordinary staff do anything attack-like. Treat it as "the rules are implemented correctly against the author's own generator".

### Resolution

| Finding | Status |
|---|---|
| Blocking 1: single-seed headline | **Fixed.** `evaluation/mapper_eval.py` runs generator and mapper in memory for 13 seeds in both profiles and prints mean, standard deviation, min and max, a per-rule table, and a limitations block. |
| Blocking 2: exfiltration rule depends on attacker-IP reuse | **Fixed.** The rule no longer uses any address seen in an earlier logon. It now needs an outbound connection to a destination new to the organisation plus either a server source or off-hours. Contract 1 has no bytes or ports, so volume and port could not be used; a repeat-connection proxy for volume was tried and removed (20 true vs 909 false positives over 13 seeds). The noisy generator gives every incident its own attacker addresses and adds benign server egress. |
| Blocking 3: benign data too clean | **Fixed in the data, not in the rules.** The generator has a `noisy` profile (now the default): staff scripting, SMB shares, UAC prompts, copy tools, home logons, one-off websites, lockouts, admin Office use, admin as a possible victim, internal mail, benign server egress, unique attacker addresses. The `clean` profile reproduces the first dataset byte-for-byte. Rules were not re-tuned against the noise, apart from T1078 (first logon from an address for that user) and the removal noted above. |
| Forward-looking Office rule | Fixed: only the nearest preceding Office launch is tagged; recorded in `DECISIONS.md` A7. |
| Session state | Partly fixed: TTL removed, `logoff` clears the session, tests added. **TODO:** one session per `(user, device)`. |
| Macro average, T1110 weighting | Fixed: `macro_all` and "excluding T1110" are printed. |
| Docs out of date | Fixed in this pass. |
| Revoked chains | Fixed. |
| Tests | Added for T1041, T1005, T1068, T1078, logoff, several Office launches, process paths. |
| Nits | Done: process path/case, relative path in output. **TODO:** burst key misses spraying; duplicated `INTERNAL_PREFIX`. |

---

## M4 — historical attack database and similarity engine

Reviewed together with M5 in one pass, on the noisy dataset. The first attempt at this review was lost to an API error overnight; this is the completed second run.

Reviewer verified: both results files reproduce byte-for-byte; Levenshtein, Jaccard, the 0.5/0.5 combination, sort order, top-k, `common_techniques` and contract 4 key order are correct; empty and unknown trajectories give `matches: []`; the tactic-order derivation is implemented as documented (9 of 176 groups have fewer than 2 parent techniques and are dropped, leaving 167).

### Blocking

None.

### Should-fix

1. **Matching is only evaluated on complete trajectories, but live use is prefixes.** Over all 66 strict prefixes of the A–C ground-truth incidents the top match is the pattern's reference in 34 of 66, against the reported 17/18; a MITRE group is the top match in 30 of 66 (0/18 at length 1, 11/18 at 2, 10/17 at 3, 11/11 at 4). Cause: both score components normalise by the longer sequence, penalising a prefix of a long reference and rewarding tiny records.
2. **The real-MITRE part of the database is effectively inert for matching.** Group sequences have median length 17, so a 5-step incident is capped near 0.29 against a median group; the best group match is a record of length 2 or 4 in 20 of 24 cases; curated is the top match 24/24. On pipeline fragments 2-step groups win at 1.000 with an inferred order.
3. **"Novel by design" needs a number next to it.** Every bigram of pattern D exists in a distractor. With those four removed, D's top similarity falls from 0.343–0.550 to 0.225–0.278.
4. **No false-match figure.** The 22 mapper incidents with no attack event get top similarities of 0.20–0.667. D base (0.550) ties an A skip+insert variant (0.550) and sits below a B skip+insert variant (0.633). No single threshold separates known, variant, novel and benign.
5. **The skew check is correct but does not state its answer, and covers ground truth only.** The data says there is no skew.
6. **`HIST-NNN` ids are positional**; adding one curated sequence renumbers all 167 groups.
7. **Inferred order has two artefacts worth documenting**: within a tactic the order is by technique id; multi-tactic techniques use the earliest tactic, so T1078 always precedes T1110.

### Nits

- Rounding before sorting creates ties; sort on the raw score.
- A negative `top_k` slices from the end.
- `lru_cache` returns one shared mutable list; a missing file raises a bare `FileNotFoundError`.
- Static and temporal modes both give 17/18 on complete trajectories, so E2 will show no matching difference.
- `trajectories.py` sets `timestamp: ""`, not a valid contract-3 timestamp (harmless).

### Resolution

| Finding | Status |
|---|---|
| 1 prefix matching | Reported: `m4_similarity.txt` now has the in-progress table (34 of 66). The measure itself is unchanged; a prefix-aware score is a **TODO**. |
| 2 groups inert | Reported in `m4_similarity.txt` and `PROGRESS.md`. |
| 3 novelty of D | Reported: best similarity with and without the four overlapping distractors, per incident. |
| 4 false-match figure | Reported: similarity distribution of the 22 attack-free inferred incidents; E3 gains a benign class. |
| 5 skew answer | Fixed: the report prints the conclusion and a pipeline-side line. |
| 6 positional ids | Fixed: `HIST-C01…` for curated, `HIST-G0016` style for groups. |
| 7 order artefacts | Documented in `prediction/historical.py`. |
| Nits | Fixed: raw-score sort, `top_k` clamp, immutable cache, clear error. Empty timestamp left as is. |

---

## M5 — Markov prediction and evaluation harness

Reviewer verified: `m5_prediction.txt` reproduces byte-for-byte; counting, backoff, `MIN_SUPPORT`, Top-1/Top-3/MRR arithmetic, the macro definition, the chance row and contract 5 key order are correct; sensitivity of default top-1 to `(MAX_ORDER, MIN_SUPPORT)` is 0.622–0.733 and the chosen cell is not the best, so there is no sign of tuning.

### Blocking

1. **Evidence is false at terminal steps.** Counts were keyed on "context followed by something", so a technique that only ends historical sequences was treated as never seen. `predict_next` on the full pattern C trajectory said the hand-specified sequences "do not contain the last step" although 3 of 11 contain T1041, then predicted T1567 at 0.5 from the group tier. The same defect undercounted occurrences ("T1021 occur 3 times in 3 of 11" when it is in 5 of 11). An empty trajectory produced a false statement too.
2. **"Leave-pattern-out never sees the tested pattern" is false for the rows that include the database.** The curated reference of the held-out pattern stayed in. "default + other patterns" reported 0.744; dropping the held-out pattern's own reference gives 0.544; treating A and C as one family (A's reference is a prefix of C's) gives 0.311. Even "other patterns only" (0.311) is A/C cross-leak.
3. **"D is novel" with top-1 0.583 is misleading as printed.** With the four D-overlapping distractors removed D scores 0/24. All of D's score comes from distractors written by the generator's author.
4. **The pipeline table reads as end-to-end accuracy and is not.** Prefix and target both come from the mapper's trajectory. Of the 70 instances only 43 are transitions that exist in the paired true incident; against the 90 true transitions that is about 0.344, not 0.457. Three single-step incidents are dropped silently.

### Should-fix

1. Add a by-variant breakdown: base 39/45 (0.867), variants 22/45 (0.489). Base incidents of A and B are verbatim copies of curated records, so the headline is roughly half memorisation.
2. Tie-breaking by technique id decides a visible share of top-1 (between 0.578 and 0.733 depending on tie-break alone). Report a tie-aware top-1.
3. The group tier is a Markov chain over an id-sorted list; its transitions are sort adjacency. Drop the tier or replace it; suppress "follows the observed order" when it answers.
4. "Closest historical attack" always queries the full database whatever predictor was passed.
5. MRR uses the full ranking while contract 5 exposes the top 5; uniform-over-222 is a straw baseline. Add a frequency baseline.
6. No test covers evidence truth, terminal steps, an empty trajectory or tiered evidence.

### Nits

- Macro P/R/F1 averages over classes with 1–2 instances; print the class count.
- "One instance is about one percentage point" is true only for n = 90.
- Carry the count instead of reconstructing it with `round`.
- The cached default predictor is never invalidated.
- `StaticPredictor` returns `[]` for an empty path, unlike Markov.

### Reviewer verdict

Clean, deterministic, reproducible, contracts met in shape, no sign of hyperparameter tuning. M5 should not be committed as it was. The honest summary: 11 hand-written sequences by the generator's author carry all the signal, about half of the headline is recall of verbatim templates, and the real MITRE group data contributes nothing to matching or prediction in its tactic-and-id-sorted form.

### Resolution

| Finding | Status |
|---|---|
| Blocking 1 false evidence | **Fixed.** "Ended there" is a counted outcome; a context's occurrences include terminal positions; the empty trajectory uses first-step counts; evidence is built from carried counts. A completed pattern C now returns no prediction and says "3 of those 3 were the last step of their trajectory". Tests check evidence numbers against a recount. |
| Blocking 2 leave-pattern-out leak | **Fixed.** Protocols `no_own_reference` and `leave_family_out` remove the reference sequences of the tested incident's family (A and C together) and the family's incidents. The old 0.744 row is gone; the corrected figure is 0.311. |
| Blocking 3 pattern D | **Fixed.** Both rows are printed side by side: 14/24 with the distractors, 0/24 without. |
| Blocking 4 pipeline table | **Fixed.** Retitled "agreement with the pipeline's own next step"; a strict end-to-end line scores against all 90 true transitions (33/90); incidents without a trajectory or with a single step are counted. |
| 1 by-variant | Fixed: base 42/45, variants 23/45 with the corrected model. |
| 2 ties | Fixed: `top1 tie` column. |
| 3 group tier | Fixed: removed. The default model uses hand-specified sequences only (decision R5). |
| 4 closest-attack line | Fixed: only with the default predictor, and marked as not used for the probabilities. |
| 5 baselines, MRR depth | Fixed: frequency baseline row; MRR depth stated. |
| 6 tests | Added. |
| Nits | Done except the default-predictor cache (**TODO**; restart after rebuilding the database). |

