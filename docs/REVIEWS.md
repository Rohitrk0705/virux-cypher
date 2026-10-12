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

---

## M6 — the three experiments

Reviewer checks that passed: `run_all` twice gives identical checksums for all 12 result files; all 9 CSVs match their markdown tables cell for cell; no train/test leakage (E3 leave-one-out refits on the other 23, benign incidents are not in the fit, E1/E2 hold out the incident or family as described); AUC direction, false-positive arithmetic and confusion matrices are correct; every metric in `docs/experiments.md` is reported somewhere; static and temporal use the same data and candidates. The problems were in the prose.

### Blocking

**B1. An E3 caveat described an error that does not occur in the data.** It said pattern C with its last step skipped equals pattern A and scores 1.0. No such incident exists in this dataset; the two actual ground-truth errors are GT-004 (B skip+insert, 0.633) and GT-015 (A skip+insert, 0.550), both variant called novel. The caveat excused the errors with a mechanism and a number the code never produced.

**B2. E2 never stated its negative results in words, and its findings skipped a row where temporal loses.** Matching is 17 vs 17 and 10 vs 10, so order improves nothing, and no finding said so. The findings printed two of four training conditions; the omitted pipeline pooled row has static ahead on every ranking metric. Without the own family's reference temporal does not win. Top-3 is equal or better for static in all four cited rows. A caveat presupposed a temporal advantage that is absent in those rows.

### Should-fix

- **S1.** E1's "unseen pattern" findings do not say where the gain comes from: 25 of 90 is B 11/24 plus D 14/24, with A and C at 0; D's hits come from the overlapping distractors and B's from a distractor sharing B's opening. Add the combined condition and say the gain is confined to B and D.
- **S2.** E1 end-to-end rows that use in-environment incidents train on ground-truth trajectories, under a table titled "label-free".
- **S3.** E3 pipeline accuracy includes a right-for-the-wrong-reason hit (GT-023 matches a 2-technique MITRE group record at 1.0), counts an incident with no trajectory as "novel" without saying so, and gives no majority-class baseline (9 of 24). In-sample accuracy (16/24) against leave-one-out (13/24) is worth reporting as threshold instability.
- **S4.** E3 lacks the caveat that "known" is 1.000 by construction.
- **S5.** Sample-size attrition on pipeline trajectories (70 instances, 20 incidents) is not explained.
- **S6.** The static predictor's no-repeat handicap is stated but not quantified (0 of 90 ground-truth instances, 5 of 70 pipeline instances).
- **S7.** Metric definitions are absent from the result files.

### Nits

- Two E1 rows read "none / all other incidents"; the chance row is a weak comparator and the frequency baseline should be quoted beside it.
- E3: "0.333 of the 6" should read "2 of 6"; one-incident differences should be called noise; on ground truth the order-aware score is worse, not merely "not better".
- Row unpacking by list order is fragile; nothing guards findings text against the tables.

### Reviewer verdict

E1 can claim that a Markov model over the 11 hand-written sequences predicts well when the history contains the generator's own template, that MITRE group data contributes nothing, and that history adds nothing once sibling incidents are available. It cannot claim that history helps on unseen attacks. E2 can claim that order does not improve matching on this dataset and raises Top-1 only when the model can replay a memorised sequence. It cannot claim a general temporal advantage. E3 can claim separation on ground-truth trajectories, with "known" trivially 1.0. It cannot claim usable discrimination on the label-free pipeline.

### Resolution

| Finding | Status |
|---|---|
| B1 false caveat | **Fixed.** Removed. The findings now list the misclassified incidents with their scores, generated from the run, and the caveat quotes the measured variant minimum and novel maximum. |
| B2 unstated negative results | **Fixed.** E2 findings are generated per row for all four training conditions with a higher / lower / no different verdict, plus a summary count; "Order does not improve matching on this dataset" is stated; the caveat no longer presupposes an advantage. |
| S1 | Fixed: combined condition added (12 of 90); by-pattern counts in the finding; "does NOT show that history helps on unseen attacks". |
| S2 | Fixed: the end-to-end table keeps only history-trained rows. |
| S3 | Fixed: majority baseline, in-sample count, spurious-known count and no-trajectory count are columns and appear in the finding. |
| S4, S5, S6, S7 | Fixed: caveats and a Metrics paragraph added; counts are computed, not typed. |
| Nits | Wording fixed; rows are looked up by key. **TODO:** no test ties findings text to tables (the text is generated from the same rows, which limits the risk). |

---

## M7 — agent tool layer and Agent 2

Reviewer verified: the five tools match `docs/agent-tools.md` in name, signature, typing and contract shape and raise `LookupError` for unknown incidents and techniques; the loop follows the Messages tool-use protocol (assistant content first, one `tool_result` per call in a single user message, `is_error` on failures, a `max_steps` exit leaves a valid conversation marked incomplete); `ScriptedLLM` is deterministic and ran cleanly on all 53 real incidents; `trajectory`, `historical_matches`, `prediction` and `event_summary` could not be made to contain anything a tool did not produce (apart from the stale-state case below).

### Blocking

**1. Model-written content reaches the bundle outside `agent_notes`.** `steps[].input` stored the model's raw arguments; extra keys were ignored rather than rejected, so a `predict_next` call carrying `"finding": "attacker WILL use T9999 p=0.99"` was recorded `ok: true` with that text verbatim. `steps[].tool` and `steps[].summary` echoed invented tool names and incident ids the same way. This matters because `/explain` builds a report from the bundle. The existing test did not catch it.

### Should-fix

2. Non-dict tool input raises out of `investigate()`; a non-JSON value breaks `json.dumps(bundle)`; `decide()` returning `None` raises.
3. Stale state: a later `query_graph` call could overwrite the trajectory while matches and prediction still described the old one.
4. `complete: True` did not mean evidence was gathered (a model answering "All clear" immediately was "complete").
5. `ScriptedLLM` wrote false notes after a tool error (for example "no ATT&CK-mapped steps" when `query_graph` had failed).
6. Any model-chosen technique landed in `bundle["techniques"]` with no marker.
7. One model turn could trigger unlimited tool calls.
8. `content=None` with tool calls left an invalid conversation; duplicate call ids produced two results with one id.
9. Hazards for the API milestone: no `EvidenceBundle` type; `list_incidents()` returned epoch seconds; model or API errors mid-run discarded evidence; the LLM was built before the incident was checked; `toolset={}` silently used the real tools; `event_summary` would fail on a null field.
10. Undocumented decisions (model-facing tools take `incident_id`; `STRONG_MATCH`; "suspicious"; key technique; `MAX_STEPS`).
11. "Untested" labelling of the Claude adapter was incomplete, and the adapter had no test. No protocol mistakes found on reading.
12. Test gaps: errors were tested on `Investigation.run`, not through `investigate()`; several adversarial cases untested.

### Nits

- Incident id parsed by splitting the prompt; mid-run text could become `agent_notes`; `lookup_technique` rejects lower-case ids; no usage line for the entry point; old `LLM_API_KEY` line kept in `.env.example`; `list_incidents` loosely typed.

### Resolution

| Finding | Status |
|---|---|
| Blocking 1 | **Fixed.** Every call is validated: known tool name, exactly one string argument, the investigation's own incident id or a well-formed technique id. A rejected call is logged with tool `<unknown>` or its real name, an empty input and a fixed error code. `test_model_strings_never_enter_the_step_log` supplies a trajectory, a lie in an extra argument, an invented tool name and a fake incident id after a real trajectory exists, and checks none of it appears outside `agent_notes`. |
| 2 | Fixed: validation rejects non-dict input; a non-`Decision` reply stops the run as `invalid_model_response`. |
| 3 | Fixed: the trajectory and events are fetched once per investigation. |
| 4 | Fixed: `complete` requires a normal stop and a fetched trajectory; `tool_calls` and `failed_tool_calls` are reported. |
| 5 | Fixed: notes name the failed tools. |
| 6 | Fixed: each looked-up technique carries `relation` (`in_trajectory`, `predicted`, `not_in_evidence`). |
| 7 | Fixed: `MAX_TOOL_CALLS = 20` per investigation. |
| 8 | Fixed: content is synthesised when missing; one result per distinct call id. |
| 9 | Fixed: `EvidenceBundle` and related types in `agents/contracts.py`; ISO timestamps; a model failure returns the evidence so far with `stop_reason: model_error`; incident checked first; empty toolset respected; null-safe summary. **Not done:** raw events are not in the bundle (the API serves them separately). |
| 10 | Fixed: `DECISIONS.md` M7 section. |
| 11 | Fixed: labelled untested in the module docstring, `default_llm`, the class, the README and `.env.example`; an offline test drives the adapter with a stand-in `anthropic` module. Still never run against the real API. |
| 12 | Fixed: tests added for each case. |
| Nits | Done, except the old `LLM_API_KEY` line, which is from the original skeleton and was left. |

---

## M8 — FastAPI endpoints, Agents 1 and 3

What passed: the service starts both ways (`uvicorn api.main:app` from `backend/`, `uvicorn backend.api.main:app` from the root) with byte-identical responses; across all 53 incidents `/events`, `/trajectory`, `/match` and `/predict` matched contracts 1, 3, 4 and 5 exactly, and the Pydantic models match `docs/data-contracts.md`; `/graph` had unique node ids, no dangling or duplicate edges and complete, ordered NEXT edges; `/investigate` bundles matched the documented keys and agreed with the direct endpoints; odd ids (URL-encoded, 60,000 characters, NUL, emoji, quote injection) all returned 404; all Cypher is parameterised; the README numbers checked out. The reviewer restored the graph after testing (3,986 events, 53 incidents; a hash over all nodes and relationships was identical before and after the test suite).

### Blocking

- **B1. One event with a year-0000 timestamp returned 500 and permanently broke ingest.** The timestamp was validated by regex only; Neo4j stored it and the next read of all events raised.
- **B2. Ingest was not atomic.** Events were written in 1,000-row transactions before mapping and inference; a failure in the 1,001st left 1,000 events in the graph with mappings and incidents not refreshed.
- **B3. Invalid dates and over-long strings returned a false 503 "Neo4j is not available"** while `/health` reported Neo4j up.
- **B4. `/health` reported `neo4j: false` whenever there were zero default incidents**, because the query returned no row. Seen in 81 of about 4,000 polls during ingests.
- **B5. `/explain` said "first seen" for a timestamp that is the start of a run**, which is false when a technique repeats (4 of 53 bundled incidents).
- **B6. An `event_id` without `-` would be reported as 404 and leave ingest broken** (by code reading): the incident-id derivation raised `IndexError`, and the handler turned every `LookupError` into a 404.

### Should-fix

1. GET endpoints returned wrong 200s while an ingest was rebuilding (`/incidents` empty 87 times, valid ids 404 about 80 times) because clear and rewrite were separate transactions.
2. Incident ids containing `/` were unreachable.
3. Incident id collisions (`evt-00138` and `x-00138` both gave `INC-00138`) would silently merge.
4. Markdown/HTML injection into the report through user and device names and through multi-line agent notes.
5. Report wording contradicted the bundle on tool failure ("No prediction was requested" when `predict_next` had failed; "Investigation complete" with a failed call).
6. A large or hostile body degrades the service; no byte limit and no auth on `POST /logs`.
7. README inaccuracies and gaps (`/events` carries no technique id; `/incidents` ordered by id string; error shapes; degraded health shape; no auth or pagination stated; `/technique` can return another id; Cytoscape id selectors).
8. Driver errors other than `ServiceUnavailable` surfaced as plain-text 500; `OSError` was mislabelled as a database outage.
9. Test gaps: cleanup used an address range the dataset also uses; one incident exercised; no tests for upsert, bad dates or the blocking cases.

### Nits

- Possible duplicate edges if an event ever had two techniques; empty strings accepted for nullable fields; inconsistent 404 text echoing the full id; every hand-written record called "reference sequence"; `--reload` scope; `/docs` needs a CDN; the lock does not span several worker processes.

### Resolution

| Finding | Status |
|---|---|
| B1, B3 | **Fixed.** Timestamps are parsed as real UTC dates between 1970 and 2100; every string is 1-256 characters with no control characters; `event_id` is limited to URL-safe characters. All are 422 with a string `detail`. Only driver connection errors map to 503. |
| B2 and Should-fix 1 | **Fixed.** An ingest is one database transaction covering the events, the refreshed mappings and the refreshed incidents. A test makes the mapper raise mid-ingest and checks nothing changed. Readers see the old state until commit. |
| B4 | **Fixed.** Two separate counts; a test checks `status: ok` with zero incidents. |
| B5 | **Fixed.** The report says "from <time>" and explains that a step is a run of consecutive events. |
| B6 and Should-fix 3 | **Fixed.** A dedicated `NotFound` exception is the only thing mapped to 404 (a test checks a stray `IndexError` is a 500). Ids without the `evt-` prefix are used whole; a collision of incident ids is rejected with 422 rather than merged. |
| 2 | Fixed by the `event_id` character rule. |
| 4 | Fixed: log-derived values and the agent's note are Markdown-escaped; each note line is quoted. README tells the frontend to render with raw HTML disabled. |
| 5 | Fixed: wording is derived from the step log. |
| 6 | Partly fixed: string caps, 5,000 events per request, optional `API_TOKEN`. **TODO:** no request byte limit; every ingest re-maps the whole graph; `mark_entities` can change hub status and re-partition existing incidents. |
| 7 | Fixed in `backend/README.md`. |
| 8 | Fixed: `DriverError` → 503; everything else → JSON 500 with the cause logged. |
| 9 | Fixed: tests use an unused address range and cover upsert, bad input (16 cases), rollback, token, non-`evt-` ids. |
| Nits | Edge de-duplication, empty strings, 404 text and record labels fixed. **TODO:** single-process lock; `/docs` CDN. |

---

## M9 — real-data validation (and the contract-1 change)

The reviewer re-ran the adapter in memory on all seven datasets and reproduced every count and the mapper score exactly (354,229 raw, 213,818 adapted, 202,193 process-access events, 1,981 `lsass.exe` targets, TP 20 / FP 30 / FN 25, and the composed-timeline incident counts by an independent implementation). It confirmed the contract change leaves both generator profiles otherwise identical, and that the adapter invents nothing beyond the disclosed derivations (host address, event ids). The problems were in what the document claimed about the numbers.

### Blocking

- **B1. Stale or mismatched synthetic numbers in the side-by-side.** "9 / 24 exact" predated the contract change (now 8); "trajectory length 4–6" was the length of the hand-written historical sequences, not pipeline trajectories (1–8); "similarity 1.000" and "top-1 0.722" were ground-truth figures set against real pipeline figures. The PROGRESS summary carried the same stale figures.
- **B2. The single T1041 hit rested on a byte count Zeek did not observe.** The one accepted record had one sender packet and `missed_bytes` equal to the whole 26.3 MB: a sequence-gap estimate. The capture was as one-sided there as everywhere else, so "1 of 6" was a capture accident.
- **B3. The "false positives" and the long trajectories are mostly the capture teardown, and the document did not say so.** 252 of 288 process-rule hits (87%) descend from `netsh trace stop`; 21 of the 30 unlabelled pairs come only from that subtree. Two mappings are wrong in meaning (`wevtutil epl` is an export; `certutil -store` is not ingress transfer). The document's explanation steered towards "real but unlabelled attack activity". The 0.400 headline should stay; the explanation needed correcting and a teardown-excluded figure added as a labelled secondary row.
- **B4. Statements the data contradicts.** The 19-hour clock offset holds for five datasets, 7 hours in two; Security 4663 is 24 events, not "hundreds"; the PowerShell count includes ids beyond the five listed; apt29 does have technique ids (in description cells, old numbering) and ordered steps; apt3 has a technique-id column; total not adapted is 140,411 (39.6%).

### Should-fix

1. Rule-fitting disclosure incomplete: `procdump64.exe` was added and occurs in the data. (With pre-M9 rules the score is P 0.630, R 0.378, F1 0.472: the additions lowered F1, so no sign of tuning.)
2. The T1608.001 exclusion is attributed to the metadata, which only covers T1587.001.
3. Unused ground truth: each metadata file has an ordered transcript of the attacker's commands.
4. The composed-timeline result is fragile: the merging link is a 29.6-minute gap under a 30-minute window; "kept whole" has a ceiling of 6 of 7.
5. Event types that could have been considered are not listed (4688, 4672/4703, 4656, Sysmon 22, 17/18, 5156/5158; the 80 dropped service logons).
6. Prediction wording overstates the fallback (3 of 7 datasets, not "usually").
7. `agents/contracts.py`: the new fields should be `NotRequired`.
8. `IP.internal` is inverted on the real graph (bank prefix).

### Nits

- RSTRH is also one-sided; duplicate 4-tuples are summed; lost-counter vs adapted network counts differ by 17; "under a minute" is not in the captured output; new `action` and `source` values are not mentioned; `.gitignore` lists `data/external/` three times.

### Reviewer verdict

The validation establishes that the adapter is faithful, that the contract was not bent to fit the data, that the headline numbers reproduce, and that the central conclusion holds: in all seven datasets a non-system process opens `lsass.exe` and contract 1 discards the one field that shows it. It does not establish anything about exfiltration detection, about what real noise looks like, or anything robust about incident separation.

### Resolution

| Finding | Status |
|---|---|
| B1 | **Fixed.** The side-by-side now compares pipeline output with pipeline output only, each cell re-read from the current results files; the PROGRESS summary was rewritten. |
| B2 | **Fixed, taking the lower number.** `byte_count` now also requires Zeek to report no missed bytes. T1041 is 0 of 6; the headline moved from F1 0.421 to **0.404** (P 0.388, R 0.422). The old figure and the reason are stated in the document. |
| B3 | **Fixed.** The evaluation computes the capture-teardown subtree from raw process lineage (returned beside the adapted events, never inside them) and prints a labelled secondary row (P 0.679, R 0.422, F1 0.521). The document explains the false positives as capture tooling, names the two wrong mappings, and keeps 0.388 as the headline precision. |
| B4 | **Fixed**: each statement corrected against the data. apt29 was then used for the time-boxed retry. |
| 1, 2, 3, 5, 6, 8 | Fixed in `docs/real-data.md` (disclosures, wording, the table of event types considered, the unused transcript, the graph caveat); the 59-pair score is printed. |
| 4 | Fixed: an offset sweep is printed and the fragility stated; the ceiling is stated. |
| 7 | Fixed. |
| Nits | RSTRH, counts, timing claim and new values addressed in the document. **TODO:** `.gitignore` duplicates (not my lines); duplicate 4-tuple summing. |

The apt29 retry (`data/adapters/apt29.py`, `evaluation/real_data_apt29.py`) was written while this review was running and was **not** covered by it. It reuses the reviewed adapter's mapping rules; its numbers are in `evaluation/results/m9_real_data_apt29.txt`.

