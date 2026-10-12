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

