# Decisions made autonomously

One line each: what was decided and why. Newest milestone last.

## Process

| # | Decision | Rationale |
|---|---|---|
| P1 | Work is committed on branch `backend-milestones`, not `main`; nothing is pushed. | Keeps `main` untouched until you have read the results; merge is one command. |
| P2 | No `milestone-reviewer` agent is defined in this repo or in `~/.claude/agents`, so each review is done by a general-purpose subagent given a fixed reviewer brief (Blocking / Should-fix / Nits, review only, no edits). | Closest available equivalent; the brief is quoted at the top of `docs/REVIEWS.md`. |
| P3 | `pytest` and `httpx` were added to `backend/requirements.txt`. | Needed to run tests and to test FastAPI endpoints. |
| P5 | From the contract-change task onward, backend work happens in a separate git worktree at `~/Desktop/virux-cypher-backend` (branch `backend-milestones`). It symlinks `backend/.venv`, `data/mitre/raw` and `data/external` from the main folder. | While I was mid-edit, the main folder was switched to a `frontend` branch by another tool, and one of my edits landed on that branch's files (I reverted it). Two tools switching branches in one folder will corrupt each other's work; a worktree gives each its own checkout of the same repository. Remove it with `git worktree remove` when no longer wanted. |
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
| K8 | Inferred incident ids derive from the incident's earliest event (`evt-00138` → `INC-00138`); ground-truth ids in `incidents.json` are `GT-001…`. | Stable across re-runs, windows and methods, and cannot be confused with ground truth (M2 review). |
| K10 | The sender address of a received e-mail is not counted towards the recipient when deciding whether an address is a hub. | The recipient never used that address. With internal mail in the noisy dataset every workstation IP became a hub, which cut the pivot-IP link that pattern B depends on. |
| K11 | The default window stays at 30 minutes although 60 scores higher on the noisy dataset. | 30 was fixed before the noisy dataset existed; switching after seeing the results would be tuning on the test data. The sweep is reported. |
| K9 | Trajectory order is by timestamp then `event_id`; a test checks that walking `NEXT` edges gives the same order. | Same result, simpler query. |

## M3 — ATT&CK mapper

| # | Decision | Rationale |
|---|---|---|
| A1 | The mapper lives in `core/attack_mapper.py`; environment knowledge (servers, admin workstation, service account, business hours) lives in `core/environment.py`. | `architecture.md` has no mapping folder; `core/` is the log-to-KG glue. The inventory reads no ground truth, but it allow-lists exactly the two benign accounts that do attack-like things, so it encodes knowledge of the generator (M3 review). |
| A2 | Rules follow ATT&CK's own meaning of a tool, not the generator's labels: `cmd.exe` → T1059.003, `whoami.exe` → T1033, `rundll32.exe` → T1218.011, `7z.exe` → T1560.001. | Tuning the rules to the generator would defeat the purpose. These are real confusions in the evaluation; `7z.exe` alone moves T1005 recall between 0.26 and 1.00 across seeds. |
| A3 | Dual-use activity (PowerShell, RDP, SMB, elevation) is not mapped when an administrator or service account performs it from its expected workstation ("expected session", tracked by session origin). | Otherwise every admin action is a false positive. An admin account used from a non-admin workstation is still mapped, which is what catches pattern B's stolen-credential hop. |
| A4 | One technique per event; a contract-2 `tactic` is a single value chosen by the rule and validated against ATT&CK's tactic list for that technique. | Contract 2 has one `tactic` field. |
| A5 | Rule confidences are fixed, hand-assigned values; sub-rules of one technique have different values (T1041 server 0.50, off-hours 0.45). | Contract 2 needs a number; they are not calibrated and nothing downstream depends on their exact value. |
| A6 | ATT&CK is downloaded by `data/mitre/fetch.py`; the 54 MB STIX bundle is gitignored and the small extracts (`techniques.json`, `groups.json`, `tactics.json`, `revoked.json`, `VERSION`) are committed. Group techniques are the direct `uses` relationships only, not those reached through software. | Reproducible without committing a large file. |
| A7 | The mapper is batch-only: brute-force bursts and the Office-then-script-host rule look forward in time. | Simplest correct form for an offline dataset; a streaming version would emit those mappings late. |
| A8 | Exfiltration rule rewritten to use no attacker-address knowledge: outbound to a destination new to the organisation, from a server or outside business hours. | Your instruction. Contract 1 is frozen and has no byte counts or ports, so volume and port cannot be used; I did not change the contract. |
| A9 | A repeat-connection proxy for volume was added and then removed. | Over 13 noisy seeds it gave 20 true and 909 false positives. This is the only rule changed after seeing results on the noisy data. |
| A10 | T1078 fires only the first time a user logs in from a given external address. | With staff working from home, "any external logon" flags every remote day. |
| A11 | The generator has two profiles: `noisy` (default) and `clean` (the first dataset, byte-identical). | Benign data rebuilt as you asked, while keeping the old dataset reproducible so old and new figures can be compared with the same code. |
| A12 | Apart from A8–A10 the rules were not tuned against the noise (for example T1021.002 stays at 7% precision). | Fitting rules to noise written by the same author would re-inflate the number. Refinements are listed as next steps. |
| A13 | The default pipeline is `method = mapper`, `technique source = mapper`. | Both are label-free. Ground truth is an explicit opt-in used only by evaluation. |

## M4 / M5 — historical database, similarity, prediction

| # | Decision | Rationale |
|---|---|---|
| R1 | Historical database = 167 MITRE ATT&CK groups (order inferred from tactic position, then technique id) + 11 hand-written sequences. | Your specification. The inferred order is flagged on every record. |
| R2 | Three hand-written sequences are the reference forms of patterns A, B and C; pattern D has none; eight are distractors. | E3 needs known, variant and novel classes. The distractors were written before any result was seen and were not changed afterwards. |
| R3 | Similarity = 0.5 × Jaccard of technique sets + 0.5 × (1 − edit distance / longer length), on parent ids with repeats collapsed. | Overlap and edit distance as you asked; equal weights, no fitting. "Temporal" means order only, because historical records carry no timestamps. |
| R4 | `common_techniques` lists the incident's own ids (sub-technique form) whose parent occurs in the historical attack. | Matches the example in contract 4, which shows sub-technique ids. |
| R5 | The default predictor is trained on the hand-written sequences only; MITRE group records are not used for prediction. | Measured: groups alone give 0 of 90 correct, and pooling them lowers top-1 from 0.722 to 0.311. Their "transitions" are sort order. Chosen after seeing results on these 24 incidents; disclosed. |
| R6 | Markov order 2 with back-off; a 2-step context needs 2 occurrences; "ended there" is a counted outcome. | Simple and explainable. The reviewer's sensitivity check found the chosen setting is not the best cell. |
| R7 | Historical ids are `HIST-C01…` (hand-written) and `HIST-G0016` style (MITRE group id). | Stable when records are added (review). Contract 4 only fixes the field, not the format. |
| R8 | Patterns A and C are one family in held-out evaluation. | A's reference is a prefix of C's; holding out one leaks the other (review). |
| R9 | One reviewer pass covered M4 and M5 together, with separate findings. | They share files and results; the review was run with nothing else in flight. |
| R10 | The similarity measure was not changed to be prefix-aware. | Changing the measure after seeing the 34-of-66 result would be tuning on the test data. It is reported and listed as next work. |

## M6 — experiments

| # | Decision | Rationale |
|---|---|---|
| E1 | Every experiment runs on ground-truth trajectories and on the label-free pipeline's trajectories. | The first isolates the component; the second is what the system would actually see. |
| E2 | "Without historical KG" is reported three ways: analytic chance, most-frequent-next-step among other incidents, and models trained on other incidents only. | There is no single obvious "no history" model; showing all three avoids picking a flattering one. |
| E3 | "Static graph" means order is not used by the scoring rule (set overlap for matching, co-occurrence for prediction); the stored graph is the same. | The cleanest way to isolate the effect of order with everything else equal. |
| E4 | E3 classes: known = base instances of A/B/C, variant = their skip/insert instances, novel = pattern D. Thresholds are chosen by leave-one-out. | Uses the generator's variants as you asked; leave-one-out avoids fitting thresholds to the tested incident. |
| E5 | Findings sentences are generated from the result rows, with fixed wording rules for higher / lower / no different (a one-instance gap is "no different"). | A reviewer found hand-written findings that the tables did not support. |

## M7 — agent tools and Agent 2

| # | Decision | Rationale |
|---|---|---|
| T1 | The five tools are plain typed functions in `agents/tools/`, matching `docs/agent-tools.md`. The versions offered to the language model take only an `incident_id` or `technique_id`; `match_historical` and `predict_next` then run on the trajectory `query_graph` returned. | A model that passes its own trajectory could fabricate a finding. This deviates from the tool table only at the model-facing boundary. |
| T2 | The evidence bundle is assembled by code from tool results. The model's text appears only in `agent_notes`; the step log stores validated arguments and fixed error codes. | "An agent never computes a finding itself", enforced rather than requested. |
| T3 | Agent 2 runs offline by default with `ScriptedLLM`, a fixed-rule policy following the documented loop. Claude is opt-in with `AGENT_LLM=anthropic`. | No API key is configured; the default must be deterministic and testable. The Claude adapter has never been run against the real API. |
| T4 | Scripted policy rules: "suspicious" = the trajectory has at least one technique; "strong match" = top similarity ≥ 0.5; the key technique to look up is the top prediction, otherwise the last observed step. | Needed concrete values for the conceptual loop; none are tuned. On the loaded graph 19 of 53 incidents reach a prediction. |
| T5 | Limits: 8 model turns and 20 tool calls per investigation. | Bounds cost and Neo4j load whatever the model does. |
| T6 | `lookup_technique` returns all tactics of a technique as one comma-separated string and resolves revoked ids. | The tool contract has a single `tactic` field; several techniques have more than one tactic. |
| T7 | The Claude adapter uses model `claude-opus-5-5` with default thinking and effort, and does not enable server-side refusal fallbacks. | Could not be verified without credentials, so only the plain documented call is used. Worth revisiting when a key is available. |

## M8 — API, Agent 1 and Agent 3

| # | Decision | Rationale |
|---|---|---|
| B1 | Three endpoints beyond your list: `GET /health`, `GET /incidents`, `GET /technique/{technique_id}`. | A frontend cannot discover incident ids or technique names without them. |
| B2 | `/graph/{id}` returns `{incident_id, nodes, edges}` with typed, prefixed node ids. | Not one of the five contracts; shaped for Cytoscape.js, which the README names as the frontend graph library. |
| B3 | `POST /logs` accepts Normalized Events only, not raw log lines. | Raw-log parsing (the OntoLogX part of the architecture) is not built; the endpoint is honest about what it takes. |
| B4 | Agent 1 is deterministic: store, re-map everything with the rule mapper, re-infer incidents, in one transaction. | The mapper needs the whole event stream (bursts, session state); a transaction keeps readers consistent. |
| B5 | Agent 3 is a template, not a language model. | A template cannot misstate the evidence. An LLM-written report is a later option on top of the same bundle. |
| B6 | `POST /logs` validation is stricter than contract 1's wording: bounded lengths, URL-safe `event_id`, real dates 1970-2100, no control characters. | Contract 1 fixes field names and types; these bounds protect the graph and the URLs. The bundled dataset satisfies all of them. |
| B7 | Optional `API_TOKEN` for `POST /logs`; reads are open; no pagination. | Enough for a demo without adding an auth system. Stated in the README. |
| B8 | `/investigate` and `/explain` re-run the agent on every call; nothing is cached. | Deterministic and fast on this data (tens of milliseconds); caching would need invalidation on ingest. |

## Contract change — destination_port and byte_count

| # | Decision | Rationale |
|---|---|---|
| C1 | `destination_port` and `byte_count` are optional on input (a missing field means null) and always present on output. | You asked for optional, nullable fields; always emitting them keeps consumers simple. |
| C2 | `byte_count` means bytes sent from `source_ip` to `destination_ip`. | Exfiltration is about outbound volume; a single direction keeps the field unambiguous. Written into `data-contracts.md`. |
| C3 | The generator fills the two fields from a separate random stream. | Both profiles are otherwise identical to the datasets before the change (checked field by field), so earlier results stay comparable. |
| C4 | Generator values: ports by service; attack exfiltration 30 MB–2 GB (one in ten is 0.5–5 MB); benign web 2 KB–3 MB with 3% uploads of 20–300 MB in the noisy profile. | Plausible magnitudes, with deliberate overlap so the rule is not perfect. Chosen by the same author as the rule's threshold; stated in the evaluation's limitations. |
| C5 | Exfiltration rule: at least 20 MB sent to an external address, plus one of: destination new to the organisation, uncommon port, outside business hours, server source. Without `byte_count` it falls back to the previous rule. | Uses the new fields as you asked; the fallback keeps sources that record no volume working (needed for real data). |
| C6 | No separate reviewer pass for this task; it is covered by the M9 review. | It is a contract-and-plumbing change with tests; the next review reads the same files. |

## M9 — real-data validation

| # | Decision | Rationale |
|---|---|---|
| V1 | Main result: the seven `LSASS_campaign_*` datasets. `apt3`, `Log4Shell` and `GoldenSAML` are out; `apt29` day 1 was used only for the time-boxed retry. | The LSASS datasets have technique ids in a metadata file, one consistent schema and host plus network logs. Reasons per dataset are in `docs/real-data.md`. |
| V2 | The mapper is scored on real data by technique SET per dataset, not per event. | The datasets have no per-event labels. Reported as such; no per-event number is claimed. |
| V3 | Resource Development techniques (T1587.001, T1608.001) are excluded from the label sets. | The dataset metadata says host and network data do not include that stage. |
| V4 | The adapter drops what contract 1 cannot hold (process-access target, command line, parent process, file name, script text, registry and image-load events) and counts it. It does not encode it into other fields. | You said not to change the contract to fit the data. Putting the target process into `action` or `process` would be a contract change in disguise. The cost is that LSASS access is invisible after adaptation; that is the main finding. |
| V5 | `source_ip` for host-local events is the host's own address, derived from its outbound connections. | The contract requires a value; this is a derivation from the data, documented as such, not an invented value. Events with no user are dropped. |
| V6 | `byte_count` from Zeek is used only when Zeek saw the sender's packets and reports no missed bytes. | Most connection records are one-sided and show 0 bytes sent for megabyte transfers; one showed 26 MB that was entirely a sequence-gap estimate. Treating either as a measurement would be false. No event keeps a byte count. This lowered the headline F1 from 0.421 to 0.404 (review B2); I took the lower number. |
| V7 | 23 standard Windows tools and a double-extension rule were added to the mapper; names of the dumping tools that occur in the datasets were not. | General tool knowledge is fair; adding `nanodump.x64.exe` after seeing it in the test data is file-name matching. Disclosed: the list was written after the survey showed which programs occur. |
| V8 | Lab environment `PANDALAB`: internal = the host subnets seen in the data; no servers, administrators or business hours. | Nothing in the data states them. "External" means outside those subnets, because the attacker's address is private. |
| V9 | `core/environment.py` became an `Environment` object passed to the mapper; `BANK` is the default. | The mapper had the bank's inventory hard-wired. Synthetic mapper output is byte-identical after the change. |
| V10 | Composed timeline: three datasets overlapping on different hosts, four in sequence on one host; only clocks are moved. Reference grouping = mapped events per source dataset. | There are no attack-event labels, so the only knowable truth is which capture an event came from. |
| V11 | Real-data runs replace the Neo4j graph and the synthetic graph is rebuilt afterwards. | Neo4j Community has one database. The script prints the restore command. |
| V12 | The headline real-data score keeps the capture-teardown activity (F1 0.404); the score without it (F1 0.521) is a labelled secondary figure. | The pipeline cannot tell capture tooling from activity, so the honest figure includes it. The secondary figure uses process lineage the pipeline does not have. |
| V13 | Process lineage is returned by the adapter beside the events for evaluation only, never inside them. | Needed to explain the false positives; contract 1 stays unchanged. |
| V14 | apt29 retry: technique names in the emulation plan become ids only by exact match with a current ATT&CK name; 13 names are left out. | Deterministic and checkable. A crosswalk from the 2020 names exists at MITRE but was not available offline; mapping by judgement would be inventing labels. |
| V15 | apt29 retry: the mapper rules were frozen before the dataset was looked at; five rules written afterwards are shown in a separate row and are not in the mapper. | Keeps the effect of fitting visible instead of hiding it in the result. |
| V16 | The retry stopped after one dataset. It scored worse than LSASS (F1 0.057 against 0.404) for the same contract reason. LSASS stays as the real-data result. | Your instruction: stop at the contract wall and do not chase further. |
| V17 | Contract 1 was not expanded for real data. The need for process lineage and process-access targets is recorded as the headline future-work finding. | Your instruction. |
| V18 | The apt29 retry was not separately reviewed. | It was written during the M9 review and reuses the reviewed adapter's rules; flagged in `REVIEWS.md`. |
