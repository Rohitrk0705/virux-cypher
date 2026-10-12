# Real-data validation (M9)

External validation of the pipeline on OTRF Security-Datasets. The synthetic dataset remains the
controlled benchmark; nothing here replaces it.

## Headline finding (future work)

> **Contract 1 must carry process lineage (parent process, command line) and process-access targets
> to represent host-level behavioural techniques; without them, endpoint credential-access attacks
> are invisible after normalization.**

Evidence: in all seven LSASS datasets a non-system process opens `lsass.exe`, and the one field that
shows it (the target of the process access) has no place in contract 1. The mapper finds LSASS
dumping in 1 of 7 datasets, and only because that one used a tool literally named `procdump.exe`.
A second, multi-step dataset (apt29) hits the same wall harder: 1 of 31 labelled techniques found.
The contract was deliberately **not** expanded in this milestone; this is recorded as the first
thing to change before any further real-data work.

## Results at a glance

| Dataset | What it is | Mapper vs the dataset's labels (technique sets) | Sample |
|---|---|---|---|
| Seven LSASS campaigns (**the real-data result**) | single host, one technique family each | precision 0.388, recall 0.422, **F1 0.404** | 7 datasets, 45 labelled pairs |
| apt29 day 1 (time-boxed retry) | four hosts, 25-step intrusion | precision 0.250, recall 0.032, **F1 0.057** (exact ids); F1 0.125 at parent level | 1 dataset, 31 labelled techniques |
| Synthetic benchmark, same set measure | – | F1 0.882 | 1 dataset |

Sources: `evaluation/results/m9_real_data.txt`, `evaluation/results/m9_real_data_apt29.txt`.

## 1. Survey (written before any adapter code)

Source: `data/external/Security-Datasets-master/` (github.com/OTRF/Security-Datasets, MIT licence,
copyright 2021 Open Threat Research Forge). Surveyed with `data/adapters/survey.py`, which reads the
archives in memory and executes nothing.

### What is in `datasets/compound/`

| Dataset | Host events | Hosts | Capture window | ATT&CK labels | Usable here |
|---|---|---|---|---|---|
| LSASS_campaign_01 (Mimikatz logonpasswords) | 53,698 | MKT01 | 14 min, 2023-08-15 | metadata file, technique ids | **yes** |
| LSASS_campaign_02 (Procdump) | 42,482 | ACCT01 | 14 min, 2023-08-15 | metadata file | **yes** |
| LSASS_campaign_03 (comsvcs.dll) | 41,954 | PRD01 | 14 min, 2023-08-18 | metadata file | **yes** |
| LSASS_campaign_04 (Out-Minidump.ps1) | 40,568 | IT01 | 10 min, 2023-08-27 | metadata file | **yes** |
| LSASS_campaign_05 (SharpDump) | 59,707 | MKT01 | 12 min, 2023-09-05 | metadata file | **yes** |
| LSASS_campaign_06 (Outflank Dumpert) | 58,096 | MKT01 | 12 min, 2023-09-05 | metadata file | **yes** |
| LSASS_campaign_07 (Nanodump) | 57,724 | MKT01 | 12 min, 2023-09-06 | metadata file | **yes** |
| apt29 day 1 / day 2 (ATT&CK Evaluations round 2) | 196,081 / 587,286 | 4 | 33 / 35 min, 2020 | emulation-plan spreadsheet: ordered steps with technique NAMES in 2020 wording; ids only inside some description cells, in pre-2020 numbering | day 1 used for the retry (section 9) |
| windows/apt3 (Caldera, Empire) | not counted | several | 2019 | playbook spreadsheet with a technique-id column | no |
| Log4Shell | 5 to 487 per file | 1 | seconds | metadata file (T1190, T1203) | no |
| GoldenSAMLADFSMailAccess | 1 to 38 per file | cloud | – | metadata file (cloud identity techniques) | no |

Why the others were not used for the main result:
- **apt29**: its labels are ordered plan steps with technique names in 2020 ATT&CK wording. Ids appear
  only inside some description cells (12 of 32 day-1 rows) and in the old numbering. Its Sysmon events
  lack the `SourceUser` field. It was left out of the first pass and then used for the time-boxed
  retry in section 9, with names matched to ids by exact current name only.
- **apt3**: a different, nested log schema (winlogbeat) that the adapter does not read. It does have
  technique ids in `scope/apt3_mordor_playbook.xlsx`.
- **Log4Shell**, **GoldenSAML**: tens of events, Linux or cloud-identity telemetry, and no technique
  that the synthetic benchmark contains.

### How ATT&CK labels attach

**Per dataset, not per event.** Each dataset has a metadata file
(`datasets/compound/_metadata/<name>.yaml`) with an `attack_mappings` list of technique, sub-technique
and tactic ids. No event carries a label, and `attack_mappings` records no order. (Each file also has a
`simulation.adversary_view` transcript of the attacker's commands in order; it was not used.)
Consequences:

- Mapper precision and recall **per event cannot be measured** on this data. What can be measured is
  the set of techniques the mapper reports for a dataset against the set the dataset is labelled with.
- There is no ground truth for which events belong to the attack, so incident-grouping quality can
  only be measured in a composed timeline, where the source dataset of each event is known.

### Are benign events present?

Yes, but only as operating-system background. Each capture is 10 to 14 minutes of everything one
Windows host logged: 40,000 to 60,000 events, of which the attack is a small part (dataset 02 has 138
process creations, 102 of them by the user account the simulation ran as). There is no benign *user*
activity (nobody is working on the machine) and no multi-day baseline.

One thing in the captures is neither attack nor normal use: **every capture ends with the operator
stopping the packet trace** (`netsh trace stop`). Windows then runs a diagnostic script that starts
`cmd.exe`, `reg.exe`, `wevtutil.exe`, `certutil.exe` and others dozens of times, under the same
account the attack ran as. Section 3 shows how much of the result this accounts for.

### Structure of a real event

One JSON object per line. Every event has `@timestamp`, `Channel`, `EventID`, `Hostname`, `Message`,
`SourceName`, `Task`, `TimeCreated`; the rest depends on the event type. Dataset 02 by channel:
Sysmon 37,592; PowerShell 3,075 + 461; Security 1,181; Application 143; System 30. Sysmon event 10
(process access) alone is 26,468 events. A Sysmon process-creation event, shortened:

```json
{"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": "1", "Hostname": "ACCT01.pandalab.com",
 "@timestamp": "2023-08-15T05:33:54.484Z", "UtcTime": "2023-08-16 00:33:54.465",
 "Image": "C:\\Windows\\System32\\wermgr.exe", "CommandLine": "\"C:\\Windows\\system32\\wermgr.exe\" ...",
 "User": "NT AUTHORITY\\SYSTEM", "ProcessGuid": "{19de6d3b-...}", "ParentImage": "...", "IntegrityLevel": "System"}
```

Each LSASS dataset also ships Zeek logs (`conn.log` in tab-separated Zeek format), which record
bytes per connection; Sysmon network events do not.

### Shortlist against the synthetic benchmark

Techniques labelled in the seven LSASS datasets, and whether the synthetic benchmark contains them:

| Technique | Datasets | In synthetic data | Mapper has a rule |
|---|---|---|---|
| T1204.002 Malicious File | 7 / 7 | yes | yes (Office app, then script host) |
| T1082 System Information Discovery | 7 / 7 | yes | yes (`systeminfo.exe`) |
| T1033 System Owner/User Discovery | 7 / 7 | no (the generator labels `whoami.exe` as T1082) | yes (`whoami.exe`) |
| T1003.001 LSASS Memory | 7 / 7 | yes | yes (`procdump.exe` only) |
| T1041 Exfiltration Over C2 Channel | 6 / 7 | yes | yes |
| T1105 Ingress Tool Transfer | 4 / 7 | no | no |
| T1057 Process Discovery | 2 / 7 | no | no |
| T1055.002, T1134.001, T1543.003, T1012 | 1 or 2 each | no | no |
| T1587.001, T1608.001 (Resource Development) | 7 / 7 | no | excluded: the metadata says host and network data do not include the development of the malicious file (T1587.001); staging it on the attacker's server (T1608.001) is excluded on our judgement that victim telemetry cannot show it |

Overlap with the synthetic benchmark: T1204.002, T1082, T1003.001, T1041. None of the datasets
contains T1078, T1110, T1059.001 as a labelled step, T1068, T1021 or T1005, so the synthetic attack
patterns A, C and D have no real counterpart here. The closest is pattern B without its phishing and
lateral-movement steps.

## 2. Adapter (`data/adapters/otrf.py`)

Contract 1 was not changed to fit the data. Each real field maps to a contract field, is used to
derive one, or is dropped and counted. An event that cannot be given a required field is dropped;
no value is made up.

| Contract-1 field | Real source | Notes |
|---|---|---|
| `event_id` | none in the data | Made by the adapter: `evt-<dataset tag>-<running number>`, numbered in millisecond time order. |
| `timestamp` | `@timestamp` | Truncated to seconds. Order within a second survives only in the event number. |
| `source` | `Channel` | `sysmon` or `security`. |
| `user` | Sysmon 1/3/11 `User`; Sysmon 10 `SourceUser`; Security `TargetUserName` | Domain prefix removed, lower case. |
| `device` | `Hostname` | Without the domain, upper case. |
| `action` | `EventID` | Sysmon 1 → `process_execution`; 3 → `network_connection`; 10 → `process_access`; 11 → `file_create`; Security 4624 → `logon_success` / `rdp_session` / `network_logon` by `LogonType`; 4625 → `logon_failure`; 4634, 4647 → `logoff`. |
| `process` | `Image`, `SourceImage` | File name only, lower case. |
| `source_ip` | Sysmon 3 `SourceIp`; Security `IpAddress` | For every other event the contract still requires a value. The adapter uses **the host's own address, derived** as the most frequent source address of that host's outbound connections. This is a derivation, not a logged value. |
| `destination_ip` | Sysmon 3 `DestinationIp` | Null elsewhere; for a remote logon it is the host's address. |
| `destination_port` | Sysmon 3 `DestinationPort` | Null elsewhere. |
| `byte_count` | Zeek `conn.log` `orig_bytes`, joined on the connection 4-tuple | **Almost never available**: see below. |

### What had no clean equivalent

| Real information | Events affected (7 datasets) | What the adapter does | Consequence |
|---|---|---|---|
| **Target of a process access** (Sysmon 10 `TargetImage`) | 202,193 events, 1,981 of them targeting `lsass.exe` | Keeps the event as `process_access` with the *source* process; the target is dropped | **LSASS access, the subject of all seven datasets, is invisible after adaptation.** |
| Command line and parent process (Sysmon 1) | 948 process creations | Dropped | `rundll32 comsvcs.dll MiniDump`, encoded PowerShell and "Office spawned a shell" cannot be recognised. |
| File name (Sysmon 11 `TargetFilename`) | 7,914 file creations | Dropped | A dump file or a downloaded tool cannot be recognised (T1105). |
| PowerShell script text (all events in the two PowerShell channels; ids 4103–4106 and 800 are 14,706 of them) | 14,821 events | Event dropped: no user field and nowhere to put the text | Script-based dumping (dataset 04) is invisible. |
| Image loads, registry (Sysmon 7, 12, 13) | 105,789 events | Event dropped | Service creation and DLL-based techniques (T1543.003, T1055.002) are invisible. |
| Object access (Security 4663) | 24 | Event dropped | In dataset 02 two of them name `lsass.exe` as the object opened by `procdump64.exe`. |
| Outbound bytes | 2,746 network events | Null unless Zeek fully observed the sender | See next paragraph. |
| Service, batch and system logons (Security 4624 types 0, 4, 5) | 80 | Dropped, counted | Not user sessions. |
| Events without a user | 18 | Dropped, counted | – |

Event types that could arguably have been mapped and were not, with the reason:

| Real event | Count | Why not |
|---|---|---|
| Security 4688 (process creation) | 277 | Duplicates Sysmon 1 where both exist; kept one source to avoid double counting. |
| Security 4672 / 4703 (privileges assigned / adjusted) | 85 / 469 | The nearest action is `privilege_change`, but these fire on every administrator logon; the T1068 rule would then fire on all of them. |
| Security 4656 (handle requested) | 324 | Nearest action is `file_access`, without the object it would say nothing. |
| Sysmon 22 (DNS query) | 1,421 | Contract 1 has no field for a domain name. |
| Sysmon 17 / 18 (named pipes) | 2,937 | No field for a pipe name. |
| Security 5156 / 5158 (filtering platform) | 706 / 953 | No user field; duplicates Sysmon 3. |

In total 140,313 of 354,229 raw events have no contract-1 representation; with the 98 dropped for a
missing user or a non-user logon, 140,411 (39.6%) are not adapted. 213,818 are adapted, 202,193 of
which are `process_access` events that have lost their target.

The adapter also introduces values the contract's examples do not use: `action` values
`process_access`, `file_create` and `network_logon`, and `source` values `sysmon` and `security`.
(`network_logon` and `rdp_session` do not occur in the LSASS data: all ten kept logons are local.)

**Byte counts.** Sysmon does not log bytes. Zeek does, but in these captures almost every connection
record is one-sided (states `SHR`, `OTH`, `RSTRH`: only the responder's packets were captured), so
`orig_bytes` is 0 for a connection that visibly carried megabytes back. The adapter therefore sets
`byte_count` only when Zeek's connection state shows it saw the sender **and** Zeek reports no missed
bytes. The second condition was added after review: one connection (dataset 06, to port 6666) showed
26 MB sent, but Zeek had seen a single sender packet and the whole figure was its estimate from a
sequence-number gap. With both conditions, **none of the 2,746 adapted network events has a measured
outbound byte count**, and the volume-based exfiltration rule never fires on real data.
(The first version of this result counted that estimate as a detection: T1041 in 1 of 6 datasets and
F1 0.421. The corrected figures are 0 of 6 and F1 0.404.)

**Clocks.** `@timestamp` and Sysmon's own `UtcTime` differ by about 19 hours in five datasets and by
7 hours in two (03 and 07); Zeek follows the `UtcTime` clock. The adapter uses `@timestamp` throughout
and joins Zeek on the connection 4-tuple, not on time, so no result depends on the offset.

**Graph caveat.** When real events are loaded, the graph's `IP.internal` flag still uses the bank's
`10.` prefix, so it is inverted for this lab. Nothing reported here uses that flag (the mapper has its
own environment), but the label-free heuristic filter and `/graph` output would.

### Environment used for the mapper

`core/environment.py`, `PANDALAB`: internal network = the two host subnets seen in the captures
(`192.168.*`) plus multicast noise; built-in accounts `system`, `network service`, `local service`;
**no** server list, **no** administrator list, **no** business hours, because nothing in the data says
what they are. The attacker's address (`10.0.5.13`, `10.0.5.14`) is a private address, so "external"
has to mean "outside our subnets", not "public".

## 3. Mapper on real data

Rules added for real Windows tools are in `core/attack_mapper.py` (`PROCESS_RULES`, marked "added
for M9"): 23 standard tools mapped from general knowledge of what each is for, plus one rule for
programs with a document or picture extension before `.exe`. Disclosure:

- The tool list was written after the survey had shown which programs occur; 12 of the 23 occur in
  the data, and 4 of the 19 correct findings come from these rules.
- The double-extension rule was written after seeing `happy_image.jpeg.exe` in dataset 02.
- `procdump64.exe` was added and does occur in dataset 02 (as a child of `procdump.exe`, which
  already had a rule, so it does not change the score).
- Names of the other dumping tools in the data (`sharpdump.exe`, `nanodump.x64.exe`,
  `outflank-dumpert.exe`) were deliberately **not** added: that would be matching file names from the
  test set.
- With the rules as they were before M9, the reviewer measured precision 0.630, recall 0.378,
  F1 0.472 on the first version of this result: the M9 additions lowered the score, so they were not
  tuned towards it.

Result (`evaluation/results/m9_real_data.txt`), technique sets per dataset, 7 datasets, 45 labelled
(dataset, technique) pairs:

| | Precision | Recall | F1 |
|---|---|---|---|
| **All seven datasets (micro), the headline** | **0.388** (19 of 49 reported) | **0.422** (19 of 45 labelled) | **0.404** |
| Best dataset (02) | 0.400 | 0.667 | 0.500 |
| Worst dataset (01) | 0.273 | 0.429 | 0.333 |
| Secondary: capture teardown left out | 0.679 (19 of 28) | 0.422 | 0.521 |
| Secondary: Resource Development labels left in (59 pairs) | 0.388 | 0.322 | 0.352 |

Per labelled technique (datasets where the mapper reported it / datasets labelled with it):

| Technique | Found | Why |
|---|---|---|
| T1082 System Information Discovery | 7 / 7 | `systeminfo.exe` |
| T1033 System Owner/User Discovery | 7 / 7 | `whoami.exe` |
| T1057 Process Discovery | 2 / 2 | `tasklist.exe` |
| T1012 Query Registry | 1 / 1 | `reg.exe` |
| **T1003.001 LSASS Memory** | **1 / 7** | Only where the tool is literally `procdump.exe`. The other six need the process-access target, the command line or script text. |
| T1204.002 Malicious File | 1 / 7 | Only the double-extension file name. |
| T1041 Exfiltration Over C2 Channel | 0 / 6 | No measured outbound byte count exists. |
| T1105 Ingress Tool Transfer | 0 / 4 | Needs a file name or inbound bytes. |
| T1055.002, T1134.001, T1543.003 | 0 / 4 | Need image-load, token or registry events. |

Where it fails, in one sentence: **the mapper finds the techniques that are a program name and
misses the ones that are a behaviour.** The technique all seven datasets exist to demonstrate is
found once.

### What the "false positives" really are

30 reported (dataset, technique) pairs are not in the datasets' labels. They are **not** mostly
unlabelled attacker activity. Using process lineage from the raw events (which contract 1 does not
carry), **252 of the 288 mapped events (87%) descend from the operator's `trace stop` command**:
capture tooling that Windows runs under the attacker's account. 21 of the 30 unlabelled pairs come
only from that. Two of those mappings are also wrong in meaning, not just unlabelled: `wevtutil epl`
exports a log (the rule says log clearing, T1685.005) and `certutil -store` reads a certificate store
(the rule says ingress transfer, T1105). Both errors follow from mapping a program name without its
command line.

The 9 unlabelled pairs that remain without the teardown are T1059.003 seven times (the attacker's own
`cmd.exe`, real but not in the label lists) and T1218.011 twice (`rundll32.exe` from a scheduled task).

So the headline 0.388 precision stays as the honest figure for what the pipeline does with these
files as they are, and 0.679 is what it would be if the pipeline could tell capture tooling from
activity. It cannot, and neither figure is a false-alarm rate for normal operation.

## 4. Full pipeline on real data

One dataset at a time, 30-minute window (section 3 of the results file).

| Stage | What happened |
|---|---|
| Graph load | **Works.** 23,741 to 34,503 events per dataset; the composed timeline is 213,818 events, 213,956 nodes and 858,305 relationships. |
| Incident inference | **Works trivially.** One incident per dataset, because each capture is one user on one host for 10 to 14 minutes. |
| Trajectory | **Degrades badly, mostly because of the capture teardown.** Trajectories have 4 to 116 steps; pipeline trajectories on synthetic data have 1 to 8. Dataset 01: 116 steps from 137 events, 132 of which descend from the capture-stop command (`cmd.exe` and `reg.exe` alternating). Datasets 06 and 07, where the capture ended before the script ran, give 4 steps each. Separately, collapsing consecutive repeats does not help when two techniques alternate. |
| Historical matching | **Breaks.** Best similarity 0.20 to 0.25, always a MITRE group record; no hand-written sequence is the top match for any dataset. Nothing in the historical database resembles a real trajectory. |
| Prediction | **Breaks.** In three datasets (02, 06, 07) the last step is a technique the 11 hand-written sequences do not contain, and the model falls back to overall frequency (T1059, p = 0.163). In three (01, 03, 05) it gives an ordinary first-order prediction after `cmd.exe` (T1068, p = 0.286), and in one (04) it predicts T1558 with p = 1.0 from a single historical occurrence. None of these should be believed, and none can be scored: the labels have no order. |
| Hub suppression | **Misfires.** Every host is classed as shared infrastructure, because the three built-in system accounts plus one or two people make four "users". Linking then happens only through the user account. |

## 5. Composed timeline

`evaluation/real_data_eval.py`, `compose()`. Each dataset keeps its own events, hosts, users and
addresses; only its clock is moved onto one morning:

- Group A, three different hosts, overlapping: dataset 02 at T0, 03 at T0 + 3 min, 04 at T0 + 6 min.
- Group B, the same host, one after another: 01 at T0 + 40 min, then 05, 06 and 07 starting 5, 20
  and 45 minutes after the previous one ends.

Because no event is labelled as attack, the reference grouping is "the mapped events of each source
dataset" (252 of those 288 events are capture teardown, see section 3). The question is only whether
inference keeps the seven captures apart.

| Window (min) | Incidents inferred | Datasets kept whole (ceiling 6) | Incidents mixing 2+ datasets | Pair precision | Pair recall | Pair F1 |
|---|---|---|---|---|---|---|
| 5 | 6 | 4 / 7 | 1 | 0.975 | 0.989 | 0.982 |
| 15 | 5 | 3 / 7 | 2 | 0.679 | 0.989 | 0.805 |
| **30 (default)** | **3** | **2 / 7** | **1** | **0.432** | **0.989** | **0.601** |
| 60 | 2 | 1 / 7 | 1 | 0.414 | 0.989 | 0.584 |

"Kept whole" means an inferred incident equals the dataset's mapped events exactly; dataset 01 has
one mapped event by a second account that can never join an incident, so 6 of 7 is the ceiling.

At the default window five of the seven captures (01, 03, 04, 05, 06) merge into one incident of
234 events, because the account `pedro.gustavo` (the account the payload runs under in six of the
seven datasets) is active in all of them, on three different hosts, within 30 minutes of each other.
Dataset 02 (a different user) and 07 (46.7 minutes later) stay separate.

**This result is fragile.** The link that joins group A to group B is a gap of 29.6 minutes, just
under the window. Moving group B by one minute changes the answer:

| Group B starts at | Incidents at 30 min | Mixing 2+ datasets | Largest incident |
|---|---|---|---|
| T0 + 30, 35 or 40 min | 3 | 1 | 234 events |
| T0 + 41, 45, 50 or 60 min | 4 | 2 | 182 events |

What does hold across the sweep: captures that share an account and fall within the window are merged
whatever their hosts, and a 5-minute window separates most of them but would fragment slow synthetic
incidents. On synthetic data the generator guaranteed this situation never arises.

## 6. Synthetic and real side by side

| | Synthetic benchmark (noisy profile, seed 42) | Real (7 LSASS datasets) |
|---|---|---|
| Events | 3,986 (12 days, 11 hosts, 10 users) | 213,818 adapted from 354,229 raw (7 captures of 10–14 min, 1 host each) |
| Labels | per event | per dataset, unordered |
| Mapper, per event, exact technique | F1 0.706 mean over 13 seeds (P 0.585, R 0.893) | **cannot be measured** |
| Mapper, technique set per dataset | P 0.789, R 1.000, F1 0.882 (whole dataset as one, n = 1) | **P 0.388, R 0.422, F1 0.404** (7 datasets, 45 pairs) |
| The dataset's main technique found | – | T1003.001 in 1 of 7 |
| Incidents kept apart, 30-minute window | 8 of 24 reproduced exactly (never interleaved on one account by construction) | 2 of 7 in a composed timeline with a shared account; fragile to placement |
| Pipeline trajectory length | 1–8 steps (51 inferred incidents) | 4–116 steps (7 incidents) |
| Pipeline incidents whose best historical similarity is 1.0 | 3 of 51 | 0 of 7 (best 0.25) |
| Prediction, strict end to end | top-1 0.367 (33 of 90 true transitions) | cannot be scored (no order in the labels) |

Every row compares pipeline output with pipeline output. The synthetic figures on ground-truth
trajectories (similarity 1.000 for known patterns, top-1 0.722) are not in this table because there
is no real counterpart for them.

The real numbers are worse on every line, and they are still optimistic in one respect: the tool
list was written after seeing which programs occur.

## 7. What this real data cannot tell us

- **Per-event accuracy.** No event is labelled, so there is no precision or recall per event, no
  confusion matrix, and no way to tell an unlabelled true technique from a false alarm.
- **Order.** `attack_mappings` is unordered, so trajectory order, order-aware matching and next-step
  prediction cannot be scored with it. (The command transcript in each metadata file could supply an
  order; it was not used.)
- **What real noise looks like.** 87% of what the mapper flags is the capture-stop script. That is
  neither attack nor ordinary background, so these files say little about either.
- **Exfiltration detection.** No outbound byte count was actually measured by the capture.
- **False-alarm rate in normal operation.** Nobody is working on these hosts; there is no benign
  user activity and no multi-day baseline.
- **Incident grouping in the wild.** One host, one capture, minutes long. The composed timeline is
  our construction, and its "truth" is the source file, not the attack.
- **The synthetic attack patterns.** Valid accounts, brute force, privilege escalation, lateral
  movement and collection do not occur in these seven datasets.
- **Generalisation.** Seven runs of one scenario by one lab, differing in the dumping tool.

## 8. Sources and licences

- OTRF Security-Datasets, github.com/OTRF/Security-Datasets, MIT licence, copyright 2021 Open Threat
  Research Forge. Datasets used: `datasets/compound/LSASS_campaign_01` to `_07` with their
  `_metadata/*.yaml` (author per metadata: Jose Rodriguez, @Cyb3rPandaH), and for the retry
  `datasets/compound/apt29/day1` with `apt29/emulationplans/apt29.xlsx` (creator per README:
  Roberto Rodriguez, @Cyb3rWard0g; the scenario is MITRE's ATT&CK Evaluations round 2 emulation plan).
- The data is not copied into this repository: `data/external/` and `data/processed/` are
  git-ignored. Reproduce with `python -m evaluation.real_data_eval` and
  `python -m evaluation.real_data_apt29`, then `python -m knowledge_graph.build --reset` to restore
  the synthetic graph (both scripts replace the Neo4j contents).
- MITRE ATT&CK v19.2 for technique names and tactics (see `data/mitre/VERSION`).

## 9. Time-boxed retry on a multi-step dataset (apt29 day 1)

The LSASS captures are single-host and about one technique family, the wrong shape for a pipeline
that reconstructs multi-stage trajectories. As a time-boxed check, one multi-step dataset was adapted
and run: `apt29` day 1, an emulation of a whole intrusion across four hosts (initial breach,
collection, exfiltration, privilege escalation, credential access, lateral movement, 33 minutes,
196,081 events). Code: `data/adapters/apt29.py`, `evaluation/real_data_apt29.py`. Results:
`evaluation/results/m9_real_data_apt29.txt`.

**Labels.** The emulation plan lists 25 ordered steps with technique names in 2020 wording. A name
became an id only by exact match with a current ATT&CK technique name: 31 distinct ids. 13 names had
no exact match and were left out rather than mapped by judgement (Command-Line Interface, Credential
Dumping, Windows Admin Shares, Exfiltration Over Command and Control Channel, Remote File Copy and
eight others). So the label set under-represents exactly the credential-access, exfiltration and
lateral-movement steps.

**Adapter.** 18,977 of 196,081 events adapted (9.7%). 152,939 have no contract-1 representation;
24,103 more had to be dropped because this older Sysmon version records no user on process-access and
file-creation events, and the user could be derived (from the process's own creation event) only for
processes that started during the capture.

**Mapper**, with the rules frozen before this dataset was looked at:

| | Precision | Recall | F1 | Found |
|---|---|---|---|---|
| Exact ids (**the result**) | 0.250 (1 of 4 reported) | 0.032 (1 of 31) | **0.057** | T1059.001 |
| Parent level | 0.667 | 0.069 (2 of 29) | 0.125 | T1059, T1021 |
| With 5 tool rules written after seeing the data (not the result) | 0.429 | 0.097 | 0.158 | + T1070.004, T1569.002 |

24 events are mapped in the whole capture. The intrusion is carried out almost entirely inside
PowerShell sessions (discovery, collection, staging, credential access), and PowerShell script text
has no place in contract 1.

**Pipeline.** One incident at the default window, spanning two hosts (SCRANTON 21 events, NASHUA 3)
through the shared account, which is the first real example of cross-host grouping working. Its
trajectory has 5 parent-level steps (T1059 > T1218 > T1059 > T1021 > T1059) against a 45-step plan:
technique overlap 0.067, order similarity 0.089, 2 of 29 labelled parent techniques present. Best
historical match 0.30; the prediction (T1068, p = 0.286) is the generic one after T1059.

**Verdict of the retry.** It does not validate better than LSASS; it validates worse (F1 0.057
against 0.404), for the same reason and more of it. The multi-step shape is right for the pipeline,
but the steps are invisible after normalization. As instructed, work stopped here: the LSASS result
stays as the real-data validation, and the contract finding at the top of this document is the
headline.
