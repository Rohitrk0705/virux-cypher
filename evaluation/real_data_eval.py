"""M9: run the pipeline on real host telemetry (OTRF Security-Datasets, LSASS campaigns).

  python -m evaluation.real_data_eval            # then: python -m knowledge_graph.build --reset

WARNING: this REPLACES the contents of the Neo4j graph several times. Rebuild
the synthetic graph afterwards with the command above.

What can and cannot be measured here:
- Labels are per DATASET (a list of techniques), not per event. So the mapper is
  scored on the SET of techniques it reports for a dataset against the set the
  dataset is labelled with. Per-event precision and recall cannot be computed.
- The label list is the simulation's documented steps, not an inventory of
  everything that happened: a reported technique that is not in the list may be
  real but unlabelled (cmd.exe ran in every capture; T1059.003 is in no list).
- Resource Development techniques are excluded from the label sets. The metadata
  says host and network data do not include the development of the malicious
  file (T1587.001); staging it on the attacker's server (T1608.001) is excluded
  on our own judgement that victim telemetry cannot show it. The score with
  both left in is printed as well.
- Every capture ends with the operator stopping the packet trace (`netsh trace
  stop`), which makes Windows run a diagnostic script that launches cmd.exe,
  reg.exe, wevtutil.exe and others dozens of times under the attacker's account.
  Those launches are capture tooling, not attack and not normal use. The
  headline score keeps them (the pipeline cannot tell); a second score leaves
  them out, using process lineage from the RAW events, which contract 1 does
  not carry and the pipeline never sees.
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from core.attack_mapper import AttackMapper
from core.environment import PANDALAB
from data.adapters import otrf
from knowledge_graph import config, loader
from prediction.markov import predict_next
from prediction.similarity import match_historical
from temporal import incidents
from temporal.trajectory import get_trajectory

from . import incident_match

DATASETS = [f"LSASS_campaign_0{n}" for n in range(1, 8)]
NOT_OBSERVABLE = {"T1587.001", "T1608.001"}
WINDOWS = [5, 15, 30, 60]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


TRACE_STOP = re.compile(r"\btrace\s+stop\b", re.I)


def teardown_events(report):
    """event ids of process creations that descend from the capture-stop command."""
    lineage = report["process_lineage"]
    children = {}
    for event_id, (guid, parent, _) in lineage.items():
        children.setdefault(parent, []).append((event_id, guid))
    found = set()
    frontier = [(event_id, guid) for event_id, (guid, _, command) in lineage.items() if TRACE_STOP.search(command)]
    while frontier:
        event_id, guid = frontier.pop()
        if event_id not in found:
            found.add(event_id)
            frontier += children.get(guid, [])
    return found


def adapter_section(reports):
    lines = ["=== 1. adapter: real events -> contract 1 ===",
             f"{'dataset':<20}{'raw':>8}{'adapted':>9}{'kept %':>8}{'proc exec':>10}{'network':>9}"
             f"{'proc access':>12}{'file create':>12}{'logon/off':>10}{'lsass target lost':>19}{'bytes known':>12}"]
    for r in reports:
        a = r["adapted_by_action"]
        logons = sum(a.get(k, 0) for k in ("logon_success", "logon_failure", "logoff", "rdp_session", "network_logon"))
        lines.append(
            f"{r['dataset']:<20}{r['raw_events']:>8}{r['adapted_events']:>9}{r['adapted_events'] / r['raw_events']:>8.1%}"
            f"{a.get('process_execution', 0):>10}{a.get('network_connection', 0):>9}{a.get('process_access', 0):>12}"
            f"{a.get('file_create', 0):>12}{logons:>10}{r['lost'].get('... of which the target was lsass.exe', 0):>19}"
            f"{r['lost'].get('network events with a byte count from Zeek', 0):>12}")
    dropped = Counter()
    for r in reports:
        for key, n in r["raw_by_type"].items():
            channel, event_id = key.rsplit(":", 1)
            if (channel, int(event_id) if event_id.lstrip("-").isdigit() else None) not in otrf.EVENT_TYPES:
                dropped[key] += n
    total_raw = sum(r["raw_events"] for r in reports)
    lines.append(f"\nevent types with no contract-1 representation, all datasets ({sum(dropped.values())} of "
                 f"{total_raw} raw events). Top ten:")
    for key, n in dropped.most_common(10):
        lines.append(f"  {key:<62}{n:>8}")
    return "\n".join(lines)


def mapper_section(adapted):
    mapper = AttackMapper(environment=PANDALAB)
    lines = ["=== 2. rule-based mapper vs the datasets' own ATT&CK labels (technique SETS per dataset) ===",
             f"{'dataset':<20}{'labelled':>9}{'reported':>9}{'tp':>4}{'fp':>4}{'fn':>4}{'prec':>7}{'recall':>8}{'f1':>7}"
             f"{'events mapped':>15}  found | missed | reported but not labelled"]
    totals, per_technique, mapped_all, outcomes = Counter(), {}, {}, {}
    for name in DATASETS:
        events, report = adapted[name]
        mapped, rules = mapper.map_with_rules(events)
        mapped_all[name] = (mapped, rules)
        labelled = set(report["labels"]) - NOT_OBSERVABLE
        reported = {m["technique_id"] for m in mapped}
        tp, fp, fn = labelled & reported, reported - labelled, labelled - reported
        outcomes[name] = (tp, fp, fn)
        totals.update(tp=len(tp), fp=len(fp), fn=len(fn))
        for t in labelled:
            per_technique.setdefault(t, [0, 0])[1] += 1
            per_technique[t][0] += t in reported
        p, r, f = prf(len(tp), len(fp), len(fn))
        lines.append(f"{name:<20}{len(labelled):>9}{len(reported):>9}{len(tp):>4}{len(fp):>4}{len(fn):>4}"
                     f"{p:>7.3f}{r:>8.3f}{f:>7.3f}{len(mapped):>15}  {' '.join(sorted(tp)) or '-'} | "
                     f"{' '.join(sorted(fn)) or '-'} | {' '.join(sorted(fp)) or '-'}")
    teardown = {name: teardown_events(adapted[name][1]) for name in DATASETS}
    alt = {"teardown": Counter(), "all labels": Counter()}
    in_teardown = 0
    for name in DATASETS:
        mapped, _ = mapped_all[name]
        in_teardown += sum(1 for m in mapped if m["event_id"] in teardown[name])
        labelled = set(adapted[name][1]["labels"]) - NOT_OBSERVABLE
        reported = {m["technique_id"] for m in mapped if m["event_id"] not in teardown[name]}
        alt["teardown"].update(tp=len(labelled & reported), fp=len(reported - labelled), fn=len(labelled - reported))
        labelled, reported = set(adapted[name][1]["labels"]), {m["technique_id"] for m in mapped}
        alt["all labels"].update(tp=len(labelled & reported), fp=len(reported - labelled), fn=len(labelled - reported))
    p, r, f = prf(totals["tp"], totals["fp"], totals["fn"])
    lines.append(f"{'ALL (micro)':<20}{totals['tp'] + totals['fn']:>9}{totals['tp'] + totals['fp']:>9}{totals['tp']:>4}"
                 f"{totals['fp']:>4}{totals['fn']:>4}{p:>7.3f}{r:>8.3f}{f:>7.3f}"
                 f"{sum(len(m) for m, _ in mapped_all.values()):>15}")
    lines.append(f"sample: {len(DATASETS)} datasets, {totals['tp'] + totals['fn']} labelled (dataset, technique) pairs. "
                 "THIS IS THE HEADLINE.")
    total_mapped = sum(len(m) for m, _ in mapped_all.values())
    t = alt["teardown"]
    p, r, f = prf(t["tp"], t["fp"], t["fn"])
    lines.append(f"\nsecondary, capture teardown left out: {in_teardown} of {total_mapped} mapped events descend from the "
                 f"operator's 'trace stop' command. Without them: reported {t['tp'] + t['fp']}, tp {t['tp']}, "
                 f"fp {t['fp']}, fn {t['fn']}; precision {p:.3f} recall {r:.3f} f1 {f:.3f}. "
                 "(Uses raw process lineage that the pipeline does not have.)")
    t = alt["all labels"]
    p, r, f = prf(t["tp"], t["fp"], t["fn"])
    lines.append(f"secondary, Resource Development labels left in ({t['tp'] + t['fn']} pairs): "
                 f"precision {p:.3f} recall {r:.3f} f1 {f:.3f}.")
    lines.append("\nper labelled technique: datasets in which the mapper reported it / datasets labelled with it")
    for t, (hit, n) in sorted(per_technique.items(), key=lambda kv: (-kv[1][1], kv[0])):
        lines.append(f"  {t:<11}{hit} / {n}")
    lines.append("\nwhich rule produced the mapped events (all datasets):")
    by_rule = Counter()
    for mapped, rules in mapped_all.values():
        by_rule.update(rules[m["event_id"]] for m in mapped)
    for rule, n in by_rule.most_common():
        lines.append(f"  {rule:<34}{n:>6}")
    return "\n".join(lines), mapped_all, teardown


def load_graph(events, mapped):
    loader.reset()
    loader.apply_schema()
    loader.load_events(events)
    loader.load_mappings(mapped, config.SOURCE_MAPPER)


def pipeline_section(adapted, mapped_all, teardown):
    lines = ["=== 3. full pipeline per dataset (graph -> incidents -> trajectory -> match -> predict), "
             f"window {config.WINDOW_MINUTES} min ==="]
    for name in DATASETS:
        events, report = adapted[name]
        mapped, _ = mapped_all[name]
        load_graph(events, mapped)
        inferred = incidents.materialize(config.METHOD_MAPPER)
        stats = loader.graph_stats()
        labelled = set(report["labels"]) - NOT_OBSERVABLE
        lines.append(f"\n{name}: {len(events)} events, {len(mapped)} mapped, graph "
                     f"{sum(stats['nodes'].values())} nodes / {sum(stats['relationships'].values())} relationships, "
                     f"{len(inferred)} incident(s)")
        for inc in sorted(inferred, key=lambda i: -len(i["event_ids"]))[:2]:
            trajectory = get_trajectory(inc["incident_id"], config.METHOD_MAPPER, config.SOURCE_MAPPER)
            steps = [t["id"] for t in trajectory["techniques"]]
            match = match_historical(trajectory)["matches"]
            prediction = predict_next(trajectory)
            top = prediction["predictions"][0] if prediction["predictions"] else None
            noise = sum(1 for e in inc["event_ids"] if e in teardown[name])
            lines.append(f"  {inc['incident_id']}: {len(inc['event_ids'])} events, {len(steps)} trajectory steps; "
                         f"{noise} of the events descend from the capture-stop command")
            lines.append(f"    trajectory: {' > '.join(steps)}")
            lines.append(f"    labelled techniques in the trajectory: {len(labelled & set(steps))} of {len(labelled)}"
                         f"; steps whose technique is not in the labels: "
                         f"{sum(1 for s in steps if s not in labelled)} of {len(steps)}")
            lines.append(f"    top historical match: "
                         + (f"{match[0]['attack_id']} similarity {match[0]['similarity']}" if match else "none"))
            lines.append("    predicted next: " + (f"{top['technique_id']} p={top['probability']}" if top
                                                   else "none") + f"  [{prediction['evidence'][0]}]")
    return "\n".join(lines)


def shift(events, start):
    """Move a dataset so that its first event is at `start`; order and gaps are kept."""
    stamp = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    delta = start - stamp(events[0]["timestamp"])
    moved = [{**e, "timestamp": (stamp(e["timestamp"]) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")} for e in events]
    return moved, stamp(moved[-1]["timestamp"])


def compose(adapted, group_b_start=40):
    """One timeline from the seven datasets. Each dataset keeps its own events,
    hosts, users and addresses; only its clock is moved.
      group A - three different hosts, overlapping:  02 at T0, 03 at T0+3 min, 04 at T0+6 min
      group B - the same host (MKT01), one after another: 01 at T0+40 min, then 05, 06 and 07
                starting 5, 20 and 45 minutes after the previous one ends
    """
    t0 = datetime(2023, 9, 10, 9, 0, 0, tzinfo=timezone.utc)
    plan, timeline = [], []
    for name, offset in (("LSASS_campaign_02", 0), ("LSASS_campaign_03", 3), ("LSASS_campaign_04", 6)):
        moved, end = shift(adapted[name][0], t0 + timedelta(minutes=offset))
        plan.append((name, moved[0]["timestamp"], moved[-1]["timestamp"]))
        timeline += moved
    cursor = t0 + timedelta(minutes=group_b_start)
    for name, gap_after in (("LSASS_campaign_01", 5), ("LSASS_campaign_05", 20), ("LSASS_campaign_06", 45),
                            ("LSASS_campaign_07", 0)):
        moved, end = shift(adapted[name][0], cursor)
        plan.append((name, moved[0]["timestamp"], moved[-1]["timestamp"]))
        timeline += moved
        cursor = end + timedelta(minutes=gap_after)
    timeline.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    return timeline, plan


def composition_section(adapted):
    timeline, plan = compose(adapted)
    mapped, _ = AttackMapper(environment=PANDALAB).map_with_rules(timeline)
    source = {}
    for name in DATASETS:
        tag = adapted[name][1]["tag"]
        source.update({m["event_id"]: name for m in mapped if m["event_id"].startswith(f"evt-{tag}-")})
    load_graph(timeline, mapped)
    stats = loader.graph_stats()
    lines = ["=== 4. several datasets composed into one timeline: can incidents be told apart? ===",
             compose.__doc__.strip().split("\n", 1)[1],
             f"composed timeline: {len(timeline)} events, {len(mapped)} mapped; graph "
             f"{sum(stats['nodes'].values())} nodes / {sum(stats['relationships'].values())} relationships",
             "placement:"]
    lines += [f"  {name:<20}{start} .. {end}   host {', '.join(adapted[name][1]['host_addresses'])}; "
              f"human accounts {', '.join(u for u in adapted[name][1]['users'] if u not in PANDALAB.system_accounts and not u.endswith('$'))}"
              for name, start, end in plan]
    truth = [{"incident_id": name, "pattern": "-", "variant": "-", "pace": "-", "techniques": [],
              "event_ids": sorted(e for e, s in source.items() if s == name)} for name in DATASETS]
    ts = {e["event_id"]: 0 for e in timeline}
    lines.append("\nReference grouping = the mapped events of each source dataset (there are no per-event attack "
                 "labels, so 'the incident' is everything the mapper flagged in that capture).")
    lines.append("'kept whole' = an inferred incident equals the dataset's mapped events exactly. Dataset 01 has one "
                 "mapped event by a second account that can never join an incident, so the ceiling is 6 of 7.")
    lines.append(f"{'W(min)':>7}{'inferred':>9}{'datasets kept whole':>20}{'mixing 2+ datasets':>20}"
                 f"{'coverage':>10}{'purity':>8}{'pairP':>7}{'pairR':>7}{'pairF1':>8}")
    detail = None
    for window in WINDOWS:
        inferred = incidents.infer_incidents(config.METHOD_MAPPER, window)
        s = incident_match.score(truth, inferred, ts, {})
        lines.append(f"{window:>7}{s['inferred_incidents']:>9}{s['exact']:>15} / {len(DATASETS)}"
                     f"{s['merged_incidents']:>20}{s['mean_coverage']:>10.3f}{s['mean_purity']:>8.3f}"
                     f"{s['attack_pair_precision']:>7.3f}{s['attack_pair_recall']:>7.3f}{s['attack_pair_f1']:>8.3f}")
        if window == config.WINDOW_MINUTES:
            detail = inferred
    lines.append(f"\nincidents at W = {config.WINDOW_MINUTES} min, by source dataset of their events:")
    for inc in sorted(detail, key=lambda i: -len(i["event_ids"])):
        mix = Counter(source[e][-2:] for e in inc["event_ids"])
        lines.append(f"  {inc['incident_id']:<18}{len(inc['event_ids']):>5} events   "
                     + ", ".join(f"dataset {d}: {n}" for d, n in sorted(mix.items())))
    lines.append(f"\nsensitivity to the (arbitrary) start of group B, window {config.WINDOW_MINUTES} min:")
    for start in (30, 35, 40, 41, 45, 50, 60):
        other, _ = compose(adapted, start)
        other_mapped, _ = AttackMapper(environment=PANDALAB).map_with_rules(other)
        load_graph(other, other_mapped)
        found = incidents.infer_incidents(config.METHOD_MAPPER, config.WINDOW_MINUTES)
        mixed = sum(1 for i in found if len({source[e] for e in i["event_ids"]}) > 1)
        lines.append(f"  group B starts at T0 + {start:>2} min: {len(found)} incidents, {mixed} mixing 2+ datasets, "
                     f"largest {max(len(i['event_ids']) for i in found)} events")
    load_graph(timeline, mapped)
    hubs = [h for h in loader.run("hubs")]
    lines.append(f"\nhosts and addresses classed as shared infrastructure (>= {config.HUB_USERS} users) and ignored for "
                 f"linking: {', '.join(h['entity'] for h in hubs) or 'none'}")
    return "\n".join(lines)


def synthetic_section():
    """The same set-level measure on the synthetic benchmark, so the two can be put side by side."""
    events = json.loads(config.EVENTS_FILE.read_text())
    labels = {l["event_id"]: l["technique_id"] for l in json.loads(config.LABELS_FILE.read_text())}
    mapped = {m["event_id"]: m["technique_id"] for m in AttackMapper().map_events(events)}
    truth = incident_match.load_truth()
    lines = ["=== 5. the same technique-SET measure on the synthetic benchmark ==="]
    labelled, reported = set(labels.values()), set(mapped.values())
    p, r, f = prf(len(labelled & reported), len(reported - labelled), len(labelled - reported))
    lines.append(f"whole synthetic dataset as one 'dataset' ({len(events)} events): labelled {len(labelled)} "
                 f"techniques, reported {len(reported)}; precision {p:.3f} recall {r:.3f} f1 {f:.3f} (n = 1 dataset)")
    tp = fp = fn = 0
    for t in truth:
        want = {labels[e] for e in t["event_ids"]}
        got = {mapped[e] for e in t["event_ids"] if e in mapped}
        tp, fp, fn = tp + len(want & got), fp + len(got - want), fn + len(want - got)
    p, r, f = prf(tp, fp, fn)
    lines.append(f"per true incident, over the incident's own (attack) events only: {tp + fn} labelled "
                 f"(incident, technique) pairs; precision {p:.3f} recall {r:.3f} f1 {f:.3f} (n = {len(truth)} "
                 "incidents). This view cannot see techniques reported on benign events, which the real "
                 "per-dataset view does include, so it flatters the synthetic side.")
    return "\n".join(lines)


def main():
    adapted = {name: otrf.adapt(name) for name in DATASETS}
    print(adapter_section([adapted[n][1] for n in DATASETS]))
    print()
    text, mapped_all, teardown = mapper_section(adapted)
    print(text)
    print()
    print(pipeline_section(adapted, mapped_all, teardown))
    print()
    print(composition_section(adapted))
    print()
    print(synthetic_section())
    print("\nThe Neo4j graph now holds the composed real timeline. Restore the synthetic benchmark with:\n"
          "  python -m knowledge_graph.build --reset")


if __name__ == "__main__":
    main()
