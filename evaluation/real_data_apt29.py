"""M9 retry: one MULTI-STEP real dataset (OTRF apt29 day 1) through the pipeline.

  python -m evaluation.real_data_apt29 [--no-graph]   # then: python -m knowledge_graph.build --reset

WARNING: without --no-graph this REPLACES the contents of the Neo4j graph.

The LSASS captures are single-host and about one technique. This dataset is a
four-host emulation of a whole intrusion, with an ordered plan of steps. Labels
come from that plan (technique NAMES matched exactly to current ATT&CK names;
see data/adapters/apt29.py), so they are per dataset and per step, still not
per event.

The mapper rules are the ones frozen before this dataset was looked at. A second
row adds five rules written AFTER looking at it; that row is shown to make the
effect of fitting visible, and is not the result.
"""

import sys
from collections import Counter

from core import attack_mapper
from core.attack_mapper import AttackMapper
from core.environment import DMEVALS
from data.adapters import apt29
from knowledge_graph import config, loader
from prediction.historical import to_sequence
from prediction.markov import predict_next
from prediction.similarity import edit_distance, jaccard, match_historical
from temporal import incidents
from temporal.trajectory import get_trajectory

# Written after seeing which programs and ports occur in this capture. NOT part of the mapper.
POST_HOC_PROCESS_RULES = {
    "psexec.exe": ("T1569.002", "Execution", 0.70),
    "psexec64.exe": ("T1569.002", "Execution", 0.70),
    "sdelete.exe": ("T1070.004", "Stealth", 0.70),
    "sdelete64.exe": ("T1070.004", "Stealth", 0.70),
    "rar.exe": ("T1560.001", "Collection", 0.70),
}
SYSTEM = DMEVALS.system_accounts


def parent(technique_id):
    return technique_id.split(".")[0]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def set_scores(labelled, reported):
    exact = prf(len(labelled & reported), len(reported - labelled), len(labelled - reported))
    lp, rp = {parent(t) for t in labelled}, {parent(t) for t in reported}
    return exact, prf(len(lp & rp), len(rp - lp), len(lp - rp)), lp, rp


def mapper_rows(events, steps):
    labelled = {t for _, ids in steps for t in ids}
    rows = []
    frozen = AttackMapper(environment=DMEVALS).map_with_rules(events)
    original = dict(attack_mapper.PROCESS_RULES)
    try:
        attack_mapper.PROCESS_RULES.update(POST_HOC_PROCESS_RULES)
        fitted = AttackMapper(environment=DMEVALS).map_with_rules(events)
    finally:
        attack_mapper.PROCESS_RULES.clear()
        attack_mapper.PROCESS_RULES.update(original)
    for label, (mapped, rules) in (("rules frozen before this dataset (THE RESULT)", frozen),
                                   ("+ 5 tool rules written after seeing it", fitted)):
        reported = {m["technique_id"] for m in mapped}
        exact, by_parent, lp, rp = set_scores(labelled, reported)
        rows.append((label, mapped, rules, reported, exact, by_parent, lp, rp))
    return labelled, rows


def report(events, rep, run_graph):
    steps, unmatched = rep["plan_steps"], rep["unmatched_technique_names"]
    a = rep["adapted_by_action"]
    lines = ["=== apt29 day 1: adapter ===",
             f"raw events {rep['raw_events']}, adapted {rep['adapted_events']} "
             f"({rep['adapted_events'] / rep['raw_events']:.1%}); hosts {rep['adapted_by_host']}",
             f"adapted by action: {a}",
             f"dropped: {rep['dropped']}",
             f"lost: {rep['lost']}",
             f"time range {rep['time_range'][0]} .. {rep['time_range'][1]}; host addresses {rep['host_addresses']}",
             "",
             "=== labels from the emulation plan ===",
             f"{len(steps)} plan steps; {len({n for _, ids in steps for n in ids})} distinct technique ids matched by "
             f"exact current ATT&CK name; {len(unmatched)} technique names had no exact match and are left out:",
             "  " + ", ".join(unmatched),
             "plan order (ids only): " + " | ".join(f"{s}: {' '.join(ids) or '-'}" for s, ids in steps)]

    labelled, rows = mapper_rows(events, steps)
    lines += ["", "=== rule-based mapper vs the plan's technique set (1 dataset) ==="]
    for label, mapped, rules, reported, exact, by_parent, lp, rp in rows:
        lines.append(f"{label}:")
        lines.append(f"  events mapped {len(mapped)}; techniques reported {len(reported)}, labelled {len(labelled)}")
        lines.append(f"  exact ids:    precision {exact[0]:.3f} recall {exact[1]:.3f} f1 {exact[2]:.3f}   "
                     f"found: {' '.join(sorted(labelled & reported)) or '-'}")
        lines.append(f"  parent level: precision {by_parent[0]:.3f} recall {by_parent[1]:.3f} f1 {by_parent[2]:.3f}   "
                     f"found: {' '.join(sorted(lp & rp)) or '-'}")
        lines.append(f"  labelled but not reported (parent level): {' '.join(sorted(lp - rp))}")
        lines.append(f"  reported but not labelled (parent level): {' '.join(sorted(rp - lp)) or '-'}")
        lines.append("  events per rule: " + ", ".join(f"{r} {n}" for r, n in
                                                       Counter(rules[m["event_id"]] for m in mapped).most_common()))
    if not run_graph:
        return "\n".join(lines)

    _, mapped, _, _, _, _, lp, _ = rows[0]     # the frozen rules
    loader.reset()
    loader.apply_schema()
    loader.load_events(events)
    loader.load_mappings(mapped, config.SOURCE_MAPPER)
    plan_sequence = to_sequence([t for _, ids in steps for t in ids])
    stats = loader.graph_stats()
    lines += ["", "=== full pipeline (frozen rules) ===",
              f"graph: {sum(stats['nodes'].values())} nodes / {sum(stats['relationships'].values())} relationships",
              f"plan as a parent-technique sequence ({len(plan_sequence)} steps): {' > '.join(plan_sequence)}"]
    for window in (5, 15, 30, 60):
        inferred = incidents.infer_incidents(config.METHOD_MAPPER, window)
        sizes = sorted((len(i["event_ids"]) for i in inferred), reverse=True)
        lines.append(f"window {window:>3} min: {len(inferred)} incident(s); events per incident {sizes[:8]}")
    inferred = incidents.materialize(config.METHOD_MAPPER)
    device = {e["event_id"]: e["device"] for e in events}
    user = {e["event_id"]: e["user"] for e in events}
    for inc in sorted(inferred, key=lambda i: -len(i["event_ids"]))[:3]:
        trajectory = get_trajectory(inc["incident_id"], config.METHOD_MAPPER, config.SOURCE_MAPPER)
        sequence = to_sequence([t["id"] for t in trajectory["techniques"]])
        hosts = Counter(device[e] for e in inc["event_ids"])
        users = Counter(user[e] for e in inc["event_ids"])
        match = match_historical(trajectory)["matches"]
        prediction = predict_next(trajectory)
        top = prediction["predictions"][0] if prediction["predictions"] else None
        order = 1 - edit_distance(sequence, plan_sequence) / max(len(sequence), len(plan_sequence), 1)
        lines += [f"incident {inc['incident_id']} (window {config.WINDOW_MINUTES} min): {len(inc['event_ids'])} events; "
                  f"hosts {dict(hosts)}; accounts {dict(users)}",
                  f"  trajectory ({len(sequence)} parent-level steps): {' > '.join(sequence)}",
                  f"  against the plan: technique overlap (Jaccard) {jaccard(sequence, plan_sequence):.3f}; "
                  f"order similarity (1 - edit distance / longer) {order:.3f}; "
                  f"{len(set(sequence) & lp)} of {len(lp)} labelled parent techniques present",
                  "  top historical match: " + (f"{match[0]['attack_id']} similarity {match[0]['similarity']}"
                                                if match else "none"),
                  "  predicted next: " + (f"{top['technique_id']} p={top['probability']}" if top else "none")
                  + f"  [{prediction['evidence'][0]}]"]
    hubs = loader.run("hubs")
    lines.append(f"hosts and addresses treated as shared infrastructure: "
                 f"{', '.join(h['entity'] for h in hubs) or 'none'}")
    lines.append("\nThe Neo4j graph now holds this dataset. Restore the synthetic benchmark with:\n"
                 "  python -m knowledge_graph.build --reset")
    return "\n".join(lines)


def main():
    events, rep = apt29.adapt()
    print(report(events, rep, run_graph="--no-graph" not in sys.argv))


if __name__ == "__main__":
    main()
