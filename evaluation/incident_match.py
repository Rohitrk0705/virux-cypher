"""Score inferred incidents against the generator's ground truth.

incidents.json is read here and nowhere else in the pipeline.

Each true incident is paired with at most one inferred incident, and each
inferred incident with at most one true incident (greedy on Jaccard overlap,
highest first). A true incident with no overlapping inferred incident left
scores zero. For each pair:
  coverage - share of the true incident's events the inferred incident holds
  purity   - share of the inferred incident's events that belong to it
  jaccard  - intersection over union

Columns of the summary table:
  inferred  inferred incidents
  false     inferred incidents containing no attack event at all
  incP      incident precision: inferred incidents with an attack event / inferred
  merged    inferred incidents containing events of two or more true incidents
  exact     true incidents reproduced event-for-event
  trajGT    true incidents whose technique sequence is reproduced when the
            paired incident's events are given their GROUND-TRUTH techniques;
            this measures grouping only
  trajMap   the same using the rule-based mapper's techniques (end to end);
            '-' when the mapper has not run
  coverage, purity, jaccard   means over the true incidents (purity says
            nothing about the 'false' incidents)
  pairP     of all event pairs placed in the same inferred incident with at
            least one attack event, the share that are two attack events of
            the same true incident (benign co-members count against it)
  atkP/atkR/atkF1   pair precision/recall/F1 restricted to pairs of attack
            events; atkP can only fall when two true incidents are merged
"""

import json
from datetime import datetime
from itertools import combinations

from knowledge_graph import config


def load_truth(incidents_file=None):
    return json.loads((incidents_file or config.INCIDENTS_FILE).read_text())


def load_event_index(events_file=None, labels_file=None):
    """event_id -> epoch seconds, and event_id -> ground-truth technique."""
    ts = {
        e["event_id"]: int(datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp())
        for e in json.loads((events_file or config.EVENTS_FILE).read_text())
    }
    labels = json.loads((labels_file or config.LABELS_FILE).read_text())
    return ts, {l["event_id"]: l["technique_id"] for l in labels}


def load_mapped(mapped_file=None):
    """event_id -> mapper technique, or None when the mapper has not run."""
    mapped_file = mapped_file or config.MAPPED_FILE
    if not mapped_file.exists():
        return None
    return {m["event_id"]: m["technique_id"] for m in json.loads(mapped_file.read_text())}


def technique_sequence(event_ids, ts, technique):
    """Collapsed technique sequence of a set of events, in time order."""
    seq = []
    for e in sorted((e for e in event_ids if e in technique), key=lambda e: (ts[e], e)):
        if not seq or seq[-1] != technique[e]:
            seq.append(technique[e])
    return seq


def assign(truth, clusters):
    """One-to-one pairing of true and inferred incidents, greedy on Jaccard."""
    options = []
    for t in truth:
        true_set = set(t["event_ids"])
        for cid, members in clusters.items():
            inter = len(true_set & members)
            if inter:
                options.append((inter / len(true_set | members), t["incident_id"], cid))
    options.sort(key=lambda o: (-o[0], o[1], o[2]))
    pairing, used = {}, set()
    for _, tid, cid in options:
        if tid not in pairing and cid not in used:
            pairing[tid] = cid
            used.add(cid)
    return pairing


def score(truth, inferred, ts, technique, mapped=None):
    """truth: incidents.json records. inferred: [{incident_id, event_ids}].
    technique: ground-truth technique per event. mapped: mapper technique per
    event, or None."""
    clusters = {c["incident_id"]: set(c["event_ids"]) for c in inferred}
    owner = {e: t["incident_id"] for t in truth for e in t["event_ids"]}
    cluster_of = {e: cid for cid, members in clusters.items() for e in members}
    pairing = assign(truth, clusters)

    per_incident = []
    for t in truth:
        true_set = set(t["event_ids"])
        match = pairing.get(t["incident_id"])
        members = clusters.get(match, set())
        inter = len(true_set & members)
        per_incident.append({
            "incident_id": t["incident_id"],
            "pattern": t["pattern"],
            "variant": t["variant"],
            "pace": t["pace"],
            "match": match,
            "coverage": inter / len(true_set),
            "purity": inter / len(members) if members else 0.0,
            "jaccard": inter / len(true_set | members) if members else 0.0,
            "fragments": len({cluster_of[e] for e in true_set if e in cluster_of}),
            "unassigned": sum(1 for e in true_set if e not in cluster_of),
            "exact": bool(members) and true_set == members,
            "trajectory_gt": bool(members)
                             and technique_sequence(members, ts, technique) == t["techniques"],
            "trajectory_mapped": None if mapped is None else (
                bool(members) and technique_sequence(members, ts, mapped) == t["techniques"]),
        })

    # pairs of attack events
    tp = fp = fn = 0
    for a, b in combinations(sorted(owner), 2):
        same_true = owner[a] == owner[b]
        same_inferred = a in cluster_of and cluster_of.get(a) == cluster_of.get(b)
        tp += same_true and same_inferred
        fp += (not same_true) and same_inferred
        fn += same_true and not same_inferred
    atk_p = tp / (tp + fp) if tp + fp else 0.0
    atk_r = tp / (tp + fn) if tp + fn else 0.0
    atk_f1 = 2 * atk_p * atk_r / (atk_p + atk_r) if atk_p + atk_r else 0.0

    # all co-clustered pairs that involve an attack event, benign members included
    good = bad = 0
    for members in clusters.values():
        attack = [e for e in members if e in owner]
        benign = len(members) - len(attack)
        for a, b in combinations(attack, 2):
            if owner[a] == owner[b]:
                good += 1
            else:
                bad += 1
        bad += len(attack) * benign

    n = len(truth)
    mean = lambda key: sum(p[key] for p in per_incident) / n
    bearing = sum(1 for m in clusters.values() if m & owner.keys())
    return {
        "true_incidents": n,
        "inferred_incidents": len(clusters),
        "false_incidents": len(clusters) - bearing,
        "incident_precision": bearing / len(clusters) if clusters else 0.0,
        "merged_incidents": sum(1 for m in clusters.values()
                                if len({owner[e] for e in m if e in owner}) > 1),
        "exact": sum(p["exact"] for p in per_incident),
        "trajectory_gt": sum(p["trajectory_gt"] for p in per_incident),
        "trajectory_mapped": None if mapped is None
                             else sum(p["trajectory_mapped"] for p in per_incident),
        "mean_coverage": mean("coverage"),
        "mean_purity": mean("purity"),
        "mean_jaccard": mean("jaccard"),
        "pair_precision": good / (good + bad) if good + bad else 0.0,
        "attack_pair_precision": atk_p,
        "attack_pair_recall": atk_r,
        "attack_pair_f1": atk_f1,
        "per_incident": per_incident,
    }


SUMMARY_COLUMNS = [
    ("inferred", "inferred_incidents", "d"), ("false", "false_incidents", "d"),
    ("incP", "incident_precision", ".3f"), ("merged", "merged_incidents", "d"),
    ("exact", "exact", "d"), ("trajGT", "trajectory_gt", "d"),
    ("trajMap", "trajectory_mapped", "d"), ("coverage", "mean_coverage", ".3f"),
    ("purity", "mean_purity", ".3f"), ("jaccard", "mean_jaccard", ".3f"),
    ("pairP", "pair_precision", ".3f"), ("atkP", "attack_pair_precision", ".3f"),
    ("atkR", "attack_pair_recall", ".3f"), ("atkF1", "attack_pair_f1", ".3f"),
]


def summary_table(rows):
    """rows: [(method, window_minutes, score dict)] -> printable text table."""
    head = f"{'method':<10}{'W(min)':>7}" + "".join(f"{name:>9}" for name, _, _ in SUMMARY_COLUMNS)
    lines = [head, "-" * len(head)]
    for method, window, s in rows:
        cells = "".join(f"{'-' if s[key] is None else format(s[key], fmt):>9}"
                        for _, key, fmt in SUMMARY_COLUMNS)
        lines.append(f"{method:<10}{window:>7}{cells}")
    return "\n".join(lines)
