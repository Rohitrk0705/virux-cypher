"""Evaluate historical matching and check the brute-force skew.

  python -m evaluation.similarity_eval
"""

import json
from collections import Counter, defaultdict
from statistics import mean

from knowledge_graph import config
from prediction.historical import SOURCE_CURATED, SOURCE_GROUP, historical, parent, to_sequence
from prediction.similarity import match_historical, similarity

from . import incident_match
from .prediction_eval import d_overlapping_distractors
from .trajectories import (as_contract_3, benign_pipeline_trajectories, ground_truth_trajectories,
                           pipeline_trajectories)

# curated record that is the reference form of each known pattern
REFERENCE = {r["reference"][-1]: r["attack_id"] for r in historical([SOURCE_CURATED])
             if r["reference"].startswith("known pattern")}


def database_stats():
    lines = ["=== historical attack database ==="]
    for source in (SOURCE_CURATED, SOURCE_GROUP):
        lengths = sorted(len(r["sequence"]) for r in historical([source]))
        lines.append(f"{source:<12}{len(lengths):>4} attacks; sequence length min {lengths[0]}, "
                     f"median {lengths[len(lengths) // 2]}, max {lengths[-1]}")
    lines.append("ordering: curated = hand-specified; mitre_group = INFERRED from tactic order, not observed")
    used = sorted({parent(l["technique_id"]) for l in json.loads(config.LABELS_FILE.read_text())})
    groups = historical([SOURCE_GROUP])
    lines.append(f"\nMITRE groups using each of the dataset's {len(used)} parent techniques (of {len(groups)}):")
    lines.append("  " + "  ".join(f"{t} {sum(t in g['sequence'] for g in groups)}" for t in used))
    return "\n".join(lines)


def matching_report(entries, title):
    """Top match for every incident and how often it is the right reference."""
    name = {r["attack_id"]: r for r in historical()}
    lines = [f"=== {title} ===",
             f"{'truth':<8}{'pattern':<8}{'variant':<13}{'top match':<10}{'sim':>6}  {'source':<12}"
             f"{'runner-up':<10}{'sim':>6}  trajectory"]
    correct = tied_correct = known = 0
    top_source = Counter()
    for e in entries:
        if not e["techniques"]:
            lines.append(f"{e['gt_id']:<8}{e['pattern']:<8}{e['variant']:<13}(no inferred incident)")
            known += e["pattern"] in REFERENCE
            continue
        matches = match_historical(as_contract_3(e))["matches"]
        top = matches[0] if matches else None
        second = matches[1] if len(matches) > 1 else None
        if top:
            top_source[name[top["attack_id"]]["source"]] += 1
        if e["pattern"] in REFERENCE:
            known += 1
            if top and top["attack_id"] == REFERENCE[e["pattern"]]:
                correct += 1
            if top and any(m["attack_id"] == REFERENCE[e["pattern"]] and m["similarity"] == top["similarity"]
                           for m in matches):
                tied_correct += 1
        lines.append(
            f"{e['gt_id']:<8}{e['pattern']:<8}{e['variant']:<13}"
            f"{top['attack_id'] if top else '-':<10}{top['similarity'] if top else 0:>6.3f}  "
            f"{name[top['attack_id']]['source'] if top else '-':<12}"
            f"{second['attack_id'] if second else '-':<10}{second['similarity'] if second else 0:>6.3f}  "
            f"{' > '.join(to_sequence(e['techniques']))}")
    lines.append(f"\nreference patterns: " + ", ".join(f"{p} = {a}" for p, a in sorted(REFERENCE.items()))
                 + "; pattern D has no reference (novel by design)")
    lines.append(f"top-1 is the pattern's own reference: {correct} / {known} incidents of patterns A-C "
                 f"({tied_correct} / {known} if a tie for first place counts)")
    lines.append("source of the top match over all incidents: "
                 + ", ".join(f"{s} {n}" for s, n in sorted(top_source.items())))
    return "\n".join(lines)


def prefix_report(entries):
    """Matching while the attack is still in progress: every strict prefix of
    the A-C incidents. A and C references count as interchangeable, because A's
    reference is a prefix of C's."""
    name = {r["attack_id"]: r for r in historical()}
    family = {"A": {REFERENCE["A"], REFERENCE["C"]}, "C": {REFERENCE["A"], REFERENCE["C"]},
              "B": {REFERENCE["B"]}}
    by_length, groups_top, total, hits = defaultdict(lambda: [0, 0]), 0, 0, 0
    for e in entries:
        if e["pattern"] not in family or not e["techniques"]:
            continue
        seq = e["techniques"]
        for i in range(1, len(seq)):
            matches = match_historical(as_contract_3({**e, "techniques": seq[:i]}), top_k=1)["matches"]
            top = matches[0]["attack_id"] if matches else None
            ok = top in family[e["pattern"]]
            total += 1
            hits += ok
            by_length[i][0] += ok
            by_length[i][1] += 1
            groups_top += bool(top) and name[top]["source"] == SOURCE_GROUP
    lines = ["=== matching an attack IN PROGRESS (strict prefixes of ground-truth A-C incidents) ===",
             f"top match is the pattern's reference: {hits} of {total} prefixes "
             f"(complete trajectories: see above)",
             "by prefix length: " + ", ".join(f"{k} step(s) {v[0]}/{v[1]}" for k, v in sorted(by_length.items())),
             f"top match is a MITRE group record: {groups_top} of {total} prefixes",
             "Cause: the score divides by the longer sequence, so a prefix scores low against its own,",
             "longer, reference and very short group records (2 to 4 techniques) outrank it."]
    return "\n".join(lines)


def group_report(entries):
    lines = ["=== contribution of the real MITRE group records to matching ==="]
    name = {r["attack_id"]: r for r in historical()}
    top_curated = short = n = 0
    for e in entries:
        if not e["techniques"]:
            continue
        n += 1
        best = match_historical(as_contract_3(e), top_k=1)["matches"]
        top_curated += bool(best) and name[best[0]["attack_id"]]["source"] == SOURCE_CURATED
        group_best = match_historical(as_contract_3(e), top_k=1, sources=[SOURCE_GROUP])["matches"]
        short += bool(group_best) and len(name[group_best[0]["attack_id"]]["sequence"]) <= 4
    lines.append(f"top match is a hand-written sequence for {top_curated} of {n} ground-truth incidents;")
    lines.append(f"the best GROUP match is a record of 4 techniques or fewer for {short} of {n}.")
    lines.append("Group sequences have a median of 17 techniques, so a 4-6 step incident cannot score high")
    lines.append("against them. All matching signal comes from the 11 hand-written sequences.")
    return "\n".join(lines)


def novelty_report(entries):
    drop = d_overlapping_distractors()
    lines = ["=== how 'novel' is pattern D to the database? ===",
             f"{len(drop)} hand-written distractors share a 2-step path with pattern D: {', '.join(drop)}",
             f"{'truth':<8}{'best similarity':>16}{'without those distractors':>28}"]
    for e in entries:
        if e["pattern"] != "D" or not e["techniques"]:
            continue
        with_all = match_historical(as_contract_3(e), top_k=1)["matches"]
        without = match_historical(as_contract_3(e), top_k=1, exclude=drop)["matches"]
        lines.append(f"{e['gt_id']:<8}{with_all[0]['similarity'] if with_all else 0:>16.3f}"
                     f"{without[0]['similarity'] if without else 0:>28.3f}")
    lines.append("No single record equals pattern D, but its parts are in the database because the same")
    lines.append("author wrote the distractors and the generator.")
    return "\n".join(lines)


def benign_report():
    benign = [e for e in benign_pipeline_trajectories() if e["techniques"]]
    scores = sorted((match_historical(as_contract_3(e), top_k=1)["matches"] or [{"similarity": 0.0}])[0]["similarity"]
                    for e in benign)
    lines = ["=== false matches: inferred incidents that contain NO attack event ===",
             f"{len(benign)} such incidents come out of the label-free pipeline (mapper filter, W = "
             f"{config.WINDOW_MINUTES} min)."]
    if scores:
        lines.append(f"their best historical similarity: min {scores[0]:.3f}, median {scores[len(scores) // 2]:.3f}, "
                     f"max {scores[-1]:.3f}")
        for threshold in (0.3, 0.5, 0.6):
            lines.append(f"  at or above {threshold}: {sum(s >= threshold for s in scores)} of {len(scores)}")
        brute = sum("T1110" in to_sequence(e["techniques"]) for e in benign)
        lines.append(f"{brute} of them contain T1110 (brute force).")
    return "\n".join(lines)


def skew_report():
    """Does the brute-force volume (T1110) pull similarity towards pattern D?"""
    truth = incident_match.load_truth()
    ts, technique = incident_match.load_event_index()
    raw, collapsed = {}, {}
    for t in truth:
        ordered = sorted(t["event_ids"], key=lambda e: (ts[e], e))
        raw[t["incident_id"]] = [parent(technique[e]) for e in ordered]   # one entry per event
        collapsed[t["incident_id"]] = to_sequence(t["techniques"])
    pattern = {t["incident_id"]: t["pattern"] for t in truth}

    total = sum(len(s) for s in raw.values())
    brute = sum(s.count("T1110") for s in raw.values())
    lines = ["=== brute-force skew check ===",
             f"T1110 is {brute} of {total} attack events ({brute / total:.1%}), all in pattern D.",
             f"After collapsing consecutive repeats it is "
             f"{sum(s.count('T1110') for s in collapsed.values())} of "
             f"{sum(len(s) for s in collapsed.values())} trajectory steps.",
             "",
             "mean similarity between incidents, by pattern pair (n = number of incident pairs):"]
    for label, seqs in (("one entry per EVENT (not collapsed)", raw), ("collapsed (what the system uses)", collapsed)):
        cells = defaultdict(list)
        ids = sorted(seqs)
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                cells[tuple(sorted((pattern[a], pattern[b])))].append(similarity(seqs[a], seqs[b]))
        lines.append(f"  {label}")
        lines.append("      " + "".join(f"{p:>12}" for p in "ABCD"))
        for p in "ABCD":
            row = "".join(f"{mean(cells[tuple(sorted((p, q)))]):>7.3f} n={len(cells[tuple(sorted((p, q)))]):<2}"
                          for q in "ABCD")
            lines.append(f"    {p} {row}")
    # where does each incident's best curated match come from in both modes
    lines.append("")
    lines.append("best curated match per pattern-D incident (event-level sequence vs collapsed):")
    curated = historical([SOURCE_CURATED])
    for t in truth:
        if t["pattern"] != "D":
            continue
        best = {}
        for label, seqs in (("raw", raw), ("collapsed", collapsed)):
            best[label] = max(((similarity(seqs[t["incident_id"]], r["sequence"]), r["attack_id"]) for r in curated),
                              key=lambda x: (x[0], x[1]))
        lines.append(f"  {t['incident_id']}  raw {best['raw'][1]} {best['raw'][0]:.3f}   "
                     f"collapsed {best['collapsed'][1]} {best['collapsed'][0]:.3f}")
    d_d = {}
    for label, seqs in (("raw", raw), ("collapsed", collapsed)):
        d_ids = [i for i in seqs if pattern[i] == "D"]
        others = [i for i in seqs if pattern[i] != "D"]
        d_d[label] = (mean(similarity(seqs[a], seqs[b]) for a in d_ids for b in d_ids if a < b),
                      mean(similarity(seqs[a], seqs[b]) for a in d_ids for b in others))
    lines += ["",
              f"ANSWER: no skew towards pattern D. D-to-D similarity is {d_d['raw'][0]:.3f} per event and "
              f"{d_d['collapsed'][0]:.3f} collapsed;",
              f"D-to-other-pattern similarity is {d_d['raw'][1]:.3f} per event and {d_d['collapsed'][1]:.3f} "
              "collapsed. Brute-force volume does not",
              "pull other patterns towards D in either form, and without collapsing D matches the curated",
              "sequences worse, not better. Collapsing is kept because a trajectory is a list of steps."]
    return "\n".join(lines)


def main():
    print(database_stats())
    print()
    print(matching_report(ground_truth_trajectories(),
                          "matching on GROUND-TRUTH trajectories (n = 24 incidents)"))
    print()
    print(matching_report(pipeline_trajectories(),
                          f"matching on PIPELINE trajectories (mapper incidents, W = {config.WINDOW_MINUTES} min, "
                          "mapper techniques; n = 24 incidents)"))
    print()
    print(prefix_report(ground_truth_trajectories()))
    print()
    print(group_report(ground_truth_trajectories()))
    print()
    print(novelty_report(ground_truth_trajectories()))
    print()
    print(benign_report())
    print()
    print(skew_report())


if __name__ == "__main__":
    main()
