"""Build the temporal knowledge graph end to end and report on it.

  python -m knowledge_graph.build [--reset]

Steps: schema -> load events, ground-truth labels and mapper output -> infer
incidents with each available filter -> NEXT edges -> statistics -> evaluation
against incidents.json (ground truth, used for scoring only) with a window sweep.
"""

import argparse
import json

from evaluation import incident_match
from temporal import incidents
from temporal.trajectory import get_trajectory

from . import config, loader
from .connection import get_driver, run

LIMITATIONS = """LIMITATIONS - read before quoting any number above:
1. Easy grouping. The generator keeps incidents at least 3 hours apart whenever
   they share a user or a device, so two attacks never interleave on one host
   or account. Grouping is therefore much easier here than on real data, and
   these scores must not be read as real-world accuracy.
2. 'labels' rows choose candidate events with the ground-truth labels. That is
   leakage; they are an optimistic upper bound and never the headline figure.
3. 'heuristic' is label-free but has a ceiling: file_access events and Office
   application launches are never candidates, so T1005 and T1204.002 steps can
   never be grouped and trajGT is capped accordingly. Its routine-application
   list equals the generator's benign application list. Most of its candidates
   are benign web and mail events, hence the many 'false' incidents.
4. 'mapper' is label-free: candidates are the events the rule-based mapper
   tagged, so it inherits every mapper false positive and miss.
5. The default window (30 min) was picked from a sweep on the first (clean)
   version of the dataset and is not validated on held-out data. Slow-paced
   incidents, whose steps are 15-45 minutes apart, fragment at 30 minutes; a
   60-minute window scores higher on this draw but was not adopted after the
   fact.
6. trajGT gives the paired incident's events their ground-truth techniques, so
   it measures grouping only. trajMap uses the mapper's techniques end to end.
7. Some coverage comes from benign events bridging gaps between attack steps."""


def available_methods():
    methods = [config.METHOD_HEURISTIC, config.METHOD_LABELS]
    if incidents.candidate_ids(config.METHOD_MAPPER):
        methods.insert(1, config.METHOD_MAPPER)
    return methods


def evaluate(methods, windows):
    truth = incident_match.load_truth()
    ts, technique = incident_match.load_event_index()
    mapped = incident_match.load_mapped()
    rows = []
    for method in methods:
        for window in windows:
            inferred = incidents.infer_incidents(method, window)
            rows.append((method, window,
                         incident_match.score(truth, inferred, ts, technique, mapped)))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--reset", action="store_true", help="wipe the database first")
    args = parser.parse_args()

    get_driver()
    if args.reset:
        loader.reset()
    n_events, n_labels, n_mapped = loader.load_files()
    print(f"loaded {n_events} events, {n_labels} ground-truth technique mappings, "
          f"{n_mapped} mapper technique mappings")

    methods = available_methods()
    stored = {m: incidents.materialize(m) for m in methods}

    stats = loader.graph_stats()
    print("\n=== graph statistics ===")
    print("nodes:")
    for label, count in stats["nodes"].items():
        print(f"  {label:<12}{count:>7}")
    print(f"  {'total':<12}{sum(stats['nodes'].values()):>7}")
    print("relationships:")
    for rel, count in stats["relationships"].items():
        print(f"  {rel:<12}{count:>7}")
    print(f"  {'total':<12}{sum(stats['relationships'].values()):>7}")
    hubs = run("hubs")
    internal = [h for h in hubs if h["label"] == "Device" or h["entity"].startswith(config.INTERNAL_PREFIX)]
    print(f"hubs (>= {config.HUB_USERS} distinct users, ignored when linking): {len(hubs)}")
    for hub in internal:
        print(f"  {hub['label']:<7}{hub['entity']:<16}{hub['users']} users")
    print(f"  plus {len(hubs) - len(internal)} external addresses: "
          + ", ".join(h["entity"] for h in hubs if h not in internal))
    print(f"inferred incidents at W={config.WINDOW_MINUTES} min "
          f"(Incident nodes, with PART_OF and NEXT edges per method):")
    for method in methods:
        candidates = len(incidents.candidate_ids(method))
        print(f"  {method:<10}{len(stored[method]):>4} incidents from {candidates} candidate events")

    truth_count = len(incident_match.load_truth())
    print(f"\n=== incident inference vs ground truth (n = {truth_count} true incidents) ===")
    rows = evaluate(methods, config.SWEEP_WINDOWS)
    print(incident_match.summary_table(rows))
    print("\ncolumn definitions: see the docstring of evaluation/incident_match.py")
    print("\n" + LIMITATIONS)

    for method in methods:
        result = next(s for m, w, s in rows if m == method and w == config.WINDOW_MINUTES)
        print(f"\n--- per true incident, method={method}, W={config.WINDOW_MINUTES} min ---")
        for p in result["per_incident"]:
            mapped = {None: "-", True: "ok", False: "NO"}[p["trajectory_mapped"]]
            print(f"  {p['incident_id']} {p['pattern']} {p['variant']:<12}{p['pace']:<5}"
                  f"-> {str(p['match']):<10} cov {p['coverage']:.2f}  pur {p['purity']:.2f}  "
                  f"jac {p['jaccard']:.2f}  frag {p['fragments']}  unassigned {p['unassigned']:>2}  "
                  f"trajGT {'ok' if p['trajectory_gt'] else 'NO'}  trajMap {mapped}")

    # most heuristic incidents are benign noise with no techniques; show a real one
    sample = next(
        (t for t in (get_trajectory(inc["incident_id"]) for inc in stored[config.DEFAULT_METHOD])
         if len(t["techniques"]) >= 3),
        None,
    )
    print(f"\n=== sample trajectory (contract 3), method={config.DEFAULT_METHOD}, "
          f"techniques from {config.DEFAULT_TECHNIQUE_SOURCE} ===")
    print(json.dumps(sample, indent=2))


if __name__ == "__main__":
    main()
