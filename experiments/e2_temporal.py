"""E2 - does temporal ordering improve matching and prediction?

Static = the order of techniques is ignored (set overlap; co-occurrence).
Temporal = order is used (edit distance component; Markov transitions).

  python -m experiments.e2_temporal
"""

from statistics import mean

from evaluation.prediction_eval import evaluate, history_sequences, markov_on
from evaluation.similarity_eval import REFERENCE
from evaluation.trajectories import as_contract_3
from prediction.historical import SOURCE_CURATED, SOURCE_GROUP, historical, to_sequence
from prediction.similarity import match_historical, similarity
from prediction.static import StaticPredictor

from .common import PREDICTION_METRICS, trajectory_sets, write

BOTH = [SOURCE_GROUP, SOURCE_CURATED]


def static_on(sources):
    return lambda extra, held_out=(): StaticPredictor(history_sequences(sources, held_out) + list(extra))


def matching_rows():
    rows = []
    for label, entries in trajectory_sets():
        known = [e for e in entries if e["pattern"] in REFERENCE]
        for mode in ("static", "temporal"):
            unique = tied = 0
            for e in known:
                if not e["techniques"]:
                    continue
                matches = match_historical(as_contract_3(e), top_k=200, mode=mode)["matches"]
                if not matches:
                    continue
                best = matches[0]["similarity"]
                winners = [m["attack_id"] for m in matches if m["similarity"] == best]
                if REFERENCE[e["pattern"]] in winners:
                    tied += 1
                    unique += len(winners) == 1
            rows.append({"trajectories": label, "graph": mode,
                         "own reference is the unique top match": unique,
                         "own reference is top or tied for top": tied,
                         "incidents (patterns A-C)": len(known),
                         "accuracy (unique)": unique / len(known)})
    return rows


def order_control_rows():
    """By construction: reverse each incident's order and compare with its own
    reference. A static graph cannot see the difference."""
    reference = {r["attack_id"]: r["sequence"] for r in historical([SOURCE_CURATED])}
    rows = []
    for label, entries in trajectory_sets():
        usable = [e for e in entries if e["pattern"] in REFERENCE and e["techniques"]]
        for mode in ("static", "temporal"):
            forward = [similarity(to_sequence(e["techniques"]), reference[REFERENCE[e["pattern"]]], mode)
                       for e in usable]
            backward = [similarity(to_sequence(e["techniques"])[::-1], reference[REFERENCE[e["pattern"]]], mode)
                        for e in usable]
            rows.append({"trajectories": label, "graph": mode,
                         "mean similarity, true order": mean(forward),
                         "mean similarity, reversed order": mean(backward),
                         "incidents told apart from their reversal": sum(f > b for f, b in zip(forward, backward)),
                         "incidents": len(usable)})
    return rows


PREDICTION = [
    # training data, static builder, temporal builder, protocol
    ("hand-written sequences", static_on([SOURCE_CURATED]), markov_on([SOURCE_CURATED]), "history_only"),
    ("groups + hand-written, pooled", static_on(BOTH), markov_on(BOTH), "history_only"),
    ("hand-written minus own family's reference", static_on([SOURCE_CURATED]), markov_on([SOURCE_CURATED]),
     "no_own_reference"),
    ("hand-written + all other incidents", static_on([SOURCE_CURATED]), markov_on([SOURCE_CURATED]),
     "leave_one_out"),
]


def prediction_rows():
    rows = []
    for label, entries in trajectory_sets():
        for training, static_build, temporal_build, protocol in PREDICTION:
            for graph, build in (("static", static_build), ("temporal", temporal_build)):
                rows.append({"trajectories": label, "training data": training, "graph": graph,
                             **evaluate(entries, build, protocol)})
    return rows


def compare(static, temporal, key, unit=None):
    """'higher', 'lower' or 'no different' for temporal relative to static.
    For counts, a gap of one instance is called no different."""
    gap = temporal[key] - static[key]
    if abs(gap) <= (unit or 0):
        return "no different"
    return "higher" if gap > 0 else "lower"


def repeats_in_path(entries):
    """Instances whose target already occurs in the path (the static model can never propose those)."""
    count = total = 0
    for e in entries:
        seq = to_sequence(e["techniques"] or [])
        for i in range(1, len(seq)):
            total += 1
            count += seq[i] in seq[:i]
    return count, total


def main():
    matching, control, prediction = matching_rows(), order_control_rows(), prediction_rows()
    findings = []
    for label, entries in trajectory_sets():
        s, t = (next(r for r in matching if r["trajectories"] == label and r["graph"] == g)
                for g in ("static", "temporal"))
        n = s["incidents (patterns A-C)"]
        same = s["own reference is the unique top match"] == t["own reference is the unique top match"]
        findings.append(
            f"Matching, {label}: the incident's own reference is the unique top match for "
            f"{s['own reference is the unique top match']} of {n} incidents with the static graph and "
            f"{t['own reference is the unique top match']} of {n} with the temporal graph. "
            + ("Order does not improve matching on this dataset." if same else
               "The two differ by "
               f"{abs(s['own reference is the unique top match'] - t['own reference is the unique top match'])} "
               "incident(s)."))
        top3_better = top1_better = 0
        for training, *_ in PREDICTION:
            ps, pt = (next(r for r in prediction if r["trajectories"] == label
                           and r["training data"] == training and r["graph"] == g)
                      for g in ("static", "temporal"))
            top1_better += compare(ps, pt, "correct", unit=1) == "higher"
            top3_better += pt["top3"] > ps["top3"]
            findings.append(
                f"Prediction, {label}, {training}: temporal Top-1 is {compare(ps, pt, 'correct', unit=1)} "
                f"({pt['correct']} vs {ps['correct']} of {pt['instances']}), Top-3 is "
                f"{compare(ps, pt, 'top3')} ({pt['top3']:.3f} vs {ps['top3']:.3f}), MRR is "
                f"{compare(ps, pt, 'mrr')} ({pt['mrr']:.3f} vs {ps['mrr']:.3f}).")
        findings.append(
            f"Summary, {label}: temporal has the higher Top-1 in {top1_better} of {len(PREDICTION)} training "
            f"conditions and the higher Top-3 in {top3_better} of {len(PREDICTION)}. Temporal wins Top-1 where "
            "the training data contains the attack's own reference or sibling incidents, which the Markov model "
            "can replay; with the reference removed there is no Top-1 difference.")
    truth_repeats = repeats_in_path(trajectory_sets()[0][1])
    pipeline_entries = trajectory_sets()[1][1]
    pipeline_repeats = repeats_in_path(pipeline_entries)
    no_trajectory = sum(1 for e in pipeline_entries if not e["techniques"])
    single = sum(1 for e in pipeline_entries if e["techniques"] and len(to_sequence(e["techniques"])) < 2)
    notes = [
        "What E2 supports: order does not improve historical matching on this dataset, and order raises Top-1 "
        "prediction only when the model can replay a memorised sequence. What it does not support: a general "
        "advantage of the temporal graph.",
        "Patterns A, B and C already differ in WHICH techniques they contain, so set overlap alone tells them "
        "apart. A dataset with patterns that use the same techniques in different orders would test matching "
        "properly; this one contains none.",
        "The reversed-order table is a control that holds by construction (set overlap cannot see order); "
        "it shows the mechanism works, not that order matters in practice.",
        "With the reference in the history, part of the Top-1 gap is by construction: a set-based model cannot "
        "rank the remaining members of a matching set, while the Markov model replays the sequence. Top-3 is "
        "the fairer comparison.",
        f"The static predictor never proposes a technique already in the path. The target is already in the "
        f"path for {truth_repeats[0]} of {truth_repeats[1]} ground-truth instances and {pipeline_repeats[0]} of "
        f"{pipeline_repeats[1]} pipeline instances, so this caps static only on pipeline trajectories.",
        f"Pipeline trajectories: {no_trajectory} of 24 true incidents have no inferred trajectory and {single} "
        "have a single step, so the prediction rows cover the remaining incidents only (survivors). The "
        "matching table counts a missing trajectory as a miss; the control table leaves it out.",
        "On pipeline trajectories the prediction target is the pipeline's own next step, mapping errors "
        "included; those rows compare the two methods on the same noisy input and are not end-to-end accuracy.",
        "'Static' and 'temporal' are two scoring rules over the same data. The Neo4j graph always stores NEXT "
        "edges; the static condition simply does not use the order.",
    ]
    text = write(
        "e2", "E2 - Temporal information",
        "Does temporal ordering improve matching and prediction, compared with a static (order-free) graph?",
        [("matching", "Historical matching: is the incident's own reference pattern ranked first?",
          ["trajectories", "graph", "own reference is the unique top match",
           "own reference is top or tied for top", "incidents (patterns A-C)", "accuracy (unique)"], matching),
         ("order_control", "Control: similarity to the own reference, true order vs reversed order",
          ["trajectories", "graph", "mean similarity, true order", "mean similarity, reversed order",
           "incidents told apart from their reversal", "incidents"], control),
         ("prediction", "Next-step prediction: order-free co-occurrence vs Markov transitions",
          ["trajectories", "training data", "graph", "top1", "top1_tie", "top3", "mrr", "precision", "recall",
           "f1", "correct", "instances", "incidents"], prediction)],
        findings, notes, metrics=PREDICTION_METRICS)
    print(text)


if __name__ == "__main__":
    main()
