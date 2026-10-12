"""Evaluation harness for next-step prediction.

A test instance is a prefix of an incident's trajectory; the target is the
technique that actually came next. An incident with L steps gives L - 1
instances. All sequences are parent ids with consecutive repeats removed.

Metrics (always reported with the number of instances and incidents):
  top1       target is the first prediction (ties broken by technique id)
  top1 tie   the same, but when the target is tied for first with m - 1 other
             techniques it counts 1/m: the expected value under a random
             tie-break, so alphabetical luck is removed
  top3       target is among the first three predictions
  mrr        mean of 1 / rank of the target over the model's FULL ranking
             (0 when it is not ranked at all); contract 5 exposes only the top 5
  P, R, F1   macro-averaged over the techniques that occur as targets,
             treating the top prediction as a classification

Train/test protocols:
  history_only      train on the historical database alone
  no_own_reference  history alone, minus the reference sequence(s) of the
                    tested incident's pattern family
  leave_one_out     history plus all OTHER incidents
  leave_family_out  history minus the family's reference(s), plus incidents of
                    the other families only
Patterns A and C are one family: A's reference is a prefix of C's, so holding
out only one of them would leak the other.

  python -m evaluation.prediction_eval
"""

import json
from collections import Counter
from pathlib import Path

from prediction.historical import SOURCE_CURATED, SOURCE_GROUP, historical, to_sequence
from prediction.markov import MarkovPredictor

from .trajectories import ground_truth_trajectories, pipeline_trajectories

TECHNIQUES_FILE = Path(__file__).resolve().parent.parent / "data" / "mitre" / "techniques.json"

FAMILY = {"A": "AC", "C": "AC", "B": "B", "D": "D"}
# Reference form of pattern D (ground truth; used only to find which curated
# distractors share a 2-step path with it).
PATTERN_D = ["T1110", "T1078", "T1083", "T1005", "T1041"]


def bigrams(seq):
    return set(zip(seq, seq[1:]))


def d_overlapping_distractors():
    """Curated distractor records that contain a 2-step path of pattern D."""
    return sorted(r["attack_id"] for r in historical([SOURCE_CURATED])
                  if r["reference"] == "distractor" and bigrams(r["sequence"]) & bigrams(PATTERN_D))


def history_sequences(sources, held_out=(), drop=()):
    """Historical sequences of the given sources, without the reference
    sequences of the held-out patterns and without the attack ids in drop."""
    out = []
    for r in historical(sources) if sources else []:
        if r["attack_id"] in drop:
            continue
        if r["source"] == SOURCE_CURATED and any(r["reference"] == f"known pattern {p}" for p in held_out):
            continue
        out.append(r["sequence"])
    return out


def markov_on(sources, drop=(), max_order=None):
    """Builder: Markov table over the given historical sources plus training incidents."""
    def build(extra, held_out=()):
        kwargs = {} if max_order is None else {"max_order": max_order}
        return MarkovPredictor(history_sequences(sources, held_out, drop) + list(extra), **kwargs)
    return build


def instances(sequence):
    seq = to_sequence(sequence)
    return [(seq[:i], seq[i]) for i in range(1, len(seq))]


def new_tally():
    return {"n": 0, "top1": 0, "tie": 0.0, "top3": 0, "rr": 0.0, "tp": Counter(), "fp": Counter(),
            "fn": Counter(), "incidents": 0}


def score_instance(tally, predictor, path, target):
    ranked = predictor.rank(path)[0]
    names = [t for t, _ in ranked]
    tally["n"] += 1
    rank = names.index(target) + 1 if target in names else None
    tally["top1"] += rank == 1
    tally["top3"] += rank is not None and rank <= 3
    tally["rr"] += 1 / rank if rank else 0.0
    if ranked:
        best = ranked[0][1]
        tied = [t for t, p in ranked if p == best]
        if target in tied:
            tally["tie"] += 1 / len(tied)
    if rank == 1:
        tally["tp"][target] += 1
    else:
        tally["fn"][target] += 1
        if names:
            tally["fp"][names[0]] += 1


def finish(tally):
    n = tally["n"]
    targets = sorted(tally["tp"].keys() | tally["fn"].keys())
    ps, rs, fs = [], [], []
    for t in targets:
        tp, fp, fn = tally["tp"][t], tally["fp"][t], tally["fn"][t]
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        ps.append(p)
        rs.append(r)
        fs.append(2 * p * r / (p + r) if p + r else 0.0)
    avg = lambda xs: sum(xs) / len(xs) if xs else 0.0
    div = lambda x: x / n if n else 0.0
    return {"instances": n, "incidents": tally["incidents"], "correct": tally["top1"],
            "top1": div(tally["top1"]), "top1_tie": div(tally["tie"]), "top3": div(tally["top3"]),
            "mrr": div(tally["rr"]), "precision": avg(ps), "recall": avg(rs), "f1": avg(fs),
            "target_classes": len(targets)}


def training_for(entry, usable, build, protocol):
    family = [p for p, f in FAMILY.items() if f == FAMILY[entry["pattern"]]]
    if protocol == "history_only":
        return build([], ())
    if protocol == "no_own_reference":
        return build([], family)
    if protocol == "leave_one_out":
        return build([o["techniques"] for o in usable if o is not entry], ())
    if protocol == "leave_family_out":
        return build([o["techniques"] for o in usable if o["pattern"] not in family], family)
    raise ValueError(protocol)


def evaluate(entries, build, protocol="history_only", by=None):
    """entries: trajectory entries (see evaluation.trajectories).
    build: function(training incident sequences, held-out patterns) -> predictor.
    by: optional key function on an entry; adds {key: metrics} under 'by'.
    Entries with no trajectory or a single step give no instance; they are
    counted in 'no_trajectory' and 'single_step'."""
    usable = [e for e in entries if e["techniques"]]
    total, groups = new_tally(), {}
    for e in usable:
        predictor = training_for(e, usable, build, protocol)
        cases = instances(e["techniques"])
        tallies = [total] + ([groups.setdefault(by(e), new_tally())] if by else [])
        for tally in tallies:
            tally["incidents"] += bool(cases)
            for path, target in cases:
                score_instance(tally, predictor, path, target)
    result = finish(total)
    result["no_trajectory"] = len(entries) - len(usable)
    result["single_step"] = sum(1 for e in usable if not instances(e["techniques"]))
    if by:
        result["by"] = {k: finish(v) for k, v in sorted(groups.items())}
    return result


def evaluate_end_to_end(truth_entries, pipeline_entries, build, protocol="history_only"):
    """Strict end-to-end score over the TRUE transitions. A true transition
    counts as correct only if the pipeline's trajectory for that incident
    reproduces the true path up to that point AND the top prediction from it is
    the true next technique. The denominator is every true transition."""
    pipeline = {e["gt_id"]: e for e in pipeline_entries}
    usable = [e for e in truth_entries if e["techniques"]]
    n = correct = reachable = 0
    for e in usable:
        predictor = training_for(e, usable, build, protocol)
        observed = to_sequence(pipeline[e["gt_id"]]["techniques"] or [])
        for path, target in instances(e["techniques"]):
            n += 1
            if observed[:len(path)] != path:
                continue
            reachable += 1
            ranked = predictor.rank(path)[0]
            correct += bool(ranked) and ranked[0][0] == target
    return {"instances": n, "path_reproduced": reachable, "correct": correct,
            "top1": correct / n if n else 0.0}


def chance():
    """Analytic expectation for a uniform random ranking of all ATT&CK parent
    techniques; this is 'no knowledge at all'."""
    techniques = json.loads(TECHNIQUES_FILE.read_text())
    n = sum(1 for t in techniques.values() if not t["is_subtechnique"])
    return {"top1": 1 / n, "top3": 3 / n, "mrr": sum(1 / r for r in range(1, n + 1)) / n, "techniques": n}


BOTH = [SOURCE_GROUP, SOURCE_CURATED]
CURATED = [SOURCE_CURATED]


def configs():
    drop = d_overlapping_distractors()
    return [
        # label, predictor builder, protocol
        ("curated, most frequent next step (no context)", markov_on(CURATED, max_order=0), "history_only"),
        ("MITRE groups only (inferred order)", markov_on([SOURCE_GROUP]), "history_only"),
        ("DEFAULT: curated (hand-specified)", markov_on(CURATED), "history_only"),
        ("groups + curated pooled in one table", markov_on(BOTH), "history_only"),
        (f"curated minus {len(drop)} distractors overlapping D", markov_on(CURATED, drop=drop), "history_only"),
        ("curated minus own family's reference", markov_on(CURATED), "no_own_reference"),
        ("other incidents only, leave-one-out", markov_on([]), "leave_one_out"),
        ("curated + other incidents, leave-one-out", markov_on(CURATED), "leave_one_out"),
        ("other families' incidents only", markov_on([]), "leave_family_out"),
        ("curated minus own ref + other families", markov_on(CURATED), "leave_family_out"),
    ]


HEADER = (f"{'training data':<47}{'top1':>7}{'top1tie':>8}{'top3':>7}{'mrr':>7}{'P':>7}{'R':>7}{'F1':>7}"
          f"{'correct/instances':>19}{'incidents':>10}")


def row(label, m):
    return (f"{label:<47}{m['top1']:>7.3f}{m['top1_tie']:>8.3f}{m['top3']:>7.3f}{m['mrr']:>7.3f}"
            f"{m['precision']:>7.3f}{m['recall']:>7.3f}{m['f1']:>7.3f}"
            f"{str(m['correct']) + ' / ' + str(m['instances']):>19}{m['incidents']:>10}")


def variant_class(entry):
    return "base (verbatim template)" if entry["variant"] == "base" else "variant (skip and/or insert)"


def report(entries, title, pipeline_of=None):
    lines = [f"=== {title} ===", HEADER, "-" * len(HEADER)]
    c = chance()
    lines.append(f"{'no knowledge: uniform over ' + str(c['techniques']) + ' techniques':<47}"
                 f"{c['top1']:>7.3f}{c['top1']:>8.3f}{c['top3']:>7.3f}{c['mrr']:>7.3f}{'-':>7}{'-':>7}{'-':>7}"
                 f"{'(analytic)':>19}{'-':>10}")
    for label, build, protocol in configs():
        lines.append(row(label, evaluate(entries, build, protocol)))

    default = markov_on(CURATED)
    full = evaluate(entries, default, "history_only", by=lambda e: e["pattern"])
    lines += ["", "DEFAULT model by pattern. A, B, C have their reference sequence in the database. D has no",
              "single reference, but every 2-step path of D occurs in a hand-written distractor:"]
    for pattern, m in full["by"].items():
        lines.append(row(f"  pattern {pattern}", m))
    without = evaluate(entries, markov_on(CURATED, drop=d_overlapping_distractors()), "history_only",
                       by=lambda e: e["pattern"])
    if "D" in without["by"]:
        lines.append(row("  pattern D, overlapping distractors removed", without["by"]["D"]))
    held = evaluate(entries, default, "no_own_reference", by=lambda e: e["pattern"])
    lines += ["", "curated minus own family's reference, by pattern (the unseen-pattern setting):"]
    for pattern, m in held["by"].items():
        lines.append(row(f"  pattern {pattern}", m))
    variants = evaluate(entries, default, "history_only", by=variant_class)
    lines += ["", "DEFAULT model by variant:"]
    for name, m in variants["by"].items():
        lines.append(row(f"  {name}", m))
    lines.append(f"\nincidents contributing no instance: {full['no_trajectory']} without a trajectory, "
                 f"{full['single_step']} with a single step; "
                 f"macro P/R/F1 average over {full['target_classes']} target techniques.")
    if pipeline_of is not None:
        e2e = evaluate_end_to_end(pipeline_of, entries, default)
        lines.append(f"\nSTRICT END-TO-END, DEFAULT model: {e2e['correct']} of {e2e['instances']} true transitions "
                     f"predicted correctly (top-1 {e2e['top1']:.3f}). The pipeline reproduced the true path up to "
                     f"the prediction point for {e2e['path_reproduced']} of them.")
    return "\n".join(lines)


NOTES = """notes:
- Sample: 24 synthetic incidents from 4 templates. With 90 instances one instance
  is about 1.1 points; in a per-pattern row (18-24 instances) it is 4 to 6 points.
- 'curated' is 11 sequences written by hand by the author of the data generator.
  Three of them are the reference forms of patterns A, B and C, so a base
  incident of those patterns is a verbatim copy of a training sequence. All the
  predictive signal in this table comes from those 11 sequences.
- MITRE ATT&CK group data contributes nothing to prediction here: alone it
  scores zero and pooled it lowers accuracy, because the order of a group's
  techniques is not published and the order inferred from tactic and technique
  id produces artificial transitions. The default model therefore does not use
  it. That choice was made after seeing these results on these 24 incidents.
- Pattern D is 'novel' only in the sense that no single historical sequence
  equals it. See the two pattern-D rows.
- leave-one-out trains on sibling incidents of the same pattern, so it measures
  recall of a known pattern.
- 'correct / instances' is the top1 count. top1tie removes alphabetical luck."""


def main():
    truth = ground_truth_trajectories()
    pipeline = pipeline_trajectories()
    print(report(truth, "next-step prediction on GROUND-TRUTH trajectories (24 incidents)"))
    print()
    print(report(pipeline,
                 "AGREEMENT WITH THE PIPELINE'S OWN NEXT STEP (mapper incidents + mapper techniques).\n"
                 "    Prefix and target both come from the pipeline, including its mapping errors.\n"
                 "    This is NOT end-to-end accuracy; see the strict end-to-end line below the table",
                 pipeline_of=truth))
    print()
    print(NOTES)


if __name__ == "__main__":
    main()
