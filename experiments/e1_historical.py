"""E1 - does historical attack knowledge improve next-step prediction?

  python -m experiments.e1_historical
"""

from evaluation.prediction_eval import (chance, d_overlapping_distractors, evaluate, evaluate_end_to_end,
                                        markov_on)
from evaluation.trajectories import ground_truth_trajectories, pipeline_trajectories
from prediction.historical import SOURCE_CURATED, SOURCE_GROUP

from .common import PREDICTION_METRICS, write

CURATED, GROUPS = [SOURCE_CURATED], [SOURCE_GROUP]
METRICS = ["top1", "top1_tie", "top3", "mrr", "precision", "recall", "f1", "correct", "instances", "incidents"]


def conditions():
    return [
        # historical knowledge, in-environment incidents, builder, protocol
        ("none (most frequent next step among other incidents)", "all other incidents",
         markov_on([], max_order=0), "leave_one_out"),
        ("MITRE groups (inferred order)", "none", markov_on(GROUPS), "history_only"),
        ("hand-written sequences (default)", "none", markov_on(CURATED), "history_only"),
        ("groups + hand-written, pooled", "none", markov_on(GROUPS + CURATED), "history_only"),
        ("hand-written minus own family's reference", "none", markov_on(CURATED), "no_own_reference"),
        ("hand-written minus distractors overlapping D", "none",
         markov_on(CURATED, drop=d_overlapping_distractors()), "history_only"),
        ("hand-written minus own family's reference and minus distractors overlapping D", "none",
         markov_on(CURATED, drop=d_overlapping_distractors()), "no_own_reference"),
        ("none", "other families only", markov_on([]), "leave_family_out"),
        ("hand-written minus own family's reference", "other families only", markov_on(CURATED),
         "leave_family_out"),
        ("none", "all other incidents", markov_on([]), "leave_one_out"),
        ("hand-written sequences (default)", "all other incidents", markov_on(CURATED), "leave_one_out"),
    ]


def run():
    truth, pipeline = ground_truth_trajectories(), pipeline_trajectories()
    c = chance()
    rows = [{"historical knowledge": "none", "in-environment incidents": "none",
             "top1": c["top1"], "top1_tie": c["top1"], "top3": c["top3"], "mrr": c["mrr"],
             "instances": f"analytic: uniform over {c['techniques']} techniques"}]
    by_pattern, end_to_end = [], []
    for knowledge, env, build, protocol in conditions():
        rows.append({"historical knowledge": knowledge, "in-environment incidents": env,
                     **evaluate(truth, build, protocol)})
        if env == "none":  # only these rows are label-free end to end
            e2e = evaluate_end_to_end(truth, pipeline, build, protocol)
            end_to_end.append({"historical knowledge": knowledge, "in-environment incidents": env,
                               "top1": e2e["top1"], "correct": e2e["correct"],
                               "path reproduced by pipeline": e2e["path_reproduced"],
                               "true transitions": e2e["instances"]})
    for knowledge, build, protocol in (
            ("hand-written sequences (default)", markov_on(CURATED), "history_only"),
            ("hand-written minus own family's reference", markov_on(CURATED), "no_own_reference"),
            ("hand-written minus distractors overlapping D",
             markov_on(CURATED, drop=d_overlapping_distractors()), "history_only"),
            ("hand-written minus own family's reference and minus distractors overlapping D",
             markov_on(CURATED, drop=d_overlapping_distractors()), "no_own_reference")):
        for pattern, m in evaluate(truth, build, protocol, by=lambda e: e["pattern"])["by"].items():
            by_pattern.append({"historical knowledge": knowledge, "pattern": pattern, **m})
    return rows, by_pattern, end_to_end


def find(rows, knowledge, env):
    return next(r for r in rows if r["historical knowledge"] == knowledge
                and r["in-environment incidents"] == env)


def main():
    rows, by_pattern, end_to_end = run()
    default = find(rows, "hand-written sequences (default)", "none")
    unseen = find(rows, "hand-written minus own family's reference", "none")
    groups = find(rows, "MITRE groups (inferred order)", "none")
    pooled = find(rows, "groups + hand-written, pooled", "none")
    family_none = find(rows, "none", "other families only")
    family_hist = find(rows, "hand-written minus own family's reference", "other families only")
    loo_none = find(rows, "none", "all other incidents")
    loo_hist = find(rows, "hand-written sequences (default)", "all other incidents")
    d_with = next(r for r in by_pattern if r["pattern"] == "D" and "default" in r["historical knowledge"])
    d_without = next(r for r in by_pattern if r["pattern"] == "D"
                     and r["historical knowledge"] == "hand-written minus distractors overlapping D")
    strict_label = "hand-written minus own family's reference and minus distractors overlapping D"
    unseen_label = "hand-written minus own family's reference"
    strict = find(rows, strict_label, "none")
    frequency = find(rows, "none (most frequent next step among other incidents)", "all other incidents")
    per = lambda label: ", ".join(f"{r['pattern']} {r['correct']}/{r['instances']}" for r in by_pattern
                                  if r["historical knowledge"] == label)
    e2e = find(end_to_end, "hand-written sequences (default)", "none")
    findings = [
        f"With a history that contains the attack's reference sequence, top-1 is {default['top1']:.3f} "
        f"({default['correct']} of {default['instances']}). Comparators: {rows[0]['top1']:.3f} for no knowledge "
        f"at all, and {frequency['top1']:.3f} ({frequency['correct']} of {frequency['instances']}) for always "
        "naming the most frequent next step seen in other incidents. This is the best case for history: three "
        "of the 11 hand-written sequences are the generator's own templates.",
        f"With the tested pattern's reference removed (an attack the history has not seen), top-1 is "
        f"{unseen['top1']:.3f} ({unseen['correct']} of {unseen['instances']}). By pattern: "
        f"{per(unseen_label)}. The gain is confined to patterns B and D and "
        "comes from distractor sequences, written by the same author, that share parts of their paths; "
        "patterns A and C get nothing.",
        f"With those overlapping distractors removed as well, top-1 is {strict['top1']:.3f} "
        f"({strict['correct']} of {strict['instances']}; by pattern: {per(strict_label)}). "
        "So this experiment does NOT show that history helps on unseen attacks.",
        f"Real MITRE ATT&CK group data does not help: {groups['correct']} of {groups['instances']} correct alone, "
        f"and pooling it with the hand-written sequences lowers top-1 from {default['top1']:.3f} to "
        f"{pooled['top1']:.3f}.",
        f"Unseen pattern with other families' incidents available: {family_none['correct']} of "
        f"{family_none['instances']} without history, {family_hist['correct']} of {family_hist['instances']} "
        "with it; the same B-and-D caveat applies.",
        f"Known pattern with sibling incidents available: {loo_none['correct']} of {loo_none['instances']} "
        f"without history, {loo_hist['correct']} of {loo_hist['instances']} with it. History adds nothing "
        "once the same pattern has been seen locally.",
        f"Pattern D (no reference in the history): {d_with['correct']} of {d_with['instances']} correct, but "
        f"{d_without['correct']} of {d_without['instances']} once the distractor sequences that share a 2-step "
        "path with D are removed.",
        f"Strict end-to-end with the label-free pipeline and the default history: {e2e['correct']} of "
        f"{e2e['true transitions']} true transitions predicted (top-1 {e2e['top1']:.3f}); the pipeline "
        f"reproduced the true path so far for {e2e['path reproduced by pipeline']} of them.",
    ]
    notes = [
        "What E1 supports: a Markov model over the hand-written sequences predicts well when the history "
        "contains the attack's own template; MITRE group data adds nothing with this method; history adds "
        "nothing once sibling incidents exist. What it does not support: that history helps on unseen attacks, "
        "or that independently sourced threat intelligence would help.",
        "All hand-written sequences, including the distractors, were written by the author of the data "
        "generator.",
        "Patterns A and C are held out together: A's reference is a prefix of C's.",
        "'none' with no in-environment incidents is an analytic chance level over 222 techniques, not a run; "
        "it is a very weak comparator, which is why the frequency baseline is quoted beside it.",
        "The end-to-end table has only history-trained rows, because rows that train on other incidents would "
        "use their labelled trajectories. A true transition counts as correct only if the pipeline reproduced "
        "the true path up to that point and the top prediction is the true next technique.",
    ]
    text = write(
        "e1", "E1 - Historical knowledge",
        "Does historical attack knowledge improve next-step prediction?",
        [("prediction", "Ground-truth trajectories: next-step prediction by what the model was trained on",
          ["historical knowledge", "in-environment incidents"] + METRICS, rows),
         ("by_pattern", "By pattern (no in-environment incidents)",
          ["historical knowledge", "pattern", "top1", "top1_tie", "top3", "mrr", "correct", "instances",
           "incidents"], by_pattern),
         ("end_to_end", "Strict end-to-end with the label-free pipeline (history-trained models only)",
          ["historical knowledge", "in-environment incidents", "top1", "correct",
           "path reproduced by pipeline", "true transitions"], end_to_end)],
        findings, notes, metrics=PREDICTION_METRICS)
    print(text)


if __name__ == "__main__":
    main()
