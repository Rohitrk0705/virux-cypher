"""E3 - can the system tell a known attack, a modified variant and a novel attack apart?

Classes come from the generator:
  known   - base instances of patterns A, B, C (their reference is in the DB)
  variant - instances of A, B, C with a step skipped and/or inserted
  novel   - pattern D (no reference in the DB)

The score is the incident's best similarity against the historical database.
Two thresholds turn it into a class: score >= t_known -> known,
score >= t_variant -> variant, otherwise novel. Because any thresholds picked
by looking at these 24 incidents would be tuned to them, they are chosen by
leave-one-out: for each incident the thresholds that classify the OTHER 23
best are applied to it.

  python -m experiments.e3_discrimination
"""

from collections import Counter
from statistics import mean

from evaluation.similarity_eval import REFERENCE
from evaluation.trajectories import as_contract_3, benign_pipeline_trajectories
from prediction.similarity import match_historical

from .common import trajectory_sets, write

CLASSES = ["known", "variant", "novel"]


def true_class(entry):
    if entry["pattern"] == "D":
        return "novel"
    return "known" if entry["variant"] == "base" else "variant"


def best_match(entry, mode):
    """(best similarity, attack id of the best match); (0.0, None) without a trajectory."""
    if not entry["techniques"]:
        return 0.0, None
    matches = match_historical(as_contract_3(entry), top_k=1, mode=mode)["matches"]
    return (matches[0]["similarity"], matches[0]["attack_id"]) if matches else (0.0, None)


def best_score(entry, mode):
    return best_match(entry, mode)[0]


def classify(score, t_variant, t_known):
    return "known" if score >= t_known else "variant" if score >= t_variant else "novel"


def fit(samples):
    """Thresholds maximising accuracy on samples [(score, class)]. Candidates
    are midpoints between neighbouring distinct scores; ties go to the lowest
    thresholds."""
    scores = sorted({s for s, _ in samples})
    cuts = [0.0] + [(a + b) / 2 for a, b in zip(scores, scores[1:])] + [1.01]
    best = None
    for i, t_variant in enumerate(cuts):
        for t_known in cuts[i:]:
            correct = sum(classify(s, t_variant, t_known) == c for s, c in samples)
            if best is None or correct > best[0]:
                best = (correct, t_variant, t_known)
    return best[1], best[2]


def auc(positive, negative):
    """Probability that a random positive scores above a random negative."""
    pairs = [(p > n) + 0.5 * (p == n) for p in positive for n in negative]
    return sum(pairs) / len(pairs) if pairs else 0.0


def run():
    summary, confusion, scores, details = [], [], [], []
    benign_entries = [e for e in benign_pipeline_trajectories() if e["techniques"]]
    for label, entries in trajectory_sets():
        for mode in ("temporal", "static"):
            samples = [(best_score(e, mode), true_class(e)) for e in entries]
            benign = [best_score(e, mode) for e in benign_entries] if label.startswith("pipeline") else []
            by_class = {c: [s for s, k in samples if k == c] for c in CLASSES}
            predicted = []
            for i, (score, _) in enumerate(samples):
                t_variant, t_known = fit(samples[:i] + samples[i + 1:])
                predicted.append(classify(score, t_variant, t_known))
            truth = [c for _, c in samples]
            matrix = Counter(zip(truth, predicted))
            novel_total = truth.count("novel")
            novel_as_match = sum(matrix[("novel", p)] for p in ("known", "variant"))
            fitted = fit(samples)
            in_sample = sum(classify(s, *fitted) == c for s, c in samples)
            # 'known' verdicts whose best match is some other record than the pattern's own reference
            spurious = [e["gt_id"] for e, p in zip(entries, predicted)
                        if p == "known" and true_class(e) == "known"
                        and best_match(e, mode)[1] != REFERENCE[e["pattern"]]]
            wrong = [f"{e['gt_id']} ({e['pattern']} {e['variant']}, {s:.3f}, {c} called {p})"
                     for e, (s, c), p in zip(entries, samples, predicted) if c != p]
            details.append({"trajectories": label, "similarity": mode, "wrong": wrong, "spurious": spurious,
                            "no_trajectory": sum(1 for e in entries if not e["techniques"])})
            benign_as_match = sum(classify(s, *fitted) != "novel" for s in benign)
            summary.append({
                "trajectories": label, "similarity": mode,
                "accuracy (leave-one-out thresholds)": sum(t == p for t, p in zip(truth, predicted)) / len(samples),
                "correct": sum(t == p for t, p in zip(truth, predicted)), "incidents": len(samples),
                "majority-class baseline": max(truth.count(c) for c in CLASSES),
                "correct with thresholds fitted on all incidents (in-sample)": in_sample,
                "correct 'known' verdicts resting on a record other than the own reference": len(spurious),
                "incidents without a trajectory (scored 0, called novel)":
                    sum(1 for e in entries if not e["techniques"]),
                "false positive rate (novel taken for known or variant)":
                    novel_as_match / novel_total if novel_total else 0.0,
                "novel incidents": novel_total,
                "AUC known vs rest": auc(by_class["known"], by_class["variant"] + by_class["novel"]),
                "AUC novel vs rest (lower score = novel)":
                    auc(by_class["known"] + by_class["variant"], by_class["novel"]),
                "thresholds fitted on all 24 (variant, known)": f"{fitted[0]:.3f}, {fitted[1]:.3f}",
                "attack-free inferred incidents taken for known or variant":
                    f"{benign_as_match} / {len(benign)}" if benign else "n/a",
            })
            if benign:
                scores.append({"trajectories": label, "similarity": mode,
                               "class": "attack-free inferred incident",
                               "min": min(benign), "mean": mean(benign), "max": max(benign),
                               "incidents": len(benign)})
            for t in CLASSES:
                confusion.append({"trajectories": label, "similarity": mode, "true class": t,
                                  **{f"predicted {p}": matrix[(t, p)] for p in CLASSES},
                                  "incidents": truth.count(t)})
                values = by_class[t]
                scores.append({"trajectories": label, "similarity": mode, "class": t,
                               "min": min(values), "mean": mean(values), "max": max(values),
                               "incidents": len(values)})
    return summary, confusion, scores, details


def main():
    summary, confusion, scores, details = run()
    findings = []
    for row in summary:
        if row["similarity"] != "temporal":
            continue
        label = row["trajectories"]
        ranges = {s["class"]: s for s in scores if s["trajectories"] == label and s["similarity"] == "temporal"}
        detail = next(d for d in details if d["trajectories"] == label and d["similarity"] == "temporal")
        novel_wrong = round(row["false positive rate (novel taken for known or variant)"] * row["novel incidents"])
        text = (
            f"{label}: {row['correct']} of {row['incidents']} incidents classified correctly with leave-one-out "
            f"thresholds (majority-class baseline {row['majority-class baseline']} of {row['incidents']}; "
            f"{row['correct with thresholds fitted on all incidents (in-sample)']} with thresholds fitted on all "
            f"incidents). {novel_wrong} of the {row['novel incidents']} novel incidents were taken for a known "
            f"or variant attack. Best-similarity ranges: known {ranges['known']['min']:.3f}-"
            f"{ranges['known']['max']:.3f}, variant {ranges['variant']['min']:.3f}-{ranges['variant']['max']:.3f}, "
            f"novel {ranges['novel']['min']:.3f}-{ranges['novel']['max']:.3f}.")
        if detail["wrong"]:
            text += " Misclassified: " + "; ".join(detail["wrong"]) + "."
        if detail["no_trajectory"]:
            text += (f" {detail['no_trajectory']} incident(s) had no pipeline trajectory; they score 0 and are "
                     "called novel.")
        if detail["spurious"]:
            text += (f" {len(detail['spurious'])} correct 'known' verdict(s) ({', '.join(detail['spurious'])}) "
                     "rest on a best match that is not the pattern's own reference, i.e. right for the wrong "
                     "reason.")
        if row["attack-free inferred incidents taken for known or variant"] != "n/a":
            static_row = next(r for r in summary if r["trajectories"] == label and r["similarity"] == "static")
            text += (f" Of the inferred incidents with no attack in them, "
                     f"{row['attack-free inferred incidents taken for known or variant']} would be reported as a "
                     f"known or variant attack ({static_row['attack-free inferred incidents taken for known or variant']} "
                     "with the order-free score; thresholds fitted on all 24).")
        findings.append(text)
    for label in dict.fromkeys(r["trajectories"] for r in summary):
        t = next(r for r in summary if r["trajectories"] == label and r["similarity"] == "temporal")
        st = next(r for r in summary if r["trajectories"] == label and r["similarity"] == "static")
        gap = st["correct"] - t["correct"]
        verdict = ("a one-incident difference, which is noise at this sample size" if abs(gap) <= 1 else
                   "the order-aware score is WORSE here" if gap > 0 else "the order-aware score is better here")
        findings.append(f"{label}, order-free (static) similarity instead: {st['correct']} of {st['incidents']} "
                        f"correct against {t['correct']} with the order-aware score; {verdict}.")
    truth_scores = {s["class"]: s for s in scores
                    if s["trajectories"].startswith("ground") and s["similarity"] == "temporal"}
    notes = [
        "What E3 supports: on ground-truth trajectories one similarity score separates verbatim-known, variant "
        "and pattern-D incidents. What it does not support: usable discrimination on the label-free pipeline.",
        "'Known' is 1.000 by construction: base incidents are verbatim copies of the reference sequences in "
        "the database, so the known row and 'AUC known vs rest' on ground truth are tautological.",
        f"The variant/novel boundary is thin and depends on the hand-written distractors: on ground truth the "
        f"lowest variant scores {truth_scores['variant']['min']:.3f} and the highest novel incident "
        f"{truth_scores['novel']['max']:.3f}. Pattern D's best matches are distractors written by the same "
        "author as the generator; without them D would score lower and separate more easily.",
        "Class sizes are 9 known, 9 variant, 6 novel. One incident changes accuracy by about 4 points.",
        "Leave-one-out thresholds avoid tuning on the tested incident but are still fitted to 23 incidents "
        "from the same 4 templates; the gap to the in-sample count shows how unstable they are.",
        "On pipeline trajectories, mapper and grouping errors lower the similarity of known attacks, and short "
        "fragments can equal very short MITRE group records.",
        "The pipeline also produces incidents that contain no attack at all. They are not part of the "
        "three-way accuracy; the summary table reports how many the in-sample thresholds would call a match.",
        "Similarity is computed on complete trajectories. For an attack still in progress the same measure "
        "is much weaker (see evaluation/results/m4_similarity.txt).",
    ]
    text = write(
        "e3", "E3 - Similarity discrimination",
        "Can the system tell a known attack, a modified variant and a previously unseen attack apart?",
        [("summary", "Three-way classification from best historical similarity",
          ["trajectories", "similarity", "accuracy (leave-one-out thresholds)", "correct", "incidents",
           "majority-class baseline", "correct with thresholds fitted on all incidents (in-sample)",
           "correct 'known' verdicts resting on a record other than the own reference",
           "incidents without a trajectory (scored 0, called novel)",
           "false positive rate (novel taken for known or variant)", "novel incidents", "AUC known vs rest",
           "AUC novel vs rest (lower score = novel)", "thresholds fitted on all 24 (variant, known)",
           "attack-free inferred incidents taken for known or variant"], summary),
         ("confusion", "Confusion matrices (leave-one-out thresholds)",
          ["trajectories", "similarity", "true class", "predicted known", "predicted variant",
           "predicted novel", "incidents"], confusion),
         ("scores", "Best similarity per class",
          ["trajectories", "similarity", "class", "min", "mean", "max", "incidents"], scores)],
        findings, notes)
    print(text)


if __name__ == "__main__":
    main()
