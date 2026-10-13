"""M10: E1, E2 and E3 redesigned, on the graded dataset.

  VIRUX_DATASET=graded python -m experiments.graded

Run after generating the graded dataset, mapping it and building the graph
with the same VIRUX_DATASET (see docs/PROGRESS.md, M10). Writes
experiments/results_graded/.

What changed from the first experiments (experiments/results/, kept):
- 90 incidents from 18 templates with graded similarity, instead of 24 from 4.
  Every template has one exact instance and four perturbed ones.
- History is made of (a) the reference sequences of the dataset's own
  templates, used in leave-own-template-out fashion so that "similar but not
  identical" exists, and (b) eight real, ORDERED adversary emulation plans
  (data/mitre/emulation_plans.json). There are no hand-written distractors.
- E3's known class is perturbed instances, never verbatim copies.
"""

import importlib.util
import json
import random
from collections import Counter
from pathlib import Path
from statistics import mean

from evaluation.prediction_eval import chance, finish, instances, new_tally, score_instance
from evaluation.trajectories import (as_contract_3, benign_pipeline_trajectories, ground_truth_trajectories,
                                     pipeline_trajectories)
from knowledge_graph import config
from prediction.historical import SOURCE_GROUP, historical, to_sequence
from prediction.markov import MarkovPredictor
from prediction.similarity import match_historical, similarity
from prediction.static import StaticPredictor

from . import common
from .e3_discrimination import auc, classify, fit

ROOT = Path(__file__).resolve().parent.parent
HELD_OUT = ["G02", "G08", "G13", "G16", "G17", "G18"]     # E3: templates the history does not contain
NEAR_NOVEL = ["G02", "G08", "G13"]                        # held out, but a close relative is in the history
BINS = [(0.7, 1.01, "0.70 or more (near sibling)"), (0.5, 0.7, "0.50 to 0.70"),
        (0.3, 0.5, "0.30 to 0.50"), (0.0, 0.3, "under 0.30 (unrelated)")]
METRICS = ["top1", "top1_tie", "top3", "mrr", "precision", "recall", "f1", "correct", "instances", "incidents"]


def generator():
    spec = importlib.util.spec_from_file_location("virux_generate", ROOT / "data" / "generator" / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TEMPLATES = generator().GRADED_TEMPLATES
REFERENCE = {name: to_sequence(steps) for name, (_, steps) in TEMPLATES.items()}
FAMILY = {name: family for name, (family, _) in TEMPLATES.items()}
REAL_PLANS = [p["sequence"] for p in json.loads((ROOT / "data" / "mitre" / "emulation_plans.json").read_text())]
GROUPS = [r["sequence"] for r in historical([SOURCE_GROUP])]


VOCABULARY = {t for seq in REFERENCE.values() for t in seq}
REAL_PLANS_IN_VOCABULARY = [to_sequence([t for t in plan if t in VOCABULARY]) for plan in REAL_PLANS]
# the reorder templates permute a credential template, so they are one family for hold-out purposes
HOLD_OUT_FAMILY = {name: ("credential" if FAMILY[name] == "reorder" else FAMILY[name]) for name in FAMILY}


class FrequencyNoRepeat:
    """Context-free prior: how often each technique follows anything in the history,
    never proposing a technique already in the path."""

    def __init__(self, sequences):
        self.counts = Counter(t for seq in sequences for t in to_sequence(seq)[1:])

    def rank(self, path):
        seen = set(to_sequence(path))
        counts = {t: c for t, c in self.counts.items() if t not in seen}
        total = sum(counts.values())
        return [(t, c / total) for t, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))], {}


class PaddedMarkov(MarkovPredictor):
    """The same Markov ranking, followed by the candidates of the shorter contexts.
    The plain model lists only continuations it has seen after the matched context
    (often one or two), which caps top-3 and MRR; this variant ranks as many
    candidates as the static predictor does. Top-1 is the same unless the plain list is empty."""

    def rank(self, path):
        ranked, info = super().rank(path)
        listed = {t for t, _ in ranked}
        path = to_sequence(path)
        extra = []
        if path:
            first_order = self.counts[1].get((path[-1],), {})
            extra += [t for t, _ in sorted(first_order.items(), key=lambda kv: (-kv[1], kv[0]))]
        extra += [t for t, _ in sorted(self.any_next.items(), key=lambda kv: (-kv[1], kv[0]))]
        for t in extra:
            if t not in listed and t != "<end>":
                listed.add(t)
                ranked.append((t, 0.0))
        return ranked, info


def nearest_other(template):
    """(similarity, name) of the most similar reference among the OTHER templates."""
    return max((similarity(REFERENCE[template], REFERENCE[o]), o) for o in REFERENCE if o != template)


def history(entry, condition):
    """Training sequences for one test incident under a named condition."""
    own = entry["pattern"]
    others = [seq for name, seq in REFERENCE.items() if name != own]
    return {
        "real plans": REAL_PLANS,
        "real plans, dataset vocabulary only": REAL_PLANS_IN_VOCABULARY,
        "MITRE groups (unordered)": GROUPS,
        "templates of other families": [seq for name, seq in REFERENCE.items()
                                        if HOLD_OUT_FAMILY[name] != HOLD_OUT_FAMILY[own]],
        "other templates + real plans, dataset vocabulary only": others + REAL_PLANS_IN_VOCABULARY,
        "other templates": others,
        "other templates + real plans": others + REAL_PLANS,
        "all templates (own included)": list(REFERENCE.values()),
        "all templates + real plans": list(REFERENCE.values()) + REAL_PLANS,
    }[condition]


def run(entries, condition, make=MarkovPredictor, by=None, **kwargs):
    """Score every usable entry under a condition; returns metrics (and per-group metrics)."""
    total, groups = new_tally(), {}
    for e in entries:
        if not e["techniques"]:
            continue
        predictor = make(history(e, condition), **kwargs)
        cases = instances(e["techniques"])
        for tally in [total] + ([groups.setdefault(by(e), new_tally())] if by else []):
            tally["incidents"] += bool(cases)
            for path, target in cases:
                score_instance(tally, predictor, path, target)
    result = finish(total)
    if by:
        result["by"] = {k: finish(v) for k, v in sorted(groups.items(), key=lambda kv: str(kv[0]))}
    return result


def end_to_end(truth, pipeline, condition):
    """A true transition counts only if the pipeline reproduced the true path so far
    and the top prediction is the true next step. Denominator: all true transitions."""
    observed = {e["gt_id"]: to_sequence(e["techniques"] or []) for e in pipeline}
    n = correct = reachable = 0
    for e in truth:
        predictor = MarkovPredictor(history(e, condition))
        for path, target in instances(e["techniques"]):
            n += 1
            if observed[e["gt_id"]][:len(path)] != path:
                continue
            reachable += 1
            ranked = predictor.rank(path)[0]
            correct += bool(ranked) and ranked[0][0] == target
    return {"correct": correct, "instances": n, "path reproduced by pipeline": reachable,
            "top1": correct / n if n else 0.0}


# ----------------------------------------------------------------------------
# E1
# ----------------------------------------------------------------------------

def e1(truth, pipeline):
    c = chance()
    PRIOR = "other templates, context removed (frequency prior)"
    rows = [{"history": "no history at all (analytic chance)", "model": "-", "top1": c["top1"],
             "top1_tie": c["top1"], "top3": c["top3"], "mrr": c["mrr"],
             "instances": f"uniform over {c['techniques']} techniques"},
            {"history": "other templates", "model": "frequency prior, no context",
             **run(truth, "other templates", max_order=0)},
            {"history": "other templates", "model": "frequency prior, no context, never repeats a seen step",
             **run(truth, "other templates", make=FrequencyNoRepeat)},
            {"history": "real plans", "model": "frequency prior, no context", **run(truth, "real plans", max_order=0)}]
    conditions = ["real plans", "real plans, dataset vocabulary only", "MITRE groups (unordered)",
                  "templates of other families", "other templates", "other templates + real plans",
                  "other templates + real plans, dataset vocabulary only", "all templates (own included)",
                  "all templates + real plans"]
    results = {}
    for condition in conditions:
        results[condition] = run(truth, condition)
        rows.append({"history": condition, "model": "Markov, order 2 with back-off", **results[condition]})
    rows.append({"history": "other templates", "model": "Markov, order 1 only",
                 **run(truth, "other templates", max_order=1)})
    rows.append({"history": "all templates (own included)", "model": "Markov, order 1 only",
                 **run(truth, "all templates (own included)", max_order=1)})

    # where in the attack the gain is, and which templates gain
    by_position, per_template = [], []
    position = lambda path: min(len(path) + 1, 6)
    tallies = {"Markov, other templates": {}, "frequency prior, other templates": {}}
    for e in truth:
        others = history(e, "other templates")
        for name, model in (("Markov, other templates", MarkovPredictor(others)),
                            ("frequency prior, other templates", MarkovPredictor(others, max_order=0))):
            for path, target in instances(e["techniques"]):
                score_instance(tallies[name].setdefault(position(path), new_tally()), model, path, target)
    for step in sorted(tallies["Markov, other templates"]):
        m, f = finish(tallies["Markov, other templates"][step]), finish(tallies["frequency prior, other templates"][step])
        by_position.append({"step being predicted": f"{step}" + (" or later" if step == 6 else ""),
                            "Markov correct": m["correct"], "frequency prior correct": f["correct"],
                            "instances": m["instances"]})
    markov_t = run(truth, "other templates", by=lambda e: e["pattern"])["by"]
    prior_t = run(truth, "other templates", by=lambda e: e["pattern"], max_order=0)["by"]
    for template in sorted(REFERENCE):
        per_template.append({"template": template, "family": FAMILY[template],
                             "nearest other template": nearest_other(template)[1],
                             "similarity": nearest_other(template)[0],
                             "Markov correct": markov_t[template]["correct"],
                             "frequency prior correct": prior_t[template]["correct"],
                             "instances": markov_t[template]["instances"]})

    # how much of the test material the real plans could cover at all
    plan_bigrams = {b for plan in REAL_PLANS for b in zip(plan, plan[1:])}
    test_transitions = [(path[-1], target) for e in truth for path, target in instances(e["techniques"])]
    plan_vocabulary = {t for plan in REAL_PLANS for t in plan}
    coverage = {
        "techniques": f"{len(VOCABULARY & plan_vocabulary)} of the dataset's {len(VOCABULARY)} parent techniques "
                      f"occur in the plans; {len(plan_vocabulary - VOCABULARY)} of the plans' {len(plan_vocabulary)} "
                      "do not occur in the dataset",
        "transitions": f"{sum(t in plan_bigrams for t in test_transitions)} of {len(test_transitions)} test "
                       "transitions occur as adjacent steps in at least one plan",
    }

    bin_of = {}
    for template in REFERENCE:
        score, other = nearest_other(template)
        bin_of[template] = next(label for lo, hi, label in BINS if lo <= score < hi)
    graded = []
    for condition in ("other templates", "real plans", "other templates + real plans"):
        binned = run(truth, condition, by=lambda e: bin_of[e["pattern"]])["by"]
        for _, _, label in BINS:
            if label in binned:
                templates = sorted(t for t, b in bin_of.items() if b == label)
                graded.append({"history": condition, "similarity of the nearest other template": label,
                               "templates": " ".join(templates), **binned[label]})
    baseline_bins = run(truth, "other templates", by=lambda e: bin_of[e["pattern"]], max_order=0)["by"]
    for _, _, label in BINS:
        if label in baseline_bins:
            graded.append({"history": PRIOR,
                           "similarity of the nearest other template": label,
                           "templates": " ".join(sorted(t for t, b in bin_of.items() if b == label)),
                           **baseline_bins[label]})

    by_level = []
    for condition in ("all templates (own included)", "other templates"):
        for level, m in run(truth, condition, by=lambda e: e["variant"])["by"].items():
            by_level.append({"history": condition, "instance": level, **m})
    nearest = [{"template": t, "family": FAMILY[t], "nearest other template": nearest_other(t)[1],
                "similarity": nearest_other(t)[0], "bin": bin_of[t],
                "reference": " > ".join(REFERENCE[t])} for t in sorted(REFERENCE)]
    e2e = [{"history": condition, **end_to_end(truth, pipeline, condition)}
           for condition in ("real plans", "other templates", "all templates (own included)")]

    base, plan_prior = rows[1], rows[3]
    other, real, both, own = (results[k] for k in ("other templates", "real plans",
                                                    "other templates + real plans", "all templates (own included)"))
    family_out = results["templates of other families"]
    order1 = next(r for r in rows if r["model"] == "Markov, order 1 only" and r["history"] == "other templates")

    def bin_row(cond, label):
        return next((g for g in graded if g["history"] == cond
                     and g["similarity of the nearest other template"] == label), None)
    step_gain = "; ".join(f"step {r['step being predicted']}: {r['Markov correct'] - r['frequency prior correct']:+d}"
                          for r in by_position)
    hurt = [t for t in per_template if t["Markov correct"] < t["frequency prior correct"]]
    findings = [
        f"Reference points. Chance is {c['top1']:.3f}. A frequency prior built from the other 17 templates with all "
        f"context removed gets {base['correct']} of {base['instances']} (top-1 {base['top1']:.3f}); it always "
        f"proposes the same technique. The same prior that never repeats a seen step gets {rows[2]['correct']}. "
        "Both priors use the author-written templates, so they are not 'no history'.",
        f"History of similar but not identical attacks (the other 17 templates, never the incident's own), with "
        f"context: {other['correct']} of {other['instances']} (top-1 {other['top1']:.3f}, tie-aware "
        f"{other['top1_tie']:.3f}, top-3 {other['top3']:.3f}), {other['correct'] - base['correct']:+d} against the "
        "prior.",
        f"Where the gain over the prior comes from, by the step being predicted: {step_gain}. It is not "
        f"concentrated in the entry steps. With every template of the incident's own family removed "
        f"from the history, the model gets {family_out['correct']} of {family_out['instances']} "
        f"({family_out['correct'] - base['correct']:+d} against the prior).",
        "By how similar the nearest other template is (Markov against the prior): " + "; ".join(
            f"{label}: {bin_row('other templates', label)['correct']} against "
            f"{bin_row(PRIOR, label)['correct']} of {bin_row('other templates', label)['instances']}"
            for _, _, label in BINS if bin_row("other templates", label))
        + ". The benefit is absent for unrelated templates but does NOT grow steadily with similarity. "
        + (f"For {len(hurt)} of 18 templates history makes prediction worse than the prior "
           f"({', '.join(t['template'] for t in hurt)})."
           + (" The templates that reorder another one are among them: the model replays the twin's order."
              if {t['template'] for t in hurt} & {"G12", "G13"} else "") if hurt else ""),
        f"Real ordered emulation plans as the only history: {real['correct']} of {real['instances']} with context, "
        f"{plan_prior['correct']} as a context-free prior. They beat chance, but stay below the in-vocabulary "
        f"template prior ({base['correct']}). Added to the other templates they lower the count from "
        f"{other['correct']} to {both['correct']}; restricted to the dataset's vocabulary, "
        f"{results['real plans, dataset vocabulary only']['correct']} alone and "
        f"{results['other templates + real plans, dataset vocabulary only']['correct']} pooled. "
        f"Coverage: {coverage['techniques']}; {coverage['transitions']}.",
        f"MITRE group technique lists (no order) as history: {results['MITRE groups (unordered)']['correct']} of "
        f"{results['MITRE groups (unordered)']['instances']}.",
        f"History that contains the incident's own template: {own['correct']} of {own['instances']} "
        f"(top-1 {own['top1']:.3f}). By instance: " + "; ".join(
            f"{r['instance']} {r['correct']} of {r['instances']} ({r['top1']:.3f})"
            for r in by_level if r["history"] == "all templates (own included)") + ".",
        f"Second-order context adds nothing for related history: order 1 alone gets {order1['correct']} against "
        f"{other['correct']}.",
        "Strict end-to-end with the label-free pipeline: " + "; ".join(
            f"{r['history']}: {r['correct']} of {r['instances']} ({r['top1']:.3f})" for r in e2e) + ".",
    ]
    notes = [
        "What E1 supports: a Markov table built from related attacks in the same technique vocabulary predicts "
        "the next step better than a context-free prior. What it "
        "does not support: that the benefit grows with similarity, or that independently written history "
        "(the real emulation plans) helps.",
        "The templates, their shared prefixes and the similarity between them were all designed by the author "
        "of this project. 'Other templates' is a controlled stand-in for 'the history contains related attacks'.",
        "The eight real plans are emulation plans written from public reporting; their order is the plan's, not "
        "telemetry. One (APT29) is two scenarios back to back, one (FIN6) lists alternative end phases one after "
        "the other, and three have no initial-access step. They have 18 to 65 steps against 5 to 7 for a template.",
        f"One template is 5 incidents and {min(t['instances'] for t in per_template)} to "
        f"{max(t['instances'] for t in per_template)} prediction instances; a similarity bin can hold as few as "
        "two templates. Per-template counts are in the table.",
        "The model is the same Markov table with back-off in every 'Markov' row; only its training data changes.",
    ]
    return ("e1", "E1 (redesigned) - Historical knowledge",
            "Does historical attack knowledge improve next-step prediction, and does the benefit grow with how "
            "similar the history is to the attack?",
            [("prediction", "Next-step prediction on ground-truth trajectories, by what the history contains",
              ["history", "model"] + METRICS, rows),
             ("by_step", "Where in the attack the gain is (history = other templates)",
              ["step being predicted", "Markov correct", "frequency prior correct", "instances"], by_position),
             ("per_template", "Per template (history = other templates)",
              ["template", "family", "nearest other template", "similarity", "Markov correct",
               "frequency prior correct", "instances"], per_template),
             ("graded", "The same, by how similar the nearest other template is (history never contains the "
                        "incident's own template)",
              ["history", "similarity of the nearest other template", "templates", "top1", "top1_tie", "top3",
               "mrr", "correct", "instances", "incidents"], graded),
             ("by_instance", "By how much the instance was perturbed",
              ["history", "instance", "top1", "top1_tie", "top3", "mrr", "correct", "instances", "incidents"],
              by_level),
             ("end_to_end", "Strict end-to-end with the label-free pipeline",
              ["history", "top1", "correct", "path reproduced by pipeline", "instances"], e2e),
             ("templates", "The 18 templates and their nearest relatives",
              ["template", "family", "nearest other template", "similarity", "bin", "reference"], nearest)],
            findings, notes)


# ----------------------------------------------------------------------------
# E2
# ----------------------------------------------------------------------------

REORDER = ["G01", "G12", "G04", "G13"]   # two pairs with the same techniques in a different order


def e2(truth, pipeline):
    records = [{"attack_id": name, "sequence": seq} for name, seq in REFERENCE.items()]
    matching = []
    for label, entries in (("ground-truth trajectories", truth), ("pipeline trajectories", pipeline)):
        for subset, keep in (("all incidents", lambda e: True),
                             ("all except the reordered templates", lambda e: e["pattern"] not in REORDER),
                             ("perturbed instances only", lambda e: e["variant"] != "exact"),
                             ("templates that reorder another template", lambda e: e["pattern"] in REORDER)):
            chosen = [e for e in entries if keep(e)]
            for mode in ("static", "temporal"):
                unique = tied = 0
                for e in chosen:
                    if not e["techniques"]:
                        continue
                    found = match_historical(as_contract_3(e), top_k=18, mode=mode, records=records)["matches"]
                    if not found:
                        continue
                    winners = [m["attack_id"] for m in found if m["similarity"] == found[0]["similarity"]]
                    if e["pattern"] in winners:
                        tied += 1
                        unique += len(winners) == 1
                matching.append({"trajectories": label, "incidents scored": subset, "graph": mode,
                                 "own template is the unique top match": unique,
                                 "own template is top or tied for top": tied, "incidents": len(chosen),
                                 "accuracy (unique)": unique / len(chosen) if chosen else 0.0})
    prediction = []
    for label, entries in (("ground-truth trajectories", truth), ("pipeline trajectories", pipeline)):
        for condition in ("other templates", "all templates (own included)", "real plans"):
            for graph, make in (("static", StaticPredictor), ("temporal", MarkovPredictor),
                                ("temporal, ranking padded with shorter-context candidates", PaddedMarkov)):
                prediction.append({"trajectories": label, "history": condition, "graph": graph,
                                   **run(entries, condition, make=make)})
    reorder_prediction = {graph: run([e for e in truth if e["pattern"] in REORDER], "other templates", make=make)
                          for graph, make in (("static", StaticPredictor), ("temporal", MarkovPredictor))}

    def pick(rows, **want):
        return next(r for r in rows if all(r[k] == v for k, v in want.items()))
    findings = []
    for label in ("ground-truth trajectories", "pipeline trajectories"):
        rest_s, rest_t = (pick(matching, trajectories=label, graph=g, **{"incidents scored": "all except the reordered templates"})
                          for g in ("static", "temporal"))
        twin_s, twin_t = (pick(matching, trajectories=label, graph=g, **{"incidents scored": "templates that reorder another template"})
                          for g in ("static", "temporal"))
        gap = rest_t["own template is the unique top match"] - rest_s["own template is the unique top match"]
        findings.append(
            f"Matching, {label}: on the four templates that are reorderings of each other, order finds the right "
            f"one for {twin_t['own template is the unique top match']} of {twin_t['incidents']} incidents against "
            f"{twin_s['own template is the unique top match']} without order. That holds by construction: the pairs "
            f"contain the same techniques. On the other {rest_t['incidents']} incidents order changes "
            + ("nothing" if gap == 0 else f"{gap:+d} incident(s)")
            + f" ({rest_s['own template is the unique top match']} without, "
              f"{rest_t['own template is the unique top match']} with).")
        for condition in ("other templates", "all templates (own included)"):
            s, t, padded = (pick(prediction, trajectories=label, history=condition, graph=g)
                            for g in ("static", "temporal", "temporal, ranking padded with shorter-context candidates"))
            findings.append(
                f"Prediction, {label}, history = {condition}: top-1 {s['correct']} of {s['instances']} without order, "
                f"{t['correct']} with order ({t['correct'] - s['correct']:+d}). Top-3 {s['top3']:.3f} vs {t['top3']:.3f} "
                f"and MRR {s['mrr']:.3f} vs {t['mrr']:.3f}; with the Markov ranking padded to a comparable length, "
                f"top-3 {padded['top3']:.3f} and MRR {padded['mrr']:.3f}.")
    findings.append(
        f"Prediction on the four reordered templates only (ground truth, history = other templates): "
        f"{reorder_prediction['temporal']['correct']} of {reorder_prediction['temporal']['instances']} with order "
        f"against {reorder_prediction['static']['correct']} without. Order gives no clear advantage here: the "
        "history contains the twin with the other order, and the order-aware model tends to follow it.")
    notes = [
        "What E2 supports: order separates two attacks that contain the same techniques, and gives a modest "
        "top-1 gain in prediction. What it does not support: a general gain in matching (none outside the "
        "reordered pairs) or in ranked prediction.",
        "Two template pairs (G01/G12 and G04/G13) contain exactly the same techniques in a different order. "
        "Without order their references are indistinguishable, so a tie is the best a static match can do. The "
        "result on them demonstrates the mechanism; it was built into the dataset.",
        "The plain Markov ranking lists only continuations seen after the matched context, often one or two, "
        "while the static predictor ranks every co-occurring technique. Top-3 and MRR therefore favour the "
        "static predictor for a reason unrelated to order; the padded row removes most of that difference.",
        "'Static' and 'temporal' are two scoring rules over the same data: set overlap vs overlap plus edit "
        "distance for matching; co-occurrence vs Markov transitions for prediction.",
        "On pipeline trajectories the prediction target is the pipeline's own next step, mapping errors "
        "included; those rows compare the two rules on the same noisy input and are not end-to-end accuracy.",
    ]
    return ("e2", "E2 (redesigned) - Temporal information",
            "Does temporal ordering improve matching and prediction, compared with a static (order-free) graph?",
            [("matching", "Historical matching against the 18 template references",
              ["trajectories", "incidents scored", "graph", "own template is the unique top match",
               "own template is top or tied for top", "incidents", "accuracy (unique)"], matching),
             ("prediction", "Next-step prediction: order-free co-occurrence vs Markov transitions",
              ["trajectories", "history", "graph"] + METRICS, prediction)],
            findings, notes)


# ----------------------------------------------------------------------------
# E3
# ----------------------------------------------------------------------------

def e3_class(entry):
    if entry["pattern"] in HELD_OUT:
        return "novel"
    return {"exact": "exact", "light": "known", "heavy": "variant"}[entry["variant"]]


def e3(truth, pipeline):
    records = [{"attack_id": name, "sequence": seq} for name, seq in REFERENCE.items() if name not in HELD_OUT]
    classes = ["known", "variant", "novel"]
    benign = [e for e in benign_pipeline_trajectories() if e["techniques"]]

    def best(entry, mode):
        if not entry["techniques"]:
            return 0.0
        found = match_historical(as_contract_3(entry), top_k=1, mode=mode, records=records)["matches"]
        return found[0]["similarity"] if found else 0.0

    summary, confusion, scores = [], [], []
    for label, entries in (("ground-truth trajectories", truth), ("pipeline trajectories", pipeline)):
        for mode in ("temporal", "static"):
            scored = [(best(e, mode), e3_class(e), e) for e in entries]
            samples = [(s, c) for s, c, _ in scored if c != "exact"]
            kept = [e for _, c, e in scored if c != "exact"]
            predicted = []
            for i, (score, _) in enumerate(samples):
                predicted.append(classify(score, *fit(samples[:i] + samples[i + 1:])))
            actual = [c for _, c in samples]
            matrix = Counter(zip(actual, predicted))
            fitted = fit(samples)
            near = [(p, e) for p, e in zip(predicted, kept) if e["pattern"] in NEAR_NOVEL]
            far = [(p, e) for p, e in zip(predicted, kept) if e["pattern"] in HELD_OUT and e["pattern"] not in NEAR_NOVEL]
            by_class = {c: [s for s, k in samples if k == c] for c in classes}
            exact_scores = [s for s, c, _ in scored if c == "exact"]
            benign_scores = [best(e, mode) for e in benign] if label.startswith("pipeline") else []
            summary.append({
                "trajectories": label, "similarity": mode,
                "correct (leave-one-out thresholds)": sum(a == p for a, p in zip(actual, predicted)),
                "incidents": len(samples), "accuracy": sum(a == p for a, p in zip(actual, predicted)) / len(samples),
                "majority-class baseline": max(actual.count(c) for c in classes),
                "correct with in-sample thresholds": sum(classify(s, *fitted) == c for s, c in samples),
                "novel called known or variant": sum(matrix[("novel", p)] for p in ("known", "variant")),
                "novel incidents": actual.count("novel"),
                "near-novel called novel": f"{sum(p == 'novel' for p, _ in near)} / {len(near)}",
                "far-novel called novel": f"{sum(p == 'novel' for p, _ in far)} / {len(far)}",
                "AUC known vs variant": auc(by_class["known"], by_class["variant"]),
                "AUC (known + variant) vs novel": auc(by_class["known"] + by_class["variant"], by_class["novel"]),
                "attack-free incidents called known or variant":
                    f"{sum(classify(s, *fitted) != 'novel' for s in benign_scores)} / {len(benign_scores)}"
                    if benign_scores else "n/a",
            })
            for c in classes:
                confusion.append({"trajectories": label, "similarity": mode, "true class": c,
                                  **{f"predicted {p}": matrix[(c, p)] for p in classes}, "incidents": actual.count(c)})
            for name, values in ([(c, by_class[c]) for c in classes]
                                 + [("exact instance (not classified)", exact_scores),
                                    ("novel, near (G02 G08 G13)", [s for s, _, e in scored if e["pattern"] in NEAR_NOVEL]),
                                    ("novel, far (G16 G17 G18)", [s for s, _, e in scored if e["pattern"] in HELD_OUT
                                                                  and e["pattern"] not in NEAR_NOVEL])]
                                 + ([("attack-free inferred incident", benign_scores)] if benign_scores else [])):
                if values:
                    scores.append({"trajectories": label, "similarity": mode, "class": name, "min": min(values),
                                   "mean": mean(values), "max": max(values), "incidents": len(values)})
    # how much the result depends on WHICH six templates are held out (ground truth only)
    def accuracy(held_out, mode):
        refs = [{"attack_id": n, "sequence": q} for n, q in REFERENCE.items() if n not in held_out]
        data = []
        for e in truth:
            if e["pattern"] not in held_out and e["variant"] == "exact":
                continue
            found = match_historical(as_contract_3(e), top_k=1, mode=mode, records=refs)["matches"]
            label = "novel" if e["pattern"] in held_out else {"light": "known", "heavy": "variant"}[e["variant"]]
            data.append((found[0]["similarity"] if found else 0.0, label))
        return sum(classify(sc, *fit(data[:i] + data[i + 1:])) == lab for i, (sc, lab) in enumerate(data)), len(data)

    rng = random.Random(0)
    names = sorted(REFERENCE)
    draws = [sorted(rng.sample(names, 6)) for _ in range(100)]
    sensitivity = []
    for mode in ("temporal", "static"):
        counts = sorted(accuracy(set(d), mode)[0] for d in draws)
        sensitivity.append({"similarity": mode, "held-out sets tried": len(draws), "incidents": 78,
                            "fewest correct": counts[0], "median correct": counts[len(counts) // 2],
                            "most correct": counts[-1],
                            "the set used here": accuracy(set(HELD_OUT), mode)[0]})
    wins = sum(accuracy(set(d), "temporal")[0] > accuracy(set(d), "static")[0] for d in draws)

    findings = []
    for row in summary:
        other = next(r for r in summary if r["trajectories"] == row["trajectories"] and r["similarity"] != row["similarity"])
        if row["similarity"] != "temporal":
            continue
        findings.append(
            f"{row['trajectories']}: {row['correct (leave-one-out thresholds)']} of {row['incidents']} classified "
            f"correctly with the order-aware score (majority-class baseline {row['majority-class baseline']}; "
            f"{row['correct with in-sample thresholds']} with thresholds fitted on all incidents); "
            f"{other['correct (leave-one-out thresholds)']} with the order-free score. "
            f"{row['novel called known or variant']} of {row['novel incidents']} novel incidents were taken for a "
            f"known or variant attack; near-novel recognised as novel {row['near-novel called novel']}, far-novel "
            f"{row['far-novel called novel']}. AUC known vs variant {row['AUC known vs variant']:.3f}; "
            f"AUC (known + variant) vs novel {row['AUC (known + variant) vs novel']:.3f}."
            + (" THIS IS BELOW THE MAJORITY-CLASS BASELINE."
               if row["correct (leave-one-out thresholds)"] < row["majority-class baseline"] else "")
            + ("" if row["attack-free incidents called known or variant"] == "n/a" else
               f" Of the pipeline's incidents with no attack in them, "
               f"{row['attack-free incidents called known or variant']} would be called a known or variant attack."))
    t_sens, s_sens = sensitivity
    findings.append(
        f"Sensitivity to which six templates are held out (ground truth, {t_sens['held-out sets tried']} random "
        f"sets): order-aware {t_sens['fewest correct']} to {t_sens['most correct']} of 78 correct (median "
        f"{t_sens['median correct']}); order-free {s_sens['fewest correct']} to {s_sens['most correct']} (median "
        f"{s_sens['median correct']}). The order-aware score was ahead in {wins} of {len(draws)} sets. The set "
        f"used here gives {t_sens['the set used here']} and {s_sens['the set used here']}.")
    notes = [
        "What E3 supports: unrelated attacks are recognised as novel; the order-aware score is better than the "
        "order-free one across held-out choices. What it does not support: telling a near relative of a known "
        "attack from a variant of it, or anything on the label-free pipeline.",
        "Known versus variant is close to arithmetic. One edit to a 5-, 6- or 7-step template gives a similarity "
        "of 0.800 to 0.875 to its own reference by the definition of the score; two edits give less. The "
        "classifier is largely recovering the number of edits. Only the novel boundary is informative.",
        "Classes: known = an instance with ONE edit of a template that is in the history; variant = TWO edits; "
        "novel = any instance of the six templates left out of the history. The 12 exact (verbatim) instances of "
        "in-history templates are not classified; their scores are listed separately. This removes the "
        "tautology of the first E3, where 'known' meant a verbatim copy.",
        "Three of the six novel templates were chosen to be near relatives of in-history ones (G02 extends G01, "
        "G08 shares the phishing entry of G05 and the ending of G01, G13 reorders G04) and three to be unrelated. A system that calls a near "
        "relative 'variant' is arguably right; the near/far split shows where the novel errors are.",
        "The known / variant boundary is one edit vs two on sequences of 5 to 7 steps, a narrow margin by design.",
        "Thresholds are chosen by leave-one-out; the in-sample count shows how much they move.",
        "Which six templates are held out was fixed before any result was computed and not varied.",
    ]
    return ("e3", "E3 (redesigned) - Similarity discrimination",
            "Can the system tell a known attack, a modified variant and a previously unseen attack apart?",
            [("summary", "Three-way classification from best similarity to the 12 in-history templates",
              ["trajectories", "similarity", "correct (leave-one-out thresholds)", "incidents", "accuracy",
               "majority-class baseline", "correct with in-sample thresholds", "novel called known or variant",
               "novel incidents", "near-novel called novel", "far-novel called novel", "AUC known vs variant",
               "AUC (known + variant) vs novel", "attack-free incidents called known or variant"], summary),
             ("confusion", "Confusion matrices (leave-one-out thresholds)",
              ["trajectories", "similarity", "true class", "predicted known", "predicted variant",
               "predicted novel", "incidents"], confusion),
             ("scores", "Best similarity per class",
              ["trajectories", "similarity", "class", "min", "mean", "max", "incidents"], scores),
             ("sensitivity", "How the ground-truth result moves with the choice of held-out templates",
              ["similarity", "held-out sets tried", "incidents", "fewest correct", "median correct",
               "most correct", "the set used here"], sensitivity)],
            findings, notes)


def main():
    if config.DATASET != "graded":
        raise SystemExit("run with VIRUX_DATASET=graded (and build the graph with it first)")
    truth = ground_truth_trajectories()
    pipeline = pipeline_trajectories()
    n_instances = sum(len(instances(e["techniques"])) for e in truth)
    common.RESULTS = ROOT / "experiments" / "results_graded"
    common.SAMPLE_NOTE = (
        f"Sample: {len(truth)} synthetic incidents from {len(TEMPLATES)} templates (5 each: 1 exact, 2 with one "
        f"edit, 2 with two edits), one dataset, one seed; {n_instances} next-step instances on ground-truth "
        "trajectories. Incidents of one template are not independent, so no confidence intervals are given; "
        "counts are shown instead. The first, 24-incident experiments are kept in experiments/results/.")
    missing = sum(1 for e in pipeline if not e["techniques"])
    print(f"{len(truth)} incidents, {n_instances} instances; pipeline produced no trajectory for {missing}\n")
    for experiment, title, question, tables, findings, notes in (e1(truth, pipeline), e2(truth, pipeline),
                                                                  e3(truth, pipeline)):
        print(common.write(experiment, title, question, tables, findings, notes, metrics=common.PREDICTION_METRICS))
        print("\n" + "=" * 100 + "\n")


if __name__ == "__main__":
    main()
