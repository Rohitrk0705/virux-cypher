"""Score the rule-based ATT&CK mapper against ground-truth labels.

  python -m evaluation.mapper_eval

An event counts as correct only if the mapper assigned exactly the labelled
technique. labels.json covers attack events only, so any benign event the
mapper tags is a false positive here.

The dataset on disk (noisy profile, seed 42) is one draw. To show how much the
score depends on that draw, the generator is also run in memory for a fixed
list of other seeds, in both profiles, and the same mapper is scored on each.
"""

import importlib.util
import json
from collections import Counter
from statistics import mean, pstdev

from core.attack_mapper import AttackMapper
from knowledge_graph import config

GENERATOR = config.ROOT / "data" / "generator" / "generate.py"
DATASET_SEED = 42
OTHER_SEEDS = list(range(1, 13))

LIMITATIONS = """LIMITATIONS - read before quoting any number above:
1. Same author. The mapper rules, the data generator and the noise added to it
   were all written by the same author. No ground-truth file is read by the
   mapper, but this is still a test against the author's own idea of benign and
   malicious activity, NOT a measure of detection accuracy on real logs.
2. The noisy profile is the headline. The clean profile is the first version
   of the dataset, where staff never did anything attack-like; it is shown
   only to make the size of that effect visible.
3. Exfiltration (T1041) now uses byte_count and destination_port, which were
   added to contract 1 for this purpose. The generator's attack transfers are
   mostly 30 MB to 2 GB and its benign web traffic mostly under 3 MB, with 3%
   benign uploads of 20 to 300 MB; that separation was chosen by the same
   author who wrote the 20 MB threshold. Small, quiet exfiltration (one in ten
   attack transfers here) is missed by design.
4. Two rules look forward in time (failure bursts; an Office launch is mapped
   only once a script host follows), so the mapper is batch-only.
5. The administrator at their own desk is allow-listed. An attack that starts
   there (a phishing document opened by the administrator) is not mapped.
6. Business hours treat log timestamps as local time.
7. Rule confidences are fixed hand-assigned values, not calibrated."""


PREVIOUS = """PREVIOUS FIGURES, kept for the record (do not quote as results):
  first mapper version, clean profile, seed 42 only:  micro P 0.947  R 0.964  F1 0.955
  (evaluation/results/m3_mapper_v1_clean.txt). Its exfiltration rule matched
  addresses that had logged in earlier, which only worked because the clean
  generator reused eight attacker addresses, and its benign data contained no
  attack-like staff activity. The reviewer measured micro F1 0.913 (range
  0.886-0.948) for that version over 12 other seeds (docs/REVIEWS.md, M3).
  second mapper version (no byte_count or port in contract 1), noisy profile, 13 seeds:
  micro P 0.564  R 0.887  F1 0.689 mean (evaluation/results/m3_mapper_v2_noisy.txt)."""


def parent(technique_id):
    return technique_id.split(".")[0]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def score(labels, mapped, n_events, normalize=lambda t: t, exclude=()):
    truth = {l["event_id"]: normalize(l["technique_id"]) for l in labels}
    pred = {m["event_id"]: normalize(m["technique_id"]) for m in mapped}

    tp, fp, fn = Counter(), Counter(), Counter()
    confusion = Counter()  # (true or 'benign', predicted or 'none')
    for event_id in truth.keys() | pred.keys():
        t, p = truth.get(event_id), pred.get(event_id)
        if t in exclude or (t is None and p in exclude):
            continue
        confusion[(t or "benign", p or "none")] += 1
        if t == p:
            tp[t] += 1
        else:
            if p:
                fp[p] += 1
            if t:
                fn[t] += 1

    per_technique = {}
    for tech in sorted(tp.keys() | fp.keys() | fn.keys()):
        p, r, f = prf(tp[tech], fp[tech], fn[tech])
        per_technique[tech] = {"tp": tp[tech], "fp": fp[tech], "fn": fn[tech],
                               "precision": p, "recall": r, "f1": f,
                               "support": tp[tech] + fn[tech]}

    def macro(rows):
        return tuple(mean(v[k] for v in rows) for k in ("precision", "recall", "f1")) if rows else (0, 0, 0)

    flagged_attack = sum(1 for e in pred if e in truth)
    return {
        "n_events": n_events, "n_labelled": len(truth), "n_mapped": len(pred),
        "micro": prf(sum(tp.values()), sum(fp.values()), sum(fn.values())),
        "macro_labelled": macro([v for v in per_technique.values() if v["support"]]),
        "macro_all": macro(list(per_technique.values())),
        "detection": prf(flagged_attack, len(pred) - flagged_attack, len(truth) - flagged_attack),
        "per_technique": per_technique, "confusion": confusion,
    }


def report(result, title):
    lines = [f"=== {title} ===",
             f"events: {result['n_events']}   labelled attack events: {result['n_labelled']}   "
             f"events the mapper mapped: {result['n_mapped']}",
             "",
             f"{'technique':<16}{'support':>8}{'tp':>6}{'fp':>6}{'fn':>6}{'prec':>8}{'recall':>8}{'f1':>8}"]
    for tech, v in result["per_technique"].items():
        lines.append(f"{tech:<16}{v['support']:>8}{v['tp']:>6}{v['fp']:>6}{v['fn']:>6}"
                     f"{v['precision']:>8.3f}{v['recall']:>8.3f}{v['f1']:>8.3f}")
    for name in ("micro", "macro_labelled", "macro_all", "detection"):
        p, r, f = result[name]
        lines.append(f"{name:<16}{'':>26}{p:>8.3f}{r:>8.3f}{f:>8.3f}")
    lines += ["",
              "micro          = over all events, exact technique",
              "macro_labelled = unweighted mean over techniques that occur in the labels",
              "                 (false positives on techniques that are never a label are not charged)",
              "macro_all      = unweighted mean over every technique labelled or predicted",
              "detection      = event flagged with any technique vs labelled as attack",
              "",
              "confusion (true -> mapped), errors only:"]
    errors = [(k, n) for k, n in result["confusion"].items() if k[0] != k[1]]
    for (t, p), n in sorted(errors, key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {t:<12}-> {p:<12}{n:>5}")
    return "\n".join(lines)


def rule_breakdown(labels, mapped, rules, technique="T1041"):
    """True and false positives of one technique, per rule that fired."""
    truth = {l["event_id"]: l["technique_id"] for l in labels}
    tally = Counter()
    for m in mapped:
        if m["technique_id"] == technique:
            tally[(rules[m["event_id"]], truth.get(m["event_id"]) == technique)] += 1
    missed = sum(1 for e, t in truth.items() if t == technique
                 and e not in {m["event_id"] for m in mapped if m["technique_id"] == technique})
    return tally, missed


def generator_module():
    spec = importlib.util.spec_from_file_location("virux_generate", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T1041_RULES = ["T1041-volume", "T1041-server", "T1041-offhours"]


def multi_seed(profile):
    """Run generator + mapper in memory for each seed; nothing is written."""
    generate, mapper = generator_module(), AttackMapper()
    rows = []
    for seed in [DATASET_SEED] + OTHER_SEEDS:
        events, labels, _ = generate.assemble(seed, profile)
        mapped, rules = mapper.map_with_rules(events)
        full = score(labels, mapped, len(events))
        without = score(labels, mapped, len(events), exclude=("T1110",))
        t1041, missed = rule_breakdown(labels, mapped, rules)
        per = full["per_technique"]
        rows.append({
            "seed": seed, "events": len(events), "labelled": len(labels),
            "micro": full["micro"], "macro_all": full["macro_all"], "detection": full["detection"],
            "micro_no_t1110": without["micro"],
            "t1005_recall": per["T1005"]["recall"] if "T1005" in per else None,
            "t1041_recall": per["T1041"]["recall"] if "T1041" in per else None,
            "t1041_tp": [t1041[(rule, True)] for rule in T1041_RULES],
            "t1041_fp": sum(t1041[(rule, False)] for rule in T1041_RULES),
            "t1041_missed": missed,
        })
        truth = {l["event_id"]: l["technique_id"] for l in labels}
        for m in mapped:
            RULE_TALLY[profile][(rules[m["event_id"]], truth.get(m["event_id"]) == m["technique_id"])] += 1
    return rows


RULE_TALLY = {"noisy": Counter(), "clean": Counter()}


def rule_table(profile):
    tally = RULE_TALLY[profile]
    lines = [f"=== per-rule true and false positives, pooled over the seeds, profile '{profile}' ===",
             f"{'rule':<26}{'tp':>7}{'fp':>7}{'precision':>11}"]
    for rule in sorted({r for r, _ in tally}):
        tp, fp = tally[(rule, True)], tally[(rule, False)]
        lines.append(f"{rule:<26}{tp:>7}{fp:>7}{tp / (tp + fp):>11.3f}")
    lines.append("A 'false positive' here is a benign event (or a differently labelled attack event) given this\n"
                 "technique. Staff running cmd.exe is, strictly, the technique T1059.003; it counts as false\n"
                 "because labels.json only labels attack events.")
    return "\n".join(lines)


def multi_seed_report(rows, profile):
    head = (f"{'seed':>5}{'events':>8}{'labelled':>9}{'microP':>8}{'microR':>8}{'microF1':>8}"
            f"{'macroF1':>8}{'detP':>7}{'detR':>7}{'F1 noT1110':>11}{'T1005 R':>9}{'T1041 R':>9}"
            f"{'T1041 tp vol/srv/off':>22}{'fp':>5}{'missed':>7}")
    lines = [f"=== mapper across {len(rows)} generator seeds, profile '{profile}' ===", head, "-" * len(head)]
    for r in rows:
        lines.append(
            f"{r['seed']:>5}{r['events']:>8}{r['labelled']:>9}{r['micro'][0]:>8.3f}{r['micro'][1]:>8.3f}"
            f"{r['micro'][2]:>8.3f}{r['macro_all'][2]:>8.3f}{r['detection'][0]:>7.3f}{r['detection'][1]:>7.3f}"
            f"{r['micro_no_t1110'][2]:>11.3f}{r['t1005_recall']:>9.3f}{r['t1041_recall']:>9.3f}"
            f"{' / '.join(str(n) for n in r['t1041_tp']):>22}{r['t1041_fp']:>5}{r['t1041_missed']:>7}")
    lines.append("-" * len(head))
    for name, fn in (("mean", mean), ("sd", pstdev), ("min", min), ("max", max)):
        lines.append(
            f"{name:>5}{'':>17}{fn([r['micro'][0] for r in rows]):>8.3f}{fn([r['micro'][1] for r in rows]):>8.3f}"
            f"{fn([r['micro'][2] for r in rows]):>8.3f}{fn([r['macro_all'][2] for r in rows]):>8.3f}"
            f"{fn([r['detection'][0] for r in rows]):>7.3f}{fn([r['detection'][1] for r in rows]):>7.3f}"
            f"{fn([r['micro_no_t1110'][2] for r in rows]):>11.3f}{fn([r['t1005_recall'] for r in rows]):>9.3f}"
            f"{fn([r['t1041_recall'] for r in rows]):>9.3f}")
    lines.append("macroF1 = macro_all; det = detection; 'F1 noT1110' = micro F1 without brute force; "
                 "sd = population standard deviation over the seeds.")
    lines.append("T1041 columns: true positives from each sub-rule (volume / server / off-hours), "
                 "false positives, missed events.")
    return "\n".join(lines)


def main():
    labels = json.loads(config.LABELS_FILE.read_text())
    mapped = json.loads(config.MAPPED_FILE.read_text())
    n_events = len(json.loads(config.EVENTS_FILE.read_text()))
    print(report(score(labels, mapped, n_events),
                 f"ATT&CK mapper vs labels.json: noisy profile, seed {DATASET_SEED} (exact technique id)"))
    print()
    p, r, f = score(labels, mapped, n_events, exclude=("T1110",))["micro"]
    print(f"excluding T1110 (brute force): micro precision {p:.3f}  recall {r:.3f}  f1 {f:.3f}")
    p, r, f = score(labels, mapped, n_events, normalize=parent)["micro"]
    print(f"sub-techniques folded into parents: micro precision {p:.3f}  recall {r:.3f}  f1 {f:.3f}"
          "  (same as exact when every confusion crosses parent techniques)")
    print()
    for profile in ("noisy", "clean"):
        print(multi_seed_report(multi_seed(profile), profile))
        print()
        print(rule_table(profile))
        print()
    print(PREVIOUS)
    print()
    print(LIMITATIONS)


if __name__ == "__main__":
    main()
