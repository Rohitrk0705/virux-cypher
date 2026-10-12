"""Shared helpers for the three locked experiments."""

import csv
from pathlib import Path

from evaluation.trajectories import ground_truth_trajectories, pipeline_trajectories

RESULTS = Path(__file__).resolve().parent / "results"

SAMPLE_NOTE = (
    "Sample: 24 synthetic incidents from 4 attack templates (6 each), one dataset, one seed. "
    "No confidence intervals are given because the incidents are not independent draws; "
    "treat differences of a few points as noise."
)


def trajectory_sets():
    """(label, entries) for the two inputs every experiment is run on."""
    return [
        ("ground-truth trajectories", ground_truth_trajectories()),
        ("pipeline trajectories", pipeline_trajectories()),
    ]


def fmt(value):
    if isinstance(value, float):
        return f"{value:.3f}"
    return "" if value is None else str(value)


def markdown_table(columns, rows):
    lines = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    lines += ["| " + " | ".join(fmt(r.get(c)) for c in columns) + " |" for r in rows]
    return "\n".join(lines)


PREDICTION_METRICS = (
    "top1: the true next technique is the first prediction (ties broken by technique id). "
    "top1_tie: the same, but a target tied for first with m - 1 others counts 1/m, which removes "
    "alphabetical luck. top3: the target is among the first three. mrr: mean of 1/rank over the model's "
    "full ranking, 0 if the target is not ranked (the API exposes only the top 5). precision / recall / f1: "
    "macro-averaged over the techniques that occur as targets, using the top prediction only. "
    "An instance is one prefix of one incident's trajectory; an incident with L steps gives L - 1 instances."
)


def write(experiment, title, question, tables, findings, notes, metrics=None):
    """tables: [(slug, caption, columns, rows)]. Writes one CSV per table and
    one markdown report; returns the markdown text."""
    RESULTS.mkdir(exist_ok=True)
    parts = [f"# {title}", "", f"**Question:** {question}", "", SAMPLE_NOTE, ""]
    if metrics:
        parts += ["**Metrics:** " + metrics, ""]
    for slug, caption, columns, rows in tables:
        with open(RESULTS / f"{experiment}_{slug}.csv", "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows({c: fmt(r.get(c)) for c in columns} for r in rows)
        parts += [f"## {caption}", "", markdown_table(columns, rows), ""]
    parts += ["## What the numbers show", ""] + [f"- {f}" for f in findings] + [""]
    parts += ["## Caveats", ""] + [f"- {n}" for n in notes] + [""]
    text = "\n".join(parts)
    (RESULTS / f"{experiment}.md").write_text(text)
    return text
