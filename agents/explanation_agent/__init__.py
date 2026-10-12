"""Agent 3 - Explanation (deterministic template).

Turns a Structured Evidence Bundle into an analyst report in Markdown. Every
statement is filled in from the bundle or from a deterministic lookup
(technique names, historical record names). Nothing is inferred, and the
language model's notes are quoted as notes, never as findings.

A language-model version of this agent is not built; a template cannot
misstate the evidence, which matters more here than fluent prose.
"""

import re

from agents import tools
from prediction.historical import historical

CAVEATS = [
    "Techniques are assigned by a rule-based mapper, which produces false positives and misses "
    "(see docs/PROGRESS.md for measured accuracy).",
    "Similarity compares complete technique sequences; an attack still in progress scores low against "
    "its own reference.",
    "Probabilities are ratios of counts over a small set of hand-written historical sequences. "
    "They are not calibrated likelihoods.",
]


def md(value):
    """Make a value from the logs safe to place in Markdown: control characters
    and line breaks become spaces, and characters that start Markdown or HTML
    constructs are escaped. Applied to everything that originates in log
    data or in the language model. Text produced by the deterministic core
    (evidence lines, step summaries, ATT&CK and historical names and ids) is
    trusted and left as it is."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value))
    return re.sub(r"([\\`*_\[\]<>#|])", r"\\\1", text)


def _failed(bundle, tool):
    return any(step["tool"] == tool and not step["ok"] for step in bundle["steps"])


def _ran(bundle, tool):
    return any(step["tool"] == tool and step["ok"] for step in bundle["steps"])


def _origin(record):
    if record is None:
        return "record not in the historical database"
    if record["source"] != "curated":
        return "MITRE ATT&CK group, order inferred"
    return "hand-written reference sequence" if record["reference"].startswith("known pattern") \
        else "hand-written sequence"


def _name(technique_id):
    try:
        return tools.lookup_technique(technique_id)["name"]
    except LookupError:
        return "unknown technique"


def explain(bundle):
    """Evidence bundle -> {"incident_id", "format": "markdown", "generated_by", "report"}."""
    records = {r["attack_id"]: r for r in historical()}
    trajectory, summary = bundle["trajectory"], bundle["event_summary"]
    matches, prediction, status = bundle["historical_matches"], bundle["prediction"], bundle["agent"]
    lines = [f"# Incident {bundle['incident_id']}", ""]

    lines += ["## What was observed", ""]
    if trajectory is None:
        lines.append("Reading the incident's trajectory failed, so there is nothing to report."
                     if _failed(bundle, "query_graph") else
                     "The incident's trajectory was not requested, so there is nothing to report.")
    elif not trajectory["techniques"]:
        lines.append("No event of this incident was mapped to an ATT&CK technique.")
    else:
        lines.append(f"{len(trajectory['techniques'])} ATT&CK technique step(s), in time order:")
        lines.append("")
        lines += [f"{n}. `{step['id']}` {_name(step['id'])} - from {step['timestamp']}"
                  for n, step in enumerate(trajectory["techniques"], 1)]
        lines += ["", "Each step is a run of consecutive events with the same technique; the time is when "
                      "that run began. A technique can appear in more than one step."]
    if summary:
        people = ", ".join(f"{md(k)} ({v})" for k, v in summary["users"].items())
        hosts = ", ".join(f"{md(k)} ({v})" for k, v in summary["devices"].items())
        actions = ", ".join(f"{md(k)} ({v})" for k, v in summary["actions"].items())
        lines += ["", f"The incident groups {summary['count']} event(s) between {summary['first']} and "
                      f"{summary['last']}.", "", f"- Accounts: {people}", f"- Hosts: {hosts}",
                  f"- Event types: {actions}"]

    lines += ["", "## Similar past attacks", ""]
    if matches is None:
        lines.append("Historical matching failed." if _failed(bundle, "match_historical")
                     else "Historical matching was not run.")
    elif not matches["matches"]:
        lines.append("No historical attack shares a technique with this incident.")
    else:
        lines += ["| Historical attack | Similarity | Techniques in common |", "|---|---|---|"]
        for m in matches["matches"][:3]:
            record = records.get(m["attack_id"])
            lines.append(f"| `{m['attack_id']}` {record['name'] if record else ''} ({_origin(record)}) | "
                         f"{m['similarity']} | {', '.join(m['common_techniques'])} |")

    lines += ["", "## Likely next step", ""]
    if prediction is None:
        lines.append("The prediction tool failed, so there is no prediction."
                     if _failed(bundle, "predict_next") else
                     "No prediction was requested for this incident.")
    elif not prediction["predictions"]:
        lines.append("The historical sequences give no basis for predicting a next step.")
    else:
        lines += ["| Technique | Probability |", "|---|---|"]
        lines += [f"| `{p['technique_id']}` {_name(p['technique_id'])} | {p['probability']} |"
                  for p in prediction["predictions"]]
    if prediction is not None and prediction["evidence"]:
        lines += ["", "Basis:"] + [f"- {line}" for line in prediction["evidence"]]

    lines += ["", "## How this was produced", ""]
    lines += [f"{n}. `{step['tool']}` - {step['summary']}" for n, step in enumerate(bundle["steps"], 1)]
    if not status["complete"]:
        state = f"INCOMPLETE (stopped: {md(status['stop_reason'])})"
    elif status["failed_tool_calls"]:
        state = "finished, but with failed tool calls, so the evidence may have gaps"
    else:
        state = "complete"
    lines += ["", f"Investigation {state}; {status['tool_calls']} tool call(s), "
                  f"{status['failed_tool_calls']} failed; tool selection by `{md(status['llm'])}`."]
    if bundle["agent_notes"]:
        lines += ["", "Agent's note (commentary, not a finding):", ""]
        lines += [f"> {md(line)}" for line in str(bundle["agent_notes"]).splitlines() if line.strip()]

    lines += ["", "## Limits of this report", ""] + [f"- {c}" for c in CAVEATS]
    return {"incident_id": bundle["incident_id"], "format": "markdown", "generated_by": "template",
            "report": "\n".join(lines) + "\n"}
