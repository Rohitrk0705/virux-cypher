"""End-to-end smoke test through the running FastAPI service, on the synthetic dataset.

  python -m evaluation.e2e_smoke        # writes evaluation/results/e2e_example.txt

  raw log lines -> POST /logs/raw (Agent 1: parse, store, map to ATT&CK, infer incidents)
  -> GET /incidents -> for two incidents: /events, /graph, /trajectory, /match, /predict,
  /investigate (Agent 2) and /explain (Agent 2 then Agent 3).

WARNING: this WIPES the Neo4j graph, fills it only through the API, and at the
end (also when it fails midway) rebuilds the graph of the DEFAULT dataset with
`python -m knowledge_graph.build --reset`, whatever the graph held before.

It proves the pieces run together; it measures nothing. Two incidents are
shown: A by a rule that uses no ground truth, B the earliest one by the same
rule that contains a true attack (so B's selection uses ground truth, and the
output says so). Ground truth is read by this script only, never by the API.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "data" / "generator"))

import raw_logs  # noqa: E402

from knowledge_graph import config, loader  # noqa: E402

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
OUT = ROOT / "evaluation" / "results" / "e2e_example.txt"

lines = []


def say(text=""):
    lines.append(text)
    print(text)


def show(title, value):
    say(f"### {title}")
    say(value if isinstance(value, str) else json.dumps(value, indent=1))
    say()


def get(client, path):
    response = client.get(path)
    response.raise_for_status()
    return response.json()


def start_server():
    env = {k: v for k, v in os.environ.items() if k not in ("AGENT_LLM", "VIRUX_DATASET", "API_TOKEN")}
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.api.main:app", "--port", str(PORT),
                               "--log-level", "warning"], cwd=ROOT, env=env)
    for _ in range(100):
        time.sleep(0.2)
        if server.poll() is not None:      # e.g. the port is taken: never test somebody else's server
            raise RuntimeError(f"the API process exited (is port {PORT} in use?)")
        try:
            if httpx.get(f"{BASE}/health", timeout=2).status_code == 200:
                return server
        except httpx.HTTPError:
            pass
    server.terminate()
    raise RuntimeError("the API did not start")


def parents(ids):
    out = []
    for technique in ids:
        parent = technique.split(".")[0]
        if not out or out[-1] != parent:
            out.append(parent)
    return out


def walk(client, label, example, raw_of, truth, members, status):
    """Every endpoint for one incident, then what the ground truth says about it."""
    say("=" * 100)
    say(f"EXAMPLE {label}: {example}   [ground truth, shown in {label}9: {status}]")
    say("=" * 100)
    incident_events = get(client, f"/events/{example}")
    say(f"### {label}1. GET /events/{example}")
    say(f"{len(incident_events)} events. Each as the raw line that was ingested, then as stored:")
    for event in incident_events:
        say(f"  raw:    {raw_of[event['event_id']]}")
        say(f"  stored: {json.dumps(event)}")
    say()
    graph = get(client, f"/graph/{example}")
    kinds = {}
    for node in graph["nodes"]:
        kinds[node["type"]] = kinds.get(node["type"], 0) + 1
    say(f"### {label}2. Graph. GET /graph/{example}")
    say(f"{len(graph['nodes'])} nodes ({', '.join(f'{v} {k}' for k, v in sorted(kinds.items()))}), "
        f"{len(graph['edges'])} edges")
    say("Events mapped to a technique (MAPS_TO edges):")
    for edge in graph["edges"]:
        if edge["type"] == "MAPS_TO":
            say(f"  {edge['source']} -> {edge['target']} (confidence {edge['confidence']})")
    say()
    trajectory = get(client, f"/trajectory/{example}")
    show(f"{label}3. Trajectory. GET /trajectory/{example}", json.dumps(trajectory))
    show(f"{label}4. Match. GET /match/{example}",
         "\n".join(json.dumps(m) for m in get(client, f"/match/{example}")["matches"]))
    prediction = get(client, f"/predict/{example}")
    show(f"{label}5. Predict. GET /predict/{example}", prediction)
    bundle = get(client, f"/investigate/{example}")
    show(f"{label}6. Agent 2 investigation. GET /investigate/{example} (trajectory, matches and prediction are "
         "the same objects as above and are left out here; technique descriptions shortened)",
         {"incident_id": bundle["incident_id"], "event_summary": bundle["event_summary"],
          "techniques": [{**t, "description": t["description"][:120] + "..."} for t in bundle["techniques"]],
          "steps": bundle["steps"], "agent": bundle["agent"], "agent_notes": bundle["agent_notes"]})
    same = (bundle["trajectory"] == trajectory and bundle["prediction"] == prediction
            and bundle["historical_matches"] == get(client, f"/match/{example}"))
    say(f"Bundle's trajectory, matches and prediction equal to the three endpoints above: {same}")
    say()
    explained = get(client, f"/explain/{example}")
    show(f"{label}7. Agent 3 explanation. GET /explain/{example} (everything except the report text)",
         json.dumps({k: v for k, v in explained.items() if k != "report"}))
    say(f"### {label}8. The report text returned by /explain (its matches table shows the top three of the "
        f"five matches in {label}4)")
    say(explained["report"])
    say(f"### {label}9. Ground truth for {example} (read by this script only; the pipeline never sees it)")
    for line in judge(example, members, trajectory, prediction, truth)[1]:
        say(line)
    say()
    return explained["agent"]["llm"]


def judge(example, members, trajectory, prediction, truth):
    """(category, lines): what the ground truth says about one inferred incident
    and its top prediction. No verdict of 'correct' is given: see the lines."""
    ids = members[example]
    overlapping = [t for t in truth if ids & set(t["event_ids"])]
    if not overlapping:
        return "false alarm", [
            "This incident overlaps NO true attack. It is a false alarm: benign events that the rule-based mapper "
            "mapped to techniques. Its trajectory, matches and prediction describe an attack that did not happen."]
    t = max(overlapping, key=lambda t: len(ids & set(t["event_ids"])))
    shared = len(ids & set(t["event_ids"]))
    observed = [s["id"] for s in trajectory["techniques"]]
    top = prediction["predictions"][0]["technique_id"]
    tied = [p["technique_id"] for p in prediction["predictions"]
            if p["probability"] == prediction["predictions"][0]["probability"]]
    others = sorted(i for i, m in members.items() if i != example and m & set(t["event_ids"]))
    covered = set().union(*(members[i] for i in others + [example])) & set(t["event_ids"])
    lines = [
        f"Overlaps true incident {t['incident_id']} (pattern {t['pattern']}, variant {t['variant']}, pace "
        f"{t['pace']}): {shared} of its {len(t['event_ids'])} events are in this incident; "
        f"{len(ids) - shared} of this incident's {len(ids)} events are not part of it.",
        (f"The pipeline split that true incident: its other events are in {', '.join(others)}"
         if others else "No other inferred incident contains events of that true incident")
        + f"; {len(t['event_ids']) - len(covered)} of its events are in no inferred incident.",
        f"True technique sequence:     {' > '.join(t['techniques'])}",
        f"Pipeline trajectory:         {' > '.join(observed)}"]
    true_parents, seen_parents = parents(t["techniques"]), parents(observed)
    starts = [i for i in range(len(true_parents)) if true_parents[i:i + len(seen_parents)] == seen_parents]
    if seen_parents == true_parents:
        category = "complete sequence, no true next step"
        lines.append("The pipeline trajectory is the complete true sequence, so there is no true next step; the "
                     f"prediction ({top}) is about a step that did not happen.")
    elif not starts:
        category = "not a contiguous part of the true sequence"
        lines.append(f"The pipeline trajectory is NOT a contiguous part of the true sequence (parent level: "
                     f"{' > '.join(seen_parents)} against {' > '.join(true_parents)}), so the prediction ({top}) "
                     "cannot be compared with a true next step.")
    else:
        after = true_parents[starts[0] + len(seen_parents):starts[0] + len(seen_parents) + 1]
        where = "a true prefix" if starts[0] == 0 else (
            f"a FRAGMENT of the true sequence, starting at true step {starts[0] + 1} of {len(true_parents)}")
        if not after:
            category = "fragment with nothing after it"
            lines.append(f"The pipeline trajectory is {where}. Nothing follows it in the true sequence; the "
                         f"prediction ({top}) is about a step that did not happen.")
        else:
            agrees = after[0] == top
            category = ("prefix" if starts[0] == 0 else "fragment") + (
                ", top prediction equals the true next step" if agrees else ", top prediction differs")
            lines.append(f"The pipeline trajectory is {where}. True next step: {after[0]}. Top prediction: {top}"
                         + (f" (tied at the same probability with {', '.join(x for x in tied if x != top)}; "
                            "listed first by technique id)" if len(tied) > 1 else "") + ".")
            if agrees:
                from prediction.historical import historical
                same = [r["attack_id"] for r in historical() if r["sequence"] == true_parents]
                lines.append(
                    (f"This agreement is NOT evidence of predictive skill: the true sequence is identical to "
                     f"historical record {', '.join(same)}, which the predictor was built from, so the model is "
                     "replaying a sequence it holds. " if same else
                     "One agreeing example is not evidence of predictive skill. ")
                    + "The probability and the counts behind it are in the prediction's evidence lines above. "
                      "Measured accuracy is in docs/PROGRESS.md.")
    return category, lines


def main():
    if config.DATASET:
        raise SystemExit("run without VIRUX_DATASET: the smoke test uses the default dataset")
    events = json.loads(config.EVENTS_FILE.read_text())
    raw = [raw_logs.render(event) for event in events]
    raw_of = {event["event_id"]: line for event, line in zip(events, raw)}

    say("End-to-end smoke test: synthetic dataset, raw log lines in, analyst report out, all through the API.")
    say("Produced by `python -m evaluation.e2e_smoke`. Dataset: data/processed/events.json (generator profile "
        "noisy, seed 42).")
    policy_line = len(lines)
    say("<filled in after the run from the agents' own status fields>")
    say("This shows that the pipeline runs. Two examples measure nothing; accuracy is in docs/PROGRESS.md.")
    say("The raw lines were rendered from the synthetic events by data/generator/raw_logs.py, written by the "
        "author of the parsers, so parsing them back is a software check, not parsing accuracy.")
    say()

    server, ok = None, False
    try:
        loader.reset()
        server = start_server()
        with httpx.Client(base_url=BASE, timeout=600) as client:
            show("1. GET /health (graph wiped before the run)", get(client, "/health"))

            say("### 2. Ingest. POST /logs/raw (Agent 1, Log Intelligence)")
            say(f"{len(raw)} raw log lines in one request. One line of each format, as sent:")
            seen = set()
            for event, line in zip(events, raw):
                if event["source"] not in seen:
                    seen.add(event["source"])
                    say(f"  {line}")
            response = client.post("/logs/raw", json=raw)
            response.raise_for_status()
            report = response.json()
            say()
            say("Ingest Report (events and techniques lists summarised):")
            say(json.dumps({**report, "events": f"<{len(report['events'])} Normalized Events>",
                            "techniques": f"<{len(report['techniques'])} Attack Technique rows>"}, indent=1))
            by_id = lambda rows: sorted(rows, key=lambda e: e["event_id"])
            same = by_id(report["events"]) == by_id([{"destination_port": None, "byte_count": None, **e} for e in events])
            say(f"Stored events equal to data/processed/events.json, field for field (the report lists them "
                f"grouped by format): {same}")
            say()

            show("3. Graph. GET /health after the ingest", get(client, "/health"))
            incidents = get(client, "/incidents")
            bundles = {i["incident_id"]: get(client, f"/investigate/{i['incident_id']}") for i in incidents}
            mapped = [b for b in bundles.values() if b["trajectory"] and b["trajectory"]["techniques"]]
            strong = [b for b in mapped if b["prediction"] is not None]
            predicted = [b for b in strong if b["prediction"]["predictions"]]
            say("### 4. GET /incidents, then GET /investigate/{id} for every incident")
            say(f"{len(incidents)} incidents inferred. Agent 2 completed {sum(b['agent']['complete'] for b in bundles.values())} "
                f"investigations; {len(mapped)} have at least one technique step; {len(strong)} had a top historical "
                f"similarity of 0.5 or more, so a prediction was requested; {len(predicted)} of those got a "
                "non-empty prediction.")
            say("Two examples follow. A is chosen by a rule that uses no ground truth: the earliest incident whose "
                "investigation ends with a non-empty prediction. B is chosen WITH ground truth, so that the file "
                "also holds a real attack: the earliest such incident that contains at least one true attack "
                "event (a weak criterion: it can be a fragment). Neither is typical; the breakdown of all such "
                "incidents is printed after the examples.")
            say()
            api_incidents = [i["incident_id"] for i in incidents]
            members = {i: {e["event_id"] for e in get(client, f"/events/{i}")} for i in api_incidents}
            truth = json.loads(config.INCIDENTS_FILE.read_text())      # used from here on, for B and for scoring
            attack_events = {e for t in truth for e in t["event_ids"]}
            first = predicted[0]["incident_id"]
            real = next((b["incident_id"] for b in predicted if members[b["incident_id"]] & attack_events), None)
            verdicts = {b["incident_id"]: judge(b["incident_id"], members, b["trajectory"], b["prediction"], truth)[0]
                        for b in predicted}
            policies = {report["agent"]["llm"]} | {b["agent"]["llm"] for b in bundles.values()}
            for label, example in (("A", first), ("B", real)):
                if example is None:
                    say("EXAMPLE B: no incident with a non-empty prediction contains a true attack event.")
                elif label == "B" and example == first:
                    say("EXAMPLE B is the same incident as example A.")
                else:
                    policies.add(walk(client, label, example, raw_of, truth, members, verdicts[example].upper()))
            with_attack = sum(1 for ids in members.values() if ids & attack_events)
            say("### 13. All inferred incidents against the ground truth (so that the examples are not read as typical)")
            say(f"Of the {len(members)} inferred incidents, {with_attack} contain at least one true attack event and "
                f"{len(members) - with_attack} contain none (there are {len(truth)} true incidents). 'Contains at "
                "least one' is a weak criterion: an incident can hold a small part of the attack, as example B does (B9).")
            say(f"The {len(predicted)} incidents with a non-empty prediction, by what the ground truth says:")
            for category in sorted(set(verdicts.values())):
                which = [i for i, c in verdicts.items() if c == category]
                say(f"  {len(which):2d}  {category}: {', '.join(which)}")
            say("Only the 'prefix' and 'fragment' rows with a true next step can be compared with a prediction at "
                "all, and base-variant attacks are copies of sequences the predictor holds. This is a count of "
                "cases, not an accuracy figure.")
            say()
            if policies != {"scripted-policy"}:
                raise RuntimeError(f"expected only the offline policy, got {sorted(policies)}")
            lines[policy_line] = (
                "All three agents ran with their offline scripted policy and no language model was called: every "
                "agent status in the responses (1 ingest, 51 investigations, 2 explanations) names "
                "`scripted-policy`.".replace("51", str(len(bundles))))
            ok = True
    finally:
        if server is not None:
            server.terminate()
            server.wait()
        rebuilt = subprocess.run([sys.executable, "-m", "knowledge_graph.build", "--reset"], cwd=ROOT,
                                 stdout=subprocess.DEVNULL).returncode == 0
        if not ok:
            print("\nSMOKE TEST FAILED. The default graph was " + ("rebuilt." if rebuilt else
                  "NOT rebuilt: the graph is wiped or holds API-ingested data only. Run "
                  "`python -m knowledge_graph.build --reset`."), file=sys.stderr)
    if not rebuilt:
        raise SystemExit("the offline rebuild failed; run `python -m knowledge_graph.build --reset`")

    say("### 14. After the run")
    from agents import tools
    offline = [i["incident_id"] for i in tools.list_incidents()]
    say("The graph was rebuilt offline with `python -m knowledge_graph.build --reset` (default dataset; this also "
        "loads the ground-truth labels used by the evaluation scripts, which were absent during the API run).")
    say(f"Incidents inferred through the API: {len(api_incidents)}; by the offline build: {len(offline)}; "
        f"same incident ids: {api_incidents == offline}")
    OUT.write_text("\n".join(lines) + "\n")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
