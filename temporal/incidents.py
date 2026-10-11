"""Incident inference from graph structure.

Candidate events are linked when they share a User, or a non-hub Device or IP,
and sit next to each other on that entity's timeline within a time window. The
connected components of those links are the incidents. incidents.json is never
read here; it is evaluation ground truth only.

Three candidate filters ("methods"):
  heuristic - label-free event-type rules (the honest default)
  labels    - ground-truth labelled events (optimistic upper bound: leakage)
  mapper    - events the rule-based ATT&CK mapper assigned a technique
"""

from knowledge_graph import config
from knowledge_graph.connection import run


def candidate_ids(method):
    if method == config.METHOD_HEURISTIC:
        rows = run("candidates_heuristic", routine_processes=config.ROUTINE_PROCESSES)
    elif method == config.METHOD_LABELS:
        rows = run("candidates_mapped", source=config.SOURCE_GROUND_TRUTH)
    elif method == config.METHOD_MAPPER:
        rows = run("candidates_mapped", source=config.SOURCE_MAPPER)
    else:
        raise ValueError(f"unknown inference method: {method}")
    return [r["event_id"] for r in rows]


def connected_components(nodes, pairs):
    """Union-find. Returns a list of sorted member lists."""
    parent = {n: n for n in nodes}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in pairs:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    groups = {}
    for n in nodes:
        groups.setdefault(find(n), []).append(n)
    return [sorted(members) for members in groups.values()]


def incident_id_for(first_event_id):
    """Stable id derived from the incident's earliest event: evt-00138 ->
    INC-00138. It does not change when other incidents appear or disappear."""
    return "INC-" + first_event_id.split("-", 1)[1]


def infer_incidents(method=None, window_minutes=None, min_events=None):
    """Read-only. Returns incidents ordered by start time:
    [{incident_id, event_ids, start, end}] with start/end in epoch seconds."""
    method = method or config.DEFAULT_METHOD
    window_minutes = config.WINDOW_MINUTES if window_minutes is None else window_minutes
    min_events = config.MIN_INCIDENT_EVENTS if min_events is None else min_events

    ids = candidate_ids(method)
    links = run("candidate_links", event_ids=ids, window_seconds=window_minutes * 60)
    ts = {r["event_id"]: r["ts"] for r in run("event_times", event_ids=ids)}

    groups = connected_components(ids, [(r["a"], r["b"]) for r in links])
    groups = [sorted(g, key=lambda e: (ts[e], e)) for g in groups if len(g) >= min_events]
    groups.sort(key=lambda g: (ts[g[0]], g[0]))

    return [
        {
            "incident_id": incident_id_for(g[0]),
            "event_ids": g,
            "start": ts[g[0]],
            "end": ts[g[-1]],
        }
        for g in groups
    ]


def materialize(method=None, window_minutes=None):
    """Infer incidents and store them: Incident nodes, PART_OF and NEXT edges.
    Replaces whatever this method stored before, so it is safe to re-run."""
    method = method or config.DEFAULT_METHOD
    window_minutes = config.WINDOW_MINUTES if window_minutes is None else window_minutes
    incidents = infer_incidents(method, window_minutes)

    run("clear_next", method=method)
    run("clear_incidents", method=method)
    run("write_incidents", incidents=[
        {**inc, "uid": f"{method}:{inc['incident_id']}", "method": method,
         "window_minutes": window_minutes}
        for inc in incidents
    ])
    run("build_next", method=method)
    return incidents


def list_incidents(method=None):
    return run("list_incidents", method=method or config.DEFAULT_METHOD)


def incident_exists(incident_id, method=None):
    return run("incident_exists", incident_id=incident_id,
               method=method or config.DEFAULT_METHOD)[0]["n"] > 0


def get_incident_events(incident_id, method=None):
    """Normalized Events (contract 1) of one inferred incident, in time order."""
    from .trajectory import iso  # local import: trajectory imports nothing from here

    method = method or config.DEFAULT_METHOD
    if not incident_exists(incident_id, method):
        raise LookupError(f"no incident {incident_id!r} for method {method!r}")
    return [
        {
            "event_id": r["event_id"], "timestamp": iso(r["ts"]), "source": r["source"],
            "user": r["user"], "source_ip": r["source_ip"],
            "destination_ip": r["destination_ip"], "device": r["device"],
            "action": r["action"], "process": r["process"],
        }
        for r in run("incident_events", incident_id=incident_id, method=method)
    ]
