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
from knowledge_graph.connection import NotFound, run


def candidate_ids(method, runner=None):
    runner = runner or run
    if method == config.METHOD_HEURISTIC:
        rows = runner("candidates_heuristic", routine_processes=config.ROUTINE_PROCESSES)
    elif method == config.METHOD_LABELS:
        rows = runner("candidates_mapped", source=config.SOURCE_GROUND_TRUTH)
    elif method == config.METHOD_MAPPER:
        rows = runner("candidates_mapped", source=config.SOURCE_MAPPER)
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
    INC-00138 (any other event id is used whole: abc -> INC-abc). It does not
    change when other incidents appear or disappear."""
    if first_event_id.startswith("evt-") and len(first_event_id) > 4:
        return "INC-" + first_event_id[4:]
    return "INC-" + first_event_id


def infer_incidents(method=None, window_minutes=None, min_events=None, runner=None):
    """Read-only. Returns incidents ordered by start time:
    [{incident_id, event_ids, start, end}] with start/end in epoch seconds."""
    method = method or config.DEFAULT_METHOD
    window_minutes = config.WINDOW_MINUTES if window_minutes is None else window_minutes
    min_events = config.MIN_INCIDENT_EVENTS if min_events is None else min_events

    runner = runner or run
    ids = candidate_ids(method, runner)
    links = runner("candidate_links", event_ids=ids, window_seconds=window_minutes * 60)
    ts = {r["event_id"]: r["ts"] for r in runner("event_times", event_ids=ids)}

    groups = connected_components(ids, [(r["a"], r["b"]) for r in links])
    groups = [sorted(g, key=lambda e: (ts[e], e)) for g in groups if len(g) >= min_events]
    groups.sort(key=lambda g: (ts[g[0]], g[0]))
    names = [incident_id_for(g[0]) for g in groups]
    if len(set(names)) != len(names):   # e.g. events "evt-7" and "7" both starting an incident
        clash = sorted({n for n in names if names.count(n) > 1})
        raise ValueError(f"two incidents would get the same id: {clash[:3]}")

    return [
        {
            "incident_id": incident_id_for(g[0]),
            "event_ids": g,
            "start": ts[g[0]],
            "end": ts[g[-1]],
        }
        for g in groups
    ]


def materialize(method=None, window_minutes=None, runner=None):
    """Infer incidents and store them: Incident nodes, PART_OF and NEXT edges.
    Replaces whatever this method stored before, so it is safe to re-run. Pass
    a transaction's runner to make the replacement atomic."""
    method = method or config.DEFAULT_METHOD
    window_minutes = config.WINDOW_MINUTES if window_minutes is None else window_minutes
    run = runner or globals()["run"]
    incidents = infer_incidents(method, window_minutes, runner=run)

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
        raise NotFound(f"no incident {incident_id!r}")
    return [
        {
            "event_id": r["event_id"], "timestamp": iso(r["ts"]), "source": r["source"],
            "user": r["user"], "source_ip": r["source_ip"],
            "destination_ip": r["destination_ip"], "device": r["device"],
            "action": r["action"], "process": r["process"],
            "destination_port": r["destination_port"], "byte_count": r["byte_count"],
        }
        for r in run("incident_events", incident_id=incident_id, method=method)
    ]


def get_all_events(runner=None):
    """Every Normalized Event (contract 1) in the graph, in time order."""
    from .trajectory import iso
    run = runner or globals()["run"]
    return [
        {"event_id": r["event_id"], "timestamp": iso(r["ts"]), "source": r["source"], "user": r["user"],
         "source_ip": r["source_ip"], "destination_ip": r["destination_ip"], "device": r["device"],
         "action": r["action"], "process": r["process"],
         "destination_port": r["destination_port"], "byte_count": r["byte_count"]}
        for r in run("all_events")
    ]


def get_incident_graph(incident_id, method=None, technique_source=None):
    """Nodes and edges of one incident for a graph view:
    {"incident_id", "nodes": [{id, type, label, ...}], "edges": [{source, target, type, ...}]}.
    Node ids are prefixed by type (event:, user:, device:, ip:, process:, technique:, tactic:)."""
    from .trajectory import iso
    method = method or config.DEFAULT_METHOD
    if not incident_exists(incident_id, method):
        raise NotFound(f"no incident {incident_id!r}")
    rows = run("incident_graph_nodes", incident_id=incident_id, method=method,
               technique_source=technique_source or config.DEFAULT_TECHNIQUE_SOURCE)
    nodes, edges, seen_edges = {}, [], set()

    def edge(source, target, kind, **properties):
        if (source, target, kind) not in seen_edges:   # an event listed twice must not repeat its edges
            seen_edges.add((source, target, kind))
            edges.append({"source": source, "target": target, "type": kind, **properties})

    def node(kind, key, **properties):
        node_id = f"{kind}:{key}"
        nodes.setdefault(node_id, {"id": node_id, "type": kind, "label": key, **properties})
        return node_id

    for r in rows:
        event = node("event", r["event_id"], timestamp=iso(r["ts"]), action=r["action"], source=r["source"])
        edge(node("user", r["user"]), event, "PERFORMED")
        edge(event, node("device", r["device"]), "OCCURRED_ON")
        for ip in sorted(r["ips"], key=lambda i: (i["role"], i["address"])):
            target = node("ip", ip["address"], internal=ip["internal"])
            if (event, target, "INVOLVES", ip["role"]) not in seen_edges:   # source and destination can be one address
                seen_edges.add((event, target, "INVOLVES", ip["role"]))
                edges.append({"source": event, "target": target, "type": "INVOLVES", "role": ip["role"]})
        if r["process"]:
            edge(event, node("process", r["process"]), "EXECUTED")
        if r["technique_id"]:
            technique = node("technique", r["technique_id"], name=r["technique_name"])
            edge(event, technique, "MAPS_TO", confidence=r["confidence"])
            for tactic in sorted(r["tactics"]):
                edge(technique, node("tactic", tactic), "BELONGS_TO")
    for r in run("incident_graph_next", incident_id=incident_id, method=method):
        edge(f"event:{r['source']}", f"event:{r['target']}", "NEXT", delta_seconds=r["delta_seconds"])
    return {"incident_id": incident_id, "nodes": list(nodes.values()), "edges": edges}
