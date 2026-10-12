"""Attack Trajectory extraction (contract 3)."""

from datetime import datetime, timezone

from knowledge_graph import config
from knowledge_graph.connection import NotFound, run


def iso(epoch_seconds):
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collapse(rows):
    """Merge consecutive events of the same technique into one entry, keeping
    the first timestamp. rows: [(technique_id, epoch_seconds)] in time order."""
    techniques = []
    for technique_id, ts in rows:
        if not techniques or techniques[-1]["id"] != technique_id:
            techniques.append({"id": technique_id, "timestamp": iso(ts)})
    return techniques


def get_trajectory(incident_id, method=None, technique_source=None, via_next=False):
    """Return the Attack Trajectory of one inferred incident:

        {"incident_id": "INC-001",
         "techniques": [{"id": "T1078", "timestamp": "2026-10-12T10:01:00Z"}, ...]}

    Raw events stay in the graph, so counts and durations per technique remain
    available to evidence queries. via_next=True orders by walking NEXT edges
    instead of sorting on the timestamp; both give the same result.
    Raises NotFound (a LookupError) for an unknown incident; an incident with no mapped
    technique returns an empty techniques list.
    """
    method = method or config.DEFAULT_METHOD
    if not run("incident_exists", incident_id=incident_id, method=method)[0]["n"]:
        raise NotFound(f"no incident {incident_id!r}")
    rows = run(
        "trajectory_via_next" if via_next else "trajectory",
        incident_id=incident_id,
        method=method,
        technique_source=technique_source or config.DEFAULT_TECHNIQUE_SOURCE,
    )
    return {
        "incident_id": incident_id,
        "techniques": collapse([(r["technique_id"], r["ts"]) for r in rows]),
    }
