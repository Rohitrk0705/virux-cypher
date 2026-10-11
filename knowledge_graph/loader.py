"""Idempotent loader: Normalized Events and technique mappings into Neo4j.

Nodes are written with MERGE on constrained keys and an event's entity edges
are replaced on every load, so loading the same files twice leaves the graph
unchanged and loading a changed event replaces the old version. Entity nodes
that no event refers to any more are not removed; use reset() when switching
to a different dataset.
"""

import json

from . import config
from .connection import SCHEMA_FILE, run, run_text, statements

BATCH = 1000


def apply_schema():
    for statement in statements(SCHEMA_FILE):
        run_text(statement)


def reset():
    """Delete all data (constraints and indexes are kept)."""
    while run_text("MATCH (n) WITH n LIMIT 5000 DETACH DELETE n RETURN count(*) AS deleted")[0]["deleted"]:
        pass


REQUIRED = ["event_id", "timestamp", "source", "user", "source_ip", "device", "action"]


def load_events(events):
    for e in events:
        missing = [k for k in REQUIRED if e.get(k) is None]
        if missing:
            raise ValueError(f"event {e.get('event_id')!r} is missing required field(s) {missing}")
    for i in range(0, len(events), BATCH):
        run("load_events", rows=events[i:i + BATCH])
    run("mark_entities", internal_prefix=config.INTERNAL_PREFIX, hub_users=config.HUB_USERS)


def load_mappings(mappings, source):
    """Replace all MAPS_TO edges of one source with the given contract-2 rows."""
    run("clear_mappings", source=source)
    for i in range(0, len(mappings), BATCH):
        run("load_mappings", rows=mappings[i:i + BATCH], source=source)


def load_files(events_file=None, labels_file=None, mapped_file=None):
    """Load events, ground-truth labels and (when present) mapper output.
    Returns the number of rows of each."""
    events = json.loads((events_file or config.EVENTS_FILE).read_text())
    labels = json.loads((labels_file or config.LABELS_FILE).read_text())
    mapped_file = mapped_file or config.MAPPED_FILE
    mapped = json.loads(mapped_file.read_text()) if mapped_file.exists() else []
    apply_schema()
    load_events(events)
    load_mappings(labels, config.SOURCE_GROUND_TRUTH)
    load_mappings(mapped, config.SOURCE_MAPPER)
    return len(events), len(labels), len(mapped)


def graph_stats():
    nodes = {r["label"]: r["count"] for r in run("stats_nodes")}
    rels = {r["type"]: r["count"] for r in run("stats_relationships")}
    return {"nodes": nodes, "relationships": rels}
