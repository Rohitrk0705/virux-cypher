"""Agent 1 - Log Intelligence (deterministic).

Takes Normalized Events (contract 1), stores them in the knowledge graph, maps
every event in the graph to ATT&CK techniques with the rule-based mapper and
re-infers incidents. There is no language model in this agent: perception here
is rules, so its output is reproducible.

An ingest is one database transaction: the new events, the refreshed technique
mappings and the refreshed incidents commit together or not at all, and readers
see the previous state until the commit.

Not built: parsing of raw, un-normalized log lines. Input must already be in
the contract-1 shape.
"""

import threading

from core.attack_mapper import AttackMapper
from knowledge_graph import config, loader
from knowledge_graph.connection import transaction
from temporal import incidents

_lock = threading.Lock()   # one ingest at a time within this process


def _refresh(runner):
    events = incidents.get_all_events(runner)
    mapped = AttackMapper().map_events(events)
    loader.load_mappings(mapped, config.SOURCE_MAPPER, runner)
    inferred = incidents.materialize(config.DEFAULT_METHOD, runner=runner)
    return {"events_in_graph": len(events), "mapped_events": len(mapped), "incidents": len(inferred)}, inferred


def refresh():
    """Re-map all events in the graph and re-infer incidents, atomically. Returns counts."""
    with _lock, transaction() as runner:
        return _refresh(runner)[0]


def ingest(events):
    """Store events (an existing event_id is replaced) and refresh mappings and
    incidents. Returns {received, events_in_graph, mapped_events, incidents,
    incidents_touched}: incidents_touched lists the incidents that now contain
    one of the submitted events. On any failure nothing is changed."""
    loader.apply_schema()
    with _lock, transaction() as runner:
        loader.load_events(events, runner)
        result, inferred = _refresh(runner)
    submitted = {e["event_id"] for e in events}
    touched = sorted(i["incident_id"] for i in inferred if submitted & set(i["event_ids"]))
    return {"received": len(events), **result, "incidents_touched": touched}
