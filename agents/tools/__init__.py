"""The five deterministic tools Agent 2 may call (docs/agent-tools.md).

Each tool is a thin, typed wrapper over the deterministic core. Agents decide
which tool to call and explain the results; they never compute a finding.

  get_events(incident_id)        -> list[NormalizedEvent]     (contract 1)
  query_graph(incident_id)       -> AttackTrajectory          (contract 3)
  match_historical(trajectory)   -> HistoricalMatch           (contract 4)
  predict_next(trajectory)       -> Prediction                (contract 5)
  lookup_technique(technique_id) -> {id, name, tactic, description}

An unknown incident or technique raises NotFound (a LookupError).
"""

import json
from functools import lru_cache
from pathlib import Path

from knowledge_graph.connection import NotFound
from prediction import markov, similarity
from temporal import incidents
from temporal.trajectory import get_trajectory, iso

from ..contracts import (AttackTrajectory, HistoricalMatch, IncidentSummary, NormalizedEvent, Prediction,
                         TechniqueInfo)

MITRE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "mitre"


def get_events(incident_id: str) -> list[NormalizedEvent]:
    """All Normalized Events of one inferred incident, in time order."""
    return incidents.get_incident_events(incident_id)


def query_graph(incident_id: str) -> AttackTrajectory:
    """The incident's ordered ATT&CK techniques, read from the knowledge graph."""
    return get_trajectory(incident_id)


def match_historical(trajectory: AttackTrajectory) -> HistoricalMatch:
    """The most similar attacks in the historical database."""
    return similarity.match_historical(trajectory)


def predict_next(trajectory: AttackTrajectory) -> Prediction:
    """Most probable next techniques, with the counts behind them."""
    return markov.predict_next(trajectory)


@lru_cache(maxsize=1)
def _attack():
    techniques = json.loads((MITRE_DIR / "techniques.json").read_text())
    revoked = json.loads((MITRE_DIR / "revoked.json").read_text())
    return techniques, revoked


def lookup_technique(technique_id: str) -> TechniqueInfo:
    """Name, tactic(s) and description of an ATT&CK technique. A revoked id is
    resolved to the technique that replaced it. A technique with several
    tactics lists them all, comma-separated, in kill-chain order."""
    techniques, revoked = _attack()
    technique_id = str(technique_id).strip().upper()
    resolved = revoked.get(technique_id, technique_id)
    entry = techniques.get(resolved)
    if entry is None:
        raise NotFound(f"unknown ATT&CK technique {technique_id!r}")
    return {
        "id": entry["id"],
        "name": entry["name"],
        "tactic": ", ".join(entry["tactics"]),
        "description": entry["description"],
    }


def incident_exists(incident_id: str) -> bool:
    return incidents.incident_exists(incident_id)


def list_incidents() -> list[IncidentSummary]:
    """Inferred incidents of the default pipeline, oldest first."""
    return [{"incident_id": i["incident_id"], "start": iso(i["start"]), "end": iso(i["end"]),
             "event_count": i["event_count"]} for i in incidents.list_incidents()]


TOOLS = {
    "get_events": get_events,
    "query_graph": query_graph,
    "match_historical": match_historical,
    "predict_next": predict_next,
    "lookup_technique": lookup_technique,
}
