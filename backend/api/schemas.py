"""Pydantic models for the API. The first five mirror docs/data-contracts.md
exactly: same field names, same order, nothing extra."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

MAX_TEXT = 256


def _real_utc_timestamp(value: str) -> str:
    """The pattern fixes the shape; this rejects impossible dates such as
    2026-02-30 and years the graph cannot store sensibly."""
    try:
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError("not a real UTC date and time") from None
    if not 1970 <= moment.year <= 2100:
        raise ValueError("year must be between 1970 and 2100")
    return value


Timestamp = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                                 examples=["2026-10-12T10:30:00Z"]),
                      AfterValidator(_real_utc_timestamp)]
# Free-text fields: 1-256 characters, no control characters, no leading or trailing space.
Text = Annotated[str, Field(min_length=1, max_length=MAX_TEXT, pattern=r"^[^\x00-\x1f\x7f\s]([^\x00-\x1f\x7f]*[^\x00-\x1f\x7f\s])?$")]
# Event ids end up in incident ids and URLs, so they are limited to URL-safe characters.
EventId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$", examples=["evt-001"])]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- contract 1 ---
class NormalizedEvent(Contract):
    event_id: EventId
    timestamp: Timestamp
    source: Text = Field(examples=["windows"])
    user: Text = Field(examples=["john"])
    source_ip: Text = Field(examples=["10.0.0.5"])
    destination_ip: Text | None = Field(examples=["10.0.0.10"])
    device: Text = Field(examples=["WS-01"])
    action: Text = Field(examples=["process_execution"])
    process: Text | None = Field(examples=["powershell.exe"])


# --- contract 2 ---
class AttackTechnique(Contract):
    event_id: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: Annotated[float, Field(ge=0, le=1)]


# --- contract 3 ---
class TrajectoryStep(Contract):
    id: str
    timestamp: Timestamp


class AttackTrajectory(Contract):
    incident_id: str
    techniques: list[TrajectoryStep]


# --- contract 4 ---
class Match(Contract):
    attack_id: str
    similarity: Annotated[float, Field(ge=0, le=1)]
    common_techniques: list[str]


class HistoricalMatch(Contract):
    incident_id: str
    matches: list[Match]


# --- contract 5 ---
class PredictedTechnique(Contract):
    technique_id: str
    probability: Annotated[float, Field(ge=0, le=1)]


class Prediction(Contract):
    incident_id: str
    predictions: list[PredictedTechnique]
    evidence: list[str]


# --- everything below is API-specific, not one of the five contracts ---
class Health(Contract):
    """status is 'degraded' (and both counts null) only when Neo4j cannot be reached."""
    status: Literal["ok", "degraded"]
    service: str
    neo4j: bool
    events: int | None
    incidents: int | None


class Error(Contract):
    detail: str


class IncidentSummary(Contract):
    incident_id: str
    start: Timestamp
    end: Timestamp
    event_count: int


class IngestResult(Contract):
    received: int
    events_in_graph: int
    mapped_events: int
    incidents: int
    incidents_touched: list[str]


class GraphNode(BaseModel):
    """id is '<type>:<key>'. Extra fields depend on the type: event has
    timestamp/action/source, ip has internal, technique has name."""
    model_config = ConfigDict(extra="allow")
    id: str
    type: Literal["event", "user", "device", "ip", "process", "technique", "tactic"]
    label: str


class GraphEdge(BaseModel):
    """INVOLVES has role, MAPS_TO has confidence, NEXT has delta_seconds."""
    model_config = ConfigDict(extra="allow")
    source: str
    target: str
    type: Literal["PERFORMED", "OCCURRED_ON", "INVOLVES", "EXECUTED", "MAPS_TO", "BELONGS_TO", "NEXT"]


class IncidentGraph(Contract):
    incident_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class TechniqueInfo(Contract):
    id: str
    name: str
    tactic: str
    description: str


class LookedUpTechnique(TechniqueInfo):
    relation: Literal["in_trajectory", "predicted", "not_in_evidence"]


class EventSummary(Contract):
    count: int
    first: Timestamp | None
    last: Timestamp | None
    users: dict[str, int]
    devices: dict[str, int]
    actions: dict[str, int]


class AgentStep(Contract):
    tool: str
    input: dict[str, str]
    ok: bool
    summary: str


class AgentStatus(Contract):
    llm: str
    complete: bool
    stop_reason: str
    tool_calls: int
    failed_tool_calls: int


class EvidenceBundle(Contract):
    incident_id: str
    trajectory: AttackTrajectory | None
    event_summary: EventSummary | None
    historical_matches: HistoricalMatch | None
    prediction: Prediction | None
    techniques: list[LookedUpTechnique]
    steps: list[AgentStep]
    agent: AgentStatus
    agent_notes: str


class Report(Contract):
    incident_id: str
    format: Literal["markdown"]
    generated_by: str
    report: str
