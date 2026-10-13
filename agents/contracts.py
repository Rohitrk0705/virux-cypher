"""The five frozen data contracts (docs/data-contracts.md) as Python types."""

from typing import NotRequired, TypedDict


class NormalizedEvent(TypedDict):
    event_id: str
    timestamp: str
    source: str
    user: str
    source_ip: str
    destination_ip: str | None
    device: str
    action: str
    process: str | None
    destination_port: NotRequired[int | None]   # optional: may be absent, treat as None
    byte_count: NotRequired[int | None]         # optional: bytes sent from source to destination


class AttackTechnique(TypedDict):
    event_id: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float


class TrajectoryStep(TypedDict):
    id: str
    timestamp: str


class AttackTrajectory(TypedDict):
    incident_id: str
    techniques: list[TrajectoryStep]


class Match(TypedDict):
    attack_id: str
    similarity: float
    common_techniques: list[str]


class HistoricalMatch(TypedDict):
    incident_id: str
    matches: list[Match]


class PredictedTechnique(TypedDict):
    technique_id: str
    probability: float


class Prediction(TypedDict):
    incident_id: str
    predictions: list[PredictedTechnique]
    evidence: list[str]


class TechniqueInfo(TypedDict):
    id: str
    name: str
    tactic: str
    description: str


# --- not one of the five frozen contracts: what Agent 2 hands to Agent 3 and the API ---

class EventSummary(TypedDict):
    count: int
    first: str | None
    last: str | None
    users: dict[str, int]
    devices: dict[str, int]
    actions: dict[str, int]


class LookedUpTechnique(TechniqueInfo):
    relation: str            # in_trajectory | predicted | not_in_evidence


class AgentStep(TypedDict):
    tool: str                # one of the five tool names, or "<unknown>"
    input: dict[str, str]    # the validated argument, or {} for a rejected call
    ok: bool
    summary: str


class AgentStatus(TypedDict):
    llm: str
    complete: bool           # the model stopped normally AND a trajectory was fetched
    stop_reason: str
    tool_calls: int
    failed_tool_calls: int


class EvidenceBundle(TypedDict):
    incident_id: str
    trajectory: AttackTrajectory | None
    event_summary: EventSummary | None
    historical_matches: HistoricalMatch | None
    prediction: Prediction | None
    techniques: list[LookedUpTechnique]
    steps: list[AgentStep]
    agent: AgentStatus
    agent_notes: str         # the model's own words; commentary, never a finding


class IngestResult(TypedDict):
    received: int
    events_in_graph: int
    mapped_events: int
    incidents: int
    incidents_touched: list[str]


class RecordGroup(TypedDict):
    group_id: str
    detected_format: str     # a parser name, or "unknown"
    count: int
    parser: str | None       # the parser the agent ran on it
    parsed: int
    rejected: dict[str, int]  # fixed reason code -> records
    status: str              # parsed | nothing parsed | quarantined | unhandled


class IngestReport(TypedDict):
    """What Agent 1 returns for one batch of raw log records."""
    received: int
    parsed: int
    rejected: int
    quarantined: int
    unhandled: int
    groups: list[RecordGroup]
    stored: bool
    events: list[NormalizedEvent]      # the events that were stored (empty if nothing was)
    techniques: list[AttackTechnique]  # their ATT&CK mappings (contract 2)
    ingest: IngestResult | None
    steps: list[AgentStep]
    agent: AgentStatus
    agent_notes: str


class Report(TypedDict):
    """What Agent 3 returns for one evidence bundle."""
    incident_id: str
    format: str              # "markdown"
    generated_by: str        # "template", or "template sections, summary by <model>"
    report: str
    sections: list[str]      # the order the sections were placed in
    summary: str             # none | accepted | discarded: <reason code>
    steps: list[AgentStep]
    agent: AgentStatus


class IncidentSummary(TypedDict):
    incident_id: str
    start: str
    end: str
    event_count: int
