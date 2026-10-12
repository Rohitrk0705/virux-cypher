"""The five frozen data contracts (docs/data-contracts.md) as Python types."""

from typing import TypedDict


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


class IncidentSummary(TypedDict):
    incident_id: str
    start: str
    end: str
    event_count: int
