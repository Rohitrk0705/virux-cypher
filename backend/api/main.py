"""Virux Cypher backend - FastAPI entry point.

Run from the repository root:

    backend/.venv/bin/uvicorn backend.api.main:app --reload

or from backend/:  uvicorn api.main:app --reload

Every endpoint returns data from the knowledge graph and the deterministic
core. {id} is an inferred incident id such as INC-00017 (list them with
GET /incidents). See backend/README.md.
"""

import os
import sys
from pathlib import Path
from typing import Annotated

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:      # lets `uvicorn api.main:app` work from backend/
    sys.path.insert(0, str(ROOT))

import logging  # noqa: E402

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from neo4j.exceptions import DriverError  # noqa: E402

from agents import tools  # noqa: E402
from agents.explanation_agent import explain  # noqa: E402
from agents.investigation_agent import investigate  # noqa: E402
from agents.log_agent import ingest  # noqa: E402
from knowledge_graph import config  # noqa: E402
from knowledge_graph.connection import NotFound, run_text  # noqa: E402
from temporal.incidents import get_incident_graph  # noqa: E402

try:                                # package import from the repo root, plain import from backend/
    from . import schemas
except ImportError:                 # pragma: no cover
    from api import schemas

MAX_EVENTS_PER_REQUEST = 5000
log = logging.getLogger("virux.api")

app = FastAPI(
    title="Virux Cypher",
    version="0.1.0",
    description="Temporal cyber-threat knowledge graph: incidents, ATT&CK trajectories, historical "
                "matching, next-step prediction, investigation and explanation.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in
                   os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def shorten(text, limit=120):
    text = str(text)
    return text if len(text) <= limit else text[:limit] + "..."


@app.exception_handler(NotFound)
def not_found(request: Request, exc: NotFound):
    """Unknown incident or technique. Only NotFound maps to 404; any other
    LookupError is a bug and becomes a 500."""
    return JSONResponse(status_code=404, content={"detail": shorten(exc)})


@app.exception_handler(DriverError)
def graph_down(request: Request, exc: DriverError):
    """The Neo4j driver could not reach or keep a connection to the database."""
    return JSONResponse(status_code=503, content={"detail": "the knowledge graph (Neo4j) is not available"})


@app.exception_handler(RequestValidationError)
def invalid_request(request: Request, exc: RequestValidationError):
    """422 with `detail` always a string: the first few problems, without echoing the body."""
    problems = [f"{'.'.join(str(p) for p in e['loc'][1:]) or 'body'}: {e['msg']}" for e in exc.errors()]
    more = f" (+{len(problems) - 5} more)" if len(problems) > 5 else ""
    return JSONResponse(status_code=422, content={"detail": "; ".join(problems[:5]) + more})


@app.exception_handler(Exception)
def internal_error(request: Request, exc: Exception):
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal error"})


def require_token(x_api_token: Annotated[str | None, Header()] = None):
    """POST /logs is open unless API_TOKEN is set in the environment; then the
    request must carry the same value in the X-API-Token header."""
    expected = os.getenv("API_TOKEN")
    if expected and x_api_token != expected:
        raise HTTPException(status_code=401, detail="missing or wrong X-API-Token header")


@app.get("/health", response_model=schemas.Health)
def health():
    """Service status and the size of the loaded graph."""
    try:
        events = run_text("MATCH (e:Event) RETURN count(e) AS n")[0]["n"]
        incidents = run_text("MATCH (i:Incident {method: $method}) RETURN count(i) AS n",
                             method=config.DEFAULT_METHOD)[0]["n"]
        return {"status": "ok", "service": "virux-cypher", "neo4j": True, "events": events, "incidents": incidents}
    except DriverError:
        return {"status": "degraded", "service": "virux-cypher", "neo4j": False,
                "events": None, "incidents": None}


@app.get("/incidents", response_model=list[schemas.IncidentSummary])
def list_incidents():
    """All inferred incidents, oldest first. Use an incident_id from here as {id} elsewhere."""
    return tools.list_incidents()


@app.post("/logs", response_model=schemas.IngestResult, dependencies=[Depends(require_token)])
def post_logs(events: Annotated[list[schemas.NormalizedEvent],
                                Body(min_length=1, max_length=MAX_EVENTS_PER_REQUEST)]):
    """Ingest Normalized Events (contract 1). An existing event_id is replaced.
    All events in the graph are then re-mapped to ATT&CK and incidents are
    re-inferred, so incident ids can change after a call. The whole request is
    one transaction: on any error nothing is stored."""
    ids = [e.event_id for e in events]
    if len(set(ids)) != len(ids):
        raise HTTPException(status_code=422, detail="duplicate event_id in request")
    try:
        return ingest([e.model_dump() for e in events])
    except ValueError as exc:      # e.g. two incidents would get the same id
        raise HTTPException(status_code=422, detail=shorten(exc)) from None


@app.get("/events/{id}", response_model=list[schemas.NormalizedEvent])
def get_events(id: str):
    """The incident's Normalized Events (contract 1), in time order."""
    return tools.get_events(id)


@app.get("/graph/{id}", response_model=schemas.IncidentGraph)
def get_graph(id: str):
    """Nodes and edges of the incident for a graph view (events, users, devices,
    addresses, processes, techniques, tactics, and NEXT edges between events)."""
    return get_incident_graph(id)


@app.get("/trajectory/{id}", response_model=schemas.AttackTrajectory)
def get_trajectory(id: str):
    """The incident's Attack Trajectory (contract 3)."""
    return tools.query_graph(id)


@app.get("/match/{id}", response_model=schemas.HistoricalMatch)
def get_match(id: str):
    """Most similar historical attacks (contract 4)."""
    return tools.match_historical(tools.query_graph(id))


@app.get("/predict/{id}", response_model=schemas.Prediction)
def get_prediction(id: str):
    """Most probable next techniques with the counts behind them (contract 5).
    `predictions` is empty when the history gives no basis for a prediction."""
    return tools.predict_next(tools.query_graph(id))


@app.get("/investigate/{id}", response_model=schemas.EvidenceBundle)
def get_investigation(id: str):
    """Run Agent 2 on the incident and return the Structured Evidence Bundle."""
    return investigate(id)


@app.get("/explain/{id}", response_model=schemas.Report)
def get_explanation(id: str):
    """Run Agent 2, then Agent 3: an analyst report in Markdown built from the evidence bundle."""
    return explain(investigate(id))


@app.get("/technique/{technique_id}", response_model=schemas.TechniqueInfo)
def get_technique(technique_id: str):
    """Name, tactic(s) and description of an ATT&CK technique."""
    return tools.lookup_technique(technique_id)
