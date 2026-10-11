"""Virux Cypher backend — FastAPI entry point (skeleton)."""
from fastapi import FastAPI

app = FastAPI(title="Virux Cypher")

@app.get("/health")
def health():
    return {"status": "ok", "service": "virux-cypher"}

# endpoints to implement (see docs/data-contracts.md):
# POST /logs          -> ingest raw logs
# GET  /events/{id}   -> normalized events
# GET  /graph/{id}    -> attack trajectory
# GET  /match/{id}    -> historical matches
# GET  /predict/{id}  -> next-step prediction
# GET  /investigate/{id} -> runs Agent 2, returns evidence bundle
# GET  /explain/{id}  -> runs Agent 3, returns analyst report
