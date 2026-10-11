# Virux Cypher

**An Agentic, Temporal Cyber-Threat Knowledge Graph System**

Converts security logs into a time-aware knowledge graph, recognises multi-step
attacks, matches them against past attacks, and predicts the attacker's next move —
driven by AI agents that reason over the system and explain findings with evidence.

> Pipeline: Logs -> Event Extraction -> Knowledge Graph -> ATT&CK Mapping ->
> Temporal Trajectory -> Historical Matching -> Next-Step Prediction ->
> Evidence + Explanation -> Dashboard

## Research foundations
- OntoLogX (2026) - base codebase: logs -> ontology-grounded KG -> ATT&CK
- CL-AP2 (2024) - temporal attack KG -> next-technique prediction
- ChronoCTI (2025) - historical temporal attack patterns

Our contribution is the integration + agentic reasoning layer, not any single paper.

## The three agents
| Agent | Job | Kind |
|---|---|---|
| Log Intelligence | raw logs -> structured, ATT&CK-mapped events | perception |
| Attack Investigation (primary) | orchestrates graph/match/predict tools | reasoning |
| Explanation | turns the evidence bundle into an analyst report | communication |

Core decisions (graph, similarity, prediction) are deterministic and auditable.
Agents orchestrate and explain - they never invent a finding.

## Stack
Backend: Python + FastAPI | Graph: Neo4j | ML: pandas, scikit-learn |
Agents: LLM API w/ tool-calling | Frontend: React + Vite + Cytoscape.js

## Getting started
1. Backend env: `cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
2. Start Neo4j: `cd ../docker && docker compose up -d`
3. Generate data: `cd ../data/generator && python generate.py`
4. Run backend: `cd ../../backend && uvicorn api.main:app --reload`
5. Run frontend: `cd ../frontend && npm install && npm run dev`

See docs/architecture.md and docs/data-contracts.md. Freeze the data contracts before coding.
