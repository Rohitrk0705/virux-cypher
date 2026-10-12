# agents — the 3 agents + shared tool layer. See docs/agent-tools.md.

| Path | What |
|---|---|
| `contracts.py` | The five data contracts as Python `TypedDict`s |
| `tools/` | The five deterministic tools: `get_events`, `query_graph`, `match_historical`, `predict_next`, `lookup_technique` |
| `investigation_agent/` | Agent 2: the tool-calling loop and the Structured Evidence Bundle |

Agent 2 runs offline by default with `ScriptedLLM`, a fixed-rule policy that follows the loop in
`docs/agent-tools.md`. Set `AGENT_LLM=anthropic` (and install `anthropic`, with credentials) to let
Claude choose the tool calls instead; that path has not been run, because no credentials were available.

    python -m agents.investigation_agent INC-00017

The model only chooses which tool to call. `match_historical` and `predict_next` run on the trajectory
`query_graph` returned, never on text the model wrote, and the bundle is assembled by code from tool results.
The model's own text appears only under `agent_notes`.
