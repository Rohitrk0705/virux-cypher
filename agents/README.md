# agents — the 3 agents + shared tool layer. See docs/agent-tools.md.

| Path | What |
|---|---|
| `contracts.py` | The five data contracts as Python `TypedDict`s |
| `tools/` | The five deterministic tools: `get_events`, `query_graph`, `match_historical`, `predict_next`, `lookup_technique` |
| `loop.py` | The tool-calling loop, the policy interface and the Claude adapter, shared by the three agents |
| `log_agent/` | Agent 1: raw log records -> Normalized Events -> graph, ATT&CK mapping, incidents (`parsers.py` holds the parsers) |
| `investigation_agent/` | Agent 2: tool selection for one incident and the Structured Evidence Bundle |
| `explanation_agent/` | Agent 3: evidence bundle -> analyst report |

Each agent is a policy choosing among deterministic tools. All three run offline by default with a
fixed-rule scripted policy (`ScriptedIntake`, `ScriptedLLM`, `ScriptedWriter`) that follows the loops in
`docs/agent-tools.md`. Set `AGENT_LLM=anthropic` (and install `anthropic`, with credentials) to let
Claude make the choices instead; **that path has never been run against the real API, for any of the
three agents, because no credentials were available.** Nothing in the repository simulates a model's answer.

    python -m agents.investigation_agent INC-00017

With the offline policies the agents' decisions are fixed rules, so Agent 1 always picks the parser named
after the detected format and Agent 3's report is exactly the deterministic template.

The model only chooses which tool to call. `match_historical` and `predict_next` run on the trajectory
`query_graph` returned, never on text the model wrote, and the bundle is assembled by code from tool results.
The model's own text appears only under `agent_notes`.
