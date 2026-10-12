"""Agent 2 - Attack Investigation.

The agent runs a loop: a language model (or the offline scripted policy)
chooses which deterministic tool to call next, the tool runs, and its result is
fed back. When the model stops, the Structured Evidence Bundle is assembled
from the tool results alone. The model's own text is kept under `agent_notes`
as commentary; it is never the source of a finding.

Two things keep the model from inventing findings:
  1. Tools take an incident_id or technique_id only. match_historical and
     predict_next are run on the trajectory that query_graph returned, not on
     anything the model writes. (docs/agent-tools.md describes those two tools
     as taking a trajectory; the Python functions in agents.tools do. Only the
     model-facing wrapper takes the incident id.)
  2. The bundle is built by code from the tool outputs. Tool arguments are
     validated, and the step log stores only validated values and fixed error
     codes, so model-written strings cannot enter it.

Runs offline by default (ScriptedLLM). The Claude adapter (AnthropicLLM) has
never been run against the real API: no credentials were available.

  python -m agents.investigation_agent INC-00017
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Protocol

from agents import tools

MAX_STEPS = 8          # model turns
MAX_TOOL_CALLS = 20    # tool executions per investigation
STRONG_MATCH = 0.5   # similarity from which the scripted policy asks for a prediction

SYSTEM_PROMPT = """You are the Attack Investigation agent of a security operations system.
Your goal is to investigate one incident and gather the evidence an analyst needs.

You do not analyse logs yourself. You decide which tool to call and in what order; every
finding comes from a tool. The usual order is:
  1. query_graph      - get the incident's ordered ATT&CK techniques
  2. get_events       - if the trajectory looks suspicious, get the underlying events
  3. match_historical - compare the trajectory with past attacks
  4. predict_next     - if there is a strong historical match, get the likely next technique
  5. lookup_technique - look up the technique that matters most (usually the predicted one)
Stop when you have what an analyst needs. Then write two or three sentences on what the tools
returned. Do not state anything the tools did not return, and do not invent technique ids,
similarity scores or probabilities."""

_incident = {"type": "object", "additionalProperties": False, "required": ["incident_id"],
             "properties": {"incident_id": {"type": "string", "description": "e.g. INC-00017"}}}

TOOL_SPECS = [
    {"name": "query_graph", "input_schema": _incident,
     "description": "Return the incident's Attack Trajectory: its ATT&CK techniques in time order. Call this first."},
    {"name": "get_events", "input_schema": _incident,
     "description": "Return the incident's normalized log events in time order."},
    {"name": "match_historical", "input_schema": _incident,
     "description": "Compare the incident's trajectory (from query_graph) with the historical attack database "
                    "and return the most similar past attacks with similarity scores."},
    {"name": "predict_next", "input_schema": _incident,
     "description": "Predict the most probable next ATT&CK techniques for the incident's trajectory "
                    "(from query_graph), with the historical counts behind the prediction."},
    {"name": "lookup_technique",
     "input_schema": {"type": "object", "additionalProperties": False, "required": ["technique_id"],
                      "properties": {"technique_id": {"type": "string", "description": "e.g. T1021 or T1059.001"}}},
     "description": "Return the name, tactic and description of an ATT&CK technique."},
]


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class Decision:
    """What the model wants next: tool calls, or nothing (it is done)."""
    tool_calls: list = field(default_factory=list)
    text: str = ""
    content: object = None      # assistant content to append to the conversation
    stop_reason: str = "end_turn"


class LLM(Protocol):
    name: str

    def decide(self, system: str, messages: list, tool_specs: list) -> Decision: ...


class ToolError(Exception):
    """A tool call that cannot be run. `code` is a fixed string that is safe to
    store in the evidence bundle; `detail` goes back to the model only."""

    def __init__(self, code, detail=None):
        super().__init__(detail or code)
        self.code = code


# ----------------------------------------------------------------------------
# Tool execution and evidence
# ----------------------------------------------------------------------------

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
ARGUMENT = {spec["name"]: spec["input_schema"]["required"][0] for spec in TOOL_SPECS}


class Investigation:
    """Runs tool calls for one incident and keeps their results.

    Nothing the model writes is stored: a step records the validated tool name
    and argument and a summary built from the tool's own output, and a rejected
    call records a fixed error code."""

    def __init__(self, incident_id, toolset=None):
        self.incident_id = incident_id
        self.tools = tools.TOOLS if toolset is None else toolset
        self.trajectory = None
        self.events = None
        self.matches = None
        self.prediction = None
        self.techniques = {}
        self.steps = []

    def run(self, call):
        """Execute one tool call. Returns (result for the model, is_error)."""
        name, argument = "<unknown>", {}
        try:
            name, argument = self._validate(call)
            result = self._dispatch(name, argument)
            error, summary = False, self._summary(name, result)
        except ToolError as exc:
            result, error, summary = {"error": str(exc)}, True, f"rejected: {exc.code}"
        except LookupError:
            result, error, summary = {"error": "not found"}, True, "rejected: not found"
        self.steps.append({"tool": name, "input": argument, "ok": not error, "summary": summary})
        return result, error

    def _validate(self, call):
        """Returns (tool name, {argument name: value}) or raises ToolError.
        Only a known tool name and its single, well-formed argument get through."""
        name = getattr(call, "name", None)
        if not isinstance(name, str) or name not in ARGUMENT or name not in self.tools:
            raise ToolError("unknown tool", "there is no such tool")
        key, args = ARGUMENT[name], getattr(call, "input", None)
        if not isinstance(args, dict) or set(args) != {key} or not isinstance(args[key], str):
            raise ToolError("invalid arguments", f"{name} takes exactly one string argument: {key}")
        value = args[key].strip()
        if key == "technique_id":
            value = value.upper()
            if not TECHNIQUE_ID.match(value):
                raise ToolError("invalid arguments", "technique_id must look like T1021 or T1059.001")
        elif value != self.incident_id:
            raise ToolError("wrong incident", f"this investigation is about {self.incident_id} only")
        return name, {key: value}

    def _dispatch(self, name, argument):
        if name == "lookup_technique":
            info = self.tools[name](argument["technique_id"])
            self.techniques[info["id"]] = info
            return info
        if name == "query_graph":
            if self.trajectory is None:   # fetched once, so later results always describe this trajectory
                self.trajectory = self.tools[name](self.incident_id)
            return self.trajectory
        if name == "get_events":
            if self.events is None:
                self.events = self.tools[name](self.incident_id)
            return self.events
        if self.trajectory is None:
            raise ToolError("query_graph not called yet", "call query_graph first; this tool works on its trajectory")
        if name == "match_historical":
            self.matches = self.tools[name](self.trajectory)
            return self.matches
        self.prediction = self.tools[name](self.trajectory)
        return self.prediction

    @staticmethod
    def _summary(name, result):
        if name == "query_graph":
            return f"{len(result['techniques'])} technique step(s): " + " > ".join(t["id"] for t in result["techniques"])
        if name == "get_events":
            return f"{len(result)} event(s)"
        if name == "match_historical":
            top = result["matches"][0] if result["matches"] else None
            return f"top match {top['attack_id']} at {top['similarity']}" if top else "no historical match"
        if name == "predict_next":
            top = result["predictions"][0] if result["predictions"] else None
            return f"top prediction {top['technique_id']} at {top['probability']}" if top else "no prediction"
        return f"{result['id']} {result['name']}"

    def event_summary(self):
        """Counts over the events, computed by code."""
        if self.events is None:
            return None
        count = lambda key: dict(sorted(_tally(str(e[key]) for e in self.events).items()))
        return {
            "count": len(self.events),
            "first": self.events[0]["timestamp"] if self.events else None,
            "last": self.events[-1]["timestamp"] if self.events else None,
            "users": count("user"), "devices": count("device"), "actions": count("action"),
        }

    def _relation(self, technique_id):
        """How a looked-up technique relates to the evidence gathered."""
        base = technique_id.split(".")[0]
        observed = [t["id"] for t in (self.trajectory or {}).get("techniques", [])]
        if technique_id in observed or base in {t.split(".")[0] for t in observed}:
            return "in_trajectory"
        if any(p["technique_id"] == base for p in (self.prediction or {}).get("predictions", [])):
            return "predicted"
        return "not_in_evidence"

    def bundle(self, llm_name, notes, model_stopped, stop_reason):
        """The Structured Evidence Bundle. Every field except agent_notes is
        built from tool results by this class."""
        failed = sum(1 for s in self.steps if not s["ok"])
        return {
            "incident_id": self.incident_id,
            "trajectory": self.trajectory,
            "event_summary": self.event_summary(),
            "historical_matches": self.matches,
            "prediction": self.prediction,
            "techniques": [{**self.techniques[k], "relation": self._relation(k)} for k in sorted(self.techniques)],
            "steps": self.steps,
            "agent": {
                "llm": llm_name,
                "complete": model_stopped and self.trajectory is not None,
                "stop_reason": stop_reason,
                "tool_calls": len(self.steps),
                "failed_tool_calls": failed,
            },
            "agent_notes": notes,
        }


def _tally(values):
    out = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


# ----------------------------------------------------------------------------
# The loop
# ----------------------------------------------------------------------------

def investigate(incident_id, llm=None, max_steps=MAX_STEPS, toolset=None, max_tool_calls=MAX_TOOL_CALLS):
    """Investigate one incident and return the Structured Evidence Bundle
    (agents.contracts.EvidenceBundle). Raises LookupError if the incident does
    not exist. A failure of the language model does not raise: the evidence
    gathered so far is returned with agent.complete = False."""
    if toolset is None and not tools.incident_exists(incident_id):
        raise LookupError(f"no incident {incident_id!r}")
    work = Investigation(incident_id, toolset)
    llm = llm or default_llm()

    messages = [{"role": "user", "content": f"Investigate incident {incident_id} and report."}]
    notes, model_stopped, stop_reason = "", False, "max_steps"
    for _ in range(max_steps):
        try:
            decision = llm.decide(SYSTEM_PROMPT, messages, TOOL_SPECS)
        except Exception as exc:  # noqa: BLE001 - an API or model failure must not lose the evidence
            stop_reason = f"model_error: {type(exc).__name__}"
            break
        if not isinstance(decision, Decision):
            stop_reason = "invalid_model_response"
            break
        if not decision.tool_calls:
            notes = decision.text if isinstance(decision.text, str) else ""
            model_stopped, stop_reason = decision.stop_reason == "end_turn", str(decision.stop_reason)
            break

        calls, ids = [], set()
        for call in decision.tool_calls:   # one result per distinct call id
            call_id = getattr(call, "id", None)
            if isinstance(call_id, str) and call_id not in ids:
                ids.add(call_id)
                calls.append(call)
        content = decision.content or [
            {"type": "tool_use", "id": c.id, "name": str(getattr(c, "name", "")),
             "input": c.input if isinstance(getattr(c, "input", None), dict) else {}} for c in calls]
        messages.append({"role": "assistant", "content": content})
        results = []
        for call in calls:
            if len(work.steps) >= max_tool_calls:
                result, error = {"error": "tool call budget for this investigation is used up"}, True
            else:
                result, error = work.run(call)
            block = {"type": "tool_result", "tool_use_id": call.id, "content": json.dumps(result)}
            if error:
                block["is_error"] = True
            results.append(block)
        messages.append({"role": "user", "content": results})   # all results in one message
        if len(work.steps) >= max_tool_calls:
            stop_reason = "max_tool_calls"
            break
    return work.bundle(getattr(llm, "name", "unknown"), notes, model_stopped, stop_reason)


# ----------------------------------------------------------------------------
# Language models
# ----------------------------------------------------------------------------

class ScriptedLLM:
    """Offline stand-in for a language model. It follows the conceptual loop in
    docs/agent-tools.md with fixed rules, reading the same conversation a real
    model would see. Deterministic, needs no credentials, and is the default."""

    name = "scripted-policy"

    def decide(self, system, messages, tool_specs):
        found = re.search(r"incident (\S+) and report", messages[0]["content"])
        incident_id = found.group(1) if found else ""
        seen = self._results(messages)
        call = self._next(incident_id, seen)
        if call is None:
            return Decision(text=self._notes(seen))
        name, args = call
        block = {"type": "tool_use", "id": f"call-{len(messages)}", "name": name, "input": args}
        return Decision(tool_calls=[ToolCall(block["id"], name, args)], content=[block], stop_reason="tool_use")

    @staticmethod
    def _results(messages):
        """{tool name: parsed result or None if it failed} for every call so far."""
        names, seen = {}, {}
        for message in messages:
            if not isinstance(message["content"], list):
                continue
            for block in message["content"]:
                if block["type"] == "tool_use":
                    names[block["id"]] = block["name"]
                elif block["type"] == "tool_result":
                    payload = None if block.get("is_error") else json.loads(block["content"])
                    seen[names[block["tool_use_id"]]] = payload
        return seen

    @staticmethod
    def _next(incident_id, seen):
        if "query_graph" not in seen:
            return "query_graph", {"incident_id": incident_id}
        trajectory = seen["query_graph"]
        if not trajectory or not trajectory["techniques"]:
            return None                                   # nothing suspicious to investigate
        if "get_events" not in seen:
            return "get_events", {"incident_id": incident_id}
        if "match_historical" not in seen:
            return "match_historical", {"incident_id": incident_id}
        matches = (seen["match_historical"] or {}).get("matches", [])
        strong = bool(matches) and matches[0]["similarity"] >= STRONG_MATCH
        if strong and "predict_next" not in seen:
            return "predict_next", {"incident_id": incident_id}
        if "lookup_technique" not in seen:
            predictions = (seen.get("predict_next") or {}).get("predictions", [])
            key = predictions[0]["technique_id"] if predictions else trajectory["techniques"][-1]["id"]
            return "lookup_technique", {"technique_id": key}
        return None

    @staticmethod
    def _notes(seen):
        failed = sorted(name for name, payload in seen.items() if payload is None)
        if failed:
            return "These tool calls failed, so the evidence is incomplete: " + ", ".join(failed) + "."
        trajectory = seen.get("query_graph")
        if not trajectory or not trajectory["techniques"]:
            return "The incident has no ATT&CK-mapped steps, so no further tools were called."
        if "predict_next" not in seen:
            return (f"No historical match reached the strong-match level ({STRONG_MATCH}), "
                    "so no next-step prediction was requested.")
        return "Trajectory, events, historical matches and a next-step prediction were collected."


class AnthropicLLM:
    """Claude through the official Anthropic SDK (manual tool-use loop).

    Used only when AGENT_LLM=anthropic. Requires `pip install anthropic` and
    credentials (ANTHROPIC_API_KEY or an `ant auth login` profile). NOT exercised
    by the test suite: no credentials were available when this was written.
    Server-side refusal fallbacks are not enabled.
    """

    def __init__(self, model="claude-opus-5-5", max_tokens=16000):
        import anthropic   # imported here so the rest of the system runs without the package

        self.client = anthropic.Anthropic()
        self.model, self.max_tokens = model, max_tokens
        self.name = model

    def decide(self, system, messages, tool_specs):
        response = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            tools=tool_specs, messages=messages)
        text = "".join(block.text for block in response.content if block.type == "text")
        if response.stop_reason != "tool_use":
            # end_turn, or refusal / max_tokens / pause_turn: stop and report why
            return Decision(text=text, stop_reason=response.stop_reason)
        calls = [ToolCall(block.id, block.name, block.input)
                 for block in response.content if block.type == "tool_use"]
        return Decision(tool_calls=calls, text=text, content=response.content, stop_reason="tool_use")


def default_llm():
    """ScriptedLLM unless AGENT_LLM=anthropic is set (that path is untested
    against the real API; see AnthropicLLM)."""
    if os.getenv("AGENT_LLM", "").lower() == "anthropic":
        return AnthropicLLM()
    return ScriptedLLM()

