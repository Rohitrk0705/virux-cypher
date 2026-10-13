"""Shared agent runtime: the tool-calling loop all three agents run on.

An agent here is: a policy (a language model, or an offline scripted stand-in)
that chooses which deterministic tool to call next, a workspace that validates
and executes those calls and keeps their results, and code that assembles the
agent's output from the tool results alone. This module holds the parts that
are the same for every agent: the conversation loop, the policy interface and
the Claude adapter.

The workspace passed to run_loop() needs two things:
  run(call) -> (result for the model, is_error)   execute one validated tool call
  steps                                           the list of calls executed so far
"""

import json
import os
from dataclasses import dataclass, field
from typing import Protocol


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
    store in an agent's output; `detail` goes back to the model only."""

    def __init__(self, code, detail=None):
        super().__init__(detail or code)
        self.code = code


def run_loop(llm, system, task, tool_specs, work, max_steps, max_tool_calls):
    """Let the policy call tools on `work` until it stops or a limit is hit.

    Returns (notes, model_stopped, stop_reason): the model's final text, whether
    it ended its turn normally, and why the loop ended. A failure of the model
    does not raise; whatever `work` gathered so far is kept."""
    messages = [{"role": "user", "content": task}]
    notes, model_stopped, stop_reason = "", False, "max_steps"
    for _ in range(max_steps):
        try:
            decision = llm.decide(system, messages, list(tool_specs))
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
                result, error = {"error": "tool call budget for this run is used up"}, True
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
    return notes, model_stopped, stop_reason


def status(llm, work, complete, stop_reason):
    """The AgentStatus block every agent reports."""
    return {
        "llm": getattr(llm, "name", "unknown"),
        "complete": complete,
        "stop_reason": stop_reason,
        "tool_calls": len(work.steps),
        "failed_tool_calls": sum(1 for s in work.steps if not s["ok"]),
    }


def tool_history(messages):
    """[(tool name, input, parsed result or None if it failed)] for every call so
    far, in order. What a scripted policy reads instead of 'understanding' the
    conversation."""
    calls, history = {}, []
    for message in messages:
        if not isinstance(message["content"], list):
            continue
        for block in message["content"]:
            if block["type"] == "tool_use":
                calls[block["id"]] = (block["name"], block["input"])
            elif block["type"] == "tool_result":
                name, args = calls[block["tool_use_id"]]
                history.append((name, args, None if block.get("is_error") else json.loads(block["content"])))
    return history


class Scripted:
    """Base of the offline policies: wraps one chosen tool call in a Decision."""

    @staticmethod
    def call(messages, name, args):
        block = {"type": "tool_use", "id": f"call-{len(messages)}", "name": name, "input": args}
        return Decision(tool_calls=[ToolCall(block["id"], name, args)], content=[block], stop_reason="tool_use")


class AnthropicLLM:
    """Claude through the official Anthropic SDK (manual tool-use loop).

    Used only when AGENT_LLM=anthropic. Requires `pip install anthropic` and
    credentials (ANTHROPIC_API_KEY or an `ant auth login` profile). NOT exercised
    by the test suite against the real API: no credentials were available when
    this was written. Server-side refusal fallbacks are not enabled.
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


def llm_requested():
    """True when the environment asks for a language model (AGENT_LLM=anthropic)."""
    return os.getenv("AGENT_LLM", "").lower() == "anthropic"


def default_llm(offline):
    """The given offline scripted policy unless AGENT_LLM=anthropic is set (that
    path is untested against the real API; see AnthropicLLM)."""
    return AnthropicLLM() if llm_requested() else offline
