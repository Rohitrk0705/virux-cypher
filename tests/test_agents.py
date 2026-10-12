"""Milestone 7: the five tools and the Agent 2 loop (offline, mock language models)."""

import json
import re

import pytest

from agents import tools
from agents.investigation_agent import (Decision, Investigation, ScriptedLLM, ToolCall, TOOL_SPECS,
                                        investigate)

TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVENT_KEYS = ["event_id", "timestamp", "source", "user", "source_ip",
              "destination_ip", "device", "action", "process", "destination_port", "byte_count"]

TRAJECTORY = {"incident_id": "INC-1", "techniques": [
    {"id": "T1078", "timestamp": "2026-09-07T10:00:00Z"},
    {"id": "T1059.001", "timestamp": "2026-09-07T10:05:00Z"},
    {"id": "T1068", "timestamp": "2026-09-07T10:09:00Z"}]}
EVENTS = [{"event_id": "evt-1", "timestamp": "2026-09-07T10:00:00Z", "source": "windows", "user": "john",
           "source_ip": "203.0.113.9", "destination_ip": "10.0.0.11", "device": "WS-01",
           "action": "logon_success", "process": None}]


def fake_tools(trajectory=TRAJECTORY):
    """Graph-free toolset: the two graph tools are stubbed, the rest are real."""
    return {**tools.TOOLS, "query_graph": lambda incident_id: trajectory,
            "get_events": lambda incident_id: EVENTS}


# ---------------------------------------------------------------- tools

def test_tool_registry_matches_the_documented_five():
    names = ["get_events", "query_graph", "match_historical", "predict_next", "lookup_technique"]
    assert list(tools.TOOLS) == names
    assert sorted(spec["name"] for spec in TOOL_SPECS) == sorted(names)
    for spec in TOOL_SPECS:
        assert spec["description"] and spec["input_schema"]["type"] == "object"


def test_lookup_technique_shape_revoked_ids_and_unknown():
    info = tools.lookup_technique("T1059.001")
    assert list(info) == ["id", "name", "tactic", "description"]
    assert info["name"] == "PowerShell" and info["tactic"] == "Execution" and info["description"]
    assert tools.lookup_technique("T1070.001")["id"] == "T1685.005"      # revoked id is resolved
    assert tools.lookup_technique("T1078")["tactic"].startswith("Initial Access, ")
    with pytest.raises(LookupError):
        tools.lookup_technique("T0000")


def test_match_and_predict_tools_return_contracts_4_and_5():
    match = tools.match_historical(TRAJECTORY)
    assert list(match) == ["incident_id", "matches"]
    assert list(match["matches"][0]) == ["attack_id", "similarity", "common_techniques"]
    prediction = tools.predict_next(TRAJECTORY)
    assert list(prediction) == ["incident_id", "predictions", "evidence"]
    assert list(prediction["predictions"][0]) == ["technique_id", "probability"]


def test_graph_tools_return_contracts_1_and_3(graph):
    listed = tools.list_incidents()
    assert listed and list(listed[0]) == ["incident_id", "start", "end", "event_count"]
    incident_id = listed[0]["incident_id"]
    events = tools.get_events(incident_id)
    assert len(events) == listed[0]["event_count"]
    assert all(list(e) == EVENT_KEYS and TS.match(e["timestamp"]) for e in events)
    trajectory = tools.query_graph(incident_id)
    assert list(trajectory) == ["incident_id", "techniques"] and trajectory["incident_id"] == incident_id
    assert all(list(step) == ["id", "timestamp"] for step in trajectory["techniques"])
    with pytest.raises(LookupError):
        tools.get_events("INC-nope")
    with pytest.raises(LookupError):
        tools.query_graph("INC-nope")


# ---------------------------------------------------------------- agent loop

def test_scripted_agent_follows_the_documented_loop():
    bundle = investigate("INC-1", llm=ScriptedLLM(), toolset=fake_tools())
    assert [s["tool"] for s in bundle["steps"]] == [
        "query_graph", "get_events", "match_historical", "predict_next", "lookup_technique"]
    assert all(s["ok"] for s in bundle["steps"])
    assert bundle["trajectory"] == TRAJECTORY
    assert bundle["historical_matches"] == tools.match_historical(TRAJECTORY)
    assert bundle["prediction"] == tools.predict_next(TRAJECTORY)
    assert bundle["event_summary"]["count"] == 1 and bundle["event_summary"]["users"] == {"john": 1}
    predicted = bundle["prediction"]["predictions"][0]["technique_id"]
    assert [(t["id"], t["relation"]) for t in bundle["techniques"]] == [(predicted, "predicted")]
    assert bundle["agent"] == {"llm": "scripted-policy", "complete": True, "stop_reason": "end_turn",
                               "tool_calls": 5, "failed_tool_calls": 0}


def test_scripted_agent_is_deterministic():
    run = lambda: investigate("INC-1", llm=ScriptedLLM(), toolset=fake_tools())
    assert json.dumps(run(), sort_keys=True) == json.dumps(run(), sort_keys=True)


def test_agent_stops_early_when_nothing_is_mapped():
    empty = {"incident_id": "INC-1", "techniques": []}
    bundle = investigate("INC-1", llm=ScriptedLLM(), toolset=fake_tools(empty))
    assert [s["tool"] for s in bundle["steps"]] == ["query_graph"]
    assert bundle["prediction"] is None and bundle["historical_matches"] is None


def test_no_prediction_without_a_strong_match():
    weak = {"incident_id": "INC-1", "techniques": [{"id": "T1486", "timestamp": "2026-09-07T10:00:00Z"}]}
    bundle = investigate("INC-1", llm=ScriptedLLM(), toolset=fake_tools(weak))
    assert "predict_next" not in [s["tool"] for s in bundle["steps"]]
    assert bundle["prediction"] is None and "strong-match" in bundle["agent_notes"]


class Script:
    """A mock model that plays back a fixed list of decisions."""
    name = "mock"

    def __init__(self, *turns):
        self.turns = list(turns)
        self.seen = []

    def decide(self, system, messages, tool_specs):
        self.seen.append(json.loads(json.dumps(messages)))
        if not self.turns:
            return Decision(text="done")
        calls = self.turns.pop(0)
        if isinstance(calls, Decision):
            return calls
        calls = [ToolCall(f"c{len(self.seen)}-{i}", name, args) for i, (name, args) in enumerate(calls)]
        content = [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls]
        return Decision(tool_calls=calls, content=content, stop_reason="tool_use")


def test_model_cannot_supply_its_own_trajectory_or_another_incident():
    llm = Script(
        [("match_historical", {"incident_id": "INC-1"})],                     # before query_graph
        [("query_graph", {"incident_id": "INC-OTHER"})],                      # different incident
        [("predict_next", {"incident_id": "INC-1", "trajectory": {"techniques": [{"id": "T9999"}]}})],
        [("not_a_tool", {})],
    )
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    assert [s["ok"] for s in bundle["steps"]] == [False, False, False, False]
    assert bundle["trajectory"] is None and bundle["prediction"] is None
    errors = [b for m in llm.seen[-1] if isinstance(m["content"], list)
              for b in m["content"] if b["type"] == "tool_result"]
    assert len(errors) == 4 and all(b["is_error"] for b in errors)


def test_bundle_findings_come_from_tools_not_from_model_text():
    llm = Script([("query_graph", {"incident_id": "INC-1"})],
                 Decision(text="The attacker will certainly use T9999 next with probability 0.99."))
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    assert bundle["prediction"] is None and bundle["historical_matches"] is None
    findings = json.dumps({k: v for k, v in bundle.items() if k != "agent_notes"})
    assert "T9999" not in findings and "0.99" not in findings
    assert "T9999" in bundle["agent_notes"]


def test_parallel_tool_calls_return_all_results_in_one_message():
    llm = Script([("query_graph", {"incident_id": "INC-1"})],
                 [("get_events", {"incident_id": "INC-1"}), ("match_historical", {"incident_id": "INC-1"}),
                  ("lookup_technique", {"technique_id": "T1068"})])
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    last = llm.seen[-1][-1]
    assert last["role"] == "user" and [b["type"] for b in last["content"]] == ["tool_result"] * 3
    assert bundle["event_summary"] and bundle["historical_matches"] and bundle["techniques"][0]["id"] == "T1068"


def test_loop_is_bounded_and_reports_why_it_stopped():
    forever = Script(*[[("lookup_technique", {"technique_id": "T1078"})]] * 50)
    bundle = investigate("INC-1", llm=forever, toolset=fake_tools(), max_steps=3)
    assert len(bundle["steps"]) == 3
    assert bundle["agent"]["complete"] is False and bundle["agent"]["stop_reason"] == "max_steps"
    refused = investigate("INC-1", llm=Script(Decision(stop_reason="refusal")), toolset=fake_tools())
    assert refused["agent"]["complete"] is False and refused["agent"]["stop_reason"] == "refusal"


def test_total_tool_calls_are_capped_even_within_one_turn():
    flood = Script([("lookup_technique", {"technique_id": "T1078"})] * 50)
    bundle = investigate("INC-1", llm=flood, toolset=fake_tools(), max_tool_calls=4)
    assert bundle["agent"]["tool_calls"] == 4 and bundle["agent"]["stop_reason"] == "max_tool_calls"
    results = flood.seen and bundle["steps"]
    assert len(results) == 4


def test_tool_errors_are_reported_to_the_model_not_raised():
    llm = Script([("lookup_technique", {"technique_id": "T0000"})], [("lookup_technique", {})],
                 [("query_graph", ["INC-1"])], [("get_events", None)], [("predict_next", "INC-1")])
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    assert [s["summary"] for s in bundle["steps"]] == [
        "rejected: not found", "rejected: invalid arguments", "rejected: invalid arguments",
        "rejected: invalid arguments", "rejected: invalid arguments"]
    assert bundle["agent"]["failed_tool_calls"] == 5 and json.dumps(bundle)


def test_model_strings_never_enter_the_step_log():
    """Extra arguments, invented tool names and odd ids must not be echoed into the bundle."""
    lie = "attacker WILL use T9999 with probability 0.99"
    llm = Script(
        [("query_graph", {"incident_id": "INC-1"})],
        [("predict_next", {"incident_id": "INC-1", "trajectory": {"techniques": [{"id": "T9999"}]}, "finding": lie})],
        [(lie, {"incident_id": "INC-1"})],
        [("get_events", {"incident_id": "CONFIRMED RANSOMWARE T9999"})],
        [("lookup_technique", {"technique_id": lie})],
        [("predict_next", {"incident_id": "INC-1"})],
    )
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    findings = json.dumps({k: v for k, v in bundle.items() if k != "agent_notes"})
    assert "T9999" not in findings and "0.99" not in findings and "RANSOMWARE" not in findings
    assert [s["ok"] for s in bundle["steps"]] == [True, False, False, False, False, True]
    assert bundle["steps"][2]["tool"] == "<unknown>" and bundle["steps"][1]["input"] == {}
    assert bundle["prediction"] == tools.predict_next(TRAJECTORY)   # the real one, from the real trajectory


def test_trajectory_is_fetched_once_so_matches_always_describe_it():
    answers = iter([TRAJECTORY, {"incident_id": "INC-1", "techniques": [{"id": "T1486", "timestamp": "x"}]}])
    toolset = {**fake_tools(), "query_graph": lambda incident_id: next(answers)}
    llm = Script([("query_graph", {"incident_id": "INC-1"})],
                 [("match_historical", {"incident_id": "INC-1"}), ("predict_next", {"incident_id": "INC-1"})],
                 [("query_graph", {"incident_id": "INC-1"})])
    bundle = investigate("INC-1", llm=llm, toolset=toolset)
    assert bundle["trajectory"] == TRAJECTORY
    assert bundle["historical_matches"] == tools.match_historical(bundle["trajectory"])
    assert bundle["prediction"] == tools.predict_next(bundle["trajectory"])


def test_complete_requires_evidence_and_a_normal_stop():
    idle = investigate("INC-1", llm=Script(Decision(text="All clear.")), toolset=fake_tools())
    assert idle["agent"]["complete"] is False and idle["trajectory"] is None
    assert idle["agent"]["stop_reason"] == "end_turn" and idle["agent_notes"] == "All clear."


def test_notes_are_the_final_answer_only_not_mid_run_text():
    llm = Script(Decision(tool_calls=[ToolCall("c1", "query_graph", {"incident_id": "INC-1"})],
                          text="thinking aloud about T9999", stop_reason="tool_use"),
                 Decision(text=""))
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    assert bundle["agent_notes"] == "" and bundle["trajectory"] == TRAJECTORY   # content=None was handled


def test_duplicate_call_ids_get_one_result():
    dup = Decision(tool_calls=[ToolCall("same", "query_graph", {"incident_id": "INC-1"}),
                               ToolCall("same", "get_events", {"incident_id": "INC-1"})], stop_reason="tool_use")
    llm = Script(dup)
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    assert [s["tool"] for s in bundle["steps"]] == ["query_graph"]
    assert len(llm.seen[-1][-1]["content"]) == 1


def test_model_failure_keeps_the_evidence_gathered_so_far():
    class Flaky(Script):
        def decide(self, system, messages, tool_specs):
            if len(self.seen) == 1:
                raise RuntimeError("API unavailable")
            return super().decide(system, messages, tool_specs)
    bundle = investigate("INC-1", llm=Flaky([("query_graph", {"incident_id": "INC-1"})]), toolset=fake_tools())
    assert bundle["trajectory"] == TRAJECTORY
    assert bundle["agent"]["complete"] is False and bundle["agent"]["stop_reason"] == "model_error: RuntimeError"
    garbage = investigate("INC-1", llm=type("Bad", (), {"name": "bad", "decide": lambda *a: None})(),
                          toolset=fake_tools())
    assert garbage["agent"]["stop_reason"] == "invalid_model_response"


def test_scripted_policy_reports_failed_tools_truthfully():
    def broken(incident_id):
        raise LookupError("gone")
    bundle = investigate("INC-1", llm=ScriptedLLM(), toolset={**fake_tools(), "query_graph": broken})
    assert bundle["agent"]["complete"] is False
    assert bundle["agent_notes"] == "These tool calls failed, so the evidence is incomplete: query_graph."
    bundle = investigate("INC-1", llm=ScriptedLLM(), toolset={**fake_tools(), "get_events": broken})
    assert "get_events" in bundle["agent_notes"] and "were collected" not in bundle["agent_notes"]


def test_looked_up_technique_is_tagged_when_unrelated_to_the_evidence():
    llm = Script([("query_graph", {"incident_id": "INC-1"})],
                 [("lookup_technique", {"technique_id": "T1486"}), ("lookup_technique", {"technique_id": " t1059 "})])
    bundle = investigate("INC-1", llm=llm, toolset=fake_tools())
    assert {t["id"]: t["relation"] for t in bundle["techniques"]} == {
        "T1486": "not_in_evidence", "T1059": "in_trajectory"}


def test_anthropic_adapter_against_a_fake_sdk(monkeypatch):
    """The real API was never called; this checks the adapter's handling of the
    documented response shape using a stand-in for the `anthropic` package."""
    import sys
    import types

    from agents.investigation_agent import AnthropicLLM

    block = lambda **kw: types.SimpleNamespace(**kw)
    replies = [
        block(stop_reason="tool_use", content=[
            block(type="thinking", thinking=""),
            block(type="text", text="Checking the graph."),
            block(type="tool_use", id="tu_1", name="query_graph", input={"incident_id": "INC-1"})]),
        block(stop_reason="end_turn", content=[block(type="text", text="One trajectory found.")]),
    ]
    sent = []

    class Messages:
        def create(self, **kwargs):
            sent.append(kwargs)
            return replies[len(sent) - 1]

    fake = types.ModuleType("anthropic")
    fake.Anthropic = lambda: types.SimpleNamespace(messages=Messages())
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    bundle = investigate("INC-1", llm=AnthropicLLM(), toolset=fake_tools())
    assert sent[0]["model"] == "claude-opus-5-5" and sent[0]["tools"] == TOOL_SPECS and sent[0]["system"]
    assert sent[1]["messages"][1]["content"] is replies[0].content        # assistant content echoed unchanged
    assert sent[1]["messages"][2]["content"][0]["tool_use_id"] == "tu_1"
    assert bundle["trajectory"] == TRAJECTORY and bundle["agent_notes"] == "One trajectory found."
    assert bundle["agent"]["llm"] == "claude-opus-5-5" and bundle["agent"]["complete"]


def test_list_incidents_uses_iso_timestamps(graph):
    first = tools.list_incidents()[0]
    assert TS.match(first["start"]) and TS.match(first["end"])


def test_real_incident_end_to_end(graph):
    incident_id = next(i["incident_id"] for i in tools.list_incidents()
                       if len(tools.query_graph(i["incident_id"])["techniques"]) >= 3)
    bundle = investigate(incident_id)
    assert bundle["incident_id"] == incident_id and bundle["agent"]["complete"]
    assert bundle["trajectory"] == tools.query_graph(incident_id)
    assert bundle["event_summary"]["count"] == len(tools.get_events(incident_id))
    with pytest.raises(LookupError):
        investigate("INC-nope")


# ---------------------------------------------------------------- Agent 3 (explanation)

def bundle_for(llm=None, toolset=None):
    return investigate("INC-1", llm=llm or ScriptedLLM(), toolset=toolset or fake_tools())


def test_report_says_from_not_first_seen_and_matches_the_bundle():
    from agents.explanation_agent import explain
    bundle = bundle_for()
    report = explain(bundle)["report"]
    assert "first seen" not in report
    for step in bundle["trajectory"]["techniques"]:
        assert f"`{step['id']}`" in report and f"from {step['timestamp']}" in report
    top = bundle["historical_matches"]["matches"][0]
    assert top["attack_id"] in report and "hand-written reference sequence" in report
    assert "Investigation complete; 5 tool call(s), 0 failed" in report


def test_report_wording_follows_tool_failures():
    from agents.explanation_agent import explain

    def broken(trajectory):
        raise LookupError("gone")

    report = explain(bundle_for(toolset={**fake_tools(), "predict_next": broken}))["report"]
    assert "The prediction tool failed" in report and "No prediction was requested" not in report
    assert "finished, but with failed tool calls" in report
    idle = explain(bundle_for(llm=Script(Decision(text="All clear."))))["report"]
    assert "was not requested" in idle and "INCOMPLETE" in idle


def test_report_escapes_values_from_the_logs_and_from_the_model():
    from agents.explanation_agent import explain
    hostile = [{**EVENTS[0], "user": "<img src=x onerror=alert(1)>|x\n\n# Injected heading",
                "device": "[click](javascript:alert(1))"}]
    toolset = {**fake_tools(), "get_events": lambda incident_id: hostile}
    llm = Script([("query_graph", {"incident_id": "INC-1"})], [("get_events", {"incident_id": "INC-1"})],
                 Decision(text="line one\n<script>alert(2)</script>\n# Not a heading"))
    report = explain(bundle_for(llm=llm, toolset=toolset))["report"]
    import re as _re
    assert "img src" in report and "script" in report                     # the text is kept, defused
    assert not _re.search(r"(?<!\\)[<>\[\]|]", report.split("Accounts:")[1].split("Event types:")[0])
    assert not _re.search(r"(?<!\\)<", report.split("commentary, not a finding):")[1].split("## Limits")[0])
    headings = [line for line in report.splitlines() if line.startswith("#")]
    assert all("Injected" not in h and "Not a heading" not in h for h in headings)
    note = report.split("commentary, not a finding):")[1].split("## Limits")[0]
    assert all(line.startswith("> ") for line in note.splitlines() if line.strip())
