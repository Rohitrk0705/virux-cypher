"""Agents 1 and 3 as agent steps: the policy chooses tools, code produces every finding."""

import json
import sys
import time
from pathlib import Path

import pytest

from agents.explanation_agent import SECTIONS, ScriptedWriter, check_summary, explain
from agents.investigation_agent import Decision
from agents.log_agent import ScriptedIntake, parsers, process_logs
from test_agents import EVENTS, Script, bundle_for, fake_tools

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "data" / "generator"))
import raw_logs  # noqa: E402

EVENT = {"event_id": "evt-1", "timestamp": "2026-09-07T10:00:00Z", "source": "windows", "user": "john",
         "source_ip": "203.0.113.9", "destination_ip": "10.0.0.11", "device": "WS-01",
         "action": "logon_success", "process": None, "destination_port": None, "byte_count": None}
NET = {**EVENT, "event_id": "evt-2", "source": "firewall", "user": "john", "source_ip": "10.0.0.11",
       "destination_ip": "198.51.100.7", "action": "network_connection", "destination_port": 443,
       "byte_count": 900}
MAIL = {**EVENT, "event_id": "evt-3", "source": "email", "source_ip": "192.0.2.5", "destination_ip": "10.0.0.5",
        "device": "SRV-MAIL01", "action": "email_received", "destination_port": 25}


class Store:
    """Stands in for the knowledge graph: remembers what was committed."""

    def __init__(self):
        self.batches = []

    def __call__(self, events):
        self.batches.append(events)
        techniques = [{"event_id": e["event_id"], "technique_id": "T1078", "technique_name": "Valid Accounts",
                       "tactic": "Initial Access", "confidence": 0.6} for e in events if e["action"] == "logon_success"]
        return ({"received": len(events), "events_in_graph": len(events), "mapped_events": len(techniques),
                 "incidents": 0, "incidents_touched": []}, techniques)


def run(records, llm=None):
    store = Store()
    return process_logs(records, llm=llm or ScriptedIntake(), store=store), store


# ---------------------------------------------------------------- Agent 1: parsers

def test_every_synthetic_event_round_trips_through_its_raw_form():
    """A software check only: the renderer and the parsers have one author."""
    events = json.loads((ROOT / "data" / "processed" / "events.json").read_text())
    for event in events:
        record = parsers.load(raw_logs.render(event))
        assert parsers.parse(parsers.detect(record), record) == event
    assert {parsers.detect(parsers.load(raw_logs.render(e))) for e in events} == {
        "windows_event_json", "firewall_kv", "mail_kv"}


def test_parsers_reject_instead_of_guessing():
    def code(record, parser=None):
        record = parsers.load(record)
        with pytest.raises(parsers.Reject) as caught:
            parsers.parse(parser or parsers.detect(record), record)
        return caught.value.code

    windows = json.loads(raw_logs.render(EVENT))
    no_user = json.loads(json.dumps(windows)); no_user["winlog"]["event_data"]["TargetUserName"] = "-"
    no_host = json.loads(json.dumps(windows)); no_host["host"] = {"name": "WS-01"}
    other = json.loads(json.dumps(windows)); other["winlog"]["event_id"] = 1102
    sysmon = json.loads(json.dumps(windows)); sysmon["winlog"]["channel"] = "Microsoft-Windows-Sysmon/Operational"
    naive = json.loads(json.dumps(windows)); naive["@timestamp"] = "2026-09-07T10:00:00"
    assert [code(r) for r in (no_user, no_host, other, sysmon, naive)] == [
        "no user", "no host address", "unsupported event type", "unsupported channel", "timestamp without time zone"]
    line = raw_logs.render(NET)
    assert code(line.replace("action=allow", "action=deny")) == "unsupported event type"
    assert code(line.replace(" srcuser=john", "")) == "no user"
    assert code(line.replace("dport=443", "dport=https")) == "bad number"
    assert code(line, "windows_event_json") == "not a Windows event record"
    assert parsers.detect(line + " src=6.6.6.6") == "unknown"                 # a repeated key is not guessed at
    assert code({**EVENT, "user": "two\nlines"}, "normalized_json") == "fails contract 1"
    assert code({**EVENT, "extra": 1}, "normalized_json") == "fails contract 1"


def test_hostile_records_are_rejected_not_crashes():
    """Each of these raised an uncaught exception (a 500 for the whole batch) before the review."""
    windows = json.loads(raw_logs.render(EVENT))

    def changed(**paths):
        record = json.loads(json.dumps(windows))
        for path, value in paths.items():
            *parents, leaf = path.split("__")
            target = record
            for key in parents:
                target = target[key]
            target[leaf] = value
        return record

    hostile = [json.loads('{"winlog": {"channel": "Security", "event_id": 1e999}, "host": {}}'),
               changed(winlog__event_id=4624.9), changed(winlog__event_id=[4624]), changed(winlog__event_id=True),
               changed(winlog__event_data__IpAddress=["10.0.0.1"]), changed(winlog__event_data__IpAddress={"a": 1}),
               changed(host__ip={"v4": "10.0.0.11"}), changed(host__ip=[]), changed(**{"@timestamp": 5}),
               changed(**{"@timestamp": "0001-01-01T00:00:00+01:00"}),
               changed(**{"@timestamp": "9999-12-31T23:59:59-01:00"}),
               raw_logs.render(NET).replace("dport=443", "dport=\u00b2"),
               raw_logs.render(NET).replace("sent=900", "sent=" + "9" * 5000),
               raw_logs.render(NET).replace("dport=443", "dport=\u0664\u0664\u0663"), {"winlog": {}}, {}, [], None, 5]
    for record in hostile:
        loaded = parsers.load(record)
        for parser in parsers.PARSERS:
            with pytest.raises(parsers.Reject):
                parsers.parse(parser, loaded)
    report, store = run([raw_logs.render(EVENT)] + [r for r in hostile if isinstance(r, (str, dict))])
    assert report["stored"] and store.batches == [[EVENT]] and report["agent"]["complete"]   # the good record survives


def test_parser_derivations_are_the_documented_ones():
    line = raw_logs.render(NET).replace("id=evt-2 ", "").replace("2026-09-07T10:00:00Z", "2026-09-07T12:00:00.250+02:00")
    event = parsers.parse("firewall_kv", line)
    assert event["timestamp"] == "2026-09-07T10:00:00Z"                       # converted to UTC, whole seconds
    assert event["event_id"].startswith("evt-") and len(event["event_id"]) == 20
    assert parsers.parse("firewall_kv", line)["event_id"] == event["event_id"]  # same line, same id
    rdp = parsers.parse("windows_event_json", json.loads(raw_logs.render({**EVENT, "action": "rdp_session",
                                                                          "destination_port": 3389})))
    assert rdp["action"] == "rdp_session" and rdp["destination_port"] == 3389


def test_key_value_detection_stays_fast_on_hostile_lines():
    started = time.perf_counter()
    assert parsers.detect("2026-09-07T10:00:00Z fw01 " + "a=b=" * 5000 + " !") == "unknown"
    assert time.perf_counter() - started < 1


# ---------------------------------------------------------------- Agent 1: the agent step

def test_scripted_intake_profiles_parses_each_group_and_commits():
    records = [raw_logs.render(EVENT), raw_logs.render(NET), raw_logs.render(MAIL), dict(EVENT, event_id="evt-4"),
               "Sep  7 10:00:01 host sshd[1]: something else", json.dumps(["not", "an", "object"])]
    report, store = run(records)
    assert [s["tool"] for s in report["steps"]] == ["profile_batch", "parse_group", "parse_group", "parse_group",
                                                    "parse_group", "quarantine_group", "commit"]
    assert [(g["detected_format"], g["parser"], g["parsed"], g["status"]) for g in report["groups"]] == [
        ("windows_event_json", "windows_event_json", 1, "parsed"), ("firewall_kv", "firewall_kv", 1, "parsed"),
        ("mail_kv", "mail_kv", 1, "parsed"), ("normalized_json", "normalized_json", 1, "parsed"),
        ("unknown", None, 0, "quarantined")]
    assert (report["received"], report["parsed"], report["quarantined"], report["unhandled"]) == (6, 4, 2, 0)
    assert report["stored"] and report["agent"]["complete"] and report["agent"]["llm"] == "scripted-policy"
    assert report["events"] == store.batches[0] == [EVENT, NET, MAIL, dict(EVENT, event_id="evt-4")]
    assert [t["event_id"] for t in report["techniques"]] == ["evt-1", "evt-4"]
    assert run(records)[0] == report                                          # deterministic


def test_nothing_is_stored_when_nothing_parses():
    report, store = run(["free text", "more free text"])
    assert not store.batches and not report["stored"] and report["events"] == [] and report["ingest"] is None
    assert report["quarantined"] == 2 and report["agent"]["complete"]
    assert "nothing was stored" in report["agent_notes"]


def test_rejected_records_are_counted_by_reason_and_duplicates_are_not_stored_twice():
    bad = raw_logs.render(NET).replace(" srcuser=john", "")
    report, store = run([raw_logs.render(NET), bad, dict(NET)])
    assert report["groups"][0]["rejected"] == {"no user": 1}
    assert report["groups"][1]["rejected"] == {"duplicate event_id": 1} and report["groups"][1]["status"] == "nothing parsed"
    assert (report["parsed"], report["rejected"]) == (1, 2) and store.batches == [[NET]]


def test_model_cannot_write_an_event_or_force_a_parser():
    forged = {**EVENT, "event_id": "evt-forged", "user": "attacker"}
    llm = Script([("profile_batch", {})],
                 [("parse_group", {"group_id": "g1", "parser": "firewall_kv", "events": json.dumps([forged])})],
                 [("parse_group", {"group_id": "g1", "parser": "trust_me"})],
                 [("parse_group", {"group_id": "g9", "parser": "firewall_kv"})],
                 [("store_event", forged)],
                 [("parse_group", {"group_id": "g1", "parser": "firewall_kv"})],     # not this group's format
                 [("commit", {})],
                 Decision(text="Stored evt-forged for attacker."))
    report, store = run([raw_logs.render(EVENT)], llm)
    assert [s["summary"] for s in report["steps"]][1:] == [
        "rejected: invalid arguments", "rejected: unknown parser", "rejected: unknown group", "rejected: unknown tool",
        "rejected: parser does not fit the group", "rejected: nothing to commit"]
    assert not store.batches and not report["stored"] and report["events"] == []
    assert "forged" not in json.dumps({k: v for k, v in report.items() if k != "agent_notes"})
    assert report["agent_notes"] == "Stored evt-forged for attacker."        # kept, as commentary only


def test_model_picks_the_parser_only_for_groups_of_unknown_format():
    both = raw_logs.render(NET) + " event=delivered client=192.0.2.5 rcpt=ceo@bank.example"   # two formats' keys
    assert parsers.detect(both) == "firewall_kv"
    report, store = run([both], Script([("profile_batch", {})], [("parse_group", {"group_id": "g1", "parser": "mail_kv"})],
                                       [("commit", {})]))
    assert not store.batches and report["steps"][1]["summary"] == "rejected: parser does not fit the group"
    odd = "2026-09-07T10:00:00Z gw9 id=evt-9 event=delivered client=192.0.2.5 recipient=ceo dst=10.0.0.5"
    report, store = run([odd], Script([("profile_batch", {})], [("parse_group", {"group_id": "g1", "parser": "mail_kv"})]))
    assert report["groups"][0]["detected_format"] == "unknown" and report["groups"][0]["rejected"] == {"no user": 1}


def test_commit_reports_a_store_that_refuses_the_events():
    def refuse(events):
        raise ValueError("two incidents would get the same id")

    report = process_logs([raw_logs.render(EVENT)], llm=ScriptedIntake(), store=refuse)
    assert report["steps"][-1]["summary"] == "rejected: store refused the events"
    assert not report["stored"] and report["events"] == [] and not report["agent"]["complete"]
    assert "failed" in report["agent_notes"]


def test_a_model_that_stops_early_leaves_an_honest_report():
    idle, store = run([raw_logs.render(EVENT)], Script(Decision(text="All done.")))
    assert not store.batches and idle["unhandled"] == 1 and not idle["agent"]["complete"]
    parsed_only, store = run([raw_logs.render(EVENT)], Script(
        [("profile_batch", {})], [("parse_group", {"group_id": "g1", "parser": "windows_event_json"})],
        Decision(text="Parsed.")))
    assert parsed_only["parsed"] == 1 and not parsed_only["stored"] and parsed_only["events"] == []
    assert not store.batches and not parsed_only["agent"]["complete"]


def test_nothing_changes_after_the_commit_and_a_model_failure_does_not_raise():
    llm = Script([("profile_batch", {})], [("parse_group", {"group_id": "g1", "parser": "windows_event_json"})],
                 [("commit", {})], [("quarantine_group", {"group_id": "g1"})], [("commit", {})])
    report, store = run([raw_logs.render(EVENT)], llm)
    assert [s["summary"] for s in report["steps"]][-2:] == ["rejected: already committed"] * 2
    assert len(store.batches) == 1 and report["events"] == [EVENT]

    class Broken:
        name = "broken"

        def decide(self, system, messages, tool_specs):
            raise RuntimeError("api down")

    report, store = run([raw_logs.render(EVENT)], Broken())
    assert report["agent"]["stop_reason"] == "model_error: RuntimeError" and not report["stored"]


def test_raw_logs_endpoint_runs_agent_1_against_the_graph(graph):
    from test_api import brute_force, cleanup, client
    before = client.get("/health").json()
    lines = [raw_logs.render({**e, "destination_port": None, "byte_count": None})
             for e in brute_force("evt-api-test-raw-")] + ["not a log line"]
    try:
        body = client.post("/logs/raw", json=lines)
        assert body.status_code == 200, body.text
        report = body.json()
        assert report["stored"] and report["parsed"] == 7 and report["quarantined"] == 1
        assert report["ingest"]["events_in_graph"] == before["events"] + 7
        assert report["ingest"]["incidents_touched"] == ["INC-api-test-raw-0"]
        assert sorted({t["technique_id"] for t in report["techniques"]}) == ["T1078", "T1110"]
        assert [s["id"] for s in client.get("/trajectory/INC-api-test-raw-0").json()["techniques"]] == ["T1110", "T1078"]
        assert client.post("/logs/raw", json=[]).status_code == 422
        assert client.post("/logs/raw", json=[5]).status_code == 422
    finally:
        cleanup()
    assert client.get("/health").json() == before


# ---------------------------------------------------------------- Agent 3: the agent step

def test_scripted_writer_reads_the_evidence_and_writes_every_section_in_order():
    result = explain(bundle_for(), llm=ScriptedWriter())
    assert [s["tool"] for s in result["steps"]] == ["read_evidence"] + ["write_section"] * 5
    assert result["sections"] == list(SECTIONS) and result["summary"] == "none"
    assert result["generated_by"] == "template" and result["agent"]["complete"]
    headings = [line for line in result["report"].splitlines() if line.startswith("## ")]
    assert headings == ["## What was observed", "## Similar past attacks", "## Likely next step",
                        "## How this was produced", "## Limits of this report"]


def test_model_chooses_the_order_but_cannot_drop_or_repeat_a_section():
    llm = Script([("read_evidence", {})], [("write_section", {"section": "prediction"})],
                 [("write_section", {"section": "prediction"})], [("write_section", {"section": "verdict"})],
                 [("write_section", {"section": "observed", "text": "## Nothing happened"})],
                 Decision(text=""))
    result = explain(bundle_for(), llm=llm)
    assert result["sections"] == ["prediction", "observed", "matches", "method", "limits"]
    assert [s["summary"] for s in result["steps"]][2:] == [
        "rejected: section already written", "rejected: unknown section", "rejected: invalid arguments"]
    assert "Nothing happened" not in result["report"] and "## Limits of this report" in result["report"]
    assert result["report"].index("## Likely next step") < result["report"].index("## What was observed")


def test_summary_is_kept_only_when_its_ids_and_figures_are_in_the_evidence():
    bundle = bundle_for()
    top = bundle["historical_matches"]["matches"][0]
    good = f"The trajectory ends at T1068 and is closest to {top['attack_id']} at {top['similarity']}."
    assert check_summary(good, bundle) is None
    unsupported = "identifier or number not in the evidence"
    for text in ("This is T1486 ransomware.", "It matches HIST-G9999.", "Also seen in INC-2.",
                 "The match is 97% certain.", "This is t1486 ransomware.", "t1486.002", "hist-g9999", "HIST_G9999",
                 "inc-2", "INC 2", "incident #2", "confidence .97", "p=.97", "x0.97", "conf97%", "1e3 hosts",
                 "0x3e8", "v1000", "\u2460\u2461 hosts", "T1068.001", "\uff34\uff11\uff14\uff18\uff16",
                 "T1068" + "9", "seen \u0664 times"):
        assert check_summary(text, bundle) == unsupported, text
    assert check_summary("x" * 2000, bundle) == "too long"
    fourth = bundle["historical_matches"]["matches"][3]["attack_id"]          # real, but not shown in the report
    assert check_summary(f"Closest to {fourth}.", bundle) == unsupported
    looked_up = bundle_for(llm=Script([("query_graph", {"incident_id": "INC-1"})],
                                      [("lookup_technique", {"technique_id": "T1486"})]))
    assert [t["relation"] for t in looked_up["techniques"]] == ["not_in_evidence"]
    assert check_summary("This incident is T1486 ransomware.", looked_up) == unsupported

    kept = explain(bundle, llm=Script([("read_evidence", {})], Decision(text=good + "\n# <b>not a heading</b>")))
    assert kept["summary"] == "accepted" and kept["generated_by"] == "template sections, summary by mock"
    assert "commentary, not a finding" in kept["report"] and "\\# \\<b\\>not a heading" in kept["report"]
    assert "number written in words were not checked" in kept["report"]
    assert kept["sections"] == list(SECTIONS)                                 # skipped sections were added

    dropped = explain(bundle, llm=Script(Decision(text="This is T1486 ransomware, 97% certain.")))
    assert dropped["summary"] == f"discarded: {unsupported}" and dropped["generated_by"] == "template"
    assert "T1486" not in dropped["report"] and "was discarded" in dropped["report"]

    cut = explain(bundle, llm=Script(Decision(text=good, stop_reason="max_tokens")))
    assert cut["summary"] == "discarded: model did not finish" and not cut["agent"]["complete"]


def test_report_is_the_full_template_when_the_model_fails():
    class Broken:
        name = "broken"

        def decide(self, system, messages, tool_specs):
            raise RuntimeError("api down")

    bundle = bundle_for()
    failed = explain(bundle, llm=Broken())
    assert failed["report"] == explain(bundle, llm=ScriptedWriter())["report"]
    assert failed["agent"]["stop_reason"] == "model_error: RuntimeError" and not failed["agent"]["complete"]


def test_log_text_in_the_evidence_cannot_reach_the_report_unescaped_through_agent_3():
    hostile = [{**EVENTS[0], "user": "<script>x</script>"}]
    bundle = bundle_for(toolset={**fake_tools(), "get_events": lambda incident_id: hostile})
    report = explain(bundle)["report"]
    assert "<script>" not in report and "\\<script\\>" in report


def test_default_policies_are_offline_and_the_claude_adapter_is_shared(monkeypatch):
    import types

    from agents import loop
    monkeypatch.delenv("AGENT_LLM", raising=False)
    assert isinstance(loop.default_llm(ScriptedWriter()), ScriptedWriter) and not loop.llm_requested()

    block = lambda **kw: types.SimpleNamespace(**kw)
    replies = [block(stop_reason="tool_use", content=[block(type="tool_use", id="tu_1", name="read_evidence", input={})]),
               block(stop_reason="end_turn", content=[block(type="text", text="")])]
    sent = []
    fake = types.ModuleType("anthropic")
    fake.Anthropic = lambda: types.SimpleNamespace(messages=types.SimpleNamespace(
        create=lambda **kwargs: (sent.append(kwargs), replies[len(sent) - 1])[1]))
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setenv("AGENT_LLM", "anthropic")
    result = explain(bundle_for())                       # the stand-in SDK, never the real API
    assert result["agent"]["llm"] == "claude-opus-5-5" and result["steps"][0]["tool"] == "read_evidence"
    assert [t["name"] for t in sent[0]["tools"]] == ["read_evidence", "write_section"]
