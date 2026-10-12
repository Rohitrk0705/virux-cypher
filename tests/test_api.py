"""Milestone 8: every endpoint returns real data in the documented shape."""

import re

import pytest
from fastapi.testclient import TestClient

from agents import tools
from backend.api.main import app
from knowledge_graph.connection import run_text

TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVENT_KEYS = ["event_id", "timestamp", "source", "user", "source_ip",
              "destination_ip", "device", "action", "process"]

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def incident(graph):
    """An incident with at least three mapped steps."""
    return next(i["incident_id"] for i in tools.list_incidents()
                if len(tools.query_graph(i["incident_id"])["techniques"]) >= 3)


def test_health_reports_the_loaded_graph(graph):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["neo4j"] is True and body["events"] > 0 and body["incidents"] > 0


def test_incidents_lists_ids_with_iso_times(graph):
    body = client.get("/incidents").json()
    assert body and list(body[0]) == ["incident_id", "start", "end", "event_count"]
    assert all(TS.match(i["start"]) and TS.match(i["end"]) and i["event_count"] >= 2 for i in body)


def test_events_is_contract_1(incident):
    body = client.get(f"/events/{incident}").json()
    assert body and all(list(e) == EVENT_KEYS and TS.match(e["timestamp"]) for e in body)
    assert [e["timestamp"] for e in body] == sorted(e["timestamp"] for e in body)


def test_trajectory_is_contract_3(incident):
    body = client.get(f"/trajectory/{incident}").json()
    assert list(body) == ["incident_id", "techniques"] and body["incident_id"] == incident
    assert len(body["techniques"]) >= 3
    assert all(list(s) == ["id", "timestamp"] and TS.match(s["timestamp"]) for s in body["techniques"])


def test_match_is_contract_4(incident):
    body = client.get(f"/match/{incident}").json()
    assert list(body) == ["incident_id", "matches"] and body["matches"]
    for m in body["matches"]:
        assert list(m) == ["attack_id", "similarity", "common_techniques"] and 0 < m["similarity"] <= 1


def test_predict_is_contract_5(incident):
    body = client.get(f"/predict/{incident}").json()
    assert list(body) == ["incident_id", "predictions", "evidence"] and body["evidence"]
    for p in body["predictions"]:
        assert list(p) == ["technique_id", "probability"] and 0 < p["probability"] <= 1


def test_graph_has_consistent_nodes_and_edges(incident):
    body = client.get(f"/graph/{incident}").json()
    ids = {n["id"] for n in body["nodes"]}
    assert len(ids) == len(body["nodes"])
    assert all(e["source"] in ids and e["target"] in ids for e in body["edges"])
    events = [n for n in body["nodes"] if n["type"] == "event"]
    assert len(events) == len(client.get(f"/events/{incident}").json())
    assert sum(e["type"] == "NEXT" for e in body["edges"]) == len(events) - 1
    assert {n["type"] for n in body["nodes"]} >= {"event", "user", "device", "ip", "technique", "tactic"}


def test_investigate_returns_a_bundle_consistent_with_the_other_endpoints(incident):
    body = client.get(f"/investigate/{incident}").json()
    assert list(body) == ["incident_id", "trajectory", "event_summary", "historical_matches", "prediction",
                          "techniques", "steps", "agent", "agent_notes"]
    assert body["trajectory"] == client.get(f"/trajectory/{incident}").json()
    assert body["historical_matches"] == client.get(f"/match/{incident}").json()
    assert body["agent"]["complete"] is True and body["steps"][0]["tool"] == "query_graph"


def test_explain_returns_a_markdown_report_built_from_the_bundle(incident):
    body = client.get(f"/explain/{incident}").json()
    assert list(body) == ["incident_id", "format", "generated_by", "report"] and body["format"] == "markdown"
    report = body["report"]
    assert report.startswith(f"# Incident {incident}")
    for step in client.get(f"/trajectory/{incident}").json()["techniques"]:
        assert f"`{step['id']}`" in report and step["timestamp"] in report
    top = client.get(f"/match/{incident}").json()["matches"][0]
    assert top["attack_id"] in report and str(top["similarity"]) in report
    assert "Limits of this report" in report


def test_technique_lookup_and_unknown_technique():
    assert client.get("/technique/T1059.001").json()["name"] == "PowerShell"
    assert client.get("/technique/T0000").status_code == 404


@pytest.mark.parametrize("path", ["events", "graph", "trajectory", "match", "predict", "investigate", "explain"])
def test_unknown_incident_is_404(graph, path):
    response = client.get(f"/{path}/INC-does-not-exist")
    assert response.status_code == 404 and "INC-does-not-exist" in response.json()["detail"]


GOOD = {"event_id": "evt-api-test-bad", "timestamp": "2026-09-07T10:00:00Z", "source": "windows", "user": "u",
        "source_ip": "10.0.0.1", "destination_ip": None, "device": "d", "action": "a", "process": None}


def cleanup():
    """Remove everything the POST tests may have created and restore mappings and incidents."""
    from agents.log_agent import refresh
    run_text("MATCH (n) WHERE n.event_id STARTS WITH 'evt-api-test-' OR n.event_id STARTS WITH 'apitest' "
             "OR n.name IN ['api_test_user', 'API-TEST-01'] OR n.address STARTS WITH '100.64.250.' "
             "OR n.address STARTS WITH '10.250.' DETACH DELETE n")
    refresh()


@pytest.mark.parametrize("change", [
    {"extra": 1},
    {"timestamp": "yesterday"},
    {"timestamp": "0000-01-01T00:00:00Z"},          # year the graph cannot round-trip
    {"timestamp": "2026-13-45T99:99:99Z"},
    {"timestamp": "2026-02-30T00:00:00Z"},
    {"timestamp": "2026-06-30T23:59:60Z"},
    {"user": None},
    {"user": "x" * 9000},
    {"action": " "},
    {"device": "two\nlines"},
    {"destination_ip": ""},
    {"process": ""},
    {"event_id": "evt-api-test/b?c#d"},
    {"event_id": "evt api test"},
    {"event_id": "e" * 200},
    {"source_ip": 5},
])
def test_logs_rejects_events_that_break_contract_1(graph, change):
    before = client.get("/health").json()
    response = client.post("/logs", json=[{**GOOD, **change}])
    assert response.status_code == 422, response.text
    assert isinstance(response.json()["detail"], str) and len(response.json()["detail"]) < 1000
    assert client.get("/health").json() == before


def test_logs_rejects_malformed_bodies(graph):
    assert client.post("/logs", json=[]).status_code == 422
    assert client.post("/logs", json=[{k: v for k, v in GOOD.items() if k != "process"}]).status_code == 422
    duplicate = client.post("/logs", json=[GOOD, GOOD])
    assert duplicate.status_code == 422 and duplicate.json()["detail"] == "duplicate event_id in request"
    assert client.post("/logs", json={"not": "a list"}).status_code == 422


def brute_force(prefix, user="api_test_user"):
    stamp = lambda second: f"2020-01-01T00:00:{second:02d}Z"
    base = {"source": "windows", "user": user, "source_ip": "100.64.250.1",
            "destination_ip": "10.250.0.1", "device": "API-TEST-01", "process": None}
    events = [{**base, "event_id": f"{prefix}{n}", "timestamp": stamp(n * 5), "action": "logon_failure"}
              for n in range(6)]
    return events + [{**base, "event_id": f"{prefix}6", "timestamp": stamp(40), "action": "logon_success"}]


def test_logs_ingests_maps_and_groups_new_events(graph):
    """Post a small brute-force-then-logon sequence in an unused time range and
    check it comes back as an incident with a trajectory; then remove it."""
    before = client.get("/health").json()
    try:
        result = client.post("/logs", json=brute_force("evt-api-test-"))
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["received"] == 7 and body["events_in_graph"] == before["events"] + 7
        assert body["incidents_touched"] == ["INC-api-test-0"]
        assert [s["id"] for s in client.get("/trajectory/INC-api-test-0").json()["techniques"]] == ["T1110", "T1078"]
        assert len(client.get("/events/INC-api-test-0").json()) == 7
        assert client.get("/incidents").json()[0]["incident_id"] == "INC-api-test-0"     # oldest first

        again = brute_force("evt-api-test-")[:1]                                          # same id: replaced
        again[0]["action"] = "logoff"
        upsert = client.post("/logs", json=again).json()
        assert upsert["events_in_graph"] == before["events"] + 7
        stored = run_text("MATCH (e:Event {event_id: 'evt-api-test-0'}) RETURN e.action AS action")
        assert stored == [{"action": "logoff"}]
    finally:
        cleanup()
    assert client.get("/health").json() == before


def test_event_ids_without_the_evt_prefix_give_reachable_incidents(graph):
    before = client.get("/health").json()
    try:
        body = client.post("/logs", json=brute_force("apitest:a.")).json()
        assert body["incidents_touched"] == ["INC-apitest:a.0"]
        assert client.get("/trajectory/INC-apitest:a.0").status_code == 200
        assert client.get("/graph/INC-apitest:a.0").status_code == 200
    finally:
        cleanup()
    assert client.get("/health").json() == before


def test_a_failed_ingest_changes_nothing(graph, monkeypatch):
    """If anything fails after the events are written, the whole request rolls back."""
    from core.attack_mapper import AttackMapper

    before = client.get("/health").json()
    listed = client.get("/incidents").json()

    def explode(self, events):
        raise RuntimeError("mapper failure")

    monkeypatch.setattr(AttackMapper, "map_events", explode)
    response = client.post("/logs", json=brute_force("evt-api-test-"))
    assert response.status_code == 500 and response.json() == {"detail": "internal error"}
    monkeypatch.undo()
    assert run_text("MATCH (e:Event) WHERE e.event_id STARTS WITH 'evt-api-test-' RETURN count(e) AS n")[0]["n"] == 0
    assert client.get("/health").json() == before and client.get("/incidents").json() == listed


def test_health_is_ok_with_zero_incidents(graph, monkeypatch):
    from knowledge_graph import config
    monkeypatch.setattr(config, "DEFAULT_METHOD", "no-such-method")
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["neo4j"] is True and body["incidents"] == 0 and body["events"] > 0


def test_post_requires_the_token_when_one_is_configured(graph, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "s3cret")
    assert client.post("/logs", json=[GOOD]).status_code == 401
    assert client.post("/logs", json=[{**GOOD, "extra": 1}], headers={"X-API-Token": "s3cret"}).status_code == 422
    assert client.get("/health").status_code == 200          # reads stay open


def test_only_notfound_becomes_404(graph, monkeypatch):
    """A stray KeyError or IndexError inside a handler is a bug, not a missing incident."""
    from agents import tools as agent_tools

    def bug(incident_id):
        raise IndexError("list index out of range")

    monkeypatch.setattr(agent_tools, "get_events", bug)
    response = client.get("/events/INC-anything")
    assert response.status_code == 500 and response.json() == {"detail": "internal error"}
