"""Milestone 2: loader, incident inference, trajectories, evaluation."""

import re

import pytest

from evaluation import incident_match
from knowledge_graph import config, loader
from knowledge_graph.connection import load_query, run, run_text
from temporal import incidents
from temporal.trajectory import collapse, get_trajectory

TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVENT_KEYS = ["event_id", "timestamp", "source", "user", "source_ip",
              "destination_ip", "device", "action", "process", "destination_port", "byte_count"]


def test_connected_components():
    groups = incidents.connected_components(["a", "b", "c", "d", "e"], [("a", "b"), ("b", "c")])
    assert sorted(groups) == [["a", "b", "c"], ["d"], ["e"]]


def test_incident_id_is_derived_from_first_event():
    assert incidents.incident_id_for("evt-00138") == "INC-00138"


def test_collapse_keeps_first_timestamp_and_order():
    out = collapse([("T1110", 0), ("T1110", 5), ("T1078", 60), ("T1110", 120)])
    assert [t["id"] for t in out] == ["T1110", "T1078", "T1110"]
    assert out[0]["timestamp"] == "1970-01-01T00:00:00Z"


TRUTH = [{"incident_id": "GT-1", "pattern": "A", "variant": "base", "pace": "fast",
          "techniques": ["T1", "T2"], "event_ids": ["e1", "e2", "e3"]}]
STAMPS = {"e1": 1, "e2": 2, "e3": 3, "b1": 4, "b2": 5}
TECH = {"e1": "T1", "e2": "T2", "e3": "T2"}


def test_score_perfect():
    s = incident_match.score(TRUTH, [{"incident_id": "I1", "event_ids": ["e1", "e2", "e3"]}], STAMPS, TECH)
    assert s["exact"] == 1 and s["trajectory_gt"] == 1
    assert s["attack_pair_f1"] == 1.0 and s["pair_precision"] == 1.0 and s["incident_precision"] == 1.0


def test_score_split_counts_fragments_and_unassigned():
    s = incident_match.score(TRUTH, [{"incident_id": "I1", "event_ids": ["e1", "b1"]}], STAMPS, TECH)
    p = s["per_incident"][0]
    assert p["fragments"] == 1 and p["unassigned"] == 2 and not p["exact"]
    assert s["attack_pair_recall"] == 0.0


def test_score_benign_members_lower_pair_precision_and_false_incidents_are_counted():
    inferred = [{"incident_id": "I1", "event_ids": ["e1", "e2", "e3", "b1"]},
                {"incident_id": "I2", "event_ids": ["b1x", "b2"]}]
    s = incident_match.score(TRUTH, inferred, {**STAMPS, "b1x": 9}, TECH)
    assert s["attack_pair_precision"] == 1.0
    assert s["pair_precision"] == 3 / 6          # 3 attack pairs, 3 attack-benign pairs
    assert s["false_incidents"] == 1 and s["incident_precision"] == 0.5


def test_score_pairing_is_one_to_one_and_no_overlap_scores_zero():
    truth = TRUTH + [{"incident_id": "GT-2", "pattern": "B", "variant": "base", "pace": "fast",
                      "techniques": ["T9"], "event_ids": ["x1", "x2"]}]
    merged = [{"incident_id": "I1", "event_ids": ["e1", "e2", "e3", "x1", "x2"]}]
    s = incident_match.score(truth, merged, {**STAMPS, "x1": 7, "x2": 8}, {**TECH, "x1": "T9", "x2": "T9"})
    matched = [p["match"] for p in s["per_incident"]]
    assert matched.count("I1") == 1 and matched.count(None) == 1
    loser = next(p for p in s["per_incident"] if p["match"] is None)
    assert loser["coverage"] == 0 and not loser["trajectory_gt"]
    assert s["merged_incidents"] == 1


def test_heuristic_queries_do_not_touch_labels_or_ground_truth():
    import inspect
    for name in ("candidates_heuristic", "candidate_links", "mark_entities"):
        text = load_query(name)
        assert "MAPS_TO" not in text and "Technique" not in text and "Incident" not in text
    source = inspect.getsource(incidents)
    assert "INCIDENTS_FILE" not in source and "incidents.json" not in source.replace(
        "incidents.json is never", "")


def test_loader_rejects_missing_required_field():
    with pytest.raises(ValueError, match="source_ip"):
        loader.load_events([{"event_id": "evt-x", "timestamp": "2026-01-01T00:00:00Z",
                             "source": "windows", "user": "u", "source_ip": None,
                             "destination_ip": None, "device": "d", "action": "a", "process": None}])


def test_loader_is_idempotent(graph):
    before = loader.graph_stats()
    loader.load_files()
    for method in (config.METHOD_HEURISTIC, config.METHOD_LABELS):
        incidents.materialize(method)
    assert loader.graph_stats() == before


def test_reloading_a_changed_event_replaces_it(graph):
    base = {"event_id": "evt-test-upsert", "timestamp": "2020-01-01T00:00:00Z", "source": "windows",
            "user": "test_user_1", "source_ip": "10.9.9.1", "destination_ip": "10.9.9.2",
            "device": "TEST-01", "action": "process_execution", "process": "one.exe"}
    try:
        run("load_events", rows=[base])
        run("load_events", rows=[{**base, "user": "test_user_2", "source_ip": "10.9.9.3",
                                  "destination_ip": None, "process": None}])
        row = run_text(
            "MATCH (e:Event {event_id: 'evt-test-upsert'}) "
            "RETURN [(u:User)-[:PERFORMED]->(e) | u.name] AS users, "
            "[(e)-[:INVOLVES]->(i) | i.address] AS ips, "
            "[(e)-[:EXECUTED]->(p) | p.name] AS processes")[0]
        assert row == {"users": ["test_user_2"], "ips": ["10.9.9.3"], "processes": []}
    finally:
        run_text("MATCH (n) WHERE n.event_id = 'evt-test-upsert' OR n.name IN "
                 "['test_user_1', 'test_user_2', 'TEST-01', 'one.exe'] "
                 "OR n.address STARTS WITH '10.9.9.' DETACH DELETE n")


def test_heuristic_inference_does_not_depend_on_mappings(graph):
    """Removing every technique mapping must not change heuristic incidents."""
    with_mappings = incidents.infer_incidents(config.METHOD_HEURISTIC)
    saved = run_text("MATCH (e:Event)-[m:MAPS_TO]->(t:Technique) "
                     "RETURN e.event_id AS e, t.technique_id AS t, m.source AS s, m.confidence AS c")
    try:
        run_text("MATCH ()-[m:MAPS_TO]->() DELETE m")
        assert incidents.infer_incidents(config.METHOD_HEURISTIC) == with_mappings
    finally:
        run_text("UNWIND $rows AS r MATCH (e:Event {event_id: r.e}), (t:Technique {technique_id: r.t}) "
                 "MERGE (e)-[m:MAPS_TO {source: r.s}]->(t) SET m.confidence = r.c", rows=saved)


def test_next_edges_run_forward_in_time(graph):
    rows = run_text("MATCH (a:Event)-[n:NEXT]->(b:Event) "
                    "RETURN count(*) AS n, min(n.delta_seconds) AS lo, "
                    "sum(CASE WHEN b.ts - a.ts = n.delta_seconds THEN 0 ELSE 1 END) AS wrong")
    assert rows[0]["n"] > 0 and rows[0]["lo"] >= 0 and rows[0]["wrong"] == 0


def test_trajectory_matches_contract_and_next_order(graph):
    method = config.METHOD_LABELS
    listed = incidents.list_incidents(method)
    assert listed
    for inc in listed:
        t = get_trajectory(inc["incident_id"], method, config.SOURCE_GROUND_TRUTH)
        assert list(t) == ["incident_id", "techniques"]
        assert t["techniques"], "a labels-method incident always has techniques"
        for step in t["techniques"]:
            assert list(step) == ["id", "timestamp"] and TS.match(step["timestamp"])
        stamps = [s["timestamp"] for s in t["techniques"]]
        assert stamps == sorted(stamps)
        ids = [s["id"] for s in t["techniques"]]
        assert all(a != b for a, b in zip(ids, ids[1:])), "consecutive repeats collapsed"
        assert t == get_trajectory(inc["incident_id"], method, config.SOURCE_GROUND_TRUTH, via_next=True)


def test_unknown_incident_raises(graph):
    with pytest.raises(LookupError):
        get_trajectory("INC-does-not-exist")
    with pytest.raises(LookupError):
        incidents.get_incident_events("INC-does-not-exist")


def test_incident_events_match_contract_1(graph):
    inc = incidents.list_incidents(config.METHOD_LABELS)[0]
    events = incidents.get_incident_events(inc["incident_id"], config.METHOD_LABELS)
    assert len(events) == inc["event_count"]
    for e in events:
        assert list(e) == EVENT_KEYS and TS.match(e["timestamp"])
