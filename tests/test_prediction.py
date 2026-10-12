"""Milestones 4 and 5: historical DB, similarity, Markov prediction, harness."""

import json

from evaluation import prediction_eval
from prediction import historical as hist
from prediction.markov import END, MarkovPredictor, predict_next
from prediction.similarity import edit_distance, jaccard, match_historical, similarity
from prediction.static import StaticPredictor


def traj(*ids, incident_id="INC-00001"):
    return {"incident_id": incident_id,
            "techniques": [{"id": t, "timestamp": "2026-09-07T10:00:00Z"} for t in ids]}


def test_to_sequence_folds_subtechniques_and_collapses():
    assert hist.to_sequence(["T1059.001", "T1059.003", "T1068", "T1059.001"]) == ["T1059", "T1068", "T1059"]


def test_historical_db_is_reproducible_and_documents_ordering():
    records = hist.build()
    assert records == json.loads(hist.HISTORICAL_FILE.read_text())
    assert len({r["attack_id"] for r in records}) == len(records)
    for r in records:
        expected = "hand_specified" if r["source"] == hist.SOURCE_CURATED else "inferred_from_tactic_order"
        assert r["ordering"] == expected and len(r["sequence"]) >= 2
    roles = [r["reference"] for r in records if r["source"] == hist.SOURCE_CURATED]
    assert not any("pattern D" in role for role in roles), "pattern D must stay novel"


def test_similarity_basics():
    a = ["T1078", "T1059", "T1068", "T1021"]
    assert edit_distance(a, a) == 0 and edit_distance(a, a[:-1]) == 1 and edit_distance([], a) == 4
    assert jaccard(a, a[::-1]) == 1.0
    assert similarity(a, a) == 1.0
    assert similarity(a, a[::-1], mode="static") == 1.0       # order ignored
    assert similarity(a, a[::-1]) < 1.0                       # order matters
    assert similarity(a, ["T9999"]) == 0.0


def test_match_historical_is_contract_4():
    out = match_historical(traj("T1078", "T1059.001", "T1068", "T1021.001"))
    assert list(out) == ["incident_id", "matches"] and out["incident_id"] == "INC-00001"
    assert out["matches"][0]["attack_id"] == "HIST-C01" and out["matches"][0]["similarity"] == 1.0
    assert out["matches"][0]["common_techniques"] == ["T1078", "T1059.001", "T1068", "T1021.001"]
    sims = [m["similarity"] for m in out["matches"]]
    assert sims == sorted(sims, reverse=True)
    for m in out["matches"]:
        assert list(m) == ["attack_id", "similarity", "common_techniques"] and 0 < m["similarity"] <= 1
    assert match_historical(traj())["matches"] == []
    assert match_historical(traj("T1078", "T1059.001"), top_k=-1)["matches"] == []
    excluded = match_historical(traj("T1078", "T1059.001", "T1068", "T1021.001"), exclude=["HIST-C01"])
    assert all(m["attack_id"] != "HIST-C01" for m in excluded["matches"])


def test_historical_ids_are_stable_not_positional():
    ids = {r["attack_id"]: r for r in hist.build()}
    assert ids["HIST-C01"]["reference"] == "known pattern A"
    assert all(k == f"HIST-{r['reference']}" for k, r in ids.items() if r["source"] == hist.SOURCE_GROUP)


def test_markov_counts_and_backoff():
    model = MarkovPredictor([["A", "B", "C"], ["A", "B", "C"], ["A", "B", "D"], ["X", "B", "E"]])
    ranked, info = model.rank(["A", "B"])
    assert info["kind"] == "context" and info["order"] == 2 and info["total"] == 3
    assert ranked[0] == ("C", 2 / 3) and ranked[1] == ("D", 1 / 3)
    ranked, info = model.rank(["X", "B"])          # 2-step context seen once -> back off
    assert info["order"] == 1 and ranked[0] == ("C", 0.5)
    ranked, info = model.rank(["Z"])               # step never seen -> overall frequency
    assert info["kind"] == "unseen" and abs(sum(p for _, p in ranked) - 1) < 1e-9
    assert MarkovPredictor([]).rank(["A"])[0] == []


def test_markov_knows_terminal_steps_and_starts():
    model = MarkovPredictor([["A", "B"], ["A", "B", "C"], ["Q", "C"]])
    ranked, info = model.rank(["C"])               # C only ever ends a sequence
    assert info["kind"] == "context" and info["outcomes"][END] == 2 and ranked == []
    text = " ".join(model.evidence(info))
    assert "2 of those 2 were the last step" in text and "no next step is predicted" in text
    ranked, info = model.rank(["B"])               # B ends one sequence and continues one
    assert ranked == [("C", 0.5)] and info["total"] == 2
    ranked, info = model.rank([])
    assert info["kind"] == "start" and ranked[0] == ("A", 2 / 3)
    assert "2 of 3" in model.evidence(info)[0]


def test_evidence_numbers_are_true():
    sequences = [["A", "B", "C"], ["A", "B", "C"], ["A", "B", "D"], ["B", "C"], ["Z", "A", "B"]]
    model = MarkovPredictor(sequences)
    ranked, info = model.rank(["A", "B"])
    occurrences = sum(1 for s in sequences for i in range(len(s) - 1) if s[i:i + 2] == ["A", "B"])
    containing = sum(1 for s in sequences if any(s[i:i + 2] == ["A", "B"] for i in range(len(s) - 1)))
    followed_by_c = sum(1 for s in sequences for i in range(len(s) - 2) if s[i:i + 3] == ["A", "B", "C"])
    lines = model.evidence(info)
    assert lines[0] == f"the last 2 step(s) A > B occur {occurrences} time(s) in {containing} of 5 historical trajectories"
    assert lines[1] == f"{followed_by_c} of those {occurrences} were followed by C"
    assert lines[2] == "1 of those 4 were the last step of their trajectory"


def test_predict_next_is_contract_5():
    out = predict_next(traj("T1078", "T1059.001", "T1068"))
    assert list(out) == ["incident_id", "predictions", "evidence"]
    assert out["predictions"][0]["technique_id"] == "T1021"
    for p in out["predictions"]:
        assert list(p) == ["technique_id", "probability"] and 0 < p["probability"] <= 1
    probabilities = [p["probability"] for p in out["predictions"]]
    assert probabilities == sorted(probabilities, reverse=True)
    assert out["evidence"] and all(isinstance(line, str) for line in out["evidence"])


def test_predict_next_edge_cases_keep_the_contract_and_tell_the_truth():
    done = predict_next(traj("T1078", "T1059.001", "T1068", "T1021.001", "T1041"))
    assert list(done) == ["incident_id", "predictions", "evidence"] and done["predictions"] == []
    assert any("last step of their trajectory" in line for line in done["evidence"])
    assert not any("do not contain" in line or "does not occur" in line for line in done["evidence"])
    empty = predict_next(traj())
    assert empty["predictions"] and "trajectory is empty" in empty["evidence"][0]
    unknown = predict_next(traj("T9999"))
    assert "does not occur" in unknown["evidence"][0]
    custom = predict_next(traj("T1078"), predictor=MarkovPredictor([["T1078", "T1059"]]))
    assert not any("closest historical attack" in line for line in custom["evidence"])


def test_static_predictor_ignores_order_and_skips_seen():
    model = StaticPredictor([["A", "B", "C"], ["C", "B", "A"]])
    ranked, _ = model.rank(["A", "B"])
    assert [t for t, _ in ranked] == ["C"]


def test_harness_metrics_on_a_known_case():
    entries = [{"gt_id": "g1", "pattern": "A", "variant": "base", "techniques": ["A", "B", "C"]},
               {"gt_id": "g2", "pattern": "B", "variant": "base", "techniques": ["A", "B", "D"]},
               {"gt_id": "g3", "pattern": "B", "variant": "base", "techniques": None},
               {"gt_id": "g4", "pattern": "B", "variant": "base", "techniques": ["A"]}]
    build = lambda extra, held=(): MarkovPredictor([["A", "B", "C"]] + list(extra))
    m = prediction_eval.evaluate(entries, build, "history_only")
    assert m["instances"] == 4 and m["incidents"] == 2
    assert m["no_trajectory"] == 1 and m["single_step"] == 1
    assert m["top1"] == 3 / 4 and m["correct"] == 3      # only B -> D is missed
    assert m["mrr"] == 3 / 4                             # D is never ranked: reciprocal rank 0


def test_tie_aware_top1_removes_alphabetical_luck():
    entries = [{"gt_id": "g1", "pattern": "A", "variant": "base", "techniques": ["A", "B"]}]
    build = lambda extra, held=(): MarkovPredictor([["A", "B"], ["A", "C"]])
    m = prediction_eval.evaluate(entries, build, "history_only")
    assert m["top1"] == 1.0 and m["top1_tie"] == 0.5


def test_leave_family_out_drops_incidents_and_references_of_the_whole_family():
    seen = []
    def build(extra, held=()):
        seen.append((sorted(tuple(s) for s in extra), tuple(held)))
        return MarkovPredictor(extra)
    entries = [{"gt_id": "g1", "pattern": "A", "variant": "base", "techniques": ["A", "B"]},
               {"gt_id": "g2", "pattern": "C", "variant": "base", "techniques": ["A", "C"]},
               {"gt_id": "g3", "pattern": "B", "variant": "base", "techniques": ["X", "Y"]}]
    prediction_eval.evaluate(entries, build, "leave_family_out")
    assert seen[0] == ([("X", "Y")], ("A", "C")) and seen[1] == ([("X", "Y")], ("A", "C"))
    assert seen[2] == ([("A", "B"), ("A", "C")], ("B",))


def test_held_out_reference_is_really_removed_from_the_history():
    full = prediction_eval.history_sequences([hist.SOURCE_CURATED])
    without = prediction_eval.history_sequences([hist.SOURCE_CURATED], held_out=("A", "C"))
    assert len(full) - len(without) == 2
    assert ["T1078", "T1059", "T1068", "T1021"] in full and ["T1078", "T1059", "T1068", "T1021"] not in without


def test_end_to_end_counts_every_true_transition():
    truth = [{"gt_id": "g1", "pattern": "A", "variant": "base", "techniques": ["A", "B", "C"]}]
    build = lambda extra, held=(): MarkovPredictor([["A", "B", "C"]])
    exact = prediction_eval.evaluate_end_to_end(truth, [{"gt_id": "g1", "techniques": ["A", "B", "C"]}], build)
    assert exact == {"instances": 2, "path_reproduced": 2, "correct": 2, "top1": 1.0}
    broken = prediction_eval.evaluate_end_to_end(truth, [{"gt_id": "g1", "techniques": ["A", "X", "C"]}], build)
    assert broken["instances"] == 2 and broken["path_reproduced"] == 1 and broken["correct"] == 1
    missing = prediction_eval.evaluate_end_to_end(truth, [{"gt_id": "g1", "techniques": None}], build)
    assert missing["correct"] == 0 and missing["instances"] == 2
