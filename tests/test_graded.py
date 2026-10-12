"""Milestone 10: the graded dataset and the redesigned experiments' building blocks."""

import importlib.util
import json
import random
from pathlib import Path

from prediction.historical import to_sequence
from prediction.similarity import match_historical, similarity

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("virux_generate_test", ROOT / "data" / "generator" / "generate.py")
generate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate)


def test_templates_have_the_intended_relations():
    t = {name: steps for name, (_, steps) in generate.GRADED_TEMPLATES.items()}
    assert len(t) == 18 and all(steps[0] in {"T1078", "T1566.001", "T1110", "T1133"} for steps in t.values())
    assert set(t["G12"]) == set(t["G01"]) and t["G12"] != t["G01"]            # same techniques, new order
    assert set(t["G13"]) == set(t["G04"]) and t["G13"] != t["G04"]
    assert t["G02"][:len(t["G01"])] == t["G01"]                                # shared prefix (extension)
    assert t["G08"][-2:] == t["G01"][-2:] and t["G10"][-2:] == t["G07"][-2:]   # shared suffixes across families
    assert all(tech in generate.TECHNIQUES for steps in t.values() for tech in steps)
    static = lambda a, b: similarity(to_sequence(t[a]), to_sequence(t[b]), mode="static")
    assert static("G01", "G12") == 1.0 and similarity(to_sequence(t["G01"]), to_sequence(t["G12"])) < 1.0
    assert static("G17", "G01") == 0.0                                         # genuinely unrelated


def test_perturbation_levels_edit_the_sequence_as_promised():
    rng = random.Random(7)
    for name, (_, base) in generate.GRADED_TEMPLATES.items():
        foothold = next(i for i, x in enumerate(base) if x in generate.GRADED_FOOTHOLDS)
        for level, edits in (("exact", 0), ("light", 1), ("heavy", 2)):
            for _ in range(20):
                seq, log = generate.perturb(rng, base, level)
                assert len(log) == edits and (seq == base) == (edits == 0)
                assert seq[:foothold + 1] == base[:foothold + 1]              # never before the foothold
                assert all(a != b for a, b in zip(seq, seq[1:]))
                others = [steps for other, (_, steps) in generate.GRADED_TEMPLATES.items() if other != name]
                if edits:
                    assert seq not in others                                  # never another template
                if edits == 1:
                    assert tuple(seq) in generate.one_edit_away(base)
                if edits == 2:
                    assert tuple(seq) not in generate.one_edit_away(base)     # two edits that one could not do


def test_graded_dataset_is_deterministic_and_well_formed(tmp_path):
    events, labels, truth = generate.assemble(42, "graded")
    again = generate.assemble(42, "graded")
    assert json.dumps([events, labels, truth]) == json.dumps(list(again))
    generate.validate(events, labels, truth)
    assert len(truth) == 90 and len({t["pattern"] for t in truth}) == 18
    for template in generate.GRADED_TEMPLATES:
        levels = sorted(t["variant"] for t in truth if t["pattern"] == template)
        assert levels == ["exact", "heavy", "heavy", "light", "light"]
    exact = [t for t in truth if t["variant"] == "exact"]
    assert all(t["techniques"] == generate.GRADED_TEMPLATES[t["pattern"]][1] and t["edits"] == [] for t in exact)
    assert all(t["techniques"] != generate.GRADED_TEMPLATES[t["pattern"]][1] for t in truth if t["variant"] != "exact")


def test_old_profiles_do_not_see_graded_fields():
    _, _, truth = generate.assemble(42, "noisy")
    assert len(truth) == 24 and "family" not in truth[0] and {t["pattern"] for t in truth} == set("ABCD")


def test_match_against_supplied_records():
    records = [{"attack_id": "X", "sequence": ["T1078", "T1059", "T1068"]},
               {"attack_id": "Y", "sequence": ["T1068", "T1059", "T1078"]}]
    trajectory = {"incident_id": "INC-1", "techniques": [{"id": t, "timestamp": ""} for t in
                                                         ("T1078", "T1059.001", "T1068")]}
    temporal = match_historical(trajectory, records=records)["matches"]
    assert [m["attack_id"] for m in temporal] == ["X", "Y"] and temporal[0]["similarity"] == 1.0
    static = match_historical(trajectory, records=records, mode="static")["matches"]
    assert [m["similarity"] for m in static] == [1.0, 1.0]                     # order ignored: a tie


def test_e3_classes_and_emulation_plans():
    from experiments import graded
    assert graded.e3_class({"pattern": "G02", "variant": "exact"}) == "novel"      # held-out template
    assert graded.e3_class({"pattern": "G01", "variant": "exact"}) == "exact"
    assert graded.e3_class({"pattern": "G01", "variant": "light"}) == "known"
    assert graded.e3_class({"pattern": "G01", "variant": "heavy"}) == "variant"
    assert len(graded.REAL_PLANS) == 8 and all(len(p) >= 15 for p in graded.REAL_PLANS)
    assert set(graded.NEAR_NOVEL) < set(graded.HELD_OUT) and len(graded.HELD_OUT) == 6
    entry = {"pattern": "G01", "variant": "light", "techniques": ["T1078"]}
    assert graded.REFERENCE["G01"] not in graded.history(entry, "other templates")
    assert graded.REFERENCE["G01"] in graded.history(entry, "all templates (own included)")
    assert len(graded.history(entry, "other templates")) == 17
