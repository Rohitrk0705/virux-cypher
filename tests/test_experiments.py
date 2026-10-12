"""Milestone 6: experiment helpers (the experiments themselves are run, not unit-tested)."""

from experiments import e3_discrimination as e3
from experiments.common import markdown_table


def test_three_way_classification_and_threshold_fit():
    samples = [(1.0, "known"), (0.96, "known"), (0.8, "variant"), (0.7, "variant"), (0.3, "novel"), (0.2, "novel")]
    t_variant, t_known = e3.fit(samples)
    assert [e3.classify(s, t_variant, t_known) for s, _ in samples] == [c for _, c in samples]
    assert 0.3 < t_variant <= 0.7 and 0.8 < t_known <= 0.96


def test_auc_and_true_class():
    assert e3.auc([0.9, 0.8], [0.1, 0.2]) == 1.0 and e3.auc([0.5], [0.5]) == 0.5
    assert e3.true_class({"pattern": "D", "variant": "base"}) == "novel"
    assert e3.true_class({"pattern": "A", "variant": "base"}) == "known"
    assert e3.true_class({"pattern": "B", "variant": "skip"}) == "variant"


def test_markdown_table_formats_floats_and_missing_values():
    text = markdown_table(["a", "b"], [{"a": 0.5, "b": None}, {"a": 3}])
    assert text.splitlines()[2] == "| 0.500 |  |" and text.splitlines()[3] == "| 3 |  |"
