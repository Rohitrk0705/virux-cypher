import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session")
def graph():
    """A live Neo4j with the dataset loaded; tests needing it are skipped otherwise."""
    try:
        from knowledge_graph.connection import get_driver, run_text
        get_driver()
        if run_text("MATCH (e:Event) RETURN count(e) AS n")[0]["n"] == 0:
            pytest.skip("graph is empty; run python -m knowledge_graph.build")
    except Exception as exc:  # noqa: BLE001 - any connection failure means skip
        pytest.skip(f"Neo4j not available: {exc}")
