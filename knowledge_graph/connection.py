"""Neo4j connection and Cypher file loading."""

from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from neo4j import GraphDatabase

from . import config

QUERY_DIR = Path(__file__).resolve().parent / "queries"
SCHEMA_FILE = Path(__file__).resolve().parent / "ontology" / "schema.cypher"


@lru_cache(maxsize=1)
def get_driver():
    driver = GraphDatabase.driver(
        config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD)
    )
    driver.verify_connectivity()
    return driver


@lru_cache(maxsize=None)
def load_query(name):
    """Return the Cypher text of knowledge_graph/queries/<name>.cypher."""
    return (QUERY_DIR / f"{name}.cypher").read_text()


def run(name, **params):
    """Run a named query file and return its records as a list of dicts."""
    result = get_driver().execute_query(load_query(name), parameters_=params)
    return [record.data() for record in result.records]


@contextmanager
def transaction():
    """One write transaction. Yields run(name, **params) with the same interface
    as the module-level run(); everything commits together or not at all, and
    readers keep seeing the previous state until the commit."""
    with get_driver().session() as session:
        tx = session.begin_transaction()

        def tx_run(name, **params):
            return [record.data() for record in tx.run(load_query(name), params)]

        try:
            yield tx_run
            tx.commit()
        except BaseException:
            tx.rollback()
            raise


class NotFound(LookupError):
    """An incident or technique that does not exist (HTTP 404 at the API)."""


def run_text(cypher, **params):
    result = get_driver().execute_query(cypher, parameters_=params)
    return [record.data() for record in result.records]


def statements(path):
    """Split a .cypher file into statements, dropping // comment lines."""
    lines = [ln for ln in path.read_text().splitlines() if not ln.strip().startswith("//")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]
