"""
Graph database backend configuration.

This module provides a simple mechanism to switch between Neo4j and Memgraph
graph database backends. The backend setting controls Cypher query generation
and driver configuration throughout cartography.

Supported backends:
- "neo4j" (default): Standard Neo4j graph database
- "memgraph": Memgraph graph database (compatible via Bolt protocol)
"""

_graph_backend: str = "neo4j"

VALID_BACKENDS = ("neo4j", "memgraph")


def set_graph_backend(backend: str) -> None:
    """Set the graph database backend. Must be called before any queries are built."""
    global _graph_backend
    if backend not in VALID_BACKENDS:
        raise ValueError(
            f"Invalid graph backend '{backend}'. Must be one of: {', '.join(VALID_BACKENDS)}",
        )
    _graph_backend = backend


def get_graph_backend() -> str:
    """Return the current graph database backend name."""
    return _graph_backend


def is_memgraph() -> bool:
    """Return True if the current backend is Memgraph."""
    return _graph_backend == "memgraph"


def patch_cypher_for_memgraph(query: str) -> str:
    """Replace Neo4j-specific Cypher functions with Memgraph equivalents in a query string.

    Currently handles:
    - ``timestamp()`` → inline epoch milliseconds value (Memgraph has no timestamp function)

    This is used by ``run_write_query`` to transparently fix handwritten queries in intel modules.
    """
    if _graph_backend != "memgraph":
        return query
    import time
    return query.replace("timestamp()", str(int(time.time() * 1000)))
