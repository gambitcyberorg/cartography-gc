import logging
import re
from typing import List

import neo4j

from cartography.client.core.tx import run_write_query
from cartography.config import Config
from cartography.graph.backend import is_memgraph
from cartography.util import load_resource_binary

logger = logging.getLogger(__name__)

# Regex to convert Neo4j index syntax to Memgraph index syntax:
# Neo4j:   CREATE INDEX IF NOT EXISTS FOR (n:Label) ON (n.property);
# Memgraph: CREATE INDEX ON :Label(property);
_NEO4J_INDEX_RE = re.compile(
    r"CREATE INDEX IF NOT EXISTS FOR \(n:(\w+)\) ON \(n\.(\w+)\);",
)


def _convert_to_memgraph_index(statement: str) -> str | None:
    """Convert a Neo4j CREATE INDEX statement to Memgraph syntax.

    Returns the converted statement, or None if the statement cannot be converted
    (e.g. relationship indexes which Memgraph does not support in this form).
    """
    match = _NEO4J_INDEX_RE.match(statement)
    if match:
        label, prop = match.groups()
        return f"CREATE INDEX ON :{label}({prop});"
    logger.debug("Skipping non-convertible index statement for Memgraph: %s", statement)
    return None


def get_index_statements() -> List[str]:
    statements = []
    with load_resource_binary("cartography.data", "indexes.cypher") as f:
        for line in f.readlines():
            statements.append(
                line.decode("UTF-8").rstrip("\r\n"),
            )
    return statements


def run(neo4j_session: neo4j.Session, config: Config) -> None:
    logger.info("Creating indexes for cartography node types.")
    for statement in get_index_statements():
        if not statement.strip():
            continue
        if is_memgraph():
            converted = _convert_to_memgraph_index(statement)
            if converted is None:
                continue
            statement = converted
        logger.debug("Executing statement: %s", statement)
        run_write_query(neo4j_session, statement)
