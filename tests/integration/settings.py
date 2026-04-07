import os

DEFAULTS = {
    "NEO4J_URL": "bolt://localhost:7687",
    "NEO4J_DOCKER_IMAGE": "neo4j:5-community",
    "GRAPH_BACKEND": "neo4j",
    "MEMGRAPH_DOCKER_IMAGE": "memgraph/memgraph-platform:latest",
}


def get(name):
    return os.environ.get(name, DEFAULTS.get(name))
