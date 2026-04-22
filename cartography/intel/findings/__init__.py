import logging

import neo4j

import cartography.intel.findings.misconfig
import cartography.intel.risk_scoring
from cartography.config import Config
from cartography.intel.findings.api_client import FINDINGS_TARGETS
from cartography.intel.findings.api_client import FindingsApiClient
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def start_findings_ingestion(neo4j_session: neo4j.Session, config: Config) -> None:
    """
    Ingest findings from the attack-surface findings API, create :Finding nodes,
    link them to assets via (asset)-[:HAS_FINDINGS]->(:Finding), and persist the
    response + stats to the existing asset-sync-info Elasticsearch document.
    """
    if not config.findings_api_url or not config.findings_api_token:
        logger.info(
            "Findings import is not configured - skipping. "
            "Provide --findings-api-url and --findings-api-token-env-var to enable.",
        )
        return

    client = FindingsApiClient(
        base_url=config.findings_api_url,
        bearer_token=config.findings_api_token,
    )

    targets_to_sync = FINDINGS_TARGETS
    if config.findings_target:
        requested_target = config.findings_target.strip().lower()
        if requested_target not in FINDINGS_TARGETS:
            logger.warning(
                "Invalid findings target '%s'. Supported values are: %s. Skipping findings sync.",
                config.findings_target,
                ", ".join(FINDINGS_TARGETS),
            )
            return
        targets_to_sync = (requested_target,)

    for target in targets_to_sync:
        logger.info("Syncing findings for target=%s", target)
        cartography.intel.findings.misconfig.sync(
            neo4j_session=neo4j_session,
            client=client,
            config=config,
            target=target,
        )

    cartography.intel.risk_scoring.run_risk_scoring(neo4j_session, config)
