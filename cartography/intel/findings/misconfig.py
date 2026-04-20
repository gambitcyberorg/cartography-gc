import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

import neo4j

from cartography.client.core.tx import write_list_of_dicts_tx
from cartography.config import Config
from cartography.es_client import update_findings_document
from cartography.intel.findings.api_client import FindingsApiClient
from cartography.util import timeit

logger = logging.getLogger(__name__)


_UPSERT_FINDINGS_QUERY = """
UNWIND $DictList AS f
MERGE (finding:Finding {id: f.id})
ON CREATE SET finding.firstseen = $UPDATE_TAG
SET finding.lastupdated = $UPDATE_TAG,
    finding.finding = f.finding,
    finding.finding_desc = f.finding_desc,
    finding.finding_date = f.finding_date,
    finding.has_automated_fix = f.has_automated_fix,
    finding.remediation_desc = f.remediation_desc,
    finding.remediation_references = f.remediation_references,
    finding.severity = f.severity,
    finding.status = f.status,
    finding.status_code = f.status_code,
    finding.event_code = f.event_code,
    finding.rule_name = f.rule_name,
    finding.rule_desc = f.rule_desc,
    finding.type = f.type,
    finding.target = f.target,
    finding.resource_arn = f.resource_arn,
    finding.resource_type = f.resource_type,
    finding.resource_name = f.resource_name,
    finding.resource_region = f.resource_region,
    finding.resource_group_name = f.resource_group_name
"""

_LINK_FINDINGS_QUERY = """
UNWIND $DictList AS f
MATCH (asset {id: f.resource_arn})
MATCH (finding:Finding {id: f.id})
MERGE (asset)-[r:HAS_FINDING]->(finding)
ON CREATE SET r.firstseen = $UPDATE_TAG
SET r.lastupdated = $UPDATE_TAG
"""

_CLEANUP_STALE_RELS_QUERY = """
MATCH (:Finding)<-[r:HAS_FINDING]-()
WHERE r.lastupdated <> $UPDATE_TAG
DELETE r
"""

_CLEANUP_STALE_FINDINGS_QUERY = """
MATCH (f:Finding)
WHERE f.lastupdated <> $UPDATE_TAG
  AND f.type = $FINDING_TYPE
  AND f.target = $TARGET
DETACH DELETE f
"""


def _normalize_finding(
    raw: Dict[str, Any],
    finding_type: str,
    target: str,
) -> List[Dict[str, Any]]:
    """
    Flatten a raw API finding into one row per (finding, resource) pair. The
    requested fields are carried verbatim and a deterministic `id` is produced
    so re-syncs upsert the same node.
    """
    remediation = raw.get("remediation") or {}
    remediation_desc = remediation.get("desc")
    remediation_refs = remediation.get("references") or []
    event_code = raw.get("event_code") or ""
    base: Dict[str, Any] = {
        "finding": raw.get("finding"),
        "finding_desc": raw.get("finding_desc"),
        "finding_date": raw.get("finding_date"),
        "has_automated_fix": raw.get("has_automated_fix"),
        "remediation_desc": remediation_desc,
        "remediation_references": remediation_refs,
        "severity": raw.get("severity"),
        "status": raw.get("status"),
        "status_code": raw.get("status_code"),
        "event_code": event_code,
        "rule_name": raw.get("rule_name"),
        "rule_desc": raw.get("rule_desc"),
        "type": finding_type,
        "target": target,
    }

    rows: List[Dict[str, Any]] = []
    for resource in raw.get("resources") or []:
        resource_arn = resource.get("uid")
        if not resource_arn:
            continue
        row = dict(base)
        row["id"] = f"{resource_arn}::{event_code}"
        row["resource_arn"] = resource_arn
        row["resource_type"] = resource.get("type")
        row["resource_name"] = resource.get("name")
        row["resource_region"] = resource.get("region")
        row["resource_group_name"] = resource.get("group_name")
        rows.append(row)
    return rows


@timeit
def sync(
    neo4j_session: neo4j.Session,
    client: FindingsApiClient,
    config: Config,
    target: str = "aws",
    finding_type: str = "misconfig",
    status_code: str = "FAIL",
) -> None:
    records, raw_pages, stats = _collect(client, finding_type, target, status_code)
    logger.info(
        "Loading %d finding rows (from %d raw findings) into the graph",
        len(records),
        sum(len(p.get("findings") or []) for p in raw_pages),
    )
    _load(neo4j_session, records, config.update_tag, finding_type, target)
    _persist_to_es(config, records, raw_pages, stats, target, finding_type)


def _collect(
    client: FindingsApiClient,
    finding_type: str,
    target: str,
    status_code: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    raw_pages: List[Dict[str, Any]] = []
    stats: Dict[str, Any] = {}

    for idx, page_resp in enumerate(
        client.iter_all(finding_type, target, status_code)
    ):
        raw_pages.append(page_resp)
        if idx == 0:
            stats = {
                "comprehensive_metrics": page_resp.get("comprehensive_metrics"),
                "summary": page_resp.get("summary"),
                "target_metrics": page_resp.get("target_metrics"),
                "pagination": page_resp.get("pagination"),
            }
        for raw in page_resp.get("findings") or []:
            records.extend(_normalize_finding(raw, finding_type, target))

    return records, raw_pages, stats


def _load(
    neo4j_session: neo4j.Session,
    records: List[Dict[str, Any]],
    update_tag: int,
    finding_type: str,
    target: str,
) -> None:
    if not records:
        logger.info("No finding records to load; running cleanup only.")
    else:
        neo4j_session.execute_write(
            write_list_of_dicts_tx,
            _UPSERT_FINDINGS_QUERY,
            DictList=records,
            UPDATE_TAG=update_tag,
        )
        neo4j_session.execute_write(
            write_list_of_dicts_tx,
            _LINK_FINDINGS_QUERY,
            DictList=records,
            UPDATE_TAG=update_tag,
        )
    neo4j_session.execute_write(
        lambda tx: tx.run(_CLEANUP_STALE_RELS_QUERY, UPDATE_TAG=update_tag).consume(),
    )
    neo4j_session.execute_write(
        lambda tx: tx.run(
            _CLEANUP_STALE_FINDINGS_QUERY,
            UPDATE_TAG=update_tag,
            FINDING_TYPE=finding_type,
            TARGET=target,
        ).consume(),
    )


def _persist_to_es(
    config: Config,
    records: List[Dict[str, Any]],
    raw_pages: List[Dict[str, Any]],
    stats: Dict[str, Any],
    target: str,
    finding_type: str,
) -> None:
    if not (config.es_cluster_nodes and config.es_document_id):
        logger.info(
            "Elasticsearch asset-sync-info update skipped - es_cluster_nodes or "
            "es_document_id not configured.",
        )
        return

    all_findings: List[Dict[str, Any]] = []
    for page in raw_pages:
        all_findings.extend(page.get("findings") or [])

    update_findings_document(
        es_uri=config.es_cluster_nodes,
        document_id=config.es_document_id,
        findings=all_findings,
        normalized=records,
        stats=stats,
        target=target,
        finding_type=finding_type,
        es_username=config.es_username,
        es_password=config.es_password,
    )
