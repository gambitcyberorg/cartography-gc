import logging
import os
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Dict

import requests

logger = logging.getLogger(__name__)

ES_TRUST_STORE_PATH = "/app/truststore/fullchain.pem"


def _es_verify() -> bool | str:
    if os.path.exists(ES_TRUST_STORE_PATH):
        return ES_TRUST_STORE_PATH
    return True


def _iso_now_millis() -> str:
    now = datetime.now(timezone.utc)
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    return now.isoformat(timespec="milliseconds")


def update_asset_sync_status(
    es_uri: str,
    document_id: str,
    status: str,
    es_username: str | None = None,
    es_password: str | None = None,
) -> None:
    """
    Update the status field of a document in the asset-sync-info Elasticsearch index.

    Args:
        es_uri: Elasticsearch cluster node URI, e.g. "localhost:9200".
        document_id: The document ID to update.
        status: The status value to set (e.g. "Running", "Completed", "Failed").
        es_username: Optional username for Elasticsearch basic auth.
        es_password: Optional password for Elasticsearch basic auth.
    """
    url = f"https://{es_uri}/asset-sync-info/_update/{document_id}"

    auth = None
    if es_username and es_password:
        auth = (es_username, es_password)

    payload = {
        "doc": {
            "status": status,
            "updated_at": _iso_now_millis(),
        },
    }

    try:
        response = requests.post(
            url,
            json=payload,
            auth=auth,
            verify=_es_verify(),
            timeout=30,
        )
        response.raise_for_status()
        logger.info(
            "Successfully updated asset-sync-info document '%s' with status '%s'.",
            document_id,
            status,
        )
    except requests.exceptions.RequestException as e:
        logger.warning(
            "Failed to update asset-sync-info document '%s' in Elasticsearch: %s",
            document_id,
            e,
        )


_FINDINGS_METRIC_KEYS = [
    "total_findings",
    "findings_mapped",
    "findings_not_mapped",
    "total_assets_with_findings",
    "assets_with_critical_findings",
    "assets_with_high_findings",
]


def _fetch_current_scan(
    es_uri: str,
    document_id: str,
    auth: tuple | None,
) -> Dict[str, Any]:
    """Return the existing current_scan block from ES, or {} if absent/unreachable."""
    try:
        resp = requests.get(
            f"https://{es_uri}/asset-sync-info/_doc/{document_id}",
            auth=auth,
            verify=_es_verify(),
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("_source", {}).get("findings_data", {}).get("current_scan", {})
    except requests.exceptions.RequestException as e:
        logger.warning(
            "Could not fetch existing findings_data for document '%s' (drift will be zero): %s",
            document_id,
            e,
        )
    return {}


def update_findings_document(
    es_uri: str,
    document_id: str,
    total_findings: int,
    findings_mapped: int,
    findings_not_mapped: int,
    total_assets_with_findings: int,
    assets_with_critical_findings: int,
    assets_with_high_findings: int,
    target: str,
    finding_type: str,
    es_username: str | None = None,
    es_password: str | None = None,
) -> None:
    """
    Update findings_data in the asset-sync-info document with current_scan,
    last_scan (promoted from the previous current_scan), and drift between them.
    """
    auth = (es_username, es_password) if es_username and es_password else None

    last_scan = _fetch_current_scan(es_uri, document_id, auth)

    current_scan: Dict[str, Any] = {
        "total_findings": total_findings,
        "findings_mapped": findings_mapped,
        "findings_not_mapped": findings_not_mapped,
        "total_assets_with_findings": total_assets_with_findings,
        "assets_with_critical_findings": assets_with_critical_findings,
        "assets_with_high_findings": assets_with_high_findings,
        "scanned_at": _iso_now_millis(),
    }

    drift = {
        key: current_scan[key] - last_scan.get(key, 0)
        for key in _FINDINGS_METRIC_KEYS
    }

    payload = {
        "doc": {
            "findings_data": {
                "target": target,
                "type": finding_type,
                "updated_at": current_scan["scanned_at"],
                "current_scan": current_scan,
                "last_scan": last_scan or None,
                "drift": drift,
            },
        },
    }

    try:
        response = requests.post(
            f"https://{es_uri}/asset-sync-info/_update/{document_id}",
            json=payload,
            auth=auth,
            verify=_es_verify(),
            timeout=60,
        )
        response.raise_for_status()
        logger.info(
            "Updated findings_data for document '%s' (target=%s, type=%s): "
            "total=%d mapped=%d not_mapped=%d assets=%d critical=%d high=%d | "
            "drift: total=%+d mapped=%+d not_mapped=%+d assets=%+d critical=%+d high=%+d.",
            document_id,
            target,
            finding_type,
            total_findings,
            findings_mapped,
            findings_not_mapped,
            total_assets_with_findings,
            assets_with_critical_findings,
            assets_with_high_findings,
            drift["total_findings"],
            drift["findings_mapped"],
            drift["findings_not_mapped"],
            drift["total_assets_with_findings"],
            drift["assets_with_critical_findings"],
            drift["assets_with_high_findings"],
        )
    except requests.exceptions.RequestException as e:
        logger.warning(
            "Failed to update asset-sync-info document '%s' with findings: %s",
            document_id,
            e,
        )
