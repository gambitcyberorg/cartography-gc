import logging
import os
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Dict
from typing import List

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


def update_findings_document(
    es_uri: str,
    document_id: str,
    total_findings: int,
    findings_mapped: int,
    findings_not_mapped: int,
    target: str,
    finding_type: str,
    es_username: str | None = None,
    es_password: str | None = None,
) -> None:
    """
    Merge findings metrics into the existing asset-sync-info document keyed by
    `document_id`. The payload is namespaced under `findings_data`.
    """
    url = f"https://{es_uri}/asset-sync-info/_update/{document_id}"

    auth = None
    if es_username and es_password:
        auth = (es_username, es_password)

    payload = {
        "doc": {
            "findings_data": {
                "target": target,
                "type": finding_type,
                "updated_at": _iso_now_millis(),
                "total_findings": total_findings,
                "findings_mapped": findings_mapped,
                "findings_not_mapped": findings_not_mapped,
            },
        },
    }

    try:
        response = requests.post(
            url,
            json=payload,
            auth=auth,
            verify=_es_verify(),
            timeout=60,
        )
        response.raise_for_status()
        logger.info(
            "Successfully updated asset-sync-info document '%s': "
            "total=%d mapped=%d not_mapped=%d (target=%s, type=%s).",
            document_id,
            total_findings,
            findings_mapped,
            findings_not_mapped,
            target,
            finding_type,
        )
    except requests.exceptions.RequestException as e:
        logger.warning(
            "Failed to update asset-sync-info document '%s' with findings: %s",
            document_id,
            e,
        )
