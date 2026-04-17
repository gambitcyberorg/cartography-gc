import logging
import os
from datetime import datetime
from datetime import timezone

import requests

logger = logging.getLogger(__name__)

ES_TRUST_STORE_PATH = "/app/truststore/fullchain.pem"


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

    verify: bool | str = True
    if os.path.exists(ES_TRUST_STORE_PATH):
        verify = ES_TRUST_STORE_PATH

    now = datetime.now(timezone.utc)
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    payload = {
        "doc": {
            "status": status,
            "updated_at": now.isoformat(timespec="milliseconds"),
        },
    }

    try:
        response = requests.post(
            url,
            json=payload,
            auth=auth,
            verify=verify,
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
