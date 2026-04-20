import logging
from typing import Any
from typing import Dict
from typing import Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_TIMEOUT = (30, 120)
_FINDINGS_PATH = "/attack-surface/process-findings"
FINDINGS_TARGETS = ("aws", "azure")


class FindingsApiClient:
    """
    Client for the attack-surface findings API.

    Pagination: the API exposes `page` (0-indexed on input, 1-indexed in the
    response body) along with `total_pages` and `total_findings`. We iterate
    pages until `total_pages` is reached or an empty page is returned.
    """

    def __init__(
        self,
        base_url: str,
        bearer_token: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({
            "accept": "application/json",
            "authorization": f"Bearer {bearer_token}",
        })

    def fetch_page(
        self,
        page: int,
        finding_type: str = "misconfig",
        target: str = "aws",
        status_code: str = "FAIL",
    ) -> Dict[str, Any]:
        params = {
            "type": finding_type,
            "target": target,
            "page": page,
            "status_code": status_code,
        }
        url = f"{self.base_url}{_FINDINGS_PATH}"
        resp = self.session.get(url, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def iter_all(
        self,
        finding_type: str = "misconfig",
        target: str = "aws",
        status_code: str = "FAIL",
    ) -> Iterator[Dict[str, Any]]:
        """
        Yield each page response in order. Caller is responsible for aggregating
        findings or stats from the first page.
        """
        first = self.fetch_page(0, finding_type, target, status_code)
        yield first

        pagination = first.get("pagination") or {}
        total_pages = int(pagination.get("total_pages") or 1)
        # API accepts page=0 as the first page; iterate remaining pages as 1..total_pages-1
        for page in range(1, total_pages):
            page_resp = self.fetch_page(page, finding_type, target, status_code)
            findings = page_resp.get("findings") or []
            if not findings:
                break
            yield page_resp
