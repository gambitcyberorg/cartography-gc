import csv
import logging
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.config import Config
from cartography.util import timeit

logger = logging.getLogger(__name__)

DEFAULT_CSV_FILENAME = "Risk_Scoring_Queries2.csv"
RISK_LEVEL_ORDER: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_TOP_ASSETS_LOG_LIMIT = 10

# Weights applied per finding severity when computing per-asset finding_risk_score.
# Tuned so a single CRITICAL outweighs several HIGHs, and LOWs barely register.
SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}

_FINDING_SEVERITY_BREAKDOWN_QUERY = """
MATCH (f:Finding)
RETURN toUpper(coalesce(f.severity, 'UNKNOWN')) AS severity, count(f) AS count
ORDER BY count DESC
"""

# Zero out any previously-written finding_risk_score so assets that lost their
# findings between syncs don't retain a stale weighted score.
_RESET_FINDING_RISK_SCORE_QUERY = """
MATCH (asset)
WHERE asset.finding_risk_score IS NOT NULL
SET asset.finding_risk_score = 0
"""

_APPLY_FINDING_RISK_SCORE_QUERY = """
MATCH (asset)-[:HAS_FINDINGS]->(f:Finding)
WITH asset, collect(toUpper(coalesce(f.severity, 'UNKNOWN'))) AS severities
WITH asset,
     size(severities) AS finding_count,
     size([s IN severities WHERE s = 'CRITICAL']) AS critical_count,
     size([s IN severities WHERE s = 'HIGH']) AS high_count,
     size([s IN severities WHERE s = 'MEDIUM']) AS medium_count,
     size([s IN severities WHERE s = 'LOW']) AS low_count,
     size([s IN severities WHERE NOT s IN ['CRITICAL','HIGH','MEDIUM','LOW']]) AS unknown_count
WITH asset, finding_count, critical_count, high_count, medium_count, low_count, unknown_count,
     (critical_count * $w_critical
      + high_count * $w_high
      + medium_count * $w_medium
      + low_count * $w_low) AS finding_score
SET asset.finding_risk_score = finding_score
RETURN asset.id AS asset_id,
       finding_count,
       critical_count,
       high_count,
       medium_count,
       low_count,
       unknown_count,
       finding_score
ORDER BY finding_score DESC
"""


def _candidate_csv_paths(override: Optional[str]) -> List[Path]:
    module_dir = Path(__file__).resolve().parent
    repo_root = module_dir.parents[2]
    candidates: List[Path] = []
    if override:
        candidates.append(Path(override))
    candidates.append(module_dir / DEFAULT_CSV_FILENAME)
    candidates.append(repo_root / DEFAULT_CSV_FILENAME)
    candidates.append(Path.cwd() / DEFAULT_CSV_FILENAME)
    return candidates


def _resolve_csv_path(override: Optional[str]) -> Optional[Path]:
    for candidate in _candidate_csv_paths(override):
        if candidate.is_file():
            return candidate.resolve()
    return None


def _parse_queries(csv_file: Path) -> List[Tuple[str, str]]:
    queries: List[Tuple[str, str]] = []
    with csv_file.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter=";", quotechar='"')
        for row in reader:
            if not row:
                continue
            first = (row[0] or "").strip().lower()
            if first == "s.no":
                continue
            if len(row) < 3:
                continue
            description = (row[1] or "").strip()
            query = (row[2] or "").strip()
            if query:
                queries.append((description, query))
    return queries


def _risk_level_index(record: Dict[str, Any]) -> int:
    for key in ("n.risk_level", "risk_level"):
        value = record.get(key)
        if value is None:
            continue
        level = str(value).upper()
        if level in RISK_LEVEL_ORDER:
            return RISK_LEVEL_ORDER.index(level)
    return len(RISK_LEVEL_ORDER)


def _risk_score(record: Dict[str, Any]) -> float:
    for key in ("n.normalized_risk", "n.risk_score", "normalized_risk", "risk_score"):
        value = record.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def _sort_records_by_risk(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(records, key=lambda r: (_risk_level_index(r), -_risk_score(r)))


def _execute_queries(
    neo4j_session: neo4j.Session,
    queries: List[Tuple[str, str]],
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Run each query in its OWN transaction so a failure in one query cannot
    poison the transaction state for subsequent queries. Returns the last
    successful query's records plus (succeeded, failed) counts.
    """
    total = len(queries)
    last: List[Dict[str, Any]] = []
    succeeded = 0
    failed = 0

    for idx, (description, query) in enumerate(queries, start=1):
        def _run(tx: neo4j.Transaction, q: str = query) -> List[Dict[str, Any]]:
            result = tx.run(q)
            return [dict(record) for record in result]

        try:
            records = neo4j_session.execute_write(_run)
            last = records
            succeeded += 1
            logger.debug(
                "Risk scoring query %d/%d [%s]: %d records",
                idx,
                total,
                description,
                len(records),
            )
        except Exception as exc:
            failed += 1
            logger.warning(
                "Risk scoring query %d/%d [%s] failed (continuing): %s",
                idx,
                total,
                description,
                exc,
            )

    return last, succeeded, failed


def _apply_finding_based_risk_scores(
    neo4j_session: neo4j.Session,
) -> None:
    """
    Preprocessing step that runs BEFORE the CSV-driven risk scoring queries.

    For every asset connected to a :Finding via (asset)-[:HAS_FINDINGS]->(:Finding),
    computes a weighted ``finding_risk_score`` by summing SEVERITY_WEIGHTS across
    the asset's findings (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1).

    The result is written to ``asset.finding_risk_score`` — a *separate* property
    from ``risk_score`` so the first CSV query (``MATCH (n) SET n.risk_score = 0``)
    does not clobber it.

    Errors are caught and logged so the downstream CSV flow still runs.
    """
    logger.info(
        "Finding-based risk scoring: starting preprocessing step "
        "(weights: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d)",
        SEVERITY_WEIGHTS["CRITICAL"],
        SEVERITY_WEIGHTS["HIGH"],
        SEVERITY_WEIGHTS["MEDIUM"],
        SEVERITY_WEIGHTS["LOW"],
    )

    try:
        def _breakdown(tx: neo4j.Transaction) -> List[Dict[str, Any]]:
            return [dict(r) for r in tx.run(_FINDING_SEVERITY_BREAKDOWN_QUERY)]

        breakdown = neo4j_session.execute_read(_breakdown)
    except Exception as exc:
        logger.warning(
            "Finding-based risk scoring: could not read :Finding severity "
            "breakdown (continuing): %s", exc,
        )
        breakdown = []

    total_findings = sum(int(row.get("count") or 0) for row in breakdown)
    if total_findings == 0:
        logger.info(
            "Finding-based risk scoring: no :Finding nodes present in graph; "
            "skipping finding-based preprocessing.",
        )
        return

    logger.info(
        "Finding-based risk scoring: %d :Finding nodes across severities %s",
        total_findings,
        {row["severity"]: row["count"] for row in breakdown},
    )

    try:
        def _reset(tx: neo4j.Transaction) -> int:
            summary = tx.run(_RESET_FINDING_RISK_SCORE_QUERY).consume()
            return summary.counters.properties_set

        reset_count = neo4j_session.execute_write(_reset)
        logger.info(
            "Finding-based risk scoring: reset finding_risk_score on %d "
            "previously-scored asset(s).",
            reset_count,
        )
    except Exception as exc:
        logger.warning(
            "Finding-based risk scoring: failed to reset stale "
            "finding_risk_score values (continuing): %s", exc,
        )

    try:
        def _apply(tx: neo4j.Transaction) -> List[Dict[str, Any]]:
            result = tx.run(
                _APPLY_FINDING_RISK_SCORE_QUERY,
                w_critical=SEVERITY_WEIGHTS["CRITICAL"],
                w_high=SEVERITY_WEIGHTS["HIGH"],
                w_medium=SEVERITY_WEIGHTS["MEDIUM"],
                w_low=SEVERITY_WEIGHTS["LOW"],
            )
            return [dict(record) for record in result]

        scored = neo4j_session.execute_write(_apply)
    except Exception as exc:
        logger.error(
            "Finding-based risk scoring: failed to apply weighted scores "
            "(downstream CSV queries will still run): %s",
            exc,
            exc_info=True,
        )
        return

    if not scored:
        logger.info(
            "Finding-based risk scoring: :Finding nodes exist but none are "
            "linked to assets via HAS_FINDINGS; no asset scored.",
        )
        return

    # Aggregate what we just wrote for a clear summary line.
    assets_scored = len(scored)
    totals = {
        "critical": sum(int(r.get("critical_count") or 0) for r in scored),
        "high": sum(int(r.get("high_count") or 0) for r in scored),
        "medium": sum(int(r.get("medium_count") or 0) for r in scored),
        "low": sum(int(r.get("low_count") or 0) for r in scored),
        "unknown": sum(int(r.get("unknown_count") or 0) for r in scored),
    }
    logger.info(
        "Finding-based risk scoring: assigned finding_risk_score to %d asset(s). "
        "Findings aggregated — CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d, UNKNOWN=%d.",
        assets_scored,
        totals["critical"],
        totals["high"],
        totals["medium"],
        totals["low"],
        totals["unknown"],
    )

    for rec in scored[:_TOP_ASSETS_LOG_LIMIT]:
        logger.info(
            "Finding-based risk scoring: asset=%s finding_risk_score=%s "
            "(findings=%s CRITICAL=%s HIGH=%s MEDIUM=%s LOW=%s)",
            rec.get("asset_id"),
            rec.get("finding_score"),
            rec.get("finding_count"),
            rec.get("critical_count"),
            rec.get("high_count"),
            rec.get("medium_count"),
            rec.get("low_count"),
        )

    logger.info(
        "Finding-based risk scoring: preprocessing complete. Proceeding to "
        "CSV-based risk scoring queries.",
    )


@timeit
def run_risk_scoring(
    neo4j_session: neo4j.Session,
    config: Config,
) -> None:
    """
    Execute risk scoring in two phases, producing a cumulative ``risk_score``:

    1. **Finding-based preprocessing** — for every asset with
       (asset)-[:HAS_FINDINGS]->(:Finding), compute a weighted
       ``finding_risk_score`` from finding severities (CRITICAL/HIGH/MEDIUM/LOW).
    2. **CSV-driven queries** — the first CSV query seeds
       ``risk_score`` from ``finding_risk_score`` (so finding weight carries
       forward), subsequent queries add category-specific deltas, and the final
       queries compute ``normalized_risk`` (capped at 100) and ``risk_level``.

    ``finding_risk_score`` is retained as a separate property so its
    contribution to the cumulative ``risk_score`` remains auditable.

    Never raises: any error (CSV parse, Neo4j failure, unexpected exception) is
    caught and logged so the enclosing sync flow continues.
    """
    try:
        logger.info("Risk scoring: phase 1/2 — finding-based weighted scoring.")
        _apply_finding_based_risk_scores(neo4j_session)

        logger.info(
            "Risk scoring: phase 2/2 — CSV-driven Cypher queries. "
            "risk_score will be seeded from finding_risk_score, then "
            "incremented by category-specific deltas for a cumulative total.",
        )
        csv_override = getattr(config, "risk_scoring_csv_path", None)
        csv_path = _resolve_csv_path(csv_override)
        if csv_path is None:
            logger.warning(
                "Risk scoring CSV not found (looked in: %s); skipping CSV phase.",
                [str(p) for p in _candidate_csv_paths(csv_override)],
            )
            return

        queries = _parse_queries(csv_path)
        if not queries:
            logger.warning(
                "No risk scoring queries parsed from %s; skipping CSV phase.",
                csv_path,
            )
            return

        logger.info(
            "Running %d risk scoring queries from %s", len(queries), csv_path,
        )

        last_result, succeeded, failed = _execute_queries(neo4j_session, queries)

        top_assets = _sort_records_by_risk(last_result)
        logger.info(
            "Risk scoring complete: %d succeeded, %d failed, %d top-risk assets reported.",
            succeeded,
            failed,
            len(top_assets),
        )
        for rec in top_assets[:_TOP_ASSETS_LOG_LIMIT]:
            logger.info("Top risk asset: %s", rec)
    except Exception as exc:
        logger.error(
            "Risk scoring aborted due to unexpected error (sync flow continues): %s",
            exc,
            exc_info=True,
        )
