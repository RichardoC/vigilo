"""Findings aggregator — unified findings_index.json from structured outputs.

Sources, all structured JSON written on purpose by agents:

- the findings ledger (``deliverables/ledger/``, written through
  ``vigilo-record``) — the white-box engine's findings, statuses and chains;
- ``sca_findings.json`` — supply-chain findings, deduplicated and annotated by
  :mod:`src.services.sca_filter`;
- ``integrity_analysis.json`` — integrity findings.

**No prose is scraped.** Findings the prover judged ``false_positive`` or
``unreachable`` stay in the index with a ``suppressed`` status and an explicit
reason (see :func:`src.pipeline.ledger.build_findings_index`), so nothing is
silently dropped; downstream consumers exclude them from primary counts but can
still audit them.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import aiofiles

logger = logging.getLogger(__name__)


async def _load_json(path: Path) -> Any | None:
    """Read and parse a JSON file, returning None on missing/malformed input."""
    if not path.is_file():
        return None
    try:
        async with aiofiles.open(path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        return json.loads(content)
    except json.JSONDecodeError as exc:
        logger.warning("Malformed JSON in %s: %s", path, exc)
        return None
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None


class FindingsAggregator:
    """Reads structured agent outputs and produces a unified findings index."""

    async def aggregate(self, repo_path: str) -> dict[str, Any]:
        """Merge the ledger, SCA and integrity outputs into the index structure.

        Returns a dict shaped as::

            {"total_vulnerabilities": 15, "by_type": {"authorization": [...], ...}}

        Missing or malformed files are skipped (logged as warnings).
        """
        deliverables_dir = Path(repo_path) / "deliverables"
        by_type: dict[str, list[dict[str, Any]]] = {}
        total = 0

        # --- Findings ledger (written by agents through vigilo-record) ---
        from src.pipeline.ledger import Ledger, build_findings_index
        ledger_index = build_findings_index(Ledger(deliverables_dir))
        for category, entries in ledger_index["by_type"].items():
            by_type.setdefault(category, []).extend(entries)
            total += len(entries)
        if ledger_index["total_vulnerabilities"]:
            logger.info(
                "Aggregated %d findings from the ledger", ledger_index["total_vulnerabilities"]
            )

        # --- Supply chain (SCA) findings (already structured JSON) ---
        # Pre-filter: dedup by (package, advisory) and annotate dependency_used
        # BEFORE the critic sees them, so the noisiest bucket is reduced up front.
        # Conservative: usage is only ever confirmed True or left unknown — never
        # asserted False — so a real finding is never hidden here (see sca_filter).
        sca_data = await _load_json(deliverables_dir / "sca_findings.json")
        if isinstance(sca_data, dict):
            sca_vulns = sca_data.get("vulnerabilities", [])
            if isinstance(sca_vulns, list) and sca_vulns:
                from src.services.sca_filter import filter_sca
                filtered = filter_sca(sca_vulns, repo_path)
                by_type["supply_chain"] = filtered
                total += len(filtered)
                logger.info("Added %d supply chain findings (%d raw)", len(filtered), len(sca_vulns))

        # --- Integrity findings (already structured JSON) ---
        integrity_data = await _load_json(deliverables_dir / "integrity_analysis.json")
        if isinstance(integrity_data, dict):
            integrity_findings = integrity_data.get("findings", [])
            if isinstance(integrity_findings, list) and integrity_findings:
                by_type["integrity"] = integrity_findings
                total += len(integrity_findings)
                logger.info("Added %d integrity findings", len(integrity_findings))

        index: dict[str, Any] = {
            "total_vulnerabilities": total,
            "by_type": by_type,
        }
        logger.info(
            "Findings aggregation complete: %d total across %d non-empty types",
            total,
            sum(1 for v in by_type.values() if v),
        )
        return index

    async def write_index(self, repo_path: str, index: dict[str, Any]) -> None:
        """Write the aggregated findings index to ``deliverables/findings_index.json``.

        Uses an atomic write (temp file + rename) for crash safety.
        """
        deliverables_dir = Path(repo_path) / "deliverables"
        deliverables_dir.mkdir(parents=True, exist_ok=True)

        index_path = deliverables_dir / "findings_index.json"
        tmp_path = deliverables_dir / f"findings_index.{os.getpid()}.{id(index)}.tmp"

        content = json.dumps(index, indent=2, ensure_ascii=False)
        async with aiofiles.open(tmp_path, mode="w", encoding="utf-8") as f:
            await f.write(content)
        tmp_path.replace(index_path)
        logger.info(
            "Wrote findings_index.json with %d total vulnerabilities",
            index.get("total_vulnerabilities", 0),
        )

    async def aggregate_and_write(self, repo_path: str) -> dict[str, Any]:
        """Aggregate and write the index in one step."""
        index = await self.aggregate(repo_path)
        await self.write_index(repo_path, index)
        return index
