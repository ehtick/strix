"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper

from strix.tools._decorator import strix_tool


logger = logging.getLogger(__name__)


def _do_finish(
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": "finish_scan_wrong_agent",
            "message": "This tool can only be used by the root/main agent",
            "suggestion": "If you are a subagent, use agent_finish instead",
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")
    if errors:
        return {"success": False, "message": "Validation failed", "errors": errors}

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            logger.warning("No global tracer; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - tracer unavailable",
            }
        tracer.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": len(tracer.vulnerability_reports),
        }
    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}


@strix_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan and persist the four executive summary sections.

    Only the root agent should call this. Subagents must use
    ``agent_finish`` (from the multi-agent graph tools) instead.

    Args:
        executive_summary: High-level scan outcome.
        methodology: Approach taken.
        technical_analysis: Findings detail across the engagement.
        recommendations: Prioritized fix list.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    result = await asyncio.to_thread(
        _do_finish,
        parent_id=inner.get("parent_id"),
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
