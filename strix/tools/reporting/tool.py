"""``create_vulnerability_report`` — file a vuln finding with dedup + CVSS.

Validates required fields, parses the CVSS-3.1 XML breakdown into a
score, runs LLM-based dedup against existing reports through
``strix.llm.dedupe.check_duplicate``, and persists via the global
:class:`strix.telemetry.tracer.Tracer` instance.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from pathlib import PurePosixPath
from typing import Any

from agents import RunContextWrapper

from strix.tools._decorator import strix_tool


logger = logging.getLogger(__name__)


_CVSS_FIELDS = (
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality",
    "integrity",
    "availability",
)


def _parse_cvss_xml(xml_str: str) -> dict[str, str] | None:
    if not xml_str or not xml_str.strip():
        return None
    result: dict[str, str] = {}
    for field in _CVSS_FIELDS:
        match = re.search(rf"<{field}>(.*?)</{field}>", xml_str, re.DOTALL)
        if match:
            result[field] = match.group(1).strip()
    return result if result else None


def _parse_code_locations_xml(xml_str: str) -> list[dict[str, Any]] | None:
    if not xml_str or not xml_str.strip():
        return None
    locations: list[dict[str, Any]] = []
    for loc_match in re.finditer(r"<location>(.*?)</location>", xml_str, re.DOTALL):
        loc: dict[str, Any] = {}
        loc_content = loc_match.group(1)
        for field in (
            "file",
            "start_line",
            "end_line",
            "snippet",
            "label",
            "fix_before",
            "fix_after",
        ):
            field_match = re.search(rf"<{field}>(.*?)</{field}>", loc_content, re.DOTALL)
            if field_match:
                raw = field_match.group(1)
                value = (
                    raw.strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else raw.strip()
                )
                if field in ("start_line", "end_line"):
                    with contextlib.suppress(ValueError, TypeError):
                        loc[field] = int(value)
                elif value:
                    loc[field] = value
        if loc.get("file") and loc.get("start_line") is not None:
            locations.append(loc)
    return locations if locations else None


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def _calculate_cvss(**kwargs: str) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{kwargs['attack_vector']}/AC:{kwargs['attack_complexity']}/"
            f"PR:{kwargs['privileges_required']}/UI:{kwargs['user_interaction']}/"
            f"S:{kwargs['scope']}/C:{kwargs['confidentiality']}/"
            f"I:{kwargs['integrity']}/A:{kwargs['availability']}"
        )
        c = CVSS3(vector)
        score = c.scores()[0]
        severity = c.severities()[0].lower()
    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return score, severity, vector


_REQUIRED_FIELDS = {
    "title": "Title cannot be empty",
    "description": "Description cannot be empty",
    "impact": "Impact cannot be empty",
    "target": "Target cannot be empty",
    "technical_analysis": "Technical analysis cannot be empty",
    "poc_description": "PoC description cannot be empty",
    "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    "remediation_steps": "Remediation steps cannot be empty",
}


_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


def _do_create(  # noqa: PLR0912
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: str,
    endpoint: str | None,
    method: str | None,
    cve: str | None,
    cwe: str | None,
    code_locations: str | None,
) -> dict[str, Any]:
    errors: list[str] = []
    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
    }
    for name, msg in _REQUIRED_FIELDS.items():
        if not str(fields.get(name) or "").strip():
            errors.append(msg)

    parsed_cvss = _parse_cvss_xml(cvss_breakdown)
    if not parsed_cvss:
        errors.append("cvss: could not parse CVSS breakdown XML")
    else:
        for name, valid in _CVSS_VALID.items():
            value = parsed_cvss.get(name)
            if value not in valid:
                errors.append(f"Invalid {name}: {value}. Must be one of: {valid}")

    parsed_locations = _parse_code_locations_xml(code_locations) if code_locations else None
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)

    if errors:
        return {"success": False, "message": "Validation failed", "errors": errors}

    assert parsed_cvss is not None
    cvss_score, severity, _vector = _calculate_cvss(**parsed_cvss)

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            logger.warning("No global tracer; vulnerability report not persisted")
            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created (not persisted)",
                "warning": "Report could not be persisted - tracer unavailable",
            }

        from strix.llm.dedupe import check_duplicate

        existing = tracer.get_existing_vulnerabilities()
        candidate = {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "endpoint": endpoint,
            "method": method,
        }
        dedupe = check_duplicate(candidate, existing)
        if dedupe.get("is_duplicate"):
            duplicate_id = dedupe.get("duplicate_id", "")
            duplicate_title = next(
                (r.get("title", "Unknown") for r in existing if r.get("id") == duplicate_id),
                "",
            )
            return {
                "success": False,
                "message": (
                    f"Potential duplicate of '{duplicate_title}' "
                    f"(id={duplicate_id[:8]}...). Do not re-report the same vulnerability."
                ),
                "duplicate_of": duplicate_id,
                "duplicate_title": duplicate_title,
                "confidence": dedupe.get("confidence", 0.0),
                "reason": dedupe.get("reason", ""),
            }

        report_id = tracer.add_vulnerability_report(
            title=title,
            description=description,
            severity=severity,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            cvss=cvss_score,
            cvss_breakdown=parsed_cvss,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=parsed_locations,
        )
    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}
    else:
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cvss_score": cvss_score,
        }


# Generous timeout: the dedup check makes a separate LLM call, and
# large scans can have many existing reports to compare against.
@strix_tool(timeout=180)
async def create_vulnerability_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: str,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: str | None = None,
) -> str:
    """File a vulnerability report — one report per fully-verified finding.

    **When to file**: you have a concrete vulnerability with a working
    proof-of-concept and you're 100% sure it's a real issue.

    **When NOT to file**:

    - General security observations without a specific vulnerability.
    - Suspicions you haven't confirmed with a PoC.
    - Tracking multiple vulnerabilities at once — one report per vuln.
    - Re-reporting something you (or another agent) already filed.

    Automatic LLM-based **deduplication** rejects reports that describe
    the same root cause on the same asset as an existing report. If you
    get a ``duplicate_of`` response, do NOT retry — move on to other
    areas.

    **Customer-facing report rules** (the report is PDF-rendered for
    delivery):

    - No internal/system details: never mention paths like
      ``/workspace``, internal tools, agents, sandboxes, models, system
      prompts, internal errors / stack traces, or tester environment.
    - Tone: formal, objective, third-person, vendor-neutral, concise.
    - Standard finding structure: Overview → Severity & CVSS →
      Affected assets → Technical details → PoC (steps + code) →
      Impact → Remediation → Evidence (in technical_analysis).
    - Numbered steps allowed only in PoC and Remediation sections.
    - Avoid hedging language; be precise and non-vague.

    **White-box requirement**: when source is available, you MUST
    populate ``code_locations`` with nested XML including
    ``fix_before`` / ``fix_after`` for proposed fixes. The fix_before
    must be a verbatim copy of source at the specified line range — it's
    used as a literal GitHub/GitLab PR suggestion block.

    **CVSS breakdown** is required as nested XML with all 8 metrics
    (each a single uppercase letter):

    - ``attack_vector``: ``N`` (Network), ``A`` (Adjacent), ``L``
      (Local), ``P`` (Physical)
    - ``attack_complexity``: ``L`` / ``H``
    - ``privileges_required``: ``N`` / ``L`` / ``H``
    - ``user_interaction``: ``N`` / ``R``
    - ``scope``: ``U`` (Unchanged) / ``C`` (Changed)
    - ``confidentiality`` / ``integrity`` / ``availability``: ``N`` /
      ``L`` / ``H``

    **CVE / CWE rules**: pass the bare ID only (``CVE-2024-1234``,
    ``CWE-89``) — no name, no parenthetical. Be 100% certain; if
    unsure, omit. Always prefer the most specific child CWE over a
    broad parent (CWE-89 not CWE-74; CWE-78 not CWE-77).

    Args:
        title: Specific finding title (e.g.
            ``"SQL Injection in /api/users login parameter"``). Don't
            include the CVE number in the title.
        description: How the vuln was discovered + what it is.
        impact: What an attacker achieves; business risk; data at risk.
        target: Affected URL / domain / repository.
        technical_analysis: The mechanism and root cause.
        poc_description: Step-by-step reproduction.
        poc_script_code: Working PoC (Python preferred).
        remediation_steps: Specific, actionable fix.
        cvss_breakdown: 8-metric XML block per the format above.
        endpoint: API path / Git path (e.g. ``/api/login``).
        method: HTTP method when relevant.
        cve: ``CVE-YYYY-NNNNN`` if certain, else omit.
        cwe: ``CWE-NNN`` (most specific child) if certain, else omit.
        code_locations: Required for white-box findings; nested XML
            list with ``file``, ``start_line``, ``end_line``,
            ``snippet``, ``fix_before``, ``fix_after``.
    """
    del ctx
    result = await asyncio.to_thread(
        _do_create,
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
