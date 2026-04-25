"""``think`` — record a private chain-of-thought note with no side effects."""

from __future__ import annotations

import json

from strix.tools._decorator import strix_tool


@strix_tool(timeout=10)
async def think(thought: str) -> str:
    """Record a private chain-of-thought note without taking any action.

    The "think" tool is the planning escape hatch for situations where a
    message-without-tool-call would otherwise halt the run (per the
    interactive-mode tool-call requirement). The thought itself is
    recorded but produces no side effects.

    Args:
        thought: The agent's reasoning to record. Must be non-empty.
    """
    if not thought or not thought.strip():
        return json.dumps({"success": False, "message": "Thought cannot be empty"})
    return json.dumps(
        {
            "success": True,
            "message": (f"Thought recorded successfully with {len(thought.strip())} characters"),
        },
        ensure_ascii=False,
    )
