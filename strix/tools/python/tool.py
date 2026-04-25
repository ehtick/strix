"""SDK function-tool wrapper for the legacy ``python_action`` tool.

Sandbox-bound. The in-container manager keeps long-lived IPython
sessions keyed by ``session_id`` so the model can build up state
across multiple ``execute`` calls. Pure pass-through wrapper.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from agents import RunContextWrapper

from strix.tools._decorator import strix_tool
from strix.tools._sandbox_dispatch import post_to_sandbox


def _dump(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, default=str)


PythonAction = Literal["new_session", "execute", "close", "list_sessions"]


@strix_tool(timeout=180)
async def python_action(
    ctx: RunContextWrapper,
    action: PythonAction,
    code: str | None = None,
    timeout: int = 30,
    session_id: str | None = None,
) -> str:
    """Run Python code in a long-lived IPython session — preferred for any
    Python work (payloads, exploit scripts, HTTP automation, log analysis,
    crypto, data processing).

    Pick this over ``terminal_execute`` whenever the work is Python.
    Don't wrap Python in bash heredocs, ``python -c`` one-liners, or
    interactive REPL sessions in the terminal — the structured,
    persistent, debuggable execution lives here.

    Sessions are **persistent** — variables, imports, and function
    definitions survive between ``execute`` calls within the same
    ``session_id``. Each session has its own isolated namespace; multiple
    sessions can run concurrently. Sessions stay alive until explicitly
    ``close``-d.

    Caido proxy helpers are pre-imported into every session, so you can
    correlate captured HTTP requests with custom analysis without any
    setup: ``list_requests`` / ``view_request`` / ``send_request`` /
    ``repeat_request`` / ``scope_rules`` / ``list_sitemap`` /
    ``view_sitemap_entry`` are all available as bare names.

    For large payload sprays / fuzzing loops, encapsulate the entire
    loop inside a single ``python_action`` ``execute`` call (e.g.,
    asyncio + aiohttp). Don't issue one tool call per payload — that
    burns turns and is dramatically slower.

    Code execution notes:

    - Both expressions and statements are supported. Expressions auto-
      return their result; ``print`` output is captured to stdout.
    - IPython magics work: ``%pip install ...``, ``%time``, ``%whos``,
      ``%%writefile``, etc.
    - Use real newlines in multi-line ``code``, not literal ``\\n``.

    Workflow:

    1. ``new_session`` (always first per ``session_id``) — optionally
       pass ``code`` for an initial setup snippet (imports, helpers).
    2. ``execute`` — run code. Variables persist across calls.
    3. ``close`` — terminate the session and free memory.
    4. ``list_sessions`` — inspect what's currently alive.

    Args:
        action: ``"new_session"`` / ``"execute"`` / ``"close"`` /
            ``"list_sessions"``.
        code: Required for ``execute``; optional initial code for
            ``new_session``.
        timeout: Per-call execution budget in seconds. Default 30.
        session_id: Required for ``execute`` / ``close``. Optional for
            ``new_session`` (auto-generated when omitted).
    """
    return _dump(
        await post_to_sandbox(
            ctx,
            "python_action",
            {
                "action": action,
                "code": code,
                "timeout": timeout,
                "session_id": session_id,
            },
        ),
    )
