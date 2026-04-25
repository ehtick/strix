"""SDK function-tool wrapper for the legacy ``browser_action`` tool.

The browser is fully sandbox-bound — the legacy implementation runs
inside the container against a Playwright instance the tool server
manages. We delegate every action verbatim to ``post_to_sandbox``.

The legacy ``browser_action`` is a single mega-tool dispatching 21
discrete actions (launch, goto, click, scroll_*, new_tab, etc.). We
preserve that shape for parity rather than fanning out into 21
separate tools — that would balloon the system prompt and surprise
the model.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from agents import RunContextWrapper

from strix.tools._decorator import strix_tool
from strix.tools._sandbox_dispatch import post_to_sandbox


def _dump(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, default=str)


BrowserAction = Literal[
    "launch",
    "goto",
    "click",
    "type",
    "scroll_down",
    "scroll_up",
    "back",
    "forward",
    "new_tab",
    "switch_tab",
    "close_tab",
    "wait",
    "execute_js",
    "double_click",
    "hover",
    "press_key",
    "save_pdf",
    "get_console_logs",
    "view_source",
    "close",
    "list_tabs",
]


# Browser actions can take time (page loads, navigation timeouts), so
# match the sandbox dispatch read budget rather than capping shorter.
@strix_tool(timeout=180)
async def browser_action(
    ctx: RunContextWrapper,
    action: BrowserAction,
    url: str | None = None,
    coordinate: str | None = None,
    text: str | None = None,
    tab_id: str | None = None,
    js_code: str | None = None,
    duration: float | None = None,
    key: str | None = None,
    file_path: str | None = None,
    clear: bool = False,
) -> str:
    """Drive the sandboxed Playwright browser (Chromium, headless).

    The browser is **persistent** — state survives across calls and tabs
    until you ``close``. Browser interaction must start with ``launch``
    and end with ``close``. Multiple tabs are supported; the first tab
    after ``launch`` is ``"tab_1"`` and new tabs are numbered
    sequentially.

    **Click coordinates** — derive them from the most recent screenshot.
    Target the *center* of the element, not the edge. After clicking,
    verify success against the next screenshot. Bad coordinates are the
    most common reason clicks silently fail.

    **JavaScript execution** (``execute_js``):

    - Code runs in the page context with full DOM access.
    - The **last evaluated expression is auto-returned** — do not use
      ``return`` (it breaks evaluation).
    - For an object literal as the final expression, wrap in parentheses:
      ``({title: document.title, url: location.href})``.
    - ``await`` is supported: ``await fetch(location.href).then(r => r.status)``.
    - Variables from your tool context are NOT available — pass data
      via the URL or DOM if you need to thread it through.
    - The ``js_code`` parameter is executed as-is; no escaping needed,
      single- or multi-line both work.

    **Form filling** — click the field first, then ``type`` the text.

    **Tabs** — actions affect the currently active tab unless ``tab_id``
    is set. Always keep at least one tab open. Close tabs you don't need
    with ``close_tab``, and ``close`` the browser when you're fully done.

    **Concurrency** — the browser session can run alongside terminal /
    python tool calls in subsequent turns; nothing in the browser is
    serialized against other tools.

    Special keys for ``press_key``: single chars ``a``-``z`` / ``0``-``9``,
    ``Enter`` / ``Escape`` / ``Tab`` / ``Space`` / ``ArrowLeft`` /
    ``ArrowRight`` / ``ArrowUp`` / ``ArrowDown``, modifiers ``Shift`` /
    ``Control`` / ``Alt`` / ``Meta``, function keys ``F1``-``F12``.

    Returns: a JSON dict with ``screenshot`` (base64 PNG), ``url``,
    ``title``, ``viewport``, ``tab_id``, ``all_tabs``. Per-action extras:
    ``js_result`` for ``execute_js``, ``pdf_saved`` for ``save_pdf``,
    ``console_logs`` (≤50 KB / ≤200 most recent) for ``get_console_logs``,
    ``page_source`` (truncated to 100 KB) for ``view_source``.

    Args:
        action: One of: ``launch``, ``goto``, ``click``, ``type``,
            ``scroll_down``, ``scroll_up``, ``back``, ``forward``,
            ``new_tab``, ``switch_tab``, ``close_tab``, ``list_tabs``,
            ``wait``, ``execute_js``, ``double_click``, ``hover``,
            ``press_key``, ``save_pdf``, ``get_console_logs``,
            ``view_source``, ``close``.
        url: Required for ``launch`` / ``goto``; optional for
            ``new_tab``. Must include the protocol (e.g.
            ``https://...``, ``file://...``).
        coordinate: ``"x,y"`` pixel target for ``click`` / ``double_click``
            / ``hover``. Format example: ``"432,321"``. Must be within
            viewport.
        text: Required for ``type``.
        tab_id: Required for ``switch_tab`` / ``close_tab``; optional
            elsewhere to target a specific tab.
        js_code: Required for ``execute_js``.
        duration: Seconds for ``wait`` (fractional OK, e.g. ``0.5``).
        key: Required for ``press_key``.
        file_path: Required for ``save_pdf``.
        clear: For ``get_console_logs``, clear logs after retrieval
            (default False).
    """
    return _dump(
        await post_to_sandbox(
            ctx,
            "browser_action",
            {
                "action": action,
                "url": url,
                "coordinate": coordinate,
                "text": text,
                "tab_id": tab_id,
                "js_code": js_code,
                "duration": duration,
                "key": key,
                "file_path": file_path,
                "clear": clear,
            },
        ),
    )
