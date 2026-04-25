"""SDK function-tool wrappers for the seven Caido proxy tools.

All seven dispatch to the in-container Caido manager via the sandbox
tool server. Same pattern as browser/terminal/python — host wrapper is
pure pass-through, no logic of its own.

Tools: list_requests, view_request, send_request, repeat_request,
scope_rules, list_sitemap, view_sitemap_entry.
"""

from __future__ import annotations

from typing import Any, Literal

from agents import RunContextWrapper

from strix.tools._decorator import dump_tool_result, strix_tool
from strix.tools._sandbox_dispatch import post_to_sandbox


RequestPart = Literal["request", "response"]
SortBy = Literal[
    "timestamp",
    "host",
    "method",
    "path",
    "status_code",
    "response_time",
    "response_size",
    "source",
]
SortOrder = Literal["asc", "desc"]
SitemapDepth = Literal["DIRECT", "ALL"]
ScopeAction = Literal["get", "list", "create", "update", "delete"]


@strix_tool(timeout=120)
async def list_requests(
    ctx: RunContextWrapper,
    httpql_filter: str | None = None,
    start_page: int = 1,
    end_page: int = 1,
    page_size: int = 50,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> str:
    """List captured HTTP requests from the Caido proxy with HTTPQL filtering.

    Caido HTTPQL syntax (operators differ by field type):

    - **Integer fields** (``resp.code``, ``req.port``, ``id``,
      ``roundtrip``) — ``eq``, ``gt``, ``gte``, ``lt``, ``lte``, ``ne``.
      Examples: ``resp.code.eq:200``, ``resp.code.gte:400``,
      ``req.port.eq:443``.
    - **Text/byte fields** (``req.method``, ``req.host``, ``req.path``,
      ``req.query``, ``req.ext``, ``req.raw``) — ``regex``, ``cont``
      (substring), ``eq``. Examples: ``req.method.eq:"POST"``,
      ``req.path.cont:"/api/"``, ``req.host.regex:".*\\.example\\.com"``.
    - **Date fields** (``req.created_at``) — ``gt``, ``lt`` with ISO
      timestamps: ``req.created_at.gt:"2024-01-01T00:00:00Z"``.
    - **Combine** with ``AND`` / ``OR``: ``req.method.eq:"POST" AND
      resp.code.gte:400``.
    - **Special**: ``source:intercept`` (only intercepted requests),
      ``preset:"name"``.

    Args:
        httpql_filter: Caido HTTPQL query.
        start_page: Starting page, 1-indexed.
        end_page: Ending page (inclusive).
        page_size: Entries per page (default 50).
        sort_by: ``timestamp`` / ``host`` / ``method`` / ``path`` /
            ``status_code`` / ``response_time`` / ``response_size`` /
            ``source``.
        sort_order: ``asc`` or ``desc``.
        scope_id: Restrict to a scope (managed via ``scope_rules``).
    """
    return dump_tool_result(
        await post_to_sandbox(
            ctx,
            "list_requests",
            {
                "httpql_filter": httpql_filter,
                "start_page": start_page,
                "end_page": end_page,
                "page_size": page_size,
                "sort_by": sort_by,
                "sort_order": sort_order,
                "scope_id": scope_id,
            },
        ),
    )


@strix_tool(timeout=60)
async def view_request(
    ctx: RunContextWrapper,
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> str:
    """View a captured request or its response, optionally regex-searched.

    Two modes:

    - **With** ``search_pattern`` (compact regex hits) — returns up to 20
      matches with ``before`` / ``after`` context and position. Useful
      for hunting reflected input, leaked URLs, hidden parameters.
    - **Without** ``search_pattern`` (full content with pagination) —
      returns the page of raw content plus ``has_more`` flag.

    Common search patterns:

    - API endpoints: ``/api/[a-zA-Z0-9._/-]+``
    - URLs: ``https?://[^\\s<>"']+``
    - Query parameters: ``[?&][a-zA-Z0-9_]+=([^&\\s<>"']+)``
    - Specific input reflection: search for the value you submitted.

    Args:
        request_id: Request ID from ``list_requests``.
        part: ``"request"`` or ``"response"``.
        search_pattern: Optional regex; switches the response shape to
            compact hits.
        page: 1-indexed page number (only when no ``search_pattern``).
        page_size: Lines per page.
    """
    return dump_tool_result(
        await post_to_sandbox(
            ctx,
            "view_request",
            {
                "request_id": request_id,
                "part": part,
                "search_pattern": search_pattern,
                "page": page,
                "page_size": page_size,
            },
        ),
    )


# strict_mode=False because ``headers`` is a free-form dict — the model
# can't enumerate all possible HTTP headers, and the SDK's strict JSON
# schema rejects ``additionalProperties: true``.
@strix_tool(timeout=120, strict_mode=False)
async def send_request(
    ctx: RunContextWrapper,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
) -> str:
    """Send an arbitrary HTTP request through the Caido proxy.

    Use this for one-off probes (test endpoints, reach external APIs).
    For modifying-and-replaying a request you've already captured, use
    ``repeat_request`` instead — it inherits the original headers /
    cookies / auth and only patches the fields you specify.

    Args:
        method: ``"GET"`` / ``"POST"`` / ``"PUT"`` / ``"DELETE"`` / etc.
        url: Full URL with protocol.
        headers: Optional header dict.
        body: Optional request body string.
        timeout: Per-request timeout in seconds (default 30).
    """
    return dump_tool_result(
        await post_to_sandbox(
            ctx,
            "send_request",
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "body": body,
                "timeout": timeout,
            },
        ),
    )


# strict_mode=False because ``modifications`` is a free-form patch dict
# (header overrides, body replacements, query-string tweaks) the model
# composes per-call.
@strix_tool(timeout=120, strict_mode=False)
async def repeat_request(
    ctx: RunContextWrapper,
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> str:
    """Repeat a captured request, optionally patching individual fields.

    The standard pentesting workflow with this tool:

    1. ``browser_action`` (or live target traffic) → request gets
       captured by Caido.
    2. ``list_requests`` → find the request ID you want to manipulate.
    3. ``repeat_request`` → send a modified version (auth-bypass test,
       payload injection, parameter tampering).

    Mirrors the manual "browse → capture → modify → test" flow used in
    real pentesting. Inherits everything from the original request
    (headers, cookies, auth, method, URL) and overlays only the fields
    you specify in ``modifications``.

    Args:
        request_id: ID of the original request (from ``list_requests``).
        modifications: Patch dict. Recognized keys:

            - ``url`` — replace the URL.
            - ``params`` — dict of query-string keys to add/update.
            - ``headers`` — dict of headers to add/update.
            - ``body`` — replace the body string entirely.
            - ``cookies`` — dict of cookies to add/update.
    """
    return dump_tool_result(
        await post_to_sandbox(
            ctx,
            "repeat_request",
            {
                "request_id": request_id,
                "modifications": modifications or {},
            },
        ),
    )


@strix_tool(timeout=60)
async def scope_rules(
    ctx: RunContextWrapper,
    action: ScopeAction,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> str:
    """CRUD on Caido scope rules (allow/deny patterns).

    Scopes filter which traffic Caido tools see. Use them to focus on a
    target, exclude noisy assets (CDNs, static files), or define a
    bug-bounty allowlist.

    Pattern semantics:

    - Glob wildcards: ``*`` (any), ``?`` (single), ``[abc]`` (one of),
      ``[a-z]`` (range), ``[^abc]`` (none of).
    - **Empty allowlist = allow all domains.**
    - **Denylist always overrides allowlist.**

    Common denylist for noisy static assets:
    ``["*.gif", "*.jpg", "*.png", "*.css", "*.js", "*.ico", "*.svg",
    "*woff*", "*.ttf"]``.

    Each scope has a unique id usable as ``scope_id`` in
    ``list_requests`` / ``list_sitemap`` / ``view_request``.

    Args:
        action:

            - ``list`` — return all scopes.
            - ``get`` — single scope by ``scope_id`` (or all when
              omitted).
            - ``create`` — needs ``scope_name``, optionally
              ``allowlist`` / ``denylist``.
            - ``update`` — needs ``scope_id`` + ``scope_name``;
              allowlist / denylist replace the previous values.
            - ``delete`` — needs ``scope_id``.

        allowlist: Domain patterns to include (e.g.
            ``["*.example.com", "api.test.com"]``).
        denylist: Patterns to exclude.
        scope_id: Required for ``get`` / ``update`` / ``delete``.
        scope_name: Required for ``create`` / ``update``.
    """
    return dump_tool_result(
        await post_to_sandbox(
            ctx,
            "scope_rules",
            {
                "action": action,
                "allowlist": allowlist,
                "denylist": denylist,
                "scope_id": scope_id,
                "scope_name": scope_name,
            },
        ),
    )


@strix_tool(timeout=60)
async def list_sitemap(
    ctx: RunContextWrapper,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
) -> str:
    """View the hierarchical sitemap of discovered attack surface.

    The sitemap is built from proxied traffic — every URL the target
    served gets indexed into a tree of domains → directories → request
    leaves. Use it to understand application structure and find
    interesting endpoints, hidden directories, parameter variations.

    Entry kinds you'll encounter:

    - ``DOMAIN`` — root host (``example.com``).
    - ``DIRECTORY`` — path segment (``/api/``, ``/admin/``).
    - ``REQUEST`` — a specific endpoint.
    - ``REQUEST_BODY`` — POST/PUT body variations (different payloads
      seen at the same URL).
    - ``REQUEST_QUERY`` — query-string variations.

    Each entry has ``hasDescendants`` — set ``parent_id`` to that
    entry's id to drill in. Pages return 30 entries each.

    Args:
        scope_id: Filter to a specific scope.
        parent_id: Drill into a subtree. ``None`` returns root domains.
        depth: ``"DIRECT"`` (immediate children) or ``"ALL"`` (recursive).
        page: 1-indexed page (30 entries/page).
    """
    return dump_tool_result(
        await post_to_sandbox(
            ctx,
            "list_sitemap",
            {
                "scope_id": scope_id,
                "parent_id": parent_id,
                "depth": depth,
                "page": page,
            },
        ),
    )


@strix_tool(timeout=60)
async def view_sitemap_entry(ctx: RunContextWrapper, entry_id: str) -> str:
    """Examine one sitemap entry — full metadata + every related request.

    Use this after ``list_sitemap`` identifies an interesting directory
    or endpoint to see all the requests captured under it (methods,
    paths, response codes, timing).

    Args:
        entry_id: Sitemap entry id from ``list_sitemap``.
    """
    return dump_tool_result(
        await post_to_sandbox(ctx, "view_sitemap_entry", {"entry_id": entry_id}),
    )
